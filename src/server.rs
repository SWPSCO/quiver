use tracing::{info, warn, error};
use anyhow::Result;
use quinn::{ServerConfig, Endpoint, Connection, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::Bytes;
use std::str::FromStr;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use crate::auth::{Authenticator, ConnectionGuard};
use crate::device_info::{DeviceInfo, DeviceInfoUpdater};
use crate::new_job::NewJobProvider;
use crate::types::{Template, Submission, SubmissionResponse, AccountInformation};
use crate::submission::SubmissionConsumer;
use crate::types::{CURRENT_VERSION, ProtocolVersion};

struct QuiverInstance {
    conn: Connection,
    authenticator: Arc<dyn Authenticator>,
    connection_guard: Option<Box<dyn ConnectionGuard>>,
    account_information: Option<AccountInformation>,
    api_key: Option<String>,
    device_info_updater: Arc<dyn DeviceInfoUpdater>,
    new_job_provider: Arc<dyn NewJobProvider>,
    submission_consumer: Arc<dyn SubmissionConsumer>,
}

impl QuiverInstance {
    fn new(
        conn: Connection,
        authenticator: Arc<dyn Authenticator>,
        device_info_updater: Arc<dyn DeviceInfoUpdater>,
        new_job_provider: Arc<dyn NewJobProvider>,
        submission_consumer: Arc<dyn SubmissionConsumer>,
    ) -> Self {
        Self {
            conn,
            authenticator,
            connection_guard: None,
            account_information: None,
            api_key: None,
            device_info_updater,
            new_job_provider,
            submission_consumer,
        }
    }
    
    const TOKEN_PREFIX: u32 = 0x6e6f636b; // nock

    pub async fn serve(&mut self) -> Result<()> {
        // First bidi stream: either legacy auth (v0) or version handshake (v1+)
        let (mut send0, mut recv0) = self.conn.accept_bi().await?;

        // Peek first 4 bytes as u32 (legacy "nock" or length of version blob)
        let first_u32 = recv0.read_u32().await;

        match first_u32 {
            Ok(x) if x == Self::TOKEN_PREFIX => {
                // v0 legacy path
                self.serve_v1(send0, recv0).await
            }
            Ok(len) => {
                // v1+ path (len = size of ProtocolVersion)
                self.serve_v2(send0, recv0, len).await
            }
            Err(e) => {
                error!("Failed to read initial handshake bytes: {}", e);
                Err(e.into())
            }
        }
    }

    /// v0 (legacy) protocol:
    /// - First stream carries the API key (raw, no length prefix), starting with "nock"
    /// - Reply on same stream with raw "authenticated"/"unauthorized"
    /// - Device info stream: raw bincode (no length), raw "accepted"/"rejected"
    async fn serve_v1(
        &mut self,
        mut send0: quinn::SendStream,
        mut recv0: quinn::RecvStream,
    ) -> Result<()> {
        warn!("Legacy authentication, no version handshake. Please update your miner!");
        // rebuild the full token:
        let mut key = Self::TOKEN_PREFIX.to_be_bytes().to_vec();
        key.extend(recv0.read_to_end(50 - 4).await?);
        let api_key = String::from_utf8(key)?;

        // Authenticate & reply on same stream
        match self.authenticator.authenticate(&api_key).await {
            Ok((acct, guard)) => {
                self.account_information = Some(acct);
                self.connection_guard = Some(guard);
                self.api_key = Some(api_key);
                send0.write_all(b"authenticated").await?;
                send0.finish()?;
            }
            Err(e) => {
                let _ = send0.write_all(b"unauthorized").await;
                let _ = send0.finish();
                return Err(e);
            }
        }

        // Device info (legacy)
        if !self.handle_device_info_stream(false).await? {
            return Err(anyhow::anyhow!("Device info rejected"));
        }

        self.after_ready_then_work().await
    }

    /// v2 protocol:
    /// - First stream is version handshake (len-prefixed bincode<ProtocolVersion>), reply "ok" (len-prefixed)
    /// - Second stream carries API key (len-prefixed), reply len-prefixed "authenticated"/"unauthorized"
    /// - Device info stream: len-prefixed bincode, len-prefixed "accepted"/"rejected"
    async fn serve_v2(
        &mut self,
        mut send0: quinn::SendStream,
        mut recv0: quinn::RecvStream,
        ver_len: u32,
    ) -> Result<()> {
        // Read version struct
        if ver_len == 0 || ver_len >= 100 {
            return Err(anyhow::anyhow!("Invalid protocol handshake length: {}", ver_len));
        }
        let mut ver_buf = vec![0; ver_len as usize];
        recv0.read_exact(&mut ver_buf).await
            .map_err(|_| anyhow::anyhow!("Malformed protocol handshake. Please update your miner."))?;
        let client_v: ProtocolVersion = bincode::deserialize(&ver_buf)
            .map_err(|_| anyhow::anyhow!("Malformed protocol handshake."))?;
        if client_v.major != CURRENT_VERSION.major {
            return Err(anyhow::anyhow!("Incompatible protocol version"));
        }
        info!("Handshake successful: v{}.{}.{}", client_v.major, client_v.minor, client_v.patch);
        // Send len-prefixed "ok" and finish handshake stream
        Self::lp_write(&mut send0, b"ok").await?;
        send0.finish()?;

        // Auth stream
        let (mut send_auth, mut recv_auth) = self.conn.accept_bi().await?;
        let key = Self::lp_read(&mut recv_auth, 256).await?; // cap 256B
        let api_key = String::from_utf8(key)?;

        match self.authenticator.authenticate(&api_key).await {
            Ok((acct, guard)) => {
                self.account_information = Some(acct);
                self.connection_guard = Some(guard);
                self.api_key = Some(api_key);
                Self::lp_write(&mut send_auth, b"authenticated").await?;
                send_auth.finish()?;
            }
            Err(e) => {
                let _ = Self::lp_write(&mut send_auth, b"unauthorized").await;
                let _ = send_auth.finish();
                return Err(e);
            }
        }

        // Device info v2
        if !self.handle_device_info_stream(true).await? {
            return Err(anyhow::anyhow!("Device info rejected"));
        }

        self.after_ready_then_work().await
    }

    async fn after_ready_then_work(&mut self) -> Result<()> {
        let truncated_api_key = self
            .api_key
            .as_ref()
            .unwrap()
            .chars()
            .rev()
            .take(8)
            .collect::<String>();

        info!(
            "{:?} device key {:?} put to work",
            self.account_information.as_ref().unwrap().user_uuid,
            truncated_api_key
        );

        self.handle_work().await
    }

    /// len_prefixed: v2, expect/read/write length-prefixed frames
    /// !len_prefixed: v1, legacy raw frames
    async fn handle_device_info_stream(&mut self, len_prefixed: bool) -> Result<bool> {
        let Ok((mut send, mut recv)) = self.conn.accept_bi().await else {
            return Err(anyhow::anyhow!("connection closed before device info"));
        };

        // Read device info bytes
        let device_info_bytes = if len_prefixed {
            Self::lp_read(&mut recv, 1_000_000).await? // 1MB cap
        } else {
            // legacy raw bincode, small bound
            recv.read_to_end(4096).await?
        };

        let device_info = bincode::deserialize::<DeviceInfo>(&device_info_bytes)?;
        let Some(api_key) = self.api_key.clone() else {
            return Err(anyhow::anyhow!("no api key"));
        };

        // update & reply in matching format
        match self.device_info_updater.update_device_info(&device_info, &api_key).await {
            Ok(_) => {
                if len_prefixed {
                    Self::lp_write(&mut send, b"accepted").await?;
                } else {
                    send.write_all(b"accepted").await?;
                }
                send.finish()?;
                Ok(true)
            }
            Err(_) => {
                if len_prefixed {
                    Self::lp_write(&mut send, b"rejected").await?;
                } else {
                    send.write_all(b"rejected").await?;
                }
                send.finish()?;
                Ok(false)
            }
        }
    }

    //  helpers for v2 length-prefixed messages
    async fn lp_read(recv: &mut quinn::RecvStream, max_len: u32) -> Result<Vec<u8>> {
        let n = recv.read_u32().await?;
        if n == 0 || n > max_len {
            return Err(anyhow::anyhow!("frame size out of bounds: {}", n));
        }
        let mut buf = vec![0; n as usize];
        recv.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn lp_write(send: &mut quinn::SendStream, bytes: &[u8]) -> Result<()> {
        send.write_u32(bytes.len() as u32).await?;
        send.write_all(bytes).await?;
        Ok(())
    }

    async fn handle_work(&mut self) -> Result<()> {
        // New job pusher
        let new_job_provider = self.new_job_provider.clone();
        let conn = self.conn.clone();
        tokio::spawn(async move {
            if let Err(e) = push_jobs(conn, new_job_provider).await {
                // if error is connection closed, we can just break the loop
                if e.to_string().contains("connection closed") {
                    return;
                }
            }
        });
        let conn = self.conn.clone();
        // Submission management
        loop {
            let (mut send_submission, mut recv_submission) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(_) => break, // connection closed
            };
            let submission_consumer = self.submission_consumer.clone();
            let account_information = self.account_information.clone();
            tokio::spawn(async move {
                let len = match recv_submission.read_u32().await {
                    Ok(len) => len,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        info!("Submission stream closed.");
                        return;
                    }
                    Err(e) => {
                        error!("submission stream error: {:?}", e);
                        return;
                    }
                };

                let mut buf = vec![0; len as usize];
                recv_submission.read_exact(&mut buf).await.expect("failed to read submission");
                let submission: Submission = bincode::deserialize(&buf).expect("failed to deserialize submission");

                let Some(account_information) = account_information.clone() else {
                    error!("no account information");
                    return;
                };

                let response: SubmissionResponse = submission_consumer.process(submission, account_information).await.expect("failed to process submission");

                let response_bytes = bincode::serialize(&response).expect("failed to serialize response");
                send_submission.write_u32(response_bytes.len() as u32).await.expect("failed to write response length");
                send_submission.write_all(&response_bytes).await.expect("failed to write response");
                let _ = send_submission.finish();
            });
        }
        Ok(())
    }
}

pub async fn run(
    address: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    authenticator: Arc<dyn Authenticator>,
    device_info_updater: Arc<dyn DeviceInfoUpdater>,
    new_job_provider: Arc<dyn NewJobProvider>,
    submission_consumer: Arc<dyn SubmissionConsumer>,
) -> Result<()> {
    info!("quiver listening...");

    let mut config = ServerConfig::with_single_cert(certs, key)?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(2)));
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into()?));
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(50));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(50));
    transport.stream_receive_window(quinn::VarInt::from_u32(10_000_000));
    transport.receive_window(quinn::VarInt::from_u32(10_000_000));
    transport.send_window(10_000_000);

    config.transport = Arc::new(transport);
    config.max_incoming(100000);
    config.incoming_buffer_size(10 * 1024 * 1024);
    config.incoming_buffer_size_total(1024 * 1024 * 1024);

    let endpoint = Endpoint::server(config, SocketAddr::from_str(&address)?)?;
    
    // Start iterating over incoming connections.
    while let Some(conn) = endpoint.accept().await {
        let Ok(connection) = conn.await else {
            continue;
        };
        let authenticator = Arc::clone(&authenticator);
        let device_info_updater = Arc::clone(&device_info_updater);
        let new_job_provider = Arc::clone(&new_job_provider);
        let submission_consumer = Arc::clone(&submission_consumer);
        tokio::spawn(async move {
            let mut instance = QuiverInstance::new(connection, authenticator, device_info_updater, new_job_provider, submission_consumer);
            if let Err(e) = instance.serve().await {
                error!("error: {:?}", e);
            }
        });
    }
    Ok(())
}

async fn push_jobs(
    conn: Connection,
    new_job_provider: Arc<dyn NewJobProvider>,
) -> Result<()> {
    let mut send = conn.open_uni().await?;
    let mut current_template = Template::new(Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new());
    loop {
        let template = new_job_provider.get(current_template.clone()).await;
        let t = match template {
            Ok(t) => t,
            Err(e) => {
                error!("error: {:?}", e);
                continue;
            }
        };
        let buf = bincode::serialize(&t)?;
        send.write_u32(buf.len() as u32).await?;
        send.write_all(&buf).await?;
        current_template = t;
    }
}