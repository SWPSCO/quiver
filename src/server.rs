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

    async fn handle_device_info_stream(&mut self) -> Result<bool> {
        let Ok((mut send, mut recv)) = self.conn.accept_bi().await else {
            return Err(anyhow::anyhow!("connection closed before device info"));
        };
        let len = recv.read_u32().await?;
        if len == 0 {
            return Err(anyhow::anyhow!("Received empty device info."));
        }
        let mut device_info_bytes = vec![0; len as usize];
        recv.read_exact(&mut device_info_bytes).await?;
        let device_info = bincode::deserialize::<DeviceInfo>(&device_info_bytes)?;
        let Some(api_key) = self.api_key.clone() else {
            return Err(anyhow::anyhow!("no api key"));
        };

        match self.device_info_updater.update_device_info(&device_info, &api_key).await {
            Ok(_) => {
                send.write_all(b"accepted").await?;
                send.finish()?;
                Ok(true)
            }
            Err(_) => {
                send.write_all(b"rejected").await?;
                send.finish()?;
                Ok(false)
            }
        }
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

    async fn serve(&mut self) -> Result<()> {
        // The first stream must handle both versioning and auth for backward compatibility
        let (mut send, mut recv) = self.conn.accept_bi().await?;
        // heuristic to determine whether this is a handshake or legacy auth attempt
        let initial_bytes = recv.read_u32().await;
        const TOKEN_PREFIX: u32 = 1852793707;

        // We should remove this in the future
        let api_key_bytes = match initial_bytes {
            Ok(TOKEN_PREFIX) => {
                warn!("Legacy authentication, no version handshake. Please update your miner!");
                let mut key_bytes = TOKEN_PREFIX.to_be_bytes().to_vec();
                key_bytes.extend(recv.read_to_end(50 - 4).await?);
                key_bytes
            },
            // assume this is a version handshake
            Ok(len) => {
                if len > 0 && len < 100 {
                    let mut ver_bytes = vec![0; len as usize];
                    match recv.read_exact(&mut ver_bytes).await {
                        Ok(_) => {
                            match bincode::deserialize::<ProtocolVersion>(&ver_bytes) {
                                // Deserialized correctly and the major version matches
                                // If we have incompatible protocol changes in the future, fork here
                                Ok(client_version) if client_version.major == CURRENT_VERSION.major => {
                                    info!("Handshake successful: v{}.{}.{}", client_version.major, client_version.minor, client_version.patch);
                                    send.write_all(b"ok").await?;
                                    send.finish()?;
                                    let (_send_auth, mut recv_auth) = self.conn.accept_bi().await?;
                                    let key_len = recv_auth.read_u32().await?;
                                    // Check length
                                    if key_len > 256 {
                                        return Err(anyhow::anyhow!("Protocol error: new client key size of {} exceeds limit of 256", key_len));
                                    }
                                    let mut key_bytes = vec![0; key_len as usize];
                                    recv_auth.read_exact(&mut key_bytes).await?;
                                    key_bytes
                                },
                                _ => return Err(anyhow::anyhow!("Incompatible protocol version or malformed handshake")),
                            }
                        },
                        Err(_) => return Err(anyhow::anyhow!("Malformed protocol handshake. Please update your miner.")),
                    }
                } else {
                    return Err(anyhow::anyhow!("Invalid protocol handshake length: {}", len));
                }
            },
            Err(e) => {
                error!("Failed to read initial handshake bytes: {}", e);
                return Err(e.into());
            }
        };

        let api_key = String::from_utf8(api_key_bytes)?;

        // --- Authentication ---
        match self.authenticator.authenticate(&api_key).await {
            Ok((account_information, guard)) => {
                self.account_information = Some(account_information);
                self.connection_guard = Some(guard);
                self.api_key = Some(api_key);
            }
            Err(e) => return Err(e),
        }

        // --- Device Info ---
        if !self.handle_device_info_stream().await? {
            return Err(anyhow::anyhow!("Device info rejected"));
        }

        let truncated_api_key = self.api_key.as_ref().unwrap().chars().rev().take(8).collect::<String>();
        info!("{:?} device key {:?} put to work", self.account_information.as_ref().unwrap().user_uuid, truncated_api_key);

        // --- Ready for work ---
        self.handle_work().await
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