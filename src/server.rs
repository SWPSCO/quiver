use anyhow::Result;
use bytes::Bytes;
use quinn::{Connection, Endpoint, ServerConfig, TransportConfig};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};

use crate::auth::{Authenticator, ConnectionGuard};
use crate::device_info::{DeviceInfo, DeviceInfoUpdater};
use crate::new_job::NewJobProvider;
use crate::submission::SubmissionConsumer;
use crate::telemetry::{
    TelemetryConsumer, TelemetryData, TELEMETRY_FRAME_MAX_BYTES, TELEMETRY_STREAM_MARKER,
};
use crate::types::{AccountInformation, Submission, SubmissionResponse, Template};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Conservative upper bound for a single submission frame.
///
/// Typical submissions are much smaller. This protects the server against
/// accidental or malicious oversized frame allocations.
const SUBMISSION_FRAME_MAX_BYTES: u32 = 2 * 1024 * 1024;

struct QuiverInstance {
    conn: Connection,
    authenticator: Arc<dyn Authenticator>,
    connection_guard: Option<Box<dyn ConnectionGuard>>,
    account_information: Option<AccountInformation>,
    api_key: Option<String>,
    device_info_updater: Arc<dyn DeviceInfoUpdater>,
    new_job_provider: Arc<dyn NewJobProvider>,
    submission_consumer: Arc<dyn SubmissionConsumer>,
    telemetry_consumer: Option<Arc<dyn TelemetryConsumer>>,
}

impl QuiverInstance {
    fn new(
        conn: Connection,
        authenticator: Arc<dyn Authenticator>,
        device_info_updater: Arc<dyn DeviceInfoUpdater>,
        new_job_provider: Arc<dyn NewJobProvider>,
        submission_consumer: Arc<dyn SubmissionConsumer>,
        telemetry_consumer: Option<Arc<dyn TelemetryConsumer>>,
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
            telemetry_consumer,
        }
    }

    async fn handle_auth_stream(&mut self) -> Result<bool> {
        let Ok((mut send, mut recv)) = self.conn.accept_bi().await else {
            return Err(anyhow::anyhow!("connection closed before auth"));
        };

        let api_key = String::from_utf8(recv.read_to_end(50).await?)?;

        match self.authenticator.authenticate(&api_key).await {
            Ok((account_information, guard)) => {
                self.account_information = Some(account_information);
                self.connection_guard = Some(guard);
                self.api_key = Some(api_key);
                send.write_all(b"authenticated").await?;
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

    async fn handle_device_info_stream(&mut self) -> Result<bool> {
        let Ok((mut send, mut recv)) = self.conn.accept_bi().await else {
            return Err(anyhow::anyhow!("connection closed before device info"));
        };

        let device_info = bincode::deserialize::<DeviceInfo>(&recv.read_to_end(1024).await?)?;
        let Some(api_key) = self.api_key.clone() else {
            return Err(anyhow::anyhow!("no api key"));
        };

        match self
            .device_info_updater
            .update_device_info(&device_info, &api_key)
            .await
        {
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
        // New job pusher on a dedicated unidirectional stream.
        // This stream is independent from bidirectional submission/telemetry streams.
        let new_job_provider = self.new_job_provider.clone();
        let conn = self.conn.clone();
        tokio::spawn(async move {
            if let Err(e) = push_jobs(conn, new_job_provider).await {
                if e.to_string().contains("connection closed") {
                    return;
                }
                warn!("job pusher exited with error: {}", e);
            }
        });

        let conn = self.conn.clone();
        let account_information = self.account_information.clone();
        let api_key = self.api_key.clone();

        // Bidirectional stream multiplexer.
        // Each inbound bi stream is either:
        // - legacy submission stream (length-prefixed submission frame), or
        // - telemetry stream (marker byte + repeating telemetry frames).
        loop {
            let (send_stream, recv_stream) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(_) => break, // connection closed
            };

            let submission_consumer = self.submission_consumer.clone();
            let telemetry_consumer = self.telemetry_consumer.clone();
            let account_information = account_information.clone();
            let api_key = api_key.clone();

            tokio::spawn(async move {
                if let Err(e) = dispatch_bi_stream(
                    send_stream,
                    recv_stream,
                    submission_consumer,
                    telemetry_consumer,
                    account_information,
                    api_key,
                )
                .await
                {
                    warn!("bi stream handler exited with error: {}", e);
                }
            });
        }
        Ok(())
    }

    async fn serve(&mut self) -> Result<()> {
        // The first stream MUST be for authentication.
        if !self.handle_auth_stream().await? {
            // If auth fails, we close the connection immediately.
            return Err(anyhow::anyhow!("Authentication failed"));
        }

        // After auth, receive device info.
        if !self.handle_device_info_stream().await? {
            return Err(anyhow::anyhow!("Device info rejected"));
        }

        // take the last 8 characters of the api key
        let truncated_api_key = self
            .api_key
            .as_ref()
            .unwrap()
            .chars()
            .rev()
            .take(8)
            .collect::<String>();
        info!(
            "{:?} put to work with key {:?}",
            self.account_information.as_ref().unwrap().user_uuid,
            truncated_api_key
        );

        // Ready for work.
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
    run_with_telemetry(
        address,
        certs,
        key,
        authenticator,
        device_info_updater,
        new_job_provider,
        submission_consumer,
        None,
    )
    .await
}

/// Start the quiver server with optional telemetry consumer support.
///
/// Existing callers can continue using `run()` without telemetry by passing `None`
/// through the compatibility wrapper above.
pub async fn run_with_telemetry(
    address: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    authenticator: Arc<dyn Authenticator>,
    device_info_updater: Arc<dyn DeviceInfoUpdater>,
    new_job_provider: Arc<dyn NewJobProvider>,
    submission_consumer: Arc<dyn SubmissionConsumer>,
    telemetry_consumer: Option<Arc<dyn TelemetryConsumer>>,
) -> Result<()> {
    info!("quiver listening...");

    let mut config = ServerConfig::with_single_cert(certs, key)?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(2)));
    transport.max_idle_timeout(Some(Duration::from_secs(5).try_into()?));
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
        let telemetry_consumer = telemetry_consumer.clone();
        tokio::spawn(async move {
            let mut instance = QuiverInstance::new(
                connection,
                authenticator,
                device_info_updater,
                new_job_provider,
                submission_consumer,
                telemetry_consumer,
            );
            if let Err(e) = instance.serve().await {
                error!("error: {:?}", e);
            }
        });
    }
    Ok(())
}

/// Route an incoming bidirectional stream to either submission or telemetry handling.
async fn dispatch_bi_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    submission_consumer: Arc<dyn SubmissionConsumer>,
    telemetry_consumer: Option<Arc<dyn TelemetryConsumer>>,
    account_information: Option<AccountInformation>,
    api_key: Option<String>,
) -> Result<()> {
    let first_byte = match recv.read_u8().await {
        Ok(byte) => byte,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            info!("bidirectional stream closed before payload");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    // Marker-prefixed stream: dedicated long-lived telemetry transport.
    if first_byte == TELEMETRY_STREAM_MARKER {
        let Some(telemetry_consumer) = telemetry_consumer else {
            warn!("received telemetry stream but no telemetry consumer is configured");
            return Ok(());
        };
        let Some(account_information) = account_information else {
            return Err(anyhow::anyhow!(
                "telemetry stream received without account information"
            ));
        };
        let Some(api_key) = api_key else {
            return Err(anyhow::anyhow!("telemetry stream received without api key"));
        };

        // Telemetry is one-way from client -> server.
        // Close send-half to signal there will be no server response payloads.
        let _ = send.finish();
        return handle_telemetry_stream(recv, telemetry_consumer, account_information, api_key)
            .await;
    }

    // Legacy submission stream: first byte belongs to u32 frame length.
    handle_submission_stream(
        first_byte,
        &mut send,
        &mut recv,
        submission_consumer,
        account_information,
    )
    .await
}

/// Handle one legacy submission stream where frame length starts at the first byte.
async fn handle_submission_stream(
    first_len_byte: u8,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    submission_consumer: Arc<dyn SubmissionConsumer>,
    account_information: Option<AccountInformation>,
) -> Result<()> {
    let Some(account_information) = account_information else {
        return Err(anyhow::anyhow!(
            "submission stream received without account information"
        ));
    };

    // Reconstruct the big-endian u32 length from the already-consumed first byte.
    let mut len_tail = [0u8; 3];
    recv.read_exact(&mut len_tail).await?;
    let frame_len = u32::from_be_bytes([first_len_byte, len_tail[0], len_tail[1], len_tail[2]]);

    if frame_len == 0 {
        return Err(anyhow::anyhow!("submission frame length is zero"));
    }
    if frame_len > SUBMISSION_FRAME_MAX_BYTES {
        return Err(anyhow::anyhow!(
            "submission frame too large: {} > {}",
            frame_len,
            SUBMISSION_FRAME_MAX_BYTES
        ));
    }

    let mut buf = vec![0; frame_len as usize];
    recv.read_exact(&mut buf).await?;
    let submission: Submission = bincode::deserialize(&buf)?;

    let response: SubmissionResponse = submission_consumer
        .process(submission, account_information)
        .await?;
    let response_bytes = bincode::serialize(&response)?;
    send.write_u32(response_bytes.len() as u32).await?;
    send.write_all(&response_bytes).await?;
    let _ = send.finish();
    Ok(())
}

/// Handle a marker-prefixed telemetry stream with repeating length-delimited frames.
async fn handle_telemetry_stream(
    mut recv: quinn::RecvStream,
    telemetry_consumer: Arc<dyn TelemetryConsumer>,
    account_information: AccountInformation,
    api_key: String,
) -> Result<()> {
    loop {
        let frame_len = match recv.read_u32().await {
            Ok(len) => len,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!("telemetry stream closed by peer");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        if frame_len == 0 {
            warn!("received empty telemetry frame");
            continue;
        }

        if frame_len > TELEMETRY_FRAME_MAX_BYTES {
            return Err(anyhow::anyhow!(
                "telemetry frame too large: {} > {}",
                frame_len,
                TELEMETRY_FRAME_MAX_BYTES
            ));
        }

        let mut buf = vec![0; frame_len as usize];
        recv.read_exact(&mut buf).await?;
        let telemetry: TelemetryData = bincode::deserialize(&buf)?;

        // Consumer failures are logged and ignored so a single bad write does
        // not terminate telemetry transport for that miner connection.
        if let Err(e) = telemetry_consumer
            .process_telemetry(telemetry, account_information.clone(), &api_key)
            .await
        {
            warn!("telemetry consumer failed: {}", e);
        }
    }
}

async fn push_jobs(conn: Connection, new_job_provider: Arc<dyn NewJobProvider>) -> Result<()> {
    let mut send = conn.open_uni().await?;
    let mut current_template = Template::new(
        Bytes::new(),
        Bytes::new(),
        Bytes::new(),
        Bytes::new(),
        Bytes::new(),
    );
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
