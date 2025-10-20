use std::net::SocketAddr;
use std::sync::Arc;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error};

use crate::device_info::DeviceInfo;
use crate::types::{Template, Submission, SubmissionResponse};
use crate::new_job::NewJobConsumer;
use crate::submission::{SubmissionProvider, SubmissionResponseHandler};
use crate::insecure::SkipServerVerification;
use crate::types::CURRENT_VERSION;

#[derive(Debug)]
pub struct QuiverClient {
    conn: quinn::Connection,
    key: String,
    device_info: DeviceInfo,
    new_job_consumer: Arc<dyn NewJobConsumer>,
    submission_provider: Arc<dyn SubmissionProvider>,
    submission_response_handler: Arc<dyn SubmissionResponseHandler>,
}

impl QuiverClient {
    fn new(
        conn: Connection,
        key: String,
        device_info: DeviceInfo,
        new_job_consumer: Arc<dyn NewJobConsumer>,
        submission_provider: Arc<dyn SubmissionProvider>,
        submission_response_handler: Arc<dyn SubmissionResponseHandler>,
    ) -> Self {
        Self {
            conn,
            key,
            device_info,
            new_job_consumer,
            submission_provider,
            submission_response_handler,
        }
    }

    async fn perform_version_handshake(&self) -> Result<()> {
        info!("Negotiating protocol version...");
        let (mut send_version, mut recv_version) = self.conn.open_bi().await?;

        let ver_bytes = bincode::serialize(&CURRENT_VERSION)?;
        send_version.write_u32(ver_bytes.len() as u32).await?;
        send_version.write_all(&ver_bytes).await?;
        send_version.finish()?;

        let response = String::from_utf8(recv_version.read_to_end(100).await?)?;
        if response != "ok" {
            return Err(anyhow::anyhow!("Protocol negotiation failed: {}", response));
        }

        info!("Protocol version compatible with server.");
        Ok(())
    }

    async fn serve(&mut self) -> Result<()> {
        // attempt version handshake
        self.perform_version_handshake().await?;
        // --- Authentication Transaction ---
        info!("authenticating...");
        let (mut send_auth, mut recv_auth) = self.conn.open_bi().await?;
        let api_key_bytes = self.key.as_bytes();
        send_auth.write_u32(api_key_bytes.len() as u32).await?;
        send_auth.write_all(api_key_bytes).await?;
        send_auth.finish()?;
        let auth_res = String::from_utf8(recv_auth.read_to_end(50).await?)?;
        if auth_res != "authenticated" {
            return Err(anyhow::anyhow!("Authentication failed: {}", auth_res));
        }

        // --- Device Info Transaction ---
        info!("sending device info...");
        let (mut send_device, mut recv_device) = self.conn.open_bi().await?;
        let device_info_bytes = bincode::serialize(&self.device_info)?;
        send_device.write_u32(device_info_bytes.len() as u32).await?;
        send_device.write_all(&device_info_bytes).await?;
        send_device.finish()?;
        let device_res = String::from_utf8(recv_device.read_to_end(50).await?)?;
        if device_res != "accepted" {
            return Err(anyhow::anyhow!("Device info rejected: {}", device_res));
        }

        info!("Client authenticated and ready for work.");

        // Spawn the background task to receive new jobs.
        let mut job_handle = tokio::spawn(receive_jobs(self.conn.clone(), self.new_job_consumer.clone()));

        loop {
            tokio::select! {
                // Use a biased select to ensure we always check for connection
                // closure and task failure before waiting on a new submission.
                biased;

                // Branch 1: The connection dies for any reason.
                reason = self.conn.closed() => {
                    error!("Connection closed: {:?}", reason);
                    job_handle.abort(); // Stop the background job stream.
                    return Err(anyhow::anyhow!("Connection closed by server or network"));
                },

                // Branch 2: The background job receiver task fails or panics.
                res = &mut job_handle => {
                     match res {
                        Ok(Ok(_)) => error!("Job stream closed unexpectedly."),
                        Ok(Err(e)) => error!("Job stream failed: {}", e),
                        Err(e) => error!("Job stream task panicked: {}", e),
                     }
                     return Err(anyhow::anyhow!("Job stream failed, disconnecting."));
                },

                // Branch 3: The submission provider (miner) has a new proof to send.
                submission_result = self.submission_provider.submit() => {
                    match submission_result {
                        Ok(submission) => {
                            let conn = self.conn.clone();
                            let handler = self.submission_response_handler.clone();
                            // Spawn a task to handle this specific submission.
                            tokio::spawn(async move {
                                if let Err(e) = handle_one_submission(conn, submission, handler).await {
                                    error!("Failed to process submission: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Submission provider failed critically: {}", e);
                            job_handle.abort(); // Clean up background task.
                            return Err(e); // Propagate critical errors.
                        }
                    }
                },
            }
        }
    }
}

/// Handle the network I/O for a single submission.
async fn handle_one_submission(
    conn: Connection,
    submission: Submission,
    handler: Arc<dyn SubmissionResponseHandler>
) -> Result<()> {
    let (mut send_submission, mut recv_submission) = conn.open_bi().await?;
    let submission_bytes = bincode::serialize(&submission)?;
    send_submission.write_u32(submission_bytes.len() as u32).await?;
    send_submission.write_all(&submission_bytes).await?;
    send_submission.finish()?;

    let len = recv_submission.read_u32().await?;
    let mut res_bytes = vec![0; len as usize];
    recv_submission.read_exact(&mut res_bytes).await?;
    let res: SubmissionResponse = bincode::deserialize(&res_bytes)?;
    handler.handle(res).await?;

    Ok(())
}


pub async fn run(
    insecure: bool,
    server_address: String,
    client_address: String,
    key: String,
    device_info: DeviceInfo,
    new_job_consumer: Arc<dyn NewJobConsumer>,
    submission_provider: Arc<dyn SubmissionProvider>,
    submission_response_handler: Arc<dyn SubmissionResponseHandler>,
) -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut endpoint = Endpoint::client(SocketAddr::from_str(&client_address)?)?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10))); // send pingz
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(Duration::from_secs(120)).expect("idle-timeout range")
    ));
    let transport = Arc::new(transport);

    // build client config then attach the transport
    let mut client_cfg = if !insecure {
        ClientConfig::with_platform_verifier()
    } else {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?))
    };
    client_cfg.transport_config(transport);

    endpoint.set_default_client_config(client_cfg);

    if !insecure {
        let config = ClientConfig::with_platform_verifier();
        endpoint.set_default_client_config(config);
    } else {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto)?,
        )));
    }

    let remote_address = tokio::net::lookup_host(server_address.as_str())
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses for {}", server_address))?;

    let host = server_address
        .rsplitn(2, ':')
        .last()
        .unwrap_or(&server_address)
        .trim_matches(|c| c == '[' || c == ']');

    info!("Connecting to nockpool at {}", server_address);

    let connection = endpoint
        .connect(remote_address, host)?
        .await?;

    info!("Connected to nockpool at {}", server_address);
    let mut client = QuiverClient::new(connection, key, device_info, new_job_consumer, submission_provider, submission_response_handler);
    client.serve().await
}

async fn receive_jobs(conn: quinn::Connection, new_job_consumer: Arc<dyn NewJobConsumer>) -> Result<()> {
    loop {
        let mut recv = match conn.accept_uni().await {
            Ok(s) => {
                tracing::info!("Job stream accepted.");
                s
            }
            Err(e) => {
                tracing::error!("accept_uni failed: {e:?}");
                return Err(e.into());
            }
        };

        // read frames from this stream until the server finishes 
        // or resets it then go back up and accept the next job stream.
        loop {
            let len = match recv.read_u32().await {
                Ok(len) => len,
                Err(e) => {
                    // distinguish eof vs reset vs connection-closed for diagnostics
                    use std::error::Error as _;
                    let mut src = (&e as &dyn std::error::Error).source();
                    while let Some(inner) = src {
                        if let Some(quinn::ReadError::Reset(code)) = inner.downcast_ref::<quinn::ReadError>() {
                            tracing::warn!("job stream reset by peer: {code:?}");
                            break;
                        }
                        src = inner.source();
                    }
                    tracing::info!("job stream ended or failed: {e:?} — waiting for next stream");
                    break; // break inner loop, accept a new uni stream
                }
            };

            let mut buf = vec![0; len as usize];
            recv.read_exact(&mut buf).await?;
            let template: Template = bincode::deserialize(&buf)?;
            new_job_consumer.process(template).await?;
        }
    }
}
