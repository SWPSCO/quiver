use std::net::SocketAddr;
use std::sync::Arc;
use std::str::FromStr;

use anyhow::Result;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;

use crate::device_info::DeviceInfo;
use crate::types::{Template, Submission, SubmissionResponse};
use crate::new_job::NewJobConsumer;
use crate::submission::{SubmissionProvider, SubmissionResponseHandler};
use crate::insecure::SkipServerVerification;


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

    async fn serve(&mut self) -> Result<()> {
        // --- Authentication Transaction ---
        info!("authenticating...");
        let (mut send_auth, mut recv_auth) = self.conn.open_bi().await?;
        send_auth.write_all(self.key.as_bytes()).await?;
        send_auth.finish()?;
        let auth_res = String::from_utf8(recv_auth.read_to_end(50).await?)?;
        if auth_res != "authenticated" {
            return Err(anyhow::anyhow!("Authentication failed: {}", auth_res));
        }

        // --- Device Info Transaction ---
        info!("sending device info...");
        let (mut send_device, mut recv_device) = self.conn.open_bi().await?;
        send_device.write_all(&bincode::serialize(&self.device_info)?).await?;
        send_device.finish()?;
        let device_res = String::from_utf8(recv_device.read_to_end(50).await?)?;
        if device_res != "accepted" {
            return Err(anyhow::anyhow!("Device info rejected: {}", device_res));
        }

        // --- Job Stream ---
        let conn = self.conn.clone();
        let new_job_consumer = self.new_job_consumer.clone();
        tokio::spawn(async move {
            if let Err(e) = receive_jobs(conn, new_job_consumer.clone()).await {
                tracing::error!("Failed to receive jobs: {}", e);
            }
        });

        // --- Submission Stream ---
        loop {
            let submission: Submission = self.submission_provider.submit().await?;
            let conn = self.conn.clone();
            let submission_response_handler = self.submission_response_handler.clone();
            tokio::spawn(async move {
                let (mut send_submission, mut recv_submission) = conn.open_bi().await.expect("failed to open submission stream");
                let submission_bytes = bincode::serialize(&submission).expect("failed to serialize submission");
                send_submission.write_u32(submission_bytes.len() as u32).await.expect("failed to write submission length");
                send_submission.write_all(&submission_bytes).await.expect("failed to write submission");
                send_submission.finish().expect("failed to finish submission");

                let len = match recv_submission.read_u32().await {
                    Ok(len) => len,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        info!("Submission stream closed.");
                        return;
                    }
                    Err(e) => {
                        tracing::error!("Failed to read submission response length: {:?}", e);
                        return;
                    }
                };

                let mut res_bytes = vec![0; len as usize];
                recv_submission.read_exact(&mut res_bytes).await.expect("failed to read submission response");
                let res: SubmissionResponse = bincode::deserialize(&res_bytes).expect("failed to deserialize submission response");
                if let Err(e) = submission_response_handler.handle(res).await {
                    tracing::error!("Failed to handle submission response: {:?}", e);
                }
            });
        }
    }
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

    info!("Connecting to nockpool at {}", server_address);
    let connection = endpoint
        .connect(SocketAddr::from_str(&server_address)?, "nockpool")?
        .await?;
    info!("Connected to nockpool at {}", server_address);
    let mut client = QuiverClient::new(connection, key, device_info, new_job_consumer, submission_provider, submission_response_handler);
    client.serve().await
}

async fn receive_jobs(conn: Connection, new_job_consumer: Arc<dyn NewJobConsumer>) -> Result<()> {
    let mut recv = conn.accept_uni().await?;
    info!("Job stream accepted.");
    loop {
        let len = match recv.read_u32().await {
            Ok(len) => len,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!("Job stream closed.");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        let mut buf = vec![0; len as usize];
        recv.read_exact(&mut buf).await?;
        let template: Template = bincode::deserialize(&buf)?;
        new_job_consumer.process(template).await?;
    }
}