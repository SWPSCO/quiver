use tracing::{info, error};
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
        let truncated_api_key = self.api_key.as_ref().unwrap().chars().rev().take(8).collect::<String>();
        info!("{:?} put to work with key {:?}", self.account_information.as_ref().unwrap().user_uuid, truncated_api_key);

        // Ready for work.
        self.handle_work().await
    }
}

pub async fn run(
    address: String,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    authenticator: Arc<dyn Authenticator>,
    device_info_updater: Arc<dyn DeviceInfoUpdater>,
    new_job_provider: Arc<dyn NewJobProvider>,
    submission_consumer: Arc<dyn SubmissionConsumer>,
) -> Result<()> {
    info!("quiver listening...");

    let mut config = ServerConfig::with_single_cert(vec![cert], key)?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(2)));
    transport.max_idle_timeout(Some(Duration::from_secs(5).try_into()?));

    config.transport = Arc::new(transport);

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