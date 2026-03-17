use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::types::AccountInformation;

/// Stream discriminator used on client-opened bi-directional streams.
///
/// Legacy clients do not send a discriminator byte and begin their submission
/// stream with a 4-byte length prefix. The server uses this value to identify
/// telemetry streams while preserving backward compatibility with legacy
/// submission framing.
pub const TELEMETRY_STREAM_MARKER: u8 = 0xF1;

/// Upper bound for a serialized telemetry message.
///
/// Telemetry payloads are intentionally small (device metadata + current rate).
/// A hard cap prevents accidental memory blowups if malformed data arrives.
pub const TELEMETRY_FRAME_MAX_BYTES: u32 = 64 * 1024;

/// Telemetry snapshot sent by miners over the dedicated quiver telemetry stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryData {
    pub device_os: String,
    pub device_cpu: String,
    pub device_ram_capacity_gb: u64,
    pub device_proof_rate_per_sec: f64,
    pub zkvm_jetpack_hash: Option<String>,
    pub miner_version: String,
    pub gpu_info: Option<String>,
    pub num_threads: Option<u32>,
    /// Miner-side wall clock used by downstream writers for ordering safeguards.
    pub sent_at_unix_ms: i64,
}

/// Pull-based telemetry producer for the quiver client.
///
/// Implementations are expected to block until the next telemetry sample should
/// be sent. This keeps scheduling policy (intervals, startup delay, etc.) in the
/// application layer and keeps the quiver crate transport-only.
#[async_trait]
pub trait TelemetryProvider: Send + Sync + std::fmt::Debug {
    async fn next_telemetry(&self) -> Result<TelemetryData>;
}

/// Telemetry sink hook for the quiver server.
///
/// The protocol crate does not know or care where telemetry is persisted.
/// Implementers can route events to NATS, Kafka, direct DB updates, etc.
#[async_trait]
pub trait TelemetryConsumer: Send + Sync {
    async fn process_telemetry(
        &self,
        telemetry: TelemetryData,
        account_information: AccountInformation,
        api_key: &str,
    ) -> Result<()>;
}
