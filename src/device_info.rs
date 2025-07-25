use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use anyhow::Result;

/// Holds the authentication details for a user.
/// This information is returned by the `Authenticator` on successful validation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceInfo {
    pub os: String,
    pub cpu_model: String,
    pub ram_capacity_gb: u64,
}

/// A trait for a device info provider.
///
/// The `quiver` server uses this trait to delegate the responsibility of persisting
/// device information received from a client. This keeps the server logic decoupled
/// from the specific storage mechanism.
#[async_trait]
pub trait DeviceInfoUpdater: Send + Sync {
    /// Persists the device information for a given API key.
    ///
    /// On success, it returns the user's `AuthDetails` and a `ConnectionGuard`
    /// to manage the connection's lifecycle. 
    async fn update_device_info(&self, device_info: &DeviceInfo, api_key: &str) -> Result<()>;
} 