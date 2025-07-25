use async_trait::async_trait;
use anyhow::Result;

use crate::types::AccountInformation;

/// A marker trait for a connection guard.
///
/// The `Authenticator` returns a `Box<dyn ConnectionGuard>`. This guard is held
/// by the server's `SessionState` for the lifetime of the connection. This is an
/// implementation of the RAII (Resource Acquisition Is Initialization) pattern.
///
/// When the client disconnects and the `SessionState` is dropped, this guard is also
/// dropped. This allows the `Authenticator` implementation to trigger cleanup logic
/// (e.g., setting the api_key activity to false in supaabase) by implementing the `Drop`
/// trait on its guard object.
pub trait ConnectionGuard: Send + Sync {}

/// A trait for an authentication provider.
///
/// The `quiver` server uses this trait to delegate the responsibility of authenticating
/// clients. This keeps the server logic decoupled from the specific authentication method.
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Authenticates a client by validating their API key.
    ///
    /// On success, it returns the user's `AccountInformation` and a `ConnectionGuard`
    /// to manage the connection's lifecycle.
    async fn authenticate(&self, api_key: &str) -> Result<(AccountInformation, Box<dyn ConnectionGuard>)>;
} 