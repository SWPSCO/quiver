use async_trait::async_trait;
use anyhow::Result;
use crate::types::Template;

/// A trait for a new job provider.
///
/// The `quiver` server uses this trait to delegate the responsibility of persisting
/// new jobs received from a client. This keeps the server logic decoupled
/// from the specific storage mechanism.
#[async_trait]
pub trait NewJobProvider: Send + Sync {
    /// On success, it returns the new job.
    async fn get(&self, current_template: Template) -> Result<Template>;
} 

/// A trait for a new job consumer.
///
/// The `quiver` server uses this trait to delegate the responsibility of processing
/// new jobs received from a client. This keeps the server logic decoupled
/// from the specific processing mechanism.
#[async_trait]
pub trait NewJobConsumer: Send + Sync + std::fmt::Debug {
    async fn process(&self, template: Template) -> Result<()>;
}