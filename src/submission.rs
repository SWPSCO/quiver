use async_trait::async_trait;
use anyhow::Result;
use crate::types::{Submission, SubmissionResponse, AccountInformation};

/// A trait for a submission provider.
#[async_trait]
pub trait SubmissionProvider: Send + Sync + std::fmt::Debug {
    /// On success, it returns the submission.
    async fn submit(&self) -> Result<Submission>;
} 

#[async_trait]
pub trait SubmissionConsumer: Send + Sync {
    async fn process(
        &self,
        submission: Submission,
        account_information: AccountInformation,
    ) -> Result<SubmissionResponse>;
}

#[async_trait]
pub trait SubmissionResponseHandler: Send + Sync + std::fmt::Debug {
    async fn handle(&self, response: SubmissionResponse) -> Result<()>;
}