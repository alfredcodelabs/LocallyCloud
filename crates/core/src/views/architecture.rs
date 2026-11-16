//! Port for the architecture-review view.
//!
//! The server owns the HTTP endpoint and dashboard identity; core does not know how a topology is
//! built. The composition root injects an [`ArchitectureSource`], which reads deployed AWS
//! state only through the [`AwsReader`] it is handed. The reader signs as the selected
//! dashboard profile and admits read operations only, so strict IAM and the dashboard's
//! read-only guarantee apply to every call the source makes.

use async_trait::async_trait;

/// One AWS API read, addressed like a client request (signing is added by the reader).
pub struct AwsRead {
    /// SigV4 signing name, e.g. `cloudformation`, `lambda`, `states`.
    pub service: &'static str,
    pub method: http::Method,
    pub uri: http::Uri,
    pub headers: http::HeaderMap,
    pub body: bytes::Bytes,
}

/// A completed read: AWS status and body, or a reader refusal.
pub struct AwsReply {
    pub status: u16,
    pub body: bytes::Bytes,
}

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("only read operations are available to the architecture view")]
    NotRead,
    #[error("response exceeds {0} bytes")]
    TooLarge(usize),
}

#[async_trait]
pub trait AwsReader: Send + Sync {
    async fn read(&self, read: AwsRead) -> Result<AwsReply, ReadError>;
}

/// The account and region verified for the dashboard profile.
pub struct Scope {
    pub account: String,
    pub region: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TopologyError {
    /// The stack does not exist in this scope (404).
    #[error("{0}")]
    NotFound(String),
    /// The caller may not read something the topology needs (403).
    #[error("{0}")]
    AccessDenied(String),
    /// Bounded work was exceeded or AWS returned something unusable (422).
    #[error("{0}")]
    Unprocessable(String),
}

/// Builds the review model JSON for one stack. The output contains identities, statuses,
/// relationships and control facts only: never raw templates, policy documents, environment
/// values or code.
#[async_trait]
pub trait ArchitectureSource: Send + Sync {
    async fn topology(
        &self,
        reader: &dyn AwsReader,
        scope: &Scope,
        stack: &str,
    ) -> Result<serde_json::Value, TopologyError>;
}
