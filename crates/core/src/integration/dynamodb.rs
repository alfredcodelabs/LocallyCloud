//! Internal cursor metadata for durable Lambda stream starting positions.
use async_trait::async_trait;

pub const DYNAMODB_STREAMS_API_VERSION: u16 = 1;

#[async_trait]
pub trait DynamoDbStreamsApi: Send + Sync {
    fn version(&self) -> u16 {
        DYNAMODB_STREAMS_API_VERSION
    }

    /// Resolve the last sequence before an authorized shard iterator. An empty
    /// sequence denotes an empty frontier, so future reads use TRIM_HORIZON.
    /// Reading records and authorizing the stream still use the AWS dispatcher.
    async fn sequence_after_iterator(
        &self,
        account: &str,
        region: &str,
        iterator: &str,
    ) -> Result<String, String>;
}
