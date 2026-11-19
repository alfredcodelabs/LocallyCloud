//! Side-effect-free delivery preflight owned by the native S3 handler.
use crate::registry::ServiceName;
use async_trait::async_trait;

pub const S3_DELIVERY_AUTHORIZATION_VERSION: u16 = 1;

pub struct S3DeliveryAuthorizationRequest {
    pub account_id: String,
    pub region: String,
    pub source_service: ServiceName,
    pub source_arn: String,
    pub bucket: String,
    pub key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3DeliveryAuthorizationError {
    Denied,
    Unavailable,
}

#[async_trait]
pub trait S3DeliveryAuthorizationApi: Send + Sync {
    fn version(&self) -> u16 {
        S3_DELIVERY_AUTHORIZATION_VERSION
    }
    /// Reuse PutObject's authorization without creating a test object or changing bucket state.
    async fn authorize_delivery(
        &self,
        request: S3DeliveryAuthorizationRequest,
    ) -> Result<(), S3DeliveryAuthorizationError>;
}
