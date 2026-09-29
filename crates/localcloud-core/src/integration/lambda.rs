//! Typed, protocol-neutral Lambda invocation for native service integrations.

use std::fmt;

use async_trait::async_trait;

/// Contract version understood by the registry and internal callers.
pub const LAMBDA_INTERNAL_API_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LambdaCallContext {
    pub source_service: String,
    pub account_id: String,
    pub region: String,
    pub request_id: String,
    pub caller_arn: Option<String>,
}

pub struct SensitivePayload(Vec<u8>);

impl SensitivePayload {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for SensitivePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitivePayload")
            .field("length", &self.0.len())
            .field("value", &"[redacted]")
            .finish()
    }
}

impl Drop for SensitivePayload {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub struct LambdaInvokeRequest {
    pub call: LambdaCallContext,
    pub function_name: String,
    pub qualifier: Option<String>,
    pub payload: SensitivePayload,
}

impl fmt::Debug for LambdaInvokeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LambdaInvokeRequest")
            .field("call", &self.call)
            .field("function_name", &self.function_name)
            .field("qualifier", &self.qualifier)
            .field("payload", &self.payload)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LambdaFunctionError {
    Handled,
    Unhandled,
}

pub struct LambdaInvokeOutput {
    pub payload: SensitivePayload,
    pub function_error: Option<LambdaFunctionError>,
    pub executed_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LambdaInternalError {
    #[error("Lambda internal capability is unavailable")]
    Unavailable,
    #[error("Lambda internal invocation is invalid")]
    InvalidRequest,
    #[error("Lambda function was not found")]
    NotFound,
    #[error("Lambda function is not invokable")]
    InvalidState,
    #[error("Lambda internal invocation was throttled")]
    Throttled,
    #[error("Lambda internal invocation failed")]
    Internal,
}

#[async_trait]
pub trait LambdaInternalApi: Send + Sync {
    fn version(&self) -> u16 {
        LAMBDA_INTERNAL_API_VERSION
    }

    async fn invoke(
        &self,
        request: LambdaInvokeRequest,
    ) -> Result<LambdaInvokeOutput, LambdaInternalError>;
}
