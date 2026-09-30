//! CloudFormation error model, rendered as a Query-protocol XML error.

use localcloud_core::error_mapping::AwsError;
use localcloud_core::registry::AwsProtocol;

pub const CFN_XMLNS: &str = "http://cloudformation.amazonaws.com/doc/2010-05-15/";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CfnError {
    /// Client validation failure (missing/invalid parameters, stack-does-not-exist, …).
    #[error("{0}")]
    Validation(String),
    /// A stack with the same name already exists.
    #[error("{0}")]
    AlreadyExists(String),
    /// A resource failed to provision during a stack operation.
    #[error("{0}")]
    ResourceFailed(String),
    /// The caller did not acknowledge IAM resources in the template.
    #[error("{0}")]
    InsufficientCapabilities(String),
    /// An unsupported operation was requested.
    #[error("{0}")]
    Unsupported(String),
    #[error("Internal error.")]
    Internal,
}

impl CfnError {
    pub fn code(&self) -> &'static str {
        match self {
            CfnError::Validation(_) => "ValidationError",
            CfnError::AlreadyExists(_) => "AlreadyExistsException",
            CfnError::ResourceFailed(_) => "ResourceFailed",
            CfnError::InsufficientCapabilities(_) => "InsufficientCapabilities",
            CfnError::Unsupported(_) => "UnsupportedOperation",
            CfnError::Internal => "InternalFailure",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            CfnError::AlreadyExists(_) => 400,
            CfnError::Validation(_) => 400,
            CfnError::Unsupported(_) => 400,
            CfnError::ResourceFailed(_) => 400,
            CfnError::InsufficientCapabilities(_) => 400,
            CfnError::Internal => 500,
        }
    }

    fn sender_fault(&self) -> bool {
        !matches!(self, CfnError::Internal)
    }

    pub fn into_response(self, request_id: &str) -> axum::response::Response {
        let mut err = AwsError::new(self.code(), self.to_string(), self.http_status())
            .with_request_id(request_id.to_string())
            .with_xml_namespace(CFN_XMLNS);
        err.sender_fault = self.sender_fault();
        err.render(AwsProtocol::Query).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_exist_is_400_validation() {
        let e = CfnError::Validation("Stack with id s does not exist".into());
        assert_eq!(e.code(), "ValidationError");
        assert_eq!(e.http_status(), 400);
    }
}
