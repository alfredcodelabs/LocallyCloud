//! IAM/STS errors mapped to the Query/XML error envelope via the Core error mapper.
//!
//! Every variant renders through [`AwsError`] as the Query error shape
//! (`<ErrorResponse><Error><Type>/<Code>/<Message></Error><RequestId></ErrorResponse>`)
//! with the AWS-faithful HTTP status, so strict SDK error deserialization succeeds.

use localcloud_core::error_mapping::AwsError;
use localcloud_core::registry::AwsProtocol;

/// An IAM or STS API error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IamStsError {
    #[error("{0}")]
    NoSuchEntity(String),
    #[error("{0}")]
    EntityAlreadyExists(String),
    #[error("{0}")]
    DeleteConflict(String),
    #[error("{0}")]
    LimitExceeded(String),
    #[error("{0}")]
    MalformedPolicyDocument(String),
    #[error("{0}")]
    ValidationError(String),
    #[error("{0}")]
    AccessDenied(String),
    #[error("{0}")]
    InvalidAction(String),
}

impl IamStsError {
    pub fn code(&self) -> &'static str {
        match self {
            IamStsError::NoSuchEntity(_) => "NoSuchEntity",
            IamStsError::EntityAlreadyExists(_) => "EntityAlreadyExists",
            IamStsError::DeleteConflict(_) => "DeleteConflict",
            IamStsError::LimitExceeded(_) => "LimitExceeded",
            IamStsError::MalformedPolicyDocument(_) => "MalformedPolicyDocument",
            IamStsError::ValidationError(_) => "ValidationError",
            IamStsError::AccessDenied(_) => "AccessDenied",
            IamStsError::InvalidAction(_) => "InvalidAction",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            IamStsError::NoSuchEntity(_) => 404,
            IamStsError::EntityAlreadyExists(_)
            | IamStsError::DeleteConflict(_)
            | IamStsError::LimitExceeded(_) => 409,
            IamStsError::MalformedPolicyDocument(_)
            | IamStsError::ValidationError(_)
            | IamStsError::InvalidAction(_) => 400,
            IamStsError::AccessDenied(_) => 403,
        }
    }

    /// Render to an Axum response as the Query/XML error envelope in the service's
    /// XML namespace (`IAM_XMLNS` for IAM, `STS_XMLNS` for STS).
    pub fn into_response(self, request_id: &str, xmlns: &'static str) -> axum::response::Response {
        AwsError::new(self.code(), self.to_string(), self.http_status())
            .with_request_id(request_id.to_string())
            .with_xml_namespace(xmlns)
            .render(AwsProtocol::Query)
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_match_aws() {
        assert_eq!(IamStsError::NoSuchEntity("x".into()).http_status(), 404);
        assert_eq!(
            IamStsError::EntityAlreadyExists("x".into()).http_status(),
            409
        );
        assert_eq!(IamStsError::DeleteConflict("x".into()).http_status(), 409);
        assert_eq!(IamStsError::LimitExceeded("x".into()).http_status(), 409);
        assert_eq!(
            IamStsError::MalformedPolicyDocument("x".into()).http_status(),
            400
        );
        assert_eq!(IamStsError::ValidationError("x".into()).http_status(), 400);
        assert_eq!(IamStsError::AccessDenied("x".into()).http_status(), 403);
        assert_eq!(IamStsError::InvalidAction("x".into()).http_status(), 400);
    }

    #[test]
    fn renders_query_xml_envelope() {
        let resp = IamStsError::NoSuchEntity("user nope not found".into())
            .into_response("req-1", crate::query::IAM_XMLNS);
        assert_eq!(resp.status(), 404);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/xml"
        );
    }
}
