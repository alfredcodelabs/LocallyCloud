//! S3 error model rendered as the S3 REST-XML error document.
//!
//! S3 errors are a bare `<Error>` root document (not the Query `<ErrorResponse>` wrapper),
//! so they are rendered here rather than through the generic Core mapper. `304 Not Modified`
//! is status-only with no body.

use axum::body::Body;
use axum::response::Response;

use crate::xml::escape;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum S3Error {
    #[error("The specified bucket does not exist")]
    NoSuchBucket,
    #[error("The bucket policy does not exist")]
    NoSuchBucketPolicy,
    #[error("The CORS configuration does not exist")]
    NoSuchCORSConfiguration,
    #[error("The public access block configuration was not found")]
    NoSuchPublicAccessBlockConfiguration,
    #[error("The TagSet does not exist")]
    NoSuchTagSet,
    #[error("The lifecycle configuration does not exist")]
    NoSuchLifecycleConfiguration,
    #[error("The replication configuration was not found")]
    ReplicationConfigurationNotFoundError,
    #[error("Object Lock configuration does not exist for this bucket")]
    ObjectLockConfigurationNotFoundError,
    #[error("The specified bucket does not have a website configuration")]
    NoSuchWebsiteConfiguration,
    #[error("The bucket ownership controls were not found")]
    OwnershipControlsNotFoundError,
    #[error("The specified key does not exist.")]
    NoSuchKey,
    #[error("The specified key does not exist.")]
    NoSuchKeyDeleteMarker,
    #[error("The specified method is not allowed against this resource.")]
    DeleteMarkerVersion(String),
    #[error("The specified multipart upload does not exist.")]
    NoSuchUpload,
    #[error("Your previous request to create the named bucket succeeded and you already own it.")]
    BucketAlreadyOwnedByYou,
    #[error("The requested bucket name is not available.")]
    BucketAlreadyExists,
    #[error("The bucket you tried to delete is not empty")]
    BucketNotEmpty,
    #[error("The specified bucket is not valid.")]
    InvalidBucketName,
    #[error("At least one of the pre-conditions you specified did not hold")]
    PreconditionFailed,
    #[error("Not Modified")]
    NotModified,
    #[error("The requested range is not satisfiable")]
    InvalidRange,
    #[error("The Content-MD5 you specified did not match what we received.")]
    BadDigest,
    #[error("The Content-MD5 you specified is not valid.")]
    InvalidDigest,
    #[error("Your proposed upload exceeds the maximum allowed object size.")]
    EntityTooLarge,
    #[error("Your proposed upload is smaller than the minimum allowed object size.")]
    EntityTooSmall,
    #[error("One or more of the specified parts could not be found.")]
    InvalidPart,
    #[error("The list of parts was not in ascending order.")]
    InvalidPartOrder,
    #[error("The specified method is not allowed against this resource.")]
    MethodNotAllowed,
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    InvalidRequest(String),
    #[error("{0}")]
    InvalidRequestParameter(String),
    #[error("{0}")]
    InvalidExpression(String),
    #[error("{0}")]
    UnsupportedSqlOperation(String),
    #[error("{0}")]
    CsvParsingError(String),
    #[error("{0}")]
    JsonParsingError(String),
    #[error("The XML you provided was not well-formed or did not validate against our schema.")]
    MalformedXML,
    #[error("The authorization query parameters are invalid")]
    AuthorizationQueryParametersError,
    #[error("The TagSet does not meet the requirements")]
    InvalidTag,
    #[error("CORS Response: This CORS request is not allowed")]
    AccessForbidden,
    #[error("Access Denied")]
    AccessDenied,
    #[error("Legacy SSE-KMS data requires offline migrate-s3-encryption before authorized reads")]
    LegacyKmsMigrationRequired,
    #[error("The specified KMS key is not enabled")]
    KmsDisabled,
    #[error("The state of the specified KMS key is not valid for this request")]
    KmsInvalidState,
    #[error("{0}")]
    NotImplemented(String),
    #[error("We encountered an internal error. Please try again.")]
    InternalError,
}

impl S3Error {
    pub fn code(&self) -> &'static str {
        match self {
            S3Error::NoSuchBucket => "NoSuchBucket",
            S3Error::NoSuchBucketPolicy => "NoSuchBucketPolicy",
            S3Error::NoSuchCORSConfiguration => "NoSuchCORSConfiguration",
            S3Error::NoSuchPublicAccessBlockConfiguration => "NoSuchPublicAccessBlockConfiguration",
            S3Error::NoSuchTagSet => "NoSuchTagSet",
            S3Error::NoSuchLifecycleConfiguration => "NoSuchLifecycleConfiguration",
            S3Error::ReplicationConfigurationNotFoundError => {
                "ReplicationConfigurationNotFoundError"
            }
            S3Error::ObjectLockConfigurationNotFoundError => "ObjectLockConfigurationNotFoundError",
            S3Error::NoSuchWebsiteConfiguration => "NoSuchWebsiteConfiguration",
            S3Error::OwnershipControlsNotFoundError => "OwnershipControlsNotFoundError",
            S3Error::NoSuchKey | S3Error::NoSuchKeyDeleteMarker => "NoSuchKey",
            S3Error::DeleteMarkerVersion(_) => "MethodNotAllowed",
            S3Error::NoSuchUpload => "NoSuchUpload",
            S3Error::BucketAlreadyOwnedByYou => "BucketAlreadyOwnedByYou",
            S3Error::BucketAlreadyExists => "BucketAlreadyExists",
            S3Error::BucketNotEmpty => "BucketNotEmpty",
            S3Error::InvalidBucketName => "InvalidBucketName",
            S3Error::PreconditionFailed => "PreconditionFailed",
            S3Error::NotModified => "NotModified",
            S3Error::InvalidRange => "InvalidRange",
            S3Error::BadDigest => "BadDigest",
            S3Error::InvalidDigest => "InvalidDigest",
            S3Error::EntityTooLarge => "EntityTooLarge",
            S3Error::EntityTooSmall => "EntityTooSmall",
            S3Error::InvalidPart => "InvalidPart",
            S3Error::InvalidPartOrder => "InvalidPartOrder",
            S3Error::MethodNotAllowed => "MethodNotAllowed",
            S3Error::InvalidArgument(_) => "InvalidArgument",
            S3Error::InvalidRequest(_) => "InvalidRequest",
            S3Error::InvalidRequestParameter(_) => "InvalidRequestParameter",
            S3Error::InvalidExpression(_) => "InvalidExpression",
            S3Error::UnsupportedSqlOperation(_) => "UnsupportedSqlOperation",
            S3Error::CsvParsingError(_) => "CSVParsingError",
            S3Error::JsonParsingError(_) => "JSONParsingError",
            S3Error::MalformedXML => "MalformedXML",
            S3Error::AuthorizationQueryParametersError => "AuthorizationQueryParametersError",
            S3Error::InvalidTag => "InvalidTag",
            S3Error::AccessForbidden => "AccessForbidden",
            S3Error::AccessDenied | S3Error::LegacyKmsMigrationRequired => "AccessDenied",
            S3Error::KmsDisabled => "KMS.DisabledException",
            S3Error::KmsInvalidState => "KMS.KMSInvalidStateException",
            S3Error::NotImplemented(_) => "NotImplemented",
            S3Error::InternalError => "InternalError",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            S3Error::NoSuchBucket
            | S3Error::NoSuchKey
            | S3Error::NoSuchKeyDeleteMarker
            | S3Error::NoSuchUpload
            | S3Error::NoSuchPublicAccessBlockConfiguration => 404,
            S3Error::NoSuchBucketPolicy
            | S3Error::NoSuchCORSConfiguration
            | S3Error::NoSuchTagSet
            | S3Error::NoSuchLifecycleConfiguration
            | S3Error::ReplicationConfigurationNotFoundError
            | S3Error::ObjectLockConfigurationNotFoundError
            | S3Error::NoSuchWebsiteConfiguration
            | S3Error::OwnershipControlsNotFoundError => 404,
            S3Error::BucketAlreadyOwnedByYou
            | S3Error::BucketAlreadyExists
            | S3Error::BucketNotEmpty => 409,
            S3Error::InvalidBucketName
            | S3Error::BadDigest
            | S3Error::InvalidDigest
            | S3Error::EntityTooLarge
            | S3Error::EntityTooSmall
            | S3Error::InvalidPart
            | S3Error::InvalidPartOrder
            | S3Error::InvalidArgument(_)
            | S3Error::InvalidRequest(_)
            | S3Error::InvalidRequestParameter(_)
            | S3Error::InvalidExpression(_)
            | S3Error::UnsupportedSqlOperation(_)
            | S3Error::CsvParsingError(_)
            | S3Error::JsonParsingError(_)
            | S3Error::MalformedXML
            | S3Error::AuthorizationQueryParametersError
            | S3Error::InvalidTag => 400,
            S3Error::KmsDisabled | S3Error::KmsInvalidState => 400,
            S3Error::PreconditionFailed => 412,
            S3Error::NotModified => 304,
            S3Error::InvalidRange => 416,
            S3Error::MethodNotAllowed | S3Error::DeleteMarkerVersion(_) => 405,
            S3Error::AccessForbidden
            | S3Error::AccessDenied
            | S3Error::LegacyKmsMigrationRequired => 403,
            S3Error::NotImplemented(_) => 501,
            S3Error::InternalError => 500,
        }
    }

    /// Render to an Axum response as the S3 XML error document. `resource` is the request
    /// path (`/bucket/key`). `304` is returned status-only. The `HostId` element mirrors the
    /// `x-amz-id-2` header, as real S3 does.
    pub fn into_response(self, resource: &str, request_id: &str) -> Response {
        let status = self.http_status();
        let host_id = format!("lc2/{request_id}");
        if status == 304 {
            return Response::builder()
                .status(304)
                .header("x-amz-request-id", request_id)
                .header("x-amz-id-2", &host_id)
                .body(Body::empty())
                .expect("304 response is always valid");
        }
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource><RequestId>{}</RequestId><HostId>{}</HostId></Error>",
            self.code(),
            escape(&self.to_string()),
            escape(resource),
            escape(request_id),
            escape(&host_id),
        );
        let mut response = Response::builder()
            .status(status)
            .header("content-type", "application/xml")
            .header("x-amz-request-id", request_id)
            .header("x-amz-id-2", &host_id);
        if matches!(
            self,
            S3Error::NoSuchKeyDeleteMarker | S3Error::DeleteMarkerVersion(_)
        ) {
            response = response.header("x-amz-delete-marker", "true");
        }
        if let S3Error::DeleteMarkerVersion(version_id) = &self {
            response = response.header("x-amz-version-id", version_id);
        }
        response
            .body(Body::from(body))
            .expect("s3 error document is always valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses() {
        assert_eq!(S3Error::NoSuchBucket.http_status(), 404);
        assert_eq!(S3Error::BucketNotEmpty.http_status(), 409);
        assert_eq!(S3Error::PreconditionFailed.http_status(), 412);
        assert_eq!(S3Error::InvalidRange.http_status(), 416);
    }

    #[test]
    fn renders_xml_document() {
        let resp = S3Error::NoSuchKey.into_response("/b/k", "rid");
        assert_eq!(resp.status(), 404);
        assert_eq!(resp.headers().get("x-amz-request-id").unwrap(), "rid");
        assert_eq!(resp.headers().get("x-amz-id-2").unwrap(), "lc2/rid");
    }

    #[test]
    fn not_modified_has_no_body() {
        let resp = S3Error::NotModified.into_response("/b/k", "rid");
        assert_eq!(resp.status(), 304);
    }
}
