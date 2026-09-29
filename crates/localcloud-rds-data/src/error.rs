use localcloud_core::error_mapping::AwsError;
use localcloud_core::registry::AwsProtocol;

#[derive(Debug)]
pub(crate) enum RdsDataError {
    BadRequest(&'static str),
    Database(&'static str),
    TransactionNotFound,
    Unsupported(&'static str),
    Internal,
    Unavailable,
}

impl RdsDataError {
    pub(crate) fn into_response(self, request_id: String) -> axum::response::Response {
        let (code, message, status) = match self {
            Self::BadRequest(message) => ("BadRequestException", message, 400),
            Self::Database(message) => ("DatabaseErrorException", message, 400),
            Self::TransactionNotFound => (
                "TransactionNotFoundException",
                "transaction was not found",
                404,
            ),
            Self::Unsupported(message) => ("UnsupportedResultException", message, 400),
            Self::Internal => (
                "InternalServerErrorException",
                "an internal error occurred",
                500,
            ),
            Self::Unavailable => (
                "ServiceUnavailableError",
                "the service is temporarily unavailable",
                503,
            ),
        };
        AwsError::new(code, message, status)
            .with_request_id(request_id)
            .render(AwsProtocol::RestJson)
            .into_response()
    }
}
