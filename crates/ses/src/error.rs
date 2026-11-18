use axum::response::Response;
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::registry::AwsProtocol;

#[derive(Debug)]
pub(crate) enum Error {
    BadRequest(&'static str),
    Rejected(&'static str),
    Missing,
    Exists,
    AccessDenied,
    Capacity,
    Storage,
    Unsupported,
}
impl Error {
    pub fn response(self, request_id: &str, wire: crate::protocol::WireProtocol) -> Response {
        use crate::protocol::WireProtocol::{Query, RestJson};
        let (code, message, status) = match (self, wire) {
            (Self::BadRequest(message), Query) => ("InvalidParameterValue", message, 400),
            (Self::BadRequest(message), RestJson) => ("BadRequestException", message, 400),
            (Self::Rejected(message), _) => ("MessageRejected", message, 400),
            (Self::Missing, Query) => (
                "InvalidParameterValue",
                "The specified resource does not exist",
                400,
            ),
            (Self::Missing, RestJson) => (
                "NotFoundException",
                "The specified resource does not exist",
                404,
            ),
            (Self::Exists, _) => (
                "AlreadyExistsException",
                "The specified resource already exists",
                400,
            ),
            (Self::AccessDenied, Query) => (
                "AccessDenied",
                "Not authorized to perform this SES operation",
                403,
            ),
            (Self::AccessDenied, RestJson) => (
                "AccessDeniedException",
                "Not authorized to perform this SES operation",
                403,
            ),
            (Self::Capacity, Query) => (
                "Throttling",
                "The local SES pending delivery budget is exhausted",
                400,
            ),
            (Self::Capacity, RestJson) => (
                "TooManyRequestsException",
                "The local SES pending delivery budget is exhausted",
                429,
            ),
            (Self::Storage, _) => (
                "InternalFailure",
                "SES state could not be committed or loaded",
                500,
            ),
            (Self::Unsupported, Query) => (
                "InvalidAction",
                "This SES operation is not implemented",
                400,
            ),
            (Self::Unsupported, RestJson) => (
                "NotFoundException",
                "This SES operation is not implemented",
                404,
            ),
        };
        let error = AwsError::new(code, message, status).with_request_id(request_id);
        if wire == Query {
            error
                .with_xml_namespace("http://ses.amazonaws.com/doc/2010-12-01/")
                .render(AwsProtocol::Query)
                .into_response()
        } else {
            error.render(AwsProtocol::RestJson).into_response()
        }
    }
}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
