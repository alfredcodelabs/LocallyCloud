//! Step Functions errors: API errors (`SfnError` → JSON 1.0 `__type`) and in-band ASL
//! execution errors (`AslError`, the `States.*` catalog).

use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::registry::AwsProtocol;

/// An API-level error returned by control-plane / execution operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SfnError {
    #[error("Access denied")]
    AccessDenied,
    #[error("{0}")]
    StateMachineDoesNotExist(String),
    #[error("{0}")]
    StateMachineAlreadyExists(String),
    #[error("{0}")]
    StateMachineDeleting(String),
    #[error("{0}")]
    StateMachineLimitExceeded(String),
    #[error("{0}")]
    ExecutionDoesNotExist(String),
    #[error("{0}")]
    ExecutionAlreadyExists(String),
    #[error("{0}")]
    ExecutionLimitExceeded(String),
    #[error("{0}")]
    ExecutionNotRedrivable(String),
    #[error("{0}")]
    ActivityDoesNotExist(String),
    #[error("{0}")]
    ActivityLimitExceeded(String),
    #[error("{0}")]
    TaskDoesNotExist(String),
    #[error("{0}")]
    TaskTimedOut(String),
    #[error("{0}")]
    InvalidExecutionInput(String),
    #[error("{0}")]
    InvalidDefinition(String),
    #[error("{0}")]
    InvalidName(String),
    #[error("{0}")]
    InvalidArn(String),
    #[error("{0}")]
    StateMachineTypeNotSupported(String),
    #[error("{0}")]
    InvalidLoggingConfiguration(String),
    #[error("{0}")]
    InvalidTracingConfiguration(String),
    #[error("{0}")]
    InvalidEncryptionConfiguration(String),
    #[error("{0}")]
    ConflictException(String),
    #[error("{0}")]
    ResourceNotFound(String),
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    UnknownOperation(String),
}

impl SfnError {
    pub fn code(&self) -> &'static str {
        match self {
            SfnError::AccessDenied => "AccessDeniedException",
            SfnError::StateMachineDoesNotExist(_) => "StateMachineDoesNotExist",
            SfnError::StateMachineAlreadyExists(_) => "StateMachineAlreadyExists",
            SfnError::StateMachineDeleting(_) => "StateMachineDeleting",
            SfnError::StateMachineLimitExceeded(_) => "StateMachineLimitExceeded",
            SfnError::ExecutionDoesNotExist(_) => "ExecutionDoesNotExist",
            SfnError::ExecutionAlreadyExists(_) => "ExecutionAlreadyExists",
            SfnError::ExecutionLimitExceeded(_) => "ExecutionLimitExceeded",
            SfnError::ExecutionNotRedrivable(_) => "ExecutionNotRedrivable",
            SfnError::ActivityDoesNotExist(_) => "ActivityDoesNotExist",
            SfnError::ActivityLimitExceeded(_) => "ActivityLimitExceeded",
            SfnError::TaskDoesNotExist(_) => "TaskDoesNotExist",
            SfnError::TaskTimedOut(_) => "TaskTimedOut",
            SfnError::InvalidExecutionInput(_) => "InvalidExecutionInput",
            SfnError::InvalidDefinition(_) => "InvalidDefinition",
            SfnError::InvalidName(_) => "InvalidName",
            SfnError::InvalidArn(_) => "InvalidArn",
            SfnError::StateMachineTypeNotSupported(_) => "StateMachineTypeNotSupported",
            SfnError::InvalidLoggingConfiguration(_) => "InvalidLoggingConfiguration",
            SfnError::InvalidTracingConfiguration(_) => "InvalidTracingConfiguration",
            SfnError::InvalidEncryptionConfiguration(_) => "InvalidEncryptionConfiguration",
            SfnError::ConflictException(_) => "ConflictException",
            SfnError::ResourceNotFound(_) => "ResourceNotFound",
            SfnError::Validation(_) => "ValidationException",
            SfnError::UnknownOperation(_) => "UnknownOperationException",
        }
    }

    pub fn into_response(self, request_id: &str) -> axum::response::Response {
        AwsError::new(
            self.code(),
            self.to_string(),
            if matches!(self, Self::AccessDenied) {
                403
            } else {
                400
            },
        )
        .with_request_id(request_id.to_string())
        .render(AwsProtocol::Json10)
        .into_response()
    }
}

/// An in-band ASL execution error (`States.*`), carried in the execution result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AslError {
    pub error: String,
    pub cause: String,
    history_event_id: Option<u64>,
}

impl AslError {
    pub fn new(error: impl Into<String>, cause: impl Into<String>) -> Self {
        AslError {
            error: error.into(),
            cause: cause.into(),
            history_event_id: None,
        }
    }

    pub(crate) fn with_history_event(mut self, event_id: Option<u64>) -> Self {
        self.history_event_id = event_id;
        self
    }

    pub(crate) fn history_event_id(&self) -> Option<u64> {
        self.history_event_id
    }

    pub fn task_failed(cause: impl Into<String>) -> Self {
        AslError::new("States.TaskFailed", cause)
    }
    pub fn runtime(cause: impl Into<String>) -> Self {
        AslError::new("States.Runtime", cause)
    }

    /// Whether this error matches an `ErrorEquals` entry (`States.ALL` matches any
    /// `States.*` and non-`States.` errors; otherwise exact match).
    pub fn matches(&self, error_equals: &str) -> bool {
        if error_equals == "States.ALL" {
            return !matches!(
                self.error.as_str(),
                "States.DataLimitExceeded" | "States.Runtime"
            );
        }
        if error_equals == "States.TaskFailed" {
            return !matches!(
                self.error.as_str(),
                "States.Timeout" | "States.DataLimitExceeded" | "States.Runtime"
            );
        }
        self.error == error_equals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_renders_json10() {
        let r = SfnError::StateMachineDoesNotExist("x".into()).into_response("rid");
        assert_eq!(r.status(), 400);
        assert_eq!(
            r.headers().get("content-type").unwrap(),
            "application/x-amz-json-1.0"
        );
    }

    #[test]
    fn states_all_matches_everything() {
        let e = AslError::new("States.Timeout", "");
        assert!(e.matches("States.ALL"));
        assert!(e.matches("States.Timeout"));
        assert!(!e.matches("States.TaskFailed"));
    }

    #[test]
    fn task_failed_matches_custom_errors() {
        assert!(AslError::new("CustomError", "").matches("States.TaskFailed"));
        assert!(AslError::new("CustomError", "").matches("CustomError"));
    }
}
