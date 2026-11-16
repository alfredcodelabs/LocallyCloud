//! REST endpoint configuration shared by management and deployed invocation checks.
use serde_json::Value;

use crate::error::ApiGwError;

#[derive(Clone, Copy, PartialEq, Eq)]
enum EndpointType {
    Edge,
    Regional,
    Private,
}

impl EndpointType {
    fn parse(value: &Value) -> Result<Self, ApiGwError> {
        match value.as_str() {
            Some("EDGE") => Ok(Self::Edge),
            Some("REGIONAL") => Ok(Self::Regional),
            Some("PRIVATE") => Ok(Self::Private),
            _ => Err(ApiGwError::BadRequest("Invalid endpoint type".into())),
        }
    }
}

pub(crate) fn is_private(configuration: &Value) -> Result<bool, ApiGwError> {
    if configuration.is_null() {
        return Ok(false);
    }
    let configuration = configuration
        .as_object()
        .ok_or_else(|| ApiGwError::BadRequest("endpointConfiguration must be an object".into()))?;
    let Some(types) = configuration.get("types") else {
        return Ok(false);
    };
    let types = types
        .as_array()
        .filter(|types| !types.is_empty() && types.len() <= 3)
        .ok_or_else(|| ApiGwError::BadRequest("Invalid endpointConfiguration.types".into()))?;
    let mut private = false;
    for kind in types {
        private |= EndpointType::parse(kind)? == EndpointType::Private;
    }
    if private && types.len() != 1 {
        return Err(ApiGwError::BadRequest(
            "PRIVATE must be the sole endpoint type".into(),
        ));
    }
    Ok(private)
}

pub(crate) fn validate_change(previous: &Value, next: &Value) -> Result<(), ApiGwError> {
    is_private(next)?;
    if is_private(previous)?
        && next
            .get("types")
            .and_then(Value::as_array)
            .is_none_or(|types| types.iter().any(|kind| kind.as_str() == Some("EDGE")))
    {
        return Err(ApiGwError::BadRequest(
            "Cannot change a private API to an edge-optimized API".into(),
        ));
    }
    Ok(())
}
