use serde_json::Value;
use std::collections::BTreeMap;

use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::authorization::{
    AuthorizationRequest, ServiceRoleAuthorizationRequest,
};
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};

use crate::error::SfnError;

fn required<'a>(body: &'a Value, field: &str) -> Result<&'a str, SfnError> {
    body.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SfnError::Validation(format!("{field} is required")))
}

// Resource types follow the AWS Step Functions service authorization reference.
fn resource(op: &str, body: &Value, request: &ServiceRequest) -> Result<Option<String>, SfnError> {
    let value = match op {
        "CreateStateMachine" => format!(
            "arn:aws:states:{}:{}:stateMachine:{}",
            request.region,
            request.account_id,
            required(body, "name")?
        ),
        "CreateActivity" => format!(
            "arn:aws:states:{}:{}:activity:{}",
            request.region,
            request.account_id,
            required(body, "name")?
        ),
        "CreateStateMachineAlias" => {
            let version = body
                .get("routingConfiguration")
                .and_then(Value::as_array)
                .and_then(|routes| routes.first())
                .and_then(|route| route.get("stateMachineVersionArn"))
                .and_then(Value::as_str)
                .ok_or_else(|| SfnError::Validation("routingConfiguration is required".into()))?;
            let prefix = format!(
                "arn:aws:states:{}:{}:stateMachine:",
                request.region, request.account_id
            );
            let name = version
                .strip_prefix(&prefix)
                .and_then(|name| name.rsplit_once(':'))
                .map(|(name, _)| name)
                .filter(|name| !name.is_empty() && !name.contains(':'))
                .ok_or_else(|| SfnError::InvalidArn(version.into()))?;
            format!("{prefix}{name}:{}", required(body, "name")?)
        }
        "DescribeStateMachineAlias" | "UpdateStateMachineAlias" | "DeleteStateMachineAlias" => {
            required(body, "stateMachineAliasArn")?.into()
        }
        "DescribeStateMachine"
        | "UpdateStateMachine"
        | "DeleteStateMachine"
        | "PublishStateMachineVersion"
        | "ListStateMachineVersions"
        | "ListStateMachineAliases"
        | "StartExecution"
        | "StartSyncExecution"
        | "ListExecutions" => required(body, "stateMachineArn")?.into(),
        "DescribeExecution"
        | "DescribeStateMachineForExecution"
        | "StopExecution"
        | "GetExecutionHistory"
        | "RedriveExecution" => required(body, "executionArn")?.into(),
        "DescribeActivity" | "DeleteActivity" | "GetActivityTask" => {
            required(body, "activityArn")?.into()
        }
        "TagResource" | "UntagResource" | "ListTagsForResource" => {
            required(body, "resourceArn")?.into()
        }
        "ListStateMachines"
        | "ListActivities"
        | "SendTaskSuccess"
        | "SendTaskFailure"
        | "SendTaskHeartbeat"
        | "ValidateStateMachineDefinition"
        | "TestState" => "*".into(),
        _ => return Ok(None),
    };
    Ok(Some(value))
}

// AWS evaluates qualified state-machine operations against the base ARN. The
// qualifier is exposed separately to conditions such as states:StateMachineQualifier.
fn policy_resource(
    op: &str,
    resource: String,
    request: &ServiceRequest,
) -> (String, BTreeMap<String, Vec<String>>) {
    let mut context = BTreeMap::new();
    if matches!(
        op,
        "CreateStateMachineAlias"
            | "DescribeStateMachineAlias"
            | "UpdateStateMachineAlias"
            | "DeleteStateMachineAlias"
            | "DescribeStateMachine"
            | "ListExecutions"
            | "StartExecution"
            | "StartSyncExecution"
    ) {
        let prefix = format!(
            "arn:aws:states:{}:{}:stateMachine:",
            request.region, request.account_id
        );
        if let Some(suffix) = resource.strip_prefix(&prefix) {
            if let Some((name, qualifier)) = suffix.split_once(':') {
                if !name.is_empty() && !qualifier.is_empty() && !qualifier.contains(':') {
                    context.insert(
                        "states:StateMachineQualifier".into(),
                        vec![qualifier.into()],
                    );
                    return (format!("{prefix}{name}"), context);
                }
            }
        }
    }
    (resource, context)
}

pub fn authorize(
    registry: &ServiceRegistry,
    request: &ServiceRequest,
    op: &str,
    body: &Value,
) -> Result<(), SfnError> {
    let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
        return Ok(());
    };
    if !evaluator.strict_sigv4_required() {
        return Ok(());
    }
    let Some(resource) = resource(op, body, request)? else {
        return Ok(());
    };
    let (resource, context) = policy_resource(op, resource, request);
    // Core removes client-supplied marker headers and sets exactly one after verification.
    if request
        .headers
        .get("x-locallycloud-verified-internal-scope")
        .is_some_and(|v| v == "1")
    {
        return Ok(());
    }
    if !request
        .headers
        .get("x-locallycloud-verified-external-sigv4")
        .is_some_and(|v| v == "1")
    {
        return Err(SfnError::AccessDenied);
    }
    let access_key_id = request
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(RequestIdentity::access_key_from_authorization)
        .ok_or(SfnError::AccessDenied)?;
    evaluator
        .authorize(AuthorizationRequest {
            request_identity: RequestIdentity {
                account_id: request.account_id.clone(),
                access_key_id: Some(access_key_id),
                arn: None,
            },
            delegated_identity: None,
            source_service: "states".into(),
            action: format!("states:{op}"),
            resource,
            context,
        })
        .map_err(|_| SfnError::AccessDenied)
}

pub fn authorize_role_assignment(
    registry: &ServiceRegistry,
    request: &ServiceRequest,
    op: &str,
    body: &Value,
) -> Result<(), SfnError> {
    if !matches!(op, "CreateStateMachine" | "UpdateStateMachine") {
        return Ok(());
    }
    let Some(role_arn) = body.get("roleArn").and_then(Value::as_str) else {
        return Ok(());
    };
    let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
        return Ok(());
    };
    if !evaluator.strict_sigv4_required() {
        return Ok(());
    }
    if !request
        .headers
        .get("x-locallycloud-verified-external-sigv4")
        .is_some_and(|value| value == "1")
    {
        return Err(SfnError::AccessDenied);
    }
    let access_key_id = request
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(RequestIdentity::access_key_from_authorization)
        .ok_or(SfnError::AccessDenied)?;
    evaluator
        .authorize_service_role_assignment(ServiceRoleAuthorizationRequest {
            source_arn: resource(op, body, request)?,
            caller: RequestIdentity {
                account_id: request.account_id.clone(),
                access_key_id: Some(access_key_id),
                arn: None,
            },
            role_arn: role_arn.into(),
            service_principal: "states.amazonaws.com".into(),
            action: "iam:PassRole".into(),
            resource: role_arn.into(),
        })
        .map_err(|_| SfnError::AccessDenied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, Method};
    use serde_json::json;

    fn request() -> ServiceRequest {
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "test".into(),
        }
    }

    #[test]
    fn operation_resources_match_aws_types() {
        let req = request();
        assert_eq!(resource("StartExecution", &json!({"stateMachineArn":"arn:aws:states:us-east-1:000000000000:stateMachine:job"}), &req).unwrap().as_deref(), Some("arn:aws:states:us-east-1:000000000000:stateMachine:job"));
        assert_eq!(
            resource(
                "GetExecutionHistory",
                &json!({"executionArn":"arn:aws:states:us-east-1:000000000000:execution:job:e"}),
                &req
            )
            .unwrap()
            .as_deref(),
            Some("arn:aws:states:us-east-1:000000000000:execution:job:e")
        );
        assert_eq!(
            resource("ListStateMachines", &json!({}), &req)
                .unwrap()
                .as_deref(),
            Some("*")
        );
        assert_eq!(resource("ListExecutions", &json!({"stateMachineArn":"arn:aws:states:us-east-1:000000000000:stateMachine:job"}), &req).unwrap().as_deref(), Some("arn:aws:states:us-east-1:000000000000:stateMachine:job"));
        let (base, context) = policy_resource(
            "StartExecution",
            "arn:aws:states:us-east-1:000000000000:stateMachine:job:PROD".into(),
            &req,
        );
        assert_eq!(
            base,
            "arn:aws:states:us-east-1:000000000000:stateMachine:job"
        );
        assert_eq!(context["states:StateMachineQualifier"], ["PROD"]);
    }
}
