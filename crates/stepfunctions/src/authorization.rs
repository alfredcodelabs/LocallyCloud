use serde_json::Value;
use std::collections::BTreeMap;

use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::authorization::{
    AuthorizationEvaluator, AuthorizationRequest, ServiceRoleAuthorizationRequest,
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

// Operators retain IAM checks through Core's scoped dispatcher. Delegated service
// calls have already been authorized by their source adapter.
fn authenticated_caller(
    evaluator: &dyn AuthorizationEvaluator,
    request: &ServiceRequest,
) -> Result<Option<RequestIdentity>, SfnError> {
    let internal = request
        .headers
        .get("x-locallycloud-verified-internal-scope")
        .is_some_and(|v| v == "1");
    let external = request
        .headers
        .get("x-locallycloud-verified-external-sigv4")
        .is_some_and(|v| v == "1");
    if internal == external {
        return Err(SfnError::AccessDenied);
    }
    let identity = RequestIdentity {
        account_id: request.account_id.clone(),
        access_key_id: request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(RequestIdentity::access_key_from_authorization),
        arn: None,
    };
    if external {
        if identity.access_key_id.is_none() {
            return Err(SfnError::AccessDenied);
        }
        return Ok(Some(identity));
    }
    let principal = request
        .headers
        .get(locallycloud_core::integration::identity::PRINCIPAL_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(SfnError::AccessDenied)?;
    match evaluator.resolve_caller_arn(&identity) {
        Ok(Some(resolved)) if resolved == principal => Ok(Some(identity)),
        Ok(Some(_)) => Err(SfnError::AccessDenied),
        _ if locallycloud_core::integration::identity::trusted_role(request).is_some()
            || principal.ends_with(".amazonaws.com") =>
        {
            Ok(None)
        }
        _ => Err(SfnError::AccessDenied),
    }
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
    let Some(identity) = authenticated_caller(evaluator.as_ref(), request)? else {
        return Ok(());
    };
    evaluator
        .authorize(AuthorizationRequest {
            request_identity: identity,
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
    let caller =
        authenticated_caller(evaluator.as_ref(), request)?.ok_or(SfnError::AccessDenied)?;
    evaluator
        .authorize_service_role_assignment(ServiceRoleAuthorizationRequest {
            source_arn: resource(op, body, request)?,
            caller,
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
    fn scoped_operator_requires_states_and_pass_role_permissions() {
        use axum::response::Response;
        use locallycloud_core::handler::NativeHandler;
        use locallycloud_core::integration::authorization::AuthorizationError;
        use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};
        use std::sync::{Arc, Mutex};
        struct Evaluator(Mutex<Option<&'static str>>);
        impl AuthorizationEvaluator for Evaluator {
            fn strict_sigv4_required(&self) -> bool {
                true
            }
            fn resolve_caller_arn(
                &self,
                identity: &RequestIdentity,
            ) -> Result<Option<String>, AuthorizationError> {
                Ok((identity.access_key_id.as_deref() == Some("OPERATOR"))
                    .then(|| "arn:aws:iam::000000000000:user/operator".into()))
            }
            fn authorize(&self, req: AuthorizationRequest) -> Result<(), AuthorizationError> {
                assert_eq!(
                    req.request_identity.access_key_id.as_deref(),
                    Some("OPERATOR")
                );
                assert_eq!(req.action, "states:CreateStateMachine");
                assert!(req.delegated_identity.is_none());
                if *self.0.lock().unwrap() == Some("states") {
                    Err(AuthorizationError::Denied)
                } else {
                    Ok(())
                }
            }
            fn authorize_service_role_assignment(
                &self,
                req: ServiceRoleAuthorizationRequest,
            ) -> Result<(), AuthorizationError> {
                assert_eq!(req.caller.access_key_id.as_deref(), Some("OPERATOR"));
                assert_eq!(req.action, "iam:PassRole");
                assert_eq!(req.service_principal, "states.amazonaws.com");
                assert_eq!(req.role_arn, "arn:aws:iam::000000000000:role/workflow");
                assert_eq!(
                    req.source_arn.as_deref(),
                    Some("arn:aws:states:us-east-1:000000000000:stateMachine:job")
                );
                if *self.0.lock().unwrap() == Some("pass-role") {
                    Err(AuthorizationError::Denied)
                } else {
                    Ok(())
                }
            }
        }
        #[async_trait::async_trait]
        impl NativeHandler for Evaluator {
            async fn handle(&self, _: ServiceRequest) -> Response {
                http::Response::builder()
                    .status(501)
                    .body(axum::body::Body::empty())
                    .unwrap()
            }
        }
        let registry = ServiceRegistry::new();
        let evaluator = Arc::new(Evaluator(Mutex::new(None)));
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            evaluator.clone(),
            evaluator.clone(),
        );
        let body = json!({"name":"job","roleArn":"arn:aws:iam::000000000000:role/workflow"});
        let mut req = request();
        req.headers.insert(
            http::header::AUTHORIZATION,
            "AWS4-HMAC-SHA256 Credential=OPERATOR/20261006/us-east-1/states/aws4_request"
                .parse()
                .unwrap(),
        );
        req.headers.insert(
            locallycloud_core::integration::identity::PRINCIPAL_HEADER,
            "arn:aws:iam::000000000000:user/operator".parse().unwrap(),
        );
        // A principal header and access key alone are never trusted.
        assert!(authorize(&registry, &req, "CreateStateMachine", &body).is_err());
        assert!(authorize_role_assignment(&registry, &req, "CreateStateMachine", &body).is_err());
        req.headers.insert(
            "x-locallycloud-verified-internal-scope",
            "1".parse().unwrap(),
        );
        assert!(authorize(&registry, &req, "CreateStateMachine", &body).is_ok());
        assert!(authorize_role_assignment(&registry, &req, "CreateStateMachine", &body).is_ok());
        *evaluator.0.lock().unwrap() = Some("states");
        assert!(authorize(&registry, &req, "CreateStateMachine", &body).is_err());
        *evaluator.0.lock().unwrap() = Some("pass-role");
        assert!(authorize_role_assignment(&registry, &req, "CreateStateMachine", &body).is_err());
        *evaluator.0.lock().unwrap() = None;
        req.headers.insert(
            locallycloud_core::integration::identity::PRINCIPAL_HEADER,
            "arn:aws:iam::000000000000:user/other".parse().unwrap(),
        );
        assert!(authorize(&registry, &req, "CreateStateMachine", &body).is_err());
        assert!(authorize_role_assignment(&registry, &req, "CreateStateMachine", &body).is_err());
        req.headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        assert!(authorize(&registry, &req, "CreateStateMachine", &body).is_err());
        req.headers.remove("x-locallycloud-verified-internal-scope");
        assert!(authorize(&registry, &req, "CreateStateMachine", &body).is_ok());
        assert!(authorize_role_assignment(&registry, &req, "CreateStateMachine", &body).is_ok());
        // Source-authorized service/role invocations keep their existing delegation path.
        req.headers.remove("x-locallycloud-verified-external-sigv4");
        req.headers.insert(
            "x-locallycloud-verified-internal-scope",
            "1".parse().unwrap(),
        );
        req.headers.insert(
            http::header::AUTHORIZATION,
            "AWS4-HMAC-SHA256 Credential=locallycloud/20261006/us-east-1/states/aws4_request"
                .parse()
                .unwrap(),
        );
        for principal in [
            "scheduler.amazonaws.com",
            "arn:aws:iam::000000000000:role/worker/session",
        ] {
            req.headers.insert(
                locallycloud_core::integration::identity::PRINCIPAL_HEADER,
                principal.parse().unwrap(),
            );
            assert!(authorize(&registry, &req, "CreateStateMachine", &body).is_ok());
            // Delegation does not authorize assigning a new execution role.
            assert!(
                authorize_role_assignment(&registry, &req, "CreateStateMachine", &body).is_err()
            );
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
