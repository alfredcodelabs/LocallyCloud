use serde_json::Value;
use std::collections::BTreeMap;

use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::authorization::{
    verified_caller, AuthorizationRequest, ServiceRoleAuthorizationRequest,
};
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
    let mut context: BTreeMap<String, Vec<String>> = BTreeMap::new();
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

pub async fn authorize_with_tags(
    registry: &ServiceRegistry,
    store: &crate::store::SfnStore,
    request: &ServiceRequest,
    op: &str,
    body: &Value,
) -> Result<(), SfnError> {
    if !registry
        .authorization_evaluator(&ServiceName::new("iam"))
        .is_some_and(|evaluator| evaluator.strict_sigv4_required())
    {
        return Ok(());
    }
    let mut context: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(resource) = resource(op, body, request)? {
        let (resource, _) = policy_resource(op, resource, request);
        let prefix = format!("arn:aws:states:{}:{}:", request.region, request.account_id);
        if let Some((kind, suffix)) = resource
            .strip_prefix(&prefix)
            .and_then(|r| r.split_once(':'))
        {
            let name = suffix.split(':').next().unwrap_or_default();
            let tags = match kind {
                "activity" => {
                    match store.get_activity(&request.account_id, &request.region, name) {
                        Some(activity) => activity.tags.read().await.clone(),
                        None => BTreeMap::new(),
                    }
                }
                // Execution authorization inherits the current state-machine tags in AWS.
                "stateMachine" | "execution" => {
                    match store.get_machine(&request.account_id, &request.region, name) {
                        Some(machine) => machine.read().await.tags.clone(),
                        None => BTreeMap::new(),
                    }
                }
                _ => BTreeMap::new(),
            };
            for (key, value) in tags {
                context
                    .entry(format!("aws:resourcetag/{}", key.to_ascii_lowercase()))
                    .or_default()
                    .push(value);
            }
        }
    }
    match op {
        "CreateStateMachine" | "CreateActivity" | "TagResource" => {
            let tags = crate::ops::parse_tags(body);
            if !tags.is_empty() {
                context.insert("aws:tagkeys".into(), tags.keys().cloned().collect());
                for (key, value) in tags {
                    context
                        .entry(format!("aws:requesttag/{}", key.to_ascii_lowercase()))
                        .or_default()
                        .push(value);
                }
            }
        }
        "UntagResource" => {
            if let Some(keys) = body.get("tagKeys").and_then(Value::as_array) {
                context.insert(
                    "aws:tagkeys".into(),
                    keys.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect(),
                );
            }
        }
        _ => {}
    }
    authorize_with_context(registry, request, op, body, context)
}

#[cfg(test)]
pub fn authorize(
    registry: &ServiceRegistry,
    request: &ServiceRequest,
    op: &str,
    body: &Value,
) -> Result<(), SfnError> {
    authorize_with_context(registry, request, op, body, BTreeMap::new())
}

fn authorize_with_context(
    registry: &ServiceRegistry,
    request: &ServiceRequest,
    op: &str,
    body: &Value,
    mut tag_context: BTreeMap<String, Vec<String>>,
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
    let (resource, mut context) = policy_resource(op, resource, request);
    context.append(&mut tag_context);
    context
        .extend(locallycloud_core::integration::request_context::verified_request_context(request));
    let (identity, delegated_identity) =
        verified_caller(evaluator.as_ref(), request).map_err(|_| SfnError::AccessDenied)?;
    let authorization = AuthorizationRequest {
        request_identity: identity,
        delegated_identity,
        source_service: "states".into(),
        action: format!("states:{op}"),
        resource,
        context,
    };
    if matches!(op, "CreateStateMachine" | "CreateActivity")
        && body
            .get("tags")
            .and_then(Value::as_array)
            .is_some_and(|tags| !tags.is_empty())
    {
        let mut tagging = authorization.clone();
        tagging.action = "states:TagResource".into();
        evaluator
            .authorize(tagging)
            .map_err(|_| SfnError::AccessDenied)?;
    }
    if matches!(op, "CreateStateMachine" | "UpdateStateMachine")
        && body.get("publish").and_then(Value::as_bool) == Some(true)
    {
        let mut publication = authorization.clone();
        publication.action = "states:PublishStateMachineVersion".into();
        evaluator
            .authorize(publication)
            .map_err(|_| SfnError::AccessDenied)?;
    }
    evaluator
        .authorize(authorization)
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
    let (caller, delegated_caller) =
        verified_caller(evaluator.as_ref(), request).map_err(|_| SfnError::AccessDenied)?;
    evaluator
        .authorize_service_role_assignment(ServiceRoleAuthorizationRequest {
            delegated_caller,
            caller_context:
                locallycloud_core::integration::request_context::verified_request_context(request),
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
    use locallycloud_core::integration::{authorization::AuthorizationEvaluator, RequestIdentity};
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
                if let Some(
                    locallycloud_core::integration::identity::CallerIdentity::AssumedRole {
                        role_arn,
                        ..
                    },
                ) = &req.delegated_identity
                {
                    assert_eq!(role_arn, "arn:aws:iam::000000000000:role/worker");
                    assert!(req.request_identity.access_key_id.is_none());
                } else {
                    assert_eq!(
                        req.request_identity.access_key_id.as_deref(),
                        Some("OPERATOR")
                    );
                }
                assert_eq!(req.action, "states:CreateStateMachine");
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
                if req.delegated_caller.is_some() {
                    assert!(req.caller.access_key_id.is_none());
                } else {
                    assert_eq!(req.caller.access_key_id.as_deref(), Some("OPERATOR"));
                }
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
        // Delegated roles need action permission; service principals cannot bypass IAM.
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
        locallycloud_core::integration::identity::IdentityPropagator::attach(
            &mut req.headers,
            &locallycloud_core::integration::identity::CallerIdentity::AssumedRole {
                role_arn: "arn:aws:iam::000000000000:role/worker".into(),
                session_name: "session".into(),
            },
        );
        for principal in [
            "scheduler.amazonaws.com",
            "arn:aws:iam::000000000000:role/worker/session",
        ] {
            req.headers.insert(
                locallycloud_core::integration::identity::PRINCIPAL_HEADER,
                principal.parse().unwrap(),
            );
            assert_eq!(
                authorize(&registry, &req, "CreateStateMachine", &body).is_ok(),
                principal.contains(":role/")
            );
            *evaluator.0.lock().unwrap() = Some("states");
            assert!(authorize(&registry, &req, "CreateStateMachine", &body).is_err());
            *evaluator.0.lock().unwrap() = None;
            // A delegated role still needs PassRole when assigning another role.
            assert_eq!(
                authorize_role_assignment(&registry, &req, "CreateStateMachine", &body).is_ok(),
                principal.contains(":role/")
            );
            *evaluator.0.lock().unwrap() = Some("pass-role");
            assert!(
                authorize_role_assignment(&registry, &req, "CreateStateMachine", &body).is_err()
            );
            *evaluator.0.lock().unwrap() = None;
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
