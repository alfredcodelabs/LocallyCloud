//! Vended-log setup uses execution-role management permissions and a scoped Logs policy.
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use locallycloud_core::integration::authorization::{
    AuthorizationRequest, ServiceRoleAuthorizationRequest,
};
use locallycloud_core::integration::identity::{CallerIdentity, IdentityPropagator};
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use serde_json::{json, Value};

use crate::error::SfnError;

fn invalid(message: impl Into<String>) -> SfnError {
    SfnError::InvalidLoggingConfiguration(message.into())
}

pub(crate) fn source(arn: &str) -> String {
    arn.split(':').take(7).collect::<Vec<_>>().join(":")
}

pub(crate) fn validate_role(
    registry: &ServiceRegistry,
    region: &str,
    account: &str,
    role: &str,
    arn: &str,
    configure: bool,
) -> Result<bool, SfnError> {
    let Some(evaluator) = registry
        .authorization_evaluator(&ServiceName::new("iam"))
        .filter(|e| e.strict_sigv4_required())
    else {
        return Ok(false);
    };
    let request = ServiceRoleAuthorizationRequest {
        source_arn: Some(source(arn)),
        caller: RequestIdentity {
            account_id: account.into(),
            access_key_id: None,
            arn: None,
        },
        role_arn: role.into(),
        service_principal: "states.amazonaws.com".into(),
        action: "logs:CreateLogDelivery".into(),
        resource: "*".into(),
    };
    if configure {
        evaluator.authorize_service_role_execution(request)
    } else {
        evaluator.authorize_service_role_trust(request)
    }
    .map_err(|_| {
        invalid(format!(
            "Execution role cannot configure or use CloudWatch log delivery in {region}"
        ))
    })?;
    Ok(true)
}

async fn call(
    registry: &ServiceRegistry,
    region: &str,
    account: &str,
    role: &str,
    operation: &str,
    body: Value,
) -> Result<(u16, Value), SfnError> {
    let dispatcher = registry
        .internal_dispatcher()
        .ok_or_else(|| SfnError::Internal("CloudWatch Logs dispatcher is unavailable".into()))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/x-amz-json-1.1"),
    );
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("Logs_20140328.{operation}"))
            .map_err(|_| invalid("Invalid log delivery operation"))?,
    );
    IdentityPropagator::attach(
        &mut headers,
        &CallerIdentity::AssumedRole {
            role_arn: role.into(),
            session_name: "states-log-delivery".into(),
        },
    );
    let response = dispatcher
        .dispatch_scoped(
            &Method::POST,
            &Uri::from_static("/"),
            &headers,
            Bytes::from(body.to_string()),
            "states-log-delivery",
            account,
            region,
        )
        .await;
    let status = response.status().as_u16();
    if status >= 500 || status == 429 {
        return Err(SfnError::Internal(format!(
            "CloudWatch Logs {operation} failed with HTTP {status}; retry log delivery configuration"
        )));
    }
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .map_err(|_| SfnError::Internal("Log delivery response exceeded its limit".into()))?;
    let value = serde_json::from_slice(&bytes)
        .map_err(|_| SfnError::Internal("Invalid CloudWatch Logs response".into()))?;
    Ok((status, value))
}

pub(crate) async fn configure(
    registry: &ServiceRegistry,
    region: &str,
    account: &str,
    role: &str,
    arn: &str,
    group: &str,
) -> Result<(), SfnError> {
    let resource = format!("arn:aws:logs:{region}:{account}:log-group:{group}");
    let source = source(arn);
    for _ in 0..3 {
        let (status, existing) = call(
            registry,
            region,
            account,
            role,
            "DescribeResourcePolicies",
            json!({"policyScope":"RESOURCE","resourceArn":resource}),
        )
        .await?;
        if status != 200 {
            return Err(invalid(
                "Execution role cannot describe CloudWatch Logs resource policies",
            ));
        }
        let existing = existing
            .get("resourcePolicies")
            .and_then(Value::as_array)
            .and_then(|p| p.first());
        let mut document: Value = match existing
            .and_then(|p| p.get("policyDocument"))
            .and_then(Value::as_str)
        {
            Some(value) => serde_json::from_str(value)
                .map_err(|_| invalid("Invalid existing log delivery policy"))?,
            None => json!({"Version":"2012-10-17","Statement":[]}),
        };
        let statements = match document.get("Statement") {
            Some(Value::Array(items)) => items.clone(),
            Some(Value::Object(_)) => vec![document["Statement"].clone()],
            _ => return Err(invalid("Invalid existing log delivery statements")),
        };
        let mut sources = std::collections::BTreeSet::from([source.clone()]);
        let mut preserved = Vec::new();
        for statement in statements {
            if statement.get("Sid").and_then(Value::as_str)
                == Some("LocallyCloudStepFunctionsDelivery")
            {
                let condition = statement.get("Condition").and_then(Value::as_object);
                let known = statement.get("Effect").and_then(Value::as_str) == Some("Allow")
                    && statement.get("Principal")
                        == Some(&json!({"Service":"delivery.logs.amazonaws.com"}))
                    && statement.get("Action")
                        == Some(&json!(["logs:CreateLogStream", "logs:PutLogEvents"]))
                    && statement.get("Resource") == Some(&json!(format!("{resource}:*")))
                    && condition.is_some_and(|c| c.len() == 2)
                    && statement
                        .get("Condition")
                        .and_then(|c| c.get("StringEquals"))
                        == Some(&json!({"aws:SourceAccount":account}))
                    && statement
                        .pointer("/Condition/ArnEquals")
                        .and_then(Value::as_object)
                        .is_some_and(|c| c.len() == 1);
                if !known {
                    return Err(invalid("Existing delivery Sid is not a recognized generated Allow; policy was preserved"));
                }
                let existing = statement
                    .pointer("/Condition/ArnEquals/aws:SourceArn")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid("Invalid existing Step Functions delivery grant"))?;
                for value in existing {
                    let value = value
                        .as_str()
                        .filter(|v| {
                            v.starts_with(&format!(
                                "arn:aws:states:{region}:{account}:stateMachine:"
                            )) && !v.contains(['*', '?'])
                        })
                        .ok_or_else(|| invalid("Invalid existing delivery source"))?;
                    sources.insert(value.into());
                }
            } else {
                preserved.push(statement);
            }
        }
        preserved.push(json!({"Sid":"LocallyCloudStepFunctionsDelivery","Effect":"Allow","Principal":{"Service":"delivery.logs.amazonaws.com"},"Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":format!("{resource}:*"),"Condition":{"ArnEquals":{"aws:SourceArn":sources},"StringEquals":{"aws:SourceAccount":account}}}));
        document["Statement"] = json!(preserved);
        let (status, account_policies) = call(
            registry,
            region,
            account,
            role,
            "DescribeResourcePolicies",
            json!({"policyScope":"ACCOUNT","limit":50}),
        )
        .await?;
        if status != 200 || account_policies.get("nextToken").is_some() {
            return Err(invalid("Cannot read all account log delivery policies"));
        }
        let mut combined = document["Statement"]
            .as_array()
            .cloned()
            .ok_or_else(|| invalid("Invalid delivery policy"))?;
        for policy in account_policies
            .get("resourcePolicies")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("Invalid account policy list"))?
        {
            let text = policy
                .get("policyDocument")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Invalid account policy"))?;
            let policy: Value = serde_json::from_str(text)
                .map_err(|_| invalid("Invalid account policy document"))?;
            match policy.get("Statement") {
                Some(Value::Array(items)) => combined.extend(items.iter().cloned()),
                Some(Value::Object(_)) => combined.push(policy["Statement"].clone()),
                _ => return Err(invalid("Invalid account policy statements")),
            }
        }
        let combined = json!({"Version":"2012-10-17","Statement":combined}).to_string();
        if let Some(evaluator) = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .filter(|e| e.strict_sigv4_required())
        {
            for action in ["logs:CreateLogStream", "logs:PutLogEvents"] {
                evaluator
                    .authorize_resource_policy(
                        AuthorizationRequest {
                            request_identity: RequestIdentity {
                                account_id: account.into(),
                                access_key_id: None,
                                arn: None,
                            },
                            delegated_identity: Some(CallerIdentity::ServicePrincipal {
                                service: "delivery.logs".into(),
                            }),
                            source_service: "logs".into(),
                            action: action.into(),
                            resource: format!("{resource}:log-stream:preflight"),
                            context: std::collections::BTreeMap::from([
                                ("aws:sourcearn".into(), vec![source.clone()]),
                                ("aws:sourceaccount".into(), vec![account.into()]),
                            ]),
                        },
                        Some(&combined),
                        account,
                    )
                    .map_err(|_| invalid("CloudWatch Logs resource policy denies this delivery"))?;
            }
        }
        let mut body = json!({"policyName":existing.and_then(|p|p.get("policyName")).and_then(Value::as_str).unwrap_or("AWSLogDeliveryWrite"),"resourceArn":resource,"policyDocument":document.to_string()});
        if let Some(revision) = existing.and_then(|p| p.get("revisionId")) {
            body["expectedRevisionId"] = revision.clone();
        }
        let (status, response) =
            call(registry, region, account, role, "PutResourcePolicy", body).await?;
        if status != 200 {
            if response
                .get("__type")
                .and_then(Value::as_str)
                .is_some_and(|code| code.ends_with("OperationAbortedException"))
            {
                continue;
            }
            return Err(invalid(
                "Execution role cannot install the CloudWatch Logs delivery policy",
            ));
        }
        return Ok(());
    }
    Err(invalid(
        "CloudWatch Logs resource policy changed concurrently; retry configuration",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::response::Response;
    use locallycloud_core::handler::{NativeHandler, ServiceRequest};
    use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};

    struct FailingLogs {
        operation: &'static str,
        status: u16,
        malformed: bool,
    }

    #[async_trait]
    impl NativeHandler for FailingLogs {
        async fn handle(&self, request: ServiceRequest) -> Response {
            let operation = request
                .headers
                .get("x-amz-target")
                .and_then(|target| target.to_str().ok())
                .and_then(|target| target.strip_prefix("Logs_20140328."));
            let failing = operation == Some(self.operation);
            let body = if failing {
                if self.malformed {
                    "private-backend-detail".into()
                } else {
                    json!({"__type":"AccessDeniedException","message":"private-backend-detail"})
                        .to_string()
                }
            } else {
                match operation {
                    Some("DescribeResourcePolicies") => json!({"resourcePolicies":[]}).to_string(),
                    Some("PutResourcePolicy") => "{}".into(),
                    _ => panic!("Unexpected Logs request in delivery failure fixture"),
                }
            };
            Response::builder()
                .status(if failing { self.status } else { 200 })
                .body(Body::from(body))
                .unwrap()
        }
    }

    #[tokio::test]
    async fn backend_failures_remain_retryable_server_errors_without_claiming_iam_denial() {
        for operation in ["DescribeResourcePolicies", "PutResourcePolicy"] {
            for (status, malformed, expected) in [
                (500, false, 500),
                (503, true, 500),
                (429, false, 500),
                (200, true, 500),
                (403, false, 400),
            ] {
                let registry = ServiceRegistry::with_known_services();
                crate::register(&registry);
                registry.register_native(
                    ServiceName::new("logs"),
                    ServiceMetadata::new(AwsProtocol::Json11, Some("Logs_20140328")),
                    Arc::new(FailingLogs {
                        operation,
                        status,
                        malformed,
                    }),
                );
                let error = configure(
                    &registry,
                    "us-east-1",
                    "111111111111",
                    "arn:aws:iam::111111111111:role/log-management",
                    "arn:aws:states:us-east-1:111111111111:stateMachine:ledger",
                    "ledger",
                )
                .await
                .unwrap_err();
                let response = error.into_response("delivery-failure");
                assert_eq!(
                    response.status().as_u16(),
                    expected,
                    "{operation}: {status}"
                );
                let body = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap();
                let text = body.to_string();
                assert!(!text.contains("private-backend-detail"));
                if expected == 500 {
                    assert_eq!(body["__type"], "InternalServerError");
                    assert!(!text.contains("Execution role"));
                } else {
                    assert_eq!(body["__type"], "InvalidLoggingConfiguration");
                    assert!(text.contains("Execution role"));
                }
            }
        }
    }
}
