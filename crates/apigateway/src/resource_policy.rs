//! REST policies use the shared IAM engine, with API Gateway's anonymous caller semantics.
use std::collections::BTreeMap;
use std::sync::Weak;

use locallycloud_core::integration::authorization::{
    ResourcePolicyDecision, ResourcePolicyEvaluationRequest,
};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use serde_json::Value;

use crate::error::ApiGwError;

pub(crate) fn normalize(
    registry: &Weak<ServiceRegistry>,
    policy: &Value,
    account: &str,
    region: &str,
    api_id: &str,
) -> Result<Value, ApiGwError> {
    if policy.is_null() {
        return Ok(Value::Null);
    }
    let document = policy.as_str().ok_or_else(|| {
        ApiGwError::BadRequest("policy must contain a JSON policy document string".into())
    })?;
    if document.len() > 8192 {
        return Err(ApiGwError::BadRequest(
            "Resource policy exceeds 8192 bytes".into(),
        ));
    }
    let mut root: Value = serde_json::from_str(document)
        .map_err(|_| ApiGwError::BadRequest("Invalid policy document".into()))?;
    let prefix = format!("arn:aws:execute-api:{region}:{account}:{api_id}");
    fn expand(value: &mut Value, prefix: &str) {
        match value {
            Value::String(text) => {
                if let Some(suffix) = text.strip_prefix("execute-api:") {
                    *text = format!("{prefix}{suffix}");
                }
            }
            Value::Array(values) => {
                for value in values {
                    expand(value, prefix);
                }
            }
            _ => {}
        }
    }
    let statements = root.get_mut("Statement");
    let expand_statement = |statement: &mut Value| {
        for name in ["Resource", "NotResource"] {
            if let Some(value) = statement.get_mut(name) {
                expand(value, &prefix);
            }
        }
    };
    match statements {
        Some(Value::Array(statements)) => {
            for statement in statements {
                expand_statement(statement);
            }
        }
        Some(statement) => expand_statement(statement),
        None => {}
    }
    let document = root.to_string();
    let evaluator = registry
        .upgrade()
        .and_then(|registry| registry.authorization_evaluator(&ServiceName::new("iam")))
        .ok_or_else(|| ApiGwError::BadRequest("Resource policy evaluator unavailable".into()))?;
    evaluator
        .validate_resource_policy(&document)
        .map_err(|error| ApiGwError::BadRequest(error.to_string()))?;
    Ok(Value::String(document))
}

pub(crate) fn evaluate(
    registry: &Weak<ServiceRegistry>,
    policy: &Value,
    resource: String,
    context: &BTreeMap<String, Vec<String>>,
) -> Result<Option<ResourcePolicyDecision>, ()> {
    if policy.is_null() {
        return Ok(None);
    }
    let evaluator = registry
        .upgrade()
        .and_then(|registry| registry.authorization_evaluator(&ServiceName::new("iam")))
        .ok_or(())?;
    if !evaluator.strict_sigv4_required() {
        return Ok(None);
    }
    evaluator
        .evaluate_anonymous_resource_policy(
            ResourcePolicyEvaluationRequest {
                action: "execute-api:Invoke".into(),
                resource,
                context: context.clone(),
            },
            policy.as_str().ok_or(())?,
        )
        .map(Some)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{RestApiRecord, RestDeploymentSnapshot};
    use serde_json::json;

    #[test]
    fn deployed_policy_is_immutable_and_persists_separately_from_current_policy() {
        let mut record = RestApiRecord {
            api: json!({"policy":"deployed"}),
            ..Default::default()
        };
        let snapshot = record.snapshot();
        record.api["policy"] = json!("pending");
        let restored: RestDeploymentSnapshot =
            serde_json::from_value(serde_json::to_value(snapshot).unwrap()).unwrap();
        assert_eq!(restored.policy, "deployed");
        assert_eq!(record.snapshot().policy, "pending");
        record.api["policy"] = Value::Null;
        let restored: RestDeploymentSnapshot =
            serde_json::from_value(serde_json::to_value(record.snapshot()).unwrap()).unwrap();
        assert!(restored.policy.is_null());
    }

    #[test]
    fn snapshots_without_policy_provenance_cannot_restore_as_public() {
        let mut snapshot = serde_json::to_value(RestDeploymentSnapshot::default()).unwrap();
        snapshot.as_object_mut().unwrap().remove("policy");
        assert!(serde_json::from_value::<RestDeploymentSnapshot>(snapshot).is_err());
    }
}
