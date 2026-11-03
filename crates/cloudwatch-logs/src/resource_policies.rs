//! CloudWatch Logs policies grant only service-principal stream creation and delivery.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{error::LogsError, groups, model::ScopeKey, store::LogsStore};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResourcePolicy {
    pub policy_name: String,
    pub policy_document: String,
    pub policy_scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_arn: Option<String>,
    pub revision_id: String,
    pub last_updated_time: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Put {
    pub policy_name: String,
    pub policy_document: String,
    pub resource_arn: Option<String>,
    pub expected_revision_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Delete {
    pub policy_name: String,
    pub resource_arn: Option<String>,
    pub expected_revision_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Describe {
    pub resource_arn: Option<String>,
    pub policy_scope: Option<String>,
    pub limit: Option<usize>,
    pub next_token: Option<String>,
}

fn invalid() -> LogsError {
    LogsError::InvalidParameter("Invalid or unsupported CloudWatch Logs resource policy".into())
}

pub(crate) fn group(scope: &ScopeKey, arn: Option<&str>) -> Result<String, LogsError> {
    let Some(arn) = arn else {
        return Ok(String::new());
    };
    let prefix = format!(
        "arn:aws:logs:{}:{}:log-group:",
        scope.region, scope.account_id
    );
    let name = arn.strip_prefix(&prefix).ok_or_else(invalid)?;
    groups::validate_group_name(name)?;
    Ok(name.into())
}

pub(crate) fn name(value: &str) -> Result<(), LogsError> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'/' | b'#'))
    {
        return Err(invalid());
    }
    Ok(())
}

fn strings(value: &Value) -> Result<Vec<&str>, LogsError> {
    match value {
        Value::String(s) if !s.is_empty() => Ok(vec![s]),
        Value::Array(values) if !values.is_empty() && values.len() <= 32 => values
            .iter()
            .map(|v| v.as_str().filter(|s| !s.is_empty()).ok_or_else(invalid))
            .collect(),
        _ => Err(invalid()),
    }
}

pub(crate) fn validate(document: &str, resource: Option<&str>) -> Result<(), LogsError> {
    if document.is_empty() || document.len() > 51200 {
        return Err(invalid());
    }
    let root: Value = serde_json::from_str(document).map_err(|_| invalid())?;
    let root = root.as_object().ok_or_else(invalid)?;
    if root
        .keys()
        .any(|key| !matches!(key.as_str(), "Version" | "Id" | "Statement"))
    {
        return Err(invalid());
    }
    let statements = root.get("Statement").ok_or_else(invalid)?;
    let statements = match statements {
        Value::Object(_) => vec![statements],
        Value::Array(s) if !s.is_empty() && s.len() <= 32 => s.iter().collect(),
        _ => return Err(invalid()),
    };
    for statement in statements {
        let object = statement.as_object().ok_or_else(invalid)?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "Sid" | "Effect" | "Principal" | "Action" | "Resource" | "Condition"
            )
        }) || !matches!(
            statement.get("Effect").and_then(Value::as_str),
            Some("Allow" | "Deny")
        ) {
            return Err(invalid());
        }
        let principal = statement
            .get("Principal")
            .and_then(Value::as_object)
            .filter(|p| p.len() == 1)
            .ok_or_else(invalid)?;
        for principal in strings(principal.get("Service").ok_or_else(invalid)?)? {
            if !principal.ends_with(".amazonaws.com")
                || !principal
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
            {
                return Err(invalid());
            }
        }
        for action in strings(statement.get("Action").ok_or_else(invalid)?)? {
            if !["logs:CreateLogStream", "logs:PutLogEvents"]
                .iter()
                .any(|allowed| action.eq_ignore_ascii_case(allowed))
            {
                return Err(invalid());
            }
        }
        for target in strings(statement.get("Resource").ok_or_else(invalid)?)? {
            if let Some(arn) = resource {
                if !target.starts_with(&format!("{arn}:")) && target != arn {
                    return Err(invalid());
                }
            }
        }
        if let Some(conditions) = statement.get("Condition") {
            let conditions = conditions
                .as_object()
                .filter(|c| !c.is_empty())
                .ok_or_else(invalid)?;
            for (op, entries) in conditions {
                if !matches!(
                    op.as_str(),
                    "ArnEquals" | "ArnLike" | "StringEquals" | "StringLike"
                ) {
                    return Err(invalid());
                }
                for (key, value) in entries
                    .as_object()
                    .filter(|e| !e.is_empty())
                    .ok_or_else(invalid)?
                {
                    if !matches!(
                        key.to_ascii_lowercase().as_str(),
                        "aws:sourcearn" | "aws:sourceaccount"
                    ) {
                        return Err(invalid());
                    }
                    strings(value)?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn describe(
    store: &LogsStore,
    scope: ScopeKey,
    request: Describe,
    now: i64,
) -> Result<Value, LogsError> {
    let policy_scope = request.policy_scope.as_deref().unwrap_or("ACCOUNT");
    if !matches!(policy_scope, "ACCOUNT" | "RESOURCE") {
        return Err(invalid());
    }
    let limit = request.limit.unwrap_or(50);
    if !(1..=50).contains(&limit) {
        return Err(invalid());
    }
    if request.resource_arn.is_some() {
        group(&scope, request.resource_arn.as_deref())?;
    }
    let mut offset = 0;
    if let Some(token) = request.next_token {
        if token.len() > 2048 {
            return Err(invalid());
        }
        let decoded = URL_SAFE_NO_PAD.decode(token).map_err(|_| invalid())?;
        let (account, region, kind, arn, index, expiry): (
            String,
            String,
            String,
            Option<String>,
            usize,
            i64,
        ) = serde_json::from_slice(&decoded).map_err(|_| invalid())?;
        if account != scope.account_id
            || region != scope.region
            || kind != policy_scope
            || arn != request.resource_arn
            || now > expiry
        {
            return Err(invalid());
        }
        offset = index;
    }
    let mut policies = store.resource_policies(
        &scope,
        policy_scope,
        request.resource_arn.as_deref(),
        offset,
        limit + 1,
    )?;
    let more = policies.len() > limit;
    policies.truncate(limit);
    let end = offset.saturating_add(policies.len());
    let mut result = json!({"resourcePolicies":policies});
    if more {
        result["nextToken"] = json!(URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&(
                &scope.account_id,
                &scope.region,
                policy_scope,
                &request.resource_arn,
                end,
                now + 86400000
            ))
            .map_err(|_| invalid())?
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_state::{StateCipher, StateDb};
    use std::sync::Arc;

    fn document() -> String {
        json!({"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"delivery.logs.amazonaws.com"},"Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:us-east-1:000000000000:log-group:group:*","Condition":{"StringEquals":{"aws:SourceAccount":"000000000000"}}}}).to_string()
    }

    #[test]
    fn resource_policy_cas_persistence_scope_and_group_cleanup() {
        let root =
            std::env::temp_dir().join(format!("logs-resource-policies-{}", uuid::Uuid::new_v4()));
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let store = LogsStore::durable(db.clone(), StateCipher::with_key(&[17; 32])).unwrap();
        let scope = ScopeKey::new("000000000000", "us-east-1");
        groups::create(
            &store,
            serde_json::from_value(json!({"logGroupName":"group"})).unwrap(),
            scope.clone(),
            0,
        )
        .unwrap();
        let resource = "arn:aws:logs:us-east-1:000000000000:log-group:group";
        let input = || Put {
            policy_name: "delivery".into(),
            policy_document: document(),
            resource_arn: Some(resource.into()),
            expected_revision_id: None,
        };
        let first = store
            .put_resource_policy(scope.clone(), input(), 1)
            .unwrap();
        assert!(matches!(
            store.put_resource_policy(scope.clone(), input(), 2),
            Err(LogsError::OperationAborted(_))
        ));
        let mut update = input();
        update.expected_revision_id = Some(first.revision_id.clone());
        let second = store.put_resource_policy(scope.clone(), update, 3).unwrap();
        assert_ne!(first.revision_id, second.revision_id);
        drop(store);
        let store = LogsStore::durable(db, StateCipher::with_key(&[17; 32])).unwrap();
        let request = || Describe {
            resource_arn: Some(resource.into()),
            policy_scope: Some("RESOURCE".into()),
            limit: Some(1),
            next_token: None,
        };
        let restored = describe(&store, scope.clone(), request(), 4).unwrap();
        assert_eq!(
            restored["resourcePolicies"][0]["revisionId"],
            second.revision_id
        );
        assert!(describe(
            &store,
            ScopeKey::new("000000000000", "us-east-2"),
            request(),
            4
        )
        .is_err());
        assert!(matches!(
            store.delete_resource_policy(
                scope.clone(),
                Delete {
                    policy_name: "delivery".into(),
                    resource_arn: Some(resource.into()),
                    expected_revision_id: Some(first.revision_id)
                }
            ),
            Err(LogsError::OperationAborted(_))
        ));
        store
            .delete_group(&crate::model::GroupKey {
                scope: scope.clone(),
                name: "group".into(),
            })
            .unwrap();
        assert!(
            describe(&store, scope, request(), 5).unwrap()["resourcePolicies"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn service_policies_reject_identity_grants_unknown_actions_and_wide_resource_scope() {
        assert!(validate(&document(), None).is_ok());
        assert!(validate(
            &document().replace("logs:PutLogEvents", "logs:DeleteLogGroup"),
            None
        )
        .is_err());
        assert!(validate(&document().replace("\"Service\"", "\"AWS\""), None).is_err());
        assert!(validate(
            &document().replace("delivery.logs.amazonaws.com", "*"),
            None
        )
        .is_err());
        assert!(validate(
            &document(),
            Some("arn:aws:logs:us-east-1:000000000000:log-group:other")
        )
        .is_err());
    }
}
