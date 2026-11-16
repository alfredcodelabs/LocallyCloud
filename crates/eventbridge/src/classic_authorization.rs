//! IAM boundary for the public EventBridge Classic JSON API.

use std::collections::BTreeMap;
use std::sync::Weak;

use crate::store::EbStore;
use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::authorization::{
    verified_caller, AuthorizationRequest, ServiceRoleAuthorizationRequest,
};
use locallycloud_core::integration::{identity::CallerIdentity, RequestIdentity};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use serde_json::json;
use serde_json::Value;

use crate::error::EventsError;

fn denied() -> EventsError {
    EventsError::AccessDenied("User is not authorized to perform this EventBridge operation".into())
}

fn required<'a>(body: &'a Value, key: &str) -> Result<&'a str, EventsError> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| EventsError::Validation(format!("{key} is required")))
}

fn bus_name(value: &str) -> &str {
    value
        .split_once(":event-bus/")
        .map(|(_, name)| name)
        .unwrap_or(value)
}

fn bus(req: &ServiceRequest, name: &str) -> String {
    format!(
        "arn:aws:events:{}:{}:event-bus/{}",
        req.region,
        req.account_id,
        bus_name(name)
    )
}

fn rule(req: &ServiceRequest, bus_name: &str, name: &str) -> String {
    let prefix = if bus_name == "default" {
        String::new()
    } else {
        format!("{bus_name}/")
    };
    format!(
        "arn:aws:events:{}:{}:rule/{prefix}{name}",
        req.region, req.account_id
    )
}

fn named(req: &ServiceRequest, kind: &str, name: &str) -> String {
    format!(
        "arn:aws:events:{}:{}:{kind}/{name}",
        req.region, req.account_id
    )
}

fn is_s3_producer(req: &ServiceRequest) -> bool {
    req.headers
        .get("x-locallycloud-verified-internal-scope")
        .is_some_and(|v| v == "1")
        && req
            .headers
            .get("x-locallycloud-verified-external-sigv4")
            .is_none_or(|v| v != "1")
        && req
            .headers
            .get(locallycloud_core::integration::identity::PRINCIPAL_HEADER)
            .is_some_and(|v| v == "s3.amazonaws.com")
}

fn verified_s3_source<'a>(
    req: &'a ServiceRequest,
    entry: &Value,
) -> Result<(&'a str, &'a str), EventsError> {
    let source = req
        .headers
        .get("x-locallycloud-source-arn")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(denied)?;
    let owner = req
        .headers
        .get("x-locallycloud-source-account")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(denied)?;
    let bucket = source
        .strip_prefix("arn:aws:s3:::")
        .filter(|bucket| !bucket.is_empty() && !bucket.contains(['/', ':', '*', '?']))
        .ok_or_else(denied)?;
    let selected = entry
        .get("EventBusName")
        .and_then(Value::as_str)
        .unwrap_or("default");
    if !is_s3_producer(req)
        || (selected != "default" && selected != bus(req, "default"))
        || owner != req.account_id
        || entry.get("Source").and_then(Value::as_str) != Some("aws.s3")
        || entry
            .get("Resources")
            .and_then(Value::as_array)
            .is_none_or(|resources| {
                resources.len() != 1 || resources.first().and_then(Value::as_str) != Some(source)
            })
        || bucket.len() > 63
    {
        return Err(denied());
    }
    Ok((source, owner))
}

pub(super) async fn check(
    store: &EbStore,
    registry: &Weak<ServiceRegistry>,
    req: &ServiceRequest,
    operation: &str,
    body: &Value,
) -> Result<crate::events::ProducerScope, EventsError> {
    let producer = if is_s3_producer(req) {
        if operation != "PutEvents" {
            return Err(denied());
        }
        for entry in crate::events::event_entries(body)? {
            verified_s3_source(req, entry)?;
        }
        crate::events::ProducerScope::S3
    } else {
        crate::events::ProducerScope::Untrusted
    };
    let Some(registry) = registry.upgrade() else {
        return Err(denied());
    };
    let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
        return Ok(producer);
    };
    if !evaluator.strict_sigv4_required() {
        return Ok(producer);
    }
    let internal_s3 = matches!(producer, crate::events::ProducerScope::S3);
    let (identity, delegated_identity) = if internal_s3 {
        if operation != "PutEvents" {
            return Err(denied());
        }
        (
            RequestIdentity {
                account_id: req.account_id.clone(),
                access_key_id: None,
                arn: None,
            },
            Some(CallerIdentity::ServicePrincipal {
                service: "s3".into(),
            }),
        )
    } else {
        verified_caller(evaluator.as_ref(), req).map_err(|_| denied())?
    };
    let authorize_action = |action: &str,
                            resource: String,
                            mut context: BTreeMap<String, Vec<String>>| {
        context
            .extend(locallycloud_core::integration::request_context::verified_request_context(req));
        evaluator
            .authorize(AuthorizationRequest {
                request_identity: identity.clone(),
                delegated_identity: delegated_identity.clone(),
                source_service: "events".into(),
                action: action.into(),
                resource,
                context,
            })
            .map_err(|_| denied())
    };
    let authorize = |resource: String, context: BTreeMap<String, Vec<String>>| {
        authorize_action(&format!("events:{operation}"), resource, context)
    };
    if operation == "PutPartnerEvents" {
        return Err(EventsError::NotImplemented(
            "Strict PutPartnerEvents requires partner source ownership, which is not implemented"
                .into(),
        ));
    }
    if operation == "PutEvents" {
        let entries = crate::events::event_entries(body)?;
        for entry in entries {
            let selected_bus = entry
                .get("EventBusName")
                .and_then(Value::as_str)
                .map(bus_name)
                .unwrap_or("default");
            let mut context = BTreeMap::new();
            if let Some(source) = entry.get("Source").and_then(Value::as_str) {
                context.insert("events:source".into(), vec![source.into()]);
            }
            if let Some(detail_type) = entry.get("DetailType").and_then(Value::as_str) {
                context.insert("events:detail-type".into(), vec![detail_type.into()]);
            }
            let resource = bus(req, selected_bus);
            if entry
                .get("EventBusName")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with("arn:") && name != resource)
            {
                return Err(denied());
            }
            let scope = store.scope(&req.account_id, &req.region).await;
            let mut policy = scope
                .read()
                .await
                .buses
                .get(selected_bus)
                .and_then(|bus| bus.policy.clone());
            context.extend(
                locallycloud_core::integration::request_context::verified_request_context(req),
            );
            if internal_s3 {
                let (source, owner) = verified_s3_source(req, entry)?;
                context.insert("aws:sourcearn".into(), vec![source.into()]);
                context.insert("aws:sourceaccount".into(), vec![owner.into()]);
                let grant = json!({"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"events:PutEvents","Resource":resource,
                    "Condition":{"ArnEquals":{"aws:SourceArn":source},"StringEquals":{"aws:SourceAccount":owner,"events:source":"aws.s3"}}});
                let document =
                    policy.get_or_insert_with(|| json!({"Version":"2012-10-17","Statement":[]}));
                let object = document.as_object_mut().ok_or_else(denied)?;
                let statements = object.get_mut("Statement").ok_or_else(denied)?;
                match statements {
                    Value::Array(statements) => statements.push(grant),
                    Value::Object(_) => *statements = Value::Array(vec![statements.clone(), grant]),
                    _ => return Err(denied()),
                }
            }
            let document = policy.as_ref().map(Value::to_string);
            evaluator
                .authorize_resource_policy(
                    AuthorizationRequest {
                        request_identity: identity.clone(),
                        delegated_identity: delegated_identity.clone(),
                        source_service: "events".into(),
                        action: "events:PutEvents".into(),
                        resource,
                        context,
                    },
                    document.as_deref(),
                    &req.account_id,
                )
                .map_err(|_| denied())?;
        }
        return Ok(producer);
    }
    let default_bus = body
        .get("EventBusName")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let resource = match operation {
        "CreateEventBus" | "DeleteEventBus" => bus(req, required(body, "Name")?),
        "UpdateEventBus" | "DescribeEventBus" => bus(
            req,
            body.get("Name")
                .and_then(Value::as_str)
                .unwrap_or("default"),
        ),
        "PutPermission" | "RemovePermission" => "*".into(),
        "PutRule" | "DeleteRule" | "DescribeRule" | "EnableRule" | "DisableRule" => {
            rule(req, bus_name(default_bus), required(body, "Name")?)
        }
        "PutTargets" | "RemoveTargets" | "ListTargetsByRule" => {
            rule(req, bus_name(default_bus), required(body, "Rule")?)
        }
        "CreateArchive" => {
            authorize(required(body, "EventSourceArn")?.into(), BTreeMap::new())?;
            named(req, "archive", required(body, "ArchiveName")?)
        }
        "DescribeArchive" | "UpdateArchive" | "DeleteArchive" => {
            named(req, "archive", required(body, "ArchiveName")?)
        }
        "StartReplay" => {
            let archive = required(body, "EventSourceArn")?.to_string();
            let destination = body
                .get("Destination")
                .and_then(|value| value.get("Arn"))
                .and_then(Value::as_str)
                .ok_or_else(|| EventsError::Validation("Destination.Arn is required".into()))?;
            authorize(archive, BTreeMap::new())?;
            authorize(destination.into(), BTreeMap::new())?;
            named(req, "replay", required(body, "ReplayName")?)
        }
        "DescribeReplay" | "CancelReplay" => named(req, "replay", required(body, "ReplayName")?),
        "CreateConnection" | "DescribeConnection" | "UpdateConnection" | "DeleteConnection" => {
            named(req, "connection", required(body, "Name")?)
        }
        "CreateApiDestination" => {
            authorize(required(body, "ConnectionArn")?.into(), BTreeMap::new())?;
            named(req, "api-destination", required(body, "Name")?)
        }
        "DescribeApiDestination" | "UpdateApiDestination" | "DeleteApiDestination" => {
            named(req, "api-destination", required(body, "Name")?)
        }
        "TagResource" | "UntagResource" | "ListTagsForResource" => body
            .get("ResourceARN")
            .or_else(|| body.get("ResourceArn"))
            .and_then(Value::as_str)
            .ok_or_else(|| EventsError::Validation("ResourceARN is required".into()))?
            .to_string(),
        "ListEventBuses"
        | "ListRules"
        | "ListRuleNamesByTarget"
        | "ListArchives"
        | "ListReplays"
        | "ListConnections"
        | "ListApiDestinations"
        | "TestEventPattern" => "*".into(),
        _ => return Err(denied()),
    };
    authorize(resource, BTreeMap::new())?;
    if matches!(operation, "CreateEventBus" | "PutRule")
        && body
            .get("Tags")
            .and_then(Value::as_array)
            .is_some_and(|tags| !tags.is_empty())
    {
        let resource = if operation == "CreateEventBus" {
            bus(req, required(body, "Name")?)
        } else {
            rule(req, bus_name(default_bus), required(body, "Name")?)
        };
        authorize_action("events:TagResource", resource, BTreeMap::new())?;
    }
    if operation == "PutRule" {
        if let Some(role) = body.get("RoleArn").and_then(Value::as_str) {
            evaluator
                .authorize_service_role_assignment(ServiceRoleAuthorizationRequest {
                    delegated_caller: locallycloud_core::integration::identity::trusted_role(req),
                    caller_context:
                        locallycloud_core::integration::request_context::verified_request_context(
                            req,
                        ),
                    source_arn: Some(rule(req, bus_name(default_bus), required(body, "Name")?)),
                    caller: identity.clone(),

                    role_arn: role.into(),

                    service_principal: "events.amazonaws.com".into(),

                    action: "iam:PassRole".into(),

                    resource: role.into(),
                })
                .map_err(|_| denied())?;
        }
    }
    if operation == "PutTargets" {
        for target in body
            .get("Targets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(role) = target.get("RoleArn").and_then(Value::as_str) {
                evaluator
                    .authorize_service_role_assignment(ServiceRoleAuthorizationRequest {
delegated_caller: locallycloud_core::integration::identity::trusted_role(req),
caller_context: locallycloud_core::integration::request_context::verified_request_context(req),
                        source_arn: Some(rule(req, bus_name(default_bus), required(body, "Rule")?)),
                        caller: identity.clone(),

                        role_arn: role.into(),

                        service_principal: "events.amazonaws.com".into(),

                        action: "iam:PassRole".into(),

                        resource: role.into(),
                    })
                    .map_err(|_| denied())?;
            }
        }
    }
    Ok(producer)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_s3_source_requires_attested_producer_and_exact_scope() {
        let mut req = ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::new(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "s3-source".into(),
        };
        for (key, value) in [
            ("x-locallycloud-verified-internal-scope", "1"),
            ("x-locallycloud-caller-principal", "s3.amazonaws.com"),
            ("x-locallycloud-source-arn", "arn:aws:s3:::bucket"),
            ("x-locallycloud-source-account", "000000000000"),
        ] {
            req.headers.insert(key, value.parse().unwrap());
        }
        let entry = json!({"Source":"aws.s3","Resources":["arn:aws:s3:::bucket"]});
        assert!(verified_s3_source(&req, &entry).is_ok());
        for (field, value) in [
            ("Source", json!("aws.ec2")),
            ("Source", json!("app.test")),
            ("Resources", json!(["arn:aws:s3:::other"])),
            ("EventBusName", json!("other")),
            (
                "EventBusName",
                json!("arn:aws:events:us-east-1:111111111111:event-bus/default"),
            ),
        ] {
            let mut wrong = entry.clone();
            wrong[field] = value;
            assert!(verified_s3_source(&req, &wrong).is_err(), "{wrong}");
        }
        req.headers.insert(
            "x-locallycloud-source-account",
            "111111111111".parse().unwrap(),
        );
        assert!(verified_s3_source(&req, &entry).is_err());
        req.headers.insert(
            "x-locallycloud-source-account",
            "000000000000".parse().unwrap(),
        );
        req.headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        assert!(verified_s3_source(&req, &entry).is_err());
        req.headers.remove("x-locallycloud-verified-internal-scope");
        assert!(verified_s3_source(&req, &entry).is_err());
    }
}
