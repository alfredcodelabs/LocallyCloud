//! IAM boundary for the public EventBridge Classic JSON API.

use std::collections::BTreeMap;
use std::sync::Weak;

use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::authorization::{
    AuthorizationRequest, ServiceRoleAuthorizationRequest,
};
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
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

pub(super) fn check(
    registry: &Weak<ServiceRegistry>,
    req: &ServiceRequest,
    operation: &str,
    body: &Value,
) -> Result<(), EventsError> {
    let Some(registry) = registry.upgrade() else {
        return Err(denied());
    };
    let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
        return Ok(());
    };
    if !evaluator.strict_sigv4_required() {
        return Ok(());
    }
    // Core strips client-supplied trust markers and adds this only for an internal dispatch.
    if req
        .headers
        .get("x-locallycloud-verified-internal-scope")
        .is_some_and(|v| v == "1")
    {
        return Ok(());
    }
    if !req
        .headers
        .get("x-locallycloud-verified-external-sigv4")
        .is_some_and(|v| v == "1")
    {
        return Err(denied());
    }
    let access_key_id = req
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(RequestIdentity::access_key_from_authorization)
        .ok_or_else(denied)?;
    let identity = RequestIdentity {
        account_id: req.account_id.clone(),
        access_key_id: Some(access_key_id),
        arn: None,
    };
    let authorize_action =
        |action: &str, resource: String, context: BTreeMap<String, Vec<String>>| {
            evaluator
                .authorize(AuthorizationRequest {
                    request_identity: identity.clone(),
                    delegated_identity: None,
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
        authorize("*".into(), BTreeMap::new())?;
        return Ok(());
    }
    if operation == "PutEvents" {
        let entries = body
            .get("Entries")
            .and_then(Value::as_array)
            .ok_or_else(|| EventsError::Validation("Entries is required".into()))?;
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
            authorize(bus(req, selected_bus), context)?;
        }
        return Ok(());
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
    Ok(())
}
