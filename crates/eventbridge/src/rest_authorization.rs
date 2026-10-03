//! IAM boundary shared by public Scheduler and Pipes REST handlers.

use std::collections::BTreeMap;
use std::sync::Weak;

use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::authorization::{
    AuthorizationRequest, ServiceRoleAuthorizationRequest,
};
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use serde_json::Value;

pub(super) fn check(
    registry: &Weak<ServiceRegistry>,
    request: &ServiceRequest,
    service: &str,
    operation: &str,
    path_value: Option<&str>,
    body: &Value,
) -> Result<(), ()> {
    let registry = registry.upgrade().ok_or(())?;
    let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
        return Ok(());
    };
    if !evaluator.strict_sigv4_required() {
        return Ok(());
    }
    // Core strips caller-supplied trust markers before setting either marker.
    if request
        .headers
        .get("x-locallycloud-verified-internal-scope")
        .is_some_and(|value| value == "1")
    {
        return Ok(());
    }
    if !request
        .headers
        .get("x-locallycloud-verified-external-sigv4")
        .is_some_and(|value| value == "1")
    {
        return Err(());
    }
    let key = request
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(RequestIdentity::access_key_from_authorization)
        .ok_or(())?;
    let identity = RequestIdentity {
        account_id: request.account_id.clone(),
        access_key_id: Some(key),
        arn: None,
    };
    let authorize = |action: &str, resource: String, context: BTreeMap<String, Vec<String>>| {
        evaluator
            .authorize(AuthorizationRequest {
                request_identity: identity.clone(),
                delegated_identity: None,
                source_service: service.into(),
                action: action.into(),
                resource,
                context,
            })
            .map_err(|_| ())
    };
    let name = path_value.filter(|value| !value.is_empty());
    let resource = match service {
        "scheduler" => match operation {
            "ListSchedules" | "ListScheduleGroups" => "*".into(),
            "CreateScheduleGroup"
            | "GetScheduleGroup"
            | "DeleteScheduleGroup"
            | "TagResource"
            | "UntagResource"
            | "ListTagsForResource" => {
                if operation.ends_with("Resource") {
                    name.ok_or(())?.into()
                } else {
                    format!(
                        "arn:aws:scheduler:{}:{}:schedule-group/{}",
                        request.region,
                        request.account_id,
                        name.ok_or(())?
                    )
                }
            }
            "CreateSchedule" | "GetSchedule" | "UpdateSchedule" | "DeleteSchedule" => {
                let group = body
                    .get("GroupName")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .unwrap_or("default");
                format!(
                    "arn:aws:scheduler:{}:{}:schedule/{group}/{}",
                    request.region,
                    request.account_id,
                    name.ok_or(())?
                )
            }
            _ => return Err(()),
        },
        "pipes" => match operation {
            "ListPipes" => "*".into(),
            "TagResource" | "UntagResource" | "ListTagsForResource" => name.ok_or(())?.into(),
            "CreatePipe" | "DescribePipe" | "UpdatePipe" | "DeletePipe" | "StartPipe"
            | "StopPipe" => format!(
                "arn:aws:pipes:{}:{}:pipe/{}",
                request.region,
                request.account_id,
                name.ok_or(())?
            ),
            _ => return Err(()),
        },
        _ => return Err(()),
    };
    authorize(
        &format!("{service}:{operation}"),
        resource.clone(),
        BTreeMap::new(),
    )?;
    if service == "scheduler" && operation == "DeleteScheduleGroup" {
        authorize(
            "scheduler:DeleteSchedule",
            format!(
                "arn:aws:scheduler:{}:{}:schedule/{}/*",
                request.region,
                request.account_id,
                name.ok_or(())?
            ),
            BTreeMap::new(),
        )?;
    }
    let has_tags = body
        .get("Tags")
        .or_else(|| body.get("tags"))
        .is_some_and(|tags| !tags.is_null() && tags != &Value::Array(Vec::new()));
    if has_tags
        && ((service == "scheduler" && operation == "CreateScheduleGroup")
            || (service == "pipes" && operation == "CreatePipe"))
    {
        authorize(&format!("{service}:TagResource"), resource, BTreeMap::new())?;
    }
    let role = match (service, operation) {
        ("scheduler", "CreateSchedule" | "UpdateSchedule") => body
            .get("Target")
            .and_then(|target| target.get("RoleArn"))
            .and_then(Value::as_str),
        ("pipes", "CreatePipe" | "UpdatePipe") => body.get("RoleArn").and_then(Value::as_str),
        _ => None,
    };
    if let Some(role) = role {
        evaluator
            .authorize_service_role_assignment(ServiceRoleAuthorizationRequest {
                caller: identity,
                role_arn: role.into(),
                service_principal: format!("{service}.amazonaws.com"),
                action: "iam:PassRole".into(),
                resource: role.into(),
            })
            .map_err(|_| ())?;
    }
    Ok(())
}
