//! `AWS::Events::Rule` → EventBridge `DescribeRule` (bus) and `ListTargetsByRule`.

use locallycloud_core::views::architecture::TopologyError;
use serde_json::{json, Value};

use super::{deployed, reason, Context, Declared};
use crate::acl::identity::{types, Accept};
use crate::acl::reads::{self, Reply};
use crate::acl::stack::StackResource;
use crate::domain::Finding;

const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const DEFAULT_BUS: &str = "default";
const MAX_TARGET_PAGES: usize = 32;
const BUS_REASON: &str = "External, default or unresolved event bus";

pub(super) async fn extract(
    ctx: &Context<'_>,
    resource: &StackResource,
) -> Result<Vec<Finding>, TopologyError> {
    let id = resource.logical_id.as_str();
    // AWS reports rules on custom buses as `bus|rule`; the local emulator reports the name.
    let (bus_hint, name) = match resource.physical_id.split_once('|') {
        Some((bus, name)) => (Some(bus.to_owned()), name),
        None => (None, resource.physical_id.as_str()),
    };
    let mut rule = None;
    for bus in candidate_buses(ctx, id, bus_hint) {
        match describe_rule(ctx, name, &bus).await? {
            Reply::Body(body) => {
                rule = Some((reads::json(&body, "EventBridge DescribeRule")?, bus));
                break;
            }
            Reply::Missing => {}
            Reply::Failed { .. } => {
                return Ok(vec![Finding::gap(id, "EventBusName", reason::READ_FAILED)])
            }
        }
    }
    let Some((rule, bus)) = rule else {
        return Ok(vec![Finding::gap(id, "EventBusName", BUS_REASON)]);
    };
    let bus = rule
        .get("EventBusName")
        .and_then(Value::as_str)
        .map_or(bus, bus_name);
    let mut findings = Vec::new();
    match ctx
        .identities
        .resolve(&bus, Accept::Types(&[types::EVENT_BUS]))
    {
        Some(from) => findings.push(Finding::configured(
            from,
            id,
            "rule",
            deployed(id, "DescribeRule", "EventBusName"),
        )),
        None => findings.push(Finding::gap(id, "EventBusName", BUS_REASON)),
    }
    let mut token: Option<String> = None;
    for _ in 0..MAX_TARGET_PAGES {
        let mut request = json!({ "Rule": name, "EventBusName": bus });
        if let Some(token) = &token {
            request["NextToken"] = json!(token);
        }
        let read = reads::json_rpc(
            "events",
            "AWSEvents.ListTargetsByRule",
            CONTENT_TYPE,
            &request,
        );
        let page = match ctx.reads.send(read).await? {
            Reply::Body(body) => reads::json(&body, "EventBridge ListTargetsByRule")?,
            Reply::Missing | Reply::Failed { .. } => {
                findings.push(Finding::gap(id, "Targets[].Arn", reason::READ_FAILED));
                break;
            }
        };
        for target in page
            .get("Targets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let arn = target
                .get("Arn")
                .and_then(Value::as_str)
                .unwrap_or_default();
            match ctx.identities.resolve(arn, Accept::Any) {
                Some(to) => findings.push(Finding::configured(
                    id,
                    to,
                    "target",
                    deployed(id, "ListTargetsByRule", "Targets[].Arn"),
                )),
                None => findings.push(Finding::gap(
                    id,
                    "Targets[].Arn",
                    reason::UNRESOLVED_DESTINATION,
                )),
            }
        }
        token = page
            .get("NextToken")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .map(str::to_owned);
        if token.is_none() {
            break;
        }
    }
    Ok(findings)
}

/// The bus the rule lives on: AWS's `bus|rule` ID, then the declared bus, then (when the
/// declaration cannot be resolved) the default and every bus of the stack. The deployed
/// `DescribeRule` decides; a candidate is never trusted on its own.
fn candidate_buses(ctx: &Context<'_>, id: &str, hint: Option<String>) -> Vec<String> {
    if let Some(bus) = hint {
        return vec![bus_name(&bus)];
    }
    match ctx.declared(id, "EventBusName") {
        Declared::Value(bus) => vec![bus_name(&bus)],
        Declared::Absent => vec![DEFAULT_BUS.to_owned()],
        Declared::Unresolved => {
            let mut buses = vec![DEFAULT_BUS.to_owned()];
            for bus in ctx
                .resources
                .iter()
                .filter(|r| r.resource_type == types::EVENT_BUS && !r.physical_id.is_empty())
            {
                let name = bus_name(&bus.physical_id);
                if !buses.contains(&name) {
                    buses.push(name);
                }
            }
            buses
        }
    }
}

fn bus_name(value: &str) -> String {
    value
        .split_once(":event-bus/")
        .map_or(value, |(_, name)| name)
        .to_owned()
}

async fn describe_rule(ctx: &Context<'_>, name: &str, bus: &str) -> Result<Reply, TopologyError> {
    let read = reads::json_rpc(
        "events",
        "AWSEvents.DescribeRule",
        CONTENT_TYPE,
        &json!({ "Name": name, "EventBusName": bus }),
    );
    ctx.reads.send(read).await
}
