//! `AWS::StepFunctions::StateMachine` → Step Functions `DescribeStateMachine`.
//!
//! The deployed definition already has its substitutions applied. It is parsed transiently
//! to find Task integrations (including inside Map and Parallel states) and dropped; no part
//! of it is emitted.

use locallycloud_core::views::architecture::TopologyError;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

use super::{deployed, reason, Context};
use crate::acl::identity::{types, Accept};
use crate::acl::reads::{self, Reply};
use crate::acl::stack::StackResource;
use crate::domain::{Fact, FactId, FactValue, Finding};

const DEFINITION_REASON: &str = "Definition unavailable or unsupported intrinsic";

/// Task integrations the review understands, tried in order.
#[derive(Clone, Copy)]
enum Integration {
    /// `Resource` is a Lambda function ARN.
    LambdaArn,
    LambdaInvoke,
    DynamoDb,
    Sqs,
    PutEvents,
}

/// Recognizes the `Resource` of one integration.
type Admits = fn(&str) -> bool;

const INTEGRATIONS: &[(Admits, Integration)] = &[
    (is_lambda_arn, Integration::LambdaArn),
    (is_lambda_service, Integration::LambdaInvoke),
    (is_dynamodb, Integration::DynamoDb),
    (is_sqs, Integration::Sqs),
    (is_put_events, Integration::PutEvents),
];

fn is_lambda_arn(resource: &str) -> bool {
    let mut parts = resource.splitn(4, ':');
    parts.next() == Some("arn") && parts.next().is_some() && parts.next() == Some("lambda")
}

fn is_lambda_service(resource: &str) -> bool {
    resource.contains(":lambda:")
}

fn is_dynamodb(resource: &str) -> bool {
    resource.contains(":dynamodb:")
}

fn is_sqs(resource: &str) -> bool {
    resource.contains(":sqs:")
}

fn is_put_events(resource: &str) -> bool {
    resource.contains(":events:putEvents")
}

pub(super) async fn extract(
    ctx: &Context<'_>,
    resource: &StackResource,
) -> Result<Vec<Finding>, TopologyError> {
    let id = resource.logical_id.as_str();
    let read = reads::json_rpc(
        "states",
        "AWSStepFunctions.DescribeStateMachine",
        "application/x-amz-json-1.0",
        &json!({ "stateMachineArn": resource.physical_id }),
    );
    let body = match ctx.reads.send(read).await? {
        Reply::Body(body) => body,
        Reply::Missing => return Ok(vec![Finding::gap(id, "Definition", reason::DRIFTED)]),
        Reply::Failed { .. } => {
            return Ok(vec![Finding::gap(id, "Definition", reason::READ_FAILED)])
        }
    };
    let described = reads::json(&body, "Step Functions DescribeStateMachine")?;
    let definition = described
        .get("definition")
        .and_then(Value::as_str)
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .filter(|definition| definition.is_object() && reads::bounded(definition));
    let Some(definition) = definition else {
        return Ok(vec![Finding::gap(id, "Definition", DEFINITION_REASON)]);
    };
    let mut findings = tasks(ctx, id, &definition);
    for (state, path) in failure_tasks(&definition) {
        let Some(resource) = state.get("Resource").and_then(Value::as_str) else {
            continue;
        };
        if !matches!(
            INTEGRATIONS
                .iter()
                .find(|(admits, _)| admits(resource))
                .map(|(_, integration)| integration),
            Some(Integration::Sqs)
        ) || resource
            .rsplit(':')
            .next()
            .and_then(|operation| operation.split('.').next())
            != Some("sendMessage")
        {
            continue;
        }
        let Some((argument_field, args)) = ["Parameters", "Arguments"].iter().find_map(|key| {
            state
                .get(*key)
                .and_then(Value::as_object)
                .map(|args| (*key, args))
        }) else {
            continue;
        };
        let Field::Value(queue) = field(args, "QueueUrl") else {
            continue;
        };
        if let Some(target) = ctx
            .identities
            .resolve(queue, Accept::Types(&[types::SQS_QUEUE]))
        {
            findings.push(Finding::Fact {
                target: target.to_owned(),
                fact: Fact {
                    id: FactId::DeadLetter,
                    value: FactValue::DeadLetterTarget,
                    evidence: deployed(
                        id,
                        "DescribeStateMachine",
                        &format!("{path}.{argument_field}.QueueUrl (Catch path)"),
                    ),
                },
            });
        }
    }
    Ok(findings)
}

/// Error-only control-flow paths, keeping nested state-machine names in their own scope.
fn failure_tasks(definition: &Value) -> Vec<(&Map<String, Value>, String)> {
    let mut pending = vec![(definition, false, "Definition".to_owned())];
    let mut tasks = Vec::new();
    while let Some((scope, inherited_failure, path)) = pending.pop() {
        let Some(states) = scope.get("States").and_then(Value::as_object) else {
            continue;
        };
        let Some(start) = scope.get("StartAt").and_then(Value::as_str) else {
            continue;
        };
        let all = reachable(states, std::iter::once(start), true);
        let normal = if inherited_failure {
            BTreeSet::new()
        } else {
            reachable(states, std::iter::once(start), false)
        };
        let seeds = all.iter().flat_map(|name| catches(&states[*name]));
        let mut failures = reachable(states, seeds, true);
        if inherited_failure {
            failures.extend(all.iter().copied());
        }
        for name in all {
            let state = &states[name];
            let failed = failures.contains(name) && !normal.contains(name);
            let path = format!("{path}.States.{name}");
            match state.get("Type").and_then(Value::as_str) {
                Some("Task") if failed => {
                    if let Some(state) = state.as_object() {
                        tasks.push((state, path));
                    }
                }
                Some("Map") => {
                    for field in ["ItemProcessor", "Iterator"] {
                        if let Some(child) = state.get(field) {
                            pending.push((child, failed, format!("{path}.{field}")));
                        }
                    }
                }
                Some("Parallel") => {
                    if let Some(branches) = state.get("Branches").and_then(Value::as_array) {
                        for (index, branch) in branches.iter().enumerate() {
                            pending.push((branch, failed, format!("{path}.Branches[{index}]")));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    tasks
}

fn catches(state: &Value) -> impl Iterator<Item = &str> {
    let can_catch = matches!(
        state.get("Type").and_then(Value::as_str),
        Some("Task" | "Map" | "Parallel")
    );
    state
        .get("Catch")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(move |catch| {
            can_catch
                && catch
                    .get("ErrorEquals")
                    .and_then(Value::as_array)
                    .is_some_and(|errors| !errors.is_empty() && errors.iter().all(Value::is_string))
        })
        .filter_map(|catch| catch.get("Next").and_then(Value::as_str))
}

fn reachable<'a>(
    states: &'a Map<String, Value>,
    seeds: impl Iterator<Item = &'a str>,
    include_catches: bool,
) -> BTreeSet<&'a str> {
    let mut pending: Vec<_> = seeds.collect();
    let mut seen = BTreeSet::new();
    while let Some(name) = pending.pop() {
        let Some(state) = states.get(name) else {
            continue;
        };
        if !seen.insert(name) {
            continue;
        }
        match state.get("Type").and_then(Value::as_str) {
            Some("Choice") => {
                pending.extend(state.get("Default").and_then(Value::as_str));
                pending.extend(
                    state
                        .get("Choices")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|choice| choice.get("Next").and_then(Value::as_str)),
                );
            }
            Some("Task" | "Pass" | "Wait" | "Map" | "Parallel") => {
                pending.extend(state.get("Next").and_then(Value::as_str))
            }
            _ => {}
        }
        if include_catches {
            pending.extend(catches(state));
        }
    }
    seen
}

/// Walks every nested object, as nested Map/Parallel states hold their own `States`.
fn tasks(ctx: &Context<'_>, id: &str, definition: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut pending = vec![definition];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(state) => {
                if state.get("Type").and_then(Value::as_str) == Some("Task") {
                    task(ctx, id, state, &mut findings);
                }
                pending.extend(
                    state
                        .values()
                        .rev()
                        .filter(|v| v.is_object() || v.is_array()),
                );
            }
            Value::Array(items) => pending.extend(items.iter().rev()),
            _ => {}
        }
    }
    findings
}

fn task(ctx: &Context<'_>, id: &str, state: &Map<String, Value>, out: &mut Vec<Finding>) {
    let Some(resource) = state.get("Resource").and_then(Value::as_str) else {
        out.push(Finding::gap(
            id,
            "Definition.Resource",
            "Unresolved task integration",
        ));
        return;
    };
    let Some(&(_, integration)) = INTEGRATIONS.iter().find(|(admits, _)| admits(resource)) else {
        out.push(Finding::gap(
            id,
            "Definition.Resource",
            "Unsupported task integration",
        ));
        return;
    };
    let empty = Map::new();
    let args = ["Parameters", "Arguments"]
        .iter()
        .find_map(|key| state.get(*key).and_then(Value::as_object))
        .unwrap_or(&empty);
    let mut connect = |value: Field<'_>, types: &[&str], label: &str, property: &str| {
        let finding = match value {
            Field::Value(value) => match ctx.identities.resolve(value, Accept::Types(types)) {
                Some(to) => Finding::configured(
                    id,
                    to,
                    label,
                    deployed(id, "DescribeStateMachine", property),
                ),
                None => Finding::gap(id, property, reason::UNRESOLVED_DESTINATION),
            },
            Field::Dynamic => Finding::gap(id, property, reason::DYNAMIC_VALUE),
            Field::Missing => Finding::gap(id, property, reason::UNRESOLVED_DESTINATION),
        };
        out.push(finding);
    };
    match integration {
        Integration::LambdaArn => connect(
            Field::Value(resource),
            &[types::LAMBDA_FUNCTION],
            "lambda:invoke",
            "Definition.Resource",
        ),
        Integration::LambdaInvoke => connect(
            field(args, "FunctionName"),
            &[types::LAMBDA_FUNCTION],
            "lambda:invoke",
            "Definition.Parameters.FunctionName",
        ),
        Integration::DynamoDb => connect(
            field(args, "TableName"),
            &[types::DYNAMODB_TABLE, types::DYNAMODB_GLOBAL_TABLE],
            &dynamodb_label(resource),
            "Definition.Parameters.TableName",
        ),
        Integration::Sqs => connect(
            field(args, "QueueUrl"),
            &[types::SQS_QUEUE],
            "sqs:sendMessage",
            "Definition.Parameters.QueueUrl",
        ),
        Integration::PutEvents => {
            const PROPERTY: &str = "Definition.Parameters.Entries.EventBusName";
            if dynamic(args, "Entries") {
                connect(
                    Field::Dynamic,
                    &[types::EVENT_BUS],
                    "events:putEvents",
                    PROPERTY,
                );
                return;
            }
            // Without an Entries list the event goes to the default bus.
            let implicit = Value::Object(Map::new());
            let entries: Vec<&Value> = match args.get("Entries") {
                Some(Value::Array(entries)) => entries.iter().collect(),
                _ => vec![&implicit],
            };
            for entry in entries {
                let bus = match entry.as_object() {
                    Some(entry) if entry.contains_key("EventBusName") => {
                        field(entry, "EventBusName")
                    }
                    Some(entry) if dynamic(entry, "EventBusName") => Field::Dynamic,
                    Some(_) => Field::Value("default"),
                    None => Field::Missing,
                };
                connect(bus, &[types::EVENT_BUS], "events:putEvents", PROPERTY);
            }
        }
    }
}

enum Field<'a> {
    Value(&'a str),
    Dynamic,
    Missing,
}

fn dynamic(args: &Map<String, Value>, name: &str) -> bool {
    args.contains_key(&format!("{name}.$"))
}

/// A static string argument; `Name.$` paths and JSONata `{% %}` expressions are dynamic.
fn field<'a>(args: &'a Map<String, Value>, name: &str) -> Field<'a> {
    if dynamic(args, name) {
        return Field::Dynamic;
    }
    match args.get(name).and_then(Value::as_str) {
        Some(value) if value.trim_start().starts_with("{%") => Field::Dynamic,
        Some(value) => Field::Value(value),
        None => Field::Missing,
    }
}

/// `arn:aws:states:::aws-sdk:dynamodb:query` → `dynamodb:query`.
fn dynamodb_label(resource: &str) -> String {
    let mut parts = resource.rsplitn(3, ':');
    let operation = parts.next().unwrap_or_default();
    let service = parts.next().unwrap_or_default();
    format!("{service}:{operation}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catch_paths_follow_control_flow_without_marking_normal_or_unreachable_tasks() {
        let definition = json!({"StartAt":"Work","States":{
            "Work":{"Type":"Task","Next":"Shared","Catch":[{"ErrorEquals":["States.ALL"],"Next":"Prepare"}]},
            "Prepare":{"Type":"Pass","Next":"Choose"},
            "Choose":{"Type":"Choice","Choices":[{"Next":"Send"}],"Default":"Shared"},
            "Send":{"Type":"Task","Next":"Prepare"},
            "Shared":{"Type":"Task","End":true},
            "Unreachable":{"Type":"Task","Catch":[{"ErrorEquals":["States.ALL"],"Next":"Ghost"}]},
            "Ghost":{"Type":"Task","End":true}
        }});
        let names: Vec<_> = failure_tasks(&definition)
            .into_iter()
            .map(|(_, path)| path)
            .collect();
        assert_eq!(names, vec!["Definition.States.Send"]);
        let nested = json!({"StartAt":"Map","States":{
            "Map":{"Type":"Map","ItemProcessor":{"StartAt":"Work","States":{
                "Work":{"Type":"Task","Catch":[{"ErrorEquals":["States.ALL"],"Next":"Send"}],"End":true},
                "Send":{"Type":"Task","End":true}}},"Next":"Send"},
            "Send":{"Type":"Task","End":true}
        }});
        let names: Vec<_> = failure_tasks(&nested)
            .into_iter()
            .map(|(_, path)| path)
            .collect();
        assert_eq!(
            names,
            vec!["Definition.States.Map.ItemProcessor.States.Send"]
        );
    }

    #[test]
    fn classifies_task_resources_in_order() {
        let kind = |resource: &str| {
            INTEGRATIONS
                .iter()
                .find(|(admits, _)| admits(resource))
                .map(|(_, i)| *i as u8)
        };
        assert_eq!(
            kind("arn:aws:lambda:us-east-1:000000000000:function:f"),
            Some(Integration::LambdaArn as u8)
        );
        assert_eq!(
            kind("arn:aws:states:::lambda:invoke"),
            Some(Integration::LambdaInvoke as u8)
        );
        assert_eq!(
            kind("arn:aws:states:::aws-sdk:dynamodb:query"),
            Some(Integration::DynamoDb as u8)
        );
        assert_eq!(
            kind("arn:aws:states:::sqs:sendMessage.waitForTaskToken"),
            Some(Integration::Sqs as u8)
        );
        assert_eq!(
            kind("arn:aws:states:::events:putEvents"),
            Some(Integration::PutEvents as u8)
        );
        assert_eq!(kind("arn:aws:states:::glue:startJobRun"), None);
        assert_eq!(
            dynamodb_label("arn:aws:states:::aws-sdk:dynamodb:query"),
            "dynamodb:query"
        );
        assert_eq!(
            dynamodb_label("arn:aws:states:::dynamodb:putItem"),
            "dynamodb:putItem"
        );
    }
}
