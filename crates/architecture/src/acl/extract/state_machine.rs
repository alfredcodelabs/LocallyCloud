//! `AWS::StepFunctions::StateMachine` → Step Functions `DescribeStateMachine`.
//!
//! The deployed definition already has its substitutions applied. It is parsed transiently
//! to find Task integrations (including inside Map and Parallel states) and dropped; no part
//! of it is emitted.

use locallycloud_core::views::architecture::TopologyError;
use serde_json::{json, Map, Value};

use super::{deployed, reason, Context};
use crate::acl::identity::{types, Accept};
use crate::acl::reads::{self, Reply};
use crate::acl::stack::StackResource;
use crate::domain::Finding;

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
    Ok(tasks(ctx, id, &definition))
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
