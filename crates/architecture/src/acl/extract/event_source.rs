//! `AWS::Lambda::EventSourceMapping` → Lambda `GetEventSourceMapping`.

use locallycloud_core::views::architecture::TopologyError;
use serde_json::Value;

use super::{deployed, reason, Context};
use crate::acl::identity::{types, Accept};
use crate::acl::reads::{self, Reply};
use crate::acl::stack::StackResource;
use crate::domain::Finding;

const SOURCES: &[&str] = &[
    types::SQS_QUEUE,
    types::KINESIS_STREAM,
    types::DYNAMODB_TABLE,
    types::DYNAMODB_GLOBAL_TABLE,
];
const FUNCTIONS: &[&str] = &[types::LAMBDA_FUNCTION];

pub(super) async fn extract(
    ctx: &Context<'_>,
    resource: &StackResource,
) -> Result<Vec<Finding>, TopologyError> {
    let id = resource.logical_id.as_str();
    let path = format!(
        "/2015-03-31/event-source-mappings/{}",
        reads::encode(&resource.physical_id)
    );
    let body = match ctx.reads.send(reads::rest_get("lambda", &path)?).await? {
        Reply::Body(body) => body,
        Reply::Missing => return Ok(vec![Finding::gap(id, "EventSourceArn", reason::DRIFTED)]),
        Reply::Failed { .. } => {
            return Ok(vec![Finding::gap(
                id,
                "EventSourceArn",
                reason::READ_FAILED,
            )])
        }
    };
    let mapping = reads::json(&body, "Lambda GetEventSourceMapping")?;
    let field = |name| {
        mapping
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
    };
    let source = ctx
        .identities
        .resolve(field("EventSourceArn"), Accept::Types(SOURCES));
    let function = ctx
        .identities
        .resolve(field("FunctionArn"), Accept::Types(FUNCTIONS));
    let mut findings = Vec::new();
    if source.is_none() {
        findings.push(Finding::gap(
            id,
            "EventSourceArn",
            "External or unresolved event source",
        ));
    }
    if function.is_none() {
        findings.push(Finding::gap(
            id,
            "FunctionName",
            "External or unresolved function",
        ));
    }
    if let (Some(from), Some(to)) = (source, function) {
        findings.push(Finding::configured(
            from,
            to,
            "event mapping",
            deployed(id, "GetEventSourceMapping", "EventSourceArn → FunctionArn"),
        ));
    }
    Ok(findings)
}
