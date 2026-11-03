//! CloudFormation reads: the stack, its deployed inventory and its processed template.

use std::collections::HashMap;

use locallycloud_core::views::architecture::{Scope, TopologyError};
use serde_json::Value;

use super::reads::{self, Reads, Reply};
use super::xml::{self, Element};

const SERVICE: &str = "cloudformation";
const VERSION: &str = "2010-05-15";
/// NoEcho parameters are masked by CloudFormation and never usable for resolution.
const MASKED: &str = "*****";

pub(crate) struct Stack {
    pub id: String,
    pub name: String,
    /// Parameter values, held transiently to resolve references; never emitted.
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub(crate) struct StackResource {
    pub logical_id: String,
    pub resource_type: String,
    pub physical_id: String,
    pub status: String,
}

fn not_found() -> TopologyError {
    TopologyError::NotFound("Stack does not exist in this account and region".into())
}

fn unusable(operation: &str) -> TopologyError {
    TopologyError::Unprocessable(format!(
        "CloudFormation {operation} returned an unusable response"
    ))
}

async fn call(
    reads: &Reads<'_>,
    operation: &'static str,
    params: &[(&str, &str)],
) -> Result<Element, TopologyError> {
    let body = match reads
        .send(reads::query(SERVICE, operation, VERSION, params))
        .await?
    {
        Reply::Body(body) => body,
        // CloudFormation reports an unknown stack as a ValidationError.
        Reply::Missing => return Err(not_found()),
        Reply::Failed { code } if code.as_deref() == Some("ValidationError") => {
            return Err(not_found())
        }
        Reply::Failed { .. } => return Err(unusable(operation)),
    };
    let root = xml::parse(&body).ok_or_else(|| unusable(operation))?;
    root.children
        .into_iter()
        .find(|child| child.name == format!("{operation}Result"))
        .ok_or_else(|| unusable(operation))
}

/// The stack named by the caller, verified to belong to the dashboard's account and region.
pub(crate) async fn describe(
    reads: &Reads<'_>,
    scope: &Scope,
    name: &str,
) -> Result<Stack, TopologyError> {
    let result = call(reads, "DescribeStacks", &[("StackName", name)]).await?;
    let member = result
        .child("Stacks")
        .and_then(|stacks| stacks.members().next())
        .ok_or_else(not_found)?;
    let id = member.text_of("StackId").unwrap_or_default();
    let stack_name = member.text_of("StackName").unwrap_or_default();
    let prefix = format!(
        "arn:aws:cloudformation:{}:{}:stack/",
        scope.region, scope.account
    );
    let deleted = member.text_of("StackStatus") == Some("DELETE_COMPLETE");
    if !id.starts_with(&prefix) || stack_name.is_empty() || deleted {
        return Err(not_found());
    }
    let parameters = member
        .child("Parameters")
        .into_iter()
        .flat_map(Element::members)
        .filter_map(|p| Some((p.text_of("ParameterKey")?, p.text_of("ParameterValue")?)))
        .filter(|(_, value)| *value != MASKED)
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    Ok(Stack {
        id: id.to_owned(),
        name: stack_name.to_owned(),
        parameters,
    })
}

pub(crate) async fn resources(
    reads: &Reads<'_>,
    stack_id: &str,
) -> Result<Vec<StackResource>, TopologyError> {
    let result = call(reads, "DescribeStackResources", &[("StackName", stack_id)]).await?;
    let members = result
        .child("StackResources")
        .ok_or_else(|| unusable("DescribeStackResources"))?;
    members
        .members()
        .map(|member| {
            let field = |name| member.text_of(name).unwrap_or_default().to_owned();
            let resource = StackResource {
                logical_id: field("LogicalResourceId"),
                resource_type: field("ResourceType"),
                physical_id: field("PhysicalResourceId"),
                status: field("ResourceStatus"),
            };
            if resource.logical_id.is_empty() || resource.resource_type.is_empty() {
                return Err(unusable("DescribeStackResources"));
            }
            Ok(resource)
        })
        .collect()
}

/// The processed template, or `None` when it is not a JSON document with `Resources`.
pub(crate) async fn processed_template(
    reads: &Reads<'_>,
    stack_id: &str,
) -> Result<Option<Value>, TopologyError> {
    let result = call(
        reads,
        "GetTemplate",
        &[("StackName", stack_id), ("TemplateStage", "Processed")],
    )
    .await?;
    let Some(body) = result.text_of("TemplateBody") else {
        return Ok(None);
    };
    let Ok(template) = serde_json::from_str::<Value>(body) else {
        return Ok(None);
    };
    if !reads::bounded(&template) {
        return Err(TopologyError::Unprocessable(
            "Template exceeds the structure/depth limit".into(),
        ));
    }
    Ok(template
        .get("Resources")
        .is_some_and(Value::is_object)
        .then_some(template))
}
