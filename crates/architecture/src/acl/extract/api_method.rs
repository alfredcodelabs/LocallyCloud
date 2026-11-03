//! `AWS::ApiGateway::Method` → API Gateway `GetIntegration`.

use locallycloud_core::views::architecture::TopologyError;
use serde_json::Value;

use super::{reason, Context, Declared};
use crate::acl::identity::{types, Accept};
use crate::acl::reads::{self, Reply};
use crate::acl::stack::StackResource;
use crate::domain::Finding;

const PROPERTY: &str = "Integration.Uri";
const UNRESOLVED_INTEGRATION: &str = "Unresolved AWS integration; Lambda destination unverified";

/// The method's REST API, resource and HTTP verb.
struct MethodId {
    api: String,
    resource: String,
    verb: String,
}

pub(super) async fn extract(
    ctx: &Context<'_>,
    resource: &StackResource,
) -> Result<Vec<Finding>, TopologyError> {
    let id = resource.logical_id.as_str();
    let Some(method) = method_id(ctx, resource) else {
        return Ok(vec![Finding::gap(id, PROPERTY, UNRESOLVED_INTEGRATION)]);
    };
    let mut findings = Vec::new();
    if let Some(api) = ctx
        .identities
        .resolve(&method.api, Accept::Types(&[types::REST_API]))
    {
        findings.push(Finding::HttpInterface(api.to_owned()));
    }
    let path = format!(
        "/restapis/{}/resources/{}/methods/{}/integration",
        reads::encode(&method.api),
        reads::encode(&method.resource),
        reads::encode(&method.verb)
    );
    let integration = match ctx
        .reads
        .send(reads::rest_get("apigateway", &path)?)
        .await?
    {
        Reply::Body(body) => reads::json(&body, "API Gateway GetIntegration")?,
        // A method without an integration has no configured destination.
        Reply::Missing => return Ok(findings),
        Reply::Failed { .. } => {
            findings.push(Finding::gap(id, PROPERTY, reason::READ_FAILED));
            return Ok(findings);
        }
    };
    let kind = integration.get("type").and_then(Value::as_str);
    if !matches!(kind, Some("AWS" | "AWS_PROXY")) {
        return Ok(findings);
    }
    let function = integration
        .get("uri")
        .and_then(Value::as_str)
        .and_then(invoked_function);
    let finding = match function {
        None => Finding::gap(id, PROPERTY, UNRESOLVED_INTEGRATION),
        Some(arn) => match ctx
            .identities
            .resolve(arn, Accept::Types(&[types::LAMBDA_FUNCTION]))
        {
            Some(to) => Finding::configured(
                id,
                to,
                "Lambda integration",
                format!("{id} GetIntegration uri (invocation not observed)"),
            ),
            None => Finding::gap(id, PROPERTY, reason::UNRESOLVED_DESTINATION),
        },
    };
    findings.push(finding);
    Ok(findings)
}

/// The local emulator reports `api:resource:VERB`; otherwise the declaration is resolved
/// against deployed IDs.
fn method_id(ctx: &Context<'_>, resource: &StackResource) -> Option<MethodId> {
    let mut parts = resource.physical_id.splitn(3, ':');
    if let (Some(api), Some(res), Some(verb)) = (parts.next(), parts.next(), parts.next()) {
        if [api, res, verb].iter().all(|part| !part.is_empty()) && valid_verb(verb) {
            return Some(MethodId {
                api: api.to_owned(),
                resource: res.to_owned(),
                verb: verb.to_owned(),
            });
        }
    }
    let declared = |property| match ctx.declared(&resource.logical_id, property) {
        Declared::Value(value) if !value.is_empty() => Some(value),
        _ => None,
    };
    let verb = declared("HttpMethod")?.to_ascii_uppercase();
    if !valid_verb(&verb) {
        return None;
    }
    Some(MethodId {
        api: declared("RestApiId")?,
        resource: declared("ResourceId")?,
        verb,
    })
}

fn valid_verb(verb: &str) -> bool {
    !verb.is_empty() && verb.len() <= 16 && verb.bytes().all(|b| b.is_ascii_uppercase())
}

/// `arn:aws:apigateway:<region>:lambda:path/2015-03-31/functions/<arn>/invocations` → `<arn>`.
fn invoked_function(uri: &str) -> Option<&str> {
    let (_, rest) = uri.split_once("/functions/")?;
    let (arn, _) = rest.split_once("/invocations")?;
    (arn.starts_with("arn:") && !arn.contains('/')).then_some(arn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_invoked_function_arn() {
        assert_eq!(
            invoked_function(
                "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:000000000000:function:f/invocations"
            ),
            Some("arn:aws:lambda:us-east-1:000000000000:function:f")
        );
        assert_eq!(
            invoked_function("arn:aws:apigateway:us-east-1:sqs:path/1/q"),
            None
        );
        assert!(valid_verb("ANY"));
        assert!(!valid_verb("get"));
    }
}
