//! IAM action/resource gate for the public Lambda REST API.

use std::collections::BTreeMap;

use localcloud_core::integration::authorization::AuthorizationRequest;
use localcloud_core::integration::RequestIdentity;

use super::*;

pub(super) fn check(handler: &LambdaHandler, req: &ServiceRequest) -> Result<(), LambdaError> {
    let Some(registry) = handler.registry.upgrade() else {
        return Ok(());
    };
    let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
        return Ok(());
    };
    if !evaluator.strict_sigv4_required() {
        return Ok(());
    }
    // Core removes client-supplied markers and sets them only after verification.
    if req
        .headers
        .get("x-localcloud-verified-internal-scope")
        .is_some_and(|v| v == "1")
    {
        return Ok(());
    }
    let denied = || {
        LambdaError::AccessDenied("User is not authorized to perform this Lambda operation".into())
    };
    if !req
        .headers
        .get("x-localcloud-verified-external-sigv4")
        .is_some_and(|v| v == "1")
    {
        return Err(denied());
    }
    let access_key_id = req
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(RequestIdentity::access_key_from_authorization)
        .ok_or_else(denied)?;
    let identity = RequestIdentity {
        account_id: req.account_id.clone(),
        access_key_id: Some(access_key_id),
        arn: None,
    };
    let segments: Vec<&str> = req.uri.path().trim_matches('/').split('/').collect();
    let method = req.method.as_str();
    let function = |name: &str| -> Result<String, LambdaError> {
        let name = resolve_function_name(&percent_decode_path(name), &req.region)?;
        Ok(function_arn(&req.region, &req.account_id, &name))
    };
    let layer = |name: &str| -> String {
        format!(
            "arn:aws:lambda:{}:{}:layer:{}",
            req.region,
            req.account_id,
            percent_decode_path(name)
        )
    };
    let mut context = BTreeMap::new();
    let (action, resource): (&str, String) = match (segments.as_slice(), method) {
        (["2015-03-31", "functions"], "POST") => {
            let body = parse_json(&req.body)?;
            let name = body
                .get("FunctionName")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    LambdaError::InvalidParameterValue("FunctionName is required".into())
                })?;
            ("CreateFunction", function(name)?)
        }
        (["2015-03-31", "functions"], "GET") => ("ListFunctions", "*".into()),
        (["2015-03-31", "functions", name], "GET") => ("GetFunction", function(name)?),
        (["2015-03-31", "functions", name], "DELETE") => ("DeleteFunction", function(name)?),
        (["2015-03-31", "functions", name, "invocations"], "POST") => {
            let mut arn = function(name)?;
            let reference = percent_decode_path(name);
            let path_qualifier = if reference.starts_with("arn:") {
                reference.split(':').nth(7)
            } else {
                reference.split_once(':').map(|(_, qualifier)| qualifier)
            };
            if let Some(q) = query_value(req.uri.query().unwrap_or(""), "Qualifier")
                .or_else(|| path_qualifier.map(str::to_string))
            {
                if !q.is_empty() {
                    arn.push(':');
                    arn.push_str(&q);
                }
            }
            ("InvokeFunction", arn)
        }
        (["2015-03-31", "functions", name, "policy"], "POST") => ("AddPermission", function(name)?),
        (["2015-03-31", "functions", name, "policy"], "GET") => ("GetPolicy", function(name)?),
        (["2015-03-31", "functions", name, "policy", _], "DELETE") => {
            ("RemovePermission", function(name)?)
        }
        (["2015-03-31", "functions", name, "configuration"], "GET") => {
            ("GetFunctionConfiguration", function(name)?)
        }
        (["2015-03-31", "functions", name, "configuration"], "PUT") => {
            ("UpdateFunctionConfiguration", function(name)?)
        }
        (["2015-03-31", "functions", name, "code"], "PUT") => {
            ("UpdateFunctionCode", function(name)?)
        }
        (["2015-03-31", "functions", name, "versions"], "POST") => {
            ("PublishVersion", function(name)?)
        }
        (["2015-03-31", "functions", name, "versions"], "GET") => {
            ("ListVersionsByFunction", function(name)?)
        }
        (["2015-03-31", "functions", name, "aliases"], "POST") => ("CreateAlias", function(name)?),
        (["2015-03-31", "functions", name, "aliases"], "GET") => ("ListAliases", function(name)?),
        (["2015-03-31", "functions", name, "aliases", _], "GET") => ("GetAlias", function(name)?),
        (["2015-03-31", "functions", name, "aliases", _], "PUT") => {
            ("UpdateAlias", function(name)?)
        }
        (["2015-03-31", "functions", name, "aliases", _], "DELETE") => {
            ("DeleteAlias", function(name)?)
        }
        (["2020-06-30", "functions", name, "code-signing-config"], "GET") => {
            ("GetFunctionCodeSigningConfig", function(name)?)
        }
        (["2017-10-31", "functions", name, "concurrency"], "PUT") => {
            ("PutFunctionConcurrency", function(name)?)
        }
        (["2017-10-31", "functions", name, "concurrency"], "GET") => {
            ("GetFunctionConcurrency", function(name)?)
        }
        (["2017-10-31", "functions", name, "concurrency"], "DELETE") => {
            ("DeleteFunctionConcurrency", function(name)?)
        }
        (["2021-10-31", "functions", name, "url"], "POST") => {
            ("CreateFunctionUrlConfig", function(name)?)
        }
        (["2021-10-31", "functions", name, "url"], "GET") => {
            ("GetFunctionUrlConfig", function(name)?)
        }
        (["2021-10-31", "functions", name, "url"], "PUT") => {
            ("UpdateFunctionUrlConfig", function(name)?)
        }
        (["2021-10-31", "functions", name, "url"], "DELETE") => {
            ("DeleteFunctionUrlConfig", function(name)?)
        }
        (["2019-09-25", "functions", name, "event-invoke-config"], "PUT") => {
            ("PutFunctionEventInvokeConfig", function(name)?)
        }
        (["2019-09-25", "functions", name, "event-invoke-config"], "POST") => {
            ("UpdateFunctionEventInvokeConfig", function(name)?)
        }
        (["2019-09-25", "functions", name, "event-invoke-config"], "GET") => {
            ("GetFunctionEventInvokeConfig", function(name)?)
        }
        (["2019-09-25", "functions", name, "event-invoke-config"], "DELETE") => {
            ("DeleteFunctionEventInvokeConfig", function(name)?)
        }
        (["2019-09-25", "functions", name, "event-invoke-config", "list"], "GET") => {
            ("ListFunctionEventInvokeConfigs", function(name)?)
        }
        (["2018-10-31", "layers"], "GET") => ("ListLayers", "*".into()),
        (["2018-10-31", "layers", name, "versions"], "POST") => {
            ("PublishLayerVersion", layer(name))
        }
        (["2018-10-31", "layers", name, "versions"], "GET") => ("ListLayerVersions", layer(name)),
        (["2018-10-31", "layers", name, "versions", version], "GET") => {
            ("GetLayerVersion", format!("{}:{version}", layer(name)))
        }
        (["2018-10-31", "layers", name, "versions", version], "DELETE") => {
            ("DeleteLayerVersion", format!("{}:{version}", layer(name)))
        }
        (["2019-09-30", "functions", name, "provisioned-concurrency"], "PUT") => {
            ("PutProvisionedConcurrencyConfig", function(name)?)
        }
        (["2019-09-30", "functions", name, "provisioned-concurrency"], "GET")
            if query_value(req.uri.query().unwrap_or(""), "List").is_some() =>
        {
            ("ListProvisionedConcurrencyConfigs", function(name)?)
        }
        (["2019-09-30", "functions", name, "provisioned-concurrency"], "GET") => {
            ("GetProvisionedConcurrencyConfig", function(name)?)
        }
        (["2019-09-30", "functions", name, "provisioned-concurrency"], "DELETE") => {
            ("DeleteProvisionedConcurrencyConfig", function(name)?)
        }
        (["2015-03-31", "event-source-mappings"], "POST") => {
            let body = parse_json(&req.body)?;
            let name = body
                .get("FunctionName")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    LambdaError::InvalidParameterValue("FunctionName is required".into())
                })?;
            context.insert("lambda:FunctionArn".into(), vec![function(name)?]);
            ("CreateEventSourceMapping", "*".into())
        }
        (["2015-03-31", "event-source-mappings"], "GET") => ("ListEventSourceMappings", "*".into()),
        (["2015-03-31", "event-source-mappings", uuid], "GET") => {
            ("GetEventSourceMapping", mapping_arn(req, uuid))
        }
        (["2015-03-31", "event-source-mappings", uuid], "PUT") => {
            ("UpdateEventSourceMapping", mapping_arn(req, uuid))
        }
        (["2015-03-31", "event-source-mappings", uuid], "DELETE") => {
            ("DeleteEventSourceMapping", mapping_arn(req, uuid))
        }
        (["2017-03-31", "tags", arn], "GET") => ("ListTags", percent_decode_path(arn)),
        (["2017-03-31", "tags", arn], "POST") => ("TagResource", percent_decode_path(arn)),
        (["2017-03-31", "tags", arn], "DELETE") => ("UntagResource", percent_decode_path(arn)),
        _ => return Ok(()), // Unsupported routes have no service effect.
    };
    let authorize = |action: &str, resource: String, context: BTreeMap<String, Vec<String>>| {
        evaluator
            .authorize(AuthorizationRequest {
                request_identity: identity.clone(),
                delegated_identity: None,
                source_service: "lambda".into(),
                action: action.into(),
                resource,
                context,
            })
            .map_err(|_| denied())
    };
    authorize(&format!("lambda:{action}"), resource, context)?;
    // AWS requires PassRole when creating a function or changing its execution role.
    if action == "CreateFunction" || action == "UpdateFunctionConfiguration" {
        let body = parse_json(&req.body)?;
        if let Some(role) = body.get("Role").and_then(Value::as_str) {
            let mut conditions = BTreeMap::new();
            conditions.insert(
                "iam:PassedToService".into(),
                vec!["lambda.amazonaws.com".into()],
            );
            authorize("iam:PassRole", role.into(), conditions)?;
        }
    }
    Ok(())
}

fn mapping_arn(req: &ServiceRequest, uuid: &str) -> String {
    format!(
        "arn:aws:lambda:{}:{}:event-source-mapping:{uuid}",
        req.region, req.account_id
    )
}
