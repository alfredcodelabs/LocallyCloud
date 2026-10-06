//! IAM action/resource gate for the public Lambda REST API.

use std::collections::BTreeMap;

use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::RequestIdentity;

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
        .get("x-locallycloud-verified-internal-scope")
        .is_some_and(|v| v == "1")
    {
        return Ok(());
    }
    let denied = || {
        LambdaError::AccessDenied("User is not authorized to perform this Lambda operation".into())
    };
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
        (["2019-09-30", "functions", name, "concurrency"], "GET") => {
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
    context.insert("aws:requestedregion".into(), vec![req.region.clone()]);
    if action == "CreateEventSourceMapping" || action == "TagResource" {
        let input = parse_json(&req.body)?;
        if let Some(tags) = input.get("Tags") {
            let tags = crate::esm::parse_tags(Some(tags))?;
            context.insert("aws:tagkeys".into(), tags.keys().cloned().collect());
            for (key, value) in tags {
                context.insert(
                    format!("aws:requesttag/{}", key.to_ascii_lowercase()),
                    vec![value],
                );
            }
        }
    }
    if action == "UntagResource" {
        context.insert(
            "aws:tagkeys".into(),
            query_values(req.uri.query().unwrap_or(""), "tagKeys"),
        );
    }
    let mapping_prefix = format!(
        "arn:aws:lambda:{}:{}:event-source-mapping:",
        req.region, req.account_id
    );
    let tags = if let Some(uuid) = resource.strip_prefix(&mapping_prefix) {
        handler
            .esm
            .get(uuid)
            .filter(|mapping| {
                mapping.function_arn.starts_with(&format!(
                    "arn:aws:lambda:{}:{}:function:",
                    req.region, req.account_id
                ))
            })
            .map(|mapping| mapping.tags)
    } else if let Some(name) = resource.strip_prefix(&format!(
        "arn:aws:lambda:{}:{}:function:",
        req.region, req.account_id
    )) {
        handler.store.get_tags(
            &req.account_id,
            &req.region,
            name.split(':').next().unwrap_or(name),
        )
    } else {
        None
    };
    for (key, value) in tags.unwrap_or_default() {
        if !key.to_ascii_lowercase().starts_with("aws:") {
            context.insert(
                format!("aws:resourcetag/{}", key.to_ascii_lowercase()),
                vec![value],
            );
        }
    }
    let context: BTreeMap<_, _> = context
        .into_iter()
        .map(|(key, value)| (key.to_ascii_lowercase(), value))
        .collect();
    authorize(&format!("lambda:{action}"), resource, context.clone())?;
    if action == "CreateEventSourceMapping" {
        let input = parse_json(&req.body)?;
        if input
            .get("Tags")
            .and_then(Value::as_object)
            .is_some_and(|tags| !tags.is_empty())
        {
            authorize("lambda:TagResource", "*".into(), context)?;
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::integration::authorization::{
        AuthorizationError, AuthorizationEvaluator,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Default)]
    struct TaggedPolicy {
        dependent: AtomicBool,
        seen: std::sync::Mutex<Vec<AuthorizationRequest>>,
    }
    impl AuthorizationEvaluator for TaggedPolicy {
        fn strict_sigv4_required(&self) -> bool {
            true
        }
        fn authorize(&self, req: AuthorizationRequest) -> Result<(), AuthorizationError> {
            let request_tag = req.context.get("aws:requesttag/team");
            // Actual IfExists behavior: missing permits, present wrong value denies.
            let valid = request_tag.is_none_or(|values| values == &vec!["orders".to_string()]);
            let dependent = req.action != "lambda:TagResource"
                || req.resource != "*"
                || self.dependent.load(Ordering::SeqCst);
            self.seen.lock().unwrap().push(req);
            if valid && dependent {
                Ok(())
            } else {
                Err(AuthorizationError::Denied)
            }
        }
    }
    fn request(method: Method, path: &str, body: &str) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        headers.insert("authorization","AWS4-HMAC-SHA256 Credential=KEY/20261006/us-east-1/lambda/aws4_request, SignedHeaders=host, Signature=test".parse().unwrap());
        ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers,
            body: Bytes::from(body.to_owned()),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "tags-policy".into(),
        }
    }
    #[tokio::test]
    async fn esm_tags_iam_receives_real_context_and_denial_has_no_effect() {
        let registry = Arc::new(ServiceRegistry::new());
        let handler = Arc::new(LambdaHandler::with_parts(Arc::downgrade(&registry), None));
        let policy = Arc::new(TaggedPolicy::default());
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            locallycloud_core::registry::ServiceMetadata::new(
                locallycloud_core::registry::AwsProtocol::Query,
                None,
            ),
            handler.clone(),
            policy.clone(),
        );
        let create = request(
            Method::POST,
            "/2015-03-31/event-source-mappings",
            r#"{"FunctionName":"fn","Tags":{"team":"orders"}}"#,
        );
        assert!(check(&handler, &create).is_err());
        policy.dependent.store(true, Ordering::SeqCst);
        check(&handler, &create).unwrap();
        let seen = policy.seen.lock().unwrap().last().unwrap().clone();
        assert_eq!(
            seen.context["lambda:functionarn"],
            vec!["arn:aws:lambda:us-east-1:000000000000:function:fn"]
        );
        assert_eq!(seen.context["aws:requesttag/team"], vec!["orders"]);
        assert_eq!(seen.context["aws:tagkeys"], vec!["team"]);
        assert_eq!(seen.context["aws:requestedregion"], vec!["us-east-1"]);
        let mapping=create_mapping("us-east-1","arn:aws:lambda:us-east-1:000000000000:function:fn",&json!({"EventSourceArn":"arn:aws:sqs:us-east-1:000000000000:q","Tags":{"owner":"orders"}})).unwrap();
        let resource = format!(
            "arn:aws:lambda:us-east-1:000000000000:event-source-mapping:{}",
            mapping.uuid
        );
        let path = format!("/2017-03-31/tags/{}", resource.replace(':', "%3A"));
        handler.esm.insert(mapping.clone()).unwrap();
        let denied = handler
            .handle(request(Method::POST, &path, r#"{"Tags":{"team":"evil"}}"#))
            .await;
        assert_eq!(denied.status(), 403);
        assert!(!handler
            .esm
            .get(&mapping.uuid)
            .unwrap()
            .tags
            .contains_key("team"));
        assert_eq!(
            handler
                .handle(request(
                    Method::POST,
                    &path,
                    r#"{"Tags":{"team":"orders"}}"#
                ))
                .await
                .status(),
            204
        );
        let seen = policy.seen.lock().unwrap().last().unwrap().clone();
        assert_eq!(seen.resource, resource);
        assert_eq!(seen.context["aws:resourcetag/owner"], vec!["orders"]);
        let untag = request(Method::DELETE, &format!("{path}?tagKeys=team"), "");
        check(&handler, &untag).unwrap();
        assert_eq!(
            policy.seen.lock().unwrap().last().unwrap().context["aws:tagkeys"],
            vec!["team"]
        );
    }
}
