//! IAM action/resource gate for the public Lambda REST API.

use std::collections::BTreeMap;

use locallycloud_core::integration::authorization::{verified_caller, AuthorizationRequest};
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
    let internal = req
        .headers
        .get("x-locallycloud-verified-internal-scope")
        .is_some_and(|v| v == "1");
    let denied = || {
        LambdaError::AccessDenied("User is not authorized to perform this Lambda operation".into())
    };
    let external = req
        .headers
        .get("x-locallycloud-verified-external-sigv4")
        .is_some_and(|v| v == "1");
    let service_principal = if internal && !external {
        req.headers
            .get(locallycloud_core::integration::identity::PRINCIPAL_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|principal| principal.strip_suffix(".amazonaws.com"))
            .filter(|service| !service.is_empty() && !service.contains('/'))
            .map(|service| {
                locallycloud_core::integration::identity::CallerIdentity::ServicePrincipal {
                    service: service.into(),
                }
            })
    } else {
        None
    };
    let (identity, delegated_identity) = if let Some(principal) = service_principal {
        (
            RequestIdentity {
                account_id: req.account_id.clone(),
                access_key_id: None,
                arn: None,
            },
            Some(principal),
        )
    } else {
        verified_caller(evaluator.as_ref(), req).map_err(|_| denied())?
    };
    let segments: Vec<&str> = req.uri.path().trim_matches('/').split('/').collect();
    let method = req.method.as_str();
    let function = |name: &str| -> Result<String, LambdaError> {
        let name = resolve_function_name(&percent_decode_path(name), &req.region)?;
        Ok(function_arn(&req.region, &req.account_id, &name))
    };
    let event_function = |name: &str| -> Result<String, LambdaError> {
        let reference = crate::event_invoke::reference(
            &percent_decode_path(name),
            query_value(req.uri.query().unwrap_or(""), "Qualifier").as_deref(),
        )?;
        let base = function(name)?;
        let decoded = percent_decode_path(name);
        let has_embedded = if decoded.starts_with("arn:") {
            decoded.split(':').nth(7).is_some()
        } else if decoded.contains(":function:") {
            decoded.split(':').nth(3).is_some()
        } else {
            decoded.contains(':')
        };
        if !has_embedded && query_value(req.uri.query().unwrap_or(""), "Qualifier").is_none() {
            return Ok(base);
        }
        let qualifier = reference.rsplit(':').next().ok_or_else(|| {
            LambdaError::InvalidParameterValue("Invalid function qualifier".into())
        })?;
        Ok(format!("{base}:{qualifier}"))
    };
    let layer = |name: &str| -> String {
        format!(
            "arn:aws:lambda:{}:{}:layer:{}",
            req.region,
            req.account_id,
            percent_decode_path(name)
        )
    };
    let mut context =
        locallycloud_core::integration::request_context::verified_request_context(req);
    let (action, resource): (&str, String) = match (segments.as_slice(), method) {
        (["2016-08-19", "account-settings"], "GET") => ("GetAccountSettings", "*".into()),
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
            ("InvokeFunction", event_function(name)?)
        }
        (["2015-03-31", "functions", name, "policy"], "POST") => {
            ("AddPermission", event_function(name)?)
        }
        (["2015-03-31", "functions", name, "policy"], "GET") => {
            ("GetPolicy", event_function(name)?)
        }
        (["2015-03-31", "functions", name, "policy", _], "DELETE") => {
            ("RemovePermission", event_function(name)?)
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
            ("PutFunctionEventInvokeConfig", event_function(name)?)
        }
        (["2019-09-25", "functions", name, "event-invoke-config"], "POST") => {
            ("UpdateFunctionEventInvokeConfig", event_function(name)?)
        }
        (["2019-09-25", "functions", name, "event-invoke-config"], "GET") => {
            ("GetFunctionEventInvokeConfig", event_function(name)?)
        }
        (["2019-09-25", "functions", name, "event-invoke-config"], "DELETE") => {
            ("DeleteFunctionEventInvokeConfig", event_function(name)?)
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
                delegated_identity: delegated_identity.clone(),
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
    let mut context: BTreeMap<_, _> = context
        .into_iter()
        .map(|(key, value)| (key.to_ascii_lowercase(), value))
        .collect();
    if action == "InvokeFunction" {
        let name = resource.split(':').nth(6).ok_or_else(denied)?;
        let document = handler
            .store
            .permissions_for_resource(&req.account_id, &req.region, name, &resource)
            .filter(|statements| !statements.is_empty())
            .map(|statements| json!({"Version":"2012-10-17", "Statement":statements}).to_string());
        if internal {
            for (header, key) in [
                ("x-locallycloud-source-arn", "aws:sourcearn"),
                ("x-locallycloud-source-account", "aws:sourceaccount"),
            ] {
                if let Some(value) = req
                    .headers
                    .get(header)
                    .and_then(|value| value.to_str().ok())
                {
                    context.insert(key.into(), vec![value.into()]);
                }
            }
        }
        evaluator
            .authorize_resource_policy(
                AuthorizationRequest {
                    request_identity: identity.clone(),
                    delegated_identity: delegated_identity.clone(),
                    source_service: "lambda".into(),
                    action: "lambda:InvokeFunction".into(),
                    resource,
                    context: context.clone(),
                },
                document.as_deref(),
                &req.account_id,
            )
            .map_err(|_| denied())?;
    } else {
        if matches!(
            delegated_identity,
            Some(locallycloud_core::integration::identity::CallerIdentity::ServicePrincipal { .. })
        ) {
            return Err(denied());
        }
        authorize(&format!("lambda:{action}"), resource, context.clone())?;
    }
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
            let mut conditions =
                locallycloud_core::integration::request_context::verified_request_context(req);
            conditions.insert(
                "iam:passedtoservice".into(),
                vec!["lambda.amazonaws.com".into()],
            );
            authorize("iam:PassRole", role.into(), conditions)?;
            evaluator.authorize_service_role_trust(
                locallycloud_core::integration::authorization::ServiceRoleAuthorizationRequest {
                    delegated_caller: locallycloud_core::integration::identity::trusted_role(req),
                    caller_context: BTreeMap::new(),
                    caller: identity.clone(),
                    role_arn: role.into(),
                    service_principal: "lambda.amazonaws.com".into(),
                    source_arn: None,
                    action: "lambda:InvokeFunction".into(),
                    resource: "*".into(),
                }
            ).map_err(|_| LambdaError::InvalidParameterValue(
                "The role defined for the function cannot be assumed by Lambda".into()
            ))?;
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

    #[test]
    fn invocation_composes_resource_grants_and_identity_denies() {
        use locallycloud_iam_sts::{
            enforcement::EnforcementMode, model::IamRole, store::IamStore, sts::SessionStore,
        };
        let account = "000000000000";
        let role_arn = format!("arn:aws:iam::{account}:role/invoker");
        let registry = Arc::new(ServiceRegistry::new());
        let store = Arc::new(IamStore::new());
        let sessions = Arc::new(SessionStore::new());
        store.create_role(
            account,
            IamRole {
                role_name: "invoker".into(),
                role_id: "AROAEXAMPLE".into(),
                arn: role_arn.clone(),
                path: "/".into(),
                create_date: "2026-01-01T00:00:00Z".into(),
                assume_role_policy_document: "{}".into(),
                description: None,
                max_session_duration: 3600,
                tags: BTreeMap::new(),
                attached_policies: Vec::new(),
                inline_policies: BTreeMap::new(),
                permission_boundary: None,
            },
        );
        let credentials = locallycloud_iam_sts::sts::issue_service_role_credentials(
            &store, &sessions, account, &role_arn,
        )
        .unwrap();
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            store.clone(),
            sessions,
            EnforcementMode::Strict,
        );
        let handler = LambdaHandler::with_parts(Arc::downgrade(&registry), None);
        create_function(&handler.store, "us-east-1", account, &json!({
            "FunctionName":"fn", "Role":role_arn, "Runtime":"python3.12", "Handler":"index.handler",
            "Code":{"ZipFile":"UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA=="}
        }), None).unwrap();
        let mut invoke = request(Method::POST, "/2015-03-31/functions/fn/invocations", "");
        invoke.headers.insert(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential={}/20261006/us-east-1/lambda/aws4_request",
                credentials.access_key_id
            )
            .parse()
            .unwrap(),
        );
        assert!(check(&handler, &invoke).is_err());
        store.update_role(account, "invoker", |role| {
            role.inline_policies.insert(
                "invoke".into(),
                json!({"Statement":{
                    "Effect":"Allow", "Action":"lambda:InvokeFunction", "Resource":"*"
                }})
                .to_string(),
            );
        });
        check(&handler, &invoke).unwrap();
        let mut scoped_operator = invoke.clone();
        scoped_operator
            .headers
            .remove("x-locallycloud-verified-external-sigv4");
        scoped_operator.headers.insert(
            "x-locallycloud-verified-internal-scope",
            "1".parse().unwrap(),
        );
        let caller = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .unwrap()
            .resolve_caller_arn(&RequestIdentity {
                account_id: account.into(),
                access_key_id: Some(credentials.access_key_id.clone()),
                arn: None,
            })
            .unwrap()
            .unwrap();
        scoped_operator.headers.insert(
            locallycloud_core::integration::identity::PRINCIPAL_HEADER,
            caller.parse().unwrap(),
        );
        check(&handler, &scoped_operator).unwrap();
        let mut forged = scoped_operator.clone();
        forged.headers.insert(
            locallycloud_core::integration::identity::PRINCIPAL_HEADER,
            "arn:aws:iam::000000000000:user/other".parse().unwrap(),
        );
        assert!(check(&handler, &forged).is_err());
        scoped_operator.headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        assert!(check(&handler, &scoped_operator).is_err());
        scoped_operator
            .headers
            .remove("x-locallycloud-verified-external-sigv4");
        store.update_role(account, "invoker", |role| role.inline_policies.clear());
        handler.store.add_permission(account, "us-east-1", "fn", "role", json!({
            "Effect":"Allow", "Principal":{"AWS":role_arn}, "Action":"lambda:InvokeFunction",
            "Resource":function_arn("us-east-1", account, "fn")
        })).unwrap();
        check(&handler, &invoke).unwrap();
        let mut partial = invoke.clone();
        partial.uri = "/2015-03-31/functions/000000000000:function:fn/invocations"
            .parse()
            .unwrap();
        check(&handler, &partial).unwrap();
        let mut other = invoke.clone();
        other.uri = "/2015-03-31/functions/fn".parse().unwrap();
        other.method = Method::GET;
        assert!(check(&handler, &other).is_err());
        store.update_role(account, "invoker", |role| {
            role.inline_policies.insert(
                "deny".into(),
                json!({"Statement":{
                    "Effect":"Deny", "Action":"lambda:InvokeFunction", "Resource":"*"
                }})
                .to_string(),
            );
        });
        assert!(check(&handler, &invoke).is_err());
        assert!(check(&handler, &scoped_operator).is_err());
    }

    #[tokio::test]
    async fn foreign_and_malformed_function_arns_never_mutate_local_collisions() {
        let handler = LambdaHandler::default();
        let account = "000000000000";
        create_function(
            &handler.store,
            "us-east-1",
            account,
            &json!({
                "FunctionName":"fn", "Role":format!("arn:aws:iam::{account}:role/execution"),
                "Runtime":"python3.12", "Handler":"index.handler",
                "Code":{"ZipFile":"UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA=="}
            }),
            None,
        )
        .unwrap();
        for reference in ["fn", "000000000000:function:fn"] {
            for method in [Method::GET, Method::POST, Method::DELETE] {
                let response = handler
                    .handle(request(
                        method,
                        &format!("/2017-03-31/tags/{reference}"),
                        "{\"Tags\":{\"critical\":\"changed\"}}",
                    ))
                    .await;
                assert_eq!(response.status(), 400);
            }
            assert!(handler
                .store
                .get_tags(account, "us-east-1", "fn")
                .unwrap()
                .is_empty());
        }

        for qualifier in ["1", "live", "$LATEST"] {
            for (method, expected) in [
                (Method::GET, 501),
                (Method::POST, 400),
                (Method::DELETE, 400),
            ] {
                let response = handler.handle(request(method,
                    &format!("/2017-03-31/tags/arn:aws:lambda:us-east-1:{account}:function:fn:{qualifier}"),
                    "{\"Tags\":{\"critical\":\"changed\"}}" )).await;
                assert_eq!(response.status().as_u16(), expected);
                assert!(handler
                    .store
                    .get_tags(account, "us-east-1", "fn")
                    .unwrap()
                    .is_empty());
            }
        }
        for (reference, expected) in [
            ("arn:aws:lambda:us-east-1:111111111111:function:fn", 501),
            ("111111111111:function:fn", 501),
            ("arn:aws:s3:us-east-1:000000000000:function:fn", 400),
            ("arn:other:lambda:us-east-1:000000000000:function:fn", 400),
            ("arn:aws:lambda:us-east-1:bad:function:fn", 400),
        ] {
            for method in [Method::GET, Method::POST, Method::DELETE] {
                let response = handler
                    .handle(request(
                        method,
                        &format!("/2017-03-31/tags/{reference}?tagKeys=critical"),
                        "{\"Tags\":{\"critical\":\"changed\"}}",
                    ))
                    .await;
                assert_eq!(
                    response.status().as_u16(),
                    if reference.starts_with("arn:") {
                        expected
                    } else {
                        400
                    },
                    "tag ARN {reference}"
                );
                assert!(handler
                    .store
                    .get_tags(account, "us-east-1", "fn")
                    .unwrap()
                    .is_empty());
            }
            for method in [Method::GET, Method::DELETE] {
                let response = handler
                    .handle(request(
                        method,
                        &format!("/2015-03-31/functions/{reference}"),
                        "",
                    ))
                    .await;
                assert_eq!(response.status().as_u16(), expected, "{reference}");
                assert!(handler.store.get(account, "us-east-1", "fn").is_some());
            }
            let response = handler
                .handle(request(
                    Method::POST,
                    &format!("/2015-03-31/functions/{reference}/invocations"),
                    "{}",
                ))
                .await;
            assert_eq!(response.status().as_u16(), expected, "{reference}");
        }
    }

    #[test]
    fn internal_service_invocation_requires_matching_function_policy() {
        use locallycloud_iam_sts::{
            enforcement::EnforcementMode, store::IamStore, sts::SessionStore,
        };
        let account = "000000000000";
        let registry = Arc::new(ServiceRegistry::new());
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            Arc::new(IamStore::new()),
            Arc::new(SessionStore::new()),
            EnforcementMode::Strict,
        );
        let handler = LambdaHandler::with_parts(Arc::downgrade(&registry), None);
        create_function(&handler.store, "us-east-1", account, &json!({
            "FunctionName":"fn", "Role":format!("arn:aws:iam::{account}:role/execution"), "Runtime":"python3.12", "Handler":"index.handler",
            "Code":{"ZipFile":"UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA=="}
        }), None).unwrap();
        let mut invoke = request(Method::POST, "/2015-03-31/functions/fn/invocations", "");
        invoke
            .headers
            .remove("x-locallycloud-verified-external-sigv4");
        invoke.headers.insert(
            "x-locallycloud-verified-internal-scope",
            "1".parse().unwrap(),
        );
        invoke.headers.insert(
            "x-locallycloud-caller-principal",
            "events.amazonaws.com".parse().unwrap(),
        );
        let rule = format!("arn:aws:events:us-east-1:{account}:rule/allowed");
        invoke
            .headers
            .insert("x-locallycloud-source-arn", rule.parse().unwrap());
        assert!(check(&handler, &invoke).is_err());
        handler.store.add_permission(account, "us-east-1", "fn", "events", json!({
            "Effect":"Allow", "Principal":{"Service":"events.amazonaws.com"}, "Action":"lambda:InvokeFunction",
            "Resource":function_arn("us-east-1", account, "fn"), "Condition":{"ArnEquals":{"aws:SourceArn":rule}}
        })).unwrap();
        check(&handler, &invoke).unwrap();
        invoke.headers.insert(
            "x-locallycloud-source-arn",
            "arn:aws:events:us-east-1:000000000000:rule/other"
                .parse()
                .unwrap(),
        );
        assert!(check(&handler, &invoke).is_err());
        invoke
            .headers
            .remove("x-locallycloud-verified-internal-scope");
        assert!(check(&handler, &invoke).is_err());
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
