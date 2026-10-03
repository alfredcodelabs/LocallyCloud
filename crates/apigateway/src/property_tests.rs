use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use proptest::prelude::*;
use serde_json::{json, Map, Value};

use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{Disposition, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::error::ApiGwError;
use crate::execute::{best_match, http_route, select_integration_response, substitute_uri};
use crate::proxy_event::{build_event, interpret_response, EventInput};
use crate::service::{custom_domain_target, ApiGwHandler};
use crate::store::{ApiGwStore, RestApiRecord};
use crate::vtl::{ContextBinding, InputBinding, UtilBinding, VtlContext, VtlEngine};
use crate::websocket::{
    delete_connection, get_connection, post_to_connection, register_test_connection,
    MAX_CONNECTION_PAYLOAD_BYTES,
};

const ACCOUNT: &str = "000000000000";
const REGION: &str = "us-east-1";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("property runtime")
}

fn install_dispatcher(registry: &Arc<ServiceRegistry>, account: &str) {
    registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
        registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: Duration::from_secs(1),
        },
        LegacyHealth::new(true),
        REGION.into(),
        account.into(),
    )));
}

struct LambdaProbe {
    allow_authorizer: bool,
    authorizer_calls: AtomicUsize,
    integration_calls: AtomicUsize,
}

impl LambdaProbe {
    fn new(allow_authorizer: bool) -> Self {
        Self {
            allow_authorizer,
            authorizer_calls: AtomicUsize::new(0),
            integration_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl NativeHandler for LambdaProbe {
    async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
        let authorizer = request.uri.path().contains("/functions/authorizer/");
        let value = if authorizer {
            self.authorizer_calls.fetch_add(1, Ordering::SeqCst);
            json!({
                "principalId": "property-user",
                "policyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Action": "execute-api:Invoke",
                        "Effect": if self.allow_authorizer { "Allow" } else { "Deny" },
                        "Resource": "*"
                    }]
                },
                "context": { "source": "property" }
            })
        } else {
            self.integration_calls.fetch_add(1, Ordering::SeqCst);
            json!({ "statusCode": 200, "body": "integration-ok" })
        };
        http::Response::builder()
            .status(200)
            .body(Body::from(value.to_string()))
            .expect("probe response")
    }
}

fn handler_with_probe(allow: bool) -> (ApiGwHandler, Arc<LambdaProbe>, Arc<ServiceRegistry>) {
    let registry = ServiceRegistry::with_known_services();
    let probe = Arc::new(LambdaProbe::new(allow));
    registry.register_native(
        ServiceName::new("lambda"),
        ServiceMetadata::new(locallycloud_core::registry::AwsProtocol::RestJson, None),
        probe.clone(),
    );
    install_dispatcher(&registry, ACCOUNT);
    let handler = ApiGwHandler::new(Arc::downgrade(&registry));
    (handler, probe, registry)
}

fn proxy_method(extra: Value) -> Value {
    let mut method = json!({
        "httpMethod": "GET",
        "authorizationType": "NONE",
        "methodIntegration": {
            "type": "AWS_PROXY",
            "uri": "integration",
            "httpMethod": "POST",
            "timeoutInMillis": 29000
        }
    });
    if let (Some(target), Some(extra)) = (method.as_object_mut(), extra.as_object()) {
        target.extend(extra.clone());
    }
    method
}

fn install_rest_api(
    handler: &ApiGwHandler,
    api_id: &str,
    stage: &str,
    method: Value,
    authorizer: Option<Value>,
    validator: Option<Value>,
) {
    let mut record = RestApiRecord {
        api: json!({ "id": api_id, "name": "property-api" }),
        ..RestApiRecord::default()
    };
    record.resources.insert(
        "resource".into(),
        json!({
            "id": "resource",
            "path": "/items",
            "resourceMethods": { "GET": method }
        }),
    );
    record
        .stages
        .insert(stage.into(), json!({ "stageName": stage, "variables": {} }));
    if let Some(authorizer) = authorizer {
        record.authorizers.insert("auth".into(), authorizer);
    }
    if let Some(validator) = validator {
        record
            .request_validators
            .insert("validator".into(), validator);
    }
    handler.store().insert_rest(ACCOUNT, REGION, api_id, record);
}

async fn invoke_rest(
    handler: &ApiGwHandler,
    api_id: &str,
    stage: &str,
    token: Option<&str>,
) -> axum::response::Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        "host",
        HeaderValue::from_str(&format!("{api_id}.execute-api.{REGION}.amazonaws.com")).unwrap(),
    );
    if let Some(token) = token {
        headers.insert("authorization", HeaderValue::from_str(token).unwrap());
    }
    handler
        .handle(ServiceRequest {
            method: Method::GET,
            uri: format!("/{stage}/items").parse().unwrap(),
            headers,
            body: Bytes::new(),
            region: REGION.into(),
            account_id: ACCOUNT.into(),
            request_id: "property-request".into(),
        })
        .await
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn property_01_native_dispatch_no_proxy(service in prop::sample::select(vec!["apigateway", "apigatewayv2", "execute-api"])) {
        let registry = Arc::new(ServiceRegistry::new());
        crate::register(&registry);
        let name = ServiceName::new(service);
        prop_assert_eq!(registry.disposition(&name), Disposition::Native);
        prop_assert!(registry.native_handler(&name).is_some());
    }

    #[test]
    fn property_02_control_plane_errors_deserialize(kind in 0usize..9, message in "[A-Za-z0-9 ]{1,24}") {
        let error = match kind {
            0 => ApiGwError::NotFound(message.clone()),
            1 => ApiGwError::BadRequest(message.clone()),
            2 => ApiGwError::Conflict(message.clone()),
            3 => ApiGwError::LimitExceeded(message.clone()),
            4 => ApiGwError::Unauthorized(message.clone()),
            5 => ApiGwError::TooManyRequests(message.clone()),
            6 => ApiGwError::Internal(message.clone()),
            7 => ApiGwError::Gone(message.clone()),
            _ => ApiGwError::PayloadTooLarge(message.clone()),
        };
        let expected_code = error.code();
        let expected_status = error.http_status();
        let response = error.into_response("property-request");
        prop_assert_eq!(response.status().as_u16(), expected_status);
        prop_assert_eq!(response.headers()["x-amzn-errortype"].to_str().unwrap(), expected_code);
        let body = runtime().block_on(axum::body::to_bytes(response.into_body(), usize::MAX)).unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        prop_assert_eq!(parsed["message"].as_str(), Some(message.as_str()));
    }

    #[test]
    fn property_03_v1_path_precedence(literal in "[a-z]{1,8}", other in "[a-z]{1,8}") {
        prop_assume!(literal != other);
        let values = [
            ("/{proxy+}".to_string(), json!("greedy")),
            ("/items/{id}".to_string(), json!("param")),
            (format!("/items/{literal}"), json!("literal")),
        ];
        let literal_match = best_match(
            values.iter().map(|(path, value)| (path.as_ref(), value)),
            &format!("/items/{literal}"),
        ).unwrap();
        prop_assert_eq!(literal_match.value, json!("literal"));
        let param_match = best_match(
            values.iter().map(|(path, value)| (path.as_ref(), value)),
            &format!("/items/{other}"),
        ).unwrap();
        prop_assert_eq!(param_match.value, json!("param"));
    }

    #[test]
    fn property_04_v2_specific_route_precedes_default(segment in "[a-z]{1,8}") {
        let routes = BTreeMap::from([
            ("specific".into(), json!({ "routeKey": format!("GET /{segment}") })),
            ("default".into(), json!({ "routeKey": "$default" })),
        ]);
        let expected = format!("GET /{segment}");
        let matched = http_route(&routes, &Method::GET, &format!("/{segment}")).unwrap();
        prop_assert_eq!(matched.value["routeKey"].as_str(), Some(expected.as_str()));
        let fallback = http_route(&routes, &Method::POST, "/unmatched").unwrap();
        prop_assert_eq!(&fallback.value["routeKey"], "$default");
        let no_default = BTreeMap::from([("specific".into(), routes["specific"].clone())]);
        prop_assert!(http_route(&no_default, &Method::POST, "/unmatched").is_none());
    }

    #[test]
    fn property_05_v1_event_keeps_last_and_all_values(values in prop::collection::vec("[a-z0-9]{1,8}", 1..8)) {
        let mut headers = HeaderMap::new();
        for value in &values {
            headers.append("x-property", HeaderValue::from_str(value).unwrap());
        }
        let raw_query = values.iter().map(|value| format!("item={value}")).collect::<Vec<_>>().join("&");
        let event = build_event("1.0", &EventInput {
            method: "GET", host: "api.execute-api.local", stage: "prod", raw_path: "/prod/items",
            resource_path: "/items", raw_query: &raw_query, route_key: "GET /items", headers: &headers,
            body: &[], account: ACCOUNT, api_id: "api", request_id: "request", jwt: None,
        });
        prop_assert_eq!(event["headers"]["x-property"].as_str(), values.last().map(String::as_str));
        prop_assert_eq!(event["multiValueHeaders"]["x-property"].clone(), json!(values));
        prop_assert_eq!(event["queryStringParameters"]["item"].as_str(), values.last().map(String::as_str));
        prop_assert_eq!(event["multiValueQueryStringParameters"]["item"].clone(), json!(values));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn property_06_payload_formats_have_only_contract_differences(body in "[A-Za-z0-9 ]{0,48}") {
        let mut headers = HeaderMap::new();
        headers.append("x-property", HeaderValue::from_static("one"));
        headers.append("x-property", HeaderValue::from_static("two"));
        headers.insert("cookie", HeaderValue::from_static("a=1; b=2"));
        let input = EventInput {
            method: "POST", host: "api.execute-api.local", stage: "prod", raw_path: "/prod/items",
            resource_path: "/items", raw_query: "tag=one&tag=two", route_key: "POST /items",
            headers: &headers, body: body.as_bytes(), account: ACCOUNT, api_id: "api",
            request_id: "request", jwt: None,
        };
        let v1 = build_event("1.0", &input);
        let v2 = build_event("2.0", &input);
        prop_assert_eq!(&v1["version"], "1.0");
        prop_assert_eq!(&v2["version"], "2.0");
        prop_assert_eq!(&v1["httpMethod"], "POST");
        prop_assert_eq!(&v2["requestContext"]["http"]["method"], "POST");
        prop_assert!(v1.get("multiValueHeaders").is_some());
        prop_assert!(v2.get("multiValueHeaders").is_none());
        prop_assert_eq!(&v2["cookies"], &json!(["a=1", "b=2"]));
        prop_assert_eq!(&v1["body"], &v2["body"]);
        prop_assert_eq!(&v1["isBase64Encoded"], &v2["isBase64Encoded"]);
    }

    #[test]
    fn property_07_body_round_trips(body in prop::collection::vec(any::<u8>(), 0..256)) {
        let headers = HeaderMap::new();
        let event = build_event("1.0", &EventInput {
            method: "POST", host: "api.execute-api.local", stage: "prod", raw_path: "/prod/items",
            resource_path: "/items", raw_query: "", route_key: "POST /items", headers: &headers,
            body: &body, account: ACCOUNT, api_id: "api", request_id: "request", jwt: None,
        });
        if body.is_empty() {
            prop_assert!(event["body"].is_null());
            prop_assert_eq!(&event["isBase64Encoded"], false);
        } else if let Ok(text) = std::str::from_utf8(&body) {
            prop_assert_eq!(event["body"].as_str(), Some(text));
            prop_assert_eq!(&event["isBase64Encoded"], false);
        } else {
            prop_assert_eq!(&event["isBase64Encoded"], true);
            let decoded = BASE64.decode(event["body"].as_str().unwrap()).unwrap();
            prop_assert_eq!(decoded, body);
        }
    }

    #[test]
    fn property_08_proxy_response_interpretation(status in 100u16..600, body in "[A-Za-z0-9 ]{0,48}", header in "[a-z0-9]{1,12}") {
        let output = json!({ "statusCode": status, "headers": { "x-property": header.clone() }, "body": body.clone() });
        let response = interpret_response("1.0", false, output.to_string().as_bytes());
        prop_assert_eq!(response.status, status);
        prop_assert_eq!(response.body, body.as_bytes());
        prop_assert!(response.headers.contains(&("x-property".into(), header)));

        let defaulted = interpret_response("1.0", false, json!({ "body": body.clone() }).to_string().as_bytes());
        prop_assert_eq!(defaulted.status, 200);
        prop_assert_eq!(defaulted.body, body.as_bytes());
        prop_assert_eq!(interpret_response("1.0", false, b"not-json").status, 502);
    }

    #[test]
    fn property_09_integration_response_selection_is_ordered_and_anchored(status in 400u16..500) {
        let responses: Map<String, Value> = [
            ("a-first".into(), json!({ "statusCode": "418", "selectionPattern": "4\\d\\d" })),
            ("b-second".into(), json!({ "statusCode": "499", "selectionPattern": "\\d+" })),
            ("default".into(), json!({ "statusCode": "200" })),
        ].into_iter().collect();
        let selected = select_integration_response(&responses, 500, &status.to_string()).unwrap();
        prop_assert_eq!(&selected["statusCode"], "418");
        let fallback = select_integration_response(&responses, 500, &format!("x{status}")).unwrap();
        prop_assert_eq!(&fallback["statusCode"], "200");
    }

    #[test]
    fn property_10_vtl_is_deterministic(body_value in "[A-Za-z0-9]{0,32}", stage_value in "[A-Za-z0-9]{0,16}") {
        let body = json!({ "value": body_value }).to_string();
        let empty = BTreeMap::new();
        let context_values = BTreeMap::from([("requestId".into(), json!("fixed-request"))]);
        let stage = BTreeMap::from([("target".into(), stage_value)]);
        let context = VtlContext {
            input: InputBinding { body: &body, querystring: &empty, path: &empty, header: &empty },
            util: UtilBinding,
            context: ContextBinding { values: &context_values },
            stage_variables: &stage,
        };
        let template = "$input.body|$stageVariables.target|$context.requestId";
        let first = VtlEngine::new().evaluate(template, &context).unwrap();
        let second = VtlEngine::new().evaluate(template, &context).unwrap();
        prop_assert_eq!(first, second);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn property_11_authorizer_deny_gates_integration(token in "Bearer [A-Za-z0-9]{1,24}") {
        let (handler, probe, _registry) = handler_with_probe(false);
        let method = proxy_method(json!({
            "authorizationType": "CUSTOM",
            "authorizerId": "auth"
        }));
        let authorizer = json!({
            "id": "auth",
            "type": "TOKEN",
            "identitySource": "method.request.header.Authorization",
            "authorizerUri": "authorizer",
            "authorizerResultTtlInSeconds": 0
        });
        install_rest_api(&handler, "deny-api", "prod", method, Some(authorizer), None);
        let response = runtime().block_on(invoke_rest(&handler, "deny-api", "prod", Some(&token)));
        prop_assert_eq!(response.status().as_u16(), 403);
        prop_assert_eq!(probe.authorizer_calls.load(Ordering::SeqCst), 1);
        prop_assert_eq!(probe.integration_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn property_12_authorizer_cache_keys_identity(token in "Bearer [A-Za-z0-9]{1,24}", ttl in 1u64..3600) {
        let (cached_handler, cached_probe, _cached_registry) = handler_with_probe(true);
        let cached_method = proxy_method(json!({ "authorizationType": "CUSTOM", "authorizerId": "auth" }));
        let cached_authorizer = json!({
            "id": "auth", "type": "TOKEN",
            "identitySource": "method.request.header.Authorization",
            "authorizerUri": "authorizer", "authorizerResultTtlInSeconds": ttl
        });
        install_rest_api(&cached_handler, "cached-api", "prod", cached_method, Some(cached_authorizer), None);
        let rt = runtime();
        let first = rt.block_on(invoke_rest(&cached_handler, "cached-api", "prod", Some(&token)));
        let second = rt.block_on(invoke_rest(&cached_handler, "cached-api", "prod", Some(&token)));
        prop_assert_eq!(first.status().as_u16(), 200);
        prop_assert_eq!(second.status().as_u16(), 200);
        prop_assert_eq!(cached_probe.authorizer_calls.load(Ordering::SeqCst), 1);
        prop_assert_eq!(cached_probe.integration_calls.load(Ordering::SeqCst), 2);

        let (uncached_handler, uncached_probe, _uncached_registry) = handler_with_probe(true);
        let uncached_method = proxy_method(json!({ "authorizationType": "CUSTOM", "authorizerId": "auth" }));
        let uncached_authorizer = json!({
            "id": "auth", "type": "TOKEN",
            "identitySource": "method.request.header.Authorization",
            "authorizerUri": "authorizer", "authorizerResultTtlInSeconds": 0
        });
        install_rest_api(&uncached_handler, "uncached-api", "prod", uncached_method, Some(uncached_authorizer), None);
        let first = rt.block_on(invoke_rest(&uncached_handler, "uncached-api", "prod", Some(&token)));
        let second = rt.block_on(invoke_rest(&uncached_handler, "uncached-api", "prod", Some(&token)));
        prop_assert_eq!(first.status().as_u16(), 200);
        prop_assert_eq!(second.status().as_u16(), 200);
        prop_assert_eq!(uncached_probe.authorizer_calls.load(Ordering::SeqCst), 2);
        prop_assert_eq!(uncached_probe.integration_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn property_13_api_key_rejection_gates_integration(api_id in "[a-z0-9]{3,10}", stage in "[a-z]{1,8}") {
        let (handler, probe, _registry) = handler_with_probe(true);
        let method = proxy_method(json!({ "apiKeyRequired": true }));
        install_rest_api(&handler, &api_id, &stage, method, None, None);
        let response = runtime().block_on(invoke_rest(&handler, &api_id, &stage, None));
        prop_assert_eq!(response.status().as_u16(), 403);
        prop_assert_eq!(probe.integration_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn property_14_request_validation_gates_integration(name in "[a-z]{1,12}", body_case in any::<bool>()) {
        let (handler, probe, _registry) = handler_with_probe(true);
        let (method, validator) = if body_case {
            (
                proxy_method(json!({
                    "requestValidatorId": "validator",
                    "requestModels": { "application/json": "PropertyModel" }
                })),
                json!({ "validateRequestBody": true, "validateRequestParameters": false })
            )
        } else {
            (
                proxy_method(json!({
                    "requestValidatorId": "validator",
                    "requestParameters": { format!("method.request.header.{name}"): true }
                })),
                json!({ "validateRequestBody": false, "validateRequestParameters": true })
            )
        };
        install_rest_api(&handler, "validation-api", "prod", method, None, Some(validator));
        if body_case {
            let record = handler.store().rest(ACCOUNT, REGION, "validation-api").unwrap();
            runtime().block_on(async {
                record.write().await.models.insert(
                    "PropertyModel".into(),
                    json!({ "schema": { "type": "object", "required": ["value"] } }),
                );
            });
        }
        let response = runtime().block_on(invoke_rest(&handler, "validation-api", "prod", None));
        prop_assert_eq!(response.status().as_u16(), 400);
        prop_assert_eq!(probe.integration_calls.load(Ordering::SeqCst), 0);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn property_15_stage_variable_substitution(name in "[A-Za-z_][A-Za-z0-9_]{0,12}", value in "[A-Za-z0-9.-]{0,24}", path_value in "[A-Za-z0-9]{1,12}") {
        let variables = BTreeMap::from([(name.clone(), value.clone())]);
        let path = BTreeMap::from([("id".into(), path_value.clone())]);
        let uri = format!("https://${{stageVariables.{name}}}/${{stageVariables.missing}}/items/{{id}}");
        let substituted = substitute_uri(&uri, &variables, &path);
        prop_assert_eq!(substituted, format!("https://{value}//items/{path_value}"));
    }

    #[test]
    fn property_16_websocket_connection_lifecycle(connection in "[a-z0-9]{1,24}", rejected in "[a-z0-9]{1,24}") {
        prop_assume!(connection != rejected);
        let store = ApiGwStore::new();
        let rt = runtime();
        rt.block_on(register_test_connection(&store, ACCOUNT, REGION, &connection, "api", "prod"));
        let accepted = rt.block_on(get_connection(&store, ACCOUNT, REGION, &connection));
        prop_assert_eq!(accepted.unwrap().0, 200);
        prop_assert!(matches!(rt.block_on(get_connection(&store, ACCOUNT, REGION, &rejected)), Err(ApiGwError::Gone(_))));
        prop_assert_eq!(rt.block_on(delete_connection(&store, ACCOUNT, REGION, &connection)).unwrap().0, 204);
        prop_assert!(matches!(rt.block_on(get_connection(&store, ACCOUNT, REGION, &connection)), Err(ApiGwError::Gone(_))));
    }

    #[test]
    fn property_17_connections_payload_bound_and_gone(extra in 0usize..1024) {
        let store = ApiGwStore::new();
        let rt = runtime();
        rt.block_on(register_test_connection(&store, ACCOUNT, REGION, "connection", "api", "prod"));
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        store.register_connection_sender(ACCOUNT, REGION, "connection", sender);
        let size = MAX_CONNECTION_PAYLOAD_BYTES + extra;
        let result = rt.block_on(post_to_connection(&store, ACCOUNT, REGION, "connection", &vec![0x5a; size]));
        if extra == 0 {
            prop_assert_eq!(result.unwrap().0, 200);
        } else {
            let error = result.unwrap_err();
            prop_assert_eq!(error.http_status(), 413);
        }
        rt.block_on(delete_connection(&store, ACCOUNT, REGION, "connection")).unwrap();
        let gone = rt.block_on(post_to_connection(&store, ACCOUNT, REGION, "connection", b"x")).unwrap_err();
        prop_assert_eq!(gone.http_status(), 410);
    }

    #[test]
    fn property_18_custom_domain_uses_longest_mapping(domain in "[a-z]{3,10}\\.example\\.test", base in "[a-z]{1,8}", tail in "[a-z]{1,8}") {
        let store = ApiGwStore::new();
        let nested = format!("{base}/private");
        runtime().block_on(async {
            store.shared(ACCOUNT, REGION).write().await.domains.insert(
                domain.clone(),
                json!({
                    "domainName": domain,
                    "__apiMappings": {
                        "base": { "apiMappingKey": base, "apiId": "base-api", "stage": "base-stage" },
                        "nested": { "apiMappingKey": nested, "apiId": "nested-api", "stage": "nested-stage" }
                    }
                }),
            );
        });
        let uri: Uri = format!("/{base}/private/{tail}?q=1").parse().unwrap();
        let target = runtime().block_on(custom_domain_target(&store, ACCOUNT, REGION, &domain, &uri)).unwrap();
        prop_assert_eq!(target.0, format!("nested-api.execute-api.{REGION}.amazonaws.com"));
        prop_assert_eq!(target.1.path(), format!("/execute-api/nested-api/nested-stage/{tail}"));
        prop_assert_eq!(target.1.query(), Some("q=1"));
        let uncovered: Uri = "/uncovered".parse().unwrap();
        prop_assert!(runtime().block_on(custom_domain_target(&store, ACCOUNT, REGION, &domain, &uncovered)).is_none());
    }

    #[test]
    fn property_19_region_account_scoping(account in "[a-z]{3,12}", region in "r-[a-z]{3,8}", id in "[a-z0-9]{3,10}") {
        let store = ApiGwStore::new();
        let first = store.insert_rest(
            ACCOUNT,
            REGION,
            &id,
            RestApiRecord { api: json!({ "name": "first" }), ..RestApiRecord::default() },
        );
        let second = store.insert_rest(
            &account,
            &region,
            &id,
            RestApiRecord { api: json!({ "name": "second" }), ..RestApiRecord::default() },
        );
        prop_assert!(!Arc::ptr_eq(&first, &second));
        let (first_name, second_name) = runtime().block_on(async {
            (
                first.read().await.api["name"].as_str().unwrap().to_string(),
                second.read().await.api["name"].as_str().unwrap().to_string(),
            )
        });
        prop_assert_eq!(first_name, "first");
        prop_assert_eq!(second_name, "second");
    }
}
