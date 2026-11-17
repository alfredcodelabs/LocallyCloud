//! HTTP API IAM regressions exercise real signed front-door requests in both modes.
use super::*;
use axum::{body::Body, response::Response};
use locallycloud_core::{
    handler::{NativeHandler, ServiceRequest},
    registry::{AwsProtocol, ServiceMetadata, ServiceName},
};
use std::sync::Mutex;

pub(super) async fn create_http_api(
    fixture: &Fixture,
    route_key: &str,
    authorization: &str,
    stage: &str,
    integration: Option<Value>,
) -> (String, String) {
    let api = fixture
        .manage(
            Method::POST,
            "/v2/apis",
            json!({"name":"owned-http","protocolType":"HTTP"}),
        )
        .await["apiId"]
        .as_str()
        .unwrap()
        .to_owned();
    let integration = fixture
        .manage(
            Method::POST,
            &format!("/v2/apis/{api}/integrations"),
            integration.unwrap_or_else(|| json!({"integrationType":"HTTP_PROXY","integrationMethod":"POST","integrationUri":fixture.backend})),
        )
        .await["integrationId"]
        .as_str()
        .unwrap()
        .to_owned();
    let route = fixture
        .manage(
            Method::POST,
            &format!("/v2/apis/{api}/routes"),
            json!({"routeKey":route_key,"authorizationType":authorization,"target":format!("integrations/{integration}")}),
        )
        .await["routeId"]
        .as_str()
        .unwrap()
        .to_owned();
    let deployment = deploy(fixture, &api).await;
    fixture
        .manage(
            Method::POST,
            &format!("/v2/apis/{api}/stages"),
            json!({"stageName":stage,"autoDeploy":false,"deploymentId":deployment}),
        )
        .await;
    (api, route)
}

async fn deploy(fixture: &Fixture, api: &str) -> String {
    fixture
        .manage(
            Method::POST,
            &format!("/v2/apis/{api}/deployments"),
            json!({}),
        )
        .await["deploymentId"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn redeploy(fixture: &Fixture, api: &str, stage: &str) {
    let deployment = deploy(fixture, api).await;
    fixture
        .manage(
            Method::PATCH,
            &format!("/v2/apis/{api}/stages/{stage}"),
            json!({"deploymentId":deployment}),
        )
        .await;
}

async fn invoke_http(
    fixture: &Fixture,
    api: &str,
    method: Method,
    path: &str,
    secret: Option<&str>,
    expected: u16,
) {
    invoke_with_headers(fixture, api, method, path, secret, &[], expected).await;
}

async fn invoke_with_headers(
    fixture: &Fixture,
    api: &str,
    method: Method,
    path: &str,
    secret: Option<&str>,
    headers: &[(&str, &str)],
    expected: u16,
) {
    let host = format!("{api}.execute-api.us-east-1.amazonaws.com");
    let before = fixture.hits.load(Ordering::SeqCst);
    let mut request = fixture
        .client
        .request(method.clone(), format!("{}{path}", fixture.base))
        .header(http::header::HOST, &host);
    if let Some(secret) = secret {
        for (name, value) in signature(
            method.as_str(),
            path,
            "",
            &host,
            b"",
            (ACTOR, secret),
            "execute-api",
        ) {
            request = request.header(name, value);
        }
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let body = response.text().await.unwrap();
    assert_eq!(status, expected, "{method} {path}: {body}");
    assert_eq!(
        fixture.hits.load(Ordering::SeqCst) - before,
        usize::from(expected == 200),
        "backend effects for {method} {path} status={expected}",
    );
}

#[tokio::test]
async fn http_iam_requires_exact_actual_method_path_stage_and_signed_permission_in_both_modes() {
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let fixture = Fixture::new(mode).await;
        let (api, _) = create_http_api(&fixture, "ANY /items/{id}", "AWS_IAM", "dev", None).await;
        let deployment = deploy(&fixture, &api).await;
        fixture
            .manage(
                Method::POST,
                &format!("/v2/apis/{api}/stages"),
                json!({"stageName":"other","deploymentId":deployment}),
            )
            .await;
        fixture.actor_policy(allow(&format!(
            "arn:aws:execute-api:us-east-1:{ACCOUNT}:{api}/dev/GET/items/42"
        )));
        invoke_http(
            &fixture,
            &api,
            Method::GET,
            "/dev/items/42",
            Some(SECRET),
            200,
        )
        .await;
        for (method, path, secret) in [
            (Method::POST, "/dev/items/42", Some(SECRET)),
            (Method::GET, "/dev/items/43", Some(SECRET)),
            (Method::GET, "/other/items/42", Some(SECRET)),
            (Method::GET, "/dev/items/42", None),
            (Method::GET, "/dev/items/42", Some("wrong-secret")),
        ] {
            invoke_http(&fixture, &api, method, path, secret, 403).await;
        }
        fixture.clear_actor_policies();
        invoke_http(
            &fixture,
            &api,
            Method::GET,
            "/dev/items/42",
            Some(SECRET),
            403,
        )
        .await;
        fixture.actor_policy(json!({"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"execute-api:Invoke","Resource":"*"}]}));
        invoke_http(
            &fixture,
            &api,
            Method::GET,
            "/dev/items/42",
            Some(SECRET),
            403,
        )
        .await;
    }
}

#[tokio::test]
async fn http_default_route_uses_default_suffix_and_default_stage_keeps_its_own_arn_segment() {
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let fixture = Fixture::new(mode).await;
        for (stage, path) in [
            ("dev", "/dev/unmatched/path"),
            ("$default", "/unmatched/path"),
        ] {
            let (api, _) = create_http_api(&fixture, "$default", "AWS_IAM", stage, None).await;
            fixture.actor_policy(allow(&format!(
                "arn:aws:execute-api:us-east-1:{ACCOUNT}:{api}/{stage}/$default"
            )));
            invoke_http(&fixture, &api, Method::GET, path, Some(SECRET), 200).await;
            invoke_http(&fixture, &api, Method::POST, path, Some(SECRET), 200).await;
            fixture.actor_policy(allow(&format!(
                "arn:aws:execute-api:us-east-1:{ACCOUNT}:{api}/{stage}/GET/unmatched/path"
            )));
            invoke_http(&fixture, &api, Method::GET, path, Some(SECRET), 403).await;
        }
        let (api, _) =
            create_http_api(&fixture, "ANY /items/{id}", "AWS_IAM", "$default", None).await;
        fixture.actor_policy(allow(&format!(
            "arn:aws:execute-api:us-east-1:{ACCOUNT}:{api}/$default/GET/items/42"
        )));
        invoke_http(&fixture, &api, Method::GET, "/items/42", Some(SECRET), 200).await;
        fixture.actor_policy(allow(&format!(
            "arn:aws:execute-api:us-east-1:{ACCOUNT}:{api}/$default/$default"
        )));
        invoke_http(&fixture, &api, Method::GET, "/items/42", Some(SECRET), 403).await;
    }
}

#[tokio::test]
async fn http_route_authorization_updates_apply_only_after_redeploy_in_both_modes() {
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let fixture = Fixture::new(mode).await;
        let (api, route) = create_http_api(&fixture, "GET /items", "NONE", "dev", None).await;
        invoke_http(&fixture, &api, Method::GET, "/dev/items", None, 200).await;
        let resource = format!("/v2/apis/{api}/routes/{route}");
        let updated = fixture
            .manage(
                Method::PATCH,
                &resource,
                json!({"authorizationType":"AWS_IAM"}),
            )
            .await;
        assert_eq!(updated["authorizationType"], "AWS_IAM");
        invoke_http(&fixture, &api, Method::GET, "/dev/items", None, 200).await;
        redeploy(&fixture, &api, "dev").await;
        invoke_http(&fixture, &api, Method::GET, "/dev/items", None, 403).await;
        invoke_http(&fixture, &api, Method::GET, "/dev/items", Some(SECRET), 200).await;
        fixture
            .manage(
                Method::PATCH,
                &resource,
                json!({"authorizationType":"NONE"}),
            )
            .await;
        invoke_http(&fixture, &api, Method::GET, "/dev/items", None, 403).await;
        redeploy(&fixture, &api, "dev").await;
        invoke_http(&fixture, &api, Method::GET, "/dev/items", None, 200).await;
    }
}

#[tokio::test]
async fn http_cors_preflight_cannot_bypass_default_iam_route_without_an_open_options_route() {
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let fixture = Fixture::new(mode).await;
        let (api, _) = create_http_api(&fixture, "$default", "AWS_IAM", "$default", None).await;
        fixture.manage(Method::PATCH, &format!("/v2/apis/{api}"), json!({"corsConfiguration":{"allowOrigins":["https://owned.invalid"],"allowMethods":["GET"]}})).await;
        redeploy(&fixture, &api, "$default").await;
        let headers = [
            ("origin", "https://owned.invalid"),
            ("access-control-request-method", "GET"),
        ];
        // Origin alone is a normal OPTIONS invocation, not an automatic preflight.
        invoke_with_headers(
            &fixture,
            &api,
            Method::OPTIONS,
            "/items",
            Some(SECRET),
            &[("origin", "https://owned.invalid")],
            200,
        )
        .await;
        invoke_with_headers(
            &fixture,
            &api,
            Method::OPTIONS,
            "/items",
            None,
            &headers,
            403,
        )
        .await;
        fixture
            .manage(
                Method::POST,
                &format!("/v2/apis/{api}/routes"),
                json!({"routeKey":"OPTIONS /{proxy+}","authorizationType":"NONE"}),
            )
            .await;
        redeploy(&fixture, &api, "$default").await;
        invoke_with_headers(
            &fixture,
            &api,
            Method::OPTIONS,
            "/items",
            None,
            &headers,
            204,
        )
        .await;
    }
}

struct RecordLambda {
    hits: Arc<AtomicUsize>,
    events: Arc<Mutex<Vec<(Value, String)>>>,
}

#[async_trait::async_trait]
impl NativeHandler for RecordLambda {
    async fn handle(&self, request: ServiceRequest) -> Response {
        assert_eq!(
            request.headers["x-locallycloud-verified-internal-scope"],
            "1"
        );
        assert_eq!(request.account_id, ACCOUNT);
        let source_arn = request.headers["x-locallycloud-source-arn"]
            .to_str()
            .unwrap()
            .to_owned();
        self.events
            .lock()
            .unwrap()
            .push((serde_json::from_slice(&request.body).unwrap(), source_arn));
        self.hits.fetch_add(1, Ordering::SeqCst);
        Response::new(Body::from(
            json!({"statusCode":200,"body":"owned"}).to_string(),
        ))
    }
}

#[tokio::test]
async fn http_iam_actor_metadata_reaches_lambda_payload_formats_one_and_two() {
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let fixture = Fixture::new(mode).await;
        let events = Arc::new(Mutex::new(Vec::new()));
        fixture.registry.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::new(RecordLambda {
                hits: fixture.hits.clone(),
                events: events.clone(),
            }),
        );
        for (format, route_key, path, arn_suffix) in [
            (
                "1.0",
                "ANY /items/{id}",
                "/dev/items/42",
                "dev/GET/items/42",
            ),
            (
                "2.0",
                "ANY /items/{id}",
                "/dev/items/42",
                "dev/GET/items/42",
            ),
            ("2.0", "$default", "/dev/unmatched/path", "dev/$default"),
        ] {
            let (api, _) = create_http_api(&fixture, route_key, "AWS_IAM", "dev", Some(json!({"integrationType":"AWS_PROXY","integrationMethod":"POST","integrationUri":format!("arn:aws:lambda:us-east-1:{ACCOUNT}:function:metadata"),"payloadFormatVersion":format}))).await;
            let expected_arn =
                format!("arn:aws:execute-api:us-east-1:{ACCOUNT}:{api}/{arn_suffix}");
            fixture.actor_policy(allow(&expected_arn));
            invoke_with_headers(
                &fixture,
                &api,
                Method::GET,
                path,
                Some(SECRET),
                &[("x-forwarded-for", "198.51.100.9")],
                200,
            )
            .await;
            let (event, source_arn) = events.lock().unwrap().last().unwrap().clone();
            assert_eq!(source_arn, expected_arn);
            assert_eq!(event["version"], format);
            let identity = match format {
                "1.0" => &event["requestContext"]["identity"],
                "2.0" => &event["requestContext"]["authorizer"]["iam"],
                _ => unreachable!(),
            };
            assert_eq!(identity["accountId"], ACCOUNT);
            assert_eq!(identity["accessKey"], ACTOR);
            assert_eq!(
                identity["userArn"],
                format!("arn:aws:iam::{ACCOUNT}:user/actor")
            );
            let (caller, user) = match format {
                "1.0" => ("caller", "user"),
                "2.0" => ("callerId", "userId"),
                _ => unreachable!(),
            };
            assert_eq!(identity[caller], "AIDAactor");
            assert_eq!(identity[user], "AIDAactor");
            let source_ip = match format {
                "1.0" => &identity["sourceIp"],
                "2.0" => &event["requestContext"]["http"]["sourceIp"],
                _ => unreachable!(),
            };
            assert_eq!(source_ip, "127.0.0.1");
            if format == "2.0" {
                assert!(event["requestContext"].get("identity").is_none());
                assert_eq!(event["routeKey"], route_key);
            }
            invoke_http(&fixture, &api, Method::GET, path, None, 403).await;
        }
        assert_eq!(events.lock().unwrap().len(), 3);
    }
}
