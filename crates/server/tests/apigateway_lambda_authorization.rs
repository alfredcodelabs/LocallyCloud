//! API Gateway invokes the real Lambda authorization boundary with an attested source.
//! A control-plane-only Lambda returns 501 after authorization, avoiding an OCI dependency.
#![cfg(feature = "services")]
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, Method};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_iam_sts::{
    enforcement::EnforcementMode,
    model::{AccessKey, IamRole, IamUser},
    store::IamStore,
    sts::SessionStore,
};
use serde_json::{json, Value};

const ACCOUNT: &str = "000000000000";
const KEY: &str = "AKIAAPIGATEWAYTEST001";
const FUNCTION: &str = "arn:aws:lambda:us-east-1:000000000000:function:api-function";
const INTEGRATION_ROLE: &str = "arn:aws:iam::000000000000:role/api-integration";
const ZIP: &str = "UEsDBBQAAAAAAOUBcF3HPNg2OwAAADsAAAAIAAAAaW5kZXguanNleHBvcnRzLmhhbmRsZXIgPSBhc3luYyAoKSA9PiAoe3N0YXR1c0NvZGU6MjAwLGJvZHk6Im9rIn0pO1BLAQIUAxQAAAAAAOUBcF3HPNg2OwAAADsAAAAIAAAAAAAAAAAAAACAAQAAAABpbmRleC5qc1BLBQYAAAAAAQABADYAAABhAAAAAAA=";

struct Recorded {
    source: String,
    principal: String,
    status: u16,
}
struct RecordLambda {
    inner: Arc<dyn NativeHandler>,
    records: Arc<Mutex<Vec<Recorded>>>,
}
#[async_trait::async_trait]
impl NativeHandler for RecordLambda {
    async fn handle(&self, request: ServiceRequest) -> Response {
        assert_eq!(
            request.headers["x-locallycloud-verified-internal-scope"],
            "1"
        );
        let source = request.headers["x-locallycloud-source-arn"]
            .to_str()
            .unwrap()
            .to_owned();
        let principal = request.headers["x-locallycloud-caller-principal"]
            .to_str()
            .unwrap()
            .to_owned();
        let response = self.inner.handle(request).await;
        self.records.lock().unwrap().push(Recorded {
            source,
            principal,
            status: response.status().as_u16(),
        });
        response
    }
}
struct Fixture {
    _registry: Arc<ServiceRegistry>,
    gateway: Arc<dyn NativeHandler>,
    lambda: Arc<dyn NativeHandler>,
    records: Arc<Mutex<Vec<Recorded>>>,
    iam: Arc<IamStore>,
}

#[tokio::test]
async fn role_assignment_keeps_verified_transport_for_pass_role_conditions() {
    let fixture = Fixture::new().await;
    fixture.iam.update_user(ACCOUNT, "admin", |user| {
        user.inline_policies = BTreeMap::from([(
            "transport".into(),
            json!({"Statement":[
                {"Effect":"Allow", "Action":"*", "Resource":"*"},
                {"Effect":"Deny", "Action":"iam:PassRole", "Resource":"*",
                    "Condition":{"Bool":{"aws:SecureTransport":"false"}}}
            ]})
            .to_string(),
        )]);
    });
    for (transport, expected) in [("false", 403), ("true", 201)] {
        let mut req = request(
            Method::POST,
            "/v2/apis",
            json!({
                "name":format!("transport-{transport}"), "protocolType":"HTTP", "credentialsArn":INTEGRATION_ROLE
            }),
        );
        req.headers.insert(
            "x-locallycloud-verified-secure-transport",
            transport.parse().unwrap(),
        );
        assert_eq!(
            fixture.gateway.handle(req).await.status().as_u16(),
            expected
        );
        let mut req = request(
            Method::PATCH,
            "/account",
            json!({"patchOperations":[{
                "op":"replace", "path":"/cloudwatchRoleArn", "value":INTEGRATION_ROLE
            }]}),
        );
        req.headers.insert(
            "x-locallycloud-verified-secure-transport",
            transport.parse().unwrap(),
        );
        assert_eq!(
            fixture.gateway.handle(req).await.status().as_u16(),
            if transport == "true" { 200 } else { 403 }
        );
    }
}
fn request(method: Method, path: &str, body: Value) -> ServiceRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-locallycloud-verified-external-sigv4",
        "1".parse().unwrap(),
    );
    headers.insert(
        http::header::AUTHORIZATION,
        format!("AWS4-HMAC-SHA256 Credential={KEY}/20261116/us-east-1/apigateway/aws4_request")
            .parse()
            .unwrap(),
    );
    ServiceRequest {
        method,
        uri: path.parse().unwrap(),
        headers,
        body: Bytes::from(body.to_string()),
        region: "us-east-1".into(),
        account_id: ACCOUNT.into(),
        request_id: "strict-integration".into(),
    }
}
async fn call(
    handler: &Arc<dyn NativeHandler>,
    method: Method,
    path: &str,
    body: Value,
) -> (u16, Value) {
    let response = handler.handle(request(method, path, body)).await;
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    (
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        },
    )
}
async fn ok(handler: &Arc<dyn NativeHandler>, method: Method, path: &str, body: Value) -> Value {
    let (status, body) = call(handler, method, path, body).await;
    assert!((200..300).contains(&status), "{path}: {status}: {body}");
    body
}
fn role(name: &str, service: &str, policies: BTreeMap<String, String>) -> IamRole {
    IamRole {
        role_name: name.into(), role_id: format!("AROA{name}"), arn: format!("arn:aws:iam::{ACCOUNT}:role/{name}"),
        path: "/".into(), create_date: "2026-01-01T00:00:00Z".into(),
        assume_role_policy_document: json!({"Statement":{"Effect":"Allow","Principal":{"Service":service},"Action":"sts:AssumeRole"}}).to_string(),
        description: None, max_session_duration: 3600, tags: BTreeMap::new(), attached_policies: Vec::new(), inline_policies: policies, permission_boundary: None,
    }
}
impl Fixture {
    async fn new() -> Self {
        let registry = ServiceRegistry::with_known_services();
        let iam = Arc::new(IamStore::new());
        iam.create_user(
            ACCOUNT,
            IamUser {
                user_name: "admin".into(),
                user_id: "AIDAADMIN".into(),
                arn: format!("arn:aws:iam::{ACCOUNT}:user/admin"),
                path: "/".into(),
                create_date: "2026-01-01T00:00:00Z".into(),
                tags: BTreeMap::new(),
                attached_policies: Vec::new(),
                inline_policies: BTreeMap::from([(
                    "admin".into(),
                    json!({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}).to_string(),
                )]),
                groups: Vec::new(),
                permission_boundary: None,
                access_keys: vec![AccessKey {
                    access_key_id: KEY.into(),
                    secret_access_key: "s".repeat(40),
                    status: "Active".into(),
                    create_date: "2026-01-01T00:00:00Z".into(),
                }],
            },
        );
        iam.create_role(
            ACCOUNT,
            role("execution", "lambda.amazonaws.com", BTreeMap::new()),
        );
        iam.create_role(ACCOUNT, role("api-integration", "apigateway.amazonaws.com", BTreeMap::from([("invoke".into(), json!({"Statement":{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":FUNCTION}}).to_string())])));
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            iam.clone(),
            Arc::new(SessionStore::new()),
            EnforcementMode::Strict,
        );
        let lambda: Arc<dyn NativeHandler> = locallycloud_lambda::register(&registry);
        locallycloud_apigateway::register(&registry);
        let gateway = registry
            .native_handler(&ServiceName::new("apigateway"))
            .unwrap();
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            ACCOUNT.into(),
        )));
        ok(&lambda, Method::POST, "/2015-03-31/functions", json!({"FunctionName":"api-function","Role":format!("arn:aws:iam::{ACCOUNT}:role/execution"),"Runtime":"nodejs22.x","Handler":"index.handler","Code":{"ZipFile":ZIP}})).await;
        let records = Arc::new(Mutex::new(Vec::new()));
        registry.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::new(RecordLambda {
                inner: lambda.clone(),
                records: records.clone(),
            }),
        );
        Self {
            _registry: registry,
            gateway,
            lambda,
            records,
            iam,
        }
    }
    async fn api(&self, rest: bool, credentials: Option<&str>) -> String {
        if rest {
            let api = ok(
                &self.gateway,
                Method::POST,
                "/restapis",
                json!({"name":"strict-api"}),
            )
            .await;
            let id = api["id"].as_str().unwrap();
            let resources = ok(
                &self.gateway,
                Method::GET,
                &format!("/restapis/{id}/resources"),
                Value::Null,
            )
            .await;
            let root = resources["item"][0]["id"].as_str().unwrap();
            let method = format!("/restapis/{id}/resources/{root}/methods/GET");
            ok(
                &self.gateway,
                Method::PUT,
                &method,
                json!({"authorizationType":"NONE"}),
            )
            .await;
            ok(&self.gateway, Method::PUT, &format!("{method}/integration"), json!({"type":"AWS_PROXY","httpMethod":"POST","uri":format!("arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{FUNCTION}/invocations"),"credentials":credentials})).await;
            ok(
                &self.gateway,
                Method::POST,
                &format!("/restapis/{id}/deployments"),
                json!({"stageName":"prod"}),
            )
            .await;
            id.into()
        } else {
            let api = ok(
                &self.gateway,
                Method::POST,
                "/v2/apis",
                json!({"name":"strict-api","protocolType":"HTTP"}),
            )
            .await;
            let id = api["apiId"].as_str().unwrap();
            let mut integration = json!({"integrationType":"AWS_PROXY","integrationUri":FUNCTION,"payloadFormatVersion":"2.0"});
            if let Some(credentials) = credentials {
                integration["credentialsArn"] = json!(credentials);
            }
            let integration = ok(
                &self.gateway,
                Method::POST,
                &format!("/v2/apis/{id}/integrations"),
                integration,
            )
            .await;
            ok(&self.gateway, Method::POST, &format!("/v2/apis/{id}/routes"), json!({"routeKey":"GET /","target":format!("integrations/{}",integration["integrationId"].as_str().unwrap())})).await;
            ok(
                &self.gateway,
                Method::POST,
                &format!("/v2/apis/{id}/stages"),
                json!({"stageName":"prod","autoDeploy":true}),
            )
            .await;
            id.into()
        }
    }
    async fn permission(&self, source: &str) {
        ok(&self.lambda, Method::POST, "/2015-03-31/functions/api-function/policy", json!({"StatementId":"gateway","Action":"lambda:InvokeFunction","Principal":"apigateway.amazonaws.com","SourceArn":source,"SourceAccount":ACCOUNT})).await;
    }
    async fn remove_permission(&self) {
        ok(
            &self.lambda,
            Method::DELETE,
            "/2015-03-31/functions/api-function/policy/gateway",
            Value::Null,
        )
        .await;
    }
    async fn invoke(&self, api: &str, rest: bool) -> Response {
        let path = if rest {
            format!("/restapis/{api}/prod/_user_request_/")
        } else {
            format!("/execute-api/{api}/prod/")
        };
        let mut request = request(Method::GET, &path, Value::Null);
        request.headers.insert(
            http::header::HOST,
            "fixture.execute-api.localhost".parse().unwrap(),
        );
        self.gateway.handle(request).await
    }
    fn last(&self, source: &str, status: u16, principal: &str) {
        let records = self.records.lock().unwrap();
        let record = records.last().expect("Lambda boundary was reached");
        assert_eq!(record.source, source);
        assert_eq!(record.principal, principal);
        assert_eq!(
            record.status, status,
            "source={} principal={}",
            record.source, record.principal
        );
    }
}
#[tokio::test]
async fn rest_and_http_invocations_require_matching_lambda_permission() {
    for rest in [true, false] {
        let fixture = Fixture::new().await;
        let api = fixture.api(rest, None).await;
        let source = format!("arn:aws:execute-api:us-east-1:{ACCOUNT}:{api}/prod/GET/");
        fixture.invoke(&api, rest).await;
        fixture.last(&source, 403, "apigateway.amazonaws.com");
        fixture
            .permission(&format!(
                "arn:aws:execute-api:us-east-1:{ACCOUNT}:other/prod/GET/"
            ))
            .await;
        fixture.invoke(&api, rest).await;
        fixture.last(&source, 403, "apigateway.amazonaws.com");
        fixture.remove_permission().await;
        fixture.permission(&source).await;
        fixture.invoke(&api, rest).await;
        fixture.last(&source, 501, "apigateway.amazonaws.com");
    }
}
#[tokio::test]
async fn integration_role_must_be_trusted_and_granted_invoke() {
    let fixture = Fixture::new().await;
    let api = fixture.api(false, Some(INTEGRATION_ROLE)).await;
    let source = format!("arn:aws:execute-api:us-east-1:{ACCOUNT}:{api}/prod/GET/");
    fixture.invoke(&api, false).await;
    fixture.last(&source, 501, &format!("{INTEGRATION_ROLE}/apigateway"));
    fixture.iam.update_role(ACCOUNT, "api-integration", |role| {
        role.inline_policies.clear()
    });
    fixture.invoke(&api, false).await;
    fixture.last(&source, 403, &format!("{INTEGRATION_ROLE}/apigateway"));
    fixture.records.lock().unwrap().clear();
    fixture.iam.update_role(ACCOUNT, "api-integration", |role| role.assume_role_policy_document = json!({"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}).to_string());
    fixture.invoke(&api, false).await;
    assert!(fixture.records.lock().unwrap().is_empty());
}
#[tokio::test]
async fn management_mutations_and_role_assignment_require_identity_permissions() {
    let fixture = Fixture::new().await;
    assert_eq!(call(&fixture.gateway, Method::POST, "/v2/apis", json!({
        "name":"foreign-role","protocolType":"HTTP","credentialsArn":"arn:aws:iam::111122223333:role/foreign"
    })).await.0, 403);
    fixture.iam.update_user(ACCOUNT, "admin", |user| {
        user.inline_policies = BTreeMap::from([(
            "api".into(),
            json!({"Statement":{"Effect":"Allow","Action":"apigateway:*","Resource":"*"}})
                .to_string(),
        )])
    });
    let (status, _) = call(
        &fixture.gateway,
        Method::POST,
        "/v2/apis",
        json!({"name":"forbidden-role","protocolType":"HTTP","credentialsArn":INTEGRATION_ROLE}),
    )
    .await;
    assert_eq!(status, 403);
    let (_, api) = call(
        &fixture.gateway,
        Method::POST,
        "/v2/apis",
        json!({"name":"no-role","protocolType":"HTTP"}),
    )
    .await;
    assert!(api["apiId"].is_string());
    fixture
        .iam
        .update_user(ACCOUNT, "admin", |user| user.inline_policies.clear());
    assert_eq!(
        call(
            &fixture.gateway,
            Method::POST,
            "/v2/apis",
            json!({"name":"forbidden-api","protocolType":"HTTP"})
        )
        .await
        .0,
        403
    );
}

#[tokio::test]
async fn rest_and_http_authorizers_use_the_authorizer_source_arn() {
    for rest in [true, false] {
        let fixture = Fixture::new().await;
        let api = fixture.api(rest, None).await;
        let uri = format!(
            "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{FUNCTION}/invocations"
        );
        let authorizer = if rest {
            ok(&fixture.gateway, Method::POST, &format!("/restapis/{api}/authorizers"), json!({
                "name":"auth","type":"TOKEN","authorizerUri":uri,
                "identitySource":"method.request.header.Authorization","authorizerResultTtlInSeconds":0
            })).await
        } else {
            ok(&fixture.gateway, Method::POST, &format!("/v2/apis/{api}/authorizers"), json!({
                "name":"auth","authorizerType":"REQUEST","authorizerUri":uri,
                "identitySource":["$request.header.Authorization"],"authorizerPayloadFormatVersion":"2.0",
                "enableSimpleResponses":true,"authorizerResultTtlInSeconds":0
            })).await
        };
        let authorizer_id = authorizer[if rest { "id" } else { "authorizerId" }]
            .as_str()
            .unwrap();
        if rest {
            let resources = ok(
                &fixture.gateway,
                Method::GET,
                &format!("/restapis/{api}/resources"),
                Value::Null,
            )
            .await;
            let root = resources["item"][0]["id"].as_str().unwrap();
            ok(
                &fixture.gateway,
                Method::PATCH,
                &format!("/restapis/{api}/resources/{root}/methods/GET"),
                json!({"patchOperations":[
                    {"op":"replace","path":"/authorizationType","value":"CUSTOM"},
                    {"op":"replace","path":"/authorizerId","value":authorizer_id}
                ]}),
            )
            .await;
            ok(
                &fixture.gateway,
                Method::POST,
                &format!("/restapis/{api}/deployments"),
                json!({"stageName":"prod"}),
            )
            .await;
        } else {
            let routes = ok(
                &fixture.gateway,
                Method::GET,
                &format!("/v2/apis/{api}/routes"),
                Value::Null,
            )
            .await;
            let route = routes["items"][0]["routeId"].as_str().unwrap();
            ok(
                &fixture.gateway,
                Method::PATCH,
                &format!("/v2/apis/{api}/routes/{route}"),
                json!({"authorizationType":"CUSTOM","authorizerId":authorizer_id}),
            )
            .await;
        }
        let source =
            format!("arn:aws:execute-api:us-east-1:{ACCOUNT}:{api}/authorizers/{authorizer_id}");
        fixture.invoke(&api, rest).await;
        fixture.last(&source, 403, "apigateway.amazonaws.com");
        fixture
            .permission(&format!(
                "arn:aws:execute-api:us-east-1:{ACCOUNT}:{api}/prod/GET/"
            ))
            .await;
        fixture.invoke(&api, rest).await;
        fixture.last(&source, 403, "apigateway.amazonaws.com");
        fixture.remove_permission().await;
        fixture.permission(&source).await;
        fixture.invoke(&api, rest).await;
        fixture.last(&source, 501, "apigateway.amazonaws.com");
    }
}

#[tokio::test]
async fn native_aws_integration_uses_role_permissions_at_the_destination() {
    let fixture = Fixture::new().await;
    locallycloud_dynamodb::register(&fixture._registry);
    let dynamodb = fixture
        ._registry
        .native_handler(&ServiceName::new("dynamodb"))
        .unwrap();
    let mut create = request(
        Method::POST,
        "/",
        json!({
            "TableName":"api-items","BillingMode":"PAY_PER_REQUEST",
            "KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],
            "AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}]
        }),
    );
    create.headers.insert(
        "x-amz-target",
        "DynamoDB_20120810.CreateTable".parse().unwrap(),
    );
    assert_eq!(dynamodb.handle(create).await.status(), 200);
    fixture.iam.update_role(ACCOUNT, "api-integration", |role| role.inline_policies = BTreeMap::from([("write".into(), json!({"Statement":{
        "Effect":"Allow","Action":"dynamodb:PutItem","Resource":format!("arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/api-items")
    }}).to_string())]));
    let api = fixture.api(true, Some(INTEGRATION_ROLE)).await;
    let resources = ok(
        &fixture.gateway,
        Method::GET,
        &format!("/restapis/{api}/resources"),
        Value::Null,
    )
    .await;
    let root = resources["item"][0]["id"].as_str().unwrap();
    let template = json!({"TableName":"api-items","Item":{"id":{"S":"written"}}}).to_string();
    ok(&fixture.gateway, Method::PUT, &format!("/restapis/{api}/resources/{root}/methods/GET/integration"), json!({
        "type":"AWS","httpMethod":"POST","uri":"arn:aws:apigateway:us-east-1:dynamodb:action/PutItem",
        "credentials":INTEGRATION_ROLE,"requestTemplates":{"application/json":template}
    })).await;
    for (status, selection) in [("200", "200"), ("403", "400|403")] {
        ok(
            &fixture.gateway,
            Method::PUT,
            &format!("/restapis/{api}/resources/{root}/methods/GET/integration/responses/{status}"),
            json!({"statusCode":status,"selectionPattern":selection}),
        )
        .await;
    }
    ok(
        &fixture.gateway,
        Method::POST,
        &format!("/restapis/{api}/deployments"),
        json!({"stageName":"prod"}),
    )
    .await;
    assert_eq!(fixture.invoke(&api, true).await.status(), 200);
    fixture.iam.update_role(ACCOUNT, "api-integration", |role| {
        role.inline_policies.clear()
    });
    let response = fixture.invoke(&api, true).await;
    assert!(!response.status().is_success());
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("AccessDenied"));
}

#[tokio::test]
async fn internal_management_calls_recheck_the_delegated_role_policy() {
    use locallycloud_core::integration::identity::{CallerIdentity, IdentityPropagator};
    let fixture = Fixture::new().await;
    fixture.iam.update_role(ACCOUNT, "api-integration", |role| role.inline_policies = BTreeMap::from([("manage".into(), json!({"Statement":{
        "Effect":"Allow","Action":"apigateway:POST","Resource":"arn:aws:apigateway:us-east-1::/v2/apis"
    }}).to_string())]));
    let dispatcher = fixture._registry.internal_dispatcher().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        "AWS4-HMAC-SHA256 Credential=locallycloud/19700101/us-east-1/apigateway/aws4_request"
            .parse()
            .unwrap(),
    );
    IdentityPropagator::attach(
        &mut headers,
        &CallerIdentity::AssumedRole {
            role_arn: INTEGRATION_ROLE.into(),
            session_name: "cloudformation".into(),
        },
    );
    let uri = "/v2/apis".parse().unwrap();
    let body = Bytes::from(json!({"name":"internal-api","protocolType":"HTTP"}).to_string());
    let response = dispatcher
        .dispatch_scoped(
            &Method::POST,
            &uri,
            &headers,
            body.clone(),
            "allowed",
            ACCOUNT,
            "us-east-1",
        )
        .await;
    assert_eq!(response.status(), 201);
    fixture.iam.update_role(ACCOUNT, "api-integration", |role| {
        role.inline_policies.clear()
    });
    let response = dispatcher
        .dispatch_scoped(
            &Method::POST,
            &uri,
            &headers,
            body,
            "denied",
            ACCOUNT,
            "us-east-1",
        )
        .await;
    assert_eq!(response.status(), 403);
}
