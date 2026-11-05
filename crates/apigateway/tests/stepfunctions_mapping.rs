//! Regression for Accounting's deployed serverless-step-functions mapping templates.
//! Fixtures retain the application's VTL; only its account/region are bound to this test.
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use http::{HeaderMap, HeaderValue, Method};
use locallycloud_core::{
    config::LocallyCloudConfig,
    handler::{NativeHandler, ServiceRequest},
    registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry},
    server::LocallyCloudServer,
};
use serde_json::{json, Value};

struct CountSyncCalls {
    real: Arc<dyn NativeHandler>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl NativeHandler for CountSyncCalls {
    async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
        if request
            .headers
            .get("x-amz-target")
            .is_some_and(|target| target == "AWSStepFunctions.StartSyncExecution")
        {
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
        self.real.handle(request).await
    }
}

struct HttpFixture {
    endpoint: String,
    client: reqwest::Client,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

async fn call(
    registry: &HttpFixture,
    service: &str,
    method: Method,
    path: &str,
    body: Value,
    bearer: bool,
) -> (u16, Value) {
    let mut headers = HeaderMap::new();
    headers.insert(
        "host",
        HeaderValue::from_static(if service == "execute-api" {
            "fixture.execute-api.localhost"
        } else {
            "localhost"
        }),
    );
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    if service == "apigateway" {
        headers.insert("authorization", HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=test/20261105/us-east-1/apigateway/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }
    if service == "states" {
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("AWSStepFunctions.{path}")).unwrap(),
        );
    }
    if bearer {
        // Unsigned fixture: this API intentionally has no authorizer. The application VTL
        // decodes payload claims for context; this is not authentication validation.
        headers.insert("authorization", HeaderValue::from_static(
            "Bearer header.eyJodHRwczovL25hcmFuamEuY29tL2luZm8iOnsiY2xpZW50SWQiOiJjbGllbnQtMSIsImNsaWVudE5hbWUiOiJ0ZXN0LWNsaWVudCJ9fQ.signature"
        ));
    }
    let uri = if service == "states" { "/" } else { path };
    let response = registry
        .client
        .request(method, format!("{}{uri}", registry.endpoint))
        .headers(headers)
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.bytes().await.unwrap();
    let value = serde_json::from_slice(&body).unwrap_or_else(|_| {
        panic!(
            "invalid JSON response {status}: {}",
            String::from_utf8_lossy(&body)
        )
    });
    (status, value)
}

async fn api(
    registry: &HttpFixture,
    service: &str,
    method: Method,
    path: &str,
    body: Value,
) -> Value {
    let (status, value) = call(registry, service, method, path, body, false).await;
    assert!((200..300).contains(&status), "{path}: {status}: {value}");
    value
}

#[tokio::test]
async fn accounting_template_reaches_real_sync_workflow_and_maps_its_response() {
    let registry = ServiceRegistry::with_known_services();
    locallycloud_stepfunctions::register(&registry);
    let calls = Arc::new(AtomicUsize::new(0));
    let real = registry
        .native_handler(&ServiceName::new("states"))
        .unwrap();
    registry.register_native(
        ServiceName::new("states"),
        ServiceMetadata::new(AwsProtocol::Json10, Some("AWSStepFunctions")),
        Arc::new(CountSyncCalls {
            real,
            calls: calls.clone(),
        }),
    );
    locallycloud_apigateway::register(&registry);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let config = LocallyCloudConfig::resolve(&|name| match name {
        "LOCALLYCLOUD_UI" => Some("off".into()),
        "LOCALLYCLOUD_LEGACY_BACKEND_URL" => Some("http://127.0.0.1:1".into()),
        _ => None,
    })
    .unwrap();
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let (ready, started) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(LocallyCloudServer::new(config, registry).run_on_listener(
        listener,
        async {
            let _ = stopped.await;
        },
        move || {
            let _ = ready.send(());
        },
    ));
    let mut registry = HttpFixture {
        endpoint,
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
        shutdown: Some(shutdown),
    };
    started.await.unwrap();
    let request_template = include_str!("fixtures/accounting-stepfunctions-request.vtl")
        .replace("\"0\"", "\"000000000000\"");
    // The actual VTL determines the machine name. Keep it in sync with the fixture.
    let machine_name = request_template
        .lines()
        .next()
        .unwrap()
        .split('"')
        .nth(1)
        .unwrap();
    api(&registry, "states", Method::POST, "CreateStateMachine", json!({
        "name": machine_name, "type": "EXPRESS",
        "roleArn": "arn:aws:iam::000000000000:role/mapping-fixture",
        "definition": json!({"StartAt": "Echo", "States": {
            "Echo": {"Type": "Pass", "Parameters": {"statusCode": 201, "body.$": "$"}, "End": true}
        }}).to_string()
    })).await;
    let rest = api(
        &registry,
        "apigateway",
        Method::POST,
        "/restapis",
        json!({"name": "mapping-fixture"}),
    )
    .await;
    let id = rest["id"].as_str().unwrap();
    let root = rest["rootResourceId"].as_str().unwrap();
    let resource = api(
        &registry,
        "apigateway",
        Method::POST,
        &format!("/restapis/{id}/resources/{root}"),
        json!({"pathPart": "flows"}),
    )
    .await;
    let rid = resource["id"].as_str().unwrap();
    let method = format!("/restapis/{id}/resources/{rid}/methods/GET");
    api(
        &registry,
        "apigateway",
        Method::PUT,
        &method,
        json!({"authorizationType": "NONE"}),
    )
    .await;
    api(
        &registry,
        "apigateway",
        Method::PUT,
        &format!("{method}/integration"),
        json!({
            "type": "AWS", "httpMethod": "POST",
            "uri": "arn:aws:apigateway:us-east-1:states:action/StartSyncExecution",
            "passthroughBehavior": "WHEN_NO_TEMPLATES",
            "requestTemplates": {"application/json": request_template}
        }),
    )
    .await;
    api(
        &registry,
        "apigateway",
        Method::PUT,
        &format!("{method}/responses/200"),
        json!({}),
    )
    .await;
    api(&registry, "apigateway", Method::PUT,
        &format!("{method}/integration/responses/200"), json!({
            "statusCode": "200",
            "responseTemplates": {"application/json": include_str!("fixtures/accounting-stepfunctions-response.vtl")}
        })).await;
    api(
        &registry,
        "apigateway",
        Method::POST,
        &format!("/restapis/{id}/deployments"),
        json!({"stageName": "test"}),
    )
    .await;

    for bearer in [false, true] {
        let (status, body) = call(
            &registry,
            "execute-api",
            Method::GET,
            &format!("/restapis/{id}/test/_user_request_/flows?limit=5"),
            json!({"marker": "O'Reilly"}),
            bearer,
        )
        .await;
        assert_eq!(status, 201, "{body}");
        assert_eq!(body["body"]["marker"], "O'Reilly");
        assert_eq!(body["params"]["querystring"]["limit"], "5");
        assert!(
            body["params"].get("header").is_none(),
            "authorization must not leak into execution input: {body}"
        );
        assert!(!body["context"]["request-id"].as_str().unwrap().is_empty());
        assert_eq!(body["context"]["account-id"], "000000000000");
        assert!(body["context"]["timestamp"].as_u64().unwrap() > 0);
        assert_eq!(
            body["context"]["client-id"],
            if bearer { "client-1" } else { "" }
        );
        assert_eq!(
            body["context"]["client-name"],
            if bearer { "test-client" } else { "" }
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    // The application fixture inserts $input.body as raw JSON. A bare GET therefore
    // produces invalid workflow input even after VTL succeeds; do not invent a body.
    let empty_get = registry
        .client
        .get(format!(
            "{}/restapis/{id}/test/_user_request_/flows",
            registry.endpoint
        ))
        .header("host", "fixture.execute-api.localhost")
        .header("content-type", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(empty_get.status(), 500);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        3,
        "the mapping now reaches Step Functions, which rejects the empty-body template's input"
    );
    api(
        &registry,
        "apigateway",
        Method::PUT,
        &format!("{method}/integration"),
        json!({
            "type": "AWS", "httpMethod": "POST",
            "uri": "arn:aws:apigateway:us-east-1:states:action/StartSyncExecution",
            "requestTemplates": {"application/json": "#set($value = )"}
        }),
    )
    .await;
    api(
        &registry,
        "apigateway",
        Method::POST,
        &format!("/restapis/{id}/deployments"),
        json!({"stageName": "test"}),
    )
    .await;
    let (status, body) = call(
        &registry,
        "execute-api",
        Method::GET,
        &format!("/restapis/{id}/test/_user_request_/flows"),
        json!({}),
        false,
    )
    .await;
    assert_eq!(status, 500, "{body}");
    assert_eq!(body, json!({"message": "Internal server error"}));
    assert_eq!(
        calls.load(Ordering::Relaxed),
        3,
        "mapping failure must not invoke the provider"
    );
    registry.shutdown.take().unwrap().send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
