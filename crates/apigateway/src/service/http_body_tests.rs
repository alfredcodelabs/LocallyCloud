use super::*;
use axum::{routing::post, Json, Router};
use bytes::Bytes;
use http::HeaderMap;
use serde_json::json;
use std::time::Duration;
use tokio::task::JoinHandle;

struct Backend {
    url: String,
    task: JoinHandle<()>,
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn backend() -> Backend {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new().route("/", post(|headers: HeaderMap, body: Bytes| async move {
        Json(json!({
            "length": headers.get(http::header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()),
            "body": String::from_utf8(body.to_vec()).unwrap(),
        }))
    }));
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Backend { url, task }
}

fn request(method: Method, path: &str, body: Bytes) -> ServiceRequest {
    ServiceRequest {
        method,
        uri: path.parse().unwrap(),
        headers: HeaderMap::new(),
        body,
        region: "us-east-1".into(),
        account_id: "000000000000".into(),
        request_id: "http-body-length".into(),
    }
}

async fn control(handler: &ApiGwHandler, method: Method, path: &str, body: Value) -> Value {
    let bytes = if body.is_null() {
        Bytes::new()
    } else {
        body.to_string().into()
    };
    let response = handler.handle(request(method, path, bytes)).await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 65_536)
        .await
        .unwrap();
    assert!(
        status.is_success(),
        "{path}: {status}: {}",
        String::from_utf8_lossy(&body)
    );
    if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    }
}

async fn rest_api(
    handler: &ApiGwHandler,
    backend: &str,
    kind: &str,
    template: Option<&str>,
) -> String {
    let api = control(
        handler,
        Method::POST,
        "/restapis",
        json!({"name":"body-length"}),
    )
    .await;
    let api = api["id"].as_str().unwrap();
    let resources = control(
        handler,
        Method::GET,
        &format!("/restapis/{api}/resources"),
        Value::Null,
    )
    .await;
    let root = resources["item"]
        .as_array()
        .unwrap()
        .iter()
        .find(|resource| resource["path"] == "/")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let method = format!("/restapis/{api}/resources/{root}/methods/POST");
    control(
        handler,
        Method::PUT,
        &method,
        json!({"authorizationType":"NONE"}),
    )
    .await;
    let mut integration = json!({"type":kind,"integrationHttpMethod":"POST","uri":backend});
    if let Some(template) = template {
        integration["requestTemplates"] = json!({"application/json":template});
    }
    control(
        handler,
        Method::PUT,
        &format!("{method}/integration"),
        integration,
    )
    .await;
    control(
        handler,
        Method::PUT,
        &format!("{method}/responses/200"),
        json!({}),
    )
    .await;
    control(
        handler,
        Method::PUT,
        &format!("{method}/integration/responses/200"),
        json!({"statusCode":"200"}),
    )
    .await;
    control(
        handler,
        Method::POST,
        &format!("/restapis/{api}/deployments"),
        json!({"stageName":"prod"}),
    )
    .await;
    format!("/restapis/{api}/prod/_user_request_/")
}

async fn http_api(handler: &ApiGwHandler, backend: &str) -> String {
    let api = control(
        handler,
        Method::POST,
        "/v2/apis",
        json!({"name":"body-length","protocolType":"HTTP"}),
    )
    .await;
    let api = api["apiId"].as_str().unwrap();
    let integration = control(
        handler,
        Method::POST,
        &format!("/v2/apis/{api}/integrations"),
        json!({"integrationType":"HTTP_PROXY","integrationMethod":"POST","integrationUri":backend}),
    )
    .await;
    let integration = integration["integrationId"].as_str().unwrap();
    control(
        handler,
        Method::POST,
        &format!("/v2/apis/{api}/routes"),
        json!({"routeKey":"$default","target":format!("integrations/{integration}")}),
    )
    .await;
    control(
        handler,
        Method::POST,
        &format!("/v2/apis/{api}/stages"),
        json!({"stageName":"prod","autoDeploy":true}),
    )
    .await;
    format!("/execute-api/{api}/prod/probe")
}

#[tokio::test]
async fn http_integrations_generate_content_length_from_the_final_body() {
    let mut backend = backend().await;
    let registry = ServiceRegistry::with_known_services();
    let handler = ApiGwHandler::new(Arc::downgrade(&registry));
    let cases = [
        ("HTTP", None, "{}", "{}"),
        ("HTTP", Some("mapped-long-body"), "{}", "mapped-long-body"),
        ("HTTP", Some("x"), "original-long-body", "x"),
        ("HTTP_PROXY", None, "proxy-ñ", "proxy-ñ"),
        ("HTTP_V2", None, "v2-ñ", "v2-ñ"),
    ];
    for (kind, template, input, expected) in cases {
        let path = match kind {
            "HTTP_V2" => http_api(&handler, &backend.url).await,
            "HTTP" | "HTTP_PROXY" => rest_api(&handler, &backend.url, kind, template).await,
            _ => unreachable!(),
        };
        let mut req = request(
            Method::POST,
            &path,
            Bytes::copy_from_slice(input.as_bytes()),
        );
        req.headers.insert(
            http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        req.headers.insert(
            http::header::CONTENT_LENGTH,
            input.len().to_string().parse().unwrap(),
        );
        let response = tokio::time::timeout(Duration::from_secs(5), handler.handle(req))
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        assert_eq!(
            status.as_u16(),
            200,
            "{kind} {template:?}: {}",
            String::from_utf8_lossy(&body)
        );
        let echoed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(echoed["body"], expected, "{kind} {template:?}");
        assert_eq!(
            echoed["length"],
            expected.len().to_string(),
            "{kind} {template:?}"
        );
    }
    backend.task.abort();
    assert!((&mut backend.task).await.unwrap_err().is_cancelled());
}
