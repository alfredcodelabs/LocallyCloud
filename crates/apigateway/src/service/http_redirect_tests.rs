use super::*;
use axum::{extract::Path, routing::get, Router};
use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
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

async fn serve(router: Router) -> Backend {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Backend { url, task }
}

fn request(method: Method, path: &str, body: Value) -> ServiceRequest {
    ServiceRequest {
        method,
        uri: path.parse().unwrap(),
        headers: HeaderMap::new(),
        body: if body.is_null() {
            Bytes::new()
        } else {
            body.to_string().into()
        },
        region: "us-east-1".into(),
        account_id: "000000000000".into(),
        request_id: "http-redirect".into(),
    }
}

async fn control(handler: &ApiGwHandler, method: Method, path: &str, body: Value) -> Value {
    let response = handler.handle(request(method, path, body)).await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 65_536)
        .await
        .unwrap();
    assert!(
        status.is_success(),
        "{path}: {status} {}",
        String::from_utf8_lossy(&body)
    );
    if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    }
}

async fn wire_api(handler: &ApiGwHandler, protocol: &str, backend: &str) -> String {
    match protocol {
        "REST" | "REST_HTTP" => {
            let api = control(
                handler,
                Method::POST,
                "/restapis",
                json!({"name":"redirect"}),
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
            let method = format!("/restapis/{api}/resources/{root}/methods/GET");
            control(
                handler,
                Method::PUT,
                &method,
                json!({"authorizationType":"NONE"}),
            )
            .await;
            control(
                handler,
                Method::PUT,
                &format!("{method}/integration"),
                json!({"type":if protocol == "REST_HTTP" { "HTTP" } else { "HTTP_PROXY" },"integrationHttpMethod":"GET","uri":backend}),
            )
            .await;
            if protocol == "REST_HTTP" {
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
            }
            control(
                handler,
                Method::POST,
                &format!("/restapis/{api}/deployments"),
                json!({"stageName":"prod"}),
            )
            .await;
            format!("/restapis/{api}/prod/_user_request_/")
        }
        "HTTP" => {
            let api = control(
                handler,
                Method::POST,
                "/v2/apis",
                json!({"name":"redirect","protocolType":"HTTP"}),
            )
            .await;
            let api = api["apiId"].as_str().unwrap();
            let integration = control(handler, Method::POST, &format!("/v2/apis/{api}/integrations"), json!({"integrationType":"HTTP_PROXY","integrationMethod":"GET","integrationUri":backend})).await;
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
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn http_and_rest_proxy_preserve_redirects_without_contacting_the_target() {
    let target_hits = Arc::new(AtomicUsize::new(0));
    let hits = target_hits.clone();
    let target = serve(Router::new().fallback(get(move || {
        let hits = hits.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            "redirect-target"
        }
    })))
    .await;
    let location = format!("{}/target?data=fictional", target.url);
    let redirect_location = location.clone();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let hits = backend_hits.clone();
    let backend = serve(Router::new().route(
        "/{status}",
        get(move |Path(status): Path<u16>| {
            let location = redirect_location.clone();
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let mut response = Response::new(Body::from("backend-original"));
                *response.status_mut() = StatusCode::from_u16(status).unwrap();
                response
                    .headers_mut()
                    .insert("x-backend", "original".parse().unwrap());
                if status != 200 {
                    response
                        .headers_mut()
                        .insert("location", location.parse().unwrap());
                }
                response
            }
        }),
    ))
    .await;
    let registry = ServiceRegistry::with_known_services();
    // No IAM or external AWS provider is installed in this owned integration fixture.
    let mut handler = ApiGwHandler::new(Arc::downgrade(&registry));
    handler.http = crate::http_integration::HttpIntegrationClient::new(
        std::slice::from_ref(&backend.url),
        &[],
    )
    .unwrap();
    for protocol in ["HTTP", "REST"] {
        for status in [200, 302, 307] {
            let path = wire_api(&handler, protocol, &format!("{}/{status}", backend.url)).await;
            let response = handler
                .handle(request(Method::GET, &path, Value::Null))
                .await;
            assert_eq!(response.status().as_u16(), status, "{protocol}");
            assert_eq!(response.headers()["x-backend"], "original");
            if status == 200 {
                assert!(!response.headers().contains_key("location"));
            } else {
                assert_eq!(response.headers()["location"], location);
            }
            let body = axum::body::to_bytes(response.into_body(), 65_536)
                .await
                .unwrap();
            assert_eq!(body.as_ref(), b"backend-original");
            assert_eq!(target_hits.load(Ordering::SeqCst), 0);
        }
    }
    assert_eq!(backend_hits.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn rest_http_omits_sigv4_authorization_without_changing_other_schemes_or_v2() {
    use axum::extract::Request;
    use std::sync::Mutex;

    let received = Arc::new(Mutex::new(None));
    let seen = received.clone();
    let hits = Arc::new(AtomicUsize::new(0));
    let backend_hits = hits.clone();
    let backend = serve(Router::new().fallback(get(move |request: Request| {
        let seen = seen.clone();
        let hits = backend_hits.clone();
        async move {
            *seen.lock().unwrap() = request.headers().get(http::header::AUTHORIZATION).cloned();
            hits.fetch_add(1, Ordering::SeqCst);
            "backend-original"
        }
    })))
    .await;
    let registry = ServiceRegistry::with_known_services();
    let mut handler = ApiGwHandler::new(Arc::downgrade(&registry));
    handler.http = crate::http_integration::HttpIntegrationClient::new(
        std::slice::from_ref(&backend.url),
        &[],
    )
    .unwrap();
    for protocol in ["REST", "REST_HTTP", "HTTP"] {
        let path = wire_api(&handler, protocol, &backend.url).await;
        for authorization in [
            None,
            Some("AWS4-HMAC-SHA256 Credential=test/20261116/us-east-1/execute-api/aws4_request, SignedHeaders=host, Signature=fictional"),
            Some("Bearer fictional-token"),
            Some("Basic ZmljdGlvbmFsOm9ubHk="),
        ] {
            let mut input = request(Method::GET, &path, Value::Null);
            if let Some(authorization) = authorization {
                input.headers.insert(http::header::AUTHORIZATION, authorization.parse().unwrap());
            }
            let response = handler.handle(input).await;
            assert_eq!(response.status(), StatusCode::OK, "{protocol}");
            let body = axum::body::to_bytes(response.into_body(), 65_536).await.unwrap();
            assert_eq!(body.as_ref(), b"backend-original");
            let observed = received.lock().unwrap().clone();
            let expected = match (protocol, authorization) {
                ("REST" | "REST_HTTP", Some(value)) if value.starts_with("AWS4-HMAC-SHA256") => None,
                (_, value) => value,
            };
            // Compare without printing authorization data if a regression fails.
            assert!(observed.as_ref().and_then(|value| value.to_str().ok()) == expected, "{protocol} authorization forwarding");
        }
    }
    assert_eq!(hits.load(Ordering::SeqCst), 12);
}
