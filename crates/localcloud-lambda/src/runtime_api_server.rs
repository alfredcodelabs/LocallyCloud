//! HTTP surface of the Lambda Runtime API (`2018-06-01`), backed by the [`InvocationBroker`].
//!
//! A guest runtime reaches these routes at `http://$AWS_LAMBDA_RUNTIME_API/2018-06-01/...`.
//! Because a single host server multiplexes every execution environment, the environment key
//! is carried as a `/e/<key>` path prefix (embedded in the guest's `AWS_LAMBDA_RUNTIME_API`),
//! standing in for AWS's per-microVM endpoint. The routes implement the long-poll `next`,
//! `response`, `error`, and `init/error` contract (Requirements 22, 23, 24).

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use http::{HeaderMap, StatusCode};

use crate::runtime_api::{ExtensionError, FunctionErrorType, InvocationBroker, Outcome};

/// Build the Runtime API router bound to `broker`.
pub fn router(broker: Arc<InvocationBroker>) -> Router {
    Router::new()
        .route("/e/{key}/2018-06-01/runtime/invocation/next", get(next))
        .route(
            "/e/{key}/2018-06-01/runtime/invocation/{rid}/response",
            post(response),
        )
        .route(
            "/e/{key}/2018-06-01/runtime/invocation/{rid}/logs",
            post(logs),
        )
        .route(
            "/e/{key}/2018-06-01/runtime/invocation/{rid}/error",
            post(error),
        )
        .route("/e/{key}/2018-06-01/runtime/init/error", post(init_error))
        .route(
            "/e/{key}/2020-01-01/extension/register",
            post(extension_register),
        )
        .route(
            "/e/{key}/2020-01-01/extension/event/next",
            get(extension_next),
        )
        .route(
            "/e/{key}/2020-01-01/extension/init/error",
            post(extension_error),
        )
        .route(
            "/e/{key}/2020-01-01/extension/exit/error",
            post(extension_error),
        )
        .with_state(broker)
}

/// `GET .../invocation/next` — long-poll the next invocation for the environment.
async fn next(State(broker): State<Arc<InvocationBroker>>, Path(key): Path<String>) -> Response {
    match broker.next(&key).await {
        Some(inv) => Response::builder()
            .status(StatusCode::OK)
            .header("Lambda-Runtime-Aws-Request-Id", inv.request_id.clone())
            .header(
                "Lambda-Runtime-Invoked-Function-Arn",
                inv.invoked_function_arn.clone(),
            )
            .header("Lambda-Runtime-Deadline-Ms", inv.deadline_ms.to_string())
            .header("content-type", "application/json")
            .body(Body::from(inv.payload))
            .expect("runtime next response is valid"),
        // The environment was stopped: signal the runtime loop to exit.
        None => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .expect("204 is valid"),
    }
}

/// `POST .../invocation/{rid}/response` — deliver a successful result.
async fn response(
    State(broker): State<Arc<InvocationBroker>>,
    Path((_key, rid)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    broker.complete(&rid, Outcome::Success(body.to_vec()));
    accepted()
}

/// `POST .../invocation/{rid}/logs` — record managed-runtime output before completion.
async fn logs(
    State(broker): State<Arc<InvocationBroker>>,
    Path((_key, rid)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    const MAX_LOG_BODY_BYTES: usize = 1_048_576;
    const MAX_LOG_LINES: usize = 10_000;
    if body.len() > MAX_LOG_BODY_BYTES {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Ok(lines) = serde_json::from_slice::<Vec<String>>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if lines.len() > MAX_LOG_LINES || lines.iter().any(|line| line.len() > MAX_LOG_BODY_BYTES) {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    if broker.record_logs(&rid, lines) {
        accepted()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// `POST .../invocation/{rid}/error` — deliver a handler-reported function error.
async fn error(
    State(broker): State<Arc<InvocationBroker>>,
    Path((_key, rid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let error_type = classify(headers.get("Lambda-Runtime-Function-Error-Type"));
    broker.complete(
        &rid,
        Outcome::Error {
            error_type,
            payload: body.to_vec(),
        },
    );
    accepted()
}

/// `POST .../init/error` — the runtime failed to initialize; tear the environment down so its
/// pending invocation fails `Unhandled`.
async fn init_error(
    State(broker): State<Arc<InvocationBroker>>,
    Path(key): Path<String>,
    _body: Bytes,
) -> Response {
    broker.stop(&key);
    accepted()
}

/// Classify the `Lambda-Runtime-Function-Error-Type` header. A reported handler error is
/// `Handled` unless the runtime explicitly flags it `Unhandled`.
fn classify(header: Option<&http::HeaderValue>) -> FunctionErrorType {
    match header.and_then(|v| v.to_str().ok()) {
        Some(v) if v.eq_ignore_ascii_case("Unhandled") => FunctionErrorType::Unhandled,
        _ => FunctionErrorType::Handled,
    }
}

fn accepted() -> Response {
    Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"status":"OK"}"#))
        .expect("202 is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_api::FunctionErrorType;

    /// Bind the router on an ephemeral port and return its base URL.
    async fn serve(broker: Arc<InvocationBroker>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(broker)).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn guest_polls_next_and_posts_response_over_http() {
        let broker = Arc::new(InvocationBroker::new());
        let base = serve(broker.clone()).await;
        let key = "envA";

        // Host submits an invocation.
        let (rid, rx) = broker.submit(key, b"{\"n\":1}".to_vec(), "arn:aws:lambda:...:fn", 5000);

        // A real guest runtime client: GET next, then POST response.
        let client = reqwest::Client::new();
        let next = client
            .get(format!("{base}/e/{key}/2018-06-01/runtime/invocation/next"))
            .send()
            .await
            .unwrap();
        assert_eq!(next.status(), 200);
        assert_eq!(
            next.headers()
                .get("Lambda-Runtime-Aws-Request-Id")
                .unwrap()
                .to_str()
                .unwrap(),
            rid
        );
        assert!(next.headers().get("Lambda-Runtime-Deadline-Ms").is_some());
        let event = next.text().await.unwrap();
        assert_eq!(event, "{\"n\":1}");

        let posted = client
            .post(format!(
                "{base}/e/{key}/2018-06-01/runtime/invocation/{rid}/response"
            ))
            .body("{\"ok\":true}")
            .send()
            .await
            .unwrap();
        assert_eq!(posted.status(), 202);

        // The host's submit resolves with the byte-exact response.
        assert_eq!(
            rx.await.unwrap(),
            Outcome::Success(b"{\"ok\":true}".to_vec())
        );
    }

    #[tokio::test]
    async fn guest_posts_error() {
        let broker = Arc::new(InvocationBroker::new());
        let base = serve(broker.clone()).await;
        let (rid, rx) = broker.submit("envB", b"e".to_vec(), "arn", 5000);
        let client = reqwest::Client::new();
        client
            .get(format!("{base}/e/envB/2018-06-01/runtime/invocation/next"))
            .send()
            .await
            .unwrap();
        client
            .post(format!(
                "{base}/e/envB/2018-06-01/runtime/invocation/{rid}/error"
            ))
            .header("Lambda-Runtime-Function-Error-Type", "Unhandled")
            .body(r#"{"errorMessage":"boom"}"#)
            .send()
            .await
            .unwrap();
        match rx.await.unwrap() {
            Outcome::Error {
                error_type,
                payload,
            } => {
                assert_eq!(error_type, FunctionErrorType::Unhandled);
                assert_eq!(payload, br#"{"errorMessage":"boom"}"#);
            }
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn next_returns_204_after_stop() {
        let broker = Arc::new(InvocationBroker::new());
        let base = serve(broker.clone()).await;
        broker.stop("envC");
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{base}/e/envC/2018-06-01/runtime/invocation/next"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);
    }
}

fn extension_status(error: ExtensionError) -> Response {
    match error {
        ExtensionError::BadRequest => StatusCode::BAD_REQUEST.into_response(),
        ExtensionError::Forbidden => StatusCode::FORBIDDEN.into_response(),
        ExtensionError::Failed => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, StatusCode> {
    headers
        .get(name)
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)
}

async fn extension_register(
    State(broker): State<Arc<InvocationBroker>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(name) = required_header(&headers, "Lambda-Extension-Name") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if body.len() > 65536 {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let value: serde_json::Value = if body.is_empty() {
        serde_json::json!({})
    } else {
        match serde_json::from_slice(&body) {
            Ok(value) => value,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    };
    let Some(object) = value.as_object() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let events = match object.get("events") {
        None => Vec::new(),
        Some(serde_json::Value::Array(values)) => {
            let Some(events) = values
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
            else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            events
        }
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    match broker.register_extension(&key, name, events) {
        Ok((id, response)) => Response::builder()
            .status(StatusCode::OK)
            .header("Lambda-Extension-Identifier", id)
            .header("content-type", "application/json")
            .body(Body::from(response.to_string()))
            .expect("extension register response is valid"),
        Err(error) => extension_status(error),
    }
}

async fn extension_next(
    State(broker): State<Arc<InvocationBroker>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(id) = required_header(&headers, "Lambda-Extension-Identifier") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match broker.next_extension(&key, id).await {
        Ok(event) => Response::builder()
            .status(StatusCode::OK)
            .header("Lambda-Extension-Event-Identifier", event.id)
            .header("content-type", "application/json")
            .body(Body::from(event.payload.to_string()))
            .expect("extension event response is valid"),
        Err(error) => extension_status(error),
    }
}

async fn extension_error(
    State(broker): State<Arc<InvocationBroker>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(id) = required_header(&headers, "Lambda-Extension-Identifier") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if required_header(&headers, "Lambda-Extension-Function-Error-Type").is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if body.len() > 65536 {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    if !body.is_empty() && serde_json::from_slice::<serde_json::Value>(&body).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match broker.report_extension_error(&key, id) {
        Ok(()) => accepted(),
        Err(error) => extension_status(error),
    }
}

#[cfg(test)]
mod extension_tests {
    use super::*;
    use tokio::time::{Duration, Instant};

    async fn serve(broker: Arc<InvocationBroker>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(broker)).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn two_extensions_init_invoke_rearm_and_shutdown() {
        let broker = Arc::new(InvocationBroker::new());
        broker
            .discover_expected_extensions(
                "a",
                vec!["one".into(), "two".into()],
                "fn",
                "7",
                "handler",
            )
            .unwrap();
        let base = serve(broker.clone()).await;
        let client = reqwest::Client::new();
        let mut ids = Vec::new();
        for name in ["one", "two"] {
            let response = client
                .post(format!("{base}/e/a/2020-01-01/extension/register"))
                .header("Lambda-Extension-Name", name)
                .json(&serde_json::json!({"events":["INVOKE","SHUTDOWN"]}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            ids.push(
                response.headers()["Lambda-Extension-Identifier"]
                    .to_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        // An identifier from another environment cannot poll this environment.
        let other = client
            .get(format!("{base}/e/b/2020-01-01/extension/event/next"))
            .header("Lambda-Extension-Identifier", &ids[0])
            .send()
            .await
            .unwrap();
        assert_eq!(other.status(), 403);
        let mut polls = Vec::new();
        for id in &ids {
            let client = client.clone();
            let url = format!("{base}/e/a/2020-01-01/extension/event/next");
            let id = id.clone();
            polls.push(tokio::spawn(async move {
                client
                    .get(url)
                    .header("Lambda-Extension-Identifier", id)
                    .send()
                    .await
                    .unwrap()
            }));
        }
        let runtime_client = client.clone();
        let runtime_url = format!("{base}/e/a/2018-06-01/runtime/invocation/next");
        let runtime_poll =
            tokio::spawn(async move { runtime_client.get(runtime_url).send().await.unwrap() });
        broker
            .wait_init_ready("a", Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let (rid, _rx) = broker.submit("a", b"{}".to_vec(), "arn:fn", 5000);
        for poll in polls {
            let response = poll.await.unwrap();
            assert_eq!(response.status(), 200);
            assert!(response
                .headers()
                .contains_key("Lambda-Extension-Event-Identifier"));
            let event: serde_json::Value = response.json().await.unwrap();
            assert_eq!(event["eventType"], "INVOKE");
            assert_eq!(event["requestId"], rid);
        }
        assert_eq!(runtime_poll.await.unwrap().status(), 200);
        assert!(broker
            .wait_extensions_rearmed("a", &rid, Instant::now() + Duration::from_millis(20))
            .await
            .is_err());
        let mut next_polls = Vec::new();
        for id in &ids {
            let client = client.clone();
            let url = format!("{base}/e/a/2020-01-01/extension/event/next");
            let id = id.clone();
            next_polls.push(tokio::spawn(async move {
                client
                    .get(url)
                    .header("Lambda-Extension-Identifier", id)
                    .send()
                    .await
                    .unwrap()
            }));
        }
        let runtime_client = client.clone();
        let runtime_url = format!("{base}/e/a/2018-06-01/runtime/invocation/next");
        let runtime_rearm =
            tokio::spawn(async move { runtime_client.get(runtime_url).send().await.unwrap() });
        broker
            .wait_extensions_rearmed("a", &rid, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        broker.begin_shutdown("a", "SPINDOWN", 12345);
        for poll in next_polls {
            let response = poll.await.unwrap();
            assert_eq!(response.status(), 200);
            let event: serde_json::Value = response.json().await.unwrap();
            assert_eq!(event["eventType"], "SHUTDOWN");
            assert_eq!(event["shutdownReason"], "SPINDOWN");
        }
        runtime_rearm.abort();
        let _ = runtime_rearm.await;
        broker.extension_exited("a", "one", true);
        broker.extension_exited("a", "two", true);
        broker
            .wait_shutdown_done("a", Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn canceled_broker_polls_revoke_init_and_warm_readiness() {
        let broker = Arc::new(InvocationBroker::new());
        broker
            .discover_expected_extensions("cancel", vec!["one".into()], "fn", "3", "h")
            .unwrap();
        let base = serve(broker.clone()).await;
        let client = reqwest::Client::new();
        let register = client
            .post(format!("{base}/e/cancel/2020-01-01/extension/register"))
            .header("Lambda-Extension-Name", "one")
            .json(&serde_json::json!({"events":["INVOKE","SHUTDOWN"]}))
            .send()
            .await
            .unwrap();
        let id = register.headers()["Lambda-Extension-Identifier"]
            .to_str()
            .unwrap()
            .to_owned();
        let body: serde_json::Value = register.json().await.unwrap();
        assert_eq!(body["functionVersion"], "3");
        let ext = broker.clone();
        let ext_id = id.clone();
        let first_poll = tokio::spawn(async move { ext.next_extension("cancel", &ext_id).await });
        let runtime = broker.clone();
        let runtime_poll = tokio::spawn(async move { runtime.next("cancel").await });
        broker
            .wait_init_ready("cancel", Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let concurrent = client
            .get(format!("{base}/e/cancel/2020-01-01/extension/event/next"))
            .header("Lambda-Extension-Identifier", &id)
            .send()
            .await
            .unwrap();
        assert_eq!(concurrent.status(), 400);
        first_poll.abort();
        let _ = first_poll.await;
        assert!(broker
            .wait_init_ready("cancel", Instant::now() + Duration::from_millis(20))
            .await
            .is_err());
        let ext = broker.clone();
        let ext_id = id.clone();
        let second_poll = tokio::spawn(async move { ext.next_extension("cancel", &ext_id).await });
        broker
            .wait_init_ready("cancel", Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        runtime_poll.abort();
        let _ = runtime_poll.await;
        assert!(broker
            .wait_init_ready("cancel", Instant::now() + Duration::from_millis(20))
            .await
            .is_err());
        let runtime = broker.clone();
        let runtime_poll = tokio::spawn(async move { runtime.next("cancel").await });
        broker
            .wait_init_ready("cancel", Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        let (rid, _rx) = broker.submit("cancel", b"{}".to_vec(), "arn:fn", 5000);
        assert_eq!(
            second_poll.await.unwrap().unwrap().payload["eventType"],
            "INVOKE"
        );
        assert_eq!(runtime_poll.await.unwrap().unwrap().request_id, rid);
        let ext = broker.clone();
        let ext_id = id.clone();
        let rearm = tokio::spawn(async move { ext.next_extension("cancel", &ext_id).await });
        let runtime = broker.clone();
        let runtime_rearm = tokio::spawn(async move { runtime.next("cancel").await });
        broker
            .wait_extensions_rearmed("cancel", &rid, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        assert!(broker.environment_healthy("cancel"));
        rearm.abort();
        let _ = rearm.await;
        runtime_rearm.abort();
        let _ = runtime_rearm.await;
        assert!(broker
            .wait_extensions_rearmed("cancel", &rid, Instant::now() + Duration::from_millis(20))
            .await
            .is_err());
        assert!(!broker.environment_healthy("cancel"));
    }

    #[tokio::test]
    async fn registration_validation_error_and_empty_environment() {
        let broker = Arc::new(InvocationBroker::new());
        broker
            .discover_expected_extensions("empty", vec![], "fn", "$LATEST", "h")
            .unwrap();
        assert!(!broker.has_extensions("empty"));
        let runtime = broker.clone();
        tokio::spawn(async move { runtime.next("empty").await });
        broker
            .wait_init_ready("empty", Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(broker
            .discover_expected_extensions("bad", vec!["../bad".into()], "f", "$LATEST", "h")
            .is_err());
        let names = (0..11).map(|i| format!("ext{i}")).collect();
        assert!(broker
            .discover_expected_extensions("many", names, "f", "$LATEST", "h")
            .is_err());
        broker
            .discover_expected_extensions("err", vec!["one".into()], "f", "$LATEST", "h")
            .unwrap();
        let base = serve(broker.clone()).await;
        let client = reqwest::Client::new();
        let url = format!("{base}/e/err/2020-01-01/extension/register");
        assert_eq!(
            client
                .post(&url)
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
        assert_eq!(
            client
                .post(&url)
                .header("Lambda-Extension-Name", "one")
                .json(&serde_json::json!({"events":["BAD"]}))
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
        let register = client
            .post(&url)
            .header("Lambda-Extension-Name", "one")
            .json(&serde_json::json!({"events":["INVOKE"]}))
            .send()
            .await
            .unwrap();
        assert_eq!(register.status(), 200);
        let id = register.headers()["Lambda-Extension-Identifier"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            client
                .post(&url)
                .header("Lambda-Extension-Name", "one")
                .json(&serde_json::json!({"events":["INVOKE"]}))
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        let error = client
            .post(format!("{base}/e/err/2020-01-01/extension/init/error"))
            .header("Lambda-Extension-Identifier", id)
            .header(
                "Lambda-Extension-Function-Error-Type",
                "Extension.ConfigInvalid",
            )
            .json(&serde_json::json!({"errorMessage":"bad"}))
            .send()
            .await
            .unwrap();
        assert_eq!(error.status(), 202);
        assert!(broker
            .wait_init_ready("err", Instant::now() + Duration::from_millis(10))
            .await
            .is_err());
    }
}
