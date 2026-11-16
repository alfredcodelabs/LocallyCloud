use super::*;
use axum::{extract::Request, routing::get, Router};
use std::sync::Arc;

#[tokio::test]
async fn iam_method_outbound_rule_drops_authorization_without_mutating_caller_headers() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(get(|request: Request| async move {
                if request.headers().contains_key(http::header::AUTHORIZATION) {
                    "present"
                } else {
                    "absent"
                }
            })),
        )
        .await
        .unwrap();
    });
    let registry = Arc::new(ServiceRegistry::new());
    let weak = Arc::downgrade(&registry);
    let store = ApiGwStore::new();
    let validator = JwtValidator::new();
    let http = reqwest::Client::new();
    let sampler = Sampler::default();
    let ctx = ExecuteCtx {
        original_request: None,
        store: &store,
        validator: &validator,
        http: &http,
        registry: &weak,
        account: "000000000000",
        region: "us-east-1",
        request_id: "outbound-header",
        waf: None,
        policy_context: &BTreeMap::new(),
        trusted_peer_ip: None,
        trace_header: None,
        trace_sampler: &sampler,
        stage_trace: None,
    };
    let method = Method::GET;
    let uri: Uri = "/".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        "Bearer fictional-token".parse().unwrap(),
    );
    let params = BTreeMap::new();
    // AWS_IAM REST invocation remains unsupported. Exercise only the private
    // outbound rule with metadata that a future verified IAM method would supply.
    let request = IntegrationRequest {
        method: &method,
        host: "api.example",
        uri: &uri,
        headers: &headers,
        rest_authorization_type: Some("AWS_IAM"),
        body: Bytes::new(),
        api_id: "api",
        stage: "prod",
        path: "/",
        route_template: "/",
        resource_id: "root",
        path_params: &params,
        variables: &params,
        auth: AuthContext::default(),
    };
    let response = forward_http_raw(&ctx, &json!({}), &request, &backend, Bytes::new())
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body.as_ref(), b"absent");
    assert!(headers.contains_key(http::header::AUTHORIZATION));
    task.abort();
    let _ = task.await;
}
