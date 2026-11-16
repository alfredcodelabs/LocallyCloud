use super::*;
use bytes::Bytes;
use http::HeaderMap;
use serde_json::json;

async fn call(handler: &ApiGwHandler, method: Method, path: &str, body: Value) -> (u16, Value) {
    let response = handler
        .handle(ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from(body.to_string()),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "private-endpoint-test".into(),
        })
        .await;
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn record(kind: &str) -> crate::store::RestApiRecord {
    let mut record = crate::store::RestApiRecord {
        api: json!({"id":"api", "endpointConfiguration":{"types":[kind]}}),
        ..Default::default()
    };
    record.resources.insert("root".into(), json!({"id":"root", "path":"/", "resourceMethods":{
        "POST":{"authorizationType":"NONE", "methodIntegration":{"type":"MOCK", "integrationResponses":{"200":{"statusCode":"200"}}}}
    }}));
    record
        .deployment_snapshots
        .insert("deployed".into(), record.snapshot());
    record
        .stages
        .insert("prod".into(), json!({"deploymentId":"deployed"}));
    record
}

#[tokio::test]
async fn private_endpoint_gate_uses_the_deployment_and_blocks_spoofed_requests() {
    let handler = ApiGwHandler::new(Weak::new());
    handler
        .store
        .insert_rest("000000000000", "us-east-1", "api", record("REGIONAL"));
    let path = "/restapis/api/prod/_user_request_/";
    assert_eq!(call(&handler, Method::POST, path, json!({})).await.0, 200);
    let (status, _) = call(
        &handler,
        Method::PATCH,
        "/restapis/api",
        json!({"patchOperations":[{
            "op":"replace", "path":"/endpointConfiguration/types/REGIONAL", "value":"PRIVATE"
        }]}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(call(&handler, Method::POST, path, json!({})).await.0, 200);
    let stored = handler
        .store
        .rest("000000000000", "us-east-1", "api")
        .unwrap();
    {
        let mut guard = stored.write().await;
        // Even an invalid stored private deployment without a policy must remain closed.
        let snapshot = guard.snapshot();
        guard
            .deployment_snapshots
            .insert("deployed".into(), snapshot);
        guard.api["endpointConfiguration"]["types"] = json!(["REGIONAL"]);
    }
    for (host, path) in [
        ("aws.localhost", path),
        ("api.execute-api.us-east-1.amazonaws.com", "/prod/"),
    ] {
        let request = ServiceRequest {
            method: Method::POST,
            uri: path.parse().unwrap(),
            headers: HeaderMap::from_iter([
                (http::header::HOST, host.parse().unwrap()),
                (
                    http::HeaderName::from_static("x-amzn-vpc-id"),
                    "vpc-forged".parse().unwrap(),
                ),
                (
                    http::HeaderName::from_static("x-amzn-vpce-id"),
                    "vpce-forged".parse().unwrap(),
                ),
            ]),
            body: Bytes::from_static(b"{}"),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "private-spoof".into(),
        };
        assert_eq!(handler.handle(request).await.status(), 403);
    }
}

#[tokio::test]
async fn private_deployment_requires_policy_without_creating_a_stage_or_deployment() {
    let handler = ApiGwHandler::new(Weak::new());
    let (_, api) = call(
        &handler,
        Method::POST,
        "/restapis",
        json!({"name":"private", "endpointConfiguration":{"types":["PRIVATE"]}}),
    )
    .await;
    let id = api["id"].as_str().unwrap();
    let (status, error) = call(
        &handler,
        Method::POST,
        &format!("/restapis/{id}/deployments"),
        json!({"stageName":"prod", "stageDescription":{"accessLogSettings":{
            "destinationArn":"arn:aws:logs:us-east-1:000000000000:log-group:private-deployment",
            "format":"$context.requestId"
        }}}),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        error["message"],
        "Private REST APIs require a resource policy before deployment"
    );
    assert_eq!(
        call(
            &handler,
            Method::POST,
            &format!("/restapis/{id}/deployments"),
            json!({"stageName":"prod"})
        )
        .await
        .0,
        400
    );
    let record = handler.store.rest("000000000000", "us-east-1", id).unwrap();
    let guard = record.read().await;
    assert!(guard.deployments.is_empty());
    assert!(guard.deployment_snapshots.is_empty());
    assert!(guard.stages.is_empty());
}

#[tokio::test]
async fn malformed_endpoint_configuration_and_invalid_private_transition_fail_atomically() {
    let handler = ApiGwHandler::new(Weak::new());
    for configuration in [
        json!("PRIVATE"),
        json!({"types":"PRIVATE"}),
        json!({"types":["PRIVATE","REGIONAL"]}),
        json!({"types":[false]}),
        json!({"types":["unknown"]}),
    ] {
        assert_eq!(
            call(
                &handler,
                Method::POST,
                "/restapis",
                json!({"name":"invalid", "endpointConfiguration":configuration})
            )
            .await
            .0,
            400
        );
    }
    assert!(handler
        .store
        .list_rest("000000000000", "us-east-1")
        .is_empty());
    handler
        .store
        .insert_rest("000000000000", "us-east-1", "api", record("PRIVATE"));
    assert_eq!(call(&handler, Method::PATCH, "/restapis/api", json!({"patchOperations":[{"op":"replace","path":"/endpointConfiguration/types/PRIVATE","value":"EDGE"}]})).await.0, 400);
    let record = handler
        .store
        .rest("000000000000", "us-east-1", "api")
        .unwrap();
    assert_eq!(
        record.read().await.api["endpointConfiguration"]["types"],
        json!(["PRIVATE"])
    );
}
