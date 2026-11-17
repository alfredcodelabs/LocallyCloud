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

const PRIVATE_KEY: &str = "AKIA1234567890123456";
const PRIVATE_ACCOUNT: &str = "000000000000";

fn private_fixture(
    mode: locallycloud_iam_sts::enforcement::EnforcementMode,
) -> (Arc<ServiceRegistry>, Arc<ApiGwHandler>) {
    let registry = Arc::new(ServiceRegistry::new());
    let config = locallycloud_iam_sts::IamConfig { enforcement: mode };
    let credentials = locallycloud_iam_sts::IamCredentials::from_lookup(
        PRIVATE_ACCOUNT,
        config,
        |name| match name {
            "LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID" => Some(PRIVATE_KEY.into()),
            "LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY" => Some("a".repeat(40).into()),
            _ => None,
        },
    )
    .unwrap();
    locallycloud_iam_sts::register_with_account_and_inputs(
        &registry,
        PRIVATE_ACCOUNT,
        config,
        credentials,
    )
    .unwrap();
    let handler = Arc::new(ApiGwHandler::new(Arc::downgrade(&registry)));
    let mut record = record("PRIVATE");
    record.api["policy"] = json!(json!({"Statement":{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"*","Condition":{
        "StringEquals":{"aws:SourceVpc":"vpc-owned","aws:SourceVpce":"vpce-owned","aws:RequestedRegion":"us-east-1"},
        "IpAddress":{"aws:VpcSourceIp":"10.0.0.0/24"},"Null":{"aws:SourceIp":"true","aws:SourceAccount":"true"},"Bool":{"aws:SecureTransport":"true"}
    }}}).to_string());
    record.api["endpointConfiguration"]["vpcEndpointIds"] = json!(["vpce-owned"]);
    record
        .deployment_snapshots
        .insert("deployed".into(), record.snapshot());
    handler
        .store
        .insert_rest(PRIVATE_ACCOUNT, "us-east-1", "api", record);
    registry.register_native(
        ServiceName::new("execute-api"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        handler.clone(),
    );
    registry.set_internal_dispatcher(Arc::new(
        locallycloud_core::integration::InternalDispatcher::new_shared(
            &registry,
            locallycloud_core::proxy::ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: std::time::Duration::from_secs(1),
            },
            locallycloud_core::proxy::LegacyHealth::new(false),
            "us-east-1".into(),
            PRIVATE_ACCOUNT.into(),
        ),
    ));
    (registry, handler)
}

fn ingress() -> PrivateApiIngress {
    PrivateApiIngress {
        endpoint_account: PRIVATE_ACCOUNT.into(), endpoint_region: "us-east-1".into(),
        vpc_id: "vpc-owned".into(), vpce_id: "vpce-owned".into(),
        original_source_ip: "10.0.0.4".parse().unwrap(), endpoint_ip: "10.0.0.5".parse().unwrap(),
        secure_transport: true,
        endpoint_policy: json!({"Statement":{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"*"}}).to_string(),
    }
}

fn private_request(host: &str, signed: bool) -> ServiceRequest {
    let mut request = ServiceRequest {
        method: Method::POST,
        uri: "/prod/".parse().unwrap(),
        headers: HeaderMap::from_iter([(http::header::HOST, host.parse().unwrap())]),
        body: Bytes::from_static(b"{}"),
        region: "us-east-1".into(),
        account_id: PRIVATE_ACCOUNT.into(),
        request_id: "trusted-private-test".into(),
    };
    if signed {
        sign_private(&mut request);
    }
    request
}

fn sign_private(request: &mut ServiceRequest) {
    locallycloud_core::integration::sigv4::sign(
        &request.method,
        &request.uri,
        &mut request.headers,
        &request.body,
        "us-east-1",
        "execute-api",
        PRIVATE_KEY,
        &locallycloud_core::integration::authorization::SigningCredentials {
            secret_access_key: "a".repeat(40),
            session_token: None,
        },
    )
    .unwrap();
}

#[tokio::test]
async fn private_ingress_uses_trusted_context_and_enforces_endpoint_policy_in_both_modes() {
    use locallycloud_iam_sts::enforcement::EnforcementMode;
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let (registry, handler) = private_fixture(mode);
        let host = "api.execute-api.us-east-1.amazonaws.com";
        assert_eq!(
            handler
                .handle_private(private_request(host, false), ingress())
                .await
                .status(),
            200
        );
        assert_eq!(
            handler.handle(private_request(host, false)).await.status(),
            403
        );
        let mut bearer = private_request(host, false);
        for authorization in ["Bearer opaque-token", "Bearer Credential=opaque-token"] {
            bearer
                .headers
                .insert(http::header::AUTHORIZATION, authorization.parse().unwrap());
            assert_eq!(
                handler
                    .handle_private(bearer.clone(), ingress())
                    .await
                    .status(),
                200
            );
            let dispatcher = registry.internal_dispatcher().unwrap();
            assert_eq!(
                dispatcher
                    .dispatch_private_api(
                        &bearer.method,
                        &bearer.uri,
                        &bearer.headers,
                        bearer.body.clone(),
                        &bearer.request_id,
                        ingress()
                    )
                    .await
                    .status(),
                200
            );
        }
        let mut restricted = ingress();
        restricted.endpoint_policy = json!({"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/locallycloud-bootstrap"},"Action":"execute-api:Invoke","Resource":"*"}}).to_string();
        assert_eq!(
            handler
                .handle_private(private_request(host, false), restricted.clone())
                .await
                .status(),
            403
        );
        assert_eq!(
            handler
                .handle_private(bearer, restricted.clone())
                .await
                .status(),
            403
        );
        assert_eq!(
            handler
                .handle_private(private_request(host, true), restricted)
                .await
                .status(),
            200
        );
        let mut invalid = private_request(host, true);
        invalid.body = Bytes::from_static(b"tampered");
        assert_eq!(
            handler.handle_private(invalid, ingress()).await.status(),
            403
        );
        let mut denied = ingress();
        denied.endpoint_policy = json!({"Statement":{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"arn:aws:execute-api:us-east-1:000000000000:other/*"}}).to_string();
        assert_eq!(
            handler
                .handle_private(private_request(host, true), denied)
                .await
                .status(),
            403
        );
        for changed in 0..5 {
            let mut wrong = ingress();
            match changed {
                0 => wrong.vpc_id = "vpc-other".into(),
                1 => wrong.vpce_id = "vpce-other".into(),
                2 => wrong.original_source_ip = "10.1.0.4".parse().unwrap(),
                3 => wrong.endpoint_account = "111111111111".into(),
                4 => wrong.endpoint_region = "us-west-2".into(),
                _ => unreachable!(),
            }
            let mut spoof = private_request(host, false);
            spoof
                .headers
                .insert("x-amzn-vpc-id", "vpc-owned".parse().unwrap());
            spoof
                .headers
                .insert("x-amzn-vpce-id", "vpce-owned".parse().unwrap());
            spoof
                .headers
                .insert("x-forwarded-for", "10.0.0.4".parse().unwrap());
            assert_eq!(handler.handle_private(spoof, wrong).await.status(), 403);
        }
        let mut wrong = ingress();
        wrong.secure_transport = false;
        assert_eq!(
            handler
                .handle_private(private_request(host, false), wrong)
                .await
                .status(),
            403
        );
    }
}

#[tokio::test]
async fn private_dns_variants_preserve_original_signature_and_require_alias_association() {
    let (_registry, handler) =
        private_fixture(locallycloud_iam_sts::enforcement::EnforcementMode::Strict);
    for host in [
        "api.execute-api.us-east-1.amazonaws.com",
        "api-vpce-owned.execute-api.us-east-1.amazonaws.com",
    ] {
        assert_eq!(
            handler
                .handle_private(private_request(host, true), ingress())
                .await
                .status(),
            200
        );
    }
    assert_ne!(
        handler
            .handle_private(
                private_request("api.execute-api.us-west-2.amazonaws.com", true),
                ingress()
            )
            .await
            .status(),
        200
    );
    let mut request = private_request(
        "vpce-owned-zone.execute-api.us-east-1.vpce.amazonaws.com",
        false,
    );
    request
        .headers
        .insert("x-apigw-api-id", "api".parse().unwrap());
    sign_private(&mut request);
    assert_eq!(
        handler.handle_private(request, ingress()).await.status(),
        200
    );
    let stored = handler
        .store
        .rest(PRIVATE_ACCOUNT, "us-east-1", "api")
        .unwrap();
    stored.write().await.api["endpointConfiguration"]["vpcEndpointIds"] = json!([]);
    assert_eq!(
        handler
            .handle_private(
                private_request("api-vpce-owned.execute-api.us-east-1.amazonaws.com", true),
                ingress()
            )
            .await
            .status(),
        403
    );
    assert_eq!(
        handler
            .handle_private(
                private_request("api.execute-api.us-east-1.amazonaws.com", true),
                ingress()
            )
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn private_signed_none_checks_resource_principal_deny_without_identity_union() {
    let (_registry, handler) =
        private_fixture(locallycloud_iam_sts::enforcement::EnforcementMode::Permissive);
    let stored = handler
        .store
        .rest(PRIVATE_ACCOUNT, "us-east-1", "api")
        .unwrap();
    {
        let mut guard = stored.write().await;
        guard.api["policy"] = json!(json!({"Statement":[
            {"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"*"},
            {"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::000000000000:user/locallycloud-bootstrap"},"Action":"execute-api:Invoke","Resource":"*"}
        ]}).to_string());
        let snapshot = guard.snapshot();
        guard
            .deployment_snapshots
            .insert("deployed".into(), snapshot);
    }
    let host = "api.execute-api.us-east-1.amazonaws.com";
    assert_eq!(
        handler
            .handle_private(private_request(host, false), ingress())
            .await
            .status(),
        200
    );
    assert_eq!(
        handler
            .handle_private(private_request(host, true), ingress())
            .await
            .status(),
        403
    );
}

#[tokio::test]
async fn private_aws_iam_methods_require_signatures_in_both_modes_and_no_management_fallback() {
    use locallycloud_iam_sts::enforcement::EnforcementMode;
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let (_registry, handler) = private_fixture(mode);
        let stored = handler
            .store
            .rest(PRIVATE_ACCOUNT, "us-east-1", "api")
            .unwrap();
        {
            let mut guard = stored.write().await;
            guard.resources.get_mut("root").unwrap()["resourceMethods"]["POST"]
                ["authorizationType"] = json!("AWS_IAM");
            let snapshot = guard.snapshot();
            guard
                .deployment_snapshots
                .insert("deployed".into(), snapshot);
        }
        let host = "api.execute-api.us-east-1.amazonaws.com";
        assert_eq!(
            handler
                .handle_private(private_request(host, false), ingress())
                .await
                .status(),
            403
        );
        assert_eq!(
            handler
                .handle_private(private_request(host, true), ingress())
                .await
                .status(),
            200
        );
        let mut management = private_request("aws.localhost", false);
        management.uri = "/restapis".parse().unwrap();
        management.body = Bytes::from_static(br#"{"name":"must-not-create"}"#);
        assert_eq!(
            handler.handle_private(management, ingress()).await.status(),
            403
        );
        assert_eq!(
            handler.store.list_rest(PRIVATE_ACCOUNT, "us-east-1").len(),
            1
        );
        {
            let mut guard = stored.write().await;
            guard.api["policy"] = Value::Null;
            let snapshot = guard.snapshot();
            guard
                .deployment_snapshots
                .insert("deployed".into(), snapshot);
        }
        assert_eq!(
            handler
                .handle_private(private_request(host, true), ingress())
                .await
                .status(),
            403
        );
    }
}
