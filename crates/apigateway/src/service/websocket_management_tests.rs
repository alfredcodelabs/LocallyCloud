use super::*;
use locallycloud_core::integration::authorization::{
    AuthorizationError, AuthorizationEvaluator, AuthorizationRequest,
};
use std::sync::atomic::{AtomicBool, Ordering};

const ACCOUNT: &str = "000000000000";
const REGION: &str = "us-east-1";
const CONNECTION: &str = "connection=";

struct ManagementAuthorization {
    allow: AtomicBool,
    seen: std::sync::Mutex<Vec<AuthorizationRequest>>,
}
impl AuthorizationEvaluator for ManagementAuthorization {
    fn strict_sigv4_required(&self) -> bool {
        true
    }
    fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError> {
        let allowed = self.allow.load(Ordering::SeqCst)
            && request.request_identity.access_key_id.as_deref() == Some("known")
            && request.action == "execute-api:ManageConnections"
            && request
                .resource
                .starts_with("arn:aws:execute-api:us-east-1:000000000000:api/prod/")
            && request.resource.ends_with("/@connections/connection=");
        self.seen.lock().unwrap().push(request);
        if allowed {
            Ok(())
        } else {
            Err(AuthorizationError::Denied)
        }
    }
}

async fn fixture(
    allow: bool,
) -> (
    Arc<ServiceRegistry>,
    ApiGwHandler,
    Arc<ManagementAuthorization>,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    let registry = ServiceRegistry::with_known_services();
    let authorization = Arc::new(ManagementAuthorization {
        allow: AtomicBool::new(allow),
        seen: Default::default(),
    });
    registry.register_native_with_authorization_evaluator(
        ServiceName::new("iam"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        Arc::new(test_handler(Weak::new())),
        authorization.clone(),
    );
    let handler = test_handler(Arc::downgrade(&registry));
    websocket::register_test_connection(&handler.store, ACCOUNT, REGION, CONNECTION, "api", "prod")
        .await;
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    handler
        .store
        .register_connection_sender(ACCOUNT, REGION, CONNECTION, sender);
    (registry, handler, authorization, receiver)
}
fn signed(method: Method, path: &str, host: &str) -> ServiceRequest {
    let mut request = req(method, path, Value::Null);
    request.body = Bytes::from_static(b"message");
    request.headers.insert("host", host.parse().unwrap());
    request.headers.insert(
        "authorization",
        "AWS4-HMAC-SHA256 Credential=known/20261116/us-east-1/execute-api/aws4_request"
            .parse()
            .unwrap(),
    );
    request.headers.insert(
        "x-locallycloud-verified-external-sigv4",
        "1".parse().unwrap(),
    );
    request.headers.insert(
        "x-locallycloud-trusted-peer-ip",
        "127.0.0.1".parse().unwrap(),
    );
    request.headers.insert(
        "x-locallycloud-verified-secure-transport",
        "false".parse().unwrap(),
    );
    request
        .headers
        .insert("x-forwarded-for", "198.51.100.123".parse().unwrap());
    request
        .headers
        .insert("x-forwarded-proto", "https".parse().unwrap());
    request
}

#[tokio::test]
async fn strict_management_denies_all_methods_before_connection_lookup_or_effects() {
    let (_registry, handler, authorization, mut receiver) = fixture(false).await;
    for method in [Method::GET, Method::POST, Method::DELETE] {
        for id in ["connection%3D", "missing"] {
            assert_eq!(
                handler
                    .handle(signed(
                        method.clone(),
                        &format!("/prod/@connections/{id}"),
                        "api.execute-api.us-east-1.amazonaws.com"
                    ))
                    .await
                    .status(),
                403
            );
        }
    }
    assert_eq!(authorization.seen.lock().unwrap().len(), 6);
    assert!(handler
        .store
        .shared(ACCOUNT, REGION)
        .read()
        .await
        .connections
        .contains_key(CONNECTION));
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn management_permissions_use_real_endpoint_scope_decoded_id_and_verified_network_context() {
    let (_registry, handler, authorization, mut receiver) = fixture(true).await;
    for method in [Method::GET, Method::POST] {
        assert_eq!(
            handler
                .handle(signed(
                    method.clone(),
                    "/prod/@connections/connection%3D",
                    "api.execute-api.us-east-1.amazonaws.com"
                ))
                .await
                .status(),
            200
        );
    }
    assert_eq!(receiver.try_recv().unwrap(), b"message");
    for (host, path) in [
        (
            "other.execute-api.us-east-1.amazonaws.com",
            "/prod/@connections/connection%3D",
        ),
        (
            "api.execute-api.us-east-1.amazonaws.com",
            "/other/@connections/connection%3D",
        ),
    ] {
        assert_eq!(
            handler
                .handle(signed(Method::DELETE, path, host))
                .await
                .status(),
            403
        );
    }
    {
        let requests = authorization.seen.lock().unwrap();
        assert_eq!(
            requests[0].resource,
            "arn:aws:execute-api:us-east-1:000000000000:api/prod/GET/@connections/connection="
        );
        assert_eq!(
            requests[1].resource,
            "arn:aws:execute-api:us-east-1:000000000000:api/prod/POST/@connections/connection="
        );
        for request in requests.iter() {
            assert_eq!(request.context["aws:sourceip"], ["127.0.0.1"]);
            assert_eq!(request.context["aws:securetransport"], ["false"]);
        }
    }
    assert_eq!(
        handler
            .handle(signed(
                Method::DELETE,
                "/prod/@connections/connection%3D",
                "api.execute-api.us-east-1.amazonaws.com"
            ))
            .await
            .status(),
        204
    );
    assert!(!handler
        .store
        .shared(ACCOUNT, REGION)
        .read()
        .await
        .connections
        .contains_key(CONNECTION));
}

#[tokio::test]
async fn ambiguous_ids_and_unattested_management_identity_fail_without_mutation() {
    let (_registry, handler, authorization, mut receiver) = fixture(true).await;
    for id in ["bad%GG", "%2F", "%252F", "%25", "%00", "%FF"] {
        assert_eq!(
            handler
                .handle(signed(
                    Method::DELETE,
                    &format!("/prod/@connections/{id}"),
                    "api.execute-api.us-east-1.amazonaws.com"
                ))
                .await
                .status(),
            400,
            "{id}"
        );
    }
    assert!(authorization.seen.lock().unwrap().is_empty());
    let mut request = signed(
        Method::DELETE,
        "/prod/@connections/connection%3D",
        "api.execute-api.us-east-1.amazonaws.com",
    );
    request
        .headers
        .remove("x-locallycloud-verified-external-sigv4");
    assert_eq!(handler.handle(request).await.status(), 403);
    assert!(handler
        .store
        .shared(ACCOUNT, REGION)
        .read()
        .await
        .connections
        .contains_key(CONNECTION));
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}
