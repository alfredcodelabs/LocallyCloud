use super::*;
use std::io::{Cursor, Write};
fn code() -> Value {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("index.js", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"exports.handler=async()=>({ok:true});")
        .unwrap();
    json!({"FunctionName":"qualified","Runtime":"nodejs22.x","Handler":"index.handler","Role":"arn:aws:iam::000000000000:role/execution","Code":{"ZipFile":base64::engine::general_purpose::STANDARD.encode(zip.finish().unwrap().into_inner())}})
}
async fn call(handler: &LambdaHandler, method: Method, path: &str, body: Value) -> (u16, Value) {
    let request = ServiceRequest {
        method,
        uri: path.parse().unwrap(),
        headers: Default::default(),
        body: Bytes::from(body.to_string()),
        account_id: "000000000000".into(),
        region: "us-east-1".into(),
        request_id: "event-config".into(),
    };
    let response = handler.handle(request).await;
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
#[tokio::test]
async fn event_configs_are_qualified_validated_paginated_and_durable() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.kiro/localcloud-tmp")
        .join(format!(
            "locallycloud-event-config-{}",
            uuid::Uuid::new_v4()
        ));
    let state = Arc::new(locallycloud_state::StateDb::open(root.join("state.sqlite3")).unwrap());
    let durable = || {
        let handler = LambdaHandler::new();
        let persistence = Arc::new(
            crate::persistence::LambdaPersistence::with_cipher(
                state.clone(),
                locallycloud_state::StateCipher::with_key(&[5; 32]),
            )
            .unwrap(),
        );
        handler
            .initialize_state(state.clone(), persistence)
            .unwrap();
        handler
    };
    let handler = durable();
    assert_eq!(
        call(&handler, Method::POST, "/2015-03-31/functions", code())
            .await
            .0,
        201
    );
    assert_eq!(
        call(
            &handler,
            Method::POST,
            "/2015-03-31/functions/qualified/versions",
            json!({})
        )
        .await
        .0,
        201
    );
    assert_eq!(
        call(
            &handler,
            Method::POST,
            "/2015-03-31/functions/qualified/aliases",
            json!({"Name":"prod","FunctionVersion":"1"})
        )
        .await
        .0,
        201
    );
    let path = "/2019-09-25/functions/qualified/event-invoke-config";
    for (q, retries) in [("%24LATEST", 0), ("1", 1), ("prod", 2)] {
        let config = json!({"MaximumRetryAttempts":retries,"MaximumEventAgeInSeconds":60,"DestinationConfig":{"OnFailure":{"Destination":"arn:aws:sqs:us-east-1:000000000000:errors"}}});
        let (status, body) = call(
            &handler,
            Method::PUT,
            &format!("{path}?Qualifier={q}"),
            config,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(body["LastModified"].is_number());
        let expected = if q == "%24LATEST" { "$LATEST" } else { q };
        assert!(body["FunctionArn"]
            .as_str()
            .unwrap()
            .ends_with(&format!(":{expected}")));
    }
    assert_eq!(
        call(
            &handler,
            Method::GET,
            "/2019-09-25/functions/qualified%3Aprod/event-invoke-config",
            Value::Null
        )
        .await
        .1["MaximumRetryAttempts"],
        2
    );
    assert_eq!(
        call(
            &handler,
            Method::GET,
            &format!("{path}?Qualifier=missing"),
            Value::Null
        )
        .await
        .0,
        404
    );
    assert_eq!(
        call(
            &handler,
            Method::GET,
            "/2019-09-25/functions/qualified%3Aprod/event-invoke-config?Qualifier=1",
            Value::Null
        )
        .await
        .0,
        400
    );
    for suffix in ["", "/list"] {
        assert_eq!(call(&handler,Method::GET,&format!("/2019-09-25/functions/arn%3Aaws%3Alambda%3Aus-east-1%3A111111111111%3Afunction%3Aqualified/event-invoke-config{suffix}"),Value::Null).await.0,400);
    }
    let first = call(
        &handler,
        Method::GET,
        &format!("{path}/list?MaxItems=1"),
        Value::Null,
    )
    .await
    .1;
    assert_eq!(
        first["FunctionEventInvokeConfigs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let next = first["NextMarker"].as_str().unwrap().replace(':', "%3A");
    let second = call(
        &handler,
        Method::GET,
        &format!("{path}/list?MaxItems=1&Marker={next}"),
        Value::Null,
    )
    .await
    .1;
    assert!(second["FunctionEventInvokeConfigs"][0]["FunctionArn"]
        .as_str()
        .unwrap()
        .ends_with(":1"));
    for bad in [
        json!({"MaximumRetryAttempts":-1}),
        json!({"MaximumRetryAttempts":"2"}),
        json!({"MaximumRetryAttempts":1.5}),
        json!({"MaximumRetryAttempts":4294967297u64}),
        json!({"MaximumEventAgeInSeconds":59}),
        json!({"DestinationConfig":{"OnFailure":{"Destination":"arn:aws:sqs:us-east-1:0:q"}}}),
    ] {
        assert_eq!(
            call(
                &handler,
                Method::PUT,
                &format!("{path}?Qualifier=prod"),
                bad
            )
            .await
            .0,
            400
        );
    }
    assert_eq!(call(&handler,Method::PUT,&format!("{path}?Qualifier=prod"),json!({"DestinationConfig":{"OnFailure":{"Destination":"arn:aws:sns:us-east-1:000000000000:topic"}}})).await.0,501);
    assert_eq!(
        call(
            &handler,
            Method::GET,
            &format!("{path}?Qualifier=prod"),
            Value::Null
        )
        .await
        .1["MaximumRetryAttempts"],
        2
    );
    // Failed durable commit must not publish a replacement config.
    state.connection().unwrap().execute_batch("CREATE TRIGGER reject_event_config BEFORE UPDATE ON lambda_entities BEGIN SELECT RAISE(ABORT,'forced'); END;").unwrap();
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            &format!("{path}?Qualifier=prod"),
            json!({"MaximumRetryAttempts":0})
        )
        .await
        .0,
        500
    );
    assert_eq!(
        call(
            &handler,
            Method::GET,
            &format!("{path}?Qualifier=prod"),
            Value::Null
        )
        .await
        .1["MaximumRetryAttempts"],
        2
    );
    state
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_event_config;")
        .unwrap();
    drop(handler);
    let restored = durable();
    for (q, retries) in [("%24LATEST", 0), ("1", 1), ("prod", 2)] {
        assert_eq!(
            call(
                &restored,
                Method::GET,
                &format!("{path}?Qualifier={q}"),
                Value::Null
            )
            .await
            .1["MaximumRetryAttempts"],
            retries
        );
    }
    let configs = ["qualified:$LATEST", "qualified:1", "qualified:prod"]
        .map(|q| restored.async_config("000000000000", "us-east-1", q));
    assert_eq!(configs.map(|c| c.max_retry_attempts), [0, 1, 2]);
    assert_eq!(
        restored
            .async_config("000000000000", "us-east-1", "qualified:other")
            .max_retry_attempts,
        2
    );
    assert_eq!(
        call(
            &restored,
            Method::PUT,
            &format!("{path}?Qualifier=prod"),
            json!({"MaximumRetryAttempts":0})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(
            &restored,
            Method::GET,
            &format!("{path}?Qualifier=prod"),
            Value::Null
        )
        .await
        .1["DestinationConfig"],
        json!({})
    );
    assert_eq!(
        call(
            &restored,
            Method::DELETE,
            &format!("{path}?Qualifier=prod"),
            Value::Null
        )
        .await
        .0,
        204
    );
    assert_eq!(
        call(
            &restored,
            Method::GET,
            &format!("{path}?Qualifier=1"),
            Value::Null
        )
        .await
        .0,
        200
    );
    drop(restored);
    drop(state);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn async_destination_uses_execution_role_and_denial_prevents_delivery() {
    use locallycloud_core::integration::authorization::{
        AuthorizationError, AuthorizationEvaluator, AuthorizationRequest,
        ServiceRoleAuthorizationRequest,
    };
    use locallycloud_core::integration::InternalDispatcher;
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Authorization {
        allow: AtomicBool,
        strict: AtomicBool,
        roles: Mutex<Vec<String>>,
    }
    impl AuthorizationEvaluator for Authorization {
        fn strict_sigv4_required(&self) -> bool {
            self.strict.load(Ordering::Relaxed)
        }
        fn authorize(&self, _: AuthorizationRequest) -> Result<(), AuthorizationError> {
            Ok(())
        }
        fn issue_service_role_credentials(
            &self,
            _account: &str,
            _role: &str,
            _service: &str,
        ) -> Result<
            locallycloud_core::integration::authorization::ServiceRoleCredentials,
            AuthorizationError,
        > {
            Ok(
                locallycloud_core::integration::authorization::ServiceRoleCredentials {
                    access_key_id: "role-key".into(),
                    secret_access_key: "test".into(),
                    session_token: "test".into(),
                    expiration: "2099-01-01T00:00:00Z".into(),
                },
            )
        }
        fn resolve_caller_arn(
            &self,
            identity: &locallycloud_core::integration::RequestIdentity,
        ) -> Result<Option<String>, AuthorizationError> {
            Ok((identity.access_key_id.as_deref() == Some("role-key"))
                .then(|| "arn:aws:iam::000000000000:role/function-execution".into()))
        }
        fn authorize_service_role_execution(
            &self,
            req: ServiceRoleAuthorizationRequest,
        ) -> Result<(), AuthorizationError> {
            assert_eq!(req.action, "sqs:SendMessage");
            assert_eq!(
                req.resource,
                "arn:aws:sqs:us-east-1:000000000000:destination"
            );
            assert_eq!(req.service_principal, "lambda.amazonaws.com");
            self.roles.lock().unwrap().push(req.role_arn);
            if self.allow.load(Ordering::Relaxed) {
                Ok(())
            } else {
                Err(AuthorizationError::Denied)
            }
        }
    }
    #[async_trait]
    impl NativeHandler for Authorization {
        async fn handle(&self, _: ServiceRequest) -> Response {
            http::Response::new(Body::empty())
        }
    }
    let registry = ServiceRegistry::with_known_services();
    locallycloud_sqs::register(&registry);
    let sqs = registry.native_handler(&ServiceName::new("sqs")).unwrap();
    let request = |action: &str, body: Value| {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("AmazonSQS.{action}")).unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            request_id: "destination".into(),
        }
    };
    assert_eq!(
        sqs.handle(request("CreateQueue", json!({"QueueName":"destination"})))
            .await
            .status(),
        200
    );
    let auth = Arc::new(Authorization {
        allow: AtomicBool::new(true),
        strict: AtomicBool::new(true),
        roles: Mutex::new(Vec::new()),
    });
    registry.register_native_with_authorization_evaluator(
        ServiceName::new("iam"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        auth.clone(),
        auth.clone(),
    );
    registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
        &registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: Duration::from_secs(1),
        },
        LegacyHealth::new(false),
        "us-east-1".into(),
        "000000000000".into(),
    )));
    let router = RegistryDestinationRouter::new(Arc::downgrade(&registry));
    let role = "arn:aws:iam::000000000000:role/function-execution";
    router
        .route(
            "arn:aws:sqs:us-east-1:000000000000:destination",
            role,
            json!({"proof":"allowed"}),
        )
        .await;
    auth.allow.store(false, Ordering::Relaxed);
    router
        .route(
            "arn:aws:sqs:us-east-1:000000000000:destination",
            role,
            json!({"proof":"denied"}),
        )
        .await;
    auth.strict.store(false, Ordering::Relaxed);
    let response=sqs.handle(request("ReceiveMessage",json!({"QueueUrl":"https://sqs.us-east-1.amazonaws.com/000000000000/destination","MaxNumberOfMessages":10}))).await;
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["Messages"].as_array().unwrap().len(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(body["Messages"][0]["Body"].as_str().unwrap()).unwrap()
            ["proof"],
        "allowed"
    );
    let roles = auth.roles.lock().unwrap();
    assert!(!roles.is_empty());
    assert!(roles.iter().all(|observed| observed == role));
}

#[tokio::test]
async fn event_config_iam_permission_is_qualified_and_legacy_config_restores() {
    use locallycloud_core::integration::authorization::{
        AuthorizationError, AuthorizationEvaluator, AuthorizationRequest,
    };
    struct Scope;
    impl AuthorizationEvaluator for Scope {
        fn strict_sigv4_required(&self) -> bool {
            true
        }
        fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError> {
            if request.resource == "arn:aws:lambda:us-east-1:000000000000:function:qualified:prod"
                && request.action == "lambda:PutFunctionEventInvokeConfig"
            {
                Ok(())
            } else {
                Err(AuthorizationError::Denied)
            }
        }
    }
    #[async_trait]
    impl NativeHandler for Scope {
        async fn handle(&self, _: ServiceRequest) -> Response {
            http::Response::new(Body::empty())
        }
    }
    let registry = ServiceRegistry::with_known_services();
    let handler = LambdaHandler::with_parts(Arc::downgrade(&registry), None);
    assert_eq!(
        call(&handler, Method::POST, "/2015-03-31/functions", code())
            .await
            .0,
        201
    );
    assert_eq!(
        call(
            &handler,
            Method::POST,
            "/2015-03-31/functions/qualified/versions",
            json!({})
        )
        .await
        .0,
        201
    );
    assert_eq!(
        call(
            &handler,
            Method::POST,
            "/2015-03-31/functions/qualified/aliases",
            json!({"Name":"prod","FunctionVersion":"1"})
        )
        .await
        .0,
        201
    );
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/2019-09-25/functions/qualified/event-invoke-config",
            json!({"MaximumRetryAttempts":1})
        )
        .await
        .0,
        200
    );
    // Emulate an old encrypted function record without the new map field.
    let (key, mut value) = {
        let entry = handler.store.records.iter().next().unwrap();
        (
            entry.key().clone(),
            serde_json::to_value(entry.value()).unwrap(),
        )
    };
    let legacy = value["event_invoke_configs"]["$LATEST"].clone();
    value
        .as_object_mut()
        .unwrap()
        .remove("event_invoke_configs");
    value["event_invoke_config"] = legacy;
    handler
        .store
        .records
        .insert(key, serde_json::from_value(value).unwrap());
    assert_eq!(
        handler
            .async_config("000000000000", "us-east-1", "qualified:$LATEST")
            .max_retry_attempts,
        1
    );
    assert_eq!(
        handler
            .async_config("000000000000", "us-east-1", "qualified:prod")
            .max_retry_attempts,
        2
    );
    registry.register_native_with_authorization_evaluator(
        ServiceName::new("iam"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        Arc::new(Scope),
        Arc::new(Scope),
    );
    for (qualifier, expected) in [("?Qualifier=prod", 200), ("?Qualifier=1", 403), ("", 403)] {
        let mut request = ServiceRequest {
            method: Method::PUT,
            uri: format!("/2019-09-25/functions/qualified/event-invoke-config{qualifier}")
                .parse()
                .unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"{\"MaximumRetryAttempts\":0}"),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            request_id: "scope".into(),
        };
        request.headers.insert(
            "x-locallycloud-verified-external-sigv4",
            HeaderValue::from_static("1"),
        );
        request.headers.insert("authorization",HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=test/20261103/us-east-1/lambda/aws4_request, SignedHeaders=host, Signature=test"));
        assert_eq!(handler.handle(request).await.status().as_u16(), expected);
    }
    assert!(handler
        .store
        .get_event_invoke_config("000000000000", "us-east-1", "qualified:1")
        .is_none());
    assert_eq!(
        handler
            .store
            .get_event_invoke_config("000000000000", "us-east-1", "qualified:$LATEST")
            .unwrap()
            .maximum_retry_attempts,
        Some(1)
    );
}

#[tokio::test]
async fn native_iam_role_policy_is_rechecked_with_cached_destination_credentials() {
    use locallycloud_core::integration::InternalDispatcher;
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use locallycloud_iam_sts::{
        enforcement::EnforcementMode, iam, query::QueryRequest, store::IamStore, sts::SessionStore,
    };
    let registry = ServiceRegistry::with_known_services();
    locallycloud_sqs::register(&registry);
    let store = Arc::new(IamStore::new());
    let sessions = Arc::new(SessionStore::new());
    let account = "000000000000";
    let arn = "arn:aws:sqs:us-east-1:000000000000:destination";
    let trust = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]});
    iam::create_role(
        &store,
        account,
        &QueryRequest::parse(
            format!("RoleName=execution&AssumeRolePolicyDocument={trust}").as_bytes(),
        ),
    )
    .unwrap();
    let policy = |effect: &str| json!({"Version":"2012-10-17","Statement":[{"Effect":effect,"Action":"sqs:SendMessage","Resource":arn}]});
    let set_policy = |effect: &str| {
        iam::put_inline_policy(
            &store,
            account,
            iam::Entity::Role,
            &QueryRequest::parse(
                format!(
                    "RoleName=execution&PolicyName=destination&PolicyDocument={}",
                    policy(effect)
                )
                .as_bytes(),
            ),
        )
        .unwrap();
    };
    set_policy("Allow");
    let sqs = registry.native_handler(&ServiceName::new("sqs")).unwrap();
    let request = |action: &str, body: Value| {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("AmazonSQS.{action}")).unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            account_id: account.into(),
            region: "us-east-1".into(),
            request_id: "native-destination".into(),
        }
    };
    assert_eq!(
        sqs.handle(request("CreateQueue", json!({"QueueName":"destination"})))
            .await
            .status(),
        200
    );
    let set_mode = |mode| {
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            store.clone(),
            sessions.clone(),
            mode,
        )
    };
    set_mode(EnforcementMode::Strict);
    registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
        &registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: Duration::from_secs(1),
        },
        LegacyHealth::new(false),
        "us-east-1".into(),
        account.into(),
    )));
    let router = RegistryDestinationRouter::new(Arc::downgrade(&registry));
    let role = "arn:aws:iam::000000000000:role/execution";
    for i in 0..2 {
        router.route(arn, role, json!({"allowed":i})).await;
    }
    let first_key = router
        .credentials
        .lock()
        .unwrap()
        .get(role)
        .unwrap()
        .access_key_id
        .clone();
    set_policy("Deny");
    router.route(arn, role, json!({"denied":true})).await;
    assert_eq!(router.credentials.lock().unwrap().len(), 1);
    assert_eq!(
        router
            .credentials
            .lock()
            .unwrap()
            .get(role)
            .unwrap()
            .access_key_id,
        first_key
    );
    set_mode(EnforcementMode::Permissive);
    let response=sqs.handle(request("ReceiveMessage",json!({"QueueUrl":"https://sqs.us-east-1.amazonaws.com/000000000000/destination","MaxNumberOfMessages":10}))).await;
    assert_eq!(response.status(), 200);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["Messages"].as_array().unwrap().len(), 2, "{body}");
}

#[tokio::test]
async fn destination_bursts_wait_for_credential_workers_without_losing_accepted_records() {
    use locallycloud_core::integration::authorization::{
        AuthorizationError, AuthorizationEvaluator, AuthorizationRequest,
        ServiceRoleAuthorizationRequest, ServiceRoleCredentials,
    };
    use locallycloud_core::integration::{InternalDispatcher, RequestIdentity};
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use locallycloud_iam_sts::{
        enforcement::EnforcementMode, iam, query::QueryRequest, store::IamStore, sts::SessionStore,
    };
    struct BlockingIssuer {
        inner: Arc<dyn AuthorizationEvaluator>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }
    impl AuthorizationEvaluator for BlockingIssuer {
        fn strict_sigv4_required(&self) -> bool {
            self.inner.strict_sigv4_required()
        }
        fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError> {
            self.inner.authorize(request)
        }
        fn resolve_caller_arn(
            &self,
            identity: &RequestIdentity,
        ) -> Result<Option<String>, AuthorizationError> {
            self.inner.resolve_caller_arn(identity)
        }
        fn authorize_service_role_execution(
            &self,
            request: ServiceRoleAuthorizationRequest,
        ) -> Result<(), AuthorizationError> {
            self.inner.authorize_service_role_execution(request)
        }
        fn issue_service_role_credentials(
            &self,
            account: &str,
            role: &str,
            service: &str,
        ) -> Result<ServiceRoleCredentials, AuthorizationError> {
            let mut released = self.release.0.lock().unwrap();
            while !*released {
                released = self.release.1.wait(released).unwrap();
            }
            drop(released);
            self.inner
                .issue_service_role_credentials(account, role, service)
        }
    }
    let registry = ServiceRegistry::with_known_services();
    locallycloud_sqs::register(&registry);
    let store = Arc::new(IamStore::new());
    let sessions = Arc::new(SessionStore::new());
    let account = "000000000000";
    let arn = "arn:aws:sqs:us-east-1:000000000000:destination";
    let trust = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]});
    let policy = json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:SendMessage","Resource":arn}]});
    for index in 0..9 {
        iam::create_role(
            &store,
            account,
            &QueryRequest::parse(
                format!("RoleName=execution{index}&AssumeRolePolicyDocument={trust}").as_bytes(),
            ),
        )
        .unwrap();
        iam::put_inline_policy(
            &store,
            account,
            iam::Entity::Role,
            &QueryRequest::parse(
                format!("RoleName=execution{index}&PolicyName=send&PolicyDocument={policy}")
                    .as_bytes(),
            ),
        )
        .unwrap();
    }
    let sqs = registry.native_handler(&ServiceName::new("sqs")).unwrap();
    let request = |action: &str, body: Value| {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("AmazonSQS.{action}")).unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            account_id: account.into(),
            region: "us-east-1".into(),
            request_id: "burst-destination".into(),
        }
    };
    assert_eq!(
        sqs.handle(request("CreateQueue", json!({"QueueName":"destination"})))
            .await
            .status(),
        200
    );
    locallycloud_iam_sts::register_with_store_and_mode(
        &registry,
        store.clone(),
        sessions.clone(),
        EnforcementMode::Strict,
    );
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let wrapper = Arc::new(BlockingIssuer {
        inner: registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .unwrap(),
        release: release.clone(),
    });
    registry.register_native_with_authorization_evaluator(
        ServiceName::new("iam"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        registry.native_handler(&ServiceName::new("iam")).unwrap(),
        wrapper,
    );
    registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
        &registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: Duration::from_secs(1),
        },
        LegacyHealth::new(false),
        "us-east-1".into(),
        account.into(),
    )));
    let router = Arc::new(RegistryDestinationRouter::new(Arc::downgrade(&registry)));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..8 {
        let router = router.clone();
        tasks.spawn(async move {
            router
                .route(
                    arn,
                    &format!("arn:aws:iam::000000000000:role/execution{index}"),
                    json!({"index":index}),
                )
                .await;
        });
    }
    let saturated = tokio::time::timeout(Duration::from_secs(2), async {
        while router.credential_slots.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let ninth = router.clone();
    tasks.spawn(async move {
        ninth
            .route(
                arn,
                "arn:aws:iam::000000000000:role/execution8",
                json!({"index":8}),
            )
            .await;
    });
    // The ninth future is scheduled while all eight workers are occupied. It must
    // yield rather than return early and lose an already accepted invocation record.
    tokio::time::sleep(Duration::from_millis(30)).await;
    {
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
    }
    assert!(saturated.is_ok());
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    assert_eq!(router.credential_slots.available_permits(), 8);
    locallycloud_iam_sts::register_with_store_and_mode(
        &registry,
        store,
        sessions,
        EnforcementMode::Permissive,
    );
    let response=sqs.handle(request("ReceiveMessage",json!({"QueueUrl":"https://sqs.us-east-1.amazonaws.com/000000000000/destination","MaxNumberOfMessages":10}))).await;
    assert_eq!(response.status(), 200);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["Messages"].as_array().unwrap().len(), 9, "{body}");
}
