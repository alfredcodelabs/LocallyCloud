mod crypto;
mod error;
mod model;
mod persistence;
mod policy;
mod service;
mod store;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::kms::{
    KmsDecryptOutput, KmsDecryptRequest, KmsEncryptOutput, KmsEncryptRequest,
    KmsGenerateDataKeyOutput, KmsGenerateDataKeyRequest, KmsInternalApi, KmsInternalError,
    KmsValidateKeyOutput, KmsValidateKeyRequest,
};
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_state::StateDb;
use serde_json::Value;

use crate::error::{unknown_operation, KmsError};
use crate::service::KmsService;

const TARGET_PREFIX: &str = "TrentService";
const MAX_REQUEST_BODY: usize = 32 * 1024;

pub struct KmsHandler {
    service: Arc<KmsService>,
    registry: Weak<ServiceRegistry>,
    internal_fault: Option<InternalFault>,
    internal_call_count: AtomicU64,
}

// Process-start fault control for public-endpoint integration gates. It never changes the
// public KMS API and does not synthesize successful cryptographic results.
enum InternalFault {
    Unavailable {
        after_calls: u64,
    },
    Delay {
        after_calls: u64,
        duration: Duration,
    },
}

impl KmsHandler {
    fn new(db: Arc<StateDb>) -> Result<Self, KmsError> {
        Ok(Self {
            service: Arc::new(KmsService::new(db)?),
            registry: Weak::new(),
            internal_fault: InternalFault::from_env(),
            internal_call_count: AtomicU64::new(0),
        })
    }
    fn with_registry(registry: &Arc<ServiceRegistry>, db: Arc<StateDb>) -> Result<Self, KmsError> {
        let mut handler = Self::new(db)?;
        handler.registry = Arc::downgrade(registry);
        Ok(handler)
    }

    fn authorize_key_admin(
        &self,
        request: &ServiceRequest,
        body: &serde_json::Map<String, Value>,
        operation: &str,
    ) -> Result<(), KmsError> {
        let key_id = body
            .get("KeyId")
            .and_then(Value::as_str)
            .ok_or(KmsError::Validation)?;
        if matches!(
            operation,
            "EnableKey"
                | "DisableKey"
                | "ScheduleKeyDeletion"
                | "TagResource"
                | "UntagResource"
                | "ListResourceTags"
                | "EnableKeyRotation"
                | "DisableKeyRotation"
                | "GetKeyRotationStatus"
                | "RotateKeyOnDemand"
        ) && (key_id.starts_with("alias/") || key_id.contains(":alias/"))
        {
            return Err(KmsError::Validation);
        }
        let (resource, policy, explicit_policy) =
            self.service
                .key_admin_policy(key_id, &request.account_id, &request.region)?;
        self.authorize_key_policy(request, operation, resource, policy, explicit_policy, body)
    }

    fn authorize_key_policy(
        &self,
        request: &ServiceRequest,
        operation: &str,
        resource: String,
        policy: crate::policy::KeyPolicy,
        explicit_policy: bool,
        body: &serde_json::Map<String, Value>,
    ) -> Result<(), KmsError> {
        let registry = self.registry.upgrade().ok_or(KmsError::AccessDenied)?;
        let dispatcher = registry
            .internal_dispatcher()
            .ok_or(KmsError::AccessDenied)?;
        let authorization = request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|header| header.to_str().ok());
        let identity = RequestIdentity {
            account_id: request.account_id.clone(),
            access_key_id: authorization.and_then(RequestIdentity::access_key_from_authorization),
            arn: None,
        };
        let principal = dispatcher
            .resolve_caller_arn(&identity)
            .map_err(|_| KmsError::AccessDenied)?;
        // Permissive mode treats an unregistered caller as the account root, as STS
        // GetCallerIdentity does; otherwise every explicit key policy denies it and CreateKey
        // reports a lockout for the standard root-delegation policy.
        let principal = match principal {
            None if !dispatcher.strict_sigv4_required() => {
                Some(format!("arn:aws:iam::{}:root", request.account_id))
            }
            resolved => resolved,
        };
        let mut context = std::collections::BTreeMap::from([(
            "kms:calleraccount".into(),
            vec![request.account_id.clone()],
        )]);
        if operation == "EnableKeyRotation" {
            let period = match body.get("RotationPeriodInDays") {
                Some(value) => value.as_u64().ok_or(KmsError::Validation)?,
                None => 365,
            };
            context.insert("kms:rotationperiodindays".into(), vec![period.to_string()]);
        }
        if let Some(principal) = &principal {
            context.insert("aws:principalarn".into(), vec![principal.clone()]);
            context.insert(
                "aws:principalaccount".into(),
                vec![request.account_id.clone()],
            );
        }
        let authorization = AuthorizationRequest {
            request_identity: identity,
            delegated_identity: None,
            source_service: "kms".into(),
            action: format!("kms:{operation}"),
            resource,
            context: context.clone(),
        };
        if dispatcher.identity_policy_denies(authorization.clone()) {
            return Err(KmsError::AccessDenied);
        }
        if principal.is_none() {
            return if !explicit_policy && !dispatcher.strict_sigv4_required() {
                Ok(())
            } else {
                Err(KmsError::AccessDenied)
            };
        }
        let iam_allowed = dispatcher.identity_policy_allows(authorization);
        if policy.allows_in_context(
            principal.as_deref(),
            &format!("kms:{operation}"),
            &request.account_id,
            iam_allowed,
            &context,
        ) {
            Ok(())
        } else {
            Err(KmsError::AccessDenied)
        }
    }

    fn validate_policy_change(
        &self,
        request: &ServiceRequest,
        body: &serde_json::Map<String, Value>,
        operation: &str,
        planned_key_id: Option<&str>,
    ) -> Result<(), KmsError> {
        if !matches!(operation, "CreateKey" | "PutKeyPolicy") {
            return Ok(());
        }
        let bypass = match body.get("BypassPolicyLockoutSafetyCheck") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err(KmsError::Validation),
        };
        let Some(raw) = body.get("Policy") else {
            return if operation == "CreateKey" {
                Ok(())
            } else {
                Err(KmsError::Validation)
            };
        };
        let policy =
            crate::policy::KeyPolicy::parse(raw.as_str().ok_or(KmsError::Validation)?.to_owned())?;
        if bypass {
            return Ok(());
        }
        let resource = match planned_key_id {
            Some(id) => crate::model::Scope::new(&request.account_id, &request.region).key_arn(id),
            None => {
                let key_id = body
                    .get("KeyId")
                    .and_then(Value::as_str)
                    .ok_or(KmsError::Validation)?;
                self.service
                    .key_admin_policy(key_id, &request.account_id, &request.region)?
                    .0
            }
        };
        match self.authorize_key_policy(request, "PutKeyPolicy", resource, policy, true, body) {
            Err(KmsError::AccessDenied) => Err(KmsError::PolicyLockout),
            result => result,
        }
    }

    fn before_internal_call(&self) -> Result<(), KmsInternalError> {
        let call = self.internal_call_count.fetch_add(1, Ordering::Relaxed);
        match &self.internal_fault {
            Some(InternalFault::Unavailable { after_calls }) if call >= *after_calls => {
                Err(KmsInternalError::Unavailable)
            }
            Some(InternalFault::Delay {
                after_calls,
                duration,
            }) if call >= *after_calls => {
                std::thread::sleep(*duration);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl InternalFault {
    fn from_env() -> Option<Self> {
        // Keep this gate-only fault control unavailable on externally bound servers.
        if std::env::var("LOCALLYCLOUD_HOST").ok().as_deref() != Some("127.0.0.1") {
            return None;
        }
        let mode = std::env::var("LOCALLYCLOUD_KMS_INTERNAL_FAULT").ok()?;
        let after_calls = std::env::var("LOCALLYCLOUD_KMS_INTERNAL_FAULT_AFTER_CALLS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())?;
        match mode.as_str() {
            "unavailable" => Some(Self::Unavailable { after_calls }),
            "delay" => Some(Self::Delay {
                after_calls,
                duration: Duration::from_secs(5),
            }),
            _ => None,
        }
    }
}

impl KmsInternalApi for KmsHandler {
    fn authorize_cached_key(
        &self,
        request: locallycloud_core::integration::kms::KmsAuthorizeCachedKeyRequest,
    ) -> Result<(), KmsInternalError> {
        self.service
            .authorize_cached_key_internal(request)
            .map_err(map_internal_error)
    }
    fn generate_data_key(
        &self,
        request: KmsGenerateDataKeyRequest,
    ) -> Result<KmsGenerateDataKeyOutput, KmsInternalError> {
        self.before_internal_call()?;
        self.service
            .generate_data_key_internal(request)
            .map_err(map_internal_error)
    }

    fn encrypt(&self, request: KmsEncryptRequest) -> Result<KmsEncryptOutput, KmsInternalError> {
        self.before_internal_call()?;
        self.service
            .encrypt_internal(request)
            .map_err(map_internal_error)
    }

    fn decrypt(&self, request: KmsDecryptRequest) -> Result<KmsDecryptOutput, KmsInternalError> {
        self.before_internal_call()?;
        self.service
            .decrypt_internal(request)
            .map_err(map_internal_error)
    }

    fn validate_key(
        &self,
        request: KmsValidateKeyRequest,
    ) -> Result<KmsValidateKeyOutput, KmsInternalError> {
        self.service
            .validate_key_internal(request)
            .map_err(map_internal_error)
    }
}

#[async_trait]
impl NativeHandler for KmsHandler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        self.service.resource_regions(account)
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let result: Result<Value, AwsError> = if request.method != http::Method::POST {
            Err(unknown_operation())
        } else if request.uri.path() != "/" || request.uri.query().is_some() {
            Err(KmsError::Validation.into_aws())
        } else if request.body.len() > MAX_REQUEST_BODY {
            Err(KmsError::Serialization.into_aws())
        } else {
            let operation = request
                .headers
                .get("x-amz-target")
                .and_then(|value| value.to_str().ok())
                .and_then(|target| target.strip_prefix(&format!("{TARGET_PREFIX}.")))
                .filter(|operation| !operation.is_empty() && !operation.contains('.'));
            match operation {
                None => Err(unknown_operation()),
                Some(operation) => match serde_json::from_slice::<Value>(&request.body) {
                    Err(_) => Err(KmsError::Serialization.into_aws()),
                    Ok(Value::Object(body)) => {
                        let planned_key_id =
                            (operation == "CreateKey").then(|| uuid::Uuid::new_v4().to_string());
                        let tagged_create_key = planned_key_id.as_deref().filter(|_| {
                            body.get("Tags")
                                .and_then(Value::as_array)
                                .is_some_and(|tags| !tags.is_empty())
                        });
                        let authorization = match (operation, tagged_create_key) {
                            ("CreateKey", Some(id)) => self.authorize_key_policy(
                                &request,
                                "TagResource",
                                crate::model::Scope::new(&request.account_id, &request.region)
                                    .key_arn(id),
                                crate::policy::KeyPolicy::default_for(&request.account_id),
                                false,
                                &body,
                            ),
                            (
                                "PutKeyPolicy"
                                | "DisableKey"
                                | "EnableKey"
                                | "ScheduleKeyDeletion"
                                | "TagResource"
                                | "UntagResource"
                                | "ListResourceTags"
                                | "EnableKeyRotation"
                                | "DisableKeyRotation"
                                | "GetKeyRotationStatus"
                                | "RotateKeyOnDemand",
                                _,
                            ) => self.authorize_key_admin(&request, &body, operation),
                            _ => Ok(()),
                        };
                        let authorization = authorization.and_then(|()| {
                            self.validate_policy_change(
                                &request,
                                &body,
                                operation,
                                planned_key_id.as_deref(),
                            )
                        });
                        match authorization {
                            Err(error) => Err(error.into_aws()),
                            Ok(()) => {
                                let service = self.service.clone();
                                let operation = operation.to_owned();
                                let account = request.account_id.clone();
                                let region = request.region.clone();
                                match tokio::task::spawn_blocking(move || match planned_key_id {
                                    Some(id) => service.create_key(
                                        &body,
                                        &crate::model::Scope::new(&account, &region),
                                        Some(id),
                                    ),
                                    None => service.dispatch(&operation, &body, &account, &region),
                                })
                                .await
                                {
                                    Ok(result) => result.map_err(KmsError::into_aws),
                                    Err(_) => Err(KmsError::Internal.into_aws()),
                                }
                            }
                        }
                    }
                    Ok(_) => Err(KmsError::Serialization.into_aws()),
                },
            }
        };

        match result {
            Ok(value) => Response::builder()
                .status(200)
                .header("content-type", "application/x-amz-json-1.1")
                .header("x-amzn-RequestId", &request.request_id)
                .body(
                    if matches!(
                        request
                            .headers
                            .get("x-amz-target")
                            .and_then(|target| target.to_str().ok()),
                        Some(
                            "TrentService.DisableKey"
                                | "TrentService.EnableKey"
                                | "TrentService.TagResource"
                                | "TrentService.UntagResource"
                                | "TrentService.EnableKeyRotation"
                                | "TrentService.DisableKeyRotation"
                        )
                    ) {
                        Body::empty()
                    } else {
                        Body::from(value.to_string())
                    },
                )
                .expect("JSON response is valid"),
            Err(error) => error
                .with_request_id(request.request_id)
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

fn map_internal_error(error: KmsError) -> KmsInternalError {
    match error {
        KmsError::Serialization
        | KmsError::Validation
        | KmsError::PolicyLockout
        | KmsError::InvalidAliasName
        | KmsError::InvalidMarker
        | KmsError::TagLimitExceeded
        | KmsError::LimitExceeded
        | KmsError::Conflict
        | KmsError::AlreadyExists
        | KmsError::Unsupported => KmsInternalError::InvalidRequest,
        KmsError::NotFound => KmsInternalError::NotFound,
        KmsError::InvalidState => KmsInternalError::InvalidState,
        KmsError::Disabled => KmsInternalError::Disabled,
        KmsError::InvalidCiphertext => KmsInternalError::InvalidCiphertext,
        KmsError::AccessDenied => KmsInternalError::AccessDenied,
        KmsError::Internal
        | KmsError::MissingMasterKey
        | KmsError::InvalidMasterKey
        | KmsError::StoredKeyUnavailable => KmsInternalError::Internal,
    }
}

/// Register KMS and its typed cryptographic capability atomically.
pub fn register(registry: &Arc<ServiceRegistry>) {
    let db = Arc::new(
        StateDb::open(StateDb::default_path().expect("KMS state path unavailable"))
            .expect("KMS state database unavailable"),
    );
    register_with_state(registry, db).expect("KMS state initialization failed");
}

pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    db: Arc<StateDb>,
) -> Result<(), &'static str> {
    let handler =
        Arc::new(KmsHandler::with_registry(registry, db).map_err(KmsError::startup_message)?);
    let native_handler: Arc<dyn NativeHandler> = handler.clone();
    let kms_api: Arc<dyn KmsInternalApi> = handler;
    registry.register_native_with_kms_api(
        ServiceName::new("kms"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        native_handler,
        kms_api,
    );
    Ok(())
}

#[cfg(test)]
fn test_db() -> Arc<StateDb> {
    static MASTER: std::sync::Once = std::sync::Once::new();
    MASTER.call_once(|| {
        std::env::set_var(
            "LOCALLYCLOUD_KMS_MASTER_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
    });
    let path = std::env::temp_dir()
        .join("locallycloud-kms-tests")
        .join(uuid::Uuid::new_v4().to_string())
        .join("state.sqlite3");
    Arc::new(StateDb::open(path).expect("temporary KMS state"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::integration::kms::KMS_INTERNAL_API_VERSION;

    struct AdminPolicy {
        denied: std::sync::atomic::AtomicBool,
        allowed: std::sync::atomic::AtomicBool,
        strict: std::sync::atomic::AtomicBool,
        principal: std::sync::Mutex<Option<String>>,
    }
    impl locallycloud_core::integration::authorization::AuthorizationEvaluator for AdminPolicy {
        fn authorize(
            &self,
            _: AuthorizationRequest,
        ) -> Result<(), locallycloud_core::integration::authorization::AuthorizationError> {
            Ok(())
        }
        fn resolve_caller_arn(
            &self,
            _: &RequestIdentity,
        ) -> Result<Option<String>, locallycloud_core::integration::authorization::AuthorizationError>
        {
            Ok(self.principal.lock().unwrap().clone())
        }
        fn identity_policy_denies(&self, _: AuthorizationRequest) -> bool {
            self.denied.load(Ordering::Relaxed)
        }
        fn identity_policy_allows(&self, _: AuthorizationRequest) -> bool {
            self.allowed.load(Ordering::Relaxed)
        }
        fn strict_sigv4_required(&self) -> bool {
            self.strict.load(Ordering::Relaxed)
        }
    }

    struct EmptyHandler;

    #[async_trait]
    impl NativeHandler for EmptyHandler {
        async fn handle(&self, _: ServiceRequest) -> Response {
            Response::new(Body::empty())
        }
    }

    #[tokio::test]
    async fn administrative_operations_honor_key_policy_and_identity_denial() {
        use locallycloud_core::integration::InternalDispatcher;
        use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
        let registry = ServiceRegistry::with_known_services();
        let admin = Arc::new(AdminPolicy {
            denied: std::sync::atomic::AtomicBool::new(false),
            allowed: std::sync::atomic::AtomicBool::new(false),
            strict: std::sync::atomic::AtomicBool::new(false),
            principal: std::sync::Mutex::new(Some("arn:aws:iam::000000000000:user/admin".into())),
        });
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            Arc::new(EmptyHandler),
            admin.clone(),
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
        let handler = KmsHandler::with_registry(&registry, test_db()).unwrap();
        let create = handler
            .service
            .dispatch(
                "CreateKey",
                serde_json::json!({}).as_object().unwrap(),
                "000000000000",
                "us-east-1",
            )
            .unwrap();
        let key = create["KeyMetadata"]["KeyId"].as_str().unwrap();
        async fn admin_call(handler: &KmsHandler, key: &str, action: &str) -> http::StatusCode {
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "x-amz-target",
                format!("TrentService.{action}").parse().unwrap(),
            );
            let mut body = serde_json::json!({"KeyId":key});
            match action {
                "CreateKey" => {
                    body = serde_json::json!({"Tags":[{"TagKey":"team","TagValue":"accounting"}]})
                }
                "TagResource" => {
                    body["Tags"] = serde_json::json!([{"TagKey":"team","TagValue":"accounting"}])
                }
                "UntagResource" => body["TagKeys"] = serde_json::json!(["team"]),
                _ => {}
            }
            let response = handler
                .handle(ServiceRequest {
                    method: http::Method::POST,
                    uri: "/".parse().unwrap(),
                    headers,
                    body: bytes::Bytes::from(body.to_string()),
                    region: "us-east-1".into(),
                    account_id: "000000000000".into(),
                    request_id: "admin-test".into(),
                })
                .await;
            let status = response.status();
            if status == 200
                && matches!(
                    action,
                    "TagResource" | "UntagResource" | "EnableKeyRotation" | "DisableKeyRotation"
                )
            {
                assert_eq!(
                    response.headers()["content-type"],
                    "application/x-amz-json-1.1"
                );
                assert_eq!(response.headers()["x-amzn-RequestId"], "admin-test");
                assert!(axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .is_empty());
            }
            status
        }
        // The default account grant delegates to actual IAM permission.
        assert_eq!(admin_call(&handler, key, "CreateKey").await, 400);
        assert_eq!(
            handler
                .service
                .dispatch(
                    "ListKeys",
                    serde_json::json!({}).as_object().unwrap(),
                    "000000000000",
                    "us-east-1"
                )
                .unwrap()["Keys"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(admin_call(&handler, key, "DisableKey").await, 400);
        assert_eq!(admin_call(&handler, key, "ScheduleKeyDeletion").await, 400);
        for action in [
            "TagResource",
            "UntagResource",
            "ListResourceTags",
            "EnableKeyRotation",
            "DisableKeyRotation",
            "GetKeyRotationStatus",
            "RotateKeyOnDemand",
        ] {
            assert_eq!(admin_call(&handler, key, action).await, 400);
        }
        assert_eq!(
            handler
                .service
                .dispatch(
                    "DescribeKey",
                    serde_json::json!({"KeyId":key}).as_object().unwrap(),
                    "000000000000",
                    "us-east-1"
                )
                .unwrap()["KeyMetadata"]["KeyState"],
            "Enabled"
        );
        admin.allowed.store(true, Ordering::Relaxed);
        assert_eq!(admin_call(&handler, key, "CreateKey").await, 200);
        for action in [
            "TagResource",
            "ListResourceTags",
            "UntagResource",
            "EnableKeyRotation",
            "DisableKeyRotation",
            "GetKeyRotationStatus",
            "RotateKeyOnDemand",
        ] {
            assert_eq!(admin_call(&handler, key, action).await, 200);
        }
        assert_eq!(admin_call(&handler, key, "DisableKey").await, 200);
        let policy = |principal: &str, deny: bool| {
            serde_json::json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":principal},"Action":"kms:*","Resource":"*"},{"Effect":if deny {"Deny"} else {"Allow"},"Principal":{"AWS":principal},"Action":"kms:DisableKey","Resource":"*"}]}).to_string()
        };
        let set_policy = |raw: String| {
            handler.service.dispatch("PutKeyPolicy", serde_json::json!({"KeyId":key,"Policy":raw,"BypassPolicyLockoutSafetyCheck":true}).as_object().unwrap(), "000000000000", "us-east-1").unwrap();
        };
        // Direct key-policy grants do not require an additional identity Allow.
        set_policy(policy("arn:aws:iam::000000000000:user/admin", false));
        admin.allowed.store(false, Ordering::Relaxed);
        assert_eq!(admin_call(&handler, key, "EnableKey").await, 200);
        // Explicit identity Deny and boundaries dominate a direct grant.
        admin.denied.store(true, Ordering::Relaxed);
        for action in ["TagResource", "UntagResource", "ListResourceTags"] {
            assert_eq!(admin_call(&handler, key, action).await, 400);
        }
        assert_eq!(admin_call(&handler, key, "DisableKey").await, 400);
        assert_eq!(admin_call(&handler, key, "ScheduleKeyDeletion").await, 400);
        admin.denied.store(false, Ordering::Relaxed);
        set_policy(policy("arn:aws:iam::000000000000:user/admin", true));
        admin.allowed.store(true, Ordering::Relaxed);
        assert_eq!(admin_call(&handler, key, "DisableKey").await, 400);
        set_policy(policy("arn:aws:iam::000000000000:user/other", false));
        assert_eq!(admin_call(&handler, key, "DisableKey").await, 400);
        *admin.principal.lock().unwrap() = None;
        assert_eq!(admin_call(&handler, key, "DisableKey").await, 400);
        let legacy = handler
            .service
            .dispatch(
                "CreateKey",
                serde_json::json!({}).as_object().unwrap(),
                "000000000000",
                "us-east-1",
            )
            .unwrap();
        let legacy = legacy["KeyMetadata"]["KeyId"].as_str().unwrap();
        assert_eq!(admin_call(&handler, legacy, "DisableKey").await, 200);
        admin.strict.store(true, Ordering::Relaxed);
        assert_eq!(admin_call(&handler, legacy, "EnableKey").await, 400);
        assert_eq!(
            admin_call(&handler, "alias/example", "DisableKey").await,
            400
        );
    }

    #[test]
    fn cached_key_authorization_rechecks_native_permissions_and_state_without_crypto() {
        use locallycloud_core::integration::kms::{
            KmsAuthorizeCachedKeyRequest, KmsCallContext, KmsDataKeyAction, SensitiveBytes,
        };
        let registry = ServiceRegistry::with_known_services();
        let handler = KmsHandler::with_registry(&registry, test_db()).unwrap();
        let account = "000000000000";
        let region = "us-east-1";
        let created = handler
            .service
            .dispatch("CreateKey", &serde_json::Map::new(), account, region)
            .unwrap();
        let key = created["KeyMetadata"]["Arn"].as_str().unwrap().to_owned();
        let context =
            std::collections::BTreeMap::from([("aws:s3:arn".into(), "arn:aws:s3:::bucket".into())]);
        let call = KmsCallContext {
            source_service: "s3".into(),
            account_id: account.into(),
            region: region.into(),
            request_id: "fixture".into(),
            caller_arn: Some(format!("arn:aws:iam::{account}:root")),
            iam_policy_allowed: false,
            iam_policy_denied: false,
        };
        let generated = handler
            .generate_data_key(KmsGenerateDataKeyRequest {
                call: call.clone(),
                key_id: key.clone(),
                number_of_bytes: 32,
                encryption_context: context.clone(),
            })
            .unwrap();
        assert_eq!(handler.internal_call_count.load(Ordering::Relaxed), 1);
        let request = |call: KmsCallContext, action| KmsAuthorizeCachedKeyRequest {
            call,
            key_id: key.clone(),
            ciphertext: SensitiveBytes::new(generated.ciphertext.as_slice().to_vec()),
            encryption_context: context.clone(),
            action,
        };
        handler
            .authorize_cached_key(request(call.clone(), KmsDataKeyAction::Generate))
            .unwrap();
        handler
            .authorize_cached_key(request(call.clone(), KmsDataKeyAction::Decrypt))
            .unwrap();
        assert_eq!(handler.internal_call_count.load(Ordering::Relaxed), 1);
        handler
            .service
            .dispatch(
                "RotateKeyOnDemand",
                serde_json::json!({"KeyId":key}).as_object().unwrap(),
                account,
                region,
            )
            .unwrap();
        assert!(matches!(
            handler.authorize_cached_key(request(call.clone(), KmsDataKeyAction::Generate)),
            Err(KmsInternalError::InvalidCiphertext)
        ));
        handler
            .authorize_cached_key(request(call.clone(), KmsDataKeyAction::Decrypt))
            .unwrap();
        let mut denied = call.clone();
        denied.iam_policy_denied = true;
        assert!(matches!(
            handler.authorize_cached_key(request(denied, KmsDataKeyAction::Generate)),
            Err(KmsInternalError::AccessDenied)
        ));
        handler
            .service
            .dispatch(
                "DisableKey",
                serde_json::json!({"KeyId":key}).as_object().unwrap(),
                account,
                region,
            )
            .unwrap();
        assert!(matches!(
            handler.authorize_cached_key(request(call.clone(), KmsDataKeyAction::Decrypt)),
            Err(KmsInternalError::Disabled)
        ));
        handler
            .service
            .dispatch(
                "EnableKey",
                serde_json::json!({"KeyId":key}).as_object().unwrap(),
                account,
                region,
            )
            .unwrap();
        let policy=serde_json::json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{account}:root")},"Action":"kms:*","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*"}]}).to_string();
        handler
            .service
            .dispatch(
                "PutKeyPolicy",
                serde_json::json!({"KeyId":key,"PolicyName":"default","Policy":policy})
                    .as_object()
                    .unwrap(),
                account,
                region,
            )
            .unwrap();
        for action in [KmsDataKeyAction::Generate, KmsDataKeyAction::Decrypt] {
            assert!(matches!(
                handler.authorize_cached_key(request(call.clone(), action)),
                Err(KmsInternalError::AccessDenied)
            ));
        }
        assert_eq!(handler.internal_call_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn register_publishes_current_kms_internal_api() {
        let registry = Arc::new(ServiceRegistry::new());
        register_with_state(&registry, test_db()).unwrap();

        let api = registry
            .kms_api(&ServiceName::new("kms"))
            .expect("KMS capability is registered");
        assert_eq!(api.version(), KMS_INTERNAL_API_VERSION);
    }
}

#[cfg(test)]
mod rotation_authorization_tests;

#[cfg(test)]
mod key_policy_authorization_tests;
