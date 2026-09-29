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
use localcloud_core::error_mapping::AwsError;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::integration::authorization::AuthorizationRequest;
use localcloud_core::integration::kms::{
    KmsDecryptOutput, KmsDecryptRequest, KmsEncryptOutput, KmsEncryptRequest,
    KmsGenerateDataKeyOutput, KmsGenerateDataKeyRequest, KmsInternalApi, KmsInternalError,
    KmsValidateKeyOutput, KmsValidateKeyRequest,
};
use localcloud_core::integration::RequestIdentity;
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use localcloud_state::StateDb;
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
    fn new(db: Arc<StateDb>) -> Self {
        Self {
            service: Arc::new(
                KmsService::new(db)
                    .expect("KMS state initialization failed; check LOCALCLOUD_KMS_MASTER_KEY"),
            ),
            registry: Weak::new(),
            internal_fault: InternalFault::from_env(),
            internal_call_count: AtomicU64::new(0),
        }
    }
    fn with_registry(registry: &Arc<ServiceRegistry>, db: Arc<StateDb>) -> Self {
        let mut handler = Self::new(db);
        handler.registry = Arc::downgrade(registry);
        handler
    }

    fn authorize_put_key_policy(
        &self,
        request: &ServiceRequest,
        body: &serde_json::Map<String, Value>,
    ) -> Result<(), KmsError> {
        let registry = self.registry.upgrade().ok_or(KmsError::AccessDenied)?;
        let dispatcher = registry
            .internal_dispatcher()
            .ok_or(KmsError::AccessDenied)?;
        let key_id = body
            .get("KeyId")
            .and_then(Value::as_str)
            .ok_or(KmsError::Validation)?;
        let resource = if key_id.starts_with("arn:aws:kms:") {
            key_id.to_owned()
        } else {
            format!(
                "arn:aws:kms:{}:{}:key/{key_id}",
                request.region, request.account_id
            )
        };
        let authorization = request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|header| header.to_str().ok());
        dispatcher
            .authorize(AuthorizationRequest {
                request_identity: RequestIdentity {
                    account_id: request.account_id.clone(),
                    access_key_id: authorization
                        .and_then(RequestIdentity::access_key_from_authorization),
                    arn: None,
                },
                delegated_identity: None,
                source_service: "kms".into(),
                action: "kms:PutKeyPolicy".into(),
                resource,
                context: Default::default(),
            })
            .map_err(|_| KmsError::AccessDenied)
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
        if std::env::var("LOCALCLOUD_HOST").ok().as_deref() != Some("127.0.0.1") {
            return None;
        }
        let mode = std::env::var("LOCALCLOUD_KMS_INTERNAL_FAULT").ok()?;
        let after_calls = std::env::var("LOCALCLOUD_KMS_INTERNAL_FAULT_AFTER_CALLS")
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
                        let authorization = if operation == "PutKeyPolicy" {
                            self.authorize_put_key_policy(&request, &body)
                        } else {
                            Ok(())
                        };
                        match authorization {
                            Err(error) => Err(error.into_aws()),
                            Ok(()) => {
                                let service = self.service.clone();
                                let operation = operation.to_owned();
                                let account = request.account_id.clone();
                                let region = request.region.clone();
                                match tokio::task::spawn_blocking(move || {
                                    service.dispatch(&operation, &body, &account, &region)
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
                .body(Body::from(value.to_string()))
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
        | KmsError::InvalidAliasName
        | KmsError::LimitExceeded
        | KmsError::AlreadyExists
        | KmsError::Unsupported => KmsInternalError::InvalidRequest,
        KmsError::NotFound => KmsInternalError::NotFound,
        KmsError::InvalidState => KmsInternalError::InvalidState,
        KmsError::InvalidCiphertext => KmsInternalError::InvalidCiphertext,
        KmsError::AccessDenied => KmsInternalError::AccessDenied,
        KmsError::Internal => KmsInternalError::Internal,
    }
}

/// Register KMS and its typed cryptographic capability atomically.
pub fn register(registry: &Arc<ServiceRegistry>) {
    let db = Arc::new(
        StateDb::open(StateDb::default_path().expect("KMS state path unavailable"))
            .expect("KMS state database unavailable"),
    );
    register_with_state(registry, db);
}

pub fn register_with_state(registry: &Arc<ServiceRegistry>, db: Arc<StateDb>) {
    let handler = Arc::new(KmsHandler::with_registry(registry, db));
    let native_handler: Arc<dyn NativeHandler> = handler.clone();
    let kms_api: Arc<dyn KmsInternalApi> = handler;
    registry.register_native_with_kms_api(
        ServiceName::new("kms"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        native_handler,
        kms_api,
    );
}

#[cfg(test)]
fn test_db() -> Arc<StateDb> {
    static MASTER: std::sync::Once = std::sync::Once::new();
    MASTER.call_once(|| {
        std::env::set_var(
            "LOCALCLOUD_KMS_MASTER_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
    });
    let path = std::env::temp_dir()
        .join(format!("localcloud-kms-{}", uuid::Uuid::new_v4()))
        .join("state.sqlite3");
    Arc::new(StateDb::open(path).expect("temporary KMS state"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use localcloud_core::integration::kms::KMS_INTERNAL_API_VERSION;

    struct DenyAdmin;

    impl localcloud_core::integration::authorization::AuthorizationEvaluator for DenyAdmin {
        fn authorize(
            &self,
            request: localcloud_core::integration::authorization::AuthorizationRequest,
        ) -> Result<(), localcloud_core::integration::authorization::AuthorizationError> {
            assert_eq!(request.action, "kms:PutKeyPolicy");
            Err(localcloud_core::integration::authorization::AuthorizationError::Denied)
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
    async fn put_key_policy_requires_administrative_iam_permission() {
        use localcloud_core::integration::InternalDispatcher;
        use localcloud_core::proxy::{LegacyHealth, ProxyConfig};
        let registry = ServiceRegistry::with_known_services();
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            Arc::new(EmptyHandler),
            Arc::new(DenyAdmin),
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
        let handler = KmsHandler::with_registry(&registry, test_db());
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-target", "TrentService.PutKeyPolicy".parse().unwrap());
        let response = handler
            .handle(ServiceRequest {
                method: http::Method::POST,
                uri: "/".parse().unwrap(),
                headers,
                body: bytes::Bytes::from_static(
                    br#"{"KeyId":"key","PolicyName":"default","Policy":"{}"}"#,
                ),
                region: "us-east-1".into(),
                account_id: "000000000000".into(),
                request_id: "request".into(),
            })
            .await;
        assert_eq!(response.status(), 400);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("AccessDeniedException"));
    }

    #[test]
    fn register_publishes_current_kms_internal_api() {
        let registry = Arc::new(ServiceRegistry::new());
        register_with_state(&registry, test_db());

        let api = registry
            .kms_api(&ServiceName::new("kms"))
            .expect("KMS capability is registered");
        assert_eq!(api.version(), KMS_INTERNAL_API_VERSION);
    }
}
