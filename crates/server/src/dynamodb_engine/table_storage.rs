//! Caller authorization and lifecycle integration for encrypted table workers.
#[path = "table_lifecycle.rs"]
mod lifecycle;
use super::FileAccess;
use std::sync::{Arc, Weak};

use base64::Engine;
use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::identity::{trusted_role, CallerIdentity};
use locallycloud_core::integration::kms::{KmsCallContext, KmsDataKeyAction, KmsInternalError};
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::ServiceRegistry;
use locallycloud_dynamodb::encryption::catalog::{FilePhase, TableCatalog, TableFileRecord};
use locallycloud_dynamodb::encryption::TableKeys;
use locallycloud_dynamodb::error::DdbError;
use locallycloud_state::{StateCipher, StateDb};
use serde_json::Value;
use tokio::sync::OnceCell;
use zeroize::Zeroizing;

pub(super) struct TableStorage {
    state: Arc<StateDb>,
    registry: Weak<ServiceRegistry>,
    services: OnceCell<Services>,
}

struct Services {
    keys: Arc<TableKeys>,
    catalog: TableCatalog,
}

pub(super) struct TableCall {
    pub record: TableFileRecord,
    storage: Arc<TableStorage>,
    identity: RequestIdentity,
    delegated: Option<CallerIdentity>,
    request_id: String,
    access: TableAccess,
}

enum TableAccess {
    Data,
    Creation(Option<Zeroizing<String>>),
    InspectCreating,
    Control,
    Updating,
}

fn unavailable() -> DdbError {
    DdbError::Internal("Encrypted table storage is unavailable".into())
}

fn kms_error(error: KmsInternalError) -> DdbError {
    match error {
        KmsInternalError::AccessDenied
        | KmsInternalError::Disabled
        | KmsInternalError::NotFound
        | KmsInternalError::InvalidState
        | KmsInternalError::InvalidCiphertext => {
            DdbError::AccessDenied("KMS key access denied".into())
        }
        KmsInternalError::InvalidRequest => {
            DdbError::Validation("Invalid table encryption request".into())
        }
        KmsInternalError::Unavailable | KmsInternalError::Internal => unavailable(),
    }
}

impl TableStorage {
    fn target_name<'a>(
        account: &str,
        region: &str,
        target: &'a str,
    ) -> Result<Option<&'a str>, DdbError> {
        if target == "*" {
            return Ok(None);
        }
        let name = if target.starts_with("arn:") {
            let prefix = format!("arn:aws:dynamodb:{region}:{account}:table/");
            target
                .strip_prefix(&prefix)
                .and_then(|value| value.split('/').next())
                .ok_or_else(|| {
                    DdbError::Validation("Resource ARN must match the request scope".into())
                })?
        } else {
            target
        };
        locallycloud_dynamodb::encryption::TableKeyScope::new(
            account,
            region,
            name,
            uuid::Uuid::from_u128(1),
        )?;
        Ok(Some(name))
    }
    fn identity(request: &ServiceRequest) -> (RequestIdentity, Option<CallerIdentity>) {
        (
            RequestIdentity {
                account_id: request.account_id.clone(),
                access_key_id: request
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(RequestIdentity::access_key_from_authorization),
                arn: None,
            },
            trusted_role(request),
        )
    }

    fn for_access(
        self: &Arc<Self>,
        record: TableFileRecord,
        request: &ServiceRequest,
        access: TableAccess,
    ) -> TableCall {
        let (identity, delegated) = Self::identity(request);
        TableCall {
            record,
            storage: self.clone(),
            identity,
            delegated,
            request_id: request.request_id.clone(),
            access,
        }
    }

    fn call(self: &Arc<Self>, record: TableFileRecord, request: &ServiceRequest) -> TableCall {
        self.for_access(record, request, TableAccess::Data)
    }

    fn creation_call(
        self: &Arc<Self>,
        record: TableFileRecord,
        request: &ServiceRequest,
        key: Option<Zeroizing<String>>,
    ) -> TableCall {
        self.for_access(record, request, TableAccess::Creation(key))
    }

    fn inspection_call(
        self: &Arc<Self>,
        record: TableFileRecord,
        request: &ServiceRequest,
    ) -> TableCall {
        self.for_access(record, request, TableAccess::InspectCreating)
    }

    fn control_call(
        self: &Arc<Self>,
        record: TableFileRecord,
        request: &ServiceRequest,
    ) -> TableCall {
        let access = if record.phase() == FilePhase::Updating {
            TableAccess::Updating
        } else {
            TableAccess::Control
        };
        self.for_access(record, request, access)
    }
    pub fn new(state: Arc<StateDb>, registry: Weak<ServiceRegistry>) -> Arc<Self> {
        Arc::new(Self {
            state,
            registry,
            services: OnceCell::new(),
        })
    }

    async fn services(&self) -> Result<&Services, DdbError> {
        self.services
            .get_or_try_init(|| async {
                let dispatcher = self
                    .registry
                    .upgrade()
                    .and_then(|r| r.internal_dispatcher())
                    .ok_or_else(unavailable)?;
                let cipher = Arc::new(StateCipher::from_env().map_err(|_| unavailable())?);
                let keys = Arc::new(TableKeys::new(dispatcher, cipher));
                let catalog = TableCatalog::new(self.state.clone(), keys.clone()).await?;
                Ok(Services { keys, catalog })
            })
            .await
    }

    pub async fn resolve(
        self: &Arc<Self>,
        account: &str,
        region: &str,
        operation: &str,
        body: &Value,
        request: Option<&ServiceRequest>,
    ) -> Result<Option<TableCall>, DdbError> {
        let services = self.services().await?;
        let Some(raw) = body.get("TableName").and_then(Value::as_str) else {
            if !matches!(
                operation,
                "DescribeLimits" | "__locallycloud_resolve_stream_iterator"
            ) && services.catalog.has_scope(account, region).await?
            {
                let targets =
                    locallycloud_dynamodb::service::authorization_targets(operation, body)?;
                for (_, target) in targets {
                    let Some(name) = Self::target_name(account, region, &target)? else {
                        continue;
                    };
                    if services
                        .catalog
                        .load(account, region, name)
                        .await?
                        .is_some()
                    {
                        return Err(DdbError::Validation(
                            "This operation is not yet supported for encrypted tables".into(),
                        ));
                    }
                }
            }
            return Ok(None);
        };
        let name = match raw.strip_prefix("arn:") {
            Some(_) => raw
                .strip_prefix(&format!("arn:aws:dynamodb:{region}:{account}:table/"))
                .ok_or_else(|| {
                    DdbError::Validation("Table ARN must match the request scope".into())
                })?,
            None => raw,
        };
        let Some(record) = services.catalog.load(account, region, name).await? else {
            return Ok(None);
        };
        if record.phase() != FilePhase::Active {
            return Err(DdbError::ResourceInUse(
                "Encrypted table storage is transitioning".into(),
            ));
        }
        // Control operations and multi-file requests need the durable coordinator.
        // In particular, never return an owned-encryption descriptor for a KMS file.
        if !matches!(
            operation,
            "GetItem" | "PutItem" | "UpdateItem" | "DeleteItem" | "Query" | "Scan"
        ) {
            return Err(DdbError::Validation(
                "This operation is not yet supported for encrypted tables".into(),
            ));
        }
        let request = request.ok_or_else(|| {
            DdbError::AccessDenied("Encrypted table access requires a caller identity".into())
        })?;
        Ok(Some(self.call(record, request)))
    }
}

impl TableCall {
    pub fn file_access(&self) -> FileAccess {
        match &self.access {
            TableAccess::Creation(_) => FileAccess::Create,
            TableAccess::Data
            | TableAccess::Control
            | TableAccess::Updating
            | TableAccess::InspectCreating => FileAccess::Existing,
        }
    }
    pub fn check_operation(&self, operation: &str) -> Result<(), DdbError> {
        let allowed = match &self.access {
            TableAccess::Data => matches!(
                operation,
                "GetItem" | "PutItem" | "UpdateItem" | "DeleteItem" | "Query" | "Scan"
            ),
            TableAccess::Creation(_) => matches!(operation, "CreateTable" | "DescribeTable"),
            TableAccess::InspectCreating => operation == "DescribeTable",
            TableAccess::Control | TableAccess::Updating => {
                matches!(operation, "DescribeTable" | "UpdateTable")
            }
        };
        if !allowed {
            return Err(DdbError::Validation(
                "Operation does not match table authorization".into(),
            ));
        }
        Ok(())
    }
    pub async fn authorize(&self) -> Result<KmsCallContext, DdbError> {
        let services = self.storage.services().await?;
        let scope = self.record.scope();
        let current = services
            .catalog
            .load(scope.account(), scope.region(), scope.table_name())
            .await?
            .ok_or_else(|| {
                DdbError::ResourceNotFound("Encrypted table storage no longer exists".into())
            })?;
        let phase = match &self.access {
            TableAccess::Data | TableAccess::Control => FilePhase::Active,
            TableAccess::Updating => FilePhase::Updating,
            TableAccess::Creation(_) | TableAccess::InspectCreating => FilePhase::Creating,
        };
        if current.phase() != phase
            || current.scope().storage_id() != scope.storage_id()
            || current.revision() != self.record.revision()
        {
            return Err(DdbError::ResourceInUse(
                "Encrypted table storage changed before execution".into(),
            ));
        }
        let (call, action) = match &self.access {
            TableAccess::Creation(_) => {
                let key_arn = services
                    .keys
                    .key_arn(scope, self.record.envelope())
                    .map_err(kms_error)?;
                let (call, _) = services
                    .keys
                    .generation_context(
                        scope,
                        Some(&key_arn),
                        &self.request_id,
                        self.identity.clone(),
                        self.delegated.clone(),
                    )
                    .await
                    .map_err(kms_error)?;
                (call, KmsDataKeyAction::Generate)
            }
            TableAccess::Data
            | TableAccess::Control
            | TableAccess::Updating
            | TableAccess::InspectCreating => (
                services
                    .keys
                    .decryption_context(
                        scope,
                        self.record.envelope(),
                        &self.request_id,
                        self.identity.clone(),
                        self.delegated.clone(),
                    )
                    .map_err(kms_error)?,
                KmsDataKeyAction::Decrypt,
            ),
        };
        services
            .keys
            .authorize_action(scope, call.clone(), self.record.envelope(), action)
            .await
            .map_err(kms_error)?;
        Ok(call)
    }

    pub async fn unlock(&self) -> Result<Zeroizing<String>, DdbError> {
        let call = self.authorize().await?;
        let services = self.storage.services().await?;
        let call = match &self.access {
            TableAccess::Creation(None) => services
                .keys
                .decryption_context(
                    self.record.scope(),
                    self.record.envelope(),
                    &self.request_id,
                    self.identity.clone(),
                    self.delegated.clone(),
                )
                .map_err(kms_error)?,
            TableAccess::Data
            | TableAccess::Control
            | TableAccess::Updating
            | TableAccess::InspectCreating => call,
            TableAccess::Creation(Some(key)) => return Ok(Zeroizing::new(key.to_string())),
        };
        let key = services
            .keys
            .open(self.record.scope(), call, self.record.envelope())
            .await
            .map_err(kms_error)?;
        Ok(Zeroizing::new(
            base64::engine::general_purpose::STANDARD.encode(key.as_slice()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Request, Worker, WorkerBudget, WorkerPool, MAX_WORKERS, REQUEST_TIMEOUT};
    use super::*;
    use axum::body::Bytes;
    use locallycloud_core::integration::identity::PRINCIPAL_HEADER;
    use locallycloud_core::integration::InternalDispatcher;
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use locallycloud_core::registry::ServiceName;
    use locallycloud_dynamodb::encryption::TableKeyScope;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use tokio::sync::oneshot;

    const ACCOUNT: &str = "000000000000";
    const REGION: &str = "us-east-1";

    fn request(body: Value, role: Option<&str>) -> ServiceRequest {
        let mut headers = http::HeaderMap::new();
        if let Some(role) = role {
            headers.insert(
                "x-locallycloud-verified-internal-scope",
                http::HeaderValue::from_static("1"),
            );
            headers.insert(
                PRINCIPAL_HEADER,
                format!("arn:aws:iam::{ACCOUNT}:role/{role}/probe")
                    .parse()
                    .unwrap(),
            );
        }
        ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            account_id: ACCOUNT.into(),
            region: REGION.into(),
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    async fn native(
        registry: &Arc<ServiceRegistry>,
        service: &str,
        operation: &str,
        body: Value,
    ) -> Value {
        let mut req = request(body.clone(), None);
        if service == "kms" {
            req.headers.insert(
                "x-amz-target",
                format!("TrentService.{operation}").parse().unwrap(),
            );
        } else {
            let mut url = reqwest::Url::parse("http://localhost").unwrap();
            url.query_pairs_mut()
                .append_pair("Version", "2010-05-08")
                .append_pair("Action", operation);
            for (name, value) in body.as_object().unwrap() {
                url.query_pairs_mut()
                    .append_pair(name, value.as_str().unwrap());
            }
            req.headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            req.body = Bytes::from(url.query().unwrap().to_owned());
        }
        let response = registry
            .native_handler(&ServiceName::new(service))
            .unwrap()
            .handle(req)
            .await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        assert_eq!(
            status,
            http::StatusCode::OK,
            "native {service} {operation}: {}",
            String::from_utf8_lossy(&bytes)
        );
        if service == "kms" && !bytes.is_empty() {
            serde_json::from_slice(&bytes).unwrap()
        } else {
            Value::Null
        }
    }

    async fn worker_call(worker: &mut Worker, op: &str, body: Value) -> Value {
        let (reply, _) = oneshot::channel();
        let (status, body) = worker
            .request(&Request {
                operation: op.into(),
                body,
                reply,
                deadline: tokio::time::Instant::now() + REQUEST_TIMEOUT,
                table: None,
            })
            .await
            .unwrap();
        assert_eq!(status, 200, "worker {op}: {body}");
        body
    }

    #[tokio::test]
    async fn actual_table_worker_reauthorizes_warm_access_and_rejects_stale_generations() {
        let Some(binary) = std::env::var_os("LOCALLYCLOUD_TEST_TABLE_WORKER") else {
            return;
        };
        // Run this explicit probe alone: it owns its temporary environment and native services.
        std::env::set_var(
            "LOCALLYCLOUD_KMS_MASTER_KEY",
            base64::engine::general_purpose::STANDARD.encode([13; 32]),
        );
        std::env::set_var("LOCALLYCLOUD_IAM_ENFORCEMENT", "permissive");
        std::env::set_var(
            "LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID",
            "AKIARRRRRRRRRRRRRRRR",
        );
        std::env::set_var("LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY", "s".repeat(40));
        let root = std::env::temp_dir().join(format!("table-worker-{}", uuid::Uuid::new_v4()));
        let fixture = root.clone();
        let (state, components) = tokio::task::spawn_blocking(move || {
            let state = Arc::new(StateDb::open(fixture.join("state.sqlite3")).unwrap());
            let bytes = std::fs::read(binary).unwrap();
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let components = fixture.join("components");
            let version = components.join("extenddb/versions").join(&digest);
            crate::component_manager::private_directory(&version).unwrap();
            std::fs::write(version.join("worker"), bytes).unwrap();
            std::fs::set_permissions(
                version.join("worker"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            std::fs::write(
                components.join("extenddb/active.json"),
                json!({"protocol":1,"sha256":digest,"previous_sha256":null}).to_string(),
            )
            .unwrap();
            (state, components)
        })
        .await
        .unwrap();
        let registry = ServiceRegistry::with_known_services();
        let dispatcher = Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            REGION.into(),
            ACCOUNT.into(),
        ));
        registry.set_internal_dispatcher(dispatcher);
        locallycloud_iam_sts::service::register_with_state(&registry, ACCOUNT, state.clone())
            .unwrap();
        locallycloud_kms::register_with_state(&registry, state.clone()).unwrap();
        let mut pool =
            WorkerPool::new(&state, crate::dynamodb_replication::RelayNotifier::new()).unwrap();
        pool.launch.components = components;
        pool.budget = WorkerBudget::new(1);
        let storage = TableStorage::new(state.clone(), Arc::downgrade(&registry));
        pool.table_storage = Some(storage.clone());
        let services = storage.services().await.unwrap();
        let root_policy=json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:root")},"Action":"kms:*","Resource":"*"}]}).to_string();
        let created = native(&registry, "kms", "CreateKey", json!({"Policy":root_policy})).await;
        let key_arn = created["KeyMetadata"]["Arn"].as_str().unwrap();
        let scope =
            TableKeyScope::new(ACCOUNT, REGION, "encrypted-orders", uuid::Uuid::new_v4()).unwrap();
        let root_call = KmsCallContext {
            source_service: "dynamodb".into(),
            account_id: ACCOUNT.into(),
            region: REGION.into(),
            request_id: "prepare".into(),
            caller_arn: Some(format!("arn:aws:iam::{ACCOUNT}:root")),
            iam_policy_allowed: false,
            iam_policy_denied: false,
        };
        let material = services
            .keys
            .generate(&scope, root_call, Some(key_arn))
            .await
            .unwrap();
        let creating = services
            .catalog
            .reserve(scope, material.envelope)
            .await
            .unwrap();
        let database = pool
            .data
            .join(ACCOUNT)
            .join(REGION)
            .join(creating.file_name());
        let encoded = Zeroizing::new(
            base64::engine::general_purpose::STANDARD.encode(material.plaintext.as_slice()),
        );
        let slot = pool.budget.acquire().await.unwrap();
        let mut seed = Worker::spawn(
            pool.launch.clone(),
            database.clone(),
            slot,
            Some(&creating),
            FileAccess::Create,
        )
        .await
        .unwrap();
        seed.initialize(
            pool.launch.mode,
            &database,
            &(ACCOUNT.into(), REGION.into()),
            &encoded,
            Some(&creating),
        )
        .await
        .unwrap();
        worker_call(&mut seed,"CreateTable",json!({"TableName":"encrypted-orders","BillingMode":"PAY_PER_REQUEST","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}]})).await;
        for _ in 0..100 {
            if worker_call(
                &mut seed,
                "DescribeTable",
                json!({"TableName":"encrypted-orders"}),
            )
            .await["Table"]["TableStatus"]
                == "ACTIVE"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        worker_call(&mut seed,"PutItem",json!({"TableName":"encrypted-orders","Item":{"id":{"S":"one"},"value":{"S":"preserved"}}})).await;
        seed.stop().await.unwrap();
        drop(seed);
        services
            .catalog
            .transition(&creating, FilePhase::Active)
            .await
            .unwrap();
        native(&registry,"iam","CreateRole",json!({"RoleName":"table-reader","AssumeRolePolicyDocument":json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}).to_string()})).await;
        let allow=json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":key_arn}]}).to_string();
        native(
            &registry,
            "iam",
            "PutRolePolicy",
            json!({"RoleName":"table-reader","PolicyName":"table-key","PolicyDocument":allow}),
        )
        .await;
        // Warm a real regional worker first: the encrypted worker must obtain the same single slot.
        let (status, body) = pool
            .query(
                ACCOUNT,
                REGION,
                "DescribeTable".into(),
                json!({"TableName":"legacy-probe"}),
            )
            .await
            .unwrap();
        assert_eq!(status, 400);
        assert!(body["__type"]
            .as_str()
            .unwrap()
            .ends_with("#ResourceNotFoundException"));
        assert_eq!(pool.budget.slots.available_permits(), 0);
        let get = json!({"TableName":"encrypted-orders","Key":{"id":{"S":"one"}}});
        let req = request(get.clone(), Some("table-reader"));
        for _ in 0..2 {
            let (status, body) = pool
                .query_external(&req, "GetItem".into(), get.clone())
                .await
                .unwrap();
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["Item"]["value"]["S"], "preserved");
        }
        let development = request(get.clone(), None);
        let (status, body) = pool
            .query_external(&development, "GetItem".into(), get.clone())
            .await
            .unwrap();
        assert_eq!(status, 200, "permissive account root: {body}");
        assert_eq!(body["Item"]["value"]["S"], "preserved");
        assert_eq!(pool.budget.slots.available_permits(), 0);
        let deny=json!({"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"kms:Decrypt","Resource":key_arn}]}).to_string();
        native(
            &registry,
            "iam",
            "PutRolePolicy",
            json!({"RoleName":"table-reader","PolicyName":"table-key","PolicyDocument":deny}),
        )
        .await;
        let (status,body)=pool.query_external(&req,"PutItem".into(),json!({"TableName":"encrypted-orders","Item":{"id":{"S":"one"},"value":{"S":"forbidden"}}})).await.unwrap();
        assert_eq!(status, 400, "{body}");
        assert!(body["__type"]
            .as_str()
            .unwrap()
            .ends_with("#AccessDeniedException"));
        native(
            &registry,
            "iam",
            "PutRolePolicy",
            json!({"RoleName":"table-reader","PolicyName":"table-key","PolicyDocument":allow}),
        )
        .await;
        let (status, body) = pool
            .query_external(&req, "GetItem".into(), get.clone())
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body["Item"]["value"]["S"], "preserved");
        native(&registry, "kms", "DisableKey", json!({"KeyId":key_arn})).await;
        let (status, body) = pool
            .query_external(&req, "GetItem".into(), get.clone())
            .await
            .unwrap();
        assert_eq!(status, 400);
        assert!(body["__type"]
            .as_str()
            .unwrap()
            .ends_with("#AccessDeniedException"));
        native(&registry, "kms", "EnableKey", json!({"KeyId":key_arn})).await;
        let (status, body) = pool
            .query_external(&req, "GetItem".into(), get.clone())
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body["Item"]["value"]["S"], "preserved");
        for (op, body) in [
            ("DescribeTable", json!({"TableName":"encrypted-orders"})),
            ("ListTables", json!({})),
        ] {
            let (status, body) = pool.query_external(&req, op.into(), body).await.unwrap();
            assert_eq!(status, 200, "{op}: {body}");
            if op == "DescribeTable" {
                assert_eq!(body["Table"]["SSEDescription"]["KMSMasterKeyArn"], key_arn);
            } else {
                assert_eq!(body["TableNames"], json!(["encrypted-orders"]));
            }
        }
        let (status, body) = pool
            .query(ACCOUNT, REGION, "GetItem".into(), get.clone())
            .await
            .unwrap();
        assert_eq!(status, 400);
        assert!(body["__type"]
            .as_str()
            .unwrap()
            .ends_with("#AccessDeniedException"));
        // A separate strict IAM capability must reject missing identities before any worker starts.
        std::env::set_var("LOCALLYCLOUD_IAM_ENFORCEMENT", "strict");
        let strict_registry = ServiceRegistry::with_known_services();
        let strict_dispatch = Arc::new(InternalDispatcher::new_shared(
            &strict_registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            REGION.into(),
            ACCOUNT.into(),
        ));
        strict_registry.set_internal_dispatcher(strict_dispatch);
        locallycloud_iam_sts::service::register_with_state(
            &strict_registry,
            ACCOUNT,
            state.clone(),
        )
        .unwrap();
        locallycloud_kms::register_with_state(&strict_registry, state.clone()).unwrap();
        let mut strict =
            WorkerPool::new(&state, crate::dynamodb_replication::RelayNotifier::new()).unwrap();
        strict.launch.components = pool.launch.components.clone();
        strict.table_storage = Some(TableStorage::new(
            state.clone(),
            Arc::downgrade(&strict_registry),
        ));
        let (status, body) = strict
            .query_external(&development, "GetItem".into(), get.clone())
            .await
            .unwrap();
        assert_eq!(status, 400);
        assert!(body["__type"]
            .as_str()
            .unwrap()
            .ends_with("#AccessDeniedException"));
        assert_eq!(strict.budget.slots.available_permits(), MAX_WORKERS);
        strict.shutdown().await;
        // Evict the encrypted cache, then require its persisted file without recreating it.
        let (status, _) = pool
            .query(
                ACCOUNT,
                REGION,
                "DescribeTable".into(),
                json!({"TableName":"legacy-probe"}),
            )
            .await
            .unwrap();
        assert_eq!(status, 400);
        let saved = database.with_extension("saved");
        tokio::fs::rename(&database, &saved).await.unwrap();
        let (status, body) = pool
            .query_external(&req, "GetItem".into(), get.clone())
            .await
            .unwrap();
        assert_eq!(status, 500);
        assert!(body["__type"]
            .as_str()
            .unwrap()
            .ends_with("#InternalServerError"));
        assert!(!tokio::fs::try_exists(&database).await.unwrap());
        tokio::fs::rename(&saved, &database).await.unwrap();
        let (status, body) = pool
            .query_external(&req, "GetItem".into(), get.clone())
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body["Item"]["value"]["S"], "preserved");
        let active = services
            .catalog
            .load(ACCOUNT, REGION, "encrypted-orders")
            .await
            .unwrap()
            .unwrap();
        let stale = storage
            .resolve(ACCOUNT, REGION, "GetItem", &get, Some(&req))
            .await
            .unwrap()
            .unwrap();
        let sender = pool.worker(ACCOUNT, REGION, Some(&stale)).unwrap();
        let deleting = services
            .catalog
            .transition(&active, FilePhase::Deleting)
            .await
            .unwrap();
        assert!(matches!(
            stale.authorize().await,
            Err(DdbError::ResourceInUse(_))
        ));
        let scope = (
            ACCOUNT.into(),
            REGION.into(),
            Some(active.scope().storage_id()),
        );
        pool.stop_worker(&scope).await.unwrap();
        assert!(sender.is_closed());
        assert!(pool.worker(ACCOUNT, REGION, Some(&stale)).is_err());
        assert_eq!(pool.budget.slots.available_permits(), 1);
        // Only after the real child acknowledged exit may its file and catalog identity go.
        tokio::fs::remove_file(&database).await.unwrap();
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = database.as_os_str().to_owned();
            sidecar.push(suffix);
            match tokio::fs::remove_file(std::path::PathBuf::from(sidecar)).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("fixture sidecar cleanup failed: {error}"),
            }
        }
        services.catalog.forget_deleted(&deleting).await.unwrap();
        let (status, _) = pool
            .query(ACCOUNT, REGION, "ListTables".into(), json!({}))
            .await
            .unwrap();
        assert_eq!(status, 200);
        pool.shutdown().await;
        assert_eq!(pool.budget.slots.available_permits(), 1);
        tokio::fs::remove_dir_all(root).await.unwrap();
        eprintln!("Real table worker: scoped file, warm IAM denial, KMS revocation/recovery, stale generation rejection and confirmed per-generation cleanup passed");
    }
}
