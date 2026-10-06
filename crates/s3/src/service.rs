//! S3 service handler: REST-XML operation selection by method + request shape + query
//! sub-resource markers, registered `Native` in the Core registry.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use http::{HeaderValue, Method};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::correlation::CorrelationContext;
use locallycloud_core::integration::delivery::{
    AsyncDeliveryPolicy, CrossServiceCall, DeliveryEngine,
};
use locallycloud_core::integration::identity::CallerIdentity;
use locallycloud_core::integration::{InternalDispatcher, RequestIdentity};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_state::StateDb;
use serde::{Deserialize, Serialize};

use crate::addr::{resolve, Shape};
use crate::error::S3Error;
use crate::notifications::{self, DeliveryTarget, EventType};
use crate::ops::{self, Ctx};
use crate::persistence::S3Persistence;
use crate::presign;
use crate::query::QueryParams;
use crate::select;
use crate::store::AccountStore;

/// The natively-implemented S3 service.
pub struct S3Handler {
    store: Arc<AccountStore>,
    registry: Weak<ServiceRegistry>,
    notification_tx: mpsc::Sender<NotificationJob>,
    notification_rx: Mutex<Option<mpsc::Receiver<NotificationJob>>>,
    persistence: Option<S3Persistence>,
    mutation_lock: tokio::sync::Mutex<()>,
    namespace_gate: tokio::sync::RwLock<()>,
    persisted_in_route: AtomicBool,
    poisoned: AtomicBool,
}

// A bounded queue wakes the worker. Persistent handlers replay committed outbox rows.
const NOTIFICATION_QUEUE_CAPACITY: usize = 1024;
pub(super) const MAX_PENDING_NOTIFICATIONS: i64 = 100_000;

struct NotificationJob {
    dispatcher: Arc<InternalDispatcher>,
    request_id: String,
    account_id: String,
    region: String,
    deliveries: Vec<notifications::DeliveryRequest>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct StoredDelivery {
    request_id: String,
    account_id: String,
    region: String,
    target: DeliveryTarget,
    arn: Option<String>,
    method: String,
    uri: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

impl StoredDelivery {
    fn from_request(req: &ServiceRequest, delivery: &notifications::DeliveryRequest) -> Self {
        Self {
            request_id: req.request_id.clone(),
            account_id: req.account_id.clone(),
            region: req.region.clone(),
            target: delivery.target,
            arn: delivery.arn.clone(),
            method: delivery.method.to_string(),
            uri: delivery.uri.to_string(),
            headers: delivery
                .headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
                .collect(),
            body: delivery.body.to_vec(),
        }
    }

    fn into_request(
        self,
    ) -> Result<(String, String, String, notifications::DeliveryRequest), String> {
        let mut headers = http::HeaderMap::new();
        for (name, value) in self.headers {
            let name = http::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|error| error.to_string())?;
            let value = HeaderValue::from_bytes(&value).map_err(|error| error.to_string())?;
            headers.append(name, value);
        }
        Ok((
            self.request_id,
            self.account_id,
            self.region,
            notifications::DeliveryRequest {
                target: self.target,
                arn: self.arn,
                method: self
                    .method
                    .parse()
                    .map_err(|error: http::method::InvalidMethod| error.to_string())?,
                uri: self
                    .uri
                    .parse()
                    .map_err(|error: http::uri::InvalidUri| error.to_string())?,
                headers,
                body: self.body.into(),
            },
        ))
    }
}

async fn deliver_notification(
    dispatcher: Arc<InternalDispatcher>,
    request_id: &str,
    account_id: &str,
    region: &str,
    delivery: notifications::DeliveryRequest,
) -> bool {
    let target = delivery.target;
    let arn = delivery
        .arn
        .clone()
        .unwrap_or_else(|| "eventbridge".to_string());
    let call = || CrossServiceCall {
        source_service: ServiceName::new("s3"),
        account_id: account_id.to_string(),
        region: region.to_string(),
        method: delivery.method.clone(),
        uri: delivery.uri.clone(),
        headers: delivery.headers.clone(),
        body: delivery.body.clone(),
        identity: CallerIdentity::ServicePrincipal {
            service: "s3".to_string(),
        },
        correlation: CorrelationContext {
            flow_id: request_id.to_string(),
            span_id: CorrelationContext::root().span_id,
        },
        pattern: None,
    };
    if target == DeliveryTarget::EventBridge {
        for attempt in 0..3 {
            let response = DeliveryEngine::new(dispatcher.clone())
                .deliver_sync(call())
                .await;
            let status = response.status().as_u16();
            if (200..300).contains(&status) {
                if let Ok(body) = axum::body::to_bytes(response.into_body(), 1024 * 1024).await {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) {
                        if value
                            .get("FailedEntryCount")
                            .and_then(serde_json::Value::as_u64)
                            == Some(0)
                        {
                            return true;
                        }
                    }
                }
            } else if matches!(
                DeliveryEngine::classify(status),
                locallycloud_core::integration::delivery::FailureClass::Terminal
            ) {
                break;
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(25_u64 << attempt)).await;
            }
        }
        tracing::error!(request_id, target = ?target, arn = %arn, "S3 EventBridge notification failed or partially accepted; pending outbox entry will retry");
        return false;
    }
    let policy = AsyncDeliveryPolicy {
        max_attempts: 3,
        on_failure: None,
    };
    match DeliveryEngine::new(dispatcher)
        .deliver_async(call(), &policy)
        .await
    {
        Ok(_) => true,
        Err(error) => {
            tracing::error!(request_id, target = ?target, arn = %arn, %error, "S3 notification delivery failed; pending outbox entry will retry");
            false
        }
    }
}

fn is_account_id(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_s3_control(req: &ServiceRequest, host: Option<&str>) -> bool {
    if req.headers.contains_key("x-amz-account-id") {
        return true;
    }
    if host.is_some_and(|host| host.to_ascii_lowercase().contains("s3-control")) {
        return true;
    }
    let segments = req
        .uri
        .path()
        .trim_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    segments.as_slice() == ["v20180820", "configuration", "publicAccessBlock"]
        || matches!(
            segments.as_slice(),
            [account, "v20180820", "configuration", "publicAccessBlock"]
                if is_account_id(account)
        )
}

fn control_account(req: &ServiceRequest, host: Option<&str>) -> String {
    if let Some(account) = req
        .headers
        .get("x-amz-account-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    {
        return account.to_string();
    }
    if let Some(account) = QueryParams::parse(req.uri.query()).get("accountId") {
        return account.to_string();
    }
    if let Some(account) = req
        .uri
        .path()
        .trim_matches('/')
        .split('/')
        .next()
        .filter(|segment| is_account_id(segment))
    {
        return account.to_string();
    }
    if let Some(account) = host
        .and_then(|host| host.split('.').next())
        .filter(|segment| is_account_id(segment))
    {
        return account.to_string();
    }
    req.account_id.clone()
}

impl Default for S3Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl S3Handler {
    pub fn new() -> Self {
        Self::with_registry(Weak::new())
    }

    fn with_registry(registry: Weak<ServiceRegistry>) -> Self {
        let (notification_tx, notification_rx) = mpsc::channel(NOTIFICATION_QUEUE_CAPACITY);
        S3Handler {
            store: Arc::new(AccountStore::new()),
            registry,
            notification_tx,
            notification_rx: Mutex::new(Some(notification_rx)),
            persistence: None,
            mutation_lock: tokio::sync::Mutex::new(()),
            namespace_gate: tokio::sync::RwLock::new(()),
            persisted_in_route: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
        }
    }

    fn with_state(registry: Weak<ServiceRegistry>, state: Arc<StateDb>) -> Result<Self, String> {
        let storage_keys = crate::encryption::StorageKeys::persistent(&state).map_err(|_| {
            "S3 storage key unavailable; check LOCALLYCLOUD_KMS_MASTER_KEY and state database"
                .to_string()
        })?;
        Self::load_state(registry, state, storage_keys, true)
    }

    /// Load offline migration state without replaying notification work.
    pub fn for_migration(
        registry: &Arc<ServiceRegistry>,
        state: Arc<StateDb>,
    ) -> Result<Self, String> {
        let storage_keys = crate::encryption::StorageKeys::persistent(&state).map_err(|_| {
            "S3 storage key unavailable; check LOCALLYCLOUD_KMS_MASTER_KEY and state database"
                .to_string()
        })?;
        Self::load_state(Arc::downgrade(registry), state, storage_keys, false)
    }

    #[cfg(test)]
    fn with_storage_keys(
        registry: Weak<ServiceRegistry>,
        state: Arc<StateDb>,
        storage_keys: crate::encryption::StorageKeys,
    ) -> Result<Self, String> {
        Self::load_state(registry, state, storage_keys, true)
    }

    fn load_state(
        registry: Weak<ServiceRegistry>,
        state: Arc<StateDb>,
        storage_keys: crate::encryption::StorageKeys,
        replay_notifications: bool,
    ) -> Result<Self, String> {
        let persistence = S3Persistence::new(state)?;
        let mut handler = Self::with_registry(registry);
        Arc::get_mut(&mut handler.store)
            .expect("new S3 store")
            .storage_keys = Arc::new(storage_keys);
        persistence.restore(&handler.store)?;
        if let Err(error) = persistence.remove_orphan_blobs() {
            tracing::warn!(%error, "S3 orphan blob cleanup at startup failed");
        }
        let has_pending = persistence.has_pending()?;
        handler.persistence = Some(persistence);
        if has_pending && replay_notifications {
            handler.start_notification_worker();
        }
        Ok(handler)
    }

    /// Explicit administrative migration: each bucket is committed atomically.
    /// Legacy bodies stay readable until this is requested; no migration runs at startup.
    pub async fn migrate_legacy_encryption(
        &self,
        request: &ServiceRequest,
    ) -> Result<usize, S3Error> {
        let _mutation = self.mutation_lock.lock().await;
        let _namespace = self.namespace_gate.write().await;
        if self.poisoned.load(Ordering::Acquire) {
            return Err(S3Error::InternalError);
        }
        let mut migrated = 0;
        for name in self.store.list_names(&request.account_id) {
            let bucket = self
                .store
                .get(&request.account_id, &name)
                .ok_or(S3Error::NoSuchBucket)?;
            let original = bucket.read().await.clone();
            let mut updated = original.clone();
            let dispatcher = self
                .registry
                .upgrade()
                .and_then(|registry| registry.internal_dispatcher());
            let ctx = Ctx {
                store: &self.store,
                account: &request.account_id,
                region: &updated.region,
                request_id: &request.request_id,
                dispatcher,
                delegated_identity: None,
                strict_external: false,
                identity: Some(RequestIdentity {
                    account_id: request.account_id.clone(),
                    access_key_id: request
                        .headers
                        .get(http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .and_then(RequestIdentity::access_key_from_authorization),
                    arn: None,
                }),
            };
            let mut count = 0;
            for (key, object) in &mut updated.objects {
                if !matches!(object.body, crate::store::StoredBody::Encrypted(_)) {
                    object.body =
                        ops::encrypt_body(&ctx, &name, key, &object.body, &object.encryption)
                            .await?;
                    count += 1;
                }
            }
            for (key, versions) in &mut updated.versions {
                for version in versions {
                    if let crate::store::VersionValue::Object(object) = &mut version.value {
                        if !matches!(object.body, crate::store::StoredBody::Encrypted(_)) {
                            object.body = ops::encrypt_body(
                                &ctx,
                                &name,
                                key,
                                &object.body,
                                &object.encryption,
                            )
                            .await?;
                            count += 1;
                        }
                    }
                }
            }
            for upload in updated.uploads.values_mut() {
                if upload.key_envelope.is_none() {
                    upload.key_envelope = Some(
                        ops::encrypt_body(
                            &ctx,
                            &name,
                            &upload.key,
                            &crate::store::StoredBody::Inline(bytes::Bytes::new()),
                            &upload.encryption,
                        )
                        .await?,
                    );
                    count += 1;
                }
                for part in upload.parts.values_mut() {
                    if !matches!(part.body, crate::store::StoredBody::Encrypted(_)) {
                        part.body = ops::encrypt_body(
                            &ctx,
                            &name,
                            &upload.key,
                            &part.body,
                            &upload.encryption,
                        )
                        .await?;
                        count += 1;
                    }
                }
            }
            if count > 0 {
                *bucket.write().await = updated;
                if let Err(error) =
                    self.persist_bucket(&request.account_id, Some(&name), Vec::new())
                {
                    *bucket.write().await = original;
                    return Err(error);
                }
                migrated += count;
            }
        }
        Ok(migrated)
    }

    fn persist_request(
        &self,
        req: &ServiceRequest,
        notifications: Vec<StoredDelivery>,
    ) -> Result<(), S3Error> {
        let host = req.headers.get("host").and_then(|v| v.to_str().ok());
        if is_s3_control(req, host) {
            return self.persist_bucket(&control_account(req, host), None, notifications);
        }
        match resolve(host, req.uri.path()) {
            Shape::Bucket(name) | Shape::Object(name, _) => {
                self.persist_bucket(&req.account_id, Some(&name), notifications)
            }
            Shape::Service => Ok(()),
        }
    }
    #[cfg(test)]
    fn persist(&self, notifications: Vec<StoredDelivery>) -> Result<(), S3Error> {
        let Some(persistence) = &self.persistence else {
            return Ok(());
        };
        let payload = self.store.durable_snapshot(&persistence.blobs)?;
        persistence
            .save(&payload, &notifications)
            .map_err(|_| S3Error::InternalError)
    }
    fn persist_bucket(
        &self,
        account: &str,
        bucket: Option<&str>,
        notifications: Vec<StoredDelivery>,
    ) -> Result<(), S3Error> {
        let Some(persistence) = &self.persistence else {
            return Ok(());
        };
        // No yield after mutation: cancellation cannot release mutation_lock while a
        // transaction is still running and let a later request overwrite it.
        let commit = || {
            let rows = self
                .store
                .durable_delta(account, bucket, &persistence.blobs)
                .inspect_err(|_| {
                    tracing::error!(
                        stage = "metadata_delta",
                        "S3 durable commit failed before SQLite transaction"
                    );
                })?;
            persistence
                .save_delta(&rows, &notifications, self.store.durable_next_id())
                .map_err(|error| {
                    tracing::error!(stage = "sqlite_delta", %error, "S3 durable commit failed");
                    S3Error::InternalError
                })
        };
        let result = if tokio::runtime::Handle::current().runtime_flavor()
            == tokio::runtime::RuntimeFlavor::MultiThread
        {
            tokio::task::block_in_place(commit)
        } else {
            commit()
        };
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        } else {
            self.persisted_in_route.store(true, Ordering::Release);
        }
        result
    }

    /// Caller holds mutation admission and the namespace write gate. Failed writes
    /// stay failed; reload committed metadata before allowing any dirty RAM reads.
    fn recover_committed_state(&self) -> Result<(), S3Error> {
        if !self.poisoned.load(Ordering::Acquire) {
            return Ok(());
        }
        let persistence = self.persistence.as_ref().ok_or(S3Error::InternalError)?;
        let restore = || persistence.restore(&self.store);
        let result = if tokio::runtime::Handle::current().runtime_flavor()
            == tokio::runtime::RuntimeFlavor::MultiThread
        {
            tokio::task::block_in_place(restore)
        } else {
            restore()
        };
        result.map_err(|error| { tracing::error!(stage = "committed_restore", %error, "S3 failed commit recovery remains unavailable"); S3Error::InternalError })?;
        self.poisoned.store(false, Ordering::Release);
        Ok(())
    }

    fn start_notification_worker(&self) {
        let receiver = self
            .notification_rx
            .lock()
            .expect("notification worker lock")
            .take();
        let Some(mut receiver) = receiver else {
            return;
        };
        if let Some(persistence) = self.persistence.clone() {
            let registry = self.registry.clone();
            tokio::spawn(async move {
                let mut retry = tokio::time::interval(Duration::from_secs(1));
                let mut cursor = 0_i64;
                let mut cycle_end = 0_i64;
                loop {
                    tokio::select! {
                        _ = retry.tick() => {}
                        job = receiver.recv() => { if job.is_none() { return; } }
                    }
                    let Some(dispatcher) = registry
                        .upgrade()
                        .and_then(|registry| registry.internal_dispatcher())
                    else {
                        continue;
                    };
                    if cursor == 0 {
                        let db = persistence.clone();
                        cycle_end =
                            match tokio::task::spawn_blocking(move || db.max_outbox_id()).await {
                                Ok(Ok(id)) => id,
                                Ok(Err(error)) => {
                                    tracing::error!(%error, "S3 outbox watermark read failed");
                                    continue;
                                }
                                Err(error) => {
                                    tracing::error!(%error, "S3 outbox watermark task failed");
                                    continue;
                                }
                            };
                    }
                    let db = persistence.clone();
                    let pending = match tokio::task::spawn_blocking(move || {
                        db.load_outbox(cursor, cycle_end)
                    })
                    .await
                    {
                        Ok(Ok(pending)) => pending,
                        Ok(Err(error)) => {
                            tracing::error!(%error, "S3 outbox read failed");
                            continue;
                        }
                        Err(error) => {
                            tracing::error!(%error, "S3 outbox read task failed");
                            continue;
                        }
                    };
                    if let Some((last, _)) = pending.last() {
                        cursor = *last;
                        if cursor >= cycle_end {
                            cursor = 0;
                        }
                    } else {
                        cursor = 0;
                    }
                    for (id, stored) in pending {
                        let (request_id, account_id, region, delivery) = match stored.into_request()
                        {
                            Ok(delivery) => delivery,
                            Err(error) => {
                                tracing::error!(%error, id, "S3 outbox entry is invalid");
                                continue;
                            }
                        };
                        if deliver_notification(
                            dispatcher.clone(),
                            &request_id,
                            &account_id,
                            &region,
                            delivery,
                        )
                        .await
                        {
                            let db = persistence.clone();
                            match tokio::task::spawn_blocking(move || db.delete_outbox(id)).await {
                                Ok(Ok(())) => {}
                                Ok(Err(error)) => {
                                    tracing::error!(%error, id, "S3 outbox acknowledgement failed")
                                }
                                Err(error) => {
                                    tracing::error!(%error, id, "S3 outbox acknowledgement task failed")
                                }
                            }
                        }
                    }
                }
            });
        } else {
            tokio::spawn(async move {
                while let Some(job) = receiver.recv().await {
                    for delivery in job.deliveries {
                        deliver_notification(
                            job.dispatcher.clone(),
                            &job.request_id,
                            &job.account_id,
                            &job.region,
                            delivery,
                        )
                        .await;
                    }
                }
            });
        }
    }

    async fn max_notification_rows(&self, req: &ServiceRequest) -> Result<i64, S3Error> {
        let host = req
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok());
        let (bucket_name, event_count) = match resolve(host, req.uri.path()) {
            Shape::Object(bucket, _) => (bucket, 1_usize),
            Shape::Bucket(bucket)
                if req.method == Method::POST
                    && QueryParams::parse(req.uri.query()).has("delete") =>
            {
                let (objects, _) = ops::parse_delete_request(&req.body)?;
                (bucket, objects.len().min(1000))
            }
            _ => return Ok(0),
        };
        let Some(bucket) = self.store.get(&req.account_id, &bucket_name) else {
            return Ok(0);
        };
        let guard = bucket.read().await;
        let configuration = &guard.notification_configuration;
        let destinations =
            configuration.queues.len() + configuration.topics.len() + configuration.lambdas.len();
        let direct = destinations.saturating_mul(event_count);
        let event_bridge = if configuration.event_bridge {
            event_count.div_ceil(10)
        } else {
            0
        };
        Ok(i64::try_from(direct.saturating_add(event_bridge)).unwrap_or(i64::MAX))
    }

    async fn run_mutation<F>(&self, req: &ServiceRequest, mutation: F) -> Result<Response, S3Error>
    where
        F: Future<Output = Result<ops::MutationResult, S3Error>>,
    {
        // Reserve capacity before polling the mutation future. A committed object must
        // never get a successful response if its notification cannot be enqueued.
        let permit = match self.notification_tx.try_reserve() {
            Ok(permit) => permit,
            Err(TrySendError::Full(_)) => return Ok(Self::slow_down_response(req)),
            Err(TrySendError::Closed(_)) => return Err(S3Error::InternalError),
        };
        if let Some(persistence) = &self.persistence {
            let required = self.max_notification_rows(req).await?;
            let check = || persistence.has_capacity(required);
            let capacity = if tokio::runtime::Handle::current().runtime_flavor()
                == tokio::runtime::RuntimeFlavor::MultiThread
            {
                tokio::task::block_in_place(check)
            } else {
                check()
            };
            if !capacity.map_err(|_| S3Error::InternalError)? {
                return Ok(Self::slow_down_response(req));
            }
        }
        let result = mutation.await?;
        let deliveries = Self::prepare_deliveries(req, &result.events);
        let stored = deliveries
            .iter()
            .map(|delivery| StoredDelivery::from_request(req, delivery))
            .collect();
        self.persist_request(req, stored)?;
        if !deliveries.is_empty() && self.persistence.is_some() {
            self.start_notification_worker();
        }
        self.publish_deliveries(req, deliveries, permit);
        Ok(result.response)
    }

    fn slow_down_response(req: &ServiceRequest) -> Response {
        let host_id = format!("lc2/{}", req.request_id);
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message><Resource>{}</Resource><RequestId>{}</RequestId><HostId>{}</HostId></Error>",
            crate::xml::escape(req.uri.path()),
            crate::xml::escape(&req.request_id),
            crate::xml::escape(&host_id),
        );
        Response::builder()
            .status(503)
            .header("content-type", "application/xml")
            .header("x-amz-request-id", &req.request_id)
            .header("x-amz-id-2", host_id)
            .body(Body::from(body))
            .expect("S3 SlowDown response is valid")
    }

    /// Core inserts this marker only after verifying an external request in strict IAM mode.
    /// Internal scoped calls and permissive mode do not carry it.
    fn authorize_object_write(
        &self,
        req: &ServiceRequest,
        bucket: &str,
        key: &str,
    ) -> Result<(), S3Error> {
        self.authorize_action(req, "s3:PutObject", &format!("arn:aws:s3:::{bucket}/{key}"))
    }

    fn authorize_action(
        &self,
        req: &ServiceRequest,
        action: &str,
        resource: &str,
    ) -> Result<(), S3Error> {
        if !Self::strict_external(req) {
            return Ok(());
        }
        let access_key_id = req
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(RequestIdentity::access_key_from_authorization)
            .ok_or(S3Error::AccessDenied)?;
        let dispatcher = self
            .registry
            .upgrade()
            .and_then(|registry| registry.internal_dispatcher())
            .ok_or(S3Error::AccessDenied)?;
        dispatcher
            .authorize(AuthorizationRequest {
                request_identity: RequestIdentity {
                    account_id: req.account_id.clone(),
                    access_key_id: Some(access_key_id),
                    arn: None,
                },
                delegated_identity: None,
                source_service: "s3".to_string(),
                action: action.to_string(),
                resource: resource.to_string(),
                context: BTreeMap::new(),
            })
            .map_err(|_| S3Error::AccessDenied)
    }

    fn strict_external(req: &ServiceRequest) -> bool {
        req.headers
            .get("x-locallycloud-verified-external-sigv4")
            .is_some_and(|value| value == "1")
    }

    fn known_strict_operation(req: &ServiceRequest, shape: &Shape, q: &QueryParams) -> bool {
        match (&req.method, shape) {
            (&Method::GET, Shape::Service) => q.only_keys(&[]),
            (&Method::OPTIONS, Shape::Bucket(_) | Shape::Object(_, _)) => true,
            (&Method::PUT, Shape::Bucket(_)) => {
                q.only_keys(&[])
                    || (q.only_keys(&["notification"]) && q.has("notification"))
                    || (q.only_keys(&["versioning"]) && q.has("versioning"))
            }
            (&Method::DELETE | &Method::HEAD, Shape::Bucket(_)) => q.only_keys(&[]),
            (&Method::GET, Shape::Bucket(_)) => {
                (q.only_keys(&["notification"]) && q.has("notification"))
                    || (q.only_keys(&["versioning"]) && q.has("versioning"))
                    || (q.has("versions")
                        && q.only_keys(&[
                            "versions",
                            "prefix",
                            "delimiter",
                            "key-marker",
                            "version-id-marker",
                            "max-keys",
                            "encoding-type",
                        ]))
                    || (q.has("uploads")
                        && q.only_keys(&[
                            "uploads",
                            "prefix",
                            "delimiter",
                            "key-marker",
                            "upload-id-marker",
                            "max-uploads",
                            "encoding-type",
                        ]))
                    || q.only_keys(&[
                        "list-type",
                        "prefix",
                        "delimiter",
                        "marker",
                        "max-keys",
                        "encoding-type",
                        "continuation-token",
                        "start-after",
                        "fetch-owner",
                    ])
            }
            (&Method::POST, Shape::Bucket(_)) => q.only_keys(&["delete"]) && q.has("delete"),
            (&Method::POST, Shape::Object(_, _)) => {
                q.only_keys(&["uploads", "uploadId"]) && (q.has("uploads") || q.has("uploadId"))
            }
            (&Method::PUT, Shape::Object(_, _)) => q.only_keys(&["uploadId", "partNumber"]),
            (&Method::GET, Shape::Object(_, _)) => {
                q.only_keys(&["versionId"])
                    || (q.has("uploadId")
                        && q.only_keys(&["uploadId", "part-number-marker", "max-parts"]))
            }
            (&Method::DELETE, Shape::Object(_, _)) => {
                q.only_keys(&["versionId"]) || (q.has("uploadId") && q.only_keys(&["uploadId"]))
            }
            (&Method::HEAD, Shape::Object(_, _)) => q.only_keys(&["versionId"]),
            _ => false,
        }
    }

    fn authorize_copy_source(&self, req: &ServiceRequest) -> Result<(), S3Error> {
        let source = req
            .headers
            .get("x-amz-copy-source")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| S3Error::InvalidArgument("x-amz-copy-source is required".into()))?;
        let (bucket, key, version) = ops::parse_copy_source(source)?;
        let action = if version.is_some() {
            "s3:GetObjectVersion"
        } else {
            "s3:GetObject"
        };
        self.authorize_action(req, action, &format!("arn:aws:s3:::{bucket}/{key}"))
    }

    fn prepare_deliveries(
        req: &ServiceRequest,
        events: &[notifications::ObjectEvent],
    ) -> Vec<notifications::DeliveryRequest> {
        let source_ip = req
            .headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .unwrap_or("127.0.0.1");
        let deliveries = events
            .iter()
            .flat_map(|event| {
                notifications::delivery_requests(
                    event,
                    &req.account_id,
                    &req.region,
                    &req.request_id,
                    source_ip,
                )
            })
            .collect();
        let mut deliveries = notifications::coalesce_event_bridge(deliveries);
        for delivery in &mut deliveries {
            let service = match delivery.target {
                DeliveryTarget::Lambda => "lambda",
                DeliveryTarget::Queue => "sqs",
                DeliveryTarget::Topic => "sns",
                DeliveryTarget::EventBridge => "events",
            };
            if let Ok(value) = HeaderValue::from_str(&format!(
                "AWS4-HMAC-SHA256 Credential={}/19700101/{}/{}/aws4_request",
                req.account_id, req.region, service
            )) {
                delivery.headers.insert("authorization", value);
            }
        }
        deliveries
    }

    fn publish_deliveries(
        &self,
        req: &ServiceRequest,
        deliveries: Vec<notifications::DeliveryRequest>,
        permit: mpsc::Permit<'_, NotificationJob>,
    ) {
        if deliveries.is_empty() {
            return;
        }
        let Some(dispatcher) = self
            .registry
            .upgrade()
            .and_then(|registry| registry.internal_dispatcher())
        else {
            tracing::warn!(
                request_id = req.request_id,
                "S3 notification worker unavailable; committed outbox will retry"
            );
            return;
        };
        let job = NotificationJob {
            dispatcher,
            request_id: req.request_id.clone(),
            account_id: req.account_id.clone(),
            region: req.region.clone(),
            deliveries,
        };
        self.start_notification_worker();
        permit.send(job);
    }

    async fn route(&self, req: &ServiceRequest) -> Result<Response, S3Error> {
        if req.headers.keys().any(|name| {
            name.as_str().contains("server-side-encryption-customer")
                || name == "x-amz-server-side-encryption-context"
        }) {
            return Err(S3Error::NotImplemented(
                "SSE-C and additional KMS encryption context are not implemented".into(),
            ));
        }
        let host = req.headers.get("host").and_then(|v| v.to_str().ok());
        let q = QueryParams::parse(req.uri.query());
        let dispatcher = self
            .registry
            .upgrade()
            .and_then(|registry| registry.internal_dispatcher());
        let ctx = Ctx {
            store: &self.store,
            account: &req.account_id,
            region: &req.region,
            request_id: &req.request_id,
            dispatcher,
            delegated_identity: locallycloud_core::integration::identity::trusted_role(req),
            strict_external: Self::strict_external(req),
            identity: Some(RequestIdentity {
                account_id: req.account_id.clone(),
                access_key_id: req
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .and_then(RequestIdentity::access_key_from_authorization),
                arn: None,
            }),
        };
        if is_s3_control(req, host) {
            if Self::strict_external(req) {
                return Err(S3Error::NotImplemented(
                    "strict IAM authorization is not mapped for S3 Control".into(),
                ));
            }
            let account = control_account(req, host);
            if !req
                .uri
                .path()
                .ends_with("/v20180820/configuration/publicAccessBlock")
            {
                return Err(S3Error::NotImplemented(format!(
                    "S3 Control operation not supported: {} {}",
                    req.method,
                    req.uri.path()
                )));
            }
            return match req.method {
                Method::PUT => ops::put_account_public_access_block(&ctx, &account, &req.body),
                Method::GET => ops::get_account_public_access_block(&ctx, &account),
                Method::DELETE => ops::delete_account_public_access_block(&ctx, &account),
                _ => Err(S3Error::NotImplemented(format!(
                    "S3 Control operation not supported: {} {}",
                    req.method,
                    req.uri.path()
                ))),
            };
        }

        if presign::is_presigned_url(req) {
            if !matches!(req.method, Method::GET | Method::PUT) {
                return Err(S3Error::AccessDenied);
            }
            presign::validate_url(req)?;
        }

        let shape = resolve(host, req.uri.path());
        if Self::strict_external(req) && !Self::known_strict_operation(req, &shape, &q) {
            return Err(S3Error::NotImplemented(
                "strict IAM authorization is not mapped for this S3 operation".into(),
            ));
        }
        match (&req.method, &shape) {
            (&Method::GET, Shape::Service) => {
                self.authorize_action(req, "s3:ListAllMyBuckets", "*")?;
                ops::list_buckets(&ctx).await
            }
            (&Method::OPTIONS, Shape::Bucket(b) | Shape::Object(b, _)) => {
                ops::options_bucket(&ctx, b, &req.headers).await
            }
            (&Method::PUT, Shape::Bucket(b)) if q.has("encryption") => {
                ops::put_bucket_encryption(&ctx, b, &req.body).await
            }
            (&Method::PUT, Shape::Bucket(b)) if q.has("notification") => {
                self.authorize_action(
                    req,
                    "s3:PutBucketNotification",
                    &format!("arn:aws:s3:::{b}"),
                )?;
                ops::put_bucket_notification(&ctx, b, &req.body).await
            }
            (&Method::PUT, Shape::Bucket(b)) if q.has("versioning") => {
                self.authorize_action(req, "s3:PutBucketVersioning", &format!("arn:aws:s3:::{b}"))?;
                ops::put_bucket_versioning(&ctx, b, &req.body).await
            }
            (&Method::PUT, Shape::Bucket(b)) if q.has("tagging") => {
                ops::put_bucket_tagging(&ctx, b, &req.body).await
            }
            (&Method::PUT, Shape::Bucket(b)) if q.has("cors") => {
                ops::put_bucket_cors(&ctx, b, &req.body).await
            }
            (&Method::PUT, Shape::Bucket(b)) if q.has("policy") => {
                ops::put_bucket_policy(&ctx, b, &req.body).await
            }
            (&Method::PUT, Shape::Bucket(b)) if q.has("website") => {
                ops::put_bucket_website(&ctx, b, &req.body).await
            }
            (&Method::PUT, Shape::Bucket(b)) if q.has("object-lock") => {
                ops::put_bucket_object_lock(&ctx, b, &req.body).await
            }
            (&Method::PUT, Shape::Bucket(b)) if q.has("publicAccessBlock") => {
                ops::put_bucket_public_access_block(&ctx, b, &req.body).await
            }
            (&Method::PUT, Shape::Bucket(b)) => {
                self.authorize_action(req, "s3:CreateBucket", &format!("arn:aws:s3:::{b}"))?;
                ops::create_bucket(&ctx, b, &req.headers).await
            }
            (&Method::DELETE, Shape::Bucket(b)) if q.has("encryption") => {
                ops::delete_bucket_encryption(&ctx, b).await
            }
            (&Method::DELETE, Shape::Bucket(b)) if q.has("tagging") => {
                ops::delete_bucket_tagging(&ctx, b).await
            }
            (&Method::DELETE, Shape::Bucket(b)) if q.has("cors") => {
                ops::delete_bucket_cors(&ctx, b).await
            }
            (&Method::DELETE, Shape::Bucket(b)) if q.has("policy") => {
                ops::delete_bucket_policy(&ctx, b).await
            }
            (&Method::DELETE, Shape::Bucket(b)) if q.has("publicAccessBlock") => {
                ops::delete_bucket_public_access_block(&ctx, b).await
            }
            (&Method::DELETE, Shape::Bucket(_)) if q.has("website") => {
                Err(S3Error::NotImplemented(format!(
                    "operation not supported: {} {}",
                    req.method,
                    req.uri.path()
                )))
            }
            (&Method::DELETE, Shape::Bucket(b)) => {
                self.authorize_action(req, "s3:DeleteBucket", &format!("arn:aws:s3:::{b}"))?;
                ops::delete_bucket(&ctx, b).await
            }
            (&Method::HEAD, Shape::Bucket(b)) => {
                self.authorize_action(req, "s3:ListBucket", &format!("arn:aws:s3:::{b}"))?;
                ops::head_bucket(&ctx, b).await
            }
            (&Method::GET, Shape::Bucket(b)) => {
                if q.has("location") {
                    ops::get_bucket_location(&ctx, b).await
                } else if q.has("policy") {
                    ops::get_bucket_policy(&ctx, b).await
                } else if q.has("versioning") {
                    self.authorize_action(
                        req,
                        "s3:GetBucketVersioning",
                        &format!("arn:aws:s3:::{b}"),
                    )?;
                    ops::get_bucket_versioning(&ctx, b).await
                } else if q.has("versions") {
                    self.authorize_action(
                        req,
                        "s3:ListBucketVersions",
                        &format!("arn:aws:s3:::{b}"),
                    )?;
                    ops::list_object_versions(&ctx, b, &q).await
                } else if q.has("uploads") {
                    self.authorize_action(
                        req,
                        "s3:ListBucketMultipartUploads",
                        &format!("arn:aws:s3:::{b}"),
                    )?;
                    ops::list_multipart_uploads(&ctx, b, &q).await
                } else if q.has("acl") {
                    ops::get_bucket_acl(&ctx, b).await
                } else if q.has("cors") {
                    ops::get_bucket_cors(&ctx, b).await
                } else if q.has("tagging") {
                    ops::get_bucket_tagging(&ctx, b).await
                } else if q.has("lifecycle") {
                    ops::get_bucket_lifecycle(&ctx, b).await
                } else if q.has("replication") {
                    ops::get_bucket_replication(&ctx, b).await
                } else if q.has("encryption") {
                    ops::get_bucket_encryption(&ctx, b).await
                } else if q.has("website") {
                    ops::get_bucket_website(&ctx, b).await
                } else if q.has("requestPayment") {
                    ops::get_bucket_request_payment(&ctx, b).await
                } else if q.has("accelerate") {
                    ops::get_bucket_accelerate(&ctx, b).await
                } else if q.has("logging") {
                    ops::get_bucket_logging(&ctx, b).await
                } else if q.has("notification") {
                    self.authorize_action(
                        req,
                        "s3:GetBucketNotification",
                        &format!("arn:aws:s3:::{b}"),
                    )?;
                    ops::get_bucket_notification(&ctx, b).await
                } else if q.has("object-lock") {
                    ops::get_bucket_object_lock(&ctx, b).await
                } else if q.has("ownershipControls") {
                    ops::get_bucket_ownership_controls(&ctx, b).await
                } else if q.has("publicAccessBlock") {
                    ops::get_bucket_public_access_block(&ctx, b).await
                } else if q.get("list-type") == Some("2") {
                    self.authorize_action(req, "s3:ListBucket", &format!("arn:aws:s3:::{b}"))?;
                    ops::list_objects_v2(&ctx, b, &q).await
                } else {
                    self.authorize_action(req, "s3:ListBucket", &format!("arn:aws:s3:::{b}"))?;
                    ops::list_objects_v1(&ctx, b, &q).await
                }
            }
            (&Method::POST, Shape::Bucket(b)) if q.has("delete") => {
                let (objects, _) = ops::parse_delete_request(&req.body)?;
                for (key, version) in objects {
                    let action = if version.is_some() {
                        "s3:DeleteObjectVersion"
                    } else {
                        "s3:DeleteObject"
                    };
                    self.authorize_action(req, action, &format!("arn:aws:s3:::{b}/{key}"))?;
                }
                self.run_mutation(req, ops::delete_objects(&ctx, b, &req.headers, &req.body))
                    .await
            }
            (&Method::POST, Shape::Bucket(b))
                if req
                    .headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        value.split(';').next().is_some_and(|kind| {
                            kind.trim().eq_ignore_ascii_case("multipart/form-data")
                        })
                    }) =>
            {
                let upload = presign::parse_post(req, b)?;
                self.authorize_object_write(req, b, &upload.key)?;
                self.run_mutation(req, async {
                    let mut result = ops::put_object_with_event(
                        &ctx,
                        b,
                        &upload.key,
                        &upload.headers,
                        upload.body,
                        EventType::ObjectCreatedPost,
                        "PostObject",
                    )
                    .await?;
                    *result.response.status_mut() = http::StatusCode::from_u16(upload.status)
                        .map_err(|_| S3Error::InternalError)?;
                    Ok(result)
                })
                .await
            }
            (&Method::POST, Shape::Object(b, k)) if q.has("uploads") => {
                self.authorize_object_write(req, b, k)?;
                ops::create_multipart_upload(&ctx, b, k, &req.headers).await
            }
            (&Method::POST, Shape::Object(b, k))
                if q.has("select") && q.get("select-type") == Some("2") =>
            {
                let object = ops::read_object_body(&ctx, b, k, q.get("versionId")).await?;
                let body = select::execute(&req.body, &object)?;
                Ok(Response::builder()
                    .status(200)
                    .header("content-type", "application/vnd.amazon.eventstream")
                    .header("x-amz-request-id", ctx.request_id)
                    .body(Body::from(body))
                    .expect("select object response is valid"))
            }
            (&Method::POST, Shape::Object(b, k)) if q.get("uploadId").is_some() => {
                self.authorize_object_write(req, b, k)?;
                self.run_mutation(
                    req,
                    ops::complete_multipart_upload(
                        &ctx,
                        b,
                        k,
                        q.get("uploadId").expect("guarded upload id"),
                        &req.headers,
                        &req.body,
                    ),
                )
                .await
            }
            (&Method::PUT, Shape::Object(b, k)) if q.get("uploadId").is_some() => {
                self.authorize_object_write(req, b, k)?;
                let upload_id = q.get("uploadId").expect("guarded upload id");
                if req.headers.contains_key("x-amz-copy-source") {
                    self.authorize_copy_source(req)?;
                    ops::upload_part_copy(&ctx, b, k, upload_id, q.get("partNumber"), &req.headers)
                        .await
                } else {
                    ops::upload_part(
                        &ctx,
                        b,
                        k,
                        upload_id,
                        q.get("partNumber"),
                        &req.headers,
                        req.body.clone(),
                    )
                    .await
                }
            }
            (&Method::PUT, Shape::Object(b, k)) if q.has("tagging") => {
                ops::put_object_tagging(&ctx, b, k, q.get("versionId"), &req.body).await
            }
            (&Method::PUT, Shape::Object(b, k)) if q.has("retention") => {
                ops::put_object_retention(&ctx, b, k, q.get("versionId"), &req.headers, &req.body)
                    .await
            }
            (&Method::PUT, Shape::Object(b, k)) if q.has("legal-hold") => {
                ops::put_object_legal_hold(&ctx, b, k, q.get("versionId"), &req.body).await
            }
            (&Method::PUT, Shape::Object(b, k)) => {
                self.authorize_object_write(req, b, k)?;
                self.run_mutation(req, async {
                    if req.headers.contains_key("x-amz-copy-source") {
                        self.authorize_copy_source(req)?;
                        ops::copy_object(&ctx, b, k, &req.headers).await
                    } else {
                        ops::put_object(&ctx, b, k, &req.headers, req.body.clone()).await
                    }
                })
                .await
            }
            (&Method::GET, Shape::Object(b, k)) if q.has("tagging") => {
                ops::get_object_tagging(&ctx, b, k, q.get("versionId")).await
            }
            (&Method::GET, Shape::Object(b, k)) if q.has("retention") => {
                ops::get_object_retention(&ctx, b, k, q.get("versionId")).await
            }
            (&Method::GET, Shape::Object(b, k)) if q.has("legal-hold") => {
                ops::get_object_legal_hold(&ctx, b, k, q.get("versionId")).await
            }
            (&Method::GET, Shape::Object(b, k)) if q.has("attributes") => {
                ops::get_object_attributes(&ctx, b, k, &req.headers, q.get("versionId")).await
            }
            (&Method::GET, Shape::Object(b, k)) if q.get("uploadId").is_some() => {
                self.authorize_action(
                    req,
                    "s3:ListMultipartUploadParts",
                    &format!("arn:aws:s3:::{b}/{k}"),
                )?;
                ops::list_parts(
                    &ctx,
                    b,
                    k,
                    q.get("uploadId").expect("guarded upload id"),
                    &q,
                )
                .await
            }
            (&Method::GET, Shape::Object(b, k)) => {
                let action = if q.get("versionId").is_some() {
                    "s3:GetObjectVersion"
                } else {
                    "s3:GetObject"
                };
                self.authorize_action(req, action, &format!("arn:aws:s3:::{b}/{k}"))?;
                ops::get_object(&ctx, b, k, &req.headers, q.get("versionId")).await
            }
            (&Method::HEAD, Shape::Object(b, k)) => {
                let action = if q.get("versionId").is_some() {
                    "s3:GetObjectVersion"
                } else {
                    "s3:GetObject"
                };
                self.authorize_action(req, action, &format!("arn:aws:s3:::{b}/{k}"))?;
                ops::head_object(&ctx, b, k, &req.headers, q.get("versionId")).await
            }
            (&Method::DELETE, Shape::Object(b, k)) if q.has("tagging") => {
                ops::delete_object_tagging(&ctx, b, k, q.get("versionId")).await
            }
            (&Method::DELETE, Shape::Object(b, k)) if q.get("uploadId").is_some() => {
                self.authorize_action(
                    req,
                    "s3:AbortMultipartUpload",
                    &format!("arn:aws:s3:::{b}/{k}"),
                )?;
                ops::abort_multipart_upload(
                    &ctx,
                    b,
                    k,
                    q.get("uploadId").expect("guarded upload id"),
                )
                .await
            }
            (&Method::DELETE, Shape::Object(b, k)) => {
                let action = if q.get("versionId").is_some() {
                    "s3:DeleteObjectVersion"
                } else {
                    "s3:DeleteObject"
                };
                self.authorize_action(req, action, &format!("arn:aws:s3:::{b}/{k}"))?;
                self.run_mutation(
                    req,
                    ops::delete_object(&ctx, b, k, q.get("versionId"), &req.headers),
                )
                .await
            }
            _ => Err(S3Error::NotImplemented(format!(
                "operation not supported: {} {}",
                req.method,
                req.uri.path()
            ))),
        }
    }
}

#[async_trait]
impl NativeHandler for S3Handler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        let _admission = self.mutation_lock.lock().await;
        if self.poisoned.load(Ordering::Acquire) {
            let _namespace = self.namespace_gate.write().await;
            self.recover_committed_state()
                .map_err(|_| "S3 committed state is unavailable")?;
        }
        self.store.resource_regions(account).await
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let host = request.headers.get("host").and_then(|v| v.to_str().ok());
        let shape = resolve(host, request.uri.path());
        let q = QueryParams::parse(request.uri.query());
        let mutating = matches!(request.method, Method::PUT | Method::POST | Method::DELETE)
            && !(request.method == Method::POST && q.has("select"));
        // Immutable gate lookup does not read bucket metadata. Independent bucket
        // readers never wait on a different bucket's durable SQL mutation.
        let recovering = self.poisoned.load(Ordering::Acquire);
        let _writer = if mutating || recovering || matches!(shape, Shape::Service) {
            Some(self.mutation_lock.lock().await)
        } else {
            None
        };
        let namespace_change = mutating
            && (is_s3_control(&request, host)
                || (matches!(shape, Shape::Bucket(_)) && request.uri.query().is_none()));
        let _namespace_write = if namespace_change || recovering {
            Some(self.namespace_gate.write().await)
        } else {
            None
        };
        let _namespace_read = if !namespace_change && !recovering {
            Some(self.namespace_gate.read().await)
        } else {
            None
        };
        if recovering && self.recover_committed_state().is_err() {
            return S3Error::InternalError.into_response(request.uri.path(), &request.request_id);
        }
        let gate = match &shape {
            Shape::Bucket(name) | Shape::Object(name, _) => {
                self.store.transaction_gate(&request.account_id, name)
            }
            Shape::Service => None,
        };
        let _bucket_write = if mutating {
            match &gate {
                Some(gate) => Some(gate.write().await),
                None => None,
            }
        } else {
            None
        };
        let _bucket_read = if !mutating {
            match &gate {
                Some(gate) => Some(gate.read().await),
                None => None,
            }
        } else {
            None
        };
        let resource = request.uri.path().to_string();
        if mutating {
            self.persisted_in_route.store(false, Ordering::Release);
        }
        let result = if self.poisoned.load(Ordering::Acquire) {
            Err(S3Error::InternalError)
        } else {
            self.route(&request).await
        };
        let result = match result {
            Ok(response)
                if mutating
                    && response.status().is_success()
                    && !self.persisted_in_route.load(Ordering::Acquire) =>
            {
                self.persist_request(&request, Vec::new())
                    .map(|()| response)
            }
            other => other,
        };
        let mut response = match result {
            Ok(response) => response,
            Err(err) => err.into_response(&resource, &request.request_id),
        };
        let host = request
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok());
        if request.method != Method::OPTIONS && !is_s3_control(&request, host) {
            let shape = resolve(host, request.uri.path());
            let bucket = match &shape {
                Shape::Bucket(bucket) | Shape::Object(bucket, _) => Some(bucket.as_str()),
                Shape::Service => None,
            };
            if let Some(bucket) = bucket {
                let ctx = Ctx {
                    store: &self.store,
                    account: &request.account_id,
                    region: &request.region,
                    request_id: &request.request_id,
                    dispatcher: None,
                    identity: None,
                    delegated_identity: None,
                    strict_external: false,
                };
                ops::apply_cors_headers(
                    &ctx,
                    bucket,
                    request.method.as_str(),
                    &request.headers,
                    &mut response,
                )
                .await;
            }
        }
        response
    }
}

/// Register S3 as a `Native` REST-XML service in the Core registry.
pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    state: Arc<StateDb>,
) -> Result<Arc<S3Handler>, String> {
    let handler = Arc::new(S3Handler::with_state(Arc::downgrade(registry), state)?);
    registry.register_native(
        ServiceName::new("s3"),
        ServiceMetadata::new(AwsProtocol::RestXml, None),
        handler.clone(),
    );
    Ok(handler)
}

pub fn register(registry: &Arc<ServiceRegistry>) {
    let handler: Arc<dyn NativeHandler> =
        Arc::new(S3Handler::with_registry(Arc::downgrade(registry)));
    registry.register_native(
        ServiceName::new("s3"),
        ServiceMetadata::new(AwsProtocol::RestXml, None),
        handler,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::time::Duration;

    use axum::body::Body;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use locallycloud_core::integration::kms::{
        KmsDecryptOutput, KmsDecryptRequest, KmsEncryptOutput, KmsEncryptRequest,
        KmsGenerateDataKeyOutput, KmsGenerateDataKeyRequest, KmsInternalApi, KmsInternalError,
        KmsValidateKeyOutput, KmsValidateKeyRequest,
    };
    use locallycloud_core::integration::InternalDispatcher;
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};

    pub(super) fn test_state_handler(
        registry: Weak<ServiceRegistry>,
        state: Arc<StateDb>,
    ) -> Result<S3Handler, String> {
        let keys = crate::encryption::StorageKeys::with_master(&state, &[0x42; 32])
            .map_err(|error| error.to_string())?;
        S3Handler::with_storage_keys(registry, state, keys)
    }

    type RecordedRequests = Arc<Mutex<Vec<(String, String)>>>;

    async fn wait_for_count<T>(items: &Arc<Mutex<Vec<T>>>, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while items.lock().unwrap().len() < expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("notification worker did not deliver expected requests");
    }

    struct RecordingEvents {
        status: u16,
        requests: RecordedRequests,
    }

    #[async_trait]
    impl NativeHandler for RecordingEvents {
        async fn handle(&self, request: ServiceRequest) -> Response {
            let target = request
                .headers
                .get("x-amz-target")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let body = String::from_utf8_lossy(&request.body).into_owned();
            self.requests.lock().unwrap().push((target, body));
            Response::builder()
                .status(self.status)
                .body(Body::from(r#"{"FailedEntryCount":0,"Entries":[]}"#))
                .unwrap()
        }
    }

    struct KmsHttpStub;

    #[async_trait]
    impl NativeHandler for KmsHttpStub {
        async fn handle(&self, _request: ServiceRequest) -> Response {
            Response::builder()
                .status(200)
                .body(Body::from("{}"))
                .unwrap()
        }
    }

    #[derive(Default)]
    struct FakeKmsApi {
        requests: Mutex<Vec<KmsValidateKeyRequest>>,
        decrypt_failure: Mutex<Option<KmsInternalError>>,
    }

    impl KmsInternalApi for FakeKmsApi {
        fn generate_data_key(
            &self,
            request: KmsGenerateDataKeyRequest,
        ) -> Result<KmsGenerateDataKeyOutput, KmsInternalError> {
            Ok(KmsGenerateDataKeyOutput {
                plaintext: locallycloud_core::integration::kms::SensitiveBytes::new(vec![0x21; 32]),
                ciphertext: locallycloud_core::integration::kms::SensitiveBytes::new(
                    serde_json::to_vec(&request.encryption_context).unwrap(),
                ),
                key_id: request.key_id,
            })
        }

        fn encrypt(
            &self,
            _request: KmsEncryptRequest,
        ) -> Result<KmsEncryptOutput, KmsInternalError> {
            Err(KmsInternalError::Unavailable)
        }

        fn decrypt(
            &self,
            request: KmsDecryptRequest,
        ) -> Result<KmsDecryptOutput, KmsInternalError> {
            if let Some(error) = *self.decrypt_failure.lock().unwrap() {
                return Err(error);
            }
            if serde_json::to_vec(&request.encryption_context).unwrap()
                != request.ciphertext.as_slice()
            {
                return Err(KmsInternalError::InvalidCiphertext);
            }
            Ok(KmsDecryptOutput {
                plaintext: locallycloud_core::integration::kms::SensitiveBytes::new(vec![0x21; 32]),
                key_id: request.key_id.unwrap(),
            })
        }

        fn validate_key(
            &self,
            request: KmsValidateKeyRequest,
        ) -> Result<KmsValidateKeyOutput, KmsInternalError> {
            self.requests.lock().unwrap().push(request.clone());
            match request.key_id.as_str() {
                "alias/aws/s3"
                | "alias/data"
                | "key-123"
                | "arn:aws:kms:us-east-1:000000000000:key/key-123" => Ok(KmsValidateKeyOutput {
                    key_arn: "arn:aws:kms:us-east-1:000000000000:key/key-123".to_string(),
                }),
                "denied" => Err(KmsInternalError::AccessDenied),
                "disabled" => Err(KmsInternalError::Disabled),
                _ => Err(KmsInternalError::NotFound),
            }
        }
    }

    struct FixtureKmsIdentity;
    impl locallycloud_core::integration::authorization::AuthorizationEvaluator for FixtureKmsIdentity {
        fn authorize(
            &self,
            _request: AuthorizationRequest,
        ) -> Result<(), locallycloud_core::integration::authorization::AuthorizationError> {
            Ok(())
        }
        fn resolve_caller_arn(
            &self,
            _: &RequestIdentity,
        ) -> Result<Option<String>, locallycloud_core::integration::authorization::AuthorizationError>
        {
            Ok(Some("arn:aws:iam::000000000000:root".into()))
        }
        fn identity_policy_allows(&self, _: AuthorizationRequest) -> bool {
            true
        }
        fn identity_policy_denies(&self, _: AuthorizationRequest) -> bool {
            false
        }
    }

    fn kms_handler() -> (S3Handler, Arc<ServiceRegistry>, Arc<FakeKmsApi>) {
        let registry = ServiceRegistry::with_known_services();
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            Arc::new(KmsHttpStub),
            Arc::new(FixtureKmsIdentity),
        );
        let kms = Arc::new(FakeKmsApi::default());
        registry.register_native_with_kms_api(
            ServiceName::new("kms"),
            ServiceMetadata::new(AwsProtocol::Json11, Some("TrentService")),
            Arc::new(KmsHttpStub),
            kms.clone(),
        );
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".to_string(),
                upstream_timeout: Duration::from_millis(10),
            },
            LegacyHealth::new(false),
            "us-east-1".to_string(),
            "000000000000".to_string(),
        )));
        (
            S3Handler::with_registry(Arc::downgrade(&registry)),
            registry,
            kms,
        )
    }

    #[derive(Debug)]
    struct RecordedDelivery {
        service: &'static str,
        target: String,
        uri: String,
        body: String,
        region: String,
        account: String,
    }

    type RecordedDeliveries = Arc<Mutex<Vec<RecordedDelivery>>>;

    struct RecordingDelivery {
        service: &'static str,
        deliveries: RecordedDeliveries,
    }

    #[async_trait]
    impl NativeHandler for RecordingDelivery {
        async fn handle(&self, request: ServiceRequest) -> Response {
            self.deliveries.lock().unwrap().push(RecordedDelivery {
                service: self.service,
                target: request
                    .headers
                    .get("x-amz-target")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string(),
                uri: request.uri.to_string(),
                body: String::from_utf8_lossy(&request.body).into_owned(),
                region: request.region,
                account: request.account_id,
            });
            Response::builder()
                .status(200)
                .body(Body::from("{}"))
                .unwrap()
        }
    }

    fn all_target_handler() -> (S3Handler, Arc<ServiceRegistry>, RecordedDeliveries) {
        let registry = ServiceRegistry::with_known_services();
        let deliveries = Arc::new(Mutex::new(Vec::new()));
        for (service, protocol, prefix) in [
            ("lambda", AwsProtocol::RestJson, None),
            ("sqs", AwsProtocol::Json10, Some("AmazonSQS")),
            ("sns", AwsProtocol::Query, None),
            ("events", AwsProtocol::Json11, Some("AWSEvents")),
        ] {
            registry.register_native(
                ServiceName::new(service),
                ServiceMetadata::new(protocol, prefix),
                Arc::new(RecordingDelivery {
                    service,
                    deliveries: deliveries.clone(),
                }),
            );
        }
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".to_string(),
                upstream_timeout: Duration::from_millis(10),
            },
            LegacyHealth::new(false),
            "us-east-1".to_string(),
            "000000000000".to_string(),
        )));
        (
            S3Handler::with_registry(Arc::downgrade(&registry)),
            registry,
            deliveries,
        )
    }

    fn event_handler(status: u16) -> (S3Handler, Arc<ServiceRegistry>, RecordedRequests) {
        let registry = ServiceRegistry::with_known_services();
        let requests = Arc::new(Mutex::new(Vec::new()));
        registry.register_native(
            ServiceName::new("events"),
            ServiceMetadata::new(AwsProtocol::Json11, Some("AWSEvents")),
            Arc::new(RecordingEvents {
                status,
                requests: requests.clone(),
            }),
        );
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".to_string(),
                upstream_timeout: Duration::from_millis(10),
            },
            LegacyHealth::new(false),
            "us-east-1".to_string(),
            "000000000000".to_string(),
        )));
        (
            S3Handler::with_registry(Arc::downgrade(&registry)),
            registry,
            requests,
        )
    }

    fn req(method: Method, path: &str, body: &str, headers: &[(&str, &str)]) -> ServiceRequest {
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_static("localhost:4566"));
        for (k, v) in headers {
            h.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers: h,
            body: Bytes::copy_from_slice(body.as_bytes()),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        }
    }

    struct WritePolicyStub {
        allow: std::sync::atomic::AtomicBool,
        requests: Mutex<Vec<AuthorizationRequest>>,
    }

    impl locallycloud_core::integration::authorization::AuthorizationEvaluator for WritePolicyStub {
        fn authorize(
            &self,
            request: AuthorizationRequest,
        ) -> Result<(), locallycloud_core::integration::authorization::AuthorizationError> {
            self.requests.lock().unwrap().push(request);
            if self.allow.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(())
            } else {
                Err(locallycloud_core::integration::authorization::AuthorizationError::Denied)
            }
        }
    }

    fn write_policy_handler() -> (S3Handler, Arc<ServiceRegistry>, Arc<WritePolicyStub>) {
        let registry = ServiceRegistry::with_known_services();
        let policy = Arc::new(WritePolicyStub {
            allow: std::sync::atomic::AtomicBool::new(false),
            requests: Mutex::new(Vec::new()),
        });
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            Arc::new(KmsHttpStub),
            policy.clone(),
        );
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".to_string(),
                upstream_timeout: Duration::from_millis(10),
            },
            LegacyHealth::new(false),
            "us-east-1".to_string(),
            "000000000000".to_string(),
        )));
        (
            S3Handler::with_registry(Arc::downgrade(&registry)),
            registry,
            policy,
        )
    }

    const VERIFIED_WRITE_HEADERS: &[(&str, &str)] = &[
        ("x-locallycloud-verified-external-sigv4", "1"),
        ("authorization", "AWS4-HMAC-SHA256 Credential=AKIATEST/20260925/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000"),
    ];

    #[tokio::test]
    async fn sdk_v3_x_id_preserves_strict_action_authorization_and_unknown_rejection() {
        let (handler, _registry, policy) = write_policy_handler();
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/bucket", "", &[]))
                .await
                .status(),
            200
        );
        // SDK v3 ListBuckets must reach the existing IAM evaluator, including Deny.
        assert_eq!(
            handler
                .handle(req(
                    Method::GET,
                    "/?x-id=ListBuckets",
                    "",
                    VERIFIED_WRITE_HEADERS
                ))
                .await
                .status(),
            403
        );
        policy
            .allow
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            handler
                .handle(req(
                    Method::GET,
                    "/?x-id=ListBuckets",
                    "",
                    VERIFIED_WRITE_HEADERS
                ))
                .await
                .status(),
            200
        );
        assert!(policy
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.action == "s3:ListAllMyBuckets" && request.resource == "*"));
        // Spoofing the advisory value cannot substitute ListBuckets permission for PutObject.
        policy
            .allow
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            handler
                .handle(req(
                    Method::PUT,
                    "/bucket/key?x-id=ListBuckets",
                    "blocked",
                    VERIFIED_WRITE_HEADERS
                ))
                .await
                .status(),
            403
        );
        assert_eq!(
            handler
                .handle(req(Method::GET, "/bucket/key", "", &[]))
                .await
                .status(),
            404
        );
        policy
            .allow
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            handler
                .handle(req(
                    Method::PUT,
                    "/bucket/key?x-id=PutObject",
                    "payload",
                    VERIFIED_WRITE_HEADERS
                ))
                .await
                .status(),
            200
        );
        let before = {
            let seen = policy.requests.lock().unwrap();
            assert!(seen
                .iter()
                .skip(2)
                .all(|request| request.action == "s3:PutObject"
                    && request.resource == "arn:aws:s3:::bucket/key"));
            seen.len()
        };
        assert_eq!(
            handler
                .handle(req(
                    Method::GET,
                    "/bucket?unsupported&x-id=ListBuckets",
                    "",
                    VERIFIED_WRITE_HEADERS
                ))
                .await
                .status(),
            501
        );
        assert_eq!(policy.requests.lock().unwrap().len(), before);
        assert_eq!(
            body_string(
                handler
                    .handle(req(Method::GET, "/bucket/key", "", &[]))
                    .await
            )
            .await
            .1,
            "payload"
        );
    }

    #[tokio::test]
    async fn verified_external_object_writes_require_put_object_before_mutation() {
        let (handler, _registry, policy) = write_policy_handler();
        // An internal service call creates the fixture without external IAM enforcement.
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/bucket", "", &[]))
                .await
                .status(),
            200
        );
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/bucket/source", "original", &[]))
                .await
                .status(),
            200
        );
        let denied_put = handler
            .handle(req(
                Method::PUT,
                "/bucket/a%20b",
                "blocked",
                VERIFIED_WRITE_HEADERS,
            ))
            .await;
        assert_eq!(denied_put.status(), 403);
        assert_eq!(
            handler
                .handle(req(Method::GET, "/bucket/a%20b", "", &[]))
                .await
                .status(),
            404
        );
        let mut copy_headers = VERIFIED_WRITE_HEADERS.to_vec();
        copy_headers.push(("x-amz-copy-source", "/bucket/source"));
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/bucket/copied", "", &copy_headers))
                .await
                .status(),
            403
        );
        assert_eq!(
            handler
                .handle(req(Method::GET, "/bucket/copied", "", &[]))
                .await
                .status(),
            404
        );
        let initiated = handler
            .handle(req(Method::POST, "/bucket/final?uploads", "", &[]))
            .await;
        let upload_id = xml_value(&body_string(initiated).await.1, "UploadId");
        let part = handler
            .handle(req(
                Method::PUT,
                &format!("/bucket/final?uploadId={upload_id}&partNumber=1"),
                "part",
                &[],
            ))
            .await;
        let etag = part
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let completion = format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>");
        assert_eq!(
            handler
                .handle(req(
                    Method::POST,
                    &format!("/bucket/final?uploadId={upload_id}"),
                    &completion,
                    VERIFIED_WRITE_HEADERS
                ))
                .await
                .status(),
            403
        );
        assert_eq!(
            handler
                .handle(req(Method::GET, "/bucket/final", "", &[]))
                .await
                .status(),
            404
        );
        let calls = policy.requests.lock().unwrap().clone();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].action, "s3:PutObject");
        assert_eq!(calls[0].resource, "arn:aws:s3:::bucket/a b");
        assert_eq!(calls[0].request_identity.account_id, "000000000000");
        assert_eq!(
            calls[0].request_identity.access_key_id.as_deref(),
            Some("AKIATEST")
        );
        assert_eq!(calls[1].resource, "arn:aws:s3:::bucket/copied");
        assert_eq!(calls[2].resource, "arn:aws:s3:::bucket/final");

        policy
            .allow
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            handler
                .handle(req(
                    Method::PUT,
                    "/bucket/a%20b",
                    "allowed",
                    VERIFIED_WRITE_HEADERS
                ))
                .await
                .status(),
            200
        );
        assert_eq!(
            body_string(
                handler
                    .handle(req(Method::GET, "/bucket/a%20b", "", &[]))
                    .await
            )
            .await
            .1,
            "allowed"
        );
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/bucket/copied", "", &copy_headers))
                .await
                .status(),
            200
        );
        assert_eq!(
            body_string(
                handler
                    .handle(req(Method::GET, "/bucket/copied", "", &[]))
                    .await
            )
            .await
            .1,
            "original"
        );
        assert_eq!(
            handler
                .handle(req(
                    Method::POST,
                    &format!("/bucket/final?uploadId={upload_id}"),
                    &completion,
                    VERIFIED_WRITE_HEADERS,
                ))
                .await
                .status(),
            200
        );
        assert_eq!(
            body_string(
                handler
                    .handle(req(Method::GET, "/bucket/final", "", &[]))
                    .await
            )
            .await
            .1,
            "part"
        );
    }

    #[tokio::test]
    async fn verified_external_read_list_and_delete_require_matching_policy() {
        let (handler, _registry, policy) = write_policy_handler();
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/bucket", "", &[]))
                .await
                .status(),
            200
        );
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/bucket/a%20b", "secret", &[]))
                .await
                .status(),
            200
        );
        for (method, uri, action, resource) in [
            (Method::GET, "/", "s3:ListAllMyBuckets", "*"),
            (
                Method::GET,
                "/bucket?list-type=2",
                "s3:ListBucket",
                "arn:aws:s3:::bucket",
            ),
            (
                Method::GET,
                "/bucket/a%20b",
                "s3:GetObject",
                "arn:aws:s3:::bucket/a b",
            ),
            (
                Method::HEAD,
                "/bucket/a%20b",
                "s3:GetObject",
                "arn:aws:s3:::bucket/a b",
            ),
            (
                Method::DELETE,
                "/bucket/a%20b",
                "s3:DeleteObject",
                "arn:aws:s3:::bucket/a b",
            ),
        ] {
            assert_eq!(
                handler
                    .handle(req(method, uri, "", VERIFIED_WRITE_HEADERS))
                    .await
                    .status(),
                403
            );
            let call = policy.requests.lock().unwrap().last().cloned().unwrap();
            assert_eq!(
                (call.action.as_str(), call.resource.as_str()),
                (action, resource)
            );
        }
        assert_eq!(
            body_string(
                handler
                    .handle(req(Method::GET, "/bucket/a%20b", "", &[]))
                    .await
            )
            .await
            .1,
            "secret"
        );
    }

    #[tokio::test]
    async fn strict_multipart_and_version_listing_use_native_iam_actions() {
        let (h, _registry, policy) = write_policy_handler();
        h.handle(req(Method::PUT, "/bucket", "", &[])).await;
        let initiated = h
            .handle(req(Method::POST, "/bucket/a%20b?uploads", "", &[]))
            .await;
        let id = xml_value(&body_string(initiated).await.1, "UploadId");
        let part_path = format!("/bucket/a%20b?uploadId={id}&partNumber=1");
        assert_eq!(
            h.handle(req(Method::PUT, &part_path, "part", &[]))
                .await
                .status(),
            200
        );
        let list_parts = format!("/bucket/a%20b?uploadId={id}");
        let cases = [
            (
                Method::GET,
                "/bucket?versions".to_string(),
                "s3:ListBucketVersions",
                "arn:aws:s3:::bucket",
            ),
            (
                Method::GET,
                "/bucket?uploads".to_string(),
                "s3:ListBucketMultipartUploads",
                "arn:aws:s3:::bucket",
            ),
            (
                Method::GET,
                list_parts.clone(),
                "s3:ListMultipartUploadParts",
                "arn:aws:s3:::bucket/a b",
            ),
            (
                Method::DELETE,
                list_parts.clone(),
                "s3:AbortMultipartUpload",
                "arn:aws:s3:::bucket/a b",
            ),
        ];
        let versioning =
            "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
        for (method, body, action) in [
            (Method::PUT, versioning, "s3:PutBucketVersioning"),
            (Method::GET, "", "s3:GetBucketVersioning"),
        ] {
            assert_eq!(
                h.handle(req(
                    method,
                    "/bucket?versioning",
                    body,
                    VERIFIED_WRITE_HEADERS
                ))
                .await
                .status(),
                403
            );
            let call = policy.requests.lock().unwrap().last().cloned().unwrap();
            assert_eq!(
                (call.action.as_str(), call.resource.as_str()),
                (action, "arn:aws:s3:::bucket")
            );
        }
        assert!(!body_string(
            h.handle(req(Method::GET, "/bucket?versioning", "", &[]))
                .await
        )
        .await
        .1
        .contains("Enabled"));
        for (method, path, action, resource) in &cases {
            assert_eq!(
                h.handle(req(method.clone(), path, "", VERIFIED_WRITE_HEADERS))
                    .await
                    .status(),
                403
            );
            let call = policy.requests.lock().unwrap().last().cloned().unwrap();
            assert_eq!(
                (call.action.as_str(), call.resource.as_str()),
                (*action, *resource)
            );
        }
        assert_eq!(
            h.handle(req(Method::GET, &list_parts, "", &[]))
                .await
                .status(),
            200
        );
        policy
            .allow
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            h.handle(req(
                Method::PUT,
                "/bucket?versioning",
                versioning,
                VERIFIED_WRITE_HEADERS
            ))
            .await
            .status(),
            200
        );
        assert!(body_string(
            h.handle(req(
                Method::GET,
                "/bucket?versioning",
                "",
                VERIFIED_WRITE_HEADERS
            ))
            .await
        )
        .await
        .1
        .contains("Enabled"));
        for (method, path, _, _) in cases {
            let expected = if method == Method::DELETE { 204 } else { 200 };
            assert_eq!(
                h.handle(req(method, &path, "", VERIFIED_WRITE_HEADERS))
                    .await
                    .status(),
                expected
            );
        }
        assert_eq!(
            h.handle(req(Method::GET, &list_parts, "", &[]))
                .await
                .status(),
            404
        );
    }

    #[tokio::test]
    async fn legacy_kms_body_requires_migration_for_verified_or_delegated_reads() {
        let (h, _registry, policy) = write_policy_handler();
        h.handle(req(Method::PUT, "/bucket", "", &[])).await;
        h.handle(req(Method::PUT, "/bucket/source", "legacy secret", &[]))
            .await;
        {
            let bucket = h.store.get("000000000000", "bucket").unwrap();
            let mut guard = bucket.write().await;
            let object = guard.objects.get_mut("source").unwrap();
            object.body = crate::store::StoredBody::Inline(Bytes::from_static(b"legacy secret"));
            object.encryption.algorithm = crate::store::SseAlgorithm::AwsKms;
        }
        policy
            .allow
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let ordinary = h.handle(req(Method::GET, "/bucket/source", "", &[])).await;
        assert_eq!(
            ordinary.headers()["x-locallycloud-storage-format"],
            "legacy-plaintext"
        );
        assert_eq!(body_string(ordinary).await.1, "legacy secret");
        for headers in [
            VERIFIED_WRITE_HEADERS,
            &[
                ("x-locallycloud-verified-internal-scope", "1"),
                (
                    "x-locallycloud-caller-principal",
                    "arn:aws:iam::000000000000:role/path/worker/session",
                ),
            ][..],
        ] {
            let denied = h
                .handle(req(Method::GET, "/bucket/source", "", headers))
                .await;
            let (status, body) = body_string(denied).await;
            assert_eq!(status, 403);
            assert!(body.contains("migrate-s3-encryption"));
            assert!(!body.contains("legacy secret"));
            let mut copy_headers = headers.to_vec();
            copy_headers.push(("x-amz-copy-source", "/bucket/source"));
            assert_eq!(
                h.handle(req(Method::PUT, "/bucket/copy", "", &copy_headers))
                    .await
                    .status(),
                403
            );
        }
        let initiated = h
            .handle(req(Method::POST, "/bucket/final?uploads", "", &[]))
            .await;
        let upload = xml_value(&body_string(initiated).await.1, "UploadId");
        let part = format!("/bucket/final?uploadId={upload}&partNumber=1");
        let mut copied = VERIFIED_WRITE_HEADERS.to_vec();
        copied.push(("x-amz-copy-source", "/bucket/source"));
        assert_eq!(
            h.handle(req(Method::PUT, &part, "", &copied))
                .await
                .status(),
            403
        );
        let uploaded = h.handle(req(Method::PUT, &part, "legacy part", &[])).await;
        let etag = uploaded.headers()["etag"].to_str().unwrap().to_string();
        {
            let bucket = h.store.get("000000000000", "bucket").unwrap();
            let mut guard = bucket.write().await;
            let staged = guard.uploads.get_mut(&upload).unwrap();
            staged.encryption.algorithm = crate::store::SseAlgorithm::AwsKms;
            staged.key_envelope = None;
            staged.parts.get_mut(&1).unwrap().body =
                crate::store::StoredBody::Inline(Bytes::from_static(b"legacy part"));
        }
        let completed = format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>");
        assert_eq!(
            h.handle(req(
                Method::POST,
                &format!("/bucket/final?uploadId={upload}"),
                &completed,
                VERIFIED_WRITE_HEADERS
            ))
            .await
            .status(),
            403
        );
        assert_eq!(
            h.handle(req(
                Method::GET,
                &format!("/bucket/final?uploadId={upload}"),
                "",
                &[]
            ))
            .await
            .status(),
            200
        );
        assert_eq!(
            h.handle(req(Method::GET, "/bucket/final", "", &[]))
                .await
                .status(),
            404
        );
        assert_eq!(
            h.handle(req(
                Method::HEAD,
                "/bucket/source",
                "",
                VERIFIED_WRITE_HEADERS
            ))
            .await
            .status(),
            200
        );
        assert_eq!(
            h.handle(req(Method::GET, "/bucket/copy", "", &[]))
                .await
                .status(),
            404
        );
    }

    #[tokio::test]
    async fn strict_unmapped_subresource_fails_before_mutation() {
        let (handler, _registry, policy) = write_policy_handler();
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/bucket", "", &[]))
                .await
                .status(),
            200
        );
        let notification =
            "<NotificationConfiguration><EventBridgeConfiguration/></NotificationConfiguration>";
        assert_eq!(
            handler
                .handle(req(
                    Method::PUT,
                    "/bucket?notification",
                    notification,
                    VERIFIED_WRITE_HEADERS
                ))
                .await
                .status(),
            403
        );
        assert!(!body_string(
            handler
                .handle(req(Method::GET, "/bucket?notification", "", &[]))
                .await
        )
        .await
        .1
        .contains("EventBridgeConfiguration"));
        policy
            .allow
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            handler
                .handle(req(
                    Method::PUT,
                    "/bucket?notification",
                    notification,
                    VERIFIED_WRITE_HEADERS
                ))
                .await
                .status(),
            200
        );
        assert!(body_string(
            handler
                .handle(req(
                    Method::GET,
                    "/bucket?notification",
                    "",
                    VERIFIED_WRITE_HEADERS
                ))
                .await
        )
        .await
        .1
        .contains("EventBridgeConfiguration"));
        assert_eq!(
            handler
                .handle(req(
                    Method::PUT,
                    "/bucket?policy",
                    "{}",
                    VERIFIED_WRITE_HEADERS
                ))
                .await
                .status(),
            501
        );
        assert_eq!(
            handler
                .handle(req(Method::GET, "/bucket?policy", "", &[]))
                .await
                .status(),
            404
        );
    }

    async fn body_string(resp: Response) -> (u16, String) {
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn xml_value(body: &str, tag: &str) -> String {
        let start = format!("<{tag}>");
        let end = format!("</{tag}>");
        body.split_once(&start)
            .and_then(|(_, tail)| tail.split_once(&end))
            .map(|(value, _)| value.to_string())
            .unwrap()
    }

    fn assert_kms_headers(response: &Response) {
        assert_eq!(
            response.headers()["x-amz-server-side-encryption"],
            "aws:kms"
        );
        assert_eq!(
            response.headers()["x-amz-server-side-encryption-aws-kms-key-id"],
            "arn:aws:kms:us-east-1:000000000000:key/key-123"
        );
        assert_eq!(
            response.headers()["x-amz-server-side-encryption-bucket-key-enabled"],
            "false"
        );
    }

    #[tokio::test]
    async fn bucket_encryption_persists_canonical_kms_and_rejects_without_mutation() {
        let (h, _registry, kms) = kms_handler();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;

        let default = body_string(
            h.handle(req(Method::GET, "/buck?encryption", "", &[]))
                .await,
        )
        .await
        .1;
        assert!(default.contains("<SSEAlgorithm>AES256</SSEAlgorithm>"));

        let kms_configuration = concat!(
            "<ServerSideEncryptionConfiguration><Rule>",
            "<ApplyServerSideEncryptionByDefault>",
            "<SSEAlgorithm>aws:kms</SSEAlgorithm>",
            "<KMSMasterKeyID>alias/data</KMSMasterKeyID>",
            "</ApplyServerSideEncryptionByDefault>",
            "<BucketKeyEnabled>false</BucketKeyEnabled>",
            "</Rule></ServerSideEncryptionConfiguration>"
        );
        assert_eq!(
            h.handle(req(Method::PUT, "/buck?encryption", kms_configuration, &[],))
                .await
                .status(),
            200
        );
        let configured = body_string(
            h.handle(req(Method::GET, "/buck?encryption", "", &[]))
                .await,
        )
        .await
        .1;
        assert!(configured.contains("<SSEAlgorithm>aws:kms</SSEAlgorithm>"));
        assert!(configured.contains(
            "<KMSMasterKeyID>arn:aws:kms:us-east-1:000000000000:key/key-123</KMSMasterKeyID>"
        ));
        assert!(configured.contains("<BucketKeyEnabled>false</BucketKeyEnabled>"));
        {
            let requests = kms.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].key_id, "alias/data");
            assert_eq!(requests[0].call.source_service, "s3");
            assert_eq!(requests[0].call.account_id, "000000000000");
        }

        for (invalid_key, expected_status) in [
            ("alias/missing", 400),
            ("missing-key", 400),
            ("disabled", 400),
            ("denied", 403),
        ] {
            let invalid_configuration = kms_configuration.replace("alias/data", invalid_key);
            assert_eq!(
                h.handle(req(
                    Method::PUT,
                    "/buck?encryption",
                    &invalid_configuration,
                    &[],
                ))
                .await
                .status(),
                expected_status
            );
            let unchanged = body_string(
                h.handle(req(Method::GET, "/buck?encryption", "", &[]))
                    .await,
            )
            .await
            .1;
            assert_eq!(unchanged, configured);
        }

        assert_eq!(
            h.handle(req(Method::DELETE, "/buck?encryption", "", &[]))
                .await
                .status(),
            204
        );
        let reset = body_string(
            h.handle(req(Method::GET, "/buck?encryption", "", &[]))
                .await,
        )
        .await
        .1;
        assert!(reset.contains("<SSEAlgorithm>AES256</SSEAlgorithm>"));
        assert!(!reset.contains("KMSMasterKeyID"));
    }

    #[tokio::test]
    async fn put_and_copy_encryption_headers_override_bucket_defaults() {
        let (h, _registry, _kms) = kms_handler();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let kms_configuration = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>key-123</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>false</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>";
        h.handle(req(Method::PUT, "/buck?encryption", kms_configuration, &[]))
            .await;

        let inherited = h
            .handle(req(Method::PUT, "/buck/inherited", "kms", &[]))
            .await;
        assert_kms_headers(&inherited);
        let head = h
            .handle(req(Method::HEAD, "/buck/inherited", "", &[]))
            .await;
        assert_kms_headers(&head);

        let overridden = h
            .handle(req(
                Method::PUT,
                "/buck/overridden",
                "aes",
                &[("x-amz-server-side-encryption", "AES256")],
            ))
            .await;
        assert_eq!(
            overridden.headers()["x-amz-server-side-encryption"],
            "AES256"
        );
        assert!(!overridden
            .headers()
            .contains_key("x-amz-server-side-encryption-aws-kms-key-id"));
        assert_eq!(
            h.handle(req(
                Method::PUT,
                "/buck/overridden",
                "mutated",
                &[("x-amz-server-side-encryption", "aws:kms")],
            ))
            .await
            .status(),
            200
        );
        let unchanged = h
            .handle(req(Method::GET, "/buck/overridden", "", &[]))
            .await;
        assert_eq!(
            unchanged.headers()["x-amz-server-side-encryption"],
            "aws:kms"
        );
        assert_eq!(body_string(unchanged).await.1, "mutated");

        for headers in [
            vec![
                ("x-amz-server-side-encryption", "AES256"),
                ("x-amz-server-side-encryption-aws-kms-key-id", "key-123"),
            ],
            vec![("x-amz-server-side-encryption-aws-kms-key-id", "key-123")],
            vec![
                ("x-amz-server-side-encryption", "AES256"),
                ("x-amz-server-side-encryption-bucket-key-enabled", "true"),
            ],
        ] {
            assert_eq!(
                h.handle(req(Method::PUT, "/buck/illegal", "data", &headers))
                    .await
                    .status(),
                400
            );
        }
        assert_eq!(
            h.handle(req(Method::GET, "/buck/illegal", "", &[]))
                .await
                .status(),
            404
        );
        let mut invalid_header = req(Method::PUT, "/buck/invalid-header", "data", &[]);
        invalid_header.headers.insert(
            "x-amz-server-side-encryption",
            HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        assert_eq!(h.handle(invalid_header).await.status(), 400);
        assert_eq!(
            h.handle(req(Method::GET, "/buck/invalid-header", "", &[]))
                .await
                .status(),
            404
        );

        let aes_configuration = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>false</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>";
        h.handle(req(Method::PUT, "/buck?encryption", aes_configuration, &[]))
            .await;
        let copied = h
            .handle(req(
                Method::PUT,
                "/buck/copied",
                "",
                &[
                    ("x-amz-copy-source", "/buck/inherited"),
                    ("x-amz-server-side-encryption", "aws:kms"),
                    ("x-amz-server-side-encryption-aws-kms-key-id", "alias/data"),
                    ("x-amz-server-side-encryption-bucket-key-enabled", "false"),
                ],
            ))
            .await;
        assert_kms_headers(&copied);
        assert_eq!(
            h.handle(req(
                Method::PUT,
                "/buck/copied",
                "",
                &[
                    ("x-amz-copy-source", "/buck/overridden"),
                    ("x-amz-server-side-encryption", "aws:kms"),
                    (
                        "x-amz-server-side-encryption-aws-kms-key-id",
                        "alias/missing",
                    ),
                ],
            ))
            .await
            .status(),
            400
        );
        let copied_get = h.handle(req(Method::GET, "/buck/copied", "", &[])).await;
        assert_kms_headers(&copied_get);
        assert_eq!(body_string(copied_get).await.1, "kms");

        let reciphered = h
            .handle(req(
                Method::PUT,
                "/buck/copied",
                "",
                &[
                    ("x-amz-copy-source", "/buck/copied"),
                    ("x-amz-server-side-encryption", "AES256"),
                ],
            ))
            .await;
        assert_eq!(reciphered.status(), 200);
        assert_eq!(
            reciphered.headers()["x-amz-server-side-encryption"],
            "AES256"
        );
        let reciphered_get = h.handle(req(Method::GET, "/buck/copied", "", &[])).await;
        assert_eq!(
            reciphered_get.headers()["x-amz-server-side-encryption"],
            "AES256"
        );
        assert_eq!(body_string(reciphered_get).await.1, "kms");
    }

    #[tokio::test]
    async fn unusable_kms_key_returns_native_s3_error_without_plaintext() {
        let (h, _registry, kms) = kms_handler();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        assert_eq!(
            h.handle(req(
                Method::PUT,
                "/buck/private",
                "protected invoice",
                &[
                    ("x-amz-server-side-encryption", "aws:kms"),
                    ("x-amz-server-side-encryption-aws-kms-key-id", "alias/data"),
                ]
            ))
            .await
            .status(),
            200
        );
        for (error, code) in [
            (KmsInternalError::Disabled, "KMS.DisabledException"),
            (
                KmsInternalError::InvalidState,
                "KMS.KMSInvalidStateException",
            ),
        ] {
            *kms.decrypt_failure.lock().unwrap() = Some(error);
            let (status, body) =
                body_string(h.handle(req(Method::GET, "/buck/private", "", &[])).await).await;
            assert_eq!(status, 400);
            assert!(body.contains(&format!("<Code>{code}</Code>")));
            assert!(!body.contains("protected invoice"));
        }
        *kms.decrypt_failure.lock().unwrap() = None;
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/buck/private", "", &[])).await)
                .await
                .1,
            "protected invoice"
        );
    }

    #[tokio::test]
    async fn multipart_encryption_is_fixed_at_initiation_and_propagated() {
        let (h, _registry, _kms) = kms_handler();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        h.handle(req(Method::PUT, "/buck/source", "source", &[]))
            .await;
        let kms_configuration = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>alias/data</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>false</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>";
        h.handle(req(Method::PUT, "/buck?encryption", kms_configuration, &[]))
            .await;

        let initiated = h
            .handle(req(Method::POST, "/buck/final?uploads", "", &[]))
            .await;
        assert_kms_headers(&initiated);
        let upload_id = xml_value(&body_string(initiated).await.1, "UploadId");
        let aes_configuration = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
        h.handle(req(Method::PUT, "/buck?encryption", aes_configuration, &[]))
            .await;

        let uploaded = h
            .handle(req(
                Method::PUT,
                &format!("/buck/final?uploadId={upload_id}&partNumber=1"),
                "part",
                &[],
            ))
            .await;
        assert_kms_headers(&uploaded);
        let copied = h
            .handle(req(
                Method::PUT,
                &format!("/buck/final?uploadId={upload_id}&partNumber=1"),
                "",
                &[("x-amz-copy-source", "/buck/source")],
            ))
            .await;
        assert_kms_headers(&copied);
        let copied_etag = xml_value(&body_string(copied).await.1, "ETag");
        let complete_body = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{copied_etag}</ETag></Part></CompleteMultipartUpload>"
        );
        let completed = h
            .handle(req(
                Method::POST,
                &format!("/buck/final?uploadId={upload_id}"),
                &complete_body,
                &[],
            ))
            .await;
        assert_kms_headers(&completed);
        let get = h.handle(req(Method::GET, "/buck/final", "", &[])).await;
        assert_kms_headers(&get);
        assert_eq!(body_string(get).await.1, "source");
    }

    #[tokio::test]
    async fn event_bridge_notification_round_trips_and_clears() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let configured = concat!(
            "<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
            "<EventBridgeConfiguration></EventBridgeConfiguration>",
            "</NotificationConfiguration>"
        );
        assert_eq!(
            h.handle(req(Method::PUT, "/buck?notification", configured, &[]))
                .await
                .status(),
            200
        );
        let (_, body) = body_string(
            h.handle(req(Method::GET, "/buck?notification", "", &[]))
                .await,
        )
        .await;
        assert_eq!(
            body,
            concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                "<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
                "<EventBridgeConfiguration/>",
                "</NotificationConfiguration>"
            )
        );

        let empty =
            "<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>";
        h.handle(req(Method::PUT, "/buck?notification", empty, &[]))
            .await;
        let (_, body) = body_string(
            h.handle(req(Method::GET, "/buck?notification", "", &[]))
                .await,
        )
        .await;
        assert!(!body.contains("EventBridgeConfiguration"));

        let malformed = h
            .handle(req(
                Method::PUT,
                "/buck?notification",
                "<WrongRoot><EventBridgeConfiguration/></WrongRoot>",
                &[],
            ))
            .await;
        assert_eq!(malformed.status(), 400);
    }

    #[tokio::test]
    async fn recorder_receives_filtered_records_for_all_four_targets() {
        let (handler, _registry, deliveries) = all_target_handler();
        handler.handle(req(Method::PUT, "/buck", "", &[])).await;
        let configuration = concat!(
            "<NotificationConfiguration>",
            "<QueueConfiguration><Id>queue-id</Id><Queue>arn:aws:sqs:us-east-1:000000000000:queue</Queue><Event>s3:ObjectCreated:*</Event><Filter><S3Key><FilterRule><Name>prefix</Name><Value>in/</Value></FilterRule><FilterRule><Name>suffix</Name><Value>.txt</Value></FilterRule></S3Key></Filter></QueueConfiguration>",
            "<TopicConfiguration><Id>topic-id</Id><Topic>arn:aws:sns:us-east-1:000000000000:topic</Topic><Event>s3:ObjectCreated:Put</Event></TopicConfiguration>",
            "<LambdaFunctionConfiguration><Id>lambda-id</Id><LambdaFunctionArn>arn:aws:lambda:us-east-1:000000000000:function:fn</LambdaFunctionArn><Event>s3:ObjectCreated:Put</Event></LambdaFunctionConfiguration>",
            "<EventBridgeConfiguration/>",
            "</NotificationConfiguration>"
        );
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/buck?notification", configuration, &[],))
                .await
                .status(),
            200
        );
        let (_, stored) = body_string(
            handler
                .handle(req(Method::GET, "/buck?notification", "", &[]))
                .await,
        )
        .await;
        assert!(stored.contains("<Id>queue-id</Id>"));
        assert!(stored.contains("<LambdaFunctionConfiguration>"));
        assert!(stored.contains("<Name>prefix</Name><Value>in/</Value>"));

        assert_eq!(
            handler
                .handle(req(Method::PUT, "/buck/in/a%20b.txt", "data", &[]))
                .await
                .status(),
            200
        );
        wait_for_count(&deliveries, 4).await;
        let deliveries = deliveries.lock().unwrap();
        assert_eq!(deliveries.len(), 4);
        assert!(deliveries
            .iter()
            .all(|delivery| delivery.region == "us-east-1" && delivery.account == "000000000000"));

        let lambda = deliveries
            .iter()
            .find(|delivery| delivery.service == "lambda")
            .unwrap();
        assert_eq!(lambda.uri, "/2015-03-31/functions/fn/invocations");
        let lambda_body: serde_json::Value = serde_json::from_str(&lambda.body).unwrap();
        assert_eq!(lambda_body["Records"][0]["eventVersion"], "2.1");
        assert_eq!(
            lambda_body["Records"][0]["s3"]["object"]["key"],
            "in%2Fa+b.txt"
        );
        assert_eq!(
            lambda_body["Records"][0]["s3"]["configurationId"],
            "lambda-id"
        );

        let sqs = deliveries
            .iter()
            .find(|delivery| delivery.service == "sqs")
            .unwrap();
        assert_eq!(sqs.target, "AmazonSQS.SendMessage");
        let sqs_body: serde_json::Value = serde_json::from_str(&sqs.body).unwrap();
        assert!(sqs_body["MessageBody"]
            .as_str()
            .unwrap()
            .contains("\"Records\""));

        let sns = deliveries
            .iter()
            .find(|delivery| delivery.service == "sns")
            .unwrap();
        assert!(sns.body.starts_with("Action=Publish&TopicArn="));
        assert!(sns.body.contains("Message=%7B%22Records%22"));

        let events = deliveries
            .iter()
            .find(|delivery| delivery.service == "events")
            .unwrap();
        assert_eq!(events.target, "AWSEvents.PutEvents");
        assert!(events.body.contains("\"Source\":\"aws.s3\""));
    }

    #[tokio::test]
    async fn oversized_notification_batch_rejects_before_delete_mutates() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
        let handler = test_state_handler(Weak::new(), state.clone()).unwrap();
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/batch-cap", "", &[]))
                .await
                .status(),
            200
        );
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/batch-cap/retained", "value", &[]))
                .await
                .status(),
            200
        );

        let mut config = String::from("<NotificationConfiguration>");
        for index in 0..101 {
            config.push_str(&format!(
                "<QueueConfiguration><Id>q{index}</Id><Queue>arn:aws:sqs:us-east-1:000000000000:q{index}</Queue><Event>s3:ObjectRemoved:*</Event></QueueConfiguration>"
            ));
        }
        config.push_str("</NotificationConfiguration>");
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/batch-cap?notification", &config, &[]))
                .await
                .status(),
            200
        );

        let mut body = String::from("<Delete>");
        body.push_str("<Object><Key>retained</Key></Object>");
        for index in 1..1000 {
            body.push_str(&format!("<Object><Key>missing-{index}</Key></Object>"));
        }
        body.push_str("</Delete>");
        let response = handler
            .handle(req(Method::POST, "/batch-cap?delete", &body, &[]))
            .await;
        assert_eq!(response.status(), 503);
        assert_eq!(
            handler
                .handle(req(Method::GET, "/batch-cap/retained", "", &[]))
                .await
                .status(),
            200
        );
        let pending: i64 = state
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM s3_notification_outbox", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(pending, 0);

        assert_eq!(
            handler
                .handle(req(
                    Method::PUT,
                    "/batch-cap?notification",
                    "<NotificationConfiguration/>",
                    &[]
                ))
                .await
                .status(),
            200
        );
        assert_eq!(
            handler
                .handle(req(
                    Method::POST,
                    "/batch-cap?delete",
                    "<Delete><Object><Key>retained</Key></Object></Delete>",
                    &[]
                ))
                .await
                .status(),
            200
        );
        assert_eq!(
            handler
                .handle(req(Method::GET, "/batch-cap/retained", "", &[]))
                .await
                .status(),
            404
        );
    }

    #[tokio::test]
    async fn committed_notification_replays_after_restart() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
        let registry = ServiceRegistry::with_known_services();
        let first = test_state_handler(Arc::downgrade(&registry), state.clone()).unwrap();
        assert_eq!(
            first
                .handle(req(Method::PUT, "/durable-events", "", &[]))
                .await
                .status(),
            200
        );
        let config =
            "<NotificationConfiguration><EventBridgeConfiguration/></NotificationConfiguration>";
        assert_eq!(
            first
                .handle(req(
                    Method::PUT,
                    "/durable-events?notification",
                    config,
                    &[]
                ))
                .await
                .status(),
            200
        );
        assert_eq!(
            first
                .handle(req(Method::PUT, "/durable-events/key", "payload", &[]))
                .await
                .status(),
            200
        );
        let pending: i64 = state
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM s3_notification_outbox", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(pending, 1);
        drop(first);
        drop(registry);

        let (_unused, failing_registry, failed_requests) = event_handler(500);
        let failing = test_state_handler(Arc::downgrade(&failing_registry), state.clone()).unwrap();
        wait_for_count(&failed_requests, 3).await;
        let pending: i64 = state
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM s3_notification_outbox", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(pending, 1);
        drop(failing);
        drop(failing_registry);

        let (_unused, registry, requests) = event_handler(200);
        let reopened = test_state_handler(Arc::downgrade(&registry), state.clone()).unwrap();
        wait_for_count(&requests, 1).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let pending: i64 = state
                    .connection()
                    .unwrap()
                    .query_row("SELECT count(*) FROM s3_notification_outbox", [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                if pending == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
        drop(reopened);
    }

    #[tokio::test]
    async fn configured_mutations_publish_canonical_put_events() {
        let (h, _registry, requests) = event_handler(200);
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        h.handle(req(Method::PUT, "/buck/source", "source", &[]))
            .await;
        assert!(requests.lock().unwrap().is_empty());

        let config =
            "<NotificationConfiguration><EventBridgeConfiguration/></NotificationConfiguration>";
        h.handle(req(Method::PUT, "/buck?notification", config, &[]))
            .await;
        h.handle(req(Method::PUT, "/buck/folder/a%20b.txt", "data", &[]))
            .await;
        h.handle(req(
            Method::PUT,
            "/buck/copied",
            "",
            &[("x-amz-copy-source", "/buck/source")],
        ))
        .await;
        h.handle(req(Method::DELETE, "/buck/copied", "", &[])).await;
        h.handle(req(Method::PUT, "/buck/k1", "1", &[])).await;
        h.handle(req(Method::PUT, "/buck/k2", "2", &[])).await;
        h.handle(req(
            Method::POST,
            "/buck?delete",
            "<Delete><Object><Key>k1</Key></Object><Object><Key>k2</Key></Object></Delete>",
            &[],
        ))
        .await;

        wait_for_count(&requests, 6).await;
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 6);
        assert!(requests
            .iter()
            .all(|(target, _)| target == "AWSEvents.PutEvents"));
        let bodies = requests
            .iter()
            .map(|(_, body)| body.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(bodies.contains("\"Source\":\"aws.s3\""));
        assert!(bodies.contains("\"DetailType\":\"Object Created\""));
        assert!(bodies.contains("\"DetailType\":\"Object Deleted\""));
        assert!(bodies.contains("\\\"key\\\":\\\"folder/a b.txt\\\""));
        assert!(bodies.contains("\\\"reason\\\":\\\"PutObject\\\""));
        assert!(bodies.contains("\\\"reason\\\":\\\"CopyObject\\\""));
        assert_eq!(
            bodies
                .matches("\\\"reason\\\":\\\"DeleteObject\\\"")
                .count(),
            3
        );
        assert!(bodies.contains("\"Resources\":[\"arn:aws:s3:::buck\"]"));
    }

    struct BlockingEvents {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl NativeHandler for BlockingEvents {
        async fn handle(&self, _request: ServiceRequest) -> Response {
            self.entered.notify_one();
            self.release.notified().await;
            Response::builder()
                .status(200)
                .body(Body::from("{}"))
                .unwrap()
        }
    }

    #[tokio::test]
    async fn full_notification_queue_rejects_put_before_object_mutation() {
        let (handler, registry, _requests) = event_handler(200);
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/buck", "", &[]))
                .await
                .status(),
            200
        );
        let config =
            "<NotificationConfiguration><EventBridgeConfiguration/></NotificationConfiguration>";
        assert_eq!(
            handler
                .handle(req(Method::PUT, "/buck?notification", config, &[]))
                .await
                .status(),
            200
        );

        // Keep the receiver alive but undrained to model a saturated worker.
        let _receiver = handler.notification_rx.lock().unwrap().take().unwrap();
        let dispatcher = registry.internal_dispatcher().unwrap();
        for _ in 0..NOTIFICATION_QUEUE_CAPACITY {
            handler
                .notification_tx
                .try_send(NotificationJob {
                    dispatcher: dispatcher.clone(),
                    request_id: "queued".to_string(),
                    account_id: "000000000000".to_string(),
                    region: "us-east-1".to_string(),
                    deliveries: Vec::new(),
                })
                .unwrap();
        }

        let response = handler
            .handle(req(Method::PUT, "/buck/key", "payload", &[]))
            .await;
        assert_eq!(response.status(), 503);
        assert_eq!(response.headers()["content-type"], "application/xml");
        let (_, body) = body_string(response).await;
        assert!(body.contains("<Code>SlowDown</Code>"), "{body}");
        assert_eq!(
            handler
                .handle(req(Method::GET, "/buck/key", "", &[]))
                .await
                .status(),
            404
        );
    }

    #[tokio::test]
    async fn object_write_finishes_while_notification_target_is_blocked() {
        let registry = ServiceRegistry::with_known_services();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        registry.register_native(
            ServiceName::new("events"),
            ServiceMetadata::new(AwsProtocol::Json11, Some("AWSEvents")),
            Arc::new(BlockingEvents {
                entered: entered.clone(),
                release: release.clone(),
            }),
        );
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".to_string(),
                upstream_timeout: Duration::from_millis(10),
            },
            LegacyHealth::new(false),
            "us-east-1".to_string(),
            "000000000000".to_string(),
        )));
        let handler = S3Handler::with_registry(Arc::downgrade(&registry));
        handler.handle(req(Method::PUT, "/buck", "", &[])).await;
        handler
            .handle(req(
                Method::PUT,
                "/buck?notification",
                "<NotificationConfiguration><EventBridgeConfiguration/></NotificationConfiguration>",
                &[],
            ))
            .await;
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            handler.handle(req(Method::PUT, "/buck/key", "value", &[])),
        )
        .await
        .expect("object write waited on the notification target");
        assert_eq!(response.status(), 200);
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("notification was not dispatched");
        let object = handler.handle(req(Method::GET, "/buck/key", "", &[])).await;
        assert_eq!(body_string(object).await.1, "value");
        release.notify_one();
    }

    #[tokio::test]
    async fn event_bridge_failure_does_not_fail_mutation() {
        let (h, _registry, requests) = event_handler(500);
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let config =
            "<NotificationConfiguration><EventBridgeConfiguration/></NotificationConfiguration>";
        h.handle(req(Method::PUT, "/buck?notification", config, &[]))
            .await;
        let response = h.handle(req(Method::PUT, "/buck/key", "body", &[])).await;
        assert_eq!(response.status(), 200);
        wait_for_count(&requests, 3).await;
        assert_eq!(requests.lock().unwrap().len(), 3);
        let get = h.handle(req(Method::GET, "/buck/key", "", &[])).await;
        assert_eq!(body_string(get).await.1, "body");
    }

    #[tokio::test]
    async fn bucket_and_object_lifecycle() {
        let h = S3Handler::new();
        assert_eq!(
            h.handle(req(Method::PUT, "/my-bucket", "", &[]))
                .await
                .status(),
            200
        );

        let put = h
            .handle(req(
                Method::PUT,
                "/my-bucket/hello.txt",
                "hello",
                &[("content-type", "text/plain")],
            ))
            .await;
        assert_eq!(put.status(), 200);
        assert_eq!(
            put.headers().get("ETag").unwrap(),
            "\"5d41402abc4b2a76b9719d911017c592\""
        );

        let get = h
            .handle(req(Method::GET, "/my-bucket/hello.txt", "", &[]))
            .await;
        let (status, body) = body_string(get).await;
        assert_eq!(status, 200);
        assert_eq!(body, "hello");
    }

    #[tokio::test]
    async fn get_missing_key_is_404() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let resp = h.handle(req(Method::GET, "/buck/missing", "", &[])).await;
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn get_missing_bucket_is_404() {
        let h = S3Handler::new();
        let resp = h.handle(req(Method::GET, "/nope/key", "", &[])).await;
        let (status, body) = body_string(resp).await;
        assert_eq!(status, 404);
        assert!(body.contains("<Code>NoSuchBucket</Code>"));
    }

    #[tokio::test]
    async fn range_request_returns_206() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        h.handle(req(Method::PUT, "/buck/k", "0123456789", &[]))
            .await;
        let resp = h
            .handle(req(Method::GET, "/buck/k", "", &[("range", "bytes=2-5")]))
            .await;
        let status = resp.status().as_u16();
        assert_eq!(status, 206);
        let (_, body) = body_string(resp).await;
        assert_eq!(body, "2345");
    }

    #[tokio::test]
    async fn list_objects_v2_with_prefix_and_delimiter() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        for k in ["a/1", "a/2", "b/1", "top"] {
            h.handle(req(Method::PUT, &format!("/buck/{k}"), "x", &[]))
                .await;
        }
        let resp = h
            .handle(req(Method::GET, "/buck?list-type=2&delimiter=/", "", &[]))
            .await;
        let (status, body) = body_string(resp).await;
        assert_eq!(status, 200);
        assert!(body.contains("<CommonPrefixes><Prefix>a/</Prefix></CommonPrefixes>"));
        assert!(body.contains("<CommonPrefixes><Prefix>b/</Prefix></CommonPrefixes>"));
        assert!(body.contains("<Key>top</Key>"));
    }

    #[tokio::test]
    async fn list_objects_v2_url_encoding_encodes_keys_and_prefixes() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        h.handle(req(Method::PUT, "/buck/a%25b/item%2520x", "x", &[]))
            .await;
        let response = h
            .handle(req(
                Method::GET,
                "/buck?list-type=2&encoding-type=url&prefix=a%25b%2F",
                "",
                &[],
            ))
            .await;
        let (status, body) = body_string(response).await;
        assert_eq!(status, 200);
        assert!(body.contains("<EncodingType>url</EncodingType>"));
        assert!(body.contains("<Prefix>a%25b/</Prefix>"));
        assert!(body.contains("<Key>a%25b/item%2520x</Key>"));

        let response = h
            .handle(req(
                Method::GET,
                "/buck?list-type=2&encoding-type=url&start-after=a%25b%2Fitem%2520x",
                "",
                &[],
            ))
            .await;
        let (_, body) = body_string(response).await;
        assert!(body.contains("<StartAfter>a%25b/item%2520x</StartAfter>"));

        let response = h
            .handle(req(
                Method::GET,
                "/buck?list-type=2&encoding-type=url&delimiter=%2F",
                "",
                &[],
            ))
            .await;
        let (_, body) = body_string(response).await;
        assert!(body.contains("<CommonPrefixes><Prefix>a%25b/</Prefix></CommonPrefixes>"));
    }

    #[tokio::test]
    async fn delete_bucket_not_empty_is_409() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        h.handle(req(Method::PUT, "/buck/k", "x", &[])).await;
        let resp = h.handle(req(Method::DELETE, "/buck", "", &[])).await;
        assert_eq!(resp.status(), 409);
    }

    #[tokio::test]
    async fn delete_objects_batch() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        h.handle(req(Method::PUT, "/buck/k1", "x", &[])).await;
        h.handle(req(Method::PUT, "/buck/k2", "y", &[])).await;
        let body = "<Delete><Object><Key>k1</Key></Object><Object><Key>k2</Key></Object></Delete>";
        let resp = h.handle(req(Method::POST, "/buck?delete", body, &[])).await;
        let (status, out) = body_string(resp).await;
        assert_eq!(status, 200);
        assert!(out.contains("<Deleted><Key>k1</Key></Deleted>"));
    }

    #[tokio::test]
    async fn copy_object() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        h.handle(req(Method::PUT, "/buck/src", "data", &[])).await;
        let resp = h
            .handle(req(
                Method::PUT,
                "/buck/dst",
                "",
                &[("x-amz-copy-source", "/buck/src")],
            ))
            .await;
        let (status, body) = body_string(resp).await;
        assert_eq!(status, 200);
        assert!(body.contains("<CopyObjectResult>"));
        let get = h.handle(req(Method::GET, "/buck/dst", "", &[])).await;
        assert_eq!(body_string(get).await.1, "data");
    }

    #[tokio::test]
    async fn checksums_are_validated_persisted_and_returned() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let sha256 = crate::integrity::checksum_base64(
            crate::integrity::ChecksumAlgorithm::Sha256,
            b"hello",
        );
        let put = h
            .handle(req(
                Method::PUT,
                "/buck/key",
                "hello",
                &[("x-amz-checksum-sha256", &sha256)],
            ))
            .await;
        assert_eq!(put.status(), 200);
        assert_eq!(put.headers()["x-amz-checksum-sha256"], sha256);

        let bad = h
            .handle(req(
                Method::PUT,
                "/buck/key",
                "changed",
                &[("x-amz-checksum-sha256", &sha256)],
            ))
            .await;
        assert_eq!(bad.status(), 400);
        let get = h.handle(req(Method::GET, "/buck/key", "", &[])).await;
        assert_eq!(get.headers()["x-amz-checksum-sha256"], sha256);
        assert_eq!(body_string(get).await.1, "hello");

        let sdk = h
            .handle(req(
                Method::PUT,
                "/buck/sdk",
                "hello",
                &[("x-amz-sdk-checksum-algorithm", "CRC32C")],
            ))
            .await;
        let crc32c = crate::integrity::checksum_base64(
            crate::integrity::ChecksumAlgorithm::Crc32c,
            b"hello",
        );
        assert_eq!(sdk.status(), 200);
        assert_eq!(sdk.headers()["x-amz-checksum-crc32c"], crc32c);

        let unknown = h
            .handle(req(
                Method::PUT,
                "/buck/other",
                "x",
                &[("x-amz-sdk-checksum-algorithm", "NOPE")],
            ))
            .await;
        assert_eq!(unknown.status(), 400);
    }

    #[tokio::test]
    async fn aws_chunked_decodes_before_storage_and_rejects_malformed_without_mutation() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let signature = "0".repeat(64);
        let checksum = crate::integrity::checksum_base64(
            crate::integrity::ChecksumAlgorithm::Crc32,
            b"Wikipedia",
        );
        let wire = format!(
            "4;chunk-signature={signature}\r\nWiki\r\n5;chunk-signature={signature}\r\npedia\r\n0;chunk-signature={signature}\r\nx-amz-checksum-crc32:{checksum}\r\n\r\n"
        );
        let put = h
            .handle(req(
                Method::PUT,
                "/buck/key",
                &wire,
                &[
                    ("content-encoding", "aws-chunked"),
                    ("x-amz-decoded-content-length", "9"),
                ],
            ))
            .await;
        assert_eq!(put.status(), 200);
        let get = h.handle(req(Method::GET, "/buck/key", "", &[])).await;
        assert_eq!(get.headers()["content-length"], "9");
        assert_eq!(get.headers()["x-amz-checksum-crc32"], checksum);
        assert_eq!(body_string(get).await.1, "Wikipedia");

        let malformed = "4;chunk-signature=nope\r\ntest\r\n";
        let failed = h
            .handle(req(
                Method::PUT,
                "/buck/key",
                malformed,
                &[
                    ("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
                    ("x-amz-decoded-content-length", "4"),
                ],
            ))
            .await;
        assert_eq!(failed.status(), 400);
        let get = h.handle(req(Method::GET, "/buck/key", "", &[])).await;
        assert_eq!(body_string(get).await.1, "Wikipedia");
    }

    #[tokio::test]
    async fn conditional_reads_honor_precedence_and_writes_are_guarded() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let first = h.handle(req(Method::PUT, "/buck/key", "old", &[])).await;
        let etag = first.headers()["etag"].to_str().unwrap().to_string();

        let mismatch = h
            .handle(req(
                Method::PUT,
                "/buck/key",
                "new",
                &[("if-match", "\"not-the-etag\"")],
            ))
            .await;
        assert_eq!(mismatch.status(), 412);
        let absent = h
            .handle(req(
                Method::PUT,
                "/buck/missing",
                "new",
                &[("if-match", "*")],
            ))
            .await;
        assert_eq!(absent.status(), 412);
        let matched = h
            .handle(req(Method::PUT, "/buck/key", "new", &[("if-match", &etag)]))
            .await;
        assert_eq!(matched.status(), 200);
        let new_etag = matched.headers()["etag"].to_str().unwrap().to_string();

        let precedence = h
            .handle(req(
                Method::GET,
                "/buck/key",
                "",
                &[
                    ("if-match", &new_etag),
                    ("if-unmodified-since", "Sat, 01 Jan 2000 00:00:00 GMT"),
                    ("if-none-match", "\"different\""),
                    ("if-modified-since", "Tue, 01 Jan 2999 00:00:00 GMT"),
                ],
            ))
            .await;
        assert_eq!(precedence.status(), 200);
        let read_mismatch = h
            .handle(req(
                Method::GET,
                "/buck/key",
                "",
                &[("if-match", "\"different\"")],
            ))
            .await;
        assert_eq!(read_mismatch.status(), 412);
        let modified_since = h
            .handle(req(
                Method::GET,
                "/buck/key",
                "",
                &[("if-modified-since", "Tue, 01 Jan 2999 00:00:00 GMT")],
            ))
            .await;
        assert_eq!(modified_since.status(), 304);
        let not_modified = h
            .handle(req(
                Method::GET,
                "/buck/key",
                "",
                &[("if-none-match", &new_etag)],
            ))
            .await;
        assert_eq!(not_modified.status(), 304);
        let stale = h
            .handle(req(
                Method::GET,
                "/buck/key",
                "",
                &[("if-unmodified-since", "Sat, 01 Jan 2000 00:00:00 GMT")],
            ))
            .await;
        assert_eq!(stale.status(), 412);

        let create = h
            .handle(req(
                Method::PUT,
                "/buck/create",
                "once",
                &[("if-none-match", "*")],
            ))
            .await;
        assert_eq!(create.status(), 200);
        let retry = h
            .handle(req(
                Method::PUT,
                "/buck/create",
                "twice",
                &[("if-none-match", "*")],
            ))
            .await;
        assert_eq!(retry.status(), 412);
        let get = h.handle(req(Method::GET, "/buck/create", "", &[])).await;
        assert_eq!(body_string(get).await.1, "once");
    }

    #[tokio::test]
    async fn copy_directives_conditions_and_attributes() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let source = h
            .handle(req(
                Method::PUT,
                "/buck/src",
                "source-data",
                &[
                    ("content-type", "text/source"),
                    ("x-amz-meta-origin", "source"),
                    ("x-amz-tagging", "a=1"),
                ],
            ))
            .await;
        let source_etag = source.headers()["etag"].to_str().unwrap().to_string();
        let failed = h
            .handle(req(
                Method::PUT,
                "/buck/nope",
                "",
                &[
                    ("x-amz-copy-source", "/buck/src"),
                    ("x-amz-copy-source-if-match", "\"wrong\""),
                ],
            ))
            .await;
        assert_eq!(failed.status(), 412);
        assert_eq!(
            h.handle(req(
                Method::PUT,
                "/buck/src",
                "",
                &[("x-amz-copy-source", "/buck/src")],
            ))
            .await
            .status(),
            400
        );
        assert_eq!(
            h.handle(req(
                Method::PUT,
                "/buck/missing-copy",
                "",
                &[("x-amz-copy-source", "/buck/missing")],
            ))
            .await
            .status(),
            404
        );
        let copied = h
            .handle(req(
                Method::PUT,
                "/buck/dst",
                "",
                &[
                    ("x-amz-copy-source", "/buck/src"),
                    ("x-amz-copy-source-if-match", &source_etag),
                    ("x-amz-metadata-directive", "REPLACE"),
                    ("content-type", "text/replaced"),
                    ("x-amz-meta-origin", "replacement"),
                    ("x-amz-tagging-directive", "REPLACE"),
                    ("x-amz-tagging", "b=2"),
                ],
            ))
            .await;
        assert_eq!(copied.status(), 200);
        let get = h.handle(req(Method::GET, "/buck/dst", "", &[])).await;
        assert_eq!(get.headers()["content-type"], "text/replaced");
        assert_eq!(get.headers()["x-amz-meta-origin"], "replacement");
        assert_eq!(body_string(get).await.1, "source-data");

        let excessive = (0..11)
            .map(|index| format!("k{index}=v"))
            .collect::<Vec<_>>()
            .join("&");
        let invalid_tags = h
            .handle(req(
                Method::PUT,
                "/buck/dst",
                "",
                &[
                    ("x-amz-copy-source", "/buck/src"),
                    ("x-amz-tagging-directive", "REPLACE"),
                    ("x-amz-tagging", &excessive),
                ],
            ))
            .await;
        assert_eq!(invalid_tags.status(), 400);
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/buck/dst", "", &[])).await)
                .await
                .1,
            "source-data"
        );

        let attrs = h
            .handle(req(
                Method::GET,
                "/buck/dst?attributes",
                "",
                &[("x-amz-object-attributes", "ETag,ObjectSize")],
            ))
            .await;
        let (_, attrs) = body_string(attrs).await;
        assert!(attrs.contains("<ETag>"));
        assert!(!attrs.contains("<ETag>\""));
        assert!(attrs.contains("<ObjectSize>11</ObjectSize>"));
        assert!(!attrs.contains("<StorageClass>"));
    }

    #[tokio::test]
    async fn multipart_upload_copy_validation_listing_and_completion() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        h.handle(req(Method::PUT, "/buck/source", "0123456789", &[]))
            .await;
        let excessive = (0..11)
            .map(|index| format!("k{index}=v"))
            .collect::<Vec<_>>()
            .join("&");
        assert_eq!(
            h.handle(req(
                Method::POST,
                "/buck/rejected?uploads",
                "",
                &[("x-amz-tagging", &excessive)],
            ))
            .await
            .status(),
            400
        );
        assert!(
            !body_string(h.handle(req(Method::GET, "/buck?uploads", "", &[])).await)
                .await
                .1
                .contains("<Key>rejected</Key>")
        );
        let initiated = h
            .handle(req(
                Method::POST,
                "/buck/final?uploads",
                "",
                &[("content-type", "text/plain"), ("x-amz-meta-kind", "multi")],
            ))
            .await;
        let upload_id = xml_value(&body_string(initiated).await.1, "UploadId");

        let missing_upload = h
            .handle(req(
                Method::PUT,
                "/buck/final?uploadId=missing&partNumber=0",
                "x",
                &[],
            ))
            .await;
        assert_eq!(missing_upload.status(), 404);
        let copied = h
            .handle(req(
                Method::PUT,
                &format!("/buck/final?uploadId={upload_id}&partNumber=1"),
                "",
                &[
                    ("x-amz-copy-source", "/buck/source"),
                    ("x-amz-copy-source-range", "bytes=2-5"),
                ],
            ))
            .await;
        let (_, copied_body) = body_string(copied).await;
        let part_etag = xml_value(&copied_body, "ETag");

        let zero = h
            .handle(req(
                Method::GET,
                &format!("/buck/final?uploadId={upload_id}&max-parts=0"),
                "",
                &[],
            ))
            .await;
        let (_, zero_body) = body_string(zero).await;
        assert!(!zero_body.contains("<Part><PartNumber>"));
        assert!(zero_body.contains("<IsTruncated>true</IsTruncated>"));

        let invalid = "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"bad\"</ETag></Part></CompleteMultipartUpload>";
        assert_eq!(
            h.handle(req(
                Method::POST,
                &format!("/buck/final?uploadId={upload_id}"),
                invalid,
                &[],
            ))
            .await
            .status(),
            400
        );
        assert_eq!(
            h.handle(req(
                Method::GET,
                &format!("/buck/final?uploadId={upload_id}"),
                "",
                &[],
            ))
            .await
            .status(),
            200
        );

        let complete = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{part_etag}</ETag></Part></CompleteMultipartUpload>"
        );
        assert_eq!(
            h.handle(req(
                Method::POST,
                &format!("/buck/final?uploadId={upload_id}"),
                &complete,
                &[],
            ))
            .await
            .status(),
            200
        );
        let get = h.handle(req(Method::GET, "/buck/final", "", &[])).await;
        assert_eq!(get.headers()["content-type"], "text/plain");
        assert_eq!(get.headers()["x-amz-meta-kind"], "multi");
        assert_eq!(body_string(get).await.1, "2345");
        assert_eq!(
            h.handle(req(
                Method::GET,
                &format!("/buck/final?uploadId={upload_id}"),
                "",
                &[],
            ))
            .await
            .status(),
            404
        );
    }

    #[tokio::test]
    async fn complete_multipart_rejects_malformed_requests_without_consuming_upload() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let initiated = h
            .handle(req(Method::POST, "/buck/final?uploads", "", &[]))
            .await;
        let upload_id = xml_value(&body_string(initiated).await.1, "UploadId");
        let uploaded = h
            .handle(req(
                Method::PUT,
                &format!("/buck/final?uploadId={upload_id}&partNumber=1"),
                "small",
                &[],
            ))
            .await;
        let etag = uploaded.headers()["etag"].to_str().unwrap().to_string();

        for path in [
            "/buck/final?uploadId=missing".to_string(),
            format!("/buck/wrong-key?uploadId={upload_id}"),
        ] {
            let response = h.handle(req(Method::POST, &path, "<broken", &[])).await;
            let (status, body) = body_string(response).await;
            assert_eq!(status, 404);
            assert!(body.contains("<Code>NoSuchUpload</Code>"));
        }

        let malformed = [
            format!(
                "<WrongRoot><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></WrongRoot>"
            ),
            format!(
                "<CompleteMultipartUpload><Wrapper><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></Wrapper></CompleteMultipartUpload>"
            ),
            format!(
                "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
            ),
            format!(
                "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
            ),
            format!(
                "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>"
            ),
        ];
        for body in malformed {
            let response = h
                .handle(req(
                    Method::POST,
                    &format!("/buck/final?uploadId={upload_id}"),
                    &body,
                    &[],
                ))
                .await;
            let (status, body) = body_string(response).await;
            assert_eq!(status, 400);
            assert!(body.contains("<Code>MalformedXML</Code>"));
        }

        let invalid_part = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"missing\"</ETag></Part></CompleteMultipartUpload>"
        );
        let invalid_part = h
            .handle(req(
                Method::POST,
                &format!("/buck/final?uploadId={upload_id}"),
                &invalid_part,
                &[],
            ))
            .await;
        let (status, body) = body_string(invalid_part).await;
        assert_eq!(status, 400);
        assert!(body.contains("<Code>InvalidPart</Code>"));

        assert_eq!(
            h.handle(req(
                Method::GET,
                &format!("/buck/final?uploadId={upload_id}"),
                "",
                &[],
            ))
            .await
            .status(),
            200
        );
    }

    #[tokio::test]
    async fn multipart_upload_markers_resume_after_key_or_pair() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let first_a = h
            .handle(req(Method::POST, "/buck/a?uploads", "", &[]))
            .await;
        let first_a = xml_value(&body_string(first_a).await.1, "UploadId");
        let second_a = h
            .handle(req(Method::POST, "/buck/a?uploads", "", &[]))
            .await;
        let second_a = xml_value(&body_string(second_a).await.1, "UploadId");
        let b = h
            .handle(req(Method::POST, "/buck/b?uploads", "", &[]))
            .await;
        let b = xml_value(&body_string(b).await.1, "UploadId");
        let mut a_ids = [first_a, second_a];
        a_ids.sort();

        let after_key = h
            .handle(req(Method::GET, "/buck?uploads&key-marker=a", "", &[]))
            .await;
        let (_, after_key) = body_string(after_key).await;
        assert!(!after_key.contains(&format!("<UploadId>{}</UploadId>", a_ids[0])));
        assert!(!after_key.contains(&format!("<UploadId>{}</UploadId>", a_ids[1])));
        assert!(after_key.contains(&format!("<UploadId>{b}</UploadId>")));

        let after_pair = h
            .handle(req(
                Method::GET,
                &format!("/buck?uploads&key-marker=a&upload-id-marker={}", a_ids[0]),
                "",
                &[],
            ))
            .await;
        let (_, after_pair) = body_string(after_pair).await;
        assert!(!after_pair.contains(&format!("<UploadId>{}</UploadId>", a_ids[0])));
        assert!(after_pair.contains(&format!("<UploadId>{}</UploadId>", a_ids[1])));
        assert!(after_pair.contains(&format!("<UploadId>{b}</UploadId>")));
    }

    #[tokio::test]
    async fn upload_part_checksums_replacement_abort_and_upload_listing() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let first = h
            .handle(req(Method::POST, "/buck/a?uploads", "", &[]))
            .await;
        let first_id = xml_value(&body_string(first).await.1, "UploadId");
        let second = h
            .handle(req(Method::POST, "/buck/b?uploads", "", &[]))
            .await;
        let second_id = xml_value(&body_string(second).await.1, "UploadId");

        let page = h
            .handle(req(Method::GET, "/buck?uploads&max-uploads=1", "", &[]))
            .await;
        let (_, page) = body_string(page).await;
        assert!(page.contains("<IsTruncated>true</IsTruncated>"));
        assert_eq!(xml_value(&page, "NextKeyMarker"), "a");
        assert_eq!(xml_value(&page, "NextUploadIdMarker"), first_id);
        let next = h
            .handle(req(
                Method::GET,
                &format!("/buck?uploads&key-marker=a&upload-id-marker={first_id}&max-uploads=1"),
                "",
                &[],
            ))
            .await;
        assert!(body_string(next).await.1.contains(&second_id));

        let wrong = crate::integrity::checksum_base64(
            crate::integrity::ChecksumAlgorithm::Sha256,
            b"wrong",
        );
        assert_eq!(
            h.handle(req(
                Method::PUT,
                &format!("/buck/a?uploadId={first_id}&partNumber=1"),
                "first",
                &[("x-amz-checksum-sha256", &wrong)],
            ))
            .await
            .status(),
            400
        );
        assert_eq!(
            h.handle(req(
                Method::PUT,
                &format!("/buck/a?uploadId={first_id}&partNumber=0"),
                "bad",
                &[],
            ))
            .await
            .status(),
            400
        );
        let checksum = crate::integrity::checksum_base64(
            crate::integrity::ChecksumAlgorithm::Sha256,
            b"first",
        );
        let original = h
            .handle(req(
                Method::PUT,
                &format!("/buck/a?uploadId={first_id}&partNumber=1"),
                "first",
                &[("x-amz-checksum-sha256", &checksum)],
            ))
            .await;
        let original_etag = original.headers()["etag"].to_str().unwrap().to_string();
        let replacement = h
            .handle(req(
                Method::PUT,
                &format!("/buck/a?uploadId={first_id}&partNumber=1"),
                "replacement",
                &[],
            ))
            .await;
        let replacement_etag = replacement.headers()["etag"].to_str().unwrap().to_string();
        assert_ne!(original_etag, replacement_etag);
        let second_part = h
            .handle(req(
                Method::PUT,
                &format!("/buck/a?uploadId={first_id}&partNumber=2"),
                "last",
                &[],
            ))
            .await;
        let second_etag = second_part.headers()["etag"].to_str().unwrap();
        let too_small = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{replacement_etag}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{second_etag}</ETag></Part></CompleteMultipartUpload>"
        );
        assert_eq!(
            h.handle(req(
                Method::POST,
                &format!("/buck/a?uploadId={first_id}"),
                &too_small,
                &[],
            ))
            .await
            .status(),
            400
        );
        let listed = h
            .handle(req(
                Method::GET,
                &format!("/buck/a?uploadId={first_id}"),
                "",
                &[],
            ))
            .await;
        let (_, listed) = body_string(listed).await;
        assert_eq!(listed.matches("<Part><PartNumber>").count(), 2);
        assert_eq!(
            h.handle(req(
                Method::DELETE,
                &format!("/buck/a?uploadId={first_id}"),
                "",
                &[],
            ))
            .await
            .status(),
            204
        );
        let uploads = h.handle(req(Method::GET, "/buck?uploads", "", &[])).await;
        let (_, uploads) = body_string(uploads).await;
        assert!(!uploads.contains(&first_id));
        assert!(uploads.contains(&second_id));
    }

    #[tokio::test]
    async fn versioning_delete_markers_targeted_access_and_suspension() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let initial = h
            .handle(req(Method::GET, "/buck?versioning", "", &[]))
            .await;
        assert!(body_string(initial).await.1.is_empty());
        let wrong_root = h
            .handle(req(
                Method::PUT,
                "/buck?versioning",
                "<WrongRoot><Status>Enabled</Status></WrongRoot>",
                &[],
            ))
            .await;
        let (status, body) = body_string(wrong_root).await;
        assert_eq!(status, 400);
        assert!(body.contains("<Code>MalformedXML</Code>"));
        let unchanged = h
            .handle(req(Method::GET, "/buck?versioning", "", &[]))
            .await;
        assert!(body_string(unchanged).await.1.is_empty());
        h.handle(req(
            Method::PUT,
            "/buck?versioning",
            "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            &[],
        ))
        .await;
        let first = h.handle(req(Method::PUT, "/buck/key", "one", &[])).await;
        let first_id = first.headers()["x-amz-version-id"]
            .to_str()
            .unwrap()
            .to_string();
        let second = h.handle(req(Method::PUT, "/buck/key", "two", &[])).await;
        let second_id = second.headers()["x-amz-version-id"]
            .to_str()
            .unwrap()
            .to_string();
        let old = h
            .handle(req(
                Method::GET,
                &format!("/buck/key?versionId={first_id}"),
                "",
                &[],
            ))
            .await;
        assert_eq!(body_string(old).await.1, "one");

        let deleted = h.handle(req(Method::DELETE, "/buck/key", "", &[])).await;
        assert_eq!(deleted.headers()["x-amz-delete-marker"], "true");
        let marker_id = deleted.headers()["x-amz-version-id"]
            .to_str()
            .unwrap()
            .to_string();
        let latest = h.handle(req(Method::GET, "/buck/key", "", &[])).await;
        assert_eq!(latest.status(), 404);
        assert_eq!(latest.headers()["x-amz-delete-marker"], "true");
        let marker = h
            .handle(req(
                Method::HEAD,
                &format!("/buck/key?versionId={marker_id}"),
                "",
                &[],
            ))
            .await;
        assert_eq!(marker.status(), 405);
        assert_eq!(marker.headers()["x-amz-delete-marker"], "true");

        let versions = h
            .handle(req(Method::GET, "/buck?versions&prefix=key", "", &[]))
            .await;
        let (_, versions) = body_string(versions).await;
        assert!(versions.contains("<DeleteMarker>"));
        assert_eq!(versions.matches("<IsLatest>true</IsLatest>").count(), 1);
        assert!(versions.find(&marker_id).unwrap() < versions.find(&second_id).unwrap());

        let first_page = h
            .handle(req(
                Method::GET,
                "/buck?versions&prefix=key&max-keys=1",
                "",
                &[],
            ))
            .await;
        let (_, first_page) = body_string(first_page).await;
        assert!(first_page.contains("<IsTruncated>true</IsTruncated>"));
        let next_key = xml_value(&first_page, "NextKeyMarker");
        let next_version = xml_value(&first_page, "NextVersionIdMarker");
        let second_page = h
            .handle(req(
                Method::GET,
                &format!(
                    "/buck?versions&prefix=key&max-keys=1&key-marker={next_key}&version-id-marker={next_version}"
                ),
                "",
                &[],
            ))
            .await;
        let (_, second_page) = body_string(second_page).await;
        assert!(second_page.contains(&second_id));

        assert_eq!(
            h.handle(req(
                Method::DELETE,
                &format!("/buck/key?versionId={marker_id}"),
                "",
                &[],
            ))
            .await
            .status(),
            204
        );
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/buck/key", "", &[])).await)
                .await
                .1,
            "two"
        );

        h.handle(req(
            Method::PUT,
            "/buck?versioning",
            "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>",
            &[],
        ))
        .await;
        let suspended = h.handle(req(Method::PUT, "/buck/key", "null", &[])).await;
        assert_eq!(suspended.headers()["x-amz-version-id"], "null");
        let null_delete = h.handle(req(Method::DELETE, "/buck/key", "", &[])).await;
        assert_eq!(null_delete.headers()["x-amz-version-id"], "null");
        let suspended_versions = h
            .handle(req(Method::GET, "/buck?versions&prefix=key", "", &[]))
            .await;
        let (_, suspended_versions) = body_string(suspended_versions).await;
        assert_eq!(
            suspended_versions
                .matches("<VersionId>null</VersionId>")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn tagging_is_validated_before_mutation_and_tracks_versions() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        h.handle(req(
            Method::PUT,
            "/buck?versioning",
            "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            &[],
        ))
        .await;
        let first = h
            .handle(req(
                Method::PUT,
                "/buck/key",
                "one",
                &[("x-amz-tagging", "stage=one")],
            ))
            .await;
        let first_id = first.headers()["x-amz-version-id"]
            .to_str()
            .unwrap()
            .to_string();
        h.handle(req(
            Method::PUT,
            "/buck/key?tagging",
            "<Tagging><TagSet><Tag><Key>stage</Key><Value>updated</Value></Tag></TagSet></Tagging>",
            &[],
        ))
        .await;
        let tags = body_string(
            h.handle(req(
                Method::GET,
                &format!("/buck/key?tagging&versionId={first_id}"),
                "",
                &[],
            ))
            .await,
        )
        .await
        .1;
        assert!(tags.contains("<Value>updated</Value>"));

        let excessive = (0..11)
            .map(|index| format!("k{index}=v"))
            .collect::<Vec<_>>()
            .join("&");
        let failed = h
            .handle(req(
                Method::PUT,
                "/buck/key",
                "mutated",
                &[("x-amz-tagging", &excessive)],
            ))
            .await;
        let (status, body) = body_string(failed).await;
        assert_eq!(status, 400);
        assert!(body.contains("<Code>InvalidTag</Code>"));
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/buck/key", "", &[])).await)
                .await
                .1,
            "one"
        );
    }

    #[tokio::test]
    async fn object_lock_enables_versioning_and_enforces_modes_and_legal_holds() {
        let h = S3Handler::new();
        h.handle(req(
            Method::PUT,
            "/locked",
            "",
            &[("x-amz-bucket-object-lock-enabled", "true")],
        ))
        .await;
        let versioning = body_string(
            h.handle(req(Method::GET, "/locked?versioning", "", &[]))
                .await,
        )
        .await
        .1;
        assert!(versioning.contains("<Status>Enabled</Status>"));
        let suspend = h
            .handle(req(
                Method::PUT,
                "/locked?versioning",
                "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>",
                &[],
            ))
            .await;
        let (status, body) = body_string(suspend).await;
        assert_eq!(status, 400);
        assert!(body.contains("<Code>InvalidRequest</Code>"));
        let versioning = body_string(
            h.handle(req(Method::GET, "/locked?versioning", "", &[]))
                .await,
        )
        .await
        .1;
        assert!(versioning.contains("<Status>Enabled</Status>"));
        assert_eq!(
            h.handle(req(Method::GET, "/locked?object-lock", "", &[]))
                .await
                .status(),
            200
        );

        h.handle(req(
            Method::PUT,
            "/locked/governed",
            "one",
            &[
                ("x-amz-object-lock-mode", "GOVERNANCE"),
                (
                    "x-amz-object-lock-retain-until-date",
                    "2999-01-01T00:00:00Z",
                ),
            ],
        ))
        .await;
        let shorter_governance = concat!(
            "<Retention><Mode>GOVERNANCE</Mode>",
            "<RetainUntilDate>2998-01-01T00:00:00Z</RetainUntilDate></Retention>"
        );
        assert_eq!(
            h.handle(req(
                Method::PUT,
                "/locked/governed?retention",
                shorter_governance,
                &[],
            ))
            .await
            .status(),
            403
        );
        assert_eq!(
            h.handle(req(
                Method::PUT,
                "/locked/governed?retention",
                shorter_governance,
                &[("x-amz-bypass-governance-retention", "true")],
            ))
            .await
            .status(),
            200
        );
        assert_eq!(
            h.handle(req(Method::PUT, "/locked/governed", "two", &[]))
                .await
                .status(),
            403
        );
        assert_eq!(
            h.handle(req(
                Method::PUT,
                "/locked/governed",
                "two",
                &[("x-amz-bypass-governance-retention", "true")],
            ))
            .await
            .status(),
            200
        );
        h.handle(req(
            Method::PUT,
            "/locked/governed?legal-hold",
            "<LegalHold><Status>ON</Status></LegalHold>",
            &[],
        ))
        .await;
        assert_eq!(
            h.handle(req(
                Method::DELETE,
                "/locked/governed",
                "",
                &[("x-amz-bypass-governance-retention", "true")],
            ))
            .await
            .status(),
            403
        );

        h.handle(req(
            Method::PUT,
            "/locked/compliant",
            "one",
            &[
                ("x-amz-object-lock-mode", "COMPLIANCE"),
                (
                    "x-amz-object-lock-retain-until-date",
                    "2999-01-01T00:00:00Z",
                ),
            ],
        ))
        .await;
        let weaker_compliance = concat!(
            "<Retention><Mode>GOVERNANCE</Mode>",
            "<RetainUntilDate>3000-01-01T00:00:00Z</RetainUntilDate></Retention>"
        );
        assert_eq!(
            h.handle(req(
                Method::PUT,
                "/locked/compliant?retention",
                weaker_compliance,
                &[("x-amz-bypass-governance-retention", "true")],
            ))
            .await
            .status(),
            403
        );
        assert_eq!(
            h.handle(req(
                Method::DELETE,
                "/locked/compliant",
                "",
                &[("x-amz-bypass-governance-retention", "true")],
            ))
            .await
            .status(),
            403
        );
    }

    #[tokio::test]
    async fn copy_object_enforces_governance_bypass() {
        let h = S3Handler::new();
        h.handle(req(
            Method::PUT,
            "/locked",
            "",
            &[("x-amz-bucket-object-lock-enabled", "true")],
        ))
        .await;
        h.handle(req(Method::PUT, "/locked/source", "source", &[]))
            .await;
        h.handle(req(
            Method::PUT,
            "/locked/target",
            "protected",
            &[
                ("x-amz-object-lock-mode", "GOVERNANCE"),
                (
                    "x-amz-object-lock-retain-until-date",
                    "2999-01-01T00:00:00Z",
                ),
            ],
        ))
        .await;

        assert_eq!(
            h.handle(req(
                Method::PUT,
                "/locked/target",
                "",
                &[("x-amz-copy-source", "/locked/source")],
            ))
            .await
            .status(),
            403
        );
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/locked/target", "", &[])).await)
                .await
                .1,
            "protected"
        );
        let copied = h
            .handle(req(
                Method::PUT,
                "/locked/target",
                "",
                &[
                    ("x-amz-copy-source", "/locked/source"),
                    ("x-amz-bypass-governance-retention", "true"),
                ],
            ))
            .await;
        assert_eq!(copied.status(), 200);
        assert_eq!(copied.headers()["x-amz-server-side-encryption"], "AES256");
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/locked/target", "", &[])).await)
                .await
                .1,
            "source"
        );
    }

    #[tokio::test]
    async fn complete_multipart_enforces_governance_and_preserves_failed_upload() {
        let h = S3Handler::new();
        h.handle(req(
            Method::PUT,
            "/locked",
            "",
            &[("x-amz-bucket-object-lock-enabled", "true")],
        ))
        .await;
        h.handle(req(
            Method::PUT,
            "/locked/target",
            "protected",
            &[
                ("x-amz-object-lock-mode", "GOVERNANCE"),
                (
                    "x-amz-object-lock-retain-until-date",
                    "2999-01-01T00:00:00Z",
                ),
            ],
        ))
        .await;
        let initiated = h
            .handle(req(Method::POST, "/locked/target?uploads", "", &[]))
            .await;
        let upload_id = xml_value(&body_string(initiated).await.1, "UploadId");
        let part = h
            .handle(req(
                Method::PUT,
                &format!("/locked/target?uploadId={upload_id}&partNumber=1"),
                "replacement",
                &[],
            ))
            .await;
        let part_etag = part.headers()["etag"].to_str().unwrap().to_string();
        let complete = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{part_etag}</ETag></Part></CompleteMultipartUpload>"
        );

        assert_eq!(
            h.handle(req(
                Method::POST,
                &format!("/locked/target?uploadId={upload_id}"),
                &complete,
                &[],
            ))
            .await
            .status(),
            403
        );
        let listed = h
            .handle(req(
                Method::GET,
                &format!("/locked/target?uploadId={upload_id}"),
                "",
                &[],
            ))
            .await;
        assert_eq!(listed.status(), 200);
        assert!(body_string(listed)
            .await
            .1
            .contains("<PartNumber>1</PartNumber>"));
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/locked/target", "", &[])).await)
                .await
                .1,
            "protected"
        );

        let completed = h
            .handle(req(
                Method::POST,
                &format!("/locked/target?uploadId={upload_id}"),
                &complete,
                &[("x-amz-bypass-governance-retention", "true")],
            ))
            .await;
        assert_eq!(completed.status(), 200);
        assert_eq!(
            completed.headers()["x-amz-server-side-encryption"],
            "AES256"
        );
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/locked/target", "", &[])).await)
                .await
                .1,
            "replacement"
        );
        assert_eq!(
            h.handle(req(
                Method::GET,
                &format!("/locked/target?uploadId={upload_id}"),
                "",
                &[],
            ))
            .await
            .status(),
            404
        );
    }

    #[tokio::test]
    async fn delete_objects_enforces_governance_bypass_before_batch_mutation() {
        let h = S3Handler::new();
        h.handle(req(
            Method::PUT,
            "/locked",
            "",
            &[("x-amz-bucket-object-lock-enabled", "true")],
        ))
        .await;
        h.handle(req(
            Method::PUT,
            "/locked/protected",
            "protected",
            &[
                ("x-amz-object-lock-mode", "GOVERNANCE"),
                (
                    "x-amz-object-lock-retain-until-date",
                    "2999-01-01T00:00:00Z",
                ),
            ],
        ))
        .await;
        h.handle(req(Method::PUT, "/locked/free", "free", &[]))
            .await;
        let delete = "<Delete><Object><Key>free</Key></Object><Object><Key>protected</Key></Object></Delete>";

        assert_eq!(
            h.handle(req(Method::POST, "/locked?delete", delete, &[]))
                .await
                .status(),
            403
        );
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/locked/free", "", &[])).await)
                .await
                .1,
            "free"
        );
        assert_eq!(
            body_string(
                h.handle(req(Method::GET, "/locked/protected", "", &[]))
                    .await
            )
            .await
            .1,
            "protected"
        );

        assert_eq!(
            h.handle(req(
                Method::POST,
                "/locked?delete",
                delete,
                &[("x-amz-bypass-governance-retention", "true")],
            ))
            .await
            .status(),
            200
        );
        assert_eq!(
            h.handle(req(Method::GET, "/locked/free", "", &[]))
                .await
                .status(),
            404
        );
        assert_eq!(
            h.handle(req(Method::GET, "/locked/protected", "", &[]))
                .await
                .status(),
            404
        );
    }

    #[tokio::test]
    async fn bucket_configuration_cors_acl_and_encryption_reads_are_guarded() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let cors = "<CORSConfiguration><CORSRule><ID>browser-rule</ID><AllowedOrigin>https://example.test</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedHeader>x-test-*</AllowedHeader><ExposeHeader>ETag</ExposeHeader><MaxAgeSeconds>60</MaxAgeSeconds></CORSRule></CORSConfiguration>";
        assert_eq!(
            h.handle(req(Method::PUT, "/buck?cors", cors, &[]))
                .await
                .status(),
            200
        );
        assert!(
            body_string(h.handle(req(Method::GET, "/buck?cors", "", &[])).await)
                .await
                .1
                .contains("<ID>browser-rule</ID>")
        );
        let preflight = h
            .handle(req(
                Method::OPTIONS,
                "/buck/key",
                "",
                &[
                    ("origin", "https://example.test"),
                    ("access-control-request-method", "GET"),
                    ("access-control-request-headers", "x-test-one"),
                ],
            ))
            .await;
        assert_eq!(preflight.status(), 200);
        assert_eq!(
            preflight.headers()["access-control-allow-origin"],
            "https://example.test"
        );
        assert_eq!(
            preflight.headers()["access-control-allow-headers"],
            "x-test-one"
        );
        let cors_miss = h
            .handle(req(
                Method::OPTIONS,
                "/buck/key",
                "",
                &[
                    ("origin", "https://example.test"),
                    ("access-control-request-method", "GET"),
                    ("access-control-request-headers", "x-other"),
                ],
            ))
            .await;
        assert_eq!(cors_miss.status(), 403);

        let put = h.handle(req(Method::PUT, "/buck/key", "data", &[])).await;
        assert_eq!(put.headers()["x-amz-server-side-encryption"], "AES256");
        let get = h
            .handle(req(
                Method::GET,
                "/buck/key",
                "",
                &[("origin", "https://example.test")],
            ))
            .await;
        assert_eq!(get.headers()["x-amz-server-side-encryption"], "AES256");
        assert_eq!(
            get.headers()["access-control-allow-origin"],
            "https://example.test"
        );
        let missing = h
            .handle(req(
                Method::GET,
                "/buck/missing",
                "",
                &[("origin", "https://example.test")],
            ))
            .await;
        assert_eq!(missing.status(), 404);
        assert_eq!(
            missing.headers()["access-control-allow-origin"],
            "https://example.test"
        );
        assert_eq!(
            h.handle(req(Method::DELETE, "/buck?cors", "", &[]))
                .await
                .status(),
            204
        );
        assert_eq!(
            h.handle(req(Method::GET, "/buck?cors", "", &[]))
                .await
                .status(),
            404
        );
        assert_eq!(
            h.handle(req(
                Method::OPTIONS,
                "/buck/key",
                "",
                &[
                    ("origin", "https://example.test"),
                    ("access-control-request-method", "GET"),
                ],
            ))
            .await
            .status(),
            403
        );
        let acl = body_string(h.handle(req(Method::GET, "/buck?acl", "", &[])).await)
            .await
            .1;
        assert!(acl.contains("<Permission>FULL_CONTROL</Permission>"));
        let encryption = body_string(
            h.handle(req(Method::GET, "/buck?encryption", "", &[]))
                .await,
        )
        .await
        .1;
        assert!(encryption.contains("<SSEAlgorithm>AES256</SSEAlgorithm>"));

        let policy = "not JSON, but opaque UTF-8";
        assert_eq!(
            h.handle(req(Method::PUT, "/buck?policy", policy, &[]))
                .await
                .status(),
            204
        );
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/buck?policy", "", &[])).await)
                .await
                .1,
            policy
        );
        h.handle(req(Method::DELETE, "/buck?policy", "", &[])).await;
        assert_eq!(
            h.handle(req(Method::GET, "/buck?policy", "", &[]))
                .await
                .status(),
            404
        );

        let website = "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>";
        h.handle(req(Method::PUT, "/buck?website", website, &[]))
            .await;
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/buck?website", "", &[])).await)
                .await
                .1,
            website
        );
        assert_eq!(
            h.handle(req(Method::DELETE, "/buck?website", "", &[]))
                .await
                .status(),
            501
        );
    }

    #[tokio::test]
    async fn bucket_tagging_distinguishes_empty_configuration_from_deleted() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let empty = "<Tagging><TagSet/></Tagging>";
        assert_eq!(
            h.handle(req(Method::PUT, "/buck?tagging", empty, &[]))
                .await
                .status(),
            204
        );
        let get = h.handle(req(Method::GET, "/buck?tagging", "", &[])).await;
        let (status, body) = body_string(get).await;
        assert_eq!(status, 200);
        assert!(body.contains("<TagSet></TagSet>"));
        assert_eq!(
            h.handle(req(Method::DELETE, "/buck?tagging", "", &[]))
                .await
                .status(),
            204
        );
        assert_eq!(
            h.handle(req(Method::GET, "/buck?tagging", "", &[]))
                .await
                .status(),
            404
        );
    }

    #[tokio::test]
    async fn bucket_and_account_public_access_block_are_distinct() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        let block = "<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>";
        h.handle(req(Method::PUT, "/buck?publicAccessBlock", block, &[]))
            .await;
        assert!(body_string(
            h.handle(req(Method::GET, "/buck?publicAccessBlock", "", &[]))
                .await
        )
        .await
        .1
        .contains("<BlockPublicAcls>true</BlockPublicAcls>"));
        assert_eq!(
            h.handle(req(Method::DELETE, "/buck?publicAccessBlock", "", &[],))
                .await
                .status(),
            204
        );
        assert_eq!(
            h.handle(req(Method::GET, "/buck?publicAccessBlock", "", &[]))
                .await
                .status(),
            404
        );

        let control_path = "/v20180820/configuration/publicAccessBlock";
        assert_eq!(
            h.handle(req(
                Method::PUT,
                control_path,
                block,
                &[("x-amz-account-id", "111122223333")],
            ))
            .await
            .status(),
            200
        );
        let account = h
            .handle(req(
                Method::GET,
                control_path,
                "",
                &[("host", "111122223333.s3-control.localhost")],
            ))
            .await;
        assert_eq!(account.status(), 200);
        assert!(body_string(account)
            .await
            .1
            .contains("<BlockPublicPolicy>true</BlockPublicPolicy>"));
        h.handle(req(
            Method::DELETE,
            "/111122223333/v20180820/configuration/publicAccessBlock",
            "",
            &[],
        ))
        .await;
        assert_eq!(
            h.handle(req(
                Method::GET,
                control_path,
                "",
                &[("x-amz-account-id", "111122223333")],
            ))
            .await
            .status(),
            404
        );
    }

    #[tokio::test]
    async fn s3_control_path_detection_does_not_capture_normal_buckets() {
        let h = S3Handler::new();
        assert_eq!(
            h.handle(req(
                Method::GET,
                "/other-control-surface",
                "",
                &[("x-amz-account-id", "111122223333")],
            ))
            .await
            .status(),
            501
        );
        assert_eq!(
            h.handle(req(Method::PUT, "/v20180820", "", &[]))
                .await
                .status(),
            200
        );
        assert_eq!(
            h.handle(req(Method::PUT, "/v20180820/key", "data", &[]))
                .await
                .status(),
            200
        );
        assert_eq!(
            body_string(h.handle(req(Method::GET, "/v20180820/key", "", &[])).await)
                .await
                .1,
            "data"
        );
    }

    #[tokio::test]
    async fn batch_deleting_last_version_removes_empty_version_chain() {
        let h = S3Handler::new();
        h.handle(req(Method::PUT, "/buck", "", &[])).await;
        h.handle(req(
            Method::PUT,
            "/buck?versioning",
            "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            &[],
        ))
        .await;
        let put = h.handle(req(Method::PUT, "/buck/key", "data", &[])).await;
        let version = put.headers()["x-amz-version-id"].to_str().unwrap();
        let body = format!(
            "<Delete><Object><Key>key</Key><VersionId>{version}</VersionId></Object></Delete>"
        );
        assert_eq!(
            h.handle(req(Method::POST, "/buck?delete", &body, &[]))
                .await
                .status(),
            200
        );
        assert_eq!(
            h.handle(req(Method::DELETE, "/buck", "", &[]))
                .await
                .status(),
            204
        );
    }
}

#[cfg(test)]
mod restart_persistence_tests {
    use super::*;
    use bytes::Bytes;
    use http::HeaderMap;
    use std::os::unix::fs::PermissionsExt;

    fn request(method: Method, path: &str, body: Bytes) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:4566"));
        ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers,
            body,
            region: "us-east-1".into(),
            account_id: "000000000001".into(),
            request_id: "restart-gate".into(),
        }
    }

    #[tokio::test]
    async fn compact_migration_preserves_null_versions_and_versioning_transitions() {
        use crate::store::{StoredVersion, VersionValue};
        use base64::{engine::general_purpose::STANDARD, Engine};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
        let handler = super::tests::test_state_handler(Weak::new(), state.clone()).unwrap();
        assert!(handler
            .handle(request(Method::PUT, "/compact", Bytes::new()))
            .await
            .status()
            .is_success());
        let original = Bytes::from(vec![b'x'; 1024]);
        assert!(handler
            .handle(request(Method::PUT, "/compact/key", original.clone()))
            .await
            .status()
            .is_success());
        let connection = state.connection().unwrap();
        let (account, payload): (String, Vec<u8>) = connection
            .query_row(
                "SELECT account,payload FROM s3_entries WHERE kind='object'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            payload.len() < 3000,
            "inline ciphertext must use compact encoding"
        );
        let versions: i64 = connection
            .query_row(
                "SELECT count(*) FROM s3_entries WHERE kind='versions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(versions, 0);
        let mut legacy: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let inline = &mut legacy["body"]["Encrypted"]["ciphertext"]["Inline"];
        *inline = serde_json::json!(STANDARD.decode(inline.as_str().unwrap()).unwrap());
        let object = serde_json::from_value(legacy.clone()).unwrap();
        let version = StoredVersion {
            id: "null".into(),
            last_modified: serde_json::from_value(legacy["last_modified"].clone()).unwrap(),
            value: VersionValue::Object(Box::new(object)),
        };
        let mut chain = serde_json::to_value(vec![version]).unwrap();
        chain[0]["value"]["Object"] = legacy.clone();
        let old_payload = serde_json::to_vec(&legacy).unwrap();
        connection
            .execute(
                "UPDATE s3_entries SET payload=?1 WHERE kind='object'",
                [&old_payload],
            )
            .unwrap();
        connection.execute("INSERT INTO s3_entries(account,bucket,kind,key,subkey,payload) VALUES(?1,'compact','versions','key','',?2)", rusqlite::params![account, serde_json::to_vec(&chain).unwrap()]).unwrap();
        connection
            .execute("UPDATE s3_metadata SET version=2", [])
            .unwrap();
        drop(handler);
        connection.execute_batch("CREATE TRIGGER reject_compaction BEFORE UPDATE ON s3_entries BEGIN SELECT RAISE(ABORT,'injected migration failure'); END").unwrap();
        assert!(super::tests::test_state_handler(Weak::new(), state.clone()).is_err());
        let unchanged: Vec<u8> = connection
            .query_row(
                "SELECT payload FROM s3_entries WHERE kind='object'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unchanged, old_payload);
        assert_eq!(
            connection
                .query_row("SELECT version FROM s3_metadata", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        connection
            .execute_batch("DROP TRIGGER reject_compaction")
            .unwrap();
        let handler = super::tests::test_state_handler(Weak::new(), state.clone()).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM s3_entries WHERE kind='versions'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        for uri in ["/compact/key", "/compact/key?versionId=null"] {
            let response = handler
                .handle(request(Method::GET, uri, Bytes::new()))
                .await;
            assert_eq!(response.status(), 200);
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 2000)
                    .await
                    .unwrap(),
                original
            );
        }
        let listed = handler
            .handle(request(Method::GET, "/compact?versions", Bytes::new()))
            .await;
        let body = axum::body::to_bytes(listed.into_body(), 10000)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("<VersionId>null</VersionId>"));
        assert!(handler
            .handle(request(
                Method::PUT,
                "/compact?versioning",
                Bytes::from_static(
                    b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"
                )
            ))
            .await
            .status()
            .is_success());
        drop(handler);
        let handler = super::tests::test_state_handler(Weak::new(), state.clone()).unwrap();
        assert!(handler
            .handle(request(
                Method::PUT,
                "/compact/key",
                Bytes::from_static(b"new version")
            ))
            .await
            .status()
            .is_success());
        assert!(handler.handle(request(Method::PUT, "/compact?versioning", Bytes::from_static(b"<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>"))).await.status().is_success());
        assert!(handler
            .handle(request(Method::DELETE, "/compact/key", Bytes::new()))
            .await
            .status()
            .is_success());
        drop(handler);
        let handler = super::tests::test_state_handler(Weak::new(), state).unwrap();
        assert_eq!(
            handler
                .handle(request(Method::GET, "/compact/key", Bytes::new()))
                .await
                .status(),
            404
        );
        let listed = handler
            .handle(request(Method::GET, "/compact?versions", Bytes::new()))
            .await;
        let body = axum::body::to_bytes(listed.into_body(), 10000)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body.matches("<DeleteMarker>").count(), 1);
        assert_eq!(body.matches("<Version>").count(), 1);
    }

    #[tokio::test]
    async fn writes_touch_only_changed_objects_and_survive_reopen() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
        let handler = super::tests::test_state_handler(Weak::new(), state.clone()).unwrap();
        for path in ["/first", "/second", "/first/untouched", "/second/untouched"] {
            assert!(handler
                .handle(request(Method::PUT, path, Bytes::from_static(b"old")))
                .await
                .status()
                .is_success());
        }
        state.connection().unwrap().execute_batch("CREATE TRIGGER preserve_untouched BEFORE UPDATE ON s3_entries WHEN OLD.kind='object' AND OLD.key='untouched' BEGIN SELECT RAISE(FAIL, 'unrelated object rewritten'); END;").unwrap();
        assert!(handler
            .handle(request(
                Method::PUT,
                "/first/new",
                Bytes::from_static(b"new")
            ))
            .await
            .status()
            .is_success());

        drop(handler);
        let reopened = super::tests::test_state_handler(Weak::new(), state).unwrap();
        let response = reopened
            .handle(request(Method::GET, "/first/new", Bytes::new()))
            .await;
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 100)
                .await
                .unwrap(),
            Bytes::from_static(b"new")
        );
    }

    #[tokio::test]
    async fn readers_and_region_discovery_wait_for_durable_commit_admission() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
        let handler =
            Arc::new(super::tests::test_state_handler(Weak::new(), state.clone()).unwrap());
        assert_eq!(
            handler
                .handle(request(Method::PUT, "/admission", Bytes::new()))
                .await
                .status(),
            200
        );
        let writer = handler.mutation_lock.lock().await;
        let gate = handler
            .store
            .transaction_gate("000000000001", "admission")
            .unwrap();
        let bucket_writer = gate.write().await;
        let read_handler = handler.clone();
        let mut read = tokio::spawn(async move {
            read_handler
                .handle(request(Method::HEAD, "/admission", Bytes::new()))
                .await
                .status()
        });
        let catalog_handler = handler.clone();
        let mut catalog =
            tokio::spawn(async move { catalog_handler.resource_regions("000000000001").await });
        // Bucket readers wait on their commit gate; region discovery retains global admission.
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut read)
            .await
            .is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut catalog)
                .await
                .is_err()
        );
        handler
            .persist_bucket("000000000001", Some("admission"), Vec::new())
            .unwrap();
        drop(bucket_writer);
        drop(writer);
        assert_eq!(read.await.unwrap(), 200);
        assert_eq!(catalog.await.unwrap().unwrap(), vec!["us-east-1"]);
        assert!(!handler.poisoned.load(Ordering::Acquire));
        assert_eq!(
            handler
                .handle(request(
                    Method::PUT,
                    "/admission/ledger",
                    Bytes::from_static(b"canonical")
                ))
                .await
                .status(),
            200
        );
        drop(handler);
        let reopened = super::tests::test_state_handler(Weak::new(), state).unwrap();
        let response = reopened
            .handle(request(Method::GET, "/admission/ledger", Bytes::new()))
            .await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap(),
            Bytes::from_static(b"canonical")
        );
    }

    #[tokio::test]
    async fn acknowledged_small_and_large_objects_survive_reopen() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
        let handler = super::tests::test_state_handler(Weak::new(), state.clone()).unwrap();
        assert!(handler
            .handle(request(Method::PUT, "/durable", Bytes::new()))
            .await
            .status()
            .is_success());
        for (key, data) in [("small", vec![1_u8; 8]), ("large", vec![2_u8; 70_000])] {
            assert!(handler
                .handle(request(
                    Method::PUT,
                    &format!("/durable/{key}"),
                    Bytes::from(data)
                ))
                .await
                .status()
                .is_success());
        }
        drop(handler);
        let reopened = super::tests::test_state_handler(Weak::new(), state).unwrap();
        for (key, expected) in [("small", vec![1_u8; 8]), ("large", vec![2_u8; 70_000])] {
            let response = reopened
                .handle(request(
                    Method::GET,
                    &format!("/durable/{key}"),
                    Bytes::new(),
                ))
                .await;
            assert!(response.status().is_success());
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 100_000)
                    .await
                    .unwrap(),
                Bytes::from(expected)
            );
        }
    }
}

#[cfg(test)]
mod encryption_storage_tests {
    use super::*;
    use crate::store::{StoredBody, VersionValue};
    use bytes::Bytes;
    use http::StatusCode;

    fn request(method: Method, uri: &str, body: Bytes) -> ServiceRequest {
        ServiceRequest {
            method,
            uri: uri.parse().unwrap(),
            headers: http::HeaderMap::new(),
            body,
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            request_id: "encryption-gate".into(),
        }
    }

    #[tokio::test]
    async fn explicit_legacy_migration_preserves_versions_and_restart_data() {
        let root = tempfile::tempdir().unwrap();
        let state = Arc::new(StateDb::open(root.path().join("private/state.sqlite3")).unwrap());
        let handler = super::tests::test_state_handler(Weak::new(), state.clone()).unwrap();
        handler
            .handle(request(Method::PUT, "/legacy-orders", Bytes::new()))
            .await;
        handler
            .handle(request(
                Method::PUT,
                "/legacy-orders?versioning",
                Bytes::from_static(
                    b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                ),
            ))
            .await;
        handler
            .handle(request(
                Method::PUT,
                "/legacy-orders/invoice",
                Bytes::from_static(b"old invoice bytes"),
            ))
            .await;
        let bucket = handler.store.get("000000000000", "legacy-orders").unwrap();
        let (version, etag) = {
            let mut guard = bucket.write().await;
            let object = guard.objects.get_mut("invoice").unwrap();
            object.body = StoredBody::Inline(Bytes::from_static(b"old invoice bytes"));
            let etag = object.etag.clone();
            let version = &mut guard.versions.get_mut("invoice").unwrap()[0];
            if let VersionValue::Object(object) = &mut version.value {
                object.body = StoredBody::Inline(Bytes::from_static(b"old invoice bytes"));
            }
            (version.id.clone(), etag)
        };
        handler.persist(Vec::new()).unwrap();
        let old = handler
            .handle(request(Method::GET, "/legacy-orders/invoice", Bytes::new()))
            .await;
        assert_eq!(
            old.headers()["x-locallycloud-storage-format"],
            "legacy-plaintext"
        );
        assert!(!old.headers().contains_key("x-amz-server-side-encryption"));
        assert_eq!(
            axum::body::to_bytes(old.into_body(), 1000).await.unwrap(),
            Bytes::from_static(b"old invoice bytes")
        );
        let migrate = request(Method::POST, "/", Bytes::new());
        let before = handler
            .persistence
            .as_ref()
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        state.connection().unwrap().execute_batch("CREATE TRIGGER migration_failure BEFORE UPDATE ON s3_entries BEGIN SELECT RAISE(FAIL, 'migration interrupted'); END;").unwrap();
        assert!(handler.migrate_legacy_encryption(&migrate).await.is_err());
        assert_eq!(
            bucket.read().await.objects["invoice"]
                .body
                .read_all()
                .unwrap(),
            Bytes::from_static(b"old invoice bytes")
        );
        let failed = handler
            .persistence
            .as_ref()
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(before, failed);
        state
            .connection()
            .unwrap()
            .execute_batch("DROP TRIGGER migration_failure;")
            .unwrap();
        drop(handler);
        let handler = super::tests::test_state_handler(Weak::new(), state.clone()).unwrap();

        assert_eq!(
            handler.migrate_legacy_encryption(&migrate).await.unwrap(),
            2
        );
        assert_eq!(
            handler.migrate_legacy_encryption(&migrate).await.unwrap(),
            0
        );
        let payload = handler
            .persistence
            .as_ref()
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert!(!payload
            .windows(17)
            .any(|bytes| bytes == b"old invoice bytes"));
        let blobs = handler.persistence.as_ref().unwrap().blobs.clone();
        for path in std::fs::read_dir(blobs).unwrap() {
            let bytes = std::fs::read(path.unwrap().path()).unwrap();
            assert!(!bytes.windows(17).any(|bytes| bytes == b"old invoice bytes"));
        }
        drop(handler);
        let reopened = super::tests::test_state_handler(Weak::new(), state).unwrap();
        for uri in [
            "/legacy-orders/invoice".to_string(),
            format!("/legacy-orders/invoice?versionId={version}"),
        ] {
            let response = reopened
                .handle(request(Method::GET, &uri, Bytes::new()))
                .await;
            assert_eq!(response.headers()["ETag"], etag);
            assert_eq!(response.headers()["x-amz-server-side-encryption"], "AES256");
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 1000)
                    .await
                    .unwrap(),
                Bytes::from_static(b"old invoice bytes")
            );
        }
    }

    #[tokio::test]
    async fn bucket_keys_reject_without_mutating_object_or_configuration() {
        let handler = S3Handler::new();
        handler
            .handle(request(Method::PUT, "/bucket-keys", Bytes::new()))
            .await;
        let mut put = request(
            Method::PUT,
            "/bucket-keys/unsupported",
            Bytes::from_static(b"private"),
        );
        put.headers.insert(
            "x-amz-server-side-encryption",
            HeaderValue::from_static("aws:kms"),
        );
        put.headers.insert(
            "x-amz-server-side-encryption-bucket-key-enabled",
            HeaderValue::from_static("true"),
        );
        assert_eq!(
            handler.handle(put).await.status(),
            StatusCode::NOT_IMPLEMENTED
        );
        assert_eq!(
            handler
                .handle(request(
                    Method::GET,
                    "/bucket-keys/unsupported",
                    Bytes::new()
                ))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        let body = Bytes::from_static(b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>");
        assert_eq!(
            handler
                .handle(request(Method::PUT, "/bucket-keys?encryption", body))
                .await
                .status(),
            StatusCode::NOT_IMPLEMENTED
        );
        let bucket = handler.store.get("000000000000", "bucket-keys").unwrap();
        assert_eq!(
            bucket.read().await.encryption,
            crate::store::ServerSideEncryption::default()
        );
    }
}

#[cfg(test)]
#[path = "visibility_tests.rs"]
mod visibility_tests;
