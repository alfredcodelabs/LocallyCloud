//! Lambda Runtime API invocation broker (`2018-06-01` correlation core).
//!
//! The broker is the concurrency-correct heart of the data plane and the Runtime API: a
//! caller `submit`s an invocation and awaits its [`Outcome`]; a guest runtime long-polls
//! `next` to receive the pending invocation, then reports the result via `complete`. Payloads
//! are carried as raw bytes end-to-end (byte-exact, no lossy re-encoding) and a single
//! `request_id` correlates the submission, the `next` delivery, and the completion
//! (Requirements 22, 23, 24). Stopping an execution environment drains its queued and
//! in-flight invocations with an `Unhandled` function error so no caller hangs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::{oneshot, Notify};
use tokio::time::Instant;
use uuid::Uuid;

/// Classification of a function error reported by the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionErrorType {
    /// The handler caught and reported the error (`/invocation/{id}/error`).
    Handled,
    /// The runtime crashed, timed out, or failed to initialize (`/init/error`, stop).
    Unhandled,
}

impl FunctionErrorType {
    pub fn as_str(self) -> &'static str {
        match self {
            FunctionErrorType::Handled => "Handled",
            FunctionErrorType::Unhandled => "Unhandled",
        }
    }
}

/// The result of an invocation as reported by the guest runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Successful response payload bytes.
    Success(Vec<u8>),
    /// A function error: classification plus the error payload bytes.
    Error {
        error_type: FunctionErrorType,
        payload: Vec<u8>,
    },
}

/// A pending invocation delivered to a guest by `next`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInvocation {
    pub request_id: String,
    pub payload: Vec<u8>,
    pub invoked_function_arn: String,
    /// Absolute invocation deadline in epoch milliseconds.
    pub deadline_ms: i64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// One execution environment's FIFO queue of pending invocations plus a long-poll waker.
struct Queue {
    pending: Mutex<VecDeque<PendingInvocation>>,
    notify: Notify,
    open: AtomicBool,
}

impl Queue {
    fn new() -> Self {
        Queue {
            pending: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            open: AtomicBool::new(true),
        }
    }
}

/// Routes invocations to guest runtimes and correlates their results back to callers.
///
/// Keyed by an opaque execution-environment id (e.g. a qualified function ARN): all guests
/// serving the same key share its queue, and a `next` poll returns the next queued invocation.
#[derive(Default)]
pub struct InvocationBroker {
    queues: DashMap<String, Arc<Queue>>,
    inflight: DashMap<String, oneshot::Sender<Outcome>>,
    inflight_keys: DashMap<String, String>,
    logs: DashMap<String, Vec<String>>,
    extensions: DashMap<String, Arc<ExtensionEnvironment>>,
}

impl InvocationBroker {
    pub fn new() -> Self {
        Self::default()
    }

    fn queue(&self, key: &str) -> Arc<Queue> {
        self.queues
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Queue::new()))
            .clone()
    }

    /// Submit an invocation for `key`, returning the generated `request_id` and a receiver
    /// that resolves when the guest reports the outcome. `timeout_ms` sets the deadline.
    pub fn submit(
        &self,
        key: &str,
        payload: Vec<u8>,
        invoked_function_arn: &str,
        timeout_ms: i64,
    ) -> (String, oneshot::Receiver<Outcome>) {
        let request_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        self.inflight.insert(request_id.clone(), tx);
        self.inflight_keys
            .insert(request_id.clone(), key.to_owned());
        if let Some(env) = self.extensions.get(key) {
            let phase = env.phase.lock().unwrap();
            if !phase.expected.is_empty()
                && (phase.failed
                    || phase.shutdown
                    || !phase.runtime_ready
                    || phase.registrations.len() != phase.expected.len()
                    || phase.registrations.values().any(|r| !r.ready))
            {
                drop(phase);
                self.fail_unhandled(&request_id, b"extensions not ready".to_vec());
                return (request_id, rx);
            }
        }
        let invocation = PendingInvocation {
            request_id: request_id.clone(),
            payload,
            invoked_function_arn: invoked_function_arn.to_string(),
            deadline_ms: now_ms() + timeout_ms.max(0),
        };
        // Publish to extensions before the runtime can consume and respond. Otherwise a
        // fast runtime could finish while an extension still appears rearmed from Init.
        self.publish_extension_invoke(key, &invocation);
        let queue = self.queue(key);
        {
            let mut pending = queue.pending.lock().unwrap();
            pending.push_back(invocation);
        }
        queue.notify.notify_one();
        (request_id, rx)
    }

    /// Long-poll the next pending invocation for `key`. Resolves immediately when one is
    /// queued, otherwise waits until one arrives. Returns `None` once the environment is
    /// stopped (the Runtime API maps this to HTTP 204).
    pub async fn next(&self, key: &str) -> Option<PendingInvocation> {
        let _poll_guard = self.mark_runtime_ready(key);
        let queue = self.queue(key);
        loop {
            let notified = queue.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !queue.open.load(Ordering::SeqCst) {
                return None;
            }
            {
                let mut pending = queue.pending.lock().unwrap();
                if let Some(invocation) = pending.pop_front() {
                    return Some(invocation);
                }
            }
            // Register the waiter before checking state, so stop cannot lose its wakeup.
            notified.await;
        }
    }

    /// Record managed-runtime output before the invocation outcome is completed.
    pub fn record_logs(&self, request_id: &str, logs: Vec<String>) -> bool {
        if !self.inflight.contains_key(request_id) {
            return false;
        }
        self.logs.insert(request_id.to_string(), logs);
        true
    }

    /// Take the output recorded for one completed invocation.
    pub fn take_logs(&self, request_id: &str) -> Option<Vec<String>> {
        self.logs.remove(request_id).map(|(_, logs)| logs)
    }

    /// Report the outcome of an in-flight invocation, waking its caller. Unknown ids are an
    /// idempotent no-op (the Runtime API returns 202 regardless).
    pub fn complete(&self, request_id: &str, outcome: Outcome) {
        if let Some((_, tx)) = self.inflight.remove(request_id) {
            self.inflight_keys.remove(request_id);
            let _ = tx.send(outcome);
        }
    }

    /// Stop an execution environment: future `next` polls return `None`, and every queued or
    /// in-flight invocation is completed with an `Unhandled` function error.
    pub fn stop(&self, key: &str) {
        self.fail_extension_environment(key);
        let queue = self.queue(key);
        queue.open.store(false, Ordering::SeqCst);
        let drained: Vec<PendingInvocation> = {
            let mut pending = queue.pending.lock().unwrap();
            pending.drain(..).collect()
        };
        for invocation in drained {
            self.fail_unhandled(
                &invocation.request_id,
                b"execution environment stopped".to_vec(),
            );
        }
        let remaining: Vec<String> = self
            .inflight_keys
            .iter()
            .filter(|entry| entry.value() == key)
            .map(|entry| entry.key().clone())
            .collect();
        for request_id in remaining {
            self.fail_unhandled(&request_id, b"execution environment stopped".to_vec());
        }
        queue.notify.notify_waiters();
    }

    /// Complete an in-flight invocation with an `Unhandled` error (timeout, crash, stop).
    pub fn fail_unhandled(&self, request_id: &str, payload: Vec<u8>) {
        self.complete(
            request_id,
            Outcome::Error {
                error_type: FunctionErrorType::Unhandled,
                payload,
            },
        );
    }

    /// Number of currently in-flight invocations (test/observability aid).
    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn submit_next_complete_round_trip() {
        let broker = Arc::new(InvocationBroker::new());
        let (request_id, rx) = broker.submit("fn", b"event".to_vec(), "arn:fn", 5000);

        // A guest polls and receives the exact payload and request id.
        let inv = broker.next("fn").await.unwrap();
        assert_eq!(inv.request_id, request_id);
        assert_eq!(inv.payload, b"event");
        assert_eq!(inv.invoked_function_arn, "arn:fn");
        assert!(inv.deadline_ms >= now_ms());

        broker.complete(&request_id, Outcome::Success(b"result".to_vec()));
        assert_eq!(rx.await.unwrap(), Outcome::Success(b"result".to_vec()));
        assert_eq!(broker.inflight_count(), 0);
    }

    #[tokio::test]
    async fn next_waits_until_submit() {
        let broker = Arc::new(InvocationBroker::new());
        let b2 = broker.clone();
        let poller = tokio::spawn(async move { b2.next("fn").await });
        // Give the poller a moment to start waiting, then submit.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (rid, _rx) = broker.submit("fn", b"x".to_vec(), "arn", 1000);
        let inv = poller.await.unwrap().unwrap();
        assert_eq!(inv.request_id, rid);
    }

    #[tokio::test]
    async fn error_outcome_is_classified() {
        let broker = InvocationBroker::new();
        let (rid, rx) = broker.submit("fn", b"e".to_vec(), "arn", 1000);
        broker.next("fn").await.unwrap();
        broker.complete(
            &rid,
            Outcome::Error {
                error_type: FunctionErrorType::Handled,
                payload: b"{\"errorMessage\":\"boom\"}".to_vec(),
            },
        );
        match rx.await.unwrap() {
            Outcome::Error {
                error_type,
                payload,
            } => {
                assert_eq!(error_type, FunctionErrorType::Handled);
                assert_eq!(payload, b"{\"errorMessage\":\"boom\"}");
            }
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stop_drains_inflight_with_unhandled() {
        let broker = InvocationBroker::new();
        let (_rid, rx) = broker.submit("fn", b"e".to_vec(), "arn", 1000);
        broker.stop("fn");
        // The queued-but-undelivered invocation fails Unhandled.
        match rx.await.unwrap() {
            Outcome::Error { error_type, .. } => {
                assert_eq!(error_type, FunctionErrorType::Unhandled)
            }
            other => panic!("expected unhandled error, got {other:?}"),
        }
        // Polling a stopped environment returns None (HTTP 204).
        assert!(broker.next("fn").await.is_none());
    }

    #[tokio::test]
    async fn stop_fails_already_delivered_invocation_without_affecting_another_environment() {
        let broker = InvocationBroker::new();
        let (_a, rx_a) = broker.submit("a", b"a".to_vec(), "arn:a", 1000);
        let (_b, rx_b) = broker.submit("b", b"b".to_vec(), "arn:b", 1000);
        broker.next("a").await.unwrap();
        broker.next("b").await.unwrap();
        broker.stop("a");
        assert!(matches!(
            rx_a.await.unwrap(),
            Outcome::Error {
                error_type: FunctionErrorType::Unhandled,
                ..
            }
        ));
        assert_eq!(broker.inflight_count(), 1);
        broker.stop("b");
        assert!(matches!(
            rx_b.await.unwrap(),
            Outcome::Error {
                error_type: FunctionErrorType::Unhandled,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn complete_unknown_request_is_noop() {
        let broker = InvocationBroker::new();
        broker.complete("does-not-exist", Outcome::Success(vec![]));
        assert_eq!(broker.inflight_count(), 0);
    }

    #[tokio::test]
    async fn fifo_delivery_order() {
        let broker = InvocationBroker::new();
        let (r1, _a) = broker.submit("fn", b"1".to_vec(), "arn", 1000);
        let (r2, _b) = broker.submit("fn", b"2".to_vec(), "arn", 1000);
        assert_eq!(broker.next("fn").await.unwrap().request_id, r1);
        assert_eq!(broker.next("fn").await.unwrap().request_id, r2);
    }
}

/// One event returned by a blocking Extensions API poll.
#[derive(Debug, Clone)]
pub struct ExtensionEvent {
    pub id: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExtensionError {
    #[error("invalid extension request")]
    BadRequest,
    #[error("extension is not registered for this environment")]
    Forbidden,
    #[error("extension environment failed or timed out")]
    Failed,
}

struct ExtensionRegistration {
    name: String,
    events: HashSet<String>,
    pending: VecDeque<ExtensionEvent>,
    delivered_request: Option<String>,
    ready: bool,
    exited: bool,
    reported_error: bool,
    poll_token: Option<Uuid>,
}

struct ExtensionPhase {
    expected: HashSet<String>,
    registrations: HashMap<String, ExtensionRegistration>,
    function_name: String,
    handler: String,
    function_version: String,
    runtime_ready: bool,
    runtime_poll_tokens: HashSet<Uuid>,
    failed: bool,
    shutdown: bool,
}

struct ExtensionEnvironment {
    phase: Mutex<ExtensionPhase>,
    notify: Notify,
}

impl ExtensionEnvironment {
    fn changed(&self) {
        self.notify.notify_waiters();
    }
}

impl InvocationBroker {
    /// Declare exactly the executable basenames found in /opt/extensions before the guest starts.
    pub fn discover_expected_extensions(
        &self,
        key: &str,
        names: Vec<String>,
        function_name: &str,
        function_version: &str,
        handler: &str,
    ) -> Result<(), ExtensionError> {
        if names.len() > 10 || names.iter().any(|n| !valid_extension_name(n)) {
            return Err(ExtensionError::BadRequest);
        }
        let count = names.len();
        let expected: HashSet<_> = names.into_iter().collect();
        if expected.len() != count {
            return Err(ExtensionError::BadRequest);
        }
        let env = Arc::new(ExtensionEnvironment {
            phase: Mutex::new(ExtensionPhase {
                expected,
                registrations: HashMap::new(),
                function_name: function_name.to_owned(),
                handler: handler.to_owned(),
                function_version: function_version.to_owned(),
                runtime_ready: false,
                runtime_poll_tokens: HashSet::new(),
                failed: false,
                shutdown: false,
            }),
            notify: Notify::new(),
        });
        match self.extensions.entry(key.to_owned()) {
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(env);
                Ok(())
            }
            dashmap::mapref::entry::Entry::Occupied(_) => Err(ExtensionError::BadRequest),
        }
    }

    pub fn register_extension(
        &self,
        key: &str,
        name: &str,
        events: Vec<String>,
    ) -> Result<(String, serde_json::Value), ExtensionError> {
        let env = self.extensions.get(key).ok_or(ExtensionError::Forbidden)?;
        let mut phase = env.phase.lock().unwrap();
        if phase.failed || phase.shutdown {
            return Err(ExtensionError::Failed);
        }
        if !phase.expected.contains(name) || phase.registrations.values().any(|r| r.name == name) {
            return Err(ExtensionError::Forbidden);
        }
        if events.iter().any(|e| e != "INVOKE" && e != "SHUTDOWN")
            || events.len() != events.iter().collect::<HashSet<_>>().len()
        {
            return Err(ExtensionError::BadRequest);
        }
        let id = Uuid::new_v4().to_string();
        phase.registrations.insert(
            id.clone(),
            ExtensionRegistration {
                name: name.to_owned(),
                events: events.into_iter().collect(),
                pending: VecDeque::new(),
                delivered_request: None,
                ready: false,
                exited: false,
                reported_error: false,
                poll_token: None,
            },
        );
        let response = serde_json::json!({
            "functionName": phase.function_name,
            "functionVersion": phase.function_version,
            "handler": phase.handler,
        });
        env.changed();
        Ok((id, response))
    }

    /// Entering Next signals completion of Init or the preceding Invoke event.
    pub async fn next_extension(
        &self,
        key: &str,
        id: &str,
    ) -> Result<ExtensionEvent, ExtensionError> {
        let env = self
            .extensions
            .get(key)
            .ok_or(ExtensionError::Forbidden)?
            .clone();
        let token = Uuid::new_v4();
        {
            let mut phase = env.phase.lock().unwrap();
            if phase.failed && !phase.shutdown {
                return Err(ExtensionError::Failed);
            }
            let registration = phase
                .registrations
                .get_mut(id)
                .ok_or(ExtensionError::Forbidden)?;
            if registration.exited || registration.reported_error {
                return Err(ExtensionError::Failed);
            }
            if registration.poll_token.is_some() {
                return Err(ExtensionError::BadRequest);
            }
            registration.poll_token = Some(token);
            registration.ready = true;
            registration.delivered_request = None;
            env.changed();
        }
        let _poll_guard = ExtensionPollGuard {
            env: env.clone(),
            id: id.to_owned(),
            token,
        };
        loop {
            let notified = env.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut phase = env.phase.lock().unwrap();
                if phase.failed && !phase.shutdown {
                    return Err(ExtensionError::Failed);
                }
                let shutdown = phase.shutdown;
                let registration = phase
                    .registrations
                    .get_mut(id)
                    .ok_or(ExtensionError::Forbidden)?;
                if registration.exited || registration.reported_error {
                    return Err(ExtensionError::Failed);
                }
                if let Some(event) = registration.pending.pop_front() {
                    registration.ready = false;
                    registration.poll_token = None;
                    if event.payload["eventType"] == "INVOKE" {
                        registration.delivered_request =
                            event.payload["requestId"].as_str().map(str::to_owned);
                    }
                    return Ok(event);
                }
                if shutdown {
                    return Err(ExtensionError::Failed);
                }
            }
            notified.await;
        }
    }

    pub fn report_extension_error(&self, key: &str, id: &str) -> Result<(), ExtensionError> {
        let env = self.extensions.get(key).ok_or(ExtensionError::Forbidden)?;
        let mut phase = env.phase.lock().unwrap();
        let registration = phase
            .registrations
            .get_mut(id)
            .ok_or(ExtensionError::Forbidden)?;
        if registration.reported_error {
            return Err(ExtensionError::Failed);
        }
        registration.reported_error = true;
        if phase.failed {
            return Err(ExtensionError::Failed);
        }
        phase.failed = true;
        env.changed();
        Ok(())
    }

    pub async fn wait_init_ready(
        &self,
        key: &str,
        deadline: Instant,
    ) -> Result<(), ExtensionError> {
        self.wait_phase(key, deadline, |p| {
            p.runtime_ready
                && p.registrations.len() == p.expected.len()
                && p.registrations.values().all(|r| r.ready)
        })
        .await
    }

    pub async fn wait_extensions_rearmed(
        &self,
        key: &str,
        request_id: &str,
        deadline: Instant,
    ) -> Result<(), ExtensionError> {
        self.wait_phase(key, deadline, |p| {
            (p.expected.is_empty() || p.runtime_ready)
                && p.registrations.values().all(|r| {
                    r.delivered_request.as_deref() != Some(request_id)
                        && r.ready
                        && r.poll_token.is_some()
                })
        })
        .await
    }

    async fn wait_phase(
        &self,
        key: &str,
        deadline: Instant,
        ready: impl Fn(&ExtensionPhase) -> bool,
    ) -> Result<(), ExtensionError> {
        let env = self
            .extensions
            .get(key)
            .ok_or(ExtensionError::Forbidden)?
            .clone();
        loop {
            let notified = env.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let phase = env.phase.lock().unwrap();
                if phase.failed {
                    return Err(ExtensionError::Failed);
                }
                if ready(&phase) {
                    return Ok(());
                }
            }
            tokio::time::timeout_at(deadline, notified)
                .await
                .map_err(|_| ExtensionError::Failed)?;
        }
    }

    pub fn begin_shutdown(&self, key: &str, reason: &str, deadline_ms: i64) {
        if let Some(env) = self.extensions.get(key) {
            let mut phase = env.phase.lock().unwrap();
            phase.shutdown = true;
            for r in phase.registrations.values_mut() {
                if r.events.contains("SHUTDOWN") && !r.exited {
                    r.pending.push_back(ExtensionEvent {
                        id: Uuid::new_v4().to_string(),
                        payload: serde_json::json!({"eventType":"SHUTDOWN","shutdownReason":reason,"deadlineMs":deadline_ms}),
                    });
                }
            }
            env.changed();
        }
    }

    pub fn extension_exited(&self, key: &str, name: &str, _success: bool) {
        if let Some(env) = self.extensions.get(key) {
            let mut phase = env.phase.lock().unwrap();
            if let Some(r) = phase.registrations.values_mut().find(|r| r.name == name) {
                r.exited = true;
            }
            if !phase.shutdown {
                phase.failed = true;
            }
            env.changed();
        }
    }

    pub async fn wait_shutdown_done(
        &self,
        key: &str,
        deadline: Instant,
    ) -> Result<(), ExtensionError> {
        self.wait_phase(key, deadline, |p| {
            p.registrations.values().all(|r| r.exited)
        })
        .await
    }

    pub fn has_extensions(&self, key: &str) -> bool {
        self.extensions
            .get(key)
            .is_some_and(|env| !env.phase.lock().unwrap().expected.is_empty())
    }

    pub fn environment_healthy(&self, key: &str) -> bool {
        let Some(queue) = self.queues.get(key) else {
            return false;
        };
        if !queue.open.load(Ordering::SeqCst) {
            return false;
        }
        self.extensions.get(key).is_some_and(|env| {
            let phase = env.phase.lock().unwrap();
            !phase.failed
                && !phase.shutdown
                && phase.registrations.len() == phase.expected.len()
                && (phase.expected.is_empty() || phase.runtime_ready)
                && phase
                    .registrations
                    .values()
                    .all(|r| !r.exited && !r.reported_error && r.ready && r.poll_token.is_some())
        })
    }

    pub fn cleanup_extensions(&self, key: &str) {
        self.extensions.remove(key);
    }

    fn mark_runtime_ready(&self, key: &str) -> Option<RuntimePollGuard> {
        let env = self.extensions.get(key)?.clone();
        let token = Uuid::new_v4();
        {
            let mut phase = env.phase.lock().unwrap();
            phase.runtime_ready = true;
            phase.runtime_poll_tokens.insert(token);
            env.changed();
        }
        Some(RuntimePollGuard { env, token })
    }

    fn fail_extension_environment(&self, key: &str) {
        if let Some(env) = self.extensions.get(key) {
            env.phase.lock().unwrap().failed = true;
            env.changed();
        }
    }

    fn publish_extension_invoke(&self, key: &str, invocation: &PendingInvocation) {
        if let Some(env) = self.extensions.get(key) {
            let mut phase = env.phase.lock().unwrap();
            for r in phase.registrations.values_mut() {
                if r.events.contains("INVOKE") && !r.exited {
                    r.pending.push_back(ExtensionEvent {
                        id: Uuid::new_v4().to_string(),
                        payload: serde_json::json!({
                            "eventType":"INVOKE", "deadlineMs":invocation.deadline_ms,
                            "requestId":invocation.request_id,
                            "invokedFunctionArn":invocation.invoked_function_arn,
                            "tracing":{"type":"X-Amzn-Trace-Id","value":""},
                        }),
                    });
                    r.ready = false;
                }
            }
            env.changed();
        }
    }
}

fn valid_extension_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

/// Releasing a canceled HTTP longpoll withdraws its readiness signal.
struct ExtensionPollGuard {
    env: Arc<ExtensionEnvironment>,
    id: String,
    token: Uuid,
}

impl Drop for ExtensionPollGuard {
    fn drop(&mut self) {
        let mut phase = self.env.phase.lock().unwrap();
        if let Some(registration) = phase.registrations.get_mut(&self.id) {
            if registration.poll_token == Some(self.token) {
                registration.poll_token = None;
                registration.ready = false;
                self.env.changed();
            }
        }
    }
}

struct RuntimePollGuard {
    env: Arc<ExtensionEnvironment>,
    token: Uuid,
}

impl Drop for RuntimePollGuard {
    fn drop(&mut self) {
        let mut phase = self.env.phase.lock().unwrap();
        phase.runtime_poll_tokens.remove(&self.token);
        phase.runtime_ready = !phase.runtime_poll_tokens.is_empty();
        self.env.changed();
    }
}
