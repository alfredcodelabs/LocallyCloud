//! Per-environment X-Ray daemon endpoints.
//!
//! The X-Ray SDKs send each segment or subsegment document as one UDP datagram prefixed by the
//! daemon header `{"format": "json", "version": 1}` and a newline. Every execution environment
//! (`Active` or `PassThrough`, as Lambda runs the daemon for all of them) gets its own socket
//! (an ephemeral port on `127.0.0.1`, or a fixed port inside the isolated network namespace of a
//! VPC guest), so the socket identifies the account and Region the documents belong to, and
//! stopping the environment closes it. A loopback port is reachable by any local process, so
//! the receiver only forwards documents whose `trace_id` is a sampled `Root` the executor handed
//! to that environment ([`TraceRoots`]). Documents are forwarded as `PutTraceSegments` through
//! the internal dispatcher, so X-Ray applies the same validation, scope and merge rules as for
//! API callers.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use locallycloud_core::registry::ServiceRegistry;
use tokio::net::UdpSocket;
use uuid::Uuid;

/// The X-Ray daemon's receive buffer (`Socket.BufferSizeKB` defaults to 64).
pub(crate) const MAX_DATAGRAM_BYTES: usize = 64 * 1024;
/// The daemon uploads at most 50 documents per `PutTraceSegments` call.
const MAX_BATCH_DOCUMENTS: usize = 50;
/// Bound on the JSON-encoded documents of one internal call (X-Ray accepts larger bodies).
const MAX_BATCH_BYTES: usize = 1024 * 1024;
/// Roots remembered per environment (most recent first to survive).
const MAX_TRACE_ROOTS: usize = 64;
/// How long a root stays accepted after its invocation ended, for late subsegment flushes.
const ROOT_GRACE: Duration = Duration::from_secs(5 * 60);

/// The sampled trace roots an environment was handed: a bounded list shared between the
/// executor (which admits a root before submitting the invocation and finishes it when the
/// invocation ends) and the environment's receiver. The lock is never held across `.await`.
#[derive(Default)]
pub(crate) struct TraceRoots {
    /// `(root, accepted until)`; `None` while the invocation is in flight. Oldest first.
    entries: Mutex<VecDeque<(String, Option<Instant>)>>,
}

impl TraceRoots {
    fn entries(&self) -> std::sync::MutexGuard<'_, VecDeque<(String, Option<Instant>)>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Accept documents of `root` until [`finish`](Self::finish) plus the grace period.
    pub(crate) fn admit(&self, root: &str) {
        let mut entries = self.entries();
        entries.retain(|(known, _)| known != root);
        if entries.len() >= MAX_TRACE_ROOTS {
            entries.pop_front();
        }
        entries.push_back((root.to_owned(), None));
    }

    /// The invocation of `root` ended; keep accepting its late documents for a while.
    pub(crate) fn finish(&self, root: &str) {
        self.finish_at(root, Instant::now());
    }

    fn finish_at(&self, root: &str, now: Instant) {
        for (known, until) in self.entries().iter_mut() {
            if known == root {
                *until = Some(now + ROOT_GRACE);
            }
        }
    }

    fn accepts(&self, root: &str) -> bool {
        self.accepts_at(root, Instant::now())
    }

    fn accepts_at(&self, root: &str, now: Instant) -> bool {
        self.entries()
            .iter()
            .any(|(known, until)| known == root && until.is_none_or(|until| now < until))
    }
}

/// A root admitted for one invocation; dropping it finishes the root, so an invocation whose
/// future is dropped (a disconnected synchronous caller) still starts the grace period instead
/// of leaving the root in flight forever.
pub(crate) struct AdmittedRoot {
    roots: Arc<TraceRoots>,
    root: String,
}

impl AdmittedRoot {
    pub(crate) fn new(roots: Arc<TraceRoots>, root: &str) -> Self {
        roots.admit(root);
        Self {
            roots,
            root: root.to_owned(),
        }
    }
}

impl Drop for AdmittedRoot {
    fn drop(&mut self) {
        self.roots.finish(&self.root);
    }
}

/// Length of `document` encoded as a JSON string by `serde_json`, without allocating it.
fn json_string_len(document: &str) -> usize {
    let escaped: usize = document
        .bytes()
        .map(|byte| match byte {
            b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 0x08 | 0x0c => 2,
            0x00..=0x1f => 6,
            _ => 1,
        })
        .sum();
    escaped + 2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatagramError {
    TooLarge,
    MissingHeader,
    InvalidHeader,
    EmptyDocument,
    NotUtf8,
    /// The document's `trace_id` is not a root handed to this environment.
    ForeignTrace,
}

/// The `trace_id` field of a segment document, if it has one.
fn document_trace_id(document: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct TraceId {
        trace_id: Option<String>,
    }
    serde_json::from_str::<TraceId>(document).ok()?.trace_id
}

/// Parse a datagram and keep its document only when it belongs to one of `roots`.
fn accepted_document<'a>(datagram: &'a [u8], roots: &TraceRoots) -> Result<&'a str, DatagramError> {
    let document = parse_datagram(datagram)?;
    match document_trace_id(document) {
        Some(trace_id) if roots.accepts(&trace_id) => Ok(document),
        _ => Err(DatagramError::ForeignTrace),
    }
}

/// Split one datagram into its daemon header and segment document, as the daemon does: the
/// header is the text before the first newline and must be `{"format":"json","version":1}`
/// (format compared case-insensitively). Surrounding whitespace of the document is dropped.
pub(crate) fn parse_datagram(datagram: &[u8]) -> Result<&str, DatagramError> {
    if datagram.len() > MAX_DATAGRAM_BYTES {
        return Err(DatagramError::TooLarge);
    }
    let split = datagram
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(DatagramError::MissingHeader)?;
    let header: serde_json::Value =
        serde_json::from_slice(&datagram[..split]).map_err(|_| DatagramError::InvalidHeader)?;
    let valid_header = header
        .get("format")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|format| format.eq_ignore_ascii_case("json"))
        && header.get("version").and_then(serde_json::Value::as_i64) == Some(1);
    if !valid_header {
        return Err(DatagramError::InvalidHeader);
    }
    let document = std::str::from_utf8(&datagram[split + 1..])
        .map_err(|_| DatagramError::NotUtf8)?
        .trim();
    if document.is_empty() {
        return Err(DatagramError::EmptyDocument);
    }
    Ok(document)
}

/// Receive documents on `socket` until the task is aborted, forwarding each burst of queued
/// datagrams of `roots` as one `PutTraceSegments` call in the socket's scope. Idle cost is one
/// parked task.
pub(crate) fn serve(
    socket: UdpSocket,
    roots: Arc<TraceRoots>,
    registry: Weak<ServiceRegistry>,
    account: String,
    region: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // One spare byte detects datagrams above the limit instead of truncating them.
        let mut buffer = vec![0u8; MAX_DATAGRAM_BYTES + 1];
        let mut dropped = 0u64;
        loop {
            let received = match socket.recv(&mut buffer).await {
                Ok(received) => received,
                Err(error) => {
                    tracing::warn!(%error, "X-Ray daemon socket closed");
                    return;
                }
            };
            let mut batch = Vec::new();
            let mut batch_bytes = 0;
            let mut reads = 0;
            let mut pending = Some(received);
            while let Some(received) = pending.take() {
                reads += 1;
                match accepted_document(&buffer[..received], &roots) {
                    Ok(document) => {
                        let encoded = json_string_len(document);
                        if batch_bytes + encoded > MAX_BATCH_BYTES && !batch.is_empty() {
                            put_trace_segments(
                                &registry,
                                &account,
                                &region,
                                std::mem::take(&mut batch),
                            )
                            .await;
                            batch_bytes = 0;
                        }
                        batch_bytes += encoded;
                        batch.push(document.to_owned());
                    }
                    Err(reason) => {
                        dropped = dropped.saturating_add(1);
                        tracing::debug!(?reason, dropped, "X-Ray daemon datagram dropped");
                    }
                }
                // Bounded so a flood of datagrams still yields to the runtime between bursts.
                if reads < MAX_BATCH_DOCUMENTS {
                    pending = socket.try_recv(&mut buffer).ok();
                }
            }
            if !batch.is_empty() {
                put_trace_segments(&registry, &account, &region, batch).await;
            }
        }
    })
}

/// Store `documents` through X-Ray `PutTraceSegments` in the given scope. Delivery is best
/// effort, as with the UDP daemon: failures are logged at debug level and dropped.
pub(crate) async fn put_trace_segments(
    registry: &Weak<ServiceRegistry>,
    account: &str,
    region: &str,
    documents: Vec<String>,
) {
    let Some(dispatcher) = registry
        .upgrade()
        .and_then(|registry| registry.internal_dispatcher())
    else {
        tracing::debug!("X-Ray segments dropped: internal dispatcher unavailable");
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // The credential scope only routes the call; the trusted scope comes from the socket.
    let Ok(authorization) = HeaderValue::from_str(&format!(
        "AWS4-HMAC-SHA256 Credential=local/19700101/{region}/xray/aws4_request"
    )) else {
        return;
    };
    headers.insert(http::header::AUTHORIZATION, authorization);
    let count = documents.len();
    let body = serde_json::json!({ "TraceSegmentDocuments": documents }).to_string();
    let response = dispatcher
        .dispatch_scoped(
            &Method::POST,
            &Uri::from_static("/TraceSegments"),
            &headers,
            Bytes::from(body),
            &Uuid::new_v4().to_string(),
            account,
            region,
        )
        .await;
    let status = response.status();
    let unprocessed = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|body| body["UnprocessedTraceSegments"].as_array().map(Vec::len))
        .unwrap_or(0);
    if !status.is_success() || unprocessed > 0 {
        tracing::debug!(%status, count, unprocessed, "X-Ray segments not fully stored");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{"trace_id":"1-5759e988-bd862e3fe1be46a994272793","id":"defdfd9912dc5a56","start_time":1.0,"end_time":2.0,"name":"x"}"#;

    #[test]
    fn parses_header_and_document() {
        let datagram = format!("{{\"format\": \"json\", \"version\": 1}}\n{DOC}");
        assert_eq!(parse_datagram(datagram.as_bytes()), Ok(DOC));
        // `cat segment.txt > /dev/udp/...` sends a trailing newline; the format is
        // compared case-insensitively, like the daemon.
        let datagram = format!("{{\"format\":\"JSON\",\"version\":1}}\n{DOC}\n");
        assert_eq!(parse_datagram(datagram.as_bytes()), Ok(DOC));
    }

    #[test]
    fn rejects_malformed_datagrams() {
        let header = "{\"format\": \"json\", \"version\": 1}\n";
        let oversized = format!("{header}{}", " ".repeat(MAX_DATAGRAM_BYTES));
        for (datagram, expected) in [
            (DOC.as_bytes().to_vec(), DatagramError::MissingHeader),
            (
                format!("{{\"format\":\"json\",\"version\":2}}\n{DOC}").into_bytes(),
                DatagramError::InvalidHeader,
            ),
            (
                format!("{{\"format\":\"xml\",\"version\":1}}\n{DOC}").into_bytes(),
                DatagramError::InvalidHeader,
            ),
            (
                format!("not json\n{DOC}").into_bytes(),
                DatagramError::InvalidHeader,
            ),
            (header.as_bytes().to_vec(), DatagramError::EmptyDocument),
            (
                format!("{header}  \n").into_bytes(),
                DatagramError::EmptyDocument,
            ),
            (
                [header.as_bytes(), &[0xff, 0xfe, b'{']].concat(),
                DatagramError::NotUtf8,
            ),
            (oversized.into_bytes(), DatagramError::TooLarge),
            (
                vec![0, 159, 146, 150, b'\n', 1, 2],
                DatagramError::InvalidHeader,
            ),
        ] {
            assert_eq!(parse_datagram(&datagram), Err(expected));
        }
    }

    #[test]
    fn only_documents_of_admitted_roots_are_accepted() {
        let roots = TraceRoots::default();
        let datagram = |trace_id: &str| {
            format!(
                "{{\"format\": \"json\", \"version\": 1}}\n{{\"trace_id\":\"{trace_id}\",\"id\":\"defdfd9912dc5a56\"}}"
            )
        };
        let own = "1-5759e988-bd862e3fe1be46a994272793";
        let foreign = "1-5759e988-000000000000000000000000";
        assert_eq!(
            accepted_document(datagram(own).as_bytes(), &roots),
            Err(DatagramError::ForeignTrace)
        );
        roots.admit(own);
        assert!(accepted_document(datagram(own).as_bytes(), &roots).is_ok());
        assert_eq!(
            accepted_document(datagram(foreign).as_bytes(), &roots),
            Err(DatagramError::ForeignTrace)
        );
        let header = "{\"format\": \"json\", \"version\": 1}\n";
        for document in ["{\"id\":\"defdfd9912dc5a56\"}", "[1]", "{\"trace_id\":7}"] {
            assert_eq!(
                accepted_document(format!("{header}{document}").as_bytes(), &roots),
                Err(DatagramError::ForeignTrace)
            );
        }
    }

    #[test]
    fn json_string_len_matches_serde_encoding() {
        let mut every_byte: String = (0u8..0x80).map(char::from).collect();
        every_byte.push_str("é\u{2028}😀");
        for document in [DOC, "", "a\"b\\c\n\t\r", every_byte.as_str()] {
            assert_eq!(
                json_string_len(document),
                serde_json::Value::from(document).to_string().len(),
                "{document:?}"
            );
        }
    }

    #[tokio::test]
    async fn dropping_an_admitted_root_finishes_it() {
        let roots = Arc::new(TraceRoots::default());
        let admitted = AdmittedRoot::new(roots.clone(), "dropped");
        assert!(roots.accepts("dropped"));
        assert_eq!(roots.entries()[0].1, None);
        // An invocation future dropped while awaiting (a disconnected caller) never reaches
        // the normal finish; its guard does.
        let (parked, wait) = tokio::sync::oneshot::channel();
        let invocation = tokio::spawn(async move {
            let _admitted = admitted;
            let _ = parked.send(());
            std::future::pending::<()>().await;
        });
        wait.await.unwrap();
        assert_eq!(roots.entries()[0].1, None);
        invocation.abort();
        assert!(invocation.await.unwrap_err().is_cancelled());
        let until = roots.entries()[0].1.expect("root finished on drop");
        assert!(until <= Instant::now() + ROOT_GRACE);
        assert!(roots.accepts("dropped"));
        assert!(!roots.accepts_at("dropped", until));
    }

    #[test]
    fn roots_are_bounded_and_expire_after_the_grace_period() {
        let roots = TraceRoots::default();
        let now = Instant::now();
        roots.admit("first");
        roots.finish_at("first", now);
        assert!(roots.accepts_at("first", now + ROOT_GRACE - Duration::from_secs(1)));
        assert!(!roots.accepts_at("first", now + ROOT_GRACE));
        // In-flight roots never expire; re-admitting a finished root makes it live again.
        roots.admit("first");
        assert!(roots.accepts_at("first", now + ROOT_GRACE * 10));
        for index in 0..MAX_TRACE_ROOTS {
            roots.admit(&format!("root-{index}"));
        }
        assert_eq!(roots.entries().len(), MAX_TRACE_ROOTS);
        assert!(!roots.accepts("first"));
        assert!(roots.accepts("root-0"));
        assert!(roots.accepts(&format!("root-{}", MAX_TRACE_ROOTS - 1)));
    }
}
