//! Reads must wait for their bucket's durable commit while independent buckets stay usable.
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_state::StateDb;
use rusqlite::TransactionBehavior;

use super::S3Handler;

fn request(method: Method, uri: &str, body: &'static str) -> ServiceRequest {
    ServiceRequest {
        method,
        uri: uri.parse().unwrap(),
        headers: HeaderMap::new(),
        body: Bytes::from_static(body.as_bytes()),
        region: "us-east-1".into(),
        account_id: "000000000000".into(),
        request_id: "s3-commit-visibility".into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_observe_commits_and_independent_bucket_does_not_wait_for_sql_writer() {
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(StateDb::open(root.path().join("private/state.sqlite3")).unwrap());
    let handler = Arc::new(
        S3Handler::with_storage_keys(
            Weak::new(),
            state.clone(),
            crate::encryption::StorageKeys::ephemeral().unwrap(),
        )
        .unwrap(),
    );
    for name in ["pending-bucket", "independent-bucket"] {
        assert_eq!(
            handler
                .handle(request(Method::PUT, &format!("/{name}"), ""))
                .await
                .status(),
            200
        );
        assert_eq!(
            handler
                .handle(request(Method::PUT, &format!("/{name}/key"), "old"))
                .await
                .status(),
            200
        );
    }
    let mut connection = state.connection().unwrap();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let writer_handler = handler.clone();
    let writer = tokio::spawn(async move {
        let mut req = request(Method::PUT, "/pending-bucket/key", "new");
        req.headers
            .insert("x-amz-meta-revision", "new".parse().unwrap());
        writer_handler.handle(req).await
    });
    // This observation puts the assertion after the actual in-memory mutation, before
    // SQLite can commit. HTTP readers must still be excluded from this intermediate state.
    let bucket = handler.store.get("000000000000", "pending-bucket").unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if bucket
                .read()
                .await
                .objects
                .get("key")
                .is_some_and(|object| {
                    object
                        .metadata
                        .get("revision")
                        .is_some_and(|value| value == "new")
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("PUT reached in-memory mutation before the blocked SQL commit");
    let reader_handler = handler.clone();
    let mut reader = tokio::spawn(async move {
        reader_handler
            .handle(request(Method::GET, "/pending-bucket/key", ""))
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut reader)
            .await
            .is_err(),
        "same-bucket HTTP read exposed an uncommitted mutation"
    );
    let independent = tokio::time::timeout(
        Duration::from_secs(1),
        handler.handle(request(Method::GET, "/independent-bucket/key", "")),
    )
    .await
    .expect("independent bucket read was blocked by another bucket's SQL commit");
    assert_eq!(independent.status(), 200);
    assert_eq!(
        axum::body::to_bytes(independent.into_body(), 1024)
            .await
            .unwrap(),
        Bytes::from_static(b"old")
    );
    assert!(!writer.is_finished());
    transaction.commit().unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), writer)
            .await
            .unwrap()
            .unwrap()
            .status(),
        200
    );
    let committed = tokio::time::timeout(Duration::from_secs(2), reader)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.status(), 200);
    assert_eq!(committed.headers()["x-amz-meta-revision"], "new");
    assert_eq!(
        axum::body::to_bytes(committed.into_body(), 1024)
            .await
            .unwrap(),
        Bytes::from_static(b"new")
    );
}
