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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_busy_failure_recovers_only_committed_state_and_failed_restore_stays_closed() {
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(StateDb::open(root.path().join("private/state.sqlite3")).unwrap());
    let make_handler = || {
        S3Handler::with_storage_keys(
            Weak::new(),
            state.clone(),
            crate::encryption::StorageKeys::with_master(&state, &[21; 32]).unwrap(),
        )
        .unwrap()
    };
    let handler = make_handler();
    assert_eq!(
        handler
            .handle(request(Method::PUT, "/recover-bucket", ""))
            .await
            .status(),
        200
    );
    assert_eq!(
        handler
            .handle(request(Method::PUT, "/recover-bucket/key", "old"))
            .await
            .status(),
        200
    );
    let mut connection = state.connection().unwrap();
    let original: Vec<u8> = connection.query_row("SELECT payload FROM s3_entries WHERE account='000000000000' AND bucket='recover-bucket' AND kind='bucket' AND key=''", [], |row| row.get(0)).unwrap();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    // A real independent SQLite writer survives the normal five-second busy timeout.
    let failed = tokio::time::timeout(
        Duration::from_secs(8),
        handler.handle(request(Method::PUT, "/recover-bucket/key", "uncommitted")),
    )
    .await
    .unwrap();
    assert_eq!(failed.status(), 500);
    assert!(handler.poisoned.load(std::sync::atomic::Ordering::Acquire));
    transaction.rollback().unwrap();
    connection
        .execute(
            "UPDATE s3_entries SET payload=?1 WHERE bucket='recover-bucket' AND kind='bucket'",
            [b"invalid-json".as_slice()],
        )
        .unwrap();
    assert_eq!(
        handler
            .handle(request(Method::GET, "/recover-bucket/key", ""))
            .await
            .status(),
        500
    );
    assert!(
        handler.poisoned.load(std::sync::atomic::Ordering::Acquire),
        "a failed restore must not reopen dirty RAM reads"
    );
    connection
        .execute(
            "UPDATE s3_entries SET payload=?1 WHERE bucket='recover-bucket' AND kind='bucket'",
            [&original],
        )
        .unwrap();
    let response = handler
        .handle(request(Method::GET, "/recover-bucket/key", ""))
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        "old"
    );
    assert!(!handler.poisoned.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(
        handler
            .handle(request(
                Method::PUT,
                "/recover-bucket/key",
                "committed-retry"
            ))
            .await
            .status(),
        200
    );
    // Failed namespace creation must be discarded too, rather than left in the map.
    connection.execute_batch("CREATE TRIGGER s3_reject_bucket BEFORE INSERT ON s3_entries WHEN NEW.bucket='failed-bucket' BEGIN SELECT RAISE(ABORT,'forced failure'); END;").unwrap();
    assert_eq!(
        handler
            .handle(request(Method::PUT, "/failed-bucket", ""))
            .await
            .status(),
        500
    );
    connection
        .execute_batch("DROP TRIGGER s3_reject_bucket;")
        .unwrap();
    assert_eq!(
        handler
            .handle(request(Method::GET, "/failed-bucket", ""))
            .await
            .status(),
        404
    );
    assert!(!handler.poisoned.load(std::sync::atomic::Ordering::Acquire));
    drop(handler);
    drop(connection);
    let reopened = make_handler();
    let response = reopened
        .handle(request(Method::GET, "/recover-bucket/key", ""))
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        "committed-retry"
    );
    assert_eq!(
        reopened
            .handle(request(Method::GET, "/failed-bucket", ""))
            .await
            .status(),
        404
    );
}
