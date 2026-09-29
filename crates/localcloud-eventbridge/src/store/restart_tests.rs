use super::*;
use crate::events::{EventsService, RequestContext};
use crate::http_client::CurlHttpClient;
use crate::model::ArchivedEvent;
use crate::schedule::SystemClock;
use rusqlite::params;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::Weak;

#[tokio::test]
async fn connection_and_destination_restore_without_plaintext_secrets() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("state.sqlite3");
    let db = Arc::new(StateDb::open(path.clone()).unwrap());
    let key = [7u8; 32];
    let store = Arc::new(
        EbStore::with_state_and_crypto(
            db.clone(),
            Some(ConnectionCrypto::from_master(&key).unwrap()),
        )
        .unwrap(),
    );
    let service = EventsService::new(
        store.clone(),
        Weak::new(),
        Arc::new(SystemClock),
        Arc::new(CurlHttpClient),
    );
    let ctx = RequestContext {
        account: "000000000001",
        region: "us-west-2",
        request_id: "r",
    };
    let secret = "sensitive-eventbridge-api-key-12345";
    let created = service.dispatch("CreateConnection", &ctx, &json!({
            "Name":"auth","AuthorizationType":"API_KEY",
            "AuthParameters":{"ApiKeyAuthParameters":{"ApiKeyName":"x-api-key","ApiKeyValue":secret}}
        })).await.unwrap();
    let connection_arn = created["ConnectionArn"].as_str().unwrap();
    service
        .dispatch(
            "CreateApiDestination",
            &ctx,
            &json!({
                "Name":"sink","ConnectionArn":connection_arn,
                "InvocationEndpoint":"https://example.test/events","HttpMethod":"POST"
            }),
        )
        .await
        .unwrap();
    let sealed: Vec<u8> = db
        .connection()
        .unwrap()
        .query_row(
            "SELECT sealed FROM events_connections WHERE account=?1 AND region=?2 AND name='auth'",
            params![ctx.account, ctx.region],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!sealed
        .windows(secret.len())
        .any(|window| window == secret.as_bytes()));
    for disk in [path.clone(), path.with_extension("sqlite3-wal")] {
        if disk.exists() {
            let bytes = std::fs::read(disk).unwrap();
            assert!(!bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()));
        }
    }
    drop(service);
    drop(store);
    assert!(EbStore::with_state_and_crypto(db.clone(), None).is_err());
    assert!(EbStore::with_state_and_crypto(
        db.clone(),
        Some(ConnectionCrypto::from_master(&[8u8; 32]).unwrap())
    )
    .is_err());
    let reopened =
        EbStore::with_state_and_crypto(db, Some(ConnectionCrypto::from_master(&key).unwrap()))
            .unwrap();
    let scope = reopened.scope(ctx.account, ctx.region).await;
    let guard = scope.read().await;
    assert_eq!(
        guard.connections["auth"].auth_parameters["ApiKeyAuthParameters"]["ApiKeyValue"],
        secret
    );
    assert_eq!(
        guard.api_destinations["sink"].connection_arn,
        connection_arn
    );
}

#[tokio::test]
async fn failed_delivery_keeps_accepted_event_in_outbox() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
    let store = Arc::new(EbStore::with_state(db.clone()).unwrap());
    let service = EventsService::new(
        store.clone(),
        Weak::new(),
        Arc::new(SystemClock),
        Arc::new(CurlHttpClient),
    );
    let ctx = RequestContext {
        account: "000000000001",
        region: "us-west-2",
        request_id: "r",
    };
    service
        .dispatch(
            "PutRule",
            &ctx,
            &json!({"Name":"retry", "EventPattern":"{\"source\":[\"app\"]}"}),
        )
        .await
        .unwrap();
    {
        let scope = store.scope(ctx.account, ctx.region).await;
        let mut guard = scope.write().await;
        guard
            .buses
            .get_mut("default")
            .unwrap()
            .rules
            .get_mut("retry")
            .unwrap()
            .targets
            .push(crate::model::Target {
                id: "t".into(),
                arn: "arn:aws:sqs:us-west-2:000000000001:missing".into(),
                role_arn: None,
                input: None,
                input_path: None,
                input_transformer: None,
                sqs_parameters: None,
                retry: crate::model::RetryPolicy {
                    maximum_attempts: 0,
                    maximum_age_seconds: None,
                },
                dead_letter_arn: None,
                extra: Value::Null,
            });
    }
    store.persist_buses(ctx.account, ctx.region).await.unwrap();
    let response = service
        .dispatch(
            "PutEvents",
            &ctx,
            &json!({"Entries":[{"Source":"app","DetailType":"x","Detail":"{}"}]}),
        )
        .await
        .unwrap();
    assert_eq!(response["FailedEntryCount"], 0);
    assert_eq!(store.pending_fanouts().await.unwrap().len(), 1);
    drop(service);
    drop(store);
    assert_eq!(
        EbStore::with_state(db)
            .unwrap()
            .pending_fanouts()
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn acknowledged_rule_and_pending_fanout_survive_reopen() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
    let store = Arc::new(EbStore::with_state(db.clone()).unwrap());
    let service = EventsService::new(
        store.clone(),
        Weak::new(),
        Arc::new(SystemClock),
        Arc::new(CurlHttpClient),
    );
    let ctx = RequestContext {
        account: "000000000001",
        region: "us-west-2",
        request_id: "r",
    };
    service
        .dispatch(
            "PutRule",
            &ctx,
            &json!({"Name":"persistent", "EventPattern":"{}"}),
        )
        .await
        .unwrap();
    let rule = store
        .scope(ctx.account, ctx.region)
        .await
        .read()
        .await
        .buses["default"]
        .rules["persistent"]
        .clone();
    store
        .enqueue_fanout(PendingFanout {
            id: "pending".into(),
            account: ctx.account.into(),
            region: ctx.region.into(),
            event: json!({"id":"pending"}),
            rules: vec![rule],
        })
        .await
        .unwrap();
    drop(service);
    drop(store);
    let reopened = EbStore::with_state(db).unwrap();
    let scope = reopened.scope(ctx.account, ctx.region).await;
    assert!(scope.read().await.buses["default"]
        .rules
        .contains_key("persistent"));
    let pending = reopened.pending_fanouts().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].rules[0].name, "persistent");
}

#[tokio::test]
async fn archive_rows_and_replay_snapshot_survive_reopen_and_archive_deletion() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
    let store = EbStore::with_state(db.clone()).unwrap();
    let account = "000000000001";
    let region = "us-west-2";
    let now = OffsetDateTime::now_utc();
    let scope = store.scope(account, region).await;
    scope.write().await.archives.insert(
        "source".into(),
        Archive {
            name: "source".into(),
            arn: format!("arn:aws:events:{region}:{account}:archive/source"),
            source_arn: format!("arn:aws:events:{region}:{account}:event-bus/default"),
            description: None,
            event_pattern: None,
            retention_days: 0,
            tags: BTreeMap::new(),
            events: Vec::new(),
        },
    );
    store
        .persist_archive(account, region, "source")
        .await
        .unwrap();
    let first = json!({"id":"first","source":"test"});
    let second = json!({"id":"second","source":"test"});
    let accepted = PendingFanout {
        id: "first".into(),
        account: account.into(),
        region: region.into(),
        event: first.clone(),
        rules: Vec::new(),
    };
    store
        .accept_event(
            accepted,
            vec![(
                "source".into(),
                ArchivedEvent {
                    event: first.clone(),
                    time: now,
                },
            )],
        )
        .await
        .unwrap();
    let restored = EbStore::with_state(db.clone()).unwrap();
    let restored_scope = restored.scope(account, region).await;
    let restored_guard = restored_scope.read().await;
    assert!(restored_guard.archives["source"].events.is_empty());
    drop(restored_guard);
    drop(restored_scope);
    assert_eq!(
        restored
            .archive_count(account, region, "source", now)
            .await
            .unwrap(),
        1
    );
    drop(restored);
    let replay = Replay {
        name: "copy".into(),
        arn: format!("arn:aws:events:{region}:{account}:replay/copy"),
        source_arn: format!("arn:aws:events:{region}:{account}:archive/source"),
        destination: json!({"Arn":format!("arn:aws:events:{region}:{account}:event-bus/default")}),
        start: now,
        end: now,
        state: "RUNNING".into(),
    };
    store
        .persist_replay(account, region, &replay, &[first.clone(), second.clone()])
        .await
        .unwrap();
    store
        .advance_replay(account, region, "copy", "RUNNING", 1)
        .await
        .unwrap();
    scope.write().await.archives.remove("source");
    store
        .delete_persisted_archive(account, region, "source")
        .await
        .unwrap();
    drop(scope);
    drop(store);
    let reopened = EbStore::with_state(db).unwrap();
    assert!(reopened
        .scope(account, region)
        .await
        .read()
        .await
        .archives
        .is_empty());
    let pending = reopened.pending_replays().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].3, 1);
    assert_eq!(pending[0].4, 2);
    assert_eq!(
        reopened
            .load_replay_item(account, region, "copy", 0)
            .await
            .unwrap(),
        Some(json!({"id":"first","source":"test","replay-name":"copy"}))
    );
    assert_eq!(
        reopened
            .load_replay_item(account, region, "copy", 1)
            .await
            .unwrap(),
        Some(json!({"id":"second","source":"test","replay-name":"copy"}))
    );
    assert_eq!(pending[0].2.state, "RUNNING");
    assert!(reopened
        .set_replay_state(account, region, "copy", "CANCELLED")
        .await
        .unwrap());
    assert!(!reopened
        .advance_replay(account, region, "copy", "COMPLETED", 2)
        .await
        .unwrap());
    assert!(!reopened
        .set_replay_state(account, region, "copy", "CANCELLED")
        .await
        .unwrap());
    assert!(reopened.pending_replays().await.unwrap().is_empty());
    assert!(reopened.healthy());
}

#[tokio::test]
async fn invalid_archive_reference_rolls_back_event_outbox() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
    let store = EbStore::with_state(db.clone()).unwrap();
    let fanout = PendingFanout {
        id: "x".into(),
        account: "a".into(),
        region: "r".into(),
        event: json!({"id":"x"}),
        rules: Vec::new(),
    };
    assert!(store
        .accept_event(
            fanout,
            vec![(
                "missing".into(),
                ArchivedEvent {
                    event: json!({"id":"x"}),
                    time: OffsetDateTime::now_utc(),
                }
            )]
        )
        .await
        .is_err());
    assert!(store.pending_fanouts().await.unwrap().is_empty());
    let count: i64 = db
        .connection()
        .unwrap()
        .query_row("SELECT count(*) FROM events_archived_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn large_archive_replay_uses_sql_snapshot_without_loading_events_at_startup() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = Arc::new(StateDb::open(root.path().join("state.sqlite3")).unwrap());
    let store = EbStore::with_state(db.clone()).unwrap();
    let account = "a";
    let region = "us-east-1";
    let now = OffsetDateTime::now_utc();
    let scope = store.scope(account, region).await;
    scope.write().await.archives.insert(
        "bulk".into(),
        Archive {
            name: "bulk".into(),
            arn: "arn:aws:events:us-east-1:a:archive/bulk".into(),
            source_arn: "arn:aws:events:us-east-1:a:event-bus/default".into(),
            description: None,
            event_pattern: None,
            retention_days: 0,
            tags: BTreeMap::new(),
            events: Vec::new(),
        },
    );
    store
        .persist_archive(account, region, "bulk")
        .await
        .unwrap();
    {
        let mut conn = db.connection().unwrap();
        let tx = conn.transaction().unwrap();
        let mut insert = tx.prepare("INSERT INTO events_archived_events(account,region,archive_name,time_ns,payload) VALUES(?1,?2,?3,?4,?5)").unwrap();
        for ordinal in 0..2_000 {
            let payload = serde_json::to_vec(&ArchivedEvent {
                event: json!({"id":ordinal,"detail":{"blob":"x".repeat(256)}}),
                time: now,
            })
            .unwrap();
            insert
                .execute(params![
                    account,
                    region,
                    "bulk",
                    now.unix_timestamp_nanos() as i64,
                    payload
                ])
                .unwrap();
        }
        drop(insert);
        tx.commit().unwrap();
    }
    drop(scope);
    drop(store);
    let reopened = EbStore::with_state(db.clone()).unwrap();
    assert!(
        reopened.scope(account, region).await.read().await.archives["bulk"]
            .events
            .is_empty()
    );
    assert_eq!(
        reopened
            .archive_count(account, region, "bulk", now)
            .await
            .unwrap(),
        2_000
    );
    let replay = Replay {
        name: "bulk-copy".into(),
        arn: "arn:aws:events:us-east-1:a:replay/bulk-copy".into(),
        source_arn: "arn:aws:events:us-east-1:a:archive/bulk".into(),
        destination: json!({"Arn":"arn:aws:events:us-east-1:a:event-bus/default"}),
        start: now,
        end: now,
        state: "RUNNING".into(),
    };
    assert_eq!(
        reopened
            .snapshot_replay(account, region, &replay)
            .await
            .unwrap(),
        2_000
    );
    let pending = reopened.pending_replays().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!((pending[0].3, pending[0].4), (0, 2_000));
    assert_eq!(
        reopened
            .load_replay_item(account, region, "bulk-copy", 1_999)
            .await
            .unwrap()
            .unwrap()["id"],
        1_999
    );
}
