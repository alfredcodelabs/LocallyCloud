use super::*;
use async_trait::async_trait;
use axum::body::Body;
use locallycloud_core::handler::NativeHandler;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};
use locallycloud_state::StateDb;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

#[derive(Default)]
struct Queues {
    good: AtomicUsize,
    bad: AtomicUsize,
    late: AtomicUsize,
    fail_bad: AtomicBool,
    requests: Mutex<Vec<Value>>,
}

#[async_trait]
impl NativeHandler for Queues {
    async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
        assert_eq!(request.account_id, "111111111111");
        assert_eq!(request.region, "eu-west-1");
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let name = body["QueueUrl"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        let failed = match name.trim_end_matches(".fifo") {
            "good" => {
                self.good.fetch_add(1, Ordering::SeqCst);
                false
            }
            "bad" => {
                self.bad.fetch_add(1, Ordering::SeqCst);
                self.fail_bad.load(Ordering::SeqCst)
            }
            "late" => {
                self.late.fetch_add(1, Ordering::SeqCst);
                false
            }
            _ => panic!("unexpected endpoint"),
        };
        self.requests.lock().unwrap().push(body);
        axum::response::Response::builder()
            .status(if failed { 503 } else { 200 })
            .body(Body::from("{}"))
            .unwrap()
    }
}

struct Fixture {
    root: PathBuf,
    state: Arc<StateDb>,
    store: Arc<crate::store::SnsStore>,
    registry: Arc<ServiceRegistry>,
    queues: Arc<Queues>,
    http: Arc<locallycloud_core::egress::EgressClient>,
    job: FanoutJob,
}

fn subscription(topic: &str, name: &str, fifo: bool) -> Subscription {
    Subscription {
        arn: format!("{topic}:{name}"),
        topic_arn: topic.into(),
        protocol: "sqs".into(),
        endpoint: format!(
            "arn:aws:sqs:eu-west-1:111111111111:{name}{}",
            if fifo { ".fifo" } else { "" }
        ),
        owner: "111111111111".into(),
        confirmed: true,
        pending_token: None,
        attributes: BTreeMap::new(),
    }
}

async fn fixture(fifo: bool, endpoints: &[&str]) -> Fixture {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.locallycloud-tmp/batch-sns-ddb-sqs/sns")
        .join(format!("test-{}", uuid::Uuid::new_v4()));
    let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
    // Opening an older schema must conservatively retain accepted jobs without invented ACKs.
    state.connection().unwrap().execute_batch("CREATE TABLE sns_topics (account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, metadata TEXT NOT NULL, PRIMARY KEY(account,region,name)); CREATE TABLE sns_outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, job TEXT NOT NULL, FOREIGN KEY(account,region,name) REFERENCES sns_topics(account,region,name) ON DELETE CASCADE);").unwrap();
    let mut store = crate::store::SnsStore::with_state(state.clone()).unwrap();
    store.config.outbox_retry_max_secs = 1;
    let store = Arc::new(store);
    let arn = crate::model::TopicArn::new(
        "eu-west-1",
        "111111111111",
        if fifo { "jobs.fifo" } else { "jobs" },
    );
    store.insert(arn.clone(), fifo, BTreeMap::new(), BTreeMap::new());
    let subscriptions: Vec<_> = endpoints
        .iter()
        .map(|name| {
            let mut sub = subscription(&arn.to_arn(), name, fifo);
            if *name == "terminal" {
                sub.protocol = "http".into();
                sub.endpoint = "http://127.0.0.1:1".into();
            }
            sub
        })
        .collect();
    let topic = store.get(&arn).unwrap();
    topic.write().await.subscriptions = subscriptions.clone();
    let mut job = FanoutJob {
        outbox_id: None,
        subscriptions,
        delivery: Delivery {
            message_id: "publication".into(),
            topic_arn: arn.to_arn(),
            message: "body".into(),
            structure: None,
            subject: None,
            timestamp: "2026-11-20T00:00:00Z".into(),
            attributes: BTreeMap::new(),
            group_id: fifo.then(|| "group".into()),
            dedup_id: fifo.then(|| "dedup".into()),
            region: arn.region.clone(),
            account: arn.account.clone(),
            request_id: "outbox-test".into(),
        },
    };
    let saved = crate::persistence::SavedTopic::from_state(&*topic.read().await);
    job.outbox_id = store.accept_job(saved, job.clone()).await.unwrap();
    let registry = ServiceRegistry::with_known_services();
    let queues = Arc::new(Queues::default());
    registry.register_native(
        ServiceName::new("sqs"),
        ServiceMetadata::new(AwsProtocol::Json10, Some("AmazonSQS")),
        queues.clone(),
    );
    registry.set_internal_dispatcher(Arc::new(
        locallycloud_core::integration::InternalDispatcher::new_shared(
            &registry,
            locallycloud_core::proxy::ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            locallycloud_core::proxy::LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        ),
    ));
    Fixture {
        root,
        state,
        store,
        registry,
        queues,
        http: Arc::new(
            locallycloud_core::egress::EgressClient::new(Default::default(), &[]).unwrap(),
        ),
        job,
    }
}

async fn attempt(
    fixture: &Fixture,
    store: Arc<crate::store::SnsStore>,
    job: FanoutJob,
) -> Result<(), DeliveryFailure> {
    fan_out(fixture.registry.clone(), fixture.http.clone(), store, job).await
}

fn count(state: &StateDb, table: &str) -> i64 {
    state
        .connection()
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[tokio::test]
async fn completed_recipients_are_not_replayed_live_or_after_restart() {
    for fifo in [false, true] {
        let endpoints = if fifo {
            vec!["good", "bad"]
        } else {
            vec!["good", "bad", "terminal"]
        };
        let fixture = fixture(fifo, &endpoints).await;
        fixture.queues.fail_bad.store(true, Ordering::SeqCst);
        let original: String = fixture
            .state
            .connection()
            .unwrap()
            .query_row("SELECT job FROM sns_outbox", [], |row| row.get(0))
            .unwrap();
        assert!(
            attempt(&fixture, fixture.store.clone(), fixture.job.clone())
                .await
                .is_err()
        );
        assert_eq!(fixture.queues.good.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.queues.bad.load(Ordering::SeqCst), 4);
        let mut completed = BTreeSet::from([fixture.job.subscriptions[0].arn.clone()]);
        if !fifo {
            completed.insert(fixture.job.subscriptions[2].arn.clone());
        }
        assert_eq!(
            fixture
                .store
                .completed_subscriptions(fixture.job.outbox_id)
                .unwrap(),
            completed
        );
        let arn = crate::model::TopicArn::parse(&fixture.job.delivery.topic_arn).unwrap();
        let topic = fixture.store.get(&arn).unwrap();
        topic.write().await.subscriptions = vec![subscription(&arn.to_arn(), "late", fifo)];
        fixture.store.mark_uncommitted(&arn);
        fixture.store.persist_metadata().await.unwrap();
        assert!(
            attempt(&fixture, fixture.store.clone(), fixture.job.clone())
                .await
                .is_err()
        );
        assert_eq!(fixture.queues.good.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.queues.bad.load(Ordering::SeqCst), 8);
        assert_eq!(fixture.queues.late.load(Ordering::SeqCst), 0);
        let encoded: String = fixture
            .state
            .connection()
            .unwrap()
            .query_row("SELECT job FROM sns_outbox", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            encoded, original,
            "recipient ACK must not rewrite the publication snapshot"
        );
        let restored = Arc::new(crate::store::SnsStore::with_state(fixture.state.clone()).unwrap());
        let jobs = restored.pending_jobs().unwrap();
        assert_eq!(jobs.len(), 1);
        fixture.queues.fail_bad.store(false, Ordering::SeqCst);
        assert!(attempt(&fixture, restored.clone(), jobs[0].clone())
            .await
            .is_ok());
        assert_eq!(fixture.queues.good.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.queues.bad.load(Ordering::SeqCst), 9);
        assert_eq!(fixture.queues.late.load(Ordering::SeqCst), 0);
        for request in fixture.queues.requests.lock().unwrap().iter() {
            if fifo {
                assert_eq!(request["MessageGroupId"], "group");
                assert_eq!(request["MessageDeduplicationId"], "dedup");
            }
        }
        restored.complete_job(fixture.job.outbox_id).unwrap();
        assert_eq!(count(&fixture.state, "sns_outbox_completed"), 0);
        let root = fixture.root.clone();
        drop((restored, topic, fixture));
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}

async fn wait_for_attempts(state: Arc<StateDb>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state = state.clone();
            let attempts = tokio::task::spawn_blocking(move || {
                state
                    .connection()
                    .unwrap()
                    .query_row("SELECT n FROM attempts", [], |row| row.get::<_, i64>(0))
                    .unwrap()
            })
            .await
            .unwrap();
            if attempts >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn recipient_and_final_ack_failures_never_repeat_delivery() {
    for (table, action, delete_topic) in [
        ("sns_outbox_completed", "INSERT", false),
        ("sns_outbox", "DELETE", false),
        ("sns_outbox_completed", "INSERT", true),
    ] {
        let fixture = fixture(false, &["good"]).await;
        fixture.state.connection().unwrap().execute_batch(&format!("CREATE TABLE attempts(n INTEGER); INSERT INTO attempts VALUES(0); CREATE TRIGGER reject_ack BEFORE {action} ON {table} BEGIN UPDATE attempts SET n=n+1; SELECT RAISE(FAIL,'injected ACK failure'); END;")).unwrap();
        let worker = tokio::spawn(deliver_accepted(
            fixture.registry.clone(),
            fixture.http.clone(),
            fixture.store.clone(),
            fixture.job.clone(),
        ));
        wait_for_attempts(fixture.state.clone()).await;
        assert_eq!(fixture.queues.good.load(Ordering::SeqCst), 1);
        assert!(fixture.store.job_exists(fixture.job.outbox_id).unwrap());
        if delete_topic {
            fixture
                .store
                .remove(&crate::model::TopicArn::parse(&fixture.job.delivery.topic_arn).unwrap());
            fixture.store.persist_metadata().await.unwrap();
        } else {
            fixture
                .state
                .connection()
                .unwrap()
                .execute_batch("DROP TRIGGER reject_ack")
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fixture.queues.good.load(Ordering::SeqCst), 1);
        assert!(!fixture.store.job_exists(fixture.job.outbox_id).unwrap());
        assert_eq!(count(&fixture.state, "sns_outbox_completed"), 0);
        let root = fixture.root.clone();
        drop(fixture);
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}

#[tokio::test]
async fn legacy_jobs_and_completion_rows_remain_scoped_to_one_publication() {
    let fixture = fixture(false, &["good"]).await;
    fixture
        .state
        .connection()
        .unwrap()
        .execute_batch("DROP TABLE sns_outbox_completed")
        .unwrap();
    let restored = Arc::new(crate::store::SnsStore::with_state(fixture.state.clone()).unwrap());
    let legacy = restored.pending_jobs().unwrap();
    assert_eq!(legacy.len(), 1);
    assert_eq!(legacy[0].outbox_id, fixture.job.outbox_id);
    assert!(restored
        .completed_subscriptions(fixture.job.outbox_id)
        .unwrap()
        .is_empty());
    assert!(attempt(&fixture, restored.clone(), legacy[0].clone())
        .await
        .is_ok());
    let arn = crate::model::TopicArn::parse(&fixture.job.delivery.topic_arn).unwrap();
    let topic = restored.get(&arn).unwrap();
    let saved = crate::persistence::SavedTopic::from_state(&*topic.read().await);
    let mut second = fixture.job.clone();
    second.outbox_id = restored.accept_job(saved, second.clone()).await.unwrap();
    assert_ne!(second.outbox_id, fixture.job.outbox_id);
    assert!(restored
        .completed_subscriptions(second.outbox_id)
        .unwrap()
        .is_empty());
    assert!(attempt(&fixture, restored.clone(), second).await.is_ok());
    assert_eq!(fixture.queues.good.load(Ordering::SeqCst), 2);
    assert!(attempt(&fixture, restored.clone(), fixture.job.clone())
        .await
        .is_ok());
    assert_eq!(fixture.queues.good.load(Ordering::SeqCst), 2);
    restored.remove(&arn);
    restored.persist_metadata().await.unwrap();
    assert_eq!(count(&fixture.state, "sns_outbox_completed"), 0);
    assert!(restored.pending_jobs().unwrap().is_empty());
    assert!(attempt(&fixture, restored.clone(), fixture.job.clone())
        .await
        .is_ok());
    assert_eq!(fixture.queues.good.load(Ordering::SeqCst), 2);
    let root = fixture.root.clone();
    drop((topic, restored, fixture));
    tokio::fs::remove_dir_all(root).await.unwrap();
}
