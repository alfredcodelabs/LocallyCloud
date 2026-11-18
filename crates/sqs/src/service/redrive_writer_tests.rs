use super::*;

async fn hold_writer(
    db: Arc<StateDb>,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (ready_send, ready_receive) = tokio::sync::oneshot::channel();
    let (release_send, release_receive) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let mut connection = db.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        ready_send.send(()).unwrap();
        // Bound regressions that would otherwise stop the single-thread runtime's timer.
        let _ = release_receive.recv_timeout(Duration::from_secs(3));
        transaction.commit().unwrap();
    });
    ready_receive.await.unwrap();
    (release_send, thread)
}

fn state() -> (std::path::PathBuf, Arc<StateDb>) {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-state")
        .join(format!("sqs-redrive-writer-{}", uuid::Uuid::new_v4()));
    let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
    (root, db)
}

#[tokio::test]
async fn automatic_redrive_keeps_runtime_live_and_commits_after_caller_cancellation() {
    let (root, db) = state();
    let registry = ServiceRegistry::with_known_services();
    let handler = Arc::new(SqsHandler::with_state(&registry, db.clone()).unwrap());
    let dlq = create(&handler, "writer-dlq").await;
    let (status, queue) = call(&handler, "CreateQueue", json!({
        "QueueName":"writer-source", "Attributes":{"RedrivePolicy":json!({
            "deadLetterTargetArn":"arn:aws:sqs:us-east-1:000000000000:writer-dlq","maxReceiveCount":1
        }).to_string()}
    })).await;
    assert_eq!(status, 200);
    let url = queue["QueueUrl"].as_str().unwrap().to_owned();
    assert_eq!(
        call(
            &handler,
            "SendMessage",
            json!({"QueueUrl":url,"MessageBody":"poison"})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(
            &handler,
            "ReceiveMessage",
            json!({"QueueUrl":url,"VisibilityTimeout":0})
        )
        .await
        .0,
        200
    );
    let (release, writer) = hold_writer(db.clone()).await;
    let receiver = handler.clone();
    let source_url = url.clone();
    let receive = tokio::spawn(async move {
        call(&receiver, "ReceiveMessage", json!({"QueueUrl":source_url})).await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        !receive.is_finished(),
        "the timer must run while the move waits for SQLite"
    );
    receive.abort();
    assert!(receive.await.unwrap_err().is_cancelled());
    let store = handler.store.clone();
    let deletion = tokio::spawn(async move { store.lifecycle_write().await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        !deletion.is_finished(),
        "the cancelled transfer must retain the queue lifecycle lease"
    );
    release.send(()).unwrap();
    tokio::task::spawn_blocking(move || writer.join().unwrap())
        .await
        .unwrap();
    drop(
        tokio::time::timeout(Duration::from_secs(5), deletion)
            .await
            .unwrap()
            .unwrap(),
    );
    drop(handler);
    let restored = SqsHandler::with_state(&registry, db.clone()).unwrap();
    let (status, received) = call(&restored, "ReceiveMessage", json!({"QueueUrl":dlq})).await;
    assert_eq!(status, 200);
    assert_eq!(received["Messages"].as_array().unwrap().len(), 1);
    assert_eq!(received["Messages"][0]["Body"], "poison");
    let (status, received) = call(&restored, "ReceiveMessage", json!({"QueueUrl":url})).await;
    assert_eq!(status, 200);
    assert!(received.get("Messages").is_none());
    let count: i64 = db
        .connection()
        .unwrap()
        .query_row("SELECT count(*) FROM sqs_messages", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    drop(restored);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn cancelled_start_still_launches_the_durable_manual_redrive_task() {
    let (root, db) = state();
    let registry = ServiceRegistry::with_known_services();
    let handler = Arc::new(SqsHandler::with_state(&registry, db.clone()).unwrap());
    let dlq = create(&handler, "manual-dlq").await;
    let dlq_arn = "arn:aws:sqs:us-east-1:000000000000:manual-dlq";
    let (status, queue) = call(&handler, "CreateQueue", json!({
        "QueueName":"manual-source", "Attributes":{"RedrivePolicy":json!({"deadLetterTargetArn":dlq_arn,"maxReceiveCount":1}).to_string()}
    })).await;
    assert_eq!(status, 200);
    let url = queue["QueueUrl"].as_str().unwrap().to_owned();
    assert_eq!(
        call(
            &handler,
            "SendMessage",
            json!({"QueueUrl":dlq,"MessageBody":"redriven"})
        )
        .await
        .0,
        200
    );
    let (release, writer) = hold_writer(db.clone()).await;
    let starter = handler.clone();
    let start = tokio::spawn(async move {
        call(
            &starter,
            "StartMessageMoveTask",
            json!({"SourceArn":dlq_arn,"MaxNumberOfMessagesPerSecond":500}),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        !start.is_finished(),
        "the timer must run while task publication waits for SQLite"
    );
    let (status, tasks) = call(
        &handler,
        "ListMessageMoveTasks",
        json!({"SourceArn":dlq_arn}),
    )
    .await;
    assert_eq!(status, 200);
    assert!(tasks["Results"].as_array().unwrap().is_empty());
    let competitor = handler.clone();
    let competing_start = tokio::spawn(async move {
        call(
            &competitor,
            "StartMessageMoveTask",
            json!({"SourceArn":dlq_arn}),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(!competing_start.is_finished());
    start.abort();
    assert!(start.await.unwrap_err().is_cancelled());
    release.send(()).unwrap();
    tokio::task::spawn_blocking(move || writer.join().unwrap())
        .await
        .unwrap();
    let (status, _) = tokio::time::timeout(Duration::from_secs(5), competing_start)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        status, 400,
        "a concurrent start must not create a second worker"
    );
    let completed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (status, tasks) = call(
                &handler,
                "ListMessageMoveTasks",
                json!({"SourceArn":dlq_arn}),
            )
            .await;
            assert_eq!(status, 200);
            if tasks["Results"][0]["Status"] == "COMPLETED" {
                break tasks;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(completed["Results"].as_array().unwrap().len(), 1);
    assert_eq!(
        completed["Results"][0]["ApproximateNumberOfMessagesMoved"],
        1
    );
    drop(handler);
    let restored = SqsHandler::with_state(&registry, db.clone()).unwrap();
    let (status, received) = call(&restored, "ReceiveMessage", json!({"QueueUrl":url})).await;
    assert_eq!(status, 200);
    assert_eq!(received["Messages"][0]["Body"], "redriven");
    let (status, tasks) = call(
        &restored,
        "ListMessageMoveTasks",
        json!({"SourceArn":dlq_arn}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(tasks["Results"][0]["Status"], "COMPLETED");
    assert_eq!(tasks["Results"][0]["ApproximateNumberOfMessagesMoved"], 1);
    drop(restored);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}
