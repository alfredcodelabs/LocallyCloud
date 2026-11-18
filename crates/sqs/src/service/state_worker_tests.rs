use super::redrive_writer_tests::hold_writer;
use super::*;

fn state() -> (std::path::PathBuf, Arc<StateDb>) {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-state")
        .join(format!("sqs-state-worker-{}", uuid::Uuid::new_v4()));
    let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
    (root, db)
}

async fn finish_writer(
    release: std::sync::mpsc::Sender<()>,
    writer: std::thread::JoinHandle<()>,
    handler: &SqsHandler,
) {
    release.send(()).unwrap();
    tokio::task::spawn_blocking(move || writer.join().unwrap())
        .await
        .unwrap();
    // Every accepted state job retains a lifecycle permit through commit/publication.
    drop(
        tokio::time::timeout(Duration::from_secs(5), handler.store.lifecycle_write())
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn cancelled_batch_send_wakes_long_poll_and_preserves_fifo_attempt_after_restart() {
    let (root, db) = state();
    let registry = ServiceRegistry::with_known_services();
    let h = Arc::new(SqsHandler::with_state(&registry, db.clone()).unwrap());
    let url = create(&h, "worker.fifo").await;
    let receiver = h.clone();
    let receive_url = url.clone();
    let receive = tokio::spawn(async move {
        call(&receiver, "ReceiveMessage", json!({"QueueUrl":receive_url,"WaitTimeSeconds":2,"ReceiveRequestAttemptId":"owned-attempt"})).await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    let (release, writer) = hold_writer(db.clone()).await;
    let sender = h.clone();
    let send_url = url.clone();
    let send = tokio::spawn(async move {
        call(&sender, "SendMessageBatch", json!({"QueueUrl":send_url,"Entries":[{"Id":"one","MessageBody":"durable","MessageGroupId":"g","MessageDeduplicationId":"d"}]})).await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        !send.is_finished(),
        "the timer must run while the send waits for SQLite"
    );
    send.abort();
    assert!(send.await.unwrap_err().is_cancelled());
    release.send(()).unwrap();
    tokio::task::spawn_blocking(move || writer.join().unwrap())
        .await
        .unwrap();
    let (status, received) = tokio::time::timeout(Duration::from_millis(750), receive)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(received["Messages"][0]["Body"], "durable");
    drop(h);
    let restored = SqsHandler::with_state(&registry, db.clone()).unwrap();
    let (status, replay) = call(
        &restored,
        "ReceiveMessage",
        json!({"QueueUrl":url,"ReceiveRequestAttemptId":"owned-attempt"}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(replay, received);
    let (status, dedup) = call(&restored, "SendMessage", json!({"QueueUrl":url,"MessageBody":"durable","MessageGroupId":"g","MessageDeduplicationId":"d"})).await;
    assert_eq!(status, 200);
    assert_eq!(dedup["MessageId"], received["Messages"][0]["MessageId"]);
    drop(restored);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn cancelled_receive_commits_visibility_without_blocking_the_runtime() {
    let (root, db) = state();
    let registry = ServiceRegistry::with_known_services();
    let h = Arc::new(SqsHandler::with_state(&registry, db.clone()).unwrap());
    let url = create(&h, "receive-worker").await;
    assert_eq!(
        call(
            &h,
            "SendMessage",
            json!({"QueueUrl":url,"MessageBody":"inflight"})
        )
        .await
        .0,
        200
    );
    let (release, writer) = hold_writer(db.clone()).await;
    let receiver = h.clone();
    let receive_url = url.clone();
    let receive = tokio::spawn(async move {
        call(
            &receiver,
            "ReceiveMessage",
            json!({"QueueUrl":receive_url,"VisibilityTimeout":30}),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(!receive.is_finished());
    receive.abort();
    assert!(receive.await.unwrap_err().is_cancelled());
    finish_writer(release, writer, &h).await;
    drop(h);
    let restored = SqsHandler::with_state(&registry, db.clone()).unwrap();
    let (status, attrs) = call(
        &restored,
        "GetQueueAttributes",
        json!({"QueueUrl":url,"AttributeNames":["All"]}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        attrs["Attributes"]["ApproximateNumberOfMessagesNotVisible"],
        "1"
    );
    assert!(!call(&restored, "ReceiveMessage", json!({"QueueUrl":url}))
        .await
        .1
        .get("Messages")
        .is_some());
    drop(restored);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn state_mutations_survive_cancelled_callers_and_sqlite_contention() {
    for operation in [
        "SendMessage",
        "DeleteMessage",
        "DeleteMessageBatch",
        "ChangeMessageVisibility",
        "ChangeMessageVisibilityBatch",
        "SetQueueAttributes",
        "TagQueue",
        "UntagQueue",
        "AddPermission",
        "RemovePermission",
        "PurgeQueue",
        "DeleteQueue",
    ] {
        let (root, db) = state();
        let registry = ServiceRegistry::with_known_services();
        let h = Arc::new(SqsHandler::with_state(&registry, db.clone()).unwrap());
        let url = create(&h, "mutations").await;
        assert_eq!(
            call(
                &h,
                "SendMessage",
                json!({"QueueUrl":url,"MessageBody":"seed"})
            )
            .await
            .0,
            200
        );
        let (status, received) = call(&h, "ReceiveMessage", json!({"QueueUrl":url})).await;
        assert_eq!(status, 200);
        let receipt = received["Messages"][0]["ReceiptHandle"].as_str().unwrap();
        assert_eq!(
            call(
                &h,
                "TagQueue",
                json!({"QueueUrl":url,"Tags":{"remove":"yes"}})
            )
            .await
            .0,
            200
        );
        let policy = json!({"Version":"2012-10-17","Statement":[{"Sid":"initial","Effect":"Allow","Principal":"*","Action":"sqs:*","Resource":"arn:aws:sqs:us-east-1:000000000000:mutations"}]});
        assert_eq!(
            call(
                &h,
                "SetQueueAttributes",
                json!({"QueueUrl":url,"Attributes":{"Policy":policy.to_string()}})
            )
            .await
            .0,
            200
        );
        let mut payload = match operation {
            "SendMessage" => json!({"MessageBody":"extra"}),
            "DeleteMessage" => json!({"ReceiptHandle":receipt}),
            "DeleteMessageBatch" => json!({"Entries":[{"Id":"one","ReceiptHandle":receipt}]}),
            "ChangeMessageVisibility" => json!({"ReceiptHandle":receipt,"VisibilityTimeout":0}),
            "ChangeMessageVisibilityBatch" => {
                json!({"Entries":[{"Id":"one","ReceiptHandle":receipt,"VisibilityTimeout":0}]})
            }
            "SetQueueAttributes" => json!({"Attributes":{"DelaySeconds":"7"}}),
            "TagQueue" => json!({"Tags":{"keep":"yes"}}),
            "UntagQueue" => json!({"TagKeys":["remove"]}),
            "AddPermission" => {
                json!({"Label":"added","AWSAccountIds":["000000000000"],"Actions":["SendMessage"]})
            }
            "RemovePermission" => json!({"Label":"initial"}),
            "PurgeQueue" | "DeleteQueue" => json!({}),
            _ => unreachable!(),
        };
        payload["QueueUrl"] = json!(url);
        let (release, writer) = hold_writer(db.clone()).await;
        let handler = h.clone();
        let mutation = tokio::spawn(async move { call(&handler, operation, payload).await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        if mutation.is_finished() {
            panic!(
                "{operation} completed before writer release: {:?}",
                mutation.await.unwrap()
            );
        }
        assert_eq!(
            call(&h, "ListQueues", json!({})).await.0,
            200,
            "{operation}"
        );
        mutation.abort();
        assert!(mutation.await.unwrap_err().is_cancelled());
        finish_writer(release, writer, &h).await;
        drop(h);
        let restored = SqsHandler::with_state(&registry, db.clone()).unwrap();
        if operation == "DeleteQueue" {
            assert_eq!(
                call(&restored, "GetQueueUrl", json!({"QueueName":"mutations"}))
                    .await
                    .0,
                400
            );
        } else {
            let (status, attrs) = call(
                &restored,
                "GetQueueAttributes",
                json!({"QueueUrl":url,"AttributeNames":["All"]}),
            )
            .await;
            assert_eq!(status, 200);
            match operation {
                "SendMessage" => {
                    assert_eq!(attrs["Attributes"]["ApproximateNumberOfMessages"], "1")
                }
                "DeleteMessage" | "DeleteMessageBatch" | "PurgeQueue" => assert_eq!(
                    attrs["Attributes"]["ApproximateNumberOfMessagesNotVisible"],
                    "0"
                ),
                "ChangeMessageVisibility" | "ChangeMessageVisibilityBatch" => {
                    assert_eq!(attrs["Attributes"]["ApproximateNumberOfMessages"], "1")
                }
                "SetQueueAttributes" => assert_eq!(attrs["Attributes"]["DelaySeconds"], "7"),
                "TagQueue" => assert_eq!(
                    call(&restored, "ListQueueTags", json!({"QueueUrl":url}))
                        .await
                        .1["Tags"]["keep"],
                    "yes"
                ),
                "UntagQueue" => assert!(call(&restored, "ListQueueTags", json!({"QueueUrl":url}))
                    .await
                    .1["Tags"]
                    .get("remove")
                    .is_none()),
                "AddPermission" => assert!(attrs["Attributes"]["Policy"]
                    .as_str()
                    .unwrap()
                    .contains("added")),
                "RemovePermission" => assert!(attrs["Attributes"].get("Policy").is_none()),
                _ => unreachable!(),
            }
        }
        drop(restored);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn queued_state_job_rejects_a_deleted_and_recreated_queue() {
    let store = Arc::new(crate::store::SqsStore::new());
    let arn = crate::model::QueueArn::new("us-east-1", "000000000000", "recreated");
    store.insert_if_absent(arn.clone(), false, Default::default(), Default::default());
    let old = store.get(&arn).unwrap();
    let lifecycle = store.lifecycle_write().await;
    let worker_store = store.clone();
    let job = tokio::spawn(async move {
        worker_store
            .with_queue_state(&old, |_, _, state| {
                state.tags.insert("stale".into(), "mutation".into());
                Ok(())
            })
            .await
    });
    tokio::task::yield_now().await;
    store.remove(&arn);
    store.insert_if_absent(arn.clone(), false, Default::default(), Default::default());
    drop(lifecycle);
    assert!(matches!(
        job.await.unwrap(),
        Err(crate::error::SqsError::QueueDoesNotExist)
    ));
    assert!(store.get(&arn).unwrap().state.lock().await.tags.is_empty());
}

#[tokio::test]
async fn failed_receive_restore_keeps_memory_at_the_committed_receipt() {
    let (root, db) = state();
    let registry = ServiceRegistry::with_known_services();
    let h = SqsHandler::with_state(&registry, db.clone()).unwrap();
    let url = create(&h, "restore-failure").await;
    assert_eq!(
        call(
            &h,
            "SendMessage",
            json!({"QueueUrl":url,"MessageBody":"seed"})
        )
        .await
        .0,
        200
    );
    let arn = crate::model::QueueArn::new("us-east-1", "000000000000", "restore-failure");
    let queue = h.store.get(&arn).unwrap();
    h.store
        .with_queue_state(&queue, |store, queue, state| {
            let message = state.messages.front_mut().unwrap();
            // Rendering will fail without a KMS dispatcher, after selection is committed.
            message.body_on_disk = false;
            message.encrypted_body = Some(crate::model::EncryptedBody {
                encryption_context_arn: queue.arn.to_arn(),
                ciphertext: vec![1],
                encrypted_data_key: vec![2],
                nonce: [0; 12],
                key_id: "alias/missing".into(),
            });
            store
                .persistence()
                .unwrap()
                .update_messages(queue, std::slice::from_ref(message), None)
        })
        .await
        .unwrap();
    db.connection().unwrap().execute_batch("CREATE TRIGGER reject_receive_restore BEFORE UPDATE ON sqs_messages WHEN json_extract(NEW.payload,'$.receipt_handle') IS NULL BEGIN SELECT RAISE(ABORT,'injected restore failure'); END;").unwrap();
    assert_eq!(
        call(&h, "ReceiveMessage", json!({"QueueUrl":url})).await.0,
        500
    );
    let receipt = queue.state.lock().await.messages[0].receipt_handle.clone();
    assert!(receipt.is_some());
    drop(queue);
    drop(h);
    let restored = SqsHandler::with_state(&registry, db.clone()).unwrap();
    let queue = restored.store.get(&arn).unwrap();
    assert_eq!(queue.state.lock().await.messages[0].receipt_handle, receipt);
    drop(queue);
    drop(restored);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}
