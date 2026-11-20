use super::*;

#[tokio::test]
async fn receipt_operations_do_not_scan_or_reindex_the_backlog() {
    for count in [8, 10_000] {
        for selected in [0, count / 2, count - 1] {
            let handler = SqsHandler::new();
            let url = create(&handler, "indexed").await;
            assert_eq!(
                call(
                    &handler,
                    "SendMessage",
                    json!({"QueueUrl":url,"MessageBody":"seed"})
                )
                .await
                .0,
                200
            );
            let queue = handler
                .store
                .get(&QueueArn::new("us-east-1", "000000000000", "indexed"))
                .unwrap();
            let target = {
                let mut state = queue.state.lock().await;
                let prototype = state.messages.iter().next().unwrap().clone();
                state.messages.clear();
                let mut target = String::new();
                for index in 0..count {
                    let mut message = prototype.clone();
                    message.id = uuid::Uuid::new_v4().to_string();
                    message.visible_at = if index == selected {
                        target = message.id.clone();
                        std::time::Instant::now()
                    } else {
                        std::time::Instant::now() + Duration::from_secs(60)
                    };
                    state.push_message(message).unwrap();
                }
                target
            };
            let (status, received) =
                call(&handler, "ReceiveMessage", json!({"QueueUrl":url})).await;
            assert_eq!(status, 200);
            assert_eq!(received["Messages"][0]["MessageId"], target);
            let old = received["Messages"][0]["ReceiptHandle"].as_str().unwrap();
            queue.state.lock().await.messages.take_work();
            assert_eq!(
                call(
                    &handler,
                    "ChangeMessageVisibility",
                    json!({"QueueUrl":url,"ReceiptHandle":old,"VisibilityTimeout":0})
                )
                .await
                .0,
                200
            );
            assert_eq!(queue.state.lock().await.messages.take_work(), 2);
            let (_, received) = call(&handler, "ReceiveMessage", json!({"QueueUrl":url})).await;
            let current = received["Messages"][0]["ReceiptHandle"].as_str().unwrap();
            assert_ne!(old, current);
            queue.state.lock().await.messages.take_work();
            assert_eq!(
                call(
                    &handler,
                    "DeleteMessage",
                    json!({"QueueUrl":url,"ReceiptHandle":old})
                )
                .await
                .0,
                200
            );
            assert_eq!(queue.state.lock().await.messages.take_work(), 2);
            let (status, error) = call(
                &handler,
                "ChangeMessageVisibility",
                json!({"QueueUrl":url,"ReceiptHandle":old,"VisibilityTimeout":30}),
            )
            .await;
            assert_eq!(status, 400);
            assert!(error.to_string().contains("MessageNotInflight"));
            assert_eq!(queue.state.lock().await.messages.take_work(), 2);
            assert_eq!(
                call(
                    &handler,
                    "ChangeMessageVisibility",
                    json!({"QueueUrl":url,"ReceiptHandle":current,"VisibilityTimeout":30})
                )
                .await
                .0,
                200
            );
            assert_eq!(queue.state.lock().await.messages.take_work(), 2);
            assert_eq!(
                call(
                    &handler,
                    "DeleteMessage",
                    json!({"QueueUrl":url,"ReceiptHandle":current})
                )
                .await
                .0,
                200
            );
            let state = queue.state.lock().await;
            assert_eq!(state.messages.take_work(), 4);
            assert_eq!(state.messages.len(), count - 1);
            assert!(state.messages.get(&target).is_none());
        }
    }
}

#[tokio::test]
async fn receipt_index_preserves_fifo_order_rollback_and_restart() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.locallycloud-tmp/batch-sns-ddb-sqs/sqs")
        .join(format!("index-{}", uuid::Uuid::new_v4()));
    let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
    let registry = ServiceRegistry::with_known_services();
    let handler = SqsHandler::with_state(&registry, db.clone()).unwrap();
    let url = create(&handler, "ordered.fifo").await;
    for body in ["a", "b", "c"] {
        assert_eq!(call(&handler, "SendMessage", json!({"QueueUrl":url,"MessageBody":body,"MessageGroupId":"g","MessageDeduplicationId":body})).await.0, 200);
    }
    let (_, received) = call(&handler, "ReceiveMessage", json!({"QueueUrl":url})).await;
    assert_eq!(received["Messages"][0]["Body"], "a");
    let receipt = received["Messages"][0]["ReceiptHandle"].as_str().unwrap();
    db.connection().unwrap().execute_batch("CREATE TRIGGER reject_visibility BEFORE UPDATE ON sqs_messages BEGIN SELECT RAISE(ABORT,'injected visibility failure'); END;").unwrap();
    assert_eq!(
        call(
            &handler,
            "ChangeMessageVisibility",
            json!({"QueueUrl":url,"ReceiptHandle":receipt,"VisibilityTimeout":0})
        )
        .await
        .0,
        500
    );
    db.connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_visibility;")
        .unwrap();
    drop(handler);
    let handler = SqsHandler::with_state(&registry, db.clone()).unwrap();
    assert_eq!(
        call(
            &handler,
            "ChangeMessageVisibility",
            json!({"QueueUrl":url,"ReceiptHandle":receipt,"VisibilityTimeout":0})
        )
        .await
        .0,
        200
    );
    let (_, received) = call(&handler, "ReceiveMessage", json!({"QueueUrl":url})).await;
    assert_eq!(received["Messages"][0]["Body"], "a");
    let receipt = received["Messages"][0]["ReceiptHandle"].as_str().unwrap();
    db.connection().unwrap().execute_batch("CREATE TRIGGER reject_delete BEFORE DELETE ON sqs_messages BEGIN SELECT RAISE(ABORT,'injected delete failure'); END;").unwrap();
    assert_eq!(
        call(
            &handler,
            "DeleteMessage",
            json!({"QueueUrl":url,"ReceiptHandle":receipt})
        )
        .await
        .0,
        500
    );
    db.connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_delete;")
        .unwrap();
    assert_eq!(
        call(
            &handler,
            "DeleteMessage",
            json!({"QueueUrl":url,"ReceiptHandle":receipt})
        )
        .await
        .0,
        200
    );
    drop(handler);
    let handler = SqsHandler::with_state(&registry, db.clone()).unwrap();
    for body in ["b", "c"] {
        let (_, received) = call(&handler, "ReceiveMessage", json!({"QueueUrl":url})).await;
        assert_eq!(received["Messages"][0]["Body"], body);
        assert_eq!(
            call(
                &handler,
                "DeleteMessage",
                json!({"QueueUrl":url,"ReceiptHandle":received["Messages"][0]["ReceiptHandle"]})
            )
            .await
            .0,
            200
        );
    }
    assert_eq!(call(&handler, "SendMessage", json!({"QueueUrl":url,"MessageBody":"purged","MessageGroupId":"g","MessageDeduplicationId":"purged"})).await.0, 200);
    assert_eq!(
        call(&handler, "PurgeQueue", json!({"QueueUrl":url}))
            .await
            .0,
        200
    );
    assert_eq!(call(&handler, "SendMessage", json!({"QueueUrl":url,"MessageBody":"fresh","MessageGroupId":"g","MessageDeduplicationId":"fresh"})).await.0, 200);
    let (_, received) = call(&handler, "ReceiveMessage", json!({"QueueUrl":url})).await;
    assert_eq!(received["Messages"][0]["Body"], "fresh");
    assert_eq!(
        call(
            &handler,
            "DeleteMessage",
            json!({"QueueUrl":url,"ReceiptHandle":received["Messages"][0]["ReceiptHandle"]})
        )
        .await
        .0,
        200
    );
    drop(handler);
    drop(db);
    tokio::fs::remove_dir_all(root).await.unwrap();
}
