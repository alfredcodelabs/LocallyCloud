use super::*;
use std::sync::atomic::Ordering;

fn call(handler: &KinesisHandler, operation: &str, body: Value) -> Result<Success, KinesisError> {
    handler.process(&ServiceRequest {
        method: http::Method::POST,
        uri: "/".parse().unwrap(),
        headers: HeaderMap::from_iter([
            (http::header::CONTENT_TYPE, CONTENT_TYPE.parse().unwrap()),
            (
                http::header::HeaderName::from_static("x-amz-target"),
                format!("{TARGET_PREFIX}.{operation}").parse().unwrap(),
            ),
        ]),
        body: body.to_string().into(),
        region: tests::scope().region,
        account_id: tests::scope().account_id,
        request_id: "trim-test".into(),
    })
}

fn create(handler: &KinesisHandler, name: &str) {
    call(
        handler,
        "CreateStream",
        json!({"StreamName":name,"ShardCount":1}),
    )
    .unwrap();
}

fn write(handler: &KinesisHandler, name: &str, batch: bool) {
    let record = json!({"Data":STANDARD.encode(b"x"),"PartitionKey":"p"});
    let result = if batch {
        call(
            handler,
            "PutRecords",
            json!({"StreamName":name,"Records":[record]}),
        )
    } else {
        call(
            handler,
            "PutRecord",
            json!({"StreamName":name,"Data":record["Data"],"PartitionKey":"p"}),
        )
    }
    .unwrap();
    if let Success::Json(value) = result {
        if batch {
            assert_eq!(value["FailedRecordCount"], 0);
        }
    }
}

#[test]
fn memory_trim_leaves_other_streams_until_capacity_requires_reclaim() {
    for batch in [false, true] {
        let mut handler = KinesisHandler::new();
        handler.simulate_write_limits = false;
        for name in ["events", "idle"] {
            create(&handler, name);
            write(&handler, name, batch);
        }
        let idle = StreamKey::new(&tests::scope(), "idle");
        handler
            .lock_store()
            .unwrap()
            .streams
            .get_mut(&idle)
            .unwrap()
            .shards[0]
            .records
            .front_mut()
            .unwrap()
            .arrival_time = now_epoch().unwrap() - RETENTION_SECONDS - 1.0;
        write(&handler, "events", batch);
        {
            let store = handler.lock_store().unwrap();
            assert_eq!(store.streams[&idle].shards[0].records.len(), 1);
            assert_eq!(store.buffered_bytes, 3 * record_charge(b"x", "p"));
        }
        handler.max_buffered_bytes = 3 * record_charge(b"x", "p");
        write(&handler, "events", batch);
        let store = handler.lock_store().unwrap();
        assert!(store.streams[&idle].shards[0].records.is_empty());
        assert_eq!(store.streams[&idle].shards[0].first_position, 1);
        assert_eq!(store.buffered_bytes, handler.max_buffered_bytes);
    }
}

#[test]
fn persistent_requests_trim_one_stream_independent_of_stream_count() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.locallycloud-tmp")
        .join(format!("kinesis-trim-{}", Uuid::new_v4()));
    let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
    let mut handler = KinesisHandler::with_state(state.clone()).unwrap();
    handler.simulate_write_limits = false;
    create(&handler, "events");
    for count in [0, 32] {
        for index in 0..count {
            let scope = Scope {
                account_id: format!("{index:012}"),
                region: "eu-west-1".into(),
            };
            handler
                .create_stream(
                    CreateStreamRequest {
                        stream_name: "idle".into(),
                        shard_count: 1,
                        ..Default::default()
                    },
                    &scope,
                )
                .unwrap();
        }
        let persistence = handler.persistence.as_ref().unwrap();
        for (operation, body) in [
            (
                "PutRecord",
                json!({"StreamName":"events","Data":"eA==","PartitionKey":"p"}),
            ),
            (
                "PutRecords",
                json!({"StreamName":"events","Records":[{"Data":"eA==","PartitionKey":"p"}]}),
            ),
            (
                "IncreaseStreamRetentionPeriod",
                json!({"StreamName":"events","RetentionPeriodHours":24}),
            ),
            (
                "GetShardIterator",
                json!({"StreamName":"events","ShardId":SHARD_ID,"ShardIteratorType":"TRIM_HORIZON"}),
            ),
        ] {
            persistence.trim_calls.store(0, Ordering::Relaxed);
            call(&handler, operation, body).unwrap();
            assert_eq!(
                persistence.trim_calls.load(Ordering::Relaxed),
                1,
                "{operation}, {count} idle streams"
            );
        }
        let Success::Json(iterator) = call(
            &handler,
            "GetShardIterator",
            json!({"StreamName":"events","ShardId":SHARD_ID,"ShardIteratorType":"TRIM_HORIZON"}),
        )
        .unwrap() else {
            panic!("iterator")
        };
        persistence.trim_calls.store(0, Ordering::Relaxed);
        let Success::Json(page) = call(
            &handler,
            "GetRecords",
            json!({"ShardIterator":iterator["ShardIterator"]}),
        )
        .unwrap() else {
            panic!("page")
        };
        assert_eq!(persistence.trim_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            page["Records"].as_array().unwrap().len(),
            if count == 0 { 2 } else { 4 }
        );
    }
    drop(handler);
    drop(state);
    std::fs::remove_dir_all(root).unwrap();
}
