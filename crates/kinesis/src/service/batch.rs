//! Batch writes validate the request before planning individual capacity outcomes.
use super::*;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(super) struct PutRecordsRequest {
    stream_name: Option<String>,
    #[serde(rename = "StreamARN")]
    stream_arn: Option<String>,
    records: Vec<Entry>,
    dry_run: Option<bool>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Entry {
    data: String,
    partition_key: String,
    explicit_hash_key: Option<String>,
}

impl KinesisHandler {
    pub(super) fn put_records(
        &self,
        request: PutRecordsRequest,
        scope: &Scope,
    ) -> Result<Success, KinesisError> {
        if request.dry_run.unwrap_or(false) {
            return Err(KinesisError::InvalidArgument(
                "DryRun is not supported".into(),
            ));
        }
        let arn_name = request
            .stream_arn
            .as_deref()
            .map(|arn| {
                let prefix = format!(
                    "arn:aws:kinesis:{}:{}:stream/",
                    scope.region, scope.account_id
                );
                arn.strip_prefix(&prefix)
                    .ok_or_else(|| stream_not_found(arn))
            })
            .transpose()?;
        let name = match (request.stream_name.as_deref(), arn_name) {
            (Some(name), Some(arn)) if name != arn => {
                return Err(KinesisError::InvalidArgument(
                    "StreamName and StreamARN must identify the same stream".into(),
                ))
            }
            (Some(name), _) | (_, Some(name)) => name,
            _ => {
                return Err(KinesisError::Validation(
                    "StreamName or StreamARN is required".into(),
                ))
            }
        };
        validate_stream_name(name)?;
        if !(1..=500).contains(&request.records.len()) {
            return Err(KinesisError::Validation(
                "Records must contain 1–500 entries".into(),
            ));
        }
        let mut decoded = Vec::with_capacity(request.records.len());
        let mut total = 0usize;
        for entry in request.records {
            validate_partition_key(&entry.partition_key)?;
            let data = STANDARD.decode(entry.data.as_bytes()).map_err(|_| {
                KinesisError::Serialization("Data must be valid base64-encoded bytes".into())
            })?;
            let size = data.len() + entry.partition_key.len();
            if size > MAX_RECORD_BYTES {
                return Err(KinesisError::InvalidArgument(
                    "Record data and partition key exceed the stream's default 1 MiB limit".into(),
                ));
            }
            total = total.checked_add(size).ok_or(KinesisError::Internal)?;
            if total > 10 * 1024 * 1024 {
                return Err(KinesisError::InvalidArgument(
                    "Batch data and partition keys exceed 10 MiB".into(),
                ));
            }
            let hash = entry
                .explicit_hash_key
                .as_deref()
                .map(parse_hash_key)
                .transpose()?
                .unwrap_or_else(|| {
                    u128::from_be_bytes(Md5::digest(entry.partition_key.as_bytes()).into())
                });
            decoded.push((data, entry.partition_key, hash));
        }
        let now = (self.write_clock)()?;
        let mut store = self.lock_store()?;
        let key = StreamKey::new(scope, name);
        if !store.streams.contains_key(&key) {
            return Err(stream_not_found(name));
        }
        self.trim_expired(&mut store, now)?;
        let mut buffered = store.buffered_bytes;
        let stream = store.streams.get_mut(&key).ok_or(KinesisError::Internal)?;
        let mut next = stream.next_sequence;
        let mut windows: Vec<_> = stream
            .shards
            .iter()
            .map(|shard| shard.write_window.clone())
            .collect();
        let mut accepted = Vec::new();
        let mut response = Vec::new();
        let mut failed = 0;
        for (data, partition_key, hash) in decoded {
            let index = (0..stream.shards.len())
                .find(|index| {
                    let (start, end) = hash_range(*index, stream.shards.len());
                    hash >= start && hash <= end
                })
                .ok_or(KinesisError::Internal)?;
            let charge = record_charge(&data, &partition_key);
            if self.persistence.is_none()
                && buffered.saturating_add(charge) > self.max_buffered_bytes
            {
                failed += 1;
                response.push(json!({"ErrorCode":"InternalFailure","ErrorMessage":"Local Kinesis buffer capacity is full; retry this entry after capacity is released"}));
                continue;
            }
            if self.simulate_write_limits
                && !windows[index].admit(now, data.len() + partition_key.len())
            {
                failed += 1;
                response.push(json!({"ErrorCode":"ProvisionedThroughputExceededException","ErrorMessage":"The modeled provisioned shard write limit was exceeded"}));
                continue;
            }
            let record = Record {
                sequence_number: next.to_string(),
                data,
                partition_key,
                arrival_time: now,
            };
            next = next
                .checked_add(1)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(KinesisError::Internal)?;
            if self.persistence.is_none() {
                buffered += charge;
            }
            response
                .push(json!({"ShardId":shard_id(index),"SequenceNumber":record.sequence_number}));
            accepted.push((index, record));
        }
        if let Some(persistence) = &self.persistence {
            let refs: Vec<_> = accepted
                .iter()
                .map(|(index, record)| (*index, record))
                .collect();
            persistence
                .append_many(&key, stream, &refs, next)
                .map_err(|_| KinesisError::Internal)?;
        }
        for (index, record) in accepted {
            stream.shards[index].next_position += 1;
            if self.persistence.is_none() {
                stream.shards[index].records.push_back(record);
            }
        }
        for (shard, window) in stream.shards.iter_mut().zip(windows) {
            shard.write_window = window;
        }
        stream.next_sequence = next;
        store.buffered_bytes = buffered;
        Ok(Success::Json(
            json!({"FailedRecordCount":failed,"Records":response}),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(scope: &Scope, records: Value) -> PutRecordsRequest {
        serde_json::from_value(json!({"StreamARN":scope.stream_arn("events"),"Records":records}))
            .unwrap()
    }
    #[test]
    fn batch_routes_partial_capacity_restarts_and_rolls_back_transaction_failure() {
        let root = std::env::temp_dir().join(format!("kinesis-batch-{}", Uuid::new_v4()));
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let mut handler = KinesisHandler::with_state(db.clone()).unwrap();
        let scope = super::super::tests::scope();
        handler
            .create_stream(
                CreateStreamRequest {
                    stream_name: "events".into(),
                    shard_count: 2,
                    ..Default::default()
                },
                &scope,
            )
            .unwrap();
        handler.simulate_write_limits = true;
        handler.write_clock = || Ok(1_900_000_000.0);
        {
            let mut store = handler.lock_store().unwrap();
            let shard = &mut store
                .streams
                .get_mut(&StreamKey::new(&scope, "events"))
                .unwrap()
                .shards[0];
            shard.write_window = WriteWindow {
                started_at: 1_900_000_000.0,
                records: 0,
                bytes: 1024 * 1024 - 2,
            };
        }
        let records = json!([{ "Data":STANDARD.encode(b"x"),"PartitionKey":"p","ExplicitHashKey":"0"},{"Data":STANDARD.encode(vec![7u8;1024]),"PartitionKey":"p","ExplicitHashKey":"0"},{"Data":STANDARD.encode(b"x"),"PartitionKey":"p","ExplicitHashKey":u128::MAX.to_string()}]);
        let Success::Json(value) = handler
            .put_records(request(&scope, records), &scope)
            .unwrap()
        else {
            panic!("json")
        };
        assert_eq!(value["FailedRecordCount"], 1);
        assert_eq!(value["Records"][0]["ShardId"], shard_id(0));
        assert_eq!(
            value["Records"][1]["ErrorCode"],
            "ProvisionedThroughputExceededException"
        );
        assert_eq!(value["Records"][2]["ShardId"], shard_id(1));
        assert!(matches!(handler.put_records(request(&scope,json!([{"Data":STANDARD.encode(b"x"),"PartitionKey":"p"},{"Data":"!","PartitionKey":"p"}])),&scope),Err(KinesisError::Serialization(_))));
        let foreign = Scope {
            region: "us-west-2".into(),
            account_id: scope.account_id.clone(),
        };
        assert!(matches!(
            handler.put_records(
                request(&scope, json!([{"Data":"eA==","PartitionKey":"p"}])),
                &foreign
            ),
            Err(KinesisError::ResourceNotFound(_))
        ));
        drop(handler);
        let mut handler = KinesisHandler::with_state(db.clone()).unwrap();
        handler.simulate_write_limits = true;
        handler.write_clock = || Ok(1_900_000_000.0);
        {
            let store = handler.lock_store().unwrap();
            let stream = &store.streams[&StreamKey::new(&scope, "events")];
            assert_eq!(
                stream
                    .shards
                    .iter()
                    .map(|s| s.next_position - s.first_position)
                    .sum::<usize>(),
                2
            );
            assert_eq!(stream.next_sequence, 3);
        }
        db.connection().unwrap().execute_batch("CREATE TRIGGER fail_batch BEFORE INSERT ON kinesis_shard_records WHEN NEW.partition_key='fail' BEGIN SELECT RAISE(ABORT,'injected');END;").unwrap();
        assert!(matches!(handler.put_records(request(&scope,json!([{"Data":"eA==","PartitionKey":"p"},{"Data":"eA==","PartitionKey":"fail"}])),&scope),Err(KinesisError::Internal)));
        assert!(
            handler.lock_store().unwrap().streams[&StreamKey::new(&scope, "events")]
                .shards
                .iter()
                .all(|shard| shard.write_window.records == 0)
        );
        drop(handler);
        let restored = KinesisHandler::with_state(db.clone()).unwrap();
        assert_eq!(
            restored.lock_store().unwrap().streams[&StreamKey::new(&scope, "events")].next_sequence,
            3
        );
        drop(restored);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn batch_limits_include_partition_keys_before_any_append() {
        let handler = KinesisHandler::new();
        super::super::tests::create(&handler);
        let scope = super::super::tests::scope();
        let one = json!({"Data":"eA==","PartitionKey":"p"});
        assert!(handler
            .put_records(request(&scope, json!(vec![one; 501])), &scope)
            .is_err());
        let data = STANDARD.encode(vec![0u8; MAX_RECORD_BYTES]);
        assert!(handler
            .put_records(
                request(&scope, json!([{"Data":data,"PartitionKey":"p"}])),
                &scope
            )
            .is_err());
        let data = STANDARD.encode(vec![0u8; MAX_RECORD_BYTES - 1]);
        let entry = json!({"Data":data,"PartitionKey":"p"});
        assert!(handler
            .put_records(request(&scope, json!(vec![entry; 11])), &scope)
            .is_err());
        assert_eq!(handler.lock_store().unwrap().buffered_bytes, 0);
    }
}
