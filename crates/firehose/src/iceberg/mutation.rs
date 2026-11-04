//! Partition-scoped Iceberg v2 equality deletes. Same-commit replacement data
//! and delete files share a sequence, so the delete applies only to older data.
use super::*;

pub(super) struct Group {
    pub partition: Option<String>,
    pub count: usize,
    pub data: Option<Vec<u8>>,
    pub deletes: Option<Vec<u8>>,
}

pub(super) fn key_fields(raw: &Value, names: &[String]) -> Result<Vec<Value>> {
    let fields = schema_fields(raw)?;
    let names = if names.is_empty() {
        let schema = raw["schemas"]
            .as_array()
            .and_then(|schemas| {
                schemas
                    .iter()
                    .find(|s| s["schema-id"] == raw["current-schema-id"])
            })
            .ok_or(Error::Unsupported)?;
        schema["identifier-field-ids"]
            .as_array()
            .ok_or(Error::Unsupported)?
            .iter()
            .map(|id| {
                fields
                    .iter()
                    .find(|field| field["id"] == *id)
                    .and_then(|field| field["name"].as_str())
                    .map(str::to_owned)
                    .ok_or(Error::Unsupported)
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        names.to_vec()
    };
    if names.is_empty() || names.len() > fields.len() {
        return Err(Error::Unsupported);
    }
    let mut seen = HashSet::new();
    names
        .iter()
        .map(|name| {
            if !seen.insert(name) {
                return Err(Error::Unsupported);
            }
            fields
                .iter()
                .find(|field| field["name"] == *name)
                .cloned()
                .ok_or(Error::Unsupported)
        })
        .collect()
}

fn canonical_key(value: &Value, fields: &[Value]) -> Result<String> {
    let values = fields
        .iter()
        .map(|field| {
            let name = field["name"].as_str().ok_or(Error::Unsupported)?;
            let value = value.get(name).unwrap_or(&Value::Null);
            if value.is_null() {
                if field["required"] == true {
                    return Err(Error::Unsupported);
                }
                return Ok(Value::Null);
            }
            match field["type"].as_str().ok_or(Error::Unsupported)? {
                "string" => value.as_str().map(|v| json!(v)).ok_or(Error::Unsupported),
                "boolean" => value.as_bool().map(|v| json!(v)).ok_or(Error::Unsupported),
                "int" => value
                    .as_i64()
                    .and_then(|v| i32::try_from(v).ok())
                    .map(|v| json!(v))
                    .ok_or(Error::Unsupported),
                "long" => value.as_i64().map(|v| json!(v)).ok_or(Error::Unsupported),
                "decimal(18,2)" | "decimal(18, 2)" => {
                    exact_cents(value.as_str().ok_or(Error::Unsupported)?).map(|v| json!(v))
                }
                "date" => {
                    let date = time::Date::parse(
                        value.as_str().ok_or(Error::Unsupported)?,
                        &time::format_description::parse_borrowed::<2>("[year]-[month]-[day]")
                            .map_err(|_| Error::Unsupported)?,
                    )
                    .map_err(|_| Error::Unsupported)?;
                    Ok(json!(date.to_julian_day()))
                }
                "timestamp" | "timestamptz" => {
                    let timestamp = time::OffsetDateTime::parse(
                        value.as_str().ok_or(Error::Unsupported)?,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .map_err(|_| Error::Unsupported)?;
                    Ok(json!(timestamp.unix_timestamp_nanos().to_string()))
                }
                _ => Err(Error::Unsupported),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    serde_json::to_string(&values).map_err(|_| Error::Unsupported)
}

pub(super) fn prepare_group(
    partition: Option<String>,
    records: Vec<Vec<u8>>,
    fields: &[Value],
    keys: &[Value],
    operation: WriteOperation,
) -> Result<Group> {
    if operation == WriteOperation::Insert {
        return Ok(Group {
            partition,
            count: records.len(),
            data: Some(parquet_rows(&records, fields)?),
            deletes: None,
        });
    }
    if operation == WriteOperation::Update {
        // Validate every source record before coalescing repeated keys.
        // A later valid update must not hide an invalid earlier payload.
        parquet_rows(&records, fields)?;
    }
    // A record later in the same buffered group replaces an earlier record
    // with the same key, rather than publishing duplicate same-sequence rows.
    let mut keyed = BTreeMap::new();
    for (index, record) in records.into_iter().enumerate() {
        let value: Value = serde_json::from_slice(&record).map_err(|_| Error::Unsupported)?;
        let key = canonical_key(&value, keys)?;
        keyed.insert(key, (index, value, record));
    }
    let mut values: Vec<_> = keyed.into_values().collect();
    values.sort_unstable_by_key(|(index, _, _)| *index);
    let mut deletes = Vec::with_capacity(values.len());
    for (_, value, _) in &values {
        let mut projected = serde_json::Map::new();
        for field in keys {
            let name = field["name"].as_str().ok_or(Error::Unsupported)?;
            projected.insert(name.into(), value.get(name).cloned().unwrap_or(Value::Null));
        }
        deletes.push(serde_json::to_vec(&projected).map_err(|_| Error::Unsupported)?);
    }
    let count = values.len();
    let records: Vec<_> = values.into_iter().map(|(_, _, record)| record).collect();
    Ok(Group {
        partition,
        count,
        data: match operation {
            WriteOperation::Insert | WriteOperation::Update => {
                Some(parquet_rows(&records, fields)?)
            }
            WriteOperation::Delete => None,
        },
        deletes: Some(parquet_rows(&deletes, keys)?),
    })
}

pub(super) async fn write_delete_manifest(
    ctx: &Context<'_>,
    metadata: &TableMetadata,
    io: &FileIO,
    batch: &str,
    snapshot: i64,
    sequence: i64,
    files: Vec<iceberg::spec::DataFile>,
) -> Result<iceberg::spec::ManifestFile> {
    let memory = format!("memory:///{batch}-{snapshot}-eq-delete.avro");
    let mut writer = ManifestWriterBuilder::new(
        io.new_output(&memory).map_err(|_| Error::Transient)?,
        Some(snapshot),
        metadata.current_schema().clone(),
        metadata.default_partition_spec().as_ref().clone(),
    )
    .build_v2_deletes();
    for file in files {
        writer
            .add_file(file, sequence)
            .map_err(|_| Error::Transient)?;
    }
    let mut descriptor = writer
        .write_manifest_file()
        .await
        .map_err(|_| Error::Transient)?;
    let bytes = io
        .new_input(&memory)
        .map_err(|_| Error::Transient)?
        .read()
        .await
        .map_err(|_| Error::Transient)?;
    if bytes.len() > MAX_BODY {
        return Err(Error::Unsupported);
    }
    descriptor.manifest_path = format!(
        "{}/metadata/{batch}-{snapshot}-eq-delete.avro",
        metadata.location().trim_end_matches('/')
    );
    ctx.put(&descriptor.manifest_path, bytes).await?;
    Ok(descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use parquet::record::RowAccessor;

    #[test]
    fn same_key_updates_keep_last_record_and_emit_only_key_columns() {
        let fields = vec![
            json!({"id":1,"name":"id","type":"long","required":true}),
            json!({"id":2,"name":"value","type":"string","required":false}),
        ];
        let records = [json!({"id":1,"value":"old"}), json!({"id":1,"value":"new"})]
            .iter()
            .map(|v| v.to_string().into_bytes())
            .collect();
        let group =
            prepare_group(None, records, &fields, &fields[..1], WriteOperation::Update).unwrap();
        assert_eq!(group.count, 1);
        let reader = SerializedFileReader::new(Bytes::from(group.data.unwrap())).unwrap();
        let row = reader.get_row_iter(None).unwrap().next().unwrap().unwrap();
        assert_eq!(row.get_string(1).unwrap(), "new");
        let reader = SerializedFileReader::new(Bytes::from(group.deletes.unwrap())).unwrap();
        let row = reader.get_row_iter(None).unwrap().next().unwrap().unwrap();
        assert_eq!(row.len(), 1);
        assert_eq!(row.get_long(0).unwrap(), 1);
    }

    #[test]
    fn missing_optional_key_matches_explicit_null_but_distinct_keys_stay_distinct() {
        let fields = vec![
            json!({"id":1,"name":"id","type":"long","required":true}),
            json!({"id":2,"name":"part","type":"int","required":false}),
            json!({"id":3,"name":"payload","type":"string","required":false}),
        ];
        let records = [
            json!({"id":1,"payload":"old"}),
            json!({"id":1,"part":null,"payload":"replacement"}),
            json!({"id":2,"part":null,"payload":"other"}),
        ]
        .iter()
        .map(|v| v.to_string().into_bytes())
        .collect();
        let group =
            prepare_group(None, records, &fields, &fields[..2], WriteOperation::Update).unwrap();
        assert_eq!(group.count, 2);
        let reader = SerializedFileReader::new(Bytes::from(group.data.unwrap())).unwrap();
        let rows = reader
            .get_row_iter(None)
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(rows[0].get_string(2).unwrap(), "replacement");
        assert_eq!(rows[1].get_string(2).unwrap(), "other");
    }

    #[test]
    fn delete_needs_only_keys_and_key_validation_is_explicit() {
        let fields = vec![
            json!({"id":1,"name":"id","type":"long","required":true}),
            json!({"id":2,"name":"value","type":"string","required":true}),
        ];
        let group = prepare_group(
            None,
            vec![br#"{"id":1}"#.to_vec()],
            &fields,
            &fields[..1],
            WriteOperation::Delete,
        )
        .unwrap();
        assert!(group.data.is_none());
        assert!(group.deletes.is_some());
        assert!(prepare_group(
            None,
            vec![br#"{"value":"x"}"#.to_vec()],
            &fields,
            &fields[..1],
            WriteOperation::Delete
        )
        .is_err());
        let raw = json!({"current-schema-id":0,"schemas":[{"schema-id":0,"fields":fields,"identifier-field-ids":[1]}]});
        assert_eq!(key_fields(&raw, &[]).unwrap().len(), 1);
        assert!(key_fields(&raw, &["missing".into()]).is_err());
        assert!(key_fields(&raw, &["id".into(), "id".into()]).is_err());
    }
}

#[cfg(test)]
mod commit_tests {
    use super::*;
    use crate::commit_test::{ConcurrentReads, FailOnce, Fixture, Stage};
    use locallycloud_core::registry::ServiceName;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::sync::Barrier;

    fn context(dispatcher: &locallycloud_core::integration::InternalDispatcher) -> Context<'_> {
        Context {
            dispatcher,
            account: "000000000000",
            region: "us-east-1",
            bucket: "ack-loss-lake",
            role_arn: "arn:aws:iam::000000000000:role/firehose",
        }
    }
    fn target() -> Target {
        Target {
            database: "lake".into(),
            table: "events".into(),
            bucket: "ack-loss-lake".into(),
        }
    }
    async fn mutate(
        fixture: &Fixture,
        token: Uuid,
        operation: WriteOperation,
        rows: &[Value],
    ) -> Result<()> {
        let dispatcher = fixture
            .registry
            .internal_dispatcher()
            .ok_or(Error::Transient)?;
        let records = rows
            .iter()
            .map(|row| serde_json::to_vec(row).map_err(|_| Error::Unsupported))
            .collect::<Result<Vec<_>>>()?;
        write(
            context(&dispatcher),
            &target(),
            token,
            &records,
            operation,
            &["id".into()],
        )
        .await
    }
    async fn metadata(fixture: &Fixture) -> (String, TableMetadata) {
        let dispatcher = fixture.registry.internal_dispatcher().unwrap();
        let ctx = context(&dispatcher);
        let (_, table) = ctx
            .glue("GetTable", json!({"DatabaseName":"lake","Name":"events"}))
            .await
            .unwrap();
        let pointer = table["Table"]["Parameters"]["metadata_location"]
            .as_str()
            .unwrap()
            .to_owned();
        let metadata = serde_json::from_slice(&ctx.get(&pointer).await.unwrap()).unwrap();
        (pointer, metadata)
    }
    async fn files(
        fixture: &Fixture,
        metadata: &TableMetadata,
    ) -> Vec<(iceberg::spec::DataFile, i64)> {
        let dispatcher = fixture.registry.internal_dispatcher().unwrap();
        let ctx = context(&dispatcher);
        let snapshot = metadata.current_snapshot().unwrap();
        let bytes = ctx.get(snapshot.manifest_list()).await.unwrap();
        let list = ManifestList::parse_with_version(&bytes, FormatVersion::V2).unwrap();
        let mut files = Vec::new();
        for descriptor in list.entries() {
            let bytes = ctx.get(&descriptor.manifest_path).await.unwrap();
            let manifest = Manifest::parse_avro(&bytes).unwrap();
            for entry in manifest.entries().iter().filter(|entry| entry.is_alive()) {
                files.push((
                    entry.data_file.clone(),
                    entry.sequence_number.unwrap_or(descriptor.sequence_number),
                ));
            }
        }
        files
    }

    #[tokio::test]
    async fn update_delete_publish_real_equality_files_with_replay_and_immutable_history() {
        let fixture = Fixture::new().await;
        let (old_pointer, old_metadata) = metadata(&fixture).await;
        let token = Uuid::new_v4();
        mutate(
            &fixture,
            token,
            WriteOperation::Update,
            &[json!({"id":0,"payload":"replacement"})],
        )
        .await
        .unwrap();
        let (pointer, updated) = metadata(&fixture).await;
        assert_ne!(pointer, old_pointer);
        let current = files(&fixture, &updated).await;
        let mut replacement = false;
        let mut deletion = false;
        for (file, sequence) in &current {
            match file.content_type() {
                DataContentType::EqualityDeletes => {
                    assert_eq!(file.equality_ids(), Some(vec![1]));
                    assert_eq!(*sequence, updated.last_sequence_number());
                    deletion = true;
                }
                DataContentType::Data if *sequence == updated.last_sequence_number() => {
                    replacement = true
                }
                DataContentType::Data => assert!(*sequence < updated.last_sequence_number()),
                _ => panic!("unexpected content"),
            }
        }
        assert!(replacement && deletion);
        assert_eq!(files(&fixture, &old_metadata).await.len(), 1);
        mutate(
            &fixture,
            token,
            WriteOperation::Update,
            &[json!({"id":0,"payload":"replacement"})],
        )
        .await
        .unwrap();
        assert_eq!(metadata(&fixture).await.0, pointer);
        mutate(
            &fixture,
            Uuid::new_v4(),
            WriteOperation::Delete,
            &[json!({"id":0})],
        )
        .await
        .unwrap();
        let (_, deleted) = metadata(&fixture).await;
        let current = files(&fixture, &deleted).await;
        assert_eq!(
            current
                .iter()
                .filter(|(file, _)| file.content_type() == DataContentType::Data)
                .count(),
            2
        );
        assert_eq!(
            current
                .iter()
                .filter(|(file, _)| file.content_type() == DataContentType::EqualityDeletes)
                .count(),
            2
        );
        assert_eq!(
            deleted.current_snapshot().unwrap().parent_snapshot_id(),
            updated.current_snapshot_id()
        );
    }

    #[tokio::test]
    async fn failed_mutation_publication_preserves_pointer_and_lost_ack_replays_once() {
        for (stage, after_write) in [(Stage::ManifestList, false), (Stage::Catalog, true)] {
            let fixture = Fixture::new().await;
            let baseline = metadata(&fixture).await.0;
            let service = if stage == Stage::Catalog {
                "glue"
            } else {
                "s3"
            };
            let handler = fixture.registry.lookup(&ServiceName::new(service)).unwrap();
            let fail = Arc::new(FailOnce {
                inner: handler.handler.unwrap(),
                stage,
                after_write,
                fired: AtomicBool::new(false),
            });
            fixture.registry.register_native(
                ServiceName::new(service),
                handler.metadata,
                fail.clone(),
            );
            let token = Uuid::new_v4();
            let rows = [json!({"id":0,"payload":"replacement"})];
            assert!(mutate(&fixture, token, WriteOperation::Update, &rows)
                .await
                .is_err());
            assert!(fail.fired.load(Ordering::Acquire));
            if !after_write {
                assert_eq!(metadata(&fixture).await.0, baseline);
            }
            mutate(&fixture, token, WriteOperation::Update, &rows)
                .await
                .unwrap();
            let (pointer, current) = metadata(&fixture).await;
            assert_eq!(current.last_sequence_number(), 2);
            mutate(&fixture, token, WriteOperation::Update, &rows)
                .await
                .unwrap();
            assert_eq!(metadata(&fixture).await.0, pointer);
            assert_eq!(files(&fixture, &current).await.len(), 3);
        }
    }

    #[tokio::test]
    async fn concurrent_mutations_retry_cas_without_changing_existing_sequences() {
        let fixture = Fixture::new().await;
        let glue = fixture.registry.lookup(&ServiceName::new("glue")).unwrap();
        let gate = Arc::new(ConcurrentReads {
            inner: glue.handler.unwrap(),
            barrier: Barrier::new(2),
            reads: AtomicUsize::new(0),
            conflicts: AtomicUsize::new(0),
            versions: Mutex::new(Vec::new()),
        });
        fixture
            .registry
            .register_native(ServiceName::new("glue"), glue.metadata, gate.clone());
        let a = [json!({"id":1,"payload":"one"})];
        let b = [json!({"id":2,"payload":"two"})];
        let (a, b) = tokio::join!(
            mutate(&fixture, Uuid::new_v4(), WriteOperation::Update, &a),
            mutate(&fixture, Uuid::new_v4(), WriteOperation::Update, &b)
        );
        a.unwrap();
        b.unwrap();
        assert!(gate.conflicts.load(Ordering::Acquire) > 0);
        let (_, current) = metadata(&fixture).await;
        assert_eq!(current.last_sequence_number(), 3);
        let files = files(&fixture, &current).await;
        assert_eq!(files.len(), 5);
        for sequence in [1, 2, 3] {
            assert!(files.iter().any(
                |(file, seq)| file.content_type() == DataContentType::Data && *seq == sequence
            ));
        }
    }
}
