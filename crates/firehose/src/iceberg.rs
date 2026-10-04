//! Narrow append-only Iceberg v2 delivery through the trusted service dispatcher.
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use iceberg::io::FileIO;
use iceberg::spec::{
    DataContentType, DataFileBuilder, DataFileFormat, FormatVersion, Literal, Manifest,
    ManifestList, ManifestListWriter, ManifestWriterBuilder, Operation, Snapshot, Struct, Summary,
    TableMetadata,
};
use locallycloud_core::integration::InternalDispatcher;
use parquet::data_type::{BoolType, ByteArray, ByteArrayType, Int32Type, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

// ponytail: bounded in-memory snapshot objects; stream S3 bodies if larger tables need support.
const MAX_BODY: usize = 12 * 1024 * 1024;
const MAX_SNAPSHOTS: usize = 32;
const MAX_MANIFESTS: usize = 256;
const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Target {
    pub database: String,
    pub table: String,
    pub bucket: String,
}

pub(super) struct Context<'a> {
    pub dispatcher: &'a InternalDispatcher,
    pub account: &'a str,
    pub region: &'a str,
    pub bucket: &'a str,
}

#[derive(Debug)]
pub(super) enum Error {
    Unsupported,
    Transient,
}

type Result<T> = std::result::Result<T, Error>;

impl Context<'_> {
    async fn call(
        &self,
        method: Method,
        uri: Uri,
        target: Option<&str>,
        body: Bytes,
    ) -> Result<(http::StatusCode, Bytes)> {
        let mut headers = HeaderMap::new();
        if let Some(target) = target {
            headers.insert(
                "x-amz-target",
                HeaderValue::from_str(target).map_err(|_| Error::Unsupported)?,
            );
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-amz-json-1.1"),
            );
            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_static(
                    "AWS4-HMAC-SHA256 Credential=local/19700101/us-east-1/glue/aws4_request",
                ),
            );
        } else {
            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_static(
                    "AWS4-HMAC-SHA256 Credential=local/19700101/us-east-1/s3/aws4_request",
                ),
            );
        }
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.dispatcher.dispatch_scoped(
                &method,
                &uri,
                &headers,
                body,
                &Uuid::new_v4().to_string(),
                self.account,
                self.region,
            ),
        )
        .await
        .map_err(|_| Error::Transient)?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), MAX_BODY)
            .await
            .map_err(|_| Error::Transient)?;
        Ok((status, bytes))
    }

    async fn glue(&self, operation: &str, body: Value) -> Result<(http::StatusCode, Value)> {
        let (status, body) = self
            .call(
                Method::POST,
                "/".parse().map_err(|_| Error::Unsupported)?,
                Some(&format!("AWSGlue.{operation}")),
                Bytes::from(body.to_string()),
            )
            .await?;
        let value = serde_json::from_slice(&body).map_err(|_| Error::Transient)?;
        Ok((status, value))
    }

    async fn get(&self, location: &str) -> Result<Bytes> {
        let uri = s3_uri(location, self.bucket)?;
        let (status, body) = self.call(Method::GET, uri, None, Bytes::new()).await?;
        if status.is_success() {
            Ok(body)
        } else if status == http::StatusCode::NOT_FOUND {
            Err(Error::Unsupported)
        } else {
            Err(Error::Transient)
        }
    }

    async fn put(&self, location: &str, body: Bytes) -> Result<()> {
        let uri = s3_uri(location, self.bucket)?;
        let (status, _) = self.call(Method::PUT, uri, None, body).await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(Error::Transient)
        }
    }
}

fn s3_uri(location: &str, allowed_bucket: &str) -> Result<Uri> {
    let path = location.strip_prefix("s3://").ok_or(Error::Unsupported)?;
    let (bucket, key) = path.split_once('/').ok_or(Error::Unsupported)?;
    if bucket != allowed_bucket
        || bucket.is_empty()
        || key.is_empty()
        || bucket.contains('/')
        || key.contains('?')
        || key.contains('#')
    {
        return Err(Error::Unsupported);
    }
    format!("/{bucket}/{key}")
        .parse()
        .map_err(|_| Error::Unsupported)
}

// Destination metadata is authoritative; admission only checks the flat JSON envelope.
pub(super) fn valid_record(record: &[u8]) -> bool {
    serde_json::from_slice::<Value>(record)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .is_some_and(|v| !v.is_empty() && v.values().all(|v| !v.is_object() && !v.is_array()))
}

fn schema_fields(raw: &Value) -> Result<&Vec<Value>> {
    raw["schemas"]
        .as_array()
        .and_then(|schemas| {
            schemas
                .iter()
                .find(|schema| schema["schema-id"] == raw["current-schema-id"])
        })
        .and_then(|schema| schema["fields"].as_array())
        .ok_or(Error::Unsupported)
}

fn parquet_type(kind: &str) -> Result<&'static str> {
    match kind {
        "long" => Ok("INT64"),
        "int" => Ok("INT32"),
        "string" => Ok("BYTE_ARRAY (UTF8)"),
        "boolean" => Ok("BOOLEAN"),
        "date" => Ok("INT32 (DATE)"),
        "timestamp" => Ok("INT64 (TIMESTAMP(MICROS,false))"),
        "timestamptz" => Ok("INT64 (TIMESTAMP(MICROS,true))"),
        "decimal(18, 2)" | "decimal(18,2)" => Ok("INT64 (DECIMAL(18,2))"),
        _ => Err(Error::Unsupported),
    }
}

fn exact_cents(value: &str) -> Result<i64> {
    let negative = value.starts_with('-');
    let value = value.strip_prefix('-').unwrap_or(value);
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 2
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::Unsupported);
    }
    let whole: i64 = whole.parse().map_err(|_| Error::Unsupported)?;
    let fraction: i64 = format!("{fraction:0<2}")
        .parse()
        .map_err(|_| Error::Unsupported)?;
    let cents = whole
        .checked_mul(100)
        .and_then(|w| w.checked_add(fraction))
        .ok_or(Error::Unsupported)?;
    if cents >= 1_000_000_000_000_000_000 {
        return Err(Error::Unsupported);
    }
    Ok(if negative { -cents } else { cents })
}

fn parquet_rows(records: &[Vec<u8>], fields: &[Value]) -> Result<Vec<u8>> {
    let rows = records
        .iter()
        .map(|record| serde_json::from_slice::<Value>(record).map_err(|_| Error::Unsupported))
        .collect::<Result<Vec<_>>>()?;
    for row in &rows {
        let object = row.as_object().ok_or(Error::Unsupported)?;
        if object
            .keys()
            .any(|name| !fields.iter().any(|f| f["name"] == *name))
        {
            return Err(Error::Unsupported);
        }
    }
    let mut schema = String::from("message events {");
    for field in fields {
        let name = field["name"].as_str().ok_or(Error::Unsupported)?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(Error::Unsupported);
        }
        let kind = parquet_type(field["type"].as_str().ok_or(Error::Unsupported)?)?;
        // Parquet grammar puts logical annotation after the field name.
        let (physical, logical) = kind.split_once(' ').unwrap_or((kind, ""));
        schema.push_str(&format!(
            " {} {physical} {name} {logical} = {};",
            if field["required"] == true {
                "REQUIRED"
            } else {
                "OPTIONAL"
            },
            field["id"].as_i64().ok_or(Error::Unsupported)?
        ));
    }
    schema.push('}');
    let schema = Arc::new(parse_message_type(&schema).map_err(|_| Error::Unsupported)?);
    let mut bytes = Vec::new();
    let mut writer = SerializedFileWriter::new(
        &mut bytes,
        schema,
        Arc::new(WriterProperties::builder().build()),
    )
    .map_err(|_| Error::Transient)?;
    let mut group = writer.next_row_group().map_err(|_| Error::Transient)?;
    for field in fields {
        let name = field["name"].as_str().ok_or(Error::Unsupported)?;
        let kind = field["type"].as_str().ok_or(Error::Unsupported)?;
        let required = field["required"] == true;
        let mut levels = Vec::new();
        let mut values = Vec::new();
        for row in &rows {
            let value = &row[name];
            if value.is_null() {
                if required {
                    return Err(Error::Unsupported);
                }
                levels.push(0);
            } else {
                levels.push(1);
                values.push(value);
            }
        }
        let levels = if required {
            None
        } else {
            Some(levels.as_slice())
        };
        let mut column = group
            .next_column()
            .map_err(|_| Error::Transient)?
            .ok_or(Error::Transient)?;
        match kind {
            "string" => {
                let values = values
                    .iter()
                    .map(|v| v.as_str().map(ByteArray::from).ok_or(Error::Unsupported))
                    .collect::<Result<Vec<_>>>()?;
                column
                    .typed::<ByteArrayType>()
                    .write_batch(&values, levels, None)
                    .map_err(|_| Error::Transient)?;
            }
            "boolean" => {
                let values = values
                    .iter()
                    .map(|v| v.as_bool().ok_or(Error::Unsupported))
                    .collect::<Result<Vec<_>>>()?;
                column
                    .typed::<BoolType>()
                    .write_batch(&values, levels, None)
                    .map_err(|_| Error::Transient)?;
            }
            "int" | "date" => {
                let values = values
                    .iter()
                    .map(|v| {
                        if kind == "int" {
                            return v
                                .as_i64()
                                .and_then(|v| i32::try_from(v).ok())
                                .ok_or(Error::Unsupported);
                        }
                        let date = time::Date::parse(
                            v.as_str().ok_or(Error::Unsupported)?,
                            &time::format_description::parse_borrowed::<2>("[year]-[month]-[day]")
                                .map_err(|_| Error::Unsupported)?,
                        )
                        .map_err(|_| Error::Unsupported)?;
                        Ok(date.to_julian_day() - 2_440_588)
                    })
                    .collect::<Result<Vec<_>>>()?;
                column
                    .typed::<Int32Type>()
                    .write_batch(&values, levels, None)
                    .map_err(|_| Error::Transient)?;
            }
            _ => {
                let values = values
                    .iter()
                    .map(|v| match kind {
                        "long" => v.as_i64().ok_or(Error::Unsupported),
                        "decimal(18,2)" | "decimal(18, 2)" => {
                            exact_cents(v.as_str().ok_or(Error::Unsupported)?)
                        }
                        "timestamp" | "timestamptz" => {
                            let date = time::OffsetDateTime::parse(
                                v.as_str().ok_or(Error::Unsupported)?,
                                &time::format_description::well_known::Rfc3339,
                            )
                            .map_err(|_| Error::Unsupported)?;
                            if date.unix_timestamp_nanos() % 1000 != 0
                                || (kind == "timestamp" && date.offset() != time::UtcOffset::UTC)
                            {
                                return Err(Error::Unsupported);
                            }
                            i64::try_from(date.unix_timestamp_nanos() / 1000)
                                .map_err(|_| Error::Unsupported)
                        }
                        _ => Err(Error::Unsupported),
                    })
                    .collect::<Result<Vec<_>>>()?;
                column
                    .typed::<Int64Type>()
                    .write_batch(&values, levels, None)
                    .map_err(|_| Error::Transient)?;
            }
        }
        column.close().map_err(|_| Error::Transient)?;
    }
    group.close().map_err(|_| Error::Transient)?;
    writer.close().map_err(|_| Error::Transient)?;
    Ok(bytes)
}

fn partition_column(raw: &Value) -> Result<Option<&str>> {
    let spec = raw["partition-specs"]
        .as_array()
        .and_then(|specs| {
            specs
                .iter()
                .find(|spec| spec["spec-id"] == raw["default-spec-id"])
        })
        .ok_or(Error::Unsupported)?;
    let partitions = spec["fields"].as_array().ok_or(Error::Unsupported)?;
    if partitions.is_empty() {
        return Ok(None);
    }
    if partitions.len() != 1 || partitions[0]["transform"] != "identity" {
        return Err(Error::Unsupported);
    }
    let field = schema_fields(raw)?
        .iter()
        .find(|f| f["id"] == partitions[0]["source-id"])
        .ok_or(Error::Unsupported)?;
    if field["type"] != "date" || field["required"] != true {
        return Err(Error::Unsupported);
    }
    field["name"].as_str().map(Some).ok_or(Error::Unsupported)
}

fn validate_metadata(raw: &Value, metadata: &TableMetadata, bucket: &str) -> Result<()> {
    if metadata.format_version() != FormatVersion::V2 {
        return Err(Error::Unsupported);
    }
    for entry in metadata.metadata_log() {
        s3_uri(&entry.metadata_file, bucket)?;
    }
    for entry in metadata.statistics_iter() {
        s3_uri(&entry.statistics_path, bucket)?;
    }
    for entry in metadata.partition_statistics_iter() {
        s3_uri(&entry.statistics_path, bucket)?;
    }
    partition_column(raw)?;
    let fields = schema_fields(raw)?;
    if fields.is_empty() || fields.len() > 32 {
        return Err(Error::Unsupported);
    }
    for field in fields {
        if field.get("initial-default").is_some_and(|v| !v.is_null())
            || field.get("write-default").is_some_and(|v| !v.is_null())
        {
            return Err(Error::Unsupported);
        }
        let name = field["name"].as_str().ok_or(Error::Unsupported)?;
        if !name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(Error::Unsupported);
        }
        parquet_type(field["type"].as_str().ok_or(Error::Unsupported)?)?;
    }
    Ok(())
}

async fn inspect(
    ctx: &Context<'_>,
    target: &Target,
) -> Result<(
    Value,
    String,
    TableMetadata,
    Vec<iceberg::spec::ManifestFile>,
    usize,
)> {
    let (status, response) = ctx
        .glue(
            "GetTable",
            json!({"DatabaseName":target.database,"Name":target.table}),
        )
        .await?;
    if !status.is_success() {
        return Err(Error::Unsupported);
    }
    let table = response["Table"].clone();
    table["VersionId"].as_str().ok_or(Error::Unsupported)?;
    let metadata_uri = table["Parameters"]["metadata_location"]
        .as_str()
        .ok_or(Error::Unsupported)?
        .to_owned();
    let raw = ctx.get(&metadata_uri).await?;
    let raw_value: Value = serde_json::from_slice(&raw).map_err(|_| Error::Unsupported)?;
    let metadata: TableMetadata = serde_json::from_slice(&raw).map_err(|_| Error::Unsupported)?;
    validate_metadata(&raw_value, &metadata, ctx.bucket)?;
    if !metadata
        .location()
        .trim_end_matches('/')
        .starts_with(&format!("s3://{}/", target.bucket))
        || metadata.snapshots().len() > MAX_SNAPSHOTS
    {
        return Err(Error::Unsupported);
    }
    let mut manifests = Vec::new();
    let mut history_bytes = 0usize;
    let mut manifest_count = 0usize;
    // A new metadata file retains all snapshots, including those used for time travel.
    for snapshot in metadata.snapshots() {
        let previous = ctx.get(snapshot.manifest_list()).await?;
        history_bytes = history_bytes.saturating_add(previous.len());
        if history_bytes > MAX_HISTORY_BYTES {
            return Err(Error::Unsupported);
        }
        let previous_manifests: Vec<_> =
            ManifestList::parse_with_version(&previous, FormatVersion::V2)
                .map_err(|_| Error::Unsupported)?
                .consume_entries()
                .into_iter()
                .collect();
        for manifest in previous_manifests {
            manifest_count += 1;
            if manifest_count > MAX_MANIFESTS {
                return Err(Error::Unsupported);
            }
            let bytes = ctx.get(&manifest.manifest_path).await?;
            history_bytes = history_bytes.saturating_add(bytes.len());
            if history_bytes > MAX_HISTORY_BYTES {
                return Err(Error::Unsupported);
            }
            let parsed = Manifest::parse_avro(&bytes).map_err(|_| Error::Unsupported)?;
            for entry in parsed.entries() {
                s3_uri(entry.file_path(), ctx.bucket)?;
            }
            if Some(snapshot.snapshot_id()) == metadata.current_snapshot_id() {
                manifests.push(manifest);
            }
        }
    }
    Ok((table, metadata_uri, metadata, manifests, manifest_count))
}

pub(super) async fn preflight(ctx: Context<'_>, target: &Target) -> Result<()> {
    let (_, _, metadata, _, manifest_count) = inspect(&ctx, target).await?;
    if metadata.snapshots().len() >= MAX_SNAPSHOTS || manifest_count >= MAX_MANIFESTS {
        return Err(Error::Unsupported);
    }
    Ok(())
}

pub(super) async fn append(
    ctx: Context<'_>,
    target: &Target,
    token: Uuid,
    records: &[Vec<u8>],
) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    // The data file URI remains fixed across CAS retries; failed attempts are unreachable until commit.
    let batch = token.to_string();
    for _ in 0..3 {
        let (table, metadata_uri, metadata, mut manifests, manifest_count) =
            inspect(&ctx, target).await?;
        let raw = serde_json::to_value(&metadata).map_err(|_| Error::Unsupported)?;
        let version = table["VersionId"].as_str().ok_or(Error::Unsupported)?;
        let root = metadata.location().trim_end_matches('/');
        if metadata.snapshots().any(|snapshot| {
            snapshot
                .summary()
                .additional_properties
                .get("locallycloud.batch-token")
                == Some(&batch)
        }) {
            return Ok(());
        }
        let mut groups: BTreeMap<Option<String>, Vec<Vec<u8>>> = BTreeMap::new();
        for record in records {
            let value: Value = serde_json::from_slice(record).map_err(|_| Error::Unsupported)?;
            let partition = partition_column(&raw)?
                .map(|name| {
                    value[name]
                        .as_str()
                        .map(str::to_owned)
                        .ok_or(Error::Unsupported)
                })
                .transpose()?;
            groups.entry(partition).or_default().push(record.clone());
        }
        // Validate every partition before writing any object.
        let groups = groups
            .into_iter()
            .map(|(partition, records)| {
                let parquet = parquet_rows(&records, schema_fields(&raw)?)?;
                Ok((partition, records.len(), parquet))
            })
            .collect::<Result<Vec<_>>>()?;
        // The new snapshot and manifest must also fit the published beta bounds.
        if metadata.snapshots().len() >= MAX_SNAPSHOTS || manifest_count >= MAX_MANIFESTS {
            return Err(Error::Unsupported);
        }
        let snapshot_id = (Uuid::new_v4().as_u128() & i64::MAX as u128) as i64;
        let seq = metadata.next_sequence_number();
        let manifest_uri = format!("{root}/metadata/{batch}-{snapshot_id}.avro");
        let list_uri = format!("{root}/metadata/{batch}-{snapshot_id}-list.avro");
        let new_meta_uri = format!("{root}/metadata/{batch}-{snapshot_id}.metadata.json");
        let mut files = Vec::new();
        for (partition, count, parquet) in groups {
            let suffix = partition.as_deref().unwrap_or("unpartitioned");
            let data_uri = format!("{root}/data/{batch}-{suffix}.parquet");
            let partition = match partition {
                Some(date) => Struct::from_iter([Some(
                    Literal::date_from_str(date).map_err(|_| Error::Unsupported)?,
                )]),
                None => Struct::empty(),
            };
            let size = parquet.len();
            ctx.put(&data_uri, Bytes::from(parquet)).await?;
            files.push(
                DataFileBuilder::default()
                    .content(DataContentType::Data)
                    .file_path(data_uri)
                    .file_format(DataFileFormat::Parquet)
                    .record_count(count as u64)
                    .file_size_in_bytes(size as u64)
                    .partition(partition)
                    .partition_spec_id(metadata.default_partition_spec_id())
                    .build()
                    .map_err(|_| Error::Unsupported)?,
            );
        }
        let io = FileIO::new_with_memory();
        let manifest_mem = format!("memory:///{batch}-{snapshot_id}.avro");
        let output = io.new_output(&manifest_mem).map_err(|_| Error::Transient)?;
        let mut writer = ManifestWriterBuilder::new(
            output,
            Some(snapshot_id),
            metadata.current_schema().clone(),
            metadata.default_partition_spec().as_ref().clone(),
        )
        .build_v2_data();
        for file in files {
            writer.add_file(file, seq).map_err(|_| Error::Transient)?;
        }
        let mut manifest = writer
            .write_manifest_file()
            .await
            .map_err(|_| Error::Transient)?;
        let manifest_bytes = io
            .new_input(&manifest_mem)
            .map_err(|_| Error::Transient)?
            .read()
            .await
            .map_err(|_| Error::Transient)?;
        manifest.manifest_path = manifest_uri.clone();
        ctx.put(&manifest_uri, manifest_bytes).await?;
        manifests.push(manifest);
        let list_mem = format!("memory:///{batch}-{snapshot_id}-list.avro");
        let mut list_writer = ManifestListWriter::v2(
            io.new_output(&list_mem)
                .map_err(|_| Error::Transient)?
                .writer()
                .await
                .map_err(|_| Error::Transient)?,
            snapshot_id,
            metadata.current_snapshot_id(),
            seq,
        );
        list_writer
            .add_manifests(manifests.into_iter())
            .map_err(|_| Error::Transient)?;
        list_writer.close().await.map_err(|_| Error::Transient)?;
        let list_bytes = io
            .new_input(&list_mem)
            .map_err(|_| Error::Transient)?
            .read()
            .await
            .map_err(|_| Error::Transient)?;
        ctx.put(&list_uri, list_bytes).await?;
        let snapshot = Snapshot::builder()
            .with_snapshot_id(snapshot_id)
            .with_parent_snapshot_id(metadata.current_snapshot_id())
            .with_sequence_number(seq)
            .with_timestamp_ms(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Error::Transient)?
                    .as_millis() as i64,
            )
            .with_manifest_list(list_uri)
            .with_summary(Summary {
                operation: Operation::Append,
                additional_properties: HashMap::from([(
                    "locallycloud.batch-token".into(),
                    batch.clone(),
                )]),
            })
            .with_schema_id(metadata.current_schema_id())
            .build();
        let updated = metadata
            .into_builder(Some(metadata_uri))
            .set_branch_snapshot(snapshot, "main")
            .map_err(|_| Error::Transient)?
            .build()
            .map_err(|_| Error::Transient)?
            .metadata;
        let updated_bytes = serde_json::to_vec(&updated).map_err(|_| Error::Transient)?;
        ctx.put(&new_meta_uri, Bytes::from(updated_bytes)).await?;
        let mut input = table.as_object().ok_or(Error::Unsupported)?.clone();
        for key in [
            "CatalogId",
            "DatabaseName",
            "CreateTime",
            "UpdateTime",
            "VersionId",
        ] {
            input.remove(key);
        }
        input.entry("Parameters").or_insert_with(|| json!({}))["metadata_location"] =
            json!(new_meta_uri);
        let (status, response) = ctx.glue("UpdateTable", json!({"DatabaseName":target.database,"TableInput":input,"VersionId":version,"SkipArchive":true})).await?;
        if status.is_success() {
            return Ok(());
        }
        let error = response["__type"].as_str().unwrap_or_default();
        if !error.contains("ConcurrentModificationException") {
            return Err(Error::Transient);
        }
    }
    Err(Error::Transient)
}

#[cfg(test)]
mod tests {
    use super::s3_uri;

    #[test]
    fn iceberg_s3_access_stays_in_authorized_bucket() {
        assert!(s3_uri("s3://lake/table/metadata.json", "lake").is_ok());
        assert!(s3_uri("s3://other/table/metadata.json", "lake").is_err());
        assert!(s3_uri("s3://lake-other/table/metadata.json", "lake").is_err());
    }
}
