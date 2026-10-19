//! Narrow append-only Iceberg v2 delivery through the trusted service dispatcher.
mod replay;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use iceberg::io::FileIO;
use iceberg::spec::{
    DataContentType, DataFileBuilder, DataFileFormat, FormatVersion, Literal, Manifest,
    ManifestContentType, ManifestEntry, ManifestList, ManifestListWriter, ManifestStatus,
    ManifestWriterBuilder, Operation, Snapshot, SnapshotReference, SnapshotRetention, Struct,
    Summary, TableMetadata,
};
use locallycloud_core::integration::identity::{CallerIdentity, IdentityPropagator};
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
pub(super) const MAX_S3_ERROR_BODY: usize = 8192;
const MAX_SNAPSHOTS: usize = 32;
const MAX_MANIFESTS: usize = 256;
const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;
const RETENTION_ENABLED: &str = "locallycloud.firehose.snapshot-retention-enabled";
const COMMITTED_TOKENS: &str = "locallycloud.firehose.committed-batch-tokens";
const MAX_REPLAY_TOKENS: usize = 256;
const MERGE_MANIFEST_COUNT: usize = 16;
const MAX_COMPACTED_FILES: usize = 4096;

// Only opted-in maintenance rewrites current manifests; historical objects remain immutable.
async fn compacted_entries(
    ctx: &Context<'_>,
    metadata: &TableMetadata,
    manifests: &[iceberg::spec::ManifestFile],
) -> Result<Option<Vec<ManifestEntry>>> {
    if metadata
        .properties()
        .get(RETENTION_ENABLED)
        .map(String::as_str)
        != Some("true")
        || manifests.len() < MERGE_MANIFEST_COUNT
    {
        return Ok(None);
    }
    let mut entries = Vec::new();
    let mut paths = HashSet::new();
    let mut bytes_read = 0usize;
    for descriptor in manifests {
        if descriptor.content != ManifestContentType::Data
            || descriptor.partition_spec_id != metadata.default_partition_spec_id()
        {
            return Err(Error::Unsupported);
        }
        let bytes = ctx.get(&descriptor.manifest_path).await?;
        bytes_read = bytes_read.saturating_add(bytes.len());
        if bytes_read > MAX_HISTORY_BYTES {
            return Err(Error::Unsupported);
        }
        let manifest = Manifest::parse_avro(&bytes).map_err(|_| Error::Unsupported)?;
        if manifest.metadata().content != ManifestContentType::Data
            || manifest.metadata().partition_spec.spec_id() != descriptor.partition_spec_id
        {
            return Err(Error::Unsupported);
        }
        for entry in manifest.entries() {
            if !entry.is_alive()
                || entry.content_type() != DataContentType::Data
                || !paths.insert(entry.file_path().to_owned())
                || entries.len() >= MAX_COMPACTED_FILES
            {
                return Err(Error::Unsupported);
            }
            s3_uri(entry.file_path(), ctx.bucket)?;
            let mut entry = entry.as_ref().clone();
            // Null tracking fields inherit from the original descriptor only for ADDED files.
            if entry.status == ManifestStatus::Added {
                entry
                    .snapshot_id
                    .get_or_insert(descriptor.added_snapshot_id);
                entry
                    .sequence_number
                    .get_or_insert(descriptor.sequence_number);
                entry
                    .file_sequence_number
                    .get_or_insert(descriptor.sequence_number);
            }
            if entry.snapshot_id.is_none()
                || !entry
                    .sequence_number
                    .is_some_and(|n| n >= 0 && n <= metadata.last_sequence_number())
                || !entry
                    .file_sequence_number
                    .is_some_and(|n| n >= 0 && n <= metadata.last_sequence_number())
            {
                return Err(Error::Unsupported);
            }
            entries.push(entry);
        }
    }
    Ok(Some(entries))
}

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
    pub role_arn: &'a str,
}

#[derive(Debug)]
pub(super) enum Error {
    Unsupported,
    Transient,
    NoSuchTable,
    GlueAccessDenied,
    S3AccessDenied,
}

type Result<T> = std::result::Result<T, Error>;

pub(super) fn s3_access_denied(status: http::StatusCode, body: &[u8]) -> bool {
    use quick_xml::events::Event;
    if status != http::StatusCode::FORBIDDEN || body.len() > MAX_S3_ERROR_BODY {
        return false;
    }
    let mut reader = quick_xml::Reader::from_reader(body);
    let mut depth = 0_u8;
    let mut root_seen = false;
    let mut in_code = false;
    let mut code = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) => {
                if in_code || depth >= 8 {
                    return false;
                }
                if depth == 0 {
                    if root_seen || tag.local_name().as_ref() != "Error" {
                        return false;
                    }
                    root_seen = true;
                }
                depth += 1;
                if depth == 2 && tag.local_name().as_ref() == "Code" {
                    if code.is_some() {
                        return false;
                    }
                    in_code = true;
                }
            }
            Ok(Event::Text(text)) if in_code => {
                if code.is_some() {
                    return false;
                }
                code = Some(text.as_ref() == "AccessDenied");
            }
            Ok(Event::Text(text))
                if depth == 0 && !text.as_ref().bytes().all(|b| b.is_ascii_whitespace()) =>
            {
                return false
            }
            Ok(Event::End(_)) => {
                if depth == 0 || (in_code && code.is_none()) {
                    return false;
                }
                in_code = false;
                depth -= 1;
            }
            Ok(Event::Empty(tag))
                if depth == 0
                    || depth >= 8
                    || in_code
                    || (depth == 1 && tag.local_name().as_ref() == "Code") =>
            {
                return false
            }
            Ok(Event::DocType(_)) | Err(_) => return false,
            Ok(Event::CData(_) | Event::GeneralRef(_)) if in_code || depth == 0 => return false,
            Ok(Event::Decl(_)) if root_seen => return false,
            Ok(Event::Eof) => return root_seen && depth == 0 && code == Some(true),
            _ => {}
        }
    }
}

impl Context<'_> {
    async fn call(
        &self,
        method: Method,
        uri: Uri,
        target: Option<&str>,
        body: Bytes,
    ) -> Result<(http::StatusCode, Bytes)> {
        self.call_limited(method, uri, target, body, MAX_BODY).await
    }

    async fn call_limited(
        &self,
        method: Method,
        uri: Uri,
        target: Option<&str>,
        body: Bytes,
        limit: usize,
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
        IdentityPropagator::attach(
            &mut headers,
            &CallerIdentity::AssumedRole {
                role_arn: self.role_arn.to_owned(),
                session_name: "firehose".into(),
            },
        );
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
        let bytes = axum::body::to_bytes(response.into_body(), limit)
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
        let value: Value = serde_json::from_slice(&body).map_err(|_| Error::Transient)?;
        let code = value["__type"]
            .as_str()
            .unwrap_or_default()
            .rsplit('#')
            .next();
        if matches!(
            status,
            http::StatusCode::BAD_REQUEST | http::StatusCode::FORBIDDEN
        ) && code == Some("AccessDeniedException")
        {
            return Err(Error::GlueAccessDenied);
        }
        Ok((status, value))
    }

    async fn get(&self, location: &str) -> Result<Bytes> {
        self.get_limited(location, MAX_BODY).await
    }

    async fn get_limited(&self, location: &str, limit: usize) -> Result<Bytes> {
        let uri = s3_uri(location, self.bucket)?;
        let (status, body) = self
            .call_limited(Method::GET, uri, None, Bytes::new(), limit)
            .await?;
        match status {
            status if status.is_success() => Ok(body),
            http::StatusCode::FORBIDDEN if s3_access_denied(status, &body) => {
                Err(Error::S3AccessDenied)
            }
            http::StatusCode::NOT_FOUND => Err(Error::Unsupported),
            _ => Err(Error::Transient),
        }
    }

    async fn put(&self, location: &str, body: Bytes) -> Result<()> {
        let uri = s3_uri(location, self.bucket)?;
        let (status, body) = self.call(Method::PUT, uri, None, body).await?;
        match status {
            status if status.is_success() => Ok(()),
            http::StatusCode::FORBIDDEN if s3_access_denied(status, &body) => {
                Err(Error::S3AccessDenied)
            }
            _ => Err(Error::Transient),
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

fn committed_tokens(metadata: &TableMetadata) -> Result<BTreeSet<String>> {
    let Some(value) = metadata.properties().get(COMMITTED_TOKENS) else {
        return Ok(BTreeSet::new());
    };
    if value.len() > MAX_REPLAY_TOKENS * 40 {
        return Err(Error::Unsupported);
    }
    let tokens: Vec<String> = serde_json::from_str(value).map_err(|_| Error::Unsupported)?;
    if tokens.len() > MAX_REPLAY_TOKENS {
        return Err(Error::Unsupported);
    }
    let mut receipts = BTreeSet::new();
    for token in tokens {
        let parsed = Uuid::parse_str(&token).map_err(|_| Error::Unsupported)?;
        if parsed.to_string() != token || !receipts.insert(token) {
            return Err(Error::Unsupported);
        }
    }
    Ok(receipts)
}

fn retain_lineage(
    metadata: &TableMetadata,
    head: i64,
    minimum: usize,
    cutoff: i64,
    retained: &mut HashSet<i64>,
) -> Result<HashSet<i64>> {
    let mut next = Some(head);
    let mut visited = HashSet::new();
    while let Some(id) = next {
        let Some(snapshot) = metadata.snapshot_by_id(id) else {
            break;
        };
        if !visited.insert(id) || visited.len() > MAX_SNAPSHOTS {
            return Err(Error::Unsupported);
        }
        if visited.len() <= minimum || snapshot.timestamp_ms() >= cutoff {
            retained.insert(id);
        }
        next = snapshot.parent_snapshot_id();
    }
    Ok(visited)
}

fn retention_plan(
    metadata: &TableMetadata,
    raw: &Value,
    mut receipts: BTreeSet<String>,
) -> Result<(Vec<i64>, BTreeSet<String>)> {
    let enabled = metadata
        .properties()
        .get(RETENTION_ENABLED)
        .map(|value| value.parse::<bool>())
        .transpose()
        .map_err(|_| Error::Unsupported)?
        .unwrap_or(false);
    if !enabled {
        return Ok((Vec::new(), receipts));
    }
    let properties = metadata.table_properties();
    if !properties.gc_enabled().map_err(|_| Error::Unsupported)? {
        return Err(Error::Unsupported);
    }
    let default_age = properties
        .max_snapshot_age_ms()
        .map_err(|_| Error::Unsupported)?;
    let mut age = default_age;
    let mut minimum = properties
        .min_snapshots_to_keep()
        .map_err(|_| Error::Unsupported)?;
    if default_age <= 0 || !(1..=MAX_SNAPSHOTS).contains(&minimum) {
        return Err(Error::Unsupported);
    }
    let references = raw
        .get("refs")
        .map(|refs| refs.as_object().ok_or(Error::Unsupported))
        .transpose()?;
    if references.is_some_and(|refs| refs.len() > MAX_SNAPSHOTS) {
        return Err(Error::Unsupported);
    }
    let mut protected = HashSet::new();
    for (name, value) in references.into_iter().flat_map(|refs| refs.iter()) {
        let reference: SnapshotReference =
            serde_json::from_value(value.clone()).map_err(|_| Error::Unsupported)?;
        if metadata.snapshot_by_id(reference.snapshot_id).is_none() {
            return Err(Error::Unsupported);
        }
        match (name.as_str(), reference.retention) {
            (
                "main",
                SnapshotRetention::Branch {
                    min_snapshots_to_keep,
                    max_snapshot_age_ms,
                    ..
                },
            ) => {
                if Some(reference.snapshot_id) != metadata.current_snapshot_id() {
                    return Err(Error::Unsupported);
                }
                if let Some(value) = min_snapshots_to_keep {
                    minimum = usize::try_from(value).map_err(|_| Error::Unsupported)?;
                }
                if let Some(value) = max_snapshot_age_ms {
                    age = value;
                }
            }
            ("main", SnapshotRetention::Tag { .. }) => return Err(Error::Unsupported),
            (_, SnapshotRetention::Tag { .. }) => {
                protected.insert(reference.snapshot_id);
            }
            (_, SnapshotRetention::Branch { .. }) => {
                // Conservative local policy: never age out another branch or its retained ancestry.
                retain_lineage(
                    metadata,
                    reference.snapshot_id,
                    MAX_SNAPSHOTS,
                    i64::MIN,
                    &mut protected,
                )?;
            }
        }
    }
    if age <= 0 || !(1..=MAX_SNAPSHOTS).contains(&minimum) {
        return Err(Error::Unsupported);
    }
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Transient)?
            .as_millis(),
    )
    .map_err(|_| Error::Transient)?;
    let cutoff = now.saturating_sub(age);
    let main_lineage = if let Some(head) = metadata.current_snapshot_id() {
        // The new snapshot counts toward the minimum; retain its predecessor as well.
        retain_lineage(
            metadata,
            head,
            minimum.saturating_sub(1).max(1),
            cutoff,
            &mut protected,
        )?
    } else {
        HashSet::new()
    };
    let mut remove = Vec::new();
    for snapshot in metadata.snapshots() {
        let cutoff = if main_lineage.contains(&snapshot.snapshot_id()) {
            cutoff
        } else {
            now.saturating_sub(default_age)
        };
        if snapshot.timestamp_ms() >= cutoff || protected.contains(&snapshot.snapshot_id()) {
            continue;
        }
        remove.push(snapshot.snapshot_id());
        if let Some(token) = snapshot
            .summary()
            .additional_properties
            .get("locallycloud.batch-token")
        {
            let token = Uuid::parse_str(token)
                .map_err(|_| Error::Unsupported)?
                .to_string();
            receipts.insert(token);
        }
    }
    remove.sort_unstable();
    Ok((remove, receipts))
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
        let code = response["__type"].as_str().unwrap_or("");
        if status == http::StatusCode::BAD_REQUEST
            && code.rsplit('#').next() == Some("EntityNotFoundException")
        {
            return Err(Error::NoSuchTable);
        }
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
    let mut seen_manifests = HashSet::new();
    // Retain time travel and replay history; immutable manifests are shared by snapshots.
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
        if previous_manifests.len() > MAX_MANIFESTS {
            return Err(Error::Unsupported);
        }
        for manifest in previous_manifests {
            if seen_manifests.insert(manifest.manifest_path.clone()) {
                if seen_manifests.len() > MAX_MANIFESTS {
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
            }
            if Some(snapshot.snapshot_id()) == metadata.current_snapshot_id() {
                manifests.push(manifest);
            }
        }
    }
    Ok((
        table,
        metadata_uri,
        metadata,
        manifests,
        seen_manifests.len(),
    ))
}

pub(super) async fn preflight(ctx: Context<'_>, target: &Target) -> Result<()> {
    let (_, _, metadata, manifests, manifest_count) = inspect(&ctx, target).await?;
    let raw = serde_json::to_value(&metadata).map_err(|_| Error::Unsupported)?;
    let (remove, receipts) = retention_plan(&metadata, &raw, committed_tokens(&metadata)?)?;
    replay::Index::load(&metadata)?
        .prepare(&ctx, receipts)
        .await?;
    if metadata.snapshots().len().saturating_sub(remove.len()) >= MAX_SNAPSHOTS
        || manifest_count >= MAX_MANIFESTS
        || manifests.len() >= MAX_MANIFESTS
    {
        return Err(Error::Unsupported);
    }
    compacted_entries(&ctx, &metadata, &manifests).await?;
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
        let receipts = committed_tokens(&metadata)?;
        let index = replay::Index::load(&metadata)?;
        if receipts.contains(&batch)
            || metadata.snapshots().any(|snapshot| {
                snapshot
                    .summary()
                    .additional_properties
                    .get("locallycloud.batch-token")
                    == Some(&batch)
            })
            || index.contains(&ctx, &batch).await?
        {
            return Ok(());
        }
        let (remove, receipts) = retention_plan(&metadata, &raw, receipts)?;
        let receipt_plan = index.prepare(&ctx, receipts).await?;
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
        if metadata.snapshots().len().saturating_sub(remove.len()) >= MAX_SNAPSHOTS
            || manifest_count >= MAX_MANIFESTS
            || manifests.len() >= MAX_MANIFESTS
        {
            return Err(Error::Unsupported);
        }
        let compacted = compacted_entries(&ctx, &metadata, &manifests).await?;
        if compacted
            .as_ref()
            .is_some_and(|entries| entries.len().saturating_add(groups.len()) > MAX_COMPACTED_FILES)
        {
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
        if let Some(entries) = compacted {
            for entry in entries {
                writer
                    .add_existing_file(
                        entry.data_file,
                        entry.snapshot_id.ok_or(Error::Unsupported)?,
                        entry.sequence_number.ok_or(Error::Unsupported)?,
                        entry.file_sequence_number,
                    )
                    .map_err(|_| Error::Unsupported)?;
            }
            manifests.clear();
        }
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
        if manifest_bytes.len() > MAX_BODY {
            return Err(Error::Unsupported);
        }
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
        let mut builder = metadata
            .into_builder(Some(metadata_uri))
            .remove_snapshots(&remove);
        for id in remove {
            builder = builder
                .remove_statistics(id)
                .remove_partition_statistics(id);
        }
        if receipt_plan.remove_inline {
            builder = builder
                .remove_properties(&[COMMITTED_TOKENS.into()])
                .map_err(|_| Error::Transient)?;
        }
        if !receipt_plan.properties.is_empty() {
            builder = builder
                .set_properties(receipt_plan.properties.clone())
                .map_err(|_| Error::Transient)?;
        }
        let updated = builder
            .set_branch_snapshot(snapshot, "main")
            .map_err(|_| Error::Transient)?
            .build()
            .map_err(|_| Error::Transient)?
            .metadata;
        let updated_bytes = serde_json::to_vec(&updated).map_err(|_| Error::Transient)?;
        if updated_bytes.len() > MAX_BODY {
            return Err(Error::Unsupported);
        }
        receipt_plan.publish(&ctx).await?;
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
    fn s3_denial_requires_bounded_structured_error_and_matching_status() {
        use super::s3_access_denied;
        use http::StatusCode;
        let valid = b"<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code><Message>hidden</Message></Error>";
        assert!(s3_access_denied(StatusCode::FORBIDDEN, valid));
        assert!(!s3_access_denied(StatusCode::INTERNAL_SERVER_ERROR, valid));
        for body in [
            "<Error><Code>SignatureDoesNotMatch</Code></Error>",
            "<Error><Message>AccessDenied</Message></Error>",
            "<Error><Code>AccessDenied</Code>",
            "<Other><Code>AccessDenied</Code></Other>",
            "<Error><Code>AccessDenied</Code><Code>Other</Code></Error>",
            "<Error><Code><Nested>AccessDenied</Nested></Code></Error>",
            "<Error><Code>AccessDenied</Code></Error><![CDATA[trailing]]>",
            "<!DOCTYPE Error><Error><Code>AccessDenied</Code></Error>",
        ] {
            assert!(
                !s3_access_denied(StatusCode::FORBIDDEN, body.as_bytes()),
                "{body}"
            );
        }
        assert!(!s3_access_denied(StatusCode::FORBIDDEN, &vec![b'x'; 8193]));
        let deep = format!(
            "<Error>{}<Code>AccessDenied</Code>{}</Error>",
            "<x>".repeat(8),
            "</x>".repeat(8)
        );
        assert!(!s3_access_denied(StatusCode::FORBIDDEN, deep.as_bytes()));
        let deep_empty = format!(
            "<Error>{}<leaf/>{}<Code>AccessDenied</Code></Error>",
            "<x>".repeat(7),
            "</x>".repeat(7)
        );
        assert!(!s3_access_denied(
            StatusCode::FORBIDDEN,
            deep_empty.as_bytes()
        ));
    }

    #[test]
    fn iceberg_s3_access_stays_in_authorized_bucket() {
        assert!(s3_uri("s3://lake/table/metadata.json", "lake").is_ok());
        assert!(s3_uri("s3://other/table/metadata.json", "lake").is_err());
        assert!(s3_uri("s3://lake-other/table/metadata.json", "lake").is_err());
    }
}
