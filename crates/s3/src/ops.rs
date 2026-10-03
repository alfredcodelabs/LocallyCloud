//! S3 operation handlers. Each builds an `axum` `Response` or returns an `S3Error`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use locallycloud_core::integration::kms::{
    KmsCallContext, KmsInternalError, KmsValidateKeyRequest,
};
use locallycloud_core::integration::InternalDispatcher;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, PrimitiveDateTime};
use tokio::sync::RwLock;

use crate::error::S3Error;
use crate::integrity::{
    checksum_base64, decode_aws_chunked, etag, md5_raw, multipart_etag, validate_checksum,
    validate_content_md5, ChecksumAlgorithm,
};
use crate::notifications::{self, EventType, ObjectEvent};
use crate::store::{
    AccountStore, BucketState, CorsRule, DefaultRetention, MultipartUpload,
    ObjectLockConfiguration, ObjectRetention, PublicAccessBlock, RetentionMode,
    ServerSideEncryption, SseAlgorithm, StoredBody, StoredObject, StoredObjectPart, StoredPart,
    StoredVersion, VersionValue, VersioningState,
};
use crate::xml::{escape, text_el, DECL};

/// Maximum single PutObject size (5 GiB).
const MAX_OBJECT_SIZE: usize = 5 * 1024 * 1024 * 1024;

/// Request context for an operation.
pub struct Ctx<'a> {
    pub store: &'a AccountStore,
    pub account: &'a str,
    pub region: &'a str,
    pub request_id: &'a str,
    pub dispatcher: Option<Arc<InternalDispatcher>>,
}

pub struct MutationResult {
    pub response: Response,
    pub events: Vec<ObjectEvent>,
}

fn sequencer(now: OffsetDateTime) -> String {
    format!("{:016X}", now.unix_timestamp_nanos())
}

// ============================ helpers ==========================================

/// Format an `OffsetDateTime` as an HTTP date (`Wed, 21 Oct 2015 07:28:00 GMT`).
pub fn http_date(dt: OffsetDateTime) -> String {
    const DOW: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let dt = dt.to_offset(time::UtcOffset::UTC);
    let dow = DOW[dt.weekday().number_days_from_monday() as usize];
    let mon = MON[dt.month() as usize - 1];
    format!(
        "{dow}, {:02} {mon} {:04} {:02}:{:02}:{:02} GMT",
        dt.day(),
        dt.year(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    )
}

/// ISO-8601 timestamp for listing responses.
fn iso8601(dt: OffsetDateTime) -> String {
    dt.to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Collect `x-amz-meta-*` headers into a metadata map (lowercased suffix).
fn user_metadata(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in headers {
        let n = name.as_str();
        if let Some(suffix) = n.strip_prefix("x-amz-meta-") {
            if let Ok(v) = value.to_str() {
                out.insert(suffix.to_string(), v.to_string());
            }
        }
    }
    out
}

fn sse_algorithm(value: &str) -> Result<SseAlgorithm, S3Error> {
    match value {
        "AES256" => Ok(SseAlgorithm::Aes256),
        "aws:kms" => Ok(SseAlgorithm::AwsKms),
        _ => Err(S3Error::InvalidArgument(
            "The server side encryption algorithm is invalid".into(),
        )),
    }
}

fn bucket_key_enabled(value: Option<&str>) -> Result<bool, S3Error> {
    match value {
        Some("true") => Ok(true),
        Some("false") | None => Ok(false),
        Some(_) => Err(S3Error::InvalidArgument(
            "x-amz-server-side-encryption-bucket-key-enabled must be true or false".into(),
        )),
    }
}

fn kms_error(error: KmsInternalError) -> S3Error {
    match error {
        KmsInternalError::AccessDenied => S3Error::AccessDenied,
        KmsInternalError::InvalidRequest
        | KmsInternalError::NotFound
        | KmsInternalError::InvalidState
        | KmsInternalError::InvalidCiphertext => {
            S3Error::InvalidArgument("The KMS key is invalid or unavailable".into())
        }
        KmsInternalError::Unavailable | KmsInternalError::Internal => S3Error::InternalError,
    }
}

fn canonical_kms_key(ctx: &Ctx<'_>, key_id: &str) -> Result<String, S3Error> {
    let dispatcher = ctx.dispatcher.as_deref().ok_or(S3Error::InternalError)?;
    dispatcher
        .kms_validate_key(KmsValidateKeyRequest {
            call: KmsCallContext {
                source_service: "s3".to_string(),
                account_id: ctx.account.to_string(),
                region: ctx.region.to_string(),
                request_id: ctx.request_id.to_string(),
                caller_arn: None,
                iam_policy_allowed: false,
            },
            key_id: key_id.to_string(),
        })
        .map(|output| output.key_arn)
        .map_err(kms_error)
}

fn explicit_encryption(
    ctx: &Ctx<'_>,
    algorithm: SseAlgorithm,
    kms_key_id: Option<&str>,
    bucket_key: bool,
) -> Result<ServerSideEncryption, S3Error> {
    match algorithm {
        SseAlgorithm::Aes256 => {
            if kms_key_id.is_some() || bucket_key {
                return Err(S3Error::InvalidArgument(
                    "KMS key and bucket key settings require aws:kms".into(),
                ));
            }
            Ok(ServerSideEncryption::default())
        }
        SseAlgorithm::AwsKms => {
            let key_id = kms_key_id
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    S3Error::InvalidArgument("A KMS key ID is required when using aws:kms".into())
                })?;
            Ok(ServerSideEncryption {
                algorithm,
                kms_key_arn: Some(canonical_kms_key(ctx, key_id)?),
                bucket_key_enabled: bucket_key,
            })
        }
    }
}

fn request_encryption(
    ctx: &Ctx<'_>,
    headers: &HeaderMap,
    default: &ServerSideEncryption,
) -> Result<ServerSideEncryption, S3Error> {
    let sse_header = |name| {
        headers
            .get(name)
            .map(|value| {
                value.to_str().map_err(|_| {
                    S3Error::InvalidArgument("Invalid server side encryption header".into())
                })
            })
            .transpose()
    };
    let algorithm = sse_header("x-amz-server-side-encryption")?;
    let kms_key_id = sse_header("x-amz-server-side-encryption-aws-kms-key-id")?;
    let bucket_key_header = sse_header("x-amz-server-side-encryption-bucket-key-enabled")?;
    if algorithm.is_none() {
        if kms_key_id.is_some() || bucket_key_header.is_some() {
            return Err(S3Error::InvalidArgument(
                "The server side encryption algorithm is required".into(),
            ));
        }
        return Ok(default.clone());
    }
    explicit_encryption(
        ctx,
        sse_algorithm(algorithm.expect("checked above"))?,
        kms_key_id,
        bucket_key_enabled(bucket_key_header)?,
    )
}

fn with_sse_headers(
    mut builder: http::response::Builder,
    encryption: &ServerSideEncryption,
) -> http::response::Builder {
    builder = builder.header(
        "x-amz-server-side-encryption",
        encryption.algorithm.as_str(),
    );
    if encryption.algorithm == SseAlgorithm::AwsKms {
        if let Some(key_arn) = &encryption.kms_key_arn {
            builder = builder.header("x-amz-server-side-encryption-aws-kms-key-id", key_arn);
        }
        builder = builder.header(
            "x-amz-server-side-encryption-bucket-key-enabled",
            encryption.bucket_key_enabled.to_string(),
        );
    }
    builder
}

async fn bucket(ctx: &Ctx<'_>, name: &str) -> Result<Arc<RwLock<BucketState>>, S3Error> {
    ctx.store
        .get(ctx.account, name)
        .ok_or(S3Error::NoSuchBucket)
}

#[derive(Debug, Clone)]
struct XmlNode {
    name: String,
    text: String,
    children: Vec<XmlNode>,
}

fn parse_xml(body: &[u8]) -> Result<XmlNode, S3Error> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root = None;
    loop {
        let node = match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) => {
                stack.push(XmlNode {
                    name: element.local_name().as_ref().to_owned(),
                    text: String::new(),
                    children: Vec::new(),
                });
                None
            }
            Ok(Event::Empty(element)) => Some(XmlNode {
                name: element.local_name().as_ref().to_owned(),
                text: String::new(),
                children: Vec::new(),
            }),
            Ok(Event::Text(text)) => {
                let value = quick_xml::escape::unescape(text.as_ref())
                    .map_err(|_| S3Error::MalformedXML)?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&value);
                } else if !value.trim().is_empty() {
                    return Err(S3Error::MalformedXML);
                }
                None
            }
            Ok(Event::GeneralRef(reference)) => {
                let encoded = format!("&{};", reference.as_ref());
                let value =
                    quick_xml::escape::unescape(&encoded).map_err(|_| S3Error::MalformedXML)?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&value);
                } else {
                    return Err(S3Error::MalformedXML);
                }
                None
            }
            Ok(Event::End(element)) => {
                let node = stack.pop().ok_or(S3Error::MalformedXML)?;
                if node.name != element.local_name().as_ref() {
                    return Err(S3Error::MalformedXML);
                }
                Some(node)
            }
            Ok(Event::Decl(_)) => None,
            Ok(Event::Eof) => break,
            Ok(_) | Err(_) => return Err(S3Error::MalformedXML),
        };
        if let Some(node) = node {
            if let Some(parent) = stack.last_mut() {
                parent.children.push(node);
            } else if root.replace(node).is_some() {
                return Err(S3Error::MalformedXML);
            }
        }
        buffer.clear();
    }
    if !stack.is_empty() {
        return Err(S3Error::MalformedXML);
    }
    root.ok_or(S3Error::MalformedXML)
}

fn child_text<'a>(node: &'a XmlNode, name: &str) -> Option<&'a str> {
    node.children
        .iter()
        .find(|child| child.name == name && child.children.is_empty())
        .map(|child| child.text.as_str())
}

fn decode_form_component(value: &str) -> String {
    crate::addr::percent_decode(&value.replace('+', " "))
}

fn validate_tags(tags: &BTreeMap<String, String>) -> Result<(), S3Error> {
    if tags.len() > 10
        || tags
            .iter()
            .any(|(key, value)| key.chars().count() > 128 || value.chars().count() > 256)
    {
        return Err(S3Error::InvalidTag);
    }
    Ok(())
}

fn parse_tagging_header(value: Option<&str>) -> Result<BTreeMap<String, String>, S3Error> {
    let mut tags = BTreeMap::new();
    for pair in value
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode_form_component(key);
        if key.is_empty() || tags.insert(key, decode_form_component(value)).is_some() {
            return Err(S3Error::InvalidTag);
        }
    }
    validate_tags(&tags)?;
    Ok(tags)
}

fn parse_tagging_xml(body: &[u8]) -> Result<BTreeMap<String, String>, S3Error> {
    let root = parse_xml(body)?;
    if root.name != "Tagging" || !root.text.is_empty() || root.children.len() != 1 {
        return Err(S3Error::MalformedXML);
    }
    let tag_set = &root.children[0];
    if tag_set.name != "TagSet" || !tag_set.text.is_empty() {
        return Err(S3Error::MalformedXML);
    }
    let mut tags = BTreeMap::new();
    for tag in &tag_set.children {
        if tag.name != "Tag" || !tag.text.is_empty() || tag.children.len() != 2 {
            return Err(S3Error::MalformedXML);
        }
        let key = child_text(tag, "Key").ok_or(S3Error::MalformedXML)?;
        let value = child_text(tag, "Value").ok_or(S3Error::MalformedXML)?;
        if key.is_empty() || tags.insert(key.to_string(), value.to_string()).is_some() {
            return Err(S3Error::InvalidTag);
        }
    }
    validate_tags(&tags)?;
    Ok(tags)
}

fn tagging_xml(tags: &BTreeMap<String, String>) -> String {
    let mut xml = format!("{DECL}<Tagging xmlns=\"{S3_XMLNS}\"><TagSet>");
    for (key, value) in tags {
        xml.push_str(&format!(
            "<Tag>{}{}</Tag>",
            text_el("Key", key),
            text_el("Value", value)
        ));
    }
    xml.push_str("</TagSet></Tagging>");
    xml
}

// ============================ bucket lifecycle =================================

pub async fn list_buckets(ctx: &Ctx<'_>) -> Result<Response, S3Error> {
    let names = ctx.store.list_names(ctx.account);
    let mut buckets_xml = String::new();
    for name in &names {
        if let Some(b) = ctx.store.get(ctx.account, name) {
            let created = iso8601(b.read().await.creation_date);
            buckets_xml.push_str(&format!(
                "<Bucket>{}<CreationDate>{}</CreationDate></Bucket>",
                text_el("Name", name),
                created
            ));
        }
    }
    let body = format!(
        "{DECL}<ListAllMyBucketsResult><Owner><ID>{acct}</ID><DisplayName>locallycloud</DisplayName></Owner><Buckets>{buckets_xml}</Buckets></ListAllMyBucketsResult>",
        acct = ctx.account,
    );
    Ok(xml_ok(body, ctx.request_id))
}

pub async fn create_bucket(
    ctx: &Ctx<'_>,
    name: &str,
    headers: &HeaderMap,
) -> Result<Response, S3Error> {
    crate::addr::validate_bucket_name(name)?;
    let account_regional = match headers.get("x-amz-bucket-namespace") {
        None => false,
        Some(value) if value == "global" => false,
        Some(value) if value == "account-regional" => true,
        Some(_) => {
            return Err(S3Error::InvalidArgument(
                "Invalid x-amz-bucket-namespace value".into(),
            ));
        }
    };
    if account_regional {
        if ctx.account.len() != 12 || !ctx.account.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(S3Error::InvalidBucketName);
        }
        if matches!(ctx.region, "me-south-1" | "me-central-1") {
            return Err(S3Error::InvalidRequest(
                "Account regional buckets are unavailable in this Region".into(),
            ));
        }
        let suffix = format!("-{}-{}-an", ctx.account, ctx.region);
        if !name
            .strip_suffix(&suffix)
            .is_some_and(|prefix| !prefix.is_empty())
        {
            return Err(S3Error::InvalidBucketName);
        }
    } else if name.ends_with("-an") {
        return Err(S3Error::InvalidBucketName);
    }
    let object_lock_enabled = match header(headers, "x-amz-bucket-object-lock-enabled") {
        None => false,
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        Some(_) => {
            return Err(S3Error::InvalidArgument(
                "x-amz-bucket-object-lock-enabled must be true or false".into(),
            ));
        }
    };
    ctx.store
        .create(ctx.account, name, ctx.region, object_lock_enabled)?;
    Ok(Response::builder()
        .status(200)
        .header("Location", format!("/{name}"))
        .header("x-amz-request-id", ctx.request_id)
        .body(Body::empty())
        .expect("create bucket response is valid"))
}

pub async fn delete_bucket(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    let guard = b.read().await;
    if !guard.objects.is_empty() || !guard.versions.is_empty() || !guard.uploads.is_empty() {
        return Err(S3Error::BucketNotEmpty);
    }
    drop(guard);
    ctx.store.remove(ctx.account, name);
    Ok(status_only(204, ctx.request_id))
}

pub async fn head_bucket(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    bucket(ctx, name).await?;
    Ok(status_only(200, ctx.request_id))
}

pub async fn get_bucket_location(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    let region = b.read().await.region.clone();
    // us-east-1 is represented as an empty LocationConstraint.
    let constraint = if region == "us-east-1" {
        String::new()
    } else {
        escape(&region)
    };
    let body = format!("{DECL}<LocationConstraint>{constraint}</LocationConstraint>");
    Ok(xml_ok(body, ctx.request_id))
}

/// S3 XML namespace used by bucket sub-resource configuration documents.
const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

// ---- Bucket sub-resource reads (faithful "not configured"/default responses) ----
// The Terraform aws_s3_bucket resource reads ~15 sub-resources on refresh; each must
// return the AWS-correct empty/default document or the specific not-found error.

pub async fn put_bucket_policy(
    ctx: &Ctx<'_>,
    name: &str,
    body: &[u8],
) -> Result<Response, S3Error> {
    let policy = String::from_utf8(body.to_vec())
        .map_err(|_| S3Error::InvalidArgument("The policy is not valid UTF-8".into()))?;
    let b = bucket(ctx, name).await?;
    b.write().await.policy = Some(policy);
    Ok(status_only(204, ctx.request_id))
}

pub async fn get_bucket_policy(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    let policy = b
        .read()
        .await
        .policy
        .clone()
        .ok_or(S3Error::NoSuchBucketPolicy)?;
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .header("x-amz-request-id", ctx.request_id)
        .body(Body::from(policy))
        .expect("policy response is valid"))
}

pub async fn delete_bucket_policy(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    b.write().await.policy = None;
    Ok(status_only(204, ctx.request_id))
}

pub async fn get_bucket_versioning(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    let state = b.read().await.versioning;
    if state == VersioningState::NeverEnabled {
        return Ok(status_only(200, ctx.request_id));
    }
    let status = if state == VersioningState::Enabled {
        "Enabled"
    } else {
        "Suspended"
    };
    Ok(xml_ok(
        format!("{DECL}<VersioningConfiguration xmlns=\"{S3_XMLNS}\"><Status>{status}</Status></VersioningConfiguration>"),
        ctx.request_id,
    ))
}

pub async fn put_bucket_versioning(
    ctx: &Ctx<'_>,
    name: &str,
    body: &[u8],
) -> Result<Response, S3Error> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut depth = 0;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut status_seen = false;
    let mut in_status = false;
    let mut parsed = None;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(event)) => {
                if root_closed {
                    return Err(S3Error::MalformedXML);
                }
                match depth {
                    0 if !root_seen && event.local_name().as_ref() == "VersioningConfiguration" => {
                        root_seen = true;
                    }
                    1 if event.local_name().as_ref() == "Status" && !status_seen => {
                        status_seen = true;
                        in_status = true;
                    }
                    _ => return Err(S3Error::MalformedXML),
                }
                depth += 1;
            }
            Ok(Event::Text(text)) => {
                let text = quick_xml::escape::unescape(text.as_ref())
                    .map_err(|_| S3Error::MalformedXML)?;
                if text.is_empty() {
                    buf.clear();
                    continue;
                }
                if depth != 2 || !in_status || parsed.is_some() {
                    return Err(S3Error::MalformedXML);
                }
                parsed = Some(text.into_owned());
            }
            Ok(Event::End(event)) => {
                match depth {
                    2 if in_status && event.local_name().as_ref() == "Status" => {
                        in_status = false;
                    }
                    1 if root_seen && event.local_name().as_ref() == "VersioningConfiguration" => {
                        root_closed = true;
                    }
                    _ => return Err(S3Error::MalformedXML),
                }
                depth -= 1;
            }
            Ok(Event::Empty(_)) => return Err(S3Error::MalformedXML),
            Ok(Event::Eof) => break,
            Err(_) => return Err(S3Error::MalformedXML),
            _ => {}
        }
        buf.clear();
    }
    if !root_seen || !root_closed || depth != 0 || !status_seen {
        return Err(S3Error::MalformedXML);
    }
    let state = match parsed.as_deref() {
        Some("Enabled") => VersioningState::Enabled,
        Some("Suspended") => VersioningState::Suspended,
        _ => return Err(S3Error::MalformedXML),
    };
    let b = bucket(ctx, name).await?;
    let mut guard = b.write().await;
    if state == VersioningState::Suspended && guard.object_lock.is_some() {
        return Err(S3Error::InvalidRequest(
            "Cannot suspend versioning on a bucket with Object Lock enabled".into(),
        ));
    }
    if guard.versioning == VersioningState::NeverEnabled {
        for (key, object) in guard.objects.clone() {
            guard.versions.insert(
                key,
                vec![StoredVersion {
                    id: "null".to_string(),
                    last_modified: object.last_modified,
                    value: VersionValue::Object(Box::new(object)),
                }],
            );
        }
    }
    guard.versioning = state;
    Ok(status_only(200, ctx.request_id))
}

fn parse_cors_configuration(body: &[u8]) -> Result<Vec<CorsRule>, S3Error> {
    let root = parse_xml(body)?;
    if root.name != "CORSConfiguration" || !root.text.is_empty() {
        return Err(S3Error::MalformedXML);
    }
    let mut rules = Vec::new();
    for node in &root.children {
        if node.name != "CORSRule" || !node.text.is_empty() {
            return Err(S3Error::MalformedXML);
        }
        let mut rule = CorsRule::default();
        for field in &node.children {
            if !field.children.is_empty() {
                return Err(S3Error::MalformedXML);
            }
            match field.name.as_str() {
                "ID" if rule.id.is_none() => rule.id = Some(field.text.clone()),
                "AllowedOrigin" => rule.allowed_origins.push(field.text.clone()),
                "AllowedMethod" => rule.allowed_methods.push(field.text.to_ascii_uppercase()),
                "AllowedHeader" => rule.allowed_headers.push(field.text.clone()),
                "ExposeHeader" => rule.expose_headers.push(field.text.clone()),
                "MaxAgeSeconds" if rule.max_age_seconds.is_none() => {
                    rule.max_age_seconds =
                        Some(field.text.parse().map_err(|_| S3Error::MalformedXML)?);
                }
                _ => return Err(S3Error::MalformedXML),
            }
        }
        if rule.allowed_origins.is_empty() || rule.allowed_methods.is_empty() {
            return Err(S3Error::MalformedXML);
        }
        rules.push(rule);
    }
    if rules.is_empty() {
        return Err(S3Error::MalformedXML);
    }
    Ok(rules)
}

fn cors_xml(rules: &[CorsRule]) -> String {
    let mut xml = format!("{DECL}<CORSConfiguration xmlns=\"{S3_XMLNS}\">");
    for rule in rules {
        xml.push_str("<CORSRule>");
        if let Some(id) = &rule.id {
            xml.push_str(&text_el("ID", id));
        }
        for origin in &rule.allowed_origins {
            xml.push_str(&text_el("AllowedOrigin", origin));
        }
        for method in &rule.allowed_methods {
            xml.push_str(&text_el("AllowedMethod", method));
        }
        for allowed_header in &rule.allowed_headers {
            xml.push_str(&text_el("AllowedHeader", allowed_header));
        }
        for expose_header in &rule.expose_headers {
            xml.push_str(&text_el("ExposeHeader", expose_header));
        }
        if let Some(max_age) = rule.max_age_seconds {
            xml.push_str(&text_el("MaxAgeSeconds", &max_age.to_string()));
        }
        xml.push_str("</CORSRule>");
    }
    xml.push_str("</CORSConfiguration>");
    xml
}

pub async fn put_bucket_cors(ctx: &Ctx<'_>, name: &str, body: &[u8]) -> Result<Response, S3Error> {
    let rules = parse_cors_configuration(body)?;
    let b = bucket(ctx, name).await?;
    b.write().await.cors = Some(rules);
    Ok(status_only(200, ctx.request_id))
}

pub async fn get_bucket_cors(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    let rules = b
        .read()
        .await
        .cors
        .clone()
        .ok_or(S3Error::NoSuchCORSConfiguration)?;
    Ok(xml_ok(cors_xml(&rules), ctx.request_id))
}

pub async fn delete_bucket_cors(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    b.write().await.cors = None;
    Ok(status_only(204, ctx.request_id))
}

pub async fn put_bucket_tagging(
    ctx: &Ctx<'_>,
    name: &str,
    body: &[u8],
) -> Result<Response, S3Error> {
    let tags = parse_tagging_xml(body)?;
    let b = bucket(ctx, name).await?;
    b.write().await.bucket_tags = Some(tags);
    Ok(status_only(204, ctx.request_id))
}

pub async fn get_bucket_tagging(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    let tags = b
        .read()
        .await
        .bucket_tags
        .clone()
        .ok_or(S3Error::NoSuchTagSet)?;
    Ok(xml_ok(tagging_xml(&tags), ctx.request_id))
}

pub async fn delete_bucket_tagging(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    b.write().await.bucket_tags = None;
    Ok(status_only(204, ctx.request_id))
}

pub async fn get_bucket_lifecycle(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    bucket(ctx, name).await?;
    Err(S3Error::NoSuchLifecycleConfiguration)
}

pub async fn get_bucket_replication(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    bucket(ctx, name).await?;
    Err(S3Error::ReplicationConfigurationNotFoundError)
}

pub async fn put_bucket_website(
    ctx: &Ctx<'_>,
    name: &str,
    body: &[u8],
) -> Result<Response, S3Error> {
    let root = parse_xml(body)?;
    if root.name != "WebsiteConfiguration" {
        return Err(S3Error::MalformedXML);
    }
    let website = String::from_utf8(body.to_vec()).map_err(|_| S3Error::MalformedXML)?;
    let b = bucket(ctx, name).await?;
    b.write().await.website = Some(website);
    Ok(status_only(200, ctx.request_id))
}

pub async fn get_bucket_website(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    let website = b
        .read()
        .await
        .website
        .clone()
        .ok_or(S3Error::NoSuchWebsiteConfiguration)?;
    Ok(xml_ok(website, ctx.request_id))
}

fn parse_retention_mode(value: &str) -> Result<RetentionMode, S3Error> {
    match value {
        "GOVERNANCE" => Ok(RetentionMode::Governance),
        "COMPLIANCE" => Ok(RetentionMode::Compliance),
        _ => Err(S3Error::MalformedXML),
    }
}

fn parse_object_lock_configuration(body: &[u8]) -> Result<ObjectLockConfiguration, S3Error> {
    let root = parse_xml(body)?;
    if root.name != "ObjectLockConfiguration"
        || child_text(&root, "ObjectLockEnabled") != Some("Enabled")
    {
        return Err(S3Error::MalformedXML);
    }
    let rule = root.children.iter().find(|child| child.name == "Rule");
    let default_retention = if let Some(rule) = rule {
        let retention = rule
            .children
            .iter()
            .find(|child| child.name == "DefaultRetention")
            .ok_or(S3Error::MalformedXML)?;
        let mode =
            parse_retention_mode(child_text(retention, "Mode").ok_or(S3Error::MalformedXML)?)?;
        let days = child_text(retention, "Days")
            .map(str::parse::<i64>)
            .transpose()
            .map_err(|_| S3Error::MalformedXML)?;
        let years = child_text(retention, "Years")
            .map(str::parse::<i64>)
            .transpose()
            .map_err(|_| S3Error::MalformedXML)?;
        if days.is_some() == years.is_some() || days == Some(0) || years == Some(0) {
            return Err(S3Error::MalformedXML);
        }
        Some(DefaultRetention { mode, days, years })
    } else {
        None
    };
    Ok(ObjectLockConfiguration { default_retention })
}

fn object_lock_xml(configuration: &ObjectLockConfiguration) -> String {
    let mut xml = format!(
        "{DECL}<ObjectLockConfiguration xmlns=\"{S3_XMLNS}\"><ObjectLockEnabled>Enabled</ObjectLockEnabled>"
    );
    if let Some(retention) = &configuration.default_retention {
        xml.push_str(&format!(
            "<Rule><DefaultRetention>{}",
            text_el("Mode", retention.mode.as_str())
        ));
        if let Some(days) = retention.days {
            xml.push_str(&text_el("Days", &days.to_string()));
        }
        if let Some(years) = retention.years {
            xml.push_str(&text_el("Years", &years.to_string()));
        }
        xml.push_str("</DefaultRetention></Rule>");
    }
    xml.push_str("</ObjectLockConfiguration>");
    xml
}

pub async fn put_bucket_object_lock(
    ctx: &Ctx<'_>,
    name: &str,
    body: &[u8],
) -> Result<Response, S3Error> {
    let configuration = parse_object_lock_configuration(body)?;
    let b = bucket(ctx, name).await?;
    let mut guard = b.write().await;
    if guard.object_lock.is_none() {
        return Err(S3Error::InvalidRequest(
            "Object Lock must be enabled when the bucket is created".into(),
        ));
    }
    guard.object_lock = Some(configuration);
    guard.versioning = VersioningState::Enabled;
    Ok(status_only(200, ctx.request_id))
}

pub async fn get_bucket_object_lock(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    let configuration = b
        .read()
        .await
        .object_lock
        .clone()
        .ok_or(S3Error::ObjectLockConfigurationNotFoundError)?;
    Ok(xml_ok(object_lock_xml(&configuration), ctx.request_id))
}

pub async fn get_bucket_ownership_controls(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    bucket(ctx, name).await?;
    Err(S3Error::OwnershipControlsNotFoundError)
}

fn parse_bucket_encryption(ctx: &Ctx<'_>, body: &[u8]) -> Result<ServerSideEncryption, S3Error> {
    let root = parse_xml(body)?;
    if root.name != "ServerSideEncryptionConfiguration"
        || !root.text.is_empty()
        || root.children.len() != 1
    {
        return Err(S3Error::MalformedXML);
    }
    let rule = &root.children[0];
    if rule.name != "Rule" || !rule.text.is_empty() || !(1..=2).contains(&rule.children.len()) {
        return Err(S3Error::MalformedXML);
    }
    let apply = rule
        .children
        .iter()
        .find(|child| child.name == "ApplyServerSideEncryptionByDefault")
        .ok_or(S3Error::MalformedXML)?;
    if !apply.text.is_empty()
        || !(1..=2).contains(&apply.children.len())
        || apply
            .children
            .iter()
            .any(|child| !matches!(child.name.as_str(), "SSEAlgorithm" | "KMSMasterKeyID"))
        || apply
            .children
            .iter()
            .filter(|child| child.name == "SSEAlgorithm")
            .count()
            != 1
        || apply
            .children
            .iter()
            .filter(|child| child.name == "KMSMasterKeyID")
            .count()
            > 1
    {
        return Err(S3Error::MalformedXML);
    }
    let bucket_key_nodes = rule
        .children
        .iter()
        .filter(|child| child.name == "BucketKeyEnabled")
        .collect::<Vec<_>>();
    if rule.children.iter().any(|child| {
        !matches!(
            child.name.as_str(),
            "ApplyServerSideEncryptionByDefault" | "BucketKeyEnabled"
        )
    }) || rule
        .children
        .iter()
        .filter(|child| child.name == "ApplyServerSideEncryptionByDefault")
        .count()
        != 1
        || bucket_key_nodes.len() > 1
    {
        return Err(S3Error::MalformedXML);
    }
    let algorithm = sse_algorithm(child_text(apply, "SSEAlgorithm").ok_or(S3Error::MalformedXML)?)?;
    let bucket_key = bucket_key_enabled(bucket_key_nodes.first().map(|node| node.text.as_str()))?;
    explicit_encryption(
        ctx,
        algorithm,
        child_text(apply, "KMSMasterKeyID"),
        bucket_key,
    )
}

fn bucket_encryption_xml(encryption: &ServerSideEncryption) -> String {
    let kms_key = encryption
        .kms_key_arn
        .as_deref()
        .map(|key| text_el("KMSMasterKeyID", key))
        .unwrap_or_default();
    format!(
        "{DECL}<ServerSideEncryptionConfiguration xmlns=\"{S3_XMLNS}\"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>{}</SSEAlgorithm>{kms_key}</ApplyServerSideEncryptionByDefault><BucketKeyEnabled>{}</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>",
        encryption.algorithm.as_str(),
        encryption.bucket_key_enabled,
    )
}

pub async fn put_bucket_encryption(
    ctx: &Ctx<'_>,
    name: &str,
    body: &[u8],
) -> Result<Response, S3Error> {
    let encryption = parse_bucket_encryption(ctx, body)?;
    let bucket = bucket(ctx, name).await?;
    bucket.write().await.encryption = encryption;
    Ok(status_only(200, ctx.request_id))
}

pub async fn get_bucket_encryption(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let bucket = bucket(ctx, name).await?;
    let encryption = bucket.read().await.encryption.clone();
    Ok(xml_ok(bucket_encryption_xml(&encryption), ctx.request_id))
}

pub async fn delete_bucket_encryption(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let bucket = bucket(ctx, name).await?;
    bucket.write().await.encryption = ServerSideEncryption::default();
    Ok(status_only(204, ctx.request_id))
}

fn parse_public_access_block(body: &[u8]) -> Result<PublicAccessBlock, S3Error> {
    let root = parse_xml(body)?;
    if root.name != "PublicAccessBlockConfiguration" {
        return Err(S3Error::MalformedXML);
    }
    let boolean = |name| match child_text(&root, name) {
        Some("true") => Ok(true),
        Some("false") | None => Ok(false),
        Some(_) => Err(S3Error::MalformedXML),
    };
    Ok(PublicAccessBlock {
        block_public_acls: boolean("BlockPublicAcls")?,
        ignore_public_acls: boolean("IgnorePublicAcls")?,
        block_public_policy: boolean("BlockPublicPolicy")?,
        restrict_public_buckets: boolean("RestrictPublicBuckets")?,
    })
}

fn public_access_block_xml(block: &PublicAccessBlock) -> String {
    format!(
        "{DECL}<PublicAccessBlockConfiguration xmlns=\"{S3_XMLNS}\"><BlockPublicAcls>{}</BlockPublicAcls><IgnorePublicAcls>{}</IgnorePublicAcls><BlockPublicPolicy>{}</BlockPublicPolicy><RestrictPublicBuckets>{}</RestrictPublicBuckets></PublicAccessBlockConfiguration>",
        block.block_public_acls,
        block.ignore_public_acls,
        block.block_public_policy,
        block.restrict_public_buckets,
    )
}

pub async fn put_bucket_public_access_block(
    ctx: &Ctx<'_>,
    name: &str,
    body: &[u8],
) -> Result<Response, S3Error> {
    let block = parse_public_access_block(body)?;
    let b = bucket(ctx, name).await?;
    b.write().await.public_access_block = Some(block);
    Ok(status_only(200, ctx.request_id))
}

pub async fn get_bucket_public_access_block(
    ctx: &Ctx<'_>,
    name: &str,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    let block = b
        .read()
        .await
        .public_access_block
        .clone()
        .ok_or(S3Error::NoSuchPublicAccessBlockConfiguration)?;
    Ok(xml_ok(public_access_block_xml(&block), ctx.request_id))
}

pub async fn delete_bucket_public_access_block(
    ctx: &Ctx<'_>,
    name: &str,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    b.write().await.public_access_block = None;
    Ok(status_only(204, ctx.request_id))
}

pub fn put_account_public_access_block(
    ctx: &Ctx<'_>,
    account: &str,
    body: &[u8],
) -> Result<Response, S3Error> {
    let block = parse_public_access_block(body)?;
    ctx.store.put_account_public_access_block(account, block);
    Ok(status_only(200, ctx.request_id))
}

pub fn get_account_public_access_block(ctx: &Ctx<'_>, account: &str) -> Result<Response, S3Error> {
    let block = ctx
        .store
        .account_public_access_block(account)
        .ok_or(S3Error::NoSuchPublicAccessBlockConfiguration)?;
    Ok(xml_ok(public_access_block_xml(&block), ctx.request_id))
}

pub fn delete_account_public_access_block(
    ctx: &Ctx<'_>,
    account: &str,
) -> Result<Response, S3Error> {
    ctx.store.delete_account_public_access_block(account);
    Ok(status_only(204, ctx.request_id))
}

pub async fn get_bucket_request_payment(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    bucket(ctx, name).await?;
    let body = format!("{DECL}<RequestPaymentConfiguration xmlns=\"{S3_XMLNS}\"><Payer>BucketOwner</Payer></RequestPaymentConfiguration>");
    Ok(xml_ok(body, ctx.request_id))
}

pub async fn get_bucket_accelerate(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    bucket(ctx, name).await?;
    Ok(xml_ok(
        format!("{DECL}<AccelerateConfiguration xmlns=\"{S3_XMLNS}\"></AccelerateConfiguration>"),
        ctx.request_id,
    ))
}

pub async fn get_bucket_logging(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    bucket(ctx, name).await?;
    Ok(xml_ok(
        format!("{DECL}<BucketLoggingStatus xmlns=\"{S3_XMLNS}\"></BucketLoggingStatus>"),
        ctx.request_id,
    ))
}

pub async fn put_bucket_notification(
    ctx: &Ctx<'_>,
    name: &str,
    body: &[u8],
) -> Result<Response, S3Error> {
    let configuration = notifications::parse_configuration(body)?;
    let b = bucket(ctx, name).await?;
    b.write().await.notification_configuration = configuration;
    Ok(status_only(200, ctx.request_id))
}

pub async fn get_bucket_notification(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    let b = bucket(ctx, name).await?;
    let configuration = b.read().await.notification_configuration.clone();
    Ok(xml_ok(
        format!(
            "{DECL}<NotificationConfiguration xmlns=\"{S3_XMLNS}\">{}</NotificationConfiguration>",
            notifications::configuration_xml(&configuration)
        ),
        ctx.request_id,
    ))
}

pub async fn get_bucket_acl(ctx: &Ctx<'_>, name: &str) -> Result<Response, S3Error> {
    bucket(ctx, name).await?;
    let acct = ctx.account;
    let body = format!(
        "{DECL}<AccessControlPolicy xmlns=\"{S3_XMLNS}\"><Owner><ID>{acct}</ID><DisplayName>locallycloud</DisplayName></Owner><AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>{acct}</ID><DisplayName>locallycloud</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>"
    );
    Ok(xml_ok(body, ctx.request_id))
}

// ============================ object tagging and lock ===========================

fn bypass_governance(headers: &HeaderMap) -> bool {
    header(headers, "x-amz-bypass-governance-retention")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn ensure_not_protected(object: &StoredObject, bypass: bool) -> Result<(), S3Error> {
    if object.legal_hold {
        return Err(S3Error::AccessDenied);
    }
    if let Some(retention) = &object.retention {
        if retention.retain_until > OffsetDateTime::now_utc()
            && (retention.mode == RetentionMode::Compliance || !bypass)
        {
            return Err(S3Error::AccessDenied);
        }
    }
    Ok(())
}

fn object_lock_values(
    headers: &HeaderMap,
    bucket: &BucketState,
    now: OffsetDateTime,
) -> Result<(Option<ObjectRetention>, bool), S3Error> {
    let mode = header(headers, "x-amz-object-lock-mode");
    let until = header(headers, "x-amz-object-lock-retain-until-date");
    let legal = match header(headers, "x-amz-object-lock-legal-hold") {
        None | Some("OFF") => false,
        Some("ON") => true,
        Some(_) => {
            return Err(S3Error::InvalidArgument(
                "x-amz-object-lock-legal-hold must be ON or OFF".into(),
            ));
        }
    };
    if (mode.is_some()
        || until.is_some()
        || header(headers, "x-amz-object-lock-legal-hold").is_some())
        && bucket.object_lock.is_none()
    {
        return Err(S3Error::InvalidRequest(
            "Bucket is missing an Object Lock configuration".into(),
        ));
    }
    let retention = match (mode, until) {
        (Some(mode), Some(until)) => Some(ObjectRetention {
            mode: parse_retention_mode(mode).map_err(|_| {
                S3Error::InvalidArgument("Invalid object lock retention mode".into())
            })?,
            retain_until: OffsetDateTime::parse(until, &Rfc3339)
                .map_err(|_| S3Error::InvalidArgument("Invalid retain-until date".into()))?,
        }),
        (None, None) => bucket
            .object_lock
            .as_ref()
            .and_then(|configuration| configuration.default_retention.as_ref())
            .map(|default| ObjectRetention {
                mode: default.mode,
                retain_until: now
                    + Duration::days(
                        default
                            .days
                            .unwrap_or_else(|| default.years.unwrap_or(0) * 365),
                    ),
            }),
        _ => {
            return Err(S3Error::InvalidArgument(
                "Both object lock mode and retain-until date are required".into(),
            ));
        }
    };
    Ok((retention, legal))
}

fn update_selected_object<F>(
    bucket: &mut BucketState,
    key: &str,
    version_id: Option<&str>,
    mut update: F,
) -> Result<Option<String>, S3Error>
where
    F: FnMut(&mut StoredObject) -> Result<(), S3Error>,
{
    let target_id = if let Some(version_id) = version_id {
        version_id.to_string()
    } else if bucket.versioning == VersioningState::NeverEnabled {
        "null".to_string()
    } else {
        bucket
            .versions
            .get(key)
            .and_then(|chain| chain.first())
            .map(|version| version.id.clone())
            .ok_or(S3Error::NoSuchKey)?
    };
    let chain = bucket.versions.get_mut(key).ok_or(S3Error::NoSuchKey)?;
    let index = chain
        .iter()
        .position(|version| version.id == target_id)
        .ok_or(S3Error::NoSuchKey)?;
    let object = match &mut chain[index].value {
        VersionValue::Object(object) => object.as_mut(),
        VersionValue::DeleteMarker => {
            return Err(S3Error::DeleteMarkerVersion(target_id));
        }
    };
    update(object)?;
    if index == 0 {
        bucket.objects.insert(key.to_string(), object.clone());
    }
    Ok((bucket.versioning != VersioningState::NeverEnabled).then_some(target_id))
}

pub async fn put_object_tagging(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    version_id: Option<&str>,
    body: &[u8],
) -> Result<Response, S3Error> {
    let tags = parse_tagging_xml(body)?;
    let b = bucket(ctx, bucket_name).await?;
    let mut guard = b.write().await;
    let resolved = update_selected_object(&mut guard, key, version_id, |object| {
        object.tags = tags.clone();
        Ok(())
    })?;
    let mut response = Response::builder()
        .status(200)
        .header("x-amz-request-id", ctx.request_id);
    if let Some(version) = resolved {
        response = response.header("x-amz-version-id", version);
    }
    Ok(response
        .body(Body::empty())
        .expect("tagging response is valid"))
}

pub async fn get_object_tagging(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    version_id: Option<&str>,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let (object, resolved) = selected_object(&guard, key, version_id)?;
    let mut response = xml_ok(tagging_xml(&object.tags), ctx.request_id);
    if let Some(version) = resolved {
        response.headers_mut().insert(
            "x-amz-version-id",
            version.parse().expect("local version id is a valid header"),
        );
    }
    Ok(response)
}

pub async fn delete_object_tagging(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    version_id: Option<&str>,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let mut guard = b.write().await;
    let resolved = update_selected_object(&mut guard, key, version_id, |object| {
        object.tags.clear();
        Ok(())
    })?;
    let mut response = Response::builder()
        .status(204)
        .header("x-amz-request-id", ctx.request_id);
    if let Some(version) = resolved {
        response = response.header("x-amz-version-id", version);
    }
    Ok(response
        .body(Body::empty())
        .expect("tagging response is valid"))
}

fn parse_retention(body: &[u8]) -> Result<Option<ObjectRetention>, S3Error> {
    let root = parse_xml(body)?;
    if root.name != "Retention" {
        return Err(S3Error::MalformedXML);
    }
    if root.children.is_empty() {
        return Ok(None);
    }
    Ok(Some(ObjectRetention {
        mode: parse_retention_mode(child_text(&root, "Mode").ok_or(S3Error::MalformedXML)?)?,
        retain_until: OffsetDateTime::parse(
            child_text(&root, "RetainUntilDate").ok_or(S3Error::MalformedXML)?,
            &Rfc3339,
        )
        .map_err(|_| S3Error::MalformedXML)?,
    }))
}

pub async fn put_object_retention(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    version_id: Option<&str>,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, S3Error> {
    let retention = parse_retention(body)?;
    let bypass = bypass_governance(headers);
    let b = bucket(ctx, bucket_name).await?;
    if b.read().await.object_lock.is_none() {
        return Err(S3Error::InvalidRequest(
            "Bucket is missing an Object Lock configuration".into(),
        ));
    }
    let mut guard = b.write().await;
    let resolved = update_selected_object(&mut guard, key, version_id, |object| {
        if let Some(current) = &object.retention {
            let weakens_compliance = current.mode == RetentionMode::Compliance
                && retention
                    .as_ref()
                    .is_none_or(|new| new.mode != RetentionMode::Compliance);
            let shortens = retention
                .as_ref()
                .is_none_or(|new| new.retain_until < current.retain_until);
            if current.retain_until > OffsetDateTime::now_utc()
                && (weakens_compliance
                    || (shortens && (current.mode == RetentionMode::Compliance || !bypass)))
            {
                return Err(S3Error::AccessDenied);
            }
        }
        object.retention = retention.clone();
        Ok(())
    })?;
    let mut response = Response::builder()
        .status(200)
        .header("x-amz-request-id", ctx.request_id);
    if let Some(version) = resolved {
        response = response.header("x-amz-version-id", version);
    }
    Ok(response
        .body(Body::empty())
        .expect("retention response is valid"))
}

pub async fn get_object_retention(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    version_id: Option<&str>,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let (object, resolved) = selected_object(&guard, key, version_id)?;
    let content = object.retention.map_or_else(String::new, |retention| {
        format!(
            "{}{}",
            text_el("Mode", retention.mode.as_str()),
            text_el(
                "RetainUntilDate",
                &retention.retain_until.format(&Rfc3339).unwrap_or_default()
            )
        )
    });
    let mut response = xml_ok(
        format!("{DECL}<Retention xmlns=\"{S3_XMLNS}\">{content}</Retention>"),
        ctx.request_id,
    );
    if let Some(version) = resolved {
        response.headers_mut().insert(
            "x-amz-version-id",
            version.parse().expect("local version id is a valid header"),
        );
    }
    Ok(response)
}

fn parse_legal_hold(body: &[u8]) -> Result<bool, S3Error> {
    let root = parse_xml(body)?;
    if root.name != "LegalHold" {
        return Err(S3Error::MalformedXML);
    }
    match child_text(&root, "Status") {
        Some("ON") => Ok(true),
        Some("OFF") => Ok(false),
        _ => Err(S3Error::MalformedXML),
    }
}

pub async fn put_object_legal_hold(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    version_id: Option<&str>,
    body: &[u8],
) -> Result<Response, S3Error> {
    let legal_hold = parse_legal_hold(body)?;
    let b = bucket(ctx, bucket_name).await?;
    if b.read().await.object_lock.is_none() {
        return Err(S3Error::InvalidRequest(
            "Bucket is missing an Object Lock configuration".into(),
        ));
    }
    let mut guard = b.write().await;
    let resolved = update_selected_object(&mut guard, key, version_id, |object| {
        object.legal_hold = legal_hold;
        Ok(())
    })?;
    let mut response = Response::builder()
        .status(200)
        .header("x-amz-request-id", ctx.request_id);
    if let Some(version) = resolved {
        response = response.header("x-amz-version-id", version);
    }
    Ok(response
        .body(Body::empty())
        .expect("legal hold response is valid"))
}

pub async fn get_object_legal_hold(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    version_id: Option<&str>,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let (object, resolved) = selected_object(&guard, key, version_id)?;
    let status = if object.legal_hold { "ON" } else { "OFF" };
    let mut response = xml_ok(
        format!(
            "{DECL}<LegalHold xmlns=\"{S3_XMLNS}\">{}</LegalHold>",
            text_el("Status", status)
        ),
        ctx.request_id,
    );
    if let Some(version) = resolved {
        response.headers_mut().insert(
            "x-amz-version-id",
            version.parse().expect("local version id is a valid header"),
        );
    }
    Ok(response)
}

// ============================ object write/read/delete =========================

fn persist_object(
    ctx: &Ctx<'_>,
    bucket: &mut BucketState,
    key: &str,
    object: StoredObject,
) -> Option<String> {
    let version_id = match bucket.versioning {
        VersioningState::NeverEnabled => {
            bucket.versions.insert(
                key.to_string(),
                vec![StoredVersion {
                    id: "null".to_string(),
                    last_modified: object.last_modified,
                    value: VersionValue::Object(Box::new(object.clone())),
                }],
            );
            None
        }
        VersioningState::Enabled => Some(ctx.store.next_version_id()),
        VersioningState::Suspended => Some("null".to_string()),
    };
    if let Some(id) = &version_id {
        let chain = bucket.versions.entry(key.to_string()).or_default();
        if id == "null" {
            chain.retain(|version| version.id != "null");
        }
        chain.insert(
            0,
            StoredVersion {
                id: id.clone(),
                last_modified: object.last_modified,
                value: VersionValue::Object(Box::new(object.clone())),
            },
        );
    }
    bucket.objects.insert(key.to_string(), object);
    version_id
}

fn persist_delete_marker(
    ctx: &Ctx<'_>,
    bucket: &mut BucketState,
    key: &str,
    now: OffsetDateTime,
) -> Option<String> {
    match bucket.versioning {
        VersioningState::NeverEnabled => {
            bucket.objects.remove(key);
            bucket.versions.remove(key);
            None
        }
        VersioningState::Enabled | VersioningState::Suspended => {
            let id = if bucket.versioning == VersioningState::Enabled {
                ctx.store.next_version_id()
            } else {
                "null".to_string()
            };
            let chain = bucket.versions.entry(key.to_string()).or_default();
            if id == "null" {
                chain.retain(|version| version.id != "null");
            }
            chain.insert(
                0,
                StoredVersion {
                    id: id.clone(),
                    last_modified: now,
                    value: VersionValue::DeleteMarker,
                },
            );
            bucket.objects.remove(key);
            Some(id)
        }
    }
}

pub async fn put_object(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    headers: &HeaderMap,
    wire_body: Bytes,
) -> Result<MutationResult, S3Error> {
    put_object_with_event(
        ctx,
        bucket_name,
        key,
        headers,
        wire_body,
        EventType::ObjectCreatedPut,
        "PutObject",
    )
    .await
}

pub(crate) async fn put_object_with_event(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    headers: &HeaderMap,
    wire_body: Bytes,
    event_type: EventType,
    reason: &'static str,
) -> Result<MutationResult, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let default_encryption = b.read().await.encryption.clone();
    let encryption = request_encryption(ctx, headers, &default_encryption)?;
    let (body, checksums) = prepare_put_body(headers, wire_body)?;
    if body.len() > MAX_OBJECT_SIZE {
        return Err(S3Error::EntityTooLarge);
    }
    if let Some(md5) = header(headers, "content-md5") {
        validate_content_md5(md5, &body)?;
    }
    let content_type = header(headers, "content-type")
        .unwrap_or("binary/octet-stream")
        .to_string();
    let storage_class = header(headers, "x-amz-storage-class")
        .unwrap_or("STANDARD")
        .to_string();
    let tags = parse_tagging_header(header(headers, "x-amz-tagging"))?;
    let now = OffsetDateTime::now_utc();
    let etag_value = etag(&body);
    let stored_body = StoredBody::new(body)?;
    let mut guard = b.write().await;
    check_write_conditions(headers, guard.objects.get(key))?;
    if let Some(current) = guard.objects.get(key) {
        ensure_not_protected(current, bypass_governance(headers))?;
    }
    let (retention, legal_hold) = object_lock_values(headers, &guard, now)?;
    let object = StoredObject {
        etag: etag_value,
        body: stored_body,
        checksums,
        content_type,
        last_modified: now,
        metadata: user_metadata(headers),
        storage_class,
        tags,
        retention,
        legal_hold,
        encryption,
        parts: Vec::new(),
    };
    let etag_value = object.etag.clone();
    let version_id = persist_object(ctx, &mut guard, key, object.clone());
    let event = (!guard.notification_configuration.is_empty()).then(|| ObjectEvent {
        bucket: bucket_name.to_string(),
        key: key.to_string(),
        event_type,
        reason,
        time: object.last_modified,
        size: Some(object.size()),
        etag: Some(object.etag.clone()),
        version_id: version_id.clone(),
        sequencer: sequencer(object.last_modified),
        configuration: guard.notification_configuration.clone(),
    });
    drop(guard);

    let mut response = with_sse_headers(
        Response::builder()
            .status(200)
            .header("ETag", etag_value)
            .header("x-amz-request-id", ctx.request_id),
        &object.encryption,
    );
    if let Some(version_id) = version_id {
        response = response.header("x-amz-version-id", version_id);
    }
    for (&algorithm, value) in &object.checksums {
        response = response.header(algorithm.header_name(), value);
    }
    Ok(MutationResult {
        response: response
            .body(Body::empty())
            .expect("put object response is valid"),
        events: event.into_iter().collect(),
    })
}

fn prepare_put_body(
    headers: &HeaderMap,
    wire_body: Bytes,
) -> Result<(Bytes, BTreeMap<ChecksumAlgorithm, String>), S3Error> {
    let aws_chunked = header(headers, "x-amz-content-sha256")
        == Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
        || header(headers, "content-encoding").is_some_and(|value| {
            value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("aws-chunked"))
        });
    let (body, mut checksums) = if aws_chunked {
        let decoded_length = header(headers, "x-amz-decoded-content-length")
            .ok_or_else(|| S3Error::InvalidRequest("Missing x-amz-decoded-content-length".into()))?
            .parse::<usize>()
            .map_err(|_| S3Error::InvalidRequest("Invalid x-amz-decoded-content-length".into()))?;
        let decoded = decode_aws_chunked(&wire_body, decoded_length)?;
        (decoded.body, decoded.checksums)
    } else {
        (wire_body, BTreeMap::new())
    };

    for (name, value) in headers {
        let name = name.as_str();
        let Some(suffix) = name.strip_prefix("x-amz-checksum-") else {
            continue;
        };
        if suffix == "mode" {
            continue;
        }
        let algorithm = ChecksumAlgorithm::parse(suffix)?;
        let value = value
            .to_str()
            .map_err(|_| S3Error::InvalidRequest("Invalid checksum header".into()))?;
        let validated = validate_checksum(algorithm, value, &body)?;
        if checksums
            .insert(algorithm, validated.clone())
            .is_some_and(|trailer| trailer != validated)
        {
            return Err(S3Error::BadDigest);
        }
    }
    if let Some(value) = header(headers, "x-amz-sdk-checksum-algorithm") {
        let algorithm = ChecksumAlgorithm::parse(value)?;
        checksums
            .entry(algorithm)
            .or_insert_with(|| checksum_base64(algorithm, &body));
    }
    Ok((body, checksums))
}

fn selected_object(
    bucket: &BucketState,
    key: &str,
    version_id: Option<&str>,
) -> Result<(StoredObject, Option<String>), S3Error> {
    if let Some(version_id) = version_id {
        if let Some(version) = bucket
            .versions
            .get(key)
            .and_then(|chain| chain.iter().find(|version| version.id == version_id))
        {
            return match &version.value {
                VersionValue::Object(object) => {
                    Ok((object.as_ref().clone(), Some(version.id.clone())))
                }
                VersionValue::DeleteMarker => Err(S3Error::DeleteMarkerVersion(version.id.clone())),
            };
        }
        if version_id == "null" && bucket.versioning == VersioningState::NeverEnabled {
            return bucket
                .objects
                .get(key)
                .cloned()
                .map(|object| (object, Some("null".to_string())))
                .ok_or(S3Error::NoSuchKey);
        }
        return Err(S3Error::NoSuchKey);
    }
    if bucket
        .versions
        .get(key)
        .and_then(|chain| chain.first())
        .is_some_and(|version| matches!(version.value, VersionValue::DeleteMarker))
    {
        return Err(S3Error::NoSuchKeyDeleteMarker);
    }
    let object = bucket.objects.get(key).cloned().ok_or(S3Error::NoSuchKey)?;
    let version_id = if bucket.versioning == VersioningState::NeverEnabled {
        None
    } else {
        bucket.versions.get(key).and_then(|chain| {
            chain.first().and_then(|version| {
                matches!(version.value, VersionValue::Object(_)).then(|| version.id.clone())
            })
        })
    };
    Ok((object, version_id))
}

pub(crate) async fn read_object_body(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    version_id: Option<&str>,
) -> Result<Bytes, S3Error> {
    let bucket = bucket(ctx, bucket_name).await?;
    let guard = bucket.read().await;
    let body = selected_object(&guard, key, version_id)?.0.body;
    drop(guard);
    body.read_all()
}

pub async fn get_object(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    headers: &HeaderMap,
    version_id: Option<&str>,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let (object, resolved_version) = selected_object(&guard, key, version_id)?;
    check_read_conditions(headers, &object)?;
    drop(guard);

    let total = object.body.len();
    if let Some(range) = header(headers, "range") {
        let (start, end) = parse_range(range, total)?;
        let body = object.body.response_body(start, end - start + 1).await?;
        return Ok(object_response(
            &object,
            Some((start, end, total)),
            body,
            ctx.request_id,
            false,
            resolved_version.as_deref(),
        ));
    }
    let body = object.body.response_body(0, total).await?;
    Ok(object_response(
        &object,
        None,
        body,
        ctx.request_id,
        false,
        resolved_version.as_deref(),
    ))
}

pub async fn head_object(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    headers: &HeaderMap,
    version_id: Option<&str>,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let (object, resolved_version) = selected_object(&guard, key, version_id)?;
    check_read_conditions(headers, &object)?;
    Ok(object_response(
        &object,
        None,
        Body::empty(),
        ctx.request_id,
        true,
        resolved_version.as_deref(),
    ))
}

pub async fn delete_object(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    version_id: Option<&str>,
    headers: &HeaderMap,
) -> Result<MutationResult, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let now = OffsetDateTime::now_utc();
    let mut guard = b.write().await;
    let protected = if let Some(version_id) = version_id {
        guard.versions.get(key).and_then(|chain| {
            chain
                .iter()
                .find(|version| version.id == version_id)
                .and_then(|version| match &version.value {
                    VersionValue::Object(object) => Some(object.as_ref()),
                    VersionValue::DeleteMarker => None,
                })
        })
    } else {
        guard.objects.get(key)
    };
    if let Some(object) = protected {
        ensure_not_protected(object, bypass_governance(headers))?;
    }
    let mut deleted_marker = false;
    let response_version = if let Some(version_id) = version_id {
        let mut removed = None;
        if let Some(chain) = guard.versions.get_mut(key) {
            if let Some(position) = chain.iter().position(|version| version.id == version_id) {
                removed = Some(chain.remove(position));
            }
        }
        if removed.is_none()
            && version_id == "null"
            && guard.versioning == VersioningState::NeverEnabled
        {
            guard.objects.remove(key);
            Some("null".to_string())
        } else {
            let removed = removed.ok_or(S3Error::NoSuchKey)?;
            deleted_marker = matches!(removed.value, VersionValue::DeleteMarker);
            let latest = guard
                .versions
                .get(key)
                .and_then(|chain| chain.first())
                .cloned();
            match latest.map(|version| version.value) {
                Some(VersionValue::Object(object)) => {
                    guard.objects.insert(key.to_string(), *object);
                }
                _ => {
                    guard.objects.remove(key);
                }
            }
            if guard.versions.get(key).is_some_and(Vec::is_empty) {
                guard.versions.remove(key);
            }
            Some(version_id.to_string())
        }
    } else {
        persist_delete_marker(ctx, &mut guard, key, now)
    };
    let created_marker = version_id.is_none() && response_version.is_some();
    let event = (!guard.notification_configuration.is_empty()).then(|| ObjectEvent {
        bucket: bucket_name.to_string(),
        key: key.to_string(),
        event_type: if created_marker {
            EventType::ObjectRemovedDeleteMarkerCreated
        } else {
            EventType::ObjectRemovedDelete
        },
        reason: "DeleteObject",
        time: now,
        size: None,
        etag: None,
        version_id: response_version.clone(),
        sequencer: sequencer(now),
        configuration: guard.notification_configuration.clone(),
    });
    drop(guard);

    let mut response = Response::builder()
        .status(204)
        .header("x-amz-request-id", ctx.request_id);
    if let Some(version_id) = response_version {
        response = response.header("x-amz-version-id", version_id);
    }
    if created_marker || deleted_marker {
        response = response.header("x-amz-delete-marker", "true");
    }
    Ok(MutationResult {
        response: response
            .body(Body::empty())
            .expect("delete object response is valid"),
        events: event.into_iter().collect(),
    })
}

// ============================ response builders ================================

fn object_response(
    object: &StoredObject,
    range: Option<(usize, usize, usize)>,
    body: Body,
    request_id: &str,
    head: bool,
    version_id: Option<&str>,
) -> Response {
    let mut builder = with_sse_headers(
        Response::builder()
            .header("ETag", &object.etag)
            .header("Content-Type", &object.content_type)
            .header("Last-Modified", http_date(object.last_modified))
            .header("Accept-Ranges", "bytes")
            .header("x-amz-request-id", request_id)
            .header("x-amz-storage-class", &object.storage_class),
        &object.encryption,
    );
    if let Some(retention) = &object.retention {
        builder = builder
            .header("x-amz-object-lock-mode", retention.mode.as_str())
            .header(
                "x-amz-object-lock-retain-until-date",
                retention.retain_until.format(&Rfc3339).unwrap_or_default(),
            );
    }
    if object.legal_hold {
        builder = builder.header("x-amz-object-lock-legal-hold", "ON");
    }
    if let Some(version_id) = version_id {
        builder = builder.header("x-amz-version-id", version_id);
    }
    for (k, v) in &object.metadata {
        builder = builder.header(format!("x-amz-meta-{k}"), v);
    }
    let (status, content_length) = match range {
        Some((start, end, total)) => {
            builder = builder.header("Content-Range", format!("bytes {start}-{end}/{total}"));
            (StatusCode::PARTIAL_CONTENT, end - start + 1)
        }
        None => {
            for (&algorithm, value) in &object.checksums {
                builder = builder.header(algorithm.header_name(), value);
            }
            (StatusCode::OK, object.size())
        }
    };
    builder = builder.header("Content-Length", content_length.to_string());
    let body = if head { Body::empty() } else { body };
    builder
        .status(status)
        .body(body)
        .expect("object response is valid")
}

fn xml_ok(body: String, request_id: &str) -> Response {
    Response::builder()
        .status(200)
        .header("content-type", "application/xml")
        .header("x-amz-request-id", request_id)
        .body(Body::from(body))
        .expect("xml response is valid")
}

fn status_only(status: u16, request_id: &str) -> Response {
    Response::builder()
        .status(status)
        .header("x-amz-request-id", request_id)
        .body(Body::empty())
        .expect("status-only response is valid")
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    if pattern == "*" {
        return true;
    }
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return pattern == value;
    };
    value.starts_with(prefix) && value.ends_with(suffix)
}

fn matching_cors_rule<'a>(
    rules: &'a [CorsRule],
    origin: &str,
    method: &str,
    requested_headers: &[&str],
) -> Option<&'a CorsRule> {
    rules.iter().find(|rule| {
        rule.allowed_origins
            .iter()
            .any(|allowed| wildcard_match(allowed, origin))
            && rule
                .allowed_methods
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(method))
            && requested_headers.iter().all(|requested| {
                rule.allowed_headers
                    .iter()
                    .any(|allowed| wildcard_match(allowed, requested.trim()))
            })
    })
}

fn insert_cors_headers(
    response: &mut Response,
    rule: &CorsRule,
    origin: &str,
    requested_headers: Option<&[&str]>,
) {
    let allowed_origin = if rule.allowed_origins.iter().any(|value| value == "*") {
        "*"
    } else {
        origin
    };
    if let Ok(value) = allowed_origin.parse() {
        response
            .headers_mut()
            .insert("access-control-allow-origin", value);
    }
    response
        .headers_mut()
        .insert("vary", "Origin".parse().expect("static header is valid"));
    if !rule.expose_headers.is_empty() {
        if let Ok(value) = rule.expose_headers.join(", ").parse() {
            response
                .headers_mut()
                .insert("access-control-expose-headers", value);
        }
    }
    if let Some(requested_headers) = requested_headers {
        if let Ok(value) = rule.allowed_methods.join(", ").parse() {
            response
                .headers_mut()
                .insert("access-control-allow-methods", value);
        }
        if !requested_headers.is_empty() {
            if let Ok(value) = requested_headers
                .iter()
                .map(|header| header.trim())
                .collect::<Vec<_>>()
                .join(", ")
                .parse()
            {
                response
                    .headers_mut()
                    .insert("access-control-allow-headers", value);
            }
        }
        if let Some(max_age) = rule.max_age_seconds {
            response.headers_mut().insert(
                "access-control-max-age",
                max_age
                    .to_string()
                    .parse()
                    .expect("integer header is valid"),
            );
        }
    }
}

pub async fn options_bucket(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    headers: &HeaderMap,
) -> Result<Response, S3Error> {
    let origin = header(headers, "origin").ok_or(S3Error::AccessForbidden)?;
    let method =
        header(headers, "access-control-request-method").ok_or(S3Error::AccessForbidden)?;
    let requested = header(headers, "access-control-request-headers")
        .map(|value| value.split(',').collect::<Vec<_>>())
        .unwrap_or_default();
    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let rules = guard.cors.as_deref().ok_or(S3Error::AccessForbidden)?;
    let rule =
        matching_cors_rule(rules, origin, method, &requested).ok_or(S3Error::AccessForbidden)?;
    let mut response = status_only(200, ctx.request_id);
    insert_cors_headers(&mut response, rule, origin, Some(&requested));
    Ok(response)
}

pub async fn apply_cors_headers(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    method: &str,
    headers: &HeaderMap,
    response: &mut Response,
) {
    let Some(origin) = header(headers, "origin") else {
        return;
    };
    let Some(bucket) = ctx.store.get(ctx.account, bucket_name) else {
        return;
    };
    let guard = bucket.read().await;
    let Some(rules) = guard.cors.as_deref() else {
        return;
    };
    if let Some(rule) = matching_cors_rule(rules, origin, method, &[]) {
        insert_cors_headers(response, rule, origin, None);
    }
}

fn etag_matches(value: &str, etag: &str) -> bool {
    value == "*" || value.split(',').any(|candidate| candidate.trim() == etag)
}

fn parse_http_date(value: &str) -> Option<OffsetDateTime> {
    let format = time::format_description::parse_borrowed::<2>(
        "[weekday repr:short], [day padding:zero] [month repr:short] [year] [hour]:[minute]:[second] GMT",
    )
    .ok()?;
    PrimitiveDateTime::parse(value, &format)
        .ok()
        .map(PrimitiveDateTime::assume_utc)
}

/// Evaluate conditional reads, including HTTP-date precision and ETag/date precedence.
fn check_read_conditions(headers: &HeaderMap, object: &StoredObject) -> Result<(), S3Error> {
    if let Some(if_match) = header(headers, "if-match") {
        if !etag_matches(if_match, &object.etag) {
            return Err(S3Error::PreconditionFailed);
        }
    } else if let Some(date) = header(headers, "if-unmodified-since").and_then(parse_http_date) {
        if object.last_modified.unix_timestamp() > date.unix_timestamp() {
            return Err(S3Error::PreconditionFailed);
        }
    }

    if let Some(if_none_match) = header(headers, "if-none-match") {
        if etag_matches(if_none_match, &object.etag) {
            return Err(S3Error::NotModified);
        }
    } else if let Some(date) = header(headers, "if-modified-since").and_then(parse_http_date) {
        if object.last_modified.unix_timestamp() <= date.unix_timestamp() {
            return Err(S3Error::NotModified);
        }
    }
    Ok(())
}

/// Evaluate and apply these checks while the caller holds the bucket write lock.
fn check_write_conditions(
    headers: &HeaderMap,
    current: Option<&StoredObject>,
) -> Result<(), S3Error> {
    if let Some(if_match) = header(headers, "if-match") {
        if !current.is_some_and(|object| etag_matches(if_match, &object.etag)) {
            return Err(S3Error::PreconditionFailed);
        }
    }
    if header(headers, "if-none-match") == Some("*") && current.is_some() {
        return Err(S3Error::PreconditionFailed);
    }
    Ok(())
}

/// Parse a `Range: bytes=...` header into an inclusive `(start, end)`; `InvalidRange` on
/// an unsatisfiable or malformed range.
fn parse_range(range: &str, total: usize) -> Result<(usize, usize), S3Error> {
    let spec = range.strip_prefix("bytes=").ok_or(S3Error::InvalidRange)?;
    if total == 0 {
        return Err(S3Error::InvalidRange);
    }
    let (start_s, end_s) = spec.split_once('-').ok_or(S3Error::InvalidRange)?;
    let (start, end) = match (start_s.trim(), end_s.trim()) {
        ("", "") => return Err(S3Error::InvalidRange),
        ("", suffix) => {
            // last `suffix` bytes
            let n: usize = suffix.parse().map_err(|_| S3Error::InvalidRange)?;
            let n = n.min(total);
            (total - n, total - 1)
        }
        (s, "") => {
            let start: usize = s.parse().map_err(|_| S3Error::InvalidRange)?;
            (start, total - 1)
        }
        (s, e) => {
            let start: usize = s.parse().map_err(|_| S3Error::InvalidRange)?;
            let end: usize = e.parse().map_err(|_| S3Error::InvalidRange)?;
            (start, end.min(total - 1))
        }
    };
    if start > end || start >= total {
        return Err(S3Error::InvalidRange);
    }
    Ok((start, end))
}

// ============================ listing ==========================================

use crate::query::QueryParams;

const DEFAULT_MAX_KEYS: usize = 1000;

struct ListResult {
    keys: Vec<(String, StoredObject)>,
    common_prefixes: Vec<String>,
    is_truncated: bool,
    next_token: Option<String>,
}

/// Shared listing computation over a bucket's objects.
fn compute_listing(
    objects: &BTreeMap<String, StoredObject>,
    prefix: &str,
    delimiter: Option<&str>,
    start_after: Option<&str>,
    max_keys: usize,
) -> ListResult {
    let mut keys = Vec::new();
    let mut common_prefixes: Vec<String> = Vec::new();
    let mut is_truncated = false;
    let mut next_token = None;
    let mut last_consumed_key = None;

    for (key, obj) in objects.iter() {
        if !key.starts_with(prefix) {
            continue;
        }
        if let Some(sa) = start_after {
            if key.as_str() <= sa {
                continue;
            }
        }
        // Delimiter rollup into common prefixes.
        if let Some(delim) = delimiter {
            let rest = &key[prefix.len()..];
            if let Some(idx) = rest.find(delim) {
                let cp = format!("{prefix}{}", &rest[..idx + delim.len()]);
                if !common_prefixes.contains(&cp) {
                    if keys.len() + common_prefixes.len() >= max_keys {
                        is_truncated = true;
                        next_token = last_consumed_key;
                        break;
                    }
                    common_prefixes.push(cp);
                }
                last_consumed_key = Some(key.clone());
                continue;
            }
        }
        if keys.len() + common_prefixes.len() >= max_keys {
            is_truncated = true;
            next_token = last_consumed_key;
            break;
        }
        keys.push((key.clone(), obj.clone()));
        last_consumed_key = Some(key.clone());
    }
    ListResult {
        keys,
        common_prefixes,
        is_truncated,
        next_token,
    }
}

pub async fn list_objects_v2(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    q: &QueryParams,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let prefix = q.get("prefix").unwrap_or("");
    let delimiter = q.get("delimiter");
    let max_keys = q
        .get("max-keys")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_KEYS);
    // continuation-token takes precedence over start-after.
    let start_after = q.get("continuation-token").or_else(|| q.get("start-after"));

    let result = compute_listing(&guard.objects, prefix, delimiter, start_after, max_keys);
    let fetch_owner = q.get("fetch-owner") == Some("true");
    let encode = match q.get("encoding-type") {
        None => false,
        Some("url") => true,
        Some(other) => {
            return Err(S3Error::InvalidArgument(format!(
                "Invalid EncodingType: {other}"
            )))
        }
    };
    let response_value = |value: &str| {
        if encode {
            crate::presign::uri_encode(value.as_bytes(), true)
        } else {
            value.to_string()
        }
    };

    let mut body = format!(
        "{DECL}<ListBucketResult><Name>{}</Name><Prefix>{}</Prefix><KeyCount>{}</KeyCount><MaxKeys>{}</MaxKeys><IsTruncated>{}</IsTruncated>",
        escape(bucket_name),
        escape(&response_value(prefix)),
        result.keys.len(),
        max_keys,
        result.is_truncated,
    );
    if let Some(d) = delimiter {
        body.push_str(&text_el("Delimiter", &response_value(d)));
    }
    if encode {
        body.push_str("<EncodingType>url</EncodingType>");
    }
    if let Some(start_after) = q.get("start-after") {
        body.push_str(&text_el("StartAfter", &response_value(start_after)));
    }
    if let Some(token) = &result.next_token {
        body.push_str(&text_el("NextContinuationToken", token));
    }
    for (key, obj) in &result.keys {
        body.push_str(&contents_xml(
            &response_value(key),
            obj,
            ctx.account,
            fetch_owner,
        ));
    }
    for cp in &result.common_prefixes {
        body.push_str(&format!(
            "<CommonPrefixes>{}</CommonPrefixes>",
            text_el("Prefix", &response_value(cp))
        ));
    }
    body.push_str("</ListBucketResult>");
    Ok(xml_ok(body, ctx.request_id))
}

pub async fn list_objects_v1(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    q: &QueryParams,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let prefix = q.get("prefix").unwrap_or("");
    let delimiter = q.get("delimiter");
    let max_keys = q
        .get("max-keys")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_KEYS);
    let marker = q.get("marker");

    let result = compute_listing(&guard.objects, prefix, delimiter, marker, max_keys);

    let mut body = format!(
        "{DECL}<ListBucketResult><Name>{}</Name><Prefix>{}</Prefix><Marker>{}</Marker><MaxKeys>{}</MaxKeys><IsTruncated>{}</IsTruncated>",
        escape(bucket_name),
        escape(prefix),
        escape(marker.unwrap_or("")),
        max_keys,
        result.is_truncated,
    );
    if let Some(d) = delimiter {
        body.push_str(&text_el("Delimiter", d));
    }
    // v1 NextMarker only appears when truncated and a delimiter is set.
    if result.is_truncated && delimiter.is_some() {
        if let Some(token) = &result.next_token {
            body.push_str(&text_el("NextMarker", token));
        }
    }
    for (key, obj) in &result.keys {
        body.push_str(&contents_xml(key, obj, ctx.account, true));
    }
    for cp in &result.common_prefixes {
        body.push_str(&format!(
            "<CommonPrefixes>{}</CommonPrefixes>",
            text_el("Prefix", cp)
        ));
    }
    body.push_str("</ListBucketResult>");
    Ok(xml_ok(body, ctx.request_id))
}

fn contents_xml(key: &str, obj: &StoredObject, account: &str, owner: bool) -> String {
    let owner_xml = if owner {
        format!("<Owner><ID>{account}</ID><DisplayName>locallycloud</DisplayName></Owner>")
    } else {
        String::new()
    };
    format!(
        "<Contents>{}<LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>{}</StorageClass>{}</Contents>",
        text_el("Key", key),
        iso8601(obj.last_modified),
        escape(&obj.etag),
        obj.size(),
        escape(&obj.storage_class),
        owner_xml,
    )
}

// ============================ copy =============================================

pub(crate) fn parse_copy_source(value: &str) -> Result<(String, String, Option<String>), S3Error> {
    let (path, query) = value.split_once('?').unwrap_or((value, ""));
    let decoded = crate::addr::percent_decode(path.trim_start_matches('/'));
    let (bucket, key) = decoded
        .split_once('/')
        .ok_or_else(|| S3Error::InvalidArgument("malformed x-amz-copy-source".into()))?;
    let version_id = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("versionId="))
        .map(crate::addr::percent_decode);
    Ok((bucket.to_string(), key.to_string(), version_id))
}

fn check_copy_conditions(headers: &HeaderMap, object: &StoredObject) -> Result<(), S3Error> {
    if let Some(value) = header(headers, "x-amz-copy-source-if-match") {
        if !etag_matches(value, &object.etag) {
            return Err(S3Error::PreconditionFailed);
        }
    } else if let Some(date) =
        header(headers, "x-amz-copy-source-if-unmodified-since").and_then(parse_http_date)
    {
        if object.last_modified.unix_timestamp() > date.unix_timestamp() {
            return Err(S3Error::PreconditionFailed);
        }
    }
    if let Some(value) = header(headers, "x-amz-copy-source-if-none-match") {
        if etag_matches(value, &object.etag) {
            return Err(S3Error::PreconditionFailed);
        }
    } else if let Some(date) =
        header(headers, "x-amz-copy-source-if-modified-since").and_then(parse_http_date)
    {
        if object.last_modified.unix_timestamp() <= date.unix_timestamp() {
            return Err(S3Error::PreconditionFailed);
        }
    }
    Ok(())
}

pub async fn copy_object(
    ctx: &Ctx<'_>,
    dest_bucket: &str,
    dest_key: &str,
    headers: &HeaderMap,
) -> Result<MutationResult, S3Error> {
    let source = header(headers, "x-amz-copy-source")
        .ok_or_else(|| S3Error::InvalidArgument("x-amz-copy-source is required".into()))?;
    let (src_bucket, src_key, src_version) = parse_copy_source(source)?;
    let metadata_directive = header(headers, "x-amz-metadata-directive")
        .unwrap_or("COPY")
        .to_ascii_uppercase();
    let tagging_directive = header(headers, "x-amz-tagging-directive")
        .unwrap_or("COPY")
        .to_ascii_uppercase();
    if !matches!(metadata_directive.as_str(), "COPY" | "REPLACE")
        || !matches!(tagging_directive.as_str(), "COPY" | "REPLACE")
    {
        return Err(S3Error::InvalidArgument("invalid copy directive".into()));
    }
    let src = bucket(ctx, &src_bucket).await?;
    let (source_object, source_is_current) = {
        let guard = src.read().await;
        let selected = selected_object(&guard, &src_key, src_version.as_deref())?.0;
        let source_is_current = src_version.as_deref().is_none_or(|version_id| {
            guard
                .versions
                .get(&src_key)
                .and_then(|chain| chain.first())
                .is_some_and(|version| version.id == version_id)
        });
        (selected, source_is_current)
    };
    let changes_encryption = [
        "x-amz-server-side-encryption",
        "x-amz-server-side-encryption-aws-kms-key-id",
        "x-amz-server-side-encryption-bucket-key-enabled",
    ]
    .iter()
    .any(|name| headers.contains_key(*name));
    if src_bucket == dest_bucket
        && src_key == dest_key
        && source_is_current
        && metadata_directive == "COPY"
        && !changes_encryption
    {
        return Err(S3Error::InvalidRequest(
            "This copy request is illegal because it is trying to copy an object to itself without changing metadata".into(),
        ));
    }
    check_copy_conditions(headers, &source_object)?;

    let (content_type, metadata) = if metadata_directive == "REPLACE" {
        (
            header(headers, "content-type")
                .unwrap_or("binary/octet-stream")
                .to_string(),
            user_metadata(headers),
        )
    } else {
        (
            source_object.content_type.clone(),
            source_object.metadata.clone(),
        )
    };
    let tags = if tagging_directive == "REPLACE" {
        parse_tagging_header(header(headers, "x-amz-tagging"))?
    } else {
        source_object.tags.clone()
    };
    validate_tags(&tags)?;
    let copied_etag = source_object.body.single_part_etag()?;
    let dest = bucket(ctx, dest_bucket).await?;
    let default_encryption = dest.read().await.encryption.clone();
    let encryption = request_encryption(ctx, headers, &default_encryption)?;
    let mut guard = dest.write().await;
    if let Some(current) = guard.objects.get(dest_key) {
        ensure_not_protected(current, bypass_governance(headers))?;
    }
    let now = OffsetDateTime::now_utc();
    let (retention, legal_hold) = object_lock_values(headers, &guard, now)?;
    let new_object = StoredObject {
        body: source_object.body.clone(),
        etag: copied_etag,
        checksums: source_object.checksums.clone(),
        content_type,
        last_modified: now,
        metadata,
        storage_class: header(headers, "x-amz-storage-class")
            .unwrap_or(&source_object.storage_class)
            .to_string(),
        tags,
        retention,
        legal_hold,
        encryption,
        parts: source_object.parts.clone(),
    };
    let version_id = persist_object(ctx, &mut guard, dest_key, new_object.clone());
    let event = (!guard.notification_configuration.is_empty()).then(|| ObjectEvent {
        bucket: dest_bucket.to_string(),
        key: dest_key.to_string(),
        event_type: EventType::ObjectCreatedCopy,
        reason: "CopyObject",
        time: new_object.last_modified,
        size: Some(new_object.size()),
        etag: Some(new_object.etag.clone()),
        version_id: version_id.clone(),
        sequencer: sequencer(new_object.last_modified),
        configuration: guard.notification_configuration.clone(),
    });
    drop(guard);

    let body = format!(
        "{DECL}<CopyObjectResult><LastModified>{}</LastModified><ETag>{}</ETag></CopyObjectResult>",
        iso8601(new_object.last_modified),
        escape(&new_object.etag),
    );
    let mut response = with_sse_headers(
        Response::builder()
            .status(200)
            .header("content-type", "application/xml")
            .header("x-amz-request-id", ctx.request_id),
        &new_object.encryption,
    );
    if let Some(version_id) = version_id {
        response = response.header("x-amz-version-id", version_id);
    }
    Ok(MutationResult {
        response: response
            .body(Body::from(body))
            .expect("copy object response is valid"),
        events: event.into_iter().collect(),
    })
}

fn checksum_elements(checksums: &BTreeMap<ChecksumAlgorithm, String>) -> String {
    let mut xml = String::new();
    for (algorithm, value) in checksums {
        let name = match algorithm {
            ChecksumAlgorithm::Crc32 => "ChecksumCRC32",
            ChecksumAlgorithm::Crc32c => "ChecksumCRC32C",
            ChecksumAlgorithm::Crc64Nvme => "ChecksumCRC64NVME",
            ChecksumAlgorithm::Sha1 => "ChecksumSHA1",
            ChecksumAlgorithm::Sha256 => "ChecksumSHA256",
        };
        xml.push_str(&text_el(name, value));
    }
    xml
}

pub async fn get_object_attributes(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    headers: &HeaderMap,
    version_id: Option<&str>,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let (object, resolved_version) = selected_object(&guard, key, version_id)?;
    let requested = header(headers, "x-amz-object-attributes")
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>();
    let mut body = format!("{DECL}<GetObjectAttributesOutput>");
    if requested.contains(&"ETag") {
        body.push_str(&text_el("ETag", object.etag.trim_matches('"')));
    }
    if requested.contains(&"Checksum") {
        body.push_str(&format!(
            "<Checksum>{}</Checksum>",
            checksum_elements(&object.checksums)
        ));
    }
    if requested.contains(&"ObjectParts") {
        let marker = header(headers, "x-amz-part-number-marker")
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(0);
        let max_parts = header(headers, "x-amz-max-parts")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1000);
        let remaining = object
            .parts
            .iter()
            .filter(|part| part.number > marker)
            .collect::<Vec<_>>();
        let shown = remaining
            .iter()
            .take(max_parts)
            .copied()
            .collect::<Vec<_>>();
        let truncated = remaining.len() > shown.len();
        body.push_str(&format!(
            "<ObjectParts><PartNumberMarker>{marker}</PartNumberMarker><NextPartNumberMarker>{}</NextPartNumberMarker><MaxParts>{max_parts}</MaxParts><IsTruncated>{truncated}</IsTruncated><PartsCount>{}</PartsCount>",
            shown.last().map_or(marker, |part| part.number),
            object.parts.len(),
        ));
        for part in shown {
            body.push_str(&format!(
                "<Part><PartNumber>{}</PartNumber><Size>{}</Size>{}</Part>",
                part.number,
                part.size,
                checksum_elements(&part.checksums)
            ));
        }
        body.push_str("</ObjectParts>");
    }
    if requested.contains(&"StorageClass") {
        body.push_str(&text_el("StorageClass", &object.storage_class));
    }
    if requested.contains(&"ObjectSize") {
        body.push_str(&format!("<ObjectSize>{}</ObjectSize>", object.size()));
    }
    body.push_str("</GetObjectAttributesOutput>");
    let mut response = Response::builder()
        .status(200)
        .header("content-type", "application/xml")
        .header("x-amz-request-id", ctx.request_id)
        .header("Last-Modified", http_date(object.last_modified));
    if let Some(version_id) = resolved_version {
        response = response.header("x-amz-version-id", version_id);
    }
    Ok(response
        .body(Body::from(body))
        .expect("object attributes response is valid"))
}

// ============================ multipart ========================================

const MIN_PART_SIZE: usize = 5 * 1024 * 1024;
const MAX_PART_NUMBER: u16 = 10_000;

pub async fn create_multipart_upload(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    headers: &HeaderMap,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let default_encryption = b.read().await.encryption.clone();
    let encryption = request_encryption(ctx, headers, &default_encryption)?;
    let tags = parse_tagging_header(header(headers, "x-amz-tagging"))?;
    let now = OffsetDateTime::now_utc();
    let mut guard = b.write().await;
    let (retention, legal_hold) = object_lock_values(headers, &guard, now)?;
    let upload_id = ctx.store.next_upload_id();
    let upload = MultipartUpload {
        id: upload_id.clone(),
        key: key.to_string(),
        initiated: now,
        content_type: header(headers, "content-type")
            .unwrap_or("binary/octet-stream")
            .to_string(),
        metadata: user_metadata(headers),
        storage_class: header(headers, "x-amz-storage-class")
            .unwrap_or("STANDARD")
            .to_string(),
        tags,
        retention,
        legal_hold,
        encryption: encryption.clone(),
        parts: BTreeMap::new(),
        parts_revision: 0,
    };
    guard.uploads.insert(upload_id.clone(), upload);
    drop(guard);
    let body = format!(
        "{DECL}<InitiateMultipartUploadResult>{}{}{}<UploadId>{}</UploadId></InitiateMultipartUploadResult>",
        text_el("Bucket", bucket_name),
        text_el("Key", key),
        "",
        escape(&upload_id),
    );
    Ok(with_sse_headers(
        Response::builder()
            .status(200)
            .header("content-type", "application/xml")
            .header("x-amz-request-id", ctx.request_id),
        &encryption,
    )
    .body(Body::from(body))
    .expect("create multipart upload response is valid"))
}

fn checked_part_number(value: Option<&str>) -> Result<u16, S3Error> {
    let number = value
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            S3Error::InvalidArgument("Part number must be between 1 and 10000".into())
        })?;
    if !(1..=MAX_PART_NUMBER).contains(&number) {
        return Err(S3Error::InvalidArgument(
            "Part number must be between 1 and 10000".into(),
        ));
    }
    Ok(number)
}

async fn ensure_upload(
    bucket: &Arc<RwLock<BucketState>>,
    key: &str,
    upload_id: &str,
) -> Result<(), S3Error> {
    let guard = bucket.read().await;
    if !guard
        .uploads
        .get(upload_id)
        .is_some_and(|upload| upload.key == key)
    {
        return Err(S3Error::NoSuchUpload);
    }
    Ok(())
}

pub async fn upload_part(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    upload_id: &str,
    part_number: Option<&str>,
    headers: &HeaderMap,
    wire_body: Bytes,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    ensure_upload(&b, key, upload_id).await?;
    let part_number = checked_part_number(part_number)?;
    let (body, checksums) = prepare_put_body(headers, wire_body)?;
    if let Some(md5) = header(headers, "content-md5") {
        validate_content_md5(md5, &body)?;
    }
    let part = StoredPart {
        etag: etag(&body),
        body,
        checksums,
        last_modified: OffsetDateTime::now_utc(),
    };
    let mut guard = b.write().await;
    let upload = guard
        .uploads
        .get_mut(upload_id)
        .ok_or(S3Error::NoSuchUpload)?;
    if upload.key != key {
        return Err(S3Error::NoSuchUpload);
    }
    upload.parts.insert(part_number, part.clone());
    upload.parts_revision = upload.parts_revision.wrapping_add(1);
    let encryption = upload.encryption.clone();
    let mut response = with_sse_headers(
        Response::builder()
            .status(200)
            .header("ETag", &part.etag)
            .header("x-amz-request-id", ctx.request_id),
        &encryption,
    );
    for (algorithm, checksum) in &part.checksums {
        response = response.header(algorithm.header_name(), checksum);
    }
    Ok(response
        .body(Body::empty())
        .expect("upload part response is valid"))
}

pub async fn upload_part_copy(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    upload_id: &str,
    part_number: Option<&str>,
    headers: &HeaderMap,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    ensure_upload(&b, key, upload_id).await?;
    let part_number = checked_part_number(part_number)?;
    let source = header(headers, "x-amz-copy-source")
        .ok_or_else(|| S3Error::InvalidArgument("x-amz-copy-source is required".into()))?;
    let (src_bucket, src_key, src_version) = parse_copy_source(source)?;
    let src = bucket(ctx, &src_bucket).await?;
    let source_object = {
        let guard = src.read().await;
        selected_object(&guard, &src_key, src_version.as_deref())?.0
    };
    check_copy_conditions(headers, &source_object)?;
    let body = if let Some(range) = header(headers, "x-amz-copy-source-range") {
        let (start, end) = parse_range(range, source_object.size())?;
        source_object.body.read_range(start, end + 1)?
    } else {
        source_object.body.read_all()?
    };
    let part = StoredPart {
        etag: etag(&body),
        body,
        checksums: BTreeMap::new(),
        last_modified: OffsetDateTime::now_utc(),
    };
    let mut guard = b.write().await;
    let upload = guard
        .uploads
        .get_mut(upload_id)
        .ok_or(S3Error::NoSuchUpload)?;
    if upload.key != key {
        return Err(S3Error::NoSuchUpload);
    }
    upload.parts.insert(part_number, part.clone());
    upload.parts_revision = upload.parts_revision.wrapping_add(1);
    let encryption = upload.encryption.clone();
    let body = format!(
        "{DECL}<CopyPartResult><LastModified>{}</LastModified><ETag>{}</ETag></CopyPartResult>",
        iso8601(part.last_modified),
        escape(&part.etag)
    );
    Ok(with_sse_headers(
        Response::builder()
            .status(200)
            .header("content-type", "application/xml")
            .header("x-amz-request-id", ctx.request_id),
        &encryption,
    )
    .body(Body::from(body))
    .expect("upload part copy response is valid"))
}

type CompletionPart = (u16, String, BTreeMap<ChecksumAlgorithm, String>);

fn parse_complete_parts(body: &[u8]) -> Result<Vec<CompletionPart>, S3Error> {
    let root = parse_xml(body)?;
    if root.name != "CompleteMultipartUpload" || !root.text.is_empty() || root.children.is_empty() {
        return Err(S3Error::MalformedXML);
    }
    let mut parts = Vec::with_capacity(root.children.len());
    for part in root.children {
        if part.name != "Part" || !part.text.is_empty() {
            return Err(S3Error::MalformedXML);
        }
        let mut number = None;
        let mut etag = None;
        let mut checksums = BTreeMap::new();
        for field in part.children {
            if !field.children.is_empty() || field.text.is_empty() {
                return Err(S3Error::MalformedXML);
            }
            match field.name.as_str() {
                "PartNumber" if number.is_none() => {
                    number = Some(
                        field
                            .text
                            .parse::<u16>()
                            .map_err(|_| S3Error::MalformedXML)?,
                    );
                }
                "ETag" if etag.is_none() => etag = Some(field.text),
                name => {
                    let algorithm = match name {
                        "ChecksumCRC32" => ChecksumAlgorithm::Crc32,
                        "ChecksumCRC32C" => ChecksumAlgorithm::Crc32c,
                        "ChecksumCRC64NVME" => ChecksumAlgorithm::Crc64Nvme,
                        "ChecksumSHA1" => ChecksumAlgorithm::Sha1,
                        "ChecksumSHA256" => ChecksumAlgorithm::Sha256,
                        _ => return Err(S3Error::MalformedXML),
                    };
                    if checksums.insert(algorithm, field.text).is_some() {
                        return Err(S3Error::MalformedXML);
                    }
                }
            }
        }
        parts.push((
            number.ok_or(S3Error::MalformedXML)?,
            etag.ok_or(S3Error::MalformedXML)?,
            checksums,
        ));
    }
    Ok(parts)
}

pub async fn complete_multipart_upload(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    upload_id: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<MutationResult, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let upload = {
        let guard = b.read().await;
        guard
            .uploads
            .get(upload_id)
            .filter(|upload| upload.key == key)
            .cloned()
            .ok_or(S3Error::NoSuchUpload)?
    };
    let requested = parse_complete_parts(body)?;
    if requested.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(S3Error::InvalidPartOrder);
    }
    let mut selected = Vec::with_capacity(requested.len());
    for (number, expected_etag, checksums) in &requested {
        let part = upload.parts.get(number).ok_or(S3Error::InvalidPart)?;
        if part.etag != *expected_etag {
            return Err(S3Error::InvalidPart);
        }
        for (algorithm, expected) in checksums {
            validate_checksum(*algorithm, expected, &part.body)?;
        }
        selected.push((*number, part.clone()));
    }
    if selected
        .iter()
        .take(selected.len().saturating_sub(1))
        .any(|(_, part)| part.body.len() < MIN_PART_SIZE)
    {
        return Err(S3Error::EntityTooSmall);
    }
    let (body, digests, object_parts) = tokio::task::spawn_blocking(move || {
        let mut bodies = Vec::with_capacity(selected.len());
        let mut digests = Vec::with_capacity(selected.len());
        let mut object_parts = Vec::with_capacity(selected.len());
        for (number, part) in selected {
            digests.push(md5_raw(&part.body));
            object_parts.push(StoredObjectPart {
                number,
                size: part.body.len(),
                checksums: part.checksums,
            });
            bodies.push(part.body);
        }
        Ok::<_, S3Error>((StoredBody::from_parts(&bodies)?, digests, object_parts))
    })
    .await
    .map_err(|_| S3Error::InternalError)??;
    let mut guard = b.write().await;
    let current = guard
        .uploads
        .get(upload_id)
        .filter(|current| current.key == key)
        .ok_or(S3Error::NoSuchUpload)?;
    if current.parts_revision != upload.parts_revision {
        return Err(S3Error::InvalidPart);
    }
    if let Some(current) = guard.objects.get(key) {
        ensure_not_protected(current, bypass_governance(headers))?;
    }
    let now = OffsetDateTime::now_utc();
    let object = StoredObject {
        body,
        etag: multipart_etag(&digests),
        checksums: BTreeMap::new(),
        content_type: upload.content_type,
        last_modified: now,
        metadata: upload.metadata,
        storage_class: upload.storage_class,
        tags: upload.tags,
        retention: upload.retention,
        legal_hold: upload.legal_hold,
        encryption: upload.encryption,
        parts: object_parts,
    };
    let version_id = persist_object(ctx, &mut guard, key, object.clone());
    guard.uploads.remove(upload_id);
    let event = (!guard.notification_configuration.is_empty()).then(|| ObjectEvent {
        bucket: bucket_name.to_string(),
        key: key.to_string(),
        event_type: EventType::ObjectCreatedCompleteMultipartUpload,
        reason: "CompleteMultipartUpload",
        time: now,
        size: Some(object.size()),
        etag: Some(object.etag.clone()),
        version_id: version_id.clone(),
        sequencer: sequencer(now),
        configuration: guard.notification_configuration.clone(),
    });
    drop(guard);
    let result = format!(
        "{DECL}<CompleteMultipartUploadResult>{}{}<ETag>{}</ETag></CompleteMultipartUploadResult>",
        text_el("Bucket", bucket_name),
        text_el("Key", key),
        escape(&object.etag),
    );
    let mut response = with_sse_headers(
        Response::builder()
            .status(200)
            .header("content-type", "application/xml")
            .header("x-amz-request-id", ctx.request_id),
        &object.encryption,
    );
    if let Some(version_id) = version_id {
        response = response.header("x-amz-version-id", version_id);
    }
    Ok(MutationResult {
        response: response
            .body(Body::from(result))
            .expect("complete multipart response is valid"),
        events: event.into_iter().collect(),
    })
}

pub async fn abort_multipart_upload(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    upload_id: &str,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let mut guard = b.write().await;
    if !guard
        .uploads
        .get(upload_id)
        .is_some_and(|upload| upload.key == key)
    {
        return Err(S3Error::NoSuchUpload);
    }
    guard.uploads.remove(upload_id);
    Ok(status_only(204, ctx.request_id))
}

pub async fn list_parts(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    key: &str,
    upload_id: &str,
    q: &QueryParams,
) -> Result<Response, S3Error> {
    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let upload = guard
        .uploads
        .get(upload_id)
        .filter(|upload| upload.key == key)
        .ok_or(S3Error::NoSuchUpload)?;
    let marker = q
        .get("part-number-marker")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    let max_parts = q
        .get("max-parts")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1000);
    let remaining = upload
        .parts
        .range((
            std::ops::Bound::Excluded(marker),
            std::ops::Bound::Unbounded,
        ))
        .collect::<Vec<_>>();
    let shown = remaining
        .iter()
        .take(max_parts)
        .copied()
        .collect::<Vec<_>>();
    let truncated = remaining.len() > shown.len();
    let next_marker = shown.last().map_or(marker, |(number, _)| **number);
    let mut body = format!(
        "{DECL}<ListPartsResult>{}{}<UploadId>{}</UploadId><PartNumberMarker>{marker}</PartNumberMarker><NextPartNumberMarker>{next_marker}</NextPartNumberMarker><MaxParts>{max_parts}</MaxParts><IsTruncated>{truncated}</IsTruncated>",
        text_el("Bucket", bucket_name),
        text_el("Key", key),
        escape(upload_id),
    );
    for (number, part) in shown {
        body.push_str(&format!(
            "<Part><PartNumber>{number}</PartNumber><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size>{}</Part>",
            iso8601(part.last_modified),
            escape(&part.etag),
            part.body.len(),
            checksum_elements(&part.checksums),
        ));
    }
    body.push_str("</ListPartsResult>");
    Ok(xml_ok(body, ctx.request_id))
}

pub async fn list_multipart_uploads(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    q: &QueryParams,
) -> Result<Response, S3Error> {
    enum Item<'a> {
        Upload(&'a MultipartUpload),
        Common {
            prefix: String,
            cursor_key: &'a str,
            cursor_id: &'a str,
        },
    }

    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let prefix = q.get("prefix").unwrap_or("");
    let delimiter = q.get("delimiter");
    let key_marker = q.get("key-marker");
    let upload_marker = q.get("upload-id-marker");
    let max_uploads = q
        .get("max-uploads")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1000);
    let mut uploads = guard
        .uploads
        .values()
        .filter(|upload| upload.key.starts_with(prefix))
        .filter(|upload| match key_marker {
            None => true,
            Some(marker) => {
                upload.key.as_str() > marker
                    || (upload.key == marker
                        && upload_marker.is_some_and(|id| upload.id.as_str() > id))
            }
        })
        .collect::<Vec<_>>();
    uploads.sort_by(|left, right| (&left.key, &left.id).cmp(&(&right.key, &right.id)));

    let mut items = Vec::new();
    for upload in uploads {
        let common = delimiter.and_then(|delimiter| {
            let rest = &upload.key[prefix.len()..];
            rest.find(delimiter)
                .map(|index| format!("{prefix}{}", &rest[..index + delimiter.len()]))
        });
        if let Some(common) = common {
            if let Some(Item::Common {
                prefix,
                cursor_key,
                cursor_id,
            }) = items.last_mut()
            {
                if *prefix == common {
                    *cursor_key = &upload.key;
                    *cursor_id = &upload.id;
                    continue;
                }
            }
            items.push(Item::Common {
                prefix: common,
                cursor_key: &upload.key,
                cursor_id: &upload.id,
            });
        } else {
            items.push(Item::Upload(upload));
        }
    }
    let truncated = items.len() > max_uploads;
    let shown = items.iter().take(max_uploads).collect::<Vec<_>>();
    let mut body = format!(
        "{DECL}<ListMultipartUploadsResult>{}<KeyMarker>{}</KeyMarker><UploadIdMarker>{}</UploadIdMarker><MaxUploads>{max_uploads}</MaxUploads><IsTruncated>{truncated}</IsTruncated>",
        text_el("Bucket", bucket_name),
        escape(key_marker.unwrap_or("")),
        escape(upload_marker.unwrap_or("")),
    );
    if truncated {
        if let Some(item) = shown.last() {
            let (key, id) = match item {
                Item::Upload(upload) => (upload.key.as_str(), upload.id.as_str()),
                Item::Common {
                    cursor_key,
                    cursor_id,
                    ..
                } => (*cursor_key, *cursor_id),
            };
            body.push_str(&text_el("NextKeyMarker", key));
            body.push_str(&text_el("NextUploadIdMarker", id));
        }
    }
    for item in shown {
        match item {
            Item::Upload(upload) => body.push_str(&format!(
                "<Upload>{}<UploadId>{}</UploadId><Initiated>{}</Initiated><StorageClass>{}</StorageClass></Upload>",
                text_el("Key", &upload.key),
                escape(&upload.id),
                iso8601(upload.initiated),
                escape(&upload.storage_class),
            )),
            Item::Common { prefix, .. } => body.push_str(&format!(
                "<CommonPrefixes>{}</CommonPrefixes>",
                text_el("Prefix", prefix)
            )),
        }
    }
    body.push_str("</ListMultipartUploadsResult>");
    Ok(xml_ok(body, ctx.request_id))
}

// ============================ versions =========================================

pub async fn list_object_versions(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    q: &QueryParams,
) -> Result<Response, S3Error> {
    enum Item<'a> {
        Version {
            key: &'a str,
            is_latest: bool,
            version: &'a StoredVersion,
        },
        Common {
            prefix: String,
            cursor_key: &'a str,
            cursor_version: &'a str,
        },
    }

    let b = bucket(ctx, bucket_name).await?;
    let guard = b.read().await;
    let prefix = q.get("prefix").unwrap_or("");
    let delimiter = q.get("delimiter");
    let key_marker = q.get("key-marker").unwrap_or("");
    let version_marker = q.get("version-id-marker");
    let max_keys = q
        .get("max-keys")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1000);
    let mut items = Vec::new();
    for (key, chain) in &guard.versions {
        if !key.starts_with(prefix) || key.as_str() < key_marker {
            continue;
        }
        let start = if key == key_marker {
            version_marker
                .and_then(|marker| chain.iter().position(|version| version.id == marker))
                .map_or(
                    if key_marker.is_empty() {
                        0
                    } else {
                        chain.len()
                    },
                    |index| index + 1,
                )
        } else {
            0
        };
        if start >= chain.len() {
            continue;
        }
        let common = delimiter.and_then(|delimiter| {
            let rest = &key[prefix.len()..];
            rest.find(delimiter)
                .map(|index| format!("{prefix}{}", &rest[..index + delimiter.len()]))
        });
        if let Some(common) = common {
            let cursor_version = chain.last().expect("non-empty version chain");
            if let Some(Item::Common {
                prefix,
                cursor_key,
                cursor_version: listed_version,
            }) = items.last_mut()
            {
                if prefix.as_str() == common {
                    *cursor_key = key;
                    *listed_version = &cursor_version.id;
                    continue;
                }
            }
            items.push(Item::Common {
                prefix: common,
                cursor_key: key,
                cursor_version: &cursor_version.id,
            });
            continue;
        }
        for (index, version) in chain.iter().enumerate().skip(start) {
            items.push(Item::Version {
                key,
                is_latest: index == 0,
                version,
            });
        }
    }
    let truncated = items.len() > max_keys;
    let shown = items.iter().take(max_keys).collect::<Vec<_>>();
    let mut body = format!(
        "{DECL}<ListVersionsResult>{}<Prefix>{}</Prefix><KeyMarker>{}</KeyMarker><VersionIdMarker>{}</VersionIdMarker><MaxKeys>{max_keys}</MaxKeys><IsTruncated>{truncated}</IsTruncated>",
        text_el("Name", bucket_name),
        escape(prefix),
        escape(key_marker),
        escape(version_marker.unwrap_or("")),
    );
    if truncated {
        if let Some(item) = shown.last() {
            let (key, version_id) = match item {
                Item::Version { key, version, .. } => (*key, version.id.as_str()),
                Item::Common {
                    cursor_key,
                    cursor_version,
                    ..
                } => (*cursor_key, *cursor_version),
            };
            body.push_str(&text_el("NextKeyMarker", key));
            body.push_str(&text_el("NextVersionIdMarker", version_id));
        }
    }
    for item in shown {
        match item {
            Item::Common { prefix, .. } => body.push_str(&format!(
                "<CommonPrefixes>{}</CommonPrefixes>",
                text_el("Prefix", prefix)
            )),
            Item::Version {
                key,
                is_latest,
                version,
            } => {
                let common = format!(
                    "{}<VersionId>{}</VersionId><IsLatest>{is_latest}</IsLatest><LastModified>{}</LastModified><Owner><ID>{}</ID><DisplayName>locallycloud</DisplayName></Owner>",
                    text_el("Key", key),
                    escape(&version.id),
                    iso8601(version.last_modified),
                    escape(ctx.account),
                );
                match &version.value {
                    VersionValue::Object(object) => body.push_str(&format!(
                        "<Version>{common}<ETag>{}</ETag><Size>{}</Size><StorageClass>{}</StorageClass></Version>",
                        escape(&object.etag),
                        object.size(),
                        escape(&object.storage_class),
                    )),
                    VersionValue::DeleteMarker => {
                        body.push_str(&format!("<DeleteMarker>{common}</DeleteMarker>"));
                    }
                }
            }
        }
    }
    body.push_str("</ListVersionsResult>");
    Ok(xml_ok(body, ctx.request_id))
}

// ============================ batch delete =====================================

pub async fn delete_objects(
    ctx: &Ctx<'_>,
    bucket_name: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<MutationResult, S3Error> {
    let (objects, quiet) = parse_delete_request(body)?;
    if objects.len() > 1000 {
        return Err(S3Error::MalformedXML);
    }
    let b = bucket(ctx, bucket_name).await?;
    let mut guard = b.write().await;
    for (key, version_id) in &objects {
        let object = version_id.as_ref().map_or_else(
            || guard.objects.get(key),
            |version_id| {
                guard.versions.get(key).and_then(|chain| {
                    chain
                        .iter()
                        .find(|version| &version.id == version_id)
                        .and_then(|version| match &version.value {
                            VersionValue::Object(object) => Some(object.as_ref()),
                            VersionValue::DeleteMarker => None,
                        })
                })
            },
        );
        if let Some(object) = object {
            ensure_not_protected(object, bypass_governance(headers))?;
        }
    }

    let configuration = guard.notification_configuration.clone();
    let mut deleted_xml = String::new();
    let mut events = Vec::new();
    for (key, requested_version) in &objects {
        let now = OffsetDateTime::now_utc();
        let version_id = if let Some(version_id) = requested_version {
            let chain = guard.versions.get_mut(key);
            let removed = chain.and_then(|chain| {
                chain
                    .iter()
                    .position(|version| &version.id == version_id)
                    .map(|position| chain.remove(position))
            });
            if removed.is_some() {
                let latest = guard
                    .versions
                    .get(key)
                    .and_then(|chain| chain.first())
                    .cloned();
                match latest.map(|version| version.value) {
                    Some(VersionValue::Object(object)) => {
                        guard.objects.insert(key.clone(), *object);
                    }
                    _ => {
                        guard.objects.remove(key);
                    }
                }
                if guard.versions.get(key).is_some_and(Vec::is_empty) {
                    guard.versions.remove(key);
                }
            }
            Some(version_id.clone())
        } else {
            persist_delete_marker(ctx, &mut guard, key, now)
        };
        if !configuration.is_empty() {
            events.push(ObjectEvent {
                bucket: bucket_name.to_string(),
                key: key.clone(),
                event_type: if requested_version.is_none() && version_id.is_some() {
                    EventType::ObjectRemovedDeleteMarkerCreated
                } else {
                    EventType::ObjectRemovedDelete
                },
                reason: "DeleteObject",
                time: now,
                size: None,
                etag: None,
                version_id: version_id.clone(),
                sequencer: sequencer(now),
                configuration: configuration.clone(),
            });
        }
        if !quiet {
            deleted_xml.push_str(&format!("<Deleted>{}", text_el("Key", key)));
            if let Some(version_id) = version_id {
                deleted_xml.push_str(&text_el("VersionId", &version_id));
            }
            deleted_xml.push_str("</Deleted>");
        }
    }
    drop(guard);
    let body = format!("{DECL}<DeleteResult>{deleted_xml}</DeleteResult>");
    Ok(MutationResult {
        response: xml_ok(body, ctx.request_id),
        events,
    })
}

pub(crate) type DeleteTarget = (String, Option<String>);

/// Parse a `<Delete>` request body into object/version pairs and the `Quiet` flag.
pub(crate) fn parse_delete_request(body: &[u8]) -> Result<(Vec<DeleteTarget>, bool), S3Error> {
    let root = parse_xml(body)?;
    if root.name != "Delete" {
        return Err(S3Error::MalformedXML);
    }
    let mut objects = Vec::new();
    let mut quiet = false;
    for child in &root.children {
        match child.name.as_str() {
            "Object" => {
                let key = child_text(child, "Key")
                    .ok_or(S3Error::MalformedXML)?
                    .to_string();
                let version = child_text(child, "VersionId").map(str::to_string);
                objects.push((key, version));
            }
            "Quiet" if child.children.is_empty() => {
                quiet = child.text.eq_ignore_ascii_case("true");
            }
            _ => return Err(S3Error::MalformedXML),
        }
    }
    Ok((objects, quiet))
}

#[cfg(test)]
mod multipart_checksum_tests {
    use super::*;

    #[test]
    fn completion_accepts_part_checksum_and_rejects_duplicate_field() {
        let body = b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>&quot;abc&quot;</ETag><ChecksumCRC32>AAAAAA==</ChecksumCRC32></Part></CompleteMultipartUpload>";
        let parts = parse_complete_parts(body).unwrap();
        assert_eq!(parts[0].0, 1);
        assert_eq!(parts[0].1, "\"abc\"");
        assert_eq!(parts[0].2[&ChecksumAlgorithm::Crc32], "AAAAAA==");
        let duplicate = String::from_utf8(body.to_vec())
            .unwrap()
            .replace("</Part>", "<ChecksumCRC32>AAAAAA==</ChecksumCRC32></Part>");
        assert!(matches!(
            parse_complete_parts(duplicate.as_bytes()),
            Err(S3Error::MalformedXML)
        ));
    }
}
