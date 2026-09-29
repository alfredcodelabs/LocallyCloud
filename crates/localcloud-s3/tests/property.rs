use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use axum::body::to_bytes;
use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_s3::addr;
use localcloud_s3::integrity::{self, ChecksumAlgorithm};
use localcloud_s3::notifications::{self, EventType, ObjectEvent};
use localcloud_s3::service::S3Handler;
use localcloud_s3::store::{AccountStore, VersioningState};
use md5::{Digest as _, Md5};
use proptest::prelude::*;
use quick_xml::events::Event;
use quick_xml::Reader;
use sha1::Sha1;
use sha2::Sha256;
use time::OffsetDateTime;
use tokio::runtime::Runtime;

struct WireResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().expect("tokio runtime"))
}

async fn wire(
    handler: &S3Handler,
    method: Method,
    uri: &str,
    body: &[u8],
    headers: &[(&str, &str)],
    account: &str,
    host: &str,
) -> WireResponse {
    let mut request_headers = HeaderMap::new();
    request_headers.insert("host", HeaderValue::from_str(host).expect("valid host"));
    for (name, value) in headers {
        request_headers.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
            HeaderValue::from_str(value).expect("valid header value"),
        );
    }
    let response = handler
        .handle(ServiceRequest {
            method,
            uri: uri.parse().expect("valid test URI"),
            headers: request_headers,
            body: Bytes::copy_from_slice(body),
            region: "us-east-1".into(),
            account_id: account.into(),
            request_id: "property-request".into(),
        })
        .await;
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    WireResponse {
        status,
        headers,
        body,
    }
}

fn path_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn event_key_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn xml_values(document: &[u8], wanted: &str) -> Vec<String> {
    let mut reader = Reader::from_reader(document);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut current = None::<String>;
    let mut values = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) if element.local_name().as_ref() == wanted => {
                current = Some(String::new());
            }
            Ok(Event::Text(text)) => {
                if let Some(value) = &mut current {
                    value.push_str(
                        &quick_xml::escape::unescape(text.as_ref()).expect("valid XML text"),
                    );
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                if let Some(value) = &mut current {
                    let encoded = format!("&{};", reference.as_ref());
                    value.push_str(
                        &quick_xml::escape::unescape(&encoded).expect("valid XML reference"),
                    );
                }
            }
            Ok(Event::End(element)) if element.local_name().as_ref() == wanted => {
                if let Some(value) = current.take() {
                    values.push(value);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => panic!("invalid XML response: {error}"),
        }
        buffer.clear();
    }
    values
}

fn xml_value(document: &[u8], wanted: &str) -> String {
    xml_values(document, wanted)
        .into_iter()
        .next()
        .unwrap_or_default()
}

fn xml_start_count(document: &[u8], wanted: &str) -> usize {
    let mut reader = Reader::from_reader(document);
    let mut buffer = Vec::new();
    let mut count = 0;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) if element.local_name().as_ref() == wanted => {
                count += 1;
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => panic!("invalid XML response: {error}"),
        }
        buffer.clear();
    }
    count
}

fn md5_hex(value: &[u8]) -> String {
    Md5::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn notification_configuration(
    prefix: &str,
    suffix: &str,
) -> notifications::NotificationConfiguration {
    let xml = format!(
        "<NotificationConfiguration><LambdaFunctionConfiguration><Id>property</Id><LambdaFunctionArn>arn:aws:lambda:us-east-1:000000000000:function:property</LambdaFunctionArn><Event>s3:ObjectCreated:Put</Event><Filter><S3Key><FilterRule><Name>prefix</Name><Value>{prefix}</Value></FilterRule><FilterRule><Name>suffix</Name><Value>{suffix}</Value></FilterRule></S3Key></Filter></LambdaFunctionConfiguration></NotificationConfiguration>"
    );
    notifications::parse_configuration(xml.as_bytes()).expect("valid notification config")
}

fn object_event(
    key: String,
    configuration: notifications::NotificationConfiguration,
) -> ObjectEvent {
    ObjectEvent {
        bucket: "property-bucket".into(),
        key,
        event_type: EventType::ObjectCreatedPut,
        reason: "PutObject",
        time: OffsetDateTime::UNIX_EPOCH,
        size: Some(1),
        etag: Some("\"etag\"".into()),
        version_id: None,
        sequencer: "1".into(),
        configuration,
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut normalized = [0_u8; 64];
    if key.len() > 64 {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..64 {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let inner = Sha256::new()
        .chain_update(inner_pad)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(outer_pad)
        .chain_update(inner)
        .finalize()
        .into()
}

fn signing_key(date: &str) -> [u8; 32] {
    let date_key = hmac_sha256(b"AWS4test", date.as_bytes());
    let region_key = hmac_sha256(&date_key, b"us-east-1");
    let service_key = hmac_sha256(&region_key, b"s3");
    hmac_sha256(&service_key, b"aws4_request")
}

fn signed_request(method: Method, path: &str, expires: u16) -> ServiceRequest {
    let now = OffsetDateTime::now_utc();
    let date = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let short = &date[..8];
    let credential = format!("test%2F{short}%2Fus-east-1%2Fs3%2Faws4_request");
    let query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={credential}&X-Amz-Date={date}&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host"
    );
    let canonical = format!(
        "{}\n{}\n{}\nhost:localhost:4599\n\nhost\nUNSIGNED-PAYLOAD",
        method.as_str(),
        path,
        query
    );
    let scope = format!("{short}/us-east-1/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let signature = hmac_sha256(&signing_key(short), string_to_sign.as_bytes());
    let signature = signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("localhost:4599"));
    ServiceRequest {
        method,
        uri: format!("{path}?{query}&X-Amz-Signature={signature}")
            .parse()
            .expect("valid signed URI"),
        headers,
        body: Bytes::new(),
        region: "us-east-1".into(),
        account_id: "000000000000".into(),
        request_id: "presign-property".into(),
    }
}

fn sha256_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::with_cases(100)
    })]

    // Feature: localcloud-s3, Property 1: Addressing Equivalence
    #[test]
    fn addressing_equivalence(key in "[a-z0-9]{1,8}", data in prop::collection::vec(any::<u8>(), 0..24)) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            let encoded = path_encode(&key);
            prop_assert_eq!(
                addr::resolve(Some("bucket.localhost:4566"), &format!("/{encoded}")),
                addr::resolve(Some("localhost:4566"), &format!("/bucket/{encoded}"))
            );
            prop_assert_eq!(wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost:4566").await.status, StatusCode::OK);
            prop_assert_eq!(wire(&handler, Method::PUT, &format!("/bucket/{encoded}"), &data, &[], "000000000000", "localhost:4566").await.status, StatusCode::OK);
            let virtual_get = wire(&handler, Method::GET, &format!("/{encoded}"), b"", &[], "000000000000", "bucket.localhost:4566").await;
            prop_assert_eq!(virtual_get.status, StatusCode::OK);
            prop_assert_eq!(virtual_get.body.as_ref(), data.as_slice());
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 2: Key Opacity (No Path Traversal)
    #[test]
    fn key_opacity(left in "[a-z]{1,3}", right in "[a-z]{1,3}", data in prop::collection::vec(any::<u8>(), 0..20)) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            let key = format!("{left}/../{right}/./leaf");
            let uri = format!("/bucket/{}", path_encode(&key));
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            prop_assert_eq!(wire(&handler, Method::PUT, &uri, &data, &[], "000000000000", "localhost").await.status, StatusCode::OK);
            let get = wire(&handler, Method::GET, &uri, b"", &[], "000000000000", "localhost").await;
            prop_assert_eq!(get.body.as_ref(), data.as_slice());
            let list = wire(&handler, Method::GET, "/bucket?list-type=2", b"", &[], "000000000000", "localhost").await;
            prop_assert_eq!(xml_values(&list.body, "Key"), vec![key]);
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 3: Single-Part ETag
    #[test]
    fn single_part_etag(data in prop::collection::vec(any::<u8>(), 0..32)) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let put = wire(&handler, Method::PUT, "/bucket/key", &data, &[], "000000000000", "localhost").await;
            let actual = put.headers.get("etag").expect("ETag").to_str().expect("text ETag");
            prop_assert_eq!(actual, format!("\"{}\"", md5_hex(&data)));
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 4: Multipart ETag
    #[test]
    fn multipart_etag(parts in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..17), 1..5)) {
        runtime().block_on(async {
            let raw = parts.iter().map(|part| Md5::digest(part).into()).collect::<Vec<[u8; 16]>>();
            let concatenated = raw.iter().flatten().copied().collect::<Vec<_>>();
            let expected = format!("\"{}-{}\"", md5_hex(&concatenated), parts.len());
            prop_assert_eq!(integrity::multipart_etag(&raw), expected);

            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let initiated = wire(&handler, Method::POST, "/bucket/key?uploads", b"", &[], "000000000000", "localhost").await;
            let upload_id = xml_value(&initiated.body, "UploadId");
            let uploaded = wire(&handler, Method::PUT, &format!("/bucket/key?uploadId={upload_id}&partNumber=1"), &parts[0], &[], "000000000000", "localhost").await;
            let part_etag = uploaded.headers["etag"].to_str().expect("part ETag");
            let completion = format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{part_etag}</ETag></Part></CompleteMultipartUpload>");
            let complete = wire(&handler, Method::POST, &format!("/bucket/key?uploadId={upload_id}"), completion.as_bytes(), &[], "000000000000", "localhost").await;
            prop_assert_eq!(complete.status, StatusCode::OK);
            prop_assert_eq!(xml_value(&complete.body, "ETag"), integrity::multipart_etag(&raw[..1]));
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 5: Checksum Determinism
    #[test]
    fn checksum_determinism(data in prop::collection::vec(any::<u8>(), 0..32), algorithm_index in 0usize..5) {
        let algorithm = ChecksumAlgorithm::ALL[algorithm_index];
        let first = integrity::checksum_base64(algorithm, &data);
        let second = integrity::checksum_base64(algorithm, &data);
        prop_assert_eq!(&first, &second);
        prop_assert_eq!(integrity::validate_checksum(algorithm, &first, &data).expect("valid checksum"), first);
        let raw = base64::engine::general_purpose::STANDARD.decode(&second).expect("base64 checksum");
        let expected = match algorithm {
            ChecksumAlgorithm::Sha1 => Sha1::digest(&data).to_vec(),
            ChecksumAlgorithm::Sha256 => Sha256::digest(&data).to_vec(),
            ChecksumAlgorithm::Crc32 | ChecksumAlgorithm::Crc32c => { prop_assert_eq!(raw.len(), 4); raw.clone() }
            ChecksumAlgorithm::Crc64Nvme => { prop_assert_eq!(raw.len(), 8); raw.clone() }
        };
        prop_assert_eq!(raw, expected);
    }

    // Feature: localcloud-s3, Property 6: Range Correctness
    #[test]
    fn range_correctness(data in prop::collection::vec(any::<u8>(), 1..33), first in 0usize..32, span in 0usize..32) {
        runtime().block_on(async {
            let start = first % data.len();
            let end = start + span % (data.len() - start);
            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            wire(&handler, Method::PUT, "/bucket/key", &data, &[], "000000000000", "localhost").await;
            let range = format!("bytes={start}-{end}");
            let response = wire(&handler, Method::GET, "/bucket/key", b"", &[("range", &range)], "000000000000", "localhost").await;
            prop_assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
            prop_assert_eq!(response.body.as_ref(), &data[start..=end]);
            prop_assert_eq!(response.headers["content-length"].to_str().expect("length"), (end - start + 1).to_string());
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 7: Conditional-Read Precedence
    #[test]
    fn conditional_read_precedence(data in prop::collection::vec(any::<u8>(), 0..24), matches in any::<bool>()) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let put = wire(&handler, Method::PUT, "/bucket/key", &data, &[], "000000000000", "localhost").await;
            let etag = put.headers["etag"].to_str().expect("ETag").to_string();
            let candidate = if matches { etag.as_str() } else { "\"different\"" };
            let none_only = wire(&handler, Method::GET, "/bucket/key", b"", &[("if-none-match", candidate)], "000000000000", "localhost").await;
            let none_both = wire(&handler, Method::GET, "/bucket/key", b"", &[("if-none-match", candidate), ("if-modified-since", "Tue, 01 Jan 2999 00:00:00 GMT")], "000000000000", "localhost").await;
            prop_assert_eq!(none_both.status, none_only.status);
            let match_only = wire(&handler, Method::GET, "/bucket/key", b"", &[("if-match", candidate)], "000000000000", "localhost").await;
            let match_both = wire(&handler, Method::GET, "/bucket/key", b"", &[("if-match", candidate), ("if-unmodified-since", "Sat, 01 Jan 2000 00:00:00 GMT")], "000000000000", "localhost").await;
            prop_assert_eq!(match_both.status, match_only.status);
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 8: Conditional-Write Idempotency
    #[test]
    fn conditional_write_idempotency(key in "[a-z]{1,6}", data in prop::collection::vec(any::<u8>(), 0..24)) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            let uri = format!("/bucket/{key}");
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let first = wire(&handler, Method::PUT, &uri, &data, &[("if-none-match", "*")], "000000000000", "localhost").await;
            let second = wire(&handler, Method::PUT, &uri, &data, &[("if-none-match", "*")], "000000000000", "localhost").await;
            prop_assert_eq!(first.status, StatusCode::OK);
            prop_assert_eq!(second.status, StatusCode::PRECONDITION_FAILED);
            prop_assert_eq!(xml_value(&second.body, "Code"), "PreconditionFailed");
            let stored = wire(&handler, Method::GET, &uri, b"", &[], "000000000000", "localhost").await;
            prop_assert_eq!(stored.body.as_ref(), data.as_slice());
            prop_assert_eq!(&stored.headers["etag"], &first.headers["etag"]);
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 9: Batch-Delete Completeness
    #[test]
    fn batch_delete_completeness(count in 1usize..6) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let mut delete = String::from("<Delete>");
            for index in 0..count {
                let key = format!("key-{index}");
                wire(&handler, Method::PUT, &format!("/bucket/{key}"), b"x", &[], "000000000000", "localhost").await;
                delete.push_str(&format!("<Object><Key>{key}</Key></Object>"));
            }
            delete.push_str("<Quiet>false</Quiet></Delete>");
            let response = wire(&handler, Method::POST, "/bucket?delete", delete.as_bytes(), &[], "000000000000", "localhost").await;
            prop_assert_eq!(response.status, StatusCode::OK);
            prop_assert_eq!(xml_start_count(&response.body, "Deleted") + xml_start_count(&response.body, "Error"), count);
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 10: ListObjectsV2 Pagination Completeness
    #[test]
    fn list_objects_v2_pagination_completeness(count in 2usize..7, page_size in 1usize..4) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let expected = (0..count).map(|index| format!("p/key-{index}")).collect::<BTreeSet<_>>();
            for key in &expected {
                wire(&handler, Method::PUT, &format!("/bucket/{}", path_encode(key)), b"x", &[], "000000000000", "localhost").await;
            }
            let mut token: Option<String> = None;
            let mut actual = Vec::new();
            loop {
                let mut uri = format!("/bucket?list-type=2&prefix=p%2F&max-keys={page_size}");
                if let Some(value) = &token {
                    uri.push_str("&continuation-token=");
                    uri.push_str(&path_encode(value));
                }
                let page = wire(&handler, Method::GET, &uri, b"", &[], "000000000000", "localhost").await;
                actual.extend(xml_values(&page.body, "Key"));
                if xml_value(&page.body, "IsTruncated") != "true" {
                    break;
                }
                let next = xml_value(&page.body, "NextContinuationToken");
                prop_assert!(!next.is_empty());
                token = Some(next);
                prop_assert!(actual.len() <= count);
            }
            let unique = actual.iter().cloned().collect::<BTreeSet<_>>();
            prop_assert_eq!(actual.len(), unique.len());
            prop_assert_eq!(unique, expected);
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 11: ListObjects v1 Pagination Completeness
    #[test]
    fn list_objects_v1_pagination_completeness(count in 2usize..7, page_size in 1usize..4) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let expected = (0..count).map(|index| format!("key-{index}")).collect::<BTreeSet<_>>();
            for key in &expected {
                wire(&handler, Method::PUT, &format!("/bucket/{key}"), b"x", &[], "000000000000", "localhost").await;
            }
            let mut marker: Option<String> = None;
            let mut actual = Vec::new();
            loop {
                let mut uri = format!("/bucket?max-keys={page_size}");
                if let Some(value) = &marker {
                    uri.push_str("&marker=");
                    uri.push_str(&path_encode(value));
                }
                let page = wire(&handler, Method::GET, &uri, b"", &[], "000000000000", "localhost").await;
                let keys = xml_values(&page.body, "Key");
                actual.extend(keys.iter().cloned());
                if xml_value(&page.body, "IsTruncated") != "true" {
                    break;
                }
                marker = keys.last().cloned();
                prop_assert!(marker.is_some());
                prop_assert!(actual.len() <= count);
            }
            let unique = actual.iter().cloned().collect::<BTreeSet<_>>();
            prop_assert_eq!(actual.len(), unique.len());
            prop_assert_eq!(unique, expected);
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 12: Multipart-Listing Completeness
    #[test]
    fn multipart_listing_completeness(count in 2usize..7, page_size in 1usize..4) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let mut expected = BTreeSet::new();
            for index in 0..count {
                let key = format!("key-{index}");
                let created = wire(&handler, Method::POST, &format!("/bucket/{key}?uploads"), b"", &[], "000000000000", "localhost").await;
                expected.insert((key, xml_value(&created.body, "UploadId")));
            }
            let mut marker: Option<(String, String)> = None;
            let mut actual = Vec::new();
            loop {
                let mut uri = format!("/bucket?uploads&max-uploads={page_size}");
                if let Some((key, upload)) = &marker {
                    uri.push_str(&format!("&key-marker={}&upload-id-marker={}", path_encode(key), path_encode(upload)));
                }
                let page = wire(&handler, Method::GET, &uri, b"", &[], "000000000000", "localhost").await;
                let keys = xml_values(&page.body, "Key");
                let uploads = xml_values(&page.body, "UploadId");
                prop_assert_eq!(keys.len(), uploads.len());
                actual.extend(keys.into_iter().zip(uploads));
                if xml_value(&page.body, "IsTruncated") != "true" {
                    break;
                }
                marker = Some((xml_value(&page.body, "NextKeyMarker"), xml_value(&page.body, "NextUploadIdMarker")));
                prop_assert!(actual.len() <= count);
            }
            let unique = actual.iter().cloned().collect::<BTreeSet<_>>();
            prop_assert_eq!(actual.len(), unique.len());
            prop_assert_eq!(unique, expected);
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 13: Multipart Validate-Before-Mutate
    #[test]
    fn multipart_validate_before_mutate(data in prop::collection::vec(any::<u8>(), 0..24)) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let initiated = wire(&handler, Method::POST, "/bucket/key?uploads", b"", &[], "000000000000", "localhost").await;
            let upload_id = xml_value(&initiated.body, "UploadId");
            let part_uri = format!("/bucket/key?uploadId={upload_id}&partNumber=1");
            let uploaded = wire(&handler, Method::PUT, &part_uri, &data, &[], "000000000000", "localhost").await;
            let etag = uploaded.headers["etag"].to_str().expect("ETag").to_string();
            let list_uri = format!("/bucket/key?uploadId={upload_id}");
            let before = wire(&handler, Method::GET, &list_uri, b"", &[], "000000000000", "localhost").await.body;
            let invalid = b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"wrong\"</ETag></Part></CompleteMultipartUpload>";
            let rejected = wire(&handler, Method::POST, &list_uri, invalid, &[], "000000000000", "localhost").await;
            prop_assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
            prop_assert_eq!(xml_value(&rejected.body, "Code"), "InvalidPart");
            let after = wire(&handler, Method::GET, &list_uri, b"", &[], "000000000000", "localhost").await.body;
            prop_assert_eq!(after, before);
            let valid = format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>");
            prop_assert_eq!(wire(&handler, Method::POST, &list_uri, valid.as_bytes(), &[], "000000000000", "localhost").await.status, StatusCode::OK);
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 14: Version-History Completeness
    #[test]
    fn version_history_completeness(write_count in 1usize..5, delete_count in 1usize..4) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let versioning = b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
            wire(&handler, Method::PUT, "/bucket?versioning", versioning, &[], "000000000000", "localhost").await;
            let mut expected_ids = Vec::new();
            for index in 0..write_count {
                let response = wire(&handler, Method::PUT, "/bucket/key", &[index as u8], &[], "000000000000", "localhost").await;
                expected_ids.push(response.headers["x-amz-version-id"].to_str().expect("version id").to_string());
            }
            for _ in 0..delete_count {
                let response = wire(&handler, Method::DELETE, "/bucket/key", b"", &[], "000000000000", "localhost").await;
                expected_ids.push(response.headers["x-amz-version-id"].to_str().expect("marker id").to_string());
            }
            let versions = wire(&handler, Method::GET, "/bucket?versions&prefix=key", b"", &[], "000000000000", "localhost").await;
            let actual_ids = xml_values(&versions.body, "VersionId");
            prop_assert_eq!(actual_ids.len(), write_count + delete_count);
            for id in expected_ids {
                prop_assert_eq!(actual_ids.iter().filter(|actual| **actual == id).count(), 1);
            }
            prop_assert_eq!(xml_start_count(&versions.body, "Version"), write_count);
            prop_assert_eq!(xml_start_count(&versions.body, "DeleteMarker"), delete_count);
            prop_assert_eq!(xml_values(&versions.body, "IsLatest").iter().filter(|value| value.as_str() == "true").count(), 1);
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 15: Notification Filter Matching
    #[test]
    fn notification_filter_matching(key in "[a-z/]{0,10}", prefix in "[a-z]{0,4}", suffix in "[a-z]{0,4}") {
        let configuration = notification_configuration(&prefix, &suffix);
        let deliveries = notifications::delivery_requests(
            &object_event(key.clone(), configuration),
            "000000000000",
            "us-east-1",
            "request",
            "127.0.0.1",
        );
        let expected = key.starts_with(&prefix) && key.ends_with(&suffix);
        prop_assert_eq!(deliveries.len(), usize::from(expected));
    }

    // Feature: localcloud-s3, Property 16: Event-Key Encoding
    #[test]
    fn event_key_encoding(key in "[A-Za-z0-9 /+?#._~]{0,12}") {
        let configuration = notification_configuration("", "");
        let mut deliveries = notifications::delivery_requests(
            &object_event(key.clone(), configuration),
            "000000000000",
            "us-east-1",
            "request",
            "127.0.0.1",
        );
        prop_assert_eq!(deliveries.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&deliveries.remove(0).body).expect("notification JSON");
        let expected_key = event_key_encode(&key);
        prop_assert_eq!(body["Records"][0]["s3"]["object"]["key"].as_str(), Some(expected_key.as_str()));
    }

    // Feature: localcloud-s3, Property 17: Presign Round-Trip
    #[test]
    fn presign_round_trip(key in "[a-z0-9]{1,8}", put in any::<bool>(), expires in 30u16..300) {
        let method = if put { Method::PUT } else { Method::GET };
        let path = format!("/bucket/{key}");
        let valid = signed_request(method.clone(), &path, expires);
        prop_assert!(localcloud_s3::presign::is_presigned_url(&valid));
        prop_assert!(localcloud_s3::presign::validate_url(&valid).is_ok());
        let mut tampered = valid.clone();
        tampered.uri = format!("/bucket/{key}x?{}", valid.uri.query().expect("signed query"))
            .parse()
            .expect("tampered URI");
        let error = localcloud_s3::presign::validate_url(&tampered).expect_err("tamper must fail");
        prop_assert_eq!(error.http_status(), 403);
    }

    // Feature: localcloud-s3, Property 18: aws-chunked Decode Round-Trip
    #[test]
    fn aws_chunked_round_trip(data in prop::collection::vec(any::<u8>(), 0..32)) {
        runtime().block_on(async {
            let signature = "0".repeat(64);
            let checksum = integrity::checksum_base64(ChecksumAlgorithm::Crc32, &data);
            let mut encoded = Vec::new();
            if !data.is_empty() {
                encoded.extend_from_slice(format!("{:x};chunk-signature={signature}\r\n", data.len()).as_bytes());
                encoded.extend_from_slice(&data);
                encoded.extend_from_slice(b"\r\n");
            }
            encoded.extend_from_slice(format!("0;chunk-signature={signature}\r\nx-amz-checksum-crc32:{checksum}\r\n\r\n").as_bytes());
            let decoded = integrity::decode_aws_chunked(&encoded, data.len()).expect("valid aws-chunked body");
            prop_assert_eq!(decoded.body.as_ref(), data.as_slice());

            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let length = data.len().to_string();
            let put = wire(&handler, Method::PUT, "/bucket/key", &encoded, &[("content-encoding", "aws-chunked"), ("x-amz-decoded-content-length", &length)], "000000000000", "localhost").await;
            prop_assert_eq!(put.status, StatusCode::OK);
            let get = wire(&handler, Method::GET, "/bucket/key", b"", &[], "000000000000", "localhost").await;
            prop_assert_eq!(get.body.as_ref(), data.as_slice());
            prop_assert_eq!(get.headers["content-length"].to_str().expect("stored length"), length);
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 19: Content-Type Fidelity
    #[test]
    fn content_type_fidelity(data in prop::collection::vec(any::<u8>(), 0..20), supplied in any::<bool>(), subtype in "[a-z]{1,8}") {
        runtime().block_on(async {
            let handler = S3Handler::new();
            wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
            let content_type = format!("application/x-{subtype}");
            let headers = if supplied { vec![("content-type", content_type.as_str())] } else { Vec::new() };
            prop_assert_eq!(wire(&handler, Method::PUT, "/bucket/key", &data, &headers, "000000000000", "localhost").await.status, StatusCode::OK);
            let get = wire(&handler, Method::GET, "/bucket/key", b"", &[], "000000000000", "localhost").await;
            let expected = if supplied { content_type.as_str() } else { "binary/octet-stream" };
            prop_assert_eq!(get.headers["content-type"].to_str().expect("content type"), expected);
            prop_assert_eq!(get.body.as_ref(), data.as_slice());
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 20: Account Scoping and Write Confluence
    #[test]
    fn account_scoping_and_write_confluence(left in prop::collection::vec(any::<u8>(), 0..20), right in prop::collection::vec(any::<u8>(), 0..20)) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            let account_a = "111111111111";
            let account_b = "222222222222";
            prop_assert_eq!(wire(&handler, Method::PUT, "/same-bucket", b"", &[], account_a, "localhost").await.status, StatusCode::OK);
            prop_assert_eq!(wire(&handler, Method::PUT, "/same-bucket", b"", &[], account_b, "localhost").await.status, StatusCode::CONFLICT);
            prop_assert_eq!(wire(&handler, Method::PUT, "/other-bucket", b"", &[], account_b, "localhost").await.status, StatusCode::OK);
            wire(&handler, Method::PUT, "/same-bucket/key", &left, &[], account_a, "localhost").await;
            prop_assert_eq!(wire(&handler, Method::GET, "/same-bucket/key", b"", &[], account_b, "localhost").await.status, StatusCode::NOT_FOUND);
            wire(&handler, Method::PUT, "/other-bucket/key", &right, &[], account_b, "localhost").await;
            let stored_a = wire(&handler, Method::GET, "/same-bucket/key", b"", &[], account_a, "localhost").await;
            let stored_b = wire(&handler, Method::GET, "/other-bucket/key", b"", &[], account_b, "localhost").await;
            prop_assert_eq!(stored_a.body.as_ref(), left.as_slice());
            prop_assert_eq!(stored_b.body.as_ref(), right.as_slice());

            let configuration = notifications::parse_configuration(b"<NotificationConfiguration><EventBridgeConfiguration/></NotificationConfiguration>").expect("event config");
            let concurrent_store = AccountStore::new();
            concurrent_store.create(account_a, "bucket", "us-east-1", false).expect("create bucket");
            {
                let bucket = concurrent_store.get(account_a, "bucket").expect("bucket");
                let mut state = bucket.write().await;
                state.versioning = VersioningState::Enabled;
                state.notification_configuration = configuration.clone();
            }
            let concurrent_ctx = localcloud_s3::ops::Ctx { store: &concurrent_store, account: account_a, region: "us-east-1", request_id: "concurrent", dispatcher: None };
            let headers = HeaderMap::new();
            let (first, second) = tokio::join!(
                localcloud_s3::ops::put_object(&concurrent_ctx, "bucket", "a", &headers, Bytes::from(left.clone())),
                localcloud_s3::ops::put_object(&concurrent_ctx, "bucket", "b", &headers, Bytes::from(right.clone()))
            );
            let concurrent_results = vec![first.expect("first write"), second.expect("second write")];

            let sequential_store = AccountStore::new();
            sequential_store.create(account_a, "bucket", "us-east-1", false).expect("create sequential bucket");
            {
                let bucket = sequential_store.get(account_a, "bucket").expect("bucket");
                let mut state = bucket.write().await;
                state.versioning = VersioningState::Enabled;
                state.notification_configuration = configuration;
            }
            let sequential_ctx = localcloud_s3::ops::Ctx { store: &sequential_store, account: account_a, region: "us-east-1", request_id: "sequential", dispatcher: None };
            let sequential_results = vec![
                localcloud_s3::ops::put_object(&sequential_ctx, "bucket", "a", &headers, Bytes::from(left)).await.expect("first sequential write"),
                localcloud_s3::ops::put_object(&sequential_ctx, "bucket", "b", &headers, Bytes::from(right)).await.expect("second sequential write"),
            ];
            let concurrent_bucket = concurrent_store.get(account_a, "bucket").expect("bucket");
            let sequential_bucket = sequential_store.get(account_a, "bucket").expect("bucket");
            let concurrent_state = concurrent_bucket.read().await;
            let sequential_state = sequential_bucket.read().await;
            let state_projection = |state: &localcloud_s3::store::BucketState| {
                state.objects.iter().map(|(key, object)| {
                    (key.clone(), (object.body.read_all().expect("stored body is readable"), object.etag.clone(), state.versions[key].len()))
                }).collect::<BTreeMap<_, _>>()
            };
            prop_assert_eq!(state_projection(&concurrent_state), state_projection(&sequential_state));
            let event_projection = |results: Vec<localcloud_s3::ops::MutationResult>| {
                results.into_iter().flat_map(|result| result.events).map(|event| (event.key, event.event_type.event_name(), event.size, event.etag)).collect::<BTreeSet<_>>()
            };
            prop_assert_eq!(event_projection(concurrent_results), event_projection(sequential_results));
            Ok(())
        })?;
    }

    // Feature: localcloud-s3, Property 21: Error Deserialization
    #[test]
    fn error_deserialization(case in 0u8..6) {
        runtime().block_on(async {
            let handler = S3Handler::new();
            let (response, code, status, resource) = match case {
                0 => (wire(&handler, Method::GET, "/absent/key", b"", &[], "000000000000", "localhost").await, "NoSuchBucket", StatusCode::NOT_FOUND, "/absent/key"),
                1 => {
                    wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
                    (wire(&handler, Method::GET, "/bucket/absent", b"", &[], "000000000000", "localhost").await, "NoSuchKey", StatusCode::NOT_FOUND, "/bucket/absent")
                }
                2 => {
                    wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
                    wire(&handler, Method::PUT, "/bucket/key", b"x", &[], "000000000000", "localhost").await;
                    (wire(&handler, Method::GET, "/bucket/key", b"", &[("range", "bytes=9-10")], "000000000000", "localhost").await, "InvalidRange", StatusCode::RANGE_NOT_SATISFIABLE, "/bucket/key")
                }
                3 => (wire(&handler, Method::PUT, "/AB", b"", &[], "000000000000", "localhost").await, "InvalidBucketName", StatusCode::BAD_REQUEST, "/AB"),
                4 => {
                    wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
                    wire(&handler, Method::PUT, "/bucket/key", b"x", &[], "000000000000", "localhost").await;
                    (wire(&handler, Method::PUT, "/bucket/key", b"y", &[("if-none-match", "*")], "000000000000", "localhost").await, "PreconditionFailed", StatusCode::PRECONDITION_FAILED, "/bucket/key")
                }
                _ => {
                    wire(&handler, Method::PUT, "/bucket", b"", &[], "000000000000", "localhost").await;
                    (wire(&handler, Method::PUT, "/bucket?versioning", b"<broken", &[], "000000000000", "localhost").await, "MalformedXML", StatusCode::BAD_REQUEST, "/bucket")
                }
            };
            prop_assert_eq!(response.status, status);
            prop_assert_eq!(&response.headers["content-type"], "application/xml");
            prop_assert_eq!(xml_start_count(&response.body, "Error"), 1);
            prop_assert_eq!(xml_value(&response.body, "Code"), code);
            prop_assert_eq!(xml_value(&response.body, "Resource"), resource);
            prop_assert_eq!(xml_value(&response.body, "RequestId"), "property-request");
            prop_assert_eq!(&response.headers["x-amz-request-id"], "property-request");
            Ok(())
        })?;
    }
}
