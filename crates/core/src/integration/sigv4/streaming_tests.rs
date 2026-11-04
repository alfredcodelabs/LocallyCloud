use super::*;

const UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
const DATE: &str = "20261103T100000Z";

fn signed_stream(service: &str, marker: &str, omit: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("host", "localhost:4566"),
        ("x-amz-date", DATE),
        ("content-encoding", "aws-chunked"),
        ("x-amz-content-sha256", marker),
        ("x-amz-decoded-content-length", "9"),
        ("x-amz-trailer", "x-amz-checksum-crc32"),
        ("x-amz-security-token", "temporary-token"),
    ] {
        headers.insert(
            http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    if marker == "UNSIGNED-PAYLOAD" {
        for name in [
            "content-encoding",
            "x-amz-decoded-content-length",
            "x-amz-trailer",
        ] {
            headers.remove(name);
        }
        headers.insert("x-amz-checksum-crc32", "adaoqw==".parse().unwrap());
    }
    let mut names: Vec<_> = headers
        .keys()
        .map(|name| name.as_str())
        .filter(|name| Some(*name) != omit)
        .collect();
    names.sort_unstable();
    let signed = names.join(";");
    let canonical_headers = names
        .iter()
        .map(|name| format!("{name}:{}\n", header(&headers, name).unwrap()))
        .collect::<String>();
    let canonical = format!(
        "PUT\n/bucket/object\npartNumber=1&uploadId=abc\n{canonical_headers}\n{signed}\n{marker}"
    );
    let scope = format!("20261103/us-east-1/{service}/aws4_request");
    let message = format!(
        "AWS4-HMAC-SHA256\n{DATE}\n{scope}\n{:x}",
        Sha256::digest(canonical)
    );
    let key = hmac(b"AWS4stream-secret", b"20261103").unwrap();
    let key = hmac(&key, b"us-east-1").unwrap();
    let key = hmac(&key, service.as_bytes()).unwrap();
    let key = hmac(&key, b"aws4_request").unwrap();
    let signature = hmac(&key, message.as_bytes())
        .unwrap()
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect::<String>();
    headers.insert("authorization", format!("AWS4-HMAC-SHA256 Credential=STREAMKEY/{scope}, SignedHeaders={signed}, Signature={signature}").parse().unwrap());
    headers
}

fn credentials(key: &str) -> Option<SigningCredentials> {
    (key == "STREAMKEY").then(|| SigningCredentials {
        secret_access_key: "stream-secret".into(),
        session_token: Some("temporary-token".into()),
    })
}

fn valid(headers: &HeaderMap, region: &str, service: &str) -> bool {
    let date_format =
        format_description::parse_borrowed::<3>("[year][month][day]T[hour][minute][second]Z")
            .unwrap();
    verify_at(
        &Method::PUT,
        &"/bucket/object?partNumber=1&uploadId=abc".parse().unwrap(),
        headers,
        b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nx-amz-checksum-crc32:adaoqw==\r\n\r\n",
        region,
        service,
        credentials,
        time::PrimitiveDateTime::parse(DATE, &date_format)
            .unwrap()
            .assume_utc(),
    )
}

#[test]
fn unsigned_stream_marker_authenticates_the_request_and_signed_framing() {
    for omit in [None, Some("x-amz-content-sha256")] {
        let headers = signed_stream("s3", UNSIGNED_TRAILER, omit);
        assert!(valid(&headers, "us-east-1", "s3"));
        assert!(!valid(&headers, "us-east-2", "s3"));
        let mut wrong_mac = headers.clone();
        let mut authorization = header(&headers, "authorization").unwrap().to_owned();
        let last = authorization.pop().unwrap();
        authorization.push(if last == '0' { '1' } else { '0' });
        wrong_mac.insert("authorization", authorization.parse().unwrap());
        assert!(!valid(&wrong_mac, "us-east-1", "s3"));
        let mut duplicate_marker = headers.clone();
        duplicate_marker.append("x-amz-content-sha256", UNSIGNED_TRAILER.parse().unwrap());
        assert!(!valid(&duplicate_marker, "us-east-1", "s3"));
        for (name, changed) in [
            ("host", "other-host"),
            ("x-amz-date", "20261103T100001Z"),
            ("content-encoding", "identity"),
            ("x-amz-decoded-content-length", "8"),
            ("x-amz-trailer", "x-amz-checksum-sha256"),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
            ("x-amz-security-token", "other-token"),
            ("authorization", "AWS4-HMAC-SHA256 Credential=forged"),
        ] {
            let mut tampered = headers.clone();
            tampered.insert(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                changed.parse().unwrap(),
            );
            assert!(!valid(&tampered, "us-east-1", "s3"), "{name}");
        }
        for name in [
            "content-encoding",
            "x-amz-decoded-content-length",
            "x-amz-trailer",
            "x-amz-security-token",
        ] {
            let mut missing = headers.clone();
            missing.remove(name);
            assert!(!valid(&missing, "us-east-1", "s3"), "{name}");
        }
    }
    for omit in [
        "content-encoding",
        "x-amz-decoded-content-length",
        "x-amz-trailer",
        "x-amz-security-token",
    ] {
        assert!(!valid(
            &signed_stream("s3", UNSIGNED_TRAILER, Some(omit)),
            "us-east-1",
            "s3"
        ));
    }
}

#[test]
fn unsigned_stream_mode_is_s3_only_and_signed_chunk_chains_are_not_accepted() {
    for service in ["lambda", "dynamodb", "sts"] {
        for marker in [UNSIGNED_TRAILER, "UNSIGNED-PAYLOAD"] {
            assert!(!valid(
                &signed_stream(service, marker, None),
                "us-east-1",
                service
            ));
        }
    }
    for marker in [
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
    ] {
        assert!(!valid(
            &signed_stream("s3", marker, None),
            "us-east-1",
            "s3"
        ));
    }
}

#[test]
fn ordinary_unsigned_payload_authenticates_its_marker_and_checksum_header() {
    for omit in [None, Some("x-amz-content-sha256")] {
        let headers = signed_stream("s3", "UNSIGNED-PAYLOAD", omit);
        assert!(valid(&headers, "us-east-1", "s3"));
        let mut changed = headers.clone();
        changed.insert("x-amz-checksum-crc32", "AAAAAA==".parse().unwrap());
        assert!(!valid(&changed, "us-east-1", "s3"));
        changed = headers.clone();
        changed.insert("x-amz-content-sha256", UNSIGNED_TRAILER.parse().unwrap());
        assert!(!valid(&changed, "us-east-1", "s3"));
    }
}
