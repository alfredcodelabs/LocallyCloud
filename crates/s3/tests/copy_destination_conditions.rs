use axum::body::to_bytes;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_s3::service::S3Handler;

async fn request(
    handler: &S3Handler,
    method: Method,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> Response<axum::body::Body> {
    let mut request_headers = HeaderMap::new();
    request_headers.insert("host", HeaderValue::from_static("localhost:4566"));
    for (name, value) in headers {
        request_headers.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    handler
        .handle(ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers: request_headers,
            body: Bytes::copy_from_slice(body.as_bytes()),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "copy-conditions".into(),
        })
        .await
}

async fn body(response: Response<axum::body::Body>) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

async fn setup() -> S3Handler {
    let handler = S3Handler::new();
    assert_eq!(
        request(&handler, Method::PUT, "/copy-bucket", "", &[])
            .await
            .status(),
        StatusCode::OK
    );
    for (key, value) in [("source", "source-data"), ("other", "other-data")] {
        assert_eq!(
            request(
                &handler,
                Method::PUT,
                &format!("/copy-bucket/{key}"),
                value,
                &[]
            )
            .await
            .status(),
            StatusCode::OK
        );
    }
    handler
}

async fn assert_precondition_failed(response: Response<axum::body::Body>) {
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert!(body(response)
        .await
        .contains("<Code>PreconditionFailed</Code>"));
}

#[tokio::test]
async fn copy_checks_destination_etag_independently_of_source_conditions() {
    let handler = setup().await;
    let source = request(&handler, Method::HEAD, "/copy-bucket/source", "", &[]).await;
    let source_etag = source.headers()["etag"].to_str().unwrap().to_owned();
    let destination = request(
        &handler,
        Method::PUT,
        "/copy-bucket/destination",
        "old",
        &[],
    )
    .await;
    let destination_etag = destination.headers()["etag"].to_str().unwrap().to_owned();

    for headers in [
        vec![
            ("x-amz-copy-source", "/copy-bucket/source"),
            ("x-amz-copy-source-if-match", source_etag.as_str()),
            ("if-match", source_etag.as_str()),
        ],
        vec![
            ("x-amz-copy-source", "/copy-bucket/source"),
            ("x-amz-copy-source-if-match", "\"wrong-source\""),
            ("if-match", destination_etag.as_str()),
        ],
        vec![
            ("x-amz-copy-source", "/copy-bucket/source"),
            ("if-none-match", "*"),
        ],
    ] {
        assert_precondition_failed(
            request(
                &handler,
                Method::PUT,
                "/copy-bucket/destination",
                "",
                &headers,
            )
            .await,
        )
        .await;
        let unchanged = request(&handler, Method::GET, "/copy-bucket/destination", "", &[]).await;
        assert_eq!(unchanged.headers()["etag"], destination_etag);
        assert_eq!(body(unchanged).await, "old");
    }

    let success = request(
        &handler,
        Method::PUT,
        "/copy-bucket/destination",
        "",
        &[
            ("x-amz-copy-source", "/copy-bucket/source"),
            ("x-amz-copy-source-if-match", &source_etag),
            (
                "x-amz-copy-source-if-unmodified-since",
                "Sat, 01 Jan 2000 00:00:00 GMT",
            ),
            ("if-match", &destination_etag),
        ],
    )
    .await;
    assert_eq!(success.status(), StatusCode::OK);
    assert!(body(success).await.contains("<CopyObjectResult>"));
    assert_eq!(
        body(request(&handler, Method::GET, "/copy-bucket/destination", "", &[]).await).await,
        "source-data"
    );
}

#[tokio::test]
async fn copy_conditional_create_treats_delete_marker_as_absent_and_preserves_versions() {
    let handler = setup().await;
    assert_eq!(
        request(
            &handler,
            Method::PUT,
            "/copy-bucket?versioning",
            "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            &[],
        )
        .await
        .status(),
        StatusCode::OK
    );
    let first = request(
        &handler,
        Method::PUT,
        "/copy-bucket/destination",
        "old",
        &[],
    )
    .await;
    let original_version = first.headers()["x-amz-version-id"]
        .to_str()
        .unwrap()
        .to_owned();
    request(
        &handler,
        Method::DELETE,
        "/copy-bucket/destination",
        "",
        &[],
    )
    .await;

    assert_precondition_failed(
        request(
            &handler,
            Method::PUT,
            "/copy-bucket/destination",
            "",
            &[
                ("x-amz-copy-source", "/copy-bucket/source"),
                ("if-match", "*"),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(
        request(&handler, Method::GET, "/copy-bucket/destination", "", &[])
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let created = request(
        &handler,
        Method::PUT,
        "/copy-bucket/destination",
        "",
        &[
            ("x-amz-copy-source", "/copy-bucket/source"),
            ("if-none-match", "*"),
        ],
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let created_version = created.headers()["x-amz-version-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_precondition_failed(
        request(
            &handler,
            Method::PUT,
            "/copy-bucket/destination",
            "",
            &[
                ("x-amz-copy-source", "/copy-bucket/other"),
                ("if-none-match", "*"),
            ],
        )
        .await,
    )
    .await;
    let current = request(&handler, Method::GET, "/copy-bucket/destination", "", &[]).await;
    assert_eq!(current.headers()["x-amz-version-id"], created_version);
    assert_eq!(body(current).await, "source-data");
    assert_eq!(
        body(
            request(
                &handler,
                Method::GET,
                &format!("/copy-bucket/destination?versionId={original_version}"),
                "",
                &[]
            )
            .await
        )
        .await,
        "old"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_conditional_copies_have_one_winner() {
    let handler = setup().await;
    for (key, condition, value) in [
        ("create", "if-none-match", "*"),
        ("replace", "if-match", ""),
    ] {
        let etag = if condition == "if-match" {
            request(&handler, Method::PUT, "/copy-bucket/replace", "old", &[])
                .await
                .headers()["etag"]
                .to_str()
                .unwrap()
                .to_owned()
        } else {
            value.to_owned()
        };
        let path = format!("/copy-bucket/{key}");
        let first_headers = [
            ("x-amz-copy-source", "/copy-bucket/source"),
            (condition, etag.as_str()),
        ];
        let second_headers = [
            ("x-amz-copy-source", "/copy-bucket/other"),
            (condition, etag.as_str()),
        ];
        let (first, second) = tokio::join!(
            request(&handler, Method::PUT, &path, "", &first_headers),
            request(&handler, Method::PUT, &path, "", &second_headers),
        );
        let winner_body = match (first.status(), second.status()) {
            (StatusCode::OK, StatusCode::PRECONDITION_FAILED) => {
                assert_precondition_failed(second).await;
                "source-data"
            }
            (StatusCode::PRECONDITION_FAILED, StatusCode::OK) => {
                assert_precondition_failed(first).await;
                "other-data"
            }
            statuses => panic!("expected one atomic winner, got {statuses:?}"),
        };
        assert_eq!(
            body(request(&handler, Method::GET, &path, "", &[]).await).await,
            winner_body
        );
    }
}

#[tokio::test]
async fn copy_versioned_encoded_source_keeps_destination_guard() {
    let handler = setup().await;
    request(
        &handler,
        Method::PUT,
        "/copy-bucket?versioning",
        "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        &[],
    )
    .await;
    let source = request(
        &handler,
        Method::PUT,
        "/copy-bucket/source%20%2B%25",
        "old-source",
        &[],
    )
    .await;
    let version = source.headers()["x-amz-version-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let etag = source.headers()["etag"].to_str().unwrap().to_owned();
    request(
        &handler,
        Method::PUT,
        "/copy-bucket/source%20%2B%25",
        "latest-source",
        &[],
    )
    .await;
    let copy_source = format!("/copy-bucket/source%20%2B%25?versionId={version}");
    let headers = [
        ("x-amz-copy-source", copy_source.as_str()),
        ("x-amz-copy-source-if-match", etag.as_str()),
        ("if-none-match", "*"),
    ];
    assert_eq!(
        request(
            &handler,
            Method::PUT,
            "/copy-bucket/version-copy",
            "",
            &headers
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_precondition_failed(
        request(
            &handler,
            Method::PUT,
            "/copy-bucket/version-copy",
            "",
            &headers,
        )
        .await,
    )
    .await;
    assert_eq!(
        body(request(&handler, Method::GET, "/copy-bucket/version-copy", "", &[]).await).await,
        "old-source"
    );
}

#[tokio::test]
async fn copy_rejects_unsupported_destination_if_none_match_without_writing() {
    let handler = setup().await;
    let response = request(
        &handler,
        Method::PUT,
        "/copy-bucket/destination",
        "",
        &[
            ("x-amz-copy-source", "/copy-bucket/source"),
            ("if-none-match", "\"etag\""),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(body(response)
        .await
        .contains("<Code>InvalidArgument</Code>"));
    assert_eq!(
        request(&handler, Method::GET, "/copy-bucket/destination", "", &[])
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn list_v2_counts_common_prefixes_and_echoes_continuation_token() {
    let handler = setup().await;
    for key in ["listing/a/1", "listing/a/2", "listing/b%26x", "listing/c"] {
        assert_eq!(
            request(
                &handler,
                Method::PUT,
                &format!("/copy-bucket/{key}"),
                "data",
                &[]
            )
            .await
            .status(),
            StatusCode::OK
        );
    }
    let first = request(
        &handler,
        Method::GET,
        "/copy-bucket?list-type=2&prefix=listing%2F&delimiter=%2F&max-keys=1",
        "",
        &[],
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first = body(first).await;
    assert!(first.contains("<KeyCount>1</KeyCount>"));
    assert!(first.contains("<CommonPrefixes><Prefix>listing/a/</Prefix></CommonPrefixes>"));
    assert!(first.contains("<NextContinuationToken>listing/a/2</NextContinuationToken>"));
    assert!(!first.contains("<ContinuationToken>"));

    let second = request(
        &handler,
        Method::GET,
        "/copy-bucket?list-type=2&prefix=listing%2F&delimiter=%2F&max-keys=1&continuation-token=listing%2Fa%2F2&start-after=z",
        "",
        &[],
    )
    .await;
    assert_eq!(second.status(), StatusCode::OK);
    let second = body(second).await;
    assert!(second.contains("<KeyCount>1</KeyCount>"));
    assert!(second.contains("<ContinuationToken>listing/a/2</ContinuationToken>"));
    assert!(second.contains("<Key>listing/b&amp;x</Key>"));
    assert!(!second.contains("<CommonPrefixes>"));

    let third = request(
        &handler,
        Method::GET,
        "/copy-bucket?list-type=2&prefix=listing%2F&delimiter=%2F&max-keys=1&continuation-token=listing%2Fb%26x",
        "",
        &[],
    )
    .await;
    assert_eq!(third.status(), StatusCode::OK);
    let third = body(third).await;
    assert!(third.contains("<ContinuationToken>listing/b&amp;x</ContinuationToken>"));
    assert!(third.contains("<Key>listing/c</Key>"));
    assert!(third.contains("<IsTruncated>false</IsTruncated>"));
    assert!(!third.contains("<NextContinuationToken>"));
}
