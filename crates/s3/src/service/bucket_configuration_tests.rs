use super::*;
use bytes::Bytes;

async fn call(
    handler: &S3Handler,
    method: Method,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let mut fields = http::HeaderMap::new();
    fields.insert("host", HeaderValue::from_static("localhost"));
    for (name, value) in headers {
        fields.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    let response = handler
        .handle(ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers: fields,
            body: Bytes::copy_from_slice(body.as_bytes()),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            request_id: "bucket-configuration".into(),
        })
        .await;
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 2_000_000)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}
const LIFECYCLE: &str = "<LifecycleConfiguration><Rule><ID>archive &amp; expire</ID><Filter><And><Prefix>ledger/</Prefix><Tag><Key>archive</Key><Value>true</Value></Tag></And></Filter><Status>Enabled</Status><Expiration><Days>365</Days></Expiration><Transition><Days>60</Days><StorageClass>GLACIER</StorageClass></Transition><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration><NoncurrentVersionTransition><NoncurrentDays>60</NoncurrentDays><StorageClass>GLACIER_IR</StorageClass></NoncurrentVersionTransition></Rule></LifecycleConfiguration>";
const OWNERSHIP: &str = "<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>";
const LOGGING: &str = "<BucketLoggingStatus><LoggingEnabled><TargetBucket>config-logs</TargetBucket><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
#[tokio::test]
async fn configuration_roundtrip_restart_updates_and_removals() {
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(StateDb::open(root.path().join("private/state.sqlite3")).unwrap());
    let handler = super::tests::test_state_handler(Weak::new(), state.clone()).unwrap();
    for name in ["config-source", "config-logs"] {
        assert_eq!(
            call(&handler, Method::PUT, &format!("/{name}"), "", &[])
                .await
                .0,
            200
        );
    }
    for (query, xml) in [
        ("lifecycle", LIFECYCLE),
        ("ownershipControls", OWNERSHIP),
        ("logging", LOGGING),
    ] {
        assert_eq!(
            call(
                &handler,
                Method::PUT,
                &format!("/config-source?{query}"),
                xml,
                &[]
            )
            .await
            .0,
            200
        );
        let result = call(
            &handler,
            Method::GET,
            &format!("/config-source?{query}"),
            "",
            &[],
        )
        .await;
        assert_eq!(result.0, 200);
        assert!(result.1.contains("xmlns="));
    }
    drop(handler);
    let handler = super::tests::test_state_handler(Weak::new(), state).unwrap();
    for (query, needle) in [
        ("lifecycle", "archive &amp; expire"),
        ("ownershipControls", "BucketOwnerEnforced"),
        ("logging", "access/"),
    ] {
        let result = call(
            &handler,
            Method::GET,
            &format!("/config-source?{query}"),
            "",
            &[],
        )
        .await;
        assert_eq!(result.0, 200);
        assert!(result.1.contains(needle));
    }
    let updated = LIFECYCLE.replace("<Days>365</Days>", "<Days>7</Days>");
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/config-source?lifecycle",
            &updated,
            &[]
        )
        .await
        .0,
        200
    );
    assert!(
        call(&handler, Method::GET, "/config-source?lifecycle", "", &[])
            .await
            .1
            .contains("<Days>7</Days>")
    );
    for query in ["lifecycle", "ownershipControls"] {
        assert_eq!(
            call(
                &handler,
                Method::DELETE,
                &format!("/config-source?{query}"),
                "",
                &[]
            )
            .await
            .0,
            204
        );
        assert_eq!(
            call(
                &handler,
                Method::GET,
                &format!("/config-source?{query}"),
                "",
                &[]
            )
            .await
            .0,
            404
        );
    }
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/config-source?logging",
            "<BucketLoggingStatus/>",
            &[]
        )
        .await
        .0,
        200
    );
    assert!(
        !call(&handler, Method::GET, "/config-source?logging", "", &[])
            .await
            .1
            .contains("LoggingEnabled")
    );
}
#[tokio::test]
async fn ownership_disables_acl_writes_including_copy_and_multipart() {
    let handler = S3Handler::new();
    call(&handler, Method::PUT, "/config-source", "", &[]).await;
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/config-source?ownershipControls",
            OWNERSHIP,
            &[]
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(&handler, Method::PUT, "/config-source/source", "data", &[])
            .await
            .0,
        200
    );
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/config-source/full-control",
            "data",
            &[("x-amz-acl", "bucket-owner-full-control")]
        )
        .await
        .0,
        200
    );
    for (method, path, headers) in [
        (
            Method::PUT,
            "/config-source/public",
            vec![("x-amz-acl", "public-read")],
        ),
        (
            Method::PUT,
            "/config-source/grant",
            vec![("x-amz-grant-read", "id=someone")],
        ),
        (
            Method::PUT,
            "/config-source/copy",
            vec![
                ("x-amz-copy-source", "/config-source/source"),
                ("x-amz-acl", "public-read"),
            ],
        ),
        (
            Method::POST,
            "/config-source/multipart?uploads",
            vec![("x-amz-acl", "private")],
        ),
        (Method::PUT, "/config-source?acl", vec![]),
        (Method::PUT, "/config-source/source?acl", vec![]),
    ] {
        let response = call(&handler, method, path, "", &headers).await;
        assert_eq!(response.0, 400, "{path}: {}", response.1);
        assert!(response.1.contains("AccessControlListNotSupported"));
    }
    assert_eq!(
        call(&handler, Method::HEAD, "/config-source/public", "", &[])
            .await
            .0,
        404
    );
    let mode = OWNERSHIP.replace("BucketOwnerEnforced", "ObjectWriter");
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/config-source?ownershipControls",
            &mode,
            &[]
        )
        .await
        .0,
        501
    );
}
#[tokio::test]
async fn malformed_configuration_is_bounded_and_does_not_overwrite() {
    let handler = S3Handler::new();
    call(&handler, Method::PUT, "/config-source", "", &[]).await;
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/config-source?lifecycle",
            LIFECYCLE,
            &[]
        )
        .await
        .0,
        200
    );
    for invalid in [
        LIFECYCLE.replace("Enabled", "Unknown"),
        LIFECYCLE.replace("<Days>365</Days>", "<Days>-1</Days>"),
        LIFECYCLE.replace(
            "<Days>365</Days>",
            "<Days>7</Days><Date>2027-01-01T00:00:00Z</Date>",
        ),
        LIFECYCLE.replace("<Status>", "<Status ignored=\"yes\">"),
        LIFECYCLE.replace("<ID>", "<Unknown>"),
        format!("{}{}", "<x>".repeat(33), "</x>".repeat(33)),
        format!("<x>{}</x>", "<y/>".repeat(20_001)),
        " ".repeat(1_048_577),
    ] {
        assert_eq!(
            call(
                &handler,
                Method::PUT,
                "/config-source?lifecycle",
                &invalid,
                &[]
            )
            .await
            .0,
            400
        );
    }
    assert!(
        call(&handler, Method::GET, "/config-source?lifecycle", "", &[])
            .await
            .1
            .contains("archive &amp; expire")
    );
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/config-source?logging",
            LOGGING,
            &[]
        )
        .await
        .0,
        400
    );
    assert_eq!(
        call(
            &handler,
            Method::PUT,
            "/config-source?lifecycle&logging",
            LIFECYCLE,
            &[]
        )
        .await
        .0,
        400
    );
}
