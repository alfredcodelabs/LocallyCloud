use super::*;
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::ServiceMetadata;
use std::time::Duration;

fn request(op: &str, value: Value) -> ServiceRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE),
    );
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("AWSGlue.{op}")).unwrap(),
    );
    ServiceRequest {
        method: Method::POST,
        uri: "/".parse().unwrap(),
        headers,
        body: value.to_string().into(),
        account_id: "000000000000".into(),
        region: "us-east-1".into(),
        request_id: Uuid::new_v4().to_string(),
    }
}
fn input() -> Value {
    json!({"DatabaseName":"lake","Name":"events","OpenTableFormatInput":{"IcebergInput":{"MetadataOperation":"CREATE","Version":"2","CreateIcebergTableInput":{
        "Location":"s3://iceberg-warehouse/events/","Schema":{"Type":"struct","SchemaId":0,"IdentifierFieldIds":[1],"Fields":[{"Id":1,"Name":"id","Type":"long","Required":true},{"Id":2,"Name":"day","Type":"string","Required":false}]},
        "PartitionSpec":{"SpecId":0,"Fields":[{"SourceId":2,"Transform":"identity","Name":"day","FieldId":1000}]},"Properties":{"write.target-file-size-bytes":"134217728"}
    }}}})
}
fn registry(state: Arc<AnalyticsState>) -> (Arc<ServiceRegistry>, GlueHandler) {
    let registry = ServiceRegistry::with_known_services();
    let handler = GlueHandler::with_registry(state, Arc::downgrade(&registry));
    registry.register_native(
        ServiceName::new("glue"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        Arc::new(handler.clone()),
    );
    registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
        &registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: Duration::from_secs(1),
        },
        LegacyHealth::new(true),
        "us-east-1".into(),
        "000000000000".into(),
    )));
    handler
        .process(&request(
            "CreateDatabase",
            json!({"DatabaseInput":{"Name":"lake"}}),
        ))
        .unwrap();
    (registry, handler)
}
async fn dispatch_s3(registry: &Arc<ServiceRegistry>, method: Method, uri: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=locallycloud/19700101/us-east-1/s3/aws4_request",
        ),
    );
    registry
        .internal_dispatcher()
        .unwrap()
        .dispatch_scoped(
            &method,
            &uri.parse().unwrap(),
            &headers,
            Bytes::new(),
            "iceberg-test",
            "000000000000",
            "us-east-1",
        )
        .await
}
fn get(handler: &GlueHandler) -> Result<Value, AnalyticsError> {
    handler.process(&request(
        "GetTable",
        json!({"DatabaseName":"lake","Name":"events"}),
    ))
}

#[test]
fn metadata_is_valid_v2_and_invalid_schemas_fail_before_upload() {
    let mut described = input();
    described["TableInput"] = json!({"Description":"description without inner Name"});
    let normalized = serde_json::from_value::<CreateTableRequest>(described.clone())
        .unwrap()
        .normalize()
        .unwrap();
    assert_eq!(normalized.table_input.name, "events");
    assert_eq!(
        normalized.table_input.fields["Description"],
        "description without inner Name"
    );
    described["TableInput"]["Name"] = json!("conflicting");
    assert!(matches!(
        serde_json::from_value::<CreateTableRequest>(described)
            .unwrap()
            .normalize(),
        Err(AnalyticsError::InvalidInput)
    ));
    let plan = Plan::new(
        decode::<CreateTableRequest>(&request("CreateTable", input()).body)
            .unwrap()
            .normalize()
            .unwrap(),
    )
    .unwrap();
    let parsed: TableMetadata = serde_json::from_slice(&plan.metadata).unwrap();
    assert_eq!(parsed.location(), "s3://iceberg-warehouse/events");
    assert_eq!(parsed.snapshots().len(), 0);
    for path in [
        "optional_identifier",
        "float_identifier",
        "duplicate_id",
        "missing_source",
        "bad_operation",
        "bad_version",
        "conflicting_descriptor",
    ] {
        let mut raw = input();
        let create = &mut raw["OpenTableFormatInput"]["IcebergInput"]["CreateIcebergTableInput"];
        match path {
            "optional_identifier" => create["Schema"]["Fields"][0]["Required"] = json!(false),
            "float_identifier" => create["Schema"]["Fields"][0]["Type"] = json!("float"),
            "duplicate_id" => create["Schema"]["Fields"][1]["Id"] = json!(1),
            "missing_source" => create["PartitionSpec"]["Fields"][0]["SourceId"] = json!(99),
            "bad_operation" => {
                raw["OpenTableFormatInput"]["IcebergInput"]["MetadataOperation"] = json!("UPDATE")
            }
            "bad_version" => {
                raw["OpenTableFormatInput"]["IcebergInput"]["Version"] = json!("bogus")
            }
            "conflicting_descriptor" => {
                raw["TableInput"] =
                    json!({"Name":"events","StorageDescriptor":{"Location":"s3://other/events"}})
            }
            _ => unreachable!(),
        }
        assert!(
            Plan::new(
                serde_json::from_value::<CreateTableRequest>(raw)
                    .unwrap()
                    .normalize()
                    .unwrap()
            )
            .is_err(),
            "{path}"
        );
    }
}

#[tokio::test]
async fn real_s3_metadata_is_published_before_durable_catalog_and_delete_retains_data() {
    use locallycloud_state::{StateCipher, StateDb};
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.kiro/localcloud-tmp/analytics-tests")
        .join(Uuid::new_v4().to_string());
    let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
    let state =
        Arc::new(AnalyticsState::with_state(db.clone(), StateCipher::with_key(&[7; 32])).unwrap());
    let (registry, handler) = registry(state);
    locallycloud_s3::register(&registry);
    assert_eq!(
        dispatch_s3(&registry, Method::PUT, "/iceberg-warehouse")
            .await
            .status(),
        200
    );
    assert_eq!(
        handler
            .handle(request("CreateTable", input()))
            .await
            .status(),
        200
    );
    let catalog = get(&handler).unwrap();
    let pointer = catalog["Table"]["Parameters"]["metadata_location"]
        .as_str()
        .unwrap();
    let path = pointer.replacen("s3://", "/", 1);
    let response = dispatch_s3(&registry, Method::GET, &path).await;
    assert_eq!(response.status(), 200);
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
        .await
        .unwrap();
    let metadata: TableMetadata = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        metadata
            .current_schema()
            .identifier_field_ids()
            .collect::<Vec<_>>(),
        vec![1]
    );
    assert_eq!(
        handler
            .handle(request("CreateTable", input()))
            .await
            .status(),
        400
    );
    let restored = AnalyticsState::with_state(db, StateCipher::with_key(&[7; 32])).unwrap();
    let recovered = GlueHandler::new(Arc::new(restored));
    assert_eq!(get(&recovered).unwrap(), catalog);
    handler
        .process(&request(
            "DeleteTable",
            json!({"DatabaseName":"lake","Name":"events"}),
        ))
        .unwrap();
    assert_eq!(
        dispatch_s3(&registry, Method::GET, &path).await.status(),
        200
    );
    tokio::task::spawn_blocking(move || std::fs::remove_dir_all(root))
        .await
        .unwrap()
        .unwrap();
}

struct HeldS3 {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
    fail: bool,
    methods: std::sync::Mutex<Vec<Method>>,
}
#[async_trait]
impl NativeHandler for HeldS3 {
    async fn handle(&self, request: ServiceRequest) -> Response {
        self.methods.lock().unwrap().push(request.method.clone());
        if request.method == Method::PUT {
            self.started.notify_one();
            self.release.notified().await;
        }
        Response::builder()
            .status(if self.fail { 403 } else { 200 })
            .body(Body::empty())
            .unwrap()
    }
}
#[tokio::test]
async fn denial_and_cancellation_release_reservations_without_partial_catalog() {
    for denied in [true, false] {
        let state = Arc::new(AnalyticsState::new());
        let (registry, handler) = registry(state.clone());
        let s3 = Arc::new(HeldS3 {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            fail: denied,
            methods: std::sync::Mutex::new(Vec::new()),
        });
        registry.register_native(
            ServiceName::new("s3"),
            ServiceMetadata::new(AwsProtocol::RestXml, None),
            s3.clone(),
        );
        let h = handler.clone();
        let pending = tokio::spawn(async move { h.handle(request("CreateTable", input())).await });
        s3.started.notified().await;
        assert!(matches!(get(&handler), Err(AnalyticsError::EntityNotFound)));
        assert!(matches!(
            handler.process(&request("DeleteDatabase", json!({"Name":"lake"}))),
            Err(AnalyticsError::ConcurrentModification)
        ));
        let duplicate = handler.handle(request("CreateTable", input())).await;
        assert_eq!(duplicate.status(), 400);
        pending.abort();
        s3.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let slot = state.catalog(&Scope::new("000000000000", "us-east-1"));
                if slot.lock().unwrap().pending_tables.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(get(&handler).is_ok(), !denied);
        assert_eq!(s3.methods.lock().unwrap().as_slice(), [Method::PUT]);
    }
}

#[tokio::test]
async fn failed_catalog_persistence_deletes_only_its_own_uploaded_metadata() {
    use locallycloud_state::{StateCipher, StateDb};
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.kiro/localcloud-tmp/analytics-tests")
        .join(Uuid::new_v4().to_string());
    let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
    let state =
        Arc::new(AnalyticsState::with_state(db.clone(), StateCipher::with_key(&[7; 32])).unwrap());
    let (registry, handler) = registry(state);
    db.connection().unwrap().execute_batch("CREATE TRIGGER fail_table BEFORE INSERT ON glue_tables BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;").unwrap();
    let s3 = Arc::new(HeldS3 {
        started: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        fail: false,
        methods: std::sync::Mutex::new(Vec::new()),
    });
    registry.register_native(
        ServiceName::new("s3"),
        ServiceMetadata::new(AwsProtocol::RestXml, None),
        s3.clone(),
    );
    s3.release.notify_one();
    let response = handler.handle(request("CreateTable", input())).await;
    assert_eq!(response.status(), 500);
    assert!(matches!(get(&handler), Err(AnalyticsError::EntityNotFound)));
    assert_eq!(
        s3.methods.lock().unwrap().as_slice(),
        [Method::PUT, Method::DELETE]
    );
    tokio::task::spawn_blocking(move || std::fs::remove_dir_all(root))
        .await
        .unwrap()
        .unwrap();
}
