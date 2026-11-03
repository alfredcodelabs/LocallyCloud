use super::*;
use locallycloud_core::handler::NativeHandler;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct GlueFixture {
    calls: Mutex<Vec<(String, Value)>>,
    fail_create: bool,
}

#[async_trait::async_trait]
impl NativeHandler for GlueFixture {
    async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
        let operation = request.headers["x-amz-target"].to_str().unwrap().to_owned();
        let input = serde_json::from_slice(&request.body).unwrap();
        self.calls.lock().unwrap().push((operation.clone(), input));
        let failed = self.fail_create && operation == "AWSGlue.CreateTable";
        http::Response::builder()
            .status(if failed { 400 } else { 200 })
            .body(axum::body::Body::from(if failed {
                r#"{"__type":"AccessDeniedException","Message":"metadata write denied"}"#
            } else {
                "{}"
            }))
            .unwrap()
    }
}

fn setup(fail_create: bool) -> (Arc<ServiceRegistry>, Arc<GlueFixture>, Provisioner) {
    let registry = ServiceRegistry::with_known_services();
    let fixture = Arc::new(GlueFixture {
        fail_create,
        ..Default::default()
    });
    registry.register_native(
        ServiceName::new("glue"),
        ServiceMetadata::new(AwsProtocol::Json11, Some("AWSGlue")),
        fixture.clone(),
    );
    let provisioner = Provisioner::new(
        Arc::downgrade(&registry),
        "us-east-1".into(),
        "000000000000".into(),
    );
    (registry, fixture, provisioner)
}

fn accounting_table() -> Value {
    json!({
        "CatalogId":"000000000000","DatabaseName":"ledger","Name":"journal",
        "OpenTableFormatInput":{"IcebergInput":{
            "MetadataOperation":"CREATE","Version":"2","IcebergTableInput":{
                "Location":"s3://ledger/parquet-iceberg/journal/",
                "Schema":{"Type":"struct","SchemaId":0,"IdentifierFieldIds":[1],
                    "Fields":[{"Id":1,"Name":"id","Type":"string","Required":true}]},
                "PartitionSpec":{"SpecId":0,"Fields":[{"SourceId":1,"Transform":"identity","Name":"id","FieldId":1000}]},
                "Properties":{"write.target-file-size-bytes":"134217728"}
            }
        }}
    })
}

#[tokio::test]
async fn accounting_open_table_maps_to_native_create_preserves_identity_and_deletes_catalog_only() {
    let (_registry, fixture, provisioner) = setup(false);
    let props = accounting_table();
    let resource = provisioner.glue_table("Table", &props).await.unwrap();
    assert_eq!(resource.ref_value, "journal");
    {
        let calls = fixture.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "AWSGlue.CreateTable");
        let input = &calls[0].1;
        assert_eq!(input["Name"], "journal");
        assert!(input.get("TableInput").is_none());
        assert_eq!(
            input["OpenTableFormatInput"]["IcebergInput"]["CreateIcebergTableInput"],
            props["OpenTableFormatInput"]["IcebergInput"]["IcebergTableInput"]
        );
        assert!(input["OpenTableFormatInput"]["IcebergInput"]
            .get("IcebergTableInput")
            .is_none());
    }
    provisioner
        .update_glue_table("Table", &resource, &props, &props)
        .await
        .unwrap();
    let mut changed = props.clone();
    changed["OpenTableFormatInput"]["IcebergInput"]["IcebergTableInput"]["Properties"]
        ["write.target-file-size-bytes"] = json!("67108864");
    assert!(provisioner
        .update_glue_table("Table", &resource, &props, &changed)
        .await
        .unwrap_err()
        .to_string()
        .contains("Iceberg metadata updates are not implemented"));
    let mut removed = props.clone();
    removed
        .as_object_mut()
        .unwrap()
        .remove("OpenTableFormatInput");
    assert!(provisioner
        .update_glue_table("Table", &resource, &props, &removed)
        .await
        .is_err());
    let mut renamed = props.clone();
    renamed["Name"] = json!("renamed");
    assert!(provisioner
        .update_glue_table("Table", &resource, &props, &renamed)
        .await
        .unwrap_err()
        .to_string()
        .contains("require replacement"));
    assert_eq!(fixture.calls.lock().unwrap().len(), 1);
    provisioner
        .delete_glue_table(&resource.ref_value, &props)
        .await
        .unwrap();
    let calls = fixture.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[1],
        (
            "AWSGlue.DeleteTable".to_owned(),
            json!({"CatalogId":"000000000000","DatabaseName":"ledger","Name":"journal"})
        )
    );
}

#[tokio::test]
async fn open_table_create_propagates_native_failures_and_rejects_ambiguous_shapes() {
    let (_registry, fixture, provisioner) = setup(true);
    let props = accounting_table();
    let error = provisioner.glue_table("Table", &props).await.unwrap_err();
    assert!(error.to_string().contains("metadata write denied"));
    assert_eq!(fixture.calls.lock().unwrap().len(), 1);
    for (property, value) in [
        ("Name", Value::Null),
        ("TableInput", json!({"Name":"other"})),
        ("OpenTableFormatInput", json!({"IcebergInput":null})),
        (
            "OpenTableFormatInput",
            json!({"IcebergInput":{"CreateIcebergTableInput":{}}}),
        ),
    ] {
        let mut invalid = props.clone();
        invalid[property] = value;
        assert!(provisioner.glue_table("Table", &invalid).await.is_err());
    }
    assert_eq!(fixture.calls.lock().unwrap().len(), 1);
    assert!(validate_glue_table_properties(
        "Legacy",
        &json!({"CatalogId":"000000000000","DatabaseName":"ledger","TableInput":{"Name":"legacy"}})
    )
    .is_ok());
}
