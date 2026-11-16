//! CloudFormation resource lifecycle against the registered native Firehose service.
#![cfg(feature = "services")]
use axum::body::to_bytes;
use bytes::Bytes;
use http::{HeaderMap, Method, Uri};
use locallycloud_cloudformation::{
    provision::{Provisioner, Replacement},
    template::ResourcePolicy,
};
use locallycloud_core::{
    integration::InternalDispatcher,
    proxy::{LegacyHealth, ProxyConfig},
    registry::ServiceRegistry,
};
use serde_json::{json, Value};
use std::sync::Arc;

async fn call_aws_json_11(
    registry: &Arc<ServiceRegistry>,
    _service: &str,
    target: &str,
    body: Value,
    _logical: &str,
) -> Result<Value, String> {
    let dispatcher = InternalDispatcher::new_shared(
        registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: std::time::Duration::from_secs(1),
        },
        LegacyHealth::new(false),
        "us-east-1".into(),
        "000000000000".into(),
    );
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-target", target.parse().unwrap());
    headers.insert(
        "content-type",
        "application/x-amz-json-1.1".parse().unwrap(),
    );
    let response = dispatcher
        .dispatch_scoped(
            &Method::POST,
            &Uri::from_static("/"),
            &headers,
            Bytes::from(body.to_string()),
            "test",
            "000000000000",
            "us-east-1",
        )
        .await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    if !status.is_success() {
        return Err(String::from_utf8_lossy(&bytes).into_owned());
    }
    Ok(serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn firehose_lifecycle_reaches_the_native_service() {
    let registry = ServiceRegistry::with_known_services();
    let _delivery = locallycloud_firehose::register(&registry);
    let provisioner = Provisioner::new(
        Arc::downgrade(&registry),
        "us-east-1".into(),
        "000000000000".into(),
    );
    let props = json!({"DeliveryStreamName":"accounting-ledger",
        "DeliveryStreamEncryptionConfigurationInput":{"KeyType":"AWS_OWNED_CMK"},
        "ExtendedS3DestinationConfiguration":{
        "RoleARN":"arn:aws:iam::000000000000:role/firehose", "BucketARN":"arn:aws:s3:::ledger",
        "Prefix":"records/", "BufferingHints":{"SizeInMBs":1,"IntervalInSeconds":60}
    }});
    let resource = provisioner
        .provision(
            "LedgerStream",
            "accounting",
            "AWS::KinesisFirehose::DeliveryStream",
            &props,
        )
        .await
        .unwrap();
    assert_eq!(resource.ref_value, "accounting-ledger");
    assert_eq!(
        resource.attributes["Arn"],
        "arn:aws:firehose:us-east-1:000000000000:deliverystream/accounting-ledger"
    );
    let description = call_aws_json_11(
        &registry,
        "firehose",
        "Firehose_20150804.DescribeDeliveryStream",
        json!({"DeliveryStreamName":resource.ref_value}),
        "LedgerStream",
    )
    .await
    .unwrap();
    assert_eq!(
        description["DeliveryStreamDescription"]["DeliveryStreamStatus"],
        "ACTIVE"
    );
    assert_eq!(
        description["DeliveryStreamDescription"]["DeliveryStreamEncryptionConfiguration"],
        json!({"KeyType":"AWS_OWNED_CMK","Status":"ENABLED"})
    );
    let customer = json!({"DeliveryStreamName":"accounting-cmk",
            "DeliveryStreamEncryptionConfigurationInput":{"KeyType":"CUSTOMER_MANAGED_CMK",
                "KeyARN":"arn:aws:kms:us-east-1:000000000000:key/x"},
            "ExtendedS3DestinationConfiguration": props["ExtendedS3DestinationConfiguration"]});
    assert!(provisioner
        .provision(
            "CmkStream",
            "accounting",
            "AWS::KinesisFirehose::DeliveryStream",
            &customer
        )
        .await
        .is_err());
    provisioner
        .update(
            "LedgerStream",
            "AWS::KinesisFirehose::DeliveryStream",
            &resource,
            &props,
            &props,
            Replacement::Update(ResourcePolicy::Delete),
        )
        .await
        .unwrap();
    provisioner
        .deprovision(
            "AWS::KinesisFirehose::DeliveryStream",
            &resource.ref_value,
            &props,
        )
        .await
        .unwrap();
    provisioner
        .deprovision(
            "AWS::KinesisFirehose::DeliveryStream",
            &resource.ref_value,
            &props,
        )
        .await
        .unwrap();
    assert!(call_aws_json_11(
        &registry,
        "firehose",
        "Firehose_20150804.DescribeDeliveryStream",
        json!({"DeliveryStreamName":resource.ref_value}),
        "LedgerStream"
    )
    .await
    .is_err());
}
