//! Firehose resources are backed by the owning service's native control plane.
use super::*;

impl Provisioner {
    pub(super) async fn firehose_stream(
        &self,
        logical: &str,
        stack: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(
            logical,
            "AWS::KinesisFirehose::DeliveryStream",
            props,
            &[
                "DeliveryStreamName",
                "DeliveryStreamType",
                "DeliveryStreamEncryptionConfigurationInput",
                "ExtendedS3DestinationConfiguration",
                "IcebergDestinationConfiguration",
                "KinesisStreamSourceConfiguration",
            ],
        )?;
        let mut body = firehose_api_properties(props)?;
        let name = match props.get("DeliveryStreamName") {
            Some(Value::String(name)) if !name.is_empty() => name.clone(),
            None => generate_name(stack, logical, 64),
            _ => {
                return Err(CfnError::Validation(
                    "DeliveryStreamName must be a non-empty string".into(),
                ))
            }
        };
        body.insert("DeliveryStreamName".into(), json!(name));
        let created = self
            .call_aws_json_11(
                "firehose",
                "Firehose_20150804.CreateDeliveryStream",
                Value::Object(body),
                logical,
            )
            .await?;
        match required_response_string(&created, "DeliveryStreamARN", logical) {
            Ok(arn) => Ok(ResolvedResource {
                ref_value: name,
                attributes: [("Arn".into(), arn)].into(),
            }),
            Err(primary) => match self.delete_firehose_stream(&name).await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
            },
        }
    }

    pub(super) async fn delete_firehose_stream(&self, name: &str) -> Result<(), CfnError> {
        self.delete_aws_json_11(
            "firehose",
            "Firehose_20150804.DeleteDeliveryStream",
            json!({"DeliveryStreamName":name}),
            name,
            &["ResourceNotFoundException"],
        )
        .await
    }
}

fn firehose_api_properties(props: &Value) -> Result<serde_json::Map<String, Value>, CfnError> {
    let mut body = props.as_object().cloned().ok_or(CfnError::Internal)?;
    if let Some(destination) = body
        .get_mut("IcebergDestinationConfiguration")
        .and_then(Value::as_object_mut)
    {
        if let Some(mode) = destination.remove("s3BackupMode") {
            if destination.insert("S3BackupMode".into(), mode).is_some() {
                return Err(CfnError::Validation(
                    "IcebergDestinationConfiguration cannot specify both s3BackupMode and S3BackupMode".into(),
                ));
            }
        }
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn iceberg_backup_property_uses_aws_api_casing_and_preserves_configuration() {
        let props = json!({"DeliveryStreamName":"accounting-iceberg",
        "IcebergDestinationConfiguration":{
            "s3BackupMode":"FailedDataOnly",
            "S3Configuration":{"BufferingHints":{"SizeInMBs":64,"IntervalInSeconds":300}},
            "ProcessingConfiguration":{"Enabled":true,"Processors":[{"Type":"MetadataExtraction"}]}
        }});
        let mapped = Value::Object(firehose_api_properties(&props).unwrap());
        assert_eq!(
            mapped["IcebergDestinationConfiguration"]["S3BackupMode"],
            "FailedDataOnly"
        );
        assert!(mapped["IcebergDestinationConfiguration"]
            .get("s3BackupMode")
            .is_none());
        for field in ["S3Configuration", "ProcessingConfiguration"] {
            assert_eq!(
                mapped["IcebergDestinationConfiguration"][field],
                props["IcebergDestinationConfiguration"][field]
            );
        }
        assert!(props["IcebergDestinationConfiguration"]
            .get("s3BackupMode")
            .is_some());
        let conflicting = json!({"IcebergDestinationConfiguration":{
            "s3BackupMode":"FailedDataOnly","S3BackupMode":"AllData"}});
        assert!(firehose_api_properties(&conflicting).is_err());
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
        let description = provisioner
            .call_aws_json_11(
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
            .delete_firehose_stream(&resource.ref_value)
            .await
            .unwrap();
        provisioner
            .delete_firehose_stream(&resource.ref_value)
            .await
            .unwrap();
        assert!(provisioner
            .call_aws_json_11(
                "firehose",
                "Firehose_20150804.DescribeDeliveryStream",
                json!({"DeliveryStreamName":resource.ref_value}),
                "LedgerStream"
            )
            .await
            .is_err());
    }
}
