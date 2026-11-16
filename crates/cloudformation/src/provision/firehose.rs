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
}
