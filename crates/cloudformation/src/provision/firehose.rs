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
                "ExtendedS3DestinationConfiguration",
                "IcebergDestinationConfiguration",
                "KinesisStreamSourceConfiguration",
            ],
        )?;
        let mut body = props.as_object().cloned().ok_or(CfnError::Internal)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn firehose_lifecycle_reaches_the_native_service() {
        let registry = ServiceRegistry::with_known_services();
        let _delivery = locallycloud_firehose::register(&registry);
        let provisioner = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let props = json!({"DeliveryStreamName":"accounting-ledger", "ExtendedS3DestinationConfiguration":{
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
