//! Translate the supported S3 control-plane configuration and preflight before creating buckets.
use super::*;

fn invalid() -> CfnError {
    CfnError::Validation("Invalid or unsupported S3 bucket configuration".into())
}
fn known(logical: &str, value: &Value, fields: &[&str]) -> Result<(), CfnError> {
    if !value.is_object() {
        return Err(invalid());
    }
    ensure_known_properties(logical, "AWS::S3::Bucket.Configuration", value, fields)
}
fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str, CfnError> {
    value.get(field).and_then(Value::as_str).ok_or_else(invalid)
}
fn element(name: &str, value: &str) -> String {
    format!("<{name}>{}</{name}>", xml_escape(value))
}
fn optional(
    xml: &mut String,
    value: &Value,
    source: &str,
    target: &str,
    number: bool,
) -> Result<(), CfnError> {
    if let Some(value) = value.get(source) {
        let value = if number {
            value
                .as_u64()
                .map(|value| value.to_string())
                .ok_or_else(invalid)?
        } else {
            value.as_str().map(str::to_owned).ok_or_else(invalid)?
        };
        xml.push_str(&element(target, &value));
    }
    Ok(())
}
pub(super) fn ownership(logical: &str, value: &Value) -> Result<String, CfnError> {
    known(logical, value, &["Rules"])?;
    let rules = value
        .get("Rules")
        .and_then(Value::as_array)
        .filter(|v| v.len() == 1)
        .ok_or_else(invalid)?;
    let rule = rules.first().ok_or_else(invalid)?;
    known(logical, rule, &["ObjectOwnership"])?;
    if string(rule, "ObjectOwnership")? != "BucketOwnerEnforced" {
        return Err(CfnError::Validation(
            "Only BucketOwnerEnforced S3 ownership is supported".into(),
        ));
    }
    Ok("<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>".into())
}
pub(super) fn logging(logical: &str, value: &Value) -> Result<String, CfnError> {
    known(logical, value, &["DestinationBucketName", "LogFilePrefix"])?;
    let target = string(value, "DestinationBucketName")?;
    if target.is_empty() || target.len() > 63 {
        return Err(invalid());
    }
    let prefix = match value.get("LogFilePrefix") {
        Some(Value::String(prefix)) if prefix.len() <= 1024 => prefix.as_str(),
        None => "",
        _ => return Err(invalid()),
    };
    Ok(format!(
        "<BucketLoggingStatus><LoggingEnabled>{}{}</LoggingEnabled></BucketLoggingStatus>",
        element("TargetBucket", target),
        element("TargetPrefix", prefix)
    ))
}
pub(super) fn lifecycle(logical: &str, value: &Value) -> Result<String, CfnError> {
    known(logical, value, &["Rules"])?;
    let rules = value
        .get("Rules")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty() && v.len() <= 1000)
        .ok_or_else(invalid)?;
    let mut xml = String::from("<LifecycleConfiguration>");
    for rule in rules {
        known(
            logical,
            rule,
            &[
                "Id",
                "Status",
                "Prefix",
                "TagFilters",
                "ExpirationInDays",
                "ExpirationDate",
                "ExpiredObjectDeleteMarker",
                "Transitions",
                "NoncurrentVersionExpiration",
                "NoncurrentVersionTransitions",
                "AbortIncompleteMultipartUpload",
            ],
        )?;
        xml.push_str("<Rule>");
        optional(&mut xml, rule, "Id", "ID", false)?;
        xml.push_str(&element("Status", string(rule, "Status")?));
        let mut filters = String::new();
        optional(&mut filters, rule, "Prefix", "Prefix", false)?;
        let mut count = usize::from(rule.get("Prefix").is_some());
        if let Some(tags) = rule.get("TagFilters") {
            let tags = tags
                .as_array()
                .filter(|tags| !tags.is_empty() && tags.len() <= 10)
                .ok_or_else(invalid)?;
            for tag in tags {
                known(logical, tag, &["Key", "Value"])?;
                filters.push_str(&format!(
                    "<Tag>{}{}</Tag>",
                    element("Key", string(tag, "Key")?),
                    element("Value", string(tag, "Value")?)
                ));
            }
            count += tags.len();
        }
        xml.push_str("<Filter>");
        if count > 1 {
            xml.push_str("<And>");
        }
        xml.push_str(&filters);
        if count > 1 {
            xml.push_str("</And>");
        }
        xml.push_str("</Filter>");
        let expiration = [
            "ExpirationInDays",
            "ExpirationDate",
            "ExpiredObjectDeleteMarker",
        ]
        .iter()
        .filter(|field| rule.get(**field).is_some())
        .count();
        if expiration > 1 {
            return Err(invalid());
        }
        if expiration == 1 {
            xml.push_str("<Expiration>");
            optional(&mut xml, rule, "ExpirationInDays", "Days", true)?;
            optional(&mut xml, rule, "ExpirationDate", "Date", false)?;
            if let Some(value) = rule.get("ExpiredObjectDeleteMarker") {
                xml.push_str(&element(
                    "ExpiredObjectDeleteMarker",
                    &value.as_bool().ok_or_else(invalid)?.to_string(),
                ));
            }
            xml.push_str("</Expiration>");
        }
        if let Some(expiration) = rule.get("NoncurrentVersionExpiration") {
            known(
                logical,
                expiration,
                &["NoncurrentDays", "NewerNoncurrentVersions"],
            )?;
            if expiration.get("NoncurrentDays").is_none() {
                return Err(invalid());
            }
            xml.push_str("<NoncurrentVersionExpiration>");
            optional(
                &mut xml,
                expiration,
                "NoncurrentDays",
                "NoncurrentDays",
                true,
            )?;
            optional(
                &mut xml,
                expiration,
                "NewerNoncurrentVersions",
                "NewerNoncurrentVersions",
                true,
            )?;
            xml.push_str("</NoncurrentVersionExpiration>");
        }
        for (field, tag, noncurrent) in [
            ("Transitions", "Transition", false),
            (
                "NoncurrentVersionTransitions",
                "NoncurrentVersionTransition",
                true,
            ),
        ] {
            if let Some(transitions) = rule.get(field) {
                let transitions = transitions
                    .as_array()
                    .filter(|values| !values.is_empty() && values.len() <= 10)
                    .ok_or_else(invalid)?;
                for transition in transitions {
                    known(
                        logical,
                        transition,
                        if noncurrent {
                            &[
                                "StorageClass",
                                "TransitionInDays",
                                "NewerNoncurrentVersions",
                            ]
                        } else {
                            &["StorageClass", "TransitionInDays", "TransitionDate"]
                        },
                    )?;
                    xml.push_str(&format!("<{tag}>"));
                    xml.push_str(&element(
                        "StorageClass",
                        string(transition, "StorageClass")?,
                    ));
                    optional(
                        &mut xml,
                        transition,
                        "TransitionInDays",
                        if noncurrent { "NoncurrentDays" } else { "Days" },
                        true,
                    )?;
                    if noncurrent {
                        optional(
                            &mut xml,
                            transition,
                            "NewerNoncurrentVersions",
                            "NewerNoncurrentVersions",
                            true,
                        )?;
                    } else {
                        optional(&mut xml, transition, "TransitionDate", "Date", false)?;
                    }
                    xml.push_str(&format!("</{tag}>"));
                }
            }
        }
        if let Some(abort) = rule.get("AbortIncompleteMultipartUpload") {
            known(logical, abort, &["DaysAfterInitiation"])?;
            xml.push_str("<AbortIncompleteMultipartUpload>");
            optional(
                &mut xml,
                abort,
                "DaysAfterInitiation",
                "DaysAfterInitiation",
                true,
            )?;
            xml.push_str("</AbortIncompleteMultipartUpload>");
        }
        xml.push_str("</Rule>");
    }
    xml.push_str("</LifecycleConfiguration>");
    locallycloud_s3::ops::validate_lifecycle_configuration(xml.as_bytes()).map_err(|error| {
        CfnError::Validation(format!("S3 lifecycle configuration for {logical}: {error}"))
    })?;
    Ok(xml)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[test]
    fn unsupported_and_malformed_properties_are_rejected_during_preflight() {
        for properties in [
            json!({"Rules":[]}),
            json!({"Rules":[{"Status":"Enabled","Unknown":1}]}),
            json!({"Rules":[{"Status":"Enabled","ExpirationInDays":-1}]}),
            json!({"Rules":[{"Status":"Enabled","ExpirationInDays":1,"ExpiredObjectDeleteMarker":true}]}),
            json!({"Rules":[{"Status":"Enabled","Transitions":[{"StorageClass":"UNKNOWN","TransitionInDays":1}]}]}),
        ] {
            assert!(lifecycle("Bucket", &properties).is_err(), "{properties}");
        }
        assert!(ownership(
            "Bucket",
            &json!({"Rules":[{"ObjectOwnership":"ObjectWriter"}]})
        )
        .is_err());
        assert!(logging(
            "Bucket",
            &json!({"DestinationBucketName":"target","LogFilePrefix":false})
        )
        .is_err());
        let xml = lifecycle("Bucket",&json!({"Rules":[{"Id":"tagged","Status":"Enabled","Prefix":"parquet/","TagFilters":[{"Key":"archive","Value":"true"}],"Transitions":[{"StorageClass":"GLACIER_IR","TransitionInDays":0}]}]})).unwrap();
        assert!(xml.contains("<And><Prefix>parquet/</Prefix><Tag>"));
    }
    #[tokio::test]
    async fn native_configs_are_updated_removed_and_rolled_back_from_actual_backend_snapshot() {
        let registry = Arc::new(ServiceRegistry::new());
        locallycloud_s3::register(&registry);
        let provisioner = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-2".into(),
            "000000000000".into(),
        );
        provisioner
            .s3_bucket(
                "Logs",
                "review",
                &json!({"BucketName":"review-access-logs"}),
            )
            .await
            .unwrap();
        let properties = json!({"BucketName":"review-source", "LifecycleConfiguration":{"Rules":[{"Id":"expire","Status":"Enabled","ExpirationInDays":2}]},"OwnershipControls":{"Rules":[{"ObjectOwnership":"BucketOwnerEnforced"}]},"LoggingConfiguration":{"DestinationBucketName":"review-access-logs","LogFilePrefix":"access/"}});
        let resource = provisioner
            .s3_bucket("Source", "review", &properties)
            .await
            .unwrap();
        let get = |query: &str| format!("/review-source?{query}");
        for query in ["lifecycle", "ownershipControls", "logging"] {
            assert_eq!(
                provisioner
                    .call("s3", Method::GET, &get(query), path_host(), Bytes::new())
                    .await
                    .unwrap()
                    .0,
                200
            );
        }
        let out_of_band = lifecycle(
            "Source",
            &json!({"Rules":[{"Id":"manual","Status":"Enabled","ExpirationInDays":7}]}),
        )
        .unwrap();
        provisioner
            .put_s3_bucket_configuration(
                "Source",
                "review-source",
                "lifecycle",
                "PutBucketLifecycleConfiguration",
                out_of_band,
            )
            .await
            .unwrap();
        let mut changed = properties.clone();
        changed["LifecycleConfiguration"]["Rules"][0]["ExpirationInDays"] = json!(9);
        changed["LoggingConfiguration"]["DestinationBucketName"] = json!("missing-access-logs");
        assert!(provisioner
            .update_s3_bucket(
                "Source",
                &resource,
                &properties,
                &changed,
                Replacement::Update(ResourcePolicy::Delete)
            )
            .await
            .is_err());
        let restored = provisioner
            .call(
                "s3",
                Method::GET,
                &get("lifecycle"),
                path_host(),
                Bytes::new(),
            )
            .await
            .unwrap();
        let restored = String::from_utf8(restored.1.to_vec()).unwrap();
        assert!(restored.contains("<ID>manual</ID>"));
        assert!(restored.contains("<Days>7</Days>"));
        let removed = json!({"BucketName":"review-source"});
        provisioner
            .update_s3_bucket(
                "Source",
                &resource,
                &properties,
                &removed,
                Replacement::Update(ResourcePolicy::Delete),
            )
            .await
            .unwrap();
        for query in ["lifecycle", "ownershipControls"] {
            assert_eq!(
                provisioner
                    .call("s3", Method::GET, &get(query), path_host(), Bytes::new())
                    .await
                    .unwrap()
                    .0,
                404
            );
        }
        let logging = provisioner
            .call(
                "s3",
                Method::GET,
                &get("logging"),
                path_host(),
                Bytes::new(),
            )
            .await
            .unwrap();
        assert_eq!(logging.0, 200);
        assert!(!String::from_utf8(logging.1.to_vec())
            .unwrap()
            .contains("LoggingEnabled"));
        provisioner.delete_bucket("review-source").await.unwrap();
        provisioner
            .delete_bucket("review-access-logs")
            .await
            .unwrap();
    }
}
