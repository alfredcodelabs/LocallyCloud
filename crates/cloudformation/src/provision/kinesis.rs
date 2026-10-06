use super::*;

impl Provisioner {
    pub(super) async fn kinesis_stream(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let (shards, hours, tags) = stream_properties(logical_id, props)?;
        let name = props
            .get("Name")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| generate_name(stack_name, logical_id, 128));
        self.call_kinesis(
            "CreateStream",
            json!({"StreamName":name,"ShardCount":shards,"Tags":tags}),
            logical_id,
        )
        .await?;
        let result = async {
            if hours != 24 {
                self.call_kinesis(
                    "IncreaseStreamRetentionPeriod",
                    json!({"StreamName":name,"RetentionPeriodHours":hours}),
                    logical_id,
                )
                .await?;
            }
            let actual = self
                .call_kinesis(
                    "DescribeStreamSummary",
                    json!({"StreamName":name}),
                    logical_id,
                )
                .await?;
            let arn = required_response_string(
                &actual["StreamDescriptionSummary"],
                "StreamARN",
                logical_id,
            )?;
            Ok(ResolvedResource {
                ref_value: name.clone(),
                attributes: std::collections::BTreeMap::from([("Arn".into(), arn)]),
            })
        }
        .await;
        if result.is_err() {
            // The resource was created before its retention/readback failed; do not orphan it.
            self.delete_kinesis_stream(&name).await?;
        }
        result
    }

    pub(super) async fn update_kinesis_stream(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let (old_shards, old_hours, old_tags) = stream_properties(logical_id, previous)?;
        let (shards, hours, tags) = stream_properties(logical_id, props)?;
        if previous.get("Name") != props.get("Name") || old_shards != shards {
            return Err(CfnError::ResourceFailed(format!("AWS::Kinesis::Stream {logical_id} Name replacement and shard-count updates are not supported by the native backend")));
        }
        let name = &current.ref_value;
        // The failing resource never reaches the stack's completed-update journal. Compensate
        // successful native steps here, using actual prior state rather than template defaults.
        let mut steps = Vec::new();
        if old_hours != hours {
            let summary = self
                .call_kinesis(
                    "DescribeStreamSummary",
                    json!({"StreamName":name}),
                    logical_id,
                )
                .await?;
            let actual_hours = summary["StreamDescriptionSummary"]["RetentionPeriodHours"]
                .as_u64()
                .ok_or(CfnError::Internal)?;
            if actual_hours != hours {
                let operation = if hours > actual_hours {
                    "IncreaseStreamRetentionPeriod"
                } else {
                    "DecreaseStreamRetentionPeriod"
                };
                let undo = if hours > actual_hours {
                    "DecreaseStreamRetentionPeriod"
                } else {
                    "IncreaseStreamRetentionPeriod"
                };
                steps.push((
                    operation,
                    json!({"StreamName":name,"RetentionPeriodHours":hours}),
                    undo,
                    json!({"StreamName":name,"RetentionPeriodHours":actual_hours}),
                ));
            }
        }
        if old_tags != tags {
            let actual_tags = self.kinesis_stream_tags(name, logical_id).await?;
            let removed: serde_json::Map<String, Value> = old_tags
                .keys()
                .filter(|key| !tags.contains_key(*key))
                .filter_map(|key| {
                    actual_tags
                        .get(key)
                        .map(|value| (key.clone(), value.clone()))
                })
                .collect();
            if !removed.is_empty() {
                steps.push((
                    "RemoveTagsFromStream",
                    json!({"StreamName":name,"TagKeys":removed.keys().collect::<Vec<_>>()}),
                    "AddTagsToStream",
                    json!({"StreamName":name,"Tags":removed}),
                ));
            }
            let changed: serde_json::Map<String, Value> = tags
                .into_iter()
                .filter(|(key, value)| actual_tags.get(key) != Some(value))
                .collect();
            if !changed.is_empty() {
                // Last step: no successful later operation can require compensation of this write.
                steps.push((
                    "AddTagsToStream",
                    json!({"StreamName":name,"Tags":changed}),
                    "",
                    Value::Null,
                ));
            }
        }
        let mut completed = Vec::new();
        for (operation, body, undo, undo_body) in steps {
            match self.call_kinesis(operation, body, logical_id).await {
                Ok(_) => completed.push((undo, undo_body)),
                Err(original) => {
                    let mut failures = Vec::new();
                    for (undo, body) in completed.into_iter().rev() {
                        if let Err(error) = self.call_kinesis(undo, body, logical_id).await {
                            failures.push(error.to_string());
                        }
                    }
                    return if failures.is_empty() {
                        Err(original)
                    } else {
                        Err(CfnError::ResourceFailed(format!(
                            "{original}; Kinesis update rollback failed: {}",
                            failures.join("; ")
                        )))
                    };
                }
            }
        }
        Ok(current.clone())
    }

    async fn kinesis_stream_tags(
        &self,
        name: &str,
        logical_id: &str,
    ) -> Result<serde_json::Map<String, Value>, CfnError> {
        let mut request = json!({"StreamName":name,"Limit":10});
        let mut tags = serde_json::Map::new();
        loop {
            let page = self
                .call_kinesis("ListTagsForStream", request.clone(), logical_id)
                .await?;
            tags.extend(cfn_tags_object(&page));
            if page["HasMoreTags"] != true {
                return Ok(tags);
            }
            let last = page["Tags"]
                .as_array()
                .and_then(|v| v.last())
                .and_then(|v| v["Key"].as_str())
                .ok_or(CfnError::Internal)?;
            if request
                .get("ExclusiveStartTagKey")
                .and_then(Value::as_str)
                .is_some_and(|previous| last <= previous)
            {
                return Err(CfnError::Internal);
            }
            request["ExclusiveStartTagKey"] = json!(last);
        }
    }

    async fn call_kinesis(
        &self,
        operation: &str,
        body: Value,
        logical_id: &str,
    ) -> Result<Value, CfnError> {
        self.call_aws_json_11(
            "kinesis",
            &format!("Kinesis_20131202.{operation}"),
            body,
            logical_id,
        )
        .await
    }

    pub(super) async fn delete_kinesis_stream(&self, name: &str) -> Result<(), CfnError> {
        self.delete_aws_json_11(
            "kinesis",
            "Kinesis_20131202.DeleteStream",
            json!({"StreamName":name}),
            name,
            &["ResourceNotFoundException"],
        )
        .await
    }
}

fn stream_properties(
    logical_id: &str,
    props: &Value,
) -> Result<(u64, u64, serde_json::Map<String, Value>), CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::Kinesis::Stream",
        props,
        &["Name", "ShardCount", "RetentionPeriodHours", "Tags"],
    )?;
    let invalid = |property: &str| {
        CfnError::ResourceFailed(format!(
            "AWS::Kinesis::Stream {logical_id} has invalid {property}"
        ))
    };
    if let Some(name) = props.get("Name") {
        let name = name.as_str().ok_or_else(|| invalid("Name"))?;
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        {
            return Err(invalid("Name"));
        }
    }
    let shards = props
        .get("ShardCount")
        .and_then(Value::as_u64)
        .filter(|n| (1..=128).contains(n))
        .ok_or_else(|| invalid("ShardCount"))?;
    let hours = match props.get("RetentionPeriodHours") {
        None => 24,
        Some(v) => v
            .as_u64()
            .filter(|n| (24..=8760).contains(n))
            .ok_or_else(|| invalid("RetentionPeriodHours"))?,
    };
    let mut tags = serde_json::Map::new();
    if let Some(value) = props.get("Tags") {
        let values = value
            .as_array()
            .filter(|v| v.len() <= 50)
            .ok_or_else(|| invalid("Tags"))?;
        for value in values {
            let object = value
                .as_object()
                .filter(|v| v.len() == 2)
                .ok_or_else(|| invalid("Tags"))?;
            let key = object
                .get("Key")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Tags.Key"))?;
            let val = object
                .get("Value")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Tags.Value"))?;
            let permitted =
                |c: char| c.is_alphanumeric() || c.is_whitespace() || "_.:/=+-@".contains(c);
            if key.is_empty()
                || key.chars().count() > 128
                || val.chars().count() > 256
                || key.to_ascii_lowercase().starts_with("aws:")
                || !key.chars().all(permitted)
                || !val.chars().all(permitted)
                || tags.insert(key.into(), json!(val)).is_some()
            {
                return Err(invalid("Tags"));
            }
        }
    }
    Ok((shards, hours, tags))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn failed_stream_update_compensates_completed_steps_or_reports_rollback_failure() {
        use locallycloud_core::handler::NativeHandler;
        use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};
        use std::{collections::VecDeque, sync::Mutex};
        struct FailCalls {
            native: Arc<dyn NativeHandler>,
            failures: Mutex<VecDeque<&'static str>>,
        }
        #[async_trait::async_trait]
        impl NativeHandler for FailCalls {
            async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
                let operation = request
                    .headers
                    .get("x-amz-target")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .rsplit('.')
                    .next()
                    .unwrap_or("");
                let failed = {
                    let mut failures = self.failures.lock().unwrap();
                    if failures.front().copied() == Some(operation) {
                        failures.pop_front();
                        true
                    } else {
                        false
                    }
                };
                if failed {
                    return http::Response::builder()
                        .status(403)
                        .body(axum::body::Body::from(
                            r#"{"__type":"AccessDeniedException","message":"injected denial"}"#,
                        ))
                        .unwrap();
                }
                self.native.handle(request).await
            }
        }
        for (failures, rollback_failed) in [
            (vec!["RemoveTagsFromStream"], false),
            (vec!["AddTagsToStream"], false),
            (vec!["AddTagsToStream", "AddTagsToStream"], true),
        ] {
            let registry = Arc::new(ServiceRegistry::new());
            locallycloud_kinesis::register(&registry);
            let wrapper = Arc::new(FailCalls {
                native: registry
                    .native_handler(&ServiceName::new("kinesis"))
                    .unwrap(),
                failures: Mutex::new(VecDeque::new()),
            });
            registry.register_native(
                ServiceName::new("kinesis"),
                ServiceMetadata::new(AwsProtocol::Json11, Some("Kinesis_20131202")),
                wrapper.clone(),
            );
            let p = Provisioner::new(
                Arc::downgrade(&registry),
                "us-west-2".into(),
                "123456789012".into(),
            );
            let previous_tags: Vec<_> = (0..12)
                .map(|i| json!({"Key":format!("key-{i:02}"),"Value":"dev"}))
                .collect();
            let old = json!({"Name":"ledger","ShardCount":2,"RetentionPeriodHours":48,"Tags":previous_tags});
            let new = json!({"Name":"ledger","ShardCount":2,"RetentionPeriodHours":72,"Tags":[{"Key":"team","Value":"data"}]});
            let stream = p.kinesis_stream("Stream", "stack", &old).await.unwrap();
            *wrapper.failures.lock().unwrap() = failures.into();
            let error = p
                .update_kinesis_stream("Stream", &stream, &old, &new)
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("injected denial"));
            assert_eq!(error.contains("rollback failed"), rollback_failed);
            assert!(wrapper.failures.lock().unwrap().is_empty());
            let summary = p
                .call_kinesis(
                    "DescribeStreamSummary",
                    json!({"StreamName":"ledger"}),
                    "Stream",
                )
                .await
                .unwrap();
            assert_eq!(
                summary["StreamDescriptionSummary"]["RetentionPeriodHours"],
                48
            );
            let tags = p.kinesis_stream_tags("ledger", "Stream").await.unwrap();
            assert_eq!(
                tags,
                if rollback_failed {
                    serde_json::Map::new()
                } else {
                    cfn_tags_object(&old)
                }
            );
        }
    }

    #[tokio::test]
    async fn stream_native_lifecycle_scopes_attributes_and_rejects_unsupported_updates() {
        let registry = Arc::new(ServiceRegistry::new());
        locallycloud_kinesis::register(&registry);
        let p = Provisioner::new(
            Arc::downgrade(&registry),
            "us-west-2".into(),
            "123456789012".into(),
        );
        let props = json!({"Name":"ledger","ShardCount":2,"RetentionPeriodHours":48,"Tags":[{"Key":"env","Value":"dev"}]});
        let stream = p
            .provision("Stream", "stack", "AWS::Kinesis::Stream", &props)
            .await
            .unwrap();
        assert_eq!(stream.ref_value, "ledger");
        assert_eq!(
            stream.attributes["Arn"],
            "arn:aws:kinesis:us-west-2:123456789012:stream/ledger"
        );
        let actual = p
            .call_kinesis(
                "DescribeStreamSummary",
                json!({"StreamName":"ledger"}),
                "Stream",
            )
            .await
            .unwrap();
        assert_eq!(actual["StreamDescriptionSummary"]["OpenShardCount"], 2);
        assert_eq!(
            actual["StreamDescriptionSummary"]["RetentionPeriodHours"],
            48
        );
        let replacement = Replacement::Update(ResourcePolicy::Delete);
        let unchanged = p
            .update(
                "Stream",
                "AWS::Kinesis::Stream",
                &stream,
                &props,
                &props,
                replacement,
            )
            .await
            .unwrap();
        assert_eq!(unchanged.ref_value, stream.ref_value);
        let updated =
            json!({"Name":"ledger","ShardCount":2,"Tags":[{"Key":"team","Value":"data"}]});
        p.update(
            "Stream",
            "AWS::Kinesis::Stream",
            &stream,
            &props,
            &updated,
            replacement,
        )
        .await
        .unwrap();
        let tags = p
            .call_kinesis(
                "ListTagsForStream",
                json!({"StreamName":"ledger"}),
                "Stream",
            )
            .await
            .unwrap();
        assert_eq!(tags["Tags"], json!([{"Key":"team","Value":"data"}]));
        let mut invalid = updated.clone();
        invalid["ShardCount"] = json!(3);
        assert!(p
            .update(
                "Stream",
                "AWS::Kinesis::Stream",
                &stream,
                &updated,
                &invalid,
                replacement
            )
            .await
            .is_err());
        invalid["StreamEncryption"] = json!({"EncryptionType":"KMS","KeyId":"key"});
        assert!(p
            .provision("Unsupported", "stack", "AWS::Kinesis::Stream", &invalid)
            .await
            .is_err());
        let other = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "123456789012".into(),
        );
        assert!(other
            .call_kinesis(
                "DescribeStreamSummary",
                json!({"StreamName":"ledger"}),
                "Stream"
            )
            .await
            .is_err());
        p.delete_kinesis_stream(&stream.ref_value).await.unwrap();
        p.delete_kinesis_stream(&stream.ref_value).await.unwrap();
        assert!(p
            .call_kinesis(
                "DescribeStreamSummary",
                json!({"StreamName":"ledger"}),
                "Stream"
            )
            .await
            .is_err());
    }
}
