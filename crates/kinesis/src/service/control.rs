use super::*;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(super) struct StreamModeDetails {
    pub stream_mode: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Identity {
    stream_name: Option<String>,
    #[serde(rename = "StreamARN", alias = "ResourceARN")]
    stream_arn: Option<String>,
}

impl Identity {
    fn name(&self, scope: &Scope) -> Result<String, KinesisError> {
        let from_arn = self
            .stream_arn
            .as_deref()
            .map(|arn| {
                let prefix = format!(
                    "arn:aws:kinesis:{}:{}:stream/",
                    scope.region, scope.account_id
                );
                arn.strip_prefix(&prefix)
                    .ok_or_else(|| stream_not_found(arn))
            })
            .transpose()?;
        let name = self.stream_name.as_deref().or(from_arn).ok_or_else(|| {
            KinesisError::InvalidArgument("StreamName or StreamARN is required".into())
        })?;
        validate_stream_name(name)?;
        if from_arn.is_some_and(|arn_name| name != arn_name) {
            return Err(KinesisError::InvalidArgument(
                "StreamName and StreamARN must identify the same stream".into(),
            ));
        }
        Ok(name.to_owned())
    }
}

pub(super) fn resolve_name(
    name: &str,
    arn: Option<&str>,
    scope: &Scope,
) -> Result<String, KinesisError> {
    Identity {
        stream_name: (!name.is_empty()).then(|| name.to_owned()),
        stream_arn: arn.map(str::to_owned),
    }
    .name(scope)
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct ListRequest {
    limit: Option<i64>,
    exclusive_start_stream_name: Option<String>,
    next_token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ListToken {
    operation: String,
    account: String,
    region: String,
    after: String,
    expires_at: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RetentionRequest {
    #[serde(flatten)]
    identity: Identity,
    retention_period_hours: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TagsRequest {
    #[serde(flatten)]
    identity: Identity,
    tags: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UntagRequest {
    #[serde(flatten)]
    identity: Identity,
    tag_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListTagsRequest {
    #[serde(flatten)]
    identity: Identity,
    limit: Option<i64>,
    exclusive_start_tag_key: Option<String>,
}

pub(super) fn validate_tags(tags: &BTreeMap<String, String>) -> Result<(), KinesisError> {
    let permitted = |c: char| c.is_alphanumeric() || c.is_whitespace() || "_.:/=+-@".contains(c);
    if tags.len() > 50
        || tags.iter().any(|(k, v)| {
            k.is_empty()
                || k.chars().count() > 128
                || v.chars().count() > 256
                || k.to_ascii_lowercase().starts_with("aws:")
                || !k.chars().all(permitted)
                || !v.chars().all(permitted)
        })
    {
        return Err(KinesisError::InvalidArgument(
            "Tags must have valid keys and values, with at most 50 tags per stream".into(),
        ));
    }
    Ok(())
}

fn summary(scope: &Scope, name: &str, stream: &Stream) -> Value {
    json!({
        "StreamName": name, "StreamARN": scope.stream_arn(name),
        "StreamStatus": "ACTIVE", "StreamCreationTimestamp": stream.created_at,
        "StreamModeDetails": {"StreamMode": "PROVISIONED"},
        "RetentionPeriodHours": stream.retention_hours,
        "OpenShardCount": stream.shards.len(), "ConsumerCount": 0,
        "MaxRecordSizeInKiB": 1024,
        "EncryptionType": "NONE", "EnhancedMonitoring": [{"ShardLevelMetrics": []}]
    })
}

impl KinesisHandler {
    pub(super) fn control(
        &self,
        operation: &str,
        body: &[u8],
        scope: &Scope,
    ) -> Result<Success, KinesisError> {
        match operation {
            "ListStreams" => self.list_streams(decode(body)?, scope),
            "DescribeStreamSummary" => {
                let identity: Identity = decode(body)?;
                let name = identity.name(scope)?;
                let store = self.lock_store()?;
                let stream = store
                    .streams
                    .get(&StreamKey::new(scope, &name))
                    .ok_or_else(|| stream_not_found(&name))?;
                Ok(Success::Json(
                    json!({"StreamDescriptionSummary": summary(scope,&name,stream)}),
                ))
            }
            "DescribeLimits" => {
                let _: BTreeMap<String, Value> = decode(body)?;
                let store = self.lock_store()?;
                let open: usize = store
                    .streams
                    .iter()
                    .filter(|(k, _)| k.scope == *scope)
                    .map(|(_, s)| s.shards.len())
                    .sum();
                Ok(Success::Json(
                    json!({"ShardLimit": MAX_SHARDS,"OpenShardCount": open,"OnDemandStreamCount": 0,"OnDemandStreamCountLimit": 0}),
                ))
            }
            "IncreaseStreamRetentionPeriod" | "DecreaseStreamRetentionPeriod" => {
                let request: RetentionRequest = decode(body)?;
                let name = request.identity.name(scope)?;
                let key = StreamKey::new(scope, &name);
                let mut store = self.lock_store()?;
                let stream = store
                    .streams
                    .get_mut(&key)
                    .ok_or_else(|| stream_not_found(&name))?;
                let hours = request.retention_period_hours;
                if !(24..=8760).contains(&hours)
                    || (operation.starts_with("Increase") && hours < stream.retention_hours)
                    || (operation.starts_with("Decrease") && hours > stream.retention_hours)
                {
                    return Err(KinesisError::InvalidArgument("RetentionPeriodHours must be between 24 and 8760 and match the requested direction".into()));
                }
                if let Some(p) = &self.persistence {
                    p.configure(&key, hours, &stream.tags)
                        .map_err(|_| KinesisError::Internal)?;
                }
                stream.retention_hours = hours;
                self.trim_expired(&mut store, now_epoch()?)?;
                Ok(Success::Empty)
            }
            "ListTagsForStream" | "ListTagsForResource" => {
                let request: ListTagsRequest = decode(body)?;
                let name = request.identity.name(scope)?;
                let limit = request.limit.unwrap_or(10);
                if !(1..=10).contains(&limit) {
                    return Err(KinesisError::InvalidArgument(
                        "Limit must be between 1 and 10".into(),
                    ));
                }
                let store = self.lock_store()?;
                let stream = store
                    .streams
                    .get(&StreamKey::new(scope, &name))
                    .ok_or_else(|| stream_not_found(&name))?;
                let tags: Vec<_> = stream
                    .tags
                    .iter()
                    .filter(|(k, _)| {
                        request
                            .exclusive_start_tag_key
                            .as_ref()
                            .is_none_or(|start| *k > start)
                    })
                    .collect();
                let count = if operation == "ListTagsForResource" {
                    tags.len()
                } else {
                    limit as usize
                };
                let mut value = json!({"Tags": tags.iter().take(count).map(|(k,v)| json!({"Key": k,"Value": v})).collect::<Vec<_>>()});
                if operation == "ListTagsForStream" {
                    value["HasMoreTags"] = json!(tags.len() > count);
                }
                Ok(Success::Json(value))
            }
            "AddTagsToStream" | "TagResource" | "RemoveTagsFromStream" | "UntagResource" => {
                let (identity, added, removed) =
                    if operation == "AddTagsToStream" || operation == "TagResource" {
                        let req: TagsRequest = decode(body)?;
                        if req.tags.is_empty() {
                            return Err(KinesisError::InvalidArgument(
                                "Tags must not be empty".into(),
                            ));
                        }
                        validate_tags(&req.tags)?;
                        (req.identity, req.tags, vec![])
                    } else {
                        let req: UntagRequest = decode(body)?;
                        if req.tag_keys.is_empty()
                            || req.tag_keys.len() > 50
                            || req
                                .tag_keys
                                .iter()
                                .any(|k| k.is_empty() || k.chars().count() > 128)
                        {
                            return Err(KinesisError::InvalidArgument(
                                "TagKeys must contain 1 to 50 valid keys".into(),
                            ));
                        }
                        (req.identity, BTreeMap::new(), req.tag_keys)
                    };
                let name = identity.name(scope)?;
                let key = StreamKey::new(scope, &name);
                let mut store = self.lock_store()?;
                let stream = store
                    .streams
                    .get_mut(&key)
                    .ok_or_else(|| stream_not_found(&name))?;
                let mut tags = stream.tags.clone();
                tags.extend(added);
                for key in removed {
                    tags.remove(&key);
                }
                validate_tags(&tags)?;
                if let Some(p) = &self.persistence {
                    p.configure(&key, stream.retention_hours, &tags)
                        .map_err(|_| KinesisError::Internal)?;
                }
                stream.tags = tags;
                Ok(Success::Empty)
            }
            _ => Err(KinesisError::UnknownOperation),
        }
    }

    fn list_streams(&self, request: ListRequest, scope: &Scope) -> Result<Success, KinesisError> {
        let limit = request.limit.unwrap_or(100);
        if !(1..=10000).contains(&limit) {
            return Err(KinesisError::InvalidArgument(
                "Limit must be between 1 and 10000".into(),
            ));
        }
        let limit = limit.min(100) as usize;
        let after = if let Some(token) = request.next_token {
            if request.exclusive_start_stream_name.is_some() {
                return Err(KinesisError::InvalidArgument(
                    "NextToken cannot be combined with ExclusiveStartStreamName".into(),
                ));
            }
            let token: ListToken = self
                .decode_token(&token)
                .map_err(|_| KinesisError::InvalidArgument("Invalid pagination token".into()))?;
            if token.operation != "ListStreams"
                || token.account != scope.account_id
                || token.region != scope.region
            {
                return Err(KinesisError::InvalidArgument(
                    "Invalid pagination token".into(),
                ));
            }
            if token.expires_at <= now_epoch_seconds()? {
                return Err(KinesisError::ExpiredNextToken);
            }
            Some(token.after)
        } else {
            request.exclusive_start_stream_name
        };
        if let Some(name) = &after {
            validate_stream_name(name)?;
        }
        let store = self.lock_store()?;
        let mut streams: Vec<_> = store
            .streams
            .iter()
            .filter(|(k, _)| k.scope == *scope && after.as_ref().is_none_or(|a| k.name > *a))
            .collect();
        streams.sort_unstable_by(|(a, _), (b, _)| a.name.cmp(&b.name));
        let more = streams.len() > limit;
        let page = &streams[..streams.len().min(limit)];
        let summaries: Vec<_> = page.iter().map(|(k,s)| json!({"StreamName": k.name,"StreamARN":scope.stream_arn(&k.name),"StreamStatus":"ACTIVE","StreamCreationTimestamp":s.created_at,"StreamModeDetails":{"StreamMode":"PROVISIONED"}})).collect();
        let mut value = json!({"StreamNames": page.iter().map(|(k,_)| &k.name).collect::<Vec<_>>(),"StreamSummaries":summaries,"HasMoreStreams":more});
        if more {
            value["NextToken"] = json!(self.encode_token(&ListToken {
                operation: "ListStreams".into(),
                account: scope.account_id.clone(),
                region: scope.region.clone(),
                after: page.last().unwrap().0.name.clone(),
                expires_at: now_epoch_seconds()?.saturating_add(300)
            })?);
        }
        Ok(Success::Json(value))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{create, put, scope};
    use super::*;

    fn call(
        handler: &KinesisHandler,
        operation: &str,
        input: Value,
        scope: &Scope,
    ) -> Result<Value, KinesisError> {
        match handler.control(operation, &serde_json::to_vec(&input).unwrap(), scope)? {
            Success::Json(value) => Ok(value),
            Success::Empty => Ok(json!({})),
        }
    }

    #[test]
    fn retention_tags_and_summary_survive_restart_and_reject_invalid_updates() {
        let root = std::env::temp_dir().join(format!("kinesis-control-{}", Uuid::new_v4()));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let handler = KinesisHandler::with_state(state.clone()).unwrap();
        create(&handler);
        put(&handler, b"record").unwrap();
        let arn = scope().stream_arn("events");
        call(
            &handler,
            "IncreaseStreamRetentionPeriod",
            json!({"StreamARN":arn,"RetentionPeriodHours":48}),
            &scope(),
        )
        .unwrap();
        call(
            &handler,
            "IncreaseStreamRetentionPeriod",
            json!({"StreamName":"events","RetentionPeriodHours":48}),
            &scope(),
        )
        .unwrap();
        call(
            &handler,
            "TagResource",
            json!({"ResourceARN":arn,"Tags":{"project":"orders","stage":"test"}}),
            &scope(),
        )
        .unwrap();
        call(
            &handler,
            "UntagResource",
            json!({"ResourceARN":arn,"TagKeys":["stage"]}),
            &scope(),
        )
        .unwrap();
        for hours in [23, 8761, 24] {
            assert!(matches!(
                call(
                    &handler,
                    "IncreaseStreamRetentionPeriod",
                    json!({"StreamName":"events","RetentionPeriodHours":hours}),
                    &scope()
                ),
                Err(KinesisError::InvalidArgument(_))
            ));
        }
        assert!(call(
            &handler,
            "DescribeStreamSummary",
            json!({"StreamName":"wrong","StreamARN":arn}),
            &scope()
        )
        .is_err());
        drop(handler);
        let handler = KinesisHandler::with_state(state).unwrap();
        let summary = call(
            &handler,
            "DescribeStreamSummary",
            json!({"StreamARN":arn}),
            &scope(),
        )
        .unwrap();
        assert_eq!(
            summary["StreamDescriptionSummary"]["RetentionPeriodHours"],
            48
        );
        assert_eq!(summary["StreamDescriptionSummary"]["OpenShardCount"], 1);
        assert_eq!(
            call(
                &handler,
                "ListTagsForResource",
                json!({"ResourceARN":arn}),
                &scope()
            )
            .unwrap()["Tags"],
            json!([{"Key":"project","Value":"orders"}])
        );
        handler
            .persistence
            .as_ref()
            .unwrap()
            .state
            .connection()
            .unwrap()
            .execute(
                "UPDATE kinesis_shard_records SET arrival_time=?1",
                [now_epoch().unwrap() - 30.0 * 3600.0],
            )
            .unwrap();
        {
            let mut store = handler.lock_store().unwrap();
            handler
                .trim_expired(&mut store, now_epoch().unwrap())
                .unwrap();
            let shard = &store.streams[&StreamKey::new(&scope(), "events")].shards[0];
            assert_eq!(shard.next_position - shard.first_position, 1);
        }
        call(
            &handler,
            "DecreaseStreamRetentionPeriod",
            json!({"StreamName":"events","RetentionPeriodHours":24}),
            &scope(),
        )
        .unwrap();
        assert_eq!(handler.lock_store().unwrap().buffered_bytes, 0);
        drop(handler);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stream_and_tag_pages_are_bounded_ordered_and_scope_bound() {
        let handler = KinesisHandler::new();
        for name in ["gamma", "alpha", "beta"] {
            handler
                .create_stream(
                    CreateStreamRequest {
                        stream_name: name.into(),
                        shard_count: 1,
                        ..Default::default()
                    },
                    &scope(),
                )
                .unwrap();
        }
        let first = call(&handler, "ListStreams", json!({"Limit":1}), &scope()).unwrap();
        assert_eq!(first["StreamNames"], json!(["alpha"]));
        let second = call(
            &handler,
            "ListStreams",
            json!({"Limit":1,"NextToken":first["NextToken"]}),
            &scope(),
        )
        .unwrap();
        assert_eq!(second["StreamNames"], json!(["beta"]));
        let other = Scope {
            region: "eu-west-1".into(),
            ..scope()
        };
        assert!(call(
            &handler,
            "ListStreams",
            json!({"NextToken":first["NextToken"]}),
            &other
        )
        .is_err());
        assert_eq!(
            call(&handler, "ListStreams", json!({}), &other).unwrap()["StreamNames"],
            json!([])
        );
        let token = handler
            .encode_token(&ListToken {
                operation: "ListStreams".into(),
                account: scope().account_id,
                region: scope().region,
                after: "alpha".into(),
                expires_at: 0,
            })
            .unwrap();
        assert!(matches!(
            call(
                &handler,
                "ListStreams",
                json!({"NextToken":token}),
                &scope()
            ),
            Err(KinesisError::ExpiredNextToken)
        ));
        for limit in [0, 10001] {
            assert!(call(&handler, "ListStreams", json!({"Limit":limit}), &scope()).is_err());
        }
        call(
            &handler,
            "AddTagsToStream",
            json!({"StreamName":"alpha","Tags":{"z":"last","a":"first"}}),
            &scope(),
        )
        .unwrap();
        let tags = call(
            &handler,
            "ListTagsForStream",
            json!({"StreamName":"alpha","Limit":1}),
            &scope(),
        )
        .unwrap();
        assert_eq!(tags["Tags"], json!([{"Key":"a","Value":"first"}]));
        assert_eq!(tags["HasMoreTags"], true);
        assert_eq!(
            call(
                &handler,
                "ListTagsForStream",
                json!({"StreamName":"alpha","ExclusiveStartTagKey":"a"}),
                &scope()
            )
            .unwrap()["Tags"],
            json!([{"Key":"z","Value":"last"}])
        );
        assert!(call(
            &handler,
            "DescribeStreamSummary",
            json!({"StreamARN":scope().stream_arn("alpha")}),
            &other
        )
        .is_err());
    }
}
