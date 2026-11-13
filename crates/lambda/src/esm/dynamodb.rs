use super::{dispatch_source_as, BatchSource, EsmStore, EventSourceMapping, SourceRecord};
use crate::model::FunctionStore;
use async_trait::async_trait;
use locallycloud_core::integration::authorization::ServiceRoleAuthorizationRequest;
use locallycloud_core::integration::identity::CallerIdentity;
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

const MAX_SHARDS: usize = 4096;

pub struct DynamoDbBatchSource {
    registry: Weak<ServiceRegistry>,
    store: Arc<EsmStore>,
    functions: Arc<FunctionStore>,
    mapping: EventSourceMapping,
    account: String,
    region: String,
    cursor: AtomicUsize,
}

impl DynamoDbBatchSource {
    pub fn new(
        registry: Weak<ServiceRegistry>,
        store: Arc<EsmStore>,
        functions: Arc<FunctionStore>,
        mapping: EventSourceMapping,
        account: &str,
        region: &str,
    ) -> Result<Self, String> {
        let parts: Vec<_> = mapping.event_source_arn.splitn(6, ':').collect();
        if parts.len() != 6
            || parts[2] != "dynamodb"
            || parts[3] != region
            || parts[4] != account
            || !parts[5].starts_with("table/")
            || !parts[5].contains("/stream/")
        {
            return Err("Invalid or cross-scope DynamoDB event source".into());
        }
        if !matches!(
            mapping.starting_position.as_deref(),
            Some("TRIM_HORIZON" | "LATEST")
        ) {
            return Err("Unsupported DynamoDB starting position".into());
        }
        Ok(Self {
            registry,
            store,
            functions,
            mapping,
            account: account.into(),
            region: region.into(),
            cursor: AtomicUsize::new(0),
        })
    }

    fn checkpoint_key(&self, shard: &str) -> String {
        json!([self.mapping.event_source_arn, shard]).to_string()
    }

    async fn dispatch(&self, action: &str, body: Value) -> Result<Value, String> {
        let registry = self
            .registry
            .upgrade()
            .ok_or("Service registry unavailable")?;
        let function_name = self
            .mapping
            .function_arn
            .split(":function:")
            .nth(1)
            .and_then(|name| name.split(':').next())
            .ok_or("Invalid function ARN")?;
        let role = self
            .functions
            .execution_role(&self.account, &self.region, function_name)
            .ok_or("FunctionUnavailable")?;
        registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .ok_or("IAM unavailable")?
            .authorize_service_role_execution(ServiceRoleAuthorizationRequest {
                source_arn: None,
                caller: RequestIdentity {
                    account_id: self.account.clone(),
                    access_key_id: None,
                    arn: None,
                },
                role_arn: role.clone(),
                service_principal: "lambda.amazonaws.com".into(),
                action: format!("dynamodb:{action}"),
                resource: self.mapping.event_source_arn.clone(),
            })
            .map_err(|_| "DynamoDB execution role is not authorized")?;
        dispatch_source_as(
            &self.registry,
            &self.account,
            &self.region,
            &format!("DynamoDBStreams_20120810.{action}"),
            body,
            CallerIdentity::AssumedRole {
                role_arn: role,
                session_name: "lambda-esm".into(),
            },
        )
        .await
    }

    async fn shards(&self) -> Result<Vec<Value>, String> {
        let mut result = Vec::new();
        let mut cursor = None;
        loop {
            let mut request = json!({"StreamArn":self.mapping.event_source_arn,"Limit":100});
            if let Some(cursor) = &cursor {
                request["ExclusiveStartShardId"] = json!(cursor);
            }
            let response = self.dispatch("DescribeStream", request).await?;
            let description = response
                .get("StreamDescription")
                .ok_or("Missing DynamoDB stream description")?;
            if description.get("StreamArn").and_then(Value::as_str)
                != Some(self.mapping.event_source_arn.as_str())
            {
                return Err("DynamoDB source stream was replaced".into());
            }
            let shards = description
                .get("Shards")
                .and_then(Value::as_array)
                .ok_or("Missing DynamoDB shards")?;
            if result.len().saturating_add(shards.len()) > MAX_SHARDS {
                return Err("DynamoDB shard discovery exceeds its bounded page budget".into());
            }
            result.extend(shards.iter().cloned());
            let Some(next) = description
                .get("LastEvaluatedShardId")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            else {
                break;
            };
            if cursor.as_deref() == Some(next) || shards.is_empty() {
                return Err("DynamoDB shard pagination did not advance".into());
            }
            cursor = Some(next.to_owned());
        }
        Ok(result)
    }

    /// Capture the initial frontier before mapping+checkpoints are committed together.
    pub async fn validate(&self) -> Result<Vec<(String, String)>, String> {
        let shards = self.shards().await?;
        let mut frontiers = vec![(self.checkpoint_key("$initialized"), String::new())];
        if self.mapping.starting_position.as_deref() != Some("LATEST") {
            return Ok(frontiers);
        }
        let registry = self
            .registry
            .upgrade()
            .ok_or("Service registry unavailable")?;
        let metadata = registry
            .dynamodb_streams_api(&ServiceName::new("streams.dynamodb"))
            .ok_or("DynamoDB starting-position metadata is unavailable")?;
        for shard in shards {
            let shard = shard
                .get("ShardId")
                .and_then(Value::as_str)
                .ok_or("Invalid DynamoDB shard")?;
            let response = self
                .dispatch(
                    "GetShardIterator",
                    json!({"StreamArn":self.mapping.event_source_arn,
                "ShardId":shard,"ShardIteratorType":"LATEST"}),
                )
                .await?;
            let iterator = response
                .get("ShardIterator")
                .and_then(Value::as_str)
                .ok_or("Missing DynamoDB iterator")?;
            let sequence = metadata
                .sequence_after_iterator(&self.account, &self.region, iterator)
                .await?;
            frontiers.push((self.checkpoint_key(shard), sequence));
        }
        Ok(frontiers)
    }

    fn parent_complete(&self, shard: &Value, shards: &[Value]) -> bool {
        let Some(parent) = shard.get("ParentShardId").and_then(Value::as_str) else {
            return true;
        };
        let Some(parent) = shards
            .iter()
            .find(|s| s.get("ShardId").and_then(Value::as_str) == Some(parent))
        else {
            return true;
        };
        let Some(end) = parent
            .get("SequenceNumberRange")
            .and_then(|r| r.get("EndingSequenceNumber"))
            .and_then(Value::as_str)
        else {
            return false;
        };
        let Some(id) = parent.get("ShardId").and_then(Value::as_str) else {
            return false;
        };
        self.store
            .checkpoints
            .get(&(self.mapping.uuid.clone(), self.checkpoint_key(id)))
            .and_then(|c| c.1.clone())
            .is_some_and(|sequence| sequence_at_least(&sequence, end))
    }
}

fn sequence_at_least(sequence: &str, end: &str) -> bool {
    if sequence.is_empty()
        || end.is_empty()
        || !sequence
            .bytes()
            .chain(end.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return false;
    }
    let sequence = sequence.trim_start_matches('0');
    let end = end.trim_start_matches('0');
    (sequence.len(), sequence) >= (end.len(), end)
}

#[async_trait]
impl BatchSource for DynamoDbBatchSource {
    async fn poll(&self, max: u32, window: Duration) -> Result<Vec<SourceRecord>, String> {
        if max == 0 {
            return Ok(Vec::new());
        }
        if self.mapping.starting_position.as_deref() == Some("LATEST")
            && !self.store.checkpoints.contains_key(&(
                self.mapping.uuid.clone(),
                self.checkpoint_key("$initialized"),
            ))
        {
            return Err(
                "DynamoDB starting frontier unavailable; recreate the event source mapping".into(),
            );
        }
        let shards = self.shards().await?;
        let eligible: Vec<_> = shards
            .iter()
            .filter(|s| self.parent_complete(s, &shards))
            .collect();
        if eligible.is_empty() {
            return Ok(Vec::new());
        }
        let shard = eligible[self.cursor.fetch_add(1, Ordering::Relaxed) % eligible.len()]
            .get("ShardId")
            .and_then(Value::as_str)
            .ok_or("Invalid DynamoDB shard")?;
        let key = self.checkpoint_key(shard);
        let store = self.store.clone();
        let uuid = self.mapping.uuid.clone();
        let checkpoint_key = key.clone();
        let checkpoint =
            tokio::task::spawn_blocking(move || store.prepare_shard(&uuid, &checkpoint_key, 0.0))
                .await
                .map_err(|_| "DynamoDB checkpoint task failed")??;
        let mut request = json!({"StreamArn":self.mapping.event_source_arn,"ShardId":shard,"ShardIteratorType":"TRIM_HORIZON"});
        if let Some(sequence) = checkpoint.filter(|s| !s.is_empty()) {
            request["ShardIteratorType"] = json!("AFTER_SEQUENCE_NUMBER");
            request["SequenceNumber"] = json!(sequence);
        }
        let response = self.dispatch("GetShardIterator", request).await?;
        let mut iterator = response
            .get("ShardIterator")
            .and_then(Value::as_str)
            .ok_or("Missing DynamoDB iterator")?
            .to_owned();
        let deadline = tokio::time::Instant::now() + window;
        let mut result = Vec::new();
        let mut bytes = 0;
        loop {
            let response = self
                .dispatch(
                    "GetRecords",
                    json!({"ShardIterator":iterator,"Limit":(max-result.len() as u32).min(1000)}),
                )
                .await?;
            let records = response
                .get("Records")
                .and_then(Value::as_array)
                .ok_or("Invalid DynamoDB records")?;
            if records.len() > (max as usize - result.len()).min(1000) {
                return Err("DynamoDB returned more records than requested".into());
            }
            let mut full = false;
            for record in records {
                let sequence = record
                    .get("dynamodb")
                    .and_then(|d| d.get("SequenceNumber"))
                    .and_then(Value::as_str)
                    .ok_or("Invalid DynamoDB sequence")?;
                if sequence.is_empty() || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err("Invalid DynamoDB sequence".into());
                }
                bytes += record.to_string().len() + self.mapping.event_source_arn.len() + 64;
                if bytes > 6 * 1024 * 1024 - 16 * 1024 {
                    full = true;
                    break;
                }
                result.push(SourceRecord {
                    item_identifier: sequence.into(),
                    ack_token: json!([key, sequence]).to_string(),
                    body: record.clone(),
                });
            }
            if full
                || result.len() >= max as usize
                || records.is_empty()
                || tokio::time::Instant::now() >= deadline
            {
                break;
            }
            let Some(next) = response.get("NextShardIterator").and_then(Value::as_str) else {
                break;
            };
            iterator = next.into();
            tokio::time::sleep_until(
                (tokio::time::Instant::now() + Duration::from_millis(200)).min(deadline),
            )
            .await;
        }
        Ok(result)
    }

    async fn ack(&self, tokens: &[String]) -> Result<(), String> {
        let mut last = None;
        for token in tokens {
            let (key, sequence): (String, String) =
                serde_json::from_str(token).map_err(|_| "Invalid DynamoDB acknowledgement")?;
            if last.as_ref().is_some_and(|(previous, _)| previous != &key) {
                return Err("DynamoDB batch crosses shard boundaries".into());
            }
            last = Some((key, sequence));
        }
        if let Some((key, sequence)) = last {
            let store = self.store.clone();
            let uuid = self.mapping.uuid.clone();
            tokio::task::spawn_blocking(move || {
                store.save_checkpoint(&uuid, &key, 0.0, Some(sequence))
            })
            .await
            .map_err(|_| "DynamoDB checkpoint task failed")??;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{create_mapping, dispatch_source, poll_once};
    use super::*;

    #[test]
    fn concurrent_mapping_creates_publish_only_one_initial_frontier() {
        let store = Arc::new(EsmStore::new());
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for sequence in ["1", "2"] {
            let store = store.clone();
            let barrier = barrier.clone();
            let mapping = create_mapping("us-east-1", "arn:aws:lambda:us-east-1:000000000000:function:sink", &json!({
                "EventSourceArn":"arn:aws:dynamodb:us-east-1:000000000000:table/source/stream/1",
                "StartingPosition":"LATEST"
            })).unwrap();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.insert_with_stream_frontiers(mapping, vec![("shard".into(), sequence.into())])
            }));
        }
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(crate::error::LambdaError::ResourceConflict(_))
                ))
                .count(),
            1
        );
        assert_eq!(store.mappings.len(), 1);
        assert_eq!(store.checkpoints.len(), 1);
    }
    use locallycloud_core::handler::{NativeHandler, ServiceRequest};
    use locallycloud_core::integration::authorization::{
        AuthorizationError, AuthorizationEvaluator, AuthorizationRequest,
    };
    use locallycloud_core::integration::InternalDispatcher;
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};
    use locallycloud_state::StateDb;
    use std::sync::atomic::AtomicBool;

    struct Authorization(AtomicBool);
    impl AuthorizationEvaluator for Authorization {
        fn authorize(&self, _: AuthorizationRequest) -> Result<(), AuthorizationError> {
            Ok(())
        }
        fn authorize_service_role_execution(
            &self,
            request: ServiceRoleAuthorizationRequest,
        ) -> Result<(), AuthorizationError> {
            assert_eq!(request.service_principal, "lambda.amazonaws.com");
            assert!(request.source_arn.is_none());
            assert!(request
                .resource
                .starts_with("arn:aws:dynamodb:us-east-1:000000000000:table/"));
            if self.0.load(Ordering::Relaxed) {
                Ok(())
            } else {
                Err(AuthorizationError::Denied)
            }
        }
    }
    #[async_trait]
    impl NativeHandler for Authorization {
        async fn handle(&self, _: ServiceRequest) -> axum::response::Response {
            http::Response::new(axum::body::Body::empty())
        }
    }

    fn zip() -> String {
        use base64::Engine;
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file("app.py", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(b"def handler(event, context): return {}\n")
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(writer.finish().unwrap().into_inner())
    }

    async fn data(registry: &Arc<ServiceRegistry>, operation: &str, body: Value) -> Value {
        dispatch_source(
            &Arc::downgrade(registry),
            "000000000000",
            "us-east-1",
            &format!("DynamoDB_20120810.{operation}"),
            body,
        )
        .await
        .unwrap()
    }

    fn source(
        registry: &Arc<ServiceRegistry>,
        store: Arc<EsmStore>,
        functions: Arc<FunctionStore>,
        mapping: EventSourceMapping,
    ) -> DynamoDbBatchSource {
        DynamoDbBatchSource::new(
            Arc::downgrade(registry),
            store,
            functions,
            mapping,
            "000000000000",
            "us-east-1",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn latest_frontier_partial_failures_and_role_revocation_survive_restart() {
        let root = std::env::temp_dir().join(format!(
            "lambda-dynamodb-checkpoint-{}",
            uuid::Uuid::new_v4()
        ));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let registry = ServiceRegistry::with_known_services();
        locallycloud_dynamodb::register(&registry);
        let authorization = Arc::new(Authorization(AtomicBool::new(true)));
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            authorization.clone(),
            authorization.clone(),
        );
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        )));
        let functions = Arc::new(FunctionStore::new());
        crate::control_plane::create_function(&functions,"us-east-1","000000000000",&json!({"FunctionName":"consumer","Runtime":"python3.13","Handler":"app.handler","Role":"arn:aws:iam::000000000000:role/consumer","Code":{"ZipFile":zip()}}),None).unwrap();
        let table=data(&registry,"CreateTable",json!({"TableName":"events","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST","StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_AND_OLD_IMAGES"}})).await;
        let arn = table["TableDescription"]["LatestStreamArn"]
            .as_str()
            .unwrap();
        data(
            &registry,
            "PutItem",
            json!({"TableName":"events","Item":{"pk":{"S":"old"}}}),
        )
        .await;
        let mapping=create_mapping("us-east-1","arn:aws:lambda:us-east-1:000000000000:function:consumer",&json!({"EventSourceArn":arn,"StartingPosition":"LATEST","BatchSize":3,"FunctionResponseTypes":["ReportBatchItemFailures"]})).unwrap();
        let store = Arc::new(EsmStore::new());
        store.attach_state(state.clone()).unwrap();
        let initial = source(&registry, store.clone(), functions.clone(), mapping.clone());
        let frontiers = initial.validate().await.unwrap();
        store
            .insert_with_stream_frontiers(mapping.clone(), frontiers)
            .unwrap();
        drop(initial);
        for value in ["a", "b", "c"] {
            data(
                &registry,
                "PutItem",
                json!({"TableName":"events","Item":{"pk":{"S":value}}}),
            )
            .await;
        }
        let current = Arc::new(source(
            &registry,
            store.clone(),
            functions.clone(),
            mapping.clone(),
        )) as Arc<dyn BatchSource>;
        poll_once(&mapping,&current,|event|async move {
            let records=event["Records"].as_array().unwrap();assert_eq!(records.len(),3);
            assert_eq!(records[0]["dynamodb"]["NewImage"]["pk"]["S"],"a");
            assert_eq!(records[0]["eventSourceARN"],arn);
            Some(json!({"batchItemFailures":[{"itemIdentifier":records[1]["dynamodb"]["SequenceNumber"]}]}).to_string().into_bytes())
        }).await.unwrap();
        drop(current);
        drop(store);
        let store = Arc::new(EsmStore::new());
        store.attach_state(state.clone()).unwrap();
        let current = Arc::new(source(
            &registry,
            store.clone(),
            functions.clone(),
            mapping.clone(),
        )) as Arc<dyn BatchSource>;
        poll_once(&mapping, &current, |event| async move {
            let records = event["Records"].as_array().unwrap();
            assert_eq!(records.len(), 2);
            assert_eq!(records[0]["dynamodb"]["NewImage"]["pk"]["S"], "b");
            assert_eq!(records[1]["dynamodb"]["NewImage"]["pk"]["S"], "c");
            Some(b"{}".to_vec())
        })
        .await
        .unwrap();
        authorization.0.store(false, Ordering::Relaxed);
        assert!(current.poll(3, Duration::ZERO).await.is_err());
        authorization.0.store(true, Ordering::Relaxed);
        assert!(current.poll(3, Duration::ZERO).await.unwrap().is_empty());
        store.remove(&mapping.uuid).unwrap();
        assert!(store.checkpoints.is_empty());
        drop(current);
        drop(store);
        let empty_table=data(&registry,"CreateTable",json!({"TableName":"empty-events","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST","StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_IMAGE"}})).await;
        let empty_arn = empty_table["TableDescription"]["LatestStreamArn"]
            .as_str()
            .unwrap();
        let empty_mapping = create_mapping(
            "us-east-1",
            "arn:aws:lambda:us-east-1:000000000000:function:consumer",
            &json!({"EventSourceArn":empty_arn,"StartingPosition":"LATEST"}),
        )
        .unwrap();
        let store = Arc::new(EsmStore::new());
        store.attach_state(state.clone()).unwrap();
        let empty_source = source(
            &registry,
            store.clone(),
            functions.clone(),
            empty_mapping.clone(),
        );
        let frontiers = empty_source.validate().await.unwrap();
        store
            .insert_with_stream_frontiers(empty_mapping.clone(), frontiers)
            .unwrap();
        assert!(empty_source
            .poll(3, Duration::ZERO)
            .await
            .unwrap()
            .is_empty());
        drop(empty_source);
        drop(store);
        let store = Arc::new(EsmStore::new());
        store.attach_state(state.clone()).unwrap();
        data(
            &registry,
            "PutItem",
            json!({"TableName":"empty-events","Item":{"pk":{"S":"after-restart"}}}),
        )
        .await;
        let empty_source = source(&registry, store.clone(), functions, empty_mapping.clone());
        let records = empty_source.poll(3, Duration::ZERO).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].body["dynamodb"]["NewImage"]["pk"]["S"],
            "after-restart"
        );
        drop(empty_source);
        drop(store);
        drop(state);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sequence_order_uses_decimal_precision_without_integer_limits() {
        assert!(sequence_at_least(
            "0001000000000000000000000000000000000",
            "999999999999999999999999999999999"
        ));
        assert!(!sequence_at_least("99", "100"));
        assert!(!sequence_at_least("invalid", "100"));
    }

    #[test]
    fn child_shards_wait_for_the_parent_contiguous_checkpoint() {
        let store = Arc::new(EsmStore::new());
        let mapping=create_mapping("us-east-1","arn:aws:lambda:us-east-1:000000000000:function:consumer",&json!({"EventSourceArn":"arn:aws:dynamodb:us-east-1:000000000000:table/events/stream/1","StartingPosition":"TRIM_HORIZON"})).unwrap();
        let source = DynamoDbBatchSource::new(
            Weak::new(),
            store.clone(),
            Arc::new(FunctionStore::new()),
            mapping.clone(),
            "000000000000",
            "us-east-1",
        )
        .unwrap();
        let shards = vec![
            json!({"ShardId":"parent","SequenceNumberRange":{"EndingSequenceNumber":"10"}}),
            json!({"ShardId":"child","ParentShardId":"parent"}),
        ];
        assert!(!source.parent_complete(&shards[1], &shards));
        store
            .save_checkpoint(
                &mapping.uuid,
                &source.checkpoint_key("parent"),
                0.0,
                Some("9".into()),
            )
            .unwrap();
        assert!(!source.parent_complete(&shards[1], &shards));
        store
            .save_checkpoint(
                &mapping.uuid,
                &source.checkpoint_key("parent"),
                0.0,
                Some("10".into()),
            )
            .unwrap();
        assert!(source.parent_complete(&shards[1], &shards));
    }

    #[test]
    fn failed_frontier_transaction_leaves_no_mapping_or_checkpoint() {
        let root =
            std::env::temp_dir().join(format!("lambda-dynamodb-frontier-{}", uuid::Uuid::new_v4()));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let store = EsmStore::new();
        store.attach_state(state.clone()).unwrap();
        let mapping=create_mapping("us-east-1","arn:aws:lambda:us-east-1:000000000000:function:consumer",&json!({"EventSourceArn":"arn:aws:dynamodb:us-east-1:000000000000:table/events/stream/1","StartingPosition":"LATEST"})).unwrap();
        assert!(store
            .insert_with_stream_frontiers(
                mapping.clone(),
                vec![
                    ("duplicate".into(), "1".into()),
                    ("duplicate".into(), "2".into())
                ]
            )
            .is_err());
        assert!(store.get(&mapping.uuid).is_none());
        assert!(store.checkpoints.is_empty());
        let restored = EsmStore::new();
        restored.attach_state(state.clone()).unwrap();
        assert!(restored.get(&mapping.uuid).is_none());
        assert!(restored.checkpoints.is_empty());
        // Reuse the same connection after rollback; failed frontiers must not advance it.
        store
            .insert_with_stream_frontiers(mapping.clone(), vec![("shard".into(), "10".into())])
            .unwrap();
        store
            .save_checkpoint(&mapping.uuid, "shard", 0.0, Some("20".into()))
            .unwrap();
        let recovered = EsmStore::new();
        recovered.attach_state(state.clone()).unwrap();
        assert!(recovered.get(&mapping.uuid).is_some());
        assert_eq!(
            recovered
                .prepare_shard(&mapping.uuid, "shard", 0.0)
                .unwrap()
                .as_deref(),
            Some("20")
        );
        recovered.remove(&mapping.uuid).unwrap();
        let cleared = EsmStore::new();
        cleared.attach_state(state.clone()).unwrap();
        assert!(cleared.get(&mapping.uuid).is_none());
        assert!(cleared.checkpoints.is_empty());
        drop((recovered, cleared));
        drop(restored);
        drop(store);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }
}
