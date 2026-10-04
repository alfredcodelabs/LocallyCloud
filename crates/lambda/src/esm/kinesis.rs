use super::{dispatch_source, BatchSource, EsmStore, EventSourceMapping, SourceRecord};
use crate::model::FunctionStore;
use async_trait::async_trait;
use locallycloud_core::integration::authorization::ServiceRoleAuthorizationRequest;
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

pub struct KinesisBatchSource {
    registry: Weak<ServiceRegistry>,
    store: Arc<EsmStore>,
    functions: Arc<FunctionStore>,
    mapping: EventSourceMapping,
    account: String,
    region: String,
    name: String,
    cursor: AtomicUsize,
}
impl KinesisBatchSource {
    pub fn new(
        registry: Weak<ServiceRegistry>,
        store: Arc<EsmStore>,
        functions: Arc<FunctionStore>,
        mapping: EventSourceMapping,
        account: &str,
        region: &str,
    ) -> Result<Self, String> {
        let parts: Vec<_> = mapping.event_source_arn.split(':').collect();
        if parts.len() != 6 || parts[2] != "kinesis" || parts[3] != region || parts[4] != account {
            return Err("Invalid or cross-scope Kinesis event source".into());
        }
        let name = parts[5]
            .strip_prefix("stream/")
            .filter(|value| !value.is_empty())
            .ok_or("Invalid Kinesis stream ARN")?
            .to_string();
        if !matches!(
            mapping.starting_position.as_deref(),
            Some("TRIM_HORIZON" | "LATEST")
        ) {
            return Err("Unsupported Kinesis starting position".into());
        }
        Ok(Self {
            registry,
            store,
            functions,
            mapping,
            account: account.into(),
            region: region.into(),
            name,
            cursor: AtomicUsize::new(0),
        })
    }
    pub async fn validate(&self) -> Result<(), String> {
        self.dispatch("DescribeStream", json!({"StreamName":self.name}))
            .await?;
        Ok(())
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
        let function = self
            .functions
            .get(&self.account, &self.region, function_name)
            .ok_or("FunctionUnavailable")?;
        let evaluator = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .ok_or("IAM unavailable")?;
        evaluator
            .authorize_service_role_execution(ServiceRoleAuthorizationRequest {
                source_arn: None,
                caller: RequestIdentity {
                    account_id: self.account.clone(),
                    access_key_id: None,
                    arn: None,
                },
                role_arn: function.role,
                service_principal: "lambda.amazonaws.com".into(),
                action: format!("kinesis:{action}"),
                resource: self.mapping.event_source_arn.clone(),
            })
            .map_err(|_| "Kinesis execution role is not authorized")?;
        dispatch_source(
            &self.registry,
            &self.account,
            &self.region,
            &format!("Kinesis_20131202.{action}"),
            body,
        )
        .await
    }
}
#[async_trait]
impl BatchSource for KinesisBatchSource {
    async fn poll(&self, max: u32, window: Duration) -> Result<Vec<SourceRecord>, String> {
        let description = self
            .dispatch("DescribeStream", json!({"StreamName":self.name}))
            .await?;
        let generation = description["StreamDescription"]["StreamCreationTimestamp"]
            .as_f64()
            .ok_or("Invalid Kinesis stream timestamp")?;
        let shards = description["StreamDescription"]["Shards"]
            .as_array()
            .filter(|shards| !shards.is_empty())
            .ok_or("No Kinesis shards")?;
        let index = self.cursor.fetch_add(1, Ordering::Relaxed) % shards.len();
        let shard = shards[index]["ShardId"]
            .as_str()
            .ok_or("Invalid Kinesis shard")?;
        let checkpoint = self
            .store
            .prepare_shard(&self.mapping.uuid, shard, generation)?;
        let mut request =
            json!({"StreamName":self.name,"ShardId":shard,"ShardIteratorType":"TRIM_HORIZON"});
        if let Some(sequence) = checkpoint {
            request["ShardIteratorType"] = json!("AFTER_SEQUENCE_NUMBER");
            request["StartingSequenceNumber"] = json!(sequence);
        } else if self.mapping.starting_position.as_deref() == Some("LATEST") {
            request["ShardIteratorType"] = json!("AT_TIMESTAMP");
            request["Timestamp"] = json!(self.mapping.starting_timestamp);
        }
        let iterator = self.dispatch("GetShardIterator", request).await?;
        let mut iterator = iterator["ShardIterator"]
            .as_str()
            .ok_or("Missing Kinesis iterator")?
            .to_string();
        let deadline = tokio::time::Instant::now() + window;
        let mut records = Vec::new();
        let mut bytes = 0;
        loop {
            let page = self
                .dispatch(
                    "GetRecords",
                    json!({"ShardIterator":iterator,"Limit":max - records.len() as u32}),
                )
                .await?;
            let mut full = false;
            for record in page["Records"]
                .as_array()
                .ok_or("Invalid Kinesis records")?
            {
                let sequence = record["SequenceNumber"]
                    .as_str()
                    .ok_or("Invalid Kinesis sequence")?;
                let body = json!({"eventID":format!("{shard}:{sequence}"),"eventName":"aws:kinesis:record","eventVersion":"1.0","awsRegion":self.region,
                    "kinesis":{"kinesisSchemaVersion":"1.0","partitionKey":record["PartitionKey"],"sequenceNumber":sequence,"data":record["Data"],"approximateArrivalTimestamp":record["ApproximateArrivalTimestamp"]}});
                bytes += body.to_string().len();
                if bytes > 6 * 1024 * 1024 - 16 * 1024 {
                    full = true;
                    break;
                }
                records.push(SourceRecord {
                    item_identifier: sequence.into(),
                    ack_token: json!([shard, sequence]).to_string(),
                    body,
                });
            }
            if full
                || records.len() >= max as usize
                || records.is_empty()
                || tokio::time::Instant::now() >= deadline
            {
                break;
            }
            let Some(next) = page["NextShardIterator"].as_str() else {
                break;
            };
            iterator = next.to_string();
            tokio::time::sleep_until(
                (tokio::time::Instant::now() + Duration::from_millis(200)).min(deadline),
            )
            .await;
        }
        let current = self
            .dispatch("DescribeStream", json!({"StreamName":self.name}))
            .await?;
        if current["StreamDescription"]["StreamCreationTimestamp"].as_f64() != Some(generation) {
            return Err("Kinesis source stream was replaced".into());
        }
        Ok(records)
    }
    async fn ack(&self, tokens: &[String]) -> Result<(), String> {
        let mut last = None;
        for token in tokens {
            let (shard, sequence): (String, String) =
                serde_json::from_str(token).map_err(|_| "Invalid Kinesis acknowledgement")?;
            if last
                .as_ref()
                .is_some_and(|(previous, _)| previous != &shard)
            {
                return Err("Kinesis batch crosses shard boundaries".into());
            }
            last = Some((shard, sequence));
        }
        if let Some((shard, sequence)) = last {
            let generation = self
                .store
                .checkpoints
                .get(&(self.mapping.uuid.clone(), shard.clone()))
                .ok_or("Kinesis shard state unavailable")?
                .0;
            self.store
                .save_checkpoint(&self.mapping.uuid, &shard, generation, Some(sequence))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{create_mapping, poll_once};
    use super::*;
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

    fn valid_zip() -> String {
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

    #[tokio::test]
    async fn multishard_partial_failure_durable_ack_and_role_revocation() {
        let root =
            std::env::temp_dir().join(format!("lambda-stream-checkpoint-{}", uuid::Uuid::new_v4()));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let registry = ServiceRegistry::with_known_services();
        locallycloud_kinesis::register_with_state(&registry, state.clone()).unwrap();
        let authorization = Arc::new(Authorization(AtomicBool::new(true)));
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            authorization.clone(),
            authorization.clone(),
        );
        let dispatcher = Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        ));
        registry.set_internal_dispatcher(dispatcher);
        let functions = Arc::new(FunctionStore::new());
        crate::control_plane::create_function(&functions,"us-east-1","000000000000",&json!({"FunctionName":"consumer","Runtime":"python3.13","Handler":"app.handler","Role":"arn:aws:iam::000000000000:role/consumer","Code":{"ZipFile":valid_zip()}}),None).unwrap();
        let mapping = create_mapping("us-east-1","arn:aws:lambda:us-east-1:000000000000:function:consumer",&json!({"EventSourceArn":"arn:aws:kinesis:us-east-1:000000000000:stream/events","BatchSize":3,"StartingPosition":"TRIM_HORIZON","FunctionResponseTypes":["ReportBatchItemFailures"]})).unwrap();
        let store = Arc::new(EsmStore::new());
        store.attach_state(state.clone()).unwrap();
        store.insert(mapping.clone()).unwrap();
        let source = Arc::new(
            KinesisBatchSource::new(
                Arc::downgrade(&registry),
                store.clone(),
                functions.clone(),
                mapping.clone(),
                "000000000000",
                "us-east-1",
            )
            .unwrap(),
        ) as Arc<dyn BatchSource>;
        dispatch_source(
            &Arc::downgrade(&registry),
            "000000000000",
            "us-east-1",
            "Kinesis_20131202.CreateStream",
            json!({"StreamName":"events","ShardCount":2}),
        )
        .await
        .unwrap();
        for (hash, key) in [
            ("0", "a"),
            ("0", "b"),
            ("0", "c"),
            ("340282366920938463463374607431768211455", "d"),
        ] {
            dispatch_source(&Arc::downgrade(&registry),"000000000000","us-east-1","Kinesis_20131202.PutRecord",json!({"StreamName":"events","PartitionKey":key,"ExplicitHashKey":hash,"Data":"YWJj"})).await.unwrap();
        }
        poll_once(&mapping,&source,|event|async move {
            let records = event["Records"].as_array().unwrap(); assert_eq!(records.len(),3);
            assert_eq!(records[1]["kinesis"]["partitionKey"],"b");
            Some(json!({"batchItemFailures":[{"itemIdentifier":records[1]["kinesis"]["sequenceNumber"]}]}).to_string().into_bytes())
        }).await.unwrap();
        assert_eq!(
            store
                .checkpoints
                .get(&(mapping.uuid.clone(), "shardId-000000000000".into()))
                .unwrap()
                .1
                .as_deref(),
            Some("1")
        );
        poll_once(&mapping, &source, |event| async move {
            assert_eq!(event["Records"][0]["kinesis"]["partitionKey"], "d");
            Some(b"{}".to_vec())
        })
        .await
        .unwrap();
        drop(source);
        drop(store);
        let store = Arc::new(EsmStore::new());
        store.attach_state(state).unwrap();
        assert_eq!(store.get(&mapping.uuid).unwrap().state, "Disabled");
        assert_eq!(
            store
                .get(&mapping.uuid)
                .unwrap()
                .last_processing_result
                .as_deref(),
            Some("FunctionUnavailable")
        );
        let source = Arc::new(
            KinesisBatchSource::new(
                Arc::downgrade(&registry),
                store.clone(),
                functions,
                mapping.clone(),
                "000000000000",
                "us-east-1",
            )
            .unwrap(),
        ) as Arc<dyn BatchSource>;
        poll_once(&mapping, &source, |event| async move {
            assert_eq!(event["Records"].as_array().unwrap().len(), 2);
            assert_eq!(event["Records"][0]["kinesis"]["partitionKey"], "b");
            Some(b"{}".to_vec())
        })
        .await
        .unwrap();
        authorization.0.store(false, Ordering::Relaxed);
        assert!(source.poll(3, Duration::ZERO).await.is_err());
        assert_eq!(
            store
                .checkpoints
                .get(&(mapping.uuid.clone(), "shardId-000000000000".into()))
                .unwrap()
                .1
                .as_deref(),
            Some("3")
        );
        store.remove(&mapping.uuid).unwrap();
        assert!(store.checkpoints.is_empty());
        drop(source);
        drop(store);
        drop(registry);
        std::fs::remove_dir_all(root).unwrap();
    }
}
