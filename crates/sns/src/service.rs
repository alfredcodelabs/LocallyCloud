//! SNS service handler: dual-protocol (Query/XML + AWS JSON) dispatch, registered `Native`.
//!
//! Publish performs real in-process fanout by dispatching to other native services through
//! the Core registry, held as a `Weak` reference to avoid a reference cycle.

use std::sync::{Arc, Weak};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;

use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_state::StateDb;

use crate::error::SnsError;
use crate::fanout::FanoutJob;
use crate::model::TopicArn;
use crate::ops::{self, Ctx};
use crate::proto::{Input, Protocol};
use crate::reply::{query_envelope, Reply};
use crate::store::SnsStore;

pub struct SnsHandler {
    store: Arc<SnsStore>,
    registry: Weak<ServiceRegistry>,
    http: reqwest::Client,
}

impl SnsHandler {
    fn new(registry: Weak<ServiceRegistry>) -> Self {
        // Bounded timeout so a slow/unreachable http(s) subscriber never stalls Publish.
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        SnsHandler {
            store: Arc::new(SnsStore::new()),
            registry,
            http,
        }
    }

    fn with_state(
        registry: Weak<ServiceRegistry>,
        state: Arc<StateDb>,
    ) -> Result<Self, crate::persistence::PersistError> {
        let mut handler = Self::new(registry);
        handler.store = Arc::new(SnsStore::with_state(state)?);
        Ok(handler)
    }

    fn resume_outbox(&self) -> Result<(), crate::persistence::PersistError> {
        let jobs = self.store.pending_jobs()?;
        let registry = self
            .registry
            .upgrade()
            .ok_or_else(|| std::io::Error::other("SNS registry is unavailable"))?;
        for job in jobs {
            self.schedule_replay(registry.clone(), job);
        }
        Ok(())
    }

    fn schedule_replay(&self, registry: Arc<ServiceRegistry>, job: FanoutJob) {
        let Some(arn) = TopicArn::parse(&job.delivery.topic_arn) else {
            return;
        };
        let Some(topic) = self.store.get(&arn) else {
            return;
        };
        let Ok(mut state) = topic.try_write() else {
            return;
        };
        if state.fifo {
            if state.fifo_delivery.is_none() {
                let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
                let http = self.http.clone();
                let store = self.store.clone();
                let registry = registry.clone();
                std::mem::drop(tokio::spawn(async move {
                    while let Some(job) = receiver.recv().await {
                        crate::fanout::deliver_accepted(
                            registry.clone(),
                            http.clone(),
                            store.clone(),
                            job,
                        )
                        .await;
                    }
                }));
                state.fifo_delivery = Some(sender);
            }
            if let Some(sender) = &state.fifo_delivery {
                if sender.send(job).is_err() {
                    tracing::error!("SNS FIFO outbox replay worker stopped");
                }
            }
        } else {
            std::mem::drop(tokio::spawn(crate::fanout::deliver_accepted(
                registry,
                self.http.clone(),
                self.store.clone(),
                job,
            )));
        }
    }

    async fn dispatch(&self, op: &str, ctx: &Ctx<'_>, input: &Input) -> Result<Reply, SnsError> {
        match op {
            "CreateTopic" => ops::create_topic(ctx, input).await,
            "DeleteTopic" => ops::delete_topic(ctx, input).await,
            "ListTopics" => ops::list_topics(ctx, input).await,
            "GetTopicAttributes" => ops::get_topic_attributes(ctx, input).await,
            "SetTopicAttributes" => ops::set_topic_attributes(ctx, input).await,
            "Subscribe" => {
                let registry = self.registry.upgrade().ok_or(SnsError::InternalError)?;
                ops::subscribe(ctx, &registry, &self.http, input).await
            }
            "ConfirmSubscription" => ops::confirm_subscription(ctx, input).await,
            "Unsubscribe" => ops::unsubscribe(ctx, input).await,
            "ListSubscriptions" => ops::list_subscriptions(ctx, input).await,
            "ListSubscriptionsByTopic" => ops::list_subscriptions_by_topic(ctx, input).await,
            "GetSubscriptionAttributes" => ops::get_subscription_attributes(ctx, input).await,
            "SetSubscriptionAttributes" => {
                let registry = self.registry.upgrade().ok_or(SnsError::InternalError)?;
                ops::set_subscription_attributes(ctx, &registry, input).await
            }
            "TagResource" => ops::tag_resource(ctx, input).await,
            "UntagResource" => ops::untag_resource(ctx, input).await,
            "ListTagsForResource" => ops::list_tags_for_resource(ctx, input).await,
            "Publish" | "PublishBatch" => {
                let registry = self.registry.upgrade().ok_or(SnsError::InternalError)?;
                if op == "Publish" {
                    ops::publish(ctx, &registry, &self.http, input).await
                } else {
                    ops::publish_batch(ctx, &registry, &self.http, input).await
                }
            }
            other => Err(SnsError::UnsupportedOperation(format!(
                "unsupported operation {other}"
            ))),
        }
    }
}

#[async_trait]
impl NativeHandler for SnsHandler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        self.store.resource_regions(account)
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let x_amz_target = request
            .headers
            .get("x-amz-target")
            .and_then(|v| v.to_str().ok());
        let (protocol, op, input) = Input::classify(x_amz_target, &request.body);
        let op = match op {
            Some(o) => o,
            None => {
                return SnsError::InvalidParameter("missing Action".into())
                    .into_response(protocol.aws(), &request.request_id)
            }
        };
        if matches!(
            op.as_str(),
            "ListTopics"
                | "ListSubscriptions"
                | "GetTopicAttributes"
                | "ListSubscriptionsByTopic"
                | "GetSubscriptionAttributes"
                | "ListTagsForResource"
        ) {
            let resource = match op.as_str() {
                "GetTopicAttributes" | "ListSubscriptionsByTopic" => {
                    input.get("TopicArn").unwrap_or_default()
                }
                "ListTagsForResource" => input.get("ResourceArn").unwrap_or_default(),
                // AWS grants subscription attribute reads against the parent topic ARN.
                "GetSubscriptionAttributes" => input
                    .get("SubscriptionArn")
                    .and_then(|arn| arn.rsplit_once(':').map(|(topic, _)| topic.to_owned()))
                    .unwrap_or_default(),
                _ => "*".into(),
            };
            if locallycloud_core::integration::authorization::authorize_native_read(
                &self.registry,
                &request,
                "sns",
                &format!("sns:{op}"),
                &resource,
            )
            .is_err()
            {
                return SnsError::AuthorizationError("Not authorized to read SNS resources".into())
                    .into_response(protocol.aws(), &request.request_id);
            }
        }
        let ctx = Ctx {
            store: &self.store,
            region: &request.region,
            account: &request.account_id,
            request_id: &request.request_id,
        };
        let _gate = self.store.operation_gate.lock().await;
        if self.store.has_uncommitted() {
            if let Err(error) = self.store.persist_metadata().await {
                return error.into_response(protocol.aws(), &request.request_id);
            }
        }
        let read_only = matches!(
            op.as_str(),
            "ListTopics"
                | "GetTopicAttributes"
                | "ListSubscriptions"
                | "ListSubscriptionsByTopic"
                | "GetSubscriptionAttributes"
                | "ListTagsForResource"
        );
        if !read_only {
            self.store.mark_uncommitted();
        }
        let result = self.dispatch(&op, &ctx, &input).await;
        if self.store.has_uncommitted() {
            if let Err(error) = self.store.persist_metadata().await {
                return error.into_response(protocol.aws(), &request.request_id);
            }
        }
        match result {
            Ok(reply) => serialize(protocol, &op, &reply, &request.request_id),
            Err(err) => err.into_response(protocol.aws(), &request.request_id),
        }
    }
}

fn serialize(protocol: Protocol, op: &str, reply: &Reply, request_id: &str) -> Response {
    match protocol {
        Protocol::Json => Response::builder()
            .status(200)
            .header("content-type", "application/x-amz-json-1.0")
            .header("x-amzn-RequestId", request_id)
            .body(Body::from(reply.to_json().to_string()))
            .expect("json response is valid"),
        Protocol::Query => {
            let body = query_envelope(op, &reply.to_xml_inner(), request_id);
            Response::builder()
                .status(200)
                .header("content-type", "text/xml")
                .header("x-amzn-RequestId", request_id)
                .body(Body::from(body))
                .expect("xml response is valid")
        }
    }
}

/// Register SNS as a `Native` service. Holds a weak reference to the registry for fanout.
pub fn register(registry: &Arc<ServiceRegistry>) {
    register_handler(
        registry,
        Arc::new(SnsHandler::new(Arc::downgrade(registry))),
    );
}

pub fn register_with_state(
    registry: &Arc<ServiceRegistry>,
    state: Arc<StateDb>,
) -> Result<(), crate::persistence::PersistError> {
    let handler = Arc::new(SnsHandler::with_state(Arc::downgrade(registry), state)?);
    handler.resume_outbox()?;
    register_handler(registry, handler);
    Ok(())
}

fn register_handler(registry: &Arc<ServiceRegistry>, handler: Arc<SnsHandler>) {
    let handler: Arc<dyn NativeHandler> = handler;
    // Internal service-principal calls use Query routing without fabricated SigV4 credentials.
    // Publish operations are unambiguous; identity authorization remains in the dispatcher.
    let mut metadata = ServiceMetadata::new(AwsProtocol::Query, None);
    metadata.known_actions = vec!["Publish".into(), "PublishBatch".into()];
    registry.register_native(ServiceName::new("sns"), metadata, handler);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method};
    use serde_json::{json, Value};

    fn registry() -> Arc<ServiceRegistry> {
        let reg = ServiceRegistry::with_known_services();
        locallycloud_sqs::register(&reg);
        reg.set_internal_dispatcher(Arc::new(
            locallycloud_core::integration::InternalDispatcher::new_shared(
                &reg,
                locallycloud_core::proxy::ProxyConfig {
                    backend_url: "http://127.0.0.1:1".into(),
                    upstream_timeout: std::time::Duration::from_secs(2),
                },
                locallycloud_core::proxy::LegacyHealth::new(false),
                "us-east-1".into(),
                "000000000000".into(),
            ),
        ));

        crate::register(&reg);
        reg
    }

    #[test]
    fn internal_query_publish_resolves_native_sns_without_signature_hint() {
        let registry = registry();
        for action in ["Publish", "PublishBatch"] {
            let body =
                format!("Action={action}&TopicArn=arn:aws:sns:us-east-1:000000000000:alerts");
            let input = locallycloud_core::router::RouteInput {
                authorization: None,
                x_amz_credential: None,
                x_amz_target: None,
                host: None,
                path: "/",
                body: body.as_bytes(),
            };
            let decision = locallycloud_core::router::resolve(&registry, &input).unwrap();
            assert_eq!(decision.service_name, ServiceName::new("sns"));
            assert_eq!(
                decision.disposition,
                locallycloud_core::router::RouteDisposition::HandledNatively
            );
        }
    }

    fn handler(reg: &Arc<ServiceRegistry>, service: &str) -> Arc<dyn NativeHandler> {
        reg.native_handler(&ServiceName::new(service)).unwrap()
    }

    fn json_req(target_prefix: &str, op: &str, body: Value) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("{target_prefix}.{op}")).unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        }
    }

    fn query_req(form: &str) -> ServiceRequest {
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::from(form.to_string()),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        }
    }

    async fn body_of(resp: Response) -> (u16, String) {
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn sns_json(h: &Arc<dyn NativeHandler>, op: &str, body: Value) -> Value {
        let resp = h
            .handle(json_req("AmazonSimpleNotificationService", op, body))
            .await;
        let (status, body) = body_of(resp).await;
        assert_eq!(status, 200, "op {op} failed: {body}");
        serde_json::from_str(&body).unwrap()
    }

    #[tokio::test]
    async fn subscribe_accepts_queue_with_send_only_resource_policy() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let sqs = handler(&reg, "sqs");
        let queue = sns_json(
            &sqs,
            "CreateQueue",
            json!({"QueueName":"restricted-subscription"}),
        )
        .await;
        let url = queue["QueueUrl"].as_str().unwrap();
        let queue_arn = "arn:aws:sqs:us-east-1:000000000000:restricted-subscription";
        let topic = sns_json(
            &sns,
            "CreateTopic",
            json!({"Name":"restricted-subscription"}),
        )
        .await;
        let topic_arn = topic["TopicArn"].as_str().unwrap();
        sns_json(&sqs,"SetQueueAttributes",json!({"QueueUrl":url,"Attributes":{"Policy":json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":queue_arn,"Condition":{"ArnEquals":{"aws:SourceArn":topic_arn},"StringEquals":{"aws:SourceAccount":"000000000000"}}},{"Effect":"Allow","Principal":"*","Action":"sqs:ReceiveMessage","Resource":queue_arn}]}).to_string()}})).await;
        assert_eq!(
            sqs.handle(json_req(
                "AmazonSQS",
                "GetQueueAttributes",
                json!({"QueueUrl":url,"AttributeNames":["QueueArn"]})
            ))
            .await
            .status(),
            http::StatusCode::FORBIDDEN
        );
        let response = sns_json(
            &sns,
            "Subscribe",
            json!({"TopicArn":topic_arn,"Protocol":"sqs","Endpoint":queue_arn}),
        )
        .await;
        assert!(response["SubscriptionArn"]
            .as_str()
            .unwrap()
            .starts_with(topic_arn));
        sns_json(
            &sns,
            "Publish",
            json!({"TopicArn":topic_arn,"Message":"policy-first-delivery"}),
        )
        .await;
        let received = receive_sqs(&sqs, url).await;
        assert!(received["Messages"][0]["Body"]
            .as_str()
            .unwrap()
            .contains("policy-first-delivery"));

        let foreign=sns.handle(json_req("AmazonSimpleNotificationService","Subscribe",json!({"TopicArn":topic_arn,"Protocol":"sqs","Endpoint":"arn:aws:sqs:us-west-2:000000000000:restricted-subscription"}))).await;
        assert_eq!(foreign.status(), http::StatusCode::BAD_REQUEST);
    }

    async fn receive_sqs(h: &Arc<dyn NativeHandler>, queue_url: &str) -> Value {
        for _ in 0..50 {
            let response = h
                .handle(json_req(
                    "AmazonSQS",
                    "ReceiveMessage",
                    json!({ "QueueUrl": queue_url }),
                ))
                .await;
            let (_, body) = body_of(response).await;
            let value: Value = serde_json::from_str(&body).unwrap();
            if value["Messages"]
                .as_array()
                .is_some_and(|messages| !messages.is_empty())
            {
                return value;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for SQS delivery");
    }

    #[tokio::test]
    async fn failed_subscriber_without_dlq_keeps_accepted_outbox_row() {
        let root = std::env::temp_dir().join(format!(
            "locallycloud-sns-failed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let store = Arc::new(SnsStore::with_state(state).unwrap());
        let arn = TopicArn::new("us-east-1", "000000000000", "failed");
        store.insert(arn.clone(), false, Default::default(), Default::default());
        let topic = store.get(&arn).unwrap();
        let sub = crate::model::Subscription {
            arn: format!("{}:sub", arn.to_arn()),
            topic_arn: arn.to_arn(),
            protocol: "sqs".into(),
            endpoint: "arn:aws:sqs:us-east-1:000000000000:missing".into(),
            owner: "000000000000".into(),
            confirmed: true,
            pending_token: None,
            attributes: Default::default(),
        };
        let mut job = FanoutJob {
            outbox_id: None,
            subscriptions: vec![sub],
            delivery: crate::fanout::Delivery {
                message_id: "failed-message".into(),
                topic_arn: arn.to_arn(),
                message: "payload".into(),
                structure: None,
                subject: None,
                timestamp: "2026-01-01T00:00:00Z".into(),
                attributes: Default::default(),
                group_id: None,
                dedup_id: None,
                region: "us-east-1".into(),
                account: "000000000000".into(),
                request_id: "rid".into(),
            },
        };
        job.outbox_id = store.accept_job(&*topic.read().await, &job).unwrap();
        let registry = ServiceRegistry::with_known_services();
        let worker = tokio::spawn(crate::fanout::deliver_accepted(
            registry,
            reqwest::Client::new(),
            store.clone(),
            job.clone(),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(store.job_exists(job.outbox_id).unwrap());
        worker.abort();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn accepted_publish_replays_from_outbox_after_restart() {
        let root = std::env::temp_dir().join(format!(
            "locallycloud-sns-restart-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let store = SnsStore::with_state(state.clone()).unwrap();
        let arn = TopicArn::new("us-east-1", "000000000000", "replay");
        store.insert(arn.clone(), false, Default::default(), Default::default());
        let topic = store.get(&arn).unwrap();
        let sub = crate::model::Subscription {
            arn: format!("{}:sub", arn.to_arn()),
            topic_arn: arn.to_arn(),
            protocol: "sqs".into(),
            endpoint: "arn:aws:sqs:us-east-1:000000000000:replay-queue".into(),
            owner: "000000000000".into(),
            confirmed: true,
            pending_token: None,
            attributes: Default::default(),
        };
        topic.write().await.subscriptions.push(sub.clone());
        store.persist_metadata().await.unwrap();
        let job = FanoutJob {
            outbox_id: None,
            subscriptions: vec![sub],
            delivery: crate::fanout::Delivery {
                message_id: "published-before-restart".into(),
                topic_arn: arn.to_arn(),
                message: "payload".into(),
                structure: None,
                subject: None,
                timestamp: "2026-01-01T00:00:00Z".into(),
                attributes: Default::default(),
                group_id: None,
                dedup_id: None,
                region: "us-east-1".into(),
                account: "000000000000".into(),
                request_id: "rid".into(),
            },
        };
        // This is the accepted-publish commit; deliberately stop before scheduling fanout.
        let id = store.accept_job(&*topic.read().await, &job).unwrap();
        assert!(id.is_some());
        drop(store);

        let reg = ServiceRegistry::with_known_services();
        locallycloud_sqs::register(&reg);
        reg.set_internal_dispatcher(Arc::new(
            locallycloud_core::integration::InternalDispatcher::new_shared(
                &reg,
                locallycloud_core::proxy::ProxyConfig {
                    backend_url: "http://127.0.0.1:1".into(),
                    upstream_timeout: std::time::Duration::from_secs(2),
                },
                locallycloud_core::proxy::LegacyHealth::new(false),
                "us-east-1".into(),
                "000000000000".into(),
            ),
        ));

        let sqs = handler(&reg, "sqs");
        let queue = sns_json(&sqs, "CreateQueue", json!({ "QueueName": "replay-queue" })).await;
        let queue_url = queue["QueueUrl"].as_str().unwrap();
        crate::register_with_state(&reg, state.clone()).unwrap();
        let delivered = receive_sqs(&sqs, queue_url).await;
        assert!(delivered["Messages"][0]["Body"]
            .as_str()
            .unwrap()
            .contains("published-before-restart"));
        for _ in 0..50 {
            if SnsStore::with_state(state.clone())
                .unwrap()
                .pending_jobs()
                .unwrap()
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(SnsStore::with_state(state)
            .unwrap()
            .pending_jobs()
            .unwrap()
            .is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn create_topic_query_and_json() {
        let reg = registry();
        let sns = handler(&reg, "sns");

        // Query protocol → XML envelope.
        let resp = sns
            .handle(query_req("Action=CreateTopic&Name=events"))
            .await;
        let (status, xml) = body_of(resp).await;
        assert_eq!(status, 200);
        assert!(xml.contains("<CreateTopicResult><TopicArn>arn:aws:sns:us-east-1:000000000000:events</TopicArn></CreateTopicResult>"));
        assert!(xml.contains("<RequestId>rid</RequestId>"));

        // JSON protocol.
        let v = sns_json(&sns, "CreateTopic", json!({ "Name": "events2" })).await;
        assert_eq!(v["TopicArn"], "arn:aws:sns:us-east-1:000000000000:events2");
    }

    #[tokio::test]
    async fn fanout_sns_to_sqs_delivers_envelope() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let sqs = handler(&reg, "sqs");

        // Create the SQS queue and the SNS topic.
        let q = sqs
            .handle(json_req(
                "AmazonSQS",
                "CreateQueue",
                json!({ "QueueName": "inbox" }),
            ))
            .await;
        let (_, qbody) = body_of(q).await;
        let queue_url: String = serde_json::from_str::<Value>(&qbody).unwrap()["QueueUrl"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(queue_url.ends_with("/inbox"));

        let topic = sns_json(&sns, "CreateTopic", json!({ "Name": "t" })).await;
        let topic_arn = topic["TopicArn"].as_str().unwrap().to_string();

        // Subscribe the queue (sqs protocol is auto-confirmed).
        sns_json(
            &sns,
            "Subscribe",
            json!({ "TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": "arn:aws:sqs:us-east-1:000000000000:inbox" }),
        )
        .await;

        // Publish → fanout into the real SQS queue.
        let pub_resp = sns_json(
            &sns,
            "Publish",
            json!({ "TopicArn": topic_arn, "Message": "hello-fanout" }),
        )
        .await;
        assert!(pub_resp["MessageId"].is_string());

        // Receive from SQS and confirm the SNS envelope arrived.
        let rv = receive_sqs(&sqs, &queue_url).await;
        let sqs_body = rv["Messages"][0]["Body"].as_str().unwrap();
        let envelope: Value = serde_json::from_str(sqs_body).unwrap();
        assert_eq!(envelope["Type"], "Notification");
        assert_eq!(envelope["Message"], "hello-fanout");
        assert_eq!(envelope["TopicArn"], topic_arn);
    }

    #[tokio::test]
    async fn raw_delivery_sends_bare_body() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let sqs = handler(&reg, "sqs");
        sqs.handle(json_req(
            "AmazonSQS",
            "CreateQueue",
            json!({ "QueueName": "raw" }),
        ))
        .await;
        let topic = sns_json(&sns, "CreateTopic", json!({ "Name": "rt" })).await;
        let topic_arn = topic["TopicArn"].as_str().unwrap().to_string();
        let sub = sns_json(
            &sns,
            "Subscribe",
            json!({ "TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": "arn:aws:sqs:us-east-1:000000000000:raw", "ReturnSubscriptionArn": "true" }),
        )
        .await;
        let sub_arn = sub["SubscriptionArn"].as_str().unwrap().to_string();
        sns_json(
            &sns,
            "SetSubscriptionAttributes",
            json!({ "SubscriptionArn": sub_arn, "AttributeName": "RawMessageDelivery", "AttributeValue": "true" }),
        )
        .await;
        sns_json(
            &sns,
            "Publish",
            json!({ "TopicArn": topic_arn, "Message": "bare" }),
        )
        .await;

        let rv = receive_sqs(&sqs, "https://sqs.us-east-1.amazonaws.com/000000000000/raw").await;
        assert_eq!(rv["Messages"][0]["Body"], "bare");
    }

    #[tokio::test]
    async fn filter_policy_blocks_non_matching() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let sqs = handler(&reg, "sqs");
        sqs.handle(json_req(
            "AmazonSQS",
            "CreateQueue",
            json!({ "QueueName": "fq" }),
        ))
        .await;
        let topic = sns_json(&sns, "CreateTopic", json!({ "Name": "ft" })).await;
        let topic_arn = topic["TopicArn"].as_str().unwrap().to_string();
        sns_json(
            &sns,
            "Subscribe",
            json!({ "TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": "arn:aws:sqs:us-east-1:000000000000:fq",
                    "Attributes": { "FilterPolicy": "{\"color\":[\"red\"]}" } }),
        )
        .await;
        // Non-matching attribute → not delivered.
        sns_json(
            &sns,
            "Publish",
            json!({ "TopicArn": topic_arn, "Message": "m", "MessageAttributes": { "color": { "DataType": "String", "StringValue": "blue" } } }),
        )
        .await;
        let recv = sqs
            .handle(json_req(
                "AmazonSQS",
                "ReceiveMessage",
                json!({ "QueueUrl": "https://sqs.us-east-1.amazonaws.com/000000000000/fq" }),
            ))
            .await;
        let (_, rbody) = body_of(recv).await;
        let rv: Value = serde_json::from_str(&rbody).unwrap();
        assert!(
            rv.get("Messages").is_none(),
            "non-matching message must not be delivered"
        );
    }

    #[tokio::test]
    async fn publish_missing_topic_is_not_found() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let resp = sns
            .handle(json_req(
                "AmazonSimpleNotificationService",
                "Publish",
                json!({ "TopicArn": "arn:aws:sns:us-east-1:000000000000:ghost", "Message": "x" }),
            ))
            .await;
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn fifo_publish_requires_group_id() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let topic = sns_json(
            &sns,
            "CreateTopic",
            json!({ "Name": "orders.fifo", "Attributes": { "FifoTopic": "true", "ContentBasedDeduplication": "true" } }),
        )
        .await;
        let topic_arn = topic["TopicArn"].as_str().unwrap().to_string();
        let resp = sns
            .handle(json_req(
                "AmazonSimpleNotificationService",
                "Publish",
                json!({ "TopicArn": topic_arn, "Message": "x" }),
            ))
            .await;
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn list_and_unsubscribe() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let sqs = handler(&reg, "sqs");
        sqs.handle(json_req(
            "AmazonSQS",
            "CreateQueue",
            json!({ "QueueName": "x" }),
        ))
        .await;
        let topic = sns_json(&sns, "CreateTopic", json!({ "Name": "lt" })).await;
        let topic_arn = topic["TopicArn"].as_str().unwrap().to_string();
        let sub = sns_json(
            &sns,
            "Subscribe",
            json!({ "TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": "arn:aws:sqs:us-east-1:000000000000:x", "ReturnSubscriptionArn": "true" }),
        )
        .await;
        let sub_arn = sub["SubscriptionArn"].as_str().unwrap().to_string();
        let listed = sns_json(
            &sns,
            "ListSubscriptionsByTopic",
            json!({ "TopicArn": topic_arn }),
        )
        .await;
        assert_eq!(listed["Subscriptions"].as_array().unwrap().len(), 1);
        sns_json(&sns, "Unsubscribe", json!({ "SubscriptionArn": sub_arn })).await;
        let listed2 = sns_json(
            &sns,
            "ListSubscriptionsByTopic",
            json!({ "TopicArn": topic_arn }),
        )
        .await;
        assert!(listed2["Subscriptions"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn tags_round_trip() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let topic = sns_json(&sns, "CreateTopic", json!({ "Name": "tg" })).await;
        let arn = topic["TopicArn"].as_str().unwrap().to_string();
        sns_json(
            &sns,
            "TagResource",
            json!({ "ResourceArn": arn, "Tags": [{ "Key": "env", "Value": "prod" }] }),
        )
        .await;
        let tags = sns_json(&sns, "ListTagsForResource", json!({ "ResourceArn": arn })).await;
        assert_eq!(tags["Tags"][0]["Key"], "env");
        assert_eq!(tags["Tags"][0]["Value"], "prod");
    }

    #[tokio::test]
    async fn unsupported_protocol_and_phone_publish_fail_without_state() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let topic = sns_json(&sns, "CreateTopic", json!({ "Name": "honest" })).await;
        let topic_arn = topic["TopicArn"].as_str().unwrap();
        let response = sns
            .handle(json_req(
                "AmazonSimpleNotificationService",
                "Subscribe",
                json!({
                    "TopicArn": topic_arn,
                    "Protocol": "email",
                    "Endpoint": "user@example.test"
                }),
            ))
            .await;
        assert_eq!(response.status(), 400);
        let listed = sns_json(
            &sns,
            "ListSubscriptionsByTopic",
            json!({ "TopicArn": topic_arn }),
        )
        .await;
        assert!(listed["Subscriptions"].as_array().unwrap().is_empty());

        let response = sns
            .handle(json_req(
                "AmazonSimpleNotificationService",
                "Publish",
                json!({ "PhoneNumber": "+15555550100", "Message": "not-delivered" }),
            ))
            .await;
        assert_eq!(response.status(), 400);
    }

    #[tokio::test]
    async fn invalid_subscription_update_preserves_previous_value() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let sqs = handler(&reg, "sqs");
        sqs.handle(json_req(
            "AmazonSQS",
            "CreateQueue",
            json!({ "QueueName": "atomic-sub" }),
        ))
        .await;
        let topic = sns_json(&sns, "CreateTopic", json!({ "Name": "atomic-sub" })).await;
        let sub = sns_json(
            &sns,
            "Subscribe",
            json!({
                "TopicArn": topic["TopicArn"],
                "Protocol": "sqs",
                "Endpoint": "arn:aws:sqs:us-east-1:000000000000:atomic-sub",
                "ReturnSubscriptionArn": "true"
            }),
        )
        .await;
        let sub_arn = sub["SubscriptionArn"].as_str().unwrap();
        sns_json(
            &sns,
            "SetSubscriptionAttributes",
            json!({
                "SubscriptionArn": sub_arn,
                "AttributeName": "RawMessageDelivery",
                "AttributeValue": "true"
            }),
        )
        .await;
        let invalid = sns
            .handle(json_req(
                "AmazonSimpleNotificationService",
                "SetSubscriptionAttributes",
                json!({
                    "SubscriptionArn": sub_arn,
                    "AttributeName": "RawMessageDelivery",
                    "AttributeValue": "yes"
                }),
            ))
            .await;
        assert_eq!(invalid.status(), 400);
        let attrs = sns_json(
            &sns,
            "GetSubscriptionAttributes",
            json!({ "SubscriptionArn": sub_arn }),
        )
        .await;
        assert_eq!(attrs["Attributes"]["RawMessageDelivery"], "true");
    }

    #[tokio::test]
    async fn fifo_duplicate_replays_original_result_and_delivers_once() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let sqs = handler(&reg, "sqs");
        let queue = sns_json(
            &sqs,
            "CreateQueue",
            json!({ "QueueName": "orders.fifo", "Attributes": { "FifoQueue": "true" } }),
        )
        .await;
        let topic = sns_json(
            &sns,
            "CreateTopic",
            json!({ "Name": "orders.fifo", "Attributes": { "FifoTopic": "true" } }),
        )
        .await;
        let topic_arn = topic["TopicArn"].as_str().unwrap();
        sns_json(
            &sns,
            "Subscribe",
            json!({
                "TopicArn": topic_arn,
                "Protocol": "sqs",
                "Endpoint": "arn:aws:sqs:us-east-1:000000000000:orders.fifo"
            }),
        )
        .await;
        let body = json!({
            "TopicArn": topic_arn,
            "Message": "one",
            "MessageGroupId": "group",
            "MessageDeduplicationId": "dedup"
        });
        let first = sns_json(&sns, "Publish", body.clone()).await;
        let duplicate = sns_json(&sns, "Publish", body).await;
        assert_eq!(duplicate["MessageId"], first["MessageId"]);
        assert_eq!(duplicate["SequenceNumber"], first["SequenceNumber"]);

        let mut received = Value::Null;
        for _ in 0..50 {
            received = sns_json(
                &sqs,
                "ReceiveMessage",
                json!({ "QueueUrl": queue["QueueUrl"], "MaxNumberOfMessages": 10 }),
            )
            .await;
            if received["Messages"]
                .as_array()
                .is_some_and(|messages| !messages.is_empty())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(received["Messages"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn concurrent_fifo_publishes_are_delivered_in_acceptance_order() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let sqs = handler(&reg, "sqs");
        let queue = sns_json(
            &sqs,
            "CreateQueue",
            json!({ "QueueName": "concurrent.fifo", "Attributes": { "FifoQueue": "true" } }),
        )
        .await;
        let queue_url = queue["QueueUrl"].as_str().unwrap().to_string();
        let topic = sns_json(
            &sns,
            "CreateTopic",
            json!({ "Name": "concurrent.fifo", "Attributes": { "FifoTopic": "true" } }),
        )
        .await;
        let topic_arn = topic["TopicArn"].as_str().unwrap().to_string();
        sns_json(
            &sns,
            "Subscribe",
            json!({
                "TopicArn": topic_arn,
                "Protocol": "sqs",
                "Endpoint": "arn:aws:sqs:us-east-1:000000000000:concurrent.fifo"
            }),
        )
        .await;

        let mut publishers = tokio::task::JoinSet::new();
        for index in 0..12 {
            let sns = sns.clone();
            let topic_arn = topic_arn.clone();
            publishers.spawn(async move {
                let message = format!("message-{index}");
                let result = sns_json(
                    &sns,
                    "Publish",
                    json!({
                        "TopicArn": topic_arn,
                        "Message": message,
                        "MessageGroupId": "group",
                        "MessageDeduplicationId": format!("dedup-{index}")
                    }),
                )
                .await;
                (
                    result["SequenceNumber"]
                        .as_str()
                        .unwrap()
                        .parse::<u128>()
                        .unwrap(),
                    message,
                )
            });
        }
        let mut accepted = Vec::new();
        while let Some(result) = publishers.join_next().await {
            accepted.push(result.unwrap());
        }
        accepted.sort_by_key(|(sequence, _)| *sequence);
        let expected: Vec<String> = accepted.into_iter().map(|(_, message)| message).collect();

        let mut delivered = Vec::new();
        for _ in 0..200 {
            let result = sns_json(
                &sqs,
                "ReceiveMessage",
                json!({ "QueueUrl": queue_url, "MaxNumberOfMessages": 1 }),
            )
            .await;
            if let Some(received) = result["Messages"]
                .as_array()
                .and_then(|items| items.first())
            {
                let envelope: Value =
                    serde_json::from_str(received["Body"].as_str().unwrap()).unwrap();
                delivered.push(envelope["Message"].as_str().unwrap().to_string());
                sns_json(
                    &sqs,
                    "DeleteMessage",
                    json!({
                        "QueueUrl": queue_url,
                        "ReceiptHandle": received["ReceiptHandle"]
                    }),
                )
                .await;
                if delivered.len() == expected.len() {
                    break;
                }
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        assert_eq!(delivered, expected);
    }

    #[tokio::test]
    async fn concurrent_conflicting_creates_never_replace_topic() {
        let reg = registry();
        let sns = handler(&reg, "sns");
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..16 {
            let sns = sns.clone();
            tasks.spawn(async move {
                let response = sns
                    .handle(json_req(
                        "AmazonSimpleNotificationService",
                        "CreateTopic",
                        json!({
                            "Name": "concurrent",
                            "Attributes": { "DisplayName": format!("value-{index}") }
                        }),
                    ))
                    .await;
                (index, response.status().as_u16())
            });
        }
        let mut winner = None;
        while let Some(result) = tasks.join_next().await {
            let (index, status) = result.unwrap();
            if status == 200 {
                assert!(winner.replace(index).is_none());
            } else {
                assert_eq!(status, 400);
            }
        }
        let winner = winner.expect("one create must win");
        let repeated = sns
            .handle(json_req(
                "AmazonSimpleNotificationService",
                "CreateTopic",
                json!({
                    "Name": "concurrent",
                    "Attributes": { "DisplayName": format!("value-{winner}") }
                }),
            ))
            .await;
        assert_eq!(repeated.status(), 200);
    }
}
