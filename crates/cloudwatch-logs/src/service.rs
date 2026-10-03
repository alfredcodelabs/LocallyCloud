use std::sync::{Arc, Weak};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{AwsProtocol, ServiceName, ServiceRegistry};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::clock::{Clock, SystemClock};
use crate::error::{LogsError, RegistrationError};
use crate::metric_delivery::MetricDeliveryWorker;
use crate::model::ScopeKey;
use crate::pagination::{DescribePaginator, EventPaginator, StreamDescribePaginator};
use crate::query_worker::QueryWorker;
use crate::retention::RetentionWorker;
use crate::store::LogsStore;
use crate::subscription_delivery::SubscriptionDeliveryWorker;
use crate::{events, groups, insights, metric_filters, protocol, streams, subscriptions};

pub struct LogsHandler {
    registry: Weak<ServiceRegistry>,
    store: Arc<LogsStore>,
    clock: Arc<dyn Clock>,
    retention_worker: RetentionWorker,
    metric_delivery_worker: MetricDeliveryWorker,
    subscription_delivery_worker: SubscriptionDeliveryWorker,
    query_worker: QueryWorker,
    insights_paginator: insights::InsightsPaginator,
    paginator: DescribePaginator,
    stream_paginator: StreamDescribePaginator,
    event_paginator: EventPaginator,
}

impl LogsHandler {
    pub(crate) fn new(registry: Weak<ServiceRegistry>) -> Result<Self, RegistrationError> {
        Self::with_clock(registry, Arc::new(SystemClock))
    }

    fn with_clock(
        registry: Weak<ServiceRegistry>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, RegistrationError> {
        registry
            .upgrade()
            .ok_or(RegistrationError::RegistryUnavailable)?;
        let store = Arc::new(LogsStore::default());
        let retention_worker = RetentionWorker::new(store.clone(), clock.clone());
        let metric_delivery_worker = MetricDeliveryWorker::new(store.clone(), registry.clone());
        let subscription_delivery_worker =
            SubscriptionDeliveryWorker::new(store.clone(), registry.clone());
        let query_worker = QueryWorker::new(store.clone(), clock.clone());
        Ok(Self {
            registry,
            store,
            clock,
            retention_worker,
            metric_delivery_worker,
            subscription_delivery_worker,
            query_worker,
            insights_paginator: insights::InsightsPaginator::default(),
            paginator: DescribePaginator::default(),
            stream_paginator: StreamDescribePaginator::default(),
            event_paginator: EventPaginator::default(),
        })
    }

    async fn process(&self, request: &ServiceRequest) -> Result<Value, LogsError> {
        if request.method != http::Method::POST {
            return Err(LogsError::UnknownOperation(
                "CloudWatch Logs JSON operations require POST".into(),
            ));
        }
        if request.uri.path() != "/" || request.uri.query().is_some() {
            return Err(LogsError::InvalidParameter(
                "CloudWatch Logs JSON operations require the exact path /".into(),
            ));
        }
        protocol::validate_content_type(&request.headers)?;
        let operation = protocol::operation(&request.headers)?;
        if !protocol::is_allowed(operation) {
            return Err(LogsError::UnknownOperation(format!(
                "operation {operation} is not supported"
            )));
        }
        if request.body.len() > protocol::MAX_REQUEST_BODY_BYTES {
            return Err(LogsError::InvalidParameter(
                "request body exceeds the CloudWatch Logs safety limit".into(),
            ));
        }
        let body: Value = serde_json::from_slice(&request.body).map_err(|_| {
            LogsError::Serialization("request body must be a valid JSON object".into())
        })?;
        if !body.is_object() {
            return Err(LogsError::Serialization(
                "request body must be a valid JSON object".into(),
            ));
        }
        let scope = ScopeKey::new(&request.account_id, &request.region);
        self.dispatch(operation, body, scope).await
    }

    async fn dispatch(
        &self,
        operation: &str,
        body: Value,
        scope: ScopeKey,
    ) -> Result<Value, LogsError> {
        match operation {
            "CreateLogGroup" => {
                groups::create(&self.store, decode(body)?, scope, self.clock.now_ms())?;
                Ok(json!({}))
            }
            "DescribeLogGroups" => serde_json::to_value(groups::describe(
                &self.store,
                &self.paginator,
                decode(body)?,
                scope,
                self.clock.now_ms(),
            )?)
            .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            "DeleteLogGroup" => {
                groups::delete(&self.store, decode(body)?, scope)?;
                Ok(json!({}))
            }
            "PutRetentionPolicy" => {
                groups::put_retention(&self.store, decode(body)?, scope)?;
                Ok(json!({}))
            }
            "DeleteRetentionPolicy" => {
                groups::delete_retention(&self.store, decode(body)?, scope)?;
                Ok(json!({}))
            }
            "CreateLogStream" => {
                streams::create(&self.store, decode(body)?, scope, self.clock.now_ms())?;
                Ok(json!({}))
            }
            "DescribeLogStreams" => serde_json::to_value(streams::describe(
                &self.store,
                &self.stream_paginator,
                decode(body)?,
                scope,
                self.clock.now_ms(),
            )?)
            .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            "DeleteLogStream" => {
                streams::delete(&self.store, decode(body)?, scope)?;
                Ok(json!({}))
            }
            "PutLogEvents" => serde_json::to_value(events::put(
                &self.store,
                decode(body)?,
                scope,
                self.clock.now_ms(),
            )?)
            .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            "GetLogEvents" => serde_json::to_value(events::get(
                &self.store,
                &self.event_paginator,
                decode(body)?,
                scope,
                self.clock.now_ms(),
            )?)
            .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            "FilterLogEvents" => serde_json::to_value(events::filter(
                &self.store,
                &self.event_paginator,
                decode(body)?,
                scope,
                self.clock.now_ms(),
            )?)
            .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            "PutMetricFilter" => {
                let registry = self.registry.upgrade().ok_or_else(|| {
                    LogsError::OperationUnavailable("Monitoring is unavailable".into())
                })?;
                if registry
                    .metric_sink(&ServiceName::new("monitoring"))
                    .is_none()
                {
                    return Err(LogsError::OperationUnavailable(
                        "a concrete Monitoring metric receiver is required".into(),
                    ));
                }
                metric_filters::put(&self.store, decode(body)?, scope, self.clock.now_ms())?;
                Ok(json!({}))
            }
            "DescribeMetricFilters" => {
                serde_json::to_value(metric_filters::describe(&self.store, decode(body)?, scope)?)
                    .map_err(|_| {
                        LogsError::ServiceUnavailable("response serialization failed".into())
                    })
            }
            "DeleteMetricFilter" => {
                metric_filters::delete(&self.store, decode(body)?, scope)?;
                Ok(json!({}))
            }
            "TestMetricFilter" => serde_json::to_value(metric_filters::test(decode(body)?)?)
                .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            "PutSubscriptionFilter" => {
                let registry = self.registry.upgrade().ok_or_else(|| {
                    LogsError::OperationUnavailable("Lambda is unavailable".into())
                })?;
                subscriptions::put(
                    &self.store,
                    &registry,
                    decode(body)?,
                    scope,
                    self.clock.now_ms(),
                )
                .await?;
                Ok(json!({}))
            }
            "DescribeSubscriptionFilters" => {
                serde_json::to_value(subscriptions::describe(&self.store, decode(body)?, scope)?)
                    .map_err(|_| {
                        LogsError::ServiceUnavailable("response serialization failed".into())
                    })
            }
            "DeleteSubscriptionFilter" => {
                subscriptions::delete(&self.store, decode(body)?, scope)?;
                Ok(json!({}))
            }
            "PutDestination"
            | "PutDestinationPolicy"
            | "DescribeDestinations"
            | "DeleteDestination" => Err(LogsError::OperationUnavailable(
                "destination resources require a concrete supported destination adapter".into(),
            )),
            "StartQuery" => serde_json::to_value(insights::start(
                &self.store,
                decode(body)?,
                scope,
                self.clock.now_ms(),
            )?)
            .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            "GetQueryResults" => serde_json::to_value(insights::get(
                &self.store,
                &self.insights_paginator,
                decode(body)?,
                scope,
                self.clock.now_ms(),
            )?)
            .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            "StopQuery" => serde_json::to_value(insights::stop(
                &self.store,
                decode(body)?,
                scope,
                self.clock.now_ms(),
            )?)
            .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            "DescribeQueries" => serde_json::to_value(insights::describe(
                &self.store,
                &self.insights_paginator,
                decode(body)?,
                scope,
                self.clock.now_ms(),
            )?)
            .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            "TagResource" => {
                groups::tag_resource(&self.store, decode(body)?, scope)?;
                Ok(json!({}))
            }
            "UntagResource" => {
                groups::untag_resource(&self.store, decode(body)?, scope)?;
                Ok(json!({}))
            }
            "ListTagsForResource" => serde_json::to_value(groups::list_tags_for_resource(
                &self.store,
                decode(body)?,
                scope,
            )?)
            .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            "TagLogGroup" => {
                groups::tag_log_group(&self.store, decode(body)?, scope)?;
                Ok(json!({}))
            }
            "UntagLogGroup" => {
                groups::untag_log_group(&self.store, decode(body)?, scope)?;
                Ok(json!({}))
            }
            "ListTagsLogGroup" => serde_json::to_value(groups::list_tags_log_group(
                &self.store,
                decode(body)?,
                scope,
            )?)
            .map_err(|_| LogsError::ServiceUnavailable("response serialization failed".into())),
            _ => Err(LogsError::OperationUnavailable(format!(
                "operation {operation} is recognized but not implemented"
            ))),
        }
    }
}

fn decode<T: DeserializeOwned>(body: Value) -> Result<T, LogsError> {
    serde_json::from_value(body)
        .map_err(|_| LogsError::InvalidParameter("request parameters are invalid".into()))
}

#[async_trait]
impl NativeHandler for LogsHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let operation = protocol::operation(&request.headers).ok();
        let wakes_retention = operation.is_some_and(|operation| {
            matches!(
                operation,
                "PutRetentionPolicy"
                    | "DeleteRetentionPolicy"
                    | "DeleteLogGroup"
                    | "DeleteLogStream"
                    | "PutLogEvents"
            )
        });
        let wakes_metric_delivery = operation == Some("PutLogEvents");
        let wakes_subscription_delivery = operation == Some("PutLogEvents");
        let wakes_query_worker = operation == Some("StartQuery");
        let result = self.process(&request).await;
        if result.is_ok() {
            if wakes_retention {
                self.retention_worker.wake();
            }
            if wakes_metric_delivery {
                self.metric_delivery_worker.wake();
            }
            if wakes_subscription_delivery {
                self.subscription_delivery_worker.wake();
            }
            if wakes_query_worker {
                self.query_worker.wake();
            }
        }
        match result {
            Ok(value) => Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, protocol::CONTENT_TYPE)
                .header("x-amzn-RequestId", &request.request_id)
                .body(Body::from(value.to_string()))
                .expect("CloudWatch Logs JSON response is valid"),
            Err(error) => locallycloud_core::error_mapping::AwsError::from(error)
                .with_request_id(request.request_id)
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use http::{HeaderMap, HeaderValue, Method};
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicI64, Ordering};

    struct TestClock(AtomicI64);

    impl TestClock {
        fn new(now_ms: i64) -> Self {
            Self(AtomicI64::new(now_ms))
        }

        fn set(&self, now_ms: i64) {
            self.0.store(now_ms, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now_ms(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn handler() -> LogsHandler {
        handler_at(1_700_000_000_000).0
    }

    fn handler_at(now_ms: i64) -> (LogsHandler, Arc<TestClock>) {
        let registry = ServiceRegistry::with_known_services();
        let clock = Arc::new(TestClock::new(now_ms));
        let handler = LogsHandler::with_clock(Arc::downgrade(&registry), clock.clone()).unwrap();
        (handler, clock)
    }

    fn request(operation: &str, body: Value) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static(protocol::CONTENT_TYPE),
        );
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("{}.{operation}", protocol::TARGET_PREFIX)).unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: body.to_string().into(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "request-123".into(),
        }
    }

    async fn response_with(
        handler: &LogsHandler,
        request: ServiceRequest,
    ) -> (u16, HeaderMap, Value) {
        let response = handler.handle(request).await;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap();
        (status, headers, body)
    }

    async fn response(request: ServiceRequest) -> (u16, HeaderMap, Value) {
        response_with(&handler(), request).await
    }

    fn assert_error(body: &Value, code: &str) {
        assert_eq!(body["__type"], code, "{body}");
    }

    async fn create(handler: &LogsHandler, name: &str) {
        let (status, _, body) = response_with(
            handler,
            request("CreateLogGroup", json!({ "logGroupName": name })),
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }

    #[tokio::test]
    async fn rejects_invalid_method_path_and_content_type() {
        let mut invalid_method = request("CreateLogGroup", json!({}));
        invalid_method.method = Method::GET;
        let (status, _, body) = response(invalid_method).await;
        assert_eq!(status, 400);
        assert_error(&body, "UnknownOperationException");

        let mut invalid_path = request("CreateLogGroup", json!({}));
        invalid_path.uri = "/logs".parse().unwrap();
        let (_, _, body) = response(invalid_path).await;
        assert_error(&body, "InvalidParameterException");

        let mut invalid_content_type = request("CreateLogGroup", json!({}));
        invalid_content_type.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let (_, _, body) = response(invalid_content_type).await;
        assert_error(&body, "InvalidParameterException");
    }

    #[tokio::test]
    async fn rejects_invalid_target_and_body_before_dispatch() {
        let mut invalid_target = request("CreateLogGroup", json!({}));
        invalid_target.headers.insert(
            "x-amz-target",
            HeaderValue::from_static("Wrong.CreateLogGroup"),
        );
        let (_, _, body) = response(invalid_target).await;
        assert_error(&body, "UnknownOperationException");

        let mut invalid_json = request("CreateLogGroup", json!({}));
        invalid_json.body = "{".into();
        let (_, _, body) = response(invalid_json).await;
        assert_error(&body, "SerializationException");

        let mut non_object = request("CreateLogGroup", json!({}));
        non_object.body = "[]".into();
        let (_, _, body) = response(non_object).await;
        assert_error(&body, "SerializationException");
    }

    #[tokio::test]
    async fn unknown_and_recognized_operations_fail_closed() {
        let (_, _, body) = response(request("FutureOperation", json!({}))).await;
        assert_error(&body, "UnknownOperationException");

        let (status, headers, body) = response(request("CreateLogStream", json!({}))).await;
        assert_eq!(status, 400);
        assert_error(&body, "InvalidParameterException");
        assert_eq!(headers.get("x-amzn-requestid").unwrap(), "request-123");
        assert_eq!(
            headers.get(http::header::CONTENT_TYPE).unwrap(),
            protocol::CONTENT_TYPE
        );
    }

    #[tokio::test]
    async fn enforces_direct_handler_body_bound() {
        let mut oversized = request("PutLogEvents", json!({}));
        oversized.body = vec![b' '; protocol::MAX_REQUEST_BODY_BYTES + 1].into();
        let (_, _, body) = response(oversized).await;
        assert_error(&body, "InvalidParameterException");
    }

    #[tokio::test]
    async fn create_and_delete_log_group_are_atomic() {
        let handler = handler();
        let create = request("CreateLogGroup", json!({ "logGroupName": "group/a" }));
        let (status, headers, body) = response_with(&handler, create.clone()).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({}));
        assert_eq!(headers.get("x-amzn-requestid").unwrap(), "request-123");

        let (_, _, body) = response_with(&handler, create).await;
        assert_error(&body, "ResourceAlreadyExistsException");

        let delete = request("DeleteLogGroup", json!({ "logGroupName": "group/a" }));
        let (status, _, body) = response_with(&handler, delete.clone()).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({}));
        let (_, _, body) = response_with(&handler, delete).await;
        assert_error(&body, "ResourceNotFoundException");
    }

    #[tokio::test]
    async fn unsupported_create_fields_and_names_fail_before_mutation() {
        let handler = handler();
        for body in [
            json!({ "logGroupName": "kms", "kmsKeyId": "alias/key" }),
            json!({ "logGroupName": "protected", "deletionProtectionEnabled": false }),
            json!({ "logGroupName": "class", "logGroupClass": "INFREQUENT_ACCESS" }),
            json!({ "logGroupName": "unknown", "futureField": true }),
            json!({ "logGroupName": "aws/reserved" }),
        ] {
            let name = body["logGroupName"].as_str().unwrap().to_owned();
            let (_, _, error) = response_with(&handler, request("CreateLogGroup", body)).await;
            assert_error(&error, "InvalidParameterException");
            if !name.starts_with("aws/") {
                let (status, _, _) = response_with(
                    &handler,
                    request("CreateLogGroup", json!({ "logGroupName": name })),
                )
                .await;
                assert_eq!(status, 200);
            }
        }
    }

    #[tokio::test]
    async fn scope_comes_only_from_service_request() {
        let handler = handler();
        let mut first = request("CreateLogGroup", json!({ "logGroupName": "shared" }));
        first.account_id = "account-a".into();
        first.region = "region-a".into();
        assert_eq!(response_with(&handler, first).await.0, 200);

        let mut second = request("CreateLogGroup", json!({ "logGroupName": "shared" }));
        second.account_id = "account-b".into();
        second.region = "region-a".into();
        assert_eq!(response_with(&handler, second.clone()).await.0, 200);
        let (_, _, duplicate) = response_with(&handler, second).await;
        assert_error(&duplicate, "ResourceAlreadyExistsException");
    }

    #[tokio::test]
    async fn describe_orders_filters_and_serializes_current_group_fields() {
        let (handler, _) = handler_at(123_456);
        create(&handler, "z-last").await;
        create(&handler, "a-first").await;
        create(&handler, "other").await;
        let (status, _, body) = response_with(
            &handler,
            request(
                "PutRetentionPolicy",
                json!({ "logGroupName": "a-first", "retentionInDays": 30 }),
            ),
        )
        .await;
        assert_eq!(status, 200, "{body}");

        let (status, headers, body) = response_with(
            &handler,
            request("DescribeLogGroups", json!({ "logGroupNamePrefix": "a" })),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(headers.get("x-amzn-requestid").unwrap(), "request-123");
        assert_eq!(body["logGroups"].as_array().unwrap().len(), 1);
        let group = &body["logGroups"][0];
        assert_eq!(group["logGroupName"], "a-first");
        assert_eq!(group["creationTime"], 123_456);
        assert_eq!(group["retentionInDays"], 30);
        assert_eq!(group["logGroupClass"], "STANDARD");
        assert_eq!(group["metricFilterCount"], 0);
        assert_eq!(group["storedBytes"], 0);
        assert_eq!(
            group["logGroupArn"],
            "arn:aws:logs:us-east-1:000000000000:log-group:a-first"
        );
        assert_eq!(
            group["arn"],
            "arn:aws:logs:us-east-1:000000000000:log-group:a-first:*"
        );
        assert!(body.get("nextToken").is_none());

        let (_, _, all) = response_with(&handler, request("DescribeLogGroups", json!({}))).await;
        let names: Vec<_> = all["logGroups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|group| group["logGroupName"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["a-first", "other", "z-last"]);
    }

    #[tokio::test]
    async fn describe_tokens_are_stable_bound_and_tamper_evident() {
        let handler = handler();
        for name in ["alpha", "beta", "gamma"] {
            create(&handler, name).await;
        }
        let (_, _, first) = response_with(
            &handler,
            request("DescribeLogGroups", json!({ "limit": 1 })),
        )
        .await;
        assert_eq!(first["logGroups"][0]["logGroupName"], "alpha");
        let token = first["nextToken"].as_str().unwrap().to_owned();

        create(&handler, "aardvark").await;

        let mut wrong_scope = request(
            "DescribeLogGroups",
            json!({ "limit": 1, "nextToken": token }),
        );
        wrong_scope.account_id = "other-account".into();
        let (_, _, error) = response_with(&handler, wrong_scope).await;
        assert_error(&error, "InvalidParameterException");

        let (_, _, second) = response_with(
            &handler,
            request(
                "DescribeLogGroups",
                json!({ "limit": 1, "nextToken": first["nextToken"] }),
            ),
        )
        .await;
        assert_eq!(second["logGroups"][0]["logGroupName"], "beta");

        let (_, _, mismatch) = response_with(
            &handler,
            request(
                "DescribeLogGroups",
                json!({ "limit": 2, "nextToken": second["nextToken"] }),
            ),
        )
        .await;
        assert_error(&mismatch, "InvalidParameterException");

        let mut tampered = second["nextToken"].as_str().unwrap().to_owned();
        tampered.push('x');
        let (_, _, error) = response_with(
            &handler,
            request(
                "DescribeLogGroups",
                json!({ "limit": 1, "nextToken": tampered }),
            ),
        )
        .await;
        assert_error(&error, "InvalidParameterException");

        let (_, _, third) = response_with(
            &handler,
            request(
                "DescribeLogGroups",
                json!({ "limit": 1, "nextToken": second["nextToken"] }),
            ),
        )
        .await;
        assert_eq!(third["logGroups"][0]["logGroupName"], "gamma");
        assert!(third.get("nextToken").is_none());
    }

    #[tokio::test]
    async fn describe_token_expires_at_24_hours() {
        let (handler, clock) = handler_at(10_000);
        create(&handler, "a").await;
        create(&handler, "b").await;
        let (_, _, first) = response_with(
            &handler,
            request("DescribeLogGroups", json!({ "limit": 1 })),
        )
        .await;
        clock.set(10_000 + 24 * 60 * 60 * 1_000);
        let (_, _, body) = response_with(
            &handler,
            request(
                "DescribeLogGroups",
                json!({ "limit": 1, "nextToken": first["nextToken"] }),
            ),
        )
        .await;
        assert_error(&body, "InvalidParameterException");
    }

    #[tokio::test]
    async fn retention_policy_validates_updates_and_restores_indefinite_retention() {
        let handler = handler();
        create(&handler, "retained").await;

        for days in [0, 2, 3654] {
            let (_, _, body) = response_with(
                &handler,
                request(
                    "PutRetentionPolicy",
                    json!({ "logGroupName": "retained", "retentionInDays": days }),
                ),
            )
            .await;
            assert_error(&body, "InvalidParameterException");
        }

        let (status, _, body) = response_with(
            &handler,
            request(
                "PutRetentionPolicy",
                json!({ "logGroupName": "retained", "retentionInDays": 3653 }),
            ),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (_, _, described) =
            response_with(&handler, request("DescribeLogGroups", json!({}))).await;
        assert_eq!(described["logGroups"][0]["retentionInDays"], 3653);

        let (status, _, body) = response_with(
            &handler,
            request(
                "DeleteRetentionPolicy",
                json!({ "logGroupName": "retained" }),
            ),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (_, _, described) =
            response_with(&handler, request("DescribeLogGroups", json!({}))).await;
        assert!(described["logGroups"][0].get("retentionInDays").is_none());

        for operation in ["PutRetentionPolicy", "DeleteRetentionPolicy"] {
            let body = if operation == "PutRetentionPolicy" {
                json!({ "logGroupName": "missing", "retentionInDays": 30 })
            } else {
                json!({ "logGroupName": "missing" })
            };
            let (_, _, error) = response_with(&handler, request(operation, body)).await;
            assert_error(&error, "ResourceNotFoundException");
        }
    }

    #[tokio::test]
    async fn describe_rejects_unsupported_filters_and_invalid_limits() {
        let handler = handler();
        for body in [
            json!({ "limit": 0 }),
            json!({ "limit": 51 }),
            json!({ "includeLinkedAccounts": false }),
            json!({ "logGroupClass": "STANDARD" }),
            json!({ "logGroupNamePattern": "group" }),
            json!({ "futureField": true }),
        ] {
            let (_, _, error) = response_with(&handler, request("DescribeLogGroups", body)).await;
            assert_error(&error, "InvalidParameterException");
        }
    }

    #[tokio::test]
    async fn describe_tokens_remain_reusable_after_the_final_page() {
        let handler = handler();
        create(&handler, "a").await;
        create(&handler, "b").await;
        let (_, _, first) = response_with(
            &handler,
            request("DescribeLogGroups", json!({ "limit": 1 })),
        )
        .await;
        let token = first["nextToken"].clone();

        for _ in 0..2 {
            let (status, _, final_page) = response_with(
                &handler,
                request(
                    "DescribeLogGroups",
                    json!({ "limit": 1, "nextToken": token }),
                ),
            )
            .await;
            assert_eq!(status, 200, "{final_page}");
            assert_eq!(final_page["logGroups"][0]["logGroupName"], "b");
            assert!(final_page.get("nextToken").is_none());
        }
    }

    #[tokio::test]
    async fn pagination_capacity_never_revokes_an_active_token() {
        let handler = handler();
        create(&handler, "a").await;
        create(&handler, "b").await;
        let mut first_token = None;
        for index in 0..1_024 {
            let (status, _, page) = response_with(
                &handler,
                request("DescribeLogGroups", json!({ "limit": 1 })),
            )
            .await;
            assert_eq!(status, 200, "snapshot {index}: {page}");
            first_token.get_or_insert_with(|| page["nextToken"].clone());
        }

        let (status, _, capacity_error) = response_with(
            &handler,
            request("DescribeLogGroups", json!({ "limit": 1 })),
        )
        .await;
        assert_eq!(status, 500);
        assert_error(&capacity_error, "ServiceUnavailableException");

        let (status, _, page) = response_with(
            &handler,
            request(
                "DescribeLogGroups",
                json!({ "limit": 1, "nextToken": first_token.unwrap() }),
            ),
        )
        .await;
        assert_eq!(status, 200, "{page}");
        assert_eq!(page["logGroups"][0]["logGroupName"], "b");
    }
}
