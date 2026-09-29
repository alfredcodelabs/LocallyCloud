//! Concurrent service registry.
//!
//! Maps each canonical AWS service name to its disposition (`Native` / `Proxied`) and the
//! protocol metadata the router and error mapper need. Every known service defaults to
//! `Proxied`; a service is flipped to `Native` when its handler crate registers, without
//! changing router resolution logic. See Requirements 7 and 8.

use crate::audit::{CompletionObserver, DispatchOutcome};
use crate::handler::NativeHandler;
use crate::integration::authorization::{AuthorizationEvaluator, AUTHORIZATION_EVALUATOR_VERSION};
use crate::integration::kms::{KmsInternalApi, KMS_INTERNAL_API_VERSION};
use crate::integration::lambda::{LambdaInternalApi, LAMBDA_INTERNAL_API_VERSION};
use crate::integration::logs::{InternalLogSink, INTERNAL_LOG_SINK_VERSION};
use crate::integration::metrics::{MetricSink, METRIC_SINK_VERSION};
use crate::integration::InternalDispatcher;
use dashmap::DashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

/// The canonical AWS service identifier as it appears in the SigV4 credential scope, e.g.
/// `s3`, `dynamodb`, `states`. Always stored lowercase for case-insensitive matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceName(String);

impl ServiceName {
    pub fn new(name: impl AsRef<str>) -> Self {
        ServiceName(name.as_ref().to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// AWS wire protocol of a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsProtocol {
    RestXml,
    Query,
    Json10,
    Json11,
    RestJson,
}

/// Whether a service is handled in-process or forwarded to the legacy backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Native,
    Proxied,
}

/// Protocol metadata the router and error mapper rely on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMetadata {
    pub protocol: AwsProtocol,
    /// X-Amz-Target prefix for JSON-RPC services (e.g. `DynamoDB_20120810`).
    pub target_prefix: Option<String>,
    /// Known Query-protocol `Action` values used as a fallback resolution source.
    pub known_actions: Vec<String>,
}

impl ServiceMetadata {
    pub fn new(protocol: AwsProtocol, target_prefix: Option<&str>) -> Self {
        ServiceMetadata {
            protocol,
            target_prefix: target_prefix.map(str::to_string),
            known_actions: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct ServiceEntry {
    pub disposition: Disposition,
    pub metadata: ServiceMetadata,
    /// Present only for `Native` services registered with a handler.
    pub handler: Option<Arc<dyn NativeHandler>>,
    /// Optional typed capability published atomically with a concrete Monitoring handler.
    metric_sink: Option<Arc<dyn MetricSink>>,
    /// Optional typed capability published atomically with a concrete CloudWatch Logs handler.
    log_sink: Option<Arc<dyn InternalLogSink>>,
    /// Optional typed capability published atomically with the concrete KMS handler.
    kms_api: Option<Arc<dyn KmsInternalApi>>,
    /// Optional typed capability published atomically with the concrete Lambda handler.
    lambda_api: Option<Arc<dyn LambdaInternalApi>>,
    /// Optional typed capability published atomically with the IAM handler.
    authorization_evaluator: Option<Arc<dyn AuthorizationEvaluator>>,
}

/// Concurrent registry. Thread-safe for reads during request processing.
pub struct ServiceRegistry {
    services: DashMap<ServiceName, ServiceEntry>,
    internal_dispatcher: RwLock<Option<Arc<InternalDispatcher>>>,
    completion_sender: RwLock<Option<mpsc::Sender<DispatchOutcome>>>,
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        ServiceRegistry {
            services: DashMap::new(),
            internal_dispatcher: RwLock::new(None),
            completion_sender: RwLock::new(None),
        }
    }

    /// Install a bounded, nonblocking completed-dispatch queue. The observer must not hold
    /// this registry. A failed observer cannot affect the originating response.
    pub fn set_completion_observer(&self, observer: Arc<dyn CompletionObserver>) {
        let (sender, mut receiver) = mpsc::channel(1024);
        tokio::spawn(async move {
            while let Some(outcome) = receiver.recv().await {
                if catch_unwind(AssertUnwindSafe(|| observer.observe(outcome))).is_err() {
                    tracing::warn!("completion observer failed");
                }
            }
        });
        *self
            .completion_sender
            .write()
            .expect("observer lock poisoned") = Some(sender);
    }

    pub fn emit_completion(&self, outcome: DispatchOutcome) {
        if let Some(sender) = self
            .completion_sender
            .read()
            .expect("observer lock poisoned")
            .as_ref()
        {
            if sender.try_send(outcome).is_err() {
                tracing::warn!("completion observer queue dropped an outcome");
            }
        }
    }

    /// A registry seeded with the known AWS services, all `Proxied`. Service crates flip
    /// their own entry to `Native` at startup.
    pub fn with_known_services() -> Arc<Self> {
        let registry = Self::new();
        use AwsProtocol::*;
        let seed: &[(&str, AwsProtocol, Option<&str>)] = &[
            ("s3", RestXml, None),
            ("dynamodb", Json10, Some("DynamoDB_20120810")),
            ("streams.dynamodb", Json10, Some("DynamoDBStreams_20120810")),
            ("lambda", RestJson, None),
            ("sqs", Json10, Some("AmazonSQS")),
            ("sns", Query, None),
            ("iam", Query, None),
            ("sts", Query, None),
            ("cloudformation", Query, None),
            ("ec2", Query, None),
            ("elasticloadbalancing", Query, None),
            ("rds", Query, None),
            ("ecs", Json11, Some("AmazonEC2ContainerServiceV20141113")),
            ("ecr", Json11, Some("AmazonEC2ContainerRegistry_V20150921")),
            ("kms", Json11, Some("TrentService")),
            ("secretsmanager", Json11, Some("secretsmanager")),
            ("rds-data", RestJson, None),
            ("logs", Json11, Some("Logs_20140328")),
            ("monitoring", Json10, Some("GraniteServiceVersion20100801")),
            ("states", Json10, Some("AWSStepFunctions")),
            ("events", Json11, Some("AWSEvents")),
            ("schemas", RestJson, None),
            ("scheduler", RestJson, None),
            ("pipes", RestJson, None),
            ("apigateway", RestJson, None),
            ("execute-api", RestJson, None),
            ("kinesis", Json11, Some("Kinesis_20131202")),
            ("ssm", Json11, Some("AmazonSSM")),
            ("glue", Json11, Some("AWSGlue")),
            ("athena", Json11, Some("AmazonAthena")),
            (
                "cloudtrail",
                Json11,
                Some("com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101"),
            ),
            ("xray", RestJson, None),
            ("route53", RestXml, None),
            ("wafv2", Json11, Some("AWSWAF_20190729")),
            (
                "cognito-idp",
                Json11,
                Some("AWSCognitoIdentityProviderService"),
            ),
            ("acm", Json11, Some("CertificateManager")),
            ("cloudfront", RestXml, None),
        ];
        for (name, protocol, prefix) in seed {
            registry.register_proxied(
                ServiceName::new(name),
                ServiceMetadata::new(*protocol, *prefix),
            );
        }
        Arc::new(registry)
    }

    /// Register (or replace) a service as `Proxied`.
    pub fn register_proxied(&self, name: ServiceName, metadata: ServiceMetadata) {
        self.services.insert(
            name,
            ServiceEntry {
                disposition: Disposition::Proxied,
                metadata,
                handler: None,
                metric_sink: None,
                log_sink: None,
                kms_api: None,
                lambda_api: None,
                authorization_evaluator: None,
            },
        );
    }

    /// Register (or replace) a service as `Native` with its handler. Adding a service this
    /// way requires no change to the router (Req 8.6).
    pub fn register_native(
        &self,
        name: ServiceName,
        metadata: ServiceMetadata,
        handler: Arc<dyn NativeHandler>,
    ) {
        self.register_native_entry(name, metadata, handler, None, None, None, None, None);
    }

    /// Register Monitoring and its typed receiver in one observable transition.
    pub fn register_native_with_metric_sink(
        &self,
        name: ServiceName,
        metadata: ServiceMetadata,
        handler: Arc<dyn NativeHandler>,
        metric_sink: Arc<dyn MetricSink>,
    ) {
        self.register_native_entry(
            name,
            metadata,
            handler,
            Some(metric_sink),
            None,
            None,
            None,
            None,
        );
    }

    /// Register CloudWatch Logs and its typed producer sink in one observable transition.
    pub fn register_native_with_log_sink(
        &self,
        name: ServiceName,
        metadata: ServiceMetadata,
        handler: Arc<dyn NativeHandler>,
        log_sink: Arc<dyn InternalLogSink>,
    ) {
        self.register_native_entry(
            name,
            metadata,
            handler,
            None,
            Some(log_sink),
            None,
            None,
            None,
        );
    }

    /// Register KMS and its typed cryptographic capability in one observable transition.
    pub fn register_native_with_kms_api(
        &self,
        name: ServiceName,
        metadata: ServiceMetadata,
        handler: Arc<dyn NativeHandler>,
        kms_api: Arc<dyn KmsInternalApi>,
    ) {
        self.register_native_entry(
            name,
            metadata,
            handler,
            None,
            None,
            Some(kms_api),
            None,
            None,
        );
    }

    /// Register Lambda and its typed invocation capability in one observable transition.
    pub fn register_native_with_lambda_api(
        &self,
        name: ServiceName,
        metadata: ServiceMetadata,
        handler: Arc<dyn NativeHandler>,
        lambda_api: Arc<dyn LambdaInternalApi>,
    ) {
        self.register_native_entry(
            name,
            metadata,
            handler,
            None,
            None,
            None,
            Some(lambda_api),
            None,
        );
    }

    /// Register IAM and its typed authorization evaluator in one observable transition.
    pub fn register_native_with_authorization_evaluator(
        &self,
        name: ServiceName,
        metadata: ServiceMetadata,
        handler: Arc<dyn NativeHandler>,
        authorization_evaluator: Arc<dyn AuthorizationEvaluator>,
    ) {
        self.register_native_entry(
            name,
            metadata,
            handler,
            None,
            None,
            None,
            None,
            Some(authorization_evaluator),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn register_native_entry(
        &self,
        name: ServiceName,
        metadata: ServiceMetadata,
        handler: Arc<dyn NativeHandler>,
        metric_sink: Option<Arc<dyn MetricSink>>,
        log_sink: Option<Arc<dyn InternalLogSink>>,
        kms_api: Option<Arc<dyn KmsInternalApi>>,
        lambda_api: Option<Arc<dyn LambdaInternalApi>>,
        authorization_evaluator: Option<Arc<dyn AuthorizationEvaluator>>,
    ) {
        self.services.insert(
            name,
            ServiceEntry {
                disposition: Disposition::Native,
                metadata,
                handler: Some(handler),
                metric_sink,
                log_sink,
                kms_api,
                lambda_api,
                authorization_evaluator,
            },
        );
    }

    /// The native handler for a service, if one is registered.
    pub fn native_handler(&self, name: &ServiceName) -> Option<Arc<dyn NativeHandler>> {
        self.services.get(name).and_then(|entry| {
            (entry.disposition == Disposition::Native)
                .then(|| entry.handler.clone())
                .flatten()
        })
    }

    /// Resolve the version-compatible metric sink of a concrete native service.
    pub fn metric_sink(&self, name: &ServiceName) -> Option<Arc<dyn MetricSink>> {
        self.services.get(name).and_then(|entry| {
            if entry.disposition != Disposition::Native || entry.handler.is_none() {
                return None;
            }
            entry
                .metric_sink
                .as_ref()
                .filter(|sink| sink.version() == METRIC_SINK_VERSION)
                .cloned()
        })
    }

    /// Resolve the version-compatible producer log sink of a concrete native service.
    pub fn log_sink(&self, name: &ServiceName) -> Option<Arc<dyn InternalLogSink>> {
        self.services.get(name).and_then(|entry| {
            if entry.disposition != Disposition::Native || entry.handler.is_none() {
                return None;
            }
            entry
                .log_sink
                .as_ref()
                .filter(|sink| sink.version() == INTERNAL_LOG_SINK_VERSION)
                .cloned()
        })
    }

    /// Resolve the version-compatible internal KMS capability.
    pub fn kms_api(&self, name: &ServiceName) -> Option<Arc<dyn KmsInternalApi>> {
        self.services.get(name).and_then(|entry| {
            if entry.disposition != Disposition::Native || entry.handler.is_none() {
                return None;
            }
            entry
                .kms_api
                .as_ref()
                .filter(|api| api.version() == KMS_INTERNAL_API_VERSION)
                .cloned()
        })
    }

    /// Resolve the version-compatible internal Lambda capability.
    pub fn lambda_api(&self, name: &ServiceName) -> Option<Arc<dyn LambdaInternalApi>> {
        self.services.get(name).and_then(|entry| {
            if entry.disposition != Disposition::Native || entry.handler.is_none() {
                return None;
            }
            entry
                .lambda_api
                .as_ref()
                .filter(|api| api.version() == LAMBDA_INTERNAL_API_VERSION)
                .cloned()
        })
    }

    /// Resolve the version-compatible IAM authorization evaluator.
    pub fn authorization_evaluator(
        &self,
        name: &ServiceName,
    ) -> Option<Arc<dyn AuthorizationEvaluator>> {
        self.services.get(name).and_then(|entry| {
            if entry.disposition != Disposition::Native || entry.handler.is_none() {
                return None;
            }
            entry
                .authorization_evaluator
                .as_ref()
                .filter(|evaluator| evaluator.version() == AUTHORIZATION_EVALUATOR_VERSION)
                .cloned()
        })
    }

    /// Install the dispatcher shared by external requests and in-process service calls.
    pub fn set_internal_dispatcher(&self, dispatcher: Arc<InternalDispatcher>) {
        *self
            .internal_dispatcher
            .write()
            .expect("dispatcher lock poisoned") = Some(dispatcher);
    }

    /// Return the shared dispatcher when server wiring has installed it.
    pub fn internal_dispatcher(&self) -> Option<Arc<InternalDispatcher>> {
        self.internal_dispatcher
            .read()
            .expect("dispatcher lock poisoned")
            .clone()
    }

    /// Look up a service entry by canonical name.
    pub fn lookup(&self, name: &ServiceName) -> Option<ServiceEntry> {
        self.services.get(name).map(|e| e.clone())
    }

    /// Disposition of a service: `Native` only if registered as such, `Proxied` otherwise
    /// (including unregistered services).
    pub fn disposition(&self, name: &ServiceName) -> Disposition {
        self.services
            .get(name)
            .map(|e| e.disposition)
            .unwrap_or(Disposition::Proxied)
    }

    /// Resolve a service by the longest registered `X-Amz-Target` prefix that the target
    /// value begins with.
    pub fn lookup_by_target_prefix(&self, target: &str) -> Option<ServiceName> {
        let mut best: Option<(ServiceName, usize)> = None;
        for entry in self.services.iter() {
            if let Some(prefix) = &entry.value().metadata.target_prefix {
                if target.starts_with(prefix.as_str()) {
                    let len = prefix.len();
                    if best.as_ref().map(|(_, b)| len > *b).unwrap_or(true) {
                        best = Some((entry.key().clone(), len));
                    }
                }
            }
        }
        best.map(|(name, _)| name)
    }

    /// Resolve a service by a Query-protocol `Action` value.
    pub fn lookup_by_action(&self, action: &str) -> Option<ServiceName> {
        for entry in self.services.iter() {
            if entry
                .value()
                .metadata
                .known_actions
                .iter()
                .any(|a| a == action)
            {
                return Some(entry.key().clone());
            }
        }
        None
    }

    /// A name-sorted snapshot of every registered service for status/UI reporting.
    pub fn statuses(&self) -> Vec<ServiceStatus> {
        let mut out: Vec<ServiceStatus> = self
            .services
            .iter()
            .map(|e| ServiceStatus {
                name: e.key().as_str().to_string(),
                protocol: e.value().metadata.protocol,
                disposition: e.value().disposition,
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

/// A read-only snapshot of one service's registration, for status/UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub name: String,
    pub protocol: AwsProtocol,
    pub disposition: Disposition,
}

impl AwsProtocol {
    /// Stable label for status/UI reporting.
    pub fn as_str(&self) -> &'static str {
        match self {
            AwsProtocol::RestXml => "REST-XML",
            AwsProtocol::Query => "Query",
            AwsProtocol::Json10 => "JSON 1.0",
            AwsProtocol::Json11 => "JSON 1.1",
            AwsProtocol::RestJson => "REST-JSON",
        }
    }
}

impl Disposition {
    /// Stable label for status/UI reporting (`Native` = in-process, `Proxied` = forwarded).
    pub fn as_str(&self) -> &'static str {
        match self {
            Disposition::Native => "Native",
            Disposition::Proxied => "Proxied",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::ServiceRequest;
    use axum::body::Body;
    use axum::response::Response;

    struct TestHandler;

    #[async_trait::async_trait]
    impl NativeHandler for TestHandler {
        async fn handle(&self, _request: ServiceRequest) -> Response {
            Response::new(Body::empty())
        }
    }

    #[test]
    fn known_services_default_to_proxied() {
        let reg = ServiceRegistry::with_known_services();
        assert_eq!(
            reg.disposition(&ServiceName::new("s3")),
            Disposition::Proxied
        );
        assert_eq!(
            reg.disposition(&ServiceName::new("states")),
            Disposition::Proxied
        );
    }

    #[test]
    fn unregistered_service_is_proxied() {
        let reg = ServiceRegistry::with_known_services();
        assert_eq!(
            reg.disposition(&ServiceName::new("opensearch")),
            Disposition::Proxied
        );
    }

    #[test]
    fn register_native_installs_handler_with_native_disposition() {
        let reg = ServiceRegistry::with_known_services();
        let handler: Arc<dyn NativeHandler> = Arc::new(TestHandler);
        reg.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::clone(&handler),
        );
        let entry = reg.lookup(&ServiceName::new("lambda")).unwrap();
        assert_eq!(entry.disposition, Disposition::Native);
        assert!(entry.handler.is_some());
    }

    #[test]
    fn service_name_is_case_insensitive() {
        let reg = ServiceRegistry::with_known_services();
        assert_eq!(
            reg.disposition(&ServiceName::new("DynamoDB")),
            Disposition::Proxied
        );
        assert!(reg.lookup(&ServiceName::new("DYNAMODB")).is_some());
    }

    #[test]
    fn target_prefix_resolves_service() {
        let reg = ServiceRegistry::with_known_services();
        let svc = reg.lookup_by_target_prefix("DynamoDB_20120810.GetItem");
        assert_eq!(svc, Some(ServiceName::new("dynamodb")));
        let sfn = reg.lookup_by_target_prefix("AWSStepFunctions.StartExecution");
        assert_eq!(sfn, Some(ServiceName::new("states")));
    }

    #[test]
    fn longest_target_prefix_wins() {
        let reg = ServiceRegistry::new();
        reg.register_proxied(
            ServiceName::new("dynamodb"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("DynamoDB_20120810")),
        );
        reg.register_proxied(
            ServiceName::new("streams.dynamodb"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("DynamoDBStreams_20120810")),
        );
        // "DynamoDBStreams_..." starts with neither "DynamoDB_" — distinct prefixes; check the
        // streams target resolves to the streams service and the plain target to dynamodb.
        assert_eq!(
            reg.lookup_by_target_prefix("DynamoDBStreams_20120810.GetRecords"),
            Some(ServiceName::new("streams.dynamodb"))
        );
        assert_eq!(
            reg.lookup_by_target_prefix("DynamoDB_20120810.PutItem"),
            Some(ServiceName::new("dynamodb"))
        );
    }

    #[test]
    fn lookup_by_action_uses_known_actions() {
        let reg = ServiceRegistry::new();
        let mut meta = ServiceMetadata::new(AwsProtocol::Query, None);
        meta.known_actions = vec!["Publish".to_string(), "CreateTopic".to_string()];
        reg.register_proxied(ServiceName::new("sns"), meta);
        assert_eq!(
            reg.lookup_by_action("Publish"),
            Some(ServiceName::new("sns"))
        );
        assert_eq!(reg.lookup_by_action("Unknown"), None);
    }
}
