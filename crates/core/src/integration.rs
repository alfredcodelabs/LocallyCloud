//! Internal dispatch — the single request-handling path.
//!
//! Both external client requests (from the server) and cross-service calls (one emulated
//! service invoking another, or an in-Guest SDK call) flow through
//! [`InternalDispatcher::dispatch`], so they resolve through the same router and registry
//! and honour the target's disposition identically. See Requirement 23 and the
//! `locallycloud-integration` spec.

use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use axum::extract::ws::WebSocketUpgrade;
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Uri};
use tokio::sync::Semaphore;

use crate::audit::DispatchOutcome;
use crate::error_mapping::{AwsError, RenderedError};
use crate::handler::ServiceRequest;
use crate::observability::log_routing_decision;
use crate::proxy::{forward_to_legacy, LegacyHealth, ProxyConfig};
use crate::registry::{AwsProtocol, ServiceName, ServiceRegistry};
use crate::router::{
    cognito_public_region, extract_region_from_credential_scope, resolve, RouteDisposition,
    RouteInput,
};

pub mod arn;
pub mod authorization;
pub mod correlation;
pub mod delivery;
pub mod guest;
pub mod identity;
pub mod kms;
pub mod lambda;
pub mod logs;
pub mod metrics;
pub mod pattern;
pub mod sigv4;

pub struct InternalDispatcher {
    registry: Weak<ServiceRegistry>,
    // Standalone dispatchers retain their registry. Registry-installed dispatchers omit this
    // owner so ServiceRegistry -> InternalDispatcher -> ServiceRegistry cannot form an Arc cycle.
    _registry_owner: Option<Arc<ServiceRegistry>>,
    proxy_config: ProxyConfig,
    legacy_health: LegacyHealth,
    default_region: String,
    account_id: String,
    meter: Option<Arc<crate::metering::Meter>>,
    kms_blocking_slots: Arc<Semaphore>,
}

/// The authenticated request principal, resolved from the SigV4 credential scope and
/// propagated along the single dispatch path. Consumed by IAM strict-mode enforcement to
/// resolve the caller's policies (Requirement 22.7). Distinct from the cross-service
/// [`identity::CallerIdentity`], which attributes a *delegated* identity to a hop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestIdentity {
    pub account_id: String,
    /// SigV4 access-key identifier (`AKIA…` long-term, `ASIA…` session), when present.
    pub access_key_id: Option<String>,
    /// Caller ARN when known (e.g. an assumed-role session); `None` for an unscoped caller.
    pub arn: Option<String>,
}

impl RequestIdentity {
    /// Extract the access-key identifier from an `Authorization: AWS4-HMAC-SHA256
    /// Credential=<access-key>/<date>/<region>/<service>/aws4_request` header.
    pub fn access_key_from_authorization(authorization: &str) -> Option<String> {
        authorization
            .split("Credential=")
            .nth(1)?
            .split('/')
            .next()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }
}

impl InternalDispatcher {
    pub fn new(
        registry: Arc<ServiceRegistry>,
        proxy_config: ProxyConfig,
        legacy_health: LegacyHealth,
        default_region: String,
        account_id: String,
    ) -> Self {
        InternalDispatcher {
            registry: Arc::downgrade(&registry),
            _registry_owner: Some(registry),
            proxy_config,
            legacy_health,
            default_region,
            account_id,
            meter: None,
            kms_blocking_slots: Arc::new(Semaphore::new(32)),
        }
    }

    /// Construct a dispatcher owned by the registry itself, without creating an Arc cycle.
    pub fn new_shared(
        registry: &Arc<ServiceRegistry>,
        proxy_config: ProxyConfig,
        legacy_health: LegacyHealth,
        default_region: String,
        account_id: String,
    ) -> Self {
        InternalDispatcher {
            registry: Arc::downgrade(registry),
            _registry_owner: None,
            proxy_config,
            legacy_health,
            default_region,
            account_id,
            meter: None,
            kms_blocking_slots: Arc::new(Semaphore::new(32)),
        }
    }

    /// Attach a usage [`Meter`](crate::metering::Meter); every dispatched request to a resolved
    /// service is recorded. Optional so existing call sites and tests are unaffected.
    pub fn with_meter(mut self, meter: Arc<crate::metering::Meter>) -> Self {
        self.meter = Some(meter);
        self
    }

    /// Evaluate one native-service authorization request through IAM/STS.
    pub fn authorize(
        &self,
        request: authorization::AuthorizationRequest,
    ) -> Result<(), authorization::AuthorizationError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(authorization::AuthorizationError::Unavailable)?;
        let evaluator = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .ok_or(authorization::AuthorizationError::Unavailable)?;
        evaluator.authorize(request)
    }

    /// Validate a service role through the registered IAM capability.
    pub fn authorize_service_role(
        &self,
        request: authorization::ServiceRoleAuthorizationRequest,
    ) -> Result<(), authorization::AuthorizationError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(authorization::AuthorizationError::Unavailable)?;
        let evaluator = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .ok_or(authorization::AuthorizationError::Unavailable)?;
        evaluator.authorize_service_role(request)
    }

    /// Whether IAM requires authorization at this service boundary.
    pub fn strict_sigv4_required(&self) -> bool {
        self.registry
            .upgrade()
            .and_then(|registry| registry.authorization_evaluator(&ServiceName::new("iam")))
            .is_some_and(|evaluator| evaluator.strict_sigv4_required())
    }

    /// Resolve the caller from IAM/STS credentials for downstream resource policies.
    pub fn resolve_caller_arn(
        &self,
        identity: &RequestIdentity,
    ) -> Result<Option<String>, authorization::AuthorizationError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(authorization::AuthorizationError::Unavailable)?;
        let evaluator = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .ok_or(authorization::AuthorizationError::Unavailable)?;
        evaluator.resolve_caller_arn(identity)
    }

    pub fn identity_policy_denies(&self, request: authorization::AuthorizationRequest) -> bool {
        self.registry
            .upgrade()
            .and_then(|registry| registry.authorization_evaluator(&ServiceName::new("iam")))
            .is_none_or(|evaluator| evaluator.identity_policy_denies(request))
    }

    pub fn identity_policy_allows(&self, request: authorization::AuthorizationRequest) -> bool {
        self.registry
            .upgrade()
            .and_then(|registry| registry.authorization_evaluator(&ServiceName::new("iam")))
            .is_some_and(|evaluator| evaluator.identity_policy_allows(request))
    }

    /// Encrypt sensitive bytes through the registered native KMS capability.
    pub fn kms_encrypt(
        &self,
        request: kms::KmsEncryptRequest,
    ) -> Result<kms::KmsEncryptOutput, kms::KmsInternalError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(kms::KmsInternalError::Unavailable)?;
        let api = registry
            .kms_api(&ServiceName::new("kms"))
            .ok_or(kms::KmsInternalError::Unavailable)?;
        api.encrypt(request)
    }

    /// Decrypt sensitive bytes through the registered native KMS capability.
    pub fn kms_decrypt(
        &self,
        request: kms::KmsDecryptRequest,
    ) -> Result<kms::KmsDecryptOutput, kms::KmsInternalError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(kms::KmsInternalError::Unavailable)?;
        let api = registry
            .kms_api(&ServiceName::new("kms"))
            .ok_or(kms::KmsInternalError::Unavailable)?;
        api.decrypt(request)
    }

    /// Bound the caller's wait for synchronous KMS work. A timed-out worker may finish later,
    /// but its result is discarded and the caller must never publish prepared state.
    pub async fn kms_encrypt_bounded(
        &self,
        request: kms::KmsEncryptRequest,
        limit: Duration,
    ) -> Result<kms::KmsEncryptOutput, kms::KmsInternalError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(kms::KmsInternalError::Unavailable)?;
        let api = registry
            .kms_api(&ServiceName::new("kms"))
            .ok_or(kms::KmsInternalError::Unavailable)?;
        let permit = self
            .kms_blocking_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| kms::KmsInternalError::Unavailable)?;
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            api.encrypt(request)
        });
        match tokio::time::timeout(limit, worker).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => Err(kms::KmsInternalError::Internal),
        }
    }

    /// Bound data-key generation before an SQS message can be published.
    pub async fn kms_generate_data_key_bounded(
        &self,
        request: kms::KmsGenerateDataKeyRequest,
        limit: Duration,
    ) -> Result<kms::KmsGenerateDataKeyOutput, kms::KmsInternalError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(kms::KmsInternalError::Unavailable)?;
        let api = registry
            .kms_api(&ServiceName::new("kms"))
            .ok_or(kms::KmsInternalError::Unavailable)?;
        let permit = self
            .kms_blocking_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| kms::KmsInternalError::Unavailable)?;
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            api.generate_data_key(request)
        });
        match tokio::time::timeout(limit, worker).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => Err(kms::KmsInternalError::Internal),
        }
    }

    /// See [`Self::kms_encrypt_bounded`]; late plaintext is dropped by the detached worker.
    pub async fn kms_decrypt_bounded(
        &self,
        request: kms::KmsDecryptRequest,
        limit: Duration,
    ) -> Result<kms::KmsDecryptOutput, kms::KmsInternalError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(kms::KmsInternalError::Unavailable)?;
        let api = registry
            .kms_api(&ServiceName::new("kms"))
            .ok_or(kms::KmsInternalError::Unavailable)?;
        let permit = self
            .kms_blocking_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| kms::KmsInternalError::Unavailable)?;
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            api.decrypt(request)
        });
        match tokio::time::timeout(limit, worker).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) | Err(_) => Err(kms::KmsInternalError::Internal),
        }
    }

    /// Resolve an enabled KMS key through the registered native KMS capability.
    pub fn kms_validate_key(
        &self,
        request: kms::KmsValidateKeyRequest,
    ) -> Result<kms::KmsValidateKeyOutput, kms::KmsInternalError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(kms::KmsInternalError::Unavailable)?;
        let api = registry
            .kms_api(&ServiceName::new("kms"))
            .ok_or(kms::KmsInternalError::Unavailable)?;
        api.validate_key(request)
    }

    /// Invoke a function synchronously through the registered native Lambda capability.
    pub async fn lambda_invoke(
        &self,
        request: lambda::LambdaInvokeRequest,
    ) -> Result<lambda::LambdaInvokeOutput, lambda::LambdaInternalError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(lambda::LambdaInternalError::Unavailable)?;
        let api = registry
            .lambda_api(&ServiceName::new("lambda"))
            .ok_or(lambda::LambdaInternalError::Unavailable)?;
        api.invoke(request).await
    }

    /// Resolve, log, and handle one request. Proxied services are forwarded to the legacy
    /// backend; native services are dispatched in-process (placeholder until handlers land);
    /// an unresolved request returns an AWS-shaped 400.
    pub async fn dispatch(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
        request_id: &str,
    ) -> Response {
        self.dispatch_in_scope(
            method, uri, headers, body, request_id, None, false, None, None,
        )
        .await
    }

    /// Dashboard region selection is an external request, never a trusted account scope.
    pub(crate) async fn dispatch_dashboard(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
        region: &str,
        service: &str,
    ) -> Response {
        let regional = Self {
            registry: self.registry.clone(),
            _registry_owner: self._registry_owner.clone(),
            proxy_config: self.proxy_config.clone(),
            legacy_health: self.legacy_health.clone(),
            default_region: region.to_owned(),
            account_id: self.account_id.clone(),
            meter: self.meter.clone(),
            kms_blocking_slots: self.kms_blocking_slots.clone(),
        };
        regional
            .dispatch_in_scope(
                method,
                uri,
                headers,
                body,
                &crate::observability::new_request_id(),
                None,
                false,
                None,
                Some(service),
            )
            .await
    }

    /// Dispatch an external request with the peer IP supplied by Axum ConnectInfo.
    /// Client headers never supply this value.
    pub async fn dispatch_verified_peer(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
        request_id: &str,
        peer_ip: IpAddr,
    ) -> Response {
        self.dispatch_in_scope(
            method,
            uri,
            headers,
            body,
            request_id,
            None,
            false,
            Some(peer_ip),
            None,
        )
        .await
    }

    /// Dispatch an in-process request with an explicit trusted account and region scope.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_scoped(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
        request_id: &str,
        account_id: &str,
        region: &str,
    ) -> Response {
        self.dispatch_in_scope(
            method,
            uri,
            headers,
            body,
            request_id,
            Some((account_id, region)),
            false,
            None,
            None,
        )
        .await
    }

    /// Trusted sink dispatch. Suppression is a function argument, never a client header.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_scoped_suppressed(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
        request_id: &str,
        account_id: &str,
        region: &str,
    ) -> Response {
        self.dispatch_in_scope(
            method,
            uri,
            headers,
            body,
            request_id,
            Some((account_id, region)),
            true,
            None,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_in_scope(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
        request_id: &str,
        scope: Option<(&str, &str)>,
        suppressed: bool,
        peer_ip: Option<IpAddr>,
        dashboard_service: Option<&str>,
    ) -> Response {
        let started_at = SystemTime::now();
        let authorization = header_str(headers, "authorization");
        let x_amz_target = header_str(headers, "x-amz-target");
        let host = header_str(headers, "host");
        let path = uri.path().to_string();
        let x_amz_credential = uri.query().and_then(extract_x_amz_credential);
        let mut region = scope
            .map(|(_, region)| region.to_owned())
            .unwrap_or_else(|| {
                extract_region_from_credential_scope(
                    authorization.as_deref(),
                    x_amz_credential.as_deref(),
                )
                .or_else(|| cognito_public_region(&path).map(str::to_string))
                .unwrap_or_else(|| self.default_region.clone())
            });
        let account_id = scope
            .map(|(account, _)| account.to_owned())
            .unwrap_or_else(|| self.account_id.clone());
        let input = RouteInput {
            authorization: authorization.as_deref(),
            x_amz_credential: x_amz_credential.as_deref(),
            x_amz_target: x_amz_target.as_deref(),
            host: host.as_deref(),
            path: &path,
            body: &body,
        };
        let Some(registry) = self.registry.upgrade() else {
            let err = AwsError::new("InternalFailure", "service registry is unavailable", 500)
                .with_request_id(request_id.to_string());
            return render(err.render(AwsProtocol::RestJson));
        };
        // The read allowlist already selected a service. Unsigned instance reads may
        // lack an AWS routing hint or share paths (ECR/API Gateway). Selecting a
        // destination never supplies an IAM scope or skips signature verification.
        let selected = dashboard_service.and_then(|service| {
            let service_name = ServiceName::new(service);
            registry.native_handler(&service_name)?;
            Some(crate::router::RoutingDecision {
                service_name,
                resolution_source: crate::router::ResolutionSource::DashboardSelection,
                disposition: RouteDisposition::HandledNatively,
            })
        });
        let public_invoke_region = if scope.is_none()
            && dashboard_service.is_none()
            && !claims_sigv4_identity(authorization.as_deref(), x_amz_credential.as_deref())
        {
            match registry.native_handler(&ServiceName::new("execute-api")) {
                Some(handler) => {
                    handler
                        .public_invoke_region(&account_id, host.as_deref().unwrap_or(""), &path)
                        .await
                }
                None => None,
            }
        } else {
            None
        };
        let Some(decision) = selected
            .or_else(|| resolve(&registry, &input).ok())
            .or_else(|| {
                public_invoke_region
                    .as_ref()
                    .map(|_| crate::router::RoutingDecision {
                        service_name: ServiceName::new("execute-api"),
                        resolution_source: crate::router::ResolutionSource::HostPath,
                        disposition: RouteDisposition::HandledNatively,
                    })
            })
            .filter(|decision| crate::router::permits_method(decision, method))
        else {
            tracing::warn!(request_id, path = %path, "unresolved request");
            let err = AwsError::new(
                "InvalidRequest",
                "could not resolve a target AWS service for the request",
                400,
            )
            .with_request_id(request_id.to_string());
            return render(err.render(AwsProtocol::RestJson));
        };
        let public_invoke =
            decision.service_name.as_str() == "execute-api" && public_invoke_region.is_some();
        if public_invoke {
            region = public_invoke_region.expect("public invocation resolved a region");
        }
        log_routing_decision(&decision, request_id);
        if let Some(meter) = &self.meter {
            meter.record(decision.service_name.as_str(), body.len() as u64);
        }
        let protocol = registry
            .lookup(&decision.service_name)
            .map(|entry| entry.metadata.protocol)
            .unwrap_or(AwsProtocol::RestJson);
        let operation = safe_operation(
            decision.service_name.as_str(),
            method,
            uri,
            x_amz_target.as_deref(),
            &body,
        );
        let resource = crate::activity::resource_name(decision.service_name.as_str(), &path, &body);
        // This excludes only dashboard reads from diagnostics, never from the audit observer.
        let dashboard_read = headers
            .get("x-locallycloud-dashboard")
            .is_some_and(|v| v == "1")
            && (*method == Method::GET
                || ["List", "Describe", "Get", "Filter"]
                    .iter()
                    .any(|prefix| operation.starts_with(prefix))
                || (decision.service_name.as_str() == "dynamodb"
                    && matches!(operation.as_str(), "Scan" | "Query")));
        let ecr_token_request = decision.service_name.as_str() == "ecr"
            && x_amz_target.as_deref()
                == Some("AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken");
        let ecs_verified_request = decision.service_name.as_str() == "ecs";
        let evaluator = registry.authorization_evaluator(&ServiceName::new("iam"));
        let strict_external = scope.is_none()
            && evaluator
                .as_ref()
                .is_some_and(|evaluator| evaluator.strict_sigv4_required());
        let public_request = public_invoke
            || unsigned_public_request(
                decision.service_name.as_str(),
                method,
                uri,
                headers,
                host.as_deref(),
            );
        let verify_external = strict_external
            && (!public_request
                || claims_sigv4_identity(authorization.as_deref(), x_amz_credential.as_deref()));
        let mut signature_rejected = false;
        if ecr_token_request || ecs_verified_request || verify_external {
            // DynamoDB Streams is routed separately but signed with the dynamodb service name.
            let signing_service = if decision.service_name.as_str() == "streams.dynamodb" {
                "dynamodb"
            } else {
                decision.service_name.as_str()
            };
            let verified = evaluator.as_ref().is_some_and(|evaluator| {
                evaluator.verify_sigv4(
                    &account_id,
                    method,
                    uri,
                    headers,
                    &body,
                    &region,
                    signing_service,
                )
            });
            if !verified {
                signature_rejected = true;
            }
        }
        let response = if signature_rejected {
            invalid_signature(request_id, protocol)
        } else {
            match decision.disposition {
                RouteDisposition::ProxiedToLegacy => {
                    if !self.legacy_health.is_healthy() {
                        tracing::warn!(
                            request_id,
                            service = decision.service_name.as_str(),
                            "legacy backend known unhealthy; fast-failing proxied request"
                        );
                        render(
                            AwsError::new("BadGateway", "legacy backend is unhealthy", 502)
                                .with_request_id(request_id.to_string())
                                .render(protocol),
                        )
                    } else {
                        match forward_to_legacy(method, uri, headers, body, &self.proxy_config)
                            .await
                        {
                            Ok(response) => response,
                            Err(error) => {
                                tracing::warn!(request_id, service = decision.service_name.as_str(), cause = %error,
                                "legacy backend forwarding failed");
                                render(
                                    AwsError::new(
                                        error.code(),
                                        error.to_string(),
                                        error.http_status(),
                                    )
                                    .with_request_id(request_id.to_string())
                                    .render(protocol),
                                )
                            }
                        }
                    }
                }
                RouteDisposition::HandledNatively => {
                    match registry.native_handler(&decision.service_name) {
                        Some(handler) => {
                            let mut native_headers = headers.clone();
                            native_headers.remove("x-locallycloud-trusted-peer-ip");
                            native_headers.remove("x-locallycloud-verified-ecr-sigv4");
                            // Only Core can attest that an external caller passed strict SigV4.
                            // Strip any client-supplied value before native dispatch.
                            native_headers.remove("x-locallycloud-verified-external-sigv4");
                            native_headers.remove("x-locallycloud-verified-internal-scope");
                            if scope.is_none() {
                                native_headers.remove(identity::PRINCIPAL_HEADER);
                            }
                            if scope.is_some() {
                                native_headers.insert(
                                    "x-locallycloud-verified-internal-scope",
                                    HeaderValue::from_static("1"),
                                );
                            }
                            if strict_external && verify_external {
                                native_headers.insert(
                                    "x-locallycloud-verified-external-sigv4",
                                    HeaderValue::from_static("1"),
                                );
                            }
                            if ecr_token_request {
                                native_headers.insert(
                                    "x-locallycloud-verified-ecr-sigv4",
                                    HeaderValue::from_static("1"),
                                );
                            }
                            if matches!(
                                decision.service_name.as_str(),
                                "apigateway" | "apigatewayv2" | "execute-api"
                            ) {
                                if let Some(peer_ip) = peer_ip {
                                    if let Ok(value) = HeaderValue::from_str(&peer_ip.to_string()) {
                                        native_headers
                                            .insert("x-locallycloud-trusted-peer-ip", value);
                                    }
                                }
                            }
                            handler
                                .handle(ServiceRequest {
                                    method: method.clone(),
                                    uri: uri.clone(),
                                    headers: native_headers,
                                    body,
                                    region: region.clone(),
                                    account_id: account_id.clone(),
                                    request_id: request_id.to_string(),
                                })
                                .await
                        }
                        None => render(
                            AwsError::new(
                                "NotImplementedException",
                                "native service has no handler registered",
                                501,
                            )
                            .with_request_id(request_id.to_string())
                            .render(protocol),
                        ),
                    }
                }
            }
        };
        if !suppressed {
            let error_code = response
                .headers()
                .get("x-amzn-errortype")
                .or_else(|| response.headers().get("x-amz-function-error"))
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.rsplit('#').next())
                .and_then(|value| value.split(':').next())
                .filter(|value| {
                    value.len() <= 128
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                })
                .map(str::to_string);
            let outcome = DispatchOutcome {
                dispatch_id: uuid::Uuid::new_v4().to_string(),
                request_id: request_id.chars().take(128).collect(),
                account_id,
                region,
                service: decision.service_name.as_str().to_string(),
                operation,
                protocol,
                disposition: match decision.disposition {
                    RouteDisposition::HandledNatively => crate::registry::Disposition::Native,
                    RouteDisposition::ProxiedToLegacy => crate::registry::Disposition::Proxied,
                },
                started_at,
                completed_at: SystemTime::now(),
                http_status: response.status().as_u16(),
                error_code,
            };
            if !dashboard_read {
                registry.activity.record(&outcome, resource);
            }
            if decision.service_name.as_str() != "cloudtrail" {
                registry.emit_completion(outcome);
            }
        }
        response
    }

    /// Resolve and dispatch a WebSocket upgrade without reading its request body.
    pub async fn dispatch_websocket(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        upgrade: WebSocketUpgrade,
        request_id: &str,
    ) -> Response {
        let authorization = header_str(headers, "authorization");
        let x_amz_target = header_str(headers, "x-amz-target");
        let host = header_str(headers, "host");
        let path = uri.path().to_string();
        let x_amz_credential = uri.query().and_then(extract_x_amz_credential);
        let body = Bytes::new();

        let input = RouteInput {
            authorization: authorization.as_deref(),
            x_amz_credential: x_amz_credential.as_deref(),
            x_amz_target: x_amz_target.as_deref(),
            host: host.as_deref(),
            path: &path,
            body: &body,
        };

        let Some(registry) = self.registry.upgrade() else {
            let err = AwsError::new("InternalFailure", "service registry is unavailable", 500)
                .with_request_id(request_id.to_string());
            return render(err.render(AwsProtocol::RestJson));
        };

        let public_invoke_region =
            if !claims_sigv4_identity(authorization.as_deref(), x_amz_credential.as_deref()) {
                match registry.native_handler(&ServiceName::new("execute-api")) {
                    Some(handler) => {
                        handler
                            .public_invoke_region(
                                &self.account_id,
                                host.as_deref().unwrap_or(""),
                                &path,
                            )
                            .await
                    }
                    None => None,
                }
            } else {
                None
            };
        let decision = resolve(&registry, &input).or_else(|error| {
            public_invoke_region
                .as_ref()
                .map(|_| crate::router::RoutingDecision {
                    service_name: ServiceName::new("execute-api"),
                    resolution_source: crate::router::ResolutionSource::HostPath,
                    disposition: RouteDisposition::HandledNatively,
                })
                .ok_or(error)
        });
        match decision {
            Ok(decision) => {
                log_routing_decision(&decision, request_id);
                if let Some(meter) = &self.meter {
                    meter.record(decision.service_name.as_str(), 0);
                }
                let protocol = registry
                    .lookup(&decision.service_name)
                    .map(|e| e.metadata.protocol)
                    .unwrap_or(AwsProtocol::RestJson);
                let region = extract_region_from_credential_scope(
                    authorization.as_deref(),
                    x_amz_credential.as_deref(),
                )
                .or_else(|| {
                    (decision.service_name.as_str() == "execute-api")
                        .then_some(public_invoke_region)
                        .flatten()
                })
                .unwrap_or_else(|| self.default_region.clone());
                let evaluator = registry.authorization_evaluator(&ServiceName::new("iam"));
                let strict = evaluator
                    .as_ref()
                    .is_some_and(|evaluator| evaluator.strict_sigv4_required());
                // An upgrade is a long-lived connection; strict mode requires a verified
                // caller even when the corresponding HTTP invoke route is public.
                if strict {
                    let signing_service = if decision.service_name.as_str() == "streams.dynamodb" {
                        "dynamodb"
                    } else {
                        decision.service_name.as_str()
                    };
                    let verified = evaluator.as_ref().is_some_and(|evaluator| {
                        evaluator.verify_sigv4(
                            &self.account_id,
                            method,
                            uri,
                            headers,
                            &body,
                            &region,
                            signing_service,
                        )
                    });
                    if !verified {
                        return invalid_signature(request_id, protocol);
                    }
                }
                match decision.disposition {
                    RouteDisposition::ProxiedToLegacy => {
                        let err = AwsError::new(
                            "NotImplementedException",
                            "WebSocket upgrades cannot be proxied to the legacy backend",
                            501,
                        )
                        .with_request_id(request_id.to_string());
                        render(err.render(protocol))
                    }
                    RouteDisposition::HandledNatively => {
                        match registry.native_handler(&decision.service_name) {
                            Some(handler) => {
                                let request = ServiceRequest {
                                    method: method.clone(),
                                    uri: uri.clone(),
                                    headers: headers.clone(),
                                    body,
                                    region,
                                    account_id: self.account_id.clone(),
                                    request_id: request_id.to_string(),
                                };
                                handler.handle_websocket(request, upgrade).await
                            }
                            None => {
                                let err = AwsError::new(
                                    "NotImplementedException",
                                    "native service has no handler registered",
                                    501,
                                )
                                .with_request_id(request_id.to_string());
                                render(err.render(protocol))
                            }
                        }
                    }
                }
            }
            Err(_unresolved) => {
                tracing::warn!(request_id, path = %path, "unresolved WebSocket request");
                let err = AwsError::new(
                    "InvalidRequest",
                    "could not resolve a target AWS service for the request",
                    400,
                )
                .with_request_id(request_id.to_string());
                render(err.render(AwsProtocol::RestJson))
            }
        }
    }
}

fn invalid_signature(request_id: &str, protocol: AwsProtocol) -> Response {
    render(
        AwsError::new(
            "SignatureDoesNotMatch",
            "The request signature is invalid",
            403,
        )
        .with_request_id(request_id.to_string())
        .render(protocol),
    )
}

fn claims_sigv4_identity(authorization: Option<&str>, query_credential: Option<&str>) -> bool {
    authorization
        .is_some_and(|value| value.contains("AWS4-HMAC-SHA256") || value.contains("Credential="))
        || query_credential.is_some()
}

/// Public HTTP surfaces use their own authentication (or are explicitly anonymous).
/// S3 presigned URLs and POST policies are excluded in strict mode until their signing
/// credentials and revocation checks are backed by IAM.
fn unsigned_public_request(
    service: &str,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    host: Option<&str>,
) -> bool {
    match service {
        "s3" => *method == Method::OPTIONS,
        "cognito-idp" => {
            cognito_public_region(uri.path()).is_some()
                && matches!(*method, Method::GET | Method::HEAD)
        }
        "execute-api" => {
            host.is_some_and(|host| host.to_ascii_lowercase().contains(".execute-api."))
        }
        "cloudfront" => host.is_some_and(|host| {
            host.split(':')
                .next()
                .is_some_and(|name| name.ends_with(".cloudfront.localhost"))
        }),
        "ecr" => {
            (*method == Method::GET
                && uri.path() == "/v2/"
                && headers.get("authorization").is_none())
                || ((uri.path() == "/v2" || uri.path().starts_with("/v2/"))
                    && headers.get("authorization").is_some_and(|value| {
                        value
                            .to_str()
                            .is_ok_and(|value| value.starts_with("Basic "))
                    }))
        }
        _ => false,
    }
}

fn safe_operation(
    service: &str,
    method: &Method,
    uri: &Uri,
    target: Option<&str>,
    body: &[u8],
) -> String {
    if service == "lambda" {
        let path: Vec<_> = uri.path().trim_matches('/').split('/').collect();
        return match (method, path.as_slice()) {
            (&Method::GET, ["2015-03-31", "functions"]) => "ListFunctions",
            (&Method::POST, ["2015-03-31", "functions"]) => "CreateFunction",
            (&Method::GET, ["2015-03-31", "functions", _]) => "GetFunction",
            (&Method::DELETE, ["2015-03-31", "functions", _]) => "DeleteFunction",
            (&Method::GET, ["2015-03-31", "functions", _, "configuration"]) => {
                "GetFunctionConfiguration"
            }
            (&Method::PUT, ["2015-03-31", "functions", _, "configuration"]) => {
                "UpdateFunctionConfiguration"
            }
            (&Method::PUT, ["2015-03-31", "functions", _, "code"]) => "UpdateFunctionCode",
            (&Method::POST, ["2015-03-31", "functions", _, "invocations"]) => "Invoke",
            (&Method::GET, ["2015-03-31", "event-source-mappings"]) => "ListEventSourceMappings",
            (&Method::POST, ["2015-03-31", "event-source-mappings"]) => "CreateEventSourceMapping",
            (&Method::GET, ["2015-03-31", "event-source-mappings", _]) => "GetEventSourceMapping",
            (&Method::PUT, ["2015-03-31", "event-source-mappings", _]) => {
                "UpdateEventSourceMapping"
            }
            (&Method::DELETE, ["2015-03-31", "event-source-mappings", _]) => {
                "DeleteEventSourceMapping"
            }
            _ => "Unknown",
        }
        .to_string();
    }
    let accepted_target = match service {
        "sqs" => target.filter(|value| value.starts_with("AmazonSQS.")),
        _ => target,
    };
    if let Some(operation) = accepted_target.and_then(|value| value.rsplit('.').next()) {
        if !operation.is_empty()
            && operation.len() <= 80
            && operation.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return operation.to_string();
        }
    }
    if let Ok(text) = std::str::from_utf8(body) {
        if let Some(operation) = text
            .split('&')
            .find_map(|part| part.strip_prefix("Action="))
        {
            if operation.len() <= 80 && operation.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                return operation.to_string();
            }
        }
    }
    if service == "s3" {
        return match *method {
            Method::GET => "GetObject",
            Method::PUT => "PutObject",
            Method::DELETE => "DeleteObject",
            Method::HEAD => "HeadObject",
            _ => "Unknown",
        }
        .to_string();
    }
    "Unknown".to_string()
}

pub(crate) fn render(r: RenderedError) -> Response {
    r.into_response()
}

pub(crate) fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Extract the `X-Amz-Credential` query parameter value, decoding `%2F` to `/`.
pub(crate) fn extract_x_amz_credential(query: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("X-Amz-Credential=") {
            return Some(value.replace("%2F", "/").replace("%2f", "/"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::NativeHandler;
    use crate::registry::{AwsProtocol, ServiceMetadata, ServiceName};
    use axum::body::Body;
    use axum::routing::any;
    use axum::Router;
    use std::time::Duration;

    struct OkHandler;

    #[async_trait::async_trait]
    impl NativeHandler for OkHandler {
        async fn handle(&self, _request: ServiceRequest) -> Response {
            Response::builder()
                .status(200)
                .body(Body::from("native-ok"))
                .unwrap()
        }
    }

    struct StrictVerifier {
        accepts_signature: bool,
    }

    impl authorization::AuthorizationEvaluator for StrictVerifier {
        fn strict_sigv4_required(&self) -> bool {
            true
        }

        fn authorize(
            &self,
            _request: authorization::AuthorizationRequest,
        ) -> Result<(), authorization::AuthorizationError> {
            Ok(())
        }

        fn verify_sigv4(
            &self,
            _account: &str,
            _method: &Method,
            _uri: &Uri,
            _headers: &HeaderMap,
            _body: &[u8],
            _region: &str,
            _service: &str,
        ) -> bool {
            self.accepts_signature
        }
    }

    #[test]
    fn lambda_operation_matches_resource_path_and_method() {
        for (method, path, expected) in [
            (Method::GET, "/2015-03-31/functions/", "ListFunctions"),
            (
                Method::DELETE,
                "/2015-03-31/functions/orders",
                "DeleteFunction",
            ),
            (
                Method::GET,
                "/2015-03-31/event-source-mappings/",
                "ListEventSourceMappings",
            ),
            (
                Method::DELETE,
                "/2015-03-31/event-source-mappings/mapping",
                "DeleteEventSourceMapping",
            ),
            (
                Method::GET,
                "/2015-03-31/functions/orders/policy",
                "Unknown",
            ),
            (Method::DELETE, "/unmapped", "Unknown"),
        ] {
            assert_eq!(
                safe_operation(
                    "lambda",
                    &method,
                    &path.parse().unwrap(),
                    Some("forged.DeleteFunction"),
                    b"Action=DeleteFunction"
                ),
                expected
            );
        }
    }

    fn strict_dispatcher(accepts_signature: bool) -> InternalDispatcher {
        let registry = ServiceRegistry::with_known_services();
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            Arc::new(OkHandler),
            Arc::new(StrictVerifier { accepts_signature }),
        );
        registry.register_native(
            ServiceName::new("sqs"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("AmazonSQS")),
            Arc::new(OkHandler),
        );
        InternalDispatcher::new(
            registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        )
    }

    #[tokio::test]
    async fn public_invoke_routes_region_without_attesting_identity_or_bypassing_signatures() {
        struct RegionalInvoke;
        #[async_trait::async_trait]
        impl NativeHandler for RegionalInvoke {
            async fn public_invoke_region(
                &self,
                account: &str,
                _: &str,
                path: &str,
            ) -> Option<String> {
                assert_eq!(account, "000000000000");
                (path == "/execute-api/west/dev/orders").then(|| "us-west-2".into())
            }
            async fn handle(&self, request: ServiceRequest) -> Response {
                assert!(!request.headers.contains_key(identity::PRINCIPAL_HEADER));
                assert!(!request
                    .headers
                    .contains_key("x-locallycloud-verified-internal-scope"));
                Response::new(Body::from(request.region))
            }
        }
        let dispatcher = strict_dispatcher(false);
        dispatcher.registry.upgrade().unwrap().register_native(
            ServiceName::new("execute-api"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::new(RegionalInvoke),
        );
        let path = "/execute-api/west/dev/orders".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(identity::PRINCIPAL_HEADER, "forged".parse().unwrap());
        let response = dispatcher
            .dispatch(&Method::GET, &path, &headers, Bytes::new(), "rid")
            .await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap(),
            "us-west-2"
        );
        headers.insert("authorization", auth("execute-api").parse().unwrap());
        let response = dispatcher
            .dispatch(&Method::GET, &path, &headers, Bytes::new(), "rid")
            .await;
        assert_eq!(
            response.status(),
            403,
            "public routing must not bypass a claimed signature"
        );
        headers.remove("authorization");
        let response = dispatcher
            .dispatch_dashboard(
                &Method::GET,
                &path,
                &headers,
                Bytes::new(),
                "us-west-2",
                "execute-api",
            )
            .await;
        assert_eq!(
            response.status(),
            403,
            "public routes must not open the dashboard proxy"
        );
    }

    #[tokio::test]
    async fn strict_ingress_rejects_unsigned_and_forged_before_native_handler() {
        let dispatcher = strict_dispatcher(false);
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-target", "AmazonSQS.SendMessage".parse().unwrap());
        let response = dispatcher
            .dispatch(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
            )
            .await;
        assert_eq!(response.status(), 403);

        headers.insert("authorization", auth("sqs").parse().unwrap());
        let response = dispatcher
            .dispatch(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
            )
            .await;
        assert_eq!(response.status(), 403);

        let dispatcher = strict_dispatcher(true);
        let response = dispatcher
            .dispatch(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
            )
            .await;
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn dashboard_region_keeps_strict_external_verification() {
        let dispatcher = strict_dispatcher(false);
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-target", "AmazonSQS.ListQueues".parse().unwrap());
        headers.insert("x-locallycloud-dashboard", "1".parse().unwrap());
        let response = dispatcher
            .dispatch_dashboard(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::from_static(b"{}"),
                "us-west-2",
                "sqs",
            )
            .await;
        assert_eq!(response.status(), 403);
        headers.remove("x-amz-target");
        let response = dispatcher
            .dispatch_dashboard(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::from_static(b"{}"),
                "us-west-2",
                "sqs",
            )
            .await;
        assert_eq!(
            response.status(),
            403,
            "explicit service selection must still verify external identity"
        );
    }

    struct MarkerHandler;

    #[async_trait::async_trait]
    impl NativeHandler for MarkerHandler {
        async fn handle(&self, request: ServiceRequest) -> Response {
            if request
                .headers
                .contains_key("x-locallycloud-verified-internal-scope")
            {
                assert_eq!(
                    request.headers.get(identity::PRINCIPAL_HEADER).unwrap(),
                    "arn:aws:iam::000000000000:role/test"
                );
            } else {
                assert!(!request.headers.contains_key(identity::PRINCIPAL_HEADER));
            }
            let marker = request
                .headers
                .get("x-locallycloud-verified-external-sigv4")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("absent")
                .to_string();
            Response::builder()
                .status(200)
                .body(Body::from(marker))
                .unwrap()
        }
    }

    #[tokio::test]
    async fn strict_attestation_cannot_be_forged_by_client() {
        let registry = ServiceRegistry::with_known_services();
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            Arc::new(OkHandler),
            Arc::new(StrictVerifier {
                accepts_signature: true,
            }),
        );
        registry.register_native(
            ServiceName::new("sqs"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("AmazonSQS")),
            Arc::new(MarkerHandler),
        );
        let dispatcher = InternalDispatcher::new(
            registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-target", "AmazonSQS.SendMessage".parse().unwrap());
        headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "forged".parse().unwrap(),
        );
        headers.insert(
            identity::PRINCIPAL_HEADER,
            "arn:aws:iam::000000000000:role/test".parse().unwrap(),
        );
        let internal = dispatcher
            .dispatch_scoped(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
                "000000000000",
                "us-east-1",
            )
            .await;
        assert_eq!(
            axum::body::to_bytes(internal.into_body(), 128)
                .await
                .unwrap(),
            "absent"
        );
        headers.insert("authorization", auth("sqs").parse().unwrap());
        let external = dispatcher
            .dispatch(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
            )
            .await;
        assert_eq!(
            axum::body::to_bytes(external.into_body(), 128)
                .await
                .unwrap(),
            "1"
        );
    }

    #[test]
    fn unsigned_public_surfaces_are_explicit() {
        let empty = HeaderMap::new();
        assert!(!unsigned_public_request(
            "s3",
            &Method::GET,
            &"/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=a&X-Amz-Date=d&X-Amz-Expires=1&X-Amz-SignedHeaders=host&X-Amz-Signature=s"
                .parse().unwrap(),
            &empty,
            Some("s3.localhost"),
        ));
        let mut multipart = HeaderMap::new();
        multipart.insert(
            "content-type",
            "multipart/form-data; boundary=x".parse().unwrap(),
        );
        assert!(!unsigned_public_request(
            "s3",
            &Method::POST,
            &"/bucket".parse().unwrap(),
            &multipart,
            Some("s3.localhost"),
        ));
        assert!(unsigned_public_request(
            "execute-api",
            &Method::GET,
            &"/prod".parse().unwrap(),
            &empty,
            Some("abc.execute-api.us-east-1.amazonaws.com"),
        ));
        assert!(!unsigned_public_request(
            "apigateway",
            &Method::GET,
            &"/restapis".parse().unwrap(),
            &empty,
            Some("localhost"),
        ));
    }

    /// Echoes the request body back, to prove payload bytes pass through unaltered.
    struct EchoHandler;

    #[async_trait::async_trait]
    impl NativeHandler for EchoHandler {
        async fn handle(&self, request: ServiceRequest) -> Response {
            Response::builder()
                .status(200)
                .body(Body::from(request.body))
                .unwrap()
        }
    }

    fn dispatcher(backend: &str) -> InternalDispatcher {
        dispatcher_with_health(backend, true)
    }

    fn dispatcher_with_health(backend: &str, healthy: bool) -> InternalDispatcher {
        InternalDispatcher::new(
            ServiceRegistry::with_known_services(),
            ProxyConfig {
                backend_url: backend.to_string(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(healthy),
            "us-east-1".to_string(),
            "000000000000".to_string(),
        )
    }

    /// A live backend that always answers 200, used to prove fast-fail does NOT forward.
    async fn spawn_ok_backend() -> String {
        let app = Router::new().fallback(any(|| async {
            axum::response::Response::builder()
                .status(200)
                .body(axum::body::Body::from("ok"))
                .unwrap()
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn auth(service: &str) -> String {
        format!("AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/{service}/aws4_request")
    }

    #[tokio::test]
    async fn native_service_invokes_registered_handler() {
        let d = dispatcher("http://127.0.0.1:1");
        d.registry_register_test_handler("s3");
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth("s3").parse().unwrap());
        let resp = d
            .dispatch(
                &Method::GET,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
            )
            .await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn proxied_service_to_dead_backend_returns_502() {
        let d = dispatcher("http://127.0.0.1:1");
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth("sns").parse().unwrap());
        let resp = d
            .dispatch(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
            )
            .await;
        assert_eq!(resp.status(), 502);
    }

    #[tokio::test]
    async fn unresolved_returns_400() {
        let d = dispatcher("http://127.0.0.1:1");
        let resp = d
            .dispatch(
                &Method::GET,
                &"/".parse().unwrap(),
                &HeaderMap::new(),
                Bytes::new(),
                "rid",
            )
            .await;
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn routing_confluence_under_concurrency() {
        let d = Arc::new(dispatcher("http://127.0.0.1:1"));
        d.registry_register_test_handler("lambda");

        let mut handles = Vec::new();
        for i in 0..60u32 {
            let d = d.clone();
            handles.push(tokio::spawn(async move {
                let (headers, expected): (HeaderMap, u16) = match i % 3 {
                    // proxied to a dead backend -> 502
                    0 => {
                        let mut h = HeaderMap::new();
                        h.insert("authorization", auth("sns").parse().unwrap());
                        (h, 502)
                    }
                    // native handler -> 200
                    1 => {
                        let mut h = HeaderMap::new();
                        h.insert("authorization", auth("lambda").parse().unwrap());
                        (h, 200)
                    }
                    // unresolved -> 400
                    _ => (HeaderMap::new(), 400),
                };
                let resp = d
                    .dispatch(
                        &Method::POST,
                        &"/".parse().unwrap(),
                        &headers,
                        Bytes::new(),
                        "rid",
                    )
                    .await;
                (resp.status().as_u16(), expected)
            }));
        }

        for h in handles {
            let (got, expected) = h.await.unwrap();
            assert_eq!(
                got, expected,
                "concurrent dispatch produced a different decision"
            );
        }
    }

    #[tokio::test]
    async fn unhealthy_backend_fast_fails_without_forwarding() {
        // Backend is live and would return 200, but health is marked unhealthy → 502.
        let backend = spawn_ok_backend().await;
        let d = dispatcher_with_health(&backend, false);
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth("sns").parse().unwrap());
        let resp = d
            .dispatch(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
            )
            .await;
        assert_eq!(
            resp.status(),
            502,
            "fast-fail should not forward to the live backend"
        );
    }

    #[tokio::test]
    async fn healthy_backend_forwards_and_returns_200() {
        let backend = spawn_ok_backend().await;
        let d = dispatcher_with_health(&backend, true);
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth("sns").parse().unwrap());
        let resp = d
            .dispatch(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
            )
            .await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn forged_ecr_identity_cannot_reach_token_handler() {
        let registry = ServiceRegistry::with_known_services();
        registry.register_native(
            ServiceName::new("ecr"),
            ServiceMetadata::new(
                AwsProtocol::Json11,
                Some("AmazonEC2ContainerRegistry_V20150921"),
            ),
            Arc::new(OkHandler),
        );
        registry.register_native(
            ServiceName::new("ecs"),
            ServiceMetadata::new(
                AwsProtocol::Json11,
                Some("AmazonEC2ContainerServiceV20141113"),
            ),
            Arc::new(OkHandler),
        );
        let dispatcher = InternalDispatcher::new(
            registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken"
                .parse()
                .unwrap(),
        );
        headers.insert("authorization", "AWS4-HMAC-SHA256 Credential=AKIAFORGED/20260101/us-east-1/ecr/aws4_request, SignedHeaders=host;x-amz-date;x-amz-target, Signature=0000000000000000000000000000000000000000000000000000000000000000".parse().unwrap());
        headers.insert("x-amz-date", "20260101T000000Z".parse().unwrap());
        headers.insert("host", "localhost".parse().unwrap());
        let response = dispatcher
            .dispatch(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::from_static(b"{}"),
                "rid",
            )
            .await;
        assert_eq!(response.status(), 403);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(std::str::from_utf8(&body)
            .unwrap()
            .contains("SignatureDoesNotMatch"));
        headers.insert(
            "x-amz-target",
            "AmazonEC2ContainerServiceV20141113.DescribeTaskDefinition"
                .parse()
                .unwrap(),
        );
        headers.insert("authorization", "AWS4-HMAC-SHA256 Credential=AKIAFORGED/20260101/us-east-1/ecs/aws4_request, SignedHeaders=host;x-amz-date;x-amz-target, Signature=0000000000000000000000000000000000000000000000000000000000000000".parse().unwrap());
        let response = dispatcher
            .dispatch(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::from_static(b"{\"taskDefinition\":\"secret\"}"),
                "rid-ecs",
            )
            .await;
        assert_eq!(response.status(), 403);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(std::str::from_utf8(&body)
            .unwrap()
            .contains("SignatureDoesNotMatch"));
    }

    struct PeerCapture;

    #[async_trait::async_trait]
    impl NativeHandler for PeerCapture {
        async fn handle(&self, request: ServiceRequest) -> Response {
            let peer = request
                .headers
                .get("x-locallycloud-trusted-peer-ip")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("absent");
            Response::builder()
                .status(200)
                .body(Body::from(peer.to_string()))
                .unwrap()
        }
    }

    #[tokio::test]
    async fn only_verified_peer_reaches_api_gateway() {
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("execute-api"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::new(PeerCapture),
        );
        let dispatcher = InternalDispatcher::new(
            reg,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(true),
            "us-east-1".to_string(),
            "000000000000".to_string(),
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth("execute-api").parse().unwrap());
        headers.insert(
            "x-locallycloud-trusted-peer-ip",
            "203.0.113.7".parse().unwrap(),
        );
        let absent = dispatcher
            .dispatch(
                &Method::GET,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
            )
            .await;
        let absent = axum::body::to_bytes(absent.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&absent[..], b"absent");
        let verified = dispatcher
            .dispatch_verified_peer(
                &Method::GET,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
                "127.0.0.1".parse().unwrap(),
            )
            .await;
        let verified = axum::body::to_bytes(verified.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&verified[..], b"127.0.0.1");
    }

    #[tokio::test]
    async fn native_handler_is_invoked() {
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::new(OkHandler),
        );
        let d = InternalDispatcher::new(
            reg,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(true),
            "us-east-1".to_string(),
            "000000000000".to_string(),
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth("lambda").parse().unwrap());
        let resp = d
            .dispatch(
                &Method::POST,
                &"/2015-03-31/functions".parse().unwrap(),
                &headers,
                Bytes::new(),
                "rid",
            )
            .await;
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"native-ok");
    }

    impl InternalDispatcher {
        fn registry_register_test_handler(&self, name: &str) {
            let registry = self
                .registry
                .upgrade()
                .expect("standalone dispatcher retains registry");
            let service_name = ServiceName::new(name);
            let metadata = registry
                .lookup(&service_name)
                .expect("test service is registered")
                .metadata;
            registry.register_native(service_name, metadata, Arc::new(OkHandler));
        }
    }

    #[tokio::test]
    async fn cross_service_payload_passes_through_unchanged() {
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::new(EchoHandler),
        );
        let d = InternalDispatcher::new(
            reg,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(true),
            "us-east-1".to_string(),
            "000000000000".to_string(),
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth("lambda").parse().unwrap());
        // A UTF-8 payload with multibyte characters must round-trip byte-for-byte.
        let payload = "café — 日本語 — 🚀".as_bytes().to_vec();
        let resp = d
            .dispatch(
                &Method::POST,
                &"/2015-03-31/functions/f/invocations".parse().unwrap(),
                &headers,
                Bytes::from(payload.clone()),
                "rid",
            )
            .await;
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            &payload[..],
            "payload must pass through without lossy re-encoding"
        );
    }
    struct CaptureObserver(std::sync::Mutex<Vec<DispatchOutcome>>);

    impl crate::audit::CompletionObserver for CaptureObserver {
        fn observe(&self, outcome: DispatchOutcome) {
            self.0.lock().unwrap().push(outcome);
        }
    }

    struct PanicObserver;

    impl crate::audit::CompletionObserver for PanicObserver {
        fn observe(&self, _outcome: DispatchOutcome) {
            panic!("observer fault");
        }
    }

    #[tokio::test]
    async fn completed_dispatch_is_scoped_once_and_client_cannot_suppress() {
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("sqs"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("AmazonSQS")),
            Arc::new(OkHandler),
        );
        let capture = Arc::new(CaptureObserver(std::sync::Mutex::new(Vec::new())));
        reg.set_completion_observer(capture.clone());
        let d = InternalDispatcher::new(
            reg,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(true),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth("sqs").parse().unwrap());
        headers.insert("x-amz-target", "AmazonSQS.CreateQueue".parse().unwrap());
        headers.insert("x-locallycloud-audit-suppress", "true".parse().unwrap());
        let response = d
            .dispatch_scoped(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::from_static(br#"{"QueueName":"test","Password":"never-observe"}"#),
                "request-one",
                "111111111111",
                "eu-west-1",
            )
            .await;
        assert_eq!(response.status(), 200);
        for _ in 0..50 {
            if capture.0.lock().unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        {
            let events = capture.0.lock().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].operation, "CreateQueue");
            assert_eq!(events[0].account_id, "111111111111");
            assert_eq!(events[0].region, "eu-west-1");
            assert_eq!(events[0].http_status, 200);
            assert!(!format!("{:?}", events[0]).contains("never-observe"));
        }
        let response = d
            .dispatch_scoped_suppressed(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "request-two",
                "111111111111",
                "eu-west-1",
            )
            .await;
        assert_eq!(response.status(), 200);
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(capture.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dashboard_reads_skip_activity_but_writes_and_audit_remain_visible() {
        struct FailedHandler;
        #[async_trait::async_trait]
        impl NativeHandler for FailedHandler {
            async fn handle(&self, _: ServiceRequest) -> Response {
                Response::builder()
                    .status(400)
                    .header("x-amzn-errortype", "QueueDoesNotExist")
                    .body(Body::from("private-response"))
                    .unwrap()
            }
        }
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("sqs"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("AmazonSQS")),
            Arc::new(FailedHandler),
        );
        reg.register_native(
            ServiceName::new("dynamodb"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("DynamoDB_20120810")),
            Arc::new(FailedHandler),
        );
        let observer = Arc::new(CaptureObserver(std::sync::Mutex::new(Vec::new())));
        reg.set_completion_observer(observer.clone());
        let dispatcher = InternalDispatcher::new(
            reg.clone(),
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(true),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let mut headers = HeaderMap::new();
        for (index, operation) in ["GetQueueUrl", "GetQueueUrl", "SendMessage"]
            .iter()
            .enumerate()
        {
            headers.insert(
                "x-amz-target",
                format!("AmazonSQS.{operation}").parse().unwrap(),
            );
            if index > 0 {
                headers.insert("x-locallycloud-dashboard", "1".parse().unwrap());
            }
            let response = dispatcher
                .dispatch(
                    &Method::POST,
                    &"/".parse().unwrap(),
                    &headers,
                    Bytes::from_static(
                        br#"{"QueueUrl":"http://localhost/queue","MessageBody":"private-payload"}"#,
                    ),
                    "request-id",
                )
                .await;
            assert_eq!(response.status(), 400);
        }
        for operation in ["Scan", "Query"] {
            headers.insert(
                "x-amz-target",
                format!("DynamoDB_20120810.{operation}").parse().unwrap(),
            );
            dispatcher
                .dispatch(
                    &Method::POST,
                    &"/".parse().unwrap(),
                    &headers,
                    Bytes::from_static(br#"{"TableName":"orders"}"#),
                    "request-id",
                )
                .await;
        }
        let snapshot = reg.activity.snapshot();
        assert_eq!(snapshot.records.len(), 2);
        let serialized = serde_json::to_string(&snapshot).unwrap();
        assert!(serialized.contains("QueueDoesNotExist"));
        assert!(!serialized.contains("private-payload"));
        assert!(!serialized.contains("private-response"));
        for _ in 0..50 {
            if observer.0.lock().unwrap().len() == 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(observer.0.lock().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn observer_panic_does_not_change_response() {
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("sqs"),
            ServiceMetadata::new(AwsProtocol::Json10, Some("AmazonSQS")),
            Arc::new(OkHandler),
        );
        reg.set_completion_observer(Arc::new(PanicObserver));
        let d = InternalDispatcher::new(
            reg,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(true),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let mut headers = HeaderMap::new();
        headers.insert("authorization", auth("sqs").parse().unwrap());
        let response = d
            .dispatch(
                &Method::POST,
                &"/".parse().unwrap(),
                &headers,
                Bytes::new(),
                "request-one",
            )
            .await;
        assert_eq!(response.status(), 200);
    }
}
