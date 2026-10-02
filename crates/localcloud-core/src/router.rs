//! Multi-protocol service router.
//!
//! Resolves the target AWS service from the SigV4 credential scope first, then falls back
//! to `X-Amz-Target`, S3 host/path, and the form-urlencoded `Action` field, producing a
//! routing decision. The request body is only inspected, never consumed, so the original
//! bytes survive for forwarding. See Requirements 5, 6, 7 and 8.

use crate::registry::{Disposition as RegDisposition, ServiceName, ServiceRegistry};

/// Where the resolved service name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionSource {
    CredentialScope,
    XAmzTarget,
    HostPath,
    ActionField,
    RestJsonPath,
}

/// Whether the request is handled in-process or forwarded to the legacy backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteDisposition {
    HandledNatively,
    ProxiedToLegacy,
}

/// The outcome of routing a single request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingDecision {
    pub service_name: ServiceName,
    pub resolution_source: ResolutionSource,
    pub disposition: RouteDisposition,
}

/// The request fields the router inspects. Borrowed, so the body is never consumed.
#[derive(Debug, Clone, Copy)]
pub struct RouteInput<'a> {
    pub authorization: Option<&'a str>,
    pub x_amz_credential: Option<&'a str>,
    pub x_amz_target: Option<&'a str>,
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub body: &'a [u8],
}

/// Raised when no resolution source yields a service. Maps to an HTTP 400 (Requirement 6.8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("could not resolve a target AWS service for the request")]
pub struct Unresolved;

/// Resolve a request to a routing decision.
pub fn resolve(
    registry: &ServiceRegistry,
    input: &RouteInput,
) -> Result<RoutingDecision, Unresolved> {
    // 1. Credential scope is authoritative when it names a registered service.
    let scope_name =
        extract_service_from_credential_scope(input.authorization, input.x_amz_credential);
    if let Some(name) = &scope_name {
        if registry.lookup(name).is_some() {
            // DynamoDB Streams is signed with the `dynamodb` credential-scope service but has
            // its own target prefix and Native handler. Preserve scope priority for every other
            // service while routing this AWS-defined alias to the Streams binding.
            if name.as_str() == "dynamodb" {
                if let Some(target) = input.x_amz_target {
                    if let Some(target_name) = registry.lookup_by_target_prefix(target) {
                        if target_name.as_str() == "streams.dynamodb" {
                            return Ok(decide(registry, target_name, ResolutionSource::XAmzTarget));
                        }
                    }
                }
            }
            return Ok(decide(
                registry,
                name.clone(),
                ResolutionSource::CredentialScope,
            ));
        }
    }

    // 2. Docker Registry requests use Basic authentication and have no SigV4 scope.
    // Route only to a registered native ECR handler, which validates Basic before touching state.
    if (input.path == "/v2" || input.path.starts_with("/v2/"))
        && input.host.is_some_and(ecr_registry_host)
    {
        let name = ServiceName::new("ecr");
        if registry.native_handler(&name).is_some() {
            return Ok(decide(registry, name, ResolutionSource::HostPath));
        }
    }

    // 2. Fallback sources, in order, taking the first that resolves to a registered service.
    if let Some(target) = input.x_amz_target {
        if let Some(name) = registry.lookup_by_target_prefix(target) {
            return Ok(decide(registry, name, ResolutionSource::XAmzTarget));
        }
    }
    if let Some(name) = resolve_s3_from_host_path(input.host, input.path) {
        if registry.lookup(&name).is_some() {
            return Ok(decide(registry, name, ResolutionSource::HostPath));
        }
    }
    if let Some(name) = resolve_cloudfront_from_host(input.host) {
        if registry.lookup(&name).is_some() {
            return Ok(decide(registry, name, ResolutionSource::HostPath));
        }
    }
    if let Some(name) = resolve_execute_api_from_host(input.host) {
        if registry.lookup(&name).is_some() {
            return Ok(decide(registry, name, ResolutionSource::HostPath));
        }
    }
    if lambda_control_plane_path(input.path) {
        let name = ServiceName::new("lambda");
        if registry.lookup(&name).is_some() {
            return Ok(decide(registry, name, ResolutionSource::RestJsonPath));
        }
    }
    if cognito_public_region(input.path).is_some() {
        let name = ServiceName::new("cognito-idp");
        if registry.lookup(&name).is_some() {
            return Ok(decide(registry, name, ResolutionSource::RestJsonPath));
        }
    }
    if let Some(action) = read_action_field(input.body) {
        if let Some(name) = registry.lookup_by_action(&action) {
            return Ok(decide(registry, name, ResolutionSource::ActionField));
        }
    }

    // 3. A credential scope that named an *unregistered* service still identifies the
    //    target (e.g. a not-yet-modelled service); proxy it to the legacy backend (Req 8.4).
    if let Some(name) = scope_name {
        return Ok(RoutingDecision {
            service_name: name,
            resolution_source: ResolutionSource::CredentialScope,
            disposition: RouteDisposition::ProxiedToLegacy,
        });
    }

    Err(Unresolved)
}

fn decide(
    registry: &ServiceRegistry,
    name: ServiceName,
    source: ResolutionSource,
) -> RoutingDecision {
    let disposition = match registry.disposition(&name) {
        RegDisposition::Native => RouteDisposition::HandledNatively,
        RegDisposition::Proxied => RouteDisposition::ProxiedToLegacy,
    };
    RoutingDecision {
        service_name: name,
        resolution_source: source,
        disposition,
    }
}

/// Extract the canonical service from a SigV4 `Authorization` header (preferred) or an
/// `X-Amz-Credential` query parameter.
pub fn extract_service_from_credential_scope(
    authorization: Option<&str>,
    x_amz_credential: Option<&str>,
) -> Option<ServiceName> {
    if let Some(auth) = authorization {
        if auth.contains("AWS4-HMAC-SHA256") {
            if let Some(cred) = credential_value(auth) {
                if let Some(name) = parse_scope(cred) {
                    return Some(name);
                }
            }
        }
    }
    x_amz_credential.and_then(parse_scope)
}

/// Pull the `Credential=<scope>` token out of an `Authorization` header value.
fn credential_value(auth: &str) -> Option<&str> {
    let start = auth.find("Credential=")? + "Credential=".len();
    let rest = &auth[start..];
    let end = rest.find([',', ' ']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Parse `<access-key>/<8-digit-date>/<region>/<service>/aws4_request` → service name.
fn parse_scope(scope: &str) -> Option<ServiceName> {
    scope_parts(scope).map(|(service, _region)| service)
}

/// Extract the region from a SigV4 credential scope, if present and well-formed.
pub fn extract_region_from_credential_scope(
    authorization: Option<&str>,
    x_amz_credential: Option<&str>,
) -> Option<String> {
    if let Some(auth) = authorization {
        if auth.contains("AWS4-HMAC-SHA256") {
            if let Some(cred) = credential_value(auth) {
                if let Some((_, region)) = scope_parts(cred) {
                    return Some(region);
                }
            }
        }
    }
    x_amz_credential
        .and_then(scope_parts)
        .map(|(_, region)| region)
}

/// Validate and split a credential scope into `(service, region)`.
fn scope_parts(scope: &str) -> Option<(ServiceName, String)> {
    let segs: Vec<&str> = scope.trim().split('/').collect();
    if segs.len() < 5 {
        return None;
    }
    let date = segs[1];
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if segs[4] != "aws4_request" {
        return None;
    }
    let region = segs[2];
    let service = segs[3];
    if service.is_empty() || region.is_empty() {
        return None;
    }
    Some((ServiceName::new(service), region.to_string()))
}

fn ecr_registry_host(host: &str) -> bool {
    let hostname = host.split(':').next().unwrap_or("").to_ascii_lowercase();
    if matches!(hostname.as_str(), "localhost" | "127.0.0.1") {
        return true;
    }
    let Some((account, rest)) = hostname.split_once(".dkr.ecr.") else {
        return false;
    };
    if account.len() != 12 || !account.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Some(region) = rest
        .strip_suffix(".amazonaws.com")
        .or_else(|| rest.strip_suffix(".localhost"))
    else {
        return false;
    };
    !region.is_empty()
        && region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Detect S3 from a virtual-hosted or `s3.`-prefixed host, or a path-style `/s3/` prefix.
fn resolve_s3_from_host_path(host: Option<&str>, path: &str) -> Option<ServiceName> {
    if let Some(host) = host {
        let h = host.to_ascii_lowercase();
        if h.starts_with("s3.") || h.contains(".s3.") || h.contains(".s3-") {
            return Some(ServiceName::new("s3"));
        }
    }
    if path == "/s3" || path.starts_with("/s3/") {
        return Some(ServiceName::new("s3"));
    }
    None
}

/// Detect API Gateway invoke traffic from an `*.execute-api.*` host. Invoke requests are
/// plain HTTP without a SigV4 credential scope, so the host is the faithful signal (the same
/// way S3 is detected from its virtual-hosted host).
fn resolve_execute_api_from_host(host: Option<&str>) -> Option<ServiceName> {
    let host = host?;
    if host.to_ascii_lowercase().contains(".execute-api.") {
        Some(ServiceName::new("execute-api"))
    } else {
        None
    }
}

/// The unsigned Lambda path fallback exists for read-only callers such as the dashboard. Any
/// web page can send simple cross-site POSTs to localhost, so mutating methods (CreateFunction,
/// Invoke, …) keep requiring a credential scope.
pub fn permits_method(decision: &RoutingDecision, method: &http::Method) -> bool {
    let unsigned_lambda = decision.resolution_source == ResolutionSource::RestJsonPath
        && decision.service_name.as_str() == "lambda";
    !unsigned_lambda || matches!(*method, http::Method::GET | http::Method::HEAD)
}

/// Lambda's REST control plane (`/2015-03-31/functions…`, `/2015-03-31/event-source-mappings…`)
/// for unsigned callers such as the built-in dashboard. Signed requests resolve by scope first.
fn lambda_control_plane_path(path: &str) -> bool {
    ["/2015-03-31/functions", "/2015-03-31/event-source-mappings"]
        .iter()
        .any(|prefix| {
            path.strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
}

/// Local CloudFront viewer domain. Distribution ownership is checked by the Native handler.
fn resolve_cloudfront_from_host(host: Option<&str>) -> Option<ServiceName> {
    let host = host?.split(':').next()?.to_ascii_lowercase();
    let distribution = host.strip_suffix(".cloudfront.localhost")?;
    if distribution.is_empty()
        || distribution.len() > 64
        || !distribution
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    Some(ServiceName::new("cloudfront"))
}

/// Cognito publishes unauthenticated OIDC and JWKS URLs under each user pool ID.
/// The region is encoded in the pool ID and determines the lookup scope.
pub fn cognito_public_region(path: &str) -> Option<&str> {
    let mut segments = path.strip_prefix('/')?.split('/');
    let (Some(pool), Some(".well-known"), Some(document), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return None;
    };
    if document != "jwks.json" && document != "openid-configuration" {
        return None;
    }
    if pool.len() > 128 {
        return None;
    }
    let (region, suffix) = pool.split_once('_')?;
    if region.is_empty()
        || suffix.is_empty()
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(region)
}

/// Read the `Action` value from a form-urlencoded body without consuming it.
fn read_action_field(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    for pair in text.split('&') {
        if let Some(value) = pair.strip_prefix("Action=") {
            let value = value.split('&').next().unwrap_or(value);
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::{NativeHandler, ServiceRequest};
    use crate::registry::{AwsProtocol, ServiceMetadata};
    use axum::body::Body;
    use axum::response::Response;
    use std::sync::Arc;

    struct TestHandler;

    #[async_trait::async_trait]
    impl NativeHandler for TestHandler {
        async fn handle(&self, _request: ServiceRequest) -> Response {
            Response::new(Body::empty())
        }
    }

    fn auth(service: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240101/us-east-1/{service}/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=abc123"
        )
    }

    #[test]
    fn docker_registry_host_routes_only_to_native_ecr() {
        let reg = ServiceRegistry::with_known_services();
        let input = RouteInput {
            authorization: Some("Basic QVdTOmZvcmdlZA=="),
            x_amz_credential: None,
            x_amz_target: None,
            host: Some("127.0.0.1:4566"),
            path: "/v2/team/app/manifests/latest",
            body: b"",
        };
        assert!(resolve(&reg, &input).is_err());
        reg.register_native(
            ServiceName::new("ecr"),
            ServiceMetadata::new(
                AwsProtocol::Json11,
                Some("AmazonEC2ContainerRegistry_V20150921"),
            ),
            Arc::new(TestHandler),
        );
        let decision = resolve(&reg, &input).unwrap();
        assert_eq!(decision.service_name, ServiceName::new("ecr"));
        assert_eq!(decision.disposition, RouteDisposition::HandledNatively);
        assert!(ecr_registry_host(
            "000000000000.dkr.ecr.us-east-1.amazonaws.com"
        ));
        assert!(!ecr_registry_host("attacker.example"));
        assert!(!ecr_registry_host(
            "000000000000.dkr.ecr.us-east-1.amazonaws.com.attacker.example"
        ));
    }

    #[test]
    fn local_cloudfront_viewer_host_routes_without_signature() {
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("cloudfront"),
            ServiceMetadata::new(AwsProtocol::RestXml, None),
            Arc::new(TestHandler),
        );
        let input = RouteInput {
            authorization: None,
            x_amz_credential: None,
            x_amz_target: None,
            host: Some("d123.cloudfront.localhost:4566"),
            path: "/asset.txt",
            body: b"",
        };
        let decision = resolve(&reg, &input).unwrap();
        assert_eq!(decision.service_name, ServiceName::new("cloudfront"));
        assert_eq!(decision.disposition, RouteDisposition::HandledNatively);
        assert_eq!(
            resolve_cloudfront_from_host(Some("cloudfront.localhost")),
            None
        );
    }

    #[test]
    fn unsigned_cognito_jwks_uses_native_route() {
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("cognito-idp"),
            ServiceMetadata::new(
                AwsProtocol::Json11,
                Some("AWSCognitoIdentityProviderService"),
            ),
            Arc::new(TestHandler),
        );
        let input = RouteInput {
            authorization: None,
            x_amz_credential: None,
            x_amz_target: None,
            host: Some("localhost:4566"),
            path: "/us-east-1_example/.well-known/jwks.json",
            body: b"",
        };
        let decision = resolve(&reg, &input).unwrap();
        assert_eq!(decision.service_name, ServiceName::new("cognito-idp"));
        assert_eq!(decision.disposition, RouteDisposition::HandledNatively);
        assert_eq!(decision.resolution_source, ResolutionSource::RestJsonPath);
        assert_eq!(cognito_public_region(input.path), Some("us-east-1"));
        assert_eq!(
            cognito_public_region("/us-west-2_pool/.well-known/openid-configuration"),
            Some("us-west-2")
        );
        assert_eq!(cognito_public_region("/bad/.well-known/jwks.json"), None);
        assert_eq!(
            cognito_public_region("/us-east-1_ok/.well-known/other"),
            None
        );
    }

    #[test]
    fn unsigned_lambda_control_plane_routes_by_path() {
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::new(TestHandler),
        );
        for path in [
            "/2015-03-31/functions",
            "/2015-03-31/functions/",
            "/2015-03-31/functions/demo/configuration",
            "/2015-03-31/event-source-mappings/",
        ] {
            let input = RouteInput {
                authorization: None,
                x_amz_credential: None,
                x_amz_target: None,
                host: Some("localhost:4566"),
                path,
                body: b"",
            };
            let decision = resolve(&reg, &input).unwrap();
            assert_eq!(decision.service_name, ServiceName::new("lambda"), "{path}");
            assert_eq!(decision.resolution_source, ResolutionSource::RestJsonPath);
        }
        let unsigned = resolve(
            &reg,
            &RouteInput {
                authorization: None,
                x_amz_credential: None,
                x_amz_target: None,
                host: Some("localhost:4566"),
                path: "/2015-03-31/functions/demo/invocations",
                body: b"",
            },
        )
        .unwrap();
        assert!(permits_method(&unsigned, &http::Method::GET));
        assert!(permits_method(&unsigned, &http::Method::HEAD));
        assert!(!permits_method(&unsigned, &http::Method::POST));
        assert!(!permits_method(&unsigned, &http::Method::PUT));
        assert!(!permits_method(&unsigned, &http::Method::DELETE));
        assert!(!lambda_control_plane_path("/2015-03-31/functionsx"));
        assert!(!lambda_control_plane_path("/2015-03-31/"));
        // A signed request keeps its credential scope even on a Lambda-looking path.
        let signed = RouteInput {
            authorization: Some(
                "AWS4-HMAC-SHA256 Credential=AKID/20250101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=x",
            ),
            x_amz_credential: None,
            x_amz_target: None,
            host: Some("localhost:4566"),
            path: "/2015-03-31/functions",
            body: b"",
        };
        assert_eq!(
            resolve(&reg, &signed).unwrap().service_name,
            ServiceName::new("s3")
        );
    }

    #[test]
    fn resolves_from_credential_scope() {
        let reg = ServiceRegistry::with_known_services();
        let a = auth("s3");
        let input = RouteInput {
            authorization: Some(&a),
            x_amz_credential: None,
            x_amz_target: None,
            host: None,
            path: "/",
            body: b"",
        };
        let d = resolve(&reg, &input).unwrap();
        assert_eq!(d.service_name, ServiceName::new("s3"));
        assert_eq!(d.resolution_source, ResolutionSource::CredentialScope);
        assert_eq!(d.disposition, RouteDisposition::ProxiedToLegacy);
    }

    #[test]
    fn resolves_from_query_credential_when_no_auth_header() {
        let svc = extract_service_from_credential_scope(
            None,
            Some("AKID/20240101/eu-west-1/dynamodb/aws4_request"),
        );
        assert_eq!(svc, Some(ServiceName::new("dynamodb")));
    }

    #[test]
    fn extracts_region_from_credential_scope() {
        let a = auth("dynamodb");
        assert_eq!(
            extract_region_from_credential_scope(Some(&a), None).as_deref(),
            Some("us-east-1")
        );
        assert_eq!(
            extract_region_from_credential_scope(
                None,
                Some("AKID/20240101/eu-west-1/s3/aws4_request")
            )
            .as_deref(),
            Some("eu-west-1")
        );
        assert_eq!(
            extract_region_from_credential_scope(Some("garbage"), None),
            None
        );
    }

    #[test]
    fn credential_scope_priority_over_target() {
        // scope says s3, X-Amz-Target says DynamoDB — scope wins.
        let reg = ServiceRegistry::with_known_services();
        let a = auth("s3");
        let input = RouteInput {
            authorization: Some(&a),
            x_amz_credential: None,
            x_amz_target: Some("DynamoDB_20120810.GetItem"),
            host: None,
            path: "/",
            body: b"",
        };
        let d = resolve(&reg, &input).unwrap();
        assert_eq!(d.service_name, ServiceName::new("s3"));
        assert_eq!(d.resolution_source, ResolutionSource::CredentialScope);
    }

    #[test]
    fn dynamodb_scope_routes_streams_target_to_streams_binding() {
        let reg = ServiceRegistry::with_known_services();
        let a = auth("dynamodb");
        let input = RouteInput {
            authorization: Some(&a),
            x_amz_credential: None,
            x_amz_target: Some("DynamoDBStreams_20120810.ListStreams"),
            host: None,
            path: "/",
            body: b"",
        };
        let decision = resolve(&reg, &input).unwrap();
        assert_eq!(decision.service_name, ServiceName::new("streams.dynamodb"));
        assert_eq!(decision.resolution_source, ResolutionSource::XAmzTarget);
    }

    #[test]
    fn malformed_scope_falls_back_to_target() {
        let reg = ServiceRegistry::with_known_services();
        let input = RouteInput {
            authorization: Some("AWS4-HMAC-SHA256 Credential=broken, Signature=x"),
            x_amz_credential: None,
            x_amz_target: Some("AWSStepFunctions.StartExecution"),
            host: None,
            path: "/",
            body: b"",
        };
        let d = resolve(&reg, &input).unwrap();
        assert_eq!(d.service_name, ServiceName::new("states"));
        assert_eq!(d.resolution_source, ResolutionSource::XAmzTarget);
    }

    #[test]
    fn native_service_is_handled_natively() {
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("s3"),
            ServiceMetadata::new(AwsProtocol::RestXml, None),
            Arc::new(TestHandler),
        );
        let a = auth("s3");
        let input = RouteInput {
            authorization: Some(&a),
            x_amz_credential: None,
            x_amz_target: None,
            host: None,
            path: "/",
            body: b"",
        };
        let d = resolve(&reg, &input).unwrap();
        assert_eq!(d.disposition, RouteDisposition::HandledNatively);
    }

    #[test]
    fn unregistered_scope_service_is_proxied() {
        let reg = ServiceRegistry::with_known_services();
        let a = auth("opensearch");
        let input = RouteInput {
            authorization: Some(&a),
            x_amz_credential: None,
            x_amz_target: None,
            host: None,
            path: "/",
            body: b"",
        };
        let d = resolve(&reg, &input).unwrap();
        assert_eq!(d.service_name, ServiceName::new("opensearch"));
        assert_eq!(d.disposition, RouteDisposition::ProxiedToLegacy);
    }

    #[test]
    fn s3_resolved_by_virtual_hosted_host() {
        let svc = resolve_s3_from_host_path(Some("my-bucket.s3.us-east-1.localhost"), "/key");
        assert_eq!(svc, Some(ServiceName::new("s3")));
    }

    #[test]
    fn execute_api_resolved_from_host() {
        let reg = ServiceRegistry::with_known_services();
        let input = RouteInput {
            authorization: None,
            x_amz_credential: None,
            x_amz_target: None,
            host: Some("abc123.execute-api.us-east-1.amazonaws.com"),
            path: "/prod/items",
            body: b"",
        };
        let d = resolve(&reg, &input).unwrap();
        assert_eq!(d.service_name, ServiceName::new("execute-api"));
        assert_eq!(d.resolution_source, ResolutionSource::HostPath);
        // Proxied until the apigateway crate registers it Native.
        assert_eq!(d.disposition, RouteDisposition::ProxiedToLegacy);
    }

    #[test]
    fn action_field_fallback() {
        let reg = ServiceRegistry::new();
        let mut meta = ServiceMetadata::new(AwsProtocol::Query, None);
        meta.known_actions = vec!["Publish".to_string()];
        reg.register_proxied(ServiceName::new("sns"), meta);
        let input = RouteInput {
            authorization: None,
            x_amz_credential: None,
            x_amz_target: None,
            host: None,
            path: "/",
            body: b"Action=Publish&TopicArn=arn:aws:sns:us-east-1:000000000000:t",
        };
        let d = resolve(&reg, &input).unwrap();
        assert_eq!(d.service_name, ServiceName::new("sns"));
        assert_eq!(d.resolution_source, ResolutionSource::ActionField);
    }

    #[test]
    fn body_is_preserved_after_action_inspection() {
        let body = b"Action=Publish&X=1".to_vec();
        let _ = read_action_field(&body);
        assert_eq!(body, b"Action=Publish&X=1");
    }

    #[test]
    fn unresolved_when_no_source() {
        let reg = ServiceRegistry::with_known_services();
        let input = RouteInput {
            authorization: None,
            x_amz_credential: None,
            x_amz_target: None,
            host: None,
            path: "/",
            body: b"",
        };
        assert_eq!(resolve(&reg, &input), Err(Unresolved));
    }
}
