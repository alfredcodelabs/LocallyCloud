//! Typed authorization capability shared by native services.

use std::collections::BTreeMap;

use http::{HeaderMap, Method, Uri};

use super::identity::CallerIdentity;
use super::RequestIdentity;

pub const AUTHORIZATION_EVALUATOR_VERSION: u16 = 1;

/// Secret material is returned only to Core's request verifier, never to a service handler.
#[derive(Clone)]
pub struct SigningCredentials {
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

/// Internal signing request. The signer returns a URL, never the underlying secret key.
pub struct S3PutPresignRequest {
    pub account: String,
    pub access_key: String,
    pub endpoint: String,
    pub path: String,
    pub region: String,
    pub expires: u32,
}

/// Short-lived credentials issued to a service for an existing execution role.
#[derive(Clone)]
pub struct ServiceRoleCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    /// RFC 3339 expiration issued by STS for these exact credentials.
    pub expiration: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub request_identity: RequestIdentity,
    pub delegated_identity: Option<CallerIdentity>,
    pub source_service: String,
    pub action: String,
    pub resource: String,
    pub context: BTreeMap<String, Vec<String>>,
}

/// The result of evaluating one resource policy without an identity-policy union.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePolicyDecision {
    Allow,
    ExplicitDeny,
    ImplicitDeny,
}

/// Verified request properties for anonymous-only resource-policy evaluation.
/// This request deliberately carries no credentials or delegated identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePolicyEvaluationRequest {
    pub action: String,
    pub resource: String,
    pub context: BTreeMap<String, Vec<String>>,
}

/// Authorization for a service to use one IAM role for one concrete operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRoleAuthorizationRequest {
    /// Only Core-attested delegation may identify an operator without signing credentials.
    pub delegated_caller: Option<CallerIdentity>,
    /// Verified operator context used for PassRole, never inherited by service execution.
    pub caller_context: BTreeMap<String, Vec<String>>,
    /// Originating service resource, supplied by native adapters, never external headers.
    /// None when AWS does not supply SourceArn/SourceAccount (Lambda execution roles).
    pub source_arn: Option<String>,
    pub caller: RequestIdentity,
    pub role_arn: String,
    pub service_principal: String,
    pub action: String,
    pub resource: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizationError {
    #[error("authorization evaluator is unavailable")]
    Unavailable,
    #[error("authorization request is invalid")]
    InvalidRequest,
    #[error("request is not authorized")]
    Denied,
    #[error("authorization evaluation failed")]
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResourcePolicyError {
    #[error("malformed resource policy: {0}")]
    Malformed(String),
    #[error("unsupported resource policy: {0}")]
    Unsupported(String),
}

pub trait AuthorizationEvaluator: Send + Sync {
    fn presign_s3_put(&self, _request: S3PutPresignRequest) -> Result<String, AuthorizationError> {
        Err(AuthorizationError::Unavailable)
    }
    fn version(&self) -> u16 {
        AUTHORIZATION_EVALUATOR_VERSION
    }

    /// Require cryptographic verification at the external ingress. Implementations can
    /// enable this only after their signing credentials have been initialized.
    fn strict_sigv4_required(&self) -> bool {
        false
    }

    fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError>;

    fn validate_resource_policy(&self, _document: &str) -> Result<(), ResourcePolicyError> {
        Err(ResourcePolicyError::Unsupported(
            "resource policies unavailable".into(),
        ))
    }

    /// Evaluate only this document for an anonymous caller, regardless of SigV4.
    /// Context must come from verified native-service metadata. Identity policies,
    /// boundaries and session policies never participate in this decision.
    fn evaluate_anonymous_resource_policy(
        &self,
        _request: ResourcePolicyEvaluationRequest,
        _document: &str,
    ) -> Result<ResourcePolicyDecision, ResourcePolicyError> {
        Err(ResourcePolicyError::Unsupported(
            "anonymous resource policy evaluation unavailable".into(),
        ))
    }

    /// Compose identity and resource policies for a resource's owning account.
    /// Delegated identities must originate from Core's attested internal dispatch.
    fn authorize_resource_policy(
        &self,
        _request: AuthorizationRequest,
        _document: Option<&str>,
        _owner_account: &str,
    ) -> Result<(), AuthorizationError> {
        Err(AuthorizationError::Denied)
    }

    /// Check caller PassRole, role trust, and the role's action/resource policy.
    /// The default denies so evaluators cannot silently grant a role.
    fn authorize_service_role(
        &self,
        _request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), AuthorizationError> {
        Err(AuthorizationError::Denied)
    }

    /// Check caller PassRole and service trust when assigning a role, before a target exists.
    fn authorize_service_role_assignment(
        &self,
        _request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), AuthorizationError> {
        Err(AuthorizationError::Denied)
    }

    /// Recheck runtime role existence and service trust when the target service composes
    /// identity permissions with its own resource policy. This grants no action permission.
    fn authorize_service_role_trust(
        &self,
        _request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), AuthorizationError> {
        Err(AuthorizationError::Denied)
    }

    /// Recheck a stored service role during execution without requiring the operator to PassRole again.
    /// Implementations must verify role existence, trust and action permissions.
    fn authorize_service_role_execution(
        &self,
        _request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), AuthorizationError> {
        Err(AuthorizationError::Denied)
    }

    /// Issue credentials bound to a role trusted by the named service.
    fn issue_service_role_credentials(
        &self,
        _account: &str,
        _role_arn: &str,
        _service_principal: &str,
    ) -> Result<ServiceRoleCredentials, AuthorizationError> {
        Err(AuthorizationError::Denied)
    }

    /// Resolve a unique credential account from trusted state. This is a verifier
    /// lookup hint, not authenticated identity until the original signature passes.
    fn credential_account(
        &self,
        _access_key_id: &str,
    ) -> Result<Option<String>, AuthorizationError> {
        Ok(None)
    }

    /// Verify a request using an active, account-scoped key without exposing secret material.
    #[allow(clippy::too_many_arguments)]
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
        false
    }

    /// Resolve an identity from credentials held by IAM/STS. Implementations must not
    /// trust `request_identity.arn`, which can originate from request metadata.
    fn resolve_caller_arn(
        &self,
        _request_identity: &RequestIdentity,
    ) -> Result<Option<String>, AuthorizationError> {
        Ok(None)
    }

    /// Identify an account root from credential provenance, never a supplied ARN.
    /// Legacy sessions without an authenticated root issuer must return false.
    fn is_account_root(
        &self,
        _request_identity: &RequestIdentity,
    ) -> Result<bool, AuthorizationError> {
        Ok(false)
    }

    /// Key-policy direct grants cannot override explicit IAM Deny, boundaries or session limits.
    /// Unknown evaluators fail closed.
    fn identity_policy_denies(&self, _request: AuthorizationRequest) -> bool {
        true
    }

    /// Evaluate genuine identity permission independently of permissive service enforcement.
    /// A KMS account-principal grant can delegate only when this returns true.
    fn identity_policy_allows(&self, _request: AuthorizationRequest) -> bool {
        false
    }
}

/// Recover an operator or execution role only from Core-attested request scope.
/// Internal operators must match their original signing credentials; delegated roles
/// carry their own typed principal and never inherit the operator's credentials.
pub fn verified_caller(
    evaluator: &dyn AuthorizationEvaluator,
    request: &crate::handler::ServiceRequest,
) -> Result<(RequestIdentity, Option<CallerIdentity>), AuthorizationError> {
    let internal = request
        .headers
        .get("x-locallycloud-verified-internal-scope")
        .is_some_and(|v| v == "1");
    let external = request
        .headers
        .get("x-locallycloud-verified-external-sigv4")
        .is_some_and(|v| v == "1");
    if internal == external {
        return Err(AuthorizationError::Denied);
    }
    let access_key_id = request
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(RequestIdentity::access_key_from_authorization);
    let delegated_identity = super::identity::trusted_role(request);
    let request_identity = RequestIdentity {
        account_id: request.account_id.clone(),
        access_key_id: if delegated_identity.is_some() {
            None
        } else {
            access_key_id
        },
        arn: None,
    };
    if delegated_identity.is_none() {
        if request_identity.access_key_id.is_none() {
            return Err(AuthorizationError::Denied);
        }
        if internal {
            let principal = request
                .headers
                .get(super::identity::PRINCIPAL_HEADER)
                .and_then(|value| value.to_str().ok())
                .ok_or(AuthorizationError::Denied)?;
            if evaluator.resolve_caller_arn(&request_identity)?.as_deref() != Some(principal) {
                return Err(AuthorizationError::Denied);
            }
        }
    }
    Ok((request_identity, delegated_identity))
}

/// Shared identity verification for external native management reads. Internal dispatcher
/// scopes are attested by Core; an external header cannot create that attestation.
pub fn authorize_native_read(
    registry: &std::sync::Weak<crate::registry::ServiceRegistry>,
    request: &crate::handler::ServiceRequest,
    service: &str,
    action: &str,
    resource: &str,
) -> Result<(), AuthorizationError> {
    // Standalone native handlers can run without IAM; Core rejects a missing registry
    // before external dispatch, so this does not bypass configured ingress enforcement.
    let Some(registry) = registry.upgrade() else {
        return Ok(());
    };
    let Some(evaluator) =
        registry.authorization_evaluator(&crate::registry::ServiceName::new("iam"))
    else {
        return Ok(());
    };
    if !evaluator.strict_sigv4_required() {
        return Ok(());
    }
    let (request_identity, delegated_identity) = verified_caller(evaluator.as_ref(), request)?;
    evaluator.authorize(AuthorizationRequest {
        request_identity,
        delegated_identity,
        source_service: service.into(),
        action: action.into(),
        resource: resource.into(),
        context: super::request_context::verified_request_context(request),
    })
}

#[cfg(test)]
mod caller_tests {
    use super::super::identity::{CallerIdentity, IdentityPropagator, PRINCIPAL_HEADER};
    use super::*;
    use crate::handler::ServiceRequest;

    struct Evaluator;
    impl AuthorizationEvaluator for Evaluator {
        fn authorize(&self, _: AuthorizationRequest) -> Result<(), AuthorizationError> {
            Ok(())
        }
        fn resolve_caller_arn(
            &self,
            identity: &RequestIdentity,
        ) -> Result<Option<String>, AuthorizationError> {
            Ok((identity.access_key_id.as_deref() == Some("OPERATOR"))
                .then(|| "arn:aws:iam::000000000000:user/operator".into()))
        }
    }
    #[test]
    fn anonymous_resource_policy_default_is_unavailable_even_for_an_allowing_evaluator() {
        let result = Evaluator.evaluate_anonymous_resource_policy(
            ResourcePolicyEvaluationRequest {
                action: "execute-api:Invoke".into(),
                resource: "arn:aws:execute-api:us-east-1:000000000000:api/prod/GET/".into(),
                context: BTreeMap::new(),
            },
            r#"{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}"#,
        );
        assert!(matches!(result, Err(ResourcePolicyError::Unsupported(_))));
    }

    #[test]
    fn caller_requires_one_attestation_and_distinguishes_operators_from_roles() {
        let mut request = ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: bytes::Bytes::new(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "test".into(),
        };
        request.headers.insert(
            http::header::AUTHORIZATION,
            "AWS4-HMAC-SHA256 Credential=OPERATOR/20261116/us-east-1/ssm/aws4_request"
                .parse()
                .unwrap(),
        );
        request.headers.insert(
            PRINCIPAL_HEADER,
            "arn:aws:iam::000000000000:user/operator".parse().unwrap(),
        );
        assert_eq!(
            verified_caller(&Evaluator, &request),
            Err(AuthorizationError::Denied)
        );
        request.headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        assert_eq!(
            verified_caller(&Evaluator, &request)
                .unwrap()
                .0
                .access_key_id
                .as_deref(),
            Some("OPERATOR")
        );
        request.headers.insert(
            "x-locallycloud-verified-internal-scope",
            "1".parse().unwrap(),
        );
        assert_eq!(
            verified_caller(&Evaluator, &request),
            Err(AuthorizationError::Denied)
        );
        request
            .headers
            .remove("x-locallycloud-verified-external-sigv4");
        assert!(verified_caller(&Evaluator, &request).unwrap().1.is_none());
        request.headers.insert(
            PRINCIPAL_HEADER,
            "arn:aws:iam::000000000000:user/other".parse().unwrap(),
        );
        assert_eq!(
            verified_caller(&Evaluator, &request),
            Err(AuthorizationError::Denied)
        );
        let role = CallerIdentity::AssumedRole {
            role_arn: "arn:aws:iam::000000000000:role/operator".into(),
            session_name: "task".into(),
        };
        IdentityPropagator::attach(&mut request.headers, &role);
        let (identity, delegated) = verified_caller(&Evaluator, &request).unwrap();
        assert_eq!(delegated, Some(role));
        assert!(identity.access_key_id.is_none());
        IdentityPropagator::attach(
            &mut request.headers,
            &CallerIdentity::AssumedRole {
                role_arn: "arn:aws:iam::111111111111:role/operator".into(),
                session_name: "task".into(),
            },
        );
        assert_eq!(
            verified_caller(&Evaluator, &request),
            Err(AuthorizationError::Denied)
        );
        IdentityPropagator::attach(
            &mut request.headers,
            &CallerIdentity::ServicePrincipal {
                service: "events".into(),
            },
        );
        assert_eq!(
            verified_caller(&Evaluator, &request),
            Err(AuthorizationError::Denied)
        );
        request
            .headers
            .remove("x-locallycloud-verified-internal-scope");
        request.headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        IdentityPropagator::attach(
            &mut request.headers,
            &CallerIdentity::AssumedRole {
                role_arn: "arn:aws:iam::000000000000:role/operator".into(),
                session_name: "task".into(),
            },
        );
        let (identity, delegated) = verified_caller(&Evaluator, &request).unwrap();
        assert!(delegated.is_none());
        assert_eq!(identity.access_key_id.as_deref(), Some("OPERATOR"));
        request.headers.remove(http::header::AUTHORIZATION);
        assert_eq!(
            verified_caller(&Evaluator, &request),
            Err(AuthorizationError::Denied)
        );
    }
}
