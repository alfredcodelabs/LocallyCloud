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

/// Short-lived credentials issued to a service for an existing execution role.
#[derive(Clone)]
pub struct ServiceRoleCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
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

/// Authorization for a service to use one IAM role for one concrete operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRoleAuthorizationRequest {
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
    if request
        .headers
        .get("x-locallycloud-verified-internal-scope")
        .is_some_and(|v| v == "1")
    {
        return Ok(());
    }
    if !request
        .headers
        .get("x-locallycloud-verified-external-sigv4")
        .is_some_and(|v| v == "1")
    {
        return Err(AuthorizationError::Denied);
    }
    let access_key_id = request
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(RequestIdentity::access_key_from_authorization)
        .ok_or(AuthorizationError::Denied)?;
    evaluator.authorize(AuthorizationRequest {
        request_identity: RequestIdentity {
            account_id: request.account_id.clone(),
            access_key_id: Some(access_key_id),
            arn: None,
        },
        delegated_identity: None,
        source_service: service.into(),
        action: action.into(),
        resource: resource.into(),
        context: BTreeMap::from([("aws:requestedregion".into(), vec![request.region.clone()])]),
    })
}
