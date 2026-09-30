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

    /// Evaluate an identity policy independently of permissive service enforcement.
    /// A KMS account-principal grant can delegate only when this returns true.
    fn identity_policy_allows(&self, _request: AuthorizationRequest) -> bool {
        false
    }
}
