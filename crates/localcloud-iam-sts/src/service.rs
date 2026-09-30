//! IAM and STS service handlers: Query-protocol dispatch, registered `Native` in the Core
//! registry. Both services share one [`IamStore`] and [`SessionStore`].

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;

use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::integration::authorization::{
    AuthorizationError, AuthorizationEvaluator, AuthorizationRequest,
    ServiceRoleAuthorizationRequest, ServiceRoleCredentials, SigningCredentials,
};
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::enforcement::{EnforcementFilter, EnforcementMode};
use crate::error::IamStsError;
use crate::iam::{self, Entity, OpResult};
use crate::policy::service_trust_allows;
use crate::query::{response_envelope, QueryRequest, IAM_XMLNS, STS_XMLNS};
use crate::store::IamStore;
use crate::sts::{self, SessionStore};
use crate::{
    arn::build_iam_arn,
    ids,
    model::{now_iso8601, AccessKey, IamUser},
};
use localcloud_core::integration::RequestIdentity;

/// State shared by the IAM and STS handlers.
struct IamStsState {
    store: Arc<IamStore>,
    sessions: Arc<SessionStore>,
    enforcement: EnforcementFilter,
    mode: EnforcementMode,
}

impl IamStsState {
    fn new(store: Arc<IamStore>, sessions: Arc<SessionStore>) -> Self {
        let enforcement = EnforcementFilter::new(store.clone(), sessions.clone());
        IamStsState {
            store,
            sessions,
            enforcement,
            mode: EnforcementMode::from_env(),
        }
    }

    fn validate_service_role(
        &self,
        request: &ServiceRoleAuthorizationRequest,
    ) -> Result<(), AuthorizationError> {
        let account = &request.caller.account_id;
        if request.service_principal.is_empty()
            || request.action.is_empty()
            || request.resource.is_empty()
            || !request
                .role_arn
                .starts_with(&format!("arn:aws:iam::{account}:role/"))
        {
            return Err(AuthorizationError::InvalidRequest);
        }
        let role_name = request
            .role_arn
            .rsplit('/')
            .next()
            .ok_or(AuthorizationError::Denied)?;
        let role = self
            .store
            .get_role(account, role_name)
            .filter(|role| role.arn == request.role_arn)
            .ok_or(AuthorizationError::Denied)?;
        if !service_trust_allows(
            &role.assume_role_policy_document,
            &request.service_principal,
            &request.role_arn,
        ) {
            return Err(AuthorizationError::Denied);
        }
        Ok(())
    }

    /// Resolve the caller identity from the request and apply strict-mode enforcement.
    /// `service` is the IAM-style prefix (`iam`/`sts`); the action gates the request.
    fn enforce(
        &self,
        request: &ServiceRequest,
        service: &str,
        action: &str,
    ) -> Result<(), IamStsError> {
        let access_key_id = request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(RequestIdentity::access_key_from_authorization);
        let identity = RequestIdentity {
            account_id: request.account_id.clone(),
            access_key_id,
            arn: None,
        };
        let result =
            self.enforcement
                .check(self.mode, &identity, &format!("{service}:{action}"), "*");
        if let Err(IamStsError::AccessDenied(_)) = &result {
            tracing::info!(
                request_id = %request.request_id,
                service,
                action,
                "strict-mode enforcement denied request"
            );
        }
        result
    }
}

impl AuthorizationEvaluator for IamStsState {
    fn issue_service_role_credentials(
        &self,
        account: &str,
        role_arn: &str,
        service_principal: &str,
    ) -> Result<ServiceRoleCredentials, AuthorizationError> {
        self.validate_service_role(&ServiceRoleAuthorizationRequest {
            caller: RequestIdentity {
                account_id: account.to_string(),
                access_key_id: None,
                arn: None,
            },
            role_arn: role_arn.to_string(),
            service_principal: service_principal.to_string(),
            action: "sts:AssumeRole".into(),
            resource: role_arn.to_string(),
        })?;
        let creds =
            sts::issue_service_role_credentials(&self.store, &self.sessions, account, role_arn)
                .map_err(|_| AuthorizationError::Denied)?;
        Ok(ServiceRoleCredentials {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
        })
    }

    fn strict_sigv4_required(&self) -> bool {
        self.mode == EnforcementMode::Strict
    }

    fn verify_sigv4(
        &self,
        account: &str,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: &[u8],
        region: &str,
        service: &str,
    ) -> bool {
        localcloud_core::integration::sigv4::verify(
            method,
            uri,
            headers,
            body,
            region,
            service,
            |access_key| {
                if let Some(session) = self.sessions.resolve(access_key) {
                    return (session.account == account).then_some(SigningCredentials {
                        secret_access_key: session.secret_access_key,
                        session_token: Some(session.session_token),
                    });
                }
                self.store.list_users(account).into_iter().find_map(|user| {
                    user.access_keys.into_iter().find_map(|key| {
                        (key.access_key_id == access_key && key.status == "Active").then_some(
                            SigningCredentials {
                                secret_access_key: key.secret_access_key,
                                session_token: None,
                            },
                        )
                    })
                })
            },
        )
    }

    fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError> {
        if request.source_service.is_empty()
            || request.action.is_empty()
            || request.resource.is_empty()
            || request.request_identity.account_id.is_empty()
        {
            return Err(AuthorizationError::InvalidRequest);
        }
        self.enforcement
            .check_with_context(
                self.mode,
                &request.request_identity,
                &request.action,
                &request.resource,
                &request.context,
            )
            .map_err(|error| match error {
                IamStsError::AccessDenied(_) => AuthorizationError::Denied,
                _ => AuthorizationError::Internal,
            })
    }

    fn authorize_service_role(
        &self,
        request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), AuthorizationError> {
        self.validate_service_role(&request)?;
        if self.mode != EnforcementMode::Strict {
            return Ok(());
        }
        let pass_context = BTreeMap::from([(
            "iam:passedtoservice".into(),
            vec![request.service_principal.clone()],
        )]);
        self.enforcement
            .check_with_context(
                EnforcementMode::Strict,
                &request.caller,
                "iam:PassRole",
                &request.role_arn,
                &pass_context,
            )
            .map_err(|_| AuthorizationError::Denied)?;
        self.enforcement
            .check_role(
                &request.caller.account_id,
                &request.role_arn,
                &request.action,
                &request.resource,
            )
            .map_err(|_| AuthorizationError::Denied)
    }

    fn authorize_service_role_assignment(
        &self,
        request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), AuthorizationError> {
        self.validate_service_role(&request)?;
        if self.mode != EnforcementMode::Strict {
            return Ok(());
        }
        let pass_context = BTreeMap::from([(
            "iam:passedtoservice".into(),
            vec![request.service_principal.clone()],
        )]);
        self.enforcement
            .check_with_context(
                EnforcementMode::Strict,
                &request.caller,
                "iam:PassRole",
                &request.role_arn,
                &pass_context,
            )
            .map_err(|_| AuthorizationError::Denied)
    }

    fn authorize_service_role_execution(
        &self,
        request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), AuthorizationError> {
        self.validate_service_role(&request)?;
        if self.mode != EnforcementMode::Strict {
            return Ok(());
        }
        self.enforcement
            .check_role(
                &request.caller.account_id,
                &request.role_arn,
                &request.action,
                &request.resource,
            )
            .map_err(|_| AuthorizationError::Denied)
    }

    fn resolve_caller_arn(
        &self,
        identity: &RequestIdentity,
    ) -> Result<Option<String>, AuthorizationError> {
        let Some(access_key_id) = identity.access_key_id.as_deref() else {
            return Ok(None);
        };
        if let Some(session) = self.sessions.resolve(access_key_id) {
            return if session.account == identity.account_id {
                Ok(Some(session.role_arn.unwrap_or(session.arn)))
            } else {
                Err(AuthorizationError::Denied)
            };
        }
        Ok(self
            .store
            .list_users(&identity.account_id)
            .into_iter()
            .find(|user| {
                user.access_keys
                    .iter()
                    .any(|key| key.access_key_id == access_key_id && key.status == "Active")
            })
            .map(|user| user.arn))
    }

    fn identity_policy_allows(&self, request: AuthorizationRequest) -> bool {
        self.enforcement
            .check_with_context(
                EnforcementMode::Strict,
                &request.request_identity,
                &request.action,
                &request.resource,
                &request.context,
            )
            .is_ok()
    }
}

/// The natively-implemented IAM service.
struct IamHandler {
    state: Arc<IamStsState>,
}

/// The natively-implemented STS service.
struct StsHandler {
    state: Arc<IamStsState>,
}

#[async_trait]
impl NativeHandler for IamHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let q = QueryRequest::parse(&request.body);
        let action = match q.action() {
            Some(a) => a.to_string(),
            None => {
                return IamStsError::InvalidAction("missing Action".into())
                    .into_response(&request.request_id, IAM_XMLNS)
            }
        };
        tracing::info!(request_id = %request.request_id, service = "iam", %action, "iam request");
        if let Err(e) = self.state.enforce(&request, "iam", &action) {
            return e.into_response(&request.request_id, IAM_XMLNS);
        }
        match dispatch_iam(&self.state, &request.account_id, &action, &q) {
            Ok(body) => xml_response(&response_envelope(
                &action,
                IAM_XMLNS,
                &body,
                &request.request_id,
            )),
            Err(e) => e.into_response(&request.request_id, IAM_XMLNS),
        }
    }
}

#[async_trait]
impl NativeHandler for StsHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let q = QueryRequest::parse(&request.body);
        let action = match q.action() {
            Some(a) => a.to_string(),
            None => {
                return IamStsError::InvalidAction("missing Action".into())
                    .into_response(&request.request_id, STS_XMLNS)
            }
        };
        let caller_key = access_key_id_from_auth(&request);
        tracing::info!(request_id = %request.request_id, service = "sts", %action, "sts request");
        if let Err(e) = self.state.enforce(&request, "sts", &action) {
            return e.into_response(&request.request_id, STS_XMLNS);
        }
        match dispatch_sts(
            &self.state,
            &request.account_id,
            &action,
            &q,
            caller_key.as_deref(),
        ) {
            Ok(body) => xml_response(&response_envelope(
                &action,
                STS_XMLNS,
                &body,
                &request.request_id,
            )),
            Err(e) => e.into_response(&request.request_id, STS_XMLNS),
        }
    }
}

fn dispatch_iam(state: &IamStsState, account: &str, action: &str, q: &QueryRequest) -> OpResult {
    let store = &state.store;
    match action {
        // Users
        "CreateUser" => iam::create_user(store, account, q),
        "GetUser" => iam::get_user(store, account, q),
        "DeleteUser" => iam::delete_user(store, account, q),
        "UpdateUser" => iam::update_user(store, account, q),
        "ListUsers" => iam::list_users(store, account, q),
        "TagUser" => iam::tag_user(store, account, q),
        "UntagUser" => iam::untag_user(store, account, q),
        "ListUserTags" => iam::list_user_tags(store, account, q),
        // Groups
        "CreateGroup" => iam::create_group(store, account, q),
        "GetGroup" => iam::get_group(store, account, q),
        "ListGroups" => iam::list_groups(store, account, q),
        "AddUserToGroup" => iam::add_user_to_group(store, account, q),
        "RemoveUserFromGroup" => iam::remove_user_from_group(store, account, q),
        "ListGroupsForUser" => iam::list_groups_for_user(store, account, q),
        "DeleteGroup" => iam::delete_group(store, account, q),
        // Roles
        "CreateRole" => iam::create_role(store, account, q),
        "GetRole" => iam::get_role(store, account, q),
        "ListRoles" => iam::list_roles(store, account, q),
        "UpdateRole" => iam::update_role(store, account, q),
        "UpdateAssumeRolePolicy" => iam::update_assume_role_policy(store, account, q),
        "TagRole" => iam::tag_role(store, account, q),
        "UntagRole" => iam::untag_role(store, account, q),
        "ListRoleTags" => iam::list_role_tags(store, account, q),
        "DeleteRole" => iam::delete_role(store, account, q),
        // Managed policies
        "CreatePolicy" => iam::create_policy(store, account, q),
        "GetPolicy" => iam::get_policy(store, account, q),
        "ListPolicies" => iam::list_policies(store, account, q),
        "DeletePolicy" => iam::delete_policy(store, account, q),
        "TagPolicy" => iam::tag_policy(store, account, q),
        "UntagPolicy" => iam::untag_policy(store, account, q),
        "ListPolicyTags" => iam::list_policy_tags(store, account, q),
        // Policy versions
        "CreatePolicyVersion" => iam::create_policy_version(store, account, q),
        "GetPolicyVersion" => iam::get_policy_version(store, account, q),
        "ListPolicyVersions" => iam::list_policy_versions(store, account, q),
        "SetDefaultPolicyVersion" => iam::set_default_policy_version(store, account, q),
        "DeletePolicyVersion" => iam::delete_policy_version(store, account, q),
        // Attachments
        "AttachUserPolicy" => iam::attach_policy(store, account, Entity::User, q),
        "AttachGroupPolicy" => iam::attach_policy(store, account, Entity::Group, q),
        "AttachRolePolicy" => iam::attach_policy(store, account, Entity::Role, q),
        "DetachUserPolicy" => iam::detach_policy(store, account, Entity::User, q),
        "DetachGroupPolicy" => iam::detach_policy(store, account, Entity::Group, q),
        "DetachRolePolicy" => iam::detach_policy(store, account, Entity::Role, q),
        "ListAttachedUserPolicies" => iam::list_attached_policies(store, account, Entity::User, q),
        "ListAttachedGroupPolicies" => {
            iam::list_attached_policies(store, account, Entity::Group, q)
        }
        "ListAttachedRolePolicies" => iam::list_attached_policies(store, account, Entity::Role, q),
        // Inline policies
        "PutUserPolicy" => iam::put_inline_policy(store, account, Entity::User, q),
        "PutGroupPolicy" => iam::put_inline_policy(store, account, Entity::Group, q),
        "PutRolePolicy" => iam::put_inline_policy(store, account, Entity::Role, q),
        "GetUserPolicy" => iam::get_inline_policy(store, account, Entity::User, q),
        "GetGroupPolicy" => iam::get_inline_policy(store, account, Entity::Group, q),
        "GetRolePolicy" => iam::get_inline_policy(store, account, Entity::Role, q),
        "ListUserPolicies" => iam::list_inline_policies(store, account, Entity::User, q),
        "ListGroupPolicies" => iam::list_inline_policies(store, account, Entity::Group, q),
        "ListRolePolicies" => iam::list_inline_policies(store, account, Entity::Role, q),
        "DeleteUserPolicy" => iam::delete_inline_policy(store, account, Entity::User, q),
        "DeleteGroupPolicy" => iam::delete_inline_policy(store, account, Entity::Group, q),
        "DeleteRolePolicy" => iam::delete_inline_policy(store, account, Entity::Role, q),
        // Permission boundaries
        "PutUserPermissionsBoundary" => {
            iam::put_permissions_boundary(store, account, Entity::User, q)
        }
        "PutRolePermissionsBoundary" => {
            iam::put_permissions_boundary(store, account, Entity::Role, q)
        }
        "DeleteUserPermissionsBoundary" => {
            iam::delete_permissions_boundary(store, account, Entity::User, q)
        }
        "DeleteRolePermissionsBoundary" => {
            iam::delete_permissions_boundary(store, account, Entity::Role, q)
        }
        // Access keys
        "CreateAccessKey" => iam::create_access_key(store, account, q),
        "ListAccessKeys" => iam::list_access_keys(store, account, q),
        "UpdateAccessKey" => iam::update_access_key(store, account, q),
        "DeleteAccessKey" => iam::delete_access_key(store, account, q),
        // Instance profiles
        "CreateInstanceProfile" => iam::create_instance_profile(store, account, q),
        "GetInstanceProfile" => iam::get_instance_profile(store, account, q),
        "ListInstanceProfiles" => iam::list_instance_profiles(store, account, q),
        "AddRoleToInstanceProfile" => iam::add_role_to_instance_profile(store, account, q),
        "RemoveRoleFromInstanceProfile" => {
            iam::remove_role_from_instance_profile(store, account, q)
        }
        "ListInstanceProfilesForRole" => iam::list_instance_profiles_for_role(store, account, q),
        "DeleteInstanceProfile" => iam::delete_instance_profile(store, account, q),
        // Simulate
        "SimulateCustomPolicy" => iam::simulate_custom_policy(store, account, q),
        "SimulatePrincipalPolicy" => iam::simulate_principal_policy(store, account, q),
        other => Err(IamStsError::InvalidAction(format!(
            "unsupported IAM action {other}"
        ))),
    }
}

fn dispatch_sts(
    state: &IamStsState,
    account: &str,
    action: &str,
    q: &QueryRequest,
    caller_key: Option<&str>,
) -> OpResult {
    let store = &state.store;
    let sessions = &state.sessions;
    match action {
        "AssumeRole" => sts::assume_role(store, sessions, account, q),
        "AssumeRoleWithWebIdentity" => {
            sts::assume_role_with_web_identity(store, sessions, account, q)
        }
        "AssumeRoleWithSAML" => sts::assume_role_with_saml(store, sessions, account, q),
        "GetCallerIdentity" => {
            let caller = caller_key
                .and_then(|key| sessions.resolve(key))
                .filter(|session| session.account == account);
            if let Some(session) = caller {
                return Ok(sts::get_caller_identity(account, Some(session)));
            }
            if let Some(user) = caller_key.and_then(|key| {
                store.list_users(account).into_iter().find(|user| {
                    user.access_keys.iter().any(|access_key| {
                        access_key.access_key_id == key && access_key.status == "Active"
                    })
                })
            }) {
                return Ok(sts::get_iam_caller_identity(account, &user));
            }
            // Permissive local mode has always returned root for an unresolved caller.
            // Strict mode already rejects missing/inactive keys in `enforce` above.
            Ok(sts::get_caller_identity(account, None))
        }
        "GetSessionToken" => Ok(sts::get_session_token(sessions, account, q)),
        "GetFederationToken" => sts::get_federation_token(sessions, account, q),
        "DecodeAuthorizationMessage" => sts::decode_authorization_message(q),
        other => Err(IamStsError::InvalidAction(format!(
            "unsupported STS action {other}"
        ))),
    }
}

/// Extract the SigV4 access key id from the `Authorization` header `Credential=` field.
fn access_key_id_from_auth(req: &ServiceRequest) -> Option<String> {
    let auth = req
        .headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let cred = auth.split("Credential=").nth(1)?;
    cred.split('/').next().map(str::to_string)
}

fn xml_response(body: &str) -> Response {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/xml")
        .body(Body::from(body.to_string()))
        .expect("xml response is always valid")
}

/// Explicit startup credential for a process-local strict-mode IAM administrator.
/// Revocation is effective in this process; a fresh process seeds the configured key again.
pub struct BootstrapCredentials {
    access_key_id: String,
    secret_access_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BootstrapError {
    #[error("strict IAM requires both bootstrap access key ID and secret access key")]
    MissingCredentials,
    #[error("invalid bootstrap access key ID or secret access key")]
    InvalidCredentials,
}

impl BootstrapCredentials {
    /// Read only explicit LocalCloud settings. Never include credential values in errors.
    pub fn from_env(strict: bool) -> Result<Option<Self>, BootstrapError> {
        Self::from_lookup(strict, &|name| std::env::var(name).ok())
    }

    fn from_lookup(
        strict: bool,
        get: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, BootstrapError> {
        let id = get("LOCALCLOUD_BOOTSTRAP_ACCESS_KEY_ID");
        let secret = get("LOCALCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY");
        match (id, secret) {
            (None, None) if !strict => Ok(None),
            (Some(access_key_id), Some(secret_access_key)) => {
                let valid_id = access_key_id.len() == 20
                    && access_key_id.starts_with("AKIA")
                    && access_key_id
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
                let valid_secret = secret_access_key.len() == 40
                    && secret_access_key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
                if !valid_id || !valid_secret {
                    return Err(BootstrapError::InvalidCredentials);
                }
                Ok(Some(Self {
                    access_key_id,
                    secret_access_key,
                }))
            }
            _ => Err(BootstrapError::MissingCredentials),
        }
    }
}

fn seed_bootstrap_user(store: &IamStore, account: &str, credentials: BootstrapCredentials) {
    let name = "localcloud-bootstrap";
    let mut inline_policies = BTreeMap::new();
    inline_policies.insert(
        "LocalCloudBootstrapAdministrator".to_string(),
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#
            .to_string(),
    );
    let created = now_iso8601();
    let user = IamUser {
        user_name: name.to_string(),
        user_id: ids::unique_id(ids::USER),
        arn: build_iam_arn(account, "user", "/", name),
        path: "/".to_string(),
        create_date: created.clone(),
        tags: BTreeMap::new(),
        attached_policies: Vec::new(),
        inline_policies,
        groups: Vec::new(),
        permission_boundary: None,
        access_keys: vec![AccessKey {
            access_key_id: credentials.access_key_id,
            secret_access_key: credentials.secret_access_key,
            status: "Active".to_string(),
            create_date: created,
        }],
    };
    let _ = store.create_user(account, user);
}

/// Register IAM and STS for the configured account. Validate bootstrap before publishing
/// either service, so strict mode never starts with an unreachable control plane.
pub fn register_with_account(
    registry: &ServiceRegistry,
    account: &str,
) -> Result<(), BootstrapError> {
    let credentials =
        BootstrapCredentials::from_env(EnforcementMode::from_env() == EnforcementMode::Strict)?;
    register_inner(registry, account, credentials);
    Ok(())
}

/// Compatibility registration for standalone permissive tests.
pub fn register(registry: &ServiceRegistry) {
    register_inner(registry, "000000000000", None);
}

fn register_inner(
    registry: &ServiceRegistry,
    account: &str,
    credentials: Option<BootstrapCredentials>,
) {
    let state = Arc::new(IamStsState::new(
        Arc::new(IamStore::new()),
        Arc::new(SessionStore::new()),
    ));
    iam::seed_aws_managed_policies(&state.store);
    if let Some(credentials) = credentials {
        seed_bootstrap_user(&state.store, account, credentials);
    }
    let iam_handler: Arc<dyn NativeHandler> = Arc::new(IamHandler {
        state: state.clone(),
    });
    let sts_handler: Arc<dyn NativeHandler> = Arc::new(StsHandler {
        state: state.clone(),
    });
    let authorization_evaluator: Arc<dyn AuthorizationEvaluator> = state;
    registry.register_native_with_authorization_evaluator(
        ServiceName::new("iam"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        iam_handler,
        authorization_evaluator,
    );
    registry.register_native(
        ServiceName::new("sts"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        sts_handler,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, Method};

    #[test]
    fn strict_bootstrap_requires_valid_explicit_pair() {
        let key = "AKIAABCDEFGHIJKLMNOP";
        let secret = "a".repeat(40);
        assert!(matches!(
            BootstrapCredentials::from_lookup(true, &|_| None),
            Err(BootstrapError::MissingCredentials)
        ));
        assert!(matches!(
            BootstrapCredentials::from_lookup(true, &|name| {
                (name == "LOCALCLOUD_BOOTSTRAP_ACCESS_KEY_ID").then(|| key.to_string())
            }),
            Err(BootstrapError::MissingCredentials)
        ));
        assert!(matches!(
            BootstrapCredentials::from_lookup(true, &|name| match name {
                "LOCALCLOUD_BOOTSTRAP_ACCESS_KEY_ID" => Some("AKIAINVALID".to_string()),
                "LOCALCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY" => Some(secret.clone()),
                _ => None,
            }),
            Err(BootstrapError::InvalidCredentials)
        ));
        let credentials = BootstrapCredentials::from_lookup(true, &|name| match name {
            "LOCALCLOUD_BOOTSTRAP_ACCESS_KEY_ID" => Some(key.to_string()),
            "LOCALCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY" => Some(secret.clone()),
            _ => None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(credentials.access_key_id, key);
    }

    #[test]
    fn bootstrap_user_is_account_scoped_and_uses_normal_iam_authorization() {
        let store = Arc::new(IamStore::new());
        let sessions = Arc::new(SessionStore::new());
        let account = "123456789012";
        let key = "AKIAABCDEFGHIJKLMNOP";
        seed_bootstrap_user(
            &store,
            account,
            BootstrapCredentials {
                access_key_id: key.to_string(),
                secret_access_key: "a".repeat(40),
            },
        );
        let user = store.get_user(account, "localcloud-bootstrap").unwrap();
        assert_eq!(
            user.arn,
            "arn:aws:iam::123456789012:user/localcloud-bootstrap"
        );
        assert!(store
            .get_user("000000000000", "localcloud-bootstrap")
            .is_none());
        let filter = EnforcementFilter::new(store.clone(), sessions);
        let identity = RequestIdentity {
            account_id: account.to_string(),
            access_key_id: Some(key.to_string()),
            arn: None,
        };
        assert!(filter
            .check(EnforcementMode::Strict, &identity, "iam:CreateUser", "*")
            .is_ok());
        store.update_user(account, "localcloud-bootstrap", |user| {
            user.access_keys[0].status = "Inactive".to_string();
        });
        assert!(matches!(
            filter.check(EnforcementMode::Strict, &identity, "iam:CreateUser", "*"),
            Err(IamStsError::AccessDenied(_))
        ));
    }

    fn request(body: &str) -> ServiceRequest {
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            body: Bytes::copy_from_slice(body.as_bytes()),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        }
    }

    fn iam_handler() -> IamHandler {
        let state = Arc::new(IamStsState::new(
            Arc::new(IamStore::new()),
            Arc::new(SessionStore::new()),
        ));
        iam::seed_aws_managed_policies(&state.store);
        IamHandler { state }
    }

    fn sts_handler() -> StsHandler {
        StsHandler {
            state: Arc::new(IamStsState::new(
                Arc::new(IamStore::new()),
                Arc::new(SessionStore::new()),
            )),
        }
    }

    #[test]
    fn service_role_requires_pass_role_trust_and_scoped_role_policy() {
        use crate::model::IamRole;

        let account = "000000000000";
        let key = "AKIAABCDEFGHIJKLMNOP";
        let role_arn = format!("arn:aws:iam::{account}:role/firehose");
        let stream_arn = format!("arn:aws:kinesis:us-east-1:{account}:stream/source");
        let store = Arc::new(IamStore::new());
        seed_bootstrap_user(
            &store,
            account,
            BootstrapCredentials {
                access_key_id: key.into(),
                secret_access_key: "a".repeat(40),
            },
        );
        let mut role = IamRole {
            role_name: "firehose".into(), role_id: "AROATEST".into(),
            arn: role_arn.clone(), path: "/".into(),
            create_date: now_iso8601(),
            assume_role_policy_document: r#"{"Statement":{"Effect":"Allow","Principal":{"Service":"firehose.amazonaws.com"},"Action":"sts:AssumeRole"}}"#.into(),
            description: None, max_session_duration: 3600, tags: BTreeMap::new(),
            attached_policies: Vec::new(), inline_policies: BTreeMap::new(),
            permission_boundary: None,
        };
        role.inline_policies.insert("read-source".into(), format!(
            r#"{{"Statement":{{"Effect":"Allow","Action":"kinesis:GetRecords","Resource":"{stream_arn}"}}}}"#
        ));
        store.create_role(account, role);
        let mut state = IamStsState::new(store.clone(), Arc::new(SessionStore::new()));
        state.mode = EnforcementMode::Strict;
        let request = ServiceRoleAuthorizationRequest {
            caller: RequestIdentity {
                account_id: account.into(),
                access_key_id: Some(key.into()),
                arn: None,
            },
            role_arn: role_arn.clone(),
            service_principal: "firehose.amazonaws.com".into(),
            action: "kinesis:GetRecords".into(),
            resource: stream_arn.clone(),
        };
        assert_eq!(state.authorize_service_role(request.clone()), Ok(()));
        assert_eq!(
            state.authorize_service_role_assignment(ServiceRoleAuthorizationRequest {
                action: "iam:PassRole".into(),
                resource: role_arn.clone(),
                ..request.clone()
            }),
            Ok(())
        );
        assert_eq!(
            state.authorize_service_role(ServiceRoleAuthorizationRequest {
                resource: format!("arn:aws:kinesis:us-east-1:{account}:stream/other"),
                ..request.clone()
            }),
            Err(AuthorizationError::Denied)
        );
        store.update_role(account, "firehose", |role| {
            role.assume_role_policy_document = r#"{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}"#.into();
        });
        assert_eq!(
            state.authorize_service_role(request.clone()),
            Err(AuthorizationError::Denied)
        );
        store.update_role(account, "firehose", |role| {
            role.assume_role_policy_document = r#"{"Statement":{"Effect":"Allow","Principal":{"Service":"firehose.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":"000000000000"}}}}"#.into();
        });
        assert_eq!(
            state.authorize_service_role(request.clone()),
            Err(AuthorizationError::Denied)
        );
        store.update_role(account, "firehose", |role| {
            role.assume_role_policy_document = r#"{"Statement":{"Effect":"Allow","Principal":{"Service":"firehose.amazonaws.com"},"Action":"sts:AssumeRole"}}"#.into();
        });
        store.update_user(account, "localcloud-bootstrap", |user| {
            user.inline_policies.clear();
        });
        assert_eq!(
            state.authorize_service_role(request.clone()),
            Err(AuthorizationError::Denied)
        );
        store.update_user(account, "localcloud-bootstrap", |user| {
            user.inline_policies.insert("pass".into(), format!(
                r#"{{"Statement":{{"Effect":"Allow","Action":"iam:PassRole","Resource":"{role_arn}","Condition":{{"StringEquals":{{"iam:PassedToService":"firehose.amazonaws.com"}}}}}}}}"#
            ));
        });
        assert_eq!(state.authorize_service_role(request.clone()), Ok(()));
        assert_eq!(
            state.authorize_service_role(ServiceRoleAuthorizationRequest {
                service_principal: "lambda.amazonaws.com".into(),
                ..request.clone()
            }),
            Err(AuthorizationError::Denied)
        );
        store.update_user(account, "localcloud-bootstrap", |user| {
            user.inline_policies.clear()
        });
        assert_eq!(
            state.authorize_service_role_assignment(ServiceRoleAuthorizationRequest {
                action: "iam:PassRole".into(),
                resource: role_arn.clone(),
                ..request.clone()
            }),
            Err(AuthorizationError::Denied)
        );
        assert_eq!(
            state.authorize_service_role(request.clone()),
            Err(AuthorizationError::Denied)
        );
        assert_eq!(
            state.authorize_service_role_execution(request.clone()),
            Ok(())
        );
        state.mode = EnforcementMode::Permissive;
        store.remove_role(account, "firehose");
        assert_eq!(
            state.authorize_service_role(request.clone()),
            Err(AuthorizationError::Denied)
        );
        assert_eq!(
            state.authorize_service_role_execution(request),
            Err(AuthorizationError::Denied)
        );
    }

    #[tokio::test]
    async fn create_user_returns_xml_envelope() {
        let h = iam_handler();
        let resp = h.handle(request("Action=CreateUser&UserName=alice")).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/xml"
        );
    }

    #[tokio::test]
    async fn get_missing_user_returns_404() {
        let h = iam_handler();
        let resp = h.handle(request("Action=GetUser&UserName=ghost")).await;
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn unknown_action_is_invalid_action() {
        let h = iam_handler();
        let resp = h.handle(request("Action=Frobnicate")).await;
        assert_eq!(resp.status(), 400);
    }

    #[test]
    fn resolves_kms_principal_from_stored_key_and_ignores_supplied_arn() {
        let state = IamStsState::new(Arc::new(IamStore::new()), Arc::new(SessionStore::new()));
        let account = "000000000000";
        iam::create_user(
            &state.store,
            account,
            &QueryRequest::parse(b"UserName=alice"),
        )
        .unwrap();
        iam::create_access_key(
            &state.store,
            account,
            &QueryRequest::parse(b"UserName=alice"),
        )
        .unwrap();
        let access_key_id = state.store.get_user(account, "alice").unwrap().access_keys[0]
            .access_key_id
            .clone();
        let identity = RequestIdentity {
            account_id: account.into(),
            access_key_id: Some(access_key_id),
            arn: Some(format!("arn:aws:iam::{account}:user/mallory")),
        };
        assert_eq!(
            state.resolve_caller_arn(&identity).unwrap(),
            Some(format!("arn:aws:iam::{account}:user/alice"))
        );
        assert_eq!(
            state
                .resolve_caller_arn(&RequestIdentity {
                    account_id: "999999999999".into(),
                    ..identity.clone()
                })
                .unwrap(),
            None
        );
        state.store.update_user(account, "alice", |user| {
            user.access_keys[0].status = "Inactive".into();
        });
        assert_eq!(state.resolve_caller_arn(&identity).unwrap(), None);
    }

    #[tokio::test]
    async fn strict_get_caller_identity_uses_active_iam_user_and_rejects_revocation() {
        let store = Arc::new(IamStore::new());
        seed_bootstrap_user(
            &store,
            "000000000000",
            BootstrapCredentials {
                access_key_id: "AKIAABCDEFGHIJKLMNOP".to_string(),
                secret_access_key: "a".repeat(40),
            },
        );
        let sessions = Arc::new(SessionStore::new());
        let mut state = IamStsState::new(store.clone(), sessions);
        state.mode = EnforcementMode::Strict;
        let handler = StsHandler {
            state: Arc::new(state),
        };
        let mut signed_request = request("Action=GetCallerIdentity");
        signed_request.headers.insert(
            http::header::AUTHORIZATION,
            "AWS4-HMAC-SHA256 Credential=AKIAABCDEFGHIJKLMNOP/20260925/us-east-1/sts/aws4_request"
                .parse()
                .unwrap(),
        );
        let response = handler.handle(signed_request.clone()).await;
        assert_eq!(response.status(), 200);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        let user = store
            .get_user("000000000000", "localcloud-bootstrap")
            .unwrap();
        assert!(body.contains(&format!("<Arn>{}</Arn>", user.arn)));
        assert!(body.contains(&format!("<UserId>{}</UserId>", user.user_id)));
        assert!(!body.contains(":root</Arn>"));

        store.update_user("000000000000", "localcloud-bootstrap", |user| {
            user.access_keys[0].status = "Inactive".to_string();
        });
        let denied = handler.handle(signed_request).await;
        assert_eq!(denied.status(), 403);
    }

    #[tokio::test]
    async fn get_caller_identity_defaults_to_root() {
        let h = sts_handler();
        let resp = h.handle(request("Action=GetCallerIdentity")).await;
        assert_eq!(resp.status(), 200);
    }
}
