//! IAM and STS service handlers: Query-protocol dispatch, registered `Native` in the Core
//! registry. Both services share one [`IamStore`] and [`SessionStore`].

#[cfg(test)]
mod endpoint_policy_tests;
mod iam_authorization;
#[cfg(test)]
mod iam_authorization_tests;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;

use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::{
    AuthorizationError, AuthorizationEvaluator, AuthorizationRequest, ResourcePolicyDecision,
    ResourcePolicyError, ResourcePolicyEvaluationRequest, S3PutPresignRequest,
    ServiceRoleAuthorizationRequest, ServiceRoleCredentials, SigningCredentials,
};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::config::IamCredentials;
#[cfg(test)]
use crate::config::{root_from_lookup, validate_root_collision};
pub use crate::config::{BootstrapCredentials, BootstrapError};
use crate::enforcement::{EnforcementFilter, EnforcementMode};
use crate::error::IamStsError;
use crate::iam::{self, Entity, OpResult};
use crate::policy::service_trust_allows;
use crate::query::{response_envelope, QueryRequest, IAM_XMLNS, STS_XMLNS};
use crate::store::{AccountRoot, IamStore, TagTarget};
use crate::sts::{self, SessionStore};
use crate::{
    arn::build_iam_arn,
    ids,
    model::{now_iso8601, AccessKey, IamUser},
};
use locallycloud_core::integration::RequestIdentity;

/// State shared by the IAM and STS handlers.
struct IamStsState {
    store: Arc<IamStore>,
    sessions: Arc<SessionStore>,
    enforcement: EnforcementFilter,
    mode: EnforcementMode,
}

fn pass_role_context(request: &ServiceRoleAuthorizationRequest) -> BTreeMap<String, Vec<String>> {
    let mut context = BTreeMap::new();
    for (key, values) in &request.caller_context {
        let [value] = values.as_slice() else {
            continue;
        };
        let key = key.to_ascii_lowercase();
        let value = match key.as_str() {
            "aws:requestedregion" if !value.is_empty() => value.clone(),
            "aws:securetransport" if matches!(value.as_str(), "true" | "false") => value.clone(),
            "aws:sourceip" => match value.parse::<std::net::IpAddr>() {
                Ok(address) => address.to_string(),
                Err(_) => continue,
            },
            _ => continue,
        };
        context.insert(key, vec![value]);
    }
    context.insert(
        "iam:passedtoservice".into(),
        vec![request.service_principal.clone()],
    );
    context
}

impl IamStsState {
    #[cfg(test)]
    fn new(store: Arc<IamStore>, sessions: Arc<SessionStore>) -> Self {
        Self::with_mode(store, sessions, EnforcementMode::default())
    }

    fn with_mode(store: Arc<IamStore>, sessions: Arc<SessionStore>, mode: EnforcementMode) -> Self {
        let enforcement = EnforcementFilter::new(store.clone(), sessions.clone());
        IamStsState {
            store,
            sessions,
            enforcement,
            mode,
        }
    }

    fn root_caller(&self, identity: &RequestIdentity) -> bool {
        let Some(key) = identity.access_key_id.as_deref() else {
            return false;
        };
        if self.store.root_for_key(&identity.account_id, key).is_some() {
            return true;
        }
        self.sessions.resolve(key).is_some_and(|session| {
            session.root_provenance(&identity.account_id, &self.store) == Ok(true)
        })
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
        let mut context = BTreeMap::new();
        if let Some(source) = &request.source_arn {
            let parts: Vec<_> = source.splitn(6, ':').collect();
            let (expected_service, resource_prefix) = match request.service_principal.as_str() {
                "states.amazonaws.com" => ("states", "stateMachine:"),
                "events.amazonaws.com" => ("events", "rule/"),
                "pipes.amazonaws.com" => ("pipes", "pipe/"),
                "scheduler.amazonaws.com" => ("scheduler", "schedule-group/"),
                "apigateway.amazonaws.com" => ("execute-api", ""),
                "cloudformation.amazonaws.com" => ("cloudformation", "stack/"),
                _ => return Err(AuthorizationError::InvalidRequest),
            };
            if parts.len() != 6
                || parts[0] != "arn"
                || parts[1] != "aws"
                || parts[2] != expected_service
                || parts[4] != account
                || parts[3].is_empty()
                || !parts[5].starts_with(resource_prefix)
                || parts[5].len() == resource_prefix.len()
                || (expected_service == "execute-api"
                    && (parts[5].split('/').count() < 3 || parts[5].starts_with('/')))
            {
                return Err(AuthorizationError::InvalidRequest);
            }
            context.insert("aws:sourcearn".into(), vec![source.clone()]);
            context.insert("aws:sourceaccount".into(), vec![account.clone()]);
        }
        crate::enforcement::apply_time_attributes(&mut context);
        if !service_trust_allows(
            &role.assume_role_policy_document,
            &request.service_principal,
            &request.role_arn,
            &context,
        ) {
            return Err(AuthorizationError::Denied);
        }
        Ok(())
    }

    fn authorize_assume_role(
        &self,
        request: &ServiceRequest,
        query: &QueryRequest,
    ) -> Result<(), IamStsError> {
        use crate::policy::{evaluate, Decision, EvalRequest, PolicyDocument};
        if self.mode == EnforcementMode::Permissive {
            return Ok(());
        }
        if [
            "Tags",
            "TransitiveTagKeys",
            "SourceIdentity",
            "ProvidedContexts",
        ]
        .iter()
        .any(|prefix| query.has_parameter_prefix(prefix))
        {
            return Err(IamStsError::ValidationError(
                "Session tags, source identity and trusted context assertions are not supported"
                    .into(),
            ));
        }
        let denied =
            || IamStsError::AccessDenied("The caller is not trusted to assume this role".into());
        let identity = RequestIdentity {
            account_id: request.account_id.clone(),
            access_key_id: access_key_id_from_auth(request),
            arn: None,
        };
        let key = identity.access_key_id.as_deref().ok_or_else(denied)?;
        // User/federated sessions currently lack inherited user policy context.
        if !self.root_caller(&identity)
            && self
                .sessions
                .resolve(key)
                .is_some_and(|session| session.role_arn.is_none())
        {
            return Err(denied());
        }
        let role = sts::resolve_role(&self.store, &request.account_id, query.require("RoleArn")?)?;
        let caller = self.enforcement.resolve_caller(&request.account_id, key)?;
        let principal = caller
            .attribute("aws:principalarn")
            .ok_or_else(denied)?
            .to_owned();
        if query.get("SerialNumber").is_some() || query.get("TokenCode").is_some() {
            return Err(IamStsError::AccessDenied(
                "MFA assertions are not verified by this emulator".into(),
            ));
        }
        let mut context = BTreeMap::from([
            ("aws:principalarn".into(), vec![principal.clone()]),
            (
                "aws:principalaccount".into(),
                vec![request.account_id.clone()],
            ),
            ("aws:requestedregion".into(), vec![request.region.clone()]),
            (
                "sts:rolesessionname".into(),
                vec![query.require("RoleSessionName")?.into()],
            ),
        ]);
        let principal_type = if self.root_caller(&identity) {
            "Account"
        } else if principal.contains(":role/") {
            "AssumedRole"
        } else {
            "User"
        };
        context.insert("aws:principaltype".into(), vec![principal_type.into()]);
        context.insert("aws:principalisawsservice".into(), vec!["false".into()]);
        context.extend(
            locallycloud_core::integration::request_context::verified_request_context(request),
        );
        if let Some(external_id) = query.get("ExternalId") {
            context.insert("sts:externalid".into(), vec![external_id.into()]);
        }
        caller.apply_attributes(&mut context);
        let evaluation = EvalRequest {
            action: "sts:AssumeRole".into(),
            resource: role.arn,
            context,
        };
        let mut trusted = false;
        let mut direct = false;
        for item in crate::resource_policy::parse_trust(&role.assume_role_policy_document)
            .map_err(|_| denied())?
        {
            let Some(grant) = item.principal_match(&request.account_id, Some(&principal), None)
            else {
                continue;
            };
            match evaluate(
                &[PolicyDocument {
                    statements: vec![item.statement],
                }],
                None,
                None,
                &evaluation,
            ) {
                Decision::ExplicitDeny => return Err(denied()),
                Decision::Allowed => {
                    trusted = true;
                    direct |= grant;
                }
                Decision::ImplicitDeny => {}
            }
        }
        let decision = evaluate(
            &caller.identity,
            caller.boundary.as_deref(),
            caller.session.as_deref(),
            &evaluation,
        );
        if !trusted || decision == Decision::ExplicitDeny {
            return Err(denied());
        }
        let limits_allow = caller.boundary.as_ref().is_none_or(|policies| {
            evaluate(policies, None, None, &evaluation) == Decision::Allowed
        }) && caller.session.as_ref().is_none_or(|policies| {
            evaluate(policies, None, None, &evaluation) == Decision::Allowed
        });
        if decision == Decision::Allowed
            || (direct && (principal.contains(":user/") || limits_allow))
        {
            Ok(())
        } else {
            Err(denied())
        }
    }

    /// Resolve the caller identity from the request and apply strict-mode enforcement.
    /// `service` is the IAM-style prefix (`iam`/`sts`); the action gates the request.
    fn enforce(
        &self,
        request: &ServiceRequest,
        service: &str,
        action: &str,
        resource: &str,
    ) -> Result<(), IamStsError> {
        self.enforce_with_context(
            request,
            service,
            action,
            resource,
            locallycloud_core::integration::request_context::verified_request_context(request),
        )
    }

    fn enforce_with_context(
        &self,
        request: &ServiceRequest,
        service: &str,
        action: &str,
        resource: &str,
        context: BTreeMap<String, Vec<String>>,
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
        // GetSessionToken authenticates long-term credentials; IAM policies cannot deny issuance.
        if self.mode == EnforcementMode::Strict && service == "sts" && action == "GetSessionToken" {
            if identity
                .access_key_id
                .as_deref()
                .is_some_and(|key| self.sessions.resolve(key).is_some())
            {
                return Err(IamStsError::AccessDenied(
                    "GetSessionToken requires long-term credentials".into(),
                ));
            }
            return match self.resolve_caller_arn(&identity) {
                Ok(Some(_)) => Ok(()),
                _ => Err(IamStsError::AccessDenied(
                    "request has no active issuer identity".into(),
                )),
            };
        }
        // STS GetCallerIdentity requires valid credentials, but no IAM permission,
        // even when an identity policy explicitly denies this action.
        if self.mode == EnforcementMode::Strict && service == "sts" && action == "GetCallerIdentity"
        {
            return match self.resolve_caller_arn(&identity) {
                Ok(Some(_)) => Ok(()),
                _ => Err(IamStsError::AccessDenied(
                    "request has no active caller identity".into(),
                )),
            };
        }
        let delegated = if self.mode == EnforcementMode::Strict && service == "iam" {
            locallycloud_core::integration::identity::trusted_role(request)
        } else {
            None
        };
        let result = match delegated {
            Some(role) => self
                .authorize(AuthorizationRequest {
                    request_identity: RequestIdentity {
                        account_id: request.account_id.clone(),
                        access_key_id: None,
                        arn: None,
                    },
                    delegated_identity: Some(role),
                    source_service: service.into(),
                    action: format!("{service}:{action}"),
                    resource: resource.into(),
                    context,
                })
                .map_err(|_| {
                    IamStsError::AccessDenied(format!(
                        "service role is not authorized for {service}:{action} on {resource}"
                    ))
                }),
            None => self.enforcement.check_with_context(
                self.mode,
                &identity,
                &format!("{service}:{action}"),
                resource,
                &context,
            ),
        };
        result
    }
}

impl IamStsState {
    fn signing_credentials(&self, account: &str, access_key: &str) -> Option<SigningCredentials> {
        if let Some(root) = self.store.root_for_key(account, access_key) {
            return Some(SigningCredentials {
                secret_access_key: root.secret_access_key,
                session_token: None,
            });
        }

        if let Some(session) = self.sessions.resolve(access_key) {
            session.root_provenance(account, &self.store).ok()?;
            return (session.account == account).then_some(SigningCredentials {
                secret_access_key: session.secret_access_key,
                session_token: Some(session.session_token),
            });
        }
        self.store
            .user_for_key(account, access_key)
            .and_then(|user| {
                user.access_keys.into_iter().find_map(|key| {
                    (key.access_key_id == access_key && key.status == "Active").then_some(
                        SigningCredentials {
                            secret_access_key: key.secret_access_key,
                            session_token: None,
                        },
                    )
                })
            })
    }
}

impl AuthorizationEvaluator for IamStsState {
    fn presign_s3_put(&self, request: S3PutPresignRequest) -> Result<String, AuthorizationError> {
        if self.credential_account(&request.access_key)?.as_deref() != Some(&request.account) {
            return Err(AuthorizationError::Denied);
        }
        let credentials = self
            .signing_credentials(&request.account, &request.access_key)
            .ok_or(AuthorizationError::Denied)?;
        locallycloud_core::integration::sigv4::presign_s3_put(
            &request.endpoint,
            &request.path,
            &request.region,
            &request.access_key,
            &credentials,
            request.expires,
        )
        .ok_or(AuthorizationError::InvalidRequest)
    }
    fn credential_account(
        &self,
        access_key_id: &str,
    ) -> Result<Option<String>, AuthorizationError> {
        let mut accounts = self.store.active_key_accounts(access_key_id);
        if let Some(account) = self.store.root_account_for_key(access_key_id) {
            accounts.push(account);
        }
        if let Some(session) = self.sessions.resolve(access_key_id) {
            session
                .root_provenance(&session.account, &self.store)
                .map_err(|_| AuthorizationError::Denied)?;
            accounts.push(session.account);
        }
        match accounts.len() {
            0 => Ok(None),
            1 => Ok(accounts.pop()),
            _ => Err(AuthorizationError::Denied),
        }
    }

    fn is_account_root(&self, identity: &RequestIdentity) -> Result<bool, AuthorizationError> {
        Ok(self.root_caller(identity))
    }

    fn validate_resource_policy(&self, document: &str) -> Result<(), ResourcePolicyError> {
        crate::resource_policy::parse(document).map(|_| ())
    }

    fn evaluate_anonymous_resource_policy(
        &self,
        mut request: ResourcePolicyEvaluationRequest,
        document: &str,
    ) -> Result<ResourcePolicyDecision, ResourcePolicyError> {
        use crate::policy::{evaluate, Decision, EvalRequest, PolicyDocument};
        if request.action.is_empty() || request.resource.is_empty() {
            return Err(ResourcePolicyError::Malformed(
                "resource policy evaluation requires an action and resource".into(),
            ));
        }
        let statements = crate::resource_policy::parse(document)?
            .into_iter()
            .filter(|statement| statement.principal_match("", None, None).is_some())
            .map(|statement| statement.statement)
            .collect();
        crate::enforcement::strip_principal_attributes(&mut request.context);
        request.context.retain(|key, _| {
            !matches!(
                key.to_ascii_lowercase().as_str(),
                "aws:username"
                    | "aws:multifactorauthage"
                    | "aws:tokenissuetime"
                    | "aws:sourceidentity"
                    | "aws:sourcearn"
                    | "aws:sourceaccount"
            )
        });
        crate::enforcement::apply_time_attributes(&mut request.context);
        request
            .context
            .insert("aws:principalaccount".into(), vec!["anonymous".into()]);
        request
            .context
            .insert("aws:principaltype".into(), vec!["Anonymous".into()]);
        request
            .context
            .insert("aws:userid".into(), vec!["anonymous".into()]);
        let evaluation = EvalRequest {
            action: request.action,
            resource: request.resource,
            context: request.context,
        };
        Ok(
            match evaluate(&[PolicyDocument { statements }], None, None, &evaluation) {
                Decision::Allowed => ResourcePolicyDecision::Allow,
                Decision::ExplicitDeny => ResourcePolicyDecision::ExplicitDeny,
                Decision::ImplicitDeny => ResourcePolicyDecision::ImplicitDeny,
            },
        )
    }

    fn evaluate_endpoint_policy(
        &self,
        mut request: ResourcePolicyEvaluationRequest,
        identity: Option<RequestIdentity>,
        document: &str,
    ) -> Result<ResourcePolicyDecision, AuthorizationError> {
        use crate::policy::{evaluate, Decision, EvalRequest, PolicyDocument};
        let Some(identity) = identity else {
            return self
                .evaluate_anonymous_resource_policy(request, document)
                .map_err(|_| AuthorizationError::Denied);
        };
        if request.action.is_empty() || request.resource.is_empty() {
            return Err(AuthorizationError::InvalidRequest);
        }
        let key = identity
            .access_key_id
            .as_deref()
            .ok_or(AuthorizationError::Denied)?;
        let caller = self
            .enforcement
            .resolve_caller(&identity.account_id, key)
            .map_err(|_| AuthorizationError::Denied)?;
        let arn = caller
            .attribute("aws:principalarn")
            .ok_or(AuthorizationError::Denied)?;
        let statements = crate::resource_policy::parse(document)
            .map_err(|_| AuthorizationError::Denied)?
            .into_iter()
            .filter(|statement| {
                statement
                    .principal_match(&identity.account_id, Some(arn), None)
                    .is_some()
            })
            .map(|statement| statement.statement)
            .collect();
        // The endpoint is an independent resource-policy gate, never an identity-policy union.
        caller.apply_attributes(&mut request.context);
        let evaluation = EvalRequest {
            action: request.action,
            resource: request.resource,
            context: request.context,
        };
        Ok(
            match evaluate(&[PolicyDocument { statements }], None, None, &evaluation) {
                Decision::Allowed => ResourcePolicyDecision::Allow,
                Decision::ExplicitDeny => ResourcePolicyDecision::ExplicitDeny,
                Decision::ImplicitDeny => ResourcePolicyDecision::ImplicitDeny,
            },
        )
    }

    fn authorize_resource_policy(
        &self,
        mut request: AuthorizationRequest,
        document: Option<&str>,
        owner_account: &str,
    ) -> Result<(), AuthorizationError> {
        use crate::policy::{evaluate, Decision, EvalRequest, PolicyDocument};
        use locallycloud_core::integration::identity::CallerIdentity;
        if request.action.is_empty() || request.resource.is_empty() || owner_account.is_empty() {
            return Err(AuthorizationError::InvalidRequest);
        }
        crate::enforcement::strip_principal_attributes(&mut request.context);
        let account = request.request_identity.account_id.clone();
        let (arn, service, caller, principal_type) = match &request.delegated_identity {
            Some(CallerIdentity::AssumedRole {
                role_arn,
                session_name,
            }) => (
                Some(role_arn.clone()),
                None,
                Some(
                    self.enforcement
                        .role_session_context(&account, role_arn, session_name)
                        .map_err(|_| AuthorizationError::Denied)?,
                ),
                "AssumedRole",
            ),
            Some(CallerIdentity::ServicePrincipal { service }) => (
                None,
                Some(if service.ends_with(".amazonaws.com") {
                    service.clone()
                } else {
                    format!("{service}.amazonaws.com")
                }),
                None,
                "AWSService",
            ),
            Some(CallerIdentity::Default) => return Err(AuthorizationError::Denied),
            None => match request.request_identity.access_key_id.as_deref() {
                Some(key) => {
                    // The current session engine has no inherited user context for these
                    // sessions; accepting direct grants could hide a user's explicit Deny.
                    if !self.root_caller(&request.request_identity)
                        && self
                            .sessions
                            .resolve(key)
                            .is_some_and(|session| session.role_arn.is_none())
                    {
                        return Err(AuthorizationError::Denied);
                    }
                    let caller = self
                        .enforcement
                        .resolve_caller(&account, key)
                        .map_err(|_| AuthorizationError::Denied)?;
                    let arn = caller
                        .attribute("aws:principalarn")
                        .ok_or(AuthorizationError::Denied)?
                        .to_owned();
                    let kind = if caller.attribute("aws:principaltype") == Some("Account") {
                        "Account"
                    } else if caller.attribute("aws:principaltype") == Some("AssumedRole") {
                        "AssumedRole"
                    } else {
                        "User"
                    };
                    (Some(arn), None, Some(caller), kind)
                }
                None => (None, None, None, "Anonymous"),
            },
        };
        if let Some(arn) = &arn {
            request
                .context
                .insert("aws:principalarn".into(), vec![arn.clone()]);
            request
                .context
                .insert("aws:principalaccount".into(), vec![account.clone()]);
        }
        request
            .context
            .insert("aws:principaltype".into(), vec![principal_type.into()]);
        request.context.insert(
            "aws:principalisawsservice".into(),
            vec![service.is_some().to_string()],
        );
        if let Some(caller) = &caller {
            caller.apply_attributes(&mut request.context);
        } else {
            crate::enforcement::apply_time_attributes(&mut request.context);
        }
        let evaluation = EvalRequest {
            action: request.action,
            resource: request.resource,
            context: request.context,
        };
        let mut resource_allow = false;
        let mut direct_allow = false;
        let mut principal_arn_session_allow = false;
        if let Some(document) = document {
            for item in
                crate::resource_policy::parse(document).map_err(|_| AuthorizationError::Denied)?
            {
                let Some(direct) =
                    item.principal_match(&account, arn.as_deref(), service.as_deref())
                else {
                    continue;
                };
                let grants_session = item.grants_principal_arn_session();
                match evaluate(
                    &[PolicyDocument {
                        statements: vec![item.statement],
                    }],
                    None,
                    None,
                    &evaluation,
                ) {
                    Decision::ExplicitDeny => return Err(AuthorizationError::Denied),
                    Decision::Allowed => {
                        resource_allow = true;
                        direct_allow |= direct;
                        principal_arn_session_allow |= grants_session;
                    }
                    Decision::ImplicitDeny => {}
                }
            }
        }
        let (identity_allow, limits_allow) = match caller {
            Some(caller) => {
                let decision = evaluate(
                    &caller.identity,
                    caller.boundary.as_deref(),
                    caller.session.as_deref(),
                    &evaluation,
                );
                if decision == Decision::ExplicitDeny {
                    return Err(AuthorizationError::Denied);
                }
                let limits_allow = caller.boundary.as_ref().is_none_or(|policies| {
                    evaluate(policies, None, None, &evaluation) == Decision::Allowed
                }) && caller.session.as_ref().is_none_or(|policies| {
                    evaluate(policies, None, None, &evaluation) == Decision::Allowed
                });
                (decision == Decision::Allowed, limits_allow)
            }
            None => (false, true),
        };
        let same_account = arn.is_some() && account == owner_account;
        let allowed = if service.is_some() || arn.is_none() {
            resource_allow
        } else if same_account {
            identity_allow
                || principal_arn_session_allow
                || (direct_allow && (principal_type == "User" || limits_allow))
        } else {
            identity_allow && resource_allow
        };
        if allowed {
            Ok(())
        } else {
            Err(AuthorizationError::Denied)
        }
    }

    fn issue_service_role_credentials(
        &self,
        account: &str,
        role_arn: &str,
        service_principal: &str,
    ) -> Result<ServiceRoleCredentials, AuthorizationError> {
        self.validate_service_role(&ServiceRoleAuthorizationRequest {
            delegated_caller: None,
            caller_context: Default::default(),
            source_arn: None,
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
            expiration: creds.expiration,
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
        locallycloud_core::integration::sigv4::verify(
            method,
            uri,
            headers,
            body,
            region,
            service,
            |access_key| self.signing_credentials(account, access_key),
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
        if self.mode == EnforcementMode::Strict && request.delegated_identity.is_some() {
            return if self.identity_policy_allows(request) {
                Ok(())
            } else {
                Err(AuthorizationError::Denied)
            };
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
        self.authorize(AuthorizationRequest {
            request_identity: request.caller.clone(),
            delegated_identity: request.delegated_caller.clone(),
            source_service: "iam".into(),
            action: "iam:PassRole".into(),
            resource: request.role_arn.clone(),
            context: pass_role_context(&request),
        })?;
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
        self.authorize(AuthorizationRequest {
            request_identity: request.caller.clone(),
            delegated_identity: request.delegated_caller.clone(),
            source_service: "iam".into(),
            action: "iam:PassRole".into(),
            resource: request.role_arn.clone(),
            context: pass_role_context(&request),
        })
    }

    fn authorize_service_role_trust(
        &self,
        request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), AuthorizationError> {
        self.validate_service_role(&request)
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

    fn resolve_caller_metadata(
        &self,
        identity: &RequestIdentity,
    ) -> Result<
        Option<locallycloud_core::integration::authorization::CallerMetadata>,
        AuthorizationError,
    > {
        use locallycloud_core::integration::authorization::CallerMetadata;
        let Some(key) = identity.access_key_id.as_deref() else {
            return Ok(None);
        };
        if let Some(root) = self.store.root_for_key(&identity.account_id, key) {
            return Ok(Some(CallerMetadata {
                account_id: root.account.clone(),
                arn: root.arn(),
                user_id: root.account,
            }));
        }
        if let Some(session) = self.sessions.resolve(key) {
            session
                .root_provenance(&identity.account_id, &self.store)
                .map_err(|_| AuthorizationError::Denied)?;
            if session.account != identity.account_id {
                return Err(AuthorizationError::Denied);
            }
            return Ok(Some(CallerMetadata {
                account_id: session.account,
                arn: session.arn,
                user_id: session.user_id,
            }));
        }
        Ok(self
            .store
            .user_for_key(&identity.account_id, key)
            .map(|user| CallerMetadata {
                account_id: identity.account_id.clone(),
                arn: user.arn,
                user_id: user.user_id,
            }))
    }

    fn resolve_caller_arn(
        &self,
        identity: &RequestIdentity,
    ) -> Result<Option<String>, AuthorizationError> {
        let Some(access_key_id) = identity.access_key_id.as_deref() else {
            return Ok(None);
        };
        if let Some(root) = self.store.root_for_key(&identity.account_id, access_key_id) {
            return Ok(Some(root.arn()));
        }
        if let Some(session) = self.sessions.resolve(access_key_id) {
            session
                .root_provenance(&identity.account_id, &self.store)
                .map_err(|_| AuthorizationError::Denied)?;
            return if session.account == identity.account_id {
                Ok(Some(session.role_arn.unwrap_or(session.arn)))
            } else {
                Err(AuthorizationError::Denied)
            };
        }
        Ok(self
            .store
            .user_for_key(&identity.account_id, access_key_id)
            .map(|user| user.arn))
    }

    fn identity_policy_denies(&self, request: AuthorizationRequest) -> bool {
        if let Some(locallycloud_core::integration::identity::CallerIdentity::AssumedRole {
            role_arn,
            session_name,
        }) = request.delegated_identity
        {
            return self
                .enforcement
                .role_session_context(
                    &request.request_identity.account_id,
                    &role_arn,
                    &session_name,
                )
                .map_or(true, |caller| {
                    caller.denies(&request.action, &request.resource, &request.context)
                });
        }
        if self.mode == EnforcementMode::Permissive
            && matches!(self.resolve_caller_arn(&request.request_identity), Ok(None))
        {
            return false;
        }
        self.enforcement.identity_policy_denies(
            &request.request_identity,
            &request.action,
            &request.resource,
            &request.context,
        )
    }

    fn identity_policy_allows(&self, request: AuthorizationRequest) -> bool {
        if let Some(locallycloud_core::integration::identity::CallerIdentity::AssumedRole {
            role_arn,
            session_name,
        }) = request.delegated_identity
        {
            return self
                .enforcement
                .role_session_context(
                    &request.request_identity.account_id,
                    &role_arn,
                    &session_name,
                )
                .is_ok_and(|caller| {
                    caller.allows(&request.action, &request.resource, &request.context)
                });
        }
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
    async fn has_global_resources(&self, account: &str) -> Result<bool, &'static str> {
        Ok(self.state.store.has_resources(account))
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let mut q = QueryRequest::parse(&request.body);
        let action = match q.action() {
            Some(a) => a.to_string(),
            None => {
                return IamStsError::MissingAction("Action is required".into())
                    .into_response(&request.request_id, IAM_XMLNS)
            }
        };
        self.state.default_iam_user(&request, &action, &mut q);
        if let Err(error) = self.state.authorize_iam(&request, &action, &q) {
            return error.into_response(&request.request_id, IAM_XMLNS);
        }
        let result = if action.starts_with("Get")
            || action.starts_with("List")
            || action.starts_with("Simulate")
        {
            dispatch_iam(&self.state, &request.account_id, &action, &q)
        } else {
            let store = self.state.store.clone();
            let account = request.account_id.clone();
            let operation = action.clone();
            let state = self.state.clone();
            let authorization_request = request.clone();
            tokio::task::spawn_blocking(move || {
                let target = match operation.as_str() {
                    "TagUser" | "UntagUser" => Some(TagTarget::User(q.require("UserName")?.into())),
                    "TagRole" | "UntagRole" => Some(TagTarget::Role(q.require("RoleName")?.into())),
                    _ => None,
                };
                let apply = |staged: &IamStore| {
                    // Evaluate the complete committed store while its mutation gate is held.
                    state.authorize_iam(&authorization_request, &operation, &q)?;
                    dispatch_iam_store(staged, &account, &operation, &q)
                };
                match target {
                    Some(target) => store.transact_tags(&account, target, apply),
                    None => store.transact(apply),
                }
            })
            .await
            .unwrap_or_else(|_| {
                Err(crate::persistence::state_error(
                    "IAM mutation worker failed",
                ))
            })
        };
        match result {
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
                return IamStsError::MissingAction("Action is required".into())
                    .into_response(&request.request_id, STS_XMLNS)
            }
        };
        let caller_key = access_key_id_from_auth(&request);
        let authorization = match action.as_str() {
            "GetSessionToken" if self.state.mode == EnforcementMode::Strict
                && (q.get("SerialNumber").is_some() || q.get("TokenCode").is_some()) => {
                Err(IamStsError::AccessDenied("MFA assertions are not verified by this emulator".into()))
            }
            "AssumeRole" => self.state.authorize_assume_role(&request, &q),
            "AssumeRoleWithWebIdentity" | "AssumeRoleWithSAML"
                if self.state.mode == EnforcementMode::Strict =>
            {
                Err(IamStsError::AccessDenied("Federated STS credentials require verified identity-provider assertions, which are not supported".into()))
            }
            _ => self.state.enforce(&request, "sts", &action, "*"),
        };
        if let Err(e) = authorization {
            return e.into_response(&request.request_id, STS_XMLNS);
        }
        let state = self.state.clone();
        let account = request.account_id.clone();
        let operation = action.clone();
        let result = tokio::task::spawn_blocking(move || {
            dispatch_sts(&state, &account, &operation, &q, caller_key.as_deref())
        })
        .await
        .unwrap_or_else(|_| Err(crate::persistence::state_error("STS worker failed")));
        match result {
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
    dispatch_iam_store(&state.store, account, action, q)
}

fn dispatch_iam_store(store: &IamStore, account: &str, action: &str, q: &QueryRequest) -> OpResult {
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
        "TagInstanceProfile" => iam::tag_instance_profile(store, account, q),
        "UntagInstanceProfile" => iam::untag_instance_profile(store, account, q),
        "ListInstanceProfileTags" => iam::list_instance_profile_tags(store, account, q),
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
        "AssumeRole" => sts::assume_role_for_caller(
            store,
            sessions,
            account,
            q,
            caller_key
                .and_then(|key| sessions.resolve(key))
                .is_some_and(|session| session.role_arn.is_some()),
        ),
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
            if let Some(root) = caller_key.and_then(|key| store.root_for_key(account, key)) {
                return Ok(sts::get_caller_identity(&root.account, None));
            }
            if let Some(user) = caller_key.and_then(|key| store.user_for_key(account, key)) {
                return Ok(sts::get_iam_caller_identity(account, &user));
            }
            // Permissive local mode has always returned root for an unresolved caller.
            // Strict mode already rejects missing/inactive keys in `enforce` above.
            Ok(sts::get_caller_identity(account, None))
        }
        "GetSessionToken" => {
            if let Some(key) = caller_key {
                if sessions.resolve(key).is_some() {
                    return Err(IamStsError::AccessDenied(
                        "GetSessionToken requires long-term credentials".into(),
                    ));
                }
                if let Some(root) = store.root_for_key(account, key) {
                    return sts::get_session_token_for_issuer(
                        sessions,
                        account,
                        q,
                        &root.arn(),
                        account,
                        true,
                    );
                }
                if let Some(user) = store.user_for_key(account, key) {
                    return sts::get_session_token_for_issuer(
                        sessions,
                        account,
                        q,
                        &user.arn,
                        &user.user_id,
                        false,
                    );
                }
            }
            if state.mode == EnforcementMode::Strict {
                return Err(IamStsError::AccessDenied(
                    "request has no active issuer identity".into(),
                ));
            }
            sts::get_session_token(sessions, account, q)
        }
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

fn seed_bootstrap_user(store: &IamStore, account: &str, credentials: BootstrapCredentials) {
    let name = "locallycloud-bootstrap";
    let mut inline_policies = BTreeMap::new();
    inline_policies.insert(
        "LocallyCloudBootstrapAdministrator".to_string(),
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

fn seed_durable_bootstrap(store: &IamStore, account: &str, credentials: BootstrapCredentials) {
    if !store.bootstrap_initialized(account) {
        seed_bootstrap_user(store, account, credentials);
        store.mark_bootstrap_initialized(account);
    }
}

/// Register IAM and STS for the configured account. Validate bootstrap before publishing
/// either service, so strict mode never starts with an unreachable control plane.
pub fn register_with_account(
    registry: &ServiceRegistry,
    account: &str,
) -> Result<(), BootstrapError> {
    register_with_account_and_config(registry, account, crate::config::IamConfig::from_env()?)
}

/// Register in-memory handlers with an explicitly resolved startup configuration.
pub fn register_with_account_and_config(
    registry: &ServiceRegistry,
    account: &str,
    config: crate::config::IamConfig,
) -> Result<(), BootstrapError> {
    let credentials = IamCredentials::from_lookup(account, config, |name| std::env::var_os(name))?;
    register_with_account_and_inputs(registry, account, config, credentials)
}

/// Register without consulting the process environment for credentials.
pub fn register_with_account_and_inputs(
    registry: &ServiceRegistry,
    account: &str,
    config: crate::config::IamConfig,
    credentials: IamCredentials,
) -> Result<(), BootstrapError> {
    credentials.validate(account, config)?;
    register_inner(
        registry,
        account,
        credentials.bootstrap,
        credentials.root,
        config.enforcement,
    )
}

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error(transparent)]
    Configuration(#[from] crate::config::IamConfigError),
    #[error(transparent)]
    Bootstrap(#[from] BootstrapError),
    #[error(transparent)]
    State(#[from] IamStsError),
}

pub fn register_with_state(
    registry: &ServiceRegistry,
    account: &str,
    db: Arc<locallycloud_state::StateDb>,
) -> Result<(), RegistrationError> {
    register_with_state_and_config(registry, account, db, crate::config::IamConfig::from_env()?)
}

/// Register with one validated mode used for bootstrap validation and both published handlers.
pub fn register_with_state_and_config(
    registry: &ServiceRegistry,
    account: &str,
    db: Arc<locallycloud_state::StateDb>,
    config: crate::config::IamConfig,
) -> Result<(), RegistrationError> {
    let credentials = IamCredentials::from_lookup(account, config, |name| std::env::var_os(name))?;
    register_with_state_and_inputs(registry, account, db, config, credentials)
}

/// Register durable handlers using the credentials resolved by the composition root.
pub fn register_with_state_and_inputs(
    registry: &ServiceRegistry,
    account: &str,
    db: Arc<locallycloud_state::StateDb>,
    config: crate::config::IamConfig,
    credentials: IamCredentials,
) -> Result<(), RegistrationError> {
    credentials.validate(account, config)?;
    let IamCredentials {
        bootstrap: credentials,
        root,
        ..
    } = credentials;
    let persistence = Arc::new(crate::persistence::IamPersistence::new(db)?);
    let store = Arc::new(IamStore::durable(persistence.clone())?);
    let sessions = Arc::new(SessionStore::durable(persistence)?);
    if let Some(root) = root {
        store
            .provision_root(root)
            .map_err(|_| BootstrapError::RootCredentialCollision)?;
    }
    store.transact(|staged| {
        iam::seed_aws_managed_policies(staged);
        if let Some(credentials) = credentials {
            seed_durable_bootstrap(staged, account, credentials);
        }
        Ok(())
    })?;
    register_with_store_and_mode(registry, store, sessions, config.enforcement);
    Ok(())
}

/// Compatibility registration for standalone permissive tests.
pub fn register(registry: &ServiceRegistry) {
    register_inner(
        registry,
        "000000000000",
        None,
        None,
        EnforcementMode::Permissive,
    )
    .expect("standalone registration has no credentials");
}

fn register_inner(
    registry: &ServiceRegistry,
    account: &str,
    credentials: Option<BootstrapCredentials>,
    root: Option<AccountRoot>,
    mode: EnforcementMode,
) -> Result<(), BootstrapError> {
    let store = Arc::new(IamStore::new());
    iam::seed_aws_managed_policies(&store);
    if let Some(credentials) = credentials {
        seed_bootstrap_user(&store, account, credentials);
    }
    if let Some(root) = root {
        store
            .provision_root(root)
            .map_err(|_| BootstrapError::RootCredentialCollision)?;
    }
    register_with_store_and_mode(registry, store, Arc::new(SessionStore::new()), mode);
    Ok(())
}

/// Publish explicitly provisioned IAM/STS stores with an injected enforcement mode.
/// This performs no environment lookup or bootstrap provisioning.
pub fn register_with_store_and_mode(
    registry: &ServiceRegistry,
    store: Arc<IamStore>,
    sessions: Arc<SessionStore>,
    mode: EnforcementMode,
) {
    publish_state(
        registry,
        Arc::new(IamStsState::with_mode(store, sessions, mode)),
    );
}

fn publish_state(registry: &ServiceRegistry, state: Arc<IamStsState>) {
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
    let mut sts_metadata = ServiceMetadata::new(AwsProtocol::Query, None);
    sts_metadata.known_actions = [
        "AssumeRole",
        "AssumeRoleWithWebIdentity",
        "AssumeRoleWithSAML",
        "GetCallerIdentity",
        "GetSessionToken",
        "GetFederationToken",
        "DecodeAuthorizationMessage",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    registry.register_native(ServiceName::new("sts"), sts_metadata, sts_handler);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, Method};

    #[test]
    fn role_operations_enforce_the_real_target_arn_and_path() {
        let state = IamStsState::with_mode(
            Arc::new(IamStore::new()),
            Arc::new(SessionStore::new()),
            EnforcementMode::Strict,
        );
        let account = "000000000000";
        let key = "AKIA1234567890123456";
        seed_bootstrap_user(
            &state.store,
            account,
            BootstrapCredentials {
                access_key_id: key.into(),
                secret_access_key: "a".repeat(40),
            },
        );
        state.store.update_user(account, "locallycloud-bootstrap", |user| {
            user.inline_policies.clear();
            user.inline_policies.insert("scoped-roles".into(), r#"{"Statement":{"Effect":"Allow","Action":["iam:CreateRole","iam:ListAttachedRolePolicies","iam:AttachRolePolicy"],"Resource":"arn:aws:iam::000000000000:role/team/*"}}"#.into());
        });
        let role = QueryRequest::parse(br#"RoleName=worker&Path=%2Fteam%2F&AssumeRolePolicyDocument={"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#);
        iam::create_role(&state.store, account, &role).unwrap();
        let mut req = request("Action=ListAttachedRolePolicies&RoleName=worker");
        req.headers.insert(
            http::header::AUTHORIZATION,
            format!("AWS4-HMAC-SHA256 Credential={key}/20260101/us-east-1/iam/aws4_request")
                .parse()
                .unwrap(),
        );
        for action in ["CreateRole", "ListAttachedRolePolicies", "AttachRolePolicy"] {
            let query = if action == "CreateRole" {
                role.clone()
            } else {
                QueryRequest::parse(b"RoleName=worker&Path=%2Fignored%2F")
            };
            let resource = state.iam_resource(account, action, &query).unwrap();
            assert_eq!(resource, "arn:aws:iam::000000000000:role/team/worker");
            assert!(state.enforce(&req, "iam", action, &resource).is_ok());
            assert!(state.enforce(&req, "iam", action, "*").is_err());
            assert!(state
                .enforce(&req, "iam", action, "arn:aws:iam::000000000000:role/other")
                .is_err());
        }
    }

    #[test]
    fn role_scoped_deny_is_enforced_for_an_administrator() {
        let state = IamStsState::with_mode(
            Arc::new(IamStore::new()),
            Arc::new(SessionStore::new()),
            EnforcementMode::Strict,
        );
        let account = "000000000000";
        let key = "AKIA1234567890123456";
        seed_bootstrap_user(
            &state.store,
            account,
            BootstrapCredentials {
                access_key_id: key.into(),
                secret_access_key: "a".repeat(40),
            },
        );
        state.store.update_user(account, "locallycloud-bootstrap", |user| {
            user.inline_policies.insert("protected-role".into(), r#"{"Statement":{"Effect":"Deny","Action":"iam:AttachRolePolicy","Resource":"arn:aws:iam::000000000000:role/protected"}}"#.into());
        });
        let mut req = request("Action=AttachRolePolicy&RoleName=protected");
        req.headers.insert(
            http::header::AUTHORIZATION,
            format!("AWS4-HMAC-SHA256 Credential={key}/20260101/us-east-1/iam/aws4_request")
                .parse()
                .unwrap(),
        );
        let resource = state
            .iam_resource(account, "AttachRolePolicy", &QueryRequest::parse(&req.body))
            .unwrap();
        assert!(state
            .enforce(&req, "iam", "AttachRolePolicy", &resource)
            .is_err());
        assert!(state
            .enforce(
                &req,
                "iam",
                "AttachRolePolicy",
                "arn:aws:iam::000000000000:role/other"
            )
            .is_ok());
    }

    #[test]
    fn registered_sts_actions_route_without_a_credential_scope() {
        let registry = ServiceRegistry::with_known_services();
        register(&registry);
        let input = locallycloud_core::router::RouteInput {
            authorization: None,
            x_amz_credential: None,
            x_amz_target: None,
            host: Some("localhost"),
            path: "/",
            body: b"Action=GetCallerIdentity&Version=2011-06-15",
        };
        assert_eq!(
            locallycloud_core::router::resolve(&registry, &input)
                .unwrap()
                .service_name,
            ServiceName::new("sts")
        );
        assert_eq!(
            registry.lookup_by_action("AssumeRole"),
            Some(ServiceName::new("sts"))
        );
    }

    fn root_fixture() -> (IamStsState, RequestIdentity) {
        let store = Arc::new(IamStore::new());
        store
            .provision_root(AccountRoot {
                account: "000000000000".into(),
                access_key_id: "AKIARRRRRRRRRRRRRRRR".into(),
                secret_access_key: "r".repeat(40),
            })
            .unwrap();
        let mut state = IamStsState::new(store, Arc::new(SessionStore::new()));
        state.mode = EnforcementMode::Strict;
        (
            state,
            RequestIdentity {
                account_id: "000000000000".into(),
                access_key_id: Some("AKIARRRRRRRRRRRRRRRR".into()),
                arn: None,
            },
        )
    }
    fn issued_key(xml: &str) -> &str {
        xml.split("<AccessKeyId>")
            .nth(1)
            .unwrap()
            .split("</AccessKeyId>")
            .next()
            .unwrap()
    }

    #[test]
    fn explicit_root_is_account_scoped_and_resource_denies_still_apply() {
        let (state, identity) = root_fixture();
        assert!(state.is_account_root(&identity).unwrap());
        assert_eq!(
            state.resolve_caller_arn(&identity).unwrap().as_deref(),
            Some("arn:aws:iam::000000000000:root")
        );
        let mut foreign = identity.clone();
        foreign.account_id = "111111111111".into();
        assert!(!state.is_account_root(&foreign).unwrap());
        let request = AuthorizationRequest {
            request_identity: identity,
            delegated_identity: None,
            source_service: "s3".into(),
            action: "s3:GetObject".into(),
            resource: "arn:aws:s3:::root-gate/key".into(),
            context: BTreeMap::new(),
        };
        assert!(state
            .authorize_resource_policy(request.clone(), None, "000000000000")
            .is_ok());
        assert_eq!(state.authorize_resource_policy(request, Some(r#"{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::root-gate/*"}}"#), "000000000000"), Err(AuthorizationError::Denied));
        assert!(state.store.list_users("000000000000").is_empty());
    }

    #[test]
    fn session_token_preserves_user_issuer_and_cannot_become_root() {
        let (state, _) = root_fixture();
        let key = "AKIAABCDEFGHIJKLMNOP";
        seed_bootstrap_user(
            &state.store,
            "000000000000",
            BootstrapCredentials {
                access_key_id: key.into(),
                secret_access_key: "a".repeat(40),
            },
        );
        state
            .store
            .update_user("000000000000", "locallycloud-bootstrap", |user| {
                user.inline_policies.clear();
                user.inline_policies.insert(
                    "deny-sts".into(),
                    r#"{"Statement":{"Effect":"Deny","Action":"sts:*","Resource":"*"}}"#.into(),
                );
            });
        let mut req = request("Action=GetSessionToken");
        req.headers.insert(
            http::header::AUTHORIZATION,
            format!("AWS4-HMAC-SHA256 Credential={key}/20260101/us-east-1/sts/aws4_request")
                .parse()
                .unwrap(),
        );
        assert!(state.enforce(&req, "sts", "GetSessionToken", "*").is_ok());
        let result = dispatch_sts(
            &state,
            "000000000000",
            "GetSessionToken",
            &QueryRequest::parse(b"Action=GetSessionToken"),
            Some(key),
        )
        .unwrap();
        let temporary = issued_key(&result);
        let session = state.sessions.resolve(temporary).unwrap();
        assert_eq!(
            session.arn,
            "arn:aws:iam::000000000000:user/locallycloud-bootstrap"
        );
        assert!(!session.root_account);
        let identity = RequestIdentity {
            account_id: "000000000000".into(),
            access_key_id: Some(temporary.into()),
            arn: Some("arn:aws:iam::000000000000:root".into()),
        };
        assert!(!state.is_account_root(&identity).unwrap());
        assert_eq!(
            state.resolve_caller_arn(&identity).unwrap(),
            Some(session.arn)
        );
        assert!(dispatch_sts(
            &state,
            "000000000000",
            "GetSessionToken",
            &QueryRequest::parse(b"Action=GetSessionToken"),
            Some(temporary)
        )
        .is_err());
    }

    #[test]
    fn root_session_has_explicit_provenance_but_legacy_root_arn_does_not() {
        let (state, root) = root_fixture();
        let result = dispatch_sts(
            &state,
            "000000000000",
            "GetSessionToken",
            &QueryRequest::parse(b"DurationSeconds=129600"),
            root.access_key_id.as_deref(),
        )
        .unwrap();
        let key = issued_key(&result);
        let session = state.sessions.resolve(key).unwrap();
        assert!(session.root_account);
        assert!((session.expires_at - time::OffsetDateTime::now_utc()).whole_seconds() <= 3600);
        let identity = RequestIdentity {
            access_key_id: Some(key.into()),
            ..root.clone()
        };
        assert!(state.is_account_root(&identity).unwrap());
        assert!(state
            .enforcement
            .check(EnforcementMode::Strict, &root, "iam:CreateUser", "*")
            .is_ok());
        assert!(state
            .enforcement
            .check(EnforcementMode::Strict, &identity, "iam:CreateUser", "*")
            .is_err());
        assert!(state
            .enforcement
            .check(
                EnforcementMode::Strict,
                &identity,
                "sts:GetFederationToken",
                "*"
            )
            .is_err());
        assert!(state
            .enforcement
            .check(EnforcementMode::Strict, &identity, "sts:AssumeRole", "*")
            .is_ok());
        assert!(dispatch_sts(
            &state,
            "000000000000",
            "GetSessionToken",
            &QueryRequest::parse(b""),
            Some(key)
        )
        .is_err());
        let legacy =
            sts::get_session_token(&state.sessions, "000000000000", &QueryRequest::parse(b""))
                .unwrap();
        let legacy_key = issued_key(&legacy);
        let legacy_identity = RequestIdentity {
            access_key_id: Some(legacy_key.into()),
            ..root
        };
        assert!(!state.is_account_root(&legacy_identity).unwrap());
        assert!(state.resolve_caller_arn(&legacy_identity).is_err());
        assert!(state
            .enforcement
            .resolve_caller("000000000000", legacy_key)
            .is_err());
        let mut serialized =
            serde_json::to_value(state.sessions.resolve(legacy_key).unwrap()).unwrap();
        serialized.as_object_mut().unwrap().remove("root_account");
        let restored: sts::Session = serde_json::from_value(serialized).unwrap();
        assert!(!restored.root_account);
    }

    #[test]
    fn malformed_root_sessions_are_rejected_by_account_arn_and_permission_resolution() {
        let (state, root) = root_fixture();
        let issued = dispatch_sts(
            &state,
            &root.account_id,
            "GetSessionToken",
            &QueryRequest::parse(b""),
            root.access_key_id.as_deref(),
        )
        .unwrap();
        let key = issued_key(&issued);
        let original = state.sessions.resolve(key).unwrap();
        let identity = RequestIdentity {
            access_key_id: Some(key.into()),
            ..root
        };
        assert!(state.is_account_root(&identity).unwrap());
        assert_eq!(
            state.credential_account(key),
            Ok(Some(identity.account_id.clone()))
        );
        assert!(state.resolve_caller_arn(&identity).unwrap().is_some());
        assert!(state
            .enforcement
            .resolve_caller(&identity.account_id, key)
            .is_ok());
        let mut cases = Vec::new();
        let mut role_claim = original.clone();
        role_claim.role_arn = Some("arn:aws:iam::000000000000:role/worker".into());
        cases.push(role_claim);
        let mut missing_provenance = original.clone();
        missing_provenance.root_account = false;
        cases.push(missing_provenance);
        let mut foreign_root = original.clone();
        foreign_root.arn = "arn:aws:iam::111111111111:root".into();
        cases.push(foreign_root);
        let mut user_claim = original;
        user_claim.arn = "arn:aws:iam::000000000000:user/reader".into();
        cases.push(user_claim);
        for malformed in cases {
            state.sessions.register(key, malformed).unwrap();
            assert!(!state.is_account_root(&identity).unwrap());
            assert_eq!(
                state.credential_account(key),
                Err(AuthorizationError::Denied)
            );
            assert!(state.resolve_caller_arn(&identity).is_err());
            assert!(state
                .enforcement
                .resolve_caller(&identity.account_id, key)
                .is_err());
        }
    }

    #[test]
    fn root_configuration_requires_complete_pair_and_rejects_user_collision() {
        assert!(root_from_lookup("000000000000", &|_| None)
            .unwrap()
            .is_none());
        assert!(matches!(
            root_from_lookup("000000000000", &|name| (name
                == "LOCALLYCLOUD_ROOT_ACCESS_KEY_ID")
                .then(|| "AKIARRRRRRRRRRRRRRRR".into())),
            Err(BootstrapError::InvalidRootCredentials)
        ));
        let (state, _) = root_fixture();
        seed_bootstrap_user(
            &state.store,
            "000000000000",
            BootstrapCredentials {
                access_key_id: "AKIAABCDEFGHIJKLMNOP".into(),
                secret_access_key: "a".repeat(40),
            },
        );
        assert!(state
            .store
            .provision_root(AccountRoot {
                account: "000000000000".into(),
                access_key_id: "AKIAABCDEFGHIJKLMNOP".into(),
                secret_access_key: "r".repeat(40)
            })
            .is_err());
        assert!(matches!(
            validate_root_collision(
                Some(&AccountRoot {
                    account: "000000000000".into(),
                    access_key_id: "AKIAABCDEFGHIJKLMNOP".into(),
                    secret_access_key: "r".repeat(40)
                }),
                Some(&BootstrapCredentials {
                    access_key_id: "AKIAABCDEFGHIJKLMNOP".into(),
                    secret_access_key: "a".repeat(40)
                })
            ),
            Err(BootstrapError::RootCredentialCollision)
        ));
        assert!(root_from_lookup("bad-account", &|name| match name {
            "LOCALLYCLOUD_ROOT_ACCESS_KEY_ID" => Some("AKIARRRRRRRRRRRRRRRR".into()),
            "LOCALLYCLOUD_ROOT_SECRET_ACCESS_KEY" => Some("r".repeat(40)),
            _ => None,
        })
        .is_err());
    }

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
                (name == "LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID").then(|| key.to_string())
            }),
            Err(BootstrapError::MissingCredentials)
        ));
        assert!(matches!(
            BootstrapCredentials::from_lookup(true, &|name| match name {
                "LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID" => Some("AKIAINVALID".to_string()),
                "LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY" => Some(secret.clone()),
                _ => None,
            }),
            Err(BootstrapError::InvalidCredentials)
        ));
        let credentials = BootstrapCredentials::from_lookup(true, &|name| match name {
            "LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID" => Some(key.to_string()),
            "LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY" => Some(secret.clone()),
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
        let user = store.get_user(account, "locallycloud-bootstrap").unwrap();
        assert_eq!(
            user.arn,
            "arn:aws:iam::123456789012:user/locallycloud-bootstrap"
        );
        assert!(store
            .get_user("000000000000", "locallycloud-bootstrap")
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
        store.update_user(account, "locallycloud-bootstrap", |user| {
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

    #[tokio::test]
    async fn injected_mode_is_the_mode_published_for_both_services() {
        for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
            let registry = ServiceRegistry::new();
            // Startup already validated the mode; publishing must never resolve environment again.
            register_inner(&registry, "000000000000", None, None, mode).unwrap();
            assert_eq!(
                registry
                    .authorization_evaluator(&ServiceName::new("iam"))
                    .unwrap()
                    .strict_sigv4_required(),
                mode == EnforcementMode::Strict
            );
            let response = registry
                .native_handler(&ServiceName::new("sts"))
                .unwrap()
                .handle(request("Action=GetCallerIdentity"))
                .await;
            assert_eq!(
                response.status().as_u16(),
                if mode == EnforcementMode::Strict {
                    403
                } else {
                    200
                }
            );
        }
    }

    #[test]
    fn public_caller_metadata_keeps_exact_sts_session_identifiers() {
        let sessions = Arc::new(SessionStore::new());
        let state = IamStsState::new(Arc::new(IamStore::new()), sessions.clone());
        let arn = "arn:aws:sts::000000000000:assumed-role/worker/session";
        sessions
            .register(
                "ASIAFIXTURE",
                sts::Session {
                    account: "000000000000".into(),
                    secret_access_key: "not-returned".into(),
                    session_token: "not-returned".into(),
                    arn: arn.into(),
                    user_id: "AROAFIXTURE:session".into(),
                    root_account: false,
                    role_arn: Some("arn:aws:iam::000000000000:role/team/worker".into()),
                    session_policy: None,
                    expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
                },
            )
            .unwrap();
        let identity = RequestIdentity {
            account_id: "000000000000".into(),
            access_key_id: Some("ASIAFIXTURE".into()),
            arn: Some("forged".into()),
        };
        let metadata = state.resolve_caller_metadata(&identity).unwrap().unwrap();
        assert_eq!(metadata.arn, arn);
        assert_eq!(metadata.user_id, "AROAFIXTURE:session");
        assert_eq!(metadata.account_id, "000000000000");
        assert_eq!(
            state.resolve_caller_arn(&identity).unwrap().unwrap(),
            "arn:aws:iam::000000000000:role/team/worker"
        );
        assert!(state
            .resolve_caller_metadata(&RequestIdentity {
                account_id: "111111111111".into(),
                ..identity
            })
            .is_err());
    }

    #[test]
    fn credential_accounts_require_unique_active_provenance() {
        let store = Arc::new(IamStore::new());
        let sessions = Arc::new(SessionStore::new());
        let state = IamStsState::new(store.clone(), sessions.clone());
        for (account, key) in [
            ("000000000000", "first-key"),
            ("111111111111", "second-key"),
        ] {
            seed_bootstrap_user(
                &store,
                account,
                BootstrapCredentials {
                    access_key_id: key.into(),
                    secret_access_key: "secret".into(),
                },
            );
            assert_eq!(state.credential_account(key), Ok(Some(account.into())));
        }
        assert_eq!(state.credential_account("unknown"), Ok(None));
        store.update_user("111111111111", "locallycloud-bootstrap", |user| {
            user.access_keys[0].status = "Inactive".into()
        });
        assert_eq!(state.credential_account("second-key"), Ok(None));
        store.update_user("111111111111", "locallycloud-bootstrap", |user| {
            user.access_keys[0].status = "Active".into();
            user.access_keys[0].access_key_id = "first-key".into();
        });
        assert_eq!(
            state.credential_account("first-key"),
            Err(AuthorizationError::Denied)
        );
        let mut session = sts::Session {
            account: "222222222222".into(),
            secret_access_key: "secret".into(),
            session_token: "token".into(),
            arn: "arn:aws:sts::222222222222:assumed-role/worker/run".into(),
            user_id: "AROA:run".into(),
            root_account: false,
            role_arn: Some("arn:aws:iam::222222222222:role/worker".into()),
            session_policy: None,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
        };
        sessions.register("session-key", session.clone()).unwrap();
        assert_eq!(
            state.credential_account("session-key"),
            Ok(Some("222222222222".into()))
        );
        sessions.register("first-key", session.clone()).unwrap();
        assert_eq!(
            state.credential_account("first-key"),
            Err(AuthorizationError::Denied)
        );
        session.expires_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
        sessions.register("expired", session.clone()).unwrap();
        assert_eq!(state.credential_account("expired"), Ok(None));
        store
            .provision_root(AccountRoot {
                account: "333333333333".into(),
                access_key_id: "root-key".into(),
                secret_access_key: "secret".into(),
            })
            .unwrap();
        assert_eq!(
            state.credential_account("root-key"),
            Ok(Some("333333333333".into()))
        );
        session.account = "333333333333".into();
        session.arn = "arn:aws:iam::333333333333:root".into();
        session.role_arn = None;
        session.expires_at = time::OffsetDateTime::now_utc() + time::Duration::minutes(5);
        sessions.register("legacy-root", session.clone()).unwrap();
        assert_eq!(
            state.credential_account("legacy-root"),
            Err(AuthorizationError::Denied)
        );
        session.root_account = true;
        sessions.register("root-session", session.clone()).unwrap();
        assert_eq!(
            state.credential_account("root-session"),
            Ok(Some("333333333333".into()))
        );
        sessions.register("root-key", session).unwrap();
        assert_eq!(
            state.credential_account("root-key"),
            Err(AuthorizationError::Denied)
        );
    }

    #[test]
    fn s3_resource_policy_composition_resolves_principal_and_preserves_denies() {
        let account = "000000000000";
        let store = Arc::new(IamStore::new());
        seed_bootstrap_user(
            &store,
            account,
            BootstrapCredentials {
                access_key_id: "resource-key".into(),
                secret_access_key: "secret".into(),
            },
        );
        let state = IamStsState::new(store.clone(), Arc::new(SessionStore::new()));
        let arn = format!("arn:aws:iam::{account}:user/locallycloud-bootstrap");
        let request = AuthorizationRequest {
            request_identity: RequestIdentity {
                account_id: account.into(),
                access_key_id: Some("resource-key".into()),
                arn: Some("spoofed".into()),
            },
            delegated_identity: None,
            source_service: "s3".into(),
            action: "s3:GetObject".into(),
            resource: "arn:aws:s3:::bucket/Key".into(),
            context: BTreeMap::from([("aws:principalarn".into(), vec!["spoofed".into()])]),
        };
        assert!(state
            .authorize_resource_policy(request.clone(), None, account)
            .is_ok());
        let deny = serde_json::json!({"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"ArnEquals":{"aws:PrincipalArn":arn}}}}).to_string();
        assert_eq!(
            state.authorize_resource_policy(request.clone(), Some(&deny), account),
            Err(AuthorizationError::Denied)
        );
        store.update_user(account, "locallycloud-bootstrap", |user| {
            user.inline_policies.clear()
        });
        let direct = serde_json::json!({"Statement":{"Effect":"Allow","Principal":{"AWS":arn},"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/Key"}}).to_string();
        assert!(state
            .authorize_resource_policy(request.clone(), Some(&direct), account)
            .is_ok());
        assert_eq!(
            state.authorize_resource_policy(request.clone(), Some(&direct), "111111111111"),
            Err(AuthorizationError::Denied)
        );
        let delegated = serde_json::json!({"Statement":{"Effect":"Allow","Principal":{"AWS":account},"Action":"s3:GetObject","Resource":"*"}}).to_string();
        assert_eq!(
            state.authorize_resource_policy(request.clone(), Some(&delegated), account),
            Err(AuthorizationError::Denied)
        );
        let boundary_arn = format!("arn:aws:iam::{account}:policy/limits");
        store.insert_policy(account, crate::model::IamPolicy {
            policy_name: "limits".into(), policy_id: "ANPA".into(), arn: boundary_arn.clone(),
            path: "/".into(), create_date: now_iso8601(), default_version_id: "v1".into(),
            versions: vec![crate::model::PolicyVersion { version_id: "v1".into(), document: r#"{"Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}}"#.into(), is_default: true, create_date: now_iso8601() }],
            attachment_count: 0, description: None, tags: BTreeMap::new(), is_aws_managed: false,
        });
        store.update_user(account, "locallycloud-bootstrap", |user| {
            user.permission_boundary = Some(boundary_arn.clone())
        });
        // A same-account direct user grant bypasses an implicit boundary deny.
        assert!(state
            .authorize_resource_policy(request.clone(), Some(&direct), account)
            .is_ok());
        let role_arn = format!("arn:aws:iam::{account}:role/reader");
        store.create_role(
            account,
            crate::model::IamRole {
                role_name: "reader".into(),
                role_id: "AROA".into(),
                arn: role_arn.clone(),
                path: "/".into(),
                create_date: now_iso8601(),
                assume_role_policy_document: "{}".into(),
                description: None,
                max_session_duration: 3600,
                tags: BTreeMap::new(),
                attached_policies: Vec::new(),
                inline_policies: BTreeMap::new(),
                permission_boundary: Some(boundary_arn),
            },
        );
        let role_grant = serde_json::json!({"Statement":{"Effect":"Allow","Principal":{"AWS":role_arn},"Action":"s3:GetObject","Resource":"*"}}).to_string();
        let role_request = AuthorizationRequest {
            delegated_identity: Some(
                locallycloud_core::integration::identity::CallerIdentity::AssumedRole {
                    role_arn,
                    session_name: "worker".into(),
                },
            ),
            ..request.clone()
        };
        assert_eq!(
            state.authorize_resource_policy(role_request, Some(&role_grant), account),
            Err(AuthorizationError::Denied)
        );
        let role_request = AuthorizationRequest {
            delegated_identity: Some(
                locallycloud_core::integration::identity::CallerIdentity::AssumedRole {
                    role_arn: format!("arn:aws:iam::{account}:role/reader"),
                    session_name: "worker".into(),
                },
            ),
            ..request.clone()
        };
        let wildcard_grant = serde_json::json!({"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"ArnEquals":{"aws:PrincipalArn":format!("arn:aws:iam::{account}:role/reader")}}}}).to_string();
        assert!(state
            .authorize_resource_policy(role_request.clone(), Some(&wildcard_grant), account)
            .is_ok());
        store.update_role(account, "reader", |role| {
            role.inline_policies.insert(
                "deny".into(),
                r#"{"Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}"#.into(),
            );
        });
        assert_eq!(
            state.authorize_resource_policy(role_request, Some(&wildcard_grant), account),
            Err(AuthorizationError::Denied)
        );
        store.update_user(account, "locallycloud-bootstrap", |user| {
            user.inline_policies.insert(
                "deny".into(),
                r#"{"Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}"#.into(),
            );
        });
        assert_eq!(
            state.authorize_resource_policy(request.clone(), Some(&direct), account),
            Err(AuthorizationError::Denied)
        );
        store.update_user(account, "locallycloud-bootstrap", |user| {
            user.access_keys[0].status = "Inactive".into()
        });
        assert_eq!(
            state.authorize_resource_policy(request, Some(&direct), account),
            Err(AuthorizationError::Denied)
        );
    }

    #[test]
    fn kms_identity_decisions_preserve_permissive_mode_without_faking_allow() {
        let mut state = IamStsState::new(Arc::new(IamStore::new()), Arc::new(SessionStore::new()));
        let request = AuthorizationRequest {
            request_identity: RequestIdentity {
                account_id: "000000000000".into(),
                access_key_id: Some("test".into()),
                arn: Some("arn:aws:iam::000000000000:root".into()),
            },
            delegated_identity: None,
            source_service: "s3".into(),
            action: "kms:Decrypt".into(),
            resource: "arn:aws:kms:us-east-1:000000000000:key/key".into(),
            context: BTreeMap::new(),
        };
        state.mode = EnforcementMode::Permissive;
        assert!(!state.identity_policy_allows(request.clone()));
        assert!(!state.identity_policy_denies(request.clone()));
        state.mode = EnforcementMode::Strict;
        assert!(!state.identity_policy_allows(request.clone()));
        assert!(state.identity_policy_denies(request.clone()));
        state.mode = EnforcementMode::Permissive;
        let delegated = AuthorizationRequest {
            delegated_identity: Some(
                locallycloud_core::integration::identity::CallerIdentity::AssumedRole {
                    role_arn: "arn:aws:iam::000000000000:role/missing".into(),
                    session_name: "s3".into(),
                },
            ),
            ..request
        };
        assert!(!state.identity_policy_allows(delegated.clone()));
        assert!(state.identity_policy_denies(delegated));
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
            delegated_caller: None,
            caller_context: Default::default(),
            source_arn: None,
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
        assert_eq!(state.authorize_service_role_trust(request.clone()), Ok(()));
        let mut no_identity_grant = request.clone();
        no_identity_grant.action = "s3:GetObject".into();
        no_identity_grant.resource = "arn:aws:s3:::bucket/object".into();
        assert_eq!(
            state.authorize_service_role_execution(no_identity_grant.clone()),
            Err(AuthorizationError::Denied)
        );
        assert_eq!(
            state.authorize_service_role_trust(no_identity_grant.clone()),
            Ok(())
        );
        let original_trust = store
            .get_role(account, "firehose")
            .unwrap()
            .assume_role_policy_document;
        store.update_role(account, "firehose", |role| role.assume_role_policy_document = r#"{"Statement":{"Effect":"Deny","Principal":{"Service":"firehose.amazonaws.com"},"Action":"sts:AssumeRole"}}"#.into());
        assert_eq!(
            state.authorize_service_role_trust(no_identity_grant),
            Err(AuthorizationError::Denied)
        );
        store.update_role(account, "firehose", |role| {
            role.assume_role_policy_document = original_trust
        });

        let delegated = AuthorizationRequest {
            request_identity: RequestIdentity {
                account_id: account.into(),
                access_key_id: None,
                arn: None,
            },
            delegated_identity: Some(
                locallycloud_core::integration::identity::CallerIdentity::AssumedRole {
                    role_arn: role_arn.clone(),
                    session_name: "firehose".into(),
                },
            ),
            source_service: "s3".into(),
            action: "kinesis:GetRecords".into(),
            resource: stream_arn.clone(),
            context: BTreeMap::new(),
        };
        assert!(state.identity_policy_allows(delegated.clone()));
        assert!(!state.identity_policy_denies(delegated.clone()));
        assert_eq!(state.authorize(delegated.clone()), Ok(()));
        assert_eq!(
            state.authorize(AuthorizationRequest {
                action: "kinesis:DeleteStream".into(),
                ..delegated.clone()
            }),
            Err(AuthorizationError::Denied)
        );

        let granted = store.get_role(account, "firehose").unwrap().inline_policies;
        store.update_role(account, "firehose", |role| role.inline_policies.clear());
        assert_eq!(state.authorize(delegated), Err(AuthorizationError::Denied));
        store.update_role(account, "firehose", |role| role.inline_policies = granted);

        assert_eq!(
            state.authorize_service_role_assignment(ServiceRoleAuthorizationRequest {
                delegated_caller: None,
                caller_context: Default::default(),
                action: "iam:PassRole".into(),
                resource: role_arn.clone(),
                ..request.clone()
            }),
            Ok(())
        );
        assert_eq!(
            state.authorize_service_role(ServiceRoleAuthorizationRequest {
                delegated_caller: None,
                caller_context: Default::default(),
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
        store.update_user(account, "locallycloud-bootstrap", |user| {
            user.inline_policies.clear();
        });
        assert_eq!(
            state.authorize_service_role(request.clone()),
            Err(AuthorizationError::Denied)
        );
        store.update_user(account, "locallycloud-bootstrap", |user| {
            user.inline_policies.insert("pass".into(), format!(
                r#"{{"Statement":{{"Effect":"Allow","Action":"iam:PassRole","Resource":"{role_arn}","Condition":{{"StringEquals":{{"iam:PassedToService":"firehose.amazonaws.com"}}}}}}}}"#
            ));
        });
        assert_eq!(state.authorize_service_role(request.clone()), Ok(()));
        assert_eq!(
            state.authorize_service_role(ServiceRoleAuthorizationRequest {
                delegated_caller: None,
                caller_context: Default::default(),
                service_principal: "lambda.amazonaws.com".into(),
                ..request.clone()
            }),
            Err(AuthorizationError::Denied)
        );
        store.update_user(account, "locallycloud-bootstrap", |user| {
            user.inline_policies.clear()
        });
        assert_eq!(
            state.authorize_service_role_assignment(ServiceRoleAuthorizationRequest {
                delegated_caller: None,
                caller_context: Default::default(),
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
        let source_arn = format!("arn:aws:events:us-east-1:{account}:rule/Orders");
        let scoped = ServiceRoleAuthorizationRequest {
            delegated_caller: None,
            caller_context: Default::default(),
            source_arn: Some(source_arn.clone()),
            service_principal: "events.amazonaws.com".into(),
            ..request.clone()
        };
        let trust = |condition: serde_json::Value| {
            serde_json::json!({"Statement": {
                "Effect": "Allow", "Principal": {"Service":"events.amazonaws.com"},
                "Action":"sts:AssumeRole", "Condition":condition
            }})
            .to_string()
        };
        let set_trust = |document| {
            store.update_role(account, "firehose", |role| {
                role.assume_role_policy_document = document;
            });
        };
        set_trust(trust(serde_json::json!({
            "StringEquals":{"AWS:SourceAccount":account},
            "ArnLike":{"aws:SourceArn":format!("arn:aws:events:*:{account}:rule/Orders")}
        })));
        assert_eq!(
            state.authorize_service_role_execution(scoped.clone()),
            Ok(())
        );
        for source in [
            None,
            Some(source_arn.replace("Orders", "Other")),
            Some(source_arn.replace("Orders", "orders")),
        ] {
            assert_eq!(
                state.authorize_service_role_execution(ServiceRoleAuthorizationRequest {
                    delegated_caller: None,
                    caller_context: Default::default(),
                    source_arn: source,
                    ..scoped.clone()
                }),
                Err(AuthorizationError::Denied)
            );
        }
        for source in [
            source_arn.replace(account, "111111111111"),
            source_arn.replace("events:", "states:"),
        ] {
            assert_eq!(
                state.authorize_service_role_execution(ServiceRoleAuthorizationRequest {
                    delegated_caller: None,
                    caller_context: Default::default(),
                    source_arn: Some(source),
                    ..scoped.clone()
                }),
                Err(AuthorizationError::InvalidRequest)
            );
        }
        for (condition, absent_allowed) in [
            (
                serde_json::json!({"ArnEquals":{"aws:SourceArn":source_arn}}),
                false,
            ),
            (
                serde_json::json!({"StringLike":{"aws:SourceArn":format!("arn:aws:events:*:{account}:rule/Ord*")}}),
                false,
            ),
            (
                serde_json::json!({"StringEqualsIfExists":{"aws:SourceAccount":account}}),
                true,
            ),
            (serde_json::json!({"Null":{"aws:SourceArn":"false"}}), false),
        ] {
            set_trust(trust(condition));
            assert_eq!(
                state.authorize_service_role_execution(scoped.clone()),
                Ok(())
            );
            assert_eq!(
                state
                    .authorize_service_role_execution(ServiceRoleAuthorizationRequest {
                        delegated_caller: None,
                        caller_context: Default::default(),
                        source_arn: None,
                        ..scoped.clone()
                    })
                    .is_ok(),
                absent_allowed
            );
        }
        set_trust(trust(serde_json::json!({"Null":{"aws:SourceArn":"true"}})));
        assert_eq!(
            state.authorize_service_role_execution(scoped.clone()),
            Err(AuthorizationError::Denied)
        );
        set_trust(trust(
            serde_json::json!({"UnsupportedIfExists":{"absent":"anything"}}),
        ));
        assert_eq!(
            state.authorize_service_role_execution(scoped.clone()),
            Err(AuthorizationError::Denied)
        );
        let mut denied: serde_json::Value =
            serde_json::from_str(&trust(serde_json::json!({}))).unwrap();
        let mut deny = denied["Statement"].clone();
        deny["Effect"] = serde_json::json!("Deny");
        deny["Condition"] = serde_json::json!({"ArnEquals":{"aws:SourceArn":source_arn}});
        denied["Statement"] = serde_json::json!([denied["Statement"].clone(), deny]);
        set_trust(denied.to_string());
        assert_eq!(
            state.authorize_service_role_execution(scoped.clone()),
            Err(AuthorizationError::Denied)
        );
        for (service, source) in [
            (
                "states",
                format!("arn:aws:states:us-east-1:{account}:stateMachine:Orders"),
            ),
            (
                "scheduler",
                format!("arn:aws:scheduler:us-east-1:{account}:schedule-group/Orders"),
            ),
            (
                "pipes",
                format!("arn:aws:pipes:us-east-1:{account}:pipe/Orders"),
            ),
        ] {
            set_trust(
                serde_json::json!({"Statement":{
                    "Effect":"Allow", "Principal":{"Service":format!("{service}.amazonaws.com")},
                    "Action":"sts:AssumeRole", "Condition":{"ArnEquals":{"aws:SourceArn":source},
                        "StringEquals":{"aws:SourceAccount":account}}
                }})
                .to_string(),
            );
            let call = ServiceRoleAuthorizationRequest {
                delegated_caller: None,
                caller_context: Default::default(),
                source_arn: Some(source),
                service_principal: format!("{service}.amazonaws.com"),
                ..request.clone()
            };
            assert_eq!(state.authorize_service_role_execution(call.clone()), Ok(()));
            assert_eq!(
                state.authorize_service_role_execution(ServiceRoleAuthorizationRequest {
                    delegated_caller: None,
                    caller_context: Default::default(),
                    source_arn: None,
                    ..call
                }),
                Err(AuthorizationError::Denied)
            );
        }
        set_trust(serde_json::json!({"Statement":{
            "Effect":"Allow", "Principal":{"Service":"lambda.amazonaws.com"},
            "Action":"sts:AssumeRole", "Condition":{"StringEquals":{"aws:SourceAccount":account}}
        }}).to_string());
        assert!(state
            .issue_service_role_credentials(account, &role_arn, "lambda.amazonaws.com")
            .is_err());
        set_trust(trust(serde_json::json!({})));
        store.update_role(account, "firehose", |role| {
            role.inline_policies.clear();
        });
        assert_eq!(
            state.authorize_service_role_execution(scoped),
            Err(AuthorizationError::Denied)
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
    async fn scoped_tag_mutations_authorize_with_the_complete_store_before_staging() {
        let account = "000000000000";
        let key = "AKIA1234567890123456";
        let store = Arc::new(IamStore::new());
        seed_bootstrap_user(
            &store,
            account,
            BootstrapCredentials {
                access_key_id: key.into(),
                secret_access_key: "a".repeat(40),
            },
        );
        iam::create_user(&store, account, &QueryRequest::parse(b"UserName=target")).unwrap();
        store.create_role(
            account,
            crate::model::IamRole {
                role_name: "worker".into(),
                role_id: "AROATARGET".into(),
                arn: format!("arn:aws:iam::{account}:role/worker"),
                path: "/".into(),
                create_date: "now".into(),
                assume_role_policy_document: "{}".into(),
                description: None,
                max_session_duration: 3600,
                tags: BTreeMap::new(),
                attached_policies: Vec::new(),
                inline_policies: BTreeMap::new(),
                permission_boundary: None,
            },
        );
        let actions = [
            "iam:TagUser",
            "iam:UntagUser",
            "iam:TagRole",
            "iam:UntagRole",
        ];
        store.update_user(account, "locallycloud-bootstrap", |caller| {
            caller.attached_policies.clear();
            caller.inline_policies = BTreeMap::from([("tags".into(), serde_json::json!({"Statement":{"Effect":"Allow","Action":actions,"Resource":[format!("arn:aws:iam::{account}:user/target"),format!("arn:aws:iam::{account}:role/worker")]}}).to_string())]);
        });
        let handler = IamHandler {
            state: Arc::new(IamStsState::with_mode(
                store.clone(),
                Arc::new(SessionStore::new()),
                EnforcementMode::Strict,
            )),
        };
        let operations = [
            "Action=TagUser&UserName=target&Tags.member.1.Key=k&Tags.member.1.Value=v",
            "Action=TagRole&RoleName=worker&Tags.member.1.Key=k&Tags.member.1.Value=v",
            "Action=UntagUser&UserName=target&TagKeys.member.1=k",
            "Action=UntagRole&RoleName=worker&TagKeys.member.1=k",
        ];
        let signed = |body: &str| {
            let mut req = request(body);
            req.headers.insert(
                http::header::AUTHORIZATION,
                format!("AWS4-HMAC-SHA256 Credential={key}/20261116/us-east-1/iam/aws4_request")
                    .parse()
                    .unwrap(),
            );
            req.headers.insert(
                "x-locallycloud-verified-external-sigv4",
                "1".parse().unwrap(),
            );
            req
        };
        for body in operations {
            assert_eq!(handler.handle(signed(body)).await.status(), 200);
        }
        assert!(store.get_user(account, "target").unwrap().tags.is_empty());
        assert!(store.get_role(account, "worker").unwrap().tags.is_empty());
        store.update_user(account, "locallycloud-bootstrap", |caller| {
            caller.inline_policies.insert(
                "deny".into(),
                serde_json::json!({"Statement":{"Effect":"Deny","Action":actions,"Resource":"*"}})
                    .to_string(),
            );
        });
        for body in operations {
            assert_eq!(handler.handle(signed(body)).await.status(), 403);
        }
        assert!(store.get_user(account, "target").unwrap().tags.is_empty());
        assert!(store.get_role(account, "worker").unwrap().tags.is_empty());
        assert_eq!(store.list_users(account).len(), 2);
        for action in ["TagUser", "UntagUser", "TagRole", "UntagRole"] {
            assert_eq!(
                handler
                    .handle(signed(&format!("Action={action}")))
                    .await
                    .status(),
                400
            );
        }
    }

    #[tokio::test]
    async fn user_tag_arn_deny_preserves_real_path_and_prevents_both_mutations() {
        let account = "000000000000";
        let key = "AKIA1234567890123456";
        let store = Arc::new(IamStore::new());
        seed_bootstrap_user(
            &store,
            account,
            BootstrapCredentials {
                access_key_id: key.into(),
                secret_access_key: "a".repeat(40),
            },
        );
        iam::create_user(
            &store,
            account,
            &QueryRequest::parse(b"UserName=target&Path=%2Fteam%2F"),
        )
        .unwrap();
        store.update_user(account, "target", |user| {
            user.tags.insert("guard".into(), "keep".into());
        });
        let target_arn = format!("arn:aws:iam::{account}:user/team/target");
        assert_eq!(store.get_user(account, "target").unwrap().arn, target_arn);
        store.update_user(account, "locallycloud-bootstrap", |caller| {
            caller.attached_policies.clear();
            caller.inline_policies = BTreeMap::from([(
                "guard".into(),
                serde_json::json!({"Statement":[
                    {"Effect":"Allow","Action":["iam:TagUser","iam:UntagUser"],"Resource":"*"},
                    {"Effect":"Deny","Action":["iam:TagUser","iam:UntagUser"],"Resource":target_arn}
                ]})
                .to_string(),
            )]);
        });
        let handler = IamHandler {
            state: Arc::new(IamStsState::with_mode(
                store.clone(),
                Arc::new(SessionStore::new()),
                EnforcementMode::Strict,
            )),
        };
        let mut statuses = Vec::new();
        for body in [
            "Action=TagUser&UserName=target&Tags.member.1.Key=new&Tags.member.1.Value=value",
            "Action=UntagUser&UserName=target&TagKeys.member.1=guard",
        ] {
            let mut req = request(body);
            req.headers.insert(
                http::header::AUTHORIZATION,
                format!("AWS4-HMAC-SHA256 Credential={key}/20261116/us-east-1/iam/aws4_request")
                    .parse()
                    .unwrap(),
            );
            req.headers.insert(
                "x-locallycloud-verified-external-sigv4",
                "1".parse().unwrap(),
            );
            statuses.push(handler.handle(req).await.status().as_u16());
        }
        assert_eq!(statuses, [403, 403]);
        assert_eq!(
            store.get_user(account, "target").unwrap().tags,
            BTreeMap::from([("guard".into(), "keep".into())])
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
    async fn missing_action_uses_the_documented_error_in_each_service_namespace() {
        let registry = ServiceRegistry::new();
        register(&registry);
        for (service, xmlns) in [("iam", IAM_XMLNS), ("sts", STS_XMLNS)] {
            let handler = registry.native_handler(&ServiceName::new(service)).unwrap();
            let response = handler.handle(request("")).await;
            assert_eq!(response.status(), 400);
            let body = axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(body.contains("<Code>MissingAction</Code>"), "{service}");
            assert!(body.contains(xmlns), "{service}");
            assert!(!body.contains("<Code>InvalidAction</Code>"), "{service}");
        }
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
        store.update_user("000000000000", "locallycloud-bootstrap", |user| {
            user.attached_policies.clear();
            user.inline_policies.insert("deny-caller".into(), r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"sts:GetCallerIdentity","Resource":"*"}]}"#.into());
        });
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
            .get_user("000000000000", "locallycloud-bootstrap")
            .unwrap();
        assert!(body.contains(&format!("<Arn>{}</Arn>", user.arn)));
        assert!(body.contains(&format!("<UserId>{}</UserId>", user.user_id)));
        assert!(!body.contains(":root</Arn>"));

        store.update_user("000000000000", "locallycloud-bootstrap", |user| {
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

#[cfg(test)]
mod durability_tests {
    use super::*;
    use crate::persistence::IamPersistence;
    use locallycloud_state::{StateCipher, StateDb};

    fn bootstrap_credentials() -> BootstrapCredentials {
        BootstrapCredentials {
            access_key_id: "AKIAABCDEFGHIJKLMNOP".into(),
            secret_access_key: "durable-bootstrap-secret".into(),
        }
    }
    fn persistence(db: Arc<StateDb>, key: u8) -> Arc<IamPersistence> {
        Arc::new(IamPersistence::with_cipher(db, StateCipher::with_key(&[key; 32])).unwrap())
    }
    fn dispatch(store: &IamStore, action: &str, query: &str) -> OpResult {
        store.transact(|staged| {
            dispatch_iam_store(
                staged,
                "000000000000",
                action,
                &QueryRequest::parse(query.as_bytes()),
            )
        })
    }

    #[test]
    fn encrypted_entities_credentials_sessions_and_revocations_survive_restart() {
        let root =
            std::env::temp_dir().join(format!("locallycloud-iam-durable-{}", uuid::Uuid::new_v4()));
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let p = persistence(db.clone(), 0x31);
        let store = IamStore::durable(p.clone()).unwrap();
        dispatch(&store, "CreateUser", "UserName=alice").unwrap();
        dispatch(&store, "CreateGroup", "GroupName=developers").unwrap();
        dispatch(
            &store,
            "AddUserToGroup",
            "UserName=alice&GroupName=developers",
        )
        .unwrap();
        let allow = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:PutItem","Resource":"*"}]}"#;
        dispatch(
            &store,
            "CreatePolicy",
            &format!(
                "PolicyName=writer&PolicyDocument={}",
                crate::model::urlencode_doc(allow)
            ),
        )
        .unwrap();
        dispatch(
            &store,
            "AttachGroupPolicy",
            "GroupName=developers&PolicyArn=arn%3Aaws%3Aiam%3A%3A000000000000%3Apolicy%2Fwriter",
        )
        .unwrap();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}]}"#;
        dispatch(
            &store,
            "CreateRole",
            &format!(
                "RoleName=executor&AssumeRolePolicyDocument={}",
                crate::model::urlencode_doc(trust)
            ),
        )
        .unwrap();
        dispatch(
            &store,
            "PutRolePolicy",
            &format!(
                "RoleName=executor&PolicyName=writer&PolicyDocument={}",
                crate::model::urlencode_doc(allow)
            ),
        )
        .unwrap();
        dispatch(&store, "CreateAccessKey", "UserName=alice").unwrap();
        let access = store.get_user("000000000000", "alice").unwrap().access_keys[0].clone();
        let sessions = SessionStore::durable(p.clone()).unwrap();
        let credentials = sts::issue_service_role_credentials(
            &store,
            &sessions,
            "000000000000",
            "arn:aws:iam::000000000000:role/executor",
        )
        .unwrap();
        let session = sessions.resolve(&credentials.access_key_id).unwrap();
        let mut expired = session.clone();
        expired.expires_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
        p.save_session("ASIAEXPIRED", &expired).unwrap();
        store
            .transact(|staged| {
                seed_durable_bootstrap(staged, "000000000000", bootstrap_credentials());
                Ok(())
            })
            .unwrap();
        dispatch(
            &store,
            "DeleteAccessKey",
            "UserName=locallycloud-bootstrap&AccessKeyId=AKIAABCDEFGHIJKLMNOP",
        )
        .unwrap();
        dispatch(
            &store,
            "DeleteUserPolicy",
            "UserName=locallycloud-bootstrap&PolicyName=LocallyCloudBootstrapAdministrator",
        )
        .unwrap();
        dispatch(&store, "DeleteUser", "UserName=locallycloud-bootstrap").unwrap();
        drop(sessions);
        drop(store);
        drop(p);
        let p = persistence(db.clone(), 0x31);
        let store = Arc::new(IamStore::durable(p.clone()).unwrap());
        store
            .transact(|staged| {
                seed_durable_bootstrap(staged, "000000000000", bootstrap_credentials());
                Ok(())
            })
            .unwrap();
        assert!(store.bootstrap_initialized("000000000000"));
        assert!(!store.bootstrap_initialized("111111111111"));
        assert!(store
            .get_user("000000000000", "locallycloud-bootstrap")
            .is_none());
        let sessions = Arc::new(SessionStore::durable(p.clone()).unwrap());
        assert!(sessions.resolve("ASIAEXPIRED").is_none());
        let restored = sessions.resolve(&credentials.access_key_id).unwrap();
        assert_eq!(restored.secret_access_key, credentials.secret_access_key);
        assert_eq!(restored.session_token, credentials.session_token);
        assert_eq!(
            restored.expires_at.unix_timestamp(),
            session.expires_at.unix_timestamp()
        );
        let state = IamStsState::new(store.clone(), sessions);
        let identity = RequestIdentity {
            account_id: "000000000000".into(),
            access_key_id: Some(access.access_key_id.clone()),
            arn: None,
        };
        assert_eq!(
            state.resolve_caller_arn(&identity).unwrap(),
            Some("arn:aws:iam::000000000000:user/alice".into())
        );
        assert_eq!(
            store
                .get_group("000000000000", "developers")
                .unwrap()
                .members,
            vec!["alice"]
        );
        assert!(store
            .get_role("000000000000", "executor")
            .unwrap()
            .inline_policies
            .contains_key("writer"));
        assert!(store.get_user("111111111111", "alice").is_none());
        dispatch(
            &store,
            "UpdateAccessKey",
            &format!(
                "UserName=alice&AccessKeyId={}&Status=Inactive",
                access.access_key_id
            ),
        )
        .unwrap();
        let reopened = Arc::new(IamStore::durable(p.clone()).unwrap());
        let state = IamStsState::new(
            reopened,
            Arc::new(SessionStore::durable(p.clone()).unwrap()),
        );
        assert_eq!(state.resolve_caller_arn(&identity).unwrap(), None);
        for table in ["iam_resources", "iam_sessions"] {
            let connection = db.connection().unwrap();
            let mut stmt = connection
                .prepare(&format!("SELECT payload FROM {table}"))
                .unwrap();
            for bytes in stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)).unwrap() {
                let bytes = bytes.unwrap();
                for secret in [
                    &access.secret_access_key,
                    &credentials.secret_access_key,
                    &credentials.session_token,
                ] {
                    assert!(!bytes
                        .windows(secret.len())
                        .any(|part| part == secret.as_bytes()));
                }
            }
        }
        assert!(IamStore::durable(persistence(db.clone(), 0x32)).is_err());
        db.connection()
            .unwrap()
            .execute(
                "UPDATE iam_resources SET payload=zeroblob(32) WHERE kind='user'",
                [],
            )
            .unwrap();
        assert!(IamStore::durable(persistence(db, 0x31)).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_commit_never_publishes_staged_iam_or_issues_sts_credentials() {
        let root = std::env::temp_dir().join(format!(
            "locallycloud-iam-rollback-{}",
            uuid::Uuid::new_v4()
        ));
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let p = persistence(db.clone(), 0x41);
        let store = IamStore::durable(p.clone()).unwrap();
        dispatch(&store, "CreateUser", "UserName=alice").unwrap();
        db.connection().unwrap().execute_batch("CREATE TRIGGER reject_iam BEFORE INSERT ON iam_resources BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
        let result = store.transact(|staged| {
            let response = dispatch_iam_store(
                staged,
                "000000000000",
                "CreateUser",
                &QueryRequest::parse(b"UserName=tentative"),
            )?;
            assert!(store.get_user("000000000000", "tentative").is_none());
            Ok(response)
        });
        assert!(matches!(result, Err(IamStsError::InternalFailure(_))));
        assert!(store.get_user("000000000000", "tentative").is_none());
        assert!(IamStore::durable(p.clone())
            .unwrap()
            .get_user("000000000000", "tentative")
            .is_none());
        assert!(store.get_user("000000000000", "alice").is_some());
        assert!(store
            .transact(|staged| {
                seed_durable_bootstrap(staged, "000000000000", bootstrap_credentials());
                Ok(())
            })
            .is_err());
        assert!(!store.bootstrap_initialized("000000000000"));
        assert!(store
            .get_user("000000000000", "locallycloud-bootstrap")
            .is_none());
        assert!(!IamStore::durable(p.clone())
            .unwrap()
            .bootstrap_initialized("000000000000"));

        db.connection().unwrap().execute_batch("DROP TRIGGER reject_iam; CREATE TRIGGER reject_session BEFORE INSERT ON iam_sessions BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}]}"#;
        dispatch(
            &store,
            "CreateRole",
            &format!(
                "RoleName=executor&AssumeRolePolicyDocument={}",
                crate::model::urlencode_doc(trust)
            ),
        )
        .unwrap();
        let sessions = SessionStore::durable(p.clone()).unwrap();
        assert!(matches!(
            sts::issue_service_role_credentials(
                &store,
                &sessions,
                "000000000000",
                "arn:aws:iam::000000000000:role/executor"
            ),
            Err(IamStsError::InternalFailure(_))
        ));
        assert!(p.load_sessions().unwrap().is_empty());
        db.connection()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_session;")
            .unwrap();
        dispatch(&store, "CreateUser", "UserName=tentative").unwrap();
        assert!(store.get_user("000000000000", "tentative").is_some());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn live_time_denies_identity_and_direct_resource_grants_despite_forged_claims() {
        let account = "000000000000";
        let store = Arc::new(IamStore::new());
        seed_bootstrap_user(
            &store,
            account,
            BootstrapCredentials {
                access_key_id: "time-key".into(),
                secret_access_key: "secret".into(),
            },
        );
        let state = IamStsState::with_mode(
            store.clone(),
            Arc::new(SessionStore::new()),
            EnforcementMode::Strict,
        );
        let grant=serde_json::json!({"Statement":{"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{account}:user/locallycloud-bootstrap")},"Action":"s3:GetObject","Resource":"*"}}).to_string();
        let request = AuthorizationRequest {
            request_identity: RequestIdentity {
                account_id: account.into(),
                access_key_id: Some("time-key".into()),
                arn: None,
            },
            delegated_identity: None,
            source_service: "s3".into(),
            action: "s3:GetObject".into(),
            resource: "arn:aws:s3:::bucket/key".into(),
            context: BTreeMap::from([
                (
                    "AWS:CurrentTime".into(),
                    vec!["1900-01-01T00:00:00Z".into()],
                ),
                ("AWS:EpochTime".into(), vec!["0".into()]),
            ]),
        };
        for condition in [
            serde_json::json!({"DateGreaterThan":{"aws:CurrentTime":"2000-01-01T00:00:00Z"}}),
            serde_json::json!({"NumericGreaterThan":{"aws:EpochTime":1}}),
        ] {
            store.update_user(account, "locallycloud-bootstrap", |user| {
                user.inline_policies=BTreeMap::from([("time".into(),serde_json::json!({"Statement":[
                {"Effect":"Allow","Action":"*","Resource":"*"},
                {"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":condition}
            ]}).to_string())])
            });
            assert_eq!(
                state.authorize(request.clone()),
                Err(AuthorizationError::Denied)
            );
            assert_eq!(
                state.authorize_resource_policy(request.clone(), Some(&grant), account),
                Err(AuthorizationError::Denied)
            );
        }
        store.update_user(account, "locallycloud-bootstrap", |user| {
            user.inline_policies.clear()
        });
        assert!(state
            .authorize_resource_policy(request, Some(&grant), account)
            .is_ok());
    }
}

#[cfg(test)]
#[path = "assume_role_tests.rs"]
mod assume_role_tests;

#[cfg(test)]
#[path = "principal_attributes_tests.rs"]
mod principal_attributes_tests;

#[cfg(test)]
#[path = "service/anonymous_resource_policy_tests.rs"]
mod anonymous_resource_policy_tests;
