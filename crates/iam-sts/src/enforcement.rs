//! IAM enforcement mode and filter.
//!
//! Permissive by default (frictionless local testing); strict on opt-in via
//! `LOCALLYCLOUD_IAM_ENFORCEMENT` (alias `LOCALSTACK_IAM_ENFORCEMENT`).
//! In strict mode the filter resolves the caller's `Caller_Context` from the SigV4 access-key
//! identifier — a session (`ASIA…`) via the role behind its assumed-role ARN, or an IAM user
//! (`AKIA…`) with inline + attached + group-inherited policies and permission boundary — then
//! evaluates the action and rejects a `Deny` with `AccessDenied`/403. Missing identities and
//! unresolved or malformed policy state also fail closed with `AccessDenied`. The decision engine
//! is the same one that powers the Simulate APIs.
//! See Requirement 22.

use std::collections::BTreeMap;
use std::sync::Arc;

use locallycloud_core::integration::RequestIdentity;

use crate::error::IamStsError;
use crate::policy::{evaluate, Decision, EvalRequest, PolicyDocument};
use crate::store::IamStore;
use crate::sts::SessionStore;

/// Whether IAM policy decisions gate request handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    #[default]
    Permissive,
    Strict,
}

impl EnforcementMode {
    /// Resolve from the name-independent configuration; defaults to permissive.
    pub fn from_env() -> Self {
        for key in ["LOCALLYCLOUD_IAM_ENFORCEMENT", "LOCALSTACK_IAM_ENFORCEMENT"] {
            if let Ok(value) = std::env::var(key) {
                return if value.eq_ignore_ascii_case("strict") {
                    EnforcementMode::Strict
                } else {
                    EnforcementMode::Permissive
                };
            }
        }
        EnforcementMode::Permissive
    }
}

/// The policy documents that bound a caller's authority.
pub(crate) struct CallerContext {
    pub(crate) identity: Vec<PolicyDocument>,
    pub(crate) boundary: Option<Vec<PolicyDocument>>,
    pub(crate) session: Option<Vec<PolicyDocument>>,
    attributes: BTreeMap<String, Vec<String>>,
    mfa_present: Option<bool>,
}

impl CallerContext {
    pub(crate) fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    pub(crate) fn allows(
        &self,
        action: &str,
        resource: &str,
        context: &BTreeMap<String, Vec<String>>,
    ) -> bool {
        let mut context = context.clone();
        self.apply_attributes(&mut context);
        evaluate(
            &self.identity,
            self.boundary.as_deref(),
            self.session.as_deref(),
            &EvalRequest {
                action: action.into(),
                resource: resource.into(),
                context,
            },
        ) == Decision::Allowed
    }

    pub(crate) fn denies(
        &self,
        action: &str,
        resource: &str,
        context: &BTreeMap<String, Vec<String>>,
    ) -> bool {
        let mut context = context.clone();
        self.apply_attributes(&mut context);
        context_denies(
            self,
            &EvalRequest {
                action: action.into(),
                resource: resource.into(),
                context,
            },
        )
    }

    pub(crate) fn apply_attributes(&self, context: &mut BTreeMap<String, Vec<String>>) {
        strip_principal_attributes(context);
        apply_time_attributes(context);
        if let Some(present) = self.mfa_present {
            context.insert(
                "aws:multifactorauthpresent".into(),
                vec![present.to_string()],
            );
        }
        context.extend(
            self.attributes
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }
}

/// One trusted instant supplies both global time keys; caller-provided aliases are removed.
pub(crate) fn apply_time_attributes(context: &mut BTreeMap<String, Vec<String>>) {
    context.retain(|key, _| {
        !key.eq_ignore_ascii_case("aws:currenttime") && !key.eq_ignore_ascii_case("aws:epochtime")
    });
    let now = time::OffsetDateTime::now_utc();
    let epoch = now.unix_timestamp().to_string();
    let current = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| epoch.clone());
    context.insert("aws:currenttime".into(), vec![current]);
    context.insert("aws:epochtime".into(), vec![epoch]);
}

pub(crate) fn strip_principal_attributes(context: &mut BTreeMap<String, Vec<String>>) {
    context.retain(|key, _| {
        !key.get(..13)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("aws:principal"))
            && !key.eq_ignore_ascii_case("aws:userid")
            && !key.eq_ignore_ascii_case("aws:multifactorauthpresent")
    });
}

fn principal_attributes(
    account: &str,
    arn: &str,
    kind: &str,
    user_id: Option<&str>,
    tags: &BTreeMap<String, String>,
) -> BTreeMap<String, Vec<String>> {
    let mut attributes = BTreeMap::from([
        ("aws:principalarn".into(), vec![arn.into()]),
        ("aws:principalaccount".into(), vec![account.into()]),
        ("aws:principaltype".into(), vec![kind.into()]),
        ("aws:principalisawsservice".into(), vec!["false".into()]),
    ]);
    if let Some(user_id) = user_id {
        attributes.insert("aws:userid".into(), vec![user_id.into()]);
    }
    for (key, value) in tags {
        attributes
            .entry(format!("aws:principaltag/{}", key.to_ascii_lowercase()))
            .or_default()
            .push(value.clone());
    }
    attributes
}

/// Evaluates a request against the resolved caller's policies under the active mode.
pub struct EnforcementFilter {
    store: Arc<IamStore>,
    sessions: Arc<SessionStore>,
}

impl EnforcementFilter {
    pub fn new(store: Arc<IamStore>, sessions: Arc<SessionStore>) -> Self {
        EnforcementFilter { store, sessions }
    }

    /// Permissive never blocks. Strict denies callers or stored policy state that cannot be
    /// resolved, and permits only an explicit allow within every applicable policy boundary.
    pub fn check(
        &self,
        mode: EnforcementMode,
        identity: &RequestIdentity,
        action: &str,
        resource: &str,
    ) -> Result<(), IamStsError> {
        self.check_with_context(mode, identity, action, resource, &BTreeMap::new())
    }

    pub fn check_with_context(
        &self,
        mode: EnforcementMode,
        identity: &RequestIdentity,
        action: &str,
        resource: &str,
        context: &BTreeMap<String, Vec<String>>,
    ) -> Result<(), IamStsError> {
        if mode == EnforcementMode::Permissive {
            return Ok(());
        }
        let access_key_id = identity.access_key_id.as_deref().ok_or_else(|| {
            IamStsError::AccessDenied("request has no resolvable access key".into())
        })?;
        if self
            .sessions
            .resolve(access_key_id)
            .is_some_and(|session| session.role_arn.is_none())
            && (action.starts_with("iam:")
                || (action.starts_with("sts:")
                    && !matches!(action, "sts:AssumeRole" | "sts:GetCallerIdentity")))
        {
            return Err(IamStsError::AccessDenied("session credentials cannot perform this IAM/STS operation without supported MFA context".into()));
        }
        let caller = self.resolve_caller(&identity.account_id, access_key_id)?;
        let mut context = context.clone();
        caller.apply_attributes(&mut context);
        let req = EvalRequest {
            action: action.to_string(),
            resource: resource.to_string(),
            context,
        };
        match evaluate(
            &caller.identity,
            caller.boundary.as_deref(),
            caller.session.as_deref(),
            &req,
        ) {
            Decision::Allowed => Ok(()),
            Decision::ImplicitDeny | Decision::ExplicitDeny => Err(IamStsError::AccessDenied(
                format!("User is not authorized to perform: {action} on resource: {resource}"),
            )),
        }
    }

    /// Resource/key policies may provide a direct Allow, but cannot override denies or limits.
    pub fn identity_policy_denies(
        &self,
        identity: &RequestIdentity,
        action: &str,
        resource: &str,
        context: &BTreeMap<String, Vec<String>>,
    ) -> bool {
        let Some(key) = identity.access_key_id.as_deref() else {
            return true;
        };
        let Ok(caller) = self.resolve_caller(&identity.account_id, key) else {
            return true;
        };
        let mut context = context.clone();
        caller.apply_attributes(&mut context);
        let request = EvalRequest {
            action: action.into(),
            resource: resource.into(),
            context,
        };
        context_denies(&caller, &request)
    }

    /// Evaluate one role's stored identity policies and permission boundary.
    pub fn check_role(
        &self,
        account: &str,
        role_arn: &str,
        action: &str,
        resource: &str,
    ) -> Result<(), IamStsError> {
        self.check_role_with_context(account, role_arn, action, resource, &BTreeMap::new())
    }

    pub fn check_role_with_context(
        &self,
        account: &str,
        role_arn: &str,
        action: &str,
        resource: &str,
        context: &BTreeMap<String, Vec<String>>,
    ) -> Result<(), IamStsError> {
        if self
            .role_context(account, role_arn)?
            .allows(action, resource, context)
        {
            Ok(())
        } else {
            Err(IamStsError::AccessDenied(format!(
                "role is not authorized for {action} on {resource}"
            )))
        }
    }

    pub fn role_policy_denies(
        &self,
        account: &str,
        role_arn: &str,
        action: &str,
        resource: &str,
        context: &BTreeMap<String, Vec<String>>,
    ) -> bool {
        let Ok(caller) = self.role_context(account, role_arn) else {
            return true;
        };
        caller.denies(action, resource, context)
    }

    pub(crate) fn role_context(
        &self,
        account: &str,
        role_arn: &str,
    ) -> Result<CallerContext, IamStsError> {
        self.role_context_with_session(account, role_arn, None)
    }

    pub(crate) fn role_session_context(
        &self,
        account: &str,
        role_arn: &str,
        session_name: &str,
    ) -> Result<CallerContext, IamStsError> {
        if session_name.is_empty() {
            return Err(IamStsError::AccessDenied(
                "service role session is unavailable".into(),
            ));
        }
        self.role_context_with_session(account, role_arn, Some(session_name))
    }

    fn role_context_with_session(
        &self,
        account: &str,
        role_arn: &str,
        session_name: Option<&str>,
    ) -> Result<CallerContext, IamStsError> {
        let name = role_arn.rsplit('/').next().unwrap_or(role_arn);
        let role = self
            .store
            .get_role(account, name)
            .filter(|role| role.arn == role_arn)
            .ok_or_else(|| IamStsError::AccessDenied("service role is unavailable".into()))?;
        let identity = self.gather_docs(account, &role.inline_policies, &role.attached_policies)?;
        let boundary = role
            .permission_boundary
            .as_deref()
            .map(|arn| self.policy_doc(account, arn))
            .transpose()?
            .map(|policy| vec![policy]);
        let user_id = session_name.map(|session| format!("{}:{session}", role.role_id));
        Ok(CallerContext {
            identity,
            boundary,
            session: None,
            mfa_present: session_name.map(|_| false),
            attributes: principal_attributes(
                account,
                &role.arn,
                "AssumedRole",
                user_id.as_deref(),
                &role.tags,
            ),
        })
    }

    pub(crate) fn resolve_caller(
        &self,
        account: &str,
        access_key_id: &str,
    ) -> Result<CallerContext, IamStsError> {
        if self.store.root_for_key(account, access_key_id).is_some() {
            return Ok(root_context(account, None));
        }
        if let Some(session) = self.sessions.resolve(access_key_id) {
            if session.account != account {
                return Err(unresolvable_caller(access_key_id));
            }
            if session
                .root_provenance(account, &self.store)
                .map_err(|_| unresolvable_caller(access_key_id))?
            {
                return Ok(root_context(account, Some(false)));
            }
            let session_policy = session
                .session_policy
                .as_deref()
                .map(parse_stored_policy)
                .transpose()?
                .map(|policy| vec![policy]);
            let Some(role_arn) = session.role_arn.as_deref() else {
                return Ok(CallerContext {
                    identity: Vec::new(),
                    boundary: None,
                    session: session_policy,
                    mfa_present: Some(false),
                    attributes: principal_attributes(
                        account,
                        &session.arn,
                        if session.arn.contains(":federated-user/") {
                            "FederatedUser"
                        } else {
                            "User"
                        },
                        Some(&session.user_id),
                        &BTreeMap::new(),
                    ),
                });
            };
            let role_name = role_arn.rsplit('/').next().unwrap_or(role_arn);
            let role = self
                .store
                .get_role(account, role_name)
                .filter(|role| role.arn == role_arn)
                .ok_or_else(|| unresolvable_caller(access_key_id))?;
            let identity =
                self.gather_docs(account, &role.inline_policies, &role.attached_policies)?;
            let boundary = role
                .permission_boundary
                .as_deref()
                .map(|arn| self.policy_doc(account, arn))
                .transpose()?
                .map(|policy| vec![policy]);
            return Ok(CallerContext {
                identity,
                boundary,
                session: session_policy,
                mfa_present: Some(false),
                attributes: principal_attributes(
                    account,
                    &role.arn,
                    "AssumedRole",
                    Some(&session.user_id),
                    &role.tags,
                ),
            });
        }

        let user = self
            .store
            .user_for_key(account, access_key_id)
            .ok_or_else(|| unresolvable_caller(access_key_id))?;
        let mut identity =
            self.gather_docs(account, &user.inline_policies, &user.attached_policies)?;
        for group_name in &user.groups {
            let group = self
                .store
                .get_group(account, group_name)
                .ok_or_else(|| unresolvable_caller(access_key_id))?;
            identity.extend(self.gather_docs(
                account,
                &group.inline_policies,
                &group.attached_policies,
            )?);
        }
        let boundary = user
            .permission_boundary
            .as_deref()
            .map(|arn| self.policy_doc(account, arn))
            .transpose()?
            .map(|policy| vec![policy]);
        Ok(CallerContext {
            identity,
            boundary,
            session: None,
            mfa_present: None,
            attributes: principal_attributes(
                account,
                &user.arn,
                "User",
                Some(&user.user_id),
                &user.tags,
            ),
        })
    }

    fn gather_docs(
        &self,
        account: &str,
        inline: &BTreeMap<String, String>,
        attached: &[String],
    ) -> Result<Vec<PolicyDocument>, IamStsError> {
        let mut docs = Vec::new();
        for document in inline.values() {
            docs.push(parse_stored_policy(document)?);
        }
        for arn in attached {
            docs.push(self.policy_doc(account, arn)?);
        }
        Ok(docs)
    }

    fn policy_doc(&self, account: &str, arn: &str) -> Result<PolicyDocument, IamStsError> {
        let policy = self
            .store
            .get_policy(account, arn)
            .or_else(|| self.store.get_policy("aws", arn))
            .ok_or_else(|| IamStsError::AccessDenied(format!("policy {arn} cannot be resolved")))?;
        let version = policy
            .versions
            .iter()
            .find(|version| version.version_id == policy.default_version_id)
            .ok_or_else(|| {
                IamStsError::AccessDenied(format!(
                    "default version for policy {arn} cannot be resolved"
                ))
            })?;
        parse_stored_policy(&version.document)
    }
}

fn parse_stored_policy(document: &str) -> Result<PolicyDocument, IamStsError> {
    PolicyDocument::parse(document)
        .map_err(|_| IamStsError::AccessDenied("stored policy is malformed".into()))
}

fn context_denies(caller: &CallerContext, request: &EvalRequest) -> bool {
    evaluate(&caller.identity, None, None, request) == Decision::ExplicitDeny
        || caller
            .boundary
            .as_ref()
            .is_some_and(|policies| evaluate(policies, None, None, request) != Decision::Allowed)
        || caller
            .session
            .as_ref()
            .is_some_and(|policies| evaluate(policies, None, None, request) != Decision::Allowed)
}

fn unresolvable_caller(access_key_id: &str) -> IamStsError {
    IamStsError::AccessDenied(format!(
        "caller for access key {access_key_id} cannot be resolved"
    ))
}

fn root_context(account: &str, mfa_present: Option<bool>) -> CallerContext {
    CallerContext {
        identity: vec![PolicyDocument::parse(
            r#"{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#,
        )
        .expect("static root policy is valid")],
        boundary: None,
        session: None,
        mfa_present,
        attributes: principal_attributes(
            account,
            &format!("arn:aws:iam::{account}:root"),
            "Account",
            Some(account),
            &BTreeMap::new(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arn::build_iam_arn;
    use crate::model::{urlencode_doc, AccessKey, IamRole, IamUser};
    use crate::query::QueryRequest;
    use crate::sts::assume_role;

    fn user_with_key(name: &str, akid: &str) -> IamUser {
        IamUser {
            user_name: name.to_string(),
            user_id: "AIDA".to_string(),
            arn: format!("arn:aws:iam::000000000000:user/{name}"),
            path: "/".to_string(),
            create_date: "2020-01-01T00:00:00Z".to_string(),
            tags: BTreeMap::new(),
            attached_policies: Vec::new(),
            inline_policies: BTreeMap::new(),
            groups: Vec::new(),
            permission_boundary: None,
            access_keys: vec![AccessKey {
                access_key_id: akid.to_string(),
                secret_access_key: "secret".to_string(),
                status: "Active".to_string(),
                create_date: "2020-01-01T00:00:00Z".to_string(),
            }],
        }
    }

    fn filter_with_sessions() -> (EnforcementFilter, Arc<IamStore>, Arc<SessionStore>) {
        let store = Arc::new(IamStore::new());
        let sessions = Arc::new(SessionStore::new());
        (
            EnforcementFilter::new(store.clone(), sessions.clone()),
            store,
            sessions,
        )
    }

    fn filter() -> (EnforcementFilter, Arc<IamStore>) {
        let (filter, store, _) = filter_with_sessions();
        (filter, store)
    }

    fn identity(akid: &str) -> RequestIdentity {
        RequestIdentity {
            account_id: "000000000000".to_string(),
            access_key_id: Some(akid.to_string()),
            arn: None,
        }
    }

    #[test]
    fn key_policy_grants_respect_explicit_denies_and_identity_revocation() {
        let (filter, store) = filter();
        let account = "000000000000";
        let key = "AKIACONTEXT";
        let mut principal = user_with_key("alice", key);
        store.create_user(account, principal.clone());
        let context = BTreeMap::from([(
            "kms:viaservice".into(),
            vec!["s3.us-east-1.amazonaws.com".into()],
        )]);
        assert!(!filter.identity_policy_denies(&identity(key), "kms:Decrypt", "*", &context));
        principal.inline_policies.insert("deny".into(), r#"{"Statement":{"Effect":"Deny","Action":"kms:Decrypt","Resource":"*","Condition":{"StringEquals":{"kms:ViaService":"s3.us-east-1.amazonaws.com"}}}}"#.into());
        store.update_user(account, "alice", |user| {
            user.inline_policies = principal.inline_policies.clone();
        });
        assert!(filter.identity_policy_denies(&identity(key), "kms:Decrypt", "*", &context));
        assert!(!filter.identity_policy_denies(
            &identity(key),
            "kms:GenerateDataKey",
            "*",
            &context
        ));
        store.update_user(account, "alice", |user| {
            user.access_keys[0].status = "Inactive".into();
        });
        assert!(filter.identity_policy_denies(
            &identity(key),
            "kms:GenerateDataKey",
            "*",
            &context
        ));
    }

    #[test]
    fn verified_user_attributes_replace_claims_and_preserve_network_conditions() {
        let (filter, store) = filter();
        let account = "000000000000";
        let key = "AKIAATTRIBUTES";
        let mut user = user_with_key("alice", key);
        user.user_id = "AIDAALICE".into();
        user.tags.insert("Team".into(), "platform".into());
        user.inline_policies.insert("conditional".into(), serde_json::json!({"Statement":{
            "Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{
                "StringEquals":{"aws:PrincipalArn":user.arn,"aws:PrincipalAccount":account,"aws:PrincipalType":"User","aws:userid":"AIDAALICE","aws:PrincipalTag/team":"platform","iam:PassedToService":"lambda.amazonaws.com"},
                "Bool":{"aws:PrincipalIsAWSService":"false","aws:SecureTransport":"true"},
                "IpAddress":{"aws:SourceIp":"2001:db8::/32"}
            }
        }}).to_string());
        store.create_user(account, user);
        let context = BTreeMap::from([
            (
                "AWS:PrincipalArn".into(),
                vec![format!("arn:aws:iam::{account}:root")],
            ),
            ("aws:userid".into(), vec!["FORGED".into()]),
            ("aws:principaltag/team".into(), vec!["attacker".into()]),
            ("aws:principaltag/admin".into(), vec!["true".into()]),
            ("aws:securetransport".into(), vec!["true".into()]),
            ("aws:sourceip".into(), vec!["2001:db8::42".into()]),
            (
                "iam:passedtoservice".into(),
                vec!["lambda.amazonaws.com".into()],
            ),
        ]);
        let mut claimed = identity(key);
        claimed.arn = Some(format!("arn:aws:iam::{account}:root"));
        assert!(filter
            .check_with_context(
                EnforcementMode::Strict,
                &claimed,
                "iam:PassRole",
                "*",
                &context
            )
            .is_ok());
        for (attribute, value) in [
            (
                "aws:PrincipalArn",
                format!("arn:aws:iam::{account}:user/alice"),
            ),
            ("aws:userid", "AIDAALICE".into()),
        ] {
            store.update_user(account, "alice", |user| { user.inline_policies.insert("deny".into(), serde_json::json!({"Statement":{
                "Effect":"Deny","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{attribute:value}}
            }}).to_string()); });
            assert!(filter
                .check_with_context(
                    EnforcementMode::Strict,
                    &claimed,
                    "iam:PassRole",
                    "*",
                    &context
                )
                .is_err());
            assert!(filter.identity_policy_denies(&claimed, "iam:PassRole", "*", &context));
        }
        let mut actual = context;
        filter
            .resolve_caller(account, key)
            .unwrap()
            .apply_attributes(&mut actual);
        assert!(!actual.contains_key("AWS:PrincipalArn"));
        assert!(!actual.contains_key("aws:principaltag/admin"));
        assert_eq!(
            actual["aws:principalarn"],
            [format!("arn:aws:iam::{account}:user/alice")]
        );
    }

    #[test]
    fn known_session_userid_is_available_but_delegated_roles_cannot_forge_one() {
        let (filter, store, sessions) = filter_with_sessions();
        let account = "000000000000";
        let role_arn = build_iam_arn(account, "role", "/", "worker");
        store.create_role(account, IamRole {
            role_name:"worker".into(),role_id:"AROAWORKER".into(),arn:role_arn.clone(),path:"/".into(),create_date:"2026-01-01T00:00:00Z".into(),
            assume_role_policy_document:"{}".into(),description:None,max_session_duration:3600,tags:BTreeMap::from([("Team".into(),"platform".into())]),
            attached_policies:Vec::new(),permission_boundary:None,inline_policies:BTreeMap::from([("allow".into(),serde_json::json!({"Statement":{
                "Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalArn":role_arn,"aws:PrincipalType":"AssumedRole","aws:PrincipalTag/team":"platform"}}
            }}).to_string())]),
        });
        let credentials =
            crate::sts::issue_service_role_credentials(&store, &sessions, account, &role_arn)
                .unwrap();
        let session = sessions.resolve(&credentials.access_key_id).unwrap();
        let spoofed = BTreeMap::from([("aws:userid".into(), vec!["AROAWORKER:forged".into()])]);
        let caller = filter
            .resolve_caller(account, &credentials.access_key_id)
            .unwrap();
        assert_eq!(
            caller.attribute("aws:principalarn"),
            Some(role_arn.as_str())
        );
        assert_eq!(
            caller.attribute("aws:userid"),
            Some(session.user_id.as_str())
        );
        assert_eq!(
            filter
                .role_context(account, &role_arn)
                .unwrap()
                .attribute("aws:userid"),
            None
        );
        assert!(filter
            .check_with_context(
                EnforcementMode::Strict,
                &identity(&credentials.access_key_id),
                "iam:PassRole",
                "*",
                &spoofed
            )
            .is_ok());
        assert!(filter
            .check_role_with_context(account, &role_arn, "iam:PassRole", "*", &spoofed)
            .is_ok());
        store.update_role(account, "worker", |role| { role.inline_policies.insert("deny".into(), serde_json::json!({"Statement":{
            "Effect":"Deny","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"aws:userid":session.user_id}}
        }}).to_string()); });
        assert!(filter.identity_policy_denies(
            &identity(&credentials.access_key_id),
            "iam:PassRole",
            "*",
            &spoofed
        ));
        assert!(!filter.role_policy_denies(account, &role_arn, "iam:PassRole", "*", &spoofed));
        store.update_role(account, "worker", |role| { role.inline_policies.remove("deny"); role.inline_policies.insert("allow".into(), serde_json::json!({"Statement":{
            "Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"aws:userid":session.user_id}}
        }}).to_string()); });
        assert!(filter
            .check_with_context(
                EnforcementMode::Strict,
                &identity(&credentials.access_key_id),
                "iam:PassRole",
                "*",
                &spoofed
            )
            .is_ok());
        assert!(filter
            .check_role_with_context(account, &role_arn, "iam:PassRole", "*", &spoofed)
            .is_err());
    }

    #[test]
    fn permissive_never_blocks() {
        let (f, _store) = filter();
        // No caller resolvable, but permissive returns Ok regardless.
        assert!(f
            .check(
                EnforcementMode::Permissive,
                &identity("AKIAZZZ"),
                "iam:CreateUser",
                "*"
            )
            .is_ok());
    }

    #[test]
    fn strict_denies_unresolvable_caller() {
        let (f, _store) = filter();
        let error = f
            .check(
                EnforcementMode::Strict,
                &identity("AKIAUNKNOWN"),
                "iam:CreateUser",
                "*",
            )
            .unwrap_err();
        assert!(matches!(error, IamStsError::AccessDenied(_)));

        let missing_key = RequestIdentity {
            account_id: "000000000000".to_string(),
            access_key_id: None,
            arn: None,
        };
        assert!(matches!(
            f.check(EnforcementMode::Strict, &missing_key, "iam:CreateUser", "*"),
            Err(IamStsError::AccessDenied(_))
        ));
    }

    #[test]
    fn strict_denies_user_without_allow() {
        let (f, store) = filter();
        store.create_user("000000000000", user_with_key("bob", "AKIABOB"));
        let err = f
            .check(
                EnforcementMode::Strict,
                &identity("AKIABOB"),
                "iam:CreateUser",
                "*",
            )
            .unwrap_err();
        assert!(matches!(err, IamStsError::AccessDenied(_)));
    }

    #[test]
    fn strict_denies_malformed_or_dangling_policy_state() {
        let (filter, store) = filter();
        let mut malformed = user_with_key("malformed", "AKIAMALFORMED");
        malformed.inline_policies.insert(
            "bad".to_string(),
            r#"{"Statement":{"Action":"*","Resource":"*"}}"#.to_string(),
        );
        store.create_user("000000000000", malformed);
        assert!(matches!(
            filter.check(
                EnforcementMode::Strict,
                &identity("AKIAMALFORMED"),
                "iam:CreateUser",
                "*"
            ),
            Err(IamStsError::AccessDenied(_))
        ));

        let mut dangling = user_with_key("dangling", "AKIADANGLING");
        dangling.inline_policies.insert(
            "allow".to_string(),
            r#"{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#.to_string(),
        );
        dangling.permission_boundary = Some("arn:aws:iam::000000000000:policy/missing".to_string());
        store.create_user("000000000000", dangling);
        assert!(matches!(
            filter.check(
                EnforcementMode::Strict,
                &identity("AKIADANGLING"),
                "iam:CreateUser",
                "*"
            ),
            Err(IamStsError::AccessDenied(_))
        ));
    }

    #[test]
    fn strict_session_policy_limits_role_permissions() {
        let (filter, store, sessions) = filter_with_sessions();
        let role_arn = build_iam_arn("000000000000", "role", "/", "app");
        let mut inline_policies = BTreeMap::new();
        inline_policies.insert(
            "allow-all".to_string(),
            r#"{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#.to_string(),
        );
        store.create_role(
            "000000000000",
            IamRole {
                role_name: "app".to_string(),
                role_id: "AROAEXAMPLE".to_string(),
                arn: role_arn.clone(),
                path: "/".to_string(),
                create_date: "2020-01-01T00:00:00Z".to_string(),
                assume_role_policy_document: r#"{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}}"#.to_string(),
                description: None,
                max_session_duration: 3600,
                tags: BTreeMap::new(),
                attached_policies: Vec::new(),
                inline_policies,
                permission_boundary: None,
            },
        );
        let session_policy =
            r#"{"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}}"#;
        let query = QueryRequest::parse(
            format!(
                "Action=AssumeRole&RoleArn={role_arn}&RoleSessionName=s1&Policy={}",
                urlencode_doc(session_policy)
            )
            .as_bytes(),
        );
        let response = assume_role(&store, &sessions, "000000000000", &query).unwrap();
        let access_key = response
            .split("<AccessKeyId>")
            .nth(1)
            .and_then(|value| value.split("</AccessKeyId>").next())
            .unwrap();
        assert!(filter
            .check(
                EnforcementMode::Strict,
                &identity(access_key),
                "iam:GetUser",
                "*"
            )
            .is_ok());
        assert!(matches!(
            filter.check(
                EnforcementMode::Strict,
                &identity(access_key),
                "iam:CreateUser",
                "*"
            ),
            Err(IamStsError::AccessDenied(_))
        ));
    }

    #[test]
    fn strict_allows_user_with_matching_allow() {
        let (f, store) = filter();
        let mut user = user_with_key("alice", "AKIAALICE");
        user.inline_policies.insert(
            "allow-all".to_string(),
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#.to_string(),
        );
        store.create_user("000000000000", user);
        assert!(f
            .check(
                EnforcementMode::Strict,
                &identity("AKIAALICE"),
                "iam:CreateUser",
                "*"
            )
            .is_ok());
    }

    #[test]
    fn strict_explicit_deny_overrides_allow() {
        let (f, store) = filter();
        let mut user = user_with_key("carol", "AKIACAROL");
        user.inline_policies.insert(
            "p".to_string(),
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:DeleteUser","Resource":"*"}]}"#.to_string(),
        );
        store.create_user("000000000000", user);
        assert!(f
            .check(
                EnforcementMode::Strict,
                &identity("AKIACAROL"),
                "iam:CreateUser",
                "*"
            )
            .is_ok());
        let err = f
            .check(
                EnforcementMode::Strict,
                &identity("AKIACAROL"),
                "iam:DeleteUser",
                "*",
            )
            .unwrap_err();
        assert!(matches!(err, IamStsError::AccessDenied(_)));
    }
    #[test]
    fn global_time_uses_one_live_instant_and_cannot_be_forged() {
        let mut context = BTreeMap::from([
            (
                "AWS:CurrentTime".into(),
                vec!["1900-01-01T00:00:00Z".into()],
            ),
            ("AWS:EpochTime".into(), vec!["0".into()]),
        ]);
        let before = time::OffsetDateTime::now_utc().unix_timestamp();
        apply_time_attributes(&mut context);
        let after = time::OffsetDateTime::now_utc().unix_timestamp();
        let current = time::OffsetDateTime::parse(
            &context["aws:currenttime"][0],
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        let epoch = context["aws:epochtime"][0].parse::<i64>().unwrap();
        assert_eq!(current.unix_timestamp(), epoch);
        assert!((before..=after).contains(&epoch));
        assert!(!context.contains_key("AWS:CurrentTime"));
        assert!(!context.contains_key("AWS:EpochTime"));
        for condition in [
            serde_json::json!({"DateGreaterThan":{"aws:CurrentTime":"2000-01-01T00:00:00Z"}}),
            serde_json::json!({"NumericGreaterThan":{"aws:EpochTime":1}}),
        ] {
            let caller = CallerContext {
                identity: vec![PolicyDocument::parse(&serde_json::json!({"Statement":[
                    {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},
                    {"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":condition}
                ]}).to_string()).unwrap()],
                boundary: None,
                session: None,
                attributes: BTreeMap::new(),
                mfa_present: None,
            };
            let forged = BTreeMap::from([
                (
                    "aws:currenttime".into(),
                    vec!["1900-01-01T00:00:00Z".into()],
                ),
                ("aws:epochtime".into(), vec!["0".into()]),
            ]);
            assert!(!caller.allows("s3:GetObject", "arn:aws:s3:::bucket/key", &forged));
            assert!(caller.denies("s3:GetObject", "arn:aws:s3:::bucket/key", &forged));
        }
    }
}
