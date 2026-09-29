//! IAM enforcement mode and filter.
//!
//! Permissive by default (frictionless local testing); strict on opt-in via
//! `LOCALCLOUD_IAM_ENFORCEMENT` (alias `LOCALSTACK_IAM_ENFORCEMENT`).
//! In strict mode the filter resolves the caller's `Caller_Context` from the SigV4 access-key
//! identifier — a session (`ASIA…`) via the role behind its assumed-role ARN, or an IAM user
//! (`AKIA…`) with inline + attached + group-inherited policies and permission boundary — then
//! evaluates the action and rejects a `Deny` with `AccessDenied`/403. Missing identities and
//! unresolved or malformed policy state also fail closed with `AccessDenied`. The decision engine
//! is the same one that powers the Simulate APIs.
//! See Requirement 22.

use std::collections::BTreeMap;
use std::sync::Arc;

use localcloud_core::integration::RequestIdentity;

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
        for key in ["LOCALCLOUD_IAM_ENFORCEMENT", "LOCALSTACK_IAM_ENFORCEMENT"] {
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
struct CallerContext {
    identity: Vec<PolicyDocument>,
    boundary: Option<Vec<PolicyDocument>>,
    session: Option<Vec<PolicyDocument>>,
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
        let caller = self.resolve_caller(&identity.account_id, access_key_id)?;
        let req = EvalRequest {
            action: action.to_string(),
            resource: resource.to_string(),
            context: context.clone(),
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

    /// Evaluate one role's stored identity policies and permission boundary.
    pub fn check_role(
        &self,
        account: &str,
        role_arn: &str,
        action: &str,
        resource: &str,
    ) -> Result<(), IamStsError> {
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
        let request = EvalRequest {
            action: action.into(),
            resource: resource.into(),
            context: BTreeMap::new(),
        };
        match evaluate(&identity, boundary.as_deref(), None, &request) {
            Decision::Allowed => Ok(()),
            Decision::ImplicitDeny | Decision::ExplicitDeny => Err(IamStsError::AccessDenied(
                format!("role is not authorized for {action} on {resource}"),
            )),
        }
    }

    fn resolve_caller(
        &self,
        account: &str,
        access_key_id: &str,
    ) -> Result<CallerContext, IamStsError> {
        if let Some(session) = self.sessions.resolve(access_key_id) {
            if session.account != account {
                return Err(unresolvable_caller(access_key_id));
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
            });
        }

        let user = self
            .store
            .list_users(account)
            .into_iter()
            .find(|user| {
                user.access_keys
                    .iter()
                    .any(|key| key.access_key_id == access_key_id && key.status == "Active")
            })
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

fn unresolvable_caller(access_key_id: &str) -> IamStsError {
    IamStsError::AccessDenied(format!(
        "caller for access key {access_key_id} cannot be resolved"
    ))
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
}
