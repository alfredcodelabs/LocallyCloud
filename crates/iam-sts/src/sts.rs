//! STS temporary-credential generation, session store, and operations.
//!
//! Every STS operation returns the inner `<{Action}Result>` XML body; the service layer
//! wraps it in the Query response envelope. Temporary credentials use the `ASIA` prefix and
//! are registered in the `SessionStore` keyed by their AccessKeyId so `GetCallerIdentity`
//! and strict-mode enforcement can resolve the caller.

use dashmap::DashMap;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::error::IamStsError;
use crate::ids;
use crate::model::{IamRole, IamUser};
use crate::policy::PolicyDocument;
use crate::query::{text_el, QueryRequest};
use crate::store::IamStore;

/// Default credential lifetimes (seconds), per AWS.
const ASSUME_ROLE_DEFAULT: i64 = 3600;
const SESSION_TOKEN_DEFAULT: i64 = 43200;

/// A generated temporary credential.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: String,
}

impl Credentials {
    fn generate(duration_seconds: i64) -> Credentials {
        let expiration = (OffsetDateTime::now_utc() + Duration::seconds(duration_seconds))
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
        Credentials {
            access_key_id: ids::unique_id(ids::TEMP_CREDENTIAL),
            secret_access_key: ids::secret_access_key(),
            session_token: ids::session_token(),
            expiration,
        }
    }

    fn xml(&self) -> String {
        format!(
            "<Credentials>{}{}{}{}</Credentials>",
            text_el("AccessKeyId", &self.access_key_id),
            text_el("SecretAccessKey", &self.secret_access_key),
            text_el("SessionToken", &self.session_token),
            text_el("Expiration", &self.expiration),
        )
    }
}

/// A registered temporary-credential session.
#[derive(Clone)]
pub struct Session {
    pub account: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub arn: String,
    pub user_id: String,
    pub role_arn: Option<String>,
    pub session_policy: Option<String>,
    expires_at: OffsetDateTime,
}

/// Sessions keyed by AccessKeyId. Expired sessions are removed on resolve.
#[derive(Default)]
pub struct SessionStore {
    sessions: DashMap<String, Session>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn register(&self, access_key_id: &str, session: Session) {
        self.sessions.insert(access_key_id.to_string(), session);
    }

    /// Resolve a caller by AccessKeyId, removing and ignoring an expired session.
    pub fn resolve(&self, access_key_id: &str) -> Option<Session> {
        let expired = self
            .sessions
            .get(access_key_id)
            .map(|s| s.expires_at <= OffsetDateTime::now_utc())
            .unwrap_or(false);
        if expired {
            self.sessions.remove(access_key_id);
            return None;
        }
        self.sessions.get(access_key_id).map(|s| s.clone())
    }
}

fn duration_or(q: &QueryRequest, default: i64) -> i64 {
    q.get("DurationSeconds")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(default)
}

struct SessionRegistration<'a> {
    account: &'a str,
    arn: &'a str,
    user_id: &'a str,
    duration: i64,
    role_arn: Option<&'a str>,
    session_policy: Option<&'a str>,
}

fn register_session(
    sessions: &SessionStore,
    creds: &Credentials,
    registration: SessionRegistration<'_>,
) {
    sessions.register(
        &creds.access_key_id,
        Session {
            account: registration.account.to_string(),
            secret_access_key: creds.secret_access_key.clone(),
            session_token: creds.session_token.clone(),
            arn: registration.arn.to_string(),
            user_id: registration.user_id.to_string(),
            role_arn: registration.role_arn.map(str::to_string),
            session_policy: registration.session_policy.map(str::to_string),
            expires_at: OffsetDateTime::now_utc() + Duration::seconds(registration.duration),
        },
    );
}

/// Short role name from a role ARN (`...:role/path/name` → `name`).
fn role_name_from_arn(arn: &str) -> &str {
    arn.rsplit('/').next().unwrap_or(arn)
}

fn resolve_role(store: &IamStore, account: &str, role_arn: &str) -> Result<IamRole, IamStsError> {
    let role = store
        .get_role(account, role_name_from_arn(role_arn))
        .ok_or_else(|| IamStsError::NoSuchEntity(format!("role {role_arn} cannot be found")))?;
    if role.arn != role_arn {
        return Err(IamStsError::NoSuchEntity(format!(
            "role {role_arn} cannot be found"
        )));
    }
    Ok(role)
}

/// Internal service execution session; caller authorization and trust are checked by IAM first.
pub fn issue_service_role_credentials(
    store: &IamStore,
    sessions: &SessionStore,
    account: &str,
    role_arn: &str,
) -> Result<Credentials, IamStsError> {
    let role = resolve_role(store, account, role_arn)?;
    let role_name = role_name_from_arn(role_arn);
    let session_name = format!("locallycloud-lambda-{}", uuid::Uuid::new_v4().simple());
    let creds = Credentials::generate(ASSUME_ROLE_DEFAULT);
    let assumed_arn = format!("arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}");
    let user_id = format!("{}:{session_name}", role.role_id);
    register_session(
        sessions,
        &creds,
        SessionRegistration {
            account,
            arn: &assumed_arn,
            user_id: &user_id,
            duration: ASSUME_ROLE_DEFAULT,
            role_arn: Some(role_arn),
            session_policy: None,
        },
    );
    Ok(creds)
}

fn session_policy(q: &QueryRequest) -> Result<Option<&str>, IamStsError> {
    let policy = q.get("Policy");
    if let Some(document) = policy {
        PolicyDocument::parse(document)?;
    }
    Ok(policy)
}

pub fn assume_role(
    store: &IamStore,
    sessions: &SessionStore,
    account: &str,
    q: &QueryRequest,
) -> Result<String, IamStsError> {
    let role_arn = q.require("RoleArn")?;
    let session_name = q.require("RoleSessionName")?;
    let duration = duration_or(q, ASSUME_ROLE_DEFAULT);
    let role = resolve_role(store, account, role_arn)?;
    let session_policy = session_policy(q)?;
    let role_name = role_name_from_arn(role_arn);

    let creds = Credentials::generate(duration);
    let assumed_arn = format!("arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}");
    let assumed_role_id = format!("{}:{session_name}", role.role_id);
    register_session(
        sessions,
        &creds,
        SessionRegistration {
            account,
            arn: &assumed_arn,
            user_id: &assumed_role_id,
            duration,
            role_arn: Some(role_arn),
            session_policy,
        },
    );

    Ok(format!(
        "{}<AssumedRoleUser>{}{}</AssumedRoleUser>",
        creds.xml(),
        text_el("AssumedRoleId", &assumed_role_id),
        text_el("Arn", &assumed_arn),
    ))
}

pub fn assume_role_with_web_identity(
    store: &IamStore,
    sessions: &SessionStore,
    account: &str,
    q: &QueryRequest,
) -> Result<String, IamStsError> {
    let role_arn = q.require("RoleArn")?;
    let session_name = q.require("RoleSessionName")?;
    let _token = q.require("WebIdentityToken")?;
    let duration = duration_or(q, ASSUME_ROLE_DEFAULT);
    let role = resolve_role(store, account, role_arn)?;
    let session_policy = session_policy(q)?;
    let role_name = role_name_from_arn(role_arn);
    let creds = Credentials::generate(duration);
    let assumed_arn = format!("arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}");
    let assumed_role_id = format!("{}:{session_name}", role.role_id);
    register_session(
        sessions,
        &creds,
        SessionRegistration {
            account,
            arn: &assumed_arn,
            user_id: &assumed_role_id,
            duration,
            role_arn: Some(role_arn),
            session_policy,
        },
    );
    let subject = q.get("SubjectFromWebIdentityToken").unwrap_or("subject");
    let provider = q.get("ProviderId").unwrap_or("provider");
    Ok(format!(
        "{}<AssumedRoleUser>{}{}</AssumedRoleUser>{}{}",
        creds.xml(),
        text_el("AssumedRoleId", &assumed_role_id),
        text_el("Arn", &assumed_arn),
        text_el("SubjectFromWebIdentityToken", subject),
        text_el("Provider", provider),
    ))
}

pub fn assume_role_with_saml(
    store: &IamStore,
    sessions: &SessionStore,
    account: &str,
    q: &QueryRequest,
) -> Result<String, IamStsError> {
    let role_arn = q.require("RoleArn")?;
    let _principal = q.require("PrincipalArn")?;
    let _assertion = q.require("SAMLAssertion")?;
    let duration = duration_or(q, ASSUME_ROLE_DEFAULT);
    let role = resolve_role(store, account, role_arn)?;
    let session_policy = session_policy(q)?;
    let role_name = role_name_from_arn(role_arn);
    let session_name = "saml";
    let creds = Credentials::generate(duration);
    let assumed_arn = format!("arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}");
    let assumed_role_id = format!("{}:{session_name}", role.role_id);
    register_session(
        sessions,
        &creds,
        SessionRegistration {
            account,
            arn: &assumed_arn,
            user_id: &assumed_role_id,
            duration,
            role_arn: Some(role_arn),
            session_policy,
        },
    );
    Ok(format!(
        "{}<AssumedRoleUser>{}{}</AssumedRoleUser>{}",
        creds.xml(),
        text_el("AssumedRoleId", &assumed_role_id),
        text_el("Arn", &assumed_arn),
        text_el("Issuer", q.get("Issuer").unwrap_or("issuer")),
    ))
}

pub fn get_caller_identity(account: &str, caller: Option<Session>) -> String {
    let (arn, user_id) = match caller {
        Some(s) => (s.arn, s.user_id),
        None => (format!("arn:aws:iam::{account}:root"), account.to_string()),
    };
    format!(
        "{}{}{}",
        text_el("UserId", &user_id),
        text_el("Account", account),
        text_el("Arn", &arn),
    )
}

/// Return the stable IAM identity associated with an active user access key.
pub fn get_iam_caller_identity(account: &str, user: &IamUser) -> String {
    format!(
        "{}{}{}",
        text_el("UserId", &user.user_id),
        text_el("Account", account),
        text_el("Arn", &user.arn),
    )
}

pub fn get_session_token(sessions: &SessionStore, account: &str, q: &QueryRequest) -> String {
    let duration = duration_or(q, SESSION_TOKEN_DEFAULT);
    let creds = Credentials::generate(duration);
    let arn = format!("arn:aws:iam::{account}:root");
    register_session(
        sessions,
        &creds,
        SessionRegistration {
            account,
            arn: &arn,
            user_id: account,
            duration,
            role_arn: None,
            session_policy: None,
        },
    );
    creds.xml()
}

pub fn get_federation_token(
    sessions: &SessionStore,
    account: &str,
    q: &QueryRequest,
) -> Result<String, IamStsError> {
    let name = q.require("Name")?;
    let duration = duration_or(q, SESSION_TOKEN_DEFAULT);
    let session_policy = session_policy(q)?;
    let creds = Credentials::generate(duration);
    let federated_arn = format!("arn:aws:sts::{account}:federated-user/{name}");
    let federated_id = format!("{account}:{name}");
    register_session(
        sessions,
        &creds,
        SessionRegistration {
            account,
            arn: &federated_arn,
            user_id: &federated_id,
            duration,
            role_arn: None,
            session_policy,
        },
    );
    Ok(format!(
        "{}<FederatedUser>{}{}</FederatedUser>",
        creds.xml(),
        text_el("FederatedUserId", &federated_id),
        text_el("Arn", &federated_arn),
    ))
}

pub fn decode_authorization_message(q: &QueryRequest) -> Result<String, IamStsError> {
    let encoded = q.require("EncodedMessage")?;
    // locallycloud does not encrypt authorization messages; echo the input back as the
    // decoded message so SDKs receive a well-formed response.
    Ok(text_el("DecodedMessage", encoded))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::arn::build_iam_arn;
    use crate::model::{urlencode_doc, IamRole};

    fn add_role(store: &IamStore, account: &str, path: &str, name: &str) -> String {
        let arn = build_iam_arn(account, "role", path, name);
        store.create_role(
            account,
            IamRole {
                role_name: name.to_string(),
                role_id: "AROAEXAMPLE".to_string(),
                arn: arn.clone(),
                path: path.to_string(),
                create_date: "2020-01-01T00:00:00Z".to_string(),
                assume_role_policy_document: r#"{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}}"#.to_string(),
                description: None,
                max_session_duration: 3600,
                tags: BTreeMap::new(),
                attached_policies: Vec::new(),
                inline_policies: BTreeMap::new(),
                permission_boundary: None,
            },
        );
        arn
    }

    #[test]
    fn assume_role_returns_credentials_and_user() {
        let store = IamStore::new();
        let sessions = SessionStore::new();
        let role_arn = add_role(&store, "1", "/", "app");
        let q = QueryRequest::parse(
            format!("Action=AssumeRole&RoleArn={role_arn}&RoleSessionName=s1").as_bytes(),
        );
        let body = assume_role(&store, &sessions, "1", &q).unwrap();
        assert!(body.contains("<AccessKeyId>ASIA"));
        assert!(body.contains("assumed-role/app/s1"));
    }

    #[test]
    fn assume_role_requires_arn_and_session() {
        let store = IamStore::new();
        let sessions = SessionStore::new();
        let q = QueryRequest::parse(b"Action=AssumeRole&RoleArn=arn:aws:iam::1:role/app");
        assert!(matches!(
            assume_role(&store, &sessions, "1", &q),
            Err(IamStsError::ValidationError(_))
        ));
    }

    #[test]
    fn assume_role_requires_exact_existing_role_arn() {
        let store = IamStore::new();
        let sessions = SessionStore::new();
        add_role(&store, "1", "/team/", "app");
        for role_arn in [
            "arn:aws:iam::1:role/missing",
            "arn:aws:iam::1:role/app",
            "arn:aws:iam::2:role/team/app",
        ] {
            let q = QueryRequest::parse(
                format!("Action=AssumeRole&RoleArn={role_arn}&RoleSessionName=s1").as_bytes(),
            );
            assert!(matches!(
                assume_role(&store, &sessions, "1", &q),
                Err(IamStsError::NoSuchEntity(_))
            ));
        }
    }

    #[test]
    fn registered_session_keeps_role_and_session_policy() {
        let store = IamStore::new();
        let sessions = SessionStore::new();
        let role_arn = add_role(&store, "1", "/", "app");
        let policy = r#"{"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}}"#;
        let q = QueryRequest::parse(
            format!(
                "Action=AssumeRole&RoleArn={role_arn}&RoleSessionName=s1&Policy={}",
                urlencode_doc(policy)
            )
            .as_bytes(),
        );
        let body = assume_role(&store, &sessions, "1", &q).unwrap();
        let akid = body
            .split("<AccessKeyId>")
            .nth(1)
            .and_then(|value| value.split("</AccessKeyId>").next())
            .unwrap();
        let session = sessions
            .resolve(akid)
            .expect("session registered under returned akid");
        assert_eq!(session.role_arn.as_deref(), Some(role_arn.as_str()));
        assert_eq!(session.session_policy.as_deref(), Some(policy));
        let identity = get_caller_identity("1", Some(session));
        assert!(identity.contains("assumed-role/app/s1"));
    }

    #[test]
    fn federated_assume_operations_reject_missing_roles() {
        let store = IamStore::new();
        let sessions = SessionStore::new();
        let web = QueryRequest::parse(
            b"Action=AssumeRoleWithWebIdentity&RoleArn=arn:aws:iam::1:role/missing&RoleSessionName=s1&WebIdentityToken=token",
        );
        let saml = QueryRequest::parse(
            b"Action=AssumeRoleWithSAML&RoleArn=arn:aws:iam::1:role/missing&PrincipalArn=arn:aws:iam::1:saml-provider/idp&SAMLAssertion=assertion",
        );
        assert!(matches!(
            assume_role_with_web_identity(&store, &sessions, "1", &web),
            Err(IamStsError::NoSuchEntity(_))
        ));
        assert!(matches!(
            assume_role_with_saml(&store, &sessions, "1", &saml),
            Err(IamStsError::NoSuchEntity(_))
        ));
    }

    #[test]
    fn caller_identity_defaults_to_root() {
        let identity = get_caller_identity("000000000000", None);
        assert!(identity.contains("arn:aws:iam::000000000000:root"));
        assert!(identity.contains("<Account>000000000000</Account>"));
    }

    #[test]
    fn federation_token_requires_name() {
        let sessions = SessionStore::new();
        let q = QueryRequest::parse(b"Action=GetFederationToken");
        assert!(matches!(
            get_federation_token(&sessions, "1", &q),
            Err(IamStsError::ValidationError(_))
        ));
    }
}
