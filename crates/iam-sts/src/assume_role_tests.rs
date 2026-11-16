use super::*;
use crate::model::urlencode_doc;
use serde_json::{json, Value};

const ACCOUNT: &str = "000000000000";
const KEY: &str = "AKIAASSUMEROLETEST001";
const TARGET: &str = "arn:aws:iam::000000000000:role/target";
const USER: &str = "arn:aws:iam::000000000000:user/locallycloud-bootstrap";

fn fixture(trust: Value, identity: Option<Value>) -> Arc<IamStsState> {
    let state = Arc::new(IamStsState::with_mode(
        Arc::new(IamStore::new()),
        Arc::new(SessionStore::new()),
        EnforcementMode::Strict,
    ));
    seed_bootstrap_user(
        &state.store,
        ACCOUNT,
        BootstrapCredentials {
            access_key_id: KEY.into(),
            secret_access_key: "s".repeat(40),
        },
    );
    state
        .store
        .update_user(ACCOUNT, "locallycloud-bootstrap", |user| {
            user.inline_policies = identity
                .into_iter()
                .map(|policy| ("caller".into(), policy.to_string()))
                .collect();
        });
    iam::create_role(
        &state.store,
        ACCOUNT,
        &QueryRequest::parse(
            format!(
                "RoleName=target&AssumeRolePolicyDocument={}",
                urlencode_doc(&trust.to_string())
            )
            .as_bytes(),
        ),
    )
    .unwrap();
    state
}

fn trust(principal: &str) -> Value {
    json!({"Statement":{"Effect":"Allow","Principal":{"AWS":principal},"Action":"sts:AssumeRole"}})
}

fn allow() -> Value {
    json!({"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":TARGET}})
}

fn request(key: &str, extra: &str) -> ServiceRequest {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("AWS4-HMAC-SHA256 Credential={key}/20261116/us-east-1/sts/aws4_request")
            .parse()
            .unwrap(),
    );
    ServiceRequest {
        method: http::Method::POST,
        uri: "/".parse().unwrap(),
        headers,
        body: format!("Action=AssumeRole&RoleArn={TARGET}&RoleSessionName=valid-session{extra}")
            .into(),
        region: "us-east-1".into(),
        account_id: ACCOUNT.into(),
        request_id: "strict-trust".into(),
    }
}

async fn response(state: Arc<IamStsState>, key: &str, extra: &str) -> (u16, String) {
    let response = StsHandler { state }.handle(request(key, extra)).await;
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn trust_is_mandatory_and_account_delegation_requires_identity_allow() {
    for (principal, identity, expected) in [
        (
            "arn:aws:iam::000000000000:user/someone-else",
            Some(allow()),
            403,
        ),
        ("000000000000", None, 403),
        ("000000000000", Some(allow()), 200),
        (USER, None, 200),
    ] {
        let (status, body) = response(fixture(trust(principal), identity), KEY, "").await;
        assert_eq!(status, expected, "{principal}: {body}");
        assert_eq!(body.contains("<Credentials>"), expected == 200);
    }
}

#[tokio::test]
async fn direct_trust_does_not_override_identity_or_trust_deny() {
    let deny = json!({"Statement":{"Effect":"Deny","Action":"sts:AssumeRole","Resource":TARGET}});
    assert_eq!(
        response(fixture(trust(USER), Some(deny)), KEY, "").await.0,
        403
    );
    let mut document = trust(USER);
    document["Statement"] = json!([
        document["Statement"].clone(),
        {"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}
    ]);
    let state = fixture(trust(USER), Some(allow()));
    state.store.update_role(ACCOUNT, "target", |role| {
        role.assume_role_policy_document = document.to_string()
    });
    assert_eq!(response(state, KEY, "").await.0, 403);
}

#[tokio::test]
async fn trust_conditions_use_verified_caller_and_external_id() {
    let mut document = trust("000000000000");
    document["Statement"]["Condition"] = json!({"StringEquals":{
        "sts:ExternalId":"expected-id", "aws:PrincipalArn":USER,
        "sts:RoleSessionName":"valid-session"
    }});
    let state = fixture(document, Some(allow()));
    assert_eq!(response(state.clone(), KEY, "").await.0, 403);
    assert_eq!(
        response(state.clone(), KEY, "&ExternalId=incorrect")
            .await
            .0,
        403
    );
    assert_eq!(response(state, KEY, "&ExternalId=expected-id").await.0, 200);
    let mut document = trust(USER);
    document["Statement"]["Condition"] = json!({"UnsupportedIfExists":{"aws:PrincipalArn":USER}});
    let state = fixture(trust(USER), Some(allow()));
    state.store.update_role(ACCOUNT, "target", |role| {
        role.assume_role_policy_document = document.to_string()
    });
    assert_eq!(response(state, KEY, "").await.0, 403);
}

#[tokio::test]
async fn duration_limits_reject_malformed_extreme_and_role_chained_sessions() {
    let state = fixture(trust(USER), Some(allow()));
    for value in [
        "not-a-number",
        "0",
        "899",
        "3601",
        "86400",
        "9223372036854775807",
    ] {
        let (status, body) =
            response(state.clone(), KEY, &format!("&DurationSeconds={value}")).await;
        assert_eq!(status, 400, "{value}: {body}");
        assert!(!body.contains("<Credentials>"));
    }
    assert_eq!(
        response(state.clone(), KEY, "&DurationSeconds=900").await.0,
        200
    );
    state.store.update_role(ACCOUNT, "target", |role| {
        role.max_session_duration = 7200;
        role.assume_role_policy_document = trust(TARGET).to_string();
        role.inline_policies
            .insert("chain".into(), allow().to_string());
    });
    let session =
        sts::issue_service_role_credentials(&state.store, &state.sessions, ACCOUNT, TARGET)
            .unwrap();
    assert_eq!(
        response(
            state.clone(),
            &session.access_key_id,
            "&DurationSeconds=3600"
        )
        .await
        .0,
        200
    );
    assert_eq!(
        response(state, &session.access_key_id, "&DurationSeconds=3601")
            .await
            .0,
        400
    );
}

#[tokio::test]
async fn direct_role_trust_respects_session_policy_limit() {
    let state = fixture(trust(TARGET), None);
    let query = QueryRequest::parse(
        format!(
            "RoleArn={TARGET}&RoleSessionName=limited&Policy={}",
            urlencode_doc(
                &json!({"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}})
                    .to_string()
            )
        )
        .as_bytes(),
    );
    let xml = sts::assume_role(&state.store, &state.sessions, ACCOUNT, &query).unwrap();
    let key = xml
        .split("<AccessKeyId>")
        .nth(1)
        .unwrap()
        .split("</AccessKeyId>")
        .next()
        .unwrap();
    assert_eq!(response(state, key, "").await.0, 403);
}

#[tokio::test]
async fn strict_federation_never_issues_credentials_for_unverified_assertions() {
    let state = fixture(trust(USER), Some(allow()));
    for action in ["AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"] {
        let mut req = request(
            KEY,
            "&WebIdentityToken=invalid&PrincipalArn=invalid&SAMLAssertion=invalid",
        );
        req.body = String::from_utf8(req.body.to_vec())
            .unwrap()
            .replace("Action=AssumeRole&", &format!("Action={action}&"))
            .into();
        let response = StsHandler {
            state: state.clone(),
        }
        .handle(req)
        .await;
        assert_eq!(response.status(), 403);
        let body = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("<Credentials>"));
    }
}

#[test]
fn role_max_session_duration_is_validated_before_mutating() {
    let state = fixture(trust(USER), None);
    for value in ["invalid", "0", "3599", "43201", "4294967296"] {
        let q =
            QueryRequest::parse(format!("RoleName=target&MaxSessionDuration={value}").as_bytes());
        assert!(matches!(
            iam::update_role(&state.store, ACCOUNT, &q),
            Err(IamStsError::ValidationError(_))
        ));
        assert_eq!(
            state
                .store
                .get_role(ACCOUNT, "target")
                .unwrap()
                .max_session_duration,
            3600
        );
    }
}

#[tokio::test]
async fn direct_role_trust_allows_without_identity_allow_but_respects_boundary() {
    let state = fixture(trust(TARGET), None);
    let session =
        sts::issue_service_role_credentials(&state.store, &state.sessions, ACCOUNT, TARGET)
            .unwrap();
    assert_eq!(
        response(state.clone(), &session.access_key_id, "").await.0,
        200
    );
    iam::create_policy(
        &state.store,
        ACCOUNT,
        &QueryRequest::parse(
            format!(
                "PolicyName=boundary&PolicyDocument={}",
                urlencode_doc(
                    &json!({"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}})
                        .to_string()
                )
            )
            .as_bytes(),
        ),
    )
    .unwrap();
    state.store.update_role(ACCOUNT, "target", |role| {
        role.permission_boundary = Some("arn:aws:iam::000000000000:policy/boundary".into())
    });
    assert_eq!(response(state, &session.access_key_id, "").await.0, 403);
}

#[tokio::test]
async fn unsupported_session_attributes_are_rejected_instead_of_ignored() {
    let state = fixture(trust(USER), Some(allow()));
    for extra in [
        "&PolicyArns.member.1.arn=arn:aws:iam::000000000000:policy/limit",
        "&PolicyArns.member.2.arn=",
        "&Tags.member.1.Key=team&Tags.member.1.Value=finance",
        "&TransitiveTagKeys.member.1=team",
        "&SourceIdentity=somebody",
        "&ProvidedContexts.member.1.ContextAssertion=unverified",
    ] {
        let (status, body) = response(state.clone(), KEY, extra).await;
        assert_eq!(status, 400, "{extra}: {body}");
        assert!(!body.contains("<Credentials>"));
    }
    let (status, body) = response(state, KEY, "&SerialNumber=unverified&TokenCode=123456").await;
    assert_eq!(status, 403, "{body}");
}

#[tokio::test]
async fn mfa_presence_distinguishes_long_term_keys_from_registered_sessions() {
    for (operator, expected) in [("Bool", 403), ("BoolIfExists", 200)] {
        for key in [KEY, "ASIALONGTERMNOTSESSION"] {
            let mut document = trust(USER);
            document["Statement"]["Condition"] =
                json!({operator:{"aws:MultiFactorAuthPresent":"false"}});
            let state = fixture(document, Some(allow()));
            if key != KEY {
                state
                    .store
                    .update_user(ACCOUNT, "locallycloud-bootstrap", |user| {
                        user.access_keys[0].access_key_id = key.into();
                    });
            }
            let (status, body) = response(state, key, "").await;
            assert_eq!(status, expected, "{operator} {key}: {body}");
            assert_eq!(body.contains("<Credentials>"), expected == 200);
        }
    }
    let mut document = trust(TARGET);
    document["Statement"]["Condition"] = json!({"Bool":{"aws:MultiFactorAuthPresent":"false"}});
    let state = fixture(document, None);
    state.store.update_role(ACCOUNT, "target", |role| {
        role.inline_policies
            .insert("chain".into(), allow().to_string());
    });
    let session =
        sts::issue_service_role_credentials(&state.store, &state.sessions, ACCOUNT, TARGET)
            .unwrap();
    assert_eq!(response(state, &session.access_key_id, "").await.0, 200);
}

#[tokio::test]
async fn strict_get_session_token_rejects_unverified_mfa_assertions() {
    let state = fixture(trust(USER), None);
    for parameters in [
        "",
        "&SerialNumber=arn:aws:iam::000000000000:mfa/device",
        "&TokenCode=000000",
        "&SerialNumber=arn:aws:iam::000000000000:mfa/device&TokenCode=000000",
    ] {
        let mut request = request(KEY, "");
        request.body = format!("Action=GetSessionToken{parameters}").into();
        let response = StsHandler {
            state: state.clone(),
        }
        .handle(request)
        .await;
        let expected = if parameters.is_empty() { 200 } else { 403 };
        assert_eq!(response.status().as_u16(), expected);
        let body = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&body).contains("<Credentials>"),
            expected == 200
        );
    }
}
