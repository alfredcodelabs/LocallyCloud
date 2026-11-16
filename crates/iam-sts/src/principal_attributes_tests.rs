use super::*;
use locallycloud_core::integration::identity::CallerIdentity;
use serde_json::json;

const ACCOUNT: &str = "000000000000";
const KEY: &str = "AKIAAAAAAAAAAAAAAAAA";
const ROLE: &str = "arn:aws:iam::000000000000:role/execution";

fn fixture() -> (IamStsState, ServiceRoleAuthorizationRequest, String, String) {
    let state = IamStsState::with_mode(
        Arc::new(IamStore::new()),
        Arc::new(SessionStore::new()),
        EnforcementMode::Strict,
    );
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
            user.tags.insert("Team".into(), "platform".into());
        });
    let user = state
        .store
        .get_user(ACCOUNT, "locallycloud-bootstrap")
        .unwrap();
    state.store.create_role(ACCOUNT, crate::model::IamRole {
        role_name:"execution".into(),role_id:"AROAEXECUTION".into(),arn:ROLE.into(),path:"/".into(),create_date:"2026-01-01T00:00:00Z".into(),
        assume_role_policy_document:json!({"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}).to_string(),
        description:None,max_session_duration:3600,tags:BTreeMap::new(),attached_policies:Vec::new(),permission_boundary:None,
        inline_policies:BTreeMap::from([("invoke".into(),json!({"Statement":{"Effect":"Allow","Action":"lambda:InvokeFunction","Resource":"*"}}).to_string())]),
    });
    let request = ServiceRoleAuthorizationRequest {
        caller_context: BTreeMap::from([
            ("aws:securetransport".into(), vec!["true".into()]),
            ("aws:sourceip".into(), vec!["2001:db8::42".into()]),
            ("aws:principalarn".into(), vec!["forged-principal".into()]),
            ("aws:userid".into(), vec!["forged-userid".into()]),
            ("aws:principaltag/team".into(), vec!["forged-tag".into()]),
            ("iam:passedtoservice".into(), vec!["forged-service".into()]),
        ]),
        delegated_caller: None,
        source_arn: None,
        caller: RequestIdentity {
            account_id: ACCOUNT.into(),
            access_key_id: Some(KEY.into()),
            arn: Some("forged-arn".into()),
        },
        role_arn: ROLE.into(),
        service_principal: "lambda.amazonaws.com".into(),
        action: "lambda:InvokeFunction".into(),
        resource: "*".into(),
    };
    (state, request, user.arn, user.user_id)
}

#[test]
fn pass_role_ports_derive_principal_attributes_and_preserve_verified_network_context() {
    let (state, request, arn, user_id) = fixture();
    state.store.update_user(ACCOUNT, "locallycloud-bootstrap", |user| user.inline_policies = BTreeMap::from([("pass".into(),json!({"Statement":{
        "Effect":"Allow","Action":"iam:PassRole","Resource":ROLE,"Condition":{
            "StringEquals":{"aws:PrincipalArn":arn,"aws:userid":user_id,"aws:PrincipalTag/team":"platform","iam:PassedToService":"lambda.amazonaws.com"},
            "Bool":{"aws:SecureTransport":"true"},"IpAddress":{"aws:SourceIp":"2001:db8::/32"}
        }
    }}).to_string())]));
    assert_eq!(
        state.authorize_service_role_assignment(request.clone()),
        Ok(())
    );
    assert_eq!(state.authorize_service_role(request.clone()), Ok(()));
    for (key, value) in [("aws:PrincipalArn", arn), ("aws:userid", user_id)] {
        state.store.update_user(ACCOUNT, "locallycloud-bootstrap", |user| {user.inline_policies.insert("deny".into(),json!({"Statement":{
            "Effect":"Deny","Action":"iam:PassRole","Resource":ROLE,"Condition":{"StringEquals":{key:value}}
        }}).to_string());});
        assert_eq!(
            state.authorize_service_role_assignment(request.clone()),
            Err(AuthorizationError::Denied)
        );
        assert_eq!(
            state.authorize_service_role(request.clone()),
            Err(AuthorizationError::Denied)
        );
    }
}

#[test]
fn resource_policy_conditions_use_verified_userid_and_tags() {
    let (state, role_request, arn, user_id) = fixture();
    state
        .store
        .update_user(ACCOUNT, "locallycloud-bootstrap", |user| {
            user.inline_policies.clear()
        });
    let request = AuthorizationRequest {
        request_identity: role_request.caller,
        delegated_identity: None,
        source_service: "s3".into(),
        action: "s3:GetObject".into(),
        resource: "arn:aws:s3:::bucket/key".into(),
        context: role_request.caller_context,
    };
    let policy = json!({"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{
        "StringEquals":{"aws:PrincipalArn":arn,"aws:userid":user_id,"aws:PrincipalTag/team":"platform"}
    }}}).to_string();
    assert_eq!(
        state.authorize_resource_policy(request.clone(), Some(&policy), ACCOUNT),
        Ok(())
    );
    state.store.update_user(ACCOUNT, "locallycloud-bootstrap", |user| {user.inline_policies.insert("deny".into(),json!({"Statement":{
        "Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:userid":user_id}}
    }}).to_string());});
    assert_eq!(
        state.authorize_resource_policy(request, Some(&policy), ACCOUNT),
        Err(AuthorizationError::Denied)
    );
}

#[test]
fn delegated_pass_role_uses_the_attested_role_session_userid() {
    let (state, mut request, _, _) = fixture();
    state.store.update_role(ACCOUNT, "execution", |role| {
        role.inline_policies.insert(
            "pass".into(),
            json!({"Statement":{
                "Effect":"Allow","Action":"iam:PassRole","Resource":ROLE,"Condition":{
                    "StringEquals":{"aws:PrincipalArn":ROLE,"aws:userid":"AROAEXECUTION:cloudformation","aws:PrincipalAccount":ACCOUNT,"aws:PrincipalType":"AssumedRole"}
                }
            }})
            .to_string(),
        );
    });
    request.caller.access_key_id = Some("locallycloud".into());
    request.delegated_caller = Some(CallerIdentity::AssumedRole {
        role_arn: ROLE.into(),
        session_name: "cloudformation".into(),
    });
    assert_eq!(
        state.authorize_service_role_assignment(request.clone()),
        Ok(())
    );
    state.store.update_role(ACCOUNT, "execution", |role| {
        role.inline_policies.remove("pass");
    });
    assert_eq!(
        state.authorize_service_role_assignment(request),
        Err(AuthorizationError::Denied)
    );
}

#[test]
fn delegated_role_userid_deny_matches_regular_sts_sessions_and_overrides_resource_grants() {
    let (state, _, _, _) = fixture();
    let resource = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:queue");
    state.store.update_role(ACCOUNT, "execution", |role| {
        role.inline_policies = BTreeMap::from([(
            "allow".into(),
            json!({"Statement":{
                "Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"
            }})
            .to_string(),
        )]);
    });
    let query = QueryRequest::parse(format!("RoleArn={ROLE}&RoleSessionName=ordinary").as_bytes());
    let xml = sts::assume_role(&state.store, &state.sessions, ACCOUNT, &query).unwrap();
    let access_key = xml
        .split("<AccessKeyId>")
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap();
    let delegated = AuthorizationRequest {
        request_identity: RequestIdentity {
            account_id: ACCOUNT.into(),
            access_key_id: Some("locallycloud-events".into()),
            arn: None,
        },
        delegated_identity: Some(CallerIdentity::AssumedRole {
            role_arn: ROLE.into(),
            session_name: "eventbridge".into(),
        }),
        source_service: "sqs".into(),
        action: "sqs:SendMessage".into(),
        resource,
        context: BTreeMap::from([("aws:userid".into(), vec!["AROAOTHER:bypass".into()])]),
    };
    let mut regular = delegated.clone();
    regular.delegated_identity = None;
    regular.request_identity.access_key_id = Some(access_key.into());
    let policy = json!({"Statement":{"Effect":"Allow","Principal":{"AWS":ROLE},"Action":"sqs:SendMessage","Resource":"*"}}).to_string();
    for request in [&delegated, &regular] {
        assert_eq!(state.authorize(request.clone()), Ok(()));
        assert!(!state.identity_policy_denies(request.clone()));
        assert_eq!(
            state.authorize_resource_policy(request.clone(), Some(&policy), ACCOUNT),
            Ok(())
        );
    }
    let caller = state
        .enforcement
        .role_session_context(ACCOUNT, ROLE, "eventbridge")
        .unwrap();
    assert_eq!(
        caller.attribute("aws:userid"),
        Some("AROAEXECUTION:eventbridge")
    );
    assert_eq!(caller.attribute("aws:principalarn"), Some(ROLE));
    assert_eq!(caller.attribute("aws:principalaccount"), Some(ACCOUNT));
    assert_eq!(caller.attribute("aws:principaltype"), Some("AssumedRole"));
    assert_eq!(
        state
            .enforcement
            .role_context(ACCOUNT, ROLE)
            .unwrap()
            .attribute("aws:userid"),
        None
    );
    state.store.update_role(ACCOUNT, "execution", |role| {
        role.inline_policies.insert("deny".into(), json!({"Statement":{
            "Effect":"Deny","Action":"sqs:SendMessage","Resource":"*","Condition":{"StringLike":{"aws:userid":"AROAEXECUTION:*"}}
        }}).to_string());
    });
    for request in [delegated, regular] {
        assert_eq!(
            state.authorize(request.clone()),
            Err(AuthorizationError::Denied)
        );
        assert!(state.identity_policy_denies(request.clone()));
        assert_eq!(
            state.authorize_resource_policy(request, Some(&policy), ACCOUNT),
            Err(AuthorizationError::Denied)
        );
    }
}

#[test]
fn mfa_presence_is_verified_for_temporary_and_delegated_identity_policies() {
    let (state, role_request, _, user_id) = fixture();
    let policy = json!({"Statement":[
        {"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"},
        {"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}
    ]}).to_string();
    state
        .store
        .update_user(ACCOUNT, "locallycloud-bootstrap", |user| {
            user.inline_policies = BTreeMap::from([("mfa".into(), policy.clone())]);
        });
    state.store.update_role(ACCOUNT, "execution", |role| {
        role.inline_policies = BTreeMap::from([("mfa".into(), policy.clone())]);
    });
    let credentials =
        sts::issue_service_role_credentials(&state.store, &state.sessions, ACCOUNT, ROLE).unwrap();
    let longterm = AuthorizationRequest {
        request_identity: role_request.caller,
        delegated_identity: None,
        source_service: "sqs".into(),
        action: "sqs:SendMessage".into(),
        resource: format!("arn:aws:sqs:us-east-1:{ACCOUNT}:queue"),
        context: BTreeMap::from([("AWS:MultiFactorAuthPresent".into(), vec!["false".into()])]),
    };
    let mut regular = longterm.clone();
    regular.request_identity.access_key_id = Some(credentials.access_key_id);
    let mut delegated = longterm.clone();
    delegated.request_identity.access_key_id = Some("locallycloud-events".into());
    delegated.delegated_identity = Some(CallerIdentity::AssumedRole {
        role_arn: ROLE.into(),
        session_name: "eventbridge".into(),
    });
    let grant=json!({"Statement":{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Resource":"*"}}).to_string();
    assert_eq!(state.authorize(longterm.clone()), Ok(()));
    assert_eq!(
        state.authorize_resource_policy(longterm, Some(&grant), ACCOUNT),
        Ok(())
    );
    for mut request in [regular, delegated] {
        request.context =
            BTreeMap::from([("AWS:MultiFactorAuthPresent".into(), vec!["true".into()])]);
        assert_eq!(
            state.authorize(request.clone()),
            Err(AuthorizationError::Denied)
        );
        assert!(state.identity_policy_denies(request.clone()));
        assert_eq!(
            state.authorize_resource_policy(request, Some(&grant), ACCOUNT),
            Err(AuthorizationError::Denied)
        );
    }
    state
        .sessions
        .register(
            "ASIAUSERSESSION",
            sts::Session {
                account: ACCOUNT.into(),
                secret_access_key: "s".repeat(40),
                session_token: "user-session".into(),
                arn: format!("arn:aws:iam::{ACCOUNT}:user/locallycloud-bootstrap"),
                user_id,
                root_account: false,
                role_arn: None,
                session_policy: None,
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            },
        )
        .unwrap();
    let caller = state
        .enforcement
        .resolve_caller(ACCOUNT, "ASIAUSERSESSION")
        .unwrap();
    let mut context = BTreeMap::new();
    caller.apply_attributes(&mut context);
    assert_eq!(context["aws:multifactorauthpresent"], ["false"]);
    let mut context = BTreeMap::new();
    state
        .enforcement
        .role_context(ACCOUNT, ROLE)
        .unwrap()
        .apply_attributes(&mut context);
    assert!(!context.contains_key("aws:multifactorauthpresent"));
}
