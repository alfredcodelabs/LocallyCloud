use super::*;
use bytes::Bytes;
use http::{HeaderMap, Method};
use serde_json::json;

const ACCOUNT: &str = "000000000000";
const KEY: &str = "AKIA1234567890123456";
const TRUST: &str = r#"{"Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}"#;
const ALLOW: &str = r#"{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#;

fn request(body: &str) -> ServiceRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("AWS4-HMAC-SHA256 Credential={KEY}/20261116/us-east-1/iam/aws4_request")
            .parse()
            .unwrap(),
    );
    headers.insert(
        "x-locallycloud-verified-external-sigv4",
        "1".parse().unwrap(),
    );
    ServiceRequest {
        method: Method::POST,
        uri: "/".parse().unwrap(),
        headers,
        body: Bytes::copy_from_slice(body.as_bytes()),
        region: "us-east-1".into(),
        account_id: ACCOUNT.into(),
        request_id: "scope-regression".into(),
    }
}

fn fixture() -> Arc<IamStsState> {
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
            secret_access_key: "a".repeat(40),
        },
    );
    for (action, query) in [
        ("CreateUser", "UserName=target&Path=/team/&Tags.member.1.Key=protected&Tags.member.1.Value=yes".to_owned()),
        ("CreateGroup", "GroupName=target&Path=/team/".to_owned()),
        ("CreateRole", format!("RoleName=target&Path=/team/&AssumeRolePolicyDocument={TRUST}&Tags.member.1.Key=protected&Tags.member.1.Value=yes")),
        ("CreatePolicy", format!("PolicyName=target&Path=/team/&PolicyDocument={ALLOW}&Tags.member.1.Key=protected&Tags.member.1.Value=yes")),
        ("CreateInstanceProfile", "InstanceProfileName=target&Path=/team/&Tags.member.1.Key=protected&Tags.member.1.Value=yes".to_owned()),
    ] { dispatch_iam(&state, ACCOUNT, action, &QueryRequest::parse(query.as_bytes())).unwrap(); }
    state
}

fn deny(state: &IamStsState, action: &str, resource: &str, condition: serde_json::Value) {
    state.store.update_user(ACCOUNT, "locallycloud-bootstrap", |user| {
        user.inline_policies.insert("test-deny".into(), json!({"Statement":{"Effect":"Deny","Action":action,"Resource":resource,"Condition":condition}}).to_string());
    });
}

#[test]
fn every_supported_scoped_action_uses_its_sar_resource_even_with_a_nonroot_path() {
    let state = fixture();
    let groups: &[(&str, &str, &[&str])] = &[
        (
            "user",
            "UserName=target",
            &[
                "GetUser",
                "DeleteUser",
                "UpdateUser",
                "TagUser",
                "UntagUser",
                "ListUserTags",
                "ListGroupsForUser",
                "AttachUserPolicy",
                "DetachUserPolicy",
                "ListAttachedUserPolicies",
                "PutUserPolicy",
                "GetUserPolicy",
                "ListUserPolicies",
                "DeleteUserPolicy",
                "PutUserPermissionsBoundary",
                "DeleteUserPermissionsBoundary",
                "CreateAccessKey",
                "ListAccessKeys",
                "UpdateAccessKey",
                "DeleteAccessKey",
            ],
        ),
        (
            "group",
            "GroupName=target",
            &[
                "GetGroup",
                "AddUserToGroup",
                "RemoveUserFromGroup",
                "DeleteGroup",
                "AttachGroupPolicy",
                "DetachGroupPolicy",
                "ListAttachedGroupPolicies",
                "PutGroupPolicy",
                "GetGroupPolicy",
                "ListGroupPolicies",
                "DeleteGroupPolicy",
            ],
        ),
        (
            "role",
            "RoleName=target",
            &[
                "GetRole",
                "UpdateRole",
                "UpdateAssumeRolePolicy",
                "TagRole",
                "UntagRole",
                "ListRoleTags",
                "DeleteRole",
                "AttachRolePolicy",
                "DetachRolePolicy",
                "ListAttachedRolePolicies",
                "PutRolePolicy",
                "GetRolePolicy",
                "ListRolePolicies",
                "DeleteRolePolicy",
                "PutRolePermissionsBoundary",
                "DeleteRolePermissionsBoundary",
                "ListInstanceProfilesForRole",
            ],
        ),
        (
            "policy",
            "PolicyArn=arn:aws:iam::000000000000:policy/team/target",
            &[
                "GetPolicy",
                "DeletePolicy",
                "TagPolicy",
                "UntagPolicy",
                "ListPolicyTags",
                "CreatePolicyVersion",
                "GetPolicyVersion",
                "ListPolicyVersions",
                "SetDefaultPolicyVersion",
                "DeletePolicyVersion",
            ],
        ),
        (
            "instance-profile",
            "InstanceProfileName=target",
            &[
                "GetInstanceProfile",
                "AddRoleToInstanceProfile",
                "RemoveRoleFromInstanceProfile",
                "DeleteInstanceProfile",
                "TagInstanceProfile",
                "UntagInstanceProfile",
                "ListInstanceProfileTags",
            ],
        ),
    ];
    for (kind, query, actions) in groups {
        let arn = format!("arn:aws:iam::{ACCOUNT}:{kind}/team/target");
        for action in *actions {
            let query = QueryRequest::parse(query.as_bytes());
            assert_eq!(
                state.iam_resource(ACCOUNT, action, &query).unwrap(),
                arn,
                "{action}"
            );
            deny(&state, &format!("iam:{action}"), &arn, json!({}));
            assert!(
                state.authorize_iam(&request(""), action, &query).is_err(),
                "{action}"
            );
        }
    }
    for action in [
        "ListUsers",
        "ListGroups",
        "ListRoles",
        "ListPolicies",
        "ListInstanceProfiles",
        "SimulateCustomPolicy",
    ] {
        assert_eq!(
            state
                .iam_resource(ACCOUNT, action, &QueryRequest::parse(b""))
                .unwrap(),
            "*"
        );
    }
    let arn = format!("arn:aws:iam::{ACCOUNT}:role/team/target");
    let query = QueryRequest::parse(format!("PolicySourceArn={arn}").as_bytes());
    deny(&state, "iam:SimulatePrincipalPolicy", &arn, json!({}));
    assert_eq!(
        state
            .iam_resource(ACCOUNT, "SimulatePrincipalPolicy", &query)
            .unwrap(),
        arn
    );
    assert!(state
        .authorize_iam(&request(""), "SimulatePrincipalPolicy", &query)
        .is_err());
    for forged in [
        "arn:aws:iam::111111111111:role/team/target",
        "arn:aws:iam::000000000000:role/wrong/target",
    ] {
        assert!(state
            .iam_resource(
                ACCOUNT,
                "SimulatePrincipalPolicy",
                &QueryRequest::parse(format!("PolicySourceArn={forged}").as_bytes())
            )
            .is_err());
        assert!(iam::simulate_principal_policy(
            &state.store,
            ACCOUNT,
            &QueryRequest::parse(
                format!("PolicySourceArn={forged}&ActionNames.member.1=s3:PutObject").as_bytes()
            )
        )
        .is_err());
    }
}

#[tokio::test]
async fn arn_denies_block_each_mutation_family_without_partial_effects() {
    let state = fixture();
    let handler = IamHandler {
        state: state.clone(),
    };
    for (kind, action, args) in [
        ("user", "CreateAccessKey", "UserName=target".to_owned()),
        ("group", "PutGroupPolicy", format!("GroupName=target&PolicyName=escalate&PolicyDocument={ALLOW}")),
        ("policy", "CreatePolicyVersion", format!("PolicyArn=arn:aws:iam::{ACCOUNT}:policy/team/target&SetAsDefault=true&PolicyDocument={ALLOW}")),
        ("instance-profile", "AddRoleToInstanceProfile", "InstanceProfileName=target&RoleName=target".to_owned()),
    ] {
        deny(&state, &format!("iam:{action}"), &format!("arn:aws:iam::{ACCOUNT}:{kind}/team/target"), json!({}));
        assert_eq!(handler.handle(request(&format!("Action={action}&{args}"))).await.status(), 403, "{action}");
    }
    assert!(state
        .store
        .get_user(ACCOUNT, "target")
        .unwrap()
        .access_keys
        .is_empty());
    assert!(state
        .store
        .get_group(ACCOUNT, "target")
        .unwrap()
        .inline_policies
        .is_empty());
    assert_eq!(
        state
            .store
            .get_policy(
                ACCOUNT,
                &format!("arn:aws:iam::{ACCOUNT}:policy/team/target")
            )
            .unwrap()
            .versions
            .len(),
        1
    );
    assert!(state
        .store
        .get_instance_profile(ACCOUNT, "target")
        .unwrap()
        .role
        .is_none());
}

#[tokio::test]
async fn resource_request_tags_policy_arn_and_boundary_conditions_cannot_be_skipped() {
    let state = fixture();
    let handler = IamHandler {
        state: state.clone(),
    };
    let policy = format!("arn:aws:iam::{ACCOUNT}:policy/team/target");
    for (action, args, condition) in [
        (
            "DeleteUser",
            "UserName=target".to_owned(),
            json!({"StringEquals":{"aws:ResourceTag/protected":"yes"}}),
        ),
        (
            "PutUserPolicy",
            format!("UserName=target&PolicyName=escalate&PolicyDocument={ALLOW}"),
            json!({"StringEquals":{"iam:ResourceTag/protected":"yes"}}),
        ),
        (
            "TagRole",
            "RoleName=target&Tags.member.1.Key=forbidden&Tags.member.1.Value=yes".to_owned(),
            json!({"StringEquals":{"aws:RequestTag/forbidden":"yes"}}),
        ),
        (
            "UntagPolicy",
            format!("PolicyArn={policy}&TagKeys.member.1=protected"),
            json!({"ForAnyValue:StringEquals":{"aws:TagKeys":"protected"}}),
        ),
        (
            "AttachGroupPolicy",
            format!("GroupName=target&PolicyArn={policy}"),
            json!({"ArnEquals":{"iam:PolicyARN":policy}}),
        ),
        (
            "PutRolePermissionsBoundary",
            format!("RoleName=target&PermissionsBoundary={policy}"),
            json!({"ArnEquals":{"iam:PermissionsBoundary":policy}}),
        ),
        (
            "DeleteInstanceProfile",
            "InstanceProfileName=target".to_owned(),
            json!({"StringEquals":{"aws:ResourceTag/protected":"yes"}}),
        ),
    ] {
        deny(&state, &format!("iam:{action}"), "*", condition);
        assert_eq!(
            handler
                .handle(request(&format!("Action={action}&{args}")))
                .await
                .status(),
            403,
            "{action}"
        );
    }
    assert!(state.store.get_user(ACCOUNT, "target").is_some());
    assert!(state
        .store
        .get_user(ACCOUNT, "target")
        .unwrap()
        .inline_policies
        .is_empty());
    assert!(!state
        .store
        .get_role(ACCOUNT, "target")
        .unwrap()
        .tags
        .contains_key("forbidden"));
    assert!(state
        .store
        .get_role(ACCOUNT, "target")
        .unwrap()
        .permission_boundary
        .is_none());
    assert!(state
        .store
        .get_group(ACCOUNT, "target")
        .unwrap()
        .attached_policies
        .is_empty());
    assert_eq!(
        state
            .store
            .get_policy(ACCOUNT, &policy)
            .unwrap()
            .tags
            .get("protected")
            .map(String::as_str),
        Some("yes")
    );
    assert!(state
        .store
        .get_instance_profile(ACCOUNT, "target")
        .is_some());
}

#[tokio::test]
async fn create_tag_and_passrole_dependencies_precede_any_mutation() {
    let state = fixture();
    let handler = IamHandler {
        state: state.clone(),
    };
    for (action, name, args, dependency, kind) in [
        (
            "CreateUser",
            "new-user",
            "UserName=new-user".to_owned(),
            "TagUser",
            "user",
        ),
        (
            "CreateRole",
            "new-role",
            format!("RoleName=new-role&AssumeRolePolicyDocument={TRUST}"),
            "TagRole",
            "role",
        ),
        (
            "CreatePolicy",
            "new-policy",
            format!("PolicyName=new-policy&PolicyDocument={ALLOW}"),
            "TagPolicy",
            "policy",
        ),
        (
            "CreateInstanceProfile",
            "new-profile",
            "InstanceProfileName=new-profile".to_owned(),
            "TagInstanceProfile",
            "instance-profile",
        ),
    ] {
        deny(
            &state,
            &format!("iam:{dependency}"),
            &format!("arn:aws:iam::{ACCOUNT}:{kind}/team/{name}"),
            json!({}),
        );
        assert_eq!(
            handler
                .handle(request(&format!(
                    "Action={action}&{args}&Path=/team/&Tags.member.1.Key=k&Tags.member.1.Value=v"
                )))
                .await
                .status(),
            403,
            "{action}"
        );
    }
    assert!(state.store.get_user(ACCOUNT, "new-user").is_none());
    assert!(state.store.get_role(ACCOUNT, "new-role").is_none());
    assert!(state
        .store
        .get_instance_profile(ACCOUNT, "new-profile")
        .is_none());
    assert!(state
        .store
        .get_policy(
            ACCOUNT,
            &format!("arn:aws:iam::{ACCOUNT}:policy/team/new-policy")
        )
        .is_none());
    deny(
        &state,
        "iam:PassRole",
        &format!("arn:aws:iam::{ACCOUNT}:role/team/target"),
        json!({"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}),
    );
    assert_eq!(
        handler
            .handle(request(
                "Action=AddRoleToInstanceProfile&InstanceProfileName=target&RoleName=target"
            ))
            .await
            .status(),
        403
    );
    assert!(state
        .store
        .get_instance_profile(ACCOUNT, "target")
        .unwrap()
        .role
        .is_none());
    state
        .store
        .update_user(ACCOUNT, "locallycloud-bootstrap", |user| {
            user.inline_policies.remove("test-deny");
        });
    assert_eq!(
        handler
            .handle(request(
                "Action=AddRoleToInstanceProfile&InstanceProfileName=target&RoleName=target"
            ))
            .await
            .status(),
        200
    );
    assert_eq!(
        handler
            .handle(request(
                "Action=RemoveRoleFromInstanceProfile&InstanceProfileName=target&RoleName=wrong"
            ))
            .await
            .status(),
        404
    );
    assert_eq!(
        state
            .store
            .get_instance_profile(ACCOUNT, "target")
            .unwrap()
            .role
            .as_deref(),
        Some("target")
    );
}

#[tokio::test]
async fn self_user_defaults_require_an_attested_long_term_user() {
    let state = fixture();
    let handler = IamHandler {
        state: state.clone(),
    };
    assert_eq!(
        handler.handle(request("Action=GetUser")).await.status(),
        200
    );
    assert_eq!(
        handler
            .handle(request("Action=CreateAccessKey"))
            .await
            .status(),
        200
    );
    assert_eq!(
        state
            .store
            .get_user(ACCOUNT, "locallycloud-bootstrap")
            .unwrap()
            .access_keys
            .len(),
        2
    );
    let mut unverified = request("Action=GetUser");
    unverified
        .headers
        .remove("x-locallycloud-verified-external-sigv4");
    assert_eq!(handler.handle(unverified).await.status(), 400);
}

#[tokio::test]
async fn scoped_allow_grants_and_identity_limits_survive_resource_resolution() {
    let state = fixture();
    let handler = IamHandler {
        state: state.clone(),
    };
    let target = format!("arn:aws:iam::{ACCOUNT}:user/team/target");
    state.store.update_user(ACCOUNT,"locallycloud-bootstrap",|user| {
        user.inline_policies.clear();
        user.inline_policies.insert("allow-target".into(),json!({"Statement":{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":target}}).to_string());
    });
    assert_eq!(
        handler
            .handle(request("Action=CreateAccessKey&UserName=target"))
            .await
            .status(),
        200
    );
    assert_eq!(
        handler
            .handle(request(
                "Action=CreateAccessKey&UserName=locallycloud-bootstrap"
            ))
            .await
            .status(),
        403
    );
    let policy = format!("arn:aws:iam::{ACCOUNT}:policy/team/target");
    state.store.update_policy(ACCOUNT,&policy,|policy| {
        policy.versions[0].document=json!({"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:CreateAccessKey","Resource":target}]}).to_string();
    });
    state
        .store
        .update_user(ACCOUNT, "locallycloud-bootstrap", |user| {
            user.permission_boundary = Some(policy)
        });
    assert_eq!(
        handler
            .handle(request("Action=CreateAccessKey&UserName=target"))
            .await
            .status(),
        403
    );
    state.store.update_role(ACCOUNT, "target", |role| {
        role.inline_policies.insert("allow".into(), ALLOW.into());
    });
    let session_policy = json!({"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:CreateAccessKey","Resource":target}]});
    let credentials=sts::assume_role(&state.store,&state.sessions,ACCOUNT,&QueryRequest::parse(format!("RoleArn=arn:aws:iam::{ACCOUNT}:role/team/target&RoleSessionName=scope&Policy={session_policy}").as_bytes())).unwrap();
    let key = credentials
        .split("<AccessKeyId>")
        .nth(1)
        .unwrap()
        .split("</AccessKeyId>")
        .next()
        .unwrap();
    let mut req = request("Action=CreateAccessKey&UserName=target");
    req.headers.insert(
        http::header::AUTHORIZATION,
        format!("AWS4-HMAC-SHA256 Credential={key}/20261116/us-east-1/iam/aws4_request")
            .parse()
            .unwrap(),
    );
    assert_eq!(handler.handle(req).await.status(), 403);
    assert_eq!(
        state
            .store
            .get_user(ACCOUNT, "target")
            .unwrap()
            .access_keys
            .len(),
        1
    );
}

#[tokio::test]
async fn create_boundaries_and_profile_tags_are_durable_and_effective() {
    use crate::persistence::IamPersistence;
    use locallycloud_state::{StateCipher, StateDb};
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../compatibility-tests/.work/iam-vpc-fixes")
        .join(format!("iam-scopes-{}", uuid::Uuid::new_v4()));
    let db = Arc::new(StateDb::open(directory.join("state.sqlite3")).unwrap());
    let persistence = Arc::new(
        IamPersistence::with_cipher(db.clone(), StateCipher::with_key(&[0x73; 32])).unwrap(),
    );
    let store = Arc::new(IamStore::durable(persistence.clone()).unwrap());
    seed_bootstrap_user(
        &store,
        ACCOUNT,
        BootstrapCredentials {
            access_key_id: KEY.into(),
            secret_access_key: "a".repeat(40),
        },
    );
    let state = Arc::new(IamStsState::with_mode(
        store.clone(),
        Arc::new(SessionStore::new()),
        EnforcementMode::Strict,
    ));
    let handler = IamHandler {
        state: state.clone(),
    };
    let boundary = format!("arn:aws:iam::{ACCOUNT}:policy/boundary");
    for body in [
        format!("Action=CreatePolicy&PolicyName=boundary&PolicyDocument={}",json!({"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}})),
        format!("Action=CreateUser&UserName=bounded&PermissionsBoundary={boundary}"),
        format!("Action=CreateRole&RoleName=bounded&PermissionsBoundary={boundary}&AssumeRolePolicyDocument={TRUST}"),
        "Action=CreateInstanceProfile&InstanceProfileName=tagged&Tags.member.1.Key=team&Tags.member.1.Value=platform".into(),
        "Action=TagInstanceProfile&InstanceProfileName=tagged&Tags.member.1.Key=environment&Tags.member.1.Value=local".into(),
    ] { assert_eq!(handler.handle(request(&body)).await.status(),200,"{body}"); }
    assert_eq!(handler.handle(request("Action=CreateUser&UserName=invalid&PermissionsBoundary=arn:aws:iam::000000000000:policy/missing")).await.status(),404);
    assert!(store.get_user(ACCOUNT, "invalid").is_none());
    let restored = Arc::new(IamStore::durable(persistence.clone()).unwrap());
    assert_eq!(
        restored
            .get_user(ACCOUNT, "bounded")
            .unwrap()
            .permission_boundary
            .as_deref(),
        Some(boundary.as_str())
    );
    assert_eq!(
        restored
            .get_role(ACCOUNT, "bounded")
            .unwrap()
            .permission_boundary
            .as_deref(),
        Some(boundary.as_str())
    );
    let profile = restored.get_instance_profile(ACCOUNT, "tagged").unwrap();
    assert_eq!(
        profile.tags.get("team").map(String::as_str),
        Some("platform")
    );
    assert_eq!(
        profile.tags.get("environment").map(String::as_str),
        Some("local")
    );
    let xml = iam::get_instance_profile(
        &restored,
        ACCOUNT,
        &QueryRequest::parse(b"InstanceProfileName=tagged"),
    )
    .unwrap();
    assert!(xml.contains("<Key>team</Key>"));
    let mut legacy = serde_json::to_value(profile).unwrap();
    legacy.as_object_mut().unwrap().remove("tags");
    assert!(
        serde_json::from_value::<crate::model::InstanceProfile>(legacy)
            .unwrap()
            .tags
            .is_empty()
    );
    restored.update_user(ACCOUNT, "bounded", |user| {
        user.inline_policies.insert("allow".into(), ALLOW.into());
        user.access_keys.push(AccessKey {
            access_key_id: "AKIABOUNDED1234567890".into(),
            secret_access_key: "b".repeat(40),
            status: "Active".into(),
            create_date: now_iso8601(),
        });
    });
    let after = IamStsState::with_mode(
        restored.clone(),
        Arc::new(SessionStore::new()),
        EnforcementMode::Strict,
    );
    let identity = RequestIdentity {
        account_id: ACCOUNT.into(),
        access_key_id: Some("AKIABOUNDED1234567890".into()),
        arn: None,
    };
    assert!(after
        .enforcement
        .check(
            EnforcementMode::Strict,
            &identity,
            "s3:GetObject",
            "arn:aws:s3:::bucket/key"
        )
        .is_ok());
    assert!(after
        .enforcement
        .check(
            EnforcementMode::Strict,
            &identity,
            "s3:PutObject",
            "arn:aws:s3:::bucket/key"
        )
        .is_err());
    assert_eq!(handler.handle(request("Action=UntagInstanceProfile&InstanceProfileName=tagged&TagKeys.member.1=environment")).await.status(),200);
    assert!(!IamStore::durable(persistence.clone())
        .unwrap()
        .get_instance_profile(ACCOUNT, "tagged")
        .unwrap()
        .tags
        .contains_key("environment"));
    drop(after);
    drop(restored);
    drop(handler);
    drop(state);
    drop(store);
    drop(persistence);
    drop(db);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn case_variant_tag_keys_share_the_condition_context_without_hiding_values() {
    let state = fixture();
    let handler = IamHandler {
        state: state.clone(),
    };
    state
        .store
        .update_instance_profile(ACCOUNT, "target", |profile| {
            profile.tags.insert("Env".into(), "prod".into());
            profile.tags.insert("env".into(), "dev".into());
        });
    deny(
        &state,
        "iam:DeleteInstanceProfile",
        "*",
        json!({"ForAnyValue:StringEquals":{"aws:ResourceTag/ENV":"prod"}}),
    );
    assert_eq!(
        handler
            .handle(request(
                "Action=DeleteInstanceProfile&InstanceProfileName=target"
            ))
            .await
            .status(),
        403
    );
    assert!(state
        .store
        .get_instance_profile(ACCOUNT, "target")
        .is_some());
    deny(
        &state,
        "iam:TagInstanceProfile",
        "*",
        json!({"ForAnyValue:StringEquals":{"aws:RequestTag/ENV":"prod"}}),
    );
    assert_eq!(handler.handle(request("Action=TagInstanceProfile&InstanceProfileName=target&Tags.member.1.Key=Env&Tags.member.1.Value=prod&Tags.member.2.Key=env&Tags.member.2.Value=dev")).await.status(),403);
    assert_eq!(
        state
            .store
            .get_instance_profile(ACCOUNT, "target")
            .unwrap()
            .tags
            .get("Env")
            .map(String::as_str),
        Some("prod")
    );
    state
        .store
        .update_instance_profile(ACCOUNT, "target", |profile| {
            profile.tags.remove("Env");
            profile.tags.remove("env");
        });
    assert_eq!(handler.handle(request("Action=TagInstanceProfile&InstanceProfileName=target&Tags.member.1.Key=Env&Tags.member.1.Value=prod&Tags.member.2.Key=env&Tags.member.2.Value=dev")).await.status(),403);
    assert!(!state
        .store
        .get_instance_profile(ACCOUNT, "target")
        .unwrap()
        .tags
        .contains_key("Env"));
}

#[test]
fn user_and_role_details_expose_escaped_boundaries_and_tags_without_changing_lists() {
    let state = fixture();
    let boundary = "arn:aws:iam::000000000000:policy/team/a&b";
    state.store.update_user(ACCOUNT, "target", |user| {
        user.permission_boundary = Some(boundary.into())
    });
    state.store.update_role(ACCOUNT, "target", |role| {
        role.permission_boundary = Some(boundary.into())
    });
    let user = state.store.get_user(ACCOUNT, "target").unwrap();
    let role = state.store.get_role(ACCOUNT, "target").unwrap();
    for xml in [user.xml(), role.xml()] {
        assert!(xml.contains("<PermissionsBoundaryType>Policy</PermissionsBoundaryType>"));
        assert!(xml.contains("<PermissionsBoundaryArn>arn:aws:iam::000000000000:policy/team/a&amp;b</PermissionsBoundaryArn>"));
        assert!(
            xml.contains("<Tags><member><Key>protected</Key><Value>yes</Value></member></Tags>")
        );
    }
    for xml in [user.member_xml(), role.member_xml()] {
        assert!(!xml.contains("PermissionsBoundary"));
        assert!(!xml.contains("<Tags>"));
    }
}

#[tokio::test]
async fn instance_profile_passrole_uses_the_documented_associated_instance_arn() {
    let state = fixture();
    let handler = IamHandler {
        state: state.clone(),
    };
    let role = format!("arn:aws:iam::{ACCOUNT}:role/team/target");
    let associated = format!("arn:aws:ec2:*:{ACCOUNT}:instance/*");
    state.store.update_user(ACCOUNT,"locallycloud-bootstrap",|user| {
        user.inline_policies.clear();
        user.inline_policies.insert("assign".into(),json!({"Statement":[
            {"Effect":"Allow","Action":"iam:AddRoleToInstanceProfile","Resource":format!("arn:aws:iam::{ACCOUNT}:instance-profile/team/target")},
            {"Effect":"Allow","Action":"iam:PassRole","Resource":role,"Condition":{"ArnLike":{"iam:AssociatedResourceArn":associated},"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}}
        ]}).to_string());
    });
    let req = request("Action=AddRoleToInstanceProfile&InstanceProfileName=target&RoleName=target");
    assert_eq!(handler.handle(req.clone()).await.status(), 200);
    state
        .store
        .update_instance_profile(ACCOUNT, "target", |profile| profile.role = None);
    deny(
        &state,
        "iam:PassRole",
        &role,
        json!({"ArnLike":{"iam:AssociatedResourceArn":associated}}),
    );
    assert_eq!(handler.handle(req).await.status(), 403);
    assert!(state
        .store
        .get_instance_profile(ACCOUNT, "target")
        .unwrap()
        .role
        .is_none());
}

#[tokio::test]
async fn mutation_rechecks_committed_resource_tags_after_waiting_for_its_gate() {
    use std::task::Poll;
    use std::time::Duration;
    let state = fixture();
    let handler = IamHandler {
        state: state.clone(),
    };
    state.store.update_user(ACCOUNT, "target", |user| {
        user.tags.insert("protected".into(), "no".into());
    });
    deny(
        &state,
        "iam:TagUser",
        "*",
        json!({"StringEquals":{"aws:ResourceTag/protected":"yes"}}),
    );
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let (commit_tx, commit_rx) = std::sync::mpsc::sync_channel(1);
    let store = state.store.clone();
    let holder = tokio::task::spawn_blocking(move || {
        store.transact(|staged| {
            staged.update_user(ACCOUNT, "target", |user| {
                user.tags.insert("protected".into(), "yes".into());
            });
            held_tx.send(()).unwrap();
            commit_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| IamStsError::InternalFailure("test gate timed out".into()))?;
            Ok(())
        })
    });
    tokio::time::timeout(Duration::from_secs(5), held_rx)
        .await
        .unwrap()
        .unwrap();
    let invocation = handler.handle(request(
        "Action=TagUser&UserName=target&Tags.member.1.Key=unauthorized&Tags.member.1.Value=yes",
    ));
    tokio::pin!(invocation);
    std::future::poll_fn(
        |cx| match std::future::Future::poll(invocation.as_mut(), cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => {
                panic!("the initial authorized request must wait for the held mutation gate")
            }
        },
    )
    .await;
    commit_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), holder)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), invocation)
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let user = state.store.get_user(ACCOUNT, "target").unwrap();
    assert_eq!(user.tags.get("protected").map(String::as_str), Some("yes"));
    assert!(!user.tags.contains_key("unauthorized"));
}

#[test]
fn instance_profile_details_and_tag_listing_preserve_tags_while_resource_lists_omit_them() {
    let state = fixture();
    let query = QueryRequest::parse(b"InstanceProfileName=target");
    let created = iam::create_instance_profile(
        &state.store,
        ACCOUNT,
        &QueryRequest::parse(
            b"InstanceProfileName=created&Tags.member.1.Key=team&Tags.member.1.Value=platform",
        ),
    )
    .unwrap();
    assert!(
        created.contains("<Tags><member><Key>team</Key><Value>platform</Value></member></Tags>")
    );
    state
        .store
        .update_instance_profile(ACCOUNT, "target", |profile| {
            profile.role = Some("target".into())
        });
    let detail = iam::get_instance_profile(&state.store, ACCOUNT, &query).unwrap();
    assert!(detail.contains("<Tags><member><Key>protected</Key><Value>yes</Value></member></Tags>"));
    for listed in [
        iam::list_instance_profiles(&state.store, ACCOUNT, &QueryRequest::parse(b"")).unwrap(),
        iam::list_instance_profiles_for_role(
            &state.store,
            ACCOUNT,
            &QueryRequest::parse(b"RoleName=target"),
        )
        .unwrap(),
    ] {
        assert!(listed.contains("<InstanceProfileName>target</InstanceProfileName>"));
        assert!(!listed.contains("<Tags>"));
    }
    assert!(
        iam::list_instance_profile_tags(&state.store, ACCOUNT, &query)
            .unwrap()
            .contains("<Key>protected</Key>")
    );
    assert_eq!(
        state
            .store
            .get_instance_profile(ACCOUNT, "target")
            .unwrap()
            .tags
            .get("protected")
            .map(String::as_str),
        Some("yes")
    );
}
