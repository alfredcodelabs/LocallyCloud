use super::*;
use serde_json::{json, Value};

const RESOURCE: &str = "arn:aws:execute-api:us-east-1:000000000000:api/prod/GET/items";
const USER: &str = "arn:aws:iam::000000000000:user/locallycloud-bootstrap";

fn state(mode: EnforcementMode) -> IamStsState {
    let state = IamStsState::with_mode(
        Arc::new(IamStore::new()),
        Arc::new(SessionStore::new()),
        mode,
    );
    seed_bootstrap_user(
        &state.store,
        "000000000000",
        BootstrapCredentials {
            access_key_id: "AKIAANONPOLICY000001".into(),
            secret_access_key: "f".repeat(40),
        },
    );
    state
}

fn evaluate(
    state: &IamStsState,
    statement: Value,
    context: BTreeMap<String, Vec<String>>,
) -> ResourcePolicyDecision {
    state
        .evaluate_anonymous_resource_policy(
            ResourcePolicyEvaluationRequest {
                action: "execute-api:Invoke".into(),
                resource: RESOURCE.into(),
                context,
            },
            &json!({"Version":"2012-10-17","Statement":statement}).to_string(),
        )
        .unwrap()
}

#[test]
fn anonymous_resource_policy_keeps_three_decisions_without_identity_union() {
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let state = state(mode);
        let allow = json!({"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":RESOURCE});
        let deny = json!({"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":RESOURCE});
        assert_eq!(
            evaluate(&state, allow.clone(), BTreeMap::new()),
            ResourcePolicyDecision::Allow
        );
        for statements in [
            json!([allow.clone(), deny.clone()]),
            json!([deny, allow.clone()]),
        ] {
            assert_eq!(
                evaluate(&state, statements, BTreeMap::new()),
                ResourcePolicyDecision::ExplicitDeny
            );
        }
        for statement in [
            json!({"Effect":"Allow","Principal":{"AWS":USER},"Action":"execute-api:Invoke","Resource":RESOURCE}),
            json!({"Effect":"Allow","Principal":{"AWS":"000000000000"},"Action":"execute-api:Invoke","Resource":RESOURCE}),
            json!({"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"execute-api:Invoke","Resource":RESOURCE}),
            json!({"Effect":"Allow","Principal":"*","Action":"execute-api:InvalidateCache","Resource":RESOURCE}),
            json!({"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"arn:aws:execute-api:us-east-1:000000000000:another/*"}),
        ] {
            assert_eq!(
                evaluate(&state, statement, BTreeMap::new()),
                ResourcePolicyDecision::ImplicitDeny
            );
        }
        state
            .store
            .update_user("000000000000", "locallycloud-bootstrap", |user| {
                user.inline_policies = [(
                    "deny".into(),
                    json!({"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}).to_string(),
                )]
                .into();
            });
        assert_eq!(
            evaluate(
                &state,
                allow,
                BTreeMap::from([("aws:principalarn".into(), vec![USER.into()])])
            ),
            ResourcePolicyDecision::Allow
        );
    }
}

#[test]
fn anonymous_resource_policy_discards_identity_claims_and_preserves_connection_conditions() {
    let state = state(EnforcementMode::Strict);
    let mut context = BTreeMap::from([
        ("AWS:PrincipalArn".into(), vec![USER.into()]),
        ("aws:principalaccount".into(), vec!["000000000000".into()]),
        ("aws:principaltype".into(), vec!["User".into()]),
        ("aws:userid".into(), vec!["AIDAFORGED".into()]),
        ("aws:principaltag/admin".into(), vec!["yes".into()]),
        ("aws:principalisawsservice".into(), vec!["true".into()]),
        (
            "aws:sourcearn".into(),
            vec!["arn:aws:events:us-east-1:000000000000:rule/forged".into()],
        ),
        ("aws:securetransport".into(), vec!["true".into()]),
        ("aws:sourceip".into(), vec!["192.0.2.10".into()]),
        ("aws:requestedregion".into(), vec!["us-east-1".into()]),
    ]);
    let allow = json!({"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":RESOURCE,"Condition":{
        "StringEquals":{"aws:PrincipalAccount":"anonymous","aws:PrincipalType":"Anonymous","aws:userid":"anonymous","aws:RequestedRegion":"us-east-1"},
        "Null":{"aws:PrincipalArn":"true","aws:PrincipalTag/admin":"true","aws:PrincipalIsAWSService":"true","aws:SourceArn":"true"},
        "IpAddress":{"aws:SourceIp":"192.0.2.0/24"},"Bool":{"aws:SecureTransport":"true"}
    }});
    assert_eq!(
        evaluate(&state, allow.clone(), context.clone()),
        ResourcePolicyDecision::Allow
    );
    context.insert("aws:sourceip".into(), vec!["198.51.100.1".into()]);
    assert_eq!(
        evaluate(&state, allow, context.clone()),
        ResourcePolicyDecision::ImplicitDeny
    );
    context.insert("aws:securetransport".into(), vec!["false".into()]);
    let deny_http = json!({"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":RESOURCE,"Condition":{"Bool":{"aws:SecureTransport":"false"}}});
    assert_eq!(
        evaluate(&state, deny_http, context),
        ResourcePolicyDecision::ExplicitDeny
    );
}

#[test]
fn anonymous_resource_policy_fails_closed_for_invalid_or_unsupported_documents() {
    let state = state(EnforcementMode::Permissive);
    let request = ResourcePolicyEvaluationRequest {
        action: "execute-api:Invoke".into(),
        resource: RESOURCE.into(),
        context: BTreeMap::new(),
    };
    for document in ["not-json".to_owned(),json!({"Statement":{"Effect":"Allow","NotPrincipal":"*","Action":"*","Resource":"*"}}).to_string(),json!({"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:unsupported":"value"}}}}).to_string()] {
        assert!(state.evaluate_anonymous_resource_policy(request.clone(),&document).is_err());
    }
    let mut invalid = request;
    invalid.action.clear();
    assert!(state
        .evaluate_anonymous_resource_policy(
            invalid,
            r#"{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}"#
        )
        .is_err());
}
