use super::*;
use serde_json::json;

const ACCOUNT: &str = "000000000000";
const KEY: &str = "endpoint-user-key";
const RESOURCE: &str = "arn:aws:execute-api:us-east-1:000000000000:api/prod/GET/";

fn fixture(mode: EnforcementMode) -> IamStsState {
    let store = Arc::new(IamStore::new());
    iam::create_user(&store, ACCOUNT, &QueryRequest::parse(b"UserName=caller")).unwrap();
    store.update_user(ACCOUNT, "caller", |user| {
        user.access_keys.push(AccessKey {
            access_key_id: KEY.into(),
            secret_access_key: "fixture-secret".into(),
            status: "Active".into(),
            create_date: now_iso8601(),
        });
        user.inline_policies.insert(
            "identity".into(),
            json!({"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}).to_string(),
        );
    });
    IamStsState::with_mode(store, Arc::new(SessionStore::new()), mode)
}

fn identity() -> Option<RequestIdentity> {
    Some(RequestIdentity {
        account_id: ACCOUNT.into(),
        access_key_id: Some(KEY.into()),
        arn: None,
    })
}

fn request() -> ResourcePolicyEvaluationRequest {
    ResourcePolicyEvaluationRequest {
        action: "execute-api:Invoke".into(),
        resource: RESOURCE.into(),
        context: BTreeMap::from([
            ("aws:sourcevpc".into(), vec!["vpc-owned".into()]),
            ("aws:sourcevpce".into(), vec!["vpce-owned".into()]),
            ("aws:vpcsourceip".into(), vec!["10.0.0.4".into()]),
        ]),
    }
}

#[test]
fn endpoint_document_is_an_independent_gate_in_both_modes() {
    for mode in [EnforcementMode::Strict, EnforcementMode::Permissive] {
        let state = fixture(mode);
        let wrong_resource = json!({"Statement":{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"arn:aws:execute-api:us-east-1:000000000000:other/*"}}).to_string();
        assert_eq!(
            state.evaluate_endpoint_policy(request(), identity(), &wrong_resource),
            Ok(ResourcePolicyDecision::ImplicitDeny)
        );
        let restricted = json!({"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/caller"},"Action":"execute-api:Invoke","Resource":"*"}}).to_string();
        assert_eq!(
            state.evaluate_endpoint_policy(request(), identity(), &restricted),
            Ok(ResourcePolicyDecision::Allow)
        );
        assert_eq!(
            state.evaluate_endpoint_policy(request(), None, &restricted),
            Ok(ResourcePolicyDecision::ImplicitDeny)
        );
        state.store.update_user(ACCOUNT, "caller", |user| {
            user.inline_policies.insert(
                "identity".into(),
                json!({"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}).to_string(),
            );
        });
        // Identity enforcement belongs to AWS_IAM methods, not the endpoint document.
        assert_eq!(
            state.evaluate_endpoint_policy(request(), identity(), &restricted),
            Ok(ResourcePolicyDecision::Allow)
        );
        let explicit_deny = json!({"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"*"}]}).to_string();
        assert_eq!(
            state.evaluate_endpoint_policy(request(), identity(), &explicit_deny),
            Ok(ResourcePolicyDecision::ExplicitDeny)
        );
        state.store.update_user(ACCOUNT, "caller", |user| {
            user.access_keys[0].status = "Inactive".into()
        });
        assert_eq!(
            state.evaluate_endpoint_policy(request(), identity(), &restricted),
            Err(AuthorizationError::Denied)
        );
    }
}

#[test]
fn endpoint_conditions_use_verified_network_context_for_anonymous_and_signed_callers() {
    let state = fixture(EnforcementMode::Permissive);
    let document = json!({"Statement":{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"*","Condition":{
        "StringEquals":{"aws:SourceVpc":"vpc-owned","aws:SourceVpce":"vpce-owned"},
        "IpAddress":{"aws:VpcSourceIp":"10.0.0.0/24"},
        "Null":{"aws:SourceIp":"true"}
    }}}).to_string();
    for identity in [None, identity()] {
        assert_eq!(
            state.evaluate_endpoint_policy(request(), identity.clone(), &document),
            Ok(ResourcePolicyDecision::Allow)
        );
        let mut wrong = request();
        wrong
            .context
            .insert("aws:sourcevpce".into(), vec!["vpce-other".into()]);
        assert_eq!(
            state.evaluate_endpoint_policy(wrong, identity.clone(), &document),
            Ok(ResourcePolicyDecision::ImplicitDeny)
        );
        let mut wrong = request();
        wrong
            .context
            .insert("aws:vpcsourceip".into(), vec!["10.1.0.4".into()]);
        assert_eq!(
            state.evaluate_endpoint_policy(wrong, identity, &document),
            Ok(ResourcePolicyDecision::ImplicitDeny)
        );
    }
}
