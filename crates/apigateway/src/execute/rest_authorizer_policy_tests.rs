use super::*;

const ROUTE: &str = "arn:aws:execute-api:us-east-1:000000000000:api/prod/GET/items";

fn response(decision: ResourcePolicyDecision) -> Value {
    let (effect, resource) = match decision {
        ResourcePolicyDecision::Allow => ("Allow", ROUTE),
        ResourcePolicyDecision::ExplicitDeny => ("Deny", ROUTE),
        ResourcePolicyDecision::ImplicitDeny => (
            "Allow",
            "arn:aws:execute-api:us-east-1:000000000000:api/prod/GET/other",
        ),
    };
    json!({"principalId":"subject", "context":{"team":"core"}, "policyDocument":{"Version":"2012-10-17","Statement":[{"Effect":effect,"Action":"execute-api:Invoke","Resource":resource}]}})
}

#[test]
fn rest_authorizer_and_resource_policies_follow_table_a() {
    use ResourcePolicyDecision::{Allow, ExplicitDeny, ImplicitDeny};
    for (authorizer, resource, allowed) in [
        (Allow, Allow, true),
        (Allow, ImplicitDeny, true),
        (Allow, ExplicitDeny, false),
        (ImplicitDeny, Allow, true),
        (ImplicitDeny, ImplicitDeny, false),
        (ImplicitDeny, ExplicitDeny, false),
        (ExplicitDeny, Allow, false),
        (ExplicitDeny, ImplicitDeny, false),
        (ExplicitDeny, ExplicitDeny, false),
    ] {
        let result = interpret_authorizer(
            ApiKind::Rest,
            &json!({}),
            &response(authorizer),
            ROUTE,
            resource,
        );
        assert_eq!(result.is_ok(), allowed, "{authorizer:?} + {resource:?}");
        if allowed {
            let context = result.unwrap().lambda.unwrap();
            assert_eq!(context["principalId"], "subject");
            assert_eq!(context["team"], "core");
        } else {
            assert_eq!(result.unwrap_err(), 403);
        }
    }
}

#[test]
fn resource_allow_does_not_rescue_malformed_or_unsupported_authorizer_responses() {
    let valid = response(ResourcePolicyDecision::Allow);
    let mut cases = vec![
        json!({}),
        json!({"principalId":"subject"}),
        json!({"principalId":"subject","policyDocument":{"Statement":[]}}),
    ];
    for (pointer, value) in [
        ("/principalId", json!(false)),
        ("/principalId", json!("")),
        ("/context", json!([])),
        ("/policyDocument/Statement/0/Effect", json!("Unknown")),
        ("/policyDocument/Statement/0/Action", json!(false)),
        ("/policyDocument/Statement/0/Resource", json!([])),
    ] {
        let mut malformed = valid.clone();
        *malformed.pointer_mut(pointer).unwrap() = value;
        cases.push(malformed);
    }
    let mut unsupported = valid.clone();
    unsupported["policyDocument"]["Statement"][0]["Condition"] =
        json!({"StringEquals":{"unsupported":"value"}});
    cases.push(unsupported);
    for malformed in cases {
        assert_eq!(
            interpret_authorizer(
                ApiKind::Rest,
                &json!({}),
                &malformed,
                ROUTE,
                ResourcePolicyDecision::Allow
            )
            .unwrap_err(),
            500
        );
    }
}

#[test]
fn cached_authorizer_policy_is_recombined_with_the_current_resource_decision() {
    let cache = BTreeMap::from([(
        "subject".into(),
        json!({"expiresAt":now_secs()+60,"result":response(ResourcePolicyDecision::ImplicitDeny)}),
    )]);
    let cached = crate::store::cached_authorizer(&cache, "subject").unwrap();
    assert!(interpret_authorizer(
        ApiKind::Rest,
        &json!({}),
        &cached,
        ROUTE,
        ResourcePolicyDecision::Allow
    )
    .is_ok());
    for resource in [
        ResourcePolicyDecision::ExplicitDeny,
        ResourcePolicyDecision::ImplicitDeny,
    ] {
        assert_eq!(
            interpret_authorizer(ApiKind::Rest, &json!({}), &cached, ROUTE, resource).unwrap_err(),
            403
        );
    }
}

#[test]
fn rest_singleton_policies_work_without_changing_http_or_websocket_policy_shape() {
    let mut singleton = response(ResourcePolicyDecision::Allow);
    singleton["policyDocument"]["Statement"] = singleton["policyDocument"]["Statement"][0].clone();
    assert!(interpret_authorizer(
        ApiKind::Rest,
        &json!({}),
        &singleton,
        ROUTE,
        ResourcePolicyDecision::ImplicitDeny
    )
    .is_ok());
    assert!(!policy_allows(&singleton, ROUTE));
    assert_eq!(
        interpret_authorizer(
            ApiKind::Http,
            &json!({}),
            &singleton,
            ROUTE,
            ResourcePolicyDecision::Allow
        )
        .unwrap_err(),
        403
    );
    assert_eq!(
        interpret_authorizer(
            ApiKind::Http,
            &json!({}),
            &response(ResourcePolicyDecision::ImplicitDeny),
            ROUTE,
            ResourcePolicyDecision::Allow
        )
        .unwrap_err(),
        403
    );
    assert!(interpret_authorizer(
        ApiKind::Http,
        &json!({"enableSimpleResponses":true}),
        &json!({"isAuthorized":true}),
        ROUTE,
        ResourcePolicyDecision::ImplicitDeny
    )
    .is_ok());
    assert_eq!(
        interpret_authorizer(
            ApiKind::Http,
            &json!({"enableSimpleResponses":true}),
            &json!({"isAuthorized":false}),
            ROUTE,
            ResourcePolicyDecision::Allow
        )
        .unwrap_err(),
        403
    );
}

#[test]
fn resource_allow_cannot_override_authorizer_deny_with_question_mark_wildcards() {
    let result = json!({"principalId":"subject","policyDocument":{"Statement":[{"Effect":"Deny","Action":"ExEcUtE-ApI:Invok?","Resource":"arn:aws:execute-api:us-east-1:000000000000:api/prod/GET/item?"}]}});
    assert_eq!(
        interpret_authorizer(
            ApiKind::Rest,
            &json!({}),
            &result,
            ROUTE,
            ResourcePolicyDecision::Allow
        )
        .unwrap_err(),
        403
    );
    let allow = json!({"principalId":"subject","policyDocument":{"Statement":[{"Effect":"Allow","Action":"EXECUTE-API:INVOKE","Resource":ROUTE}]}});
    assert!(interpret_authorizer(
        ApiKind::Rest,
        &json!({}),
        &allow,
        ROUTE,
        ResourcePolicyDecision::ImplicitDeny
    )
    .is_ok());
    assert_eq!(
        interpret_authorizer(
            ApiKind::Rest,
            &json!({}),
            &allow,
            &ROUTE.replace("items", "ITEMS"),
            ResourcePolicyDecision::ImplicitDeny
        )
        .unwrap_err(),
        403
    );
}
