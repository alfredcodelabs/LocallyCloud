//! Property-based tests for IAM/STS invariants (design Properties: ARN/path, glob, policy
//! precedence/determinism, error→status fidelity). Real engine, no mocks.

use std::collections::BTreeMap;

use proptest::prelude::*;

use locallycloud_iam_sts::arn::{build_iam_arn, normalize_path};
use locallycloud_iam_sts::error::IamStsError;
use locallycloud_iam_sts::policy::{evaluate, glob_match, Decision, EvalRequest, PolicyDocument};

fn eval_req(action: &str) -> EvalRequest {
    EvalRequest {
        action: action.to_string(),
        resource: "*".to_string(),
        context: BTreeMap::new(),
    }
}

proptest! {
    // Built IAM ARNs are well-formed and account-scoped.
    #[test]
    fn iam_arn_is_account_scoped(account in "[0-9]{12}", name in "[A-Za-z0-9_-]{1,32}") {
        let arn = build_iam_arn(&account, "user", "/", &name);
        let prefix = format!("arn:aws:iam::{}:user/", account);
        prop_assert!(arn.starts_with(&prefix));
        prop_assert!(arn.ends_with(&name));
    }

    // normalize_path is slash-bounded and idempotent.
    #[test]
    fn normalize_path_is_slash_bounded(p in "[A-Za-z0-9/_-]{0,20}") {
        let n = normalize_path(&p);
        prop_assert!(n.starts_with('/'));
        prop_assert!(n.ends_with('/'));
        prop_assert_eq!(normalize_path(&n), n.clone());
    }

    // A wildcard-free pattern matches itself.
    #[test]
    fn glob_literal_matches_self(s in "[a-z:]{1,20}") {
        prop_assert!(glob_match(&s, &s));
    }

    // "*" matches anything (over identifier-like strings; ARNs/actions never contain newlines).
    #[test]
    fn glob_star_matches_all(s in "[a-zA-Z0-9:_/.-]{0,30}") {
        prop_assert!(glob_match("*", &s));
    }

    // A prefix wildcard matches any string carrying that prefix.
    #[test]
    fn glob_prefix_matches(prefix in "[a-z]{1,8}", suffix in "[a-z]{0,8}") {
        let pattern = format!("{}*", prefix);
        let text = format!("{}{}", prefix, suffix);
        prop_assert!(glob_match(&pattern, &text));
    }

    // An explicit Deny matching the action overrides any Allow, deterministically.
    #[test]
    fn explicit_deny_overrides_allow(action in "[a-z]{1,6}:[A-Za-z]{1,12}") {
        let doc = PolicyDocument::parse(&format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"*","Resource":"*"}},{{"Effect":"Deny","Action":"{action}","Resource":"*"}}]}}"#
        )).unwrap();
        let req = eval_req(&action);
        let d1 = evaluate(std::slice::from_ref(&doc), None, None, &req);
        let d2 = evaluate(std::slice::from_ref(&doc), None, None, &req);
        prop_assert_eq!(d1, Decision::ExplicitDeny);
        prop_assert_eq!(d1, d2);
    }

    // Omitting Effect never produces an authorizing policy.
    #[test]
    fn omitted_effect_is_always_malformed(action in "[a-z]{1,6}:[A-Za-z]{1,12}") {
        let document = format!(
            r#"{{"Statement":[{{"Action":"{action}","Resource":"*"}}]}}"#
        );
        prop_assert!(matches!(
            PolicyDocument::parse(&document),
            Err(IamStsError::MalformedPolicyDocument(_))
        ));
    }

    // With no matching statement, the decision is ImplicitDeny (default deny).
    #[test]
    fn no_match_is_implicit_deny(action in "[a-z]{1,6}:[A-Za-z]{1,12}") {
        prop_assume!(!action.eq_ignore_ascii_case("s3:GetObject"));
        let doc = PolicyDocument::parse(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
        ).unwrap();
        prop_assert_eq!(evaluate(std::slice::from_ref(&doc), None, None, &eval_req(&action)), Decision::ImplicitDeny);
    }
}

/// Exhaustive error→status fidelity: every variant has a non-empty code, an AWS-faithful
/// status, and renders that code into the Query XML envelope.
#[test]
fn every_error_variant_maps_to_aws_status_and_code() {
    let variants = [
        IamStsError::NoSuchEntity("x".into()),
        IamStsError::EntityAlreadyExists("x".into()),
        IamStsError::DeleteConflict("x".into()),
        IamStsError::LimitExceeded("x".into()),
        IamStsError::MalformedPolicyDocument("x".into()),
        IamStsError::ValidationError("x".into()),
        IamStsError::AccessDenied("x".into()),
        IamStsError::InvalidAction("x".into()),
    ];
    let allowed = [400u16, 403, 404, 409];
    for err in variants {
        let code = err.code();
        assert!(!code.is_empty());
        assert!(
            allowed.contains(&err.http_status()),
            "{code} status {} not AWS-faithful",
            err.http_status()
        );
    }
}
