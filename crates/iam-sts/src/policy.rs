//! IAM policy parsing and the evaluation engine.
//!
//! Parses policy documents into statements, matches actions/resources with case-insensitive
//! globbing, evaluates condition operators, and applies the AWS order of precedence
//! (explicit Deny overrides; default deny; boundary/session withhold when present-but-
//! unmatched). Shared by the `Simulate*` APIs and by strict-mode enforcement.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde_json::Value;

use crate::error::IamStsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

/// One parsed policy statement.
#[derive(Debug, Clone)]
pub struct Statement {
    pub effect: Effect,
    pub actions: Vec<String>,
    pub not_actions: Vec<String>,
    pub resources: Vec<String>,
    pub not_resources: Vec<String>,
    /// operator → (condition key → candidate values).
    pub conditions: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

/// A parsed policy document.
#[derive(Debug, Clone, Default)]
pub struct PolicyDocument {
    pub statements: Vec<Statement>,
}

/// An evaluation request: the action, the target resource ARN, and the lowercased
/// condition context.
#[derive(Debug, Clone)]
pub struct EvalRequest {
    pub action: String,
    pub resource: String,
    pub context: BTreeMap<String, Vec<String>>,
}

/// Evaluation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    ImplicitDeny,
    ExplicitDeny,
}

impl PolicyDocument {
    /// Parse an identity or resource policy document.
    pub fn parse(doc: &str) -> Result<PolicyDocument, IamStsError> {
        Self::parse_with_options(doc, true)
    }

    /// Parse a role trust policy, where the role itself is the implicit resource.
    pub fn parse_trust(doc: &str) -> Result<PolicyDocument, IamStsError> {
        Self::parse_with_options(doc, false)
    }

    fn parse_with_options(
        doc: &str,
        resource_required: bool,
    ) -> Result<PolicyDocument, IamStsError> {
        let root: Value = serde_json::from_str(doc)
            .map_err(|e| IamStsError::MalformedPolicyDocument(format!("invalid JSON: {e}")))?;
        let statements_value = root.get("Statement").ok_or_else(|| {
            IamStsError::MalformedPolicyDocument("policy has no Statement".into())
        })?;
        let raw = match statements_value {
            Value::Array(items) if !items.is_empty() => items.clone(),
            Value::Array(_) => {
                return Err(IamStsError::MalformedPolicyDocument(
                    "Statement must not be empty".into(),
                ))
            }
            Value::Object(_) => vec![statements_value.clone()],
            _ => {
                return Err(IamStsError::MalformedPolicyDocument(
                    "Statement must be an object or array".into(),
                ))
            }
        };
        let mut statements = Vec::with_capacity(raw.len());
        for item in &raw {
            statements.push(parse_statement(item, resource_required)?);
        }
        Ok(PolicyDocument { statements })
    }
}

/// Minimal service-principal trust check. Unsupported trust constructs deny the role.
pub fn service_trust_allows(
    document: &str,
    service: &str,
    role_arn: &str,
    context: &BTreeMap<String, Vec<String>>,
) -> bool {
    let Ok(root) = serde_json::from_str::<Value>(document) else {
        return false;
    };
    let Some(statement) = root.get("Statement") else {
        return false;
    };
    let statements = match statement {
        Value::Array(items) if !items.is_empty() => items.iter().collect::<Vec<_>>(),
        Value::Object(_) => vec![statement],
        _ => return false,
    };
    let mut allowed = false;
    for statement in statements {
        if statement.get("NotPrincipal").is_some()
            || statement.get("NotAction").is_some()
            || statement.get("NotResource").is_some()
        {
            return false;
        }
        let Ok(parsed) = parse_statement(statement, false) else {
            return false;
        };
        // Unknown operators fail closed even with IfExists or an explicit Deny.
        if parsed.conditions.keys().any(|operator| {
            !matches!(
                operator.as_str(),
                "StringEquals"
                    | "StringLike"
                    | "ArnEquals"
                    | "ArnLike"
                    | "Null"
                    | "StringEqualsIfExists"
                    | "StringLikeIfExists"
                    | "ArnEqualsIfExists"
                    | "ArnLikeIfExists"
            )
        }) {
            return false;
        }
        let principal = statement.get("Principal");
        let principal_matches = match principal {
            Some(Value::String(value)) if value == "*" => true,
            Some(Value::Object(map)) if map.len() == 1 => map
                .get("Service")
                .and_then(|value| parse_string_set("Service", Some(value)).ok())
                .is_some_and(|services| any_glob(&services, service)),
            _ => false,
        };
        let request = EvalRequest {
            action: "sts:AssumeRole".into(),
            resource: role_arn.into(),
            context: context.clone(),
        };
        if !principal_matches || !parsed.matches(&request) {
            continue;
        }
        if parsed.effect == Effect::Deny {
            return false;
        }
        allowed = true;
    }
    allowed
}

fn parse_statement(item: &Value, resource_required: bool) -> Result<Statement, IamStsError> {
    let obj = item.as_object().ok_or_else(|| {
        IamStsError::MalformedPolicyDocument("statement must be an object".into())
    })?;
    let effect = match obj.get("Effect") {
        Some(Value::String(value)) if value == "Allow" => Effect::Allow,
        Some(Value::String(value)) if value == "Deny" => Effect::Deny,
        Some(Value::String(value)) => {
            return Err(IamStsError::MalformedPolicyDocument(format!(
                "invalid Effect: {value}"
            )))
        }
        Some(_) => {
            return Err(IamStsError::MalformedPolicyDocument(
                "Effect must be a string".into(),
            ))
        }
        None => {
            return Err(IamStsError::MalformedPolicyDocument(
                "statement has no Effect".into(),
            ))
        }
    };
    let actions = parse_string_set("Action", obj.get("Action"))?;
    let not_actions = parse_string_set("NotAction", obj.get("NotAction"))?;
    require_exactly_one("Action", &actions, "NotAction", &not_actions, true)?;
    let resources = parse_string_set("Resource", obj.get("Resource"))?;
    let not_resources = parse_string_set("NotResource", obj.get("NotResource"))?;
    require_exactly_one(
        "Resource",
        &resources,
        "NotResource",
        &not_resources,
        resource_required,
    )?;
    let conditions = parse_conditions(obj.get("Condition"))?;
    Ok(Statement {
        effect,
        actions,
        not_actions,
        resources,
        not_resources,
        conditions,
    })
}

fn require_exactly_one(
    first_name: &str,
    first: &[String],
    second_name: &str,
    second: &[String],
    required: bool,
) -> Result<(), IamStsError> {
    if (!first.is_empty() && !second.is_empty())
        || (required && first.is_empty() && second.is_empty())
    {
        return Err(IamStsError::MalformedPolicyDocument(format!(
            "statement must contain exactly one of {first_name} or {second_name}"
        )));
    }
    Ok(())
}

fn parse_conditions(
    value: Option<&Value>,
) -> Result<BTreeMap<String, BTreeMap<String, Vec<String>>>, IamStsError> {
    let mut out = BTreeMap::new();
    let Some(map) = value else { return Ok(out) };
    let map = map.as_object().ok_or_else(|| {
        IamStsError::MalformedPolicyDocument("Condition must be an object".into())
    })?;
    for (operator, keys) in map {
        let keys = keys.as_object().ok_or_else(|| {
            IamStsError::MalformedPolicyDocument("condition operator must map keys".into())
        })?;
        let mut key_map = BTreeMap::new();
        for (key, value) in keys {
            key_map.insert(key.to_ascii_lowercase(), condition_values(value)?);
        }
        out.insert(operator.clone(), key_map);
    }
    Ok(out)
}

fn parse_string_set(field: &str, value: Option<&Value>) -> Result<Vec<String>, IamStsError> {
    let values = match value {
        None => return Ok(Vec::new()),
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(items)) if !items.is_empty() => items
            .iter()
            .map(|item| match item {
                Value::String(value) => Ok(value.clone()),
                _ => Err(IamStsError::MalformedPolicyDocument(format!(
                    "{field} array values must be strings"
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(Value::Array(_)) => {
            return Err(IamStsError::MalformedPolicyDocument(format!(
                "{field} must not be empty"
            )))
        }
        Some(_) => {
            return Err(IamStsError::MalformedPolicyDocument(format!(
                "{field} must be a string or array of strings"
            )))
        }
    };
    if values.iter().any(String::is_empty) {
        return Err(IamStsError::MalformedPolicyDocument(format!(
            "{field} values must not be empty"
        )));
    }
    Ok(values)
}

fn condition_values(value: &Value) -> Result<Vec<String>, IamStsError> {
    fn scalar(value: &Value) -> Option<String> {
        match value {
            Value::String(value) => Some(value.clone()),
            Value::Bool(value) => Some(value.to_string()),
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        }
    }

    match value {
        Value::Array(items) if !items.is_empty() => items
            .iter()
            .map(|item| {
                scalar(item).ok_or_else(|| {
                    IamStsError::MalformedPolicyDocument(
                        "Condition array values must be scalar".into(),
                    )
                })
            })
            .collect(),
        Value::Array(_) => Err(IamStsError::MalformedPolicyDocument(
            "Condition values must not be empty".into(),
        )),
        _ => scalar(value).map(|value| vec![value]).ok_or_else(|| {
            IamStsError::MalformedPolicyDocument("Condition values must be scalar".into())
        }),
    }
}

/// Case-insensitive glob: `*` matches any sequence (incl. empty), `?` exactly one char.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_case_sensitive(&pattern.to_ascii_lowercase(), &text.to_ascii_lowercase())
}

fn glob_match_case_sensitive(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // Iterative wildcard match with backtracking.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn any_glob(patterns: &[String], text: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, text))
}

impl Statement {
    /// Whether this statement applies to the request (action, resource, conditions).
    fn matches(&self, req: &EvalRequest) -> bool {
        let action_ok = if !self.actions.is_empty() {
            any_glob(&self.actions, &req.action)
        } else if !self.not_actions.is_empty() {
            !any_glob(&self.not_actions, &req.action)
        } else {
            false
        };
        if !action_ok {
            return false;
        }
        let resource_ok = if !self.resources.is_empty() {
            self.resources
                .iter()
                .any(|pattern| glob_match_case_sensitive(pattern, &req.resource))
        } else if !self.not_resources.is_empty() {
            !self
                .not_resources
                .iter()
                .any(|pattern| glob_match_case_sensitive(pattern, &req.resource))
        } else {
            // No resource constraint is treated as `*`.
            true
        };
        if !resource_ok {
            return false;
        }
        self.conditions_satisfied(&req.context)
    }

    fn conditions_satisfied(&self, context: &BTreeMap<String, Vec<String>>) -> bool {
        self.conditions.iter().all(|(op, keys)| {
            keys.iter()
                .all(|(k, vals)| eval_condition(op, k, vals, context))
        })
    }
}

/// Evaluate one condition `operator`/`key`/`values` against the request context.
/// AND across operator blocks/keys (caller), OR across candidate values (here).
fn eval_condition(
    operator: &str,
    key: &str,
    values: &[String],
    context: &BTreeMap<String, Vec<String>>,
) -> bool {
    let (base, if_exists) = match operator.strip_suffix("IfExists") {
        Some(b) => (b, true),
        None => (operator, false),
    };
    if base == "Null" {
        // {"Null": {"key": "true"}} ⇒ matches iff the key is absent.
        let present = context.get(key).map(|v| !v.is_empty()).unwrap_or(false);
        return values.iter().any(|v| (v == "true") != present);
    }
    let negated = matches!(
        base,
        "StringNotEquals"
            | "StringNotEqualsIgnoreCase"
            | "StringNotLike"
            | "ArnNotLike"
            | "ArnNotEquals"
            | "NumericNotEquals"
            | "DateNotEquals"
            | "NotIpAddress"
    );
    let ctx_values = match context.get(key) {
        Some(v) if !v.is_empty() => v,
        _ => return if_exists || negated,
    };
    if negated {
        ctx_values
            .iter()
            .all(|cv| values.iter().all(|pv| apply_operator(base, pv, cv)))
    } else {
        ctx_values
            .iter()
            .any(|cv| values.iter().any(|pv| apply_operator(base, pv, cv)))
    }
}

fn apply_operator(op: &str, policy_value: &str, ctx_value: &str) -> bool {
    if op.starts_with("Numeric") && (num(policy_value).is_none() || num(ctx_value).is_none()) {
        return false;
    }
    match op {
        "StringEquals" => policy_value == ctx_value,
        "StringNotEquals" => policy_value != ctx_value,
        "StringEqualsIgnoreCase" => policy_value.eq_ignore_ascii_case(ctx_value),
        "StringNotEqualsIgnoreCase" => !policy_value.eq_ignore_ascii_case(ctx_value),
        "StringLike" | "ArnLike" | "ArnEquals" => {
            glob_match_case_sensitive(policy_value, ctx_value)
        }
        "StringNotLike" | "ArnNotLike" | "ArnNotEquals" => {
            !glob_match_case_sensitive(policy_value, ctx_value)
        }
        "Bool" => policy_value.eq_ignore_ascii_case(ctx_value),
        "NumericEquals" => num(policy_value) == num(ctx_value),
        "NumericNotEquals" => num(policy_value) != num(ctx_value),
        "NumericLessThan" => num(ctx_value) < num(policy_value),
        "NumericLessThanEquals" => num(ctx_value) <= num(policy_value),
        "NumericGreaterThan" => num(ctx_value) > num(policy_value),
        "NumericGreaterThanEquals" => num(ctx_value) >= num(policy_value),
        // ISO-8601 UTC (`Z`) timestamps compare correctly lexicographically.
        "DateEquals" => policy_value == ctx_value,
        "DateNotEquals" => policy_value != ctx_value,
        "DateLessThan" => ctx_value < policy_value,
        "DateLessThanEquals" => ctx_value <= policy_value,
        "DateGreaterThan" => ctx_value > policy_value,
        "DateGreaterThanEquals" => ctx_value >= policy_value,
        "IpAddress" => ip_in_cidr(ctx_value, policy_value),
        "NotIpAddress" => !ip_in_cidr(ctx_value, policy_value),
        _ => false, // unsupported operator never matches
    }
}

fn num(s: &str) -> Option<f64> {
    s.parse::<f64>().ok().filter(|value| value.is_finite())
}

/// Whether `ip` (IPv4) falls within `cidr` (`a.b.c.d/n` or an exact address).
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let Ok(addr) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    let (net, bits) = match cidr.split_once('/') {
        Some((n, b)) => (n, b.parse::<u32>().unwrap_or(32)),
        None => (cidr, 32),
    };
    let Ok(net_addr) = net.parse::<Ipv4Addr>() else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let mask: u32 = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    (u32::from(addr) & mask) == (u32::from(net_addr) & mask)
}

/// Evaluate the AWS order of precedence across identity policies, with optional permission
/// boundary and session policy sets (each withholds when present-but-unmatched).
pub fn evaluate(
    identity: &[PolicyDocument],
    boundary: Option<&[PolicyDocument]>,
    session: Option<&[PolicyDocument]>,
    req: &EvalRequest,
) -> Decision {
    // Explicit Deny anywhere overrides everything.
    let mut all = Vec::new();
    all.extend(identity.iter());
    if let Some(b) = boundary {
        all.extend(b.iter());
    }
    if let Some(s) = session {
        all.extend(s.iter());
    }
    if all.iter().any(|doc| has_matching(doc, Effect::Deny, req)) {
        return Decision::ExplicitDeny;
    }
    let identity_allows = identity
        .iter()
        .any(|doc| has_matching(doc, Effect::Allow, req));
    let boundary_allows = boundary.map(|b| b.iter().any(|d| has_matching(d, Effect::Allow, req)));
    let session_allows = session.map(|s| s.iter().any(|d| has_matching(d, Effect::Allow, req)));
    let allowed =
        identity_allows && boundary_allows.unwrap_or(true) && session_allows.unwrap_or(true);
    if allowed {
        Decision::Allowed
    } else {
        Decision::ImplicitDeny
    }
}

fn has_matching(doc: &PolicyDocument, effect: Effect, req: &EvalRequest) -> bool {
    doc.statements
        .iter()
        .any(|s| s.effect == effect && s.matches(req))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(action: &str, resource: &str) -> EvalRequest {
        EvalRequest {
            action: action.to_string(),
            resource: resource.to_string(),
            context: BTreeMap::new(),
        }
    }

    #[test]
    fn resource_case_and_negated_value_sets_are_preserved() {
        let document = PolicyDocument::parse(r#"{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/Key"}}"#).unwrap();
        assert_eq!(
            evaluate(
                std::slice::from_ref(&document),
                None,
                None,
                &req("s3:getobject", "arn:aws:s3:::bucket/Key")
            ),
            Decision::Allowed
        );
        assert_eq!(
            evaluate(
                &[document],
                None,
                None,
                &req("s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ImplicitDeny
        );
        let context = BTreeMap::from([("key".into(), vec!["a".into()])]);
        assert!(!eval_condition(
            "StringNotEquals",
            "key",
            &["a".into(), "b".into()],
            &context
        ));
        assert!(eval_condition(
            "StringNotEquals",
            "missing",
            &["a".into()],
            &context
        ));
    }

    #[test]
    fn glob_matches_wildcards() {
        assert!(glob_match("s3:*", "s3:GetObject"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("s3:Get?bject", "s3:GetObject"));
        assert!(!glob_match("s3:Put*", "s3:GetObject"));
        assert!(glob_match("ARN:AWS:*", "arn:aws:s3:::bucket")); // case-insensitive
    }

    #[test]
    fn parse_rejects_invalid_json() {
        assert!(matches!(
            PolicyDocument::parse("{not json"),
            Err(IamStsError::MalformedPolicyDocument(_))
        ));
    }

    #[test]
    fn parse_requires_valid_explicit_effect() {
        for document in [
            r#"{"Statement":{"Action":"s3:*","Resource":"*"}}"#,
            r#"{"Statement":{"Effect":null,"Action":"s3:*","Resource":"*"}}"#,
            r#"{"Statement":{"Effect":"Permit","Action":"s3:*","Resource":"*"}}"#,
        ] {
            assert!(matches!(
                PolicyDocument::parse(document),
                Err(IamStsError::MalformedPolicyDocument(_))
            ));
        }
    }

    #[test]
    fn parse_rejects_mixed_or_ambiguous_sets() {
        for document in [
            r#"{"Statement":{"Effect":"Allow","Action":["s3:*",7],"Resource":"*"}}"#,
            r#"{"Statement":{"Effect":"Allow","Action":"s3:*","NotAction":"iam:*","Resource":"*"}}"#,
            r#"{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":["*",null]}}"#,
            r#"{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","NotResource":"arn:aws:s3:::private/*"}}"#,
        ] {
            assert!(matches!(
                PolicyDocument::parse(document),
                Err(IamStsError::MalformedPolicyDocument(_))
            ));
        }
    }

    #[test]
    fn trust_policy_allows_implicit_role_resource() {
        PolicyDocument::parse_trust(
            r#"{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}}"#,
        )
        .unwrap();
    }

    #[test]
    fn parse_single_statement_object() {
        let doc = PolicyDocument::parse(
            r#"{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}"#,
        )
        .unwrap();
        assert_eq!(doc.statements.len(), 1);
        assert_eq!(doc.statements[0].effect, Effect::Allow);
    }

    #[test]
    fn explicit_deny_overrides_allow() {
        let allow = PolicyDocument::parse(
            r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#,
        )
        .unwrap();
        let deny = PolicyDocument::parse(
            r#"{"Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}"#,
        )
        .unwrap();
        let d = evaluate(&[allow, deny], None, None, &req("s3:DeleteBucket", "*"));
        assert_eq!(d, Decision::ExplicitDeny);
    }

    #[test]
    fn default_deny_without_allow() {
        let doc = PolicyDocument::parse(
            r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
        )
        .unwrap();
        assert_eq!(
            evaluate(&[doc], None, None, &req("s3:PutObject", "*")),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn boundary_withholds_when_unmatched() {
        let identity = PolicyDocument::parse(
            r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#,
        )
        .unwrap();
        let boundary = PolicyDocument::parse(
            r#"{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
        )
        .unwrap();
        // Allowed by identity but outside the boundary ⇒ implicit deny.
        assert_eq!(
            evaluate(
                std::slice::from_ref(&identity),
                Some(std::slice::from_ref(&boundary)),
                None,
                &req("ec2:RunInstances", "*")
            ),
            Decision::ImplicitDeny
        );
        // Within the boundary ⇒ allowed.
        assert_eq!(
            evaluate(
                &[identity],
                Some(&[boundary]),
                None,
                &req("s3:GetObject", "*")
            ),
            Decision::Allowed
        );
    }

    #[test]
    fn string_condition_gates_match() {
        let doc = PolicyDocument::parse(
            r#"{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:username":"alice"}}}]}"#,
        )
        .unwrap();
        let mut r = req("s3:GetObject", "*");
        assert_eq!(
            evaluate(std::slice::from_ref(&doc), None, None, &r),
            Decision::ImplicitDeny
        );
        r.context
            .insert("aws:username".into(), vec!["alice".into()]);
        assert_eq!(evaluate(&[doc], None, None, &r), Decision::Allowed);
    }

    #[test]
    fn null_condition_checks_presence() {
        let doc = PolicyDocument::parse(
            r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Null":{"aws:TokenIssueTime":"true"}}}]}"#,
        )
        .unwrap();
        // Key absent ⇒ Null:true satisfied ⇒ allowed.
        assert_eq!(
            evaluate(&[doc], None, None, &req("s3:Get", "*")),
            Decision::Allowed
        );
    }

    #[test]
    fn ip_cidr_matching() {
        assert!(ip_in_cidr("10.0.0.5", "10.0.0.0/24"));
        assert!(!ip_in_cidr("10.0.1.5", "10.0.0.0/24"));
        assert!(ip_in_cidr("192.168.1.1", "192.168.1.1"));
    }

    #[test]
    fn numeric_operator() {
        assert!(apply_operator("NumericLessThan", "100", "50"));
        assert!(!apply_operator("NumericLessThan", "100", "150"));
    }
}
