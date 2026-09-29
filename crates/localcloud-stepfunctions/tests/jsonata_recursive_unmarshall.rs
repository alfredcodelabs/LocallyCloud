//! Regression gate for H6: recursive `$u`-style unmarshalling must not collapse
//! to `null`. Covers recursive `$unmarshall` input from a consumer integration.

use std::collections::BTreeMap;

use localcloud_stepfunctions::jsonata::evaluate;
use serde_json::{json, Value};

fn vars(input: Value) -> BTreeMap<String, Value> {
    BTreeMap::from([(
        "$states".to_string(),
        json!({"input": input, "context": {}}),
    )])
}

/// H6 reproducer: a Pass state expression that self-recursive-unmarshals `x`.
#[test]
fn recursive_unmarshall_returns_nested_data() {
    let input = json!({"x":{"M":{"eq":{"L":[{"M":{"name":{"S":"a"}}}]}}}});
    let expr =
        "{% ( $u := function($v){( $exists($v.S) ? $v.S : $exists($v.L) ? [$v.L.($u($))] : $v )}; $u(x) ) %}";
    let got = evaluate(expr, &vars(json!({"x": input["x"]}))).unwrap();
    // No `S`/`L` at the top level of `x`, so the recursive identity path must
    // return the nested data untouched — never `null`.
    assert_eq!(
        got, input["x"],
        "recursive unmarshall must return nested data"
    );
    assert_ne!(
        got,
        Value::Null,
        "recursive unmarshall must not return null"
    );
}

#[test]
fn recursive_identity_on_plain_object() {
    // Simpler sibling case: recursion that never hits S/L.
    let expr = "{% ( $u := function($v){( $exists($v.S) ? $v.S : $v )}; $u(x) ) %}";
    let got = evaluate(expr, &vars(json!({"x": {"deep": [1, 2]}}))).unwrap();
    assert_eq!(got, json!({"deep": [1, 2]}));
}

#[test]
fn missing_field_and_explicit_null_remain_distinct() {
    let vars = vars(json!({"x": {"N": null}}));
    assert_eq!(
        evaluate("{% ( $v := x; $exists($v.S) ) %}", &vars).unwrap(),
        json!(false)
    );
    assert_eq!(
        evaluate("{% ( $v := x; $exists($v.N) ) %}", &vars).unwrap(),
        json!(true)
    );
}

#[test]
fn integer_results_and_hashes_use_json_integer_format() {
    let vars = vars(json!({}));
    assert_eq!(evaluate("{% 1 + 1 %}", &vars).unwrap().to_string(), "2");
    assert_eq!(
        evaluate("{% {\"a\": 1, \"nested\": [2, 2.5]} %}", &vars)
            .unwrap()
            .to_string(),
        "{\"a\":1,\"nested\":[2,2.5]}"
    );
    assert_eq!(
        evaluate("{% $reduce([1,2,3], function($a,$b){$a+$b}) %}", &vars)
            .unwrap()
            .to_string(),
        "6"
    );
    assert_eq!(
        evaluate("{% $hash({\"a\":1}, \"SHA-256\") %}", &vars).unwrap(),
        json!("015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862")
    );
}

#[test]
fn recursive_unmarshall_visits_list_items() {
    let expr = "{% ( $u := function($v){( $exists($v.S) ? $v.S : $exists($v.L) ? [$v.L.($u($))] : $v )}; $u(x) ) %}";
    let input = vars(json!({"x": {"L": [{"S": "a"}, {"S": "b"}]}}));
    let got = evaluate(expr, &input).unwrap();
    assert_eq!(got, json!(["a", "b"]));
}

#[test]
fn exists_on_array_path_respects_empty_sequence() {
    let vars = vars(json!({"x": [{"a": []}]}));
    let direct = evaluate("{% $exists(x.a) %}", &vars).unwrap();
    let variable = evaluate("{% ($v := x; $exists($v.a)) %}", &vars).unwrap();
    assert_eq!(variable, direct);
}

#[test]
fn exists_on_object_empty_array_matches_direct_path() {
    let vars = vars(json!({"x": {"a": []}}));
    let direct = evaluate("{% $exists(x.a) %}", &vars).unwrap();
    let variable = evaluate("{% ($v := x; $exists($v.a)) %}", &vars).unwrap();
    assert_eq!(variable, direct);
}
