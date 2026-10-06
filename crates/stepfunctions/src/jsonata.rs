//! JSONata evaluation for Step Functions, backed by a complete external engine.
//! AWS-specific functions and `$states`/workflow bindings are installed per evaluation.

use std::collections::BTreeMap;

use jsonata_core::ast::{AstNode, BinaryOp, Stage};
use jsonata_core::evaluator::{Context, Evaluator, EvaluatorError};
use jsonata_core::value::JValue;
use md5::Md5;
use serde_json::{Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::AslError;

/// Whether a string field is a JSONata expression (`{% ... %}`).
pub fn is_expression(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("{%") && trimmed.ends_with("%}")
}

fn inner(value: &str) -> &str {
    value
        .trim()
        .trim_start_matches("{%")
        .trim_end_matches("%}")
        .trim()
}

/// Evaluate a `{% %}` expression against `$states` and workflow-variable bindings.
pub fn evaluate(expr: &str, vars: &BTreeMap<String, Value>) -> Result<Value, AslError> {
    let mut ast = jsonata_core::parser::parse(inner(expr))
        .map_err(|error| query_error(error.display_message()))?;
    preserve_empty_state_arrays(&mut ast, vars);
    preserve_exists_on_variable_paths(&mut ast);
    let mut context = Context::new();
    for (name, value) in vars {
        context.bind(
            name.trim_start_matches('$').to_string(),
            JValue::from(value.clone()),
        );
    }
    let root = vars
        .get("$states")
        .and_then(|states| states.get("input"))
        .cloned()
        .unwrap_or(Value::Null);
    let mut evaluator = Evaluator::with_context(context);
    register_aws_functions(&mut evaluator)?;
    let result = evaluator
        .evaluate(&ast, &JValue::from(root))
        .map_err(|error| query_error(error.message()))?;
    if result.is_undefined() {
        return Err(query_error(
            "JSONata expression returned nothing (undefined)",
        ));
    }
    Ok(normalize_integral_numbers(Value::from(&result)))
}

/// Add the ASL field context to errors observed from AWS JSONata evaluation.
pub fn evaluate_for_field(
    expr: &str,
    vars: &BTreeMap<String, Value>,
    field: &str,
) -> Result<Value, AslError> {
    evaluate(expr, vars).map_err(|mut error| {
        let prefix = format!(
            "The JSONata expression '{}' specified for the field '{field}'",
            inner(expr)
        );
        if error.cause == "JSONata expression returned nothing (undefined)" {
            error.cause = format!("{prefix} returned nothing (undefined).");
        } else if error.cause.starts_with("T0410:") {
            error.cause = format!("{prefix} threw an error during evaluation. {}", error.cause);
        }
        error
    })
}

/// The engine represents every JSON number as f64. Serialize exactly
/// representable integral values as JSON integers, including nested results.
fn normalize_integral_numbers(value: Value) -> Value {
    match value {
        Value::Number(number) => {
            let Some(float) = number.as_f64() else {
                return Value::Number(number);
            };
            const MAX_EXACT_INTEGER: f64 = 9_007_199_254_740_991.0;
            if float.is_finite()
                && float.fract() == 0.0
                && float.abs() <= MAX_EXACT_INTEGER
                && !(float == 0.0 && float.is_sign_negative())
            {
                Value::from(float as i64)
            } else {
                Value::Number(number)
            }
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().map(normalize_integral_numbers).collect())
        }
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (key, normalize_integral_numbers(value)))
                .collect(),
        ),
        other => other,
    }
}

/// The external engine flattens a terminal empty array on a variable path into
/// `undefined`. Direct object lookup preserves the array. Apply that equivalent
/// lookup only to simple `$states` paths known to end at an empty JSON array.
fn preserve_empty_state_arrays(node: &mut AstNode, vars: &BTreeMap<String, Value>) {
    match node {
        AstNode::Path { steps } => {
            if steps.len() >= 2
                && steps.iter().all(|step| {
                    step.stages.is_empty()
                        && step.focus.is_none()
                        && step.index_var.is_none()
                        && step.ancestor_label.is_none()
                        && !step.is_tuple
                })
                && matches!(&steps[0].node, AstNode::Variable(name) if name == "states")
            {
                let names: Option<Vec<&str>> = steps[1..]
                    .iter()
                    .map(|step| match &step.node {
                        AstNode::Name(name) => Some(name.as_str()),
                        _ => None,
                    })
                    .collect();
                if let Some(names) = names {
                    let mut value = vars.get("$states");
                    for name in &names {
                        value = value.and_then(|current| current.get(*name));
                    }
                    if matches!(value, Some(Value::Array(items)) if items.is_empty()) {
                        let last = names.last().expect("path has a field").to_string();
                        let prefix = if steps.len() == 2 {
                            AstNode::Variable("states".to_string())
                        } else {
                            AstNode::Path {
                                steps: steps[..steps.len() - 1].to_vec(),
                            }
                        };
                        *node = AstNode::Function {
                            name: "lookup".to_string(),
                            args: vec![prefix, AstNode::String(last)],
                            is_builtin: true,
                        };
                        return;
                    }
                }
            }
            for step in steps {
                preserve_empty_state_arrays(&mut step.node, vars);
                for stage in &mut step.stages {
                    if let Stage::Filter(filter) = stage {
                        preserve_empty_state_arrays(filter, vars);
                    }
                }
            }
        }
        AstNode::Function { args, .. } | AstNode::Array(args) | AstNode::ArrayGroup(args) => {
            for arg in args {
                preserve_empty_state_arrays(arg, vars);
            }
        }
        AstNode::Call { procedure, args } => {
            preserve_empty_state_arrays(procedure, vars);
            for arg in args {
                preserve_empty_state_arrays(arg, vars);
            }
        }
        AstNode::Object(pairs) => {
            for (key, value) in pairs {
                preserve_empty_state_arrays(key, vars);
                preserve_empty_state_arrays(value, vars);
            }
        }
        AstNode::Block(expressions)
            if !expressions.iter().any(|expression| {
                matches!(expression, AstNode::Binary {
                    op: BinaryOp::ColonEqual,
                    lhs,
                    ..
                } if matches!(lhs.as_ref(), AstNode::Variable(name) if name == "states"))
            }) =>
        {
            for expression in expressions {
                preserve_empty_state_arrays(expression, vars);
            }
        }
        AstNode::Lambda { params, body, .. } if !params.iter().any(|param| param == "states") => {
            preserve_empty_state_arrays(body, vars);
        }
        AstNode::Unary { operand, .. }
        | AstNode::Predicate(operand)
        | AstNode::FunctionApplication(operand) => preserve_empty_state_arrays(operand, vars),
        AstNode::Binary { op, lhs, rhs } if *op != BinaryOp::ColonEqual => {
            preserve_empty_state_arrays(lhs, vars);
            preserve_empty_state_arrays(rhs, vars);
        }
        AstNode::Conditional {
            condition,
            then_branch,
            else_branch,
        } => {
            preserve_empty_state_arrays(condition, vars);
            preserve_empty_state_arrays(then_branch, vars);
            if let Some(else_branch) = else_branch {
                preserve_empty_state_arrays(else_branch, vars);
            }
        }
        // Leave any scope that can shadow `$states` to the engine.
        _ => {}
    }
}

/// jsonata-core turns a missing property on a variable path into JSON null.
/// For `$exists($v.field)`, inspect the parent object directly so missing and
/// explicit null retain distinct meanings.
fn preserve_exists_on_variable_paths(node: &mut AstNode) {
    match node {
        AstNode::Function {
            name,
            args,
            is_builtin: true,
        } if name == "exists" && args.len() == 1 => {
            preserve_exists_on_variable_paths(&mut args[0]);
            if let AstNode::Path { steps } = &args[0] {
                if steps.len() >= 2
                    && matches!(
                        steps.first().map(|step| &step.node),
                        Some(AstNode::Variable(_))
                    )
                    && steps.iter().all(|step| {
                        step.stages.is_empty()
                            && step.focus.is_none()
                            && step.index_var.is_none()
                            && step.ancestor_label.is_none()
                            && !step.is_tuple
                    })
                {
                    if let AstNode::Name(field) = &steps.last().expect("path has field").node {
                        let parent = if steps.len() == 2 {
                            steps[0].node.clone()
                        } else {
                            AstNode::Path {
                                steps: steps[..steps.len() - 1].to_vec(),
                            }
                        };
                        *node = AstNode::Function {
                            name: "existsField".to_string(),
                            args: vec![parent, AstNode::String(field.clone())],
                            is_builtin: true,
                        };
                    }
                }
            }
        }
        AstNode::Path { steps } => {
            for step in steps {
                preserve_exists_on_variable_paths(&mut step.node);
                for stage in &mut step.stages {
                    if let Stage::Filter(filter) = stage {
                        preserve_exists_on_variable_paths(filter);
                    }
                }
            }
        }
        AstNode::Function { args, .. }
        | AstNode::Array(args)
        | AstNode::ArrayGroup(args)
        | AstNode::Block(args) => {
            for arg in args {
                preserve_exists_on_variable_paths(arg);
            }
        }
        AstNode::Call { procedure, args } => {
            preserve_exists_on_variable_paths(procedure);
            for arg in args {
                preserve_exists_on_variable_paths(arg);
            }
        }
        AstNode::Object(pairs) => {
            for (key, value) in pairs {
                preserve_exists_on_variable_paths(key);
                preserve_exists_on_variable_paths(value);
            }
        }
        AstNode::Unary { operand, .. }
        | AstNode::Predicate(operand)
        | AstNode::FunctionApplication(operand) => preserve_exists_on_variable_paths(operand),
        AstNode::Binary { lhs, rhs, .. } => {
            preserve_exists_on_variable_paths(lhs);
            preserve_exists_on_variable_paths(rhs);
        }
        AstNode::Conditional {
            condition,
            then_branch,
            else_branch,
        } => {
            preserve_exists_on_variable_paths(condition);
            preserve_exists_on_variable_paths(then_branch);
            if let Some(branch) = else_branch {
                preserve_exists_on_variable_paths(branch);
            }
        }
        AstNode::Lambda { body, .. } => preserve_exists_on_variable_paths(body),
        AstNode::ObjectTransform { input, pattern } => {
            preserve_exists_on_variable_paths(input);
            for (key, value) in pattern {
                preserve_exists_on_variable_paths(key);
                preserve_exists_on_variable_paths(value);
            }
        }
        AstNode::Sort { input, terms } => {
            preserve_exists_on_variable_paths(input);
            for (term, _) in terms {
                preserve_exists_on_variable_paths(term);
            }
        }
        AstNode::Transform {
            location,
            update,
            delete,
        } => {
            preserve_exists_on_variable_paths(location);
            preserve_exists_on_variable_paths(update);
            if let Some(delete) = delete {
                preserve_exists_on_variable_paths(delete);
            }
        }
        _ => {}
    }
}

/// Recursively process an `Arguments`/`Output`/`Assign` JSONata template.
pub fn process(template: &Value, vars: &BTreeMap<String, Value>) -> Result<Value, AslError> {
    match template {
        Value::String(value) if is_expression(value) => evaluate(value, vars),
        Value::Object(object) => {
            let mut output = Map::new();
            for (key, value) in object {
                output.insert(key.clone(), process(value, vars)?);
            }
            Ok(Value::Object(output))
        }
        Value::Array(values) => values
            .iter()
            .map(|value| process(value, vars))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        value => Ok(value.clone()),
    }
}

/// Process a whole-field expression while retaining the field's error context.
pub fn process_for_field(
    template: &Value,
    vars: &BTreeMap<String, Value>,
    field: &str,
) -> Result<Value, AslError> {
    match template {
        Value::String(value) if is_expression(value) => evaluate_for_field(value, vars, field),
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| {
                Ok((
                    key.clone(),
                    process_for_field(value, vars, &format!("{field}/{key}"))?,
                ))
            })
            .collect::<Result<Map<_, _>, AslError>>()
            .map(Value::Object),
        Value::Array(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| process_for_field(value, vars, &format!("{field}[{index}]")))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        value => Ok(value.clone()),
    }
}

fn register_aws_functions(evaluator: &mut Evaluator) -> Result<(), AslError> {
    evaluator.register_fn("hash", hash).map_err(engine_error)?;
    evaluator
        .register_fn("existsField", exists_field)
        .map_err(engine_error)?;
    evaluator.register_fn("uuid", uuid).map_err(engine_error)?;
    evaluator
        .register_fn("parse", parse)
        .map_err(engine_error)?;
    evaluator
        .register_fn("partition", partition)
        .map_err(engine_error)?;
    evaluator
        .register_fn("range", range)
        .map_err(engine_error)?;
    evaluator
        .register_fn_override("random", random)
        .map_err(engine_error)?;
    evaluator
        .register_fn_override("exists", exists)
        .map_err(engine_error)?;
    Ok(())
}

/// JSONata `$exists`: true when the argument yields a value, false only for an
/// empty sequence. The engine's built-in also treats an explicit `null` as absent,
/// which diverges from JSONata 2.0.6.
fn exists(args: &[JValue]) -> Result<JValue, EvaluatorError> {
    let present = match args.first() {
        None => false,
        Some(JValue::Undefined) => false,
        Some(_) => true,
    };
    Ok(JValue::Bool(present))
}

fn exists_field(args: &[JValue]) -> Result<JValue, EvaluatorError> {
    let Some(JValue::String(field)) = args.get(1) else {
        return Err(custom_error("$exists field must be a string"));
    };
    let present = match args.first() {
        Some(JValue::Object(object)) => match object.get(field.as_ref()) {
            Some(JValue::Array(values)) => !values.is_empty(),
            Some(_) => true,
            None => false,
        },
        Some(JValue::Array(items)) => items.iter().any(|item| {
            let JValue::Object(object) = item else {
                return false;
            };
            match object.get(field.as_ref()) {
                Some(JValue::Array(values)) => !values.is_empty(),
                Some(JValue::Null | JValue::Undefined) | None => false,
                Some(_) => true,
            }
        }),
        _ => false,
    };
    Ok(JValue::Bool(present))
}

fn hash(args: &[JValue]) -> Result<JValue, EvaluatorError> {
    let data = required(args, 0, "$hash requires data and an algorithm")?;
    let algorithm = required(args, 1, "$hash requires data and an algorithm")?
        .as_str()
        .ok_or_else(|| custom_error("$hash algorithm must be a string"))?
        .to_ascii_uppercase();
    let bytes = match data {
        JValue::String(value) => value.as_bytes().to_vec(),
        value => normalize_integral_numbers(Value::from(value))
            .to_string()
            .into_bytes(),
    };
    let digest = match algorithm.as_str() {
        "MD5" => format!("{:x}", Md5::digest(&bytes)),
        "SHA-1" | "SHA1" => format!("{:x}", Sha1::digest(&bytes)),
        "SHA-256" | "SHA256" => format!("{:x}", Sha256::digest(&bytes)),
        "SHA-384" | "SHA384" => format!("{:x}", Sha384::digest(&bytes)),
        "SHA-512" | "SHA512" => format!("{:x}", Sha512::digest(&bytes)),
        _ => {
            return Err(custom_error(
                "$hash algorithm must be MD5, SHA-1, SHA-256, SHA-384, or SHA-512",
            ))
        }
    };
    Ok(JValue::from(digest))
}

fn uuid(args: &[JValue]) -> Result<JValue, EvaluatorError> {
    if !args.is_empty() {
        return Err(custom_error("$uuid does not accept arguments"));
    }
    Ok(JValue::from(uuid::Uuid::new_v4().to_string()))
}

fn parse(args: &[JValue]) -> Result<JValue, EvaluatorError> {
    let source = required(args, 0, "$parse requires a JSON string")?
        .as_str()
        .ok_or_else(|| custom_error("$parse argument must be a string"))?;
    if args.len() != 1 {
        return Err(custom_error("$parse accepts exactly one argument"));
    }
    JValue::from_json_str(source)
        .map_err(|error| custom_error(format!("$parse received invalid JSON: {error}")))
}

fn partition(args: &[JValue]) -> Result<JValue, EvaluatorError> {
    let values = required(args, 0, "$partition requires an array and chunk size")?
        .as_array()
        .ok_or_else(|| custom_error("$partition first argument must be an array"))?;
    let size = positive_usize(
        required(args, 1, "$partition requires an array and chunk size")?,
        "$partition chunk size",
    )?;
    if args.len() != 2 {
        return Err(custom_error("$partition accepts exactly two arguments"));
    }
    Ok(JValue::array(
        values
            .chunks(size)
            .map(|chunk| JValue::array(chunk.to_vec()))
            .collect(),
    ))
}

fn range(args: &[JValue]) -> Result<JValue, EvaluatorError> {
    let signature_error = |index| {
        custom_error(format!(
            "T0410: Argument {index} of function \"range\" does not match function signature"
        ))
    };
    if args.len() > 3 {
        return Err(signature_error(4));
    }
    for (index, value) in args.iter().enumerate() {
        if !value.is_number() && !value.is_undefined() {
            return Err(signature_error(index + 1));
        }
    }
    if args.len() < 3 || args.iter().any(JValue::is_undefined) {
        return Ok(JValue::Undefined);
    }
    let rounded_integer = |value: &JValue, name: &str| {
        value
            .as_f64()
            .map(f64::trunc)
            .filter(|number| {
                number.is_finite() && *number >= i64::MIN as f64 && *number < -(i64::MIN as f64)
            })
            .map(|number| number as i64)
            .ok_or_else(|| {
                custom_error(format!(
                    "Local $range limit: {name} must be a finite number within the supported integer range"
                ))
            })
    };
    let start = rounded_integer(&args[0], "$range start")?;
    let end = rounded_integer(&args[1], "$range end")?;
    let step = rounded_integer(&args[2], "$range step")?;
    if step == 0 || (step > 0 && start > end) || (step < 0 && start < end) {
        return Ok(JValue::Undefined);
    }
    let count = (i128::from(end) - i128::from(start)).abs() / i128::from(step).abs() + 1;
    // Local allocation budget; AWS JSONata range accepts more than 1000 items.
    if count > 100_000 {
        return Err(custom_error(
            "Local $range limit: result must not exceed 100000 items",
        ));
    }
    if count == 1 {
        return Ok(JValue::from(start));
    }
    Ok(JValue::array(
        (0..count)
            .map(|index| JValue::from((i128::from(start) + index * i128::from(step)) as i64))
            .collect(),
    ))
}

fn random(args: &[JValue]) -> Result<JValue, EvaluatorError> {
    if args.len() > 1 {
        return Err(custom_error("$random accepts at most one seed"));
    }
    let bytes = match args.first() {
        Some(seed) => Sha256::digest(Value::from(seed).to_string().as_bytes()).to_vec(),
        None => uuid::Uuid::new_v4().as_bytes().to_vec(),
    };
    let mut sample = [0u8; 8];
    sample.copy_from_slice(&bytes[..8]);
    let mantissa = u64::from_be_bytes(sample) >> 11;
    Ok(JValue::from(mantissa as f64 / (1u64 << 53) as f64))
}

fn required<'a>(
    args: &'a [JValue],
    index: usize,
    message: &str,
) -> Result<&'a JValue, EvaluatorError> {
    args.get(index).ok_or_else(|| custom_error(message))
}

fn integer(value: &JValue, name: &str) -> Result<i64, EvaluatorError> {
    value
        .as_i64()
        .ok_or_else(|| custom_error(format!("{name} must be an integer")))
}

fn positive_usize(value: &JValue, name: &str) -> Result<usize, EvaluatorError> {
    let number = integer(value, name)?;
    usize::try_from(number)
        .ok()
        .filter(|number| *number > 0)
        .ok_or_else(|| custom_error(format!("{name} must be at least 1")))
}

fn custom_error(message: impl Into<String>) -> EvaluatorError {
    EvaluatorError::EvaluationError(message.into())
}

fn engine_error(error: EvaluatorError) -> AslError {
    query_error(error.message())
}

fn query_error(message: impl Into<String>) -> AslError {
    AslError::new("States.QueryEvaluationError", message.into())
}

#[cfg(test)]
mod range_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inclusive_endpoints_and_observed_truncation() {
        for (expression, expected) in [
            ("$range(1, 9, 2)", json!([1, 3, 5, 7, 9])),
            ("$range(9, 1, -2)", json!([9, 7, 5, 3, 1])),
            ("$range(1, 8, 2)", json!([1, 3, 5, 7])),
            ("$range(8, 1, -2)", json!([8, 6, 4, 2])),
            ("$range(3, 3, 1)", json!(3)),
            ("$range(3, 3, -1)", json!(3)),
            ("$range(-1.2, 2.8, 1.9)", json!([-1, 0, 1, 2])),
            ("$range(2.8, -1.2, -1.2)", json!([2, 1, 0, -1])),
            ("$range(-1.1, -5.1, -1.1)", json!([-1, -2, -3, -4, -5])),
        ] {
            assert_eq!(
                evaluate(&format!("{{% {expression} %}}"), &BTreeMap::new()).unwrap(),
                expected,
                "{expression}"
            );
        }
    }

    #[test]
    fn invalid_arguments_and_sequence_limit_are_query_errors() {
        for expression in [
            "$range()",
            "$range(1)",
            "$range(1, 3)",
            "$range(1, 3, 1, 1)",
            "$range('1', 3, 1)",
            "$range(1, null, 1)",
            "$range(1, 3, true)",
            "$range(1, 3, 0)",
            "$range(1, 3, 0.9)",
            "$range(1, 3, $missing)",
            "$range(1, 3, -1)",
            "$range(3, 1, 1)",
            "$range(0, 100000, 1)",
            "$range(9223372036854775808, 0, -1)",
        ] {
            assert_eq!(
                evaluate(&format!("{{% {expression} %}}"), &BTreeMap::new())
                    .unwrap_err()
                    .error,
                "States.QueryEvaluationError",
                "{expression}"
            );
        }
        let values = evaluate("{% $range(0, 999, 1) %}", &BTreeMap::new()).unwrap();
        assert_eq!(values.as_array().unwrap().len(), 1000);
        assert_eq!(values[999], json!(999));
        let values = evaluate("{% $range(0, 1000, 1) %}", &BTreeMap::new()).unwrap();
        assert_eq!(values.as_array().unwrap().len(), 1001);
        assert_eq!(values[1000], json!(1000));
    }

    #[test]
    fn stops_without_an_overflowing_final_increment() {
        for (start, end, step) in [
            (i64::MIN, i64::MIN, -1),
            (i64::MIN + 1024, i64::MIN, -2048),
            (i64::MAX - 1023, i64::MAX - 1023, 2048),
            (i64::MAX - 2047, i64::MAX - 1023, 4096),
        ] {
            let result =
                range(&[JValue::from(start), JValue::from(end), JValue::from(step)]).unwrap();
            assert_eq!(result.as_f64(), Some(start as f64));
        }
        for number in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            assert!(range(&[JValue::from(number), JValue::from(0), JValue::from(1)]).is_err());
        }
    }

    #[test]
    fn undefined_and_singleton_ranges_follow_jsonata_composition() {
        for expression in [
            "$range(3,1,1)",
            "$range(1,3,-1)",
            "$range(0,4,0)",
            "$range(0,4)",
        ] {
            assert_eq!(
                evaluate(
                    &format!("{{% $append([], {expression}) %}}"),
                    &BTreeMap::new()
                )
                .unwrap(),
                json!([])
            );
            let error =
                evaluate_for_field(&format!("{{% {expression} %}}"), &BTreeMap::new(), "Output")
                    .unwrap_err();
            assert_eq!(error.cause, format!("The JSONata expression '{expression}' specified for the field 'Output' returned nothing (undefined)."));
        }
        assert_eq!(
            evaluate("{% $append([], $range(7,7,1)) %}", &BTreeMap::new()).unwrap(),
            json!([7])
        );
        let error = process_for_field(&json!("{% $range('0',4,1) %}"), &BTreeMap::new(), "Output")
            .unwrap_err();
        assert_eq!(error.cause, "The JSONata expression '$range('0',4,1)' specified for the field 'Output' threw an error during evaluation. T0410: Argument 1 of function \"range\" does not match function signature");
        let error =
            evaluate_for_field("{% $range(0,4,1,2) %}", &BTreeMap::new(), "Output").unwrap_err();
        assert_eq!(error.cause, "The JSONata expression '$range(0,4,1,2)' specified for the field 'Output' threw an error during evaluation. T0410: Argument 4 of function \"range\" does not match function signature");
        assert_eq!(
            evaluate("{% null %}", &BTreeMap::new()).unwrap(),
            Value::Null
        );
    }
}

#[cfg(test)]
mod exists_tests {
    use super::*;
    use serde_json::json;

    fn vars() -> BTreeMap<String, Value> {
        BTreeMap::from([(
            "$states".to_string(),
            json!({"input":{"items":[1,2],"empty":[],"presentNull":null}}),
        )])
    }

    #[test]
    fn empty_array_path_stays_a_value() {
        let vars = vars();
        assert_eq!(
            evaluate("{% $states.input.empty %}", &vars).unwrap(),
            json!([])
        );
        assert_eq!(
            evaluate("{% $exists($states.input.empty) %}", &vars).unwrap(),
            json!(true)
        );
        assert_eq!(
            evaluate(
                "{% $filter($states.input.empty, function($v) {$v > 5}) %}",
                &vars
            )
            .unwrap_err()
            .error,
            "States.QueryEvaluationError"
        );
        assert_eq!(
            evaluate("{% ($x := 1; $exists($states.input.empty)) %}", &vars).unwrap(),
            json!(true)
        );
        assert_eq!(
            evaluate("{% $exists($states.input.missing) %}", &vars).unwrap(),
            json!(false)
        );
        assert_eq!(
            evaluate("{% $exists($states.input.items[$ > 5]) %}", &vars).unwrap(),
            json!(false)
        );
    }

    // The fixable part of the report: $exists(null) must be true, while a missing
    // path / empty sequence must stay false.
    #[test]
    fn exists_null_and_missing() {
        let vars = vars();
        assert_eq!(
            evaluate("{% $exists($states.input.presentNull) %}", &vars).unwrap(),
            json!(true)
        );
        assert_eq!(
            evaluate("{% $exists($states.input.missing) %}", &vars).unwrap(),
            json!(false)
        );
        // A non-empty array is a value; an empty filter produces an absent sequence.
        assert_eq!(
            evaluate("{% $exists($states.input.items) %}", &vars).unwrap(),
            json!(true)
        );
        assert_eq!(
            evaluate(
                "{% $exists($filter($states.input.items, function($v) {$v > 5})) %}",
                &vars
            )
            .unwrap(),
            json!(false)
        );
        // An empty sequence from a predicate with no match stays absent.
        assert_eq!(
            evaluate("{% $exists($states.input.items[$ > 5]) %}", &vars).unwrap(),
            json!(false)
        );
    }
}
