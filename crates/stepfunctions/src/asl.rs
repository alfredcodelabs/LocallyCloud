//! Amazon States Language parsing and structural validation. The interpreter operates on
//! the validated JSON state objects directly (idiomatic for ASL's dynamic shape).

use std::collections::{HashSet, VecDeque};

use serde_json::{Map, Value};

use crate::error::SfnError;

pub const MAX_DEFINITION_BYTES: usize = 1_048_576;
pub const MAX_NESTING_DEPTH: usize = 100;

/// A parsed, structurally-validated state machine definition.
#[derive(Debug, Clone)]
pub struct StateMachine {
    pub start_at: String,
    pub states: Map<String, Value>,
    /// The original definition JSON (for DescribeStateMachine).
    pub definition: Value,
}

const VALID_TYPES: &[&str] = &[
    "Pass", "Task", "Choice", "Wait", "Succeed", "Fail", "Parallel", "Map",
];
const JSONPATH_FIELDS: &[&str] = &[
    "InputPath",
    "Parameters",
    "ResultPath",
    "ResultSelector",
    "OutputPath",
    "ItemsPath",
    "MaxConcurrencyPath",
    "ToleratedFailureCountPath",
    "ToleratedFailurePercentagePath",
    "SecondsPath",
    "TimestampPath",
    "TimeoutSecondsPath",
    "HeartbeatSecondsPath",
    "ErrorPath",
    "CausePath",
];
const JSONATA_FIELDS: &[&str] = &["Arguments", "Output", "Items"];

impl StateMachine {
    pub fn parse(definition: &str) -> Result<Self, SfnError> {
        Self::parse_for_type(definition, None)
    }

    pub fn parse_for_type(definition: &str, machine_type: Option<&str>) -> Result<Self, SfnError> {
        let diagnostics = Self::diagnostics(definition, machine_type);
        if let Some(message) = diagnostics.first() {
            return Err(SfnError::InvalidDefinition(message.clone()));
        }
        let value: Value = serde_json::from_str(definition).map_err(|error| {
            SfnError::InvalidDefinition(format!("definition is not valid JSON: {error}"))
        })?;
        Self::from_validated_value(value)
    }

    pub fn diagnostics(definition: &str, machine_type: Option<&str>) -> Vec<String> {
        if definition.len() > MAX_DEFINITION_BYTES {
            return vec![format!(
                "definition exceeds the {MAX_DEFINITION_BYTES}-byte limit"
            )];
        }
        let value: Value = match serde_json::from_str(definition) {
            Ok(value) => value,
            Err(error) => return vec![format!("definition is not valid JSON: {error}")],
        };
        validate_definition(&value, machine_type)
    }

    pub fn from_value(value: Value) -> Result<Self, SfnError> {
        let diagnostics = validate_definition(&value, None);
        if let Some(message) = diagnostics.first() {
            return Err(SfnError::InvalidDefinition(message.clone()));
        }
        Self::from_validated_value(value)
    }

    /// Parse a nested branch or processor using the enclosing state's query language
    /// when the nested machine does not declare its own default.
    pub fn from_value_with_default(mut value: Value, default_ql: &str) -> Result<Self, SfnError> {
        if let Some(object) = value.as_object_mut() {
            object
                .entry("QueryLanguage")
                .or_insert_with(|| Value::String(default_ql.to_string()));
        }
        Self::from_value(value)
    }

    fn from_validated_value(value: Value) -> Result<Self, SfnError> {
        let start_at = value
            .get("StartAt")
            .and_then(Value::as_str)
            .ok_or_else(|| SfnError::InvalidDefinition("missing StartAt".into()))?
            .to_string();
        let states = value
            .get("States")
            .and_then(Value::as_object)
            .ok_or_else(|| SfnError::InvalidDefinition("missing States".into()))?
            .clone();
        Ok(Self {
            start_at,
            states,
            definition: value,
        })
    }

    pub fn state(&self, name: &str) -> Option<&Value> {
        self.states.get(name)
    }
}

/// Validate a standalone state definition as accepted by TestState.
pub fn validate_single_state(state: &Value) -> Vec<String> {
    let Some(object) = state.as_object() else {
        return vec!["definition must contain a state object".into()];
    };
    let mut states = Map::new();
    states.insert("TestState".into(), state.clone());
    for target in transition_targets(state) {
        if target != "TestState" {
            states.insert(target.to_string(), serde_json::json!({ "Type": "Succeed" }));
        }
    }
    let default_ql = object
        .get("QueryLanguage")
        .and_then(Value::as_str)
        .unwrap_or("JSONPath");
    let mut errors = Vec::new();
    validate_scope(
        &states,
        Some("TestState"),
        default_ql,
        None,
        0,
        "TestState definition",
        &mut errors,
    );
    errors
}

fn validate_definition(value: &Value, machine_type: Option<&str>) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(object) = value.as_object() else {
        return vec!["definition must be a JSON object".into()];
    };
    let default_ql =
        validate_query_language(object.get("QueryLanguage"), "definition", &mut errors)
            .unwrap_or("JSONPath");
    if let Some(timeout) = object.get("TimeoutSeconds") {
        match timeout.as_u64().filter(|value| *value > 0) {
            None => errors.push("TimeoutSeconds must be a positive integer".into()),
            Some(value) if machine_type == Some("EXPRESS") && value > 300 => {
                errors.push("EXPRESS TimeoutSeconds must not exceed 300".into());
            }
            Some(value) if machine_type == Some("STANDARD") && value > 31_536_000 => {
                errors.push("STANDARD TimeoutSeconds must not exceed one year".into());
            }
            _ => {}
        }
    }
    if object
        .get("Version")
        .is_some_and(|value| value.as_str() != Some("1.0"))
    {
        errors.push("Version must be the string '1.0'".into());
    }
    if object
        .get("Comment")
        .is_some_and(|value| !value.is_string())
    {
        errors.push("Comment must be a string".into());
    }
    let start_at = object.get("StartAt").and_then(Value::as_str);
    if start_at.is_none() {
        errors.push("missing StartAt".into());
    }
    let Some(states) = object.get("States").and_then(Value::as_object) else {
        errors.push("missing States".into());
        return errors;
    };
    if states.is_empty() {
        errors.push("States must not be empty".into());
    }
    if let Some(start) = start_at {
        if !states.contains_key(start) {
            errors.push(format!("StartAt '{start}' is not a defined state"));
        }
    }
    validate_scope(
        states,
        start_at,
        default_ql,
        machine_type,
        0,
        "definition",
        &mut errors,
    );
    errors
}

fn validate_scope(
    states: &Map<String, Value>,
    start_at: Option<&str>,
    default_ql: &str,
    machine_type: Option<&str>,
    depth: usize,
    scope: &str,
    errors: &mut Vec<String>,
) {
    if depth > MAX_NESTING_DEPTH {
        errors.push(format!(
            "{scope} exceeds the maximum nesting depth of {MAX_NESTING_DEPTH}"
        ));
        return;
    }
    for (name, state) in states {
        let label = format!("{scope} state '{name}'");
        let Some(object) = state.as_object() else {
            errors.push(format!("{label} must be an object"));
            continue;
        };
        let Some(state_type) = object.get("Type").and_then(Value::as_str) else {
            errors.push(format!("{label} missing Type"));
            continue;
        };
        if !VALID_TYPES.contains(&state_type) {
            errors.push(format!("{label} has invalid Type '{state_type}'"));
            continue;
        }
        let query_language = validate_query_language(object.get("QueryLanguage"), &label, errors)
            .unwrap_or(default_ql);
        validate_language_fields(object, query_language, &label, errors);
        validate_transition(object, state_type, states, &label, errors);
        validate_retry_and_catch(object, state_type, states, &label, errors);
        validate_state_fields(
            object,
            state_type,
            states,
            query_language,
            machine_type,
            depth,
            &label,
            errors,
        );
    }
    validate_reachability(states, start_at, scope, errors);
}

fn validate_query_language<'a>(
    value: Option<&'a Value>,
    label: &str,
    errors: &mut Vec<String>,
) -> Option<&'a str> {
    match value {
        None => None,
        Some(Value::String(language)) if matches!(language.as_str(), "JSONPath" | "JSONata") => {
            Some(language)
        }
        Some(_) => {
            errors.push(format!("{label} QueryLanguage must be JSONPath or JSONata"));
            None
        }
    }
}

fn validate_language_fields(
    state: &Map<String, Value>,
    query_language: &str,
    label: &str,
    errors: &mut Vec<String>,
) {
    let forbidden = if query_language == "JSONata" {
        JSONPATH_FIELDS
    } else {
        JSONATA_FIELDS
    };
    for field in forbidden {
        if state.contains_key(*field) {
            errors.push(format!(
                "{label} uses field '{field}' under QueryLanguage {query_language}"
            ));
        }
    }
    for field in ["InputPath", "ResultPath", "OutputPath"] {
        if let Some(value) = state.get(field) {
            if !value.is_null() && !value.is_string() {
                errors.push(format!("{label} {field} must be a string or null"));
            }
        }
    }
    if state.get("Assign").is_some_and(|value| !value.is_object()) {
        errors.push(format!("{label} Assign must be an object"));
    }
}

fn validate_transition(
    state: &Map<String, Value>,
    state_type: &str,
    states: &Map<String, Value>,
    label: &str,
    errors: &mut Vec<String>,
) {
    let has_next = state.contains_key("Next");
    let has_end = state.contains_key("End");
    if has_next && has_end {
        errors.push(format!("{label} cannot specify both Next and End"));
    }
    if let Some(next) = state.get("Next") {
        match next.as_str() {
            Some(next) if !states.contains_key(next) => {
                errors.push(format!("{label} transitions to undefined state '{next}'"));
            }
            None => errors.push(format!("{label} Next must be a string")),
            _ => {}
        }
    }
    if let Some(end) = state.get("End") {
        if end.as_bool() != Some(true) {
            errors.push(format!("{label} End must be true"));
        }
    }
    match state_type {
        "Choice" | "Succeed" | "Fail" if has_next || has_end => {
            errors.push(format!("{label} cannot specify Next or End"));
        }
        "Choice" | "Succeed" | "Fail" => {}
        _ if !has_next && !has_end => errors.push(format!("{label} must specify Next or End")),
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_state_fields(
    state: &Map<String, Value>,
    state_type: &str,
    states: &Map<String, Value>,
    query_language: &str,
    machine_type: Option<&str>,
    depth: usize,
    label: &str,
    errors: &mut Vec<String>,
) {
    match state_type {
        "Task" => {
            let resource = state.get("Resource").and_then(Value::as_str);
            if resource.is_none() {
                errors.push(format!("{label} requires a string Resource"));
            }
            if machine_type == Some("EXPRESS")
                && resource.is_some_and(|value| {
                    value.ends_with(".sync")
                        || value.ends_with(".sync:2")
                        || value.ends_with(".waitForTaskToken")
                        || value.contains(":activity:")
                })
            {
                errors.push(format!(
                    "{label} uses an integration pattern unsupported by EXPRESS workflows"
                ));
            }
            validate_positive_integer_fields(
                state,
                &["TimeoutSeconds", "HeartbeatSeconds"],
                label,
                errors,
            );
            validate_mutually_exclusive(
                state,
                &[
                    ("TimeoutSeconds", "TimeoutSecondsPath"),
                    ("HeartbeatSeconds", "HeartbeatSecondsPath"),
                ],
                label,
                errors,
            );
            if let (Some(timeout), Some(heartbeat)) = (
                state.get("TimeoutSeconds").and_then(Value::as_u64),
                state.get("HeartbeatSeconds").and_then(Value::as_u64),
            ) {
                if heartbeat >= timeout {
                    errors.push(format!(
                        "{label} HeartbeatSeconds must be less than TimeoutSeconds"
                    ));
                }
            }
        }
        "Choice" => validate_choice(state, states, query_language, label, errors),
        "Fail" => {
            validate_mutually_exclusive(
                state,
                &[("Error", "ErrorPath"), ("Cause", "CausePath")],
                label,
                errors,
            );
            for field in ["Error", "ErrorPath", "Cause", "CausePath"] {
                if state.get(field).is_some_and(|value| !value.is_string()) {
                    errors.push(format!("{label} {field} must be a string"));
                }
            }
        }
        "Wait" => {
            let fields = ["Seconds", "SecondsPath", "Timestamp", "TimestampPath"];
            if fields
                .iter()
                .filter(|field| state.contains_key(**field))
                .count()
                != 1
            {
                errors.push(format!("{label} must specify exactly one Wait time field"));
            }
            if let Some(seconds) = state.get("Seconds") {
                if seconds.as_u64().is_none()
                    && !seconds.as_str().is_some_and(crate::jsonata::is_expression)
                {
                    errors.push(format!(
                        "{label} Seconds must be a non-negative integer or JSONata expression"
                    ));
                }
            }
        }
        "Parallel" => match state.get("Branches").and_then(Value::as_array) {
            Some(branches) if !branches.is_empty() => {
                for (index, branch) in branches.iter().enumerate() {
                    validate_nested_machine(
                        branch,
                        query_language,
                        machine_type,
                        depth + 1,
                        &format!("{label} branch {index}"),
                        errors,
                    );
                }
            }
            _ => errors.push(format!("{label} requires a non-empty Branches array")),
        },
        "Map" => {
            let processor = state.get("ItemProcessor").or_else(|| state.get("Iterator"));
            if processor.is_none()
                || (state.contains_key("ItemProcessor") && state.contains_key("Iterator"))
            {
                errors.push(format!(
                    "{label} requires exactly one ItemProcessor or Iterator"
                ));
            }
            if let Some(processor) = processor {
                validate_nested_machine(
                    processor,
                    query_language,
                    machine_type,
                    depth + 1,
                    &format!("{label} processor"),
                    errors,
                );
            }
            let mode = state
                .get("ItemProcessor")
                .and_then(|processor| processor.pointer("/ProcessorConfig/Mode"))
                .and_then(Value::as_str)
                .unwrap_or("INLINE");
            if !matches!(mode, "INLINE" | "DISTRIBUTED") {
                errors.push(format!(
                    "{label} ProcessorConfig.Mode must be INLINE or DISTRIBUTED"
                ));
            }
            let distributed = mode == "DISTRIBUTED";
            if distributed && machine_type == Some("EXPRESS") {
                errors.push(format!(
                    "{label} Distributed Map is unsupported by EXPRESS workflows"
                ));
            }
            if !distributed
                && [
                    "ItemReader",
                    "ItemBatcher",
                    "ResultWriter",
                    "ToleratedFailureCount",
                    "ToleratedFailureCountPath",
                    "ToleratedFailurePercentage",
                    "ToleratedFailurePercentagePath",
                ]
                .iter()
                .any(|field| state.contains_key(*field))
            {
                errors.push(format!("{label} uses fields that require DISTRIBUTED mode"));
            }
            validate_non_negative_number_fields(
                state,
                &[
                    "MaxConcurrency",
                    "ToleratedFailureCount",
                    "ToleratedFailurePercentage",
                ],
                label,
                errors,
            );
            if state
                .get("ToleratedFailurePercentage")
                .and_then(Value::as_f64)
                .is_some_and(|value| value > 100.0)
            {
                errors.push(format!(
                    "{label} ToleratedFailurePercentage must not exceed 100"
                ));
            }
            validate_mutually_exclusive(
                state,
                &[
                    ("MaxConcurrency", "MaxConcurrencyPath"),
                    ("ToleratedFailureCount", "ToleratedFailureCountPath"),
                    (
                        "ToleratedFailurePercentage",
                        "ToleratedFailurePercentagePath",
                    ),
                ],
                label,
                errors,
            );
            if let Some(batcher) = state.get("ItemBatcher").and_then(Value::as_object) {
                if !batcher.contains_key("MaxItemsPerBatch")
                    && !batcher.contains_key("MaxInputBytesPerBatch")
                {
                    errors.push(format!("{label} ItemBatcher requires a batch size limit"));
                }
            }
        }
        _ => {}
    }
}

fn validate_nested_machine(
    value: &Value,
    default_ql: &str,
    machine_type: Option<&str>,
    depth: usize,
    label: &str,
    errors: &mut Vec<String>,
) {
    let Some(object) = value.as_object() else {
        errors.push(format!("{label} must be an object"));
        return;
    };
    let default_ql =
        validate_query_language(object.get("QueryLanguage"), label, errors).unwrap_or(default_ql);
    let start_at = object.get("StartAt").and_then(Value::as_str);
    let Some(states) = object.get("States").and_then(Value::as_object) else {
        errors.push(format!("{label} missing States"));
        return;
    };
    if start_at.is_none() {
        errors.push(format!("{label} missing StartAt"));
    }
    if let Some(start) = start_at {
        if !states.contains_key(start) {
            errors.push(format!("{label} StartAt '{start}' is not defined"));
        }
    }
    validate_scope(
        states,
        start_at,
        default_ql,
        machine_type,
        depth,
        label,
        errors,
    );
}

fn validate_choice(
    state: &Map<String, Value>,
    states: &Map<String, Value>,
    query_language: &str,
    label: &str,
    errors: &mut Vec<String>,
) {
    match state.get("Choices").and_then(Value::as_array) {
        Some(choices) if !choices.is_empty() => {
            for (index, choice) in choices.iter().enumerate() {
                let choice_label = format!("{label} choice {index}");
                let Some(choice) = choice.as_object() else {
                    errors.push(format!("{choice_label} must be an object"));
                    continue;
                };
                validate_reference(choice.get("Next"), states, &choice_label, errors);
                if query_language == "JSONata" {
                    if !choice
                        .get("Condition")
                        .and_then(Value::as_str)
                        .is_some_and(crate::jsonata::is_expression)
                    {
                        errors.push(format!("{choice_label} requires a JSONata Condition"));
                    }
                } else if !choice.contains_key("Variable")
                    && !choice.contains_key("And")
                    && !choice.contains_key("Or")
                    && !choice.contains_key("Not")
                {
                    errors.push(format!("{choice_label} has no JSONPath comparison rule"));
                }
            }
        }
        _ => errors.push(format!("{label} requires a non-empty Choices array")),
    }
    if let Some(default) = state.get("Default") {
        validate_reference(Some(default), states, label, errors);
    }
}

fn validate_retry_and_catch(
    state: &Map<String, Value>,
    state_type: &str,
    states: &Map<String, Value>,
    label: &str,
    errors: &mut Vec<String>,
) {
    if (state.contains_key("Retry") || state.contains_key("Catch"))
        && !matches!(state_type, "Task" | "Parallel" | "Map")
    {
        errors.push(format!("{label} cannot specify Retry or Catch"));
    }
    for field in ["Retry", "Catch"] {
        let Some(entries) = state.get(field) else {
            continue;
        };
        let Some(entries) = entries.as_array() else {
            errors.push(format!("{label} {field} must be an array"));
            continue;
        };
        if entries.is_empty() {
            errors.push(format!("{label} {field} must not be empty"));
        }
        for (index, entry) in entries.iter().enumerate() {
            let entry_label = format!("{label} {field}[{index}]");
            let Some(entry) = entry.as_object() else {
                errors.push(format!("{entry_label} must be an object"));
                continue;
            };
            let error_equals = entry.get("ErrorEquals").and_then(Value::as_array);
            match error_equals {
                Some(names) if !names.is_empty() && names.iter().all(Value::is_string) => {
                    if names.iter().any(|name| name.as_str() == Some("States.ALL"))
                        && (names.len() != 1 || index + 1 != entries.len())
                    {
                        errors.push(format!(
                            "{entry_label} States.ALL must be alone in the final {field} entry"
                        ));
                    }
                }
                _ => errors.push(format!(
                    "{entry_label} requires non-empty string ErrorEquals"
                )),
            }
            if field == "Catch" {
                validate_reference(entry.get("Next"), states, &entry_label, errors);
                if entry
                    .get("ResultPath")
                    .is_some_and(|value| !value.is_null() && !value.is_string())
                {
                    errors.push(format!("{entry_label} ResultPath must be a string or null"));
                }
            } else {
                for numeric in ["IntervalSeconds", "MaxAttempts", "MaxDelaySeconds"] {
                    if entry
                        .get(numeric)
                        .is_some_and(|value| value.as_u64().is_none())
                    {
                        errors.push(format!(
                            "{entry_label} {numeric} must be a non-negative integer"
                        ));
                    }
                }
                if entry
                    .get("BackoffRate")
                    .is_some_and(|value| value.as_f64().filter(|value| *value >= 1.0).is_none())
                {
                    errors.push(format!("{entry_label} BackoffRate must be at least 1"));
                }
                if entry
                    .get("JitterStrategy")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !matches!(value, "FULL" | "NONE"))
                {
                    errors.push(format!("{entry_label} JitterStrategy must be FULL or NONE"));
                }
            }
        }
    }
}

fn validate_reference(
    value: Option<&Value>,
    states: &Map<String, Value>,
    label: &str,
    errors: &mut Vec<String>,
) {
    match value.and_then(Value::as_str) {
        Some(next) if states.contains_key(next) => {}
        Some(next) => errors.push(format!("{label} references undefined state '{next}'")),
        None => errors.push(format!("{label} missing string Next")),
    }
}

fn validate_mutually_exclusive(
    state: &Map<String, Value>,
    pairs: &[(&str, &str)],
    label: &str,
    errors: &mut Vec<String>,
) {
    for (left, right) in pairs {
        if state.contains_key(*left) && state.contains_key(*right) {
            errors.push(format!("{label} cannot specify both {left} and {right}"));
        }
    }
}

fn validate_positive_integer_fields(
    state: &Map<String, Value>,
    fields: &[&str],
    label: &str,
    errors: &mut Vec<String>,
) {
    for field in fields {
        if let Some(value) = state.get(*field) {
            if value.as_u64().filter(|value| *value > 0).is_none() {
                errors.push(format!("{label} {field} must be a positive integer"));
            }
        }
    }
}

fn validate_non_negative_number_fields(
    state: &Map<String, Value>,
    fields: &[&str],
    label: &str,
    errors: &mut Vec<String>,
) {
    for field in fields {
        if let Some(value) = state.get(*field) {
            if value.as_f64().filter(|value| *value >= 0.0).is_none() {
                errors.push(format!("{label} {field} must be a non-negative number"));
            }
        }
    }
}

fn validate_reachability(
    states: &Map<String, Value>,
    start_at: Option<&str>,
    scope: &str,
    errors: &mut Vec<String>,
) {
    let Some(start) = start_at.filter(|start| states.contains_key(*start)) else {
        return;
    };
    let mut queue = VecDeque::from([start.to_string()]);
    let mut reachable = HashSet::new();
    let mut has_terminal = false;
    while let Some(name) = queue.pop_front() {
        if !reachable.insert(name.clone()) {
            continue;
        }
        let Some(state) = states.get(&name) else {
            continue;
        };
        let state_type = state
            .get("Type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        has_terminal |= matches!(state_type, "Succeed" | "Fail")
            || state.get("End").and_then(Value::as_bool) == Some(true);
        for next in transition_targets(state) {
            if states.contains_key(next) {
                queue.push_back(next.to_string());
            }
        }
    }
    for name in states.keys().filter(|name| !reachable.contains(*name)) {
        errors.push(format!(
            "{scope} state '{name}' is unreachable from StartAt"
        ));
    }
    if !has_terminal {
        errors.push(format!("{scope} has no reachable terminal state"));
    }
}

fn transition_targets(state: &Value) -> Vec<&str> {
    let mut targets = Vec::new();
    if let Some(next) = state.get("Next").and_then(Value::as_str) {
        targets.push(next);
    }
    if let Some(default) = state.get("Default").and_then(Value::as_str) {
        targets.push(default);
    }
    for field in ["Choices", "Catch"] {
        if let Some(entries) = state.get(field).and_then(Value::as_array) {
            targets.extend(
                entries
                    .iter()
                    .filter_map(|entry| entry.get("Next").and_then(Value::as_str)),
            );
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_definition() {
        let def = r#"{"StartAt":"A","States":{"A":{"Type":"Pass","End":true}}}"#;
        let sm = StateMachine::parse(def).unwrap();
        assert_eq!(sm.start_at, "A");
        assert!(sm.state("A").is_some());
    }

    #[test]
    fn rejects_missing_start_at() {
        let def = r#"{"States":{"A":{"Type":"Pass","End":true}}}"#;
        assert!(matches!(
            StateMachine::parse(def),
            Err(SfnError::InvalidDefinition(_))
        ));
    }

    #[test]
    fn rejects_dangling_next() {
        let def = r#"{"StartAt":"A","States":{"A":{"Type":"Pass","Next":"Z"}}}"#;
        assert!(matches!(
            StateMachine::parse(def),
            Err(SfnError::InvalidDefinition(_))
        ));
    }

    #[test]
    fn rejects_unknown_type() {
        let def = r#"{"StartAt":"A","States":{"A":{"Type":"Frob","End":true}}}"#;
        assert!(matches!(
            StateMachine::parse(def),
            Err(SfnError::InvalidDefinition(_))
        ));
    }

    #[test]
    fn rejects_missing_next_or_end() {
        let def = r#"{"StartAt":"A","States":{"A":{"Type":"Pass"}}}"#;
        assert!(StateMachine::parse(def).is_err());
    }
}
