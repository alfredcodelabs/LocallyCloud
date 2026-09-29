//! The ASL interpreter: state loop, JSONPath data pipeline, Choice/Wait/Parallel/Map,
//! Retry/Catch, and Task integration dispatch through the Core registry.

#![allow(
    clippy::too_many_arguments,
    reason = "ASL pipeline stages pass explicit input, context, variables, history, and inspection state"
)]

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{json, Value};
use tokio::sync::RwLock;
use uuid::Uuid;

use localcloud_core::integration::authorization::ServiceRoleAuthorizationRequest;
use localcloud_core::integration::identity::{CallerIdentity, IdentityPropagator};
use localcloud_core::integration::RequestIdentity;
use localcloud_core::registry::ServiceRegistry;

use crate::asl::StateMachine;
use crate::choice;
use crate::clock::now_iso;
use crate::error::{AslError, SfnError};
use crate::jsonata;
use crate::logging;
use crate::path;
use crate::store::{Execution, PendingTask, SfnStore, TaskOutcome};

/// Maximum state transitions before aborting (loop guard).
const MAX_TRANSITIONS: u32 = 100_000;

type ExecutionResult = Result<(Value, Option<u64>), AslError>;
type ExecutionFuture<'a> = Pin<Box<dyn Future<Output = ExecutionResult> + Send + 'a>>;

#[derive(Clone)]
pub struct Interpreter {
    pub sm: Arc<StateMachine>,
    pub store: SfnStore,
    pub registry: Weak<ServiceRegistry>,
    pub region: String,
    pub account: String,
    pub sm_arn: String,
    pub sm_name: String,
    pub role_arn: String,
    pub exec_arn: String,
    pub exec_name: String,
    pub execution_type: String,
    pub record_history: bool,
    /// Default query language for the state machine (`JSONPath` or `JSONata`).
    pub default_ql: String,
    /// Optional TestState service-integration result/error. Never used by durable executions.
    pub test_mock: Option<TestStateMock>,
    /// Optional TestState Context Object override.
    pub context_override: Option<Value>,
    /// Immutable execution-level values exposed in every state's Context Object.
    pub execution_input: Value,
    pub execution_start_time: String,
    /// Initial retry count supplied by TestState stateConfiguration.
    pub initial_retry_count: u32,
    /// Execute at most one attempt and report Retry/Catch eligibility to TestState.
    pub test_state_mode: bool,
}

#[derive(Clone)]
pub struct TestStateMock {
    pub result: Option<Value>,
    pub error: Option<AslError>,
}

#[derive(Default)]
struct StateInspection {
    input: Option<Value>,
    after_input_path: Option<Value>,
    after_parameters: Option<Value>,
    after_arguments: Option<Value>,
    result: Option<Value>,
    after_result_selector: Option<Value>,
    after_result_path: Option<Value>,
    output: Option<Value>,
    caught_error: bool,
}

pub struct TestStateOutcome {
    pub output: Option<Value>,
    pub error: Option<AslError>,
    pub next_state: Option<String>,
    pub status: &'static str,
    pub inspection_data: Option<Value>,
    pub variables: BTreeMap<String, Value>,
}

enum Transition {
    Next(String),
    End,
}

impl Interpreter {
    /// Run a new execution to completion.
    pub async fn run(&self, exec: Arc<RwLock<Execution>>) -> Result<(), SfnError> {
        let input = exec.read().await.input.clone();
        if self.record_history {
            let mut execution = exec.write().await;
            if execution.status != crate::store::Status::Running {
                return Ok(());
            }
            execution.record("ExecutionStarted", json!({ "input": input }));
        }
        self.run_from(exec.clone(), None, input).await;
        logging::deliver_execution(&self.registry, &self.region, &self.account, &exec).await
    }

    /// Resume a redriven execution at the unsuccessful state without replaying completed states.
    pub async fn redrive(
        &self,
        exec: Arc<RwLock<Execution>>,
        state: String,
        input: Value,
    ) -> Result<(), SfnError> {
        self.run_from(exec.clone(), Some(state), input).await;
        logging::deliver_execution(&self.registry, &self.region, &self.account, &exec).await
    }

    /// Execute exactly one state for the TestState API without creating durable resources.
    pub async fn test_state(
        &self,
        state_name: &str,
        state: &Value,
        input: Value,
        variables: BTreeMap<String, Value>,
        inspection_level: &str,
    ) -> TestStateOutcome {
        let mut inspection = StateInspection::default();
        let result = self
            .run_state(
                state_name,
                state,
                input,
                &variables,
                None,
                None,
                Some(&mut inspection),
            )
            .await;
        let inspection_data = (inspection_level != "INFO").then(|| render_inspection(&inspection));
        match result {
            Ok((output, transition, variables, _)) => TestStateOutcome {
                output: Some(output),
                error: None,
                next_state: match transition {
                    Transition::Next(next) => Some(next),
                    Transition::End => None,
                },
                status: if inspection.caught_error {
                    "CAUGHT_ERROR"
                } else {
                    "SUCCEEDED"
                },
                inspection_data,
                variables,
            },
            Err(error) => {
                let retriers = state
                    .get("Retry")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let retriable = retry_available(&retriers, &error, self.initial_retry_count);
                TestStateOutcome {
                    output: None,
                    error: Some(error),
                    next_state: None,
                    status: if retriable { "RETRIABLE" } else { "FAILED" },
                    inspection_data,
                    variables,
                }
            }
        }
    }

    async fn run_from(
        &self,
        exec: Arc<RwLock<Execution>>,
        start_state: Option<String>,
        input: Value,
    ) {
        let configured_timeout = self
            .sm
            .definition
            .get("TimeoutSeconds")
            .and_then(Value::as_u64);
        let timeout_seconds = match self.execution_type.as_str() {
            "EXPRESS" => Some(configured_timeout.unwrap_or(300).min(300)),
            _ => Some(configured_timeout.unwrap_or(31_536_000).min(31_536_000)),
        };
        let variables = exec.read().await.variables.clone();
        let previous_event_id = exec.read().await.history.last().map(|event| event.id);
        let execution = self.execute(
            &self.sm,
            input,
            Some(&exec),
            Some(&exec),
            start_state.as_deref(),
            variables,
            previous_event_id,
        );
        let result = match timeout_seconds {
            Some(seconds) => {
                match tokio::time::timeout(Duration::from_secs(seconds), execution).await {
                    Ok(result) => result,
                    Err(_) => {
                        let timed_out = {
                            let mut execution = exec.write().await;
                            if execution.status != crate::store::Status::Running {
                                false
                            } else {
                                execution.status = crate::store::Status::TimedOut;
                                execution.error = Some("States.Timeout".into());
                                execution.cause =
                                    Some(format!("Execution exceeded TimeoutSeconds ({seconds})"));
                                execution.stop_date = Some(crate::clock::now_epoch());
                                if self.record_history {
                                    let cause = execution.cause.clone();
                                    execution.record(
                                        "ExecutionTimedOut",
                                        json!({ "error": "States.Timeout", "cause": cause }),
                                    );
                                }
                                true
                            }
                        };
                        if timed_out {
                            self.store.cancel_pending_tasks(&self.exec_arn).await;
                        }
                        return;
                    }
                }
            }
            None => execution.await,
        };
        match result {
            Ok((output, _)) => {
                let mut execution = exec.write().await;
                if execution.status != crate::store::Status::Running {
                    return;
                }
                execution.status = crate::store::Status::Succeeded;
                execution.output = Some(output.clone());
                execution.stop_date = Some(crate::clock::now_epoch());
                execution.current_state = None;
                execution.current_input = None;
                if self.record_history {
                    execution.record("ExecutionSucceeded", json!({ "output": output }));
                }
            }
            Err(err) => {
                let mut execution = exec.write().await;
                if execution.status != crate::store::Status::Running {
                    return;
                }
                execution.status = crate::store::Status::Failed;
                execution.error = Some(err.error.clone());
                execution.cause = Some(err.cause.clone());
                execution.stop_date = Some(crate::clock::now_epoch());
                if self.record_history {
                    execution.record(
                        "ExecutionFailed",
                        json!({ "error": err.error, "cause": err.cause }),
                    );
                }
            }
        }
    }

    /// Execute a (sub-)state-machine. `cursor` tracks the top-level redrive position while
    /// `events` may be shared by concurrently executing Map iterations and Parallel branches.
    fn execute<'a>(
        &'a self,
        sm: &'a StateMachine,
        input: Value,
        cursor: Option<&'a Arc<RwLock<Execution>>>,
        events: Option<&'a Arc<RwLock<Execution>>>,
        start_state: Option<&'a str>,
        initial_variables: BTreeMap<String, Value>,
        mut previous_event_id: Option<u64>,
    ) -> ExecutionFuture<'a> {
        Box::pin(async move {
            let mut current = start_state.unwrap_or(&sm.start_at).to_string();
            let mut state_input = input;
            let mut variables = initial_variables;
            let mut transitions = 0u32;
            loop {
                if let Some(execution) = events.or(cursor) {
                    if execution.read().await.status != crate::store::Status::Running {
                        return Err(AslError::new("States.TaskFailed", "execution was stopped"));
                    }
                }
                transitions += 1;
                if transitions > MAX_TRANSITIONS {
                    return Err(AslError::runtime("maximum state transitions exceeded"));
                }
                let state = sm
                    .state(&current)
                    .cloned()
                    .ok_or_else(|| AslError::runtime(format!("undefined state {current}")))?;
                if let Some(execution) = cursor {
                    let mut execution = execution.write().await;
                    execution.current_state = Some(current.clone());
                    execution.current_input = Some(state_input.clone());
                }
                let mut state_event_id = previous_event_id;
                if let Some(execution) = events {
                    let mut execution = execution.write().await;
                    if execution.status != crate::store::Status::Running {
                        return Err(AslError::new("States.TaskFailed", "execution was stopped")
                            .with_history_event(previous_event_id));
                    }
                    if execution.history.len() >= crate::store::MAX_HISTORY_EVENTS.saturating_sub(6)
                    {
                        return Err(AslError::runtime("execution history event limit exceeded"));
                    }
                    if self.record_history {
                        let state_type =
                            state.get("Type").and_then(Value::as_str).unwrap_or("State");
                        state_event_id = execution.record_after(
                            &format!("{state_type}StateEntered"),
                            json!({ "name": current, "input": state_input }),
                            previous_event_id,
                        );
                    }
                }
                let state_result = self
                    .run_state(
                        &current,
                        &state,
                        state_input.clone(),
                        &variables,
                        events,
                        state_event_id,
                        None,
                    )
                    .await;
                let (output, transition, updated_variables, state_event_id) = match state_result {
                    Ok(result) => result,
                    Err(error) => return Err(error),
                };
                validate_state_payload_size(&output)?;
                variables = updated_variables;
                if let Some(execution) = cursor {
                    execution.write().await.variables = variables.clone();
                }
                if let Some(execution) = events {
                    let mut execution = execution.write().await;
                    if execution.status != crate::store::Status::Running {
                        return Err(AslError::new("States.TaskFailed", "execution was stopped")
                            .with_history_event(state_event_id));
                    }
                    if self.record_history {
                        let state_type =
                            state.get("Type").and_then(Value::as_str).unwrap_or("State");
                        previous_event_id = execution.record_after(
                            &format!("{state_type}StateExited"),
                            json!({ "name": current, "output": output }),
                            state_event_id,
                        );
                    }
                }
                match transition {
                    Transition::End => return Ok((output, previous_event_id)),
                    Transition::Next(next) => {
                        current = next;
                        state_input = output;
                    }
                }
            }
        })
    }

    async fn run_state(
        &self,
        name: &str,
        state: &Value,
        input: Value,
        variables: &BTreeMap<String, Value>,
        history: Option<&Arc<RwLock<Execution>>>,
        history_parent_id: Option<u64>,
        mut inspection: Option<&mut StateInspection>,
    ) -> Result<(Value, Transition, BTreeMap<String, Value>, Option<u64>), AslError> {
        if let Some(data) = inspection.as_deref_mut() {
            data.input = Some(input.clone());
        }
        validate_state_payload_size(&input)?;
        let typ = state.get("Type").and_then(Value::as_str).unwrap_or("");
        let context = self.context(name, &input, None);
        let jsonata = self.is_jsonata(state);
        // JSONata states do not use InputPath; JSONPath states do.
        let ip_input = if jsonata {
            input.clone()
        } else {
            path::apply_input_path_value(&input, state.get("InputPath"))?
        };
        if let Some(data) = inspection.as_deref_mut() {
            data.after_input_path = Some(ip_input.clone());
        }

        let (output, transition) = match typ {
            "Pass" => {
                let payload =
                    self.params_applied(state, &ip_input, &context, jsonata, variables)?;
                validate_state_payload_size(&payload)?;
                if let Some(data) = inspection.as_deref_mut() {
                    if jsonata {
                        data.after_arguments = Some(payload.clone());
                    } else {
                        data.after_parameters = Some(payload.clone());
                    }
                }
                let result = state.get("Result").cloned().unwrap_or(payload);
                let output = self.finalize(
                    state,
                    &ip_input,
                    result,
                    &context,
                    jsonata,
                    false,
                    variables,
                    inspection.as_deref_mut(),
                )?;
                (output, self.transition(state))
            }
            "Succeed" => {
                let output = if jsonata {
                    self.finalize(
                        state,
                        &ip_input,
                        ip_input.clone(),
                        &context,
                        true,
                        false,
                        variables,
                        inspection.as_deref_mut(),
                    )?
                } else {
                    path::apply_output_path_value(&ip_input, state.get("OutputPath"))?
                };
                (output, Transition::End)
            }
            "Fail" => {
                let resolve = |field: &str,
                               path_field: &str,
                               default: &str|
                 -> Result<String, AslError> {
                    if jsonata {
                        return match state.get(field) {
                            Some(Value::String(value)) if jsonata::is_expression(value) => {
                                jsonata::evaluate(
                                    value,
                                    &self.jsonata_vars(&ip_input, None, None, &context, variables),
                                )?
                                .as_str()
                                .map(String::from)
                                .ok_or_else(|| {
                                    AslError::runtime(format!(
                                        "Fail {field} must resolve to a string"
                                    ))
                                })
                            }
                            Some(Value::String(value)) => Ok(value.clone()),
                            Some(_) => {
                                Err(AslError::runtime(format!("Fail {field} must be a string")))
                            }
                            None => Ok(default.to_string()),
                        };
                    }
                    if let Some(path) = str_opt(state, path_field) {
                        return path::get_path(&ip_input, path)
                            .and_then(|value| value.as_str().map(String::from))
                            .ok_or_else(|| {
                                AslError::runtime(format!(
                                    "Fail {path_field} must resolve to a string"
                                ))
                            });
                    }
                    Ok(str_opt(state, field).unwrap_or(default).to_string())
                };
                return Err(AslError::new(
                    resolve("Error", "ErrorPath", "States.Fail")?,
                    resolve("Cause", "CausePath", "")?,
                ));
            }
            "Wait" => {
                self.do_wait(state, &ip_input, &context, jsonata, variables)
                    .await?;
                let output = if jsonata {
                    self.finalize(
                        state,
                        &ip_input,
                        ip_input.clone(),
                        &context,
                        true,
                        false,
                        variables,
                        inspection.as_deref_mut(),
                    )?
                } else {
                    path::apply_output_path_value(&ip_input, state.get("OutputPath"))?
                };
                (output, self.transition(state))
            }
            "Choice" => {
                let next = if jsonata {
                    self.evaluate_jsonata_choice(state, &ip_input, &context, variables)?
                } else {
                    choice::evaluate(state, &ip_input)?
                };
                let output = if jsonata {
                    self.finalize(
                        state,
                        &ip_input,
                        ip_input.clone(),
                        &context,
                        true,
                        false,
                        variables,
                        inspection.as_deref_mut(),
                    )?
                } else {
                    path::apply_output_path_value(&ip_input, state.get("OutputPath"))?
                };
                (output, Transition::Next(next))
            }
            "Task" => {
                let resource = state
                    .get("Resource")
                    .and_then(Value::as_str)
                    .ok_or_else(|| AslError::runtime("Task missing Resource"))?
                    .to_string();
                return self
                    .run_with_handling(
                        state,
                        &ip_input,
                        &context,
                        jsonata,
                        variables,
                        Attempt::Task {
                            resource,
                            heartbeat_seconds: self.state_seconds(
                                state,
                                "HeartbeatSeconds",
                                "HeartbeatSecondsPath",
                                &ip_input,
                                &context,
                                jsonata,
                                variables,
                            )?,
                        },
                        history,
                        history_parent_id,
                        inspection.as_deref_mut(),
                    )
                    .await;
            }
            "Parallel" => {
                let branches = state
                    .get("Branches")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                return self
                    .run_with_handling(
                        state,
                        &ip_input,
                        &context,
                        jsonata,
                        variables,
                        Attempt::Parallel { branches },
                        history,
                        history_parent_id,
                        inspection.as_deref_mut(),
                    )
                    .await;
            }
            "Map" => {
                return self
                    .run_with_handling(
                        state,
                        &ip_input,
                        &context,
                        jsonata,
                        variables,
                        Attempt::Map {
                            state: state.clone(),
                        },
                        history,
                        history_parent_id,
                        inspection.as_deref_mut(),
                    )
                    .await;
            }
            other => return Err(AslError::runtime(format!("unsupported state type {other}"))),
        };
        if let Some(data) = inspection {
            if data.output.is_none() {
                data.output = Some(output.clone());
            }
        }
        validate_state_payload_size(&output)?;
        let updated_variables =
            self.apply_assign(state, &ip_input, None, None, &context, variables)?;
        Ok((output, transition, updated_variables, history_parent_id))
    }

    /// Whether the state uses JSONata (per-state override, else the machine default).
    fn is_jsonata(&self, state: &Value) -> bool {
        let ql = state
            .get("QueryLanguage")
            .and_then(Value::as_str)
            .unwrap_or(&self.default_ql);
        ql == "JSONata"
    }

    fn jsonata_vars(
        &self,
        input: &Value,
        result: Option<&Value>,
        error_output: Option<&Value>,
        context: &Value,
        variables: &BTreeMap<String, Value>,
    ) -> BTreeMap<String, Value> {
        let mut states = serde_json::Map::new();
        states.insert("input".into(), input.clone());
        if let Some(result) = result {
            states.insert("result".into(), result.clone());
        }
        if let Some(error_output) = error_output {
            states.insert("errorOutput".into(), error_output.clone());
        }
        states.insert("context".into(), context.clone());
        let mut vars = variables
            .iter()
            .map(|(name, value)| (format!("${}", name.trim_start_matches('$')), value.clone()))
            .collect::<BTreeMap<_, _>>();
        vars.insert("$states".to_string(), Value::Object(states));
        vars
    }

    fn apply_assign(
        &self,
        source: &Value,
        input: &Value,
        result: Option<&Value>,
        error_output: Option<&Value>,
        context: &Value,
        variables: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, Value>, AslError> {
        let Some(assignments) = source.get("Assign").and_then(Value::as_object) else {
            return Ok(variables.clone());
        };
        let vars = self.jsonata_vars(input, result, error_output, context, variables);
        let evaluated = assignments
            .iter()
            .map(|(name, value)| Ok((name.clone(), jsonata::process(value, &vars)?)))
            .collect::<Result<Vec<_>, AslError>>()?;
        let mut updated = variables.clone();
        for (name, value) in evaluated {
            updated.insert(name.trim_start_matches('$').to_string(), value);
        }
        Ok(updated)
    }

    fn evaluate_jsonata_choice(
        &self,
        state: &Value,
        input: &Value,
        context: &Value,
        variables: &BTreeMap<String, Value>,
    ) -> Result<String, AslError> {
        let vars = self.jsonata_vars(input, None, None, context, variables);
        if let Some(choices) = state.get("Choices").and_then(Value::as_array) {
            for choice in choices {
                if let Some(cond) = choice.get("Condition").and_then(Value::as_str) {
                    let result = jsonata::evaluate(cond, &vars)?;
                    if result.as_bool().unwrap_or(false) {
                        if let Some(next) = choice.get("Next").and_then(Value::as_str) {
                            return Ok(next.to_string());
                        }
                    }
                }
            }
        }
        state
            .get("Default")
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| {
                AslError::new(
                    "States.NoChoiceMatched",
                    "no Condition matched and no Default",
                )
            })
    }

    /// Apply input shaping: JSONata `Arguments` or JSONPath `Parameters`.
    fn params_applied(
        &self,
        state: &Value,
        ip_input: &Value,
        context: &Value,
        jsonata: bool,
        variables: &BTreeMap<String, Value>,
    ) -> Result<Value, AslError> {
        if jsonata {
            match state.get("Arguments") {
                Some(args) => jsonata::process(
                    args,
                    &self.jsonata_vars(ip_input, None, None, context, variables),
                ),
                None => Ok(ip_input.clone()),
            }
        } else {
            match state.get("Parameters") {
                Some(params) => path::process_payload(params, ip_input, context),
                None => Ok(ip_input.clone()),
            }
        }
    }

    /// Apply output shaping: JSONata `Output` or JSONPath ResultSelector→ResultPath→OutputPath.
    fn finalize(
        &self,
        state: &Value,
        ip_input: &Value,
        raw_result: Value,
        context: &Value,
        jsonata: bool,
        expose_result: bool,
        variables: &BTreeMap<String, Value>,
        mut inspection: Option<&mut StateInspection>,
    ) -> Result<Value, AslError> {
        if let Some(data) = inspection.as_deref_mut() {
            data.result = Some(raw_result.clone());
        }
        if jsonata {
            let output = match state.get("Output") {
                Some(output) => jsonata::process(
                    output,
                    &self.jsonata_vars(
                        ip_input,
                        expose_result.then_some(&raw_result),
                        None,
                        context,
                        variables,
                    ),
                ),
                None => Ok(raw_result),
            }?;
            if let Some(data) = inspection.as_deref_mut() {
                data.output = Some(output.clone());
            }
            return Ok(output);
        }
        let selected_result = match state.get("ResultSelector") {
            Some(selector) => path::process_payload(selector, &raw_result, context)?,
            None => raw_result,
        };
        if let Some(data) = inspection.as_deref_mut() {
            data.after_result_selector = Some(selected_result.clone());
        }
        let combined =
            path::apply_result_path_checked(ip_input, selected_result, result_path_option(state))?;
        if let Some(data) = inspection.as_deref_mut() {
            data.after_result_path = Some(combined.clone());
        }
        let output = path::apply_output_path_value(&combined, state.get("OutputPath"))?;
        if let Some(data) = inspection {
            data.output = Some(output.clone());
        }
        Ok(output)
    }

    fn transition(&self, state: &Value) -> Transition {
        if state.get("End").and_then(Value::as_bool).unwrap_or(false) {
            Transition::End
        } else if let Some(next) = state.get("Next").and_then(Value::as_str) {
            Transition::Next(next.to_string())
        } else {
            Transition::End
        }
    }

    fn context(&self, state_name: &str, _input: &Value, task_token: Option<&str>) -> Value {
        if let Some(context) = &self.context_override {
            let mut context = context.clone();
            if let Some(object) = context.as_object_mut() {
                object
                    .entry("Task")
                    .or_insert_with(|| json!({ "Token": task_token }));
            }
            return context;
        }
        json!({
            "Execution": {
                "Id": self.exec_arn,
                "Name": self.exec_name,
                "Input": self.execution_input,
                "RoleArn": self.role_arn,
                "StartTime": self.execution_start_time
            },
            "State": { "Name": state_name, "EnteredTime": now_iso(), "RetryCount": 0 },
            "StateMachine": { "Id": self.sm_arn, "Name": self.sm_name },
            "Task": { "Token": task_token },
        })
    }

    fn state_seconds(
        &self,
        state: &Value,
        value_field: &str,
        path_field: &str,
        input: &Value,
        context: &Value,
        jsonata_mode: bool,
        variables: &BTreeMap<String, Value>,
    ) -> Result<Option<u64>, AslError> {
        if let Some(value) = state.get(value_field) {
            let value = if jsonata_mode && value.as_str().is_some_and(jsonata::is_expression) {
                jsonata::evaluate(
                    value.as_str().expect("checked above"),
                    &self.jsonata_vars(input, None, None, context, variables),
                )?
            } else {
                value.clone()
            };
            return value
                .as_u64()
                .filter(|value| *value > 0)
                .map(Some)
                .ok_or_else(|| {
                    AslError::runtime(format!("{value_field} must resolve to a positive integer"))
                });
        }
        if let Some(path_value) = str_opt(state, path_field) {
            return path::get_path(input, path_value)
                .and_then(|value| value.as_u64())
                .filter(|value| *value > 0)
                .map(Some)
                .ok_or_else(|| {
                    AslError::runtime(format!("{path_field} must resolve to a positive integer"))
                });
        }
        Ok(None)
    }

    async fn do_wait(
        &self,
        state: &Value,
        input: &Value,
        context: &Value,
        jsonata_mode: bool,
        variables: &BTreeMap<String, Value>,
    ) -> Result<(), AslError> {
        let evaluate = |value: &Value| -> Result<Value, AslError> {
            if jsonata_mode {
                if let Some(expression) =
                    value.as_str().filter(|value| jsonata::is_expression(value))
                {
                    return jsonata::evaluate(
                        expression,
                        &self.jsonata_vars(input, None, None, context, variables),
                    );
                }
            }
            Ok(value.clone())
        };
        let duration = if let Some(seconds) = state.get("Seconds") {
            let seconds = evaluate(seconds)?.as_u64().ok_or_else(|| {
                AslError::runtime("Wait Seconds must resolve to a non-negative integer")
            })?;
            Duration::from_secs(seconds)
        } else if let Some(path) = str_opt(state, "SecondsPath") {
            let seconds = path::get_path(input, path)
                .and_then(|value| value.as_u64())
                .ok_or_else(|| {
                    AslError::runtime("Wait SecondsPath must resolve to a non-negative integer")
                })?;
            Duration::from_secs(seconds)
        } else {
            let timestamp = if let Some(timestamp) = state.get("Timestamp") {
                evaluate(timestamp)?
                    .as_str()
                    .map(String::from)
                    .ok_or_else(|| AslError::runtime("Wait Timestamp must resolve to a string"))?
            } else if let Some(path) = str_opt(state, "TimestampPath") {
                path::get_path(input, path)
                    .and_then(|value| value.as_str().map(String::from))
                    .ok_or_else(|| {
                        AslError::runtime("Wait TimestampPath must resolve to a string")
                    })?
            } else {
                return Err(AslError::runtime("Wait state has no time field"));
            };
            let target = time::OffsetDateTime::parse(
                &timestamp,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|error| AslError::runtime(format!("Wait timestamp is invalid: {error}")))?;
            let milliseconds = (target - time::OffsetDateTime::now_utc()).whole_milliseconds();
            Duration::from_millis(u64::try_from(milliseconds.max(0)).unwrap_or(u64::MAX))
        };
        if !duration.is_zero() {
            tokio::time::sleep(duration).await;
        }
        Ok(())
    }

    /// Run an attempt with Retry/Catch handling, then finalize the result.
    async fn run_with_handling(
        &self,
        state: &Value,
        ip_input: &Value,
        context: &Value,
        jsonata: bool,
        variables: &BTreeMap<String, Value>,
        attempt: Attempt,
        history: Option<&Arc<RwLock<Execution>>>,
        history_parent_id: Option<u64>,
        mut inspection: Option<&mut StateInspection>,
    ) -> Result<(Value, Transition, BTreeMap<String, Value>, Option<u64>), AslError> {
        let retriers = state
            .get("Retry")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let catchers = state
            .get("Catch")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut retry_counts = vec![self.initial_retry_count; retriers.len()];
        let mut retry_count = self.initial_retry_count;
        let mut attempt_context = context.clone();
        let mut last_history_event_id = history_parent_id;
        let timeout_seconds = self.state_seconds(
            state,
            "TimeoutSeconds",
            "TimeoutSecondsPath",
            ip_input,
            context,
            jsonata,
            variables,
        )?;
        loop {
            if let Some(execution) = history {
                if execution.read().await.status != crate::store::Status::Running {
                    return Err(AslError::new("States.TaskFailed", "execution was stopped")
                        .with_history_event(last_history_event_id));
                }
            }
            let deadline = timeout_seconds
                .map(|seconds| tokio::time::Instant::now() + Duration::from_secs(seconds));
            let task_token = match &attempt {
                Attempt::Task { resource, .. }
                    if resource.ends_with(".waitForTaskToken")
                        || resource.contains(":activity:") =>
                {
                    Some(Uuid::new_v4().to_string())
                }
                _ => None,
            };
            if let Some(object) = attempt_context.as_object_mut() {
                object.insert("Task".into(), json!({ "Token": task_token }));
            }
            if let Some(state_context) = attempt_context
                .get_mut("State")
                .and_then(Value::as_object_mut)
            {
                state_context.insert("RetryCount".into(), Value::from(retry_count));
            }
            let shaped_input = if matches!(&attempt, Attempt::Map { .. }) {
                Ok(ip_input.clone())
            } else {
                self.params_applied(state, ip_input, &attempt_context, jsonata, variables)
            };
            let result = match shaped_input {
                Ok(payload) => {
                    validate_state_payload_size(&payload)?;
                    if let Some(data) = inspection.as_deref_mut() {
                        if jsonata {
                            data.after_arguments = Some(payload.clone());
                        } else {
                            data.after_parameters = Some(payload.clone());
                        }
                    }
                    if self.record_history {
                        if let Some(execution) = history {
                            let mut execution = execution.write().await;
                            if execution.status != crate::store::Status::Running {
                                return Err(AslError::new(
                                    "States.TaskFailed",
                                    "execution was stopped",
                                )
                                .with_history_event(last_history_event_id));
                            }
                            if execution.history.len()
                                >= crate::store::MAX_HISTORY_EVENTS.saturating_sub(4)
                            {
                                return Err(AslError::runtime(
                                    "execution history event limit exceeded",
                                ));
                            }
                            last_history_event_id = match &attempt {
                                Attempt::Task { resource, .. } => {
                                    let scheduled = execution.record_after(
                                        "TaskScheduled",
                                        json!({ "resource": resource, "parameters": payload }),
                                        last_history_event_id,
                                    );
                                    execution.record_after(
                                        "TaskStarted",
                                        json!({ "resource": resource }),
                                        scheduled,
                                    )
                                }
                                Attempt::Parallel { .. } => execution.record_after(
                                    "ParallelStateStarted",
                                    json!({}),
                                    last_history_event_id,
                                ),
                                Attempt::Map { .. } => execution.record_after(
                                    "MapStateStarted",
                                    json!({}),
                                    last_history_event_id,
                                ),
                            };
                        }
                    }
                    let result = match deadline {
                        Some(deadline) => match tokio::time::timeout_at(
                            deadline,
                            self.attempt(
                                &attempt,
                                task_token.as_deref(),
                                &payload,
                                ip_input,
                                &attempt_context,
                                variables,
                                jsonata,
                                history,
                                last_history_event_id,
                            ),
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => {
                                if let Some(token) = task_token.as_deref() {
                                    self.store.remove_pending_task(token);
                                    self.store.remove_queued_activity_task(token).await;
                                } else if matches!(
                                    attempt,
                                    Attempt::Parallel { .. } | Attempt::Map { .. }
                                ) {
                                    self.store.cancel_pending_tasks(&self.exec_arn).await;
                                }
                                Err(AslError::new(
                                    "States.Timeout",
                                    "Task exceeded TimeoutSeconds",
                                ))
                            }
                        },
                        None => {
                            self.attempt(
                                &attempt,
                                task_token.as_deref(),
                                &payload,
                                ip_input,
                                &attempt_context,
                                variables,
                                jsonata,
                                history,
                                last_history_event_id,
                            )
                            .await
                        }
                    };
                    if let Some(execution) = history {
                        if execution.read().await.status != crate::store::Status::Running {
                            return Err(AslError::new(
                                "States.TaskFailed",
                                "execution was stopped",
                            )
                            .with_history_event(last_history_event_id));
                        }
                    }
                    if self.record_history {
                        if let Some(execution) = history {
                            let mut execution = execution.write().await;
                            if execution.status != crate::store::Status::Running {
                                return Err(AslError::new(
                                    "States.TaskFailed",
                                    "execution was stopped",
                                )
                                .with_history_event(last_history_event_id));
                            }
                            let (succeeded, failed, timed_out) = match &attempt {
                                Attempt::Task { .. } => {
                                    ("TaskSucceeded", "TaskFailed", Some("TaskTimedOut"))
                                }
                                Attempt::Parallel { .. } => {
                                    ("ParallelStateSucceeded", "ParallelStateFailed", None)
                                }
                                Attempt::Map { .. } => {
                                    ("MapStateSucceeded", "MapStateFailed", None)
                                }
                            };
                            last_history_event_id = match &result {
                                Ok(output) => execution.record_after(
                                    succeeded,
                                    json!({ "output": output }),
                                    last_history_event_id,
                                ),
                                Err(error)
                                    if timed_out.is_some()
                                        && matches!(
                                            error.error.as_str(),
                                            "States.Timeout" | "States.HeartbeatTimeout"
                                        ) =>
                                {
                                    execution.record_after(
                                        timed_out.expect("checked above"),
                                        json!({ "error": error.error, "cause": error.cause }),
                                        error.history_event_id().or(last_history_event_id),
                                    )
                                }
                                Err(error) => execution.record_after(
                                    failed,
                                    json!({ "error": error.error, "cause": error.cause }),
                                    error.history_event_id().or(last_history_event_id),
                                ),
                            };
                        }
                    }
                    result
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(raw_result) => {
                    validate_state_payload_size(&raw_result)?;
                    let output = self.finalize(
                        state,
                        ip_input,
                        raw_result.clone(),
                        &attempt_context,
                        jsonata,
                        true,
                        variables,
                        inspection.as_deref_mut(),
                    )?;
                    validate_state_payload_size(&output)?;
                    let updated_variables = self.apply_assign(
                        state,
                        ip_input,
                        Some(&raw_result),
                        None,
                        &attempt_context,
                        variables,
                    )?;
                    return Ok((
                        output,
                        self.transition(state),
                        updated_variables,
                        last_history_event_id,
                    ));
                }
                Err(err) => {
                    if self.test_state_mode
                        && retry_available(&retriers, &err, self.initial_retry_count)
                    {
                        return Err(err.with_history_event(last_history_event_id));
                    }
                    if !self.test_state_mode {
                        if let Some(delay) = match_retry(&retriers, &err, &mut retry_counts) {
                            retry_count += 1;
                            if !delay.is_zero() {
                                tokio::time::sleep(delay).await;
                            }
                            continue;
                        }
                    }
                    if let Some((catcher, next, rp)) = match_catch(&catchers, &err) {
                        if let Some(data) = inspection.as_deref_mut() {
                            data.caught_error = true;
                        }
                        let error_output = json!({ "Error": err.error, "Cause": err.cause });
                        let combined = if jsonata {
                            match catcher.get("Output") {
                                Some(output) => jsonata::process(
                                    output,
                                    &self.jsonata_vars(
                                        ip_input,
                                        None,
                                        Some(&error_output),
                                        &attempt_context,
                                        variables,
                                    ),
                                )?,
                                None => error_output.clone(),
                            }
                        } else {
                            path::apply_result_path_checked(ip_input, error_output.clone(), rp)?
                        };
                        if let Some(data) = inspection.as_deref_mut() {
                            data.result = Some(error_output.clone());
                            data.output = Some(combined.clone());
                        }
                        let updated_variables = self.apply_assign(
                            catcher,
                            ip_input,
                            None,
                            Some(&error_output),
                            &attempt_context,
                            variables,
                        )?;
                        return Ok((
                            combined,
                            Transition::Next(next),
                            updated_variables,
                            last_history_event_id,
                        ));
                    }
                    return Err(err.with_history_event(last_history_event_id));
                }
            }
        }
    }

    async fn attempt(
        &self,
        attempt: &Attempt,
        task_token: Option<&str>,
        payload: &Value,
        state_input: &Value,
        context: &Value,
        variables: &BTreeMap<String, Value>,
        jsonata: bool,
        history: Option<&Arc<RwLock<Execution>>>,
        history_parent_id: Option<u64>,
    ) -> Result<Value, AslError> {
        if let Some(mock) = self.test_mock.as_ref().filter(|_| {
            matches!(
                attempt,
                Attempt::Task { .. } | Attempt::Parallel { .. } | Attempt::Map { .. }
            )
        }) {
            if let Some(error) = &mock.error {
                return Err(error.clone());
            }
            if let Some(result) = &mock.result {
                return Ok(result.clone());
            }
        }
        match attempt {
            Attempt::Task {
                resource,
                heartbeat_seconds,
            } => {
                self.dispatch_task(resource, payload, task_token, *heartbeat_seconds)
                    .await
            }
            Attempt::Parallel { branches } => {
                let mut tasks = tokio::task::JoinSet::new();
                let mut branch_start_ids = vec![None; branches.len()];
                for (index, branch) in branches.iter().enumerate() {
                    let inherited_ql = if jsonata { "JSONata" } else { "JSONPath" };
                    let sub = Arc::new(
                        StateMachine::from_value_with_default(branch.clone(), inherited_ql)
                            .map_err(|error| {
                                AslError::runtime(format!("invalid branch: {error}"))
                            })?,
                    );
                    let mut interpreter = self.clone();
                    interpreter.default_ql = sub
                        .definition
                        .get("QueryLanguage")
                        .and_then(Value::as_str)
                        .unwrap_or(inherited_ql)
                        .to_string();
                    let branch_input = payload.clone();
                    let inherited_variables = variables.clone();
                    let event_history = history.cloned();
                    let branch_started = if self.record_history {
                        if let Some(execution) = history {
                            let mut execution = execution.write().await;
                            if execution.status == crate::store::Status::Running {
                                execution.record_after(
                                    "ParallelStateBranchStarted",
                                    json!({ "index": index }),
                                    history_parent_id,
                                )
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    branch_start_ids[index] = branch_started;
                    tasks.spawn(async move {
                        let result = interpreter
                            .execute(
                                sub.as_ref(),
                                branch_input,
                                None,
                                event_history.as_ref(),
                                None,
                                inherited_variables,
                                branch_started,
                            )
                            .await;
                        let result = match result {
                            Ok((output, last_event_id)) => {
                                if interpreter.record_history {
                                    if let Some(execution) = event_history.as_ref() {
                                        let mut execution = execution.write().await;
                                        if execution.status == crate::store::Status::Running {
                                            execution.record_after(
                                                "ParallelStateBranchSucceeded",
                                                json!({ "index": index, "output": output }),
                                                last_event_id,
                                            );
                                        }
                                    }
                                }
                                Ok(output)
                            }
                            Err(error) => {
                                let failed_event_id = if interpreter.record_history {
                                    if let Some(execution) = event_history.as_ref() {
                                        let mut execution = execution.write().await;
                                        if execution.status == crate::store::Status::Running {
                                            execution.record_after(
                                                "ParallelStateBranchFailed",
                                                json!({ "index": index, "error": error.error, "cause": error.cause }),
                                                error.history_event_id().or(branch_started),
                                            )
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };
                                Err(error.with_history_event(failed_event_id))
                            }
                        };
                        (index, result)
                    });
                }
                let mut outputs = vec![None; branches.len()];
                let mut completed = vec![false; branches.len()];
                while let Some(joined) = tasks.join_next().await {
                    let (index, result) = match joined {
                        Ok(result) => result,
                        Err(error) => {
                            tasks.abort_all();
                            while tasks.join_next().await.is_some() {}
                            self.store.cancel_pending_tasks(&self.exec_arn).await;
                            if self.record_history {
                                if let Some(execution) = history {
                                    let mut execution = execution.write().await;
                                    if execution.status == crate::store::Status::Running {
                                        for (index, started) in branch_start_ids.iter().enumerate()
                                        {
                                            if !completed[index] {
                                                execution.record_after(
                                                    "ParallelStateBranchAborted",
                                                    json!({ "index": index }),
                                                    *started,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            return Err(AslError::task_failed(format!(
                                "Parallel branch task failed: {error}"
                            )));
                        }
                    };
                    completed[index] = true;
                    match result {
                        Ok(output) => outputs[index] = Some(output),
                        Err(error) => {
                            tasks.abort_all();
                            while tasks.join_next().await.is_some() {}
                            self.store.cancel_pending_tasks(&self.exec_arn).await;
                            if self.record_history {
                                if let Some(execution) = history {
                                    let mut execution = execution.write().await;
                                    if execution.status == crate::store::Status::Running {
                                        for (pending_index, started) in
                                            branch_start_ids.iter().enumerate()
                                        {
                                            if !completed[pending_index] {
                                                execution.record_after(
                                                    "ParallelStateBranchAborted",
                                                    json!({ "index": pending_index }),
                                                    *started,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            return Err(error);
                        }
                    }
                }
                Ok(Value::Array(
                    outputs
                        .into_iter()
                        .map(|output| output.unwrap_or(Value::Null))
                        .collect(),
                ))
            }
            Attempt::Map { state } => {
                self.run_map(
                    state,
                    payload,
                    state_input,
                    context,
                    variables,
                    jsonata,
                    history,
                    history_parent_id,
                )
                .await
            }
        }
    }

    fn map_number(
        &self,
        state: &Value,
        value_field: &str,
        path_field: &str,
        input: &Value,
        context: &Value,
        jsonata_mode: bool,
        variables: &BTreeMap<String, Value>,
    ) -> Result<Option<f64>, AslError> {
        let value = if let Some(value) = state.get(value_field) {
            if jsonata_mode && value.as_str().is_some_and(jsonata::is_expression) {
                Some(jsonata::evaluate(
                    value.as_str().expect("checked above"),
                    &self.jsonata_vars(input, None, None, context, variables),
                )?)
            } else {
                Some(value.clone())
            }
        } else if let Some(path_value) = str_opt(state, path_field) {
            Some(path::get_path(input, path_value).ok_or_else(|| {
                AslError::runtime(format!("{path_field} does not select a value"))
            })?)
        } else {
            None
        };
        value
            .map(|value| {
                value
                    .as_f64()
                    .filter(|value| value.is_finite() && *value >= 0.0)
                    .ok_or_else(|| {
                        AslError::runtime(format!(
                            "{value_field} must resolve to a non-negative number"
                        ))
                    })
            })
            .transpose()
    }

    async fn run_map(
        &self,
        state: &Value,
        input: &Value,
        state_input: &Value,
        context: &Value,
        variables: &BTreeMap<String, Value>,
        jsonata: bool,
        history: Option<&Arc<RwLock<Execution>>>,
        history_parent_id: Option<u64>,
    ) -> Result<Value, AslError> {
        let distributed = state
            .pointer("/ItemProcessor/ProcessorConfig/Mode")
            .and_then(Value::as_str)
            == Some("DISTRIBUTED");
        let source_items = if distributed {
            match state.get("ItemReader") {
                Some(reader) => {
                    self.read_map_items(reader, state_input, context, variables, jsonata)
                        .await?
                }
                None => {
                    self.resolve_map_items(state, input, state_input, context, variables, jsonata)?
                }
            }
        } else {
            self.resolve_map_items(state, input, state_input, context, variables, jsonata)?
        };
        let processor = state
            .get("ItemProcessor")
            .or_else(|| state.get("Iterator"))
            .cloned()
            .ok_or_else(|| AslError::runtime("Map missing ItemProcessor/Iterator"))?;
        let inherited_ql = if jsonata { "JSONata" } else { "JSONPath" };
        let sub = Arc::new(
            StateMachine::from_value_with_default(processor, inherited_ql)
                .map_err(|e| AslError::runtime(format!("invalid Map processor: {e}")))?,
        );
        let processor_ql = sub
            .definition
            .get("QueryLanguage")
            .and_then(Value::as_str)
            .unwrap_or(inherited_ql)
            .to_string();

        let selector = state
            .get("ItemSelector")
            .or_else(|| (!jsonata).then(|| state.get("Parameters")).flatten());
        let mut iteration_inputs = Vec::with_capacity(source_items.len());
        for (index, item) in source_items.into_iter().enumerate() {
            let mut item_context = context.clone();
            if let Some(context_object) = item_context.as_object_mut() {
                context_object.insert(
                    "Map".into(),
                    json!({ "Item": { "Index": index, "Value": item, "Source": "STATE_DATA" } }),
                );
            }
            let item_input = match selector {
                Some(selector) if jsonata => jsonata::process(
                    selector,
                    &self.jsonata_vars(&item, None, None, &item_context, variables),
                )?,
                Some(selector) => path::process_payload(selector, &item, &item_context)?,
                None => item,
            };
            validate_state_payload_size(&item_input)?;
            iteration_inputs.push(item_input);
        }

        if distributed {
            if let Some(batcher) = state.get("ItemBatcher") {
                iteration_inputs = self.batch_map_items(
                    batcher,
                    iteration_inputs,
                    state_input,
                    context,
                    variables,
                    jsonata,
                )?;
            }
        }

        let total = iteration_inputs.len();
        let configured_concurrency_value = self.map_number(
            state,
            "MaxConcurrency",
            "MaxConcurrencyPath",
            state_input,
            context,
            jsonata,
            variables,
        )?;
        if configured_concurrency_value.is_some_and(|value| value.fract() != 0.0) {
            return Err(AslError::runtime(
                "MaxConcurrency must resolve to an integer",
            ));
        }
        let configured_concurrency = configured_concurrency_value
            .and_then(|value| usize::try_from(value as u64).ok())
            .unwrap_or(0);
        let mode_cap = if distributed { 10_000 } else { 40 };
        let requested_concurrency = if configured_concurrency == 0 {
            mode_cap
        } else {
            configured_concurrency.min(mode_cap)
        };
        let concurrency = requested_concurrency.min(total.max(1));
        let tolerated_count_value = self.map_number(
            state,
            "ToleratedFailureCount",
            "ToleratedFailureCountPath",
            state_input,
            context,
            jsonata,
            variables,
        )?;
        if tolerated_count_value.is_some_and(|value| value.fract() != 0.0) {
            return Err(AslError::runtime(
                "ToleratedFailureCount must resolve to an integer",
            ));
        }
        let tolerated_count = tolerated_count_value.map(|value| value as u64);
        let tolerated_percentage = self.map_number(
            state,
            "ToleratedFailurePercentage",
            "ToleratedFailurePercentagePath",
            state_input,
            context,
            jsonata,
            variables,
        )?;
        if tolerated_percentage.is_some_and(|value| value > 100.0) {
            return Err(AslError::runtime(
                "ToleratedFailurePercentage must not exceed 100",
            ));
        }
        let tolerates_failures = tolerated_count.is_some() || tolerated_percentage.is_some();

        let mut tasks = tokio::task::JoinSet::new();
        let mut inputs = iteration_inputs.into_iter().enumerate();
        for _ in 0..concurrency {
            let Some((index, item_input)) = inputs.next() else {
                break;
            };
            let mut interpreter = self.clone();
            interpreter.default_ql = processor_ql.clone();
            let sub = Arc::clone(&sub);
            let inherited_variables = variables.clone();
            let event_history = history.cloned();
            tasks.spawn(async move {
                interpreter
                    .execute_map_iteration(
                        index,
                        sub,
                        item_input,
                        inherited_variables,
                        event_history,
                        history_parent_id,
                    )
                    .await
            });
        }

        let mut outputs = vec![None; total];
        let mut failed = 0usize;
        while let Some(joined) = tasks.join_next().await {
            let (index, result) = match joined {
                Ok(iteration) => iteration,
                Err(error) => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    self.store.cancel_pending_tasks(&self.exec_arn).await;
                    return Err(AslError::task_failed(format!(
                        "Map iteration task failed: {error}"
                    )));
                }
            };
            match result {
                Ok(output) => outputs[index] = Some(output),
                Err(error) if tolerates_failures => {
                    let failure_event_id = error.history_event_id();
                    failed += 1;
                    outputs[index] = Some(json!({ "Error": error.error, "Cause": error.cause }));
                    let count_exceeded = tolerated_count
                        .map(|limit| failed as u64 > limit)
                        .unwrap_or(false);
                    let percentage = if total == 0 {
                        0.0
                    } else {
                        failed as f64 * 100.0 / total as f64
                    };
                    let percentage_exceeded = tolerated_percentage
                        .map(|limit| percentage > limit)
                        .unwrap_or(false);
                    if count_exceeded || percentage_exceeded {
                        tasks.abort_all();
                        while tasks.join_next().await.is_some() {}
                        self.store.cancel_pending_tasks(&self.exec_arn).await;
                        return Err(AslError::new(
                            "States.ExceedToleratedFailureThreshold",
                            format!("{failed} of {total} Map iterations failed ({percentage:.2}%)"),
                        )
                        .with_history_event(failure_event_id));
                    }
                }
                Err(error) => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    self.store.cancel_pending_tasks(&self.exec_arn).await;
                    return Err(error);
                }
            }

            if let Some((next_index, item_input)) = inputs.next() {
                let mut interpreter = self.clone();
                interpreter.default_ql = processor_ql.clone();
                let sub = Arc::clone(&sub);
                let inherited_variables = variables.clone();
                let event_history = history.cloned();
                tasks.spawn(async move {
                    interpreter
                        .execute_map_iteration(
                            next_index,
                            sub,
                            item_input,
                            inherited_variables,
                            event_history,
                            history_parent_id,
                        )
                        .await
                });
            }
        }

        let results = Value::Array(
            outputs
                .into_iter()
                .map(|output| output.unwrap_or(Value::Null))
                .collect(),
        );
        if distributed {
            if let Some(writer) = state.get("ResultWriter") {
                self.write_map_results(writer, &results, state_input, context, variables, jsonata)
                    .await?;
            }
        }
        Ok(results)
    }

    async fn execute_map_iteration(
        &self,
        index: usize,
        sub: Arc<StateMachine>,
        input: Value,
        variables: BTreeMap<String, Value>,
        history: Option<Arc<RwLock<Execution>>>,
        history_parent_id: Option<u64>,
    ) -> (usize, Result<Value, AslError>) {
        let started = if self.record_history {
            if let Some(execution) = history.as_ref() {
                let mut execution = execution.write().await;
                if execution.status == crate::store::Status::Running {
                    execution.record_after(
                        "MapIterationStarted",
                        json!({ "index": index }),
                        history_parent_id,
                    )
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        let result = self
            .execute(
                sub.as_ref(),
                input,
                None,
                history.as_ref(),
                None,
                variables,
                started,
            )
            .await;
        let result = match result {
            Ok((output, last_event_id)) => {
                if self.record_history {
                    if let Some(execution) = history.as_ref() {
                        let mut execution = execution.write().await;
                        if execution.status == crate::store::Status::Running {
                            execution.record_after(
                                "MapIterationSucceeded",
                                json!({ "index": index, "output": output }),
                                last_event_id,
                            );
                        }
                    }
                }
                Ok(output)
            }
            Err(error) => {
                let failed_event_id = if self.record_history {
                    if let Some(execution) = history.as_ref() {
                        let mut execution = execution.write().await;
                        if execution.status == crate::store::Status::Running {
                            execution.record_after(
                                "MapIterationFailed",
                                json!({ "index": index, "error": error.error, "cause": error.cause }),
                                error.history_event_id().or(started),
                            )
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                Err(error.with_history_event(failed_event_id))
            }
        };
        (index, result)
    }

    fn resolve_map_items(
        &self,
        state: &Value,
        input: &Value,
        state_input: &Value,
        context: &Value,
        variables: &BTreeMap<String, Value>,
        jsonata: bool,
    ) -> Result<Vec<Value>, AslError> {
        let items = if jsonata {
            match state.get("Items") {
                Some(items) => jsonata::process(
                    items,
                    &self.jsonata_vars(state_input, None, None, context, variables),
                )?,
                None => state_input.clone(),
            }
        } else {
            let items_path = str_opt(state, "ItemsPath").unwrap_or("$");
            path::get_path(input, items_path).unwrap_or(Value::Null)
        };
        items
            .as_array()
            .cloned()
            .ok_or_else(|| AslError::new("States.Runtime", "Map items must resolve to an array"))
    }

    fn process_map_arguments(
        &self,
        source: &Value,
        input: &Value,
        context: &Value,
        variables: &BTreeMap<String, Value>,
        jsonata: bool,
    ) -> Result<Value, AslError> {
        let arguments = if jsonata {
            match source.get("Arguments") {
                Some(arguments) => jsonata::process(
                    arguments,
                    &self.jsonata_vars(input, None, None, context, variables),
                ),
                None => Ok(input.clone()),
            }
        } else {
            match source.get("Parameters") {
                Some(parameters) => path::process_payload(parameters, input, context),
                None => Ok(input.clone()),
            }
        }?;
        validate_state_payload_size(&arguments)?;
        Ok(arguments)
    }

    async fn read_map_items(
        &self,
        reader: &Value,
        input: &Value,
        context: &Value,
        variables: &BTreeMap<String, Value>,
        jsonata: bool,
    ) -> Result<Vec<Value>, AslError> {
        let read = async {
            if reader.get("Resource").and_then(Value::as_str)
                != Some("arn:aws:states:::s3:getObject")
            {
                return Err(AslError::runtime(
                    "ItemReader only supports arn:aws:states:::s3:getObject",
                ));
            }
            let request = self.process_map_arguments(reader, input, context, variables, jsonata)?;
            let config = reader
                .get("ReaderConfig")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let response = self.dispatch_s3("getObject", &request).await?;
            let body = response
                .get("Body")
                .ok_or_else(|| AslError::runtime("ItemReader S3 response omitted Body"))?;
            parse_item_reader_body(body, &config).map_err(AslError::runtime)
        }
        .await;
        read.map_err(|error| {
            AslError::new(
                "States.ItemReaderFailed",
                format!("{}: {}", error.error, error.cause),
            )
        })
    }

    fn batch_map_items(
        &self,
        batcher: &Value,
        items: Vec<Value>,
        input: &Value,
        context: &Value,
        variables: &BTreeMap<String, Value>,
        jsonata: bool,
    ) -> Result<Vec<Value>, AslError> {
        let max_items = batcher
            .get("MaxItemsPerBatch")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value >= 1);
        let max_bytes = batcher
            .get("MaxInputBytesPerBatch")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value >= 1);
        if max_items.is_none() && max_bytes.is_none() {
            return Err(AslError::runtime(
                "ItemBatcher requires MaxItemsPerBatch or MaxInputBytesPerBatch",
            ));
        }
        let batch_input = match batcher.get("BatchInput") {
            Some(value) if jsonata => jsonata::process(
                value,
                &self.jsonata_vars(input, None, None, context, variables),
            )?,
            Some(value) => path::process_payload(value, input, context)?,
            None => json!({}),
        };
        let batch_fields = batch_input
            .as_object()
            .cloned()
            .ok_or_else(|| AslError::runtime("ItemBatcher BatchInput must resolve to an object"))?;
        let mut batches = Vec::new();
        let mut current = Vec::new();
        for item in items {
            let would_exceed_items = max_items.is_some_and(|limit| current.len() >= limit);
            let would_exceed_bytes = if let Some(limit) = max_bytes {
                let mut candidate = batch_fields.clone();
                let mut candidate_items = current.clone();
                candidate_items.push(item.clone());
                candidate.insert("Items".into(), Value::Array(candidate_items));
                serde_json::to_vec(&Value::Object(candidate))
                    .map_or(true, |value| value.len() > limit)
            } else {
                false
            };
            if !current.is_empty() && (would_exceed_items || would_exceed_bytes) {
                batches.push(std::mem::take(&mut current));
            }
            current.push(item);
            if let Some(limit) = max_bytes {
                let mut candidate = batch_fields.clone();
                candidate.insert("Items".into(), Value::Array(current.clone()));
                if serde_json::to_vec(&Value::Object(candidate))
                    .map_or(true, |value| value.len() > limit)
                {
                    return Err(AslError::new(
                        "States.DataLimitExceeded",
                        "a single Map item exceeds MaxInputBytesPerBatch",
                    ));
                }
            }
        }
        if !current.is_empty() {
            batches.push(current);
        }
        Ok(batches
            .into_iter()
            .map(|items| {
                let mut batch = batch_fields.clone();
                batch.insert("Items".into(), Value::Array(items));
                Value::Object(batch)
            })
            .collect())
    }

    async fn write_map_results(
        &self,
        writer: &Value,
        results: &Value,
        input: &Value,
        context: &Value,
        variables: &BTreeMap<String, Value>,
        jsonata: bool,
    ) -> Result<(), AslError> {
        let write = async {
            if writer.get("Resource").and_then(Value::as_str)
                != Some("arn:aws:states:::s3:putObject")
            {
                return Err(AslError::runtime(
                    "ResultWriter only supports arn:aws:states:::s3:putObject",
                ));
            }
            let request = self.process_map_arguments(writer, input, context, variables, jsonata)?;
            let mut request = request.as_object().cloned().ok_or_else(|| {
                AslError::runtime("ResultWriter parameters must resolve to an object")
            })?;
            if !request.contains_key("Key") {
                let prefix = request
                    .get("Prefix")
                    .and_then(Value::as_str)
                    .ok_or_else(|| AslError::runtime("ResultWriter requires Prefix or Key"))?;
                let key = if prefix.is_empty() {
                    "results.json".to_string()
                } else {
                    format!("{}/results.json", prefix.trim_end_matches('/'))
                };
                request.insert("Key".into(), Value::String(key));
            }
            request.remove("Prefix");
            request.insert("Body".into(), results.clone());
            request.insert(
                "ContentType".into(),
                Value::String("application/json".into()),
            );
            let request = Value::Object(request);
            validate_state_payload_size(&request)?;
            self.dispatch_s3("putObject", &request).await?;
            Ok(())
        }
        .await;
        write.map_err(|error| {
            AslError::new(
                "States.ResultWriterFailed",
                format!("{}: {}", error.error, error.cause),
            )
        })
    }

    /// Resolve a Task `Resource` and dispatch to the target through InternalDispatcher.
    async fn dispatch_task(
        &self,
        resource: &str,
        payload: &Value,
        task_token: Option<&str>,
        heartbeat_seconds: Option<u64>,
    ) -> Result<Value, AslError> {
        let (base, pattern) = IntegrationPattern::parse(resource);
        if base.contains(":activity:") {
            let token = task_token
                .ok_or_else(|| AslError::runtime("activity task token was not generated"))?;
            return self
                .dispatch_activity(base, payload, token, heartbeat_seconds)
                .await;
        }
        if matches!(pattern, IntegrationPattern::WaitForTaskToken) {
            let token = task_token
                .ok_or_else(|| AslError::runtime("callback task token was not generated"))?;
            let pending = self.store.insert_pending_task(
                token.to_string(),
                PendingTask::new(self.exec_arn.clone(), heartbeat_seconds),
            );
            if let Err(error) = Box::pin(self.dispatch_task(base, payload, None, None)).await {
                self.store.remove_pending_task(token);
                return Err(error);
            }
            return self.await_callback(token, pending).await;
        }
        if !matches!(pattern, IntegrationPattern::RequestResponse)
            && self.execution_type == "EXPRESS"
        {
            return Err(AslError::runtime(format!(
                "integration pattern {} is not supported by EXPRESS workflows",
                pattern.label()
            )));
        }

        if let Some(rest) = base.strip_prefix("arn:aws:states:::") {
            if let Some(sdk) = rest.strip_prefix("aws-sdk:") {
                return self.dispatch_aws_sdk(sdk, payload, pattern).await;
            }
            if rest == "athena:startQueryExecution" {
                if !matches!(pattern, IntegrationPattern::Sync) {
                    return Err(AslError::runtime(
                        "Athena startQueryExecution requires .sync",
                    ));
                }
                return self.dispatch_athena_sync(payload).await;
            }
            if rest == "states:startExecution" {
                return self
                    .dispatch_nested_execution(payload, pattern, false)
                    .await;
            }
            if !matches!(pattern, IntegrationPattern::RequestResponse) {
                return Err(AslError::runtime(format!(
                    "integration pattern {} is not supported for {rest}",
                    pattern.label()
                )));
            }
            return self.dispatch_optimized(rest, payload).await;
        }
        if base.starts_with("arn:aws:lambda:") && base.contains(":function:") {
            if !matches!(pattern, IntegrationPattern::RequestResponse) {
                return Err(AslError::runtime(
                    "direct Lambda ARNs only support request-response",
                ));
            }
            return self.invoke_lambda(base, payload, None, None).await;
        }
        Err(AslError::runtime(format!(
            "unsupported Task resource {resource}"
        )))
    }

    async fn dispatch_optimized(&self, op: &str, payload: &Value) -> Result<Value, AslError> {
        match op {
            "lambda:invoke" => {
                let name = payload
                    .get("FunctionName")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let inner = payload.get("Payload").cloned().unwrap_or(json!({}));
                let qualifier = payload.get("Qualifier").and_then(Value::as_str);
                let invocation_type = payload.get("InvocationType").and_then(Value::as_str);
                let client_context = payload.get("ClientContext").and_then(Value::as_str);
                let response = self
                    .invoke_lambda_http(name, &inner, qualifier, invocation_type, client_context)
                    .await?;
                let status_code = response.status().as_u16();
                let executed_version = response
                    .headers()
                    .get("x-amz-executed-version")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("$LATEST")
                    .to_string();
                let function_error = response
                    .headers()
                    .get("x-amz-function-error")
                    .and_then(|value| value.to_str().ok())
                    .map(String::from);
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .map_err(|_| AslError::task_failed("failed to read Lambda response"))?;
                let result: Value = serde_json::from_slice(&body)
                    .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
                if function_error.is_some() {
                    return Err(lambda_function_error(&result));
                }
                Ok(json!({
                    "ExecutedVersion": executed_version,
                    "Payload": result,
                    "StatusCode": status_code,
                }))
            }
            "sqs:sendMessage" => {
                self.dispatch_json("sqs", "AmazonSQS.SendMessage", payload)
                    .await
            }
            "sns:publish" => {
                self.dispatch_json("sns", "AmazonSimpleNotificationService.Publish", payload)
                    .await
            }
            "dynamodb:putItem" => {
                self.dispatch_json("dynamodb", "DynamoDB_20120810.PutItem", payload)
                    .await
            }
            "dynamodb:getItem" => {
                self.dispatch_json("dynamodb", "DynamoDB_20120810.GetItem", payload)
                    .await
            }
            "dynamodb:query" => {
                self.dispatch_json("dynamodb", "DynamoDB_20120810.Query", payload)
                    .await
            }
            "dynamodb:updateItem" => {
                self.dispatch_json("dynamodb", "DynamoDB_20120810.UpdateItem", payload)
                    .await
            }
            "dynamodb:deleteItem" => {
                self.dispatch_json("dynamodb", "DynamoDB_20120810.DeleteItem", payload)
                    .await
            }
            "dynamodb:transactWriteItems" => {
                self.dispatch_json("dynamodb", "DynamoDB_20120810.TransactWriteItems", payload)
                    .await
            }
            "events:putEvents" => {
                self.dispatch_json("events", "AWSEvents.PutEvents", payload)
                    .await
            }
            "s3:putObject" => self.dispatch_s3("putObject", payload).await,
            "s3:getObject" => self.dispatch_s3("getObject", payload).await,
            "s3:headObject" => self.dispatch_s3("headObject", payload).await,
            other => Err(AslError::runtime(format!(
                "unsupported integration {other}"
            ))),
        }
    }

    async fn dispatch_activity(
        &self,
        activity_arn: &str,
        payload: &Value,
        token: &str,
        heartbeat_seconds: Option<u64>,
    ) -> Result<Value, AslError> {
        let prefix = format!("arn:aws:states:{}:{}:activity:", self.region, self.account);
        let name = activity_arn
            .strip_prefix(&prefix)
            .filter(|name| !name.is_empty() && !name.contains(':'))
            .ok_or_else(|| AslError::runtime(format!("invalid activity ARN {activity_arn}")))?;
        let activity = self
            .store
            .get_activity(&self.account, &self.region, name)
            .ok_or_else(|| {
                AslError::new(
                    "ActivityDoesNotExist",
                    format!("{activity_arn} does not exist"),
                )
            })?;
        let pending = self.store.insert_pending_task(
            token.to_string(),
            PendingTask::new(self.exec_arn.clone(), heartbeat_seconds),
        );
        activity
            .queue
            .lock()
            .await
            .push_back(crate::store::ActivityTask {
                token: token.to_string(),
                input: payload.clone(),
            });
        activity.notify.notify_one();
        self.await_callback(token, pending).await
    }

    async fn await_callback(
        &self,
        token: &str,
        pending: Arc<PendingTask>,
    ) -> Result<Value, AslError> {
        loop {
            let notified = pending.notify.notified();
            if let Some(outcome) = pending.outcome.lock().await.take() {
                self.store.remove_pending_task(token);
                self.store.remove_queued_activity_task(token).await;
                return match outcome {
                    TaskOutcome::Success(output) => Ok(output),
                    TaskOutcome::Failure { error, cause } => Err(AslError::new(error, cause)),
                };
            }
            if let Some(seconds) = pending.heartbeat_seconds {
                let deadline = *pending.last_heartbeat.lock().await + Duration::from_secs(seconds);
                tokio::select! {
                    _ = notified => {}
                    _ = tokio::time::sleep_until(deadline) => {
                        let timed_out = {
                            let outcome = pending.outcome.lock().await;
                            outcome.is_none()
                                && pending.heartbeat_expired().await
                                && self.store.remove_pending_task(token).is_some()
                        };
                        if timed_out {
                            self.store.remove_queued_activity_task(token).await;
                            return Err(AslError::new("States.HeartbeatTimeout", "task heartbeat timed out"));
                        }
                    }
                }
            } else {
                notified.await;
            }
        }
    }

    async fn dispatch_aws_sdk(
        &self,
        target: &str,
        payload: &Value,
        pattern: IntegrationPattern,
    ) -> Result<Value, AslError> {
        let (service, action) = target
            .split_once(':')
            .ok_or_else(|| AslError::runtime(format!("invalid AWS SDK integration {target}")))?;
        if service == "sfn" {
            return match action {
                "startExecution" => self.dispatch_nested_execution(payload, pattern, true).await,
                "startSyncExecution" if matches!(pattern, IntegrationPattern::RequestResponse) => {
                    let request = nested_request(payload);
                    match self
                        .dispatch_json("states", "AWSStepFunctions.StartSyncExecution", &request)
                        .await
                    {
                        Ok(response) => Ok(pascalize_top_level(response)),
                        Err(error) if error.error.ends_with("StateMachineTypeNotSupported") => {
                            self.dispatch_nested_execution(payload, IntegrationPattern::Sync, true)
                                .await
                        }
                        Err(error) => Err(error),
                    }
                }
                _ => Err(AslError::runtime(format!(
                    "unsupported AWS SDK integration {target}"
                ))),
            };
        }
        if service == "s3" {
            if !matches!(pattern, IntegrationPattern::RequestResponse) {
                return Err(AslError::runtime(
                    "S3 AWS SDK integrations do not support this pattern",
                ));
            }
            return self.dispatch_s3(action, payload).await;
        }
        if service == "athena" && action == "startQueryExecution" {
            if !matches!(pattern, IntegrationPattern::Sync) {
                return Err(AslError::runtime(
                    "Athena startQueryExecution requires .sync",
                ));
            }
            return self.dispatch_athena_sync(payload).await;
        }
        if !matches!(pattern, IntegrationPattern::RequestResponse) {
            return Err(AslError::runtime(format!(
                "integration pattern {} is unsupported for {target}",
                pattern.label()
            )));
        }
        let (canonical, prefix, supported): (&str, &str, &[&str]) = match service {
            "dynamodb" => (
                "dynamodb",
                "DynamoDB_20120810",
                &[
                    "getItem",
                    "putItem",
                    "query",
                    "updateItem",
                    "deleteItem",
                    "transactWriteItems",
                ],
            ),
            "sqs" => ("sqs", "AmazonSQS", &["sendMessage"]),
            "sns" => ("sns", "AmazonSimpleNotificationService", &["publish"]),
            "eventbridge" | "events" => ("events", "AWSEvents", &["putEvents"]),
            _ => {
                return Err(AslError::runtime(format!(
                    "unsupported AWS SDK service {service}"
                )))
            }
        };
        if !supported.contains(&action) {
            return Err(AslError::runtime(format!(
                "unsupported AWS SDK action {target}"
            )));
        }
        let operation = upper_camel(action);
        let result = self
            .dispatch_json(canonical, &format!("{prefix}.{operation}"), payload)
            .await;
        if service == "dynamodb" {
            result.map_err(|mut error| {
                if let Some(name) = error.error.strip_prefix("DynamoDB.") {
                    error.error = format!("DynamoDb.{name}");
                }
                error
            })
        } else {
            result
        }
    }

    async fn dispatch_nested_execution(
        &self,
        payload: &Value,
        pattern: IntegrationPattern,
        aws_sdk: bool,
    ) -> Result<Value, AslError> {
        if matches!(pattern, IntegrationPattern::WaitForTaskToken) {
            return Err(AslError::runtime(
                "states:startExecution.waitForTaskToken is not a supported callback integration",
            ));
        }
        let mut request = nested_request(payload);
        if let Some(input) = request.get("input") {
            if aws_sdk && !input.is_string() {
                return Err(AslError::new(
                    "Sfn.InvalidExecutionInput",
                    "StartExecution Input must be a serialized JSON string",
                ));
            }
            if !aws_sdk && !input.is_string() {
                let serialized = serde_json::to_string(input)
                    .map_err(|error| AslError::runtime(format!("invalid nested input: {error}")))?;
                request["input"] = Value::String(serialized);
            }
        }
        let started = self
            .dispatch_json("states", "AWSStepFunctions.StartExecution", &request)
            .await?;
        if matches!(pattern, IntegrationPattern::RequestResponse) {
            return Ok(pascalize_top_level(started));
        }
        let execution_arn = started
            .get("executionArn")
            .and_then(Value::as_str)
            .ok_or_else(|| AslError::task_failed("StartExecution response omitted executionArn"))?
            .to_string();
        loop {
            let described = self
                .dispatch_json(
                    "states",
                    "AWSStepFunctions.DescribeExecution",
                    &json!({ "executionArn": execution_arn }),
                )
                .await?;
            match described
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("RUNNING")
            {
                "RUNNING" | "PENDING_REDRIVE" => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                "SUCCEEDED" => {
                    if matches!(pattern, IntegrationPattern::Sync2) {
                        let mut result = pascalize_top_level(described);
                        if let Some(output) = result.get_mut("Output") {
                            let serialized = output.as_str().ok_or_else(|| {
                                AslError::task_failed("child output is not a JSON string")
                            })?;
                            *output = serde_json::from_str(serialized).map_err(|_| {
                                AslError::task_failed("child output is not valid JSON")
                            })?;
                        }
                        return Ok(result);
                    }
                    return Ok(pascalize_top_level(described));
                }
                _ => {
                    let error = described
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("States.TaskFailed");
                    let cause = described
                        .get("cause")
                        .and_then(Value::as_str)
                        .unwrap_or("child execution failed");
                    return Err(AslError::task_failed(
                        json!({ "Error": error, "Cause": cause }).to_string(),
                    ));
                }
            }
        }
    }

    async fn dispatch_athena_sync(&self, payload: &Value) -> Result<Value, AslError> {
        let started = self
            .dispatch_json("athena", "AmazonAthena.StartQueryExecution", payload)
            .await?;
        let query_id = started
            .get("QueryExecutionId")
            .and_then(Value::as_str)
            .ok_or_else(|| AslError::task_failed("Athena response omitted QueryExecutionId"))?;
        loop {
            let workgroup = payload
                .get("WorkGroup")
                .and_then(Value::as_str)
                .unwrap_or("primary");
            let resource = format!(
                "arn:aws:athena:{}:{}:workgroup/{workgroup}",
                self.region, self.account
            );
            let response = self
                .dispatch_json_with_resource(
                    "athena",
                    "AmazonAthena.GetQueryExecution",
                    &json!({ "QueryExecutionId": query_id }),
                    Some(&resource),
                )
                .await?;
            let state = response
                .pointer("/QueryExecution/Status/State")
                .and_then(Value::as_str)
                .unwrap_or("QUEUED");
            match state {
                "QUEUED" | "RUNNING" => tokio::time::sleep(Duration::from_millis(50)).await,
                "SUCCEEDED" => return Ok(response),
                _ => {
                    let cause = response
                        .pointer("/QueryExecution/Status/StateChangeReason")
                        .and_then(Value::as_str)
                        .unwrap_or("Athena query failed");
                    return Err(AslError::task_failed(cause));
                }
            }
        }
    }

    fn authorize_task(&self, action: &str, resource: &str) -> Result<(), AslError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or_else(|| AslError::task_failed("registry gone"))?;
        let Some(evaluator) =
            registry.authorization_evaluator(&localcloud_core::registry::ServiceName::new("iam"))
        else {
            return Ok(());
        };
        if !evaluator.strict_sigv4_required() {
            return Ok(());
        }
        evaluator
            .authorize_service_role_execution(ServiceRoleAuthorizationRequest {
                caller: RequestIdentity {
                    account_id: self.account.clone(),
                    access_key_id: None,
                    arn: None,
                },
                role_arn: self.role_arn.clone(),
                service_principal: "states.amazonaws.com".into(),
                action: action.into(),
                resource: resource.into(),
            })
            .map_err(|_| {
                AslError::new(
                    "States.Permissions",
                    format!("execution role is not authorized for {action} on {resource}"),
                )
            })
    }

    fn authorize_json_task(
        &self,
        service: &str,
        target: &str,
        payload: &Value,
    ) -> Result<(), AslError> {
        if !self
            .registry
            .upgrade()
            .and_then(|registry| {
                registry
                    .authorization_evaluator(&localcloud_core::registry::ServiceName::new("iam"))
            })
            .is_some_and(|evaluator| evaluator.strict_sigv4_required())
        {
            return Ok(());
        }
        let operation = target.rsplit('.').next().unwrap_or("");
        let (action, resource) = match service {
            "sqs" => {
                let url = payload
                    .get("QueueUrl")
                    .and_then(Value::as_str)
                    .ok_or_else(|| AslError::runtime("SQS integration requires QueueUrl"))?;
                let without_scheme = url.split("://").last().unwrap_or(url);
                let (host, path) = without_scheme
                    .split_once('/')
                    .ok_or_else(|| AslError::runtime("invalid SQS QueueUrl"))?;
                let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
                if segments.len() < 2 {
                    return Err(AslError::runtime("invalid SQS QueueUrl"));
                }
                let name = segments[segments.len() - 1];
                let account = segments[segments.len() - 2];
                let region = host
                    .strip_prefix("sqs.")
                    .and_then(|host| host.split('.').next())
                    .unwrap_or("us-east-1");
                (
                    format!("sqs:{operation}"),
                    format!("arn:aws:sqs:{region}:{account}:{name}"),
                )
            }
            "sns" => {
                let arn = payload
                    .get("TopicArn")
                    .or_else(|| payload.get("TargetArn"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        AslError::runtime("SNS integration requires TopicArn or TargetArn")
                    })?;
                (format!("sns:{operation}"), arn.into())
            }
            "dynamodb" => {
                let name = payload
                    .get("TableName")
                    .and_then(Value::as_str)
                    .ok_or_else(|| AslError::runtime("DynamoDB integration requires TableName"))?;
                let arn = if name.starts_with("arn:") {
                    name.into()
                } else {
                    format!(
                        "arn:aws:dynamodb:{}:{}:table/{name}",
                        self.region, self.account
                    )
                };
                (format!("dynamodb:{operation}"), arn)
            }
            "states" => {
                let (field, alternate) = if operation == "DescribeExecution" {
                    ("executionArn", "ExecutionArn")
                } else {
                    ("stateMachineArn", "StateMachineArn")
                };
                let arn = payload
                    .get(field)
                    .or_else(|| payload.get(alternate))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        AslError::runtime(format!(
                            "nested Step Functions integration requires {field}"
                        ))
                    })?;
                (format!("states:{operation}"), arn.into())
            }
            "athena" => {
                let workgroup = payload
                    .get("WorkGroup")
                    .and_then(Value::as_str)
                    .unwrap_or("primary");
                (
                    format!("athena:{operation}"),
                    format!(
                        "arn:aws:athena:{}:{}:workgroup/{workgroup}",
                        self.region, self.account
                    ),
                )
            }
            "events" => {
                let entries = payload
                    .get("Entries")
                    .and_then(Value::as_array)
                    .ok_or_else(|| AslError::runtime("EventBridge integration requires Entries"))?;
                for entry in entries {
                    let bus = entry
                        .get("EventBusName")
                        .and_then(Value::as_str)
                        .unwrap_or("default");
                    let arn = if bus.starts_with("arn:") {
                        bus.into()
                    } else {
                        format!(
                            "arn:aws:events:{}:{}:event-bus/{bus}",
                            self.region, self.account
                        )
                    };
                    self.authorize_task("events:PutEvents", &arn)?;
                }
                return Ok(());
            }
            _ => return Err(AslError::runtime(format!("unsupported service {service}"))),
        };
        self.authorize_task(&action, &resource)
    }

    async fn dispatch_s3(&self, action: &str, payload: &Value) -> Result<Value, AslError> {
        let bucket = payload
            .get("Bucket")
            .and_then(Value::as_str)
            .ok_or_else(|| AslError::runtime("S3 integration requires Bucket"))?;
        let key = payload
            .get("Key")
            .and_then(Value::as_str)
            .ok_or_else(|| AslError::runtime("S3 integration requires Key"))?;
        let iam_action = if action == "putObject" {
            "s3:PutObject"
        } else {
            "s3:GetObject"
        };
        self.authorize_task(iam_action, &format!("arn:aws:s3:::{bucket}/{key}"))?;
        let uri: http::Uri = format!("/{}/{}", encode_path(bucket), encode_path(key))
            .parse()
            .map_err(|_| AslError::runtime("S3 Bucket or Key is invalid"))?;
        let registry = self
            .registry
            .upgrade()
            .ok_or_else(|| AslError::task_failed("registry gone"))?;
        let dispatcher = registry
            .internal_dispatcher()
            .ok_or_else(|| AslError::task_failed("internal dispatcher unavailable"))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!(
                "AWS4-HMAC-SHA256 Credential=localcloud/19700101/{}/s3/aws4_request",
                self.region
            ))
            .expect("generated authorization header is valid"),
        );
        for (field, header) in [
            ("ContentMD5", "content-md5"),
            ("ContentType", "content-type"),
            ("IfNoneMatch", "if-none-match"),
        ] {
            if let Some(value) = payload.get(field).and_then(Value::as_str) {
                if let (Ok(name), Ok(value)) = (
                    http::header::HeaderName::from_bytes(header.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    headers.insert(name, value);
                }
            }
        }
        IdentityPropagator::attach(
            &mut headers,
            &CallerIdentity::AssumedRole {
                role_arn: self.role_arn.clone(),
                session_name: "stepfunctions".into(),
            },
        );
        let (method, body) = match action {
            "putObject" => {
                let body = payload.get("Body").cloned().unwrap_or(Value::Null);
                let bytes = match body {
                    Value::String(value) => value.into_bytes(),
                    Value::Null => Vec::new(),
                    value => value.to_string().into_bytes(),
                };
                (Method::PUT, Bytes::from(bytes))
            }
            "getObject" => (Method::GET, Bytes::new()),
            "headObject" => (Method::HEAD, Bytes::new()),
            _ => return Err(AslError::runtime(format!("unsupported S3 action {action}"))),
        };
        let response = dispatcher
            .dispatch_scoped(
                &method,
                &uri,
                &headers,
                body,
                &uuid::Uuid::new_v4().to_string(),
                &self.account,
                &self.region,
            )
            .await;
        let status = response.status();
        let response_headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|_| AslError::task_failed("failed to read S3 response"))?;
        if !status.is_success() {
            let xml = String::from_utf8_lossy(&body);
            let code = xml_value(&xml, "Code").unwrap_or_else(|| "S3Error".into());
            let message = xml_value(&xml, "Message").unwrap_or_else(|| status.to_string());
            return Err(AslError::new(format!("S3.{code}"), message));
        }
        let mut result = serde_json::Map::new();
        for (header, field) in [
            ("etag", "ETag"),
            ("content-type", "ContentType"),
            ("content-length", "ContentLength"),
            ("last-modified", "LastModified"),
            ("x-amz-version-id", "VersionId"),
        ] {
            if let Some(value) = response_headers
                .get(header)
                .and_then(|value| value.to_str().ok())
            {
                if field == "ContentLength" {
                    if let Ok(number) = value.parse::<u64>() {
                        result.insert(field.into(), json!(number));
                        continue;
                    }
                }
                result.insert(field.into(), json!(value));
            }
        }
        if action == "getObject" {
            let body = serde_json::from_slice(&body)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
            result.insert("Body".into(), body);
        }
        Ok(Value::Object(result))
    }

    async fn dispatch_json(
        &self,
        service: &str,
        target: &str,
        payload: &Value,
    ) -> Result<Value, AslError> {
        self.dispatch_json_with_resource(service, target, payload, None)
            .await
    }

    async fn dispatch_json_with_resource(
        &self,
        service: &str,
        target: &str,
        payload: &Value,
        resource_override: Option<&str>,
    ) -> Result<Value, AslError> {
        if let Some(resource) = resource_override {
            let operation = target.rsplit('.').next().unwrap_or("");
            self.authorize_task(&format!("{service}:{operation}"), resource)?;
        } else {
            self.authorize_json_task(service, target, payload)?;
        }
        let registry = self
            .registry
            .upgrade()
            .ok_or_else(|| AslError::task_failed("registry gone"))?;
        let dispatcher = registry
            .internal_dispatcher()
            .ok_or_else(|| AslError::task_failed("internal dispatcher unavailable"))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(target).expect("static target"),
        );
        let content_type = if service == "athena" {
            "application/x-amz-json-1.1"
        } else {
            "application/x-amz-json-1.0"
        };
        headers.insert("content-type", HeaderValue::from_static(content_type));
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!(
                "AWS4-HMAC-SHA256 Credential=localcloud/19700101/{}/{service}/aws4_request",
                self.region
            ))
            .expect("generated authorization header is valid"),
        );
        IdentityPropagator::attach(
            &mut headers,
            &CallerIdentity::AssumedRole {
                role_arn: self.role_arn.clone(),
                session_name: "stepfunctions".into(),
            },
        );
        let uri = "/".parse().expect("root uri");
        let body = Bytes::from(payload.to_string().into_bytes());
        let request_id = uuid::Uuid::new_v4().to_string();
        let resp = dispatcher
            .dispatch_scoped(
                &Method::POST,
                &uri,
                &headers,
                body,
                &request_id,
                &self.account,
                &self.region,
            )
            .await;
        parse_target_response(resp, Some(service)).await
    }

    async fn invoke_lambda(
        &self,
        name: &str,
        payload: &Value,
        qualifier: Option<&str>,
        invocation_type: Option<&str>,
    ) -> Result<Value, AslError> {
        let response = self
            .invoke_lambda_http(name, payload, qualifier, invocation_type, None)
            .await?;
        let function_error = response
            .headers()
            .get("x-amz-function-error")
            .and_then(|value| value.to_str().ok())
            .map(String::from);
        let value = parse_target_response(response, Some("lambda")).await?;
        if function_error.is_some() {
            return Err(lambda_function_error(&value));
        }
        Ok(value)
    }

    async fn invoke_lambda_http(
        &self,
        name: &str,
        payload: &Value,
        qualifier: Option<&str>,
        invocation_type: Option<&str>,
        client_context: Option<&str>,
    ) -> Result<axum::response::Response, AslError> {
        let function_arn = if name.starts_with("arn:") {
            name.to_string()
        } else {
            format!(
                "arn:aws:lambda:{}:{}:function:{name}",
                self.region, self.account
            )
        };
        let function_arn = match qualifier {
            Some(qualifier) if !function_arn.ends_with(&format!(":{qualifier}")) => {
                format!("{function_arn}:{qualifier}")
            }
            _ => function_arn,
        };
        self.authorize_task("lambda:InvokeFunction", &function_arn)?;
        let registry = self
            .registry
            .upgrade()
            .ok_or_else(|| AslError::task_failed("registry gone"))?;
        let dispatcher = registry
            .internal_dispatcher()
            .ok_or_else(|| AslError::task_failed("internal dispatcher unavailable"))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!(
                "AWS4-HMAC-SHA256 Credential=localcloud/19700101/{}/lambda/aws4_request",
                self.region
            ))
            .expect("generated authorization header is valid"),
        );
        if let Some(invocation_type) = invocation_type {
            headers.insert(
                "x-amz-invocation-type",
                HeaderValue::from_str(invocation_type)
                    .map_err(|_| AslError::runtime("invalid Lambda InvocationType"))?,
            );
        }
        if let Some(client_context) = client_context {
            headers.insert(
                "x-amz-client-context",
                HeaderValue::from_str(client_context)
                    .map_err(|_| AslError::runtime("invalid Lambda ClientContext"))?,
            );
        }
        IdentityPropagator::attach(
            &mut headers,
            &CallerIdentity::AssumedRole {
                role_arn: self.role_arn.clone(),
                session_name: "stepfunctions".into(),
            },
        );
        let qualifier = qualifier
            .map(|value| format!("?Qualifier={}", encode_path(value)))
            .unwrap_or_default();
        let uri = format!(
            "/2015-03-31/functions/{}/invocations{qualifier}",
            encode_path(name)
        )
        .parse()
        .map_err(|_| AslError::task_failed("invalid Lambda function name"))?;
        Ok(dispatcher
            .dispatch_scoped(
                &Method::POST,
                &uri,
                &headers,
                Bytes::from(payload.to_string().into_bytes()),
                &uuid::Uuid::new_v4().to_string(),
                &self.account,
                &self.region,
            )
            .await)
    }
}

fn lambda_function_error(payload: &Value) -> AslError {
    let error = payload
        .get("errorType")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("Lambda.Unknown");
    AslError::new(error, payload.to_string())
}

#[cfg(test)]
mod lambda_error_tests {
    use super::*;

    #[test]
    fn function_error_preserves_error_type_and_full_payload() {
        let payload = json!({
            "errorType": "LedgerPhaseContentConflictError",
            "errorMessage": "slot conflict",
            "trace": ["index.js:12"]
        });
        let error = lambda_function_error(&payload);
        assert_eq!(error.error, "LedgerPhaseContentConflictError");
        assert_eq!(
            serde_json::from_str::<Value>(&error.cause).unwrap(),
            payload
        );
        assert!(error.matches("LedgerPhaseContentConflictError"));
    }

    #[test]
    fn function_error_without_type_uses_lambda_unknown() {
        let error = lambda_function_error(&json!({"errorMessage": "failed"}));
        assert_eq!(error.error, "Lambda.Unknown");
    }
}

async fn parse_target_response(
    response: axum::response::Response,
    service: Option<&str>,
) -> Result<Value, AslError> {
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|_| AslError::task_failed("failed to read target response"))?;
    let value: Value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
    if status.is_success() {
        return Ok(value);
    }
    let raw_error = value
        .get("__type")
        .or_else(|| value.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("States.TaskFailed")
        .rsplit(['#', ':'])
        .next()
        .unwrap_or("States.TaskFailed");
    let error = if raw_error.starts_with("States.") || raw_error.contains('.') {
        raw_error.to_string()
    } else if let Some(service) = service {
        format!("{}.{raw_error}", service_error_prefix(service))
    } else {
        raw_error.to_string()
    };
    let cause = value
        .get("message")
        .or_else(|| value.get("Message"))
        .and_then(Value::as_str)
        .map(String::from)
        .unwrap_or_else(|| value.to_string());
    Err(AslError::new(error, cause))
}

fn service_error_prefix(service: &str) -> &str {
    match service {
        "dynamodb" => "DynamoDB",
        "lambda" => "Lambda",
        "s3" => "S3",
        "sqs" => "SQS",
        "sns" => "SNS",
        "events" => "EventBridge",
        "states" => "StepFunctions",
        "athena" => "Athena",
        other => other,
    }
}

#[derive(Clone, Copy)]
enum IntegrationPattern {
    RequestResponse,
    Sync,
    Sync2,
    WaitForTaskToken,
}

impl IntegrationPattern {
    fn parse(resource: &str) -> (&str, Self) {
        if let Some(base) = resource.strip_suffix(".waitForTaskToken") {
            (base, Self::WaitForTaskToken)
        } else if let Some(base) = resource.strip_suffix(".sync:2") {
            (base, Self::Sync2)
        } else if let Some(base) = resource.strip_suffix(".sync") {
            (base, Self::Sync)
        } else {
            (resource, Self::RequestResponse)
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::RequestResponse => "request-response",
            Self::Sync => ".sync",
            Self::Sync2 => ".sync:2",
            Self::WaitForTaskToken => ".waitForTaskToken",
        }
    }
}

fn upper_camel(value: &str) -> String {
    let mut characters = value.chars();
    match characters.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), characters.as_str()),
        None => String::new(),
    }
}

fn nested_request(payload: &Value) -> Value {
    let mut request = serde_json::Map::new();
    for (source, target) in [
        ("StateMachineArn", "stateMachineArn"),
        ("Name", "name"),
        ("Input", "input"),
        ("TraceHeader", "traceHeader"),
    ] {
        if let Some(value) = payload.get(source).or_else(|| payload.get(target)) {
            request.insert(target.into(), value.clone());
        }
    }
    Value::Object(request)
}

fn pascalize_top_level(value: Value) -> Value {
    let Value::Object(object) = value else {
        return value;
    };
    Value::Object(
        object
            .into_iter()
            .map(|(key, value)| (upper_camel(&key), value))
            .collect(),
    )
}

fn encode_path(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn xml_value(xml: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{tag}>");
    let end_tag = format!("</{tag}>");
    let start = xml.find(&start_tag)? + start_tag.len();
    let end = xml[start..].find(&end_tag)? + start;
    Some(xml[start..end].to_string())
}

fn parse_item_reader_body(body: &Value, config: &Value) -> Result<Vec<Value>, String> {
    let input_type = config
        .get("InputType")
        .and_then(Value::as_str)
        .unwrap_or("JSON")
        .to_ascii_uppercase();
    match input_type.as_str() {
        "JSON" => {
            let value = parse_reader_json(body)?;
            value
                .as_array()
                .cloned()
                .ok_or_else(|| "ItemReader JSON Body must be an array".to_string())
        }
        "JSONL" => reader_body_text(body)?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line)
                    .map_err(|error| format!("invalid ItemReader JSONL record: {error}"))
            })
            .collect(),
        "CSV" => parse_reader_csv(&reader_body_text(body)?, config),
        "MANIFEST" => {
            let value = parse_reader_json(body)?;
            if let Some(items) = value.as_array() {
                return Ok(items.clone());
            }
            ["Items", "items", "Entries", "entries"]
                .into_iter()
                .find_map(|field| value.get(field).and_then(Value::as_array))
                .cloned()
                .ok_or_else(|| {
                    "ItemReader manifest must be an array or contain Items/entries array"
                        .to_string()
                })
        }
        other => Err(format!("unsupported ItemReader InputType {other}")),
    }
}

fn parse_reader_json(body: &Value) -> Result<Value, String> {
    match body {
        Value::String(text) => serde_json::from_str(text)
            .map_err(|error| format!("invalid ItemReader JSON Body: {error}")),
        value => Ok(value.clone()),
    }
}

fn reader_body_text(body: &Value) -> Result<String, String> {
    match body {
        Value::String(text) => Ok(text.clone()),
        Value::Null => Err("ItemReader Body is empty".to_string()),
        value => Ok(value.to_string()),
    }
}

fn parse_reader_csv(text: &str, config: &Value) -> Result<Vec<Value>, String> {
    let mut records = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_csv_record)
        .collect::<Result<Vec<_>, _>>()?;
    let configured_headers = config.get("CSVHeaders").and_then(Value::as_array);
    let mut headers = match configured_headers {
        Some(values) if !values.is_empty() => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(String::from)
                    .ok_or_else(|| "ItemReader CSVHeaders must contain strings".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ if config.get("CSVHeaderLocation").and_then(Value::as_str) == Some("FIRST_ROW") => {
            if records.is_empty() {
                return Ok(Vec::new());
            }
            records.remove(0)
        }
        _ => {
            return Err(
                "ItemReader CSV requires CSVHeaderLocation FIRST_ROW or CSVHeaders".to_string(),
            )
        }
    };
    if let Some(first) = headers.first_mut() {
        *first = first.trim_start_matches('\u{feff}').to_string();
    }
    Ok(records
        .into_iter()
        .map(|record| {
            Value::Object(
                headers
                    .iter()
                    .enumerate()
                    .map(|(index, header)| {
                        (
                            header.clone(),
                            Value::String(record.get(index).cloned().unwrap_or_default()),
                        )
                    })
                    .collect(),
            )
        })
        .collect())
}

fn parse_csv_record(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.trim_end_matches('\r').chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(std::mem::take(&mut field));
            }
            character => field.push(character),
        }
    }
    if quoted {
        return Err("unterminated quoted field in ItemReader CSV".to_string());
    }
    fields.push(field);
    Ok(fields)
}

fn render_inspection(inspection: &StateInspection) -> Value {
    fn encoded(value: &Option<Value>) -> Option<Value> {
        value.as_ref().map(|value| Value::String(value.to_string()))
    }
    let mut data = serde_json::Map::new();
    for (name, value) in [
        ("input", encoded(&inspection.input)),
        ("afterInputPath", encoded(&inspection.after_input_path)),
        ("afterParameters", encoded(&inspection.after_parameters)),
        ("afterArguments", encoded(&inspection.after_arguments)),
        ("result", encoded(&inspection.result)),
        (
            "afterResultSelector",
            encoded(&inspection.after_result_selector),
        ),
        ("afterResultPath", encoded(&inspection.after_result_path)),
        ("output", encoded(&inspection.output)),
    ] {
        if let Some(value) = value {
            data.insert(name.into(), value);
        }
    }
    Value::Object(data)
}

enum Attempt {
    Task {
        resource: String,
        heartbeat_seconds: Option<u64>,
    },
    Parallel {
        branches: Vec<Value>,
    },
    Map {
        state: Value,
    },
}

fn validate_state_payload_size(value: &Value) -> Result<(), AslError> {
    if serde_json::to_vec(value).map_or(true, |payload| payload.len() > 256 * 1024) {
        return Err(AslError::new(
            "States.DataLimitExceeded",
            "state input or output exceeds the 256 KiB limit",
        ));
    }
    Ok(())
}

/// `ResultPath` option: `None` (absent), `Some(None)` (explicit null), `Some(Some(path))`.
fn result_path_option(state: &Value) -> Option<Option<&str>> {
    match state.get("ResultPath") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(s)) => Some(Some(s.as_str())),
        Some(_) => Some(Some("$")),
    }
}

fn str_opt<'a>(state: &'a Value, key: &str) -> Option<&'a str> {
    state.get(key).and_then(Value::as_str)
}

/// Whether the first matching retrier has another attempt available.
fn retry_available(retriers: &[Value], err: &AslError, retry_count: u32) -> bool {
    retriers
        .iter()
        .find(|retrier| error_equals_match(retrier, err))
        .is_some_and(|retrier| {
            let max_attempts = retrier
                .get("MaxAttempts")
                .and_then(Value::as_u64)
                .unwrap_or(3) as u32;
            retry_count < max_attempts
        })
}

/// Compute a retry delay from a caller-supplied jitter sample in `[0, 1]`.
pub(crate) fn retry_backoff_seconds(
    interval: f64,
    backoff: f64,
    attempt: u32,
    max_delay: f64,
    jitter_full: bool,
    jitter_sample: f64,
) -> f64 {
    let ceiling = (interval * backoff.powi(attempt.saturating_sub(1) as i32))
        .min(max_delay)
        .max(0.0);
    if jitter_full {
        ceiling * jitter_sample.clamp(0.0, 1.0)
    } else {
        ceiling
    }
}

/// Find a matching retrier and return the delay, updating attempt counts.
fn match_retry(retriers: &[Value], err: &AslError, counts: &mut [u32]) -> Option<Duration> {
    for (i, retrier) in retriers.iter().enumerate() {
        if !error_equals_match(retrier, err) {
            continue;
        }
        let max_attempts = retrier
            .get("MaxAttempts")
            .and_then(Value::as_u64)
            .unwrap_or(3) as u32;
        if counts[i] >= max_attempts {
            return None;
        }
        counts[i] += 1;
        let interval = retrier
            .get("IntervalSeconds")
            .and_then(Value::as_f64)
            .unwrap_or(1.0);
        let backoff = retrier
            .get("BackoffRate")
            .and_then(Value::as_f64)
            .unwrap_or(2.0);
        let max_delay = retrier
            .get("MaxDelaySeconds")
            .and_then(Value::as_f64)
            .unwrap_or(f64::MAX);
        let jitter_full = retrier.get("JitterStrategy").and_then(Value::as_str) == Some("FULL");
        let sample = if jitter_full {
            (Uuid::new_v4().as_u128() as f64) / (u128::MAX as f64)
        } else {
            1.0
        };
        let seconds =
            retry_backoff_seconds(interval, backoff, counts[i], max_delay, jitter_full, sample);
        return Some(Duration::from_secs_f64(seconds));
    }
    None
}

/// Find a matching catcher and return `(catcher, Next, ResultPath option)`.
fn match_catch<'a>(
    catchers: &'a [Value],
    err: &AslError,
) -> Option<(&'a Value, String, Option<Option<&'a str>>)> {
    for catcher in catchers {
        if !error_equals_match(catcher, err) {
            continue;
        }
        let next = catcher.get("Next").and_then(Value::as_str)?.to_string();
        let rp = result_path_option(catcher);
        return Some((catcher, next, rp));
    }
    None
}

fn error_equals_match(entry: &Value, err: &AslError) -> bool {
    entry
        .get("ErrorEquals")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).any(|e| err.matches(e)))
        .unwrap_or(false)
}
