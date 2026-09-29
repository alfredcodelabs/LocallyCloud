//! Execution environment variables for a Lambda guest.
//!
//! Builds the variable map injected into the execution environment: the Runtime API endpoint,
//! the handler, the standard function/region/log variables, endpoint + credentials for
//! in-guest SDK calls back to localcloud, and the user-configured `Environment` map. Reserved
//! keys cannot be set by the user and are rejected at configuration time (Requirement 21.7).

use std::collections::BTreeMap;

use crate::error::LambdaError;

/// The guest task root where function code is placed.
pub const LAMBDA_TASK_ROOT: &str = "/var/task";

/// Keys reserved by the Lambda execution environment; a user `Environment` may not set these.
pub const RESERVED_ENV_KEYS: &[&str] = &[
    "_HANDLER",
    "_X_AMZN_TRACE_ID",
    "AWS_EXECUTION_ENV",
    "AWS_LAMBDA_FUNCTION_NAME",
    "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
    "AWS_LAMBDA_FUNCTION_VERSION",
    "AWS_LAMBDA_INITIALIZATION_TYPE",
    "AWS_LAMBDA_LOG_GROUP_NAME",
    "AWS_LAMBDA_LOG_STREAM_NAME",
    "AWS_LAMBDA_RUNTIME_API",
    "AWS_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "AWS_SESSION_TOKEN",
    "LAMBDA_TASK_ROOT",
    "LAMBDA_RUNTIME_DIR",
    "TZ",
];

/// Reject a user `Environment` map that sets any reserved key.
pub fn validate_environment(env: &BTreeMap<String, String>) -> Result<(), LambdaError> {
    for key in env.keys() {
        if RESERVED_ENV_KEYS.contains(&key.as_str()) {
            return Err(LambdaError::InvalidParameterValue(format!(
                "Environment variable {key} is reserved and cannot be set"
            )));
        }
    }
    Ok(())
}

/// Inputs for assembling the execution environment.
pub struct ExecEnvInputs<'a> {
    pub function_name: &'a str,
    pub function_version: &'a str,
    pub runtime: Option<&'a str>,
    pub handler: Option<&'a str>,
    pub memory_size: u32,
    pub region: &'a str,
    pub log_stream: &'a str,
    /// Host endpoint the guest reaches the Runtime API on, e.g. `127.0.0.1:9001` (no scheme).
    pub runtime_api: &'a str,
    /// localcloud endpoint URL for in-guest AWS SDK calls, e.g. `http://127.0.0.1:4566`.
    pub aws_endpoint_url: &'a str,
    /// Credentials injected for in-guest SDK calls (the local fixed test identity).
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub session_token: Option<&'a str>,
    /// The user-configured environment (already validated).
    pub user_env: &'a BTreeMap<String, String>,
}

/// Build the full execution environment variable map. Standard variables take precedence over
/// the user map for reserved keys (the user map is validated to exclude them anyway).
pub fn build_execution_env(input: &ExecEnvInputs) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();

    // User variables first; reserved variables below overwrite to guarantee correctness.
    for (k, v) in input.user_env {
        env.insert(k.clone(), v.clone());
    }

    env.insert(
        "AWS_LAMBDA_RUNTIME_API".into(),
        input.runtime_api.to_string(),
    );
    env.insert(
        "AWS_LAMBDA_FUNCTION_NAME".into(),
        input.function_name.to_string(),
    );
    env.insert(
        "AWS_LAMBDA_FUNCTION_VERSION".into(),
        input.function_version.to_string(),
    );
    env.insert(
        "AWS_LAMBDA_FUNCTION_MEMORY_SIZE".into(),
        input.memory_size.to_string(),
    );
    env.insert("AWS_REGION".into(), input.region.to_string());
    env.insert("AWS_DEFAULT_REGION".into(), input.region.to_string());
    env.insert("LAMBDA_TASK_ROOT".into(), LAMBDA_TASK_ROOT.to_string());
    env.insert(
        "AWS_LAMBDA_LOG_GROUP_NAME".into(),
        format!("/aws/lambda/{}", input.function_name),
    );
    env.insert(
        "AWS_LAMBDA_LOG_STREAM_NAME".into(),
        input.log_stream.to_string(),
    );
    env.insert("AWS_LAMBDA_INITIALIZATION_TYPE".into(), "on-demand".into());
    if let Some(runtime) = input.runtime {
        env.insert("AWS_EXECUTION_ENV".into(), format!("AWS_Lambda_{runtime}"));
    }
    // `_HANDLER` is set for Zip (managed-runtime) functions.
    if let Some(handler) = input.handler {
        env.insert("_HANDLER".into(), handler.to_string());
    }

    // Endpoint + credentials so an in-guest AWS SDK reaches localcloud, not real AWS.
    env.insert(
        "AWS_ENDPOINT_URL".into(),
        input.aws_endpoint_url.to_string(),
    );
    env.insert("AWS_ACCESS_KEY_ID".into(), input.access_key_id.to_string());
    env.insert(
        "AWS_SECRET_ACCESS_KEY".into(),
        input.secret_access_key.to_string(),
    );
    if let Some(token) = input.session_token {
        env.insert("AWS_SESSION_TOKEN".into(), token.to_string());
    }

    env
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn rejects_reserved_keys() {
        let env = user(&[("AWS_LAMBDA_FUNCTION_NAME", "other")]);
        assert!(validate_environment(&env).is_err());
        let env = user(&[("_HANDLER", "x")]);
        assert!(validate_environment(&env).is_err());
    }

    #[test]
    fn allows_user_keys() {
        let env = user(&[("TABLE_NAME", "items"), ("LOG_LEVEL", "debug")]);
        assert!(validate_environment(&env).is_ok());
    }

    #[test]
    fn builds_standard_variables() {
        let user_env = user(&[("TABLE_NAME", "items")]);
        let env = build_execution_env(&ExecEnvInputs {
            function_name: "fn",
            function_version: "$LATEST",
            runtime: Some("nodejs22.x"),
            handler: Some("index.handler"),
            memory_size: 256,
            region: "us-east-1",
            log_stream: "2024/01/01/[$LATEST]abc",
            runtime_api: "127.0.0.1:9001",
            aws_endpoint_url: "http://127.0.0.1:4566",
            access_key_id: "test",
            secret_access_key: "test",
            session_token: None,
            user_env: &user_env,
        });
        assert_eq!(env["AWS_LAMBDA_RUNTIME_API"], "127.0.0.1:9001");
        assert_eq!(env["_HANDLER"], "index.handler");
        assert_eq!(env["AWS_LAMBDA_FUNCTION_NAME"], "fn");
        assert_eq!(env["AWS_LAMBDA_FUNCTION_MEMORY_SIZE"], "256");
        assert_eq!(env["AWS_REGION"], "us-east-1");
        assert_eq!(env["LAMBDA_TASK_ROOT"], "/var/task");
        assert_eq!(env["AWS_LAMBDA_LOG_GROUP_NAME"], "/aws/lambda/fn");
        assert_eq!(env["AWS_EXECUTION_ENV"], "AWS_Lambda_nodejs22.x");
        assert_eq!(env["AWS_ENDPOINT_URL"], "http://127.0.0.1:4566");
        assert_eq!(env["AWS_ACCESS_KEY_ID"], "test");
        assert_eq!(env["TABLE_NAME"], "items");
    }

    #[test]
    fn standard_variables_win_over_user_collisions() {
        // Even if a user map somehow contains a reserved key, the standard value wins in the
        // assembled environment (validation rejects this earlier, but the builder is robust).
        let user_env = user(&[("AWS_REGION", "eu-west-1")]);
        let env = build_execution_env(&ExecEnvInputs {
            function_name: "fn",
            function_version: "$LATEST",
            runtime: None,
            handler: None,
            memory_size: 128,
            region: "us-east-1",
            log_stream: "s",
            runtime_api: "127.0.0.1:9001",
            aws_endpoint_url: "http://127.0.0.1:4566",
            access_key_id: "test",
            secret_access_key: "test",
            session_token: None,
            user_env: &user_env,
        });
        assert_eq!(env["AWS_REGION"], "us-east-1");
        // Custom-runtime function: no _HANDLER injected.
        assert!(!env.contains_key("_HANDLER"));
    }
}
