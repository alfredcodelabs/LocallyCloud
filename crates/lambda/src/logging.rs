//! CloudWatch formatting and filtering; application JSON is produced by the AWS runtime.

use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::executor::{InitStatus, InvokeResult};
use crate::model::{ApplicationLogLevel, LambdaFunction, LogFormat, LoggingConfig, SystemLogLevel};
use crate::runtime_api::Outcome;

pub(crate) fn invocation_lines(result: &InvokeResult, function: &LambdaFunction) -> Vec<String> {
    if function.logging_config.log_format == LogFormat::Text {
        return result.log_lines(&function.version, function.memory_size);
    }
    json_lines(
        result,
        &function.logging_config,
        &function.version,
        function.memory_size,
        function.runtime.as_deref(),
    )
}

pub(crate) fn application_lines(
    logs: &str,
    config: &LoggingConfig,
    runtime: Option<&str>,
) -> Vec<String> {
    if config.log_format == LogFormat::Text {
        return logs.lines().map(str::to_owned).collect();
    }
    logs.lines()
        .filter_map(|line| application_line(line, config.application_log_level(), runtime))
        .collect()
}

fn application_line(
    line: &str,
    minimum: ApplicationLogLevel,
    runtime: Option<&str>,
) -> Option<String> {
    let mut value = serde_json::from_str::<Value>(line).ok();
    let object = value.as_mut().and_then(Value::as_object_mut);
    let Some(object) = object else {
        return (ApplicationLogLevel::Info >= minimum).then(|| line.to_owned());
    };
    let valid_timestamp = ["timestamp", "time", "@timestamp"]
        .iter()
        .filter_map(|key| object.get(*key).and_then(Value::as_str))
        .any(|timestamp| OffsetDateTime::parse(timestamp, &Rfc3339).is_ok());
    let runtime_level = object
        .get("level")
        .and_then(Value::as_str)
        .and_then(|level| match level.to_ascii_uppercase().as_str() {
            "TRACE" => Some(ApplicationLogLevel::Trace),
            "DEBUG" => Some(ApplicationLogLevel::Debug),
            "INFO" => Some(ApplicationLogLevel::Info),
            "WARN" => Some(ApplicationLogLevel::Warn),
            "ERROR" => Some(ApplicationLogLevel::Error),
            "FATAL" => Some(ApplicationLogLevel::Fatal),
            _ => None,
        });
    // The official logger already applied its level, including an explicit code override.
    // Raw/custom output must still pass the service-side filter.
    let managed_logger = runtime
        .is_some_and(|runtime| runtime.starts_with("python3.") || runtime.starts_with("nodejs"))
        && valid_timestamp
        && runtime_level.is_some()
        && object.contains_key("message")
        && object.get("requestId").is_some_and(Value::is_string);
    if managed_logger {
        return Some(line.to_owned());
    }
    let level = if valid_timestamp {
        runtime_level.unwrap_or(ApplicationLogLevel::Info)
    } else {
        ApplicationLogLevel::Info
    };
    if level < minimum {
        return None;
    }
    if valid_timestamp {
        return Some(line.to_owned());
    }
    object.insert("timestamp".into(), json!(timestamp()));
    value.map(|value| value.to_string())
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn json_lines(
    result: &InvokeResult,
    config: &LoggingConfig,
    version: &str,
    memory_size: u32,
    runtime: Option<&str>,
) -> Vec<String> {
    let mut lines = application_lines(&result.init_logs, config, runtime);
    let platform = |kind: &str, level: SystemLogLevel, record: Value, lines: &mut Vec<String>| {
        if level >= config.system_log_level() {
            lines.push(json!({"time":timestamp(), "type":kind, "record":record}).to_string());
        }
    };
    if let Some(init) = &result.init {
        let (status, level, error_type) = match &init.status {
            InitStatus::Success => ("success", SystemLogLevel::Debug, None),
            InitStatus::Timeout => ("timeout", SystemLogLevel::Warn, None),
            InitStatus::Error(error) => ("error", SystemLogLevel::Warn, Some(error)),
        };
        let mut record = json!({"initializationType":"on-demand", "phase":"init", "status":status,
            "metrics":{"durationMs":init.duration_us as f64 / 1000.0}});
        if let Some(error) = error_type {
            record["errorType"] = json!(error);
        }
        platform("platform.initReport", level, record, &mut lines);
    }
    let Some(request_id) = result.request_id.as_deref() else {
        lines.extend(application_lines(&result.logs, config, runtime));
        return lines;
    };
    platform(
        "platform.start",
        SystemLogLevel::Info,
        json!({"requestId":request_id, "version":version}),
        &mut lines,
    );
    lines.extend(application_lines(&result.logs, config, runtime));
    let (status, runtime_level, report_level) = match &result.outcome {
        Outcome::Success(_) => ("success", SystemLogLevel::Debug, SystemLogLevel::Info),
        Outcome::Error { .. } => ("error", SystemLogLevel::Warn, SystemLogLevel::Warn),
    };
    platform(
        "platform.runtimeDone",
        runtime_level,
        json!({"requestId":request_id,"status":status,
        "metrics":{"durationMs":result.duration_us as f64 / 1000.0}}),
        &mut lines,
    );
    let mut metrics = json!({"durationMs":result.duration_us as f64 / 1000.0,
        "billedDurationMs":result.billed_duration_ms,"memorySizeMB":memory_size});
    if let Some(init) = &result.init {
        if init.status == InitStatus::Success {
            metrics["initDurationMs"] = json!(init.duration_us as f64 / 1000.0);
        }
    }
    platform(
        "platform.report",
        report_level,
        json!({"requestId":request_id,"status":status,"metrics":metrics}),
        &mut lines,
    );
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::InitReport;
    use crate::runtime_api::FunctionErrorType;

    fn result() -> InvokeResult {
        InvokeResult {
            outcome: Outcome::Success(Vec::new()),
            logs: String::new(),
            request_id: Some("request".into()),
            log_stream_name: Some("stream".into()),
            duration_us: 1250,
            billed_duration_ms: 2,
            init: None,
            init_logs: String::new(),
            formatted_log_tail: None,
        }
    }

    #[test]
    fn json_logs_preserve_application_objects_and_filter_levels() {
        let mut config = LoggingConfig {
            log_format: LogFormat::Json,
            ..Default::default()
        };
        config.application_log_level = Some(ApplicationLogLevel::Warn);
        let high = r#"{"timestamp":"2026-11-13T00:00:00Z","level":"ERROR","message":"keep"}"#;
        let low = r#"{"timestamp":"2026-11-13T00:00:00Z","level":"DEBUG","message":"drop"}"#;
        let no_timestamp = r#"{"level":"ERROR","message":"treated as INFO"}"#;
        let input = format!("{high}\n{low}\n{no_timestamp}\nplain INFO\n");
        assert_eq!(application_lines(&input, &config, None), vec![high]);
        config.application_log_level = Some(ApplicationLogLevel::Info);
        let output = application_lines(no_timestamp, &config, None);
        let parsed: Value = serde_json::from_str(&output[0]).unwrap();
        assert!(OffsetDateTime::parse(parsed["timestamp"].as_str().unwrap(), &Rfc3339).is_ok());
        assert_eq!(
            application_lines("plain INFO", &config, None),
            vec!["plain INFO"]
        );
    }

    #[test]
    fn managed_logger_code_override_is_not_filtered_twice() {
        let config = LoggingConfig {
            log_format: LogFormat::Json,
            application_log_level: Some(ApplicationLogLevel::Warn),
            ..Default::default()
        };
        let line = r#"{"timestamp":"2026-11-13T00:00:00Z","level":"INFO","message":"explicit Python logger level","requestId":"request"}"#;
        assert_eq!(application_lines(line, &config, Some("python3.13")), [line]);
        assert_eq!(application_lines(line, &config, Some("nodejs22.x")), [line]);
        assert!(application_lines(line, &config, Some("provided.al2023")).is_empty());
        assert!(application_lines("plain INFO", &config, Some("python3.13")).is_empty());
    }

    #[test]
    fn platform_logs_use_aws_schema_and_system_severity() {
        let mut config = LoggingConfig {
            log_format: LogFormat::Json,
            ..Default::default()
        };
        let mut invocation = result();
        let lines = json_lines(&invocation, &config, "$LATEST", 128, None);
        let parsed: Vec<Value> = lines
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            parsed
                .iter()
                .map(|value| value["type"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["platform.start", "platform.report"]
        );
        assert_eq!(parsed[1]["record"]["metrics"]["durationMs"], 1.25);
        config.system_log_level = Some(SystemLogLevel::Warn);
        assert!(json_lines(&invocation, &config, "$LATEST", 128, None).is_empty());
        invocation.outcome = Outcome::Error {
            error_type: FunctionErrorType::Unhandled,
            payload: Vec::new(),
        };
        invocation.init = Some(InitReport {
            duration_us: 2000,
            status: InitStatus::Error("Runtime.ImportModuleError".into()),
        });
        let types: Vec<String> = json_lines(&invocation, &config, "$LATEST", 128, None)
            .into_iter()
            .map(|line| {
                serde_json::from_str::<Value>(&line).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            types,
            [
                "platform.initReport",
                "platform.runtimeDone",
                "platform.report"
            ]
        );
    }
}
