use std::sync::{Arc, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use localcloud_core::integration::correlation::CorrelationContext;
use localcloud_core::integration::identity::CallerIdentity;
use localcloud_core::integration::logs::{
    GroupRef, InternalLogSink, LogScope, ProducerContext, ProducerGroupSpec, ProducerLogEvent,
    ProducerStreamSpec, SinkError,
};
use localcloud_core::registry::{ServiceName, ServiceRegistry};
use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiGwError;

const ACCESS_FIELDS: &[&str] = &[
    "$context.requestId",
    "$context.extendedRequestId",
    "$context.status",
    "$context.httpMethod",
    "$context.path",
    "$context.resourcePath",
    "$context.routeKey",
    "$context.stage",
    "$context.protocol",
    "$context.domainName",
    "$context.identity.sourceIp",
    "$context.identity.userAgent",
    "$context.responseLength",
    "$context.integrationStatus",
];

#[derive(Clone)]
enum FormatPart {
    Literal(String),
    Field { name: String, json_escaped: bool },
}

#[derive(Clone)]
pub struct AccessLogSettings {
    group_name: String,
    format: Vec<FormatPart>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExecutionLevel {
    Off,
    Error,
    Info,
}

#[derive(Clone)]
pub struct StageLogging {
    access: Option<AccessLogSettings>,
    execution: ExecutionLevel,
    execution_group: Option<String>,
}

impl StageLogging {
    pub fn disabled() -> Self {
        Self {
            access: None,
            execution: ExecutionLevel::Off,
            execution_group: None,
        }
    }

    pub fn enabled(&self) -> bool {
        self.access.is_some() || self.execution != ExecutionLevel::Off
    }
}

pub struct RequestLogValues<'a> {
    pub request_id: &'a str,
    pub status: u16,
    pub method: &'a str,
    pub path: &'a str,
    pub resource_path: Option<&'a str>,
    pub route_key: Option<&'a str>,
    pub stage: &'a str,
    pub protocol: &'a str,
    pub domain_name: &'a str,
    pub source_ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub response_length: usize,
    pub integration_status: Option<u16>,
}

impl RequestLogValues<'_> {
    fn value(&self, field: &str) -> String {
        match field {
            "$context.requestId" | "$context.extendedRequestId" => self.request_id.to_string(),
            "$context.status" => self.status.to_string(),
            "$context.httpMethod" => self.method.to_string(),
            "$context.path" => self.path.to_string(),
            "$context.resourcePath" => self.resource_path.unwrap_or("-").to_string(),
            "$context.routeKey" => self.route_key.unwrap_or("-").to_string(),
            "$context.stage" => self.stage.to_string(),
            "$context.protocol" => self.protocol.to_string(),
            "$context.domainName" => value_or_dash(Some(self.domain_name)),
            "$context.identity.sourceIp" => value_or_dash(self.source_ip),
            "$context.identity.userAgent" => value_or_dash(self.user_agent),
            "$context.responseLength" => self.response_length.to_string(),
            "$context.integrationStatus" => self
                .integration_status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "-".into()),
            _ => "-".into(),
        }
    }
}

fn value_or_dash(value: Option<&str>) -> String {
    value
        .filter(|value| !value.is_empty())
        .unwrap_or("-")
        .to_string()
}

fn parse_format(format: &str) -> Result<Vec<FormatPart>, ApiGwError> {
    if format.trim().is_empty() {
        return Err(ApiGwError::BadRequest(
            "accessLogSettings.format must not be empty".into(),
        ));
    }
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut index = 0;
    let mut in_json_string = false;
    let mut escaped = false;
    let mut includes_request_id = false;
    while index < format.len() {
        let rest = &format[index..];
        if rest.starts_with("$context.") {
            if !literal.is_empty() {
                parts.push(FormatPart::Literal(std::mem::take(&mut literal)));
            }
            let end = rest
                .char_indices()
                .skip("$context.".len())
                .find_map(|(offset, ch)| {
                    (!ch.is_ascii_alphanumeric() && ch != '_' && ch != '.').then_some(offset)
                })
                .unwrap_or(rest.len());
            let token = &rest[..end];
            if !ACCESS_FIELDS.contains(&token) {
                return Err(ApiGwError::BadRequest(format!(
                    "Unsupported access log variable: {token}"
                )));
            }
            includes_request_id |=
                matches!(token, "$context.requestId" | "$context.extendedRequestId");
            parts.push(FormatPart::Field {
                name: token.to_string(),
                json_escaped: in_json_string,
            });
            index += end;
            continue;
        }
        let ch = rest.chars().next().expect("index is inside string");
        literal.push(ch);
        index += ch.len_utf8();
        if in_json_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_json_string = false;
            }
        } else if ch == '"' {
            in_json_string = true;
        }
    }
    if !literal.is_empty() {
        parts.push(FormatPart::Literal(literal));
    }
    if !includes_request_id {
        return Err(ApiGwError::BadRequest(
            "accessLogSettings.format must include $context.requestId or $context.extendedRequestId"
                .into(),
        ));
    }
    Ok(parts)
}

fn parse_destination_arn(arn: &str, account: &str, region: &str) -> Result<String, ApiGwError> {
    let mut fields = arn.splitn(6, ':');
    if fields.next() != Some("arn")
        || fields.next() != Some("aws")
        || fields.next() != Some("logs")
        || fields.next() != Some(region)
        || fields.next() != Some(account)
    {
        return Err(ApiGwError::BadRequest(
            "accessLogSettings.destinationArn must be a Logs log-group ARN in this account and region"
                .into(),
        ));
    }
    let resource = fields.next().unwrap_or("");
    let name = resource
        .strip_prefix("log-group:")
        .and_then(|value| value.strip_suffix(":*").or(Some(value)))
        .filter(|value| !value.is_empty() && !value.contains(':'))
        .ok_or_else(|| {
            ApiGwError::BadRequest(
                "accessLogSettings.destinationArn must identify a non-empty log group".into(),
            )
        })?;
    Ok(name.to_string())
}

fn access_settings(
    stage: &Value,
    account: &str,
    region: &str,
) -> Result<Option<AccessLogSettings>, ApiGwError> {
    let Some(settings) = stage.get("accessLogSettings") else {
        return Ok(None);
    };
    if settings.is_null() {
        return Ok(None);
    }
    let settings = settings
        .as_object()
        .ok_or_else(|| ApiGwError::BadRequest("accessLogSettings must be an object".into()))?;
    if settings
        .keys()
        .any(|key| !matches!(key.as_str(), "destinationArn" | "format"))
    {
        return Err(ApiGwError::BadRequest(
            "accessLogSettings contains unsupported fields".into(),
        ));
    }
    let destination = settings
        .get("destinationArn")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiGwError::BadRequest("accessLogSettings.destinationArn is required".into())
        })?;
    let format = settings
        .get("format")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiGwError::BadRequest("accessLogSettings.format is required".into()))?;
    Ok(Some(AccessLogSettings {
        group_name: parse_destination_arn(destination, account, region)?,
        format: parse_format(format)?,
    }))
}

fn default_bool(settings: &serde_json::Map<String, Value>, key: &str) -> bool {
    settings.get(key).and_then(Value::as_bool) == Some(false)
}

fn execution_level(stage: &Value) -> Result<ExecutionLevel, ApiGwError> {
    let Some(all_settings) = stage.get("methodSettings") else {
        return Ok(ExecutionLevel::Off);
    };
    if all_settings.is_null() {
        return Ok(ExecutionLevel::Off);
    }
    let all_settings = all_settings
        .as_object()
        .ok_or_else(|| ApiGwError::BadRequest("methodSettings must be an object".into()))?;
    if all_settings.is_empty() {
        return Ok(ExecutionLevel::Off);
    }
    if all_settings.len() != 1 || !all_settings.contains_key("*/*") {
        return Err(ApiGwError::BadRequest(
            "Only the global */* methodSettings entry is supported".into(),
        ));
    }
    let settings = all_settings["*/*"]
        .as_object()
        .ok_or_else(|| ApiGwError::BadRequest("methodSettings.*/* must be an object".into()))?;
    let allowed = [
        "loggingLevel",
        "dataTraceEnabled",
        "metricsEnabled",
        "cachingEnabled",
        "cacheTtlInSeconds",
        "cacheDataEncrypted",
        "requireAuthorizationForCacheControl",
        "unauthorizedCacheControlHeaderStrategy",
        "throttlingBurstLimit",
        "throttlingRateLimit",
    ];
    if settings.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ApiGwError::BadRequest(
            "methodSettings contains unsupported fields".into(),
        ));
    }
    if settings.get("dataTraceEnabled").and_then(Value::as_bool) == Some(true) {
        return Err(ApiGwError::BadRequest(
            "dataTraceEnabled=true is not supported".into(),
        ));
    }
    for key in [
        "dataTraceEnabled",
        "metricsEnabled",
        "cachingEnabled",
        "cacheDataEncrypted",
        "requireAuthorizationForCacheControl",
    ] {
        if settings.contains_key(key) && !default_bool(settings, key) {
            return Err(ApiGwError::BadRequest(format!(
                "methodSettings.{key} must be false"
            )));
        }
    }
    if settings
        .get("cacheTtlInSeconds")
        .is_some_and(|value| value.as_i64() != Some(300))
    {
        return Err(ApiGwError::BadRequest(
            "methodSettings.cacheTtlInSeconds must use its default value".into(),
        ));
    }
    if settings
        .get("unauthorizedCacheControlHeaderStrategy")
        .is_some_and(|value| value.as_str() != Some("SUCCEED_WITH_RESPONSE_HEADER"))
    {
        return Err(ApiGwError::BadRequest(
            "methodSettings.unauthorizedCacheControlHeaderStrategy must use its default value"
                .into(),
        ));
    }
    if settings
        .get("throttlingBurstLimit")
        .is_some_and(|value| value.as_i64() != Some(-1))
        || settings
            .get("throttlingRateLimit")
            .is_some_and(|value| value.as_f64() != Some(-1.0))
    {
        return Err(ApiGwError::BadRequest(
            "methodSettings throttling must use default values".into(),
        ));
    }
    match settings.get("loggingLevel") {
        None => Ok(ExecutionLevel::Off),
        Some(Value::String(level)) if level == "OFF" => Ok(ExecutionLevel::Off),
        Some(Value::String(level)) if level == "ERROR" => Ok(ExecutionLevel::Error),
        Some(Value::String(level)) if level == "INFO" => Ok(ExecutionLevel::Info),
        _ => Err(ApiGwError::BadRequest(
            "methodSettings.loggingLevel must be OFF, ERROR, or INFO".into(),
        )),
    }
}

pub fn rest_stage_logging(
    stage: &Value,
    account: &str,
    region: &str,
    api_id: &str,
    stage_name: &str,
) -> Result<StageLogging, ApiGwError> {
    let execution = execution_level(stage)?;
    Ok(StageLogging {
        access: access_settings(stage, account, region)?,
        execution,
        execution_group: (execution != ExecutionLevel::Off)
            .then(|| format!("API-Gateway-Execution-Logs_{api_id}/{stage_name}")),
    })
}

pub fn http_stage_logging(
    stage: &Value,
    account: &str,
    region: &str,
    protocol: &str,
) -> Result<StageLogging, ApiGwError> {
    let access = access_settings(stage, account, region)?;
    if protocol != "HTTP" && access.is_some() {
        return Err(ApiGwError::BadRequest(
            "Access logging is supported only for HTTP APIs".into(),
        ));
    }
    Ok(StageLogging {
        access,
        execution: ExecutionLevel::Off,
        execution_group: None,
    })
}

fn producer_context(request_id: &str) -> ProducerContext {
    ProducerContext {
        source_service: "apigateway".into(),
        identity: CallerIdentity::ServicePrincipal {
            service: "apigateway".into(),
        },
        correlation: CorrelationContext {
            flow_id: request_id.to_string(),
            span_id: Uuid::new_v4().to_string(),
        },
        loop_depth: 0,
    }
}

fn concrete_sink(registry: &Weak<ServiceRegistry>) -> Result<Arc<dyn InternalLogSink>, SinkError> {
    registry
        .upgrade()
        .and_then(|registry| registry.log_sink(&ServiceName::new("logs")))
        .ok_or(SinkError::Unavailable)
}

pub async fn preflight(
    registry: &Weak<ServiceRegistry>,
    account: &str,
    region: &str,
    request_id: &str,
    settings: &StageLogging,
) -> Result<(), ApiGwError> {
    if !settings.enabled() {
        return Ok(());
    }
    let sink = concrete_sink(registry).map_err(|error| {
        ApiGwError::BadRequest(format!("CloudWatch Logs preflight failed: {error}"))
    })?;
    let scope = LogScope::new(account, region);
    for group_name in settings
        .access
        .iter()
        .map(|settings| settings.group_name.as_str())
        .chain(settings.execution_group.iter().map(String::as_str))
    {
        sink.resolve_group(
            scope.clone(),
            ProducerGroupSpec {
                name: group_name.to_string(),
            },
            producer_context(request_id),
        )
        .await
        .map_err(|error| {
            ApiGwError::BadRequest(format!("CloudWatch Logs preflight failed: {error}"))
        })?;
    }
    Ok(())
}

fn render_access(settings: &AccessLogSettings, values: &RequestLogValues<'_>) -> String {
    let mut output = String::new();
    for part in &settings.format {
        match part {
            FormatPart::Literal(value) => output.push_str(value),
            FormatPart::Field { name, json_escaped } => {
                let value = values.value(name);
                if *json_escaped {
                    let encoded = serde_json::to_string(&value).unwrap_or_else(|_| "\"-\"".into());
                    output.push_str(&encoded[1..encoded.len() - 1]);
                } else {
                    output.push_str(&value);
                }
            }
        }
    }
    output
}

fn render_execution(values: &RequestLogValues<'_>) -> String {
    json!({
        "requestId": values.request_id,
        "status": values.status,
        "httpMethod": values.method,
        "path": values.path,
        "resourcePath": values.resource_path.unwrap_or("-"),
        "routeKey": values.route_key.unwrap_or("-"),
        "stage": values.stage,
        "protocol": values.protocol,
        "domainName": value_or_dash(Some(values.domain_name)),
        "sourceIp": value_or_dash(values.source_ip),
        "userAgent": value_or_dash(values.user_agent),
        "responseLength": values.response_length,
        "integrationStatus": values.integration_status.map(Value::from).unwrap_or(Value::String("-".into())),
    })
    .to_string()
}

async fn append_one(
    sink: &Arc<dyn InternalLogSink>,
    scope: &LogScope,
    group_name: &str,
    stream_name: &str,
    request_id: &str,
    message: String,
) -> Result<(), SinkError> {
    let group = sink
        .resolve_group(
            scope.clone(),
            ProducerGroupSpec {
                name: group_name.to_string(),
            },
            producer_context(request_id),
        )
        .await?;
    let stream = sink
        .ensure_stream(
            scope.clone(),
            GroupRef { name: group.name },
            ProducerStreamSpec {
                name: stream_name.to_string(),
            },
            producer_context(request_id),
        )
        .await?;
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0);
    let outcome = sink
        .append(
            scope.clone(),
            stream,
            vec![ProducerLogEvent {
                timestamp_ms,
                message,
            }],
            producer_context(request_id),
        )
        .await?;
    if outcome.stored_events != 1 {
        return Err(SinkError::Rejected("partial producer commit".into()));
    }
    Ok(())
}

pub async fn emit(
    registry: &Weak<ServiceRegistry>,
    account: &str,
    region: &str,
    settings: &StageLogging,
    values: &RequestLogValues<'_>,
) -> Result<(), SinkError> {
    if !settings.enabled() {
        return Ok(());
    }
    let sink = concrete_sink(registry)?;
    let scope = LogScope::new(account, region);
    let stream_name = format!("{}/{}", values.stage, OffsetDateTime::now_utc().date());
    if let Some(access) = &settings.access {
        append_one(
            &sink,
            &scope,
            &access.group_name,
            &stream_name,
            values.request_id,
            render_access(access, values),
        )
        .await?;
    }
    let emit_execution = match settings.execution {
        ExecutionLevel::Off => false,
        ExecutionLevel::Error => values.status >= 400,
        ExecutionLevel::Info => true,
    };
    if emit_execution {
        append_one(
            &sink,
            &scope,
            settings
                .execution_group
                .as_deref()
                .ok_or_else(|| SinkError::InvalidRequest("execution log group".into()))?,
            &stream_name,
            values.request_id,
            render_execution(values),
        )
        .await?;
    }
    Ok(())
}

pub fn request_source_ip(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub fn request_user_agent(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
}
