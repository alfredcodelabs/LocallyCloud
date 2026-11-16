//! Logging choices are resolved by the composition root, never from hidden environment reads.
use std::fmt;
use std::io::{self, IsTerminal};

use serde::Deserialize;
use tracing::{field::Visit, Event, Subscriber};
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::{time::FormatTime, FmtContext};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{registry::LookupSpan, EnvFilter};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Auto,
    Pretty,
    Json,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogColor {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub filter: String,
    pub format: LogFormat,
    pub color: LogColor,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            filter: "info".into(),
            format: LogFormat::Auto,
            color: LogColor::Auto,
        }
    }
}

impl LoggingConfig {
    fn env_filter(&self) -> Result<EnvFilter, String> {
        if self.filter.is_empty() || self.filter.len() > 1024 {
            return Err("logging.filter must contain 1 to 1024 bytes".into());
        }
        EnvFilter::builder()
            .with_regex(false)
            .parse(&self.filter)
            .map_err(|_| "logging.filter contains an invalid tracing directive".into())
    }

    pub fn validate(&self) -> Result<(), String> {
        self.env_filter().map(|_| ())
    }

    fn style(&self, terminal: bool) -> (LogFormat, bool) {
        let format = match (self.format, terminal) {
            (LogFormat::Auto, true) => LogFormat::Pretty,
            (LogFormat::Auto, false) => LogFormat::Json,
            (format, _) => format,
        };
        let color = format == LogFormat::Pretty
            && match self.color {
                LogColor::Auto => terminal,
                LogColor::Always => true,
                LogColor::Never => false,
            };
        (format, color)
    }
}

#[derive(Default)]
struct Context {
    service: Option<String>,
}

impl Visit for Context {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "service" {
            self.service = Some(
                value
                    .chars()
                    .take(64)
                    .flat_map(char::escape_debug)
                    .collect(),
            );
        }
    }

    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn fmt::Debug) {}
}

struct ConsoleFormat;

impl<S, N> FormatEvent<S, N> for ConsoleFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        tracing_subscriber::fmt::time::SystemTime.format_time(&mut writer)?;
        let mut context = Context::default();
        event.record(&mut context);
        let context = match context.service.as_deref() {
            Some("apigateway") => "ApiGateway",
            Some("iam") => "IAM",
            Some("sts") => "STS",
            Some("lambda") => "Lambda",
            Some("ec2") => "EC2",
            Some("cloudformation") => "CloudFormation",
            Some("s3") => "S3",
            Some("sqs") => "SQS",
            Some("dynamodb") => "DynamoDB",
            Some("events" | "eventbridge") => "EventBridge",
            Some("states" | "stepfunctions") => "StepFunctions",
            Some(service) => service,
            None => event.metadata().target(),
        };
        let level = *event.metadata().level();
        if writer.has_ansi_escapes() {
            let color = match level {
                tracing::Level::ERROR => 31,
                tracing::Level::WARN => 33,
                tracing::Level::INFO => 32,
                tracing::Level::DEBUG => 36,
                tracing::Level::TRACE => 90,
            };
            write!(writer, " \x1b[{color}m{level:>5}\x1b[0m [{context}] ")?;
        } else {
            write!(writer, " {level:>5} [{context}] ")?;
        }
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// Install one subscriber after startup validation. JSON is always free of ANSI escapes.
pub fn init_tracing(config: &LoggingConfig) -> Result<(), String> {
    let filter = config.env_filter()?;
    let (format, color) = config.style(io::stderr().is_terminal());
    let result = match format {
        LogFormat::Json => tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_ansi(false)
                    .with_writer(io::stderr),
            )
            .try_init(),
        LogFormat::Auto | LogFormat::Pretty => tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .event_format(ConsoleFormat)
                    .with_ansi(color)
                    .with_writer(io::stderr),
            )
            .try_init(),
    };
    result.map_err(|_| "logging subscriber initialization failed".into())
}

#[cfg(test)]
mod tests;
