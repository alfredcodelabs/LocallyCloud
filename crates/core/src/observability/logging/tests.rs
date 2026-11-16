use super::*;
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn terminal_style_and_color_choices_are_explicit() {
    let mut config = LoggingConfig::default();
    assert_eq!(config.style(true), (LogFormat::Pretty, true));
    assert_eq!(config.style(false), (LogFormat::Json, false));
    config.format = LogFormat::Pretty;
    assert_eq!(config.style(false), (LogFormat::Pretty, false));
    config.color = LogColor::Always;
    assert_eq!(config.style(false), (LogFormat::Pretty, true));
    config.color = LogColor::Never;
    assert_eq!(config.style(true), (LogFormat::Pretty, false));
    config.format = LogFormat::Json;
    config.color = LogColor::Always;
    assert_eq!(config.style(true), (LogFormat::Json, false));
}

#[test]
fn invalid_filters_and_documents_fail_without_echoing_values() {
    for filter in [
        "".to_string(),
        "owned_target=not_a_level".into(),
        "x".repeat(1025),
    ] {
        let config = LoggingConfig {
            filter: filter.clone(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
        if !filter.is_empty() {
            assert!(!config.validate().unwrap_err().contains(&filter));
        }
    }
    for document in [
        r#"{"filter":null}"#,
        r#"{"format":"xml"}"#,
        r#"{"color":null}"#,
        r#"{"unknown":true}"#,
    ] {
        assert!(serde_json::from_str::<LoggingConfig>(document).is_err());
    }
}

#[test]
fn json_diagnostics_keep_fields_and_expected_denials_stay_below_info() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::new("info"))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_ansi(false)
                .with_writer(capture.clone()),
        );
    tracing::subscriber::with_default(subscriber, || {
        crate::observability::log_service_error(
            "lambda",
            Some("GetFunction"),
            "owned-request",
            "ServiceException",
            500,
        );
        crate::observability::log_service_error(
            "lambda",
            Some("GetFunction"),
            "expected-denial",
            "AccessDeniedException",
            403,
        );
        tracing::warn!(
            service = "s3",
            cause_code = "outbox_acknowledgement_failed",
            outbox_id = 7,
            request_id = "owned-request"
        );
    });
    let bytes = capture.0.lock().unwrap();
    let lines: Vec<_> = bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(lines.len(), 2);
    let event: serde_json::Value = serde_json::from_slice(lines[0]).unwrap();
    assert_eq!(event["level"], "ERROR");
    assert_eq!(event["fields"]["service"], "lambda");
    assert_eq!(event["fields"]["operation"], "GetFunction");
    assert_eq!(event["fields"]["request_id"], "owned-request");
    assert_eq!(event["fields"]["cause_code"], "ServiceException");
    assert_eq!(event["fields"]["status"], 500);
    let background: serde_json::Value = serde_json::from_slice(lines[1]).unwrap();
    assert_eq!(background["level"], "WARN");
    assert_eq!(background["target"], module_path!());
    assert_eq!(background["fields"]["service"], "s3");
    assert_eq!(
        background["fields"]["cause_code"],
        "outbox_acknowledgement_failed"
    );
    assert_eq!(background["fields"]["outbox_id"], 7);
    assert_eq!(background["fields"]["request_id"], "owned-request");
    assert!(background["fields"].get("message").is_none());
    assert!(!bytes.contains(&0x1b));
}

#[test]
fn console_diagnostics_render_context_and_preserve_correlation() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .event_format(ConsoleFormat)
            .with_ansi(false)
            .with_writer(capture.clone()),
    );
    tracing::subscriber::with_default(subscriber, || {
        crate::observability::log_service_error(
            "apigateway",
            None,
            "owned-request",
            "destination_denied",
            500,
        );
        tracing::warn!(
            service = "s3",
            cause_code = "outbox_acknowledgement_failed",
            outbox_id = 7,
            request_id = "owned-background"
        );
    });
    let bytes = capture.0.lock().unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("ERROR [ApiGateway] service request failed"),
        "{text}"
    );
    assert!(text.contains("owned-request"));
    assert!(text.contains("destination_denied"));
    for field in [
        "WARN [S3]",
        "outbox_acknowledgement_failed",
        "outbox_id=7",
        "owned-background",
    ] {
        assert!(text.contains(field), "{text}");
    }
    assert_eq!(text.lines().count(), 2);
    assert!(!bytes.contains(&0x1b));
}
