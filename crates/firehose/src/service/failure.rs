//! Explicit failure legs: S3 backup acknowledgement is distinct from an Iceberg commit.
use super::*;
use locallycloud_core::integration::correlation::CorrelationContext;
use locallycloud_core::integration::identity::CallerIdentity;
use locallycloud_core::integration::logs::{
    LogScope, ProducerContext, ProducerLogEvent, StreamRef,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum DeliveryPhase {
    #[default]
    Primary,
    Backup,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(super) enum FailureCode {
    #[default]
    InternalError,
    #[serde(rename = "Iceberg.NoSuchTable")]
    NoSuchTable,
    #[serde(rename = "Glue.AccessDenied")]
    GlueAccessDenied,
    #[serde(rename = "S3.AccessDenied")]
    S3AccessDenied,
}

impl FailureCode {
    pub fn code(self) -> &'static str {
        match self {
            Self::InternalError => "InternalError",
            Self::NoSuchTable => "Iceberg.NoSuchTable",
            Self::GlueAccessDenied => "Glue.AccessDenied",
            Self::S3AccessDenied => "S3.AccessDenied",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::InternalError => {
                "Local Iceberg delivery failed after the configured retry duration"
            }
            Self::NoSuchTable => "The configured Iceberg destination table does not exist",
            Self::GlueAccessDenied => "Access to the configured Glue catalog was denied",
            Self::S3AccessDenied => "Access to the configured S3 destination was denied",
        }
    }
}

impl From<iceberg::Error> for FailureCode {
    fn from(error: iceberg::Error) -> Self {
        match error {
            iceberg::Error::NoSuchTable => Self::NoSuchTable,
            iceberg::Error::GlueAccessDenied => Self::GlueAccessDenied,
            iceberg::Error::S3AccessDenied => Self::S3AccessDenied,
            iceberg::Error::Unsupported | iceberg::Error::Transient => Self::InternalError,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(super) struct LoggingOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_group_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_stream_name: Option<String>,
}

impl LoggingOptions {
    pub fn validate(&self) -> Result<(), FirehoseError> {
        if self.enabled
            && (self.log_group_name.as_deref().is_none_or(str::is_empty)
                || self.log_stream_name.as_deref().is_none_or(str::is_empty))
        {
            return Err(FirehoseError::InvalidArgument(
                "Enabled CloudWatchLoggingOptions requires LogGroupName and LogStreamName".into(),
            ));
        }
        if self.log_group_name.as_ref().is_some_and(|name| {
            name.len() > 512
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_/#".contains(&b))
        }) || self
            .log_stream_name
            .as_ref()
            .is_some_and(|name| name.len() > 512 || name.contains([':', '*']))
        {
            return Err(FirehoseError::InvalidArgument(
                "CloudWatchLoggingOptions contains an invalid log name".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ErrorBackup {
    pub prefix: String,
    pub global_prefix: Option<String>,
    pub table_prefix: Option<String>,
    pub logging: Option<LoggingOptions>,
}

pub(super) fn backup_configuration(
    mode: Option<&str>,
    table_prefix: Option<&str>,
    config: &IcebergS3Configuration,
) -> Result<Option<ErrorBackup>, FirehoseError> {
    if config
        .compression_format
        .as_deref()
        .is_some_and(|v| v != "UNCOMPRESSED")
    {
        return Err(unsupported("Iceberg S3 backup only supports UNCOMPRESSED"));
    }
    if let Some(options) = &config.cloud_watch_logging_options {
        options.validate()?;
    }
    match mode {
        None if table_prefix.is_none() && config.error_output_prefix.is_none() && config.cloud_watch_logging_options.as_ref().is_none_or(|o| !o.enabled) => Ok(None),
        Some("FailedDataOnly") => {
            if config.error_output_prefix.as_ref().is_some_and(|p| p.len()>512) || table_prefix.is_some_and(|p|p.len()>1024) {
                return Err(FirehoseError::InvalidArgument("S3 error output prefix exceeds its field limit".into()));
            }
            let prefix=table_prefix.or(config.error_output_prefix.as_deref()).ok_or_else(|| unsupported("FailedDataOnly requires an explicit literal ErrorOutputPrefix or S3ErrorOutputPrefix"))?;
            if prefix.is_empty() || prefix.starts_with('/') || prefix.contains(['\0','\\','%']) || prefix.contains("!{") || prefix.split('/').any(|p|p=="..") {
                return Err(unsupported("S3 error output prefix must be a nonempty safe literal; automatic prefix expressions are not implemented"));
            }
            Ok(Some(ErrorBackup{prefix:prefix.into(),global_prefix:config.error_output_prefix.clone(),table_prefix:table_prefix.map(str::to_owned),logging:config.cloud_watch_logging_options.clone()}))
        },
        _ => Err(unsupported("Iceberg error backup requires explicit S3BackupMode=FailedDataOnly; AllData is not supported")),
    }
}

pub(super) fn backoff(attempt: u8) -> Duration {
    Duration::from_secs(1_u64 << attempt.saturating_sub(1).min(5)).min(MAX_RETRY_DELAY)
}

impl DeliveryStream {
    pub(super) fn exhaust_primary(&mut self) {
        self.phase = if self.destination.error_backup.is_some() {
            DeliveryPhase::Backup
        } else {
            DeliveryPhase::Primary
        };
        self.terminal_failure = self.destination.error_backup.is_none();
        self.backup_attempts = 0;
        self.retry_at = None;
    }
}

// Only an explicit evaluator denial identifies a service access failure.
pub(super) fn role_failure(error: AuthorizationError, denied: FailureCode) -> FailureCode {
    match error {
        AuthorizationError::Denied => denied,
        AuthorizationError::Unavailable
        | AuthorizationError::InvalidRequest
        | AuthorizationError::Internal => FailureCode::InternalError,
    }
}

impl Inner {
    pub(super) fn authorize_backup(
        &self,
        batch: &Batch,
        caller: &RequestIdentity,
    ) -> Result<(), FailureCode> {
        let evaluator = self
            .registry
            .upgrade()
            .and_then(|r| r.authorization_evaluator(&ServiceName::new("iam")))
            .ok_or(FailureCode::InternalError)?;
        evaluator
            .authorize_service_role_execution(ServiceRoleAuthorizationRequest {
                source_arn: None,
                caller: caller.clone(),
                role_arn: batch.destination.s3_role_arn.clone(),
                service_principal: "firehose.amazonaws.com".into(),
                action: "s3:PutObject".into(),
                resource: format!("{}/*", batch.destination.bucket_arn),
            })
            .map_err(|error| role_failure(error, FailureCode::S3AccessDenied))
    }

    pub(super) async fn deliver_error_backup(&self, batch: &Batch) -> Result<(), FailureCode> {
        let Some(backup) = &batch.destination.error_backup else {
            return Err(FailureCode::InternalError);
        };
        let mut body = Vec::new();
        for record in &batch.records {
            // Bounded local error envelope; full AWS Iceberg error-file fixtures remain a gate.
            let envelope = json!({"rawData":base64::engine::general_purpose::STANDARD.encode(record),
                "errorCode":batch.primary_failure.code(),"errorMessage":batch.primary_failure.message()});
            if serde_json::to_writer(&mut body, &envelope).is_err() {
                return Err(FailureCode::InternalError);
            }
            body.push(b'\n');
        }
        let key = object_key(&backup.prefix, &batch.key.name, batch.token);
        self.put_s3(batch, &key, Bytes::from(body)).await
    }

    pub(super) async fn log_delivery_error(&self, batch: &Batch, failure: FailureCode) {
        // FailedDataOnly routes both failure legs to DestinationDelivery.
        let options = batch.destination.logging.as_ref();
        let message = match batch.phase {
            DeliveryPhase::Primary => "Local Iceberg delivery failed; the batch remains owned until delivery or backup acknowledgement",
            DeliveryPhase::Backup => "Local S3 error backup failed; the batch remains retained",
        };
        let Some(options) = options.filter(|o| o.enabled) else {
            return;
        };
        let (Some(group), Some(stream)) = (&options.log_group_name, &options.log_stream_name)
        else {
            return;
        };
        let Some(sink) = self
            .registry
            .upgrade()
            .and_then(|r| r.log_sink(&ServiceName::new("logs")))
        else {
            tracing::warn!(stream=%batch.key.name,"Firehose error logging sink is unavailable");
            return;
        };
        let Ok(now) = StartedAt::now() else {
            return;
        };
        let Ok(timestamp_ms) = i64::try_from(now.unix_ms) else {
            return;
        };
        let message=json!({"deliveryStreamARN":batch.key.scope.stream_arn(&batch.key.name),
            "deliveryStreamVersionId":1,"destination":batch.destination.bucket_arn,"errorCode":failure.code(),"message":message}).to_string();
        let context = ProducerContext {
            source_service: "firehose".into(),
            identity: CallerIdentity::AssumedRole {
                role_arn: batch.destination.role_arn.clone(),
                session_name: batch.token.to_string(),
            },
            correlation: CorrelationContext::root(),
            loop_depth: 0,
        };
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            sink.append(
                LogScope::new(&batch.key.scope.account_id, &batch.key.scope.region),
                StreamRef {
                    group_name: group.clone(),
                    stream_name: stream.clone(),
                },
                vec![ProducerLogEvent {
                    timestamp_ms,
                    message,
                }],
                context,
            ),
        )
        .await;
        if !matches!(result, Ok(Ok(_))) {
            tracing::warn!(stream=%batch.key.name,"Firehose error log was not acknowledged; delivery state is unaffected");
        }
    }
}
