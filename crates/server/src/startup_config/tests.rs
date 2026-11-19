use super::*;
use locallycloud_iam_sts::enforcement::EnforcementMode;
use std::os::unix::ffi::OsStringExt;

fn resolve(json: &str, pairs: &[(&str, &str)]) -> Result<StartupConfig, StartupError> {
    let document = serde_json::from_str(json).unwrap();
    StartupConfig::resolve(document, &|key| {
        pairs
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| OsString::from(value))
            .or_else(|| match key {
                "HOME" => Some(OsString::from("/owned-home")),
                "LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID" => {
                    Some(OsString::from("AKIA0000000000000000"))
                }
                "LOCALLYCLOUD_BOOTSTRAP_SECRET_ACCESS_KEY" => {
                    Some(OsString::from("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS"))
                }
                _ => None,
            })
    })
}

#[test]
fn partial_file_inherits_defaults_and_environment_aliases_win() {
    let config = resolve(r#"{"common":{"region":"eu-west-1","port":9876,"allow_http":false,"ui_enabled":false},"iam":{"enforcement":"strict"},"apigateway":{"authorizer_cache_capacity":3},"state":{"path":"/file/state.sqlite3"}}"#,
        &[("LOCALSTACK_PORT","0"),("AWS_REGION","us-west-2"),("LOCALSTACK_IAM_ENFORCEMENT","permissive"),("LOCALLYCLOUD_STATE_DB","/env/state.sqlite3"),("LOCALLYCLOUD_APIGATEWAY_AUTHORIZER_CACHE_CAPACITY","2")]).unwrap();
    assert_eq!(config.common.listen_addr.port(), 0);
    assert_eq!(config.common.default_region, "us-west-2");
    assert!(!config.common.allow_http);
    assert!(!config.common.ui_enabled);
    assert_eq!(config.iam.enforcement, EnforcementMode::Permissive);
    assert_eq!(config.apigateway.authorizer_cache_capacity, 2);
    assert_eq!(config.apigateway.websocket_outbound_channel_capacity, 32);
    assert_eq!(config.state.path, PathBuf::from("/env/state.sqlite3"));
    let default = resolve("{}", &[]).unwrap();
    assert_eq!(
        default.state.path,
        PathBuf::from("/owned-home/.local/share/locallycloud/state.sqlite3")
    );
    assert_eq!(default.common.listen_addr.port(), 4566);
    assert_eq!(default.iam.enforcement, EnforcementMode::Permissive);
}

#[test]
fn invalid_explicit_values_never_fall_back_to_file_or_defaults() {
    for pairs in [
        vec![("LOCALLYCLOUD_IAM_ENFORCEMENT", "strcit")],
        vec![("LOCALLYCLOUD_PORT", "")],
        vec![("LOCALSTACK_PORT", "invalid")],
        vec![("LOCALLYCLOUD_STATE_DB", "relative.sqlite3")],
        vec![("LOCALLYCLOUD_STATE_DB", "")],
        vec![("LOCALLYCLOUD_APIGATEWAY_AUTHORIZER_CACHE_CAPACITY", "0")],
        vec![("LOCALLYCLOUD_APIGATEWAY_AUTHORIZER_CACHE_CAPACITY", "-1")],
    ] {
        assert!(
            resolve(
                r#"{"common":{"port":4568},"iam":{"enforcement":"strict"}}"#,
                &pairs
            )
            .is_err(),
            "{pairs:?}"
        );
    }
    assert!(StartupConfig::resolve(FileConfig::default(), &|key| {
        (key == "LOCALLYCLOUD_ALLOW_HTTP").then(|| OsString::from_vec(vec![0xff]))
    })
    .is_err());
    for json in [
        r#"{"state":{"path":"relative"}}"#,
        r#"{"common":{"account_id":"wrong"}}"#,
        r#"{"common":{"upstream_timeout_secs":0}}"#,
    ] {
        assert!(resolve(json, &[]).is_err());
    }
}

#[test]
fn null_unknown_and_wrong_types_are_rejected() {
    for json in [
        "null",
        r#"{"common":null}"#,
        r#"{"common":{"port":null}}"#,
        r#"{"common":{"region":null}}"#,
        r#"{"common":{"port":"4566"}}"#,
        r#"{"iam":{"enforcement":null}}"#,
        r#"{"state":{"path":null}}"#,
        r#"{"apigateway":{"authorizer_cache_capacity":null}}"#,
        r#"{"common":{"prot":4566}}"#,
        r#"{"services":{}}"#,
    ] {
        assert!(serde_json::from_str::<FileConfig>(json).is_err(), "{json}");
    }
    let config = resolve(r#"{"common":{"port":0,"allow_http":false}}"#, &[]).unwrap();
    assert_eq!(config.common.listen_addr.port(), 0);
    assert!(!config.common.allow_http);
}

fn test_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.kiro/localcloud-tmp/startup-config")
        .join(uuid::Uuid::new_v4().to_string())
}

#[tokio::test]
async fn optional_discovery_and_required_file_have_distinct_missing_behavior() {
    let root = test_root();
    let lookup = |name: &str| match name {
        "HOME" | "XDG_CONFIG_HOME" => Some(root.clone().into_os_string()),
        _ => None,
    };
    let config = StartupConfig::load_with(&lookup).await.unwrap();
    assert_eq!(config.common.listen_addr.port(), 4566);
    let explicit = |name: &str| match name {
        "LOCALLYCLOUD_CONFIG_FILE" => Some(root.join("absent.json").into_os_string()),
        _ => lookup(name),
    };
    assert!(StartupConfig::load_with(&explicit).await.is_err());
    assert!(!root.exists());
}

#[tokio::test]
async fn file_read_is_bounded_errors_are_redacted_and_resolved_state_opens() {
    let root = test_root();
    tokio::fs::create_dir_all(&root).await.unwrap();
    let path = root.join("config.json");
    tokio::fs::write(&path, vec![b' '; (MAX_CONFIG_BYTES + 1) as usize])
        .await
        .unwrap();
    assert!(read_file(path.clone(), true).await.is_err());
    tokio::fs::write(
        &path,
        br#"{"iam":{"enforcement":"synthetic-secret-must-not-appear"}}"#,
    )
    .await
    .unwrap();
    let error = read_file(path.clone(), true)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(!error.contains("synthetic-secret"));
    tokio::fs::write(&path,serde_json::json!({"common":{"port":0},"state":{"path":root.join("private/state.sqlite3")}}).to_string()).await.unwrap();
    let config = StartupConfig::load_with(&|name| {
        (name == "LOCALLYCLOUD_CONFIG_FILE").then(|| path.clone().into_os_string())
    })
    .await
    .unwrap();
    let state = config.state.open().await.unwrap();
    assert_eq!(state.path(), root.join("private/state.sqlite3"));
    let guard = state.lock_runtime().unwrap();
    assert!(state.lock_runtime().is_err());
    drop(guard);
    drop(state);
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn named_pipe_is_rejected_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let root = test_root();
    tokio::fs::create_dir_all(&root).await.unwrap();
    let path = root.join("config.json");
    let owned_path = path.clone();
    tokio::task::spawn_blocking(move || {
        let path = std::ffi::CString::new(owned_path.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated owned fixture path is valid for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    })
    .await
    .unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), read_file(path, true))
        .await
        .unwrap();
    assert!(matches!(result, Err(StartupError::Invalid(_))));
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[test]
fn retired_settings_remain_ignored_without_masking_invalid_active_settings() {
    let config = resolve("{}", &[("LOCALLYCLOUD_RUNTIME", "")]).unwrap();
    assert!(config
        .common
        .ignored_settings
        .contains(&"LOCALLYCLOUD_RUNTIME"));
    assert!(resolve(
        "{}",
        &[("LOCALLYCLOUD_HOST", ""), ("LOCALLYCLOUD_RUNTIME", "")]
    )
    .is_err());
    let config = StartupConfig::resolve(FileConfig::default(), &|key| match key {
        "LOCALLYCLOUD_RUNTIME" => Some(OsString::from_vec(vec![0xff])),
        "HOME" => Some(OsString::from("/owned-home")),
        _ => None,
    })
    .unwrap();
    assert!(config
        .common
        .ignored_settings
        .contains(&"LOCALLYCLOUD_RUNTIME"));
}

#[test]
fn http_origin_environment_override_can_clear_file_entries_and_rejects_invalid_values() {
    let json = r#"{"apigateway":{"http_local_origins":["http://127.0.0.1:8080"]}}"#;
    assert_eq!(
        resolve(json, &[])
            .unwrap()
            .apigateway
            .http_local_origins
            .len(),
        1
    );
    assert!(resolve(
        json,
        &[("LOCALLYCLOUD_HTTP_INTEGRATION_LOCAL_ORIGINS", "[]")]
    )
    .unwrap()
    .apigateway
    .http_local_origins
    .is_empty());
    for value in [
        "",
        "null",
        "localhost",
        "[1]",
        "[\"http://127.0.0.1:8080/path\"]",
        "[\"http://169.254.169.254\"]",
    ] {
        assert!(resolve(
            json,
            &[("LOCALLYCLOUD_HTTP_INTEGRATION_LOCAL_ORIGINS", value)]
        )
        .is_err());
    }
}

#[test]
fn http_pool_settings_resolve_file_environment_and_defaults() {
    let json = r#"{"apigateway":{"http_client_cache_capacity":2,"http_max_idle_per_host":3,"http_idle_timeout_secs":4}}"#;
    let file = resolve(json, &[]).unwrap().apigateway;
    assert_eq!(
        (
            file.http_client_cache_capacity,
            file.http_max_idle_per_host,
            file.http_idle_timeout_secs
        ),
        (2, 3, 4)
    );
    let environment = [
        ("LOCALLYCLOUD_APIGATEWAY_HTTP_CLIENT_CACHE_CAPACITY", "5"),
        ("LOCALLYCLOUD_APIGATEWAY_HTTP_MAX_IDLE_PER_HOST", "6"),
        ("LOCALLYCLOUD_APIGATEWAY_HTTP_IDLE_TIMEOUT_SECS", "7"),
    ];
    let overrides = resolve(json, &environment).unwrap().apigateway;
    assert_eq!(
        (
            overrides.http_client_cache_capacity,
            overrides.http_max_idle_per_host,
            overrides.http_idle_timeout_secs
        ),
        (5, 6, 7)
    );
    let defaults = resolve("{}", &[]).unwrap().apigateway;
    assert_eq!(
        (
            defaults.http_client_cache_capacity,
            defaults.http_max_idle_per_host,
            defaults.http_idle_timeout_secs
        ),
        (16, 1, 30)
    );
    for (name, _) in environment {
        for value in ["", "0", "301", "null", "-1", "1.5"] {
            assert!(resolve(json, &[(name, value)]).is_err(), "{name}={value}");
        }
    }
    for name in [
        "http_client_cache_capacity",
        "http_max_idle_per_host",
        "http_idle_timeout_secs",
    ] {
        assert!(serde_json::from_str::<FileConfig>(&format!(
            r#"{{"apigateway":{{"{name}":null}}}}"#
        ))
        .is_err());
    }
}

#[test]
fn logging_is_resolved_before_initialization_with_explicit_precedence() {
    let file = r#"{"logging":{"filter":"warn","format":"json","color":"always"}}"#;
    let configured = resolve(file, &[]).unwrap().logging;
    assert_eq!(configured.filter, "warn");
    assert_eq!(configured.format, LogFormat::Json);
    let overridden = resolve(
        file,
        &[
            ("RUST_LOG", "error"),
            ("LOCALLYCLOUD_LOG_FORMAT", "pretty"),
            ("LOCALLYCLOUD_LOG_COLOR", "auto"),
            ("NO_COLOR", "1"),
        ],
    )
    .unwrap()
    .logging;
    assert_eq!(overridden.filter, "error");
    assert_eq!(overridden.format, LogFormat::Pretty);
    assert_eq!(overridden.color, LogColor::Never);
    for (key, value) in [
        ("RUST_LOG", "owned=invalid_level"),
        ("RUST_LOG", ""),
        ("LOCALLYCLOUD_LOG_FORMAT", "JSON"),
        ("LOCALLYCLOUD_LOG_COLOR", "maybe"),
    ] {
        assert!(resolve(file, &[(key, value)]).is_err(), "{key}");
    }
    for document in [
        r#"{"logging":null}"#,
        r#"{"logging":{"filter":null}}"#,
        r#"{"logging":{"format":"xml"}}"#,
        r#"{"logging":{"extra":1}}"#,
    ] {
        assert!(serde_json::from_str::<FileConfig>(document).is_err());
    }
}

#[test]
fn batch_one_runtime_settings_resolve_through_startup() {
    let file = r#"{"lambda":{"max_warm_total":2,"memory_budget_mb":512,"work_dir":"local-lambda"},"ec2":{"image_rootfs":"local-image","startup_timeout_secs":3,"connect_timeout_secs":4},"cloudformation":{"operation_capacity":2}}"#;
    let configured = resolve(file, &[]).unwrap();
    assert_eq!(configured.lambda.max_warm_total, 2);
    assert_eq!(configured.lambda.memory_budget_mb, 512);
    assert!(configured.lambda.work_dir.ends_with("local-lambda"));
    assert!(configured
        .ec2
        .image_rootfs
        .unwrap()
        .ends_with("local-image"));
    assert_eq!(configured.ec2.startup_timeout_secs, 3);
    assert_eq!(configured.ec2.connect_timeout_secs, 4);
    assert_eq!(configured.cloudformation.operation_capacity, 2);
    let overridden = resolve(
        file,
        &[
            ("LOCALLYCLOUD_LAMBDA_MAX_WARM_TOTAL", "0"),
            ("LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB", "1024"),
            ("LOCALLYCLOUD_WORK_DIR", "/env/lambda"),
            ("LOCALLYCLOUD_EC2_IMAGE_ROOTFS", "/env/image"),
            ("LOCALLYCLOUD_EC2_STARTUP_TIMEOUT_SECS", "7"),
            ("LOCALLYCLOUD_EC2_CONNECT_TIMEOUT_SECS", "8"),
            ("LOCALLYCLOUD_CLOUDFORMATION_OPERATION_CAPACITY", "3"),
        ],
    )
    .unwrap();
    assert_eq!(overridden.lambda.max_warm_total, 0);
    assert_eq!(overridden.lambda.memory_budget_mb, 1024);
    assert_eq!(overridden.lambda.work_dir, PathBuf::from("/env/lambda"));
    assert_eq!(
        overridden.ec2.image_rootfs,
        Some(PathBuf::from("/env/image"))
    );
    assert_eq!(
        (
            overridden.ec2.startup_timeout_secs,
            overridden.ec2.connect_timeout_secs
        ),
        (7, 8)
    );
    assert_eq!(overridden.cloudformation.operation_capacity, 3);
    for (key, value) in [
        ("LOCALLYCLOUD_EC2_IMAGE_ROOTFS", ""),
        ("LOCALLYCLOUD_EC2_STARTUP_TIMEOUT_SECS", "0"),
        ("LOCALLYCLOUD_EC2_CONNECT_TIMEOUT_SECS", "301"),
        ("LOCALLYCLOUD_CLOUDFORMATION_OPERATION_CAPACITY", "65"),
        ("LOCALLYCLOUD_COMPUTE_MEMORY_BUDGET_MB", "0"),
    ] {
        assert!(resolve(file, &[(key, value)]).is_err(), "{key}");
    }
    for document in [
        r#"{"ec2":{"image_rootfs":null}}"#,
        r#"{"lambda":{"work_dir":null}}"#,
        r#"{"cloudformation":{"operation_capacity":null}}"#,
    ] {
        assert!(serde_json::from_str::<FileConfig>(document).is_err());
    }
}

#[test]
fn strict_startup_requires_explicit_secret_inputs_before_service_registration() {
    let document = serde_json::from_str(r#"{"iam":{"enforcement":"strict"}}"#).unwrap();
    let result = StartupConfig::resolve(document, &|key| {
        (key == "HOME").then(|| "/owned-home".into())
    });
    assert!(result.is_err());
}

#[test]
fn second_batch_defaults_file_and_environment_are_resolved_by_service() {
    let defaults = resolve("{}", &[]).unwrap();
    assert_eq!(defaults.s3.notification_queue_capacity, 1024);
    assert_eq!(defaults.s3.notification_retry_interval_ms, 1000);
    assert_eq!(
        defaults.sqs.endpoint_strategy,
        locallycloud_sqs::SqsEndpointStrategy::Path
    );
    assert_eq!(
        defaults.dynamodb.engine,
        locallycloud_dynamodb::DynamoDbEngineChoice::Native
    );
    assert!(!defaults.dynamodb.simulate_write_limits);
    assert_eq!(
        defaults.eventbridge.retry_second(),
        std::time::Duration::from_secs(1)
    );
    assert_eq!(defaults.stepfunctions.execution_poll_interval_ms, 10);
    let file = r#"{"s3":{"notification_queue_capacity":2,"notification_retry_interval_ms":2000},"sqs":{"endpoint_strategy":"aws"},"dynamodb":{"engine":"native","simulate_write_limits":true,"kms_timeout_secs":7},"eventbridge":{"retry_time_scale":0.01,"pending_retry_poll_interval_ms":5,"http_connect_timeout_secs":2,"http_request_timeout_secs":3,"http_response_body_limit_bytes":4096},"stepfunctions":{"execution_poll_interval_ms":5,"athena_poll_interval_ms":20,"athena_cancel_timeout_secs":2}}"#;
    let configured = resolve(file, &[]).unwrap();
    assert_eq!(configured.s3.notification_queue_capacity, 2);
    assert_eq!(configured.s3.notification_retry_interval_ms, 2000);
    assert_eq!(
        configured.sqs.endpoint_strategy,
        locallycloud_sqs::SqsEndpointStrategy::Aws
    );
    assert!(configured.dynamodb.simulate_write_limits);
    assert_eq!(configured.dynamodb.kms_timeout_secs, 7);
    assert_eq!(
        configured.eventbridge.retry_second(),
        std::time::Duration::from_millis(10)
    );
    assert_eq!(configured.eventbridge.http_response_body_limit_bytes, 4096);
    assert_eq!(configured.stepfunctions.athena_poll_interval_ms, 20);
    let env = [
        ("LOCALLYCLOUD_S3_NOTIFICATION_QUEUE_CAPACITY", "3"),
        ("LOCALLYCLOUD_SQS_ENDPOINT_STRATEGY", "PATH"),
        ("LOCALLYCLOUD_DYNAMODB_ENGINE", "extenddb"),
        ("LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS", "false"),
        ("LOCALLYCLOUD_DYNAMODB_KMS_TIMEOUT_SECS", "8"),
        ("LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE", "0.02"),
        ("LOCALLYCLOUD_STEPFUNCTIONS_ATHENA_POLL_INTERVAL_MS", "30"),
    ];
    let overridden = resolve(file, &env).unwrap();
    assert_eq!(overridden.s3.notification_queue_capacity, 3);
    assert_eq!(overridden.s3.notification_retry_interval_ms, 2000);
    assert_eq!(
        overridden.sqs.endpoint_strategy,
        locallycloud_sqs::SqsEndpointStrategy::Path
    );
    assert_eq!(
        overridden.dynamodb.engine,
        locallycloud_dynamodb::DynamoDbEngineChoice::ExtendDb
    );
    assert!(!overridden.dynamodb.simulate_write_limits);
    assert_eq!(overridden.dynamodb.kms_timeout_secs, 8);
    assert_eq!(
        overridden.eventbridge.retry_second(),
        std::time::Duration::from_millis(20)
    );
    assert_eq!(overridden.stepfunctions.athena_poll_interval_ms, 30);
}

#[test]
fn second_batch_invalid_inputs_do_not_become_silent_defaults() {
    for (name, value) in [
        ("LOCALLYCLOUD_S3_NOTIFICATION_QUEUE_CAPACITY", "0"),
        ("LOCALLYCLOUD_S3_NOTIFICATION_RETRY_INTERVAL_MS", "1"),
        ("LOCALLYCLOUD_SQS_ENDPOINT_STRATEGY", "domain"),
        ("LOCALLYCLOUD_DYNAMODB_ENGINE", "other"),
        ("LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS", "other"),
        ("LOCALLYCLOUD_DYNAMODB_KMS_TIMEOUT_SECS", "0"),
        ("LOCALLYCLOUD_EVENTS_RETRY_TIME_SCALE", "NaN"),
        (
            "LOCALLYCLOUD_EVENTBRIDGE_HTTP_RESPONSE_BODY_LIMIT_BYTES",
            "0",
        ),
        ("LOCALLYCLOUD_STEPFUNCTIONS_EXECUTION_POLL_INTERVAL_MS", "0"),
    ] {
        assert!(resolve("{}", &[(name, value)]).is_err(), "{name}");
    }
    for document in [
        r#"{"s3":null}"#,
        r#"{"sqs":{"endpoint_strategy":null}}"#,
        r#"{"dynamodb":{"simulate_write_limits":null}}"#,
        r#"{"eventbridge":{"retry_time_scale":null}}"#,
        r#"{"stepfunctions":{"execution_poll_interval_ms":null}}"#,
        r#"{"dynamodb":{"unknown":true}}"#,
    ] {
        assert!(serde_json::from_str::<FileConfig>(document).is_err());
    }
}

#[test]
fn ses_uses_shared_file_environment_precedence_and_separate_credentials() {
    let config = resolve(
        r#"{"ses":{"provider":"resend","max_concurrency":3}}"#,
        &[
            ("LOCALLYCLOUD_SES_PROVIDER", "capture"),
            ("LOCALLYCLOUD_SES_MAX_CONCURRENCY", "4"),
        ],
    )
    .unwrap();
    assert_eq!(
        config.ses.provider,
        locallycloud_ses::config::Provider::Capture
    );
    assert_eq!(config.ses.max_concurrency, 4);
    assert!(resolve(r#"{"ses":{"provider":"resend"}}"#, &[]).is_err());
    assert!(resolve(
        r#"{"ses":{"provider":"capture"}}"#,
        &[("LOCALLYCLOUD_SES_PROVIDER_API_KEY", "")]
    )
    .is_err());
    for input in [
        r#"{"ses":{"api_key":"must-stay-out-of-json"}}"#,
        r#"{"ses":null}"#,
        r#"{"ses":{"request_timeout_secs":null}}"#,
    ] {
        assert!(serde_json::from_str::<FileConfig>(input).is_err());
    }
    let result = resolve(
        r#"{"ses":{"provider":"resend"}}"#,
        &[(
            "LOCALLYCLOUD_SES_PROVIDER_API_KEY",
            "secret\nshould-not-appear",
        )],
    );
    let error = result.err().unwrap().to_string();
    assert!(!error.contains("should-not-appear"));
}

#[test]
fn batch_three_defaults_file_and_environment_are_resolved_independently() {
    let defaults = resolve("{}", &[]).unwrap();
    assert_eq!(defaults.sns.http_timeout_secs, 5);
    assert_eq!(defaults.sns.outbox_retry_max_secs, 30);
    assert_eq!(defaults.kinesis.max_buffered_bytes, 64 * 1024 * 1024);
    assert!(!defaults.kinesis.simulate_write_limits);
    assert_eq!(defaults.firehose.s3_dispatch_timeout_secs, 10);
    assert_eq!(defaults.logs.delivery_retry_interval_ms, 5000);
    assert!(defaults.cognito.mailbox_dir.is_none());
    let json = r#"{"sns":{"http_timeout_secs":7},"kinesis":{"max_buffered_bytes":2048,"simulate_write_limits":true},"firehose":{"s3_dispatch_timeout_secs":8,"source_poll_interval_ms":750},"cognito":{"mailbox_dir":"/file/mailbox"},"logs":{"delivery_retry_interval_ms":1200}}"#;
    let file = resolve(json, &[]).unwrap();
    assert_eq!(file.sns.http_timeout_secs, 7);
    assert_eq!(file.kinesis.max_buffered_bytes, 2048);
    assert_eq!(
        file.cognito.mailbox_dir,
        Some(PathBuf::from("/file/mailbox"))
    );
    let env = resolve(
        json,
        &[
            ("LOCALLYCLOUD_SNS_HTTP_TIMEOUT_SECS", "2"),
            (
                "LOCALLYCLOUD_SNS_HTTP_LOCAL_ORIGINS",
                r#"["http://127.0.0.1:8080"]"#,
            ),
            ("LOCALLYCLOUD_SNS_HTTP_CLIENT_CACHE_CAPACITY", "4"),
            ("LOCALLYCLOUD_KINESIS_SIMULATE_WRITE_LIMITS", "0"),
            ("LOCALLYCLOUD_FIREHOSE_SOURCE_POLL_INTERVAL_MS", "25"),
            ("LOCALLYCLOUD_COGNITO_MAILBOX_DIR", "/env/mailbox"),
            ("LOCALLYCLOUD_LOGS_DELIVERY_RETRY_INTERVAL_MS", "50"),
        ],
    )
    .unwrap();
    assert_eq!(env.sns.http_timeout_secs, 2);
    assert_eq!(env.sns.http_client_cache_capacity, 4);
    assert_eq!(env.sns.http_local_origins, vec!["http://127.0.0.1:8080"]);
    assert_eq!(env.sns.outbox_retry_initial_secs, 1);
    assert_eq!(env.kinesis.max_buffered_bytes, 2048);
    assert!(!env.kinesis.simulate_write_limits);
    assert_eq!(env.firehose.source_poll_interval_ms, 25);
    assert_eq!(env.firehose.s3_dispatch_timeout_secs, 8);
    assert_eq!(env.cognito.mailbox_dir, Some(PathBuf::from("/env/mailbox")));
    assert_eq!(env.logs.delivery_retry_interval_ms, 50);
    assert_eq!(env.logs.retention_reclaim_delay_ms, 100);
}

#[test]
fn batch_three_rejects_invalid_explicit_settings_without_echoing_values() {
    let numeric = [
        "LOCALLYCLOUD_SNS_HTTP_TIMEOUT_SECS",
        "LOCALLYCLOUD_SNS_HTTP_CLIENT_CACHE_CAPACITY",
        "LOCALLYCLOUD_SNS_OUTBOX_RETRY_INITIAL_SECS",
        "LOCALLYCLOUD_SNS_OUTBOX_RETRY_MAX_SECS",
        "LOCALLYCLOUD_KINESIS_MAX_BUFFERED_BYTES",
        "LOCALLYCLOUD_FIREHOSE_SOURCE_POLL_INTERVAL_MS",
        "LOCALLYCLOUD_FIREHOSE_S3_DISPATCH_TIMEOUT_SECS",
        "LOCALLYCLOUD_FIREHOSE_MAX_RETRY_DELAY_SECS",
        "LOCALLYCLOUD_LOGS_DELIVERY_RETRY_INTERVAL_MS",
        "LOCALLYCLOUD_LOGS_RETENTION_RECLAIM_DELAY_MS",
    ];
    for name in numeric {
        for value in ["", "0", "-1", "999999999999", "private-canary-value"] {
            let error = match resolve("{}", &[(name, value)]) {
                Err(error) => error,
                Ok(_) => panic!("accepted invalid {name}"),
            };
            assert!(!error.to_string().contains("private-canary-value"));
        }
        assert!(StartupConfig::resolve(FileConfig::default(), &|key| {
            (key == name).then(|| OsString::from_vec(vec![0xff]))
        })
        .is_err());
    }
    for (name, value) in [
        (
            "LOCALLYCLOUD_KINESIS_SIMULATE_WRITE_LIMITS",
            "private-canary-value",
        ),
        (
            "LOCALLYCLOUD_COGNITO_MAILBOX_DIR",
            "relative/private-canary-value",
        ),
    ] {
        let error = match resolve("{}", &[(name, value)]) {
            Err(error) => error,
            Ok(_) => panic!("accepted invalid {name}"),
        };
        assert!(!error.to_string().contains("private-canary-value"));
    }
    assert!(resolve(
        r#"{"sns":{"outbox_retry_initial_secs":10,"outbox_retry_max_secs":5}}"#,
        &[]
    )
    .is_err());
    for value in [
        "private-canary-value",
        r#"["http://user:private-canary-value@127.0.0.1:8080"]"#,
        r#"["http://169.254.169.254"]"#,
        r#"["http://127.0.0.1:8080/path"]"#,
    ] {
        let error = match resolve("{}", &[("LOCALLYCLOUD_SNS_HTTP_LOCAL_ORIGINS", value)]) {
            Err(error) => error,
            Ok(_) => panic!("accepted invalid local origins"),
        };
        assert!(!error.to_string().contains("private-canary-value"));
    }

    for json in [
        r#"{"sns":{"http_timeout_secs":null}}"#,
        r#"{"kinesis":{"simulate_write_limits":"true"}}"#,
        r#"{"firehose":{"source_poll_interval_ms":null}}"#,
        r#"{"cognito":{"mailbox_dir":null}}"#,
        r#"{"logs":{"unknown":1}}"#,
        r#"{"sns":{"http_local_origins":null}}"#,
        r#"{"sns":null}"#,
        r#"{"kinesis":null}"#,
        r#"{"firehose":null}"#,
        r#"{"cognito":null}"#,
        r#"{"logs":null}"#,
    ] {
        assert!(serde_json::from_str::<FileConfig>(json).is_err(), "{json}");
    }
}
