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
            .or_else(|| (key == "HOME").then(|| OsString::from("/owned-home")))
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
