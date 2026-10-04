//! Explicit offline storage migration using the existing injected service capabilities.
use std::sync::Arc;
use std::time::Duration;

use locallycloud_core::config::LocallyCloudConfig;
use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::InternalDispatcher;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::ServiceRegistry;
use locallycloud_state::StateDb;

pub async fn s3(config: &LocallyCloudConfig) -> Result<(), String> {
    let state = tokio::task::spawn_blocking(|| StateDb::default_path().and_then(StateDb::open))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    let _guard = state.lock_runtime().map_err(|error| error.to_string())?;
    let state = Arc::new(state);
    let registry = ServiceRegistry::with_known_services();
    locallycloud_iam_sts::service::register_with_account(&registry, &config.account_id)
        .map_err(|error| error.to_string())?;
    locallycloud_kms::register_with_state(&registry, state.clone())?;
    let handler = locallycloud_s3::service::S3Handler::for_migration(&registry, state)?;
    let dispatcher = Arc::new(InternalDispatcher::new_shared(
        &registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: Duration::from_secs(1),
        },
        LegacyHealth::new(false),
        config.default_region.clone(),
        config.account_id.clone(),
    ));
    registry.set_internal_dispatcher(dispatcher);
    // This is an offline administrative process, not an HTTP request. The existing
    // bootstrap identity still has to satisfy customer KMS key policy and IAM checks.
    let mut request = ServiceRequest {
        method: "POST".parse().unwrap(),
        uri: "/".parse().unwrap(),
        headers: Default::default(),
        body: Default::default(),
        region: config.default_region.clone(),
        account_id: config.account_id.clone(),
        request_id: "offline-s3-migration".into(),
    };
    if let Ok(access) = std::env::var("LOCALLYCLOUD_BOOTSTRAP_ACCESS_KEY_ID") {
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access}/19700101/{}/s3/aws4_request",
            config.default_region
        );
        request.headers.insert(
            "authorization",
            authorization
                .parse()
                .map_err(|_| "invalid bootstrap access key")?,
        );
    }
    let count = handler
        .migrate_legacy_encryption(&request)
        .await
        .map_err(|error| error.to_string())?;
    println!("Migrated {count} legacy S3 bodies; rerunning the command resumes remaining buckets.");
    Ok(())
}
