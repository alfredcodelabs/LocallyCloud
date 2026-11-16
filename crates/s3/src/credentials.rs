//! Explicit local presign credential sources. Profile contents are read live, never cached.
use std::ffi::OsString;
use std::path::PathBuf;

use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

// Local defensive file-read bound, not an AWS credential quota.
const MAX_PROFILE_BYTES: u64 = 1024 * 1024;

/// Process inputs and profile location, deliberately neither Debug nor serializable.
/// Environment values are fixed startup inputs; profile contents are resolved per use.
pub struct S3CredentialSources {
    local_key: Option<String>,
    local_secret: Option<Zeroizing<String>>,
    aws_key: Option<String>,
    aws_secret: Option<Zeroizing<String>>,
    profile: String,
    profile_path: Option<PathBuf>,
}

impl Default for S3CredentialSources {
    fn default() -> Self {
        Self {
            local_key: None,
            local_secret: None,
            aws_key: None,
            aws_secret: None,
            profile: "default".into(),
            profile_path: None,
        }
    }
}

impl S3CredentialSources {
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, String> {
        let text = |name| {
            get(name)
                .map(|value| {
                    value
                        .into_string()
                        .map_err(|_| format!("{name} must be valid UTF-8"))
                })
                .transpose()
        };
        let profile_path = get("AWS_SHARED_CREDENTIALS_FILE")
            .map(PathBuf::from)
            .or_else(|| get("HOME").map(|home| PathBuf::from(home).join(".aws/credentials")));
        let profile_path = match profile_path {
            Some(path) if path.is_relative() => Some(
                std::env::current_dir()
                    .map_err(|_| "Could not resolve the local credentials file location")?
                    .join(path),
            ),
            path => path,
        };
        Ok(Self {
            local_key: text("LOCALLYCLOUD_S3_ACCESS_KEY_ID")?,
            local_secret: text("LOCALLYCLOUD_S3_SECRET_ACCESS_KEY")?.map(Zeroizing::new),
            aws_key: text("AWS_ACCESS_KEY_ID")?,
            aws_secret: text("AWS_SECRET_ACCESS_KEY")?.map(Zeroizing::new),
            profile: text("AWS_PROFILE")?.unwrap_or_else(|| "default".into()),
            profile_path,
        })
    }

    pub(crate) fn callback_access_key(&self) -> &str {
        self.local_key.as_deref().unwrap_or("locallycloud")
    }

    pub(crate) async fn resolve_secret(&self, access_key: &str) -> Option<Zeroizing<String>> {
        if let Some(secret) = &self.local_secret {
            if self
                .local_key
                .as_deref()
                .is_none_or(|key| key == access_key)
            {
                return Some(secret.clone());
            }
        }
        if self.aws_key.as_deref() == Some(access_key) {
            if let Some(secret) = &self.aws_secret {
                return Some(secret.clone());
            }
        }
        if let Some(secret) = self.profile_secret(access_key).await {
            return Some(secret);
        }
        matches!(access_key, "test" | "locallycloud").then(|| Zeroizing::new("test".into()))
    }

    async fn profile_secret(&self, access_key: &str) -> Option<Zeroizing<String>> {
        let path = self.profile_path.as_ref()?;
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .await
            .ok()?;
        let metadata = file.metadata().await.ok()?;
        if !metadata.is_file() || metadata.len() > MAX_PROFILE_BYTES {
            return None;
        }
        let mut contents = Zeroizing::new(Vec::new());
        file.take(MAX_PROFILE_BYTES + 1)
            .read_to_end(&mut contents)
            .await
            .ok()?;
        if contents.len() as u64 > MAX_PROFILE_BYTES {
            return None;
        }
        profile_secret(
            std::str::from_utf8(&contents).ok()?,
            &self.profile,
            access_key,
        )
    }
}

fn profile_secret(contents: &str, profile: &str, access_key: &str) -> Option<Zeroizing<String>> {
    let mut sections = std::collections::BTreeSet::new();
    let mut options = std::collections::BTreeSet::new();
    let mut section = None;
    let mut key = None;
    let mut secret = None;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let (name, suffix) = header.split_once(']')?;
            let name = name.trim();
            let suffix = suffix.trim_start();
            if name.is_empty()
                || name.contains(['[', ']'])
                || !(suffix.is_empty() || suffix.starts_with(['#', ';']))
                || !sections.insert(name)
            {
                return None;
            }
            section = Some(name);
            options.clear();
            continue;
        }
        let current = section?;
        let (name, value) = line.split_once(['=', ':'])?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || !options.insert(name.clone()) {
            return None;
        }
        if current == profile {
            match name.as_str() {
                "aws_access_key_id" => key = Some(value.trim()),
                "aws_secret_access_key" => secret = Some(value.trim()),
                _ => {}
            }
        }
    }
    if key == Some(access_key) {
        secret.map(|value| Zeroizing::new(value.to_owned()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::sync::Arc;
    use std::time::Duration;

    fn directory() -> tempfile::TempDir {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../compatibility-tests/.work/s3-live-credentials");
        std::fs::create_dir_all(&base).unwrap();
        tempfile::tempdir_in(base).unwrap()
    }

    fn from_profile(path: &std::path::Path, profile: &str) -> S3CredentialSources {
        S3CredentialSources::from_lookup(&|name| match name {
            "AWS_SHARED_CREDENTIALS_FILE" => Some(path.as_os_str().to_owned()),
            "AWS_PROFILE" => Some(profile.into()),
            _ => None,
        })
        .unwrap()
    }

    fn profile(key: &str, secret: &str) -> String {
        format!("[owned]\naws_access_key_id = {key}\naws_secret_access_key = {secret}\n")
    }

    #[tokio::test]
    async fn source_precedence_preserves_matching_and_explicit_developer_fallbacks() {
        let root = directory();
        let path = root.path().join("credentials");
        tokio::fs::write(&path, profile("PROFILE", "profile-secret"))
            .await
            .unwrap();
        let sources = S3CredentialSources::from_lookup(&|name| match name {
            "LOCALLYCLOUD_S3_ACCESS_KEY_ID" => Some("LOCAL".into()),
            "LOCALLYCLOUD_S3_SECRET_ACCESS_KEY" => Some("local-secret".into()),
            "AWS_ACCESS_KEY_ID" => Some("AWS".into()),
            "AWS_SECRET_ACCESS_KEY" => Some("aws-secret".into()),
            "AWS_PROFILE" => Some("owned".into()),
            "AWS_SHARED_CREDENTIALS_FILE" => Some(path.as_os_str().to_owned()),
            _ => None,
        })
        .unwrap();
        for (key, expected) in [
            ("LOCAL", "local-secret"),
            ("AWS", "aws-secret"),
            ("PROFILE", "profile-secret"),
            ("test", "test"),
            ("locallycloud", "test"),
        ] {
            assert_eq!(
                sources
                    .resolve_secret(key)
                    .await
                    .as_deref()
                    .map(String::as_str),
                Some(expected)
            );
        }
        assert!(sources.resolve_secret("OTHER").await.is_none());
        let unrestricted = S3CredentialSources::from_lookup(&|name| {
            (name == "LOCALLYCLOUD_S3_SECRET_ACCESS_KEY").then(|| "legacy-secret".into())
        })
        .unwrap();
        assert_eq!(
            unrestricted
                .resolve_secret("ANY")
                .await
                .as_deref()
                .map(String::as_str),
            Some("legacy-secret")
        );
    }

    #[tokio::test]
    async fn atomic_profile_rotation_new_key_and_deletion_do_not_reuse_previous_material() {
        let root = directory();
        let path = root.path().join("credentials");
        let replacement = root.path().join("replacement");
        tokio::fs::write(&path, profile("OLD", "old-secret"))
            .await
            .unwrap();
        let sources = from_profile(&path, "owned");
        assert_eq!(
            sources
                .resolve_secret("OLD")
                .await
                .as_deref()
                .map(String::as_str),
            Some("old-secret")
        );
        tokio::fs::write(&replacement, profile("NEW", "new-secret"))
            .await
            .unwrap();
        tokio::fs::rename(&replacement, &path).await.unwrap();
        assert!(sources.resolve_secret("OLD").await.is_none());
        assert_eq!(
            sources
                .resolve_secret("NEW")
                .await
                .as_deref()
                .map(String::as_str),
            Some("new-secret")
        );
        tokio::fs::remove_file(&path).await.unwrap();
        assert!(sources.resolve_secret("NEW").await.is_none());
        assert_eq!(
            sources
                .resolve_secret("test")
                .await
                .as_deref()
                .map(String::as_str),
            Some("test")
        );
    }

    #[tokio::test]
    async fn invalid_profiles_and_non_regular_sources_never_retain_previous_keys() {
        let root = directory();
        let path = root.path().join("credentials");
        let sources = from_profile(&path, "owned");
        for body in [
            profile("KEY", "old-secret").into_bytes(),
            b"malformed profile".to_vec(),
            vec![0xff],
            vec![b'x'; MAX_PROFILE_BYTES as usize + 1],
        ] {
            tokio::fs::write(&path, &body).await.unwrap();
            let resolved = sources.resolve_secret("KEY").await;
            if body == profile("KEY", "old-secret").into_bytes() {
                assert_eq!(resolved.as_deref().map(String::as_str), Some("old-secret"));
            } else {
                assert!(resolved.is_none());
            }
        }
        tokio::fs::remove_file(&path).await.unwrap();
        tokio::fs::create_dir(&path).await.unwrap();
        assert!(sources.resolve_secret("KEY").await.is_none());
        tokio::fs::remove_dir(&path).await.unwrap();
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // This is a private fixture path; no client data enters the C call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), sources.resolve_secret("KEY"))
                .await
                .unwrap()
                .is_none()
        );
        let null = from_profile(std::path::Path::new("/dev/null"), "owned");
        assert_eq!(
            null.resolve_secret("test")
                .await
                .as_deref()
                .map(String::as_str),
            Some("test")
        );
    }

    #[tokio::test]
    async fn concurrent_atomic_rotations_return_only_complete_selected_profile_credentials() {
        let root = directory();
        let path = root.path().join("credentials");
        tokio::fs::write(&path, profile("KEY", "generation-0"))
            .await
            .unwrap();
        let sources = Arc::new(from_profile(&path, "owned"));
        let mut readers = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let sources = sources.clone();
            readers.spawn(async move {
                for _ in 0..8 {
                    let secret = sources.resolve_secret("KEY").await.unwrap();
                    assert!((0..=8)
                        .any(|generation| secret.as_str() == format!("generation-{generation}")));
                }
            });
        }
        for generation in 1..=8 {
            let replacement = root.path().join(format!("replacement-{generation}"));
            tokio::fs::write(
                &replacement,
                profile("KEY", &format!("generation-{generation}")),
            )
            .await
            .unwrap();
            tokio::fs::rename(replacement, &path).await.unwrap();
        }
        while let Some(result) = readers.join_next().await {
            result.unwrap();
        }
    }

    #[tokio::test]
    async fn callback_signing_and_query_validation_share_live_profile_rotation() {
        use bytes::Bytes;
        use http::{HeaderMap, HeaderValue, Method};
        use locallycloud_core::handler::ServiceRequest;
        let root = directory();
        let path = root.path().join("credentials");
        let replacement = root.path().join("replacement");
        tokio::fs::write(&path, profile("locallycloud", "old-secret"))
            .await
            .unwrap();
        let sources = from_profile(&path, "owned");
        let make_request = |url: String| {
            let mut headers = HeaderMap::new();
            headers.insert("host", HeaderValue::from_static("owned.localhost:4566"));
            ServiceRequest {
                method: Method::PUT,
                uri: url.parse().unwrap(),
                headers,
                body: Bytes::new(),
                region: "us-east-1".into(),
                account_id: "000000000000".into(),
                request_id: "owned-query".into(),
            }
        };
        let old_url = crate::presign::presign_local_put_with_sources(
            "https://owned.localhost:4566",
            "/bucket/callback",
            "us-east-1",
            60,
            &sources,
        )
        .await
        .unwrap();
        let old = make_request(old_url);
        assert!(crate::presign::validate_url_with_sources(&old, &sources)
            .await
            .is_ok());
        tokio::fs::write(&replacement, profile("locallycloud", "new-secret"))
            .await
            .unwrap();
        tokio::fs::rename(&replacement, &path).await.unwrap();
        assert!(crate::presign::validate_url_with_sources(&old, &sources)
            .await
            .is_err());
        let new_url = crate::presign::presign_local_put_with_sources(
            "https://owned.localhost:4566",
            "/bucket/callback",
            "us-east-1",
            60,
            &sources,
        )
        .await
        .unwrap();
        assert!(
            crate::presign::validate_url_with_sources(&make_request(new_url), &sources)
                .await
                .is_ok()
        );
    }

    #[test]
    fn source_selection_is_validated_without_serializing_secrets() {
        for name in [
            "LOCALLYCLOUD_S3_ACCESS_KEY_ID",
            "LOCALLYCLOUD_S3_SECRET_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_PROFILE",
        ] {
            let result = S3CredentialSources::from_lookup(&|key| {
                (key == name).then(|| OsString::from_vec(vec![0xff]))
            });
            assert!(result.is_err());
        }
        let contents = "[other]\naws_access_key_id=KEY\naws_secret_access_key=wrong\n[owned]\naws_access_key_id=KEY\naws_secret_access_key=right\n[unused]\naws_access_key_id=KEY\naws_secret_access_key=wrong\n";
        assert_eq!(
            profile_secret(contents, "owned", "KEY")
                .as_deref()
                .map(String::as_str),
            Some("right")
        );
        assert!(profile_secret(contents, "missing", "KEY").is_none());
    }

    #[test]
    fn complete_profile_file_is_validated_before_returning_any_secret() {
        let owned = "[owned]\naws_access_key_id=KEY\naws_secret_access_key=right\n";
        for comment in ["# comment", "; comment"] {
            let contents = format!(
                "{owned}[other] {comment}\naws_access_key_id=OTHER\naws_secret_access_key=wrong\n"
            );
            assert_eq!(
                profile_secret(&contents, "owned", "KEY")
                    .as_deref()
                    .map(String::as_str),
                Some("right")
            );
            assert!(profile_secret(&contents, "owned", "OTHER").is_none());
            let contents = format!(
                "[owned] {comment}\naws_access_key_id: KEY\naws_secret_access_key: right\n"
            );
            assert_eq!(
                profile_secret(&contents, "owned", "KEY")
                    .as_deref()
                    .map(String::as_str),
                Some("right")
            );
        }
        for suffix in [
            "[other\naws_access_key_id=OTHER\naws_secret_access_key=wrong\n",
            "[other] garbage\n",
            "[]\n",
            "[[other]]\n",
            "garbage after credentials\n",
            "aws_secret_access_key=duplicate\n",
            "AWS_ACCESS_KEY_ID=duplicate\n",
            "[owned]\nunknown=value\n",
            "[other]\nunknown=first\nUNKNOWN=duplicate\n",
            "[other]\nkey=value\n[other]\nkey=value\n",
        ] {
            assert!(
                profile_secret(&format!("{owned}{suffix}"), "owned", "KEY").is_none(),
                "accepted malformed or duplicate profile data"
            );
        }
        assert!(profile_secret(&format!("garbage\n{owned}"), "owned", "KEY").is_none());
    }
}
