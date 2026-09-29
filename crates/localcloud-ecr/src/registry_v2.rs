//! OCI Distribution storage behind ECR's authenticated Registry v2 entrypoint.
//!
//! The control plane shares this repository state. Only EcrHandler may pass external
//! requests here after validating a scoped, unexpired Basic token.
use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use http::{Method, StatusCode};
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_BLOB: usize = 64 * 1024 * 1024;
const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const MAX_UPLOADS: usize = 32;
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct RepoKey {
    account: String,
    region: String,
    name: String,
}
impl RepoKey {
    fn new(request: &ServiceRequest, name: &str) -> Self {
        Self {
            account: request.account_id.clone(),
            region: request.region.clone(),
            name: name.into(),
        }
    }
}
#[derive(Default)]
struct Repository {
    blobs: BTreeMap<String, Bytes>,
    manifests: BTreeMap<String, (Bytes, &'static str)>,
    tags: BTreeMap<String, String>,
    uploads: BTreeMap<String, Vec<u8>>,
    immutable_tags: bool,
}
#[derive(Default)]
pub(crate) struct RegistryV2Handler {
    repos: Mutex<BTreeMap<RepoKey, Repository>>,
}
impl RegistryV2Handler {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    /// Provisioning hook for the ECR control plane. This is not public Registry API.
    pub(crate) fn provision_repository(
        &self,
        account: &str,
        region: &str,
        name: &str,
        immutable_tags: bool,
    ) -> bool {
        if !valid_repo(name) {
            return false;
        }
        let Ok(mut repos) = self.repos.lock() else {
            return false;
        };
        let key = RepoKey {
            account: account.into(),
            region: region.into(),
            name: name.into(),
        };
        if repos.contains_key(&key) {
            return false;
        }
        repos.insert(
            key,
            Repository {
                immutable_tags,
                ..Repository::default()
            },
        );
        true
    }
    pub(crate) fn delete_repository(
        &self,
        account: &str,
        region: &str,
        name: &str,
        force: bool,
    ) -> Result<(), DeleteRepositoryError> {
        let mut repos = self
            .repos
            .lock()
            .map_err(|_| DeleteRepositoryError::Unavailable)?;
        let key = RepoKey {
            account: account.into(),
            region: region.into(),
            name: name.into(),
        };
        let repo = repos.get(&key).ok_or(DeleteRepositoryError::Missing)?;
        if !force && !repo.manifests.is_empty() {
            return Err(DeleteRepositoryError::NotEmpty);
        }
        repos.remove(&key);
        Ok(())
    }
    pub(crate) fn image_ids(&self, account: &str, region: &str, name: &str) -> Option<Vec<Value>> {
        let repos = self.repos.lock().ok()?;
        let key = RepoKey {
            account: account.into(),
            region: region.into(),
            name: name.into(),
        };
        let repo = repos.get(&key)?;
        let mut ids = Vec::new();
        for digest in repo.manifests.keys() {
            let tags = repo
                .tags
                .iter()
                .filter(|(_, tagged)| *tagged == digest)
                .map(|(tag, _)| tag);
            let mut tagged = false;
            for tag in tags {
                ids.push(json!({"imageDigest": digest, "imageTag": tag}));
                tagged = true;
            }
            if !tagged {
                ids.push(json!({"imageDigest": digest}));
            }
        }
        Some(ids)
    }
    pub(crate) fn image_blobs(
        &self,
        account: &str,
        region: &str,
        name: &str,
        reference: &str,
    ) -> Option<(Bytes, Vec<(Bytes, bool)>)> {
        let repos = self.repos.lock().ok()?;
        let key = RepoKey {
            account: account.into(),
            region: region.into(),
            name: name.into(),
        };
        let repo = repos.get(&key)?;
        let digest = if reference.starts_with("sha256:") {
            reference
        } else {
            repo.tags.get(reference)?
        };
        let (manifest, _) = repo.manifests.get(digest)?;
        let value: Value = serde_json::from_slice(manifest).ok()?;
        let config_digest = value["config"]["digest"].as_str()?;
        let config = repo.blobs.get(config_digest)?.clone();
        if sha256(&config) != config_digest
            || config.len() as u64 != value["config"]["size"].as_u64()?
            || !matches!(
                value["config"]["mediaType"].as_str()?,
                "application/vnd.oci.image.config.v1+json"
                    | "application/vnd.docker.container.image.v1+json"
            )
        {
            return None;
        }
        let layers = value["layers"]
            .as_array()?
            .iter()
            .map(|entry| {
                let compressed = match entry["mediaType"].as_str()? {
                    "application/vnd.oci.image.layer.v1.tar" => false,
                    "application/vnd.oci.image.layer.v1.tar+gzip"
                    | "application/vnd.docker.image.rootfs.diff.tar.gzip" => true,
                    _ => return None,
                };
                let digest = entry["digest"].as_str()?;
                let blob = repo.blobs.get(digest)?.clone();
                if sha256(&blob) != digest || blob.len() as u64 != entry["size"].as_u64()? {
                    return None;
                }
                Some((blob, compressed))
            })
            .collect::<Option<Vec<_>>>()?;
        Some((config, layers))
    }
    fn process(&self, request: &ServiceRequest) -> Response {
        if request.uri.path() == "/v2/" && request.method == Method::GET {
            return response(StatusCode::OK, Bytes::new(), None, None, None);
        }
        let Some(path) = request.uri.path().strip_prefix("/v2/") else {
            return error(
                StatusCode::NOT_FOUND,
                "UNSUPPORTED",
                "Unsupported registry path",
            );
        };
        let (name, action) = if let Some((name, rest)) = path.split_once("/blobs/uploads/") {
            (name, Action::Upload(rest))
        } else if let Some((name, digest)) = path.split_once("/blobs/") {
            (name, Action::Blob(digest))
        } else if let Some((name, reference)) = path.split_once("/manifests/") {
            (name, Action::Manifest(reference))
        } else {
            return error(
                StatusCode::NOT_FOUND,
                "UNSUPPORTED",
                "Unsupported registry path",
            );
        };
        if !valid_repo(name) {
            return error(
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
                "Invalid repository name",
            );
        }
        let Ok(mut repos) = self.repos.lock() else {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "UNKNOWN",
                "Registry state unavailable",
            );
        };
        let Some(repo) = repos.get_mut(&RepoKey::new(request, name)) else {
            return error(
                StatusCode::NOT_FOUND,
                "NAME_UNKNOWN",
                "Repository not found",
            );
        };
        match action {
            Action::Upload("") if request.method == Method::POST => {
                if repo.uploads.len() >= MAX_UPLOADS {
                    return error(
                        StatusCode::TOO_MANY_REQUESTS,
                        "TOOMANYREQUESTS",
                        "Too many uploads",
                    );
                }
                let id = Uuid::new_v4().to_string();
                repo.uploads.insert(id.clone(), Vec::new());
                let location = format!("/v2/{name}/blobs/uploads/{id}");
                response(
                    StatusCode::ACCEPTED,
                    Bytes::new(),
                    None,
                    Some(&location),
                    Some(&id),
                )
            }
            Action::Upload(id) if request.method == Method::PATCH => {
                if !request.uri.query().is_none_or(str::is_empty) {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "UNSUPPORTED",
                        "Upload query is unsupported",
                    );
                }
                let Some(upload) = repo.uploads.get_mut(id) else {
                    return error(
                        StatusCode::NOT_FOUND,
                        "BLOB_UPLOAD_UNKNOWN",
                        "Upload not found",
                    );
                };
                if upload.len().saturating_add(request.body.len()) > MAX_BLOB {
                    return error(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "BLOB_UPLOAD_INVALID",
                        "Blob size limit exceeded",
                    );
                }
                upload.extend_from_slice(&request.body);
                let location = format!("/v2/{name}/blobs/uploads/{id}");
                response(
                    StatusCode::ACCEPTED,
                    Bytes::new(),
                    None,
                    Some(&location),
                    Some(id),
                )
            }
            Action::Upload(id) if request.method == Method::PUT => {
                let Some(digest) = request
                    .uri
                    .query()
                    .and_then(|query| query.strip_prefix("digest="))
                else {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "DIGEST_INVALID",
                        "digest is required",
                    );
                };
                if !valid_digest(digest) {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "DIGEST_INVALID",
                        "Only sha256 digest is supported",
                    );
                }
                let Some(upload) = repo.uploads.get(id) else {
                    return error(
                        StatusCode::NOT_FOUND,
                        "BLOB_UPLOAD_UNKNOWN",
                        "Upload not found",
                    );
                };
                if upload.len().saturating_add(request.body.len()) > MAX_BLOB {
                    return error(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "BLOB_UPLOAD_INVALID",
                        "Blob size limit exceeded",
                    );
                }
                let mut content = upload.clone();
                content.extend_from_slice(&request.body);
                if sha256(&content) != digest {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "DIGEST_INVALID",
                        "Blob digest mismatch",
                    );
                }
                repo.uploads.remove(id);
                repo.blobs.insert(digest.into(), Bytes::from(content));
                let location = format!("/v2/{name}/blobs/{digest}");
                response(
                    StatusCode::CREATED,
                    Bytes::new(),
                    Some(digest),
                    Some(&location),
                    None,
                )
            }
            Action::Upload(id) if request.method == Method::DELETE => {
                if repo.uploads.remove(id).is_none() {
                    return error(
                        StatusCode::NOT_FOUND,
                        "BLOB_UPLOAD_UNKNOWN",
                        "Upload not found",
                    );
                }
                response(StatusCode::NO_CONTENT, Bytes::new(), None, None, None)
            }
            Action::Blob(digest)
                if request.method == Method::GET || request.method == Method::HEAD =>
            {
                if !valid_digest(digest) {
                    return error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "Invalid digest");
                }
                let Some(body) = repo.blobs.get(digest) else {
                    return error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "Blob not found");
                };
                let mut result = response(
                    StatusCode::OK,
                    if request.method == Method::HEAD {
                        Bytes::new()
                    } else {
                        body.clone()
                    },
                    Some(digest),
                    None,
                    None,
                );
                if request.method == Method::HEAD {
                    result.headers_mut().insert(
                        http::header::CONTENT_LENGTH,
                        body.len()
                            .to_string()
                            .parse()
                            .expect("valid content length"),
                    );
                }
                result
            }
            Action::Manifest(reference) if request.method == Method::PUT => {
                if !valid_reference(reference) {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "TAG_INVALID",
                        "Invalid manifest reference",
                    );
                }
                if request.body.len() > MAX_MANIFEST {
                    return error(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "MANIFEST_INVALID",
                        "Manifest size limit exceeded",
                    );
                }
                let media_type = request
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let media_type = match media_type {
                    OCI_MANIFEST => OCI_MANIFEST,
                    DOCKER_MANIFEST => DOCKER_MANIFEST,
                    _ => {
                        return error(
                            StatusCode::BAD_REQUEST,
                            "MANIFEST_INVALID",
                            "Unsupported manifest media type",
                        )
                    }
                };
                let digest = sha256(&request.body);
                if reference.starts_with("sha256:") && reference != digest {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "DIGEST_INVALID",
                        "Manifest digest mismatch",
                    );
                }
                let Ok(manifest) = serde_json::from_slice::<Value>(&request.body) else {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "MANIFEST_INVALID",
                        "Manifest JSON is invalid",
                    );
                };
                if !valid_manifest(&manifest, media_type, &repo.blobs) {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "MANIFEST_BLOB_UNKNOWN",
                        "Manifest references missing or invalid blobs",
                    );
                }
                if !reference.starts_with("sha256:")
                    && repo.immutable_tags
                    && repo.tags.contains_key(reference)
                {
                    return error(
                        StatusCode::CONFLICT,
                        "TAG_INVALID",
                        "Repository tag is immutable",
                    );
                }
                repo.manifests
                    .insert(digest.clone(), (request.body.clone(), media_type));
                if !reference.starts_with("sha256:") {
                    repo.tags.insert(reference.into(), digest.clone());
                }
                let location = format!("/v2/{name}/manifests/{digest}");
                response(
                    StatusCode::CREATED,
                    Bytes::new(),
                    Some(&digest),
                    Some(&location),
                    None,
                )
            }
            Action::Manifest(reference)
                if request.method == Method::GET || request.method == Method::HEAD =>
            {
                let digest = if reference.starts_with("sha256:") {
                    reference
                } else {
                    repo.tags.get(reference).map(String::as_str).unwrap_or("")
                };
                let Some((body, media_type)) = repo.manifests.get(digest) else {
                    return error(
                        StatusCode::NOT_FOUND,
                        "MANIFEST_UNKNOWN",
                        "Manifest not found",
                    );
                };
                let mut result = response(
                    StatusCode::OK,
                    if request.method == Method::HEAD {
                        Bytes::new()
                    } else {
                        body.clone()
                    },
                    Some(digest),
                    None,
                    None,
                );
                result.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    (*media_type).parse().expect("static media type"),
                );
                if request.method == Method::HEAD {
                    result.headers_mut().insert(
                        http::header::CONTENT_LENGTH,
                        body.len()
                            .to_string()
                            .parse()
                            .expect("valid content length"),
                    );
                }
                result
            }
            _ => error(
                StatusCode::METHOD_NOT_ALLOWED,
                "UNSUPPORTED",
                "Registry operation is unsupported",
            ),
        }
    }
}
pub(crate) enum DeleteRepositoryError {
    Missing,
    NotEmpty,
    Unavailable,
}

enum Action<'a> {
    Upload(&'a str),
    Blob(&'a str),
    Manifest(&'a str),
}
fn valid_repo(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.starts_with('/')
        && !name.ends_with('/')
        && name.split('/').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
                })
        })
}
fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}
fn valid_reference(value: &str) -> bool {
    valid_digest(value)
        || (!value.is_empty()
            && value.len() <= 128
            && !value.contains('/')
            && !value.contains(':')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
}
fn sha256(body: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(body))
}
fn valid_manifest(value: &Value, media_type: &str, blobs: &BTreeMap<String, Bytes>) -> bool {
    if value.get("schemaVersion").and_then(Value::as_u64) != Some(2)
        || value.get("mediaType").and_then(Value::as_str) != Some(media_type)
    {
        return false;
    }
    let Some(config) = value.get("config") else {
        return false;
    };
    let Some(layers) = value.get("layers").and_then(Value::as_array) else {
        return false;
    };
    std::iter::once(config).chain(layers.iter()).all(|entry| {
        let Some(digest) = entry.get("digest").and_then(Value::as_str) else {
            return false;
        };
        let Some(size) = entry.get("size").and_then(Value::as_u64) else {
            return false;
        };
        valid_digest(digest)
            && blobs
                .get(digest)
                .is_some_and(|body| body.len() as u64 == size)
    })
}
fn response(
    status: StatusCode,
    body: Bytes,
    digest: Option<&str>,
    location: Option<&str>,
    upload_id: Option<&str>,
) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header("docker-distribution-api-version", "registry/2.0");
    if let Some(digest) = digest {
        builder = builder.header("docker-content-digest", digest);
    }
    if let Some(location) = location {
        builder = builder.header(http::header::LOCATION, location);
    }
    if let Some(id) = upload_id {
        builder = builder.header("docker-upload-uuid", id);
    }
    builder.body(Body::from(body)).expect("registry response")
}
fn error(status: StatusCode, code: &str, message: &str) -> Response {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header("docker-distribution-api-version", "registry/2.0")
        .body(Body::from(
            json!({"errors":[{"code":code,"message":message}]}).to_string(),
        ))
        .expect("registry error")
}
#[async_trait]
impl NativeHandler for RegistryV2Handler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        self.process(&request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue};

    fn request(
        method: Method,
        path: &str,
        body: &[u8],
        account: &str,
        media_type: Option<&str>,
    ) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        if let Some(media_type) = media_type {
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_str(media_type).unwrap(),
            );
        }
        ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers,
            body: Bytes::copy_from_slice(body),
            account_id: account.into(),
            region: "us-east-1".into(),
            request_id: "test".into(),
        }
    }
    async fn body(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec()
    }
    async fn push_blob(handler: &RegistryV2Handler, account: &str, content: &[u8]) -> String {
        let start = handler
            .handle(request(
                Method::POST,
                "/v2/team/app/blobs/uploads/",
                b"",
                account,
                None,
            ))
            .await;
        assert_eq!(start.status(), StatusCode::ACCEPTED);
        let location = start.headers()[http::header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned();
        let digest = sha256(content);
        let finish = handler
            .handle(request(
                Method::PUT,
                &format!("{location}?digest={digest}"),
                content,
                account,
                None,
            ))
            .await;
        assert_eq!(finish.status(), StatusCode::CREATED);
        digest
    }
    #[tokio::test]
    async fn blob_digest_rejection_keeps_upload_and_scope() {
        let handler = RegistryV2Handler::new();
        assert!(handler.provision_repository("111111111111", "us-east-1", "team/app", false));
        assert!(!handler.provision_repository("111111111111", "us-east-1", "team/app", false));
        let start = handler
            .handle(request(
                Method::POST,
                "/v2/team/app/blobs/uploads/",
                b"",
                "111111111111",
                None,
            ))
            .await;
        let location = start.headers()[http::header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned();
        let wrong = sha256(b"wrong");
        let rejected = handler
            .handle(request(
                Method::PUT,
                &format!("{location}?digest={wrong}"),
                b"right",
                "111111111111",
                None,
            ))
            .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let actual = sha256(b"right");
        let accepted = handler
            .handle(request(
                Method::PUT,
                &format!("{location}?digest={actual}"),
                b"right",
                "111111111111",
                None,
            ))
            .await;
        assert_eq!(accepted.status(), StatusCode::CREATED);
        let found = handler
            .handle(request(
                Method::GET,
                &format!("/v2/team/app/blobs/{actual}"),
                b"",
                "111111111111",
                None,
            ))
            .await;
        assert_eq!(body(found).await, b"right");
        let other = handler
            .handle(request(
                Method::GET,
                &format!("/v2/team/app/blobs/{actual}"),
                b"",
                "222222222222",
                None,
            ))
            .await;
        assert_eq!(other.status(), StatusCode::NOT_FOUND);
        let missing = handler
            .handle(request(
                Method::POST,
                "/v2/nope/blobs/uploads/",
                b"",
                "111111111111",
                None,
            ))
            .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }
    #[tokio::test]
    async fn manifest_requires_blobs_and_immutable_tag_preserves_original() {
        let handler = RegistryV2Handler::new();
        let account = "111111111111";
        assert!(handler.provision_repository(account, "us-east-1", "team/app", true));
        let config = b"{}";
        let layer = b"layer data";
        let config_digest = sha256(config);
        let layer_digest = sha256(layer);
        let manifest = json!({"schemaVersion":2,"mediaType":OCI_MANIFEST,
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":config_digest,"size":config.len()},
            "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":layer_digest,"size":layer.len()}]}).to_string();
        let path = "/v2/team/app/manifests/latest";
        let rejected = handler
            .handle(request(
                Method::PUT,
                path,
                manifest.as_bytes(),
                account,
                Some(OCI_MANIFEST),
            ))
            .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let unknown = handler
            .handle(request(Method::GET, path, b"", account, None))
            .await;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        push_blob(&handler, account, config).await;
        push_blob(&handler, account, layer).await;
        let accepted = handler
            .handle(request(
                Method::PUT,
                path,
                manifest.as_bytes(),
                account,
                Some(OCI_MANIFEST),
            ))
            .await;
        assert_eq!(accepted.status(), StatusCode::CREATED);
        assert_eq!(
            accepted.headers()["docker-content-digest"],
            sha256(manifest.as_bytes())
        );
        let overwrite = handler
            .handle(request(
                Method::PUT,
                path,
                manifest.as_bytes(),
                account,
                Some(OCI_MANIFEST),
            ))
            .await;
        assert_eq!(overwrite.status(), StatusCode::CONFLICT);
        let fetched = handler
            .handle(request(Method::GET, path, b"", account, None))
            .await;
        assert_eq!(body(fetched).await, manifest.as_bytes());
        let head = handler
            .handle(request(Method::HEAD, path, b"", account, None))
            .await;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers()[http::header::CONTENT_LENGTH],
            manifest.len().to_string()
        );
    }
}
