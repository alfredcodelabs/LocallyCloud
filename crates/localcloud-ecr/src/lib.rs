//! ECR repository control plane and authenticated OCI Distribution subset.
//!
//! Core verifies SigV4 before marking GetAuthorizationToken as trusted. Issued tokens are
//! account/region scoped and expire after 12 hours. Every Registry v2 request checks Basic
//! authentication before reaching the shared in-memory repository store.

mod registry_v2;

use std::collections::HashSet;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use base64::Engine;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use localcloud_core::error_mapping::AwsError;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::integration::authorization::AuthorizationRequest;
use localcloud_core::integration::RequestIdentity;
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

const TARGET_PREFIX: &str = "AmazonEC2ContainerRegistry_V20150921";
const DEFAULT_PAGE_SIZE: usize = 100;
const TOKEN_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
const MAX_ACTIVE_TOKENS: usize = 4096;

#[derive(Clone)]
struct Repository {
    name: String,
    created_at: f64,
    image_tag_mutability: String,
    scan_on_push: bool,
    encryption_type: String,
    kms_key: Option<String>,
}

#[derive(Clone)]
struct RegistryToken {
    account: String,
    region: String,
    expires_at: Instant,
}

pub struct EcrHandler {
    // key: "{account}:{region}:{name}"
    repos: DashMap<String, Repository>,
    registry_v2: Arc<registry_v2::RegistryV2Handler>,
    tokens: DashMap<String, RegistryToken>,
    registry: Option<Weak<ServiceRegistry>>,
}

impl EcrHandler {
    fn new() -> Self {
        Self {
            repos: DashMap::new(),
            registry_v2: Arc::new(registry_v2::RegistryV2Handler::new()),
            tokens: DashMap::new(),
            registry: None,
        }
    }

    fn with_registry(registry: &Arc<ServiceRegistry>) -> Self {
        let mut handler = Self::new();
        handler.registry = Some(Arc::downgrade(registry));
        handler
    }

    fn authorize_get_authorization_token(&self, request: &ServiceRequest) -> Result<(), AwsError> {
        let Some(registry) = &self.registry else {
            // A standalone handler has no IAM service and retains permissive behavior.
            return Ok(());
        };
        let registry = registry.upgrade().ok_or_else(|| {
            AwsError::new("ServerException", "ECR authorization is unavailable", 500)
        })?;
        let evaluator = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .ok_or_else(|| {
                AwsError::new("ServerException", "ECR authorization is unavailable", 500)
            })?;
        if !evaluator.strict_sigv4_required() {
            return Ok(());
        }
        let authorization = request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        evaluator
            .authorize(AuthorizationRequest {
                request_identity: RequestIdentity {
                    account_id: request.account_id.clone(),
                    access_key_id: authorization
                        .and_then(RequestIdentity::access_key_from_authorization),
                    arn: None,
                },
                delegated_identity: None,
                source_service: "ecr".to_owned(),
                action: "ecr:GetAuthorizationToken".to_owned(),
                resource: "*".to_owned(),
                context: Default::default(),
            })
            .map_err(|_| AwsError::new("AccessDeniedException", "Access denied", 400))
    }

    /// Internal image snapshot for an ECS task in the same account and region.
    pub fn image_blobs(
        &self,
        account: &str,
        region: &str,
        name: &str,
        reference: &str,
    ) -> Option<(bytes::Bytes, Vec<(bytes::Bytes, bool)>)> {
        self.registry_v2
            .image_blobs(account, region, name, reference)
    }

    fn issue_authorization_token(
        &self,
        request: &ServiceRequest,
        body: &Map<String, Value>,
        account: &str,
        region: &str,
        verified: bool,
        host: Option<&str>,
    ) -> Result<Value, AwsError> {
        if !verified {
            return Err(AwsError::new(
                "SignatureDoesNotMatch",
                "The request signature is invalid",
                403,
            ));
        }
        self.authorize_get_authorization_token(request)?;
        if let Some(ids) = body.get("registryIds") {
            let ids = ids
                .as_array()
                .ok_or_else(|| invalid("registryIds must be an array"))?;
            if ids.len() != 1 || ids[0].as_str() != Some(account) {
                return Err(invalid("registryIds must contain the current account"));
            }
        }
        let endpoint = local_registry_endpoint(host)
            .ok_or_else(|| invalid("Host is invalid for local ECR registry"))?;
        let now = Instant::now();
        self.tokens.retain(|_, token| token.expires_at > now);
        if self.tokens.len() >= MAX_ACTIVE_TOKENS {
            return Err(AwsError::new(
                "ServerException",
                "Too many active registry tokens",
                500,
            ));
        }
        let password = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        self.tokens.insert(
            password.clone(),
            RegistryToken {
                account: account.to_owned(),
                region: region.to_owned(),
                expires_at: now + TOKEN_LIFETIME,
            },
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("AWS:{password}"));
        Ok(json!({"authorizationData": [{
            "authorizationToken": encoded,
            "expiresAt": now_epoch() + TOKEN_LIFETIME.as_secs_f64(),
            "proxyEndpoint": endpoint,
        }]}))
    }

    async fn handle_registry(&self, mut request: ServiceRequest) -> Response {
        let Some(scope) = self.basic_scope(&request) else {
            return registry_unauthorized();
        };
        request.account_id = scope.account;
        request.region = scope.region;
        self.registry_v2.handle(request).await
    }

    fn basic_scope(&self, request: &ServiceRequest) -> Option<RegistryToken> {
        let authorization = request
            .headers
            .get(http::header::AUTHORIZATION)?
            .to_str()
            .ok()?;
        let encoded = authorization.strip_prefix("Basic ")?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        let decoded = std::str::from_utf8(&decoded).ok()?;
        let (username, password) = decoded.split_once(':')?;
        if username != "AWS"
            || password.len() != 64
            || !password.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        let token = self.tokens.get(password)?;
        if token.expires_at <= Instant::now() {
            drop(token);
            self.tokens.remove(password);
            return None;
        }
        let scope = token.clone();
        if !registry_host_matches_scope(
            request.headers.get(http::header::HOST)?.to_str().ok()?,
            &scope,
        ) {
            return None;
        }
        Some(scope)
    }

    fn key(account: &str, region: &str, name: &str) -> String {
        format!("{account}:{region}:{name}")
    }

    fn repo_json(&self, account: &str, region: &str, repo: &Repository) -> Value {
        let mut encryption = json!({ "encryptionType": repo.encryption_type });
        if let Some(kms_key) = &repo.kms_key {
            encryption["kmsKey"] = Value::String(kms_key.clone());
        }
        json!({
            "repositoryArn": format!("arn:aws:ecr:{region}:{account}:repository/{}", repo.name),
            "registryId": account,
            "repositoryName": repo.name,
            "repositoryUri": format!("{account}.dkr.ecr.{region}.amazonaws.com/{}", repo.name),
            "createdAt": repo.created_at,
            "imageTagMutability": repo.image_tag_mutability,
            "imageScanningConfiguration": { "scanOnPush": repo.scan_on_push },
            "encryptionConfiguration": encryption,
        })
    }

    fn dispatch(
        &self,
        request: &ServiceRequest,
        operation: &str,
        body: &Map<String, Value>,
    ) -> Result<Value, AwsError> {
        let region = request.region.as_str();
        let account = request.account_id.as_str();
        let verified = request
            .headers
            .get("x-localcloud-verified-ecr-sigv4")
            .is_some_and(|value| value == "1");
        let host = request
            .headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok());
        match operation {
            "GetAuthorizationToken" => {
                self.issue_authorization_token(request, body, account, region, verified, host)
            }
            "CreateRepository" => self.create_repository(body, region, account),
            "DescribeRepositories" => self.describe_repositories(body, region, account),
            "DeleteRepository" => self.delete_repository(body, region, account),
            "ListImages" => self.list_images(body, region, account),
            "BatchDeleteImage" => self.batch_delete_image(body, region, account),
            other => Err(unknown_operation(format!(
                "operation {other} is not supported"
            ))),
        }
    }

    fn create_repository(
        &self,
        body: &Map<String, Value>,
        region: &str,
        account: &str,
    ) -> Result<Value, AwsError> {
        validate_registry_id(body, account)?;
        let name = required_repository_name(body)?;

        if let Some(tags) = body.get("tags") {
            let tags = tags
                .as_array()
                .ok_or_else(|| invalid("tags must be an array"))?;
            if !tags.is_empty() {
                return Err(invalid("tags are not supported"));
            }
        }

        let image_tag_mutability = optional_enum(
            body,
            "imageTagMutability",
            &["MUTABLE", "IMMUTABLE"],
            "MUTABLE",
        )?;
        let scan_on_push = parse_scanning_configuration(body)?;
        let (encryption_type, kms_key) = parse_encryption_configuration(body)?;
        let created_at = now_epoch();
        let repository = Repository {
            name: name.to_owned(),
            created_at,
            image_tag_mutability: image_tag_mutability.to_owned(),
            scan_on_push,
            encryption_type: encryption_type.to_owned(),
            kms_key,
        };
        let key = Self::key(account, region, name);

        match self.repos.entry(key) {
            Entry::Occupied(_) => Err(AwsError::new(
                "RepositoryAlreadyExistsException",
                format!(
                    "The repository with name '{name}' already exists in the registry with id '{account}'"
                ),
                400,
            )),
            Entry::Vacant(entry) => {
                if !self.registry_v2.provision_repository(account, region, name, image_tag_mutability == "IMMUTABLE") {
                    return Err(AwsError::new("ServerException", "ECR registry state is unavailable", 500));
                }
                entry.insert(repository.clone());
                Ok(json!({
                    "repository": self.repo_json(account, region, &repository)
                }))
            }
        }
    }

    fn describe_repositories(
        &self,
        body: &Map<String, Value>,
        region: &str,
        account: &str,
    ) -> Result<Value, AwsError> {
        validate_registry_id(body, account)?;
        if let Some(names_value) = body.get("repositoryNames") {
            if body.contains_key("maxResults") || body.contains_key("nextToken") {
                return Err(invalid(
                    "repositoryNames cannot be combined with maxResults or nextToken",
                ));
            }
            let names = names_value
                .as_array()
                .ok_or_else(|| invalid("repositoryNames must be an array"))?;
            if !(1..=100).contains(&names.len()) {
                return Err(invalid(
                    "repositoryNames must contain between 1 and 100 names",
                ));
            }
            let mut seen = HashSet::with_capacity(names.len());
            let mut validated_names = Vec::with_capacity(names.len());
            for value in names {
                let name = value
                    .as_str()
                    .ok_or_else(|| invalid("each repository name must be a string"))?;
                validate_repository_name(name)?;
                if !seen.insert(name) {
                    return Err(invalid("repositoryNames must not contain duplicates"));
                }
                validated_names.push(name);
            }
            let mut repositories = Vec::with_capacity(validated_names.len());
            for name in validated_names {
                let repo = self
                    .repos
                    .get(&Self::key(account, region, name))
                    .ok_or_else(|| repository_not_found(name, account))?;
                repositories.push(self.repo_json(account, region, &repo));
            }
            return Ok(json!({ "repositories": repositories }));
        }

        let max_results = optional_max_results(body, DEFAULT_PAGE_SIZE)?;
        let mut repositories = self.repositories_in_scope(account, region);
        repositories.sort_by(|left, right| left.name.cmp(&right.name));
        let start = match body.get("nextToken") {
            Some(value) => {
                let token = value
                    .as_str()
                    .filter(|token| !token.is_empty())
                    .ok_or_else(|| invalid("nextToken must be a non-empty string"))?;
                let cursor = decode_token(token, "DescribeRepositories", account, region, "")?;
                repositories
                    .binary_search_by(|repo| repo.name.as_str().cmp(cursor.as_str()))
                    .map_err(|_| invalid("nextToken is invalid or expired"))?
                    + 1
            }
            None => 0,
        };
        let end = start.saturating_add(max_results).min(repositories.len());
        let page: Vec<Value> = repositories[start..end]
            .iter()
            .map(|repo| self.repo_json(account, region, repo))
            .collect();
        let mut response = json!({ "repositories": page });
        if end < repositories.len() {
            response["nextToken"] = Value::String(encode_token(
                "DescribeRepositories",
                account,
                region,
                "",
                &repositories[end - 1].name,
            ));
        }
        Ok(response)
    }

    fn delete_repository(
        &self,
        body: &Map<String, Value>,
        region: &str,
        account: &str,
    ) -> Result<Value, AwsError> {
        validate_registry_id(body, account)?;
        let name = required_repository_name(body)?;
        if let Some(force) = body.get("force") {
            if !force.is_boolean() {
                return Err(invalid("force must be a boolean"));
            }
        }
        let force = body.get("force").and_then(Value::as_bool).unwrap_or(false);
        let key = Self::key(account, region, name);
        let repository = match self.repos.entry(key) {
            Entry::Vacant(_) => return Err(repository_not_found(name, account)),
            Entry::Occupied(entry) => {
                match self
                    .registry_v2
                    .delete_repository(account, region, name, force)
                {
                    Ok(()) => entry.remove(),
                    Err(
                        registry_v2::DeleteRepositoryError::Missing
                        | registry_v2::DeleteRepositoryError::Unavailable,
                    ) => {
                        return Err(AwsError::new(
                            "ServerException",
                            "ECR registry state is unavailable",
                            500,
                        ));
                    }
                    Err(registry_v2::DeleteRepositoryError::NotEmpty) => {
                        return Err(AwsError::new(
                            "RepositoryNotEmptyException",
                            format!("The repository with name '{name}' contains images"),
                            400,
                        ));
                    }
                }
            }
        };
        Ok(json!({
            "repository": self.repo_json(account, region, &repository)
        }))
    }

    fn list_images(
        &self,
        body: &Map<String, Value>,
        region: &str,
        account: &str,
    ) -> Result<Value, AwsError> {
        validate_registry_id(body, account)?;
        let name = required_repository_name(body)?;
        self.require_repository(account, region, name)?;
        let max_results = optional_max_results(body, DEFAULT_PAGE_SIZE)?;
        let tag_status = if let Some(filter) = body.get("filter") {
            let filter = filter
                .as_object()
                .ok_or_else(|| invalid("filter must be an object"))?;
            reject_unknown_fields(filter, &["tagStatus"], "filter")?;
            optional_enum(filter, "tagStatus", &["ANY", "TAGGED", "UNTAGGED"], "ANY")?
        } else {
            "ANY"
        };
        let mut image_ids = self
            .registry_v2
            .image_ids(account, region, name)
            .ok_or_else(|| {
                AwsError::new("ServerException", "ECR registry state is unavailable", 500)
            })?;
        image_ids.retain(|id| match tag_status {
            "TAGGED" => id.get("imageTag").is_some(),
            "UNTAGGED" => id.get("imageTag").is_none(),
            _ => true,
        });
        image_ids.sort_by_key(image_cursor);
        let context = format!("{name}:{tag_status}");
        let start = match body.get("nextToken") {
            Some(value) => {
                let token = value
                    .as_str()
                    .filter(|token| !token.is_empty())
                    .ok_or_else(|| invalid("nextToken must be a non-empty string"))?;
                let cursor = decode_token(token, "ListImages", account, region, &context)?;
                image_ids
                    .binary_search_by(|id| image_cursor(id).cmp(&cursor))
                    .map_err(|_| invalid("nextToken is invalid or expired"))?
                    + 1
            }
            None => 0,
        };
        let end = start.saturating_add(max_results).min(image_ids.len());
        let mut output = json!({ "imageIds": image_ids[start..end] });
        if end < image_ids.len() {
            output["nextToken"] = Value::String(encode_token(
                "ListImages",
                account,
                region,
                &context,
                &image_cursor(&image_ids[end - 1]),
            ));
        }
        Ok(output)
    }

    fn batch_delete_image(
        &self,
        body: &Map<String, Value>,
        region: &str,
        account: &str,
    ) -> Result<Value, AwsError> {
        validate_registry_id(body, account)?;
        let name = required_repository_name(body)?;
        self.require_repository(account, region, name)?;
        let image_ids = body
            .get("imageIds")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("imageIds must be an array"))?;
        if !(1..=100).contains(&image_ids.len()) {
            return Err(invalid("imageIds must contain between 1 and 100 items"));
        }
        for image_id in image_ids {
            validate_image_id(image_id)?;
        }
        if self
            .registry_v2
            .image_ids(account, region, name)
            .is_some_and(|ids| !ids.is_empty())
        {
            return Err(unknown_operation(
                "BatchDeleteImage for populated repositories is not supported".into(),
            ));
        }
        let failures: Vec<Value> = image_ids
            .iter()
            .map(|image_id| {
                json!({
                    "imageId": image_id,
                    "failureCode": "ImageNotFound",
                    "failureReason": "Requested image not found"
                })
            })
            .collect();
        Ok(json!({ "imageIds": [], "failures": failures }))
    }

    fn repositories_in_scope(&self, account: &str, region: &str) -> Vec<Repository> {
        let prefix = format!("{account}:{region}:");
        self.repos
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.value().clone())
            .collect()
    }

    fn require_repository(&self, account: &str, region: &str, name: &str) -> Result<(), AwsError> {
        self.repos
            .contains_key(&Self::key(account, region, name))
            .then_some(())
            .ok_or_else(|| repository_not_found(name, account))
    }
}

fn image_cursor(image_id: &Value) -> String {
    format!(
        "{}|{}",
        image_id["imageDigest"].as_str().unwrap_or(""),
        image_id["imageTag"].as_str().unwrap_or("")
    )
}

fn required_repository_name(body: &Map<String, Value>) -> Result<&str, AwsError> {
    let name = body
        .get("repositoryName")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("repositoryName must be a string"))?;
    validate_repository_name(name)?;
    Ok(name)
}

fn validate_registry_id(body: &Map<String, Value>, account: &str) -> Result<(), AwsError> {
    let Some(value) = body.get("registryId") else {
        return Ok(());
    };
    let registry_id = value
        .as_str()
        .ok_or_else(|| invalid("registryId must be a string of 12 digits"))?;
    if registry_id.len() != 12 || !registry_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("registryId must be a string of 12 digits"));
    }
    if registry_id != account {
        return Err(invalid("registryId must match the request account"));
    }
    Ok(())
}

fn validate_repository_name(name: &str) -> Result<(), AwsError> {
    if !(2..=256).contains(&name.len()) {
        return Err(invalid(
            "repositoryName must contain between 2 and 256 characters",
        ));
    }
    for component in name.split('/') {
        if component.is_empty() {
            return Err(invalid("repositoryName contains an empty path component"));
        }
        let mut previous_separator = false;
        for (index, byte) in component.bytes().enumerate() {
            let alphanumeric = byte.is_ascii_lowercase() || byte.is_ascii_digit();
            let separator = matches!(byte, b'.' | b'_' | b'-');
            if !alphanumeric && !separator {
                return Err(invalid(
                    "repositoryName may contain only lowercase letters, digits, '/', '.', '_', and '-'",
                ));
            }
            if separator && (index == 0 || previous_separator) {
                return Err(invalid(
                    "repositoryName separators cannot be leading or consecutive",
                ));
            }
            previous_separator = separator;
        }
        if previous_separator {
            return Err(invalid("repositoryName separators cannot be terminal"));
        }
    }
    Ok(())
}

fn parse_scanning_configuration(body: &Map<String, Value>) -> Result<bool, AwsError> {
    let Some(value) = body.get("imageScanningConfiguration") else {
        return Ok(false);
    };
    let configuration = value
        .as_object()
        .ok_or_else(|| invalid("imageScanningConfiguration must be an object"))?;
    reject_unknown_fields(configuration, &["scanOnPush"], "imageScanningConfiguration")?;
    configuration
        .get("scanOnPush")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("imageScanningConfiguration.scanOnPush must be a boolean"))
}

fn parse_encryption_configuration(
    body: &Map<String, Value>,
) -> Result<(&str, Option<String>), AwsError> {
    let Some(value) = body.get("encryptionConfiguration") else {
        return Ok(("AES256", None));
    };
    let configuration = value
        .as_object()
        .ok_or_else(|| invalid("encryptionConfiguration must be an object"))?;
    reject_unknown_fields(
        configuration,
        &["encryptionType", "kmsKey"],
        "encryptionConfiguration",
    )?;
    let encryption_type = configuration
        .get("encryptionType")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("encryptionConfiguration.encryptionType must be a string"))?;
    match encryption_type {
        "AES256" => {
            if configuration.contains_key("kmsKey") {
                return Err(invalid("kmsKey is valid only for KMS encryption"));
            }
            Ok(("AES256", None))
        }
        "KMS" => {
            let kms_key = configuration
                .get("kmsKey")
                .and_then(Value::as_str)
                .filter(|key| !key.is_empty())
                .ok_or_else(|| invalid("KMS encryption requires a non-empty kmsKey"))?;
            Ok(("KMS", Some(kms_key.to_owned())))
        }
        _ => Err(invalid("encryptionType must be AES256 or KMS")),
    }
}

fn optional_enum<'a>(
    body: &'a Map<String, Value>,
    field: &str,
    allowed: &[&str],
    default: &'a str,
) -> Result<&'a str, AwsError> {
    let Some(value) = body.get(field) else {
        return Ok(default);
    };
    let value = value
        .as_str()
        .ok_or_else(|| invalid(&format!("{field} must be a string")))?;
    allowed
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| invalid(&format!("{field} has an invalid value")))
}

fn optional_max_results(body: &Map<String, Value>, default: usize) -> Result<usize, AwsError> {
    let Some(value) = body.get("maxResults") else {
        return Ok(default);
    };
    let max_results = value
        .as_u64()
        .filter(|value| (1..=1000).contains(value))
        .ok_or_else(|| invalid("maxResults must be an integer between 1 and 1000"))?;
    Ok(max_results as usize)
}

fn reject_unknown_fields(
    body: &Map<String, Value>,
    allowed: &[&str],
    shape: &str,
) -> Result<(), AwsError> {
    if body.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(&format!("{shape} contains an unknown field")));
    }
    Ok(())
}

fn validate_image_id(value: &Value) -> Result<(), AwsError> {
    let image_id = value
        .as_object()
        .ok_or_else(|| invalid("each imageId must be an object"))?;
    reject_unknown_fields(image_id, &["imageDigest", "imageTag"], "imageId")?;
    let digest = match image_id.get("imageDigest") {
        Some(value) => {
            let digest = value
                .as_str()
                .ok_or_else(|| invalid("imageDigest must be a string"))?;
            let hash = digest
                .strip_prefix("sha256:")
                .filter(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .ok_or_else(|| invalid("imageDigest must be a sha256 digest"))?;
            Some(hash)
        }
        None => None,
    };
    let tag = match image_id.get("imageTag") {
        Some(value) => {
            let tag = value
                .as_str()
                .filter(|tag| !tag.is_empty() && tag.len() <= 300)
                .ok_or_else(|| {
                    invalid("imageTag must be a non-empty string of at most 300 characters")
                })?;
            Some(tag)
        }
        None => None,
    };
    if digest.is_none() && tag.is_none() {
        return Err(invalid("imageId requires imageDigest or imageTag"));
    }
    Ok(())
}

fn encode_token(kind: &str, account: &str, region: &str, context: &str, cursor: &str) -> String {
    let payload = format!("{kind}\n{account}\n{region}\n{context}\n{cursor}");
    payload
        .bytes()
        .flat_map(|byte| {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            [
                HEX[(byte >> 4) as usize] as char,
                HEX[(byte & 0x0f) as usize] as char,
            ]
        })
        .collect()
}

fn decode_token(
    token: &str,
    kind: &str,
    account: &str,
    region: &str,
    context: &str,
) -> Result<String, AwsError> {
    if !token.len().is_multiple_of(2) {
        return Err(invalid("nextToken is invalid"));
    }
    let bytes = token.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let high = hex_value(pair[0]).ok_or_else(|| invalid("nextToken is invalid"))?;
        let low = hex_value(pair[1]).ok_or_else(|| invalid("nextToken is invalid"))?;
        decoded.push((high << 4) | low);
    }
    let payload = String::from_utf8(decoded).map_err(|_| invalid("nextToken is invalid"))?;
    let parts: Vec<&str> = payload.split('\n').collect();
    if parts.len() != 5
        || parts[0] != kind
        || parts[1] != account
        || parts[2] != region
        || parts[3] != context
        || parts[4].is_empty()
    {
        return Err(invalid("nextToken is invalid for this request scope"));
    }
    Ok(parts[4].to_owned())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn local_registry_endpoint(host: Option<&str>) -> Option<String> {
    let host = host?;
    if host
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b == b'/' || b == b'\\')
    {
        return None;
    }
    let hostname = host.split(':').next()?.to_ascii_lowercase();
    if matches!(hostname.as_str(), "localhost" | "127.0.0.1") {
        Some(format!("http://{host}"))
    } else {
        None
    }
}

fn registry_host_matches_scope(host: &str, scope: &RegistryToken) -> bool {
    let hostname = host.split(':').next().unwrap_or("").to_ascii_lowercase();
    if matches!(hostname.as_str(), "localhost" | "127.0.0.1") {
        return true;
    }
    hostname == format!("{}.dkr.ecr.{}.amazonaws.com", scope.account, scope.region)
        || hostname == format!("{}.dkr.ecr.{}.localhost", scope.account, scope.region)
}

fn registry_unauthorized() -> Response {
    Response::builder()
        .status(401)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::WWW_AUTHENTICATE, "Basic realm=\"ECR\"")
        .header("docker-distribution-api-version", "registry/2.0")
        .body(Body::from(
            json!({"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]})
                .to_string(),
        ))
        .expect("registry error")
}

fn invalid(message: &str) -> AwsError {
    AwsError::new("InvalidParameterException", message.to_owned(), 400)
}

fn unknown_operation(message: String) -> AwsError {
    AwsError::new("UnknownOperationException", message, 400)
}

fn repository_not_found(name: &str, account: &str) -> AwsError {
    AwsError::new(
        "RepositoryNotFoundException",
        format!(
            "The repository with name '{name}' does not exist in the registry with id '{account}'"
        ),
        400,
    )
}

fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

#[async_trait]
impl NativeHandler for EcrHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        if request.uri.path() == "/v2" || request.uri.path().starts_with("/v2/") {
            return self.handle_registry(request).await;
        }
        let result = if request.method != http::Method::POST {
            Err(unknown_operation(
                "ECR JSON operations require POST".to_owned(),
            ))
        } else if request.uri.path() != "/" || request.uri.query().is_some() {
            Err(invalid("ECR JSON operations require the exact path /"))
        } else {
            let operation = request
                .headers
                .get("x-amz-target")
                .and_then(|value| value.to_str().ok())
                .and_then(|target| target.strip_prefix(&format!("{TARGET_PREFIX}.")))
                .filter(|operation| !operation.is_empty() && !operation.contains('.'));
            match operation {
                None => Err(unknown_operation("x-amz-target is invalid".to_owned())),
                Some(operation) => match serde_json::from_slice::<Value>(&request.body) {
                    Err(error) => Err(AwsError::new(
                        "SerializationException",
                        format!("Could not deserialize request body: {error}"),
                        400,
                    )),
                    Ok(Value::Object(body)) => self.dispatch(&request, operation, &body),
                    Ok(_) => Err(AwsError::new(
                        "SerializationException",
                        "Request body must be a JSON object".to_owned(),
                        400,
                    )),
                },
            }
        };

        match result {
            Ok(value) => Response::builder()
                .status(200)
                .header("content-type", "application/x-amz-json-1.1")
                .header("x-amzn-RequestId", &request.request_id)
                .body(Body::from(value.to_string()))
                .expect("JSON response is valid"),
            Err(error) => error
                .with_request_id(request.request_id.clone())
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

/// Register ECR as a `Native` JSON-1.1 service.
pub fn register(registry: &Arc<ServiceRegistry>) {
    register_with_handle(registry);
}

pub fn register_with_handle(registry: &Arc<ServiceRegistry>) -> Arc<EcrHandler> {
    let handle = Arc::new(EcrHandler::with_registry(registry));
    let handler: Arc<dyn NativeHandler> = handle.clone();
    registry.register_native(
        ServiceName::new("ecr"),
        ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
        handler,
    );
    handle
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Method};
    use tokio::sync::Barrier;

    fn request(op: &str, body: Value) -> ServiceRequest {
        request_in_scope(
            op,
            Bytes::from(body.to_string()),
            "us-east-1",
            "000000000000",
        )
    }

    fn request_in_scope(op: &str, body: Bytes, region: &str, account: &str) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("{TARGET_PREFIX}.{op}")).unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body,
            region: region.to_owned(),
            account_id: account.to_owned(),
            request_id: "rid".to_owned(),
        }
    }

    async fn response(handler: &EcrHandler, request: ServiceRequest) -> (u16, HeaderMap, Value) {
        let response = handler.handle(request).await;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, headers, body)
    }

    async fn call(handler: &EcrHandler, op: &str, body: Value) -> (u16, Value) {
        let (status, _, body) = response(handler, request(op, body)).await;
        (status, body)
    }

    fn assert_error(body: &Value, kind: &str) {
        assert!(body["__type"].as_str().unwrap().contains(kind), "{body}");
    }

    #[tokio::test]
    async fn validates_method_path_target_and_json_object_body() {
        let handler = EcrHandler::new();

        let mut malformed = request_in_scope(
            "DescribeRepositories",
            Bytes::from_static(b"{"),
            "us-east-1",
            "000000000000",
        );
        let (status, _, body) = response(&handler, malformed.clone()).await;
        assert_eq!(status, 400);
        assert_error(&body, "SerializationException");

        malformed.body = Bytes::from_static(b"[]");
        let (_, _, body) = response(&handler, malformed).await;
        assert_error(&body, "SerializationException");

        let mut bad_method = request("DescribeRepositories", json!({}));
        bad_method.method = Method::GET;
        let (_, _, body) = response(&handler, bad_method).await;
        assert_error(&body, "UnknownOperationException");

        let mut bad_path = request("DescribeRepositories", json!({}));
        bad_path.uri = "/repositories".parse().unwrap();
        let (_, _, body) = response(&handler, bad_path).await;
        assert_error(&body, "InvalidParameterException");

        let mut bad_target = request("DescribeRepositories", json!({}));
        bad_target.headers.insert(
            "x-amz-target",
            HeaderValue::from_static("Wrong.DescribeRepositories"),
        );
        let (_, _, body) = response(&handler, bad_target).await;
        assert_error(&body, "UnknownOperationException");
    }

    #[tokio::test]
    async fn validates_registry_id_and_repository_names() {
        let handler = EcrHandler::new();
        for registry_id in [json!(123), json!("123"), json!("111111111111")] {
            let (status, body) = call(
                &handler,
                "CreateRepository",
                json!({ "repositoryName": "valid-name", "registryId": registry_id }),
            )
            .await;
            assert_eq!(status, 400);
            assert_error(&body, "InvalidParameterException");
        }

        for name in [
            "a",
            "Upper",
            "/repo",
            "repo/",
            "repo//name",
            "repo..name",
            "repo_-name",
            "repo-",
            "répo",
        ] {
            let (status, body) = call(
                &handler,
                "CreateRepository",
                json!({ "repositoryName": name }),
            )
            .await;
            assert_eq!(status, 400, "{name}");
            assert_error(&body, "InvalidParameterException");
        }
        let (status, _) = call(
            &handler,
            "CreateRepository",
            json!({
                "repositoryName": "team_1/service.name-v2",
                "registryId": "000000000000"
            }),
        )
        .await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn duplicate_create_is_atomic_and_preserves_metadata() {
        let handler = EcrHandler::new();
        let create = json!({
            "repositoryName": "team/app",
            "imageTagMutability": "IMMUTABLE",
            "imageScanningConfiguration": { "scanOnPush": true },
            "encryptionConfiguration": { "encryptionType": "KMS", "kmsKey": "alias/ecr" },
            "tags": []
        });
        let (status, first) = call(&handler, "CreateRepository", create).await;
        assert_eq!(status, 200);
        let created_at = first["repository"]["createdAt"].clone();
        assert_eq!(first["repository"]["imageTagMutability"], "IMMUTABLE");
        assert_eq!(
            first["repository"]["imageScanningConfiguration"]["scanOnPush"],
            true
        );
        assert_eq!(
            first["repository"]["encryptionConfiguration"],
            json!({ "encryptionType": "KMS", "kmsKey": "alias/ecr" })
        );

        let (status, body) = call(
            &handler,
            "CreateRepository",
            json!({ "repositoryName": "team/app" }),
        )
        .await;
        assert_eq!(status, 400);
        assert_error(&body, "RepositoryAlreadyExistsException");
        let (_, described) = call(
            &handler,
            "DescribeRepositories",
            json!({ "repositoryNames": ["team/app"] }),
        )
        .await;
        assert_eq!(described["repositories"][0]["createdAt"], created_at);
        assert_eq!(
            described["repositories"][0]["imageTagMutability"],
            "IMMUTABLE"
        );
    }

    #[tokio::test]
    async fn concurrent_create_has_exactly_one_success() {
        let handler = Arc::new(EcrHandler::new());
        let barrier = Arc::new(Barrier::new(16));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let handler = Arc::clone(&handler);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                response(
                    &handler,
                    request("CreateRepository", json!({ "repositoryName": "race-repo" })),
                )
                .await
                .0
            }));
        }
        let mut success_count = 0;
        for task in tasks {
            if task.await.unwrap() == 200 {
                success_count += 1;
            }
        }
        assert_eq!(success_count, 1);
    }

    #[tokio::test]
    async fn rejects_invalid_create_shapes_and_enums() {
        let handler = EcrHandler::new();
        let invalid_bodies = [
            json!({ "repositoryName": "repo-one", "imageTagMutability": "BROKEN" }),
            json!({ "repositoryName": "repo-two", "imageScanningConfiguration": true }),
            json!({ "repositoryName": "repo-three", "imageScanningConfiguration": {} }),
            json!({ "repositoryName": "repo-four", "encryptionConfiguration": { "encryptionType": "KMS" } }),
            json!({ "repositoryName": "repo-five", "encryptionConfiguration": { "encryptionType": "AES256", "kmsKey": "x" } }),
            json!({ "repositoryName": "repo-six", "tags": [{ "Key": "x", "Value": "y" }] }),
        ];
        for body in invalid_bodies {
            let (status, response_body) = call(&handler, "CreateRepository", body).await;
            assert_eq!(status, 400);
            assert_error(&response_body, "InvalidParameterException");
        }
    }

    #[tokio::test]
    async fn describe_is_scoped_and_named_input_is_strict() {
        let handler = EcrHandler::new();
        let (_, _, _) = response(
            &handler,
            request_in_scope(
                "CreateRepository",
                Bytes::from(json!({ "repositoryName": "scoped-repo" }).to_string()),
                "us-west-2",
                "000000000000",
            ),
        )
        .await;
        let (status, _, body) = response(
            &handler,
            request_in_scope(
                "DescribeRepositories",
                Bytes::from(json!({ "repositoryNames": ["scoped-repo"] }).to_string()),
                "us-east-1",
                "000000000000",
            ),
        )
        .await;
        assert_eq!(status, 400);
        assert_error(&body, "RepositoryNotFoundException");

        for body in [
            json!({ "repositoryNames": [] }),
            json!({ "repositoryNames": [4] }),
            json!({ "repositoryNames": ["one-repo", "one-repo"] }),
            json!({ "repositoryNames": ["one-repo"], "maxResults": 2 }),
            json!({ "repositoryNames": ["one-repo"], "nextToken": "token" }),
        ] {
            let (_, response_body) = call(&handler, "DescribeRepositories", body).await;
            assert_error(&response_body, "InvalidParameterException");
        }
    }

    #[tokio::test]
    async fn describe_pagination_is_complete_deterministic_and_scope_bound() {
        let handler = EcrHandler::new();
        for name in ["repo-e", "repo-a", "repo-d", "repo-b", "repo-c"] {
            let (status, _) = call(
                &handler,
                "CreateRepository",
                json!({ "repositoryName": name }),
            )
            .await;
            assert_eq!(status, 200);
        }

        let mut token: Option<String> = None;
        let mut names = Vec::new();
        loop {
            let mut input = json!({ "maxResults": 2 });
            if let Some(value) = &token {
                input["nextToken"] = Value::String(value.clone());
            }
            let (status, body) = call(&handler, "DescribeRepositories", input).await;
            assert_eq!(status, 200);
            names.extend(
                body["repositories"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|repo| repo["repositoryName"].as_str().unwrap().to_owned()),
            );
            token = body
                .get("nextToken")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if token.is_none() {
                break;
            }
        }
        assert_eq!(names, ["repo-a", "repo-b", "repo-c", "repo-d", "repo-e"]);
        assert_eq!(names.iter().collect::<HashSet<_>>().len(), names.len());

        let (_, body) = call(
            &handler,
            "DescribeRepositories",
            json!({ "nextToken": "not-hex" }),
        )
        .await;
        assert_error(&body, "InvalidParameterException");

        let (_, first_page) =
            call(&handler, "DescribeRepositories", json!({ "maxResults": 1 })).await;
        let scoped_token = first_page["nextToken"].as_str().unwrap();
        let request = request_in_scope(
            "DescribeRepositories",
            Bytes::from(json!({ "nextToken": scoped_token }).to_string()),
            "us-west-2",
            "000000000000",
        );
        let (_, _, body) = response(&handler, request).await;
        assert_error(&body, "InvalidParameterException");
    }

    #[tokio::test]
    async fn list_images_requires_repo_and_validates_inputs() {
        let handler = EcrHandler::new();
        let (status, body) = call(
            &handler,
            "ListImages",
            json!({ "repositoryName": "missing-repo" }),
        )
        .await;
        assert_eq!(status, 400);
        assert_error(&body, "RepositoryNotFoundException");

        call(
            &handler,
            "CreateRepository",
            json!({ "repositoryName": "images-repo" }),
        )
        .await;
        let (status, body) = call(
            &handler,
            "ListImages",
            json!({
                "repositoryName": "images-repo",
                "registryId": "000000000000",
                "filter": { "tagStatus": "TAGGED" },
                "maxResults": 1000
            }),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({ "imageIds": [] }));

        for input in [
            json!({ "repositoryName": "images-repo", "filter": { "tagStatus": "BAD" } }),
            json!({ "repositoryName": "images-repo", "maxResults": 0 }),
            json!({ "repositoryName": "images-repo", "nextToken": "foreign" }),
            json!({ "repositoryName": "images-repo", "registryId": "111111111111" }),
        ] {
            let (_, response_body) = call(&handler, "ListImages", input).await;
            assert_error(&response_body, "InvalidParameterException");
        }
    }

    #[tokio::test]
    async fn batch_delete_returns_one_not_found_failure_per_valid_id() {
        let handler = EcrHandler::new();
        call(
            &handler,
            "CreateRepository",
            json!({ "repositoryName": "batch-repo" }),
        )
        .await;
        let digest = format!("sha256:{}", "a".repeat(64));
        let image_ids = json!([
            { "imageTag": "latest" },
            { "imageDigest": digest, "imageTag": "stable" }
        ]);
        let (status, body) = call(
            &handler,
            "BatchDeleteImage",
            json!({ "repositoryName": "batch-repo", "imageIds": image_ids }),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body["imageIds"], json!([]));
        assert_eq!(body["failures"].as_array().unwrap().len(), 2);
        assert_eq!(
            body["failures"][0]["imageId"],
            json!({ "imageTag": "latest" })
        );
        assert_eq!(body["failures"][0]["failureCode"], "ImageNotFound");
        assert_eq!(
            body["failures"][1]["imageId"],
            json!({ "imageDigest": digest, "imageTag": "stable" })
        );

        for input in [
            json!({ "repositoryName": "missing-repo", "imageIds": [{ "imageTag": "x" }] }),
            json!({ "repositoryName": "batch-repo", "imageIds": [] }),
            json!({ "repositoryName": "batch-repo", "imageIds": [{}] }),
            json!({ "repositoryName": "batch-repo", "imageIds": [{ "imageDigest": "bad" }] }),
        ] {
            let (status, response_body) = call(&handler, "BatchDeleteImage", input).await;
            assert_eq!(status, 400);
            assert!(response_body["__type"].is_string());
        }
    }

    #[tokio::test]
    async fn delete_validates_force_and_repeated_delete_is_not_found() {
        let handler = EcrHandler::new();
        call(
            &handler,
            "CreateRepository",
            json!({ "repositoryName": "delete-repo" }),
        )
        .await;
        let (_, body) = call(
            &handler,
            "DeleteRepository",
            json!({ "repositoryName": "delete-repo", "force": "true" }),
        )
        .await;
        assert_error(&body, "InvalidParameterException");
        let (status, _) = call(
            &handler,
            "DeleteRepository",
            json!({ "repositoryName": "delete-repo", "force": true }),
        )
        .await;
        assert_eq!(status, 200);
        let (status, body) = call(
            &handler,
            "DeleteRepository",
            json!({ "repositoryName": "delete-repo" }),
        )
        .await;
        assert_eq!(status, 400);
        assert_error(&body, "RepositoryNotFoundException");
    }

    fn registry_request(
        method: Method,
        path: &str,
        body: &[u8],
        account: &str,
        content_type: Option<&str>,
    ) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        if let Some(media_type) = content_type {
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
            region: "us-east-1".into(),
            account_id: account.into(),
            request_id: "rid".into(),
        }
    }
    async fn push_registry_blob(handler: &EcrHandler, account: &str, content: &[u8]) -> String {
        use sha2::Digest;
        let digest = format!("sha256:{:x}", sha2::Sha256::digest(content));
        let start = handler
            .registry_v2
            .handle(registry_request(
                Method::POST,
                "/v2/team/app/blobs/uploads/",
                b"",
                account,
                None,
            ))
            .await;
        assert_eq!(start.status(), 202);
        let location = start.headers()[http::header::LOCATION].to_str().unwrap();
        let finish = handler
            .registry_v2
            .handle(registry_request(
                Method::PUT,
                &format!("{location}?digest={digest}"),
                content,
                account,
                None,
            ))
            .await;
        assert_eq!(finish.status(), 201);
        digest
    }
    #[tokio::test]
    async fn control_plane_repository_lifecycle_tracks_private_registry_images() {
        let handler = EcrHandler::new();
        let account = "000000000000";
        let (status, _) = call(
            &handler,
            "CreateRepository",
            json!({"repositoryName":"team/app"}),
        )
        .await;
        assert_eq!(status, 200);
        let config = b"{}";
        let layer = b"layer";
        let config_digest = push_registry_blob(&handler, account, config).await;
        let layer_digest = push_registry_blob(&handler, account, layer).await;
        let manifest = json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":config_digest,"size":config.len()},
            "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":layer_digest,"size":layer.len()}]}).to_string();
        let pushed = handler
            .registry_v2
            .handle(registry_request(
                Method::PUT,
                "/v2/team/app/manifests/latest",
                manifest.as_bytes(),
                account,
                Some("application/vnd.oci.image.manifest.v1+json"),
            ))
            .await;
        assert_eq!(pushed.status(), 201);
        let digest = pushed.headers()["docker-content-digest"]
            .to_str()
            .unwrap()
            .to_owned();
        let (status, listed) =
            call(&handler, "ListImages", json!({"repositoryName":"team/app"})).await;
        assert_eq!(status, 200);
        assert_eq!(
            listed["imageIds"],
            json!([{"imageDigest":digest,"imageTag":"latest"}])
        );
        let (status, denied) = call(
            &handler,
            "DeleteRepository",
            json!({"repositoryName":"team/app"}),
        )
        .await;
        assert_eq!(status, 400);
        assert_error(&denied, "RepositoryNotEmptyException");
        let (status, listed) =
            call(&handler, "ListImages", json!({"repositoryName":"team/app"})).await;
        assert_eq!(status, 200);
        assert_eq!(listed["imageIds"].as_array().unwrap().len(), 1);
        let other = handler
            .registry_v2
            .handle(registry_request(
                Method::GET,
                &format!("/v2/team/app/manifests/{digest}"),
                b"",
                "111111111111",
                None,
            ))
            .await;
        assert_eq!(other.status(), 404);
        let (status, _) = call(
            &handler,
            "DeleteRepository",
            json!({"repositoryName":"team/app","force":true}),
        )
        .await;
        assert_eq!(status, 200);
        let gone = handler
            .registry_v2
            .handle(registry_request(
                Method::GET,
                &format!("/v2/team/app/manifests/{digest}"),
                b"",
                account,
                None,
            ))
            .await;
        assert_eq!(gone.status(), 404);
        let (status, missing) =
            call(&handler, "ListImages", json!({"repositoryName":"team/app"})).await;
        assert_eq!(status, 400);
        assert_error(&missing, "RepositoryNotFoundException");
    }

    struct TokenPolicy {
        strict: bool,
        allow: bool,
        requests: std::sync::Mutex<Vec<AuthorizationRequest>>,
    }

    impl localcloud_core::integration::authorization::AuthorizationEvaluator for TokenPolicy {
        fn strict_sigv4_required(&self) -> bool {
            self.strict
        }

        fn authorize(
            &self,
            request: AuthorizationRequest,
        ) -> Result<(), localcloud_core::integration::authorization::AuthorizationError> {
            self.requests.lock().unwrap().push(request);
            if self.allow {
                Ok(())
            } else {
                Err(localcloud_core::integration::authorization::AuthorizationError::Denied)
            }
        }
    }

    #[tokio::test]
    async fn registered_handler_without_iam_cannot_issue_token() {
        let registry = Arc::new(ServiceRegistry::new());
        let handler = register_with_handle(&registry);
        let mut issuance = request("GetAuthorizationToken", json!({}));
        issuance.headers.insert(
            http::header::HOST,
            HeaderValue::from_static("127.0.0.1:4566"),
        );
        issuance.headers.insert(
            "x-localcloud-verified-ecr-sigv4",
            HeaderValue::from_static("1"),
        );
        let (status, _, body) = response(&handler, issuance).await;
        assert_eq!(status, 500);
        assert_error(&body, "ServerException");
        assert!(handler.tokens.is_empty());
    }

    #[tokio::test]
    async fn registry_token_requires_identity_policy_before_issuance() {
        for (strict, allow) in [(true, false), (true, true), (false, false)] {
            let expected_issued = !strict || allow;
            let registry = Arc::new(ServiceRegistry::new());
            let handler = register_with_handle(&registry);
            let policy = Arc::new(TokenPolicy {
                strict,
                allow,
                requests: std::sync::Mutex::new(Vec::new()),
            });
            let iam_handler: Arc<dyn NativeHandler> = handler.clone();
            registry.register_native_with_authorization_evaluator(
                ServiceName::new("iam"),
                ServiceMetadata::new(AwsProtocol::Query, None),
                iam_handler,
                policy.clone(),
            );
            let mut issuance = request("GetAuthorizationToken", json!({}));
            issuance.headers.insert(
                http::header::HOST,
                HeaderValue::from_static("127.0.0.1:4566"),
            );
            issuance.headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=AKIATEST/20260925/us-east-1/ecr/aws4_request, SignedHeaders=host, Signature=abc"),
            );
            issuance.headers.insert(
                "x-localcloud-verified-ecr-sigv4",
                HeaderValue::from_static("1"),
            );
            let (status, _, body) = response(&handler, issuance).await;
            assert_eq!(status, if expected_issued { 200 } else { 400 });
            if expected_issued {
                assert!(body["authorizationData"][0]["authorizationToken"].is_string());
                assert_eq!(handler.tokens.len(), 1);
            } else {
                assert_error(&body, "AccessDeniedException");
                assert!(handler.tokens.is_empty());
            }
            let requests = policy.requests.lock().unwrap();
            if !strict {
                assert!(requests.is_empty());
                continue;
            }
            assert_eq!(requests.len(), 1);
            let request = &requests[0];
            assert_eq!(request.request_identity.account_id, "000000000000");
            assert_eq!(
                request.request_identity.access_key_id.as_deref(),
                Some("AKIATEST")
            );
            assert_eq!(request.source_service, "ecr");
            assert_eq!(request.action, "ecr:GetAuthorizationToken");
            assert_eq!(request.resource, "*");
        }
    }

    #[tokio::test]
    async fn registry_token_requires_verified_request_and_basic_auth() {
        let handler = EcrHandler::new();
        let denied = handler
            .handle(registry_request(
                Method::GET,
                "/v2/",
                b"",
                "000000000000",
                None,
            ))
            .await;
        assert_eq!(denied.status(), 401);
        assert_eq!(
            denied.headers()[http::header::WWW_AUTHENTICATE],
            "Basic realm=\"ECR\""
        );
        let mut issuance = request("GetAuthorizationToken", json!({}));
        issuance.headers.insert(
            http::header::HOST,
            HeaderValue::from_static("127.0.0.1:4566"),
        );
        let (status, _, error) = response(&handler, issuance.clone()).await;
        assert_eq!(status, 403);
        assert_error(&error, "SignatureDoesNotMatch");
        issuance.headers.insert(
            "x-localcloud-verified-ecr-sigv4",
            HeaderValue::from_static("1"),
        );
        let (status, _, issued) = response(&handler, issuance).await;
        assert_eq!(status, 200);
        assert_eq!(
            issued["authorizationData"][0]["proxyEndpoint"],
            "http://127.0.0.1:4566"
        );
        let encoded = issued["authorizationData"][0]["authorizationToken"]
            .as_str()
            .unwrap();
        let mut registry = registry_request(Method::GET, "/v2/", b"", "000000000000", None);
        registry.headers.insert(
            http::header::HOST,
            HeaderValue::from_static("127.0.0.1:4566"),
        );
        registry.headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        assert_eq!(handler.handle(registry.clone()).await.status(), 200);
        registry.headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic QVdTOmZvcmdlZA=="),
        );
        assert_eq!(handler.handle(registry).await.status(), 401);
        let password = std::str::from_utf8(
            &base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap(),
        )
        .unwrap()
        .split_once(':')
        .unwrap()
        .1
        .to_owned();
        handler.tokens.get_mut(&password).unwrap().expires_at =
            Instant::now() - Duration::from_secs(1);
        let mut expired = registry_request(Method::GET, "/v2/", b"", "000000000000", None);
        expired.headers.insert(
            http::header::HOST,
            HeaderValue::from_static("127.0.0.1:4566"),
        );
        expired.headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        assert_eq!(handler.handle(expired).await.status(), 401);
    }

    #[tokio::test]
    async fn unsupported_operations_and_success_protocol_are_explicit() {
        let handler = EcrHandler::new();
        let (_, body) = call(&handler, "GetAuthorizationToken", json!({})).await;
        assert_error(&body, "SignatureDoesNotMatch");
        let (status, headers, body) =
            response(&handler, request("DescribeRepositories", json!({}))).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({ "repositories": [] }));
        assert_eq!(headers["content-type"], "application/x-amz-json-1.1");
        assert_eq!(headers["x-amzn-requestid"], "rid");
    }
}
