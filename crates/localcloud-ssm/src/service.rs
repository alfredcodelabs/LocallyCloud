use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use localcloud_state::StateDb;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use localcloud_core::error_mapping::AwsError;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::integration::kms::{
    KmsCallContext, KmsDecryptRequest, KmsEncryptRequest, KmsInternalError, KmsKeySelector,
    KmsServiceKey, SensitiveBytes,
};
use localcloud_core::registry::{AwsProtocol, ServiceRegistry};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::error::SsmError;
use crate::model::{ParameterValue, ParameterValueSnapshot, Scope, SecretString};
use crate::protocol::{
    self, AddTagsToResourceRequest, DeleteParameterRequest, DescribeParametersRequest,
    DescribeParametersResponse, GetParameterRequest, GetParameterResponse,
    ListTagsForResourceRequest, ListTagsForResourceResponse, ParameterMetadataOutput,
    ParameterOutput, PutParameterRequest, PutParameterResponse, RemoveTagsFromResourceRequest,
    TagInput, TagOutput,
};
use crate::store::ParameterStore;

const KMS_CALL_LIMIT: Duration = Duration::from_secs(2);

pub(crate) struct SsmHandler {
    registry: Weak<ServiceRegistry>,
    store: Arc<ParameterStore>,
    persistence_failed: AtomicBool,
}

impl SsmHandler {
    pub(crate) fn new(registry: Weak<ServiceRegistry>) -> Self {
        Self {
            registry,
            store: Arc::new(ParameterStore::new()),
            persistence_failed: AtomicBool::new(false),
        }
    }

    pub(crate) fn with_state(
        registry: Weak<ServiceRegistry>,
        state: Arc<StateDb>,
    ) -> Result<Self, SsmError> {
        Ok(Self {
            registry,
            store: Arc::new(ParameterStore::with_state(state)?),
            persistence_failed: AtomicBool::new(false),
        })
    }

    async fn persist(&self) -> Result<(), SsmError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.save())
            .await
            .map_err(|_| SsmError::Internal)?
    }

    async fn process(&self, request: &ServiceRequest) -> Result<Value, SsmError> {
        if request.method != http::Method::POST
            || request.uri.path() != "/"
            || request.uri.query().is_some()
        {
            return Err(SsmError::UnknownOperation);
        }
        protocol::validate_content_type(&request.headers)?;
        if request.body.len() > protocol::MAX_REQUEST_BODY {
            return Err(SsmError::Validation);
        }
        let operation = protocol::operation(&request.headers)?;
        if !protocol::is_allowed(operation) {
            return Err(SsmError::UnknownOperation);
        }
        let scope = Scope::new(&request.account_id, &request.region);
        match operation {
            "PutParameter" => {
                self.put_parameter(decode(&request.body)?, &scope, request)
                    .await
            }
            "GetParameter" => {
                self.get_parameter(decode(&request.body)?, &scope, request)
                    .await
            }
            "DescribeParameters" => self.describe_parameters(decode(&request.body)?, &scope),
            "DeleteParameter" => self.delete_parameter(decode(&request.body)?, &scope),
            "AddTagsToResource" => self.add_tags(decode(&request.body)?, &scope),
            "RemoveTagsFromResource" => self.remove_tags(decode(&request.body)?, &scope),
            "ListTagsForResource" => self.list_tags(decode(&request.body)?, &scope),
            _ => Err(SsmError::UnknownOperation),
        }
    }

    async fn put_parameter(
        &self,
        request: PutParameterRequest,
        scope: &Scope,
        service_request: &ServiceRequest,
    ) -> Result<Value, SsmError> {
        validate_name(&request.name)?;
        if request.value.len() > 4096 {
            return Err(SsmError::Validation);
        }
        if request
            .description
            .as_ref()
            .is_some_and(|value| value.len() > 1024)
        {
            return Err(SsmError::Validation);
        }
        let parameter_type = request.parameter_type.as_deref().unwrap_or("String");
        if !matches!(parameter_type, "String" | "SecureString") {
            return Err(SsmError::UnsupportedParameterType);
        }
        if request.key_id.is_some() && parameter_type != "SecureString" {
            return Err(SsmError::Validation);
        }
        if request.key_id.as_deref().is_some_and(str::is_empty) {
            return Err(SsmError::InvalidKeyId);
        }
        if request.tier.as_deref().unwrap_or("Standard") != "Standard" {
            return Err(SsmError::Validation);
        }
        if !matches!(request.data_type.as_deref(), None | Some("") | Some("text")) {
            return Err(SsmError::Validation);
        }
        if request
            .allowed_pattern
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            return Err(SsmError::Validation);
        }
        if request
            .policies
            .as_deref()
            .is_some_and(|value| !value.is_empty() && value != "[]")
        {
            return Err(SsmError::Validation);
        }
        let tags = request.tags.map(validate_tags).transpose()?;
        let value = if parameter_type == "SecureString" {
            let key = request
                .key_id
                .as_deref()
                .map_or(KmsKeySelector::ServiceDefault(KmsServiceKey::Ssm), |id| {
                    KmsKeySelector::Explicit(id.to_owned())
                });
            let output = self
                .dispatcher()?
                .kms_encrypt_bounded(
                    KmsEncryptRequest {
                        call: kms_call(service_request, scope),
                        key,
                        plaintext: SensitiveBytes::new(request.value.into_bytes()),
                        encryption_context: encryption_context(scope, &request.name),
                    },
                    KMS_CALL_LIMIT,
                )
                .await
                .map_err(map_kms_error)?;
            ParameterValue::Encrypted {
                ciphertext: output.ciphertext.into_vec(),
                key_arn: output.key_id,
                key_id: request.key_id.unwrap_or_else(|| "alias/aws/ssm".to_owned()),
            }
        } else {
            ParameterValue::Plain(SecretString::new(request.value))
        };
        let version = self.store.put(
            scope,
            request.name,
            value,
            request.description,
            request.overwrite.unwrap_or(false),
            tags,
            now_epoch()?,
        )?;
        serialize(PutParameterResponse {
            version,
            tier: "Standard",
        })
    }

    async fn get_parameter(
        &self,
        request: GetParameterRequest,
        scope: &Scope,
        service_request: &ServiceRequest,
    ) -> Result<Value, SsmError> {
        validate_name(&request.name)?;
        let parameter = self.store.get(scope, &request.name)?;
        let (parameter_type, value) = match parameter.value {
            ParameterValueSnapshot::Plain(value) => ("String", value),
            ParameterValueSnapshot::Encrypted {
                ciphertext,
                key_arn,
            } => {
                if request.with_decryption.unwrap_or(false) {
                    let result = self
                        .dispatcher()?
                        .kms_decrypt_bounded(
                            KmsDecryptRequest {
                                call: kms_call(service_request, scope),
                                key_id: Some(key_arn),
                                ciphertext: SensitiveBytes::new(ciphertext),
                                encryption_context: encryption_context(scope, &parameter.name),
                            },
                            KMS_CALL_LIMIT,
                        )
                        .await
                        .map_err(map_kms_error)?;
                    let plaintext = String::from_utf8(result.plaintext.into_vec())
                        .map_err(|_| SsmError::Internal)?;
                    ("SecureString", plaintext)
                } else {
                    ("SecureString", STANDARD.encode(ciphertext))
                }
            }
        };
        serialize(GetParameterResponse {
            parameter: ParameterOutput {
                arn: scope.parameter_arn(&parameter.name),
                name: parameter.name,
                parameter_type,
                value,
                version: parameter.version,
                last_modified_date: parameter.last_modified_date,
                data_type: "text",
            },
        })
    }

    fn describe_parameters(
        &self,
        request: DescribeParametersRequest,
        scope: &Scope,
    ) -> Result<Value, SsmError> {
        if request.max_results.is_some()
            || request.next_token.is_some()
            || request.shared.unwrap_or(false)
            || (request.filters.is_some() && request.parameter_filters.is_some())
        {
            return Err(SsmError::Validation);
        }

        let exact_name = match (
            request.filters.as_deref(),
            request.parameter_filters.as_deref(),
        ) {
            (None, None) => None,
            (Some([filter]), None) if filter.key == "Name" && filter.values.len() == 1 => {
                Some(filter.values[0].as_str())
            }
            (None, Some([filter]))
                if filter.key == "Name"
                    && filter.option.as_deref().unwrap_or("Equals") == "Equals"
                    && filter.values.len() == 1 =>
            {
                Some(filter.values[0].as_str())
            }
            _ => return Err(SsmError::Validation),
        };
        if let Some(name) = exact_name {
            validate_name(name)?;
        }

        let parameters = self
            .store
            .describe(scope, exact_name)
            .into_iter()
            .map(|parameter| ParameterMetadataOutput {
                name: parameter.name,
                parameter_type: parameter.parameter_type,
                description: parameter.description,
                key_id: parameter.key_id,
                last_modified_date: parameter.last_modified_date,
                version: parameter.version,
                tier: "Standard",
                data_type: "text",
            })
            .collect();
        serialize(DescribeParametersResponse { parameters })
    }

    fn delete_parameter(
        &self,
        request: DeleteParameterRequest,
        scope: &Scope,
    ) -> Result<Value, SsmError> {
        validate_name(&request.name)?;
        self.store.delete(scope, &request.name)?;
        Ok(json!({}))
    }

    fn add_tags(
        &self,
        request: AddTagsToResourceRequest,
        scope: &Scope,
    ) -> Result<Value, SsmError> {
        validate_resource(&request.resource_type, &request.resource_id)?;
        let tags = validate_tags(request.tags)?;
        if tags.is_empty() {
            return Err(SsmError::Validation);
        }
        self.store.add_tags(scope, &request.resource_id, tags)?;
        Ok(json!({}))
    }

    fn remove_tags(
        &self,
        request: RemoveTagsFromResourceRequest,
        scope: &Scope,
    ) -> Result<Value, SsmError> {
        validate_resource(&request.resource_type, &request.resource_id)?;
        if request.tag_keys.is_empty() || request.tag_keys.len() > 50 {
            return Err(SsmError::Validation);
        }
        let mut unique = BTreeSet::new();
        for key in &request.tag_keys {
            validate_tag_key(key)?;
            if !unique.insert(key) {
                return Err(SsmError::Validation);
            }
        }
        self.store
            .remove_tags(scope, &request.resource_id, &request.tag_keys)?;
        Ok(json!({}))
    }

    fn list_tags(
        &self,
        request: ListTagsForResourceRequest,
        scope: &Scope,
    ) -> Result<Value, SsmError> {
        validate_resource(&request.resource_type, &request.resource_id)?;
        let tag_list = self
            .store
            .list_tags(scope, &request.resource_id)?
            .into_iter()
            .map(|(key, value)| TagOutput { key, value })
            .collect();
        serialize(ListTagsForResourceResponse { tag_list })
    }

    fn dispatcher(
        &self,
    ) -> Result<Arc<localcloud_core::integration::InternalDispatcher>, SsmError> {
        self.registry
            .upgrade()
            .and_then(|registry| registry.internal_dispatcher())
            .ok_or(SsmError::Internal)
    }
}

fn kms_call(request: &ServiceRequest, scope: &Scope) -> KmsCallContext {
    KmsCallContext {
        source_service: "ssm".to_owned(),
        account_id: scope.account_id.clone(),
        region: scope.region.clone(),
        request_id: request.request_id.clone(),
        caller_arn: None,
        iam_policy_allowed: false,
    }
}

fn encryption_context(scope: &Scope, name: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("PARAMETER_ARN".to_owned(), scope.parameter_arn(name))])
}

fn map_kms_error(error: KmsInternalError) -> SsmError {
    match error {
        KmsInternalError::Unavailable | KmsInternalError::Internal => SsmError::Internal,
        _ => SsmError::InvalidKeyId,
    }
}

#[async_trait]
impl NativeHandler for SsmHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let result = if self.persistence_failed.load(Ordering::Acquire) {
            Err(SsmError::Internal)
        } else {
            let write = protocol::operation(&request.headers).is_ok_and(|op| {
                matches!(
                    op,
                    "PutParameter"
                        | "DeleteParameter"
                        | "AddTagsToResource"
                        | "RemoveTagsFromResource"
                )
            });
            let result = self.process(&request).await;
            if write && result.is_ok() && self.persist().await.is_err() {
                self.persistence_failed.store(true, Ordering::Release);
                Err(SsmError::Internal)
            } else {
                result
            }
        };
        match result {
            Ok(value) => Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, protocol::CONTENT_TYPE)
                .header("x-amzn-RequestId", &request.request_id)
                .body(Body::from(value.to_string()))
                .expect("SSM JSON response is valid"),
            Err(error) => AwsError::from(error)
                .with_request_id(request.request_id)
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, SsmError> {
    serde_json::from_slice(body).map_err(|_| SsmError::Serialization)
}

fn serialize<T: serde::Serialize>(value: T) -> Result<Value, SsmError> {
    serde_json::to_value(value).map_err(|_| SsmError::Internal)
}

fn now_epoch() -> Result<f64, SsmError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|_| SsmError::Internal)
}

fn validate_name(name: &str) -> Result<(), SsmError> {
    if name.is_empty()
        || name.len() > 1011
        || name.trim() != name
        || name.ends_with('/')
        || name.contains("//")
        || name.contains(':')
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/_.-".contains(character))
    {
        return Err(SsmError::Validation);
    }
    let segments: Vec<&str> = name
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() || segments.len() > 15 {
        return Err(SsmError::Validation);
    }
    let first = segments[0].to_ascii_lowercase();
    if first.starts_with("aws") || first.starts_with("ssm") {
        return Err(SsmError::Validation);
    }
    Ok(())
}

fn validate_resource(resource_type: &str, resource_id: &str) -> Result<(), SsmError> {
    if resource_type != "Parameter" {
        return Err(SsmError::InvalidResourceType);
    }
    validate_name(resource_id)
}

fn validate_tags(tags: Vec<TagInput>) -> Result<BTreeMap<String, String>, SsmError> {
    if tags.len() > 50 {
        return Err(SsmError::Validation);
    }
    let mut result = BTreeMap::new();
    for tag in tags {
        validate_tag_key(&tag.key)?;
        if tag.value.len() > 256 || result.insert(tag.key, tag.value).is_some() {
            return Err(SsmError::Validation);
        }
    }
    Ok(result)
}

fn validate_tag_key(key: &str) -> Result<(), SsmError> {
    if key.is_empty() || key.len() > 128 || key.to_ascii_lowercase().starts_with("aws:") {
        Err(SsmError::Validation)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use axum::body::{to_bytes, Bytes};

    fn request(operation: &str, body: Value) -> ServiceRequest {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            protocol::CONTENT_TYPE.parse().unwrap(),
        );
        headers.insert(
            "x-amz-target",
            format!("AmazonSSM.{operation}").parse().unwrap(),
        );
        ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: Bytes::from(body.to_string()),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "test".into(),
        }
    }

    #[tokio::test]
    async fn parameter_and_tags_survive_restart() {
        let registry = ServiceRegistry::with_known_services();
        let path = std::env::temp_dir()
            .join(format!("localcloud-ssm-{}", uuid::Uuid::new_v4()))
            .join("state.sqlite3");
        let state = Arc::new(StateDb::open(path).unwrap());
        let handler = SsmHandler::with_state(Arc::downgrade(&registry), state.clone()).unwrap();
        let put = handler.handle(request("PutParameter", json!({"Name":"/etl/config","Value":"v1","Type":"String","Tags":[{"Key":"team","Value":"data"}]}))).await;
        assert_eq!(put.status(), http::StatusCode::OK);
        drop(handler);
        let restarted = SsmHandler::with_state(Arc::downgrade(&registry), state).unwrap();
        let get = restarted
            .handle(request("GetParameter", json!({"Name":"/etl/config"})))
            .await;
        assert_eq!(get.status(), http::StatusCode::OK);
        let body = to_bytes(get.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["Parameter"]["Value"],
            "v1"
        );
        assert_eq!(
            restarted
                .store
                .list_tags(&Scope::new("000000000000", "us-east-1"), "/etl/config")
                .unwrap(),
            vec![("team".to_owned(), "data".to_owned())]
        );
    }

    #[tokio::test]
    async fn sqlite_failure_never_acknowledges_parameter_write() {
        let registry = ServiceRegistry::with_known_services();
        let path = std::env::temp_dir()
            .join(format!("localcloud-ssm-{}", uuid::Uuid::new_v4()))
            .join("state.sqlite3");
        let state = Arc::new(StateDb::open(path).unwrap());
        let handler = SsmHandler::with_state(Arc::downgrade(&registry), state.clone()).unwrap();
        state
            .connection()
            .unwrap()
            .execute("DROP TABLE ssm_parameters", [])
            .unwrap();
        let put = handler
            .handle(request(
                "PutParameter",
                json!({"Name":"/etl/config","Value":"v1","Type":"String"}),
            ))
            .await;
        assert_eq!(put.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
        let get = handler
            .handle(request("GetParameter", json!({"Name":"/etl/config"})))
            .await;
        assert_eq!(get.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    }
}
