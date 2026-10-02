//! Lambda service handler: REST-JSON routing, registered `Native` in the Core registry.

mod authorization;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{json, Value};
use tokio::task::JoinHandle;

use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::integration::correlation::CorrelationContext;
use localcloud_core::integration::delivery::{
    AsyncDeliveryPolicy, CrossServiceCall, DeliveryEngine,
};
use localcloud_core::integration::identity::CallerIdentity;
use localcloud_core::integration::lambda::{
    LambdaCallContext, LambdaFunctionError, LambdaInternalApi, LambdaInternalError,
    LambdaInvokeOutput, LambdaInvokeRequest, SensitivePayload,
};
use localcloud_core::integration::pattern::IntegrationPatternId;
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use localcloud_ec2::Ec2Handler;

use crate::concurrency::{ConcurrencyLimiter, DEFAULT_REGION_LIMIT};
use crate::control_plane::{
    add_permission, create_alias, create_function, create_function_url_config, delete_alias,
    delete_function, delete_function_concurrency, delete_function_event_invoke_config,
    delete_function_url_config, delete_layer_version, delete_provisioned_concurrency, get_alias,
    get_function, get_function_code_signing_config, get_function_concurrency,
    get_function_configuration, get_function_event_invoke_config, get_function_url_config,
    get_layer_version, get_policy, get_provisioned_concurrency, list_aliases,
    list_function_event_invoke_configs, list_functions, list_layer_versions, list_layers,
    list_provisioned_concurrency, list_tags, list_versions_by_function, parse_layers,
    publish_layer_version, publish_version, put_function_concurrency,
    put_function_event_invoke_config, put_provisioned_concurrency, remove_permission, tag_resource,
    untag_resource, update_alias, update_function_code, update_function_configuration,
    update_function_event_invoke_config, update_function_url_config,
};
use crate::error::LambdaError;
use crate::esm::{
    create_mapping, parse_batching_window, poll_once, update_response_types,
    validate_batch_configuration, validate_batch_size, BatchSource, EsmStore, SourceType,
    SqsBatchSource,
};
use crate::executor::{DestinationRouter, Executor};
use crate::model::{function_arn, resolve_function_name, FunctionStore, LayerStore, VpcConfig};
use crate::runtime_api::{FunctionErrorType, Outcome};

/// The natively-implemented Lambda service.
pub struct LambdaHandler {
    store: Arc<FunctionStore>,
    layers: Arc<LayerStore>,
    esm: Arc<EsmStore>,
    /// Weak access to sibling native services, used to resolve local S3 deployment artifacts
    /// without creating a registry → handler → registry ownership cycle.
    registry: Weak<ServiceRegistry>,
    ec2: Mutex<Option<Arc<Ec2Handler>>>,
    /// Present when the data plane is wired; absent handlers reject invoke with 501.
    executor: Option<Arc<Executor>>,
    concurrency: Arc<ConcurrencyLimiter>,
    esm_workers: Mutex<HashMap<String, JoinHandle<()>>>,
}

impl Default for LambdaHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl LambdaHandler {
    pub fn new() -> Self {
        Self::with_parts(Weak::new(), None)
    }

    fn with_parts(registry: Weak<ServiceRegistry>, executor: Option<Arc<Executor>>) -> Self {
        let layers = executor
            .as_ref()
            .map(|executor| executor.layer_store())
            .unwrap_or_else(|| Arc::new(LayerStore::new()));
        LambdaHandler {
            store: Arc::new(FunctionStore::new()),
            layers,
            esm: Arc::new(EsmStore::new()),
            registry,
            ec2: Mutex::new(None),
            executor,
            concurrency: ConcurrencyLimiter::new(DEFAULT_REGION_LIMIT),
            esm_workers: Mutex::new(HashMap::new()),
        }
    }

    /// Inject the EC2 control plane used to validate Lambda VPC selections.
    pub fn attach_ec2(&self, ec2: Arc<Ec2Handler>) {
        if let Some(executor) = &self.executor {
            executor.attach_ec2(ec2.clone());
        }
        *self.ec2.lock().unwrap() = Some(ec2);
    }

    fn validate_vpc_config(
        &self,
        account: &str,
        region: &str,
        input: &Value,
    ) -> Result<Option<Option<VpcConfig>>, LambdaError> {
        let Some(raw) = input.get("VpcConfig") else {
            return Ok(None);
        };
        let object = raw.as_object().ok_or_else(|| {
            LambdaError::InvalidParameterValue("VpcConfig must be an object".into())
        })?;
        let ids = |field: &str, max: usize| -> Result<Vec<String>, LambdaError> {
            let Some(value) = object.get(field) else {
                return Ok(Vec::new());
            };
            let entries = value.as_array().ok_or_else(|| {
                LambdaError::InvalidParameterValue(format!("VpcConfig.{field} must be an array"))
            })?;
            if entries.len() > max {
                return Err(LambdaError::InvalidParameterValue(format!(
                    "VpcConfig.{field} exceeds the limit of {max}"
                )));
            }
            let mut unique = HashSet::new();
            let mut output = Vec::with_capacity(entries.len());
            for entry in entries {
                let id = entry.as_str().filter(|id| !id.is_empty()).ok_or_else(|| {
                    LambdaError::InvalidParameterValue(format!(
                        "VpcConfig.{field} must contain nonempty resource IDs"
                    ))
                })?;
                if !unique.insert(id) {
                    return Err(LambdaError::InvalidParameterValue(format!(
                        "VpcConfig.{field} contains duplicate ID {id}"
                    )));
                }
                output.push(id.to_string());
            }
            Ok(output)
        };
        let subnet_ids = ids("SubnetIds", 16)?;
        let security_group_ids = ids("SecurityGroupIds", 5)?;
        let ipv6 = match object.get("Ipv6AllowedForDualStack") {
            None => false,
            Some(value) => value.as_bool().ok_or_else(|| {
                LambdaError::InvalidParameterValue(
                    "VpcConfig.Ipv6AllowedForDualStack must be a boolean".into(),
                )
            })?,
        };
        if ipv6 {
            return Err(LambdaError::InvalidParameterValue(
                "IPv6 VPC networking is not supported by the IPv4-only EC2 network".into(),
            ));
        }
        if subnet_ids.is_empty() && security_group_ids.is_empty() {
            return Ok(Some(None));
        }
        if subnet_ids.is_empty() || security_group_ids.is_empty() {
            return Err(LambdaError::InvalidParameterValue(
                "VpcConfig requires both SubnetIds and SecurityGroupIds".into(),
            ));
        }
        let ec2 = self.ec2.lock().unwrap().clone().ok_or_else(|| {
            LambdaError::InvalidParameterValue("EC2 VPC service is unavailable".into())
        })?;
        let lease = ec2
            .network_selection_lease(account, region, &subnet_ids, &security_group_ids)
            .ok_or_else(|| {
                LambdaError::InvalidParameterValue(
                    "VPC subnets and security groups must exist in one VPC in this account and region"
                        .into(),
                )
            })?;
        Ok(Some(Some(VpcConfig {
            subnet_ids,
            security_group_ids,
            vpc_id: lease.vpc_id.clone(),
            ipv6_allowed_for_dual_stack: false,
            lease: Some(lease),
        })))
    }

    /// Build a handler with the data plane wired to `executor`.
    pub fn with_executor(executor: Arc<Executor>) -> Self {
        Self::with_parts(Weak::new(), Some(executor))
    }

    fn validate_layer_references(
        &self,
        region: &str,
        account: &str,
        input: &Value,
    ) -> Result<(), LambdaError> {
        if input.get("Layers").is_none() {
            return Ok(());
        }
        for arn in parse_layers(input)? {
            let parts: Vec<&str> = arn.split(':').collect();
            if parts.len() != 8
                || parts[..4] != ["arn", "aws", "lambda", region]
                || parts[4] != account
                || parts[5] != "layer"
                || parts[6].is_empty()
            {
                return Err(LambdaError::InvalidParameterValue(format!(
                    "invalid layer version ARN: {arn}"
                )));
            }
            let version = parts[7].parse::<u64>().map_err(|_| {
                LambdaError::InvalidParameterValue(format!("invalid layer version ARN: {arn}"))
            })?;
            if self
                .layers
                .get_version(account, region, parts[6], version)
                .is_none()
            {
                return Err(LambdaError::ResourceNotFound(format!(
                    "Layer version not found: {arn}"
                )));
            }
        }
        Ok(())
    }

    async fn materialize_s3_zip(
        &self,
        req: &ServiceRequest,
        input: &Value,
        container_field: Option<&str>,
    ) -> Result<Value, LambdaError> {
        let source = match container_field {
            Some(field) => input.get(field).ok_or_else(|| {
                LambdaError::InvalidParameterValue(format!("{field} is required"))
            })?,
            None => input,
        };
        if source.get("S3Bucket").is_none() {
            return Ok(input.clone());
        }
        if source.get("ZipFile").is_some() || source.get("ImageUri").is_some() {
            return Err(LambdaError::InvalidParameterValue(
                "exactly one deployment package source is allowed".into(),
            ));
        }
        let bucket = require_nonempty_string(source, "S3Bucket")?;
        let key = require_nonempty_string(source, "S3Key")?;
        let version = optional_nonempty_string(source, "S3ObjectVersion")?;
        let zip = self.fetch_s3_object(req, bucket, key, version).await?;
        crate::code_store::validate_zip(&zip)?;

        let mut resolved = input.clone();
        let destination = match container_field {
            Some(field) => resolved.get_mut(field).and_then(Value::as_object_mut),
            None => resolved.as_object_mut(),
        }
        .ok_or_else(|| {
            LambdaError::InvalidParameterValue("deployment package must be an object".into())
        })?;
        destination.remove("S3Bucket");
        destination.remove("S3Key");
        destination.remove("S3ObjectVersion");
        destination.insert(
            "ZipFile".into(),
            Value::String(base64::engine::general_purpose::STANDARD.encode(zip)),
        );
        Ok(resolved)
    }

    async fn fetch_s3_object(
        &self,
        req: &ServiceRequest,
        bucket: &str,
        key: &str,
        version: Option<&str>,
    ) -> Result<Vec<u8>, LambdaError> {
        let registry = self.registry.upgrade().ok_or_else(|| {
            LambdaError::InvalidParameterValue("local S3 service is unavailable".into())
        })?;
        let handler = registry
            .native_handler(&ServiceName::new("s3"))
            .ok_or_else(|| {
                LambdaError::InvalidParameterValue("local S3 service is unavailable".into())
            })?;
        let mut path = format!("/{}/{}", encode_path(bucket, false), encode_path(key, true));
        if let Some(version) = version {
            path.push_str("?versionId=");
            path.push_str(&encode_path(version, false));
        }
        let mut headers = http::HeaderMap::new();
        headers.insert("host", http::HeaderValue::from_static("localhost:4599"));
        let response = handler
            .handle(ServiceRequest {
                method: Method::GET,
                uri: path.parse().map_err(|_| {
                    LambdaError::InvalidParameterValue("invalid S3 deployment package path".into())
                })?,
                headers,
                body: bytes::Bytes::new(),
                region: req.region.clone(),
                account_id: req.account_id.clone(),
                request_id: req.request_id.clone(),
            })
            .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|_| LambdaError::InternalError("could not read S3 object response".into()))?;
        if !status.is_success() {
            return Err(LambdaError::InvalidParameterValue(format!(
                "could not fetch s3://{bucket}/{key} ({status})"
            )));
        }
        Ok(body.to_vec())
    }

    async fn validate_sqs_event_source(
        &self,
        req: &ServiceRequest,
        source_arn: &str,
    ) -> Result<(), LambdaError> {
        let parts: Vec<&str> = source_arn.split(':').collect();
        if parts.len() != 6 || parts[4].is_empty() || parts[5].is_empty() {
            return Err(LambdaError::InvalidParameterValue(format!(
                "invalid SQS event source ARN: {source_arn}"
            )));
        }
        let registry = self
            .registry
            .upgrade()
            .ok_or_else(|| LambdaError::InternalError("service registry is unavailable".into()))?;
        let handler = registry
            .native_handler(&ServiceName::new("sqs"))
            .ok_or_else(|| LambdaError::InternalError("SQS service is unavailable".into()))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_static("AmazonSQS.GetQueueUrl"),
        );
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-amz-json-1.0"),
        );
        let response = handler
            .handle(ServiceRequest {
                method: Method::POST,
                uri: "/".parse().expect("static SQS URI"),
                headers,
                body: Bytes::from(
                    json!({
                        "QueueName": parts[5],
                        "QueueOwnerAWSAccountId": parts[4],
                    })
                    .to_string(),
                ),
                region: req.region.clone(),
                account_id: req.account_id.clone(),
                request_id: req.request_id.clone(),
            })
            .await;
        if response.status().is_success() {
            Ok(())
        } else if response.status().is_client_error() {
            Err(LambdaError::InvalidParameterValue(format!(
                "SQS event source does not exist: {source_arn}"
            )))
        } else {
            Err(LambdaError::InternalError(format!(
                "could not validate SQS event source: {}",
                response.status()
            )))
        }
    }

    async fn route(&self, req: &ServiceRequest) -> Result<(u16, Option<Value>), LambdaError> {
        let path = req.uri.path().trim_matches('/').to_string();
        let segments: Vec<&str> = if path.is_empty() {
            Vec::new()
        } else {
            path.split('/').collect()
        };
        let (region, account) = (req.region.as_str(), req.account_id.as_str());

        match segments.as_slice() {
            ["2015-03-31", "functions"] => match req.method {
                Method::POST => {
                    let input = parse_json(&req.body)?;
                    let input = self.materialize_s3_zip(req, &input, Some("Code")).await?;
                    self.validate_layer_references(region, account, &input)?;
                    let vpc = self.validate_vpc_config(account, region, &input)?;
                    create_function(&self.store, region, account, &input, vpc)
                }
                Method::GET => list_functions(&self.store, region, account),
                _ => Err(unsupported()),
            },
            ["2015-03-31", "functions", name] => match req.method {
                Method::GET => get_function(&self.store, region, account, name),
                Method::DELETE => {
                    let result = delete_function(&self.store, region, account, name)?;
                    if let (Some(exec), Ok(resolved_name)) =
                        (&self.executor, resolve_function_name(name, region))
                    {
                        exec.invalidate_function_warm(&function_arn(
                            region,
                            account,
                            &resolved_name,
                        ))
                        .await;
                    }
                    Ok(result)
                }
                _ => Err(unsupported()),
            },
            ["2015-03-31", "functions", name, "policy"] => match req.method {
                Method::POST => {
                    let input = parse_json(&req.body)?;
                    add_permission(&self.store, region, account, name, &input)
                }
                Method::GET => get_policy(&self.store, region, account, name),
                _ => Err(unsupported()),
            },
            ["2015-03-31", "functions", name, "policy", statement_id] => match req.method {
                Method::DELETE => {
                    remove_permission(&self.store, region, account, name, statement_id)
                }
                _ => Err(unsupported()),
            },
            ["2015-03-31", "functions", name, "configuration"] => match req.method {
                Method::GET => get_function_configuration(&self.store, region, account, name),
                Method::PUT => {
                    let input = parse_json(&req.body)?;
                    self.validate_layer_references(region, account, &input)?;
                    let vpc = self.validate_vpc_config(account, region, &input)?;
                    let result = update_function_configuration(
                        &self.store,
                        region,
                        account,
                        name,
                        &input,
                        vpc,
                    )?;
                    self.invalidate_warm(region, account, name).await;
                    Ok(result)
                }
                _ => Err(unsupported()),
            },
            ["2015-03-31", "functions", name, "code"] => match req.method {
                Method::PUT => {
                    let input = parse_json(&req.body)?;
                    let input = self.materialize_s3_zip(req, &input, None).await?;
                    let result = update_function_code(&self.store, region, account, name, &input)?;
                    self.invalidate_warm(region, account, name).await;
                    Ok(result)
                }
                _ => Err(unsupported()),
            },
            ["2015-03-31", "functions", name, "versions"] => match req.method {
                Method::POST => publish_version(&self.store, region, account, name),
                Method::GET => list_versions_by_function(&self.store, region, account, name),
                _ => Err(unsupported()),
            },
            ["2015-03-31", "functions", name, "aliases"] => match req.method {
                Method::POST => {
                    let input = parse_json(&req.body)?;
                    create_alias(&self.store, region, account, name, &input)
                }
                Method::GET => list_aliases(&self.store, region, account, name),
                _ => Err(unsupported()),
            },
            ["2015-03-31", "functions", name, "aliases", alias] => match req.method {
                Method::GET => get_alias(&self.store, region, account, name, alias),
                Method::PUT => {
                    let input = parse_json(&req.body)?;
                    update_alias(&self.store, region, account, name, alias, &input)
                }
                Method::DELETE => delete_alias(&self.store, region, account, name, alias),
                _ => Err(unsupported()),
            },
            ["2020-06-30", "functions", name, "code-signing-config"] => match req.method {
                Method::GET => get_function_code_signing_config(&self.store, region, account, name),
                _ => Err(unsupported()),
            },
            ["2017-10-31", "functions", name, "concurrency"] => match req.method {
                Method::PUT => {
                    let input = parse_json(&req.body)?;
                    let result =
                        put_function_concurrency(&self.store, region, account, name, &input)?;
                    if let (Ok(rn), Some(v)) = (
                        resolve_function_name(name, region),
                        input
                            .get("ReservedConcurrentExecutions")
                            .and_then(Value::as_u64),
                    ) {
                        self.concurrency
                            .set_reserved(&function_arn(region, account, &rn), v as u32);
                    }
                    Ok(result)
                }
                Method::GET => get_function_concurrency(&self.store, region, account, name),
                Method::DELETE => {
                    let result = delete_function_concurrency(&self.store, region, account, name)?;
                    if let Ok(rn) = resolve_function_name(name, region) {
                        self.concurrency
                            .clear_reserved(&function_arn(region, account, &rn));
                    }
                    Ok(result)
                }
                _ => Err(unsupported()),
            },
            ["2021-10-31", "functions", name, "url"] => match req.method {
                Method::POST => {
                    let input = parse_json(&req.body)?;
                    create_function_url_config(&self.store, region, account, name, &input)
                }
                Method::GET => get_function_url_config(&self.store, region, account, name),
                Method::PUT => {
                    let input = parse_json(&req.body)?;
                    update_function_url_config(&self.store, region, account, name, &input)
                }
                Method::DELETE => delete_function_url_config(&self.store, region, account, name),
                _ => Err(unsupported()),
            },
            ["2019-09-25", "functions", name, "event-invoke-config"] => match req.method {
                Method::PUT => {
                    let input = parse_json(&req.body)?;
                    put_function_event_invoke_config(&self.store, region, account, name, &input)
                }
                Method::POST => {
                    let input = parse_json(&req.body)?;
                    update_function_event_invoke_config(&self.store, region, account, name, &input)
                }
                Method::GET => get_function_event_invoke_config(&self.store, region, account, name),
                Method::DELETE => {
                    delete_function_event_invoke_config(&self.store, region, account, name)
                }
                _ => Err(unsupported()),
            },
            ["2019-09-25", "functions", name, "event-invoke-config", "list"] => match req.method {
                Method::GET => {
                    list_function_event_invoke_configs(&self.store, region, account, name)
                }
                _ => Err(unsupported()),
            },
            ["2018-10-31", "layers"] => match req.method {
                Method::GET => list_layers(&self.layers, region, account),
                _ => Err(unsupported()),
            },
            ["2018-10-31", "layers", name, "versions"] => match req.method {
                Method::POST => {
                    let input = parse_json(&req.body)?;
                    let input = self
                        .materialize_s3_zip(req, &input, Some("Content"))
                        .await?;
                    publish_layer_version(&self.layers, region, account, name, &input)
                }
                Method::GET => list_layer_versions(&self.layers, region, account, name),
                _ => Err(unsupported()),
            },
            ["2018-10-31", "layers", name, "versions", version] => match req.method {
                Method::GET => get_layer_version(&self.layers, region, account, name, version),
                Method::DELETE => {
                    delete_layer_version(&self.layers, region, account, name, version)
                }
                _ => Err(unsupported()),
            },
            ["2019-09-30", "functions", name, "provisioned-concurrency"] => {
                let query = req.uri.query().unwrap_or("");
                match req.method {
                    Method::PUT => {
                        let qualifier = query_value(query, "Qualifier").unwrap_or_default();
                        let input = parse_json(&req.body)?;
                        put_provisioned_concurrency(
                            &self.store,
                            region,
                            account,
                            name,
                            &qualifier,
                            &input,
                        )
                    }
                    Method::GET => {
                        if query_value(query, "List").is_some() {
                            list_provisioned_concurrency(&self.store, region, account, name)
                        } else {
                            let qualifier = query_value(query, "Qualifier").unwrap_or_default();
                            get_provisioned_concurrency(
                                &self.store,
                                region,
                                account,
                                name,
                                &qualifier,
                            )
                        }
                    }
                    Method::DELETE => {
                        let qualifier = query_value(query, "Qualifier").unwrap_or_default();
                        delete_provisioned_concurrency(
                            &self.store,
                            region,
                            account,
                            name,
                            &qualifier,
                        )
                    }
                    _ => Err(unsupported()),
                }
            }
            ["2015-03-31", "event-source-mappings"] => match req.method {
                Method::POST => {
                    let input = parse_json(&req.body)?;
                    let fn_ref = input
                        .get("FunctionName")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            LambdaError::InvalidParameterValue("FunctionName is required".into())
                        })?;
                    let name = resolve_function_name(fn_ref, region)?;
                    let function = self.store.get(account, region, &name).ok_or_else(|| {
                        LambdaError::ResourceNotFound(format!("Function not found: {name}"))
                    })?;
                    let arn = function.function_arn;
                    let esm = create_mapping(region, &arn, &input)?;
                    if SourceType::from_arn(&esm.event_source_arn) == Some(SourceType::Sqs) {
                        self.validate_sqs_event_source(req, &esm.event_source_arn)
                            .await?;
                    }
                    if !self
                        .esm
                        .list(Some(&esm.function_arn), Some(&esm.event_source_arn))
                        .is_empty()
                    {
                        return Err(LambdaError::ResourceConflict(format!(
                            "event source mapping already exists for {} and {}",
                            esm.function_arn, esm.event_source_arn
                        )));
                    }
                    self.esm.insert(esm.clone());
                    self.reconcile_esm(account, region, &esm);
                    Ok((202, Some(esm.to_json())))
                }
                Method::GET => {
                    let query = req.uri.query().unwrap_or("");
                    let function_filter = query_value(query, "FunctionName")
                        .and_then(|n| resolve_function_name(&n, region).ok())
                        .map(|n| function_arn(region, account, &n));
                    let source_filter = query_value(query, "EventSourceArn");
                    let list: Vec<Value> = self
                        .esm
                        .list(function_filter.as_deref(), source_filter.as_deref())
                        .iter()
                        .map(|e| e.to_json())
                        .collect();
                    Ok((
                        200,
                        Some(serde_json::json!({ "EventSourceMappings": list })),
                    ))
                }
                _ => Err(unsupported()),
            },
            ["2015-03-31", "event-source-mappings", uuid] => match req.method {
                Method::GET => self
                    .esm
                    .get(uuid)
                    .map(|e| (200, Some(e.to_json())))
                    .ok_or_else(|| {
                        LambdaError::ResourceNotFound(format!(
                            "event source mapping not found: {uuid}"
                        ))
                    }),
                Method::PUT => {
                    let input = parse_json(&req.body)?;
                    let existing = self.esm.get(uuid).ok_or_else(|| {
                        LambdaError::ResourceNotFound(format!(
                            "event source mapping not found: {uuid}"
                        ))
                    })?;
                    let batch_size = input
                        .get("BatchSize")
                        .map(|value| {
                            let size = value.as_u64().ok_or_else(|| {
                                LambdaError::InvalidParameterValue(
                                    "BatchSize must be an integer".into(),
                                )
                            })?;
                            validate_batch_size(
                                SourceType::from_arn(&existing.event_source_arn)
                                    .expect("stored event source type"),
                                size,
                            )
                        })
                        .transpose()?;
                    let source_type = SourceType::from_arn(&existing.event_source_arn)
                        .expect("stored event source type");
                    let window =
                        parse_batching_window(&input, existing.maximum_batching_window_in_seconds)?;
                    validate_batch_configuration(
                        source_type,
                        &existing.event_source_arn,
                        batch_size.unwrap_or(existing.batch_size),
                        window,
                    )?;
                    let function_response_types = update_response_types(&input)?;
                    let updated = self
                        .esm
                        .update(uuid, |e| {
                            if let Some(batch_size) = batch_size {
                                e.batch_size = batch_size;
                            }
                            e.maximum_batching_window_in_seconds = window;
                            if let Some(types) = function_response_types {
                                e.function_response_types = types;
                            }
                            if let Some(enabled) = input.get("Enabled").and_then(Value::as_bool) {
                                e.enabled = enabled;
                                e.state = if enabled {
                                    "Enabled".into()
                                } else {
                                    "Disabled".into()
                                };
                            }
                        })
                        .expect("mapping existence checked above");
                    self.reconcile_esm(account, region, &updated);
                    Ok((202, Some(updated.to_json())))
                }
                Method::DELETE => {
                    let removed = self.esm.remove(uuid).ok_or_else(|| {
                        LambdaError::ResourceNotFound(format!(
                            "event source mapping not found: {uuid}"
                        ))
                    })?;
                    self.abort_esm(uuid);
                    Ok((202, Some(removed.to_json())))
                }
                _ => Err(unsupported()),
            },
            ["2017-03-31", "tags", arn] => match req.method {
                Method::GET => list_tags(&self.store, region, account, arn),
                Method::POST => {
                    let input = parse_json(&req.body)?;
                    tag_resource(&self.store, region, account, arn, &input)
                }
                Method::DELETE => {
                    let keys = query_values(req.uri.query().unwrap_or(""), "tagKeys");
                    untag_resource(&self.store, region, account, arn, &keys)
                }
                _ => Err(unsupported()),
            },
            _ => Err(unsupported()),
        }
    }
}

impl LambdaHandler {
    fn reconcile_esm(&self, account: &str, region: &str, mapping: &crate::esm::EventSourceMapping) {
        self.abort_esm(&mapping.uuid);
        if !mapping.enabled
            || self.executor.is_none()
            || SourceType::from_arn(&mapping.event_source_arn) != Some(SourceType::Sqs)
        {
            return;
        }

        let source = match SqsBatchSource::new(
            self.registry.clone(),
            &mapping.event_source_arn,
            account,
            region,
        ) {
            Ok(source) => Arc::new(source) as Arc<dyn BatchSource>,
            Err(error) => {
                tracing::warn!(uuid = %mapping.uuid, %error, "could not start SQS event source mapping");
                return;
            }
        };
        let store = self.esm.clone();
        let registry = self.registry.clone();
        let uuid = mapping.uuid.clone();
        let worker_uuid = uuid.clone();
        let account = account.to_string();
        let region = region.to_string();
        let worker = tokio::spawn(async move {
            while let Some(current) = store.get(&worker_uuid).filter(|item| item.enabled) {
                let result = poll_once(&current, &source, |event| {
                    let registry = registry.clone();
                    let account = account.clone();
                    let region = region.clone();
                    let function_name = current.function_arn.clone();
                    async move {
                        let registry = registry.upgrade()?;
                        let lambda = registry.lambda_api(&ServiceName::new("lambda"))?;
                        let payload = serde_json::to_vec(&event).ok()?;
                        let output = lambda
                            .invoke(LambdaInvokeRequest {
                                call: LambdaCallContext {
                                    source_service: "lambda-esm".into(),
                                    account_id: account,
                                    region,
                                    request_id: uuid::Uuid::new_v4().to_string(),
                                    caller_arn: None,
                                },
                                function_name,
                                qualifier: None,
                                payload: SensitivePayload::new(payload),
                            })
                            .await
                            .ok()?;
                        output
                            .function_error
                            .is_none()
                            .then(|| output.payload.into_vec())
                    }
                })
                .await;
                if let Err(error) = result {
                    tracing::warn!(uuid = %worker_uuid, %error, "SQS event source mapping cycle failed");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        });
        if let Ok(mut workers) = self.esm_workers.lock() {
            workers.retain(|_, worker| !worker.is_finished());
            workers.insert(uuid, worker);
        }
    }

    fn abort_esm(&self, uuid: &str) {
        if let Ok(mut workers) = self.esm_workers.lock() {
            workers.retain(|_, worker| !worker.is_finished());
            if let Some(worker) = workers.remove(uuid) {
                worker.abort();
            }
        }
    }
}

impl LambdaHandler {
    /// Stop background polling before draining all execution environments.
    pub async fn shutdown(&self) {
        let workers = self
            .esm_workers
            .lock()
            .map(|mut workers| {
                workers
                    .drain()
                    .map(|(_, worker)| worker)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for worker in &workers {
            worker.abort();
        }
        for worker in workers {
            let _ = worker.await;
        }
        if let Some(executor) = &self.executor {
            executor.shutdown().await;
        }
    }
}

impl Drop for LambdaHandler {
    fn drop(&mut self) {
        if let Ok(mut workers) = self.esm_workers.lock() {
            for (_, worker) in workers.drain() {
                worker.abort();
            }
        }
    }
}

#[async_trait]
impl NativeHandler for LambdaHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        if let Err(error) = authorization::check(self, &request) {
            return error.into_response(&request.request_id);
        }
        // The data plane (invoke) is async and returns a raw payload, not a JSON envelope.
        if is_invoke_path(&request) {
            return self.invoke(&request).await;
        }
        match self.route(&request).await {
            Ok((status, body)) => json_response(status, body),
            Err(err) => err.into_response(&request.request_id),
        }
    }
}

/// Whether the request targets `POST /2015-03-31/functions/{name}/invocations`.
fn is_invoke_path(req: &ServiceRequest) -> bool {
    if req.method != Method::POST {
        return false;
    }
    let path = req.uri.path().trim_matches('/');
    let segments: Vec<&str> = path.split('/').collect();
    matches!(
        segments.as_slice(),
        ["2015-03-31", "functions", _, "invocations"]
    )
}

impl LambdaHandler {
    /// Handle `POST /2015-03-31/functions/{name}/invocations`.
    async fn invoke(&self, req: &ServiceRequest) -> Response {
        let path = req.uri.path().trim_matches('/').to_string();
        let segments: Vec<&str> = path.split('/').collect();
        let name_ref = percent_decode_path(segments[2]);

        let executor = match &self.executor {
            Some(e) => e.clone(),
            None => {
                return LambdaError::NotImplemented("invocation is not enabled".into())
                    .into_response(&req.request_id)
            }
        };

        let (region, account) = (req.region.as_str(), req.account_id.as_str());
        let name = match resolve_function_name(&name_ref, region) {
            Ok(n) => n,
            Err(e) => return e.into_response(&req.request_id),
        };
        let qualifier = query_value(req.uri.query().unwrap_or(""), "Qualifier");
        let func = match self.resolve_invoke_target(account, region, &name, qualifier.as_deref()) {
            Ok(f) => f,
            Err(e) => return e.into_response(&req.request_id),
        };
        // A function must be Active to be invoked (task 14 state gate).
        if func.state != "Active" {
            return LambdaError::ResourceConflict(format!(
                "The function {name} is currently in the {} state and cannot be invoked",
                func.state
            ))
            .into_response(&req.request_id);
        }

        let invocation_type = req
            .headers
            .get("x-amz-invocation-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("RequestResponse");
        let tail_logs = req
            .headers
            .get("x-amz-log-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("Tail"))
            .unwrap_or(false);

        match invocation_type {
            "DryRun" => empty_status(204),
            "Event" => {
                if req.body.len() > MAX_ASYNC_PAYLOAD {
                    return LambdaError::RequestTooLarge(
                        "async invocation payload exceeds 256 KB".into(),
                    )
                    .into_response(&req.request_id);
                }
                let payload = req.body.to_vec();
                let mut cfg = self.async_config(account, region, &name);
                // The DeadLetterConfig ARN is the OnFailure fallback when no destination is set.
                if cfg.on_failure_arn.is_none() {
                    cfg.on_failure_arn = func.dead_letter_arn.clone();
                }
                let (acct, reg) = (account.to_string(), region.to_string());
                tokio::spawn(async move {
                    executor
                        .invoke_async(&acct, &reg, &func, payload, &cfg)
                        .await;
                });
                empty_status(202)
            }
            "RequestResponse" => {
                if req.body.len() > MAX_SYNC_PAYLOAD {
                    return LambdaError::RequestTooLarge(
                        "invocation payload exceeds the 6 MB limit".into(),
                    )
                    .into_response(&req.request_id);
                }
                // Acquire a concurrency slot (released on drop after the invoke).
                let _slot = match self.concurrency.acquire(&func.function_arn) {
                    Some(guard) => guard,
                    None => {
                        executor.publish_throttle_metric(account, region, &func, &req.request_id);
                        return LambdaError::TooManyRequests(
                            "Rate Exceeded: concurrent execution limit reached".into(),
                        )
                        .into_response(&req.request_id);
                    }
                };
                let payload = req.body.to_vec();
                let trace = req
                    .headers
                    .get("x-amzn-trace-id")
                    .and_then(|v| v.to_str().ok());
                match executor
                    .invoke_sync_traced(account, region, &func, payload, trace)
                    .await
                {
                    Ok(result) => {
                        invoke_response(&func.version, &req.request_id, result, tail_logs)
                    }
                    Err(e) => e.into_response(&req.request_id),
                }
            }
            other => LambdaError::InvalidParameterValue(format!(
                "invalid X-Amz-Invocation-Type: {other}"
            ))
            .into_response(&req.request_id),
        }
    }

    /// Drain the warm pool for a function's `$LATEST` before completing a code/config update.
    async fn invalidate_warm(&self, region: &str, account: &str, name: &str) {
        if let (Some(exec), Ok(resolved_name)) =
            (&self.executor, resolve_function_name(name, region))
        {
            let key = format!("{}:$LATEST", function_arn(region, account, &resolved_name));
            exec.invalidate_warm(&key).await;
        }
    }

    /// Resolve the invocation target for an optional `Qualifier` (version number, alias, or
    /// `$LATEST`/absent). Unknown function or qualifier → `ResourceNotFoundException`.
    fn resolve_invoke_target(
        &self,
        account: &str,
        region: &str,
        name: &str,
        qualifier: Option<&str>,
    ) -> Result<crate::model::LambdaFunction, LambdaError> {
        let not_found = || LambdaError::ResourceNotFound(format!("Function not found: {name}"));
        match qualifier {
            None | Some("") | Some("$LATEST") => {
                self.store.get(account, region, name).ok_or_else(not_found)
            }
            Some(q) => {
                if let Ok(version) = q.parse::<u64>() {
                    self.store
                        .get_version(account, region, name, version)
                        .ok_or_else(not_found)
                } else {
                    let alias = self
                        .store
                        .get_alias(account, region, name, q)
                        .ok_or_else(not_found)?;
                    if alias.function_version == "$LATEST" {
                        self.store.get(account, region, name).ok_or_else(not_found)
                    } else {
                        let version = alias
                            .function_version
                            .parse::<u64>()
                            .map_err(|_| not_found())?;
                        self.store
                            .get_version(account, region, name, version)
                            .ok_or_else(not_found)
                    }
                }
            }
        }
    }

    /// Resolve the effective asynchronous-invocation config for a function (retries default 2;
    /// `OnSuccess`/`OnFailure` destination ARNs from the event-invoke config).
    fn async_config(
        &self,
        account: &str,
        region: &str,
        name: &str,
    ) -> crate::executor::AsyncConfig {
        let cfg = self.store.get_event_invoke_config(account, region, name);
        let max_retry_attempts = cfg
            .as_ref()
            .and_then(|c| c.maximum_retry_attempts)
            .unwrap_or(2);
        let destination = cfg.as_ref().and_then(|c| c.destination_config.clone());
        let arn_at = |key: &str| {
            destination
                .as_ref()
                .and_then(|d| d.get(key))
                .and_then(|o| o.get("Destination"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        crate::executor::AsyncConfig {
            max_retry_attempts,
            on_success_arn: arn_at("OnSuccess"),
            on_failure_arn: arn_at("OnFailure"),
        }
    }
}

#[async_trait]
impl LambdaInternalApi for LambdaHandler {
    async fn invoke(
        &self,
        request: LambdaInvokeRequest,
    ) -> Result<LambdaInvokeOutput, LambdaInternalError> {
        let LambdaInvokeRequest {
            call,
            function_name,
            qualifier,
            payload,
        } = request;
        if call.source_service.is_empty()
            || call.account_id.is_empty()
            || call.region.is_empty()
            || call.request_id.is_empty()
            || function_name.is_empty()
            || payload.as_slice().len() > MAX_SYNC_PAYLOAD
        {
            return Err(LambdaInternalError::InvalidRequest);
        }
        let executor = self
            .executor
            .clone()
            .ok_or(LambdaInternalError::Unavailable)?;
        let name = resolve_function_name(&function_name, &call.region)
            .map_err(map_internal_lambda_error)?;
        let function = self
            .resolve_invoke_target(&call.account_id, &call.region, &name, qualifier.as_deref())
            .map_err(map_internal_lambda_error)?;
        if function.state != "Active" {
            return Err(LambdaInternalError::InvalidState);
        }
        let Some(_slot) = self.concurrency.acquire(&function.function_arn) else {
            executor.publish_throttle_metric(
                &call.account_id,
                &call.region,
                &function,
                &call.request_id,
            );
            return Err(LambdaInternalError::Throttled);
        };
        let executed_version = function.version.clone();
        let result = executor
            .invoke_sync(
                &call.account_id,
                &call.region,
                &function,
                payload.into_vec(),
            )
            .await
            .map_err(map_internal_lambda_error)?;
        let (payload, function_error) = match result.outcome {
            Outcome::Success(payload) => (payload, None),
            Outcome::Error {
                error_type,
                payload,
            } => {
                let function_error = match error_type {
                    FunctionErrorType::Handled => LambdaFunctionError::Handled,
                    FunctionErrorType::Unhandled => LambdaFunctionError::Unhandled,
                };
                (payload, Some(function_error))
            }
        };
        Ok(LambdaInvokeOutput {
            payload: SensitivePayload::new(payload),
            function_error,
            executed_version,
        })
    }
}

fn map_internal_lambda_error(error: LambdaError) -> LambdaInternalError {
    match error {
        LambdaError::ResourceNotFound(_) => LambdaInternalError::NotFound,
        LambdaError::ResourceConflict(_) => LambdaInternalError::InvalidState,
        LambdaError::TooManyRequests(_) => LambdaInternalError::Throttled,
        LambdaError::InvalidParameterValue(_)
        | LambdaError::InvalidRequestContent(_)
        | LambdaError::RequestTooLarge(_) => LambdaInternalError::InvalidRequest,
        LambdaError::AccessDenied(_)
        | LambdaError::CodeStorageExceeded(_)
        | LambdaError::InternalError(_)
        | LambdaError::NotImplemented(_) => LambdaInternalError::Internal,
    }
}

/// AWS synchronous / asynchronous invocation payload caps.
const MAX_SYNC_PAYLOAD: usize = 6 * 1024 * 1024;
const MAX_ASYNC_PAYLOAD: usize = 256 * 1024;

/// Extract a single query parameter value.
fn percent_decode_path(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                output.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn query_value(query: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix(prefix.as_str()))
        .map(percent_decode_query)
}

fn percent_decode_query(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                output.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        output.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Build the synchronous-invoke HTTP response (HTTP 200 with payload; `X-Amz-Function-Error`
/// header on a function error; `X-Amz-Log-Result` tail when requested).
fn invoke_response(
    executed_version: &str,
    request_id: &str,
    result: crate::executor::InvokeResult,
    tail_logs: bool,
) -> Response {
    let mut builder = http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .header("x-amz-executed-version", executed_version)
        .header("x-amzn-requestid", request_id);
    if tail_logs {
        // The last 4 KB of logs, base64-encoded.
        let bytes = result.logs.as_bytes();
        let tail = &bytes[bytes.len().saturating_sub(4096)..];
        let encoded = base64::engine::general_purpose::STANDARD.encode(tail);
        if let Ok(value) = http::HeaderValue::from_str(&encoded) {
            builder = builder.header("x-amz-log-result", value);
        }
    }
    let body = match result.outcome {
        Outcome::Success(payload) => payload,
        Outcome::Error {
            error_type,
            payload,
        } => {
            let label = match error_type {
                FunctionErrorType::Handled => "Handled",
                FunctionErrorType::Unhandled => "Unhandled",
            };
            builder = builder.header("x-amz-function-error", label);
            payload
        }
    };
    builder
        .body(Body::from(body))
        .expect("invoke response is valid")
}

fn empty_status(status: u16) -> Response {
    http::Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("empty response is valid")
}

struct RegistryDestinationRouter {
    registry: Weak<ServiceRegistry>,
}

#[async_trait]
impl DestinationRouter for RegistryDestinationRouter {
    async fn route(&self, target_arn: &str, record: Value) {
        let parts: Vec<&str> = target_arn.split(':').collect();
        if parts.len() != 6 || parts[0] != "arn" || parts[2] != "sqs" || parts[5].is_empty() {
            tracing::warn!(target_arn, "unsupported Lambda async destination");
            return;
        }
        let Some(registry) = self.registry.upgrade() else {
            tracing::warn!("Lambda async destination skipped: registry unavailable");
            return;
        };
        let Some(dispatcher) = registry.internal_dispatcher() else {
            tracing::warn!("Lambda async destination skipped: dispatcher unavailable");
            return;
        };
        let region = parts[3];
        let account = parts[4];
        let queue = parts[5];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_static("AmazonSQS.SendMessage"),
        );
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/x-amz-json-1.0"),
        );
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential=localcloud/19700101/{region}/sqs/aws4_request, SignedHeaders=host, Signature=localcloud"
        );
        let Ok(authorization) = HeaderValue::from_str(&authorization) else {
            tracing::warn!(target_arn, "invalid Lambda async destination region");
            return;
        };
        headers.insert("authorization", authorization);
        let body = json!({
            "QueueUrl": format!("https://sqs.{region}.amazonaws.com/{account}/{queue}"),
            "MessageBody": record.to_string(),
        });
        let call = CrossServiceCall {
            source_service: ServiceName::new("lambda"),
            account_id: account.to_string(),
            region: region.to_string(),
            method: Method::POST,
            uri: "/".parse().expect("root URI is valid"),
            headers,
            body: Bytes::from(body.to_string()),
            identity: CallerIdentity::ServicePrincipal {
                service: "lambda".into(),
            },
            correlation: CorrelationContext::root(),
            pattern: Some(IntegrationPatternId("lambda->sqs")),
        };
        if let Err(error) = DeliveryEngine::new(dispatcher)
            .deliver_async(
                call,
                &AsyncDeliveryPolicy {
                    max_attempts: 1,
                    on_failure: None,
                },
            )
            .await
        {
            tracing::warn!(target_arn, %error, "Lambda async destination delivery failed");
        }
    }
}

/// Register Lambda as a `Native` REST-JSON service in the Core registry.
pub fn register(registry: &Arc<ServiceRegistry>) {
    let handler = Arc::new(LambdaHandler::with_parts(Arc::downgrade(registry), None));
    let native_handler: Arc<dyn NativeHandler> = handler.clone();
    let lambda_api: Arc<dyn LambdaInternalApi> = handler.clone();
    registry.register_native_with_lambda_api(
        ServiceName::new("lambda"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        native_handler,
        lambda_api,
    );
}

/// Register Lambda with the data plane wired: spin up the Runtime API server on an ephemeral
/// loopback port, build the executor over the daemonless OCI runtime (`crun`/`youki`), and
/// register a handler that can invoke. Falls back to control-plane-only when no OCI runtime is
/// present. `aws_endpoint_url` is injected into guests for in-Guest SDK calls.
pub async fn register_with_execution(
    registry: &Arc<ServiceRegistry>,
    aws_endpoint_url: &str,
) -> Option<Arc<LambdaHandler>> {
    use crate::code_store::CodeStore;
    use crate::executor::Executor;
    use crate::runtime_api::InvocationBroker;
    use crate::runtime_api_server::router;
    use localcloud_compute::runtime::ComputeRuntime;
    use localcloud_compute::youki::YoukiRuntime;

    let runtime = match YoukiRuntime::discover() {
        Some(rt) => Arc::new(rt) as Arc<dyn ComputeRuntime>,
        None => {
            tracing::warn!("no daemonless OCI runtime (crun/youki) found; Lambda invoke disabled");
            register(registry);
            return None;
        }
    };

    let max_warm_total = match std::env::var("LOCALCLOUD_LAMBDA_MAX_WARM_TOTAL") {
        Ok(value) => Executor::parse_max_warm_total(Some(&value)),
        Err(std::env::VarError::NotPresent) => Executor::parse_max_warm_total(None),
        Err(error) => Err(error.to_string()),
    };
    let max_warm_total = match max_warm_total {
        Ok(limit) => limit,
        Err(error) => {
            tracing::error!(%error, "invalid LOCALCLOUD_LAMBDA_MAX_WARM_TOTAL; Lambda invoke disabled");
            register(registry);
            return None;
        }
    };

    let work = match std::env::var_os("LOCALCLOUD_WORK_DIR") {
        Some(path) if !path.is_empty() => {
            let path = std::path::PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                match std::env::current_dir() {
                    Ok(current) => current.join(path),
                    Err(error) => {
                        tracing::error!(%error, "could not resolve LOCALCLOUD_WORK_DIR");
                        register(registry);
                        return None;
                    }
                }
            }
        }
        _ => localcloud_compute::private_dir::work_dir("lambda"),
    };
    if let Err(error) = localcloud_compute::private_dir::ensure(&work) {
        tracing::error!(%error, path = %work.display(), "Lambda work directory is unavailable or insecure");
        register(registry);
        return None;
    }

    let broker = Arc::new(InvocationBroker::new());
    // Bind the Runtime API server on an ephemeral loopback port; guests reach it via the host
    // network namespace (see YoukiRuntime egress).
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "could not bind the Lambda Runtime API; invoke disabled");
            register(registry);
            return None;
        }
    };
    let runtime_api_base = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let broker_for_server = broker.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(broker_for_server)).await;
    });

    let layers = Arc::new(LayerStore::new());
    let executor = Executor::new(
        broker,
        Arc::new(CodeStore::new(work.join("code"))),
        work.join("rootfs"),
        runtime,
        runtime_api_base,
        aws_endpoint_url,
        "test",
        "test",
    )
    .with_layer_store(layers)
    .with_max_warm_total(max_warm_total)
    .with_service_registry(Arc::downgrade(registry))
    .with_destination_router(Arc::new(RegistryDestinationRouter {
        registry: Arc::downgrade(registry),
    }))
    .with_host_managed_runtime();
    let executor = Arc::new(executor);
    executor.bind_arc();
    let reaper = Arc::downgrade(&executor);
    tokio::spawn(async move {
        if let Some(executor) = reaper.upgrade() {
            executor.reap_expired_warm().await;
        }
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            let Some(executor) = reaper.upgrade() else {
                break;
            };
            executor.reap_expired_warm().await;
        }
    });
    let handler = Arc::new(LambdaHandler::with_parts(
        Arc::downgrade(registry),
        Some(executor.clone()),
    ));
    let native_handler: Arc<dyn NativeHandler> = handler.clone();
    let lambda_api: Arc<dyn LambdaInternalApi> = handler.clone();
    registry.register_native_with_lambda_api(
        ServiceName::new("lambda"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        native_handler,
        lambda_api,
    );
    tracing::info!("Lambda data plane enabled (Runtime API on loopback, OCI runtime)");
    Some(handler)
}

fn unsupported() -> LambdaError {
    LambdaError::NotImplemented("operation not yet implemented".into())
}

fn require_nonempty_string<'a>(input: &'a Value, field: &str) -> Result<&'a str, LambdaError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| LambdaError::InvalidParameterValue(format!("{field} is required")))
}

fn optional_nonempty_string<'a>(
    input: &'a Value,
    field: &str,
) -> Result<Option<&'a str>, LambdaError> {
    match input.get(field) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value)),
        Some(_) => Err(LambdaError::InvalidParameterValue(format!(
            "{field} must be a non-empty string"
        ))),
    }
}

fn encode_path(value: &str, preserve_slashes: bool) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (preserve_slashes && byte == b'/')
        {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// Collect all values of a repeated query parameter (e.g. `?tagKeys=a&tagKeys=b`).
fn query_values(query: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key}=");
    query
        .split('&')
        .filter_map(|pair| pair.strip_prefix(prefix.as_str()))
        .map(|v| v.replace('+', " "))
        .collect()
}

fn parse_json(body: &bytes::Bytes) -> Result<Value, LambdaError> {
    if body.is_empty() {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    serde_json::from_slice(body)
        .map_err(|e| LambdaError::InvalidRequestContent(format!("invalid JSON request body: {e}")))
}

fn json_response(status: u16, body: Option<Value>) -> Response {
    let builder = http::Response::builder().status(status);
    match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .expect("json response is always valid"),
        None => builder
            .body(Body::empty())
            .expect("empty response is always valid"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::io::{Cursor, Write};

    #[test]
    fn vpc_selection_rejects_partial_invalid_and_unavailable_networks() {
        let handler = LambdaHandler::new();
        let scope = ("000000000000", "us-east-1");
        let invalid = serde_json::json!({"VpcConfig": {"SubnetIds": ["subnet-a"]}});
        assert!(matches!(
            handler.validate_vpc_config(scope.0, scope.1, &invalid),
            Err(LambdaError::InvalidParameterValue(_))
        ));
        let malformed = serde_json::json!({"VpcConfig": {"SubnetIds": "subnet-a"}});
        assert!(matches!(
            handler.validate_vpc_config(scope.0, scope.1, &malformed),
            Err(LambdaError::InvalidParameterValue(_))
        ));
        let unsupported = serde_json::json!({"VpcConfig": {
            "SubnetIds": ["subnet-a"], "SecurityGroupIds": ["sg-a"],
            "Ipv6AllowedForDualStack": true
        }});
        assert!(matches!(
            handler.validate_vpc_config(scope.0, scope.1, &unsupported),
            Err(LambdaError::InvalidParameterValue(_))
        ));
        let selected = serde_json::json!({"VpcConfig": {
            "SubnetIds": ["subnet-a"], "SecurityGroupIds": ["sg-a"]
        }});
        assert!(matches!(
            handler.validate_vpc_config(scope.0, scope.1, &selected),
            Err(LambdaError::InvalidParameterValue(_))
        ));
        let detached = serde_json::json!({"VpcConfig": {"SubnetIds": [], "SecurityGroupIds": []}});
        assert!(matches!(
            handler.validate_vpc_config(scope.0, scope.1, &detached),
            Ok(Some(None))
        ));
    }

    #[tokio::test]
    async fn vpc_selection_checks_real_ec2_scope() {
        use axum::body::to_bytes;
        let ec2 = Arc::new(Ec2Handler::default());
        let call = |form: String| {
            let ec2 = ec2.clone();
            async move {
                let response = ec2
                    .handle(ServiceRequest {
                        method: Method::POST,
                        uri: "/".parse().unwrap(),
                        headers: http::HeaderMap::new(),
                        body: Bytes::from(form),
                        account_id: "000000000000".into(),
                        region: "us-east-1".into(),
                        request_id: "vpc-test".into(),
                    })
                    .await;
                assert_eq!(response.status(), http::StatusCode::OK);
                String::from_utf8(
                    to_bytes(response.into_body(), usize::MAX)
                        .await
                        .unwrap()
                        .to_vec(),
                )
                .unwrap()
            }
        };
        let id = |xml: &str, tag: &str| {
            xml.split(&format!("<{tag}>"))
                .nth(1)
                .unwrap()
                .split(&format!("</{tag}>"))
                .next()
                .unwrap()
                .to_string()
        };
        let vpc = id(
            &call("Action=CreateVpc&CidrBlock=10.7.0.0%2F16".into()).await,
            "vpcId",
        );
        let subnet = id(
            &call(format!(
                "Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.7.1.0%2F24"
            ))
            .await,
            "subnetId",
        );
        let group = id(
            &call(format!(
                "Action=CreateSecurityGroup&VpcId={vpc}&GroupName=lambda&GroupDescription=lambda"
            ))
            .await,
            "groupId",
        );
        let handler = LambdaHandler::new();
        handler.attach_ec2(ec2);
        let request = serde_json::json!({"VpcConfig": {
            "SubnetIds": [subnet], "SecurityGroupIds": [group]
        }});
        let selected = handler
            .validate_vpc_config("000000000000", "us-east-1", &request)
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(selected.vpc_id, vpc);
        let mut missing_group = request.clone();
        missing_group["VpcConfig"]["SecurityGroupIds"] = serde_json::json!(["sg-missing"]);
        assert!(handler
            .validate_vpc_config("000000000000", "us-east-1", &missing_group)
            .is_err());
        assert!(handler
            .validate_vpc_config("000000000000", "eu-west-1", &request)
            .is_err());
        assert!(handler
            .validate_vpc_config("other", "us-east-1", &request)
            .is_err());
    }

    fn zip_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(Cursor::new(&mut bytes));
            writer
                .start_file("index.js", zip::write::SimpleFileOptions::default())
                .unwrap();
            writer
                .write_all(b"exports.handler=async()=>({statusCode:200,body:'ok'})")
                .unwrap();
            writer.finish().unwrap();
        }
        bytes
    }

    fn zip_base64() -> String {
        base64::engine::general_purpose::STANDARD.encode(zip_bytes())
    }

    fn create_body(name: &str, code: Value) -> String {
        serde_json::json!({
            "FunctionName": name,
            "Role": "arn:aws:iam::000000000000:role/r",
            "Runtime": "nodejs22.x",
            "Handler": "index.handler",
            "Code": code
        })
        .to_string()
    }

    fn request(method: Method, path: &str, body: &str) -> ServiceRequest {
        ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: Bytes::copy_from_slice(body.as_bytes()),
            region: "us-east-1".to_string(),
            account_id: "000000000000".to_string(),
            request_id: "rid".to_string(),
        }
    }

    #[tokio::test]
    async fn create_and_get_via_handler() {
        let handler = LambdaHandler::new();
        let create_body = create_body("fn", serde_json::json!({ "ZipFile": zip_base64() }));
        let resp = handler
            .handle(request(Method::POST, "/2015-03-31/functions", &create_body))
            .await;
        assert_eq!(resp.status(), 201);

        let resp = handler
            .handle(request(Method::GET, "/2015-03-31/functions/fn", ""))
            .await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn get_missing_function_returns_404() {
        let handler = LambdaHandler::new();
        let resp = handler
            .handle(request(Method::GET, "/2015-03-31/functions/nope", ""))
            .await;
        assert_eq!(resp.status(), 404);
        assert_eq!(
            resp.headers().get("x-amzn-errortype").unwrap(),
            "ResourceNotFoundException"
        );
    }

    #[tokio::test]
    async fn unknown_operation_returns_501() {
        let handler = LambdaHandler::new();
        let resp = handler
            .handle(request(
                Method::POST,
                "/2015-03-31/functions/fn/invocations",
                "",
            ))
            .await;
        assert_eq!(resp.status(), 501);
    }

    #[tokio::test]
    async fn malformed_create_body_returns_400() {
        let handler = LambdaHandler::new();
        let resp = handler
            .handle(request(Method::POST, "/2015-03-31/functions", "{not json"))
            .await;
        assert_eq!(resp.status(), 400);
    }

    struct ZipS3;

    #[async_trait]
    impl NativeHandler for ZipS3 {
        async fn handle(&self, request: ServiceRequest) -> Response {
            if request.method == Method::GET && request.uri.path().ends_with(".zip") {
                Response::builder()
                    .status(200)
                    .body(Body::from(zip_bytes()))
                    .unwrap()
            } else {
                Response::builder()
                    .status(404)
                    .body(Body::from("<Error><Code>NoSuchKey</Code></Error>"))
                    .unwrap()
            }
        }
    }

    #[tokio::test]
    async fn s3_zip_sources_cover_create_update_and_layers() {
        let registry = ServiceRegistry::with_known_services();
        registry.register_native(
            ServiceName::new("s3"),
            ServiceMetadata::new(AwsProtocol::RestXml, None),
            Arc::new(ZipS3),
        );
        let handler = LambdaHandler::with_parts(Arc::downgrade(&registry), None);

        let create = create_body(
            "s3-fn",
            serde_json::json!({
                "S3Bucket": "artifacts",
                "S3Key": "functions/code.zip",
                "S3ObjectVersion": "v1"
            }),
        );
        let response = handler
            .handle(request(Method::POST, "/2015-03-31/functions", &create))
            .await;
        assert_eq!(response.status(), 201);

        let update = serde_json::json!({
            "S3Bucket": "artifacts",
            "S3Key": "updates/code.zip"
        })
        .to_string();
        let response = handler
            .handle(request(
                Method::PUT,
                "/2015-03-31/functions/s3-fn/code",
                &update,
            ))
            .await;
        assert_eq!(response.status(), 200);

        let layer = serde_json::json!({
            "Content": { "S3Bucket": "artifacts", "S3Key": "layers/code.zip" }
        })
        .to_string();
        let response = handler
            .handle(request(
                Method::POST,
                "/2018-10-31/layers/libs/versions",
                &layer,
            ))
            .await;
        assert_eq!(response.status(), 201);
    }

    async fn create_fn(handler: &LambdaHandler) {
        let create_body = create_body("fn", serde_json::json!({ "ZipFile": zip_base64() }));
        let resp = handler
            .handle(request(Method::POST, "/2015-03-31/functions", &create_body))
            .await;
        assert_eq!(resp.status(), 201);
    }

    #[tokio::test]
    async fn concurrency_routes_via_handler() {
        let handler = LambdaHandler::new();
        create_fn(&handler).await;
        let resp = handler
            .handle(request(
                Method::PUT,
                "/2017-10-31/functions/fn/concurrency",
                r#"{"ReservedConcurrentExecutions":3}"#,
            ))
            .await;
        assert_eq!(resp.status(), 200);
        let resp = handler
            .handle(request(
                Method::GET,
                "/2017-10-31/functions/fn/concurrency",
                "",
            ))
            .await;
        assert_eq!(resp.status(), 200);
        let resp = handler
            .handle(request(
                Method::DELETE,
                "/2017-10-31/functions/fn/concurrency",
                "",
            ))
            .await;
        assert_eq!(resp.status(), 204);
    }

    #[tokio::test]
    async fn url_config_routes_via_handler() {
        let handler = LambdaHandler::new();
        create_fn(&handler).await;
        let resp = handler
            .handle(request(
                Method::POST,
                "/2021-10-31/functions/fn/url",
                r#"{"AuthType":"NONE"}"#,
            ))
            .await;
        assert_eq!(resp.status(), 201);
        let resp = handler
            .handle(request(Method::GET, "/2021-10-31/functions/fn/url", ""))
            .await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn event_invoke_routes_via_handler() {
        let handler = LambdaHandler::new();
        create_fn(&handler).await;
        let resp = handler
            .handle(request(
                Method::PUT,
                "/2019-09-25/functions/fn/event-invoke-config",
                r#"{"MaximumRetryAttempts":1}"#,
            ))
            .await;
        assert_eq!(resp.status(), 200);
        let resp = handler
            .handle(request(
                Method::GET,
                "/2019-09-25/functions/fn/event-invoke-config/list",
                "",
            ))
            .await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn provisioned_concurrency_routes_via_handler() {
        let handler = LambdaHandler::new();
        create_fn(&handler).await;
        // Publish a version to qualify.
        let pv = handler
            .handle(request(
                Method::POST,
                "/2015-03-31/functions/fn/versions",
                "",
            ))
            .await;
        assert_eq!(pv.status(), 201);

        // $LATEST is rejected.
        let bad = handler
            .handle(request(
                Method::PUT,
                "/2019-09-30/functions/fn/provisioned-concurrency?Qualifier=$LATEST",
                r#"{"ProvisionedConcurrentExecutions":2}"#,
            ))
            .await;
        assert_eq!(bad.status(), 400);

        // A published version qualifier succeeds (202).
        let put = handler
            .handle(request(
                Method::PUT,
                "/2019-09-30/functions/fn/provisioned-concurrency?Qualifier=1",
                r#"{"ProvisionedConcurrentExecutions":2}"#,
            ))
            .await;
        assert_eq!(put.status(), 202);

        let get = handler
            .handle(request(
                Method::GET,
                "/2019-09-30/functions/fn/provisioned-concurrency?Qualifier=1",
                "",
            ))
            .await;
        assert_eq!(get.status(), 200);

        let list = handler
            .handle(request(
                Method::GET,
                "/2019-09-30/functions/fn/provisioned-concurrency?List=ALL",
                "",
            ))
            .await;
        assert_eq!(list.status(), 200);

        let del = handler
            .handle(request(
                Method::DELETE,
                "/2019-09-30/functions/fn/provisioned-concurrency?Qualifier=1",
                "",
            ))
            .await;
        assert_eq!(del.status(), 204);
    }

    #[tokio::test]
    async fn event_source_mapping_crud_via_handler() {
        let registry = ServiceRegistry::with_known_services();
        localcloud_sqs::register(&registry);
        let handler = LambdaHandler::with_parts(Arc::downgrade(&registry), None);
        create_fn(&handler).await;
        let source_arn = "arn:aws:sqs:us-east-1:000000000000:q";
        let create_request = request(
            Method::POST,
            "/2015-03-31/event-source-mappings",
            &json!({
                "FunctionName": "fn",
                "EventSourceArn": source_arn,
                "BatchSize": 5
            })
            .to_string(),
        );
        let missing = handler.handle(create_request.clone()).await;
        assert_eq!(missing.status(), 400);
        assert!(handler.esm.list(None, None).is_empty());

        let sqs = registry.native_handler(&ServiceName::new("sqs")).unwrap();
        let mut queue_request = request(Method::POST, "/", r#"{"QueueName":"q"}"#);
        queue_request.headers.insert(
            "x-amz-target",
            HeaderValue::from_static("AmazonSQS.CreateQueue"),
        );
        assert_eq!(sqs.handle(queue_request).await.status(), 200);

        // Create an SQS ESM.
        let create = handler.handle(create_request).await;
        assert_eq!(create.status(), 202);
        let bytes = axum::body::to_bytes(create.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let uuid = v["UUID"].as_str().unwrap().to_string();
        assert_eq!(v["BatchSize"], 5);
        assert_eq!(v["State"], "Enabled");

        // Get, list, update (disable), delete.
        let get = handler
            .handle(request(
                Method::GET,
                &format!("/2015-03-31/event-source-mappings/{uuid}"),
                "",
            ))
            .await;
        assert_eq!(get.status(), 200);
        let list = handler
            .handle(request(
                Method::GET,
                "/2015-03-31/event-source-mappings",
                "",
            ))
            .await;
        assert_eq!(list.status(), 200);
        let invalid = handler
            .handle(request(
                Method::PUT,
                &format!("/2015-03-31/event-source-mappings/{uuid}"),
                r#"{"BatchSize":15}"#,
            ))
            .await;
        assert_eq!(invalid.status(), 400);
        let large = handler
            .handle(request(
                Method::PUT,
                &format!("/2015-03-31/event-source-mappings/{uuid}"),
                r#"{"BatchSize":15,"MaximumBatchingWindowInSeconds":1}"#,
            ))
            .await;
        assert_eq!(large.status(), 202);
        let large_body = axum::body::to_bytes(large.into_body(), usize::MAX)
            .await
            .unwrap();
        let large_json: serde_json::Value = serde_json::from_slice(&large_body).unwrap();
        assert_eq!(large_json["BatchSize"], 15);
        assert_eq!(large_json["MaximumBatchingWindowInSeconds"], 1);
        let upd = handler
            .handle(request(
                Method::PUT,
                &format!("/2015-03-31/event-source-mappings/{uuid}"),
                r#"{"Enabled":false}"#,
            ))
            .await;
        assert_eq!(upd.status(), 202);
        let del = handler
            .handle(request(
                Method::DELETE,
                &format!("/2015-03-31/event-source-mappings/{uuid}"),
                "",
            ))
            .await;
        assert_eq!(del.status(), 202);
        // Gone.
        let get2 = handler
            .handle(request(
                Method::GET,
                &format!("/2015-03-31/event-source-mappings/{uuid}"),
                "",
            ))
            .await;
        assert_eq!(get2.status(), 404);
    }

    #[tokio::test]
    async fn layer_routes_via_handler() {
        let handler = LambdaHandler::new();
        let layer_body = serde_json::json!({
            "Content": { "ZipFile": zip_base64() }
        })
        .to_string();
        let resp = handler
            .handle(request(
                Method::POST,
                "/2018-10-31/layers/libs/versions",
                &layer_body,
            ))
            .await;
        assert_eq!(resp.status(), 201);
        let resp = handler
            .handle(request(Method::GET, "/2018-10-31/layers", ""))
            .await;
        assert_eq!(resp.status(), 200);
        let resp = handler
            .handle(request(
                Method::GET,
                "/2018-10-31/layers/libs/versions/1",
                "",
            ))
            .await;
        assert_eq!(resp.status(), 200);
        let resp = handler
            .handle(request(
                Method::GET,
                "/2018-10-31/layers/libs/versions/9",
                "",
            ))
            .await;
        assert_eq!(resp.status(), 404);
    }
}
