//! REGIONAL WAFv2 control plane and a typed API Gateway evaluation boundary.
//! Unsupported scopes, statements, actions, and association targets fail before mutation.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use base64::Engine;
use localcloud_core::error_mapping::AwsError;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::registry::AwsProtocol;
use serde_json::{json, Map, Value};
use uuid::Uuid;

const PREFIX: &str = "AWSWAF_20190729.";
const MAX_BODY: usize = 256 * 1024;
const MAX_RESOURCES: usize = 1000;
const MAX_RULES: usize = 100;
const MAX_ADDRESSES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafDecision {
    Unassociated,
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafEvaluationError {
    StateUnavailable,
    MissingWebAcl,
    InvalidSourceIp,
}

pub struct WafRequest<'a> {
    pub account_id: &'a str,
    pub region: &'a str,
    pub resource_arn: &'a str,
    pub source_ip: &'a str,
    pub method: &'a str,
    pub uri_path: &'a str,
    pub headers: &'a http::HeaderMap,
}

pub trait WafEvaluator: Send + Sync {
    fn evaluate(&self, request: &WafRequest<'_>) -> Result<WafDecision, WafEvaluationError>;
    fn detach_stage(
        &self,
        account_id: &str,
        region: &str,
        resource_arn: &str,
    ) -> Result<(), WafEvaluationError>;
}

/// The API Gateway owner validates stage existence without sharing its store with WAF.
pub trait StageResolver: Send + Sync {
    fn stage_exists(&self, account_id: &str, region: &str, stage_arn: &str) -> bool;
}

#[derive(Clone)]
struct IpSet {
    id: String,
    name: String,
    description: Option<String>,
    arn: String,
    lock: String,
    version: String,
    addresses: Vec<String>,
    cidrs: Vec<Cidr>,
}

#[derive(Clone)]
struct WebAcl {
    id: String,
    name: String,
    description: Option<String>,
    arn: String,
    lock: String,
    default: Action,
    rules: Vec<Rule>,
    visibility: Value,
}

#[derive(Clone)]
struct Rule {
    priority: u64,
    action: Action,
    statement: Statement,
    wire: Value,
}

#[derive(Clone)]
enum Statement {
    IpSet(String),
    ByteMatch {
        field: Field,
        search: Vec<u8>,
        position: Position,
    },
}

#[derive(Clone)]
enum Field {
    UriPath,
    Header(String),
}
#[derive(Clone, Copy)]
enum Position {
    Exact,
    StartsWith,
    EndsWith,
    Contains,
}
#[derive(Clone, Copy)]
enum Action {
    Allow,
    Block,
}

#[derive(Clone)]
struct Cidr {
    ip: IpAddr,
    prefix: u8,
}

#[derive(Default)]
struct State {
    ipsets: HashMap<(String, String, String), IpSet>,
    webacls: HashMap<(String, String, String), WebAcl>,
    associations: HashMap<(String, String, String), String>,
}

pub struct WafHandler {
    state: Mutex<State>,
    stage_resolver: Option<Arc<dyn StageResolver>>,
}

impl WafHandler {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            stage_resolver: None,
        })
    }

    pub fn new_with_stage_resolver(resolver: Arc<dyn StageResolver>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            stage_resolver: Some(resolver),
        })
    }

    fn execute(
        &self,
        operation: &str,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        match operation {
            "CreateIPSet" => self.create_ipset(req, body),
            "GetIPSet" => self.get_ipset(req, body),
            "UpdateIPSet" => self.update_ipset(req, body),
            "DeleteIPSet" => self.delete_ipset(req, body),
            "ListIPSets" => self.list_ipsets(req, body),
            "CreateWebACL" => self.create_webacl(req, body),
            "GetWebACL" => self.get_webacl(req, body),
            "UpdateWebACL" => self.update_webacl(req, body),
            "DeleteWebACL" => self.delete_webacl(req, body),
            "ListWebACLs" => self.list_webacls(req, body),
            "AssociateWebACL" => self.associate_webacl(req, body),
            "DisassociateWebACL" => self.disassociate_webacl(req, body),
            "GetWebACLForResource" => self.get_webacl_for_resource(req, body),
            "ListResourcesForWebACL" => self.list_resources_for_webacl(req, body),
            _ => Err(WafError::unsupported()),
        }
    }

    fn create_ipset(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(
            body,
            &[
                "Name",
                "Scope",
                "IPAddressVersion",
                "Addresses",
                "Description",
            ],
        )?;
        regional(body)?;
        let name = name(body)?;
        let version = string(body, "IPAddressVersion")?;
        if version != "IPV4" && version != "IPV6" {
            return Err(WafError::invalid());
        }
        let (addresses, cidrs) = addresses(body, version)?;
        let description = optional_string(body, "Description", 256)?;
        let mut state = self.state.lock().map_err(|_| WafError::internal())?;
        if state.ipsets.iter().any(|((account, region, _), item)| {
            account == &req.account_id && region == &req.region && item.name == name
        }) {
            return Err(WafError::duplicate());
        }
        if state.ipsets.len() >= MAX_RESOURCES {
            return Err(WafError::limit());
        }
        let id = Uuid::new_v4().to_string();
        let arn = arn(req, "ipset", name, &id);
        let set = IpSet {
            id: id.clone(),
            name: name.into(),
            description,
            arn,
            lock: token(),
            version: version.into(),
            addresses,
            cidrs,
        };
        let result = json!({"Summary": ip_summary(&set)});
        state.ipsets.insert(key(req, &id), set);
        Ok(result)
    }

    fn get_ipset(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(body, &["Name", "Scope", "Id"])?;
        regional(body)?;
        let id = string(body, "Id")?;
        let name = name(body)?;
        let state = self.state.lock().map_err(|_| WafError::internal())?;
        let set = state
            .ipsets
            .get(&key(req, id))
            .filter(|set| set.name == name)
            .ok_or_else(WafError::not_found)?;
        Ok(json!({"IPSet": ip_full(set), "LockToken": set.lock}))
    }

    fn update_ipset(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(
            body,
            &[
                "Name",
                "Scope",
                "Id",
                "LockToken",
                "Addresses",
                "Description",
            ],
        )?;
        regional(body)?;
        let id = string(body, "Id")?;
        let name = name(body)?;
        let lock = string(body, "LockToken")?;
        let mut state = self.state.lock().map_err(|_| WafError::internal())?;
        let set = state
            .ipsets
            .get_mut(&key(req, id))
            .filter(|set| set.name == name)
            .ok_or_else(WafError::not_found)?;
        if lock != set.lock {
            return Err(WafError::stale());
        }
        let (addresses, cidrs) = addresses(body, &set.version)?;
        let description = optional_string(body, "Description", 256)?;
        set.addresses = addresses;
        set.cidrs = cidrs;
        set.description = description;
        set.lock = token();
        Ok(json!({"NextLockToken": set.lock}))
    }

    fn delete_ipset(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(body, &["Name", "Scope", "Id", "LockToken"])?;
        regional(body)?;
        let id = string(body, "Id")?;
        let name = name(body)?;
        let lock = string(body, "LockToken")?;
        let mut state = self.state.lock().map_err(|_| WafError::internal())?;
        let set = state
            .ipsets
            .get(&key(req, id))
            .filter(|set| set.name == name)
            .ok_or_else(WafError::not_found)?;
        if lock != set.lock {
            return Err(WafError::stale());
        }
        if state.webacls.iter().any(|((account, region, _), acl)| {
            account == &req.account_id
                && region == &req.region
                && acl
                    .rules
                    .iter()
                    .any(|rule| matches!(&rule.statement, Statement::IpSet(arn) if arn == &set.arn))
        }) {
            return Err(WafError::associated());
        }
        state.ipsets.remove(&key(req, id));
        Ok(json!({}))
    }

    fn list_ipsets(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(body, &["Scope", "Limit", "NextMarker"])?;
        regional(body)?;
        let limit = list_limit(body)?;
        if body.contains_key("NextMarker") {
            return Err(WafError::unsupported());
        }
        let state = self.state.lock().map_err(|_| WafError::internal())?;
        let mut items: Vec<Value> = state
            .ipsets
            .iter()
            .filter(|((account, region, _), _)| account == &req.account_id && region == &req.region)
            .map(|(_, set)| ip_summary(set))
            .collect();
        items.sort_by(|a, b| a["Name"].as_str().cmp(&b["Name"].as_str()));
        if items.len() > limit {
            return Err(WafError::unsupported());
        }
        Ok(json!({"IPSets": items}))
    }

    fn create_webacl(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(
            body,
            &[
                "Name",
                "Scope",
                "DefaultAction",
                "Rules",
                "VisibilityConfig",
                "Description",
            ],
        )?;
        regional(body)?;
        let name = name(body)?;
        let default = action(body.get("DefaultAction"))?;
        let visibility = visibility(body.get("VisibilityConfig"))?;
        let rules = parse_rules(body.get("Rules"))?;
        let description = optional_string(body, "Description", 256)?;
        let mut state = self.state.lock().map_err(|_| WafError::internal())?;
        validate_references(&state, req, &rules)?;
        if state.webacls.iter().any(|((account, region, _), item)| {
            account == &req.account_id && region == &req.region && item.name == name
        }) {
            return Err(WafError::duplicate());
        }
        if state.webacls.len() >= MAX_RESOURCES {
            return Err(WafError::limit());
        }
        let id = Uuid::new_v4().to_string();
        let acl = WebAcl {
            id: id.clone(),
            name: name.into(),
            description,
            arn: arn(req, "webacl", name, &id),
            lock: token(),
            default,
            rules,
            visibility,
        };
        let result = json!({"Summary": web_summary(&acl)});
        state.webacls.insert(key(req, &id), acl);
        Ok(result)
    }

    fn get_webacl(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(body, &["Name", "Scope", "Id"])?;
        regional(body)?;
        let id = string(body, "Id")?;
        let name = name(body)?;
        let state = self.state.lock().map_err(|_| WafError::internal())?;
        let acl = state
            .webacls
            .get(&key(req, id))
            .filter(|acl| acl.name == name)
            .ok_or_else(WafError::not_found)?;
        Ok(json!({"WebACL": web_full(acl), "LockToken": acl.lock}))
    }

    fn update_webacl(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(
            body,
            &[
                "Name",
                "Scope",
                "Id",
                "LockToken",
                "DefaultAction",
                "Rules",
                "VisibilityConfig",
                "Description",
            ],
        )?;
        regional(body)?;
        let id = string(body, "Id")?;
        let name = name(body)?;
        let lock = string(body, "LockToken")?;
        let default = action(body.get("DefaultAction"))?;
        let visibility = visibility(body.get("VisibilityConfig"))?;
        let rules = parse_rules(body.get("Rules"))?;
        let description = optional_string(body, "Description", 256)?;
        let mut state = self.state.lock().map_err(|_| WafError::internal())?;
        validate_references(&state, req, &rules)?;
        let acl = state
            .webacls
            .get_mut(&key(req, id))
            .filter(|acl| acl.name == name)
            .ok_or_else(WafError::not_found)?;
        if lock != acl.lock {
            return Err(WafError::stale());
        }
        acl.default = default;
        acl.visibility = visibility;
        acl.rules = rules;
        acl.description = description;
        acl.lock = token();
        Ok(json!({"NextLockToken": acl.lock}))
    }

    fn delete_webacl(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(body, &["Name", "Scope", "Id", "LockToken"])?;
        regional(body)?;
        let id = string(body, "Id")?;
        let name = name(body)?;
        let lock = string(body, "LockToken")?;
        let mut state = self.state.lock().map_err(|_| WafError::internal())?;
        let acl = state
            .webacls
            .get(&key(req, id))
            .filter(|acl| acl.name == name)
            .ok_or_else(WafError::not_found)?;
        if lock != acl.lock {
            return Err(WafError::stale());
        }
        if state
            .associations
            .iter()
            .any(|((account, region, _), arn)| {
                account == &req.account_id && region == &req.region && arn == &acl.arn
            })
        {
            return Err(WafError::associated());
        }
        state.webacls.remove(&key(req, id));
        Ok(json!({}))
    }

    fn list_webacls(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(body, &["Scope", "Limit", "NextMarker"])?;
        regional(body)?;
        let limit = list_limit(body)?;
        if body.contains_key("NextMarker") {
            return Err(WafError::unsupported());
        }
        let state = self.state.lock().map_err(|_| WafError::internal())?;
        let mut items: Vec<Value> = state
            .webacls
            .iter()
            .filter(|((account, region, _), _)| account == &req.account_id && region == &req.region)
            .map(|(_, acl)| web_summary(acl))
            .collect();
        items.sort_by(|a, b| a["Name"].as_str().cmp(&b["Name"].as_str()));
        if items.len() > limit {
            return Err(WafError::unsupported());
        }
        Ok(json!({"WebACLs": items}))
    }

    fn associate_webacl(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(body, &["WebACLArn", "ResourceArn"])?;
        let acl_arn = string(body, "WebACLArn")?;
        let resource = string(body, "ResourceArn")?;
        stage_arn(req, resource)?;
        let resolver = self
            .stage_resolver
            .as_ref()
            .ok_or_else(WafError::unavailable)?;
        // Hold the WAF lock across stage validation and insertion. DeleteStage holds the
        // stage write lock while detaching, so an in-flight associate cannot leave a
        // stale association after the stage is removed.
        let mut state = self.state.lock().map_err(|_| WafError::internal())?;
        if !resolver.stage_exists(&req.account_id, &req.region, resource) {
            return Err(WafError::unavailable());
        }
        if !state.webacls.iter().any(|((account, region, _), acl)| {
            account == &req.account_id && region == &req.region && acl.arn == acl_arn
        }) {
            return Err(WafError::not_found());
        }
        state.associations.insert(
            (req.account_id.clone(), req.region.clone(), resource.into()),
            acl_arn.into(),
        );
        Ok(json!({}))
    }

    fn disassociate_webacl(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(body, &["ResourceArn"])?;
        let resource = string(body, "ResourceArn")?;
        stage_arn(req, resource)?;
        let mut state = self.state.lock().map_err(|_| WafError::internal())?;
        if state
            .associations
            .remove(&(req.account_id.clone(), req.region.clone(), resource.into()))
            .is_none()
        {
            return Err(WafError::not_found());
        }
        Ok(json!({}))
    }

    fn get_webacl_for_resource(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(body, &["ResourceArn"])?;
        let resource = string(body, "ResourceArn")?;
        stage_arn(req, resource)?;
        let state = self.state.lock().map_err(|_| WafError::internal())?;
        let arn = state
            .associations
            .get(&(req.account_id.clone(), req.region.clone(), resource.into()))
            .ok_or_else(WafError::not_found)?;
        let acl = state
            .webacls
            .iter()
            .find(|((account, region, _), acl)| {
                account == &req.account_id && region == &req.region && acl.arn == arn.as_str()
            })
            .map(|(_, acl)| acl)
            .ok_or_else(WafError::internal)?;
        Ok(json!({"WebACL": web_full(acl)}))
    }

    fn list_resources_for_webacl(
        &self,
        req: &ServiceRequest,
        body: &Map<String, Value>,
    ) -> Result<Value, WafError> {
        fields(body, &["WebACLArn", "ResourceType"])?;
        let arn = string(body, "WebACLArn")?;
        if body.get("ResourceType").and_then(Value::as_str) != Some("API_GATEWAY") {
            return Err(WafError::unsupported());
        }
        let state = self.state.lock().map_err(|_| WafError::internal())?;
        if !state.webacls.iter().any(|((account, region, _), acl)| {
            account == &req.account_id && region == &req.region && acl.arn == arn
        }) {
            return Err(WafError::not_found());
        }
        let mut resources: Vec<&String> = state
            .associations
            .iter()
            .filter(|((account, region, _), linked)| {
                account == &req.account_id && region == &req.region && linked == &arn
            })
            .map(|((_, _, resource), _)| resource)
            .collect();
        resources.sort();
        Ok(json!({"ResourceArns": resources}))
    }
}

impl WafEvaluator for WafHandler {
    fn detach_stage(
        &self,
        account_id: &str,
        region: &str,
        resource_arn: &str,
    ) -> Result<(), WafEvaluationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WafEvaluationError::StateUnavailable)?;
        state.associations.remove(&(
            account_id.to_owned(),
            region.to_owned(),
            resource_arn.to_owned(),
        ));
        Ok(())
    }

    fn evaluate(&self, req: &WafRequest<'_>) -> Result<WafDecision, WafEvaluationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| WafEvaluationError::StateUnavailable)?;
        let key = (
            req.account_id.into(),
            req.region.into(),
            req.resource_arn.into(),
        );
        let Some(arn) = state.associations.get(&key) else {
            return Ok(WafDecision::Unassociated);
        };
        let acl = state
            .webacls
            .iter()
            .find(|((account, region, _), acl)| {
                account == req.account_id && region == req.region && &acl.arn == arn
            })
            .map(|(_, acl)| acl)
            .ok_or(WafEvaluationError::MissingWebAcl)?;
        let ip: IpAddr = req
            .source_ip
            .parse()
            .map_err(|_| WafEvaluationError::InvalidSourceIp)?;
        for rule in &acl.rules {
            if rule_matches(rule, &state, req, ip)? {
                return Ok(match rule.action {
                    Action::Allow => WafDecision::Allow,
                    Action::Block => WafDecision::Block,
                });
            }
        }
        Ok(match acl.default {
            Action::Allow => WafDecision::Allow,
            Action::Block => WafDecision::Block,
        })
    }
}

#[async_trait]
impl NativeHandler for WafHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        if request.method != http::Method::POST {
            return WafError::invalid().render(&request.request_id);
        }
        if !request
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|mime| mime.eq_ignore_ascii_case("application/x-amz-json-1.1"))
            })
        {
            return WafError::invalid().render(&request.request_id);
        }
        let target = request
            .headers
            .get("x-amz-target")
            .and_then(|v| v.to_str().ok());
        let Some(operation) = target.and_then(|value| value.strip_prefix(PREFIX)) else {
            return WafError::unsupported().render(&request.request_id);
        };
        if operation.is_empty() || !operation.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return WafError::unsupported().render(&request.request_id);
        }
        if request.body.len() > MAX_BODY {
            return WafError::limit().render(&request.request_id);
        }
        let body: Value = match serde_json::from_slice(&request.body) {
            Ok(value) => value,
            Err(_) => return WafError::invalid().render(&request.request_id),
        };
        let Some(body) = body.as_object() else {
            return WafError::invalid().render(&request.request_id);
        };
        match self.execute(operation, &request, body) {
            Ok(value) => Response::builder()
                .status(200)
                .header("content-type", "application/x-amz-json-1.1")
                .header("x-amzn-RequestId", request.request_id.as_str())
                .body(Body::from(value.to_string()))
                .expect("static response"),
            Err(error) => error.render(&request.request_id),
        }
    }
}

fn fields(body: &Map<String, Value>, accepted: &[&str]) -> Result<(), WafError> {
    if body.keys().any(|key| !accepted.contains(&key.as_str())) {
        return Err(WafError::unsupported());
    }
    Ok(())
}
fn regional(body: &Map<String, Value>) -> Result<(), WafError> {
    if body.get("Scope").and_then(Value::as_str) == Some("REGIONAL") {
        Ok(())
    } else {
        Err(WafError::unsupported())
    }
}
fn string<'a>(body: &'a Map<String, Value>, name: &str) -> Result<&'a str, WafError> {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(WafError::invalid)
}
fn name(body: &Map<String, Value>) -> Result<&str, WafError> {
    let name = string(body, "Name")?;
    if name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(WafError::invalid());
    }
    Ok(name)
}
fn optional_string(
    body: &Map<String, Value>,
    key: &str,
    limit: usize,
) -> Result<Option<String>, WafError> {
    match body.get(key) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() && value.len() <= limit => {
            Ok(Some(value.clone()))
        }
        _ => Err(WafError::invalid()),
    }
}
fn token() -> String {
    Uuid::new_v4().to_string()
}
fn key(req: &ServiceRequest, id: &str) -> (String, String, String) {
    (req.account_id.clone(), req.region.clone(), id.into())
}
fn arn(req: &ServiceRequest, kind: &str, name: &str, id: &str) -> String {
    format!(
        "arn:aws:wafv2:{}:{}:regional/{kind}/{name}/{id}",
        req.region, req.account_id
    )
}
fn ip_summary(set: &IpSet) -> Value {
    let mut value = json!({"ARN": set.arn, "Id": set.id, "LockToken": set.lock, "Name": set.name});
    if let Some(description) = &set.description {
        value["Description"] = json!(description);
    }
    value
}
fn ip_full(set: &IpSet) -> Value {
    let mut value = json!({"ARN": set.arn, "Id": set.id, "Name": set.name, "IPAddressVersion": set.version, "Addresses": set.addresses});
    if let Some(description) = &set.description {
        value["Description"] = json!(description);
    }
    value
}
fn web_summary(acl: &WebAcl) -> Value {
    let mut value = json!({"ARN": acl.arn, "Id": acl.id, "LockToken": acl.lock, "Name": acl.name});
    if let Some(description) = &acl.description {
        value["Description"] = json!(description);
    }
    value
}
fn web_full(acl: &WebAcl) -> Value {
    let rules: Vec<Value> = acl.rules.iter().map(|rule| rule.wire.clone()).collect();
    let mut value = json!({"ARN": acl.arn, "Id": acl.id, "Name": acl.name,
    "DefaultAction": action_wire(acl.default), "Rules": rules, "VisibilityConfig": acl.visibility,
    });
    if let Some(description) = &acl.description {
        value["Description"] = json!(description);
    }
    value
}
fn action_wire(action: Action) -> Value {
    match action {
        Action::Allow => json!({"Allow":{}}),
        Action::Block => json!({"Block":{}}),
    }
}
fn action(value: Option<&Value>) -> Result<Action, WafError> {
    let value = value
        .and_then(Value::as_object)
        .ok_or_else(WafError::invalid)?;
    if value.len() != 1 {
        return Err(WafError::invalid());
    }
    match value.keys().next().map(String::as_str) {
        Some("Allow") if value["Allow"].as_object().is_some_and(Map::is_empty) => Ok(Action::Allow),
        Some("Block") if value["Block"].as_object().is_some_and(Map::is_empty) => Ok(Action::Block),
        _ => Err(WafError::unsupported()),
    }
}
fn visibility(value: Option<&Value>) -> Result<Value, WafError> {
    let value = value
        .and_then(Value::as_object)
        .ok_or_else(WafError::invalid)?;
    if value.len() != 3
        || value
            .get("CloudWatchMetricsEnabled")
            .and_then(Value::as_bool)
            .is_none()
        || value
            .get("SampledRequestsEnabled")
            .and_then(Value::as_bool)
            .is_none()
        || value
            .get("MetricName")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && name.len() <= 128)
            .is_none()
    {
        return Err(WafError::invalid());
    }
    Ok(Value::Object(value.clone()))
}
fn addresses(
    body: &Map<String, Value>,
    version: &str,
) -> Result<(Vec<String>, Vec<Cidr>), WafError> {
    let values = body
        .get("Addresses")
        .and_then(Value::as_array)
        .ok_or_else(WafError::invalid)?;
    if values.len() > MAX_ADDRESSES {
        return Err(WafError::limit());
    }
    let mut strings = Vec::with_capacity(values.len());
    let mut cidrs = Vec::with_capacity(values.len());
    let mut seen = HashSet::new();
    for value in values {
        let text = value.as_str().ok_or_else(WafError::invalid)?;
        let cidr = parse_cidr(text, version)?;
        if !seen.insert(text) {
            return Err(WafError::invalid());
        }
        strings.push(text.into());
        cidrs.push(cidr);
    }
    Ok((strings, cidrs))
}
fn parse_cidr(text: &str, version: &str) -> Result<Cidr, WafError> {
    let (ip, prefix) = text.split_once('/').ok_or_else(WafError::invalid)?;
    let ip: IpAddr = ip.parse().map_err(|_| WafError::invalid())?;
    let prefix: u8 = prefix.parse().map_err(|_| WafError::invalid())?;
    if prefix == 0
        || match ip {
            IpAddr::V4(_) => version != "IPV4" || prefix > 32,
            IpAddr::V6(_) => version != "IPV6" || prefix > 128,
        }
    {
        return Err(WafError::invalid());
    }
    Ok(Cidr { ip, prefix })
}
impl Cidr {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl((32 - self.prefix) as u32).unwrap_or(0);
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl((128 - self.prefix) as u32)
                    .unwrap_or(0);
                (u128::from(network) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}
fn parse_rules(value: Option<&Value>) -> Result<Vec<Rule>, WafError> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(WafError::invalid)?;
    if values.len() > MAX_RULES {
        return Err(WafError::limit());
    }
    let mut rules = Vec::new();
    let mut priorities = HashSet::new();
    let mut names = HashSet::new();
    for value in values {
        let rule = value.as_object().ok_or_else(WafError::invalid)?;
        fields(
            rule,
            &[
                "Name",
                "Priority",
                "Statement",
                "Action",
                "VisibilityConfig",
            ],
        )?;
        let name = name(rule)?.to_string();
        let priority = rule
            .get("Priority")
            .and_then(Value::as_u64)
            .ok_or_else(WafError::invalid)?;
        if !names.insert(name.clone()) || !priorities.insert(priority) {
            return Err(WafError::invalid());
        }
        let action = action(rule.get("Action"))?;
        visibility(rule.get("VisibilityConfig"))?;
        let statement = parse_statement(rule.get("Statement"))?;
        rules.push(Rule {
            priority,
            action,
            statement,
            wire: value.clone(),
        });
    }
    rules.sort_by_key(|rule| rule.priority);
    Ok(rules)
}
fn parse_statement(value: Option<&Value>) -> Result<Statement, WafError> {
    let value = value
        .and_then(Value::as_object)
        .ok_or_else(WafError::invalid)?;
    if value.len() != 1 {
        return Err(WafError::invalid());
    }
    if let Some(reference) = value.get("IPSetReferenceStatement") {
        let reference = reference.as_object().ok_or_else(WafError::invalid)?;
        fields(reference, &["ARN"])?;
        return Ok(Statement::IpSet(string(reference, "ARN")?.into()));
    }
    if let Some(spec) = value.get("ByteMatchStatement") {
        let spec = spec.as_object().ok_or_else(WafError::invalid)?;
        fields(
            spec,
            &[
                "SearchString",
                "FieldToMatch",
                "TextTransformations",
                "PositionalConstraint",
            ],
        )?;
        let search = string(spec, "SearchString")?;
        let search = base64::engine::general_purpose::STANDARD
            .decode(search)
            .map_err(|_| WafError::invalid())?;
        if search.is_empty() || search.len() > 200 {
            return Err(WafError::invalid());
        }
        let field = spec
            .get("FieldToMatch")
            .and_then(Value::as_object)
            .ok_or_else(WafError::invalid)?;
        if field.len() != 1 {
            return Err(WafError::invalid());
        }
        let field = if field
            .get("UriPath")
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty)
        {
            Field::UriPath
        } else if let Some(header) = field.get("SingleHeader").and_then(Value::as_object) {
            if header.len() != 1 {
                return Err(WafError::invalid());
            }
            let name = string(header, "Name")?.to_ascii_lowercase();
            if !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(WafError::invalid());
            }
            Field::Header(name)
        } else {
            return Err(WafError::unsupported());
        };
        let transforms = spec
            .get("TextTransformations")
            .and_then(Value::as_array)
            .ok_or_else(WafError::invalid)?;
        if transforms.len() != 1 || transforms[0] != json!({"Priority":0,"Type":"NONE"}) {
            return Err(WafError::unsupported());
        }
        let position = match string(spec, "PositionalConstraint")? {
            "EXACTLY" => Position::Exact,
            "STARTS_WITH" => Position::StartsWith,
            "ENDS_WITH" => Position::EndsWith,
            "CONTAINS" => Position::Contains,
            _ => return Err(WafError::unsupported()),
        };
        return Ok(Statement::ByteMatch {
            field,
            search,
            position,
        });
    }
    Err(WafError::unsupported())
}
fn validate_references(
    state: &State,
    req: &ServiceRequest,
    rules: &[Rule],
) -> Result<(), WafError> {
    for rule in rules {
        if let Statement::IpSet(arn) = &rule.statement {
            if !state.ipsets.iter().any(|((account, region, _), set)| {
                account == &req.account_id && region == &req.region && &set.arn == arn
            }) {
                return Err(WafError::not_found());
            }
        }
    }
    Ok(())
}
fn rule_matches(
    rule: &Rule,
    state: &State,
    req: &WafRequest<'_>,
    ip: IpAddr,
) -> Result<bool, WafEvaluationError> {
    match &rule.statement {
        Statement::IpSet(arn) => {
            let set = state
                .ipsets
                .iter()
                .find(|((account, region, _), set)| {
                    account == req.account_id && region == req.region && &set.arn == arn
                })
                .map(|(_, set)| set)
                .ok_or(WafEvaluationError::MissingWebAcl)?;
            Ok(set.cidrs.iter().any(|cidr| cidr.contains(ip)))
        }
        Statement::ByteMatch {
            field,
            search,
            position,
        } => {
            let data: &[u8] = match field {
                Field::UriPath => req.uri_path.as_bytes(),
                Field::Header(name) => req
                    .headers
                    .get(name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .as_bytes(),
            };
            Ok(match position {
                Position::Exact => data == search,
                Position::StartsWith => data.starts_with(search),
                Position::EndsWith => data.ends_with(search),
                Position::Contains => data.windows(search.len()).any(|window| window == search),
            })
        }
    }
}
fn stage_arn(req: &ServiceRequest, arn: &str) -> Result<(), WafError> {
    let prefix = format!("arn:aws:apigateway:{}::/restapis/", req.region);
    let Some(tail) = arn.strip_prefix(&prefix) else {
        return Err(WafError::unsupported());
    };
    let Some((api, stage)) = tail.split_once("/stages/") else {
        return Err(WafError::invalid());
    };
    if api.is_empty() || stage.is_empty() || stage.contains('/') || api.contains('/') {
        return Err(WafError::invalid());
    }
    Ok(())
}
fn list_limit(body: &Map<String, Value>) -> Result<usize, WafError> {
    match body.get("Limit") {
        None => Ok(100),
        Some(value) => value
            .as_u64()
            .filter(|limit| (1..=100).contains(limit))
            .map(|limit| limit as usize)
            .ok_or_else(WafError::invalid),
    }
}
#[derive(Debug)]
struct WafError {
    code: &'static str,
    message: &'static str,
    status: u16,
}
impl WafError {
    fn new(code: &'static str, message: &'static str, status: u16) -> Self {
        Self {
            code,
            message,
            status,
        }
    }
    fn invalid() -> Self {
        Self::new("WAFInvalidParameterException", "Invalid WAF parameter", 400)
    }
    fn unsupported() -> Self {
        Self::new(
            "WAFInvalidOperationException",
            "WAF operation or feature is unavailable",
            400,
        )
    }
    fn duplicate() -> Self {
        Self::new(
            "WAFDuplicateItemException",
            "WAF resource already exists",
            400,
        )
    }
    fn not_found() -> Self {
        Self::new(
            "WAFNonexistentItemException",
            "WAF resource does not exist",
            400,
        )
    }
    fn stale() -> Self {
        Self::new("WAFOptimisticLockException", "WAF lock token is stale", 400)
    }
    fn associated() -> Self {
        Self::new("WAFAssociatedItemException", "WAF resource is in use", 400)
    }
    fn unavailable() -> Self {
        Self::new(
            "WAFUnavailableEntityException",
            "Protected stage is unavailable",
            400,
        )
    }
    fn limit() -> Self {
        Self::new(
            "WAFLimitsExceededException",
            "WAF resource limit exceeded",
            400,
        )
    }
    fn internal() -> Self {
        Self::new("WAFInternalErrorException", "WAF state is unavailable", 500)
    }
    fn render(self, request_id: &str) -> Response {
        AwsError::new(self.code, self.message, self.status)
            .with_request_id(request_id)
            .render(AwsProtocol::Json11)
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;

    struct ExistingStage;
    impl StageResolver for ExistingStage {
        fn stage_exists(&self, account: &str, region: &str, arn: &str) -> bool {
            account == "111111111111" && region == "us-east-1" && arn.ends_with("/stages/prod")
        }
    }

    fn request(account: &str, region: &str) -> ServiceRequest {
        ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: Bytes::new(),
            account_id: account.into(),
            region: region.into(),
            request_id: "test-request".into(),
        }
    }
    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }
    fn visibility() -> Value {
        json!({"CloudWatchMetricsEnabled":false,"SampledRequestsEnabled":false,"MetricName":"test"})
    }

    #[test]
    fn ipset_lock_tokens_and_scope_are_atomic() {
        let waf = WafHandler::new();
        let req = request("111111111111", "us-east-1");
        let created = waf.create_ipset(&req, &object(json!({
            "Name":"test-ip", "Scope":"REGIONAL", "IPAddressVersion":"IPV4", "Addresses":["192.0.2.0/24"]
        }))).unwrap();
        let id = created["Summary"]["Id"].as_str().unwrap();
        let lock = created["Summary"]["LockToken"].as_str().unwrap();
        let mut update = object(json!({"Name":"test-ip","Scope":"REGIONAL","Id":id,
            "LockToken":lock,"Addresses":["198.51.100.0/24"]}));
        let next = waf.update_ipset(&req, &update).unwrap()["NextLockToken"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(lock, next);
        assert!(waf.update_ipset(&req, &update).is_err());
        update.insert("LockToken".into(), json!(next));
        let east = waf
            .get_ipset(
                &req,
                &object(json!({"Name":"test-ip","Scope":"REGIONAL","Id":id})),
            )
            .unwrap();
        assert_eq!(east["IPSet"]["Addresses"], json!(["198.51.100.0/24"]));
        assert!(waf
            .get_ipset(
                &request("222222222222", "us-east-1"),
                &object(json!({"Name":"test-ip","Scope":"REGIONAL","Id":id}))
            )
            .is_err());
        assert!(waf
            .get_ipset(
                &request("111111111111", "us-west-2"),
                &object(json!({"Name":"test-ip","Scope":"REGIONAL","Id":id}))
            )
            .is_err());
        assert!(waf.create_ipset(&req, &object(json!({"Name":"other","Scope":"CLOUDFRONT","IPAddressVersion":"IPV4","Addresses":[]}))).is_err());
    }

    #[test]
    fn associated_acl_blocks_matching_ip_and_keeps_references() {
        let waf = WafHandler::new_with_stage_resolver(Arc::new(ExistingStage));
        let req = request("111111111111", "us-east-1");
        let ipset = waf.create_ipset(&req, &object(json!({
            "Name":"blocked-ip", "Scope":"REGIONAL", "IPAddressVersion":"IPV4", "Addresses":["192.0.2.0/24"]
        }))).unwrap();
        let ip_arn = ipset["Summary"]["ARN"].as_str().unwrap();
        let acl = waf
            .create_webacl(
                &req,
                &object(json!({
                    "Name":"test-acl", "Scope":"REGIONAL", "DefaultAction":{"Allow":{}},
                    "VisibilityConfig":visibility(),
                    "Rules":[{"Name":"block-ip","Priority":0,"Action":{"Block":{}},
                        "Statement":{"IPSetReferenceStatement":{"ARN":ip_arn}},
                        "VisibilityConfig":visibility()}]
                })),
            )
            .unwrap();
        let arn = acl["Summary"]["ARN"].as_str().unwrap();
        let stage = "arn:aws:apigateway:us-east-1::/restapis/abc/stages/prod";
        waf.associate_webacl(&req, &object(json!({"WebACLArn":arn,"ResourceArn":stage})))
            .unwrap();
        let headers = http::HeaderMap::new();
        let mut eval = WafRequest {
            account_id: "111111111111",
            region: "us-east-1",
            resource_arn: stage,
            source_ip: "192.0.2.42",
            method: "GET",
            uri_path: "/",
            headers: &headers,
        };
        assert_eq!(waf.evaluate(&eval), Ok(WafDecision::Block));
        eval.source_ip = "198.51.100.3";
        assert_eq!(waf.evaluate(&eval), Ok(WafDecision::Allow));
        assert!(waf
            .delete_ipset(
                &req,
                &object(json!({"Name":"blocked-ip","Scope":"REGIONAL",
            "Id":ipset["Summary"]["Id"],"LockToken":ipset["Summary"]["LockToken"]}))
            )
            .is_err());
        waf.disassociate_webacl(&req, &object(json!({"ResourceArn":stage})))
            .unwrap();
        assert_eq!(waf.evaluate(&eval), Ok(WafDecision::Unassociated));
    }

    #[test]
    fn unsupported_statement_and_missing_stage_fail_before_commit() {
        let waf = WafHandler::new();
        let req = request("111111111111", "us-east-1");
        let candidate = object(
            json!({"Name":"bad","Scope":"REGIONAL","DefaultAction":{"Allow":{}},
            "VisibilityConfig":visibility(), "Rules":[{"Name":"bad","Priority":0,
                "Action":{"Block":{}},"Statement":{"RateBasedStatement":{"Limit":100}},
                "VisibilityConfig":visibility()}]}),
        );
        assert!(waf.create_webacl(&req, &candidate).is_err());
        assert!(waf
            .list_webacls(&req, &object(json!({"Scope":"REGIONAL"})))
            .unwrap()["WebACLs"]
            .as_array()
            .unwrap()
            .is_empty());
        let candidate = object(
            json!({"Name":"good","Scope":"REGIONAL","DefaultAction":{"Allow":{}},
            "VisibilityConfig":visibility(),"Rules":[]}),
        );
        let created = waf.create_webacl(&req, &candidate).unwrap();
        let stage = "arn:aws:apigateway:us-east-1::/restapis/abc/stages/prod";
        assert!(waf
            .associate_webacl(
                &req,
                &object(json!({"WebACLArn":created["Summary"]["ARN"],"ResourceArn":stage}))
            )
            .is_err());
        assert!(waf
            .get_webacl_for_resource(&req, &object(json!({"ResourceArn":stage})))
            .is_err());
    }

    #[test]
    fn byte_match_uri_and_header() {
        let req = request("111111111111", "us-east-1");
        let waf = WafHandler::new_with_stage_resolver(Arc::new(ExistingStage));
        let encoded = base64::engine::general_purpose::STANDARD.encode("/admin");
        let acl = waf.create_webacl(&req, &object(json!({"Name":"uri-acl","Scope":"REGIONAL",
            "DefaultAction":{"Allow":{}},"VisibilityConfig":visibility(),"Rules":[{
            "Name":"admin", "Priority":0,"Action":{"Block":{}},"VisibilityConfig":visibility(),
            "Statement":{"ByteMatchStatement":{"SearchString":encoded,"PositionalConstraint":"STARTS_WITH",
              "FieldToMatch":{"UriPath":{}},"TextTransformations":[{"Priority":0,"Type":"NONE"}]}}
        }]}))).unwrap();
        let stage = "arn:aws:apigateway:us-east-1::/restapis/abc/stages/prod";
        waf.associate_webacl(
            &req,
            &object(json!({"WebACLArn":acl["Summary"]["ARN"],"ResourceArn":stage})),
        )
        .unwrap();
        let headers = http::HeaderMap::new();
        let mut eval = WafRequest {
            account_id: "111111111111",
            region: "us-east-1",
            resource_arn: stage,
            source_ip: "192.0.2.42",
            method: "GET",
            uri_path: "/admin/jobs",
            headers: &headers,
        };
        assert_eq!(waf.evaluate(&eval), Ok(WafDecision::Block));
        eval.uri_path = "/public";
        assert_eq!(waf.evaluate(&eval), Ok(WafDecision::Allow));
    }
}
