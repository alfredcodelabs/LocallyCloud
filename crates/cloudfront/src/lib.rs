//! Minimal CloudFront distribution control plane and process-local S3 viewer.
//! Unsupported configuration is rejected before publishing any distribution.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::response::Response;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use quick_xml::events::Event;
use quick_xml::Reader;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

const API: &str = "/2020-05-31";
const NS: &str = "http://cloudfront.amazonaws.com/doc/2020-05-31/";
const MAX_BODY: usize = 64 * 1024;
const MAX_CACHE_ENTRIES: usize = 256;
const MAX_CACHE_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBJECT_BYTES: usize = 1024 * 1024;
const MAX_VIEWER_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
struct Config {
    xml: String,
    caller_reference: String,
    origin_bucket: String,
    origin_region: String,
    enabled: bool,
    default_root_object: Option<String>,
    ttl: Duration,
}

struct Distribution {
    id: String,
    account: String,
    etag: u64,
    cache_generation: u64,
    updated_at: String,
    config: Config,
    cache: HashMap<String, Cached>,
    cache_bytes: usize,
    invalidations: Vec<Invalidation>,
}

struct Invalidation {
    id: String,
    caller_reference: String,
    paths: Vec<String>,
    created_at: String,
}

#[derive(Clone)]
struct Cached {
    body: Bytes,
    headers: HeaderMap,
    expires: Instant,
}

#[derive(Default)]
struct State {
    distributions: BTreeMap<String, Distribution>,
    caller_refs: HashMap<(String, String), String>,
}

pub struct CloudFrontHandler {
    registry: Weak<ServiceRegistry>,
    state: Mutex<State>,
}

impl CloudFrontHandler {
    pub fn new(registry: &Arc<ServiceRegistry>) -> Arc<Self> {
        Arc::new(Self {
            registry: Arc::downgrade(registry),
            state: Mutex::new(State::default()),
        })
    }

    async fn process(&self, request: &ServiceRequest) -> Response {
        let path = request.uri.path();
        if path.starts_with(API) {
            self.control(request).await
        } else {
            self.viewer(request).await
        }
    }

    async fn control(&self, request: &ServiceRequest) -> Response {
        if request.body.len() > MAX_BODY {
            return error("InvalidArgument", 400);
        }
        let path = request.uri.path().trim_end_matches('/');
        if path == format!("{API}/distribution") {
            return match request.method {
                Method::POST => self.create(request),
                Method::GET => self.list(request),
                _ => error("InvalidArgument", 400),
            };
        }
        let Some(suffix) = path.strip_prefix(&format!("{API}/distribution/")) else {
            return error("NoSuchDistribution", 404);
        };
        let segments: Vec<&str> = suffix.split('/').collect();
        match segments.as_slice() {
            [id] => match request.method {
                Method::GET => self.get(request, id, false),
                Method::DELETE => self.delete(request, id),
                _ => error("InvalidArgument", 400),
            },
            [id, "config"] => match request.method {
                Method::GET => self.get(request, id, true),
                Method::PUT => self.update(request, id),
                _ => error("InvalidArgument", 400),
            },
            [id, "invalidation"] => match request.method {
                Method::POST => self.invalidate(request, id),
                Method::GET => self.list_invalidations(request, id),
                _ => error("InvalidArgument", 400),
            },
            [id, "invalidation", inv_id] if request.method == Method::GET => {
                self.get_invalidation(request, id, inv_id)
            }
            _ => error("NoSuchDistribution", 404),
        }
    }

    fn create(&self, request: &ServiceRequest) -> Response {
        let config = match parse_config(&request.body) {
            Ok(config) => config,
            Err(code) => return error(code, 400),
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error("InternalError", 500),
        };
        if state
            .caller_refs
            .contains_key(&(request.account_id.clone(), config.caller_reference.clone()))
        {
            return error("DistributionAlreadyExists", 409);
        }
        if state.distributions.len() >= 1000 {
            return error("TooManyDistributions", 400);
        }
        let id = format!(
            "E{}",
            Uuid::new_v4().simple().to_string()[..12].to_ascii_uppercase()
        );
        let distribution = Distribution {
            id: id.clone(),
            account: request.account_id.clone(),
            etag: 1,
            cache_generation: 0,
            updated_at: timestamp(),
            config,
            cache: HashMap::new(),
            cache_bytes: 0,
            invalidations: Vec::new(),
        };
        let xml = distribution_xml(&distribution);
        let domain = domain(&id);
        state.caller_refs.insert(
            (
                request.account_id.clone(),
                distribution.config.caller_reference.clone(),
            ),
            id.clone(),
        );
        state.distributions.insert(id.clone(), distribution);
        xml_response(
            201,
            &xml,
            Some("1"),
            Some(&format!("{API}/distribution/{id}")),
            Some(&domain),
        )
    }

    fn get(&self, request: &ServiceRequest, id: &str, config_only: bool) -> Response {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error("InternalError", 500),
        };
        let Some(dist) = state
            .distributions
            .get(id)
            .filter(|d| d.account == request.account_id)
        else {
            return error("NoSuchDistribution", 404);
        };
        let xml = if config_only {
            dist.config.xml.clone()
        } else {
            distribution_xml(dist)
        };
        xml_response(200, &xml, Some(&dist.etag.to_string()), None, None)
    }

    fn list(&self, request: &ServiceRequest) -> Response {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error("InternalError", 500),
        };
        let list: Vec<&Distribution> = state
            .distributions
            .values()
            .filter(|d| d.account == request.account_id)
            .collect();
        let items = list
            .iter()
            .map(|d| distribution_summary_xml(d))
            .collect::<String>();
        let xml = format!("<DistributionList xmlns=\"{NS}\"><Marker></Marker><MaxItems>1000</MaxItems><IsTruncated>false</IsTruncated><Quantity>{}</Quantity><Items>{items}</Items></DistributionList>", list.len());
        xml_response(200, &xml, None, None, None)
    }

    fn update(&self, request: &ServiceRequest, id: &str) -> Response {
        let config = match parse_config(&request.body) {
            Ok(config) => config,
            Err(code) => return error(code, 400),
        };
        let Some(match_etag) = request
            .headers
            .get("if-match")
            .and_then(|h| h.to_str().ok())
        else {
            return error("PreconditionFailed", 412);
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error("InternalError", 500),
        };
        let Some(dist) = state
            .distributions
            .get_mut(id)
            .filter(|d| d.account == request.account_id)
        else {
            return error("NoSuchDistribution", 404);
        };
        if match_etag != dist.etag.to_string() {
            return error("PreconditionFailed", 412);
        }
        if config.caller_reference != dist.config.caller_reference {
            return error("IllegalUpdate", 400);
        }
        dist.config = config;
        dist.etag += 1;
        dist.updated_at = timestamp();
        dist.cache_generation += 1;
        dist.cache.clear();
        dist.cache_bytes = 0;
        xml_response(
            200,
            &distribution_xml(dist),
            Some(&dist.etag.to_string()),
            None,
            None,
        )
    }

    fn delete(&self, request: &ServiceRequest, id: &str) -> Response {
        let Some(match_etag) = request
            .headers
            .get("if-match")
            .and_then(|h| h.to_str().ok())
        else {
            return error("PreconditionFailed", 412);
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error("InternalError", 500),
        };
        let Some(dist) = state
            .distributions
            .get(id)
            .filter(|d| d.account == request.account_id)
        else {
            return error("NoSuchDistribution", 404);
        };
        if match_etag != dist.etag.to_string() {
            return error("PreconditionFailed", 412);
        }
        if dist.config.enabled {
            return error("DistributionNotDisabled", 409);
        }
        let caller = dist.config.caller_reference.clone();
        state.distributions.remove(id);
        state
            .caller_refs
            .remove(&(request.account_id.clone(), caller));
        Response::builder()
            .status(204)
            .body(Body::empty())
            .expect("valid response")
    }

    fn invalidate(&self, request: &ServiceRequest, id: &str) -> Response {
        let (caller_reference, paths) = match parse_invalidation(&request.body) {
            Ok(parsed) => parsed,
            Err(code) => return error(code, 400),
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error("InternalError", 500),
        };
        let Some(dist) = state
            .distributions
            .get_mut(id)
            .filter(|d| d.account == request.account_id)
        else {
            return error("NoSuchDistribution", 404);
        };
        if let Some(previous) = dist
            .invalidations
            .iter()
            .find(|i| i.caller_reference == caller_reference)
        {
            if previous.paths != paths {
                return error("InvalidationBatchAlreadyExists", 400);
            }
            return xml_response(
                201,
                &invalidation_xml(previous),
                None,
                Some(&format!(
                    "{API}/distribution/{id}/invalidation/{}",
                    previous.id
                )),
                None,
            );
        }
        dist.cache_generation += 1;
        for path in &paths {
            if path == "/*" {
                dist.cache.clear();
                dist.cache_bytes = 0;
                break;
            }
            if let Some(entry) = dist.cache.remove(path) {
                dist.cache_bytes -= entry.body.len();
            }
        }
        let invalidation = Invalidation {
            id: format!(
                "I{}",
                Uuid::new_v4().simple().to_string()[..12].to_ascii_uppercase()
            ),
            caller_reference,
            paths,
            created_at: timestamp(),
        };
        let xml = invalidation_xml(&invalidation);
        let location = format!("{API}/distribution/{id}/invalidation/{}", invalidation.id);
        dist.invalidations.insert(0, invalidation);
        xml_response(201, &xml, None, Some(&location), None)
    }

    fn get_invalidation(&self, request: &ServiceRequest, id: &str, inv_id: &str) -> Response {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error("InternalError", 500),
        };
        let Some(dist) = state
            .distributions
            .get(id)
            .filter(|d| d.account == request.account_id)
        else {
            return error("NoSuchDistribution", 404);
        };
        let Some(invalidation) = dist.invalidations.iter().find(|i| i.id == inv_id) else {
            return error("NoSuchInvalidation", 404);
        };
        xml_response(200, &invalidation_xml(invalidation), None, None, None)
    }

    fn list_invalidations(&self, request: &ServiceRequest, id: &str) -> Response {
        let mut marker = "";
        let mut max_items = 100usize;
        if let Some(query) = request.uri.query() {
            for pair in query.split('&') {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                match key {
                    "Marker" => marker = value,
                    "MaxItems" => match value.parse::<usize>() {
                        Ok(value) if value > 0 => max_items = value,
                        _ => return error("InvalidArgument", 400),
                    },
                    _ => {}
                }
            }
        }
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return error("InternalError", 500),
        };
        let Some(dist) = state
            .distributions
            .get(id)
            .filter(|d| d.account == request.account_id)
        else {
            return error("NoSuchDistribution", 404);
        };
        let start = if marker.is_empty() {
            0
        } else {
            match dist.invalidations.iter().position(|i| i.id == marker) {
                Some(position) => position + 1,
                None => return error("InvalidArgument", 400),
            }
        };
        let end = start
            .saturating_add(max_items)
            .min(dist.invalidations.len());
        let page = &dist.invalidations[start..end];
        let items = page
            .iter()
            .map(|i| {
                format!("<InvalidationSummary><Id>{}</Id><CreateTime>{}</CreateTime><Status>Completed</Status></InvalidationSummary>", i.id, i.created_at)
            })
            .collect::<String>();
        let truncated = end < dist.invalidations.len();
        let next_marker = if truncated {
            format!(
                "<NextMarker>{}</NextMarker>",
                page.last().expect("nonempty page").id
            )
        } else {
            String::new()
        };
        let xml = format!("<InvalidationList xmlns=\"{NS}\"><Marker>{}</Marker><MaxItems>{max_items}</MaxItems><IsTruncated>{truncated}</IsTruncated><Quantity>{}</Quantity><Items>{items}</Items>{next_marker}</InvalidationList>", escape(marker), page.len());
        xml_response(200, &xml, None, None, None)
    }

    async fn viewer(&self, request: &ServiceRequest) -> Response {
        if request.method != Method::GET && request.method != Method::HEAD {
            return viewer_error(405);
        }
        let host = request
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let Some(id) = host
            .split(':')
            .next()
            .unwrap_or(host)
            .strip_suffix(".cloudfront.localhost")
        else {
            return viewer_error(404);
        };
        let (bucket, key, account, region, cached, revision, cache_generation) = {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return viewer_error(503),
            };
            let Some(dist) = state
                .distributions
                .get_mut(id)
                .filter(|d| d.account == request.account_id && d.config.enabled)
            else {
                return viewer_error(404);
            };
            let path = if request.uri.path() == "/" {
                match &dist.config.default_root_object {
                    Some(root) => format!("/{root}"),
                    None => return viewer_error(404),
                }
            } else {
                request.uri.path().to_owned()
            };
            if path.contains("..") || path.len() > 1024 || request.uri.query().is_some() {
                return viewer_error(400);
            }
            let cached = dist
                .cache
                .get(&path)
                .filter(|entry| entry.expires > Instant::now())
                .cloned();
            (
                dist.config.origin_bucket.clone(),
                path,
                dist.account.clone(),
                dist.config.origin_region.clone(),
                cached,
                dist.etag,
                dist.cache_generation,
            )
        };
        if let Some(entry) = cached {
            return cached_response(entry, request.method == Method::HEAD, true);
        }
        let Some(registry) = self.registry.upgrade() else {
            return viewer_error(503);
        };
        let Some(dispatcher) = registry.internal_dispatcher() else {
            return viewer_error(503);
        };
        let uri: Uri = match key.parse() {
            Ok(uri) => uri,
            Err(_) => return viewer_error(400),
        };
        let mut headers = HeaderMap::new();
        let origin_host = format!("{bucket}.s3.{region}.amazonaws.com");
        let host_value = match HeaderValue::from_str(&origin_host) {
            Ok(value) => value,
            Err(_) => return viewer_error(502),
        };
        headers.insert("host", host_value);
        let response = dispatcher
            .dispatch_scoped(
                &request.method,
                &uri,
                &headers,
                Bytes::new(),
                &request.request_id,
                &account,
                &region,
            )
            .await;
        let status = response.status();
        let origin_headers = response.headers().clone();
        let body = match to_bytes(response.into_body(), MAX_VIEWER_BYTES).await {
            Ok(body) => body,
            Err(_) => return viewer_error(502),
        };
        let mut result = Response::builder()
            .status(status)
            .header("x-cache", "Miss from cloudfront");
        for name in ["content-type", "etag", "last-modified", "cache-control"] {
            if let Some(value) = origin_headers.get(name) {
                result = result.header(name, value);
            }
        }
        if status == StatusCode::OK
            && request.method == Method::GET
            && body.len() <= MAX_OBJECT_BYTES
            && origin_headers.get("set-cookie").is_none()
            && !origin_headers
                .get("cache-control")
                .and_then(|h| h.to_str().ok())
                .is_some_and(|h| {
                    let h = h.to_ascii_lowercase();
                    h.contains("private") || h.contains("no-store") || h.contains("no-cache")
                })
        {
            if let Ok(mut state) = self.state.lock() {
                if let Some(dist) = state.distributions.get_mut(id).filter(|d| {
                    d.etag == revision && d.cache_generation == cache_generation && d.config.enabled
                }) {
                    while dist.cache.len() >= MAX_CACHE_ENTRIES
                        || dist.cache_bytes + body.len() > MAX_CACHE_BYTES
                    {
                        let Some(first) = dist.cache.keys().next().cloned() else {
                            break;
                        };
                        if let Some(removed) = dist.cache.remove(&first) {
                            dist.cache_bytes -= removed.body.len();
                        }
                    }
                    dist.cache_bytes += body.len();
                    dist.cache.insert(
                        key.clone(),
                        Cached {
                            body: body.clone(),
                            headers: origin_headers.clone(),
                            expires: Instant::now() + dist.config.ttl,
                        },
                    );
                }
            }
        }
        result
            .body(if request.method == Method::HEAD {
                Body::empty()
            } else {
                Body::from(body)
            })
            .expect("valid response")
    }
}

#[async_trait]
impl NativeHandler for CloudFrontHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        self.process(&request).await
    }
}

pub fn register(registry: &Arc<ServiceRegistry>) -> Arc<CloudFrontHandler> {
    let handler = CloudFrontHandler::new(registry);
    registry.register_native(
        ServiceName::new("cloudfront"),
        ServiceMetadata::new(AwsProtocol::RestXml, None),
        handler.clone(),
    );
    handler
}

fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 timestamp")
}
fn domain(id: &str) -> String {
    format!("{id}.cloudfront.localhost")
}
fn distribution_xml(dist: &Distribution) -> String {
    format!("<Distribution xmlns=\"{NS}\"><Id>{}</Id><ARN>arn:aws:cloudfront::{}:distribution/{}</ARN><Status>Deployed</Status><LastModifiedTime>{}</LastModifiedTime><DomainName>{}</DomainName><InProgressInvalidationBatches>0</InProgressInvalidationBatches>{}</Distribution>", dist.id, dist.account, dist.id, dist.updated_at, domain(&dist.id), dist.config.xml)
}
fn invalidation_xml(invalidation: &Invalidation) -> String {
    let items = invalidation
        .paths
        .iter()
        .map(|path| format!("<Path>{}</Path>", escape(path)))
        .collect::<String>();
    format!("<Invalidation xmlns=\"{NS}\"><Id>{}</Id><Status>Completed</Status><CreateTime>{}</CreateTime><InvalidationBatch><Paths><Quantity>{}</Quantity><Items>{items}</Items></Paths><CallerReference>{}</CallerReference></InvalidationBatch></Invalidation>", invalidation.id, invalidation.created_at, invalidation.paths.len(), escape(&invalidation.caller_reference))
}
fn distribution_summary_xml(dist: &Distribution) -> String {
    format!("<DistributionSummary><Id>{}</Id><ARN>arn:aws:cloudfront::{}:distribution/{}</ARN><Status>Deployed</Status><LastModifiedTime>{}</LastModifiedTime><DomainName>{}</DomainName><Enabled>{}</Enabled><Comment></Comment><Aliases><Quantity>0</Quantity></Aliases><Origins><Quantity>1</Quantity></Origins></DistributionSummary>", dist.id, dist.account, dist.id, dist.updated_at, domain(&dist.id), dist.config.enabled)
}
fn xml_response(
    status: u16,
    xml: &str,
    etag: Option<&str>,
    location: Option<&str>,
    _domain: Option<&str>,
) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/xml");
    if let Some(etag) = etag {
        builder = builder.header("etag", etag);
    }
    if let Some(location) = location {
        builder = builder.header("location", location);
    }
    builder
        .body(Body::from(xml.to_owned()))
        .expect("valid XML response")
}
fn error(code: &str, status: u16) -> Response {
    let xml = format!("<ErrorResponse xmlns=\"{NS}\"><Error><Type>Sender</Type><Code>{code}</Code><Message>{code}</Message></Error><RequestId>locallycloud</RequestId></ErrorResponse>");
    xml_response(status, &xml, None, None, None)
}
fn viewer_error(status: u16) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Body::from("CloudFront request failed"))
        .expect("valid response")
}
fn cached_response(entry: Cached, head: bool, hit: bool) -> Response {
    let mut builder = Response::builder().status(200).header(
        "x-cache",
        if hit {
            "Hit from cloudfront"
        } else {
            "Miss from cloudfront"
        },
    );
    for name in ["content-type", "etag", "last-modified", "cache-control"] {
        if let Some(value) = entry.headers.get(name) {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(if head {
            Body::empty()
        } else {
            Body::from(entry.body)
        })
        .expect("valid cache response")
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Default)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}
impl Node {
    fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|n| n.name == name)
    }
    fn children(&self, name: &str) -> Vec<&Node> {
        self.children.iter().filter(|n| n.name == name).collect()
    }
    fn value(&self, name: &str) -> Result<&str, &'static str> {
        self.child(name)
            .map(|n| n.text.as_str())
            .ok_or("InvalidArgument")
    }
    fn quantity(&self) -> Result<usize, &'static str> {
        self.value("Quantity")?
            .parse()
            .map_err(|_| "InvalidArgument")
    }
}
fn parse_xml(body: &[u8]) -> Result<Node, &'static str> {
    if body.is_empty() || body.len() > MAX_BODY {
        return Err("InvalidArgument");
    }
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<Node> = Vec::new();
    let mut result = None;
    let mut count = 0;
    loop {
        match reader.read_event().map_err(|_| "InvalidArgument")? {
            Event::Start(event) => {
                count += 1;
                if count > 256 || stack.len() >= 32 {
                    return Err("InvalidArgument");
                }
                let name = event.local_name().as_ref().to_owned();
                stack.push(Node {
                    name,
                    ..Node::default()
                });
            }
            Event::Empty(event) => {
                count += 1;
                if count > 256 {
                    return Err("InvalidArgument");
                }
                let name = event.local_name().as_ref().to_owned();
                let node = Node {
                    name,
                    ..Node::default()
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if result.replace(node).is_some() {
                    return Err("InvalidArgument");
                }
            }
            Event::Text(event) => {
                let text =
                    quick_xml::escape::unescape(event.as_ref()).map_err(|_| "InvalidArgument")?;
                if let Some(parent) = stack.last_mut() {
                    parent.text.push_str(&text);
                } else if !text.trim().is_empty() {
                    return Err("InvalidArgument");
                }
            }
            Event::CData(event) => {
                let text = event.as_ref();
                if let Some(parent) = stack.last_mut() {
                    parent.text.push_str(text);
                } else {
                    return Err("InvalidArgument");
                }
            }
            Event::End(_) => {
                let node = stack.pop().ok_or("InvalidArgument")?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if result.replace(node).is_some() {
                    return Err("InvalidArgument");
                }
            }
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) => {}
            _ => return Err("InvalidArgument"),
        }
    }
    if !stack.is_empty() {
        return Err("InvalidArgument");
    }
    result.ok_or("InvalidArgument")
}
fn empty_collection(node: Option<&Node>) -> Result<(), &'static str> {
    if let Some(node) = node {
        if node.quantity()? != 0
            || node
                .child("Items")
                .is_some_and(|items| !items.children.is_empty())
        {
            return Err("InvalidArgument");
        }
    }
    Ok(())
}
fn only_children(node: &Node, names: &[&str]) -> Result<(), &'static str> {
    if node
        .children
        .iter()
        .any(|child| !names.contains(&child.name.as_str()))
    {
        Err("InvalidArgument")
    } else {
        Ok(())
    }
}
fn parse_config(body: &[u8]) -> Result<Config, &'static str> {
    let root = parse_xml(body)?;
    if root.name != "DistributionConfig" {
        return Err("InvalidArgument");
    }
    only_children(
        &root,
        &[
            "CallerReference",
            "Aliases",
            "DefaultRootObject",
            "Origins",
            "DefaultCacheBehavior",
            "Comment",
            "Enabled",
            "ViewerCertificate",
        ],
    )?;
    let caller_reference = root.value("CallerReference")?;
    if caller_reference.is_empty() || caller_reference.len() > 128 {
        return Err("InvalidArgument");
    }
    if root.value("Comment")?.len() > 128 {
        return Err("InvalidArgument");
    }
    let enabled = match root.value("Enabled")? {
        "true" => true,
        "false" => false,
        _ => return Err("InvalidArgument"),
    };
    empty_collection(root.child("Aliases"))?;
    empty_collection(root.child("CacheBehaviors"))?;
    empty_collection(root.child("CustomErrorResponses"))?;
    if root.child("WebACLId").is_some_and(|n| !n.text.is_empty()) {
        return Err("InvalidArgument");
    }
    if root.child("OriginGroups").is_some() || root.child("ContinuousDeploymentPolicyId").is_some()
    {
        return Err("InvalidArgument");
    }
    if let Some(cert) = root.child("ViewerCertificate") {
        if cert.value("CloudFrontDefaultCertificate")? != "true"
            || cert
                .children
                .iter()
                .any(|c| c.name != "CloudFrontDefaultCertificate")
        {
            return Err("InvalidArgument");
        }
    }
    let origins = root.child("Origins").ok_or("InvalidArgument")?;
    if origins.quantity()? != 1 {
        return Err("InvalidArgument");
    }
    let items = origins.child("Items").ok_or("InvalidArgument")?;
    let one_origin = items.children("Origin");
    if one_origin.len() != 1 {
        return Err("InvalidArgument");
    }
    let origin = one_origin[0];
    only_children(
        origin,
        &[
            "Id",
            "DomainName",
            "S3OriginConfig",
            "OriginPath",
            "OriginAccessControlId",
        ],
    )?;
    let origin_id = origin.value("Id")?;
    let origin_host = origin.value("DomainName")?;
    let (bucket, tail) = origin_host.split_once(".s3.").ok_or("InvalidArgument")?;
    let region = tail
        .strip_suffix(".amazonaws.com")
        .ok_or("InvalidArgument")?;
    if region.is_empty()
        || region.len() > 32
        || !region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("InvalidArgument");
    }
    if bucket.len() < 3
        || bucket.len() > 63
        || !bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err("InvalidArgument");
    }
    if origin.child("S3OriginConfig").is_none()
        || origin.child("CustomOriginConfig").is_some()
        || origin
            .child("OriginAccessControlId")
            .is_some_and(|n| !n.text.is_empty())
        || origin
            .child("OriginPath")
            .is_some_and(|n| !n.text.is_empty())
        || origin.child("CustomHeaders").is_some()
    {
        return Err("InvalidArgument");
    }
    let s3 = origin.child("S3OriginConfig").ok_or("InvalidArgument")?;
    only_children(s3, &["OriginAccessIdentity"])?;
    if s3
        .child("OriginAccessIdentity")
        .is_some_and(|n| !n.text.is_empty())
    {
        return Err("InvalidArgument");
    }
    let behavior = root
        .child("DefaultCacheBehavior")
        .ok_or("InvalidArgument")?;
    if behavior.value("TargetOriginId")? != origin_id
        || behavior.value("ViewerProtocolPolicy")? != "allow-all"
    {
        return Err("InvalidArgument");
    }
    if behavior.child("CachePolicyId").is_some()
        || behavior.child("OriginRequestPolicyId").is_some()
        || behavior.child("ResponseHeadersPolicyId").is_some()
    {
        return Err("InvalidArgument");
    }
    empty_collection(behavior.child("TrustedSigners"))?;
    empty_collection(behavior.child("TrustedKeyGroups"))?;
    empty_collection(behavior.child("LambdaFunctionAssociations"))?;
    empty_collection(behavior.child("FunctionAssociations"))?;
    if behavior
        .child("FieldLevelEncryptionId")
        .is_some_and(|n| !n.text.is_empty())
    {
        return Err("InvalidArgument");
    }
    if let Some(methods) = behavior.child("AllowedMethods") {
        let items = methods.child("Items").ok_or("InvalidArgument")?;
        let values: Vec<&str> = items
            .children("Method")
            .iter()
            .map(|n| n.text.as_str())
            .collect();
        if methods.quantity()? != 2 || values != ["GET", "HEAD"] {
            return Err("InvalidArgument");
        }
    }
    if let Some(forwarded) = behavior.child("ForwardedValues") {
        only_children(forwarded, &["QueryString", "Cookies", "Headers"])?;
        if forwarded.value("QueryString")? != "false" {
            return Err("InvalidArgument");
        }
        if forwarded
            .child("Cookies")
            .ok_or("InvalidArgument")?
            .value("Forward")?
            != "none"
        {
            return Err("InvalidArgument");
        }
        empty_collection(forwarded.child("Headers"))?;
    }
    let ttl = behavior
        .child("DefaultTTL")
        .map(|n| n.text.parse::<u64>().map_err(|_| "InvalidArgument"))
        .transpose()?
        .unwrap_or(60)
        .min(60);
    let default_root_object = root
        .child("DefaultRootObject")
        .map(|n| n.text.clone())
        .filter(|n| !n.is_empty());
    if default_root_object
        .as_ref()
        .is_some_and(|n| n.starts_with('/') || n.contains("..") || n.len() > 1024)
    {
        return Err("InvalidArgument");
    }
    let raw = std::str::from_utf8(body).map_err(|_| "InvalidArgument")?;
    let start = raw.find("<DistributionConfig").ok_or("InvalidArgument")?;
    let xml = raw[start..].trim().to_owned();
    Ok(Config {
        xml,
        caller_reference: caller_reference.to_owned(),
        origin_bucket: bucket.to_owned(),
        origin_region: region.to_owned(),
        enabled,
        default_root_object,
        ttl: Duration::from_secs(ttl),
    })
}
fn parse_invalidation(body: &[u8]) -> Result<(String, Vec<String>), &'static str> {
    let root = parse_xml(body)?;
    if root.name != "InvalidationBatch" || root.value("CallerReference")?.is_empty() {
        return Err("InvalidArgument");
    }
    let paths = root.child("Paths").ok_or("InvalidArgument")?;
    let quantity = paths.quantity()?;
    if quantity == 0 || quantity > 1000 {
        return Err("InvalidArgument");
    }
    let items = paths.child("Items").ok_or("InvalidArgument")?;
    let values: Vec<String> = items
        .children("Path")
        .iter()
        .map(|n| n.text.clone())
        .collect();
    if values.len() != quantity
        || values
            .iter()
            .any(|p| !p.starts_with('/') || p.len() > 1024 || (p.contains('*') && p != "/*"))
    {
        return Err("InvalidArgument");
    }
    Ok((root.value("CallerReference")?.to_owned(), values))
}

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::integration::InternalDispatcher;
    use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    struct PausedS3 {
        calls: AtomicUsize,
        entered: Notify,
        release: Notify,
    }

    #[async_trait]
    impl NativeHandler for PausedS3 {
        async fn handle(&self, _request: ServiceRequest) -> Response {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                self.entered.notify_one();
                self.release.notified().await;
            }
            Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .body(Body::from(if call == 0 { "old" } else { "new" }))
                .unwrap()
        }
    }

    fn request(
        method: Method,
        path: &str,
        body: impl Into<Bytes>,
        host: Option<&str>,
    ) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        if let Some(host) = host {
            headers.insert("host", host.parse().unwrap());
        }
        ServiceRequest {
            method,
            uri: path.parse().unwrap(),
            headers,
            body: body.into(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "test".into(),
        }
    }

    #[tokio::test]
    async fn completed_invalidations_do_not_exhaust_creation_capacity() {
        let registry = ServiceRegistry::with_known_services();
        let cloudfront = CloudFrontHandler::new(&registry);
        let id = "EBOUNDARY";
        cloudfront.state.lock().unwrap().distributions.insert(
            id.to_owned(),
            Distribution {
                id: id.to_owned(),
                account: "000000000000".to_owned(),
                etag: 1,
                cache_generation: 0,
                updated_at: timestamp(),
                config: Config {
                    xml: String::new(),
                    caller_reference: "boundary".to_owned(),
                    origin_bucket: String::new(),
                    origin_region: String::new(),
                    enabled: true,
                    default_root_object: None,
                    ttl: Duration::ZERO,
                },
                cache: HashMap::new(),
                cache_bytes: 0,
                invalidations: Vec::new(),
            },
        );
        for n in 0..1001 {
            let body = format!("<InvalidationBatch><CallerReference>boundary-{n}</CallerReference><Paths><Quantity>1</Quantity><Items><Path>/*</Path></Items></Paths></InvalidationBatch>");
            let response = cloudfront.invalidate(
                &request(
                    Method::POST,
                    &format!("{API}/distribution/{id}/invalidation"),
                    body,
                    None,
                ),
                id,
            );
            assert_eq!(response.status(), 201, "invalidation {n} failed");
        }
        let list = cloudfront.list_invalidations(
            &request(
                Method::GET,
                &format!("{API}/distribution/{id}/invalidation?MaxItems=1001"),
                Bytes::new(),
                None,
            ),
            id,
        );
        assert_eq!(list.status(), 200);
        let xml = to_bytes(list.into_body(), 1024 * 1024).await.unwrap();
        let xml = std::str::from_utf8(&xml).unwrap();
        assert!(xml.contains("<Quantity>1001</Quantity>"));
        let first_id = cloudfront.state.lock().unwrap().distributions[id]
            .invalidations
            .last()
            .unwrap()
            .id
            .clone();
        let first = cloudfront.get_invalidation(
            &request(
                Method::GET,
                &format!("{API}/distribution/{id}/invalidation/{first_id}"),
                Bytes::new(),
                None,
            ),
            id,
            &first_id,
        );
        assert_eq!(first.status(), 200);
        let first_xml = to_bytes(first.into_body(), 4096).await.unwrap();
        assert!(std::str::from_utf8(&first_xml)
            .unwrap()
            .contains("<CallerReference>boundary-0</CallerReference>"));
    }

    #[tokio::test]
    async fn invalidation_during_origin_read_prevents_stale_cache_reinsert() {
        let registry = ServiceRegistry::with_known_services();
        let s3 = Arc::new(PausedS3 {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
        });
        registry.register_native(
            ServiceName::new("s3"),
            ServiceMetadata::new(AwsProtocol::RestXml, None),
            s3.clone(),
        );
        let dispatcher = Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(2),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        ));
        registry.set_internal_dispatcher(dispatcher);
        let cloudfront = CloudFrontHandler::new(&registry);
        let config = format!("<DistributionConfig xmlns=\"{NS}\"><CallerReference>race</CallerReference><Aliases><Quantity>0</Quantity></Aliases><DefaultRootObject>key</DefaultRootObject><Origins><Quantity>1</Quantity><Items><Origin><Id>s3</Id><DomainName>bucket.s3.us-east-1.amazonaws.com</DomainName><S3OriginConfig><OriginAccessIdentity></OriginAccessIdentity></S3OriginConfig></Origin></Items></Origins><DefaultCacheBehavior><TargetOriginId>s3</TargetOriginId><ViewerProtocolPolicy>allow-all</ViewerProtocolPolicy><TrustedSigners><Quantity>0</Quantity></TrustedSigners><ForwardedValues><QueryString>false</QueryString><Cookies><Forward>none</Forward></Cookies></ForwardedValues><DefaultTTL>60</DefaultTTL></DefaultCacheBehavior><Comment></Comment><Enabled>true</Enabled></DistributionConfig>");
        let created = cloudfront.create(&request(
            Method::POST,
            &format!("{API}/distribution"),
            config,
            None,
        ));
        assert_eq!(created.status(), 201);
        let id = cloudfront
            .state
            .lock()
            .unwrap()
            .distributions
            .keys()
            .next()
            .unwrap()
            .clone();
        let host = domain(&id);
        let first = {
            let handler = cloudfront.clone();
            let host = host.clone();
            tokio::spawn(async move {
                handler
                    .viewer(&request(Method::GET, "/", Bytes::new(), Some(&host)))
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), s3.entered.notified())
            .await
            .unwrap();
        let invalidation = format!("<InvalidationBatch xmlns=\"{NS}\"><CallerReference>race-invalidation</CallerReference><Paths><Quantity>1</Quantity><Items><Path>/*</Path></Items></Paths></InvalidationBatch>");
        let invalidated = cloudfront.invalidate(
            &request(
                Method::POST,
                &format!("{API}/distribution/{id}/invalidation"),
                invalidation,
                None,
            ),
            &id,
        );
        assert_eq!(invalidated.status(), 201);
        s3.release.notify_one();
        let stale = first.await.unwrap();
        assert_eq!(to_bytes(stale.into_body(), 64).await.unwrap(), "old");
        let fresh = cloudfront
            .viewer(&request(Method::GET, "/", Bytes::new(), Some(&host)))
            .await;
        assert_eq!(
            fresh.headers().get("x-cache").unwrap(),
            "Miss from cloudfront"
        );
        assert_eq!(to_bytes(fresh.into_body(), 64).await.unwrap(), "new");
        let hit = cloudfront
            .viewer(&request(Method::GET, "/", Bytes::new(), Some(&host)))
            .await;
        assert_eq!(hit.headers().get("x-cache").unwrap(), "Hit from cloudfront");
        assert_eq!(to_bytes(hit.into_body(), 64).await.unwrap(), "new");
        assert_eq!(s3.calls.load(Ordering::SeqCst), 2);
    }
}
