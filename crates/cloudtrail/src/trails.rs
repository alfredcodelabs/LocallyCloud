//! Lazy serialized trail control and real S3 delivery. The audit callback never waits for I/O.
use super::*;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use locallycloud_core::integration::{
    correlation::CorrelationContext,
    delivery::{CrossServiceCall, DeliveryEngine},
    identity::CallerIdentity,
};
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::params;
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    OnceLock, Weak,
};
use tokio::sync::{mpsc, oneshot};

const QUEUE_LIMIT: usize = 1024;
type Key = (String, String, String);

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Trail {
    account: String,
    region: String,
    name: String,
    bucket: String,
    prefix: String,
    include_global: bool,
    multi_region: bool,
    tags: BTreeMap<String, String>,
    logging: bool,
    started: Option<f64>,
    stopped: Option<f64>,
    delivered: Option<f64>,
    error: Option<String>,
    selectors: Vec<Value>,
}
impl Trail {
    fn arn(&self) -> String {
        format!(
            "arn:aws:cloudtrail:{}:{}:trail/{}",
            self.region, self.account, self.name
        )
    }
    fn key(&self) -> Key {
        (self.account.clone(), self.region.clone(), self.name.clone())
    }
    fn view(&self) -> Value {
        json!({"Name":self.name,"S3BucketName":self.bucket,"S3KeyPrefix":self.prefix,"TrailARN":self.arn(),"HomeRegion":self.region,"IncludeGlobalServiceEvents":self.include_global,"IsMultiRegionTrail":self.multi_region,"LogFileValidationEnabled":false,"IsOrganizationTrail":false})
    }
}
struct Persistence {
    db: Arc<StateDb>,
    cipher: StateCipher,
}
impl Persistence {
    fn with_cipher(db: Arc<StateDb>, cipher: StateCipher) -> Result<Self, String> {
        db.connection().map_err(|e|e.to_string())?.execute_batch("CREATE TABLE IF NOT EXISTS cloudtrail_trails(account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(account,region,name))").map_err(|e|e.to_string())?;
        Ok(Self { db, cipher })
    }
    fn restore(&self) -> Result<BTreeMap<Key, Trail>, String> {
        let connection = self.db.connection().map_err(|e| e.to_string())?;
        let mut query=connection.prepare("SELECT account,region,name,payload FROM cloudtrail_trails ORDER BY account,region,name").map_err(|e|e.to_string())?;
        let rows = query
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut trails = BTreeMap::new();
        for row in rows {
            let (account, region, name, payload) = row.map_err(|e| e.to_string())?;
            let data = self
                .cipher
                .open(&["cloudtrail", &account, &region, &name], &payload)
                .map_err(|e| e.to_string())?;
            let trail: Trail = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
            if trail.key() != (account, region, name) {
                return Err("Invalid persisted CloudTrail scope".into());
            }
            trails.insert(trail.key(), trail);
        }
        Ok(trails)
    }
    fn save(&self, trail: &Trail) -> Result<(), Error> {
        let value = serde_json::to_vec(trail).map_err(|_| Error::internal())?;
        let payload = self
            .cipher
            .seal(
                &["cloudtrail", &trail.account, &trail.region, &trail.name],
                &value,
            )
            .map_err(|_| Error::internal())?;
        self.db.connection().map_err(|_|Error::internal())?.execute("INSERT INTO cloudtrail_trails(account,region,name,payload) VALUES(?1,?2,?3,?4) ON CONFLICT(account,region,name) DO UPDATE SET payload=excluded.payload",params![trail.account,trail.region,trail.name,payload]).map_err(|_|Error::internal())?;
        Ok(())
    }
    fn delete(&self, key: &Key) -> Result<(), Error> {
        self.db
            .connection()
            .map_err(|_| Error::internal())?
            .execute(
                "DELETE FROM cloudtrail_trails WHERE account=?1 AND region=?2 AND name=?3",
                params![key.0, key.1, key.2],
            )
            .map_err(|_| Error::internal())?;
        Ok(())
    }
}
#[derive(Default)]
struct Store {
    trails: BTreeMap<Key, Trail>,
    persistence: Option<Arc<Persistence>>,
    failed: bool,
}
impl Store {
    async fn save(&mut self, trail: Trail) -> Result<(), Error> {
        if let Some(persistence) = &self.persistence {
            let persistence = persistence.clone();
            let saved = trail.clone();
            let result = tokio::task::spawn_blocking(move || persistence.save(&saved))
                .await
                .map_err(|_| Error::internal())?;
            if let Err(error) = result {
                self.failed = true;
                return Err(error);
            }
            self.failed = false;
        }
        self.trails.insert(trail.key(), trail);
        Ok(())
    }
    async fn delete(&mut self, key: &Key) -> Result<(), Error> {
        if let Some(persistence) = &self.persistence {
            let persistence = persistence.clone();
            let key = key.clone();
            tokio::task::spawn_blocking(move || persistence.delete(&key))
                .await
                .map_err(|_| Error::internal())??;
        }
        self.trails.remove(key);
        Ok(())
    }
}
enum Command {
    Operation {
        op: String,
        request: Box<ServiceRequest>,
        body: Map<String, Value>,
        reply: oneshot::Sender<Result<Value, Error>>,
    },
    Event(AuditEvent),
}
#[derive(Default)]
pub(super) struct Trails {
    registry: Weak<ServiceRegistry>,
    initial: Mutex<Option<Store>>,
    sender: OnceLock<mpsc::Sender<Command>>,
    overflow: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
}
impl Trails {
    pub fn with_state(registry: Weak<ServiceRegistry>, db: Arc<StateDb>) -> Result<Self, String> {
        Self::with_cipher(
            registry,
            db,
            StateCipher::from_env().map_err(|e| e.to_string())?,
        )
    }
    pub(super) fn with_cipher(
        registry: Weak<ServiceRegistry>,
        db: Arc<StateDb>,
        cipher: StateCipher,
    ) -> Result<Self, String> {
        let persistence = Arc::new(Persistence::with_cipher(db, cipher)?);
        let trails = persistence.restore()?;
        let active = Arc::new(AtomicBool::new(trails.values().any(|trail| trail.logging)));
        Ok(Self {
            registry,
            active,
            initial: Mutex::new(Some(Store {
                trails,
                persistence: Some(persistence),
                failed: false,
            })),
            ..Self::default()
        })
    }
    fn sender(&self) -> Result<&mpsc::Sender<Command>, Error> {
        if let Some(sender) = self.sender.get() {
            return Ok(sender);
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| Error::internal())?;
        let mut initial = self.initial.lock().map_err(|_| Error::internal())?;
        Ok(self.sender.get_or_init(|| {
            let (sender, receiver) = mpsc::channel(QUEUE_LIMIT);
            let store = initial.take().unwrap_or_default();
            let registry = self.registry.clone();
            let overflow = self.overflow.clone();
            let active = self.active.clone();
            runtime.spawn(run_actor(receiver, store, registry, overflow, active));
            sender
        }))
    }
    pub fn observe(&self, event: AuditEvent) {
        if self.active.load(Ordering::Relaxed) {
            match self.sender() {
                Ok(sender) => {
                    if sender.try_send(Command::Event(event)).is_err() {
                        self.overflow.store(true, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    self.overflow.store(true, Ordering::Relaxed);
                }
            }
        }
    }
    pub(super) fn authorize(
        &self,
        request: &ServiceRequest,
        op: &str,
        resource: &str,
    ) -> Result<(), Error> {
        locallycloud_core::integration::authorization::authorize_native_read(
            &self.registry,
            request,
            "cloudtrail",
            &format!("cloudtrail:{op}"),
            resource,
        )
        .map_err(|_| {
            Error::new(
                "AccessDeniedException",
                "CloudTrail operation is not authorized",
            )
        })
    }
    pub async fn execute(
        &self,
        op: &str,
        request: ServiceRequest,
        body: Map<String, Value>,
    ) -> Result<Value, Error> {
        if !matches!(
            op,
            "CreateTrail"
                | "UpdateTrail"
                | "DeleteTrail"
                | "GetTrail"
                | "DescribeTrails"
                | "ListTrails"
                | "StartLogging"
                | "StopLogging"
                | "GetTrailStatus"
                | "AddTags"
                | "RemoveTags"
                | "ListTags"
                | "PutEventSelectors"
                | "GetEventSelectors"
        ) {
            return Err(Error::new(
                "UnsupportedOperationException",
                "CloudTrail operation is unavailable",
            ));
        }
        let resource = body
            .get("Name")
            .or_else(|| body.get("ResourceId"))
            .or_else(|| body.get("TrailName"))
            .and_then(Value::as_str)
            .map(|name| {
                if name.starts_with("arn:") {
                    name.to_owned()
                } else {
                    format!(
                        "arn:aws:cloudtrail:{}:{}:trail/{name}",
                        request.region, request.account_id
                    )
                }
            })
            .unwrap_or_else(|| "*".into());
        if op == "ListTags" {
            let resources = body
                .get("ResourceIdList")
                .and_then(Value::as_array)
                .filter(|values| !values.is_empty() && values.len() <= 20)
                .ok_or_else(|| Error::new("InvalidParameterException", "Invalid resource list"))?;
            for resource in resources {
                self.authorize(
                    &request,
                    op,
                    resource.as_str().ok_or_else(|| {
                        Error::new("InvalidParameterException", "Invalid resource ARN")
                    })?,
                )?;
            }
        } else {
            self.authorize(&request, op, &resource)?;
        }
        let (reply, result) = oneshot::channel();
        self.sender()?
            .send(Command::Operation {
                op: op.into(),
                request: Box::new(request),
                body,
                reply,
            })
            .await
            .map_err(|_| Error::internal())?;
        result.await.map_err(|_| Error::internal())?
    }
}

fn fields(body: &Map<String, Value>, allowed: &[&str]) -> Result<(), Error> {
    if body.keys().any(|key| !allowed.contains(&key.as_str())) {
        Err(Error::new(
            "UnsupportedOperationException",
            "Unsupported trail configuration",
        ))
    } else {
        Ok(())
    }
}
fn required<'a>(body: &'a Map<String, Value>, key: &str) -> Result<&'a str, Error> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            Error::new(
                "InvalidParameterException",
                "Required string parameter is missing",
            )
        })
}
fn boolean(body: &Map<String, Value>, key: &str, default: bool) -> Result<bool, Error> {
    match body.get(key) {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(Error::new(
            "InvalidParameterException",
            "Invalid Boolean parameter",
        )),
    }
}
fn key(request: &ServiceRequest, name: &str) -> Result<Key, Error> {
    let prefix = format!(
        "arn:aws:cloudtrail:{}:{}:trail/",
        request.region, request.account_id
    );
    let name = if name.starts_with("arn:") {
        name.strip_prefix(&prefix)
            .ok_or_else(|| Error::new("TrailNotFoundException", "Trail not found"))?
    } else {
        name
    };
    Ok((
        request.account_id.clone(),
        request.region.clone(),
        name.into(),
    ))
}
fn get(store: &Store, key: &Key) -> Result<Trail, Error> {
    store
        .trails
        .get(key)
        .cloned()
        .ok_or_else(|| Error::new("TrailNotFoundException", "Trail not found"))
}
fn tags(value: Option<&Value>) -> Result<BTreeMap<String, String>, Error> {
    let mut result = BTreeMap::new();
    let Some(value) = value else {
        return Ok(result);
    };
    let list = value
        .as_array()
        .filter(|l| l.len() <= 200)
        .ok_or_else(|| Error::new("InvalidTagParameterException", "Invalid trail tags"))?;
    for tag in list {
        let key = tag["Key"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 128 && !v.starts_with("aws:"))
            .ok_or_else(|| Error::new("InvalidTagParameterException", "Invalid tag key"))?;
        let value = tag
            .get("Value")
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| Error::new("InvalidTagParameterException", "Invalid tag value"))
            })
            .transpose()?
            .unwrap_or("");
        if value.len() > 256 || result.insert(key.into(), value.into()).is_some() {
            return Err(Error::new(
                "InvalidTagParameterException",
                "Invalid trail tags",
            ));
        }
    }
    Ok(result)
}
fn configuration(request: &ServiceRequest, body: &Map<String, Value>) -> Result<Trail, Error> {
    fields(
        body,
        &[
            "Name",
            "S3BucketName",
            "S3KeyPrefix",
            "IncludeGlobalServiceEvents",
            "IsMultiRegionTrail",
            "EnableLogFileValidation",
            "IsOrganizationTrail",
            "TagsList",
        ],
    )?;
    let name = required(body, "Name")?;
    if !(3..=128).contains(&name.len())
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        || !name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || name
            .as_bytes()
            .windows(2)
            .any(|p| !p[0].is_ascii_alphanumeric() && !p[1].is_ascii_alphanumeric())
        || name.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(Error::new(
            "InvalidTrailNameException",
            "Invalid trail name",
        ));
    }
    let bucket = required(body, "S3BucketName")?;
    if !(3..=63).contains(&bucket.len())
        || !bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        || bucket.contains("..")
        || bucket.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(Error::new(
            "InvalidS3BucketNameException",
            "Invalid S3 bucket name",
        ));
    }
    let prefix = match body.get("S3KeyPrefix") {
        None => "",
        Some(Value::String(v)) => v,
        _ => return Err(Error::new("InvalidS3PrefixException", "Invalid S3 prefix")),
    };
    if prefix.len() > 200
        || prefix
            .bytes()
            .any(|b| b.is_ascii_control() || b == b'\\' || b == b'%')
        || prefix.split('/').any(|p| p == ".." || p == ".")
    {
        return Err(Error::new("InvalidS3PrefixException", "Invalid S3 prefix"));
    }
    if boolean(body, "EnableLogFileValidation", false)?
        || boolean(body, "IsOrganizationTrail", false)?
    {
        return Err(Error::new(
            "UnsupportedOperationException",
            "Log digests and organization trails are unavailable",
        ));
    }
    Ok(Trail {
        account: request.account_id.clone(),
        region: request.region.clone(),
        name: name.into(),
        bucket: bucket.into(),
        prefix: prefix.trim_matches('/').into(),
        include_global: boolean(body, "IncludeGlobalServiceEvents", true)?,
        multi_region: boolean(body, "IsMultiRegionTrail", false)?,
        tags: tags(body.get("TagsList"))?,
        logging: false,
        started: None,
        stopped: None,
        delivered: None,
        error: None,
        selectors: vec![
            json!({"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[]}),
        ],
    })
}

async fn operation(
    registry: &Weak<ServiceRegistry>,
    store: &mut Store,
    op: &str,
    request: &ServiceRequest,
    body: &Map<String, Value>,
) -> Result<Value, Error> {
    match op {
        "CreateTrail" => {
            let trail = configuration(request, body)?;
            if store.trails.contains_key(&trail.key()) {
                return Err(Error::new(
                    "TrailAlreadyExistsException",
                    "Trail already exists",
                ));
            }
            if store.trails.len() >= 1000
                || store
                    .trails
                    .values()
                    .filter(|t| t.account == request.account_id && t.region == request.region)
                    .count()
                    >= 5
            {
                return Err(Error::new(
                    "MaximumNumberOfTrailsExceededException",
                    "Trail limit exceeded",
                ));
            }
            preflight(registry, &trail).await?;
            let response = trail.view();
            store.save(trail).await?;
            Ok(response)
        }
        "DescribeTrails" => {
            fields(body, &["trailNameList", "includeShadowTrails"])?;
            let shadow = boolean(body, "includeShadowTrails", true)?;
            let names = body
                .get("trailNameList")
                .map(|v| {
                    v.as_array().filter(|v| v.len() <= 100).ok_or_else(|| {
                        Error::new("InvalidParameterException", "Invalid trail list")
                    })
                })
                .transpose()?;
            if names.is_some_and(|names| names.iter().any(|name| name.as_str().is_none())) {
                return Err(Error::new(
                    "InvalidParameterException",
                    "Invalid trail list",
                ));
            }
            Ok(
                json!({"trailList":store.trails.values().filter(|t|t.account==request.account_id&&(t.region==request.region||(shadow&&t.multi_region))&&names.is_none_or(|names|names.is_empty()||names.iter().any(|name|name==&Value::String(t.name.clone())||name==&Value::String(t.arn())))).map(Trail::view).collect::<Vec<_>>()}),
            )
        }
        "ListTrails" => {
            fields(body, &["NextToken"])?;
            let cursor = cursor(body.get("NextToken"), request)?;
            let mut rows = store.trails.values().filter(|t| {
                t.account == request.account_id
                    && t.region == request.region
                    && cursor.as_ref().is_none_or(|c| t.name > *c)
            });
            let page = rows.by_ref().take(50).collect::<Vec<_>>();
            let mut response = json!({"Trails":page.iter().map(|t|json!({"TrailARN":t.arn(),"Name":t.name,"HomeRegion":t.region})).collect::<Vec<_>>()});
            if rows.next().is_some() {
                if let Some(t) = page.last() {
                    response["NextToken"] =
                        serde_json::to_string(&(&request.account_id, &request.region, &t.name))
                            .map_err(|_| Error::internal())?
                            .into();
                }
            }
            Ok(response)
        }
        "ListTags" => {
            fields(body, &["ResourceIdList", "NextToken"])?;
            if body.contains_key("NextToken") {
                return Err(Error::new("InvalidTokenException", "Invalid NextToken"));
            }
            let ids = body
                .get("ResourceIdList")
                .and_then(Value::as_array)
                .filter(|v| !v.is_empty() && v.len() <= 20)
                .ok_or_else(|| Error::new("InvalidParameterException", "Invalid resource list"))?;
            let mut resources = Vec::new();
            for id in ids {
                let id = id.as_str().ok_or_else(|| {
                    Error::new("InvalidParameterException", "Invalid resource ARN")
                })?;
                let trail = get(store, &key(request, id)?)?;
                resources.push(json!({"ResourceId":trail.arn(),"TagsList":trail.tags.iter().map(|(k,v)|json!({"Key":k,"Value":v})).collect::<Vec<_>>()}));
            }
            Ok(json!({"ResourceTagList":resources}))
        }
        _ => {
            let name_field = match op {
                "AddTags" | "RemoveTags" => "ResourceId",
                "PutEventSelectors" | "GetEventSelectors" => "TrailName",
                _ => "Name",
            };
            let id = key(request, required(body, name_field)?)?;
            let mut trail = get(store, &id)?;
            match op {
                "GetTrail" => {
                    fields(body, &["Name"])?;
                    Ok(json!({"Trail":trail.view()}))
                }
                "GetTrailStatus" => {
                    fields(body, &["Name"])?;
                    let mut response = json!({"IsLogging":trail.logging});
                    for (key, value) in [
                        ("StartLoggingTime", trail.started),
                        ("StopLoggingTime", trail.stopped),
                        ("LatestDeliveryTime", trail.delivered),
                    ] {
                        if let Some(value) = value {
                            response[key] = json!(value);
                        }
                    }
                    if let Some(error) = trail.error {
                        response["LatestDeliveryError"] = error.into();
                    }
                    if store.failed {
                        return Err(Error::internal());
                    }
                    Ok(response)
                }
                "StartLogging" | "StopLogging" => {
                    fields(body, &["Name"])?;
                    trail.logging = op == "StartLogging";
                    if trail.logging {
                        trail.started = Some(epoch(SystemTime::now()));
                        trail.error = None;
                    } else {
                        trail.stopped = Some(epoch(SystemTime::now()));
                    }
                    store.save(trail).await?;
                    Ok(json!({}))
                }
                "DeleteTrail" => {
                    fields(body, &["Name"])?;
                    store.delete(&id).await?;
                    Ok(json!({}))
                }
                "UpdateTrail" => {
                    fields(
                        body,
                        &[
                            "Name",
                            "S3BucketName",
                            "S3KeyPrefix",
                            "IncludeGlobalServiceEvents",
                            "IsMultiRegionTrail",
                            "EnableLogFileValidation",
                            "IsOrganizationTrail",
                        ],
                    )?;
                    let mut updated = trail
                        .view()
                        .as_object()
                        .cloned()
                        .ok_or_else(Error::internal)?;
                    updated.remove("TrailARN");
                    updated.remove("HomeRegion");
                    updated.insert(
                        "TagsList".into(),
                        json!(trail
                            .tags
                            .iter()
                            .map(|(k, v)| json!({"Key":k,"Value":v}))
                            .collect::<Vec<_>>()),
                    );
                    for (k, v) in body {
                        if k != "Name" {
                            updated.insert(k.clone(), v.clone());
                        }
                    }
                    let candidate = configuration(request, &updated)?;
                    preflight(registry, &candidate).await?;
                    trail.bucket = candidate.bucket;
                    trail.prefix = candidate.prefix;
                    trail.multi_region = candidate.multi_region;
                    trail.include_global = candidate.include_global;
                    let response = trail.view();
                    store.save(trail).await?;
                    Ok(response)
                }
                "AddTags" | "RemoveTags" => {
                    fields(body, &["ResourceId", "TagsList"])?;
                    let values = tags(body.get("TagsList"))?;
                    if op == "AddTags" {
                        trail.tags.extend(values);
                    } else {
                        for key in values.keys() {
                            trail.tags.remove(key);
                        }
                    }
                    if trail.tags.len() > 200 {
                        return Err(Error::new(
                            "TagsLimitExceededException",
                            "Trail tag limit exceeded",
                        ));
                    }
                    store.save(trail).await?;
                    Ok(json!({}))
                }
                "GetEventSelectors" => {
                    fields(body, &["TrailName"])?;
                    Ok(json!({"TrailARN":trail.arn(),"EventSelectors":trail.selectors}))
                }
                "PutEventSelectors" => {
                    fields(body, &["TrailName", "EventSelectors"])?;
                    let selectors = body
                        .get("EventSelectors")
                        .and_then(Value::as_array)
                        .filter(|v| !v.is_empty() && v.len() <= 5)
                        .ok_or_else(|| {
                            Error::new("InvalidEventSelectorsException", "Invalid event selectors")
                        })?;
                    let mut values = Vec::new();
                    for selector in selectors {
                        let selector = selector.as_object().ok_or_else(|| {
                            Error::new("InvalidEventSelectorsException", "Invalid event selector")
                        })?;
                        fields(
                            selector,
                            &["ReadWriteType", "IncludeManagementEvents", "DataResources"],
                        )?;
                        let mode = selector
                            .get("ReadWriteType")
                            .and_then(Value::as_str)
                            .unwrap_or("All");
                        if !matches!(mode, "All" | "ReadOnly" | "WriteOnly")
                            || selector
                                .get("DataResources")
                                .is_some_and(|v| v.as_array().is_none_or(|v| !v.is_empty()))
                        {
                            return Err(Error::new(
                                "UnsupportedOperationException",
                                "Only management event selectors are supported",
                            ));
                        }
                        values.push(json!({"ReadWriteType":mode,"IncludeManagementEvents":boolean(selector,"IncludeManagementEvents",true)?,"DataResources":[]}));
                    }
                    trail.selectors = values;
                    let response = json!({"TrailARN":trail.arn(),"EventSelectors":trail.selectors});
                    store.save(trail).await?;
                    Ok(response)
                }
                _ => Err(Error::new(
                    "UnsupportedOperationException",
                    "CloudTrail operation is unavailable",
                )),
            }
        }
    }
}
fn cursor(value: Option<&Value>, request: &ServiceRequest) -> Result<Option<String>, Error> {
    match value {
        None => Ok(None),
        Some(Value::String(token)) if token.len() <= 4096 => {
            let (account, region, last): (String, String, String) = serde_json::from_str(token)
                .map_err(|_| Error::new("InvalidTokenException", "Invalid NextToken"))?;
            if account != request.account_id || region != request.region {
                return Err(Error::new("InvalidTokenException", "Invalid NextToken"));
            }
            Ok(Some(last))
        }
        _ => Err(Error::new("InvalidTokenException", "Invalid NextToken")),
    }
}
fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}
async fn s3(
    registry: &Weak<ServiceRegistry>,
    trail: &Trail,
    method: Method,
    key: &str,
    query: &str,
    body: Bytes,
) -> Result<(), Error> {
    let registry = registry.upgrade().ok_or_else(Error::internal)?;
    let dispatcher = registry.internal_dispatcher().ok_or_else(Error::internal)?;
    let uri = format!(
        "/{}{}{}{}",
        trail.bucket,
        if key.is_empty() { "" } else { "/" },
        encode(key),
        query
    )
    .parse()
    .map_err(|_| Error::internal())?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential=locallycloud/19700101/{}/s3/aws4_request",
            trail.region
        ))
        .map_err(|_| Error::internal())?,
    );
    headers.insert(
        "x-locallycloud-source-arn",
        HeaderValue::from_str(&trail.arn()).map_err(|_| Error::internal())?,
    );
    headers.insert(
        "x-locallycloud-source-account",
        HeaderValue::from_str(&trail.account).map_err(|_| Error::internal())?,
    );
    if method == Method::PUT {
        headers.insert(
            "x-amz-acl",
            HeaderValue::from_static("bucket-owner-full-control"),
        );
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("content-encoding", HeaderValue::from_static("gzip"));
    }
    let response = DeliveryEngine::new(dispatcher)
        .deliver_sync(CrossServiceCall {
            source_service: ServiceName::new("cloudtrail"),
            account_id: trail.account.clone(),
            region: trail.region.clone(),
            method,
            uri,
            headers,
            body,
            identity: CallerIdentity::ServicePrincipal {
                service: "cloudtrail".into(),
            },
            correlation: CorrelationContext::root(),
            pattern: None,
        })
        .await;
    match response.status().as_u16() {
        200..=299 => Ok(()),
        404 => Err(Error::new(
            "S3BucketDoesNotExistException",
            "The CloudTrail S3 bucket does not exist",
        )),
        400..=499 => Err(Error::new(
            "InsufficientS3BucketPolicyException",
            "CloudTrail cannot access the S3 bucket",
        )),
        _ => Err(Error::internal()),
    }
}
fn compress(value: &Value) -> Result<Bytes, Error> {
    use std::io::Write;
    let mut output = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let json = serde_json::to_vec(value).map_err(|_| Error::internal())?;
    output.write_all(&json).map_err(|_| Error::internal())?;
    Ok(Bytes::from(output.finish().map_err(|_| Error::internal())?))
}
fn log_body(event: &AuditEvent) -> Result<Bytes, Error> {
    let detail = render_event(event)["CloudTrailEvent"]
        .as_str()
        .ok_or_else(Error::internal)?
        .to_owned();
    let detail: Value = serde_json::from_str(&detail).map_err(|_| Error::internal())?;
    compress(&json!({"Records":[detail]}))
}
fn prefix(trail: &Trail) -> String {
    if trail.prefix.is_empty() {
        String::new()
    } else {
        format!("{}/", trail.prefix)
    }
}
async fn preflight(registry: &Weak<ServiceRegistry>, trail: &Trail) -> Result<(), Error> {
    s3(registry, trail, Method::GET, "", "?acl", Bytes::new()).await?;
    let key = format!(
        "{}AWSLogs/{}/CloudTrail/{}/permission-check.json.gz",
        prefix(trail),
        trail.account,
        trail.region
    );
    let registry = registry.upgrade().ok_or_else(Error::internal)?;
    let api = registry
        .s3_delivery_api(&ServiceName::new("s3"))
        .ok_or_else(Error::internal)?;
    api.authorize_delivery(
        locallycloud_core::integration::s3::S3DeliveryAuthorizationRequest {
            account_id: trail.account.clone(),
            region: trail.region.clone(),
            source_service: ServiceName::new("cloudtrail"),
            source_arn: trail.arn(),
            bucket: trail.bucket.clone(),
            key,
        },
    )
    .await
    .map_err(|error| match error {
        locallycloud_core::integration::s3::S3DeliveryAuthorizationError::Denied => Error::new(
            "InsufficientS3BucketPolicyException",
            "CloudTrail cannot write to the S3 bucket",
        ),
        locallycloud_core::integration::s3::S3DeliveryAuthorizationError::Unavailable => {
            Error::internal()
        }
    })
}
async fn put_log(
    registry: &Weak<ServiceRegistry>,
    trail: &Trail,
    event: &AuditEvent,
    body: Bytes,
) -> Result<(), Error> {
    let time = OffsetDateTime::from(event.time);
    let date = time
        .format(
            &time::format_description::parse_borrowed::<2>("[year]/[month]/[day]")
                .map_err(|_| Error::internal())?,
        )
        .map_err(|_| Error::internal())?;
    let stamp = time
        .format(
            &time::format_description::parse_borrowed::<2>("[year][month][day]T[hour][minute]Z")
                .map_err(|_| Error::internal())?,
        )
        .map_err(|_| Error::internal())?;
    let key = format!(
        "{}AWSLogs/{}/CloudTrail/{}/{date}/{}_CloudTrail_{}_{stamp}_{}.json.gz",
        prefix(trail),
        trail.account,
        event.region,
        trail.account,
        event.region,
        event.id
    );
    s3(registry, trail, Method::PUT, &key, "", body).await
}

async fn run_actor(
    mut receiver: mpsc::Receiver<Command>,
    mut store: Store,
    registry: Weak<ServiceRegistry>,
    overflow: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
) {
    while let Some(command) = receiver.recv().await {
        if overflow.swap(false, Ordering::Relaxed) {
            let trails = store
                .trails
                .values()
                .filter(|t| t.logging)
                .cloned()
                .collect::<Vec<_>>();
            for mut trail in trails {
                trail.error = Some("Audit queue overflow: log delivery is incomplete".into());
                if store.save(trail).await.is_err() {
                    store.failed = true;
                }
            }
        }
        match command {
            Command::Operation {
                op,
                request,
                body,
                reply,
            } => {
                let result = operation(&registry, &mut store, &op, &request, &body).await;
                active.store(
                    store.trails.values().any(|trail| trail.logging),
                    Ordering::Relaxed,
                );
                let _ = reply.send(result);
            }
            Command::Event(event) => {
                let trails = store
                    .trails
                    .values()
                    .filter(|t| {
                        t.logging
                            && t.account == event.account
                            && (t.multi_region || t.region == event.region)
                            && t.selectors.iter().any(|s| {
                                s["IncludeManagementEvents"] != false
                                    && s["ReadWriteType"] != "ReadOnly"
                            })
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                for mut trail in trails {
                    let result = match log_body(&event) {
                        Ok(body) => put_log(&registry, &trail, &event, body).await,
                        Err(error) => Err(error),
                    };
                    match result {
                        Ok(()) => {
                            trail.delivered = Some(epoch(SystemTime::now()));
                            trail.error = trail
                                .error
                                .filter(|error| error.starts_with("Audit queue overflow"));
                        }
                        Err(_) => {
                            trail.error = Some("S3 log delivery failed; check the bucket and CloudTrail service policy".into());
                        }
                    }
                    if store.save(trail).await.is_err() {
                        store.failed = true;
                    }
                }
            }
        }
    }
}
