//! Native EventBridge Schemas REST API. Registry/schema metadata lives in shared SQLite.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use http::{Method, StatusCode};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_state::StateDb;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub(crate) mod bindings;
pub(crate) mod discovery;

pub(crate) struct SchemasService {
    pub(crate) state: Arc<StateDb>,
    registry: Weak<ServiceRegistry>,
}

#[derive(Debug)]
pub(crate) enum SchemasError {
    Validation(String),
    NotFound(String),
    Conflict(String),
    Internal(String),
    AccessDenied,
}

pub(crate) type SchemaResult = Result<(StatusCode, Value), SchemasError>;

impl SchemasError {
    fn response(self, request_id: &str) -> Response {
        let (status, code, message) = match self {
            Self::Validation(m) => (StatusCode::BAD_REQUEST, "BadRequestException", m),
            Self::NotFound(m) => (StatusCode::NOT_FOUND, "NotFoundException", m),
            Self::Conflict(m) => (StatusCode::CONFLICT, "ConflictException", m),
            Self::AccessDenied => (
                StatusCode::FORBIDDEN,
                "AccessDeniedException",
                "User is not authorized to perform this operation".into(),
            ),
            Self::Internal(m) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerException",
                m,
            ),
        };
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("x-amzn-errortype", code)
            .header("x-amzn-requestid", request_id)
            .body(Body::from(
                json!({"Code":code,"Message":message}).to_string(),
            ))
            .expect("valid error response")
    }
}

fn internal(error: impl std::fmt::Display) -> SchemasError {
    SchemasError::Internal(error.to_string())
}

pub fn register(registry: &Arc<ServiceRegistry>, state: Arc<StateDb>) -> Result<(), String> {
    initialize(&state)?;
    discovery::init(&state)?;
    bindings::init(&state)?;
    registry.register_native(
        ServiceName::new("schemas"),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        Arc::new(SchemasService {
            state,
            registry: Arc::downgrade(registry),
        }),
    );
    Ok(())
}

fn initialize(state: &StateDb) -> Result<(), String> {
    state
        .connection()
        .map_err(|e| e.to_string())?
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schemas_registries (
          account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
          description TEXT NOT NULL, tags TEXT NOT NULL,
          PRIMARY KEY(account,region,name));
         CREATE TABLE IF NOT EXISTS schemas_items (
          account TEXT NOT NULL, region TEXT NOT NULL, registry TEXT NOT NULL, name TEXT NOT NULL,
          description TEXT NOT NULL, schema_type TEXT NOT NULL, tags TEXT NOT NULL,
          modified TEXT NOT NULL, PRIMARY KEY(account,region,registry,name));
         CREATE TABLE IF NOT EXISTS schemas_versions (
          account TEXT NOT NULL, region TEXT NOT NULL, registry TEXT NOT NULL, name TEXT NOT NULL,
          version INTEGER NOT NULL, content TEXT NOT NULL, created TEXT NOT NULL,
          PRIMARY KEY(account,region,registry,name,version));",
        )
        .map_err(|e| e.to_string())
}

#[async_trait]
impl NativeHandler for SchemasService {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        let state = self.state.clone();
        let account = account.to_owned();
        tokio::task::spawn_blocking(move || {
            let db = state.connection().map_err(|_| "Schemas inventory unavailable")?;
            let mut stmt = db.prepare("SELECT region FROM schemas_registries WHERE account=?1 AND name NOT LIKE 'aws.%' UNION SELECT region FROM schemas_items WHERE account=?1 UNION SELECT region FROM schemas_discoverers WHERE account=?1").map_err(|_| "Schemas inventory unavailable")?;
            let rows = stmt.query_map([account], |row| row.get(0)).map_err(|_| "Schemas inventory unavailable")?;
            rows.collect::<Result<Vec<String>, _>>().map_err(|_| "Schemas inventory unavailable")
        }).await.map_err(|_| "Schemas inventory unavailable")?
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let state = self.state.clone();
        let registry = self.registry.clone();
        let request_id = request.request_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            let service = Self { state, registry };
            let query = parse_query(request.uri.query());
            let segments: Vec<String> = request
                .uri
                .path()
                .split('/')
                .filter(|s| !s.is_empty())
                .map(decode)
                .collect();
            let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
            service.authorize(&request, &parts)?;
            if let Some(result) = bindings::source(&service, &request, &parts, &query) {
                return result.map(|bytes| (StatusCode::OK, bytes, "application/zip"));
            }
            service.dispatch(&request).map(|(status, body)| {
                (
                    status,
                    if status == StatusCode::NO_CONTENT {
                        Vec::new()
                    } else {
                        body.to_string().into_bytes()
                    },
                    "application/json",
                )
            })
        })
        .await;
        match result {
            Ok(Ok((status, body, content_type))) => Response::builder()
                .status(status)
                .header("content-type", content_type)
                .header("x-amzn-requestid", &request_id)
                .body(Body::from(body))
                .expect("valid schema response"),
            Ok(Err(error)) => error.response(&request_id),
            Err(error) => internal(error).response(&request_id),
        }
    }
}

impl SchemasService {
    fn authorize(&self, request: &ServiceRequest, parts: &[&str]) -> Result<(), SchemasError> {
        let registry = self.registry.upgrade().ok_or(SchemasError::AccessDenied)?;
        let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
            return Ok(());
        };
        if !evaluator.strict_sigv4_required() {
            return Ok(());
        }
        let Some((action, resource)) = Self::authorization_target(request, parts) else {
            return Ok(()); // Unknown routes return NotFound without touching state.
        };
        // Core strips client-supplied markers and sets this only for dispatch_scoped.
        if request
            .headers
            .get("x-locallycloud-verified-internal-scope")
            .is_some_and(|value| value == "1")
        {
            return Ok(());
        }
        if !request
            .headers
            .get("x-locallycloud-verified-external-sigv4")
            .is_some_and(|value| value == "1")
        {
            return Err(SchemasError::AccessDenied);
        }
        let access_key_id = request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(RequestIdentity::access_key_from_authorization)
            .ok_or(SchemasError::AccessDenied)?;
        evaluator
            .authorize(AuthorizationRequest {
                request_identity: RequestIdentity {
                    account_id: request.account_id.clone(),
                    access_key_id: Some(access_key_id),
                    arn: None,
                },
                delegated_identity: None,
                source_service: "schemas".into(),
                action: format!("schemas:{action}"),
                resource,
                context: BTreeMap::new(),
            })
            .map_err(|_| SchemasError::AccessDenied)
    }

    // Action/resource pairs follow the AWS EventBridge Schemas IAM reference.
    fn authorization_target(
        request: &ServiceRequest,
        parts: &[&str],
    ) -> Option<(&'static str, String)> {
        let registry = |name| Self::registry_arn(request, name);
        let schema = |registry, name| Self::schema_arn(request, registry, name);
        let discoverer = |id: &str| {
            format!(
                "arn:aws:schemas:{}:{}:discoverer/{id}",
                request.region, request.account_id
            )
        };
        let target = match (&request.method, parts) {
            (&Method::POST, ["v1", "discover"]) => ("GetDiscoveredSchema", "*".into()),
            (&Method::POST, ["v1", "discoverers"]) => ("CreateDiscoverer", "*".into()),
            (&Method::GET, ["v1", "discoverers"]) => ("ListDiscoverers", discoverer("*")),
            (&Method::GET, ["v1", "discoverers", "id", id]) => {
                ("DescribeDiscoverer", discoverer(id))
            }
            (&Method::PUT, ["v1", "discoverers", "id", id]) => ("UpdateDiscoverer", discoverer(id)),
            (&Method::DELETE, ["v1", "discoverers", "id", id]) => {
                ("DeleteDiscoverer", discoverer(id))
            }
            (&Method::POST, ["v1", "discoverers", "id", id, "start"]) => {
                ("StartDiscoverer", discoverer(id))
            }
            (&Method::POST, ["v1", "discoverers", "id", id, "stop"]) => {
                ("StopDiscoverer", discoverer(id))
            }
            (&Method::GET, ["v1", "registries"]) => ("ListRegistries", registry("*")),
            (&Method::POST, ["v1", "registries", "name", name]) => {
                ("CreateRegistry", registry(name))
            }
            (&Method::PUT, ["v1", "registries", "name", name]) => {
                ("UpdateRegistry", registry(name))
            }
            (&Method::GET, ["v1", "registries", "name", name]) => {
                ("DescribeRegistry", registry(name))
            }
            (&Method::DELETE, ["v1", "registries", "name", name]) => {
                ("DeleteRegistry", registry(name))
            }
            (&Method::GET, ["v1", "registries", "name", registry_name, "schemas"]) => {
                ("ListSchemas", schema(registry_name, "*"))
            }
            (&Method::GET, ["v1", "registries", "name", registry_name, "schemas", "search"]) => {
                ("SearchSchemas", schema(registry_name, "*"))
            }
            (
                &Method::POST,
                ["v1", "registries", "name", registry_name, "schemas", "name", name],
            ) => ("CreateSchema", schema(registry_name, name)),
            (
                &Method::PUT,
                ["v1", "registries", "name", registry_name, "schemas", "name", name],
            ) => ("UpdateSchema", schema(registry_name, name)),
            (
                &Method::GET,
                ["v1", "registries", "name", registry_name, "schemas", "name", name],
            ) => ("DescribeSchema", schema(registry_name, name)),
            (
                &Method::DELETE,
                ["v1", "registries", "name", registry_name, "schemas", "name", name],
            ) => ("DeleteSchema", schema(registry_name, name)),
            (
                &Method::GET,
                ["v1", "registries", "name", registry_name, "schemas", "name", name, "versions"],
            ) => ("ListSchemaVersions", schema(registry_name, name)),
            (
                &Method::DELETE,
                ["v1", "registries", "name", registry_name, "schemas", "name", name, "version", _],
            ) => ("DeleteSchemaVersion", schema(registry_name, name)),
            (
                &Method::GET,
                ["v1", "registries", "name", registry_name, "schemas", "name", name, "language", _],
            ) => ("DescribeCodeBinding", schema(registry_name, name)),
            (
                &Method::POST,
                ["v1", "registries", "name", registry_name, "schemas", "name", name, "language", _],
            ) => ("PutCodeBinding", schema(registry_name, name)),
            (
                &Method::GET,
                ["v1", "registries", "name", registry_name, "schemas", "name", name, "language", _, "source"],
            ) => ("GetCodeBindingSource", schema(registry_name, name)),
            _ => return None,
        };
        Some(target)
    }

    fn dispatch(&self, request: &ServiceRequest) -> SchemaResult {
        let body: Value = if request.body.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&request.body)
                .map_err(|e| SchemasError::Validation(format!("invalid JSON: {e}")))?
        };
        if !body.is_object() {
            return Err(SchemasError::Validation(
                "request body must be an object".into(),
            ));
        }
        let query = parse_query(request.uri.query());
        let segments: Vec<String> = request
            .uri
            .path()
            .split('/')
            .filter(|s| !s.is_empty())
            .map(decode)
            .collect();
        let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
        if let Some(result) = discovery::dispatch(self, request, &parts, &body, &query) {
            return result;
        }
        if let Some(result) = bindings::dispatch(self, request, &parts, &body, &query) {
            return result;
        }
        match (request.method.clone(), parts.as_slice()) {
            (Method::GET, ["v1", "registries"]) => self.list_registries(request, &query),
            (Method::POST, ["v1", "registries", "name", name]) => {
                self.put_registry(request, name, &body, false)
            }
            (Method::PUT, ["v1", "registries", "name", name]) => {
                self.put_registry(request, name, &body, true)
            }
            (Method::GET, ["v1", "registries", "name", name]) => self.get_registry(request, name),
            (Method::DELETE, ["v1", "registries", "name", name]) => {
                self.delete_registry(request, name)
            }
            (Method::GET, ["v1", "registries", "name", registry, "schemas"]) => {
                self.list_schemas(request, registry, &query)
            }
            (Method::GET, ["v1", "registries", "name", registry, "schemas", "search"]) => {
                self.search_schemas(request, registry, &query)
            }
            (Method::POST, ["v1", "registries", "name", registry, "schemas", "name", name]) => {
                self.put_schema(request, registry, name, &body, false)
            }
            (Method::PUT, ["v1", "registries", "name", registry, "schemas", "name", name]) => {
                self.put_schema(request, registry, name, &body, true)
            }
            (Method::GET, ["v1", "registries", "name", registry, "schemas", "name", name]) => {
                self.get_schema(request, registry, name, &query)
            }
            (Method::DELETE, ["v1", "registries", "name", registry, "schemas", "name", name]) => {
                self.delete_schema(request, registry, name)
            }
            (
                Method::GET,
                ["v1", "registries", "name", registry, "schemas", "name", name, "versions"],
            ) => self.list_versions(request, registry, name, &query),
            (
                Method::DELETE,
                ["v1", "registries", "name", registry, "schemas", "name", name, "version", version],
            ) => self.delete_version(request, registry, name, version),
            _ => Err(SchemasError::NotFound("operation not found".into())),
        }
    }

    fn registry_arn(request: &ServiceRequest, name: &str) -> String {
        format!(
            "arn:aws:schemas:{}:{}:registry/{}",
            request.region, request.account_id, name
        )
    }
    fn schema_arn(request: &ServiceRequest, registry: &str, name: &str) -> String {
        format!(
            "arn:aws:schemas:{}:{}:schema/{}/{}",
            request.region, request.account_id, registry, name
        )
    }
    fn exists_registry(&self, req: &ServiceRequest, name: &str) -> Result<bool, SchemasError> {
        if name == "discovered-schemas" {
            return Ok(true);
        }
        let conn = self.state.connection().map_err(internal)?;
        conn.query_row(
            "SELECT 1 FROM schemas_registries WHERE account=?1 AND region=?2 AND name=?3",
            params![req.account_id, req.region, name],
            |_| Ok(true),
        )
        .optional()
        .map_err(internal)
        .map(|v| v.unwrap_or(false))
    }
    fn require_registry(&self, req: &ServiceRequest, name: &str) -> Result<(), SchemasError> {
        if self.exists_registry(req, name)? {
            Ok(())
        } else {
            Err(SchemasError::NotFound(format!("registry {name} not found")))
        }
    }
    fn put_registry(
        &self,
        req: &ServiceRequest,
        name: &str,
        body: &Value,
        update: bool,
    ) -> SchemaResult {
        check_name(name)?;
        if name == "discovered-schemas" || name == "aws.events" {
            return Err(SchemasError::Validation("reserved registry name".into()));
        }
        let description = body
            .get("Description")
            .and_then(Value::as_str)
            .unwrap_or("");
        if description.len() > 256 {
            return Err(SchemasError::Validation(
                "Description exceeds 256 characters".into(),
            ));
        }
        let tags = body
            .get("Tags")
            .or_else(|| body.get("tags"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        if !tags.is_object() {
            return Err(SchemasError::Validation("tags must be an object".into()));
        }
        let conn = self.state.connection().map_err(internal)?;
        let exists = self.exists_registry(req, name)?;
        if update && !exists {
            return Err(SchemasError::NotFound("registry not found".into()));
        }
        if !update && exists {
            return Err(SchemasError::Conflict("registry already exists".into()));
        }
        if update {
            conn.execute("UPDATE schemas_registries SET description=?4 WHERE account=?1 AND region=?2 AND name=?3",
                params![req.account_id, req.region, name, description]).map_err(internal)?;
        } else {
            conn.execute(
                "INSERT INTO schemas_registries VALUES (?1,?2,?3,?4,?5)",
                params![
                    req.account_id,
                    req.region,
                    name,
                    description,
                    tags.to_string()
                ],
            )
            .map_err(internal)?;
        }
        Ok((
            if update {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            json!({"RegistryName":name,"RegistryArn":Self::registry_arn(req,name),"Description":description,"Tags":tags}),
        ))
    }
    fn get_registry(&self, req: &ServiceRequest, name: &str) -> SchemaResult {
        if name == "discovered-schemas" {
            return Ok((
                StatusCode::OK,
                json!({"RegistryName":name,"RegistryArn":Self::registry_arn(req,name)}),
            ));
        }
        let conn = self.state.connection().map_err(internal)?;
        let row: Option<(String,String)> = conn.query_row("SELECT description,tags FROM schemas_registries WHERE account=?1 AND region=?2 AND name=?3", params![req.account_id,req.region,name], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(internal)?;
        let (description, tags) =
            row.ok_or_else(|| SchemasError::NotFound("registry not found".into()))?;
        Ok((
            StatusCode::OK,
            json!({"RegistryName":name,"RegistryArn":Self::registry_arn(req,name),"Description":description,"Tags":serde_json::from_str::<Value>(&tags).map_err(internal)?}),
        ))
    }
    fn delete_registry(&self, req: &ServiceRequest, name: &str) -> SchemaResult {
        self.require_registry(req, name)?;
        if name == "discovered-schemas" {
            return Err(SchemasError::Validation("reserved registry".into()));
        }
        let mut conn = self.state.connection().map_err(internal)?;
        let tx = conn.transaction().map_err(internal)?;
        let count: i64 = tx
            .query_row(
                "SELECT count(*) FROM schemas_items WHERE account=?1 AND region=?2 AND registry=?3",
                params![req.account_id, req.region, name],
                |r| r.get(0),
            )
            .map_err(internal)?;
        if count != 0 {
            return Err(SchemasError::Conflict("registry contains schemas".into()));
        }
        tx.execute(
            "DELETE FROM schemas_registries WHERE account=?1 AND region=?2 AND name=?3",
            params![req.account_id, req.region, name],
        )
        .map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok((StatusCode::NO_CONTENT, json!({})))
    }
    fn list_registries(
        &self,
        req: &ServiceRequest,
        query: &HashMap<String, String>,
    ) -> SchemaResult {
        let conn = self.state.connection().map_err(internal)?;
        let mut stmt = conn
            .prepare(
                "SELECT name FROM schemas_registries WHERE account=?1 AND region=?2 ORDER BY name",
            )
            .map_err(internal)?;
        let mut names = stmt
            .query_map(params![req.account_id, req.region], |r| {
                r.get::<_, String>(0)
            })
            .map_err(internal)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal)?;
        if query.get("scope").is_none_or(|s| s != "Local") {
            names.push("discovered-schemas".into());
        }
        names.sort();
        names.dedup();
        let names = names
            .into_iter()
            .filter(|name| {
                name.starts_with(
                    query
                        .get("registryNamePrefix")
                        .map(String::as_str)
                        .unwrap_or(""),
                )
            })
            .collect::<Vec<_>>();
        let (names, next) = paginate(names, query)?;
        let mut out = json!({"Registries":names.into_iter().map(|name| json!({"RegistryName":name,"RegistryArn":Self::registry_arn(req,&name)})).collect::<Vec<_>>()});
        if let Some(next) = next {
            out["NextToken"] = json!(next);
        }
        Ok((StatusCode::OK, out))
    }
    fn put_schema(
        &self,
        req: &ServiceRequest,
        registry: &str,
        name: &str,
        body: &Value,
        update: bool,
    ) -> SchemaResult {
        self.require_registry(req, registry)?;
        check_name(name)?;
        let previous = if update {
            Some(self.get_schema(req, registry, name, &HashMap::new())?.1)
        } else {
            None
        };
        let schema_type = body
            .get("Type")
            .and_then(Value::as_str)
            .or_else(|| {
                previous
                    .as_ref()
                    .and_then(|value| value.get("Type").and_then(Value::as_str))
            })
            .ok_or_else(|| SchemasError::Validation("Type required".into()))?;
        if schema_type != "OpenApi3" && schema_type != "JSONSchemaDraft4" {
            return Err(SchemasError::Validation("unsupported schema Type".into()));
        }
        let content = body
            .get("Content")
            .and_then(Value::as_str)
            .or_else(|| {
                previous
                    .as_ref()
                    .and_then(|value| value.get("Content").and_then(Value::as_str))
            })
            .ok_or_else(|| SchemasError::Validation("Content required".into()))?;
        if content.is_empty() || content.len() > 100000 {
            return Err(SchemasError::Validation(
                "Content length must be 1..100000".into(),
            ));
        }
        serde_json::from_str::<Value>(content)
            .map_err(|_| SchemasError::Validation("Content must be JSON".into()))?;
        let description = body
            .get("Description")
            .and_then(Value::as_str)
            .or_else(|| {
                previous
                    .as_ref()
                    .and_then(|value| value.get("Description").and_then(Value::as_str))
            })
            .unwrap_or("");
        if description.len() > 256 {
            return Err(SchemasError::Validation(
                "Description exceeds 256 characters".into(),
            ));
        }
        let tags = body
            .get("Tags")
            .or_else(|| body.get("tags"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        if !tags.is_object() {
            return Err(SchemasError::Validation("tags must be an object".into()));
        }
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(internal)?;
        let mut conn = self.state.connection().map_err(internal)?;
        let tx = conn.transaction().map_err(internal)?;
        let existing: Option<(String,String,String,String)> = tx.query_row("SELECT description,schema_type,tags,modified FROM schemas_items WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4",params![req.account_id,req.region,registry,name],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(internal)?;
        if update && existing.is_none() {
            return Err(SchemasError::NotFound("schema not found".into()));
        }
        if !update && existing.is_some() {
            return Err(SchemasError::Conflict("schema already exists".into()));
        }
        let version: i64 = if update {
            tx.query_row("SELECT COALESCE(MAX(version),0)+1 FROM schemas_versions WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4",params![req.account_id,req.region,registry,name],|r|r.get(0)).map_err(internal)?
        } else {
            1
        };
        if update {
            tx.execute("UPDATE schemas_items SET description=?5,schema_type=?6,modified=?7 WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4",params![req.account_id,req.region,registry,name,description,schema_type,now]).map_err(internal)?;
        } else {
            tx.execute(
                "INSERT INTO schemas_items VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    req.account_id,
                    req.region,
                    registry,
                    name,
                    description,
                    schema_type,
                    tags.to_string(),
                    now
                ],
            )
            .map_err(internal)?;
        }
        tx.execute(
            "INSERT INTO schemas_versions VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                req.account_id,
                req.region,
                registry,
                name,
                version,
                content,
                now
            ],
        )
        .map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok((
            if update {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            json!({"SchemaArn":Self::schema_arn(req,registry,name),"SchemaName":name,"SchemaVersion":version.to_string(),"Type":schema_type,"Description":description,"LastModified":now,"VersionCreatedDate":now,"Tags":tags}),
        ))
    }
    fn get_schema(
        &self,
        req: &ServiceRequest,
        registry: &str,
        name: &str,
        query: &HashMap<String, String>,
    ) -> SchemaResult {
        let conn = self.state.connection().map_err(internal)?;
        let meta: Option<(String,String,String,String)> = conn.query_row("SELECT description,schema_type,tags,modified FROM schemas_items WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4",params![req.account_id,req.region,registry,name],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(internal)?;
        let (description, schema_type, tags, modified) =
            meta.ok_or_else(|| SchemasError::NotFound("schema not found".into()))?;
        let version = query
            .get("schemaVersion")
            .map(|v| {
                v.parse::<i64>()
                    .map_err(|_| SchemasError::Validation("invalid schemaVersion".into()))
            })
            .transpose()?;
        let (version,content,created): (i64,String,String) = if let Some(version) = version {
            conn.query_row("SELECT version,content,created FROM schemas_versions WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4 AND version=?5",params![req.account_id,req.region,registry,name,version],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(internal)?
        } else {
            conn.query_row("SELECT version,content,created FROM schemas_versions WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4 ORDER BY version DESC LIMIT 1",params![req.account_id,req.region,registry,name],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(internal)?
        }.ok_or_else(||SchemasError::NotFound("schema version not found".into()))?;
        Ok((
            StatusCode::OK,
            json!({"SchemaArn":Self::schema_arn(req,registry,name),"SchemaName":name,"SchemaVersion":version.to_string(),"Type":schema_type,"Description":description,"Content":content,"LastModified":modified,"VersionCreatedDate":created,"Tags":serde_json::from_str::<Value>(&tags).map_err(internal)?}),
        ))
    }
    fn delete_schema(&self, req: &ServiceRequest, registry: &str, name: &str) -> SchemaResult {
        let mut conn = self.state.connection().map_err(internal)?;
        let tx = conn.transaction().map_err(internal)?;
        let n = tx.execute("DELETE FROM schemas_items WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4",params![req.account_id,req.region,registry,name]).map_err(internal)?;
        if n == 0 {
            return Err(SchemasError::NotFound("schema not found".into()));
        }
        tx.execute("DELETE FROM schemas_versions WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4",params![req.account_id,req.region,registry,name]).map_err(internal)?;
        tx.execute("DELETE FROM schemas_bindings WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4",params![req.account_id,req.region,registry,name]).map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok((StatusCode::NO_CONTENT, json!({})))
    }
    fn delete_version(
        &self,
        req: &ServiceRequest,
        registry: &str,
        name: &str,
        version: &str,
    ) -> SchemaResult {
        let version: i64 = version
            .parse()
            .map_err(|_| SchemasError::Validation("invalid schemaVersion".into()))?;
        let mut conn = self.state.connection().map_err(internal)?;
        let tx = conn.transaction().map_err(internal)?;
        let n = tx.execute("DELETE FROM schemas_versions WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4 AND version=?5",params![req.account_id,req.region,registry,name,version]).map_err(internal)?;
        if n == 0 {
            return Err(SchemasError::NotFound("schema version not found".into()));
        }
        tx.execute("DELETE FROM schemas_bindings WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4 AND version=?5",params![req.account_id,req.region,registry,name,version]).map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok((StatusCode::NO_CONTENT, json!({})))
    }
    fn list_schemas(
        &self,
        req: &ServiceRequest,
        registry: &str,
        query: &HashMap<String, String>,
    ) -> SchemaResult {
        self.require_registry(req, registry)?;
        let conn = self.state.connection().map_err(internal)?;
        let mut stmt = conn.prepare("SELECT i.name,i.modified, i.tags, (SELECT count(*) FROM schemas_versions v WHERE v.account=i.account AND v.region=i.region AND v.registry=i.registry AND v.name=i.name) FROM schemas_items i WHERE i.account=?1 AND i.region=?2 AND i.registry=?3 ORDER BY i.name").map_err(internal)?;
        let rows = stmt
            .query_map(params![req.account_id, req.region, registry], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(internal)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal)?;
        let rows = rows
            .into_iter()
            .filter(|(name, _, _, _)| {
                name.starts_with(
                    query
                        .get("schemaNamePrefix")
                        .map(String::as_str)
                        .unwrap_or(""),
                )
            })
            .collect::<Vec<_>>();
        let (rows, next) = paginate(rows, query)?;
        let mut out = json!({"Schemas":rows.into_iter().map(|(name,modified,tags,count)|json!({"SchemaName":name,"SchemaArn":Self::schema_arn(req,registry,&name),"LastModified":modified,"VersionCount":count,"Tags":serde_json::from_str::<Value>(&tags).unwrap_or_else(|_|json!({}))})).collect::<Vec<_>>()});
        if let Some(next) = next {
            out["NextToken"] = json!(next);
        }
        Ok((StatusCode::OK, out))
    }
    fn list_versions(
        &self,
        req: &ServiceRequest,
        registry: &str,
        name: &str,
        query: &HashMap<String, String>,
    ) -> SchemaResult {
        let conn = self.state.connection().map_err(internal)?;
        let schema_type: String = conn.query_row("SELECT schema_type FROM schemas_items WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4",params![req.account_id,req.region,registry,name],|r|r.get(0)).optional().map_err(internal)?.ok_or_else(||SchemasError::NotFound("schema not found".into()))?;
        let mut stmt=conn.prepare("SELECT version FROM schemas_versions WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4 ORDER BY version").map_err(internal)?;
        let rows = stmt
            .query_map(params![req.account_id, req.region, registry, name], |r| {
                r.get::<_, i64>(0)
            })
            .map_err(internal)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal)?;
        let (rows, next) = paginate(rows, query)?;
        let mut out = json!({"SchemaVersions":rows.into_iter().map(|version|json!({"SchemaVersion":version.to_string(),"SchemaName":name,"SchemaArn":Self::schema_arn(req,registry,name),"Type":schema_type})).collect::<Vec<_>>()});
        if let Some(next) = next {
            out["NextToken"] = json!(next);
        }
        Ok((StatusCode::OK, out))
    }
    fn search_schemas(
        &self,
        req: &ServiceRequest,
        registry: &str,
        query: &HashMap<String, String>,
    ) -> SchemaResult {
        let keywords = query
            .get("keywords")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SchemasError::Validation("keywords required".into()))?
            .to_ascii_lowercase();
        self.require_registry(req, registry)?;
        let conn = self.state.connection().map_err(internal)?;
        let mut stmt=conn.prepare("SELECT i.name,i.schema_type,v.version,v.content,v.created FROM schemas_items i JOIN schemas_versions v ON i.account=v.account AND i.region=v.region AND i.registry=v.registry AND i.name=v.name WHERE i.account=?1 AND i.region=?2 AND i.registry=?3 ORDER BY i.name,v.version").map_err(internal)?;
        let rows = stmt
            .query_map(params![req.account_id, req.region, registry], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(internal)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal)?;
        let mut by_name: std::collections::BTreeMap<String, (String, Vec<Value>)> =
            std::collections::BTreeMap::new();
        for (name, kind, version, content, created) in rows {
            if name.to_ascii_lowercase().contains(&keywords)
                || content.to_ascii_lowercase().contains(&keywords)
            {
                by_name
                    .entry(name)
                    .or_insert_with(|| (kind, Vec::new()))
                    .1
                    .push(json!({"SchemaVersion":version.to_string(),"CreatedDate":created}));
            }
        }
        let rows = by_name.into_iter().collect::<Vec<_>>();
        let (rows, next) = paginate(rows, query)?;
        let mut out = json!({"Schemas":rows.into_iter().map(|(name,(kind,versions))|json!({"SchemaName":name,"RegistryName":registry,"SchemaArn":Self::schema_arn(req,registry,&name),"Type":kind,"SchemaVersions":versions})).collect::<Vec<_>>()});
        if let Some(next) = next {
            out["NextToken"] = json!(next);
        }
        Ok((StatusCode::OK, out))
    }
}

fn check_name(name: &str) -> Result<(), SchemasError> {
    if name.is_empty()
        || name.len() > 255
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(SchemasError::Validation("invalid name".into()));
    }
    Ok(())
}
fn parse_query(query: Option<&str>) -> HashMap<String, String> {
    query
        .unwrap_or("")
        .split('&')
        .filter_map(|part| part.split_once('='))
        .map(|(k, v)| (decode(k), decode(v)))
        .collect()
}
fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(b)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push((a * 16 + b) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
fn paginate<T>(
    items: Vec<T>,
    query: &HashMap<String, String>,
) -> Result<(Vec<T>, Option<String>), SchemasError> {
    let offset = query
        .get("nextToken")
        .map(|v| {
            v.parse::<usize>()
                .map_err(|_| SchemasError::Validation("invalid nextToken".into()))
        })
        .transpose()?
        .unwrap_or(0);
    let limit = query
        .get("limit")
        .map(|v| {
            v.parse::<usize>()
                .map_err(|_| SchemasError::Validation("invalid limit".into()))
        })
        .transpose()?
        .unwrap_or(100);
    if limit == 0 || limit > 1000 || offset > items.len() {
        return Err(SchemasError::Validation("invalid pagination".into()));
    }
    let end = offset.saturating_add(limit).min(items.len());
    let next = (end < items.len()).then(|| end.to_string());
    Ok((items.into_iter().skip(offset).take(limit).collect(), next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, Uri};
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn request(
        method: Method,
        path: &str,
        body: Value,
        account: &str,
        region: &str,
    ) -> ServiceRequest {
        ServiceRequest {
            method,
            uri: path.parse::<Uri>().expect("uri"),
            headers: HeaderMap::new(),
            body: Bytes::from(body.to_string()),
            account_id: account.into(),
            region: region.into(),
            request_id: "test".into(),
        }
    }

    #[test]
    fn schema_versions_survive_reopen_and_are_scope_isolated() {
        let dir = TempDir::new().expect("temporary directory");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private state directory");
        let path = dir.path().join("state.sqlite3");
        let state = Arc::new(StateDb::open(path.clone()).expect("state"));
        initialize(&state).expect("tables");
        let service = SchemasService {
            state,
            registry: Weak::new(),
        };
        let registry = "/v1/registries/name/orders";
        let schema = "/v1/registries/name/orders/schemas/name/placed";
        let own_request =
            |method, path, body| request(method, path, body, "111111111111", "us-east-1");
        assert_eq!(
            service
                .put_registry(
                    &own_request(Method::POST, registry, json!({})),
                    "orders",
                    &json!({}),
                    false
                )
                .expect("registry")
                .0,
            StatusCode::CREATED
        );
        let body = json!({"Type":"JSONSchemaDraft4","Content":"{\"type\":\"object\"}"});
        assert_eq!(
            service
                .put_schema(
                    &own_request(Method::POST, schema, body.clone()),
                    "orders",
                    "placed",
                    &body,
                    false
                )
                .expect("create")
                .0,
            StatusCode::CREATED
        );
        assert_eq!(
            service
                .put_schema(
                    &own_request(Method::PUT, schema, body.clone()),
                    "orders",
                    "placed",
                    &body,
                    true
                )
                .expect("update")
                .1["SchemaVersion"],
            "2"
        );
        drop(service);
        let reopened = SchemasService {
            state: Arc::new(StateDb::open(path).expect("reopen")),
            registry: Weak::new(),
        };
        let value = reopened
            .get_schema(
                &own_request(Method::GET, schema, json!({})),
                "orders",
                "placed",
                &HashMap::new(),
            )
            .expect("version")
            .1;
        assert_eq!(value["SchemaVersion"], "2");
        let other = request(Method::GET, schema, json!({}), "222222222222", "us-east-1");
        assert!(matches!(
            reopened.get_schema(&other, "orders", "placed", &HashMap::new()),
            Err(SchemasError::NotFound(_))
        ));
        let other_region = request(Method::GET, schema, json!({}), "111111111111", "us-west-2");
        assert!(matches!(
            reopened.get_schema(&other_region, "orders", "placed", &HashMap::new()),
            Err(SchemasError::NotFound(_))
        ));
    }
}
