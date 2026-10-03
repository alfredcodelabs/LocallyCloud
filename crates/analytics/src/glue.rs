use std::collections::BTreeMap;
use std::sync::{Arc, MutexGuard, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use http::{HeaderMap, HeaderValue};
use locallycloud_core::error_mapping::AwsError;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::AwsProtocol;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::error::AnalyticsError;
use crate::state::{
    AnalyticsState, Catalog, DatabaseInput, DatabaseRecord, Scope, TableInput, TableRecord,
};

pub(crate) const TARGET_PREFIX: &str = "AWSGlue";
const CONTENT_TYPE: &str = "application/x-amz-json-1.1";

pub(crate) struct GlueHandler {
    state: Arc<AnalyticsState>,
    registry: Weak<ServiceRegistry>,
}

impl GlueHandler {
    #[cfg(test)]
    pub(crate) fn new(state: Arc<AnalyticsState>) -> Self {
        Self {
            state,
            registry: Weak::new(),
        }
    }

    pub(crate) fn with_registry(
        state: Arc<AnalyticsState>,
        registry: Weak<ServiceRegistry>,
    ) -> Self {
        Self { state, registry }
    }

    fn authorize_path(
        &self,
        request: &ServiceRequest,
        operation: &str,
        database: Option<&str>,
        table: Option<&str>,
    ) -> Result<(), AnalyticsError> {
        let Some(registry) = self.registry.upgrade() else {
            return Ok(());
        };
        let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
            return Ok(());
        };
        if !evaluator.strict_sigv4_required() {
            return Ok(());
        }
        // Core alone sets these markers after verifying external SigV4 or a scoped
        // in-process dispatch. The source service owns internal role checks.
        if request
            .headers
            .get("x-locallycloud-verified-internal-scope")
            == Some(&HeaderValue::from_static("1"))
        {
            return Ok(());
        }
        if request
            .headers
            .get("x-locallycloud-verified-external-sigv4")
            != Some(&HeaderValue::from_static("1"))
        {
            return Err(AnalyticsError::AccessDenied);
        }
        let key = request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(RequestIdentity::access_key_from_authorization)
            .ok_or(AnalyticsError::AccessDenied)?;
        let root = format!("arn:aws:glue:{}:{}:", request.region, request.account_id);
        let mut resources = vec![format!("{root}catalog")];
        if let Some(database) = database {
            resources.push(format!("{root}database/{database}"));
            if let Some(table) = table {
                resources.push(format!("{root}table/{database}/{table}"));
            }
        }
        for resource in resources {
            evaluator
                .authorize(AuthorizationRequest {
                    request_identity: RequestIdentity {
                        account_id: request.account_id.clone(),
                        access_key_id: Some(key.clone()),
                        arn: None,
                    },
                    delegated_identity: None,
                    source_service: "glue".into(),
                    action: format!("glue:{operation}"),
                    resource,
                    context: Default::default(),
                })
                .map_err(|_| AnalyticsError::AccessDenied)?;
        }
        Ok(())
    }

    fn process(&self, request: &ServiceRequest) -> Result<Value, AnalyticsError> {
        if request.method != http::Method::POST
            || request.uri.path() != "/"
            || request.uri.query().is_some()
        {
            return Err(AnalyticsError::UnknownOperation);
        }
        validate_content_type(&request.headers)?;
        let operation = operation(&request.headers)?;
        match operation {
            "CreateDatabase" => self.create_database(decode(&request.body)?, request),
            "GetDatabase" => self.get_database(decode(&request.body)?, request),
            "GetDatabases" => self.get_databases(decode(&request.body)?, request),
            "UpdateDatabase" => self.update_database(decode(&request.body)?, request),
            "DeleteDatabase" => self.delete_database(decode(&request.body)?, request),
            "CreateTable" => self.create_table(decode(&request.body)?, request),
            "GetTable" => self.get_table(decode(&request.body)?, request),
            "GetTables" => self.get_tables(decode(&request.body)?, request),
            "UpdateTable" => self.update_table(decode(&request.body)?, request),
            "DeleteTable" => self.delete_table(decode(&request.body)?, request),
            "GetPartitions" => self.get_partitions(decode(&request.body)?, request),
            _ => Err(AnalyticsError::UnknownOperation),
        }
    }

    fn create_database(
        &self,
        input: CreateDatabaseRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        validate_name(&input.database_input.name)?;
        validate_catalog_id(input.catalog_id.as_deref(), &request.account_id)?;
        self.authorize_path(
            request,
            "CreateDatabase",
            Some(&input.database_input.name),
            None,
        )?;
        let scope = Scope::new(&request.account_id, &request.region);
        let slot = self.state.catalog(&scope);
        let mut catalog = lock(&slot)?;
        if catalog.databases.contains_key(&input.database_input.name) {
            return Err(AnalyticsError::AlreadyExists);
        }
        let now = now_epoch()?;
        catalog.databases.insert(
            input.database_input.name.clone(),
            DatabaseRecord {
                input: input.database_input,
                create_time: now,
                update_time: now,
                tables: BTreeMap::new(),
            },
        );
        Ok(json!({}))
    }

    fn get_database(
        &self,
        input: GetDatabaseRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        validate_name(&input.name)?;
        let catalog_id = validate_catalog_id(input.catalog_id.as_deref(), &request.account_id)?;
        self.authorize_path(request, "GetDatabase", Some(&input.name), None)?;
        let scope = Scope::new(&request.account_id, &request.region);
        let slot = self.state.catalog(&scope);
        let catalog = lock(&slot)?;
        let database = catalog
            .databases
            .get(&input.name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        Ok(json!({ "Database": database_value(database, catalog_id)? }))
    }

    fn get_databases(
        &self,
        input: GetDatabasesRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        let catalog_id = validate_catalog_id(input.catalog_id.as_deref(), &request.account_id)?;
        if input.attributes_to_get.is_some() || input.resource_share_type.is_some() {
            return Err(AnalyticsError::InvalidInput);
        }
        self.authorize_path(request, "GetDatabases", None, None)?;
        let limit = page_limit(input.max_results)?;
        let cursor = page_cursor(input.next_token.as_deref(), request, "databases")?;
        let scope = Scope::new(&request.account_id, &request.region);
        let slot = self.state.catalog(&scope);
        let catalog = lock(&slot)?;
        let mut database_list = Vec::new();
        let mut last_name = None;
        for (name, database) in catalog.databases.iter().filter(|(name, _)| {
            cursor
                .as_deref()
                .is_none_or(|cursor| name.as_str() > cursor)
                && self
                    .authorize_path(request, "GetDatabases", Some(name), None)
                    .is_ok()
        }) {
            if database_list.len() == limit {
                break;
            }
            database_list.push(database_value(database, catalog_id)?);
            last_name = Some(name.as_str());
        }
        let has_more = last_name.is_some_and(|last| {
            catalog.databases.keys().any(|name| {
                name.as_str() > last
                    && self
                        .authorize_path(request, "GetDatabases", Some(name), None)
                        .is_ok()
            })
        });
        let mut result = json!({ "DatabaseList": database_list });
        if has_more {
            result["NextToken"] =
                page_token(request, "databases", last_name.expect("nonempty page")).into();
        }
        Ok(result)
    }

    fn update_database(
        &self,
        input: UpdateDatabaseRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        validate_name(&input.name)?;
        validate_name(&input.database_input.name)?;
        if input.database_input.name != input.name {
            return Err(AnalyticsError::InvalidInput);
        }
        validate_catalog_id(input.catalog_id.as_deref(), &request.account_id)?;
        self.authorize_path(request, "UpdateDatabase", Some(&input.name), None)?;
        let scope = Scope::new(&request.account_id, &request.region);
        let slot = self.state.catalog(&scope);
        let mut catalog = lock(&slot)?;
        let database = catalog
            .databases
            .get_mut(&input.name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        database.input = input.database_input;
        database.update_time = now_epoch()?;
        Ok(json!({}))
    }

    fn delete_database(
        &self,
        input: DeleteDatabaseRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        validate_name(&input.name)?;
        validate_catalog_id(input.catalog_id.as_deref(), &request.account_id)?;
        self.authorize_path(request, "DeleteDatabase", Some(&input.name), None)?;
        let scope = Scope::new(&request.account_id, &request.region);
        let slot = self.state.catalog(&scope);
        let mut catalog = lock(&slot)?;
        let database = catalog
            .databases
            .get(&input.name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        if !database.tables.is_empty() {
            return Err(AnalyticsError::InvalidInput);
        }
        catalog.databases.remove(&input.name);
        Ok(json!({}))
    }

    fn create_table(
        &self,
        input: CreateTableRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        validate_name(&input.database_name)?;
        validate_name(&input.table_input.name)?;
        validate_table_input(&input.table_input)?;
        if input.open_table_format_input.is_some() {
            // This operation also creates Iceberg metadata in S3. A catalog-only
            // success would leave a table that no reader can open.
            return Err(AnalyticsError::InvalidInput);
        }
        validate_catalog_id(input.catalog_id.as_deref(), &request.account_id)?;
        self.authorize_path(
            request,
            "CreateTable",
            Some(&input.database_name),
            Some(&input.table_input.name),
        )?;
        let scope = Scope::new(&request.account_id, &request.region);
        let slot = self.state.catalog(&scope);
        let mut catalog = lock(&slot)?;
        let database = catalog
            .databases
            .get_mut(&input.database_name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        if database.tables.contains_key(&input.table_input.name) {
            return Err(AnalyticsError::AlreadyExists);
        }
        let now = now_epoch()?;
        database.tables.insert(
            input.table_input.name.clone(),
            TableRecord {
                input: input.table_input,
                create_time: now,
                update_time: now,
                version_id: 1,
                partitions: Vec::new(),
            },
        );
        Ok(json!({}))
    }

    fn get_table(
        &self,
        input: GetTableRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        validate_name(&input.database_name)?;
        validate_name(&input.name)?;
        let catalog_id = validate_catalog_id(input.catalog_id.as_deref(), &request.account_id)?;
        self.authorize_path(
            request,
            "GetTable",
            Some(&input.database_name),
            Some(&input.name),
        )?;
        let scope = Scope::new(&request.account_id, &request.region);
        let slot = self.state.catalog(&scope);
        let catalog = lock(&slot)?;
        let database = catalog
            .databases
            .get(&input.database_name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        let table = database
            .tables
            .get(&input.name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        Ok(json!({
            "Table": table_value(table, catalog_id, &input.database_name)?
        }))
    }

    fn get_tables(
        &self,
        input: GetTablesRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        validate_name(&input.database_name)?;
        let catalog_id = validate_catalog_id(input.catalog_id.as_deref(), &request.account_id)?;
        if input.attributes_to_get.is_some()
            || input.audit_context.is_some()
            || input
                .expression
                .as_ref()
                .is_some_and(|value| !value.is_empty())
            || input.include_status_details == Some(true)
            || input.query_as_of_time.is_some()
            || input.transaction_id.is_some()
        {
            return Err(AnalyticsError::InvalidInput);
        }
        self.authorize_path(request, "GetTables", Some(&input.database_name), None)?;
        let limit = page_limit(input.max_results)?;
        let collection = format!("tables:{}", input.database_name);
        let cursor = page_cursor(input.next_token.as_deref(), request, &collection)?;
        let scope = Scope::new(&request.account_id, &request.region);
        let slot = self.state.catalog(&scope);
        let catalog = lock(&slot)?;
        let database = catalog
            .databases
            .get(&input.database_name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        let mut table_list = Vec::new();
        let mut last_name = None;
        for (name, table) in database.tables.iter().filter(|(name, _)| {
            cursor
                .as_deref()
                .is_none_or(|cursor| name.as_str() > cursor)
                && self
                    .authorize_path(request, "GetTables", Some(&input.database_name), Some(name))
                    .is_ok()
        }) {
            if table_list.len() == limit {
                break;
            }
            table_list.push(table_value(table, catalog_id, &input.database_name)?);
            last_name = Some(name.as_str());
        }
        let has_more = last_name.is_some_and(|last| {
            database.tables.keys().any(|name| {
                name.as_str() > last
                    && self
                        .authorize_path(
                            request,
                            "GetTables",
                            Some(&input.database_name),
                            Some(name),
                        )
                        .is_ok()
            })
        });
        let mut result = json!({ "TableList": table_list });
        if has_more {
            result["NextToken"] =
                page_token(request, &collection, last_name.expect("nonempty page")).into();
        }
        Ok(result)
    }

    fn update_table(
        &self,
        input: UpdateTableRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        validate_name(&input.database_name)?;
        validate_name(&input.table_input.name)?;
        validate_table_input(&input.table_input)?;
        if input.update_open_table_format_input.is_some() {
            return Err(AnalyticsError::InvalidInput);
        }
        validate_catalog_id(input.catalog_id.as_deref(), &request.account_id)?;
        self.authorize_path(
            request,
            "UpdateTable",
            Some(&input.database_name),
            Some(&input.table_input.name),
        )?;
        let scope = Scope::new(&request.account_id, &request.region);
        let slot = self.state.catalog(&scope);
        let mut catalog = lock(&slot)?;
        let database = catalog
            .databases
            .get_mut(&input.database_name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        let table = database
            .tables
            .get_mut(&input.table_input.name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        if input
            .version_id
            .as_deref()
            .is_some_and(|version_id| version_id != table.version_id.to_string())
        {
            return Err(AnalyticsError::ConcurrentModification);
        }
        let next_version = table
            .version_id
            .checked_add(1)
            .ok_or(AnalyticsError::Internal)?;
        let now = now_epoch()?;
        table.input = input.table_input;
        table.update_time = now;
        table.version_id = next_version;
        Ok(json!({}))
    }

    fn delete_table(
        &self,
        input: DeleteTableRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        validate_name(&input.database_name)?;
        validate_name(&input.name)?;
        validate_catalog_id(input.catalog_id.as_deref(), &request.account_id)?;
        self.authorize_path(
            request,
            "DeleteTable",
            Some(&input.database_name),
            Some(&input.name),
        )?;
        let scope = Scope::new(&request.account_id, &request.region);
        let slot = self.state.catalog(&scope);
        let mut catalog = lock(&slot)?;
        let database = catalog
            .databases
            .get_mut(&input.database_name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        database
            .tables
            .remove(&input.name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        Ok(json!({}))
    }

    fn get_partitions(
        &self,
        input: GetPartitionsRequest,
        request: &ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        validate_name(&input.database_name)?;
        validate_name(&input.table_name)?;
        validate_catalog_id(input.catalog_id.as_deref(), &request.account_id)?;
        if input
            .expression
            .as_ref()
            .is_some_and(|value| !value.is_empty())
            || input.next_token.is_some()
            || input
                .max_results
                .is_some_and(|value| !(1..=1000).contains(&value))
        {
            return Err(AnalyticsError::InvalidInput);
        }
        self.authorize_path(
            request,
            "GetPartitions",
            Some(&input.database_name),
            Some(&input.table_name),
        )?;
        let scope = Scope::new(&request.account_id, &request.region);
        let slot = self.state.catalog(&scope);
        let catalog = lock(&slot)?;
        let database = catalog
            .databases
            .get(&input.database_name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        let table = database
            .tables
            .get(&input.table_name)
            .ok_or(AnalyticsError::EntityNotFound)?;
        Ok(json!({ "Partitions": table.partitions }))
    }
}

#[async_trait]
impl NativeHandler for GlueHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        match self.process(&request) {
            Ok(value) => Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, CONTENT_TYPE)
                .header("x-amzn-RequestId", &request.request_id)
                .body(Body::from(value.to_string()))
                .expect("Glue JSON response is valid"),
            Err(error) => AwsError::from(error)
                .with_request_id(request.request_id)
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), AnalyticsError> {
    let media_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .ok_or(AnalyticsError::InvalidInput)?;
    if media_type.eq_ignore_ascii_case(CONTENT_TYPE) {
        Ok(())
    } else {
        Err(AnalyticsError::InvalidInput)
    }
}

fn operation(headers: &HeaderMap) -> Result<&str, AnalyticsError> {
    headers
        .get("x-amz-target")
        .and_then(|value| value.to_str().ok())
        .and_then(|target| target.strip_prefix(&format!("{TARGET_PREFIX}.")))
        .filter(|operation| !operation.is_empty() && !operation.contains('.'))
        .ok_or(AnalyticsError::UnknownOperation)
}

fn validate_catalog_id<'a>(
    catalog_id: Option<&'a str>,
    account_id: &'a str,
) -> Result<&'a str, AnalyticsError> {
    match catalog_id {
        Some(catalog_id) if catalog_id != account_id => Err(AnalyticsError::InvalidInput),
        Some(catalog_id) => Ok(catalog_id),
        None => Ok(account_id),
    }
}

fn page_limit(max_results: Option<i64>) -> Result<usize, AnalyticsError> {
    match max_results {
        Some(value @ 1..=100) => Ok(value as usize),
        None => Ok(100),
        _ => Err(AnalyticsError::InvalidInput),
    }
}

fn page_token(request: &ServiceRequest, collection: &str, last_name: &str) -> String {
    format!(
        "lc1:{}:{}:{}:{}:{}",
        request.account_id,
        request.region,
        collection.len(),
        collection,
        last_name
    )
}

fn page_cursor(
    token: Option<&str>,
    request: &ServiceRequest,
    collection: &str,
) -> Result<Option<String>, AnalyticsError> {
    let Some(token) = token else {
        return Ok(None);
    };
    if token.len() > 4096 {
        return Err(AnalyticsError::InvalidInput);
    }
    let prefix = page_token(request, collection, "");
    let last_name = token.strip_prefix(&prefix).filter(|name| !name.is_empty());
    last_name
        .map(|name| Some(name.to_owned()))
        .ok_or(AnalyticsError::InvalidInput)
}

fn validate_name(name: &str) -> Result<(), AnalyticsError> {
    if name.trim().is_empty() {
        Err(AnalyticsError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_table_input(input: &TableInput) -> Result<(), AnalyticsError> {
    if input.fields.contains_key("FederatedTable") {
        return Err(AnalyticsError::InvalidInput);
    }
    let Some(parameters) = input.fields.get("Parameters") else {
        return Ok(());
    };
    let parameters = parameters.as_object().ok_or(AnalyticsError::InvalidInput)?;
    let Some(table_type) = parameters.get("table_type") else {
        return Ok(());
    };
    let table_type = table_type.as_str().ok_or(AnalyticsError::InvalidInput)?;
    if !table_type.eq_ignore_ascii_case("ICEBERG") {
        return Ok(());
    }

    // Iceberg discovery is driven by the current metadata JSON file. A
    // table_type flag alone is not an initialized Iceberg table.
    let metadata_location = parameters
        .get("metadata_location")
        .and_then(Value::as_str)
        .ok_or(AnalyticsError::InvalidInput)?;
    if !is_s3_object_uri(metadata_location) {
        return Err(AnalyticsError::InvalidInput);
    }
    // Glue's StorageDescriptor is optional, including for tables registered by
    // external Iceberg engines. Athena reads the table root from metadata JSON.
    if let Some(descriptor) = input.fields.get("StorageDescriptor") {
        let descriptor = descriptor.as_object().ok_or(AnalyticsError::InvalidInput)?;
        if let Some(location) = descriptor.get("Location") {
            if !location.as_str().is_some_and(is_s3_object_uri) {
                return Err(AnalyticsError::InvalidInput);
            }
        }
    }
    Ok(())
}

fn is_s3_object_uri(uri: &str) -> bool {
    uri.strip_prefix("s3://")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(bucket, key)| !bucket.is_empty() && !key.is_empty())
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, AnalyticsError> {
    serde_json::from_slice(body).map_err(|_| AnalyticsError::InvalidInput)
}

fn lock(slot: &Arc<std::sync::Mutex<Catalog>>) -> Result<MutexGuard<'_, Catalog>, AnalyticsError> {
    slot.lock().map_err(|_| AnalyticsError::Internal)
}

fn database_value(record: &DatabaseRecord, catalog_id: &str) -> Result<Value, AnalyticsError> {
    let mut object = input_object(&record.input)?;
    object.insert("CatalogId".to_owned(), catalog_id.into());
    object.insert("CreateTime".to_owned(), record.create_time.into());
    object.insert("UpdateTime".to_owned(), record.update_time.into());
    Ok(Value::Object(object))
}

fn table_value(
    record: &TableRecord,
    catalog_id: &str,
    database_name: &str,
) -> Result<Value, AnalyticsError> {
    let mut object = input_object(&record.input)?;
    object.insert("CatalogId".to_owned(), catalog_id.into());
    object.insert("DatabaseName".to_owned(), database_name.into());
    object.insert("CreateTime".to_owned(), record.create_time.into());
    object.insert("UpdateTime".to_owned(), record.update_time.into());
    object.insert("VersionId".to_owned(), record.version_id.to_string().into());
    Ok(Value::Object(object))
}

fn input_object<T: serde::Serialize>(input: &T) -> Result<Map<String, Value>, AnalyticsError> {
    match serde_json::to_value(input).map_err(|_| AnalyticsError::Internal)? {
        Value::Object(object) => Ok(object),
        _ => Err(AnalyticsError::Internal),
    }
}

fn now_epoch() -> Result<f64, AnalyticsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .map_err(|_| AnalyticsError::Internal)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct CreateDatabaseRequest {
    catalog_id: Option<String>,
    database_input: DatabaseInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct GetDatabaseRequest {
    catalog_id: Option<String>,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct GetDatabasesRequest {
    catalog_id: Option<String>,
    attributes_to_get: Option<Vec<String>>,
    max_results: Option<i64>,
    next_token: Option<String>,
    resource_share_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct UpdateDatabaseRequest {
    catalog_id: Option<String>,
    name: String,
    database_input: DatabaseInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct DeleteDatabaseRequest {
    catalog_id: Option<String>,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct CreateTableRequest {
    catalog_id: Option<String>,
    database_name: String,
    table_input: TableInput,
    open_table_format_input: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct GetTableRequest {
    catalog_id: Option<String>,
    database_name: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct GetTablesRequest {
    catalog_id: Option<String>,
    database_name: String,
    attributes_to_get: Option<Vec<String>>,
    audit_context: Option<Value>,
    expression: Option<String>,
    include_status_details: Option<bool>,
    max_results: Option<i64>,
    next_token: Option<String>,
    query_as_of_time: Option<f64>,
    transaction_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct UpdateTableRequest {
    catalog_id: Option<String>,
    database_name: String,
    table_input: TableInput,
    version_id: Option<String>,
    // ponytail: current-only catalog; add archived versions when GetTableVersions is needed.
    #[serde(rename = "SkipArchive")]
    _skip_archive: Option<bool>,
    update_open_table_format_input: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct DeleteTableRequest {
    catalog_id: Option<String>,
    database_name: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct GetPartitionsRequest {
    catalog_id: Option<String>,
    database_name: String,
    table_name: String,
    expression: Option<String>,
    next_token: Option<String>,
    max_results: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderValue, Method, Uri};

    fn request(operation: &str, body: Value) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static(CONTENT_TYPE),
        );
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("AWSGlue.{operation}")).unwrap(),
        );
        ServiceRequest {
            method: Method::POST,
            uri: Uri::from_static("/"),
            headers,
            body: Bytes::from(body.to_string()),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "glue-iceberg-test".into(),
        }
    }

    struct DenyAll;

    impl locallycloud_core::integration::authorization::AuthorizationEvaluator for DenyAll {
        fn strict_sigv4_required(&self) -> bool {
            true
        }

        fn authorize(
            &self,
            _request: AuthorizationRequest,
        ) -> Result<(), locallycloud_core::integration::authorization::AuthorizationError> {
            Err(locallycloud_core::integration::authorization::AuthorizationError::Denied)
        }
    }

    #[test]
    fn strict_glue_denies_all_public_operations_without_resource_permission() {
        let registry = ServiceRegistry::with_known_services();
        let state = Arc::new(AnalyticsState::new());
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            locallycloud_core::registry::ServiceMetadata::new(AwsProtocol::Query, None),
            Arc::new(GlueHandler::new(Arc::clone(&state))),
            Arc::new(DenyAll),
        );
        let handler = GlueHandler::with_registry(state, Arc::downgrade(&registry));
        let cases = [
            ("CreateDatabase", json!({"DatabaseInput":{"Name":"db"}})),
            ("GetDatabase", json!({"Name":"db"})),
            ("GetDatabases", json!({})),
            (
                "UpdateDatabase",
                json!({"Name":"db","DatabaseInput":{"Name":"db"}}),
            ),
            ("DeleteDatabase", json!({"Name":"db"})),
            (
                "CreateTable",
                json!({"DatabaseName":"db","TableInput":{"Name":"tab"}}),
            ),
            ("GetTable", json!({"DatabaseName":"db","Name":"tab"})),
            ("GetTables", json!({"DatabaseName":"db"})),
            (
                "UpdateTable",
                json!({"DatabaseName":"db","TableInput":{"Name":"tab"}}),
            ),
            ("DeleteTable", json!({"DatabaseName":"db","Name":"tab"})),
            (
                "GetPartitions",
                json!({"DatabaseName":"db","TableName":"tab"}),
            ),
        ];
        for (operation, body) in cases {
            let mut request = request(operation, body);
            request.headers.insert(
                "x-locallycloud-verified-external-sigv4",
                HeaderValue::from_static("1"),
            );
            request.headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_static(
                    "AWS4-HMAC-SHA256 Credential=AKIATEST/20260927/us-east-1/glue/aws4_request",
                ),
            );
            assert!(
                matches!(handler.process(&request), Err(AnalyticsError::AccessDenied)),
                "{operation}"
            );
        }
    }

    #[test]
    fn catalog_lists_are_paginated_and_scoped() {
        let handler = GlueHandler::new(Arc::new(AnalyticsState::new()));
        for name in ["a", "b", "c"] {
            handler
                .process(&request(
                    "CreateDatabase",
                    json!({"DatabaseInput":{"Name":name}}),
                ))
                .unwrap();
            handler
                .process(&request(
                    "CreateTable",
                    json!({"DatabaseName":name,"TableInput":{"Name":"first"}}),
                ))
                .unwrap();
        }
        handler
            .process(&request(
                "CreateTable",
                json!({"DatabaseName":"a","TableInput":{"Name":"second"}}),
            ))
            .unwrap();

        let first = handler
            .process(&request("GetDatabases", json!({"MaxResults":2})))
            .unwrap();
        assert_eq!(first["DatabaseList"].as_array().unwrap().len(), 2);
        assert_eq!(first["DatabaseList"][0]["Name"], "a");
        assert_eq!(first["DatabaseList"][1]["Name"], "b");
        let token = first["NextToken"].as_str().unwrap();
        let second = handler
            .process(&request(
                "GetDatabases",
                json!({"MaxResults":2,"NextToken":token}),
            ))
            .unwrap();
        assert_eq!(second["DatabaseList"][0]["Name"], "c");
        assert!(second.get("NextToken").is_none());

        let tables = handler
            .process(&request(
                "GetTables",
                json!({"DatabaseName":"a","MaxResults":1}),
            ))
            .unwrap();
        assert_eq!(tables["TableList"][0]["Name"], "first");
        assert_eq!(tables["TableList"][0]["DatabaseName"], "a");
        let table_token = tables["NextToken"].as_str().unwrap();
        let next = handler
            .process(&request(
                "GetTables",
                json!({"DatabaseName":"a","MaxResults":1,"NextToken":table_token}),
            ))
            .unwrap();
        assert_eq!(next["TableList"][0]["Name"], "second");
        assert!(next.get("NextToken").is_none());

        assert!(matches!(
            handler.process(&request("GetDatabases", json!({"NextToken":table_token}))),
            Err(AnalyticsError::InvalidInput)
        ));
        assert!(matches!(
            handler.process(&request(
                "GetTables",
                json!({"DatabaseName":"b","NextToken":table_token})
            )),
            Err(AnalyticsError::InvalidInput)
        ));
        let prefix_database = request("CreateDatabase", json!({"DatabaseInput":{"Name":"a:b"}}));
        handler.process(&prefix_database).unwrap();
        let prefixed = handler.process(&request(
            "GetTables",
            json!({"DatabaseName":"a:b","NextToken":table_token}),
        ));
        assert!(matches!(prefixed, Err(AnalyticsError::InvalidInput)));
        let mut other_region = request("GetDatabases", json!({"NextToken":token}));
        other_region.region = "eu-west-1".into();
        assert!(matches!(
            handler.process(&other_region),
            Err(AnalyticsError::InvalidInput)
        ));
        let mut other_account = request("GetDatabases", json!({}));
        other_account.account_id = "111111111111".into();
        assert!(handler.process(&other_account).unwrap()["DatabaseList"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn unsupported_catalog_list_options_fail_closed() {
        let handler = GlueHandler::new(Arc::new(AnalyticsState::new()));
        for body in [
            json!({"MaxResults":0}),
            json!({"MaxResults":101}),
            json!({"AttributesToGet":["NAME"]}),
            json!({"ResourceShareType":"ALL"}),
        ] {
            assert!(matches!(
                handler.process(&request("GetDatabases", body)),
                Err(AnalyticsError::InvalidInput)
            ));
        }
        for body in [
            json!({"DatabaseName":"lake","Expression":"event.*"}),
            json!({"DatabaseName":"lake","TransactionId":"txn"}),
            json!({"DatabaseName":"lake","AttributesToGet":["NAME"]}),
            json!({"DatabaseName":"lake","MaxResults":0}),
        ] {
            assert!(matches!(
                handler.process(&request("GetTables", body)),
                Err(AnalyticsError::InvalidInput)
            ));
        }
        assert!(matches!(
            handler.process(&request("GetTables", json!({"DatabaseName":"missing"}))),
            Err(AnalyticsError::EntityNotFound)
        ));
    }

    #[test]
    fn update_table_version_is_atomic_and_stale_commit_preserves_metadata() {
        use std::sync::Barrier;

        let handler = Arc::new(GlueHandler::new(Arc::new(AnalyticsState::new())));
        assert!(handler
            .process(&request(
                "CreateDatabase",
                json!({"DatabaseInput":{"Name":"lake"}}),
            ))
            .is_ok());
        assert!(handler
            .process(&request(
                "CreateTable",
                json!({
                    "DatabaseName":"lake",
                    "TableInput":{"Name":"events","Parameters":{"metadata_location":"s3://warehouse/metadata/1.json"}}
                }),
            ))
            .is_ok());
        let get = json!({"DatabaseName":"lake","Name":"events"});
        let initial = handler.process(&request("GetTable", get.clone())).unwrap();
        assert_eq!(initial["Table"]["VersionId"], "1");

        let barrier = Arc::new(Barrier::new(3));
        let writes: Vec<_> = (0..2)
            .map(|writer| {
                let handler = Arc::clone(&handler);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let update = json!({
                        "DatabaseName":"lake",
                        "VersionId":"1",
                        "TableInput":{
                            "Name":"events",
                            "Parameters":{"metadata_location":format!("s3://warehouse/metadata/writer-{writer}.json")}
                        }
                    });
                    barrier.wait();
                    handler.process(&request("UpdateTable", update))
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = writes
            .into_iter()
            .map(|write| write.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(AnalyticsError::ConcurrentModification)))
                .count(),
            1
        );
        let committed = handler.process(&request("GetTable", get.clone())).unwrap();
        assert_eq!(committed["Table"]["VersionId"], "2");
        assert!(committed["Table"]["Parameters"]["metadata_location"]
            .as_str()
            .unwrap()
            .starts_with("s3://warehouse/metadata/writer-"));

        let stale = json!({
            "DatabaseName":"lake",
            "VersionId":"1",
            "SkipArchive":true,
            "TableInput":{"Name":"events","Parameters":{"metadata_location":"s3://warehouse/metadata/stale.json"}}
        });
        assert!(matches!(
            handler.process(&request("UpdateTable", stale)),
            Err(AnalyticsError::ConcurrentModification)
        ));
        assert_eq!(
            handler.process(&request("GetTable", get.clone())).unwrap(),
            committed
        );

        let unconditional = json!({
            "DatabaseName":"lake",
            "SkipArchive":false,
            "TableInput":{"Name":"events","Parameters":{"metadata_location":"s3://warehouse/metadata/3.json"}}
        });
        assert!(handler
            .process(&request("UpdateTable", unconditional))
            .is_ok());
        let latest = handler.process(&request("GetTable", get.clone())).unwrap();
        assert_eq!(latest["Table"]["VersionId"], "3");

        let bad_skip_archive = json!({
            "DatabaseName":"lake",
            "SkipArchive":"true",
            "TableInput":{"Name":"events","Parameters":{"metadata_location":"s3://warehouse/metadata/invalid.json"}}
        });
        assert!(matches!(
            handler.process(&request("UpdateTable", bad_skip_archive)),
            Err(AnalyticsError::InvalidInput)
        ));
        assert_eq!(handler.process(&request("GetTable", get)).unwrap(), latest);
    }

    #[test]
    fn federated_table_is_rejected_without_catalog_mutation() {
        let handler = GlueHandler::new(Arc::new(AnalyticsState::new()));
        handler
            .process(&request(
                "CreateDatabase",
                json!({"DatabaseInput":{"Name":"lake"}}),
            ))
            .unwrap();
        let federated = json!({"Name":"events","FederatedTable":{"Identifier":"external"}});
        assert!(matches!(
            handler.process(&request(
                "CreateTable",
                json!({"DatabaseName":"lake","TableInput":federated})
            )),
            Err(AnalyticsError::InvalidInput)
        ));
        assert!(matches!(
            handler.process(&request(
                "GetTable",
                json!({"DatabaseName":"lake","Name":"events"})
            )),
            Err(AnalyticsError::EntityNotFound)
        ));
    }

    #[test]
    fn iceberg_catalog_roundtrip_and_reject_before_mutation() {
        let handler = GlueHandler::new(Arc::new(AnalyticsState::new()));
        let database = json!({"DatabaseInput":{"Name":"lake"}});
        assert!(handler
            .process(&request("CreateDatabase", database))
            .is_ok());

        let incomplete = json!({
            "DatabaseName":"lake",
            "TableInput":{
                "Name":"events",
                "Parameters":{"table_type":"ICEBERG"},
                "StorageDescriptor":{"Location":"s3://warehouse/events/"}
            }
        });
        assert!(matches!(
            handler.process(&request("CreateTable", incomplete)),
            Err(AnalyticsError::InvalidInput)
        ));
        assert!(matches!(
            handler.process(&request(
                "GetTable",
                json!({"DatabaseName":"lake","Name":"events"})
            )),
            Err(AnalyticsError::EntityNotFound)
        ));

        let lowercase = json!({
            "DatabaseName":"lake",
            "TableInput":{"Name":"lowercase","Parameters":{"table_type":"iceberg"}}
        });
        assert!(matches!(
            handler.process(&request("CreateTable", lowercase)),
            Err(AnalyticsError::InvalidInput)
        ));
        assert!(matches!(
            handler.process(&request(
                "GetTable",
                json!({"DatabaseName":"lake","Name":"lowercase"})
            )),
            Err(AnalyticsError::EntityNotFound)
        ));

        let table = json!({
            "Name":"events",
            "TableType":"EXTERNAL_TABLE",
            "Parameters":{
                "table_type":"ICEBERG",
                "metadata_location":"s3://warehouse/events/metadata/00001.metadata.json"
            }
        });
        assert!(handler
            .process(&request(
                "CreateTable",
                json!({
                    "DatabaseName":"lake","TableInput":table
                })
            ))
            .is_ok());
        let get = json!({"DatabaseName":"lake","Name":"events"});
        let original = handler
            .process(&request("GetTable", get.clone()))
            .unwrap_or_else(|_| panic!("created table must be readable"));
        assert_eq!(original["Table"]["Parameters"]["table_type"], "ICEBERG");
        assert_eq!(
            original["Table"]["Parameters"]["metadata_location"],
            "s3://warehouse/events/metadata/00001.metadata.json"
        );

        let bad_update = json!({"DatabaseName":"lake","TableInput":{
            "Name":"events",
            "Parameters":{"table_type":"ICEBERG","metadata_location":"http://elsewhere/metadata.json"},
            "StorageDescriptor":{"Location":"s3://warehouse/events/"}
        }});
        assert!(matches!(
            handler.process(&request("UpdateTable", bad_update)),
            Err(AnalyticsError::InvalidInput)
        ));
        let after = handler
            .process(&request("GetTable", get))
            .unwrap_or_else(|_| panic!("table must remain readable"));
        assert_eq!(after, original);

        let open_table = json!({
            "DatabaseName":"lake",
            "TableInput":{"Name":"uninitialized"},
            "OpenTableFormatInput":{"IcebergInput":{"MetadataOperation":"CREATE"}}
        });
        assert!(matches!(
            handler.process(&request("CreateTable", open_table)),
            Err(AnalyticsError::InvalidInput)
        ));
    }
}
