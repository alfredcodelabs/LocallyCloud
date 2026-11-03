//! Iceberg creation publishes real immutable metadata before its catalog pointer.
use super::*;
use ::iceberg::spec::TableMetadata;
use bytes::Bytes;
use http::{Method, Uri};
use locallycloud_core::integration::identity::IdentityPropagator;
use uuid::Uuid;

pub(super) fn is_create(request: &ServiceRequest) -> bool {
    request.method == Method::POST
        && request.uri.path() == "/"
        && request.uri.query().is_none()
        && operation(&request.headers).ok() == Some("CreateTable")
        && serde_json::from_slice::<Value>(&request.body)
            .ok()
            .is_some_and(|value| value.get("OpenTableFormatInput").is_some())
}

#[derive(Clone)]
struct Plan {
    input: NormalizedCreateTableRequest,
    bucket: String,
    key: String,
    metadata: Bytes,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct OpenInput {
    iceberg_input: IcebergInput,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct IcebergInput {
    metadata_operation: String,
    version: Option<String>,
    create_iceberg_table_input: CreateInput,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct CreateInput {
    location: String,
    schema: SchemaInput,
    partition_spec: Option<PartitionInput>,
    properties: Option<BTreeMap<String, String>>,
    write_order: Option<Value>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct SchemaInput {
    r#type: String,
    schema_id: Option<i32>,
    identifier_field_ids: Option<Vec<i32>>,
    fields: Vec<FieldInput>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct FieldInput {
    id: i32,
    name: String,
    r#type: Value,
    required: bool,
    doc: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct PartitionInput {
    spec_id: Option<i32>,
    fields: Vec<PartitionField>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct PartitionField {
    source_id: i32,
    transform: String,
    name: String,
    field_id: i32,
}

impl Plan {
    fn new(mut input: NormalizedCreateTableRequest) -> Result<Self, AnalyticsError> {
        let raw = input
            .open_table_format_input
            .take()
            .ok_or(AnalyticsError::InvalidInput)?;
        let open: OpenInput =
            serde_json::from_value(raw).map_err(|_| AnalyticsError::InvalidInput)?;
        let iceberg = open.iceberg_input;
        if iceberg.metadata_operation != "CREATE" {
            return Err(AnalyticsError::InvalidInput);
        }
        match iceberg.version.as_deref().unwrap_or("2") {
            "2" => {}
            "1" | "3" => {
                return Err(AnalyticsError::Unsupported(
                    "LocalCloud Iceberg table creation supports format version 2 only",
                ))
            }
            _ => return Err(AnalyticsError::InvalidInput),
        }
        let create = iceberg.create_iceberg_table_input;
        if create.write_order.is_some() {
            return Err(AnalyticsError::Unsupported(
                "LocalCloud Iceberg WriteOrder creation is not implemented",
            ));
        }
        if create.schema.r#type != "struct"
            || create.schema.fields.is_empty()
            || create.schema.fields.len() > 1000
        {
            return Err(AnalyticsError::InvalidInput);
        }
        // A supplied pointer describes registration, not a new physical table.
        if input
            .table_input
            .fields
            .get("Parameters")
            .and_then(|p| p.get("metadata_location"))
            .is_some()
        {
            return Err(AnalyticsError::InvalidInput);
        }
        let location = create.location.trim_end_matches('/');
        let (bucket, prefix) = location
            .strip_prefix("s3://")
            .and_then(|p| p.split_once('/'))
            .ok_or(AnalyticsError::InvalidInput)?;
        if bucket.is_empty()
            || bucket.len() > 63
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
            || prefix.is_empty()
            || prefix.len() > 800
            || prefix
                .split('/')
                .any(|p| p.is_empty() || matches!(p, "." | ".."))
            || prefix.chars().any(|c| c.is_control() || c == '\\')
        {
            return Err(AnalyticsError::InvalidInput);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        let mut fields = Vec::new();
        let mut columns = Vec::new();
        for field in create.schema.fields {
            if field.id <= 0
                || field.name.is_empty()
                || field.name.len() > 255
                || !ids.insert(field.id)
                || !names.insert(field.name.clone())
            {
                return Err(AnalyticsError::InvalidInput);
            }
            if field.r#type.is_object() {
                return Err(AnalyticsError::Unsupported(
                    "LocalCloud Iceberg nested-type creation is not implemented",
                ));
            }
            let primitive: ::iceberg::spec::PrimitiveType =
                serde_json::from_value(field.r#type.clone())
                    .map_err(|_| AnalyticsError::InvalidInput)?;
            let mut value = json!({"id":field.id,"name":field.name,"type":primitive.to_string(),"required":field.required});
            if let Some(doc) = field.doc {
                value["doc"] = doc.into();
            }
            fields.push(value);
            let hive_type = match field.r#type.as_str().ok_or(AnalyticsError::InvalidInput)? {
                "long" => "bigint",
                "timestamptz" => "timestamp",
                "uuid" => "string",
                other => other,
            };
            columns.push(json!({"Name":field.name,"Type":hive_type}));
        }
        let schema_id = create.schema.schema_id.unwrap_or(0);
        if schema_id < 0 {
            return Err(AnalyticsError::InvalidInput);
        }
        let schema = json!({"type":"struct","schema-id":schema_id,"identifier-field-ids":create.schema.identifier_field_ids.unwrap_or_default(),"fields":fields});
        // Reuse Iceberg's semantic validation (identifier fields and primitive types).
        let _: ::iceberg::spec::Schema =
            serde_json::from_value(schema.clone()).map_err(|_| AnalyticsError::InvalidInput)?;
        let spec = create.partition_spec.unwrap_or(PartitionInput {
            spec_id: Some(0),
            fields: Vec::new(),
        });
        let spec_id = spec.spec_id.unwrap_or(0);
        if spec_id < 0 || spec.fields.len() > 100 {
            return Err(AnalyticsError::InvalidInput);
        }
        let mut partition_ids = std::collections::BTreeSet::new();
        let mut partition_names = std::collections::BTreeSet::new();
        let mut partition_fields = Vec::new();
        for field in spec.fields {
            if !ids.contains(&field.source_id)
                || field.field_id < 1000
                || field.name.is_empty()
                || field.name.len() > 255
                || !partition_ids.insert(field.field_id)
                || !partition_names.insert(field.name.clone())
            {
                return Err(AnalyticsError::InvalidInput);
            }
            let transform: ::iceberg::spec::Transform = field
                .transform
                .parse()
                .map_err(|_| AnalyticsError::InvalidInput)?;
            if transform != ::iceberg::spec::Transform::Identity {
                return Err(AnalyticsError::Unsupported(
                    "LocalCloud Iceberg creation supports identity partition transforms only",
                ));
            }
            partition_fields.push(json!({"source-id":field.source_id,"field-id":field.field_id,"name":field.name,"transform":field.transform}));
        }
        let properties = create.properties.unwrap_or_default();
        if properties.len() > 100
            || properties
                .iter()
                .any(|(k, v)| k.len() > 255 || v.len() > 4096)
        {
            return Err(AnalyticsError::InvalidInput);
        }
        let now = (now_epoch()? * 1000.0) as i64;
        let uuid = Uuid::new_v4();
        let metadata = json!({"format-version":2,"table-uuid":uuid,"location":location,
            "last-sequence-number":0,"last-updated-ms":now,"last-column-id":ids.last().copied().unwrap_or(0),
            "schemas":[schema],"current-schema-id":schema_id,
            "partition-specs":[{"spec-id":spec_id,"fields":partition_fields}],"default-spec-id":spec_id,
            "last-partition-id":partition_ids.last().copied().unwrap_or(999),"properties":properties,
            "current-snapshot-id":-1,"snapshots":[],"snapshot-log":[],"metadata-log":[],
            "sort-orders":[{"order-id":0,"fields":[]}],"default-sort-order-id":0});
        let _: TableMetadata =
            serde_json::from_value(metadata.clone()).map_err(|_| AnalyticsError::InvalidInput)?;
        let key = format!("{prefix}/metadata/00000-{uuid}.metadata.json");
        let uri = format!("s3://{bucket}/{key}");
        if input
            .table_input
            .fields
            .get("TableType")
            .is_some_and(|value| value != "EXTERNAL_TABLE")
            || input
                .table_input
                .fields
                .get("PartitionKeys")
                .is_some_and(|value| value.as_array().is_none_or(|fields| !fields.is_empty()))
        {
            return Err(AnalyticsError::InvalidInput);
        }
        if let Some(descriptor) = input.table_input.fields.get("StorageDescriptor") {
            let descriptor = descriptor.as_object().ok_or(AnalyticsError::InvalidInput)?;
            if descriptor.iter().any(|(key, value)| match key.as_str() {
                "Location" => value
                    .as_str()
                    .is_none_or(|value| value.trim_end_matches('/') != location),
                "Columns" => value != &json!(columns),
                _ => true,
            }) {
                return Err(AnalyticsError::InvalidInput);
            }
        }
        let params = input
            .table_input
            .fields
            .entry("Parameters".into())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or(AnalyticsError::InvalidInput)?;
        if params.values().any(|value| !value.is_string())
            || params
                .get("table_type")
                .is_some_and(|value| value != "ICEBERG")
        {
            return Err(AnalyticsError::InvalidInput);
        }
        params.insert("table_type".into(), json!("ICEBERG"));
        params.insert("metadata_location".into(), json!(uri));
        input
            .table_input
            .fields
            .insert("TableType".into(), json!("EXTERNAL_TABLE"));
        input.table_input.fields.insert(
            "StorageDescriptor".into(),
            json!({"Location":location,"Columns":columns}),
        );
        validate_table_input(&input.table_input)?;
        Ok(Self {
            input,
            bucket: bucket.to_owned(),
            key,
            metadata: Bytes::from(metadata.to_string()),
        })
    }
}

impl GlueHandler {
    pub(super) async fn create_iceberg(
        &self,
        request: ServiceRequest,
    ) -> Result<Value, AnalyticsError> {
        let handler = self.clone();
        let prepare_request = request.clone();
        let plan = tokio::task::spawn_blocking(move || {
            validate_content_type(&prepare_request.headers)?;
            let plan =
                Plan::new(decode::<CreateTableRequest>(&prepare_request.body)?.normalize()?)?;
            let input = &plan.input;
            validate_catalog_id(input.catalog_id.as_deref(), &prepare_request.account_id)?;
            validate_name(&input.database_name)?;
            validate_name(&input.table_input.name)?;
            handler.authorize_path(
                &prepare_request,
                "CreateTable",
                Some(&input.database_name),
                Some(&input.table_input.name),
            )?;
            let slot = handler.state.catalog(&Scope::new(
                &prepare_request.account_id,
                &prepare_request.region,
            ));
            let mut catalog = lock(&slot)?;
            let database = catalog
                .databases
                .get(&input.database_name)
                .ok_or(AnalyticsError::EntityNotFound)?;
            if database.tables.contains_key(&input.table_input.name) {
                return Err(AnalyticsError::AlreadyExists);
            }
            if !catalog
                .pending_tables
                .insert((input.database_name.clone(), input.table_input.name.clone()))
            {
                return Err(AnalyticsError::ConcurrentModification);
            }
            Ok(plan)
        })
        .await
        .map_err(|_| AnalyticsError::Internal)??;
        let uploaded = self.metadata_request(&request, &plan, Method::PUT).await;
        let upload_succeeded = uploaded.is_ok();
        let cleanup_plan = plan.clone();
        let handler = self.clone();
        let account = request.account_id.clone();
        let region = request.region.clone();
        let result = tokio::task::spawn_blocking(move || {
            let scope = Scope::new(&account, &region);
            let slot = handler.state.catalog(&scope);
            let mut catalog = lock(&slot)?;
            catalog.pending_tables.remove(&(
                plan.input.database_name.clone(),
                plan.input.table_input.name.clone(),
            ));
            uploaded?;
            let database = catalog
                .databases
                .get_mut(&plan.input.database_name)
                .ok_or(AnalyticsError::EntityNotFound)?;
            if database.tables.contains_key(&plan.input.table_input.name) {
                return Err(AnalyticsError::AlreadyExists);
            }
            let now = now_epoch()?;
            let record = TableRecord {
                input: plan.input.table_input,
                create_time: now,
                update_time: now,
                version_id: 1,
                partitions: Vec::new(),
            };
            if let Some(persistence) = &handler.state.persistence {
                persistence
                    .save_table(&scope, &plan.input.database_name, &record)
                    .map_err(|_| AnalyticsError::Internal)?;
            }
            database.tables.insert(record.input.name.clone(), record);
            Ok(json!({}))
        })
        .await
        .map_err(|_| AnalyticsError::Internal)?;
        if result.is_err() && upload_succeeded {
            // Delete only this operation's immutable object, using the same caller.
            // A denied cleanup cannot erase a pre-existing table or another writer.
            let _cleanup = self
                .metadata_request(&request, &cleanup_plan, Method::DELETE)
                .await;
        }
        result
    }

    async fn metadata_request(
        &self,
        request: &ServiceRequest,
        plan: &Plan,
        method: Method,
    ) -> Result<(), AnalyticsError> {
        let registry = self.registry.upgrade().ok_or(AnalyticsError::Internal)?;
        let dispatcher = registry
            .internal_dispatcher()
            .ok_or(AnalyticsError::Internal)?;
        let mut headers = HeaderMap::new();
        if let Some(role) = trusted_role(request) {
            IdentityPropagator::attach(&mut headers, &role);
        } else {
            let key = request
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(RequestIdentity::access_key_from_authorization)
                .unwrap_or_else(|| "locallycloud".into());
            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!(
                    "AWS4-HMAC-SHA256 Credential={key}/19700101/{}/s3/aws4_request",
                    request.region
                ))
                .map_err(|_| AnalyticsError::AccessDenied)?,
            );
        }
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if method == Method::PUT {
            headers.insert(http::header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        }
        let uri: Uri = format!("/{}/{}", plan.bucket, encode_key(&plan.key))
            .parse()
            .map_err(|_| AnalyticsError::InvalidInput)?;
        let response = dispatcher
            .dispatch_scoped(
                &method,
                &uri,
                &headers,
                if method == Method::PUT {
                    plan.metadata.clone()
                } else {
                    Bytes::new()
                },
                &request.request_id,
                &request.account_id,
                &request.region,
            )
            .await;
        match response.status().as_u16() {
            200..=299 => Ok(()),
            401 | 403 => Err(AnalyticsError::AccessDenied),
            404 => Err(AnalyticsError::EntityNotFound),
            _ => Err(AnalyticsError::Internal),
        }
    }
}

fn encode_key(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

#[cfg(test)]
mod tests;
