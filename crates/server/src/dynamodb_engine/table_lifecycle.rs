//! Public lifecycle for isolated KMS table files.
use std::collections::BTreeSet;
use std::time::Duration;

use locallycloud_dynamodb::encryption::TableKeyScope;
use serde_json::json;

use super::super::WorkerPool;
use super::*;

type Response = (u16, Value);

fn validation(message: &str) -> DdbError {
    DdbError::Validation(message.into())
}

fn busy() -> DdbError {
    DdbError::ResourceInUse("Table already exists or its storage is transitioning".into())
}

fn transport(_: String) -> DdbError {
    unavailable()
}

fn is_exception(body: &Value, exception: &str) -> bool {
    body.get("__type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.rsplit(['#', ':']).next() == Some(exception))
}

fn table_name<'a>(
    body: &'a Value,
    member: &str,
    account: &str,
    region: &str,
) -> Result<Option<&'a str>, DdbError> {
    let Some(raw) = body.get(member) else {
        return Ok(None);
    };
    let raw = raw
        .as_str()
        .ok_or_else(|| validation("Table name must be a string"))?;
    let name = if raw.starts_with("arn:") {
        raw.strip_prefix(&format!("arn:aws:dynamodb:{region}:{account}:table/"))
            .ok_or_else(|| validation("Table ARN must match the request scope"))?
    } else {
        raw
    };
    TableKeyScope::new(account, region, name, uuid::Uuid::from_u128(1))?;
    Ok(Some(name))
}

fn cmk_selector(body: &Value) -> Result<Option<&str>, DdbError> {
    let spec = body
        .get("SSESpecification")
        .ok_or_else(|| validation("SSESpecification is required"))?;
    if spec.get("Enabled").and_then(Value::as_bool) != Some(true)
        || spec
            .get("SSEType")
            .is_some_and(|kind| kind.as_str() != Some("KMS"))
    {
        return Err(validation(
            "Encrypted tables require Enabled=true and support only SSEType=KMS",
        ));
    }
    match spec.get("KMSMasterKeyId") {
        None => Ok(None),
        Some(Value::String(key)) if !key.is_empty() => Ok(Some(key)),
        Some(_) => Err(validation("KMSMasterKeyId must be a nonempty string")),
    }
}

fn encrypted_create(body: &Value) -> bool {
    body.get("SSESpecification").is_some_and(|spec| {
        spec.get("Enabled").and_then(Value::as_bool) == Some(true)
            || spec.get("SSEType").and_then(Value::as_str) == Some("KMS")
            || spec.get("KMSMasterKeyId").is_some()
    })
}

fn reject_integrations(body: &Value) -> Result<(), DdbError> {
    const REPLICA_FIELDS: &[&str] = &[
        "Replicas",
        "ReplicaUpdates",
        "ReplicationGroup",
        "GlobalTableSettingsReplicationMode",
        "GlobalTableSourceArn",
        "GlobalTableWitnessUpdates",
        "MultiRegionConsistency",
    ];
    if REPLICA_FIELDS.iter().any(|field| body.get(field).is_some())
        || body
            .pointer("/StreamSpecification/StreamEnabled")
            .and_then(Value::as_bool)
            == Some(true)
    {
        return Err(validation(
            "Streams and global tables are not supported for encrypted tables",
        ));
    }
    Ok(())
}

fn normalized(body: &Value, name: &str) -> Result<Value, DdbError> {
    let mut object = body
        .as_object()
        .cloned()
        .ok_or_else(|| validation("Request must be an object"))?;
    object.insert("TableName".into(), Value::String(name.into()));
    object.remove("SSESpecification");
    Ok(Value::Object(object))
}

fn status_description(record: &TableFileRecord, status: &str) -> Result<Value, DdbError> {
    let mut description = record.description().cloned().unwrap_or_else(|| json!({
        "TableName":record.scope().table_name(),
        "TableArn":format!("arn:aws:dynamodb:{}:{}:table/{}",record.scope().region(),record.scope().account(),record.scope().table_name())
    }));
    description
        .as_object_mut()
        .ok_or_else(unavailable)?
        .insert("TableStatus".into(), json!(status));
    Ok(description)
}

impl TableStorage {
    pub(in crate::dynamodb_engine) async fn lifecycle(
        self: &Arc<Self>,
        pool: &WorkerPool,
        account: &str,
        region: &str,
        operation: &str,
        body: &Value,
        request: Option<&ServiceRequest>,
    ) -> Result<Option<Response>, DdbError> {
        if !matches!(
            operation,
            "ListTables"
                | "CreateTable"
                | "DescribeTable"
                | "DeleteTable"
                | "UpdateTable"
                | "RestoreTableFromBackup"
                | "RestoreTableToPointInTime"
        ) {
            return Ok(None);
        }
        let services = self.services().await?;
        if operation == "ListTables" {
            if request.is_none() {
                if services.catalog.has_scope(account, region).await? {
                    return Err(DdbError::AccessDenied(
                        "Encrypted table listing requires a caller identity".into(),
                    ));
                }
                return Ok(None);
            }
            return self
                .list_tables(pool, account, region, body)
                .await
                .map(Some);
        }
        let member = match operation {
            "RestoreTableFromBackup" | "RestoreTableToPointInTime" => "TargetTableName",
            _ => "TableName",
        };
        let Some(name) = table_name(body, member, account, region)? else {
            if operation == "CreateTable" && encrypted_create(body) {
                return Err(validation("TableName is required"));
            }
            return Ok(None);
        };
        let record = services.catalog.load(account, region, name).await?;
        let source = match operation {
            "RestoreTableFromBackup" => body.get("BackupArn"),
            "RestoreTableToPointInTime" => body
                .get("SourceTableName")
                .or_else(|| body.get("SourceTableArn")),
            _ => None,
        };
        if record.is_none() {
            if let Some(source) = source.and_then(Value::as_str) {
                if let Some(source) = Self::target_name(account, region, source)? {
                    if services
                        .catalog
                        .load(account, region, source)
                        .await?
                        .is_some()
                    {
                        return Err(validation("Restoring an encrypted table is not supported"));
                    }
                }
            }
        }
        let Some(request) = request else {
            if record.is_some() || (operation == "CreateTable" && encrypted_create(body)) {
                return Err(DdbError::AccessDenied(
                    "Encrypted table operations require a caller identity".into(),
                ));
            }
            return Ok(None);
        };
        match operation {
            "CreateTable" if encrypted_create(body) => self
                .create_table(pool, name, body, request, record)
                .await
                .map(Some),
            "CreateTable" | "RestoreTableFromBackup" | "RestoreTableToPointInTime"
                if record.is_some() =>
            {
                Err(busy())
            }
            "DescribeTable" => match record {
                Some(record) => self.describe_table(pool, record, request).await.map(Some),
                None => Ok(None),
            },
            "DeleteTable" => match record {
                Some(record) => self.delete_table(pool, record).await.map(Some),
                None => Ok(None),
            },
            "UpdateTable" => match record {
                Some(record) => self
                    .update_table(pool, record, body, request)
                    .await
                    .map(Some),
                None if encrypted_create(body) => Err(validation(
                    "Changing default-owned table encryption is not supported",
                )),
                None => Ok(None),
            },
            _ => Ok(None),
        }
    }

    async fn sse_description(
        &self,
        record: &TableFileRecord,
        mut description: Value,
    ) -> Result<Value, DdbError> {
        let arn = self
            .services()
            .await?
            .keys
            .key_arn(record.scope(), record.envelope())
            .map_err(kms_error)?;
        description.as_object_mut().ok_or_else(unavailable)?.insert(
            "SSEDescription".into(),
            json!({"Status":"ENABLED", "SSEType":"KMS", "KMSMasterKeyArn":arn}),
        );
        Ok(description)
    }

    async fn describe_table(
        self: &Arc<Self>,
        pool: &WorkerPool,
        record: TableFileRecord,
        request: &ServiceRequest,
    ) -> Result<Response, DdbError> {
        match record.phase() {
            FilePhase::Deleting => Ok((
                200,
                json!({"Table":self.sse_description(&record, status_description(&record, "DELETING")?).await?}),
            )),
            FilePhase::Updating => self.describe_updating(pool, record, request).await,
            FilePhase::Active => {
                let path = pool
                    .data
                    .join(record.scope().account())
                    .join(record.scope().region())
                    .join(record.file_name());
                let metadata = tokio::fs::symlink_metadata(path)
                    .await
                    .map_err(|_| unavailable())?;
                if !metadata.is_file() || metadata.len() == 0 {
                    return Err(unavailable());
                }
                let description = match record.description() {
                    Some(description) => description.clone(),
                    None => {
                        let (status, response) = pool
                            .query_table(
                                self.control_call(record.clone(), request),
                                "DescribeTable".into(),
                                json!({"TableName":record.scope().table_name()}),
                            )
                            .await
                            .map_err(transport)?;
                        if status != 200 {
                            return Ok((status, response));
                        }
                        let description = response.get("Table").cloned().ok_or_else(unavailable)?;
                        self.services()
                            .await?
                            .catalog
                            .refresh_description(&record, description.clone())
                            .await?;
                        description
                    }
                };
                Ok((
                    200,
                    json!({"Table":self.sse_description(&record, description).await?}),
                ))
            }
            FilePhase::Creating => {
                let (status, response) = pool
                    .query_table(
                        self.inspection_call(record.clone(), request),
                        "DescribeTable".into(),
                        json!({"TableName":record.scope().table_name()}),
                    )
                    .await
                    .map_err(transport)?;
                if status != 200 {
                    return Ok((status, response));
                }
                let description = response.get("Table").cloned().ok_or_else(unavailable)?;
                if description.get("TableStatus").and_then(Value::as_str) == Some("ACTIVE") {
                    self.services()
                        .await?
                        .catalog
                        .activate(&record, description.clone())
                        .await?;
                }
                Ok((
                    200,
                    json!({"Table":self.sse_description(&record, description).await?}),
                ))
            }
        }
    }

    async fn create_table(
        self: &Arc<Self>,
        pool: &WorkerPool,
        name: &str,
        body: &Value,
        request: &ServiceRequest,
        existing: Option<TableFileRecord>,
    ) -> Result<Response, DdbError> {
        let account = request.account_id.as_str();
        let region = request.region.as_str();
        reject_integrations(body)?;
        let selector = cmk_selector(body)?;
        let intent = normalized(body, name)?;
        let services = self.services().await?;
        let (record, key) = match existing {
            Some(record) => {
                if record.phase() != FilePhase::Creating || record.create_intent() != Some(&intent)
                {
                    return Err(busy());
                }
                let (identity, delegated) = Self::identity(request);
                let (_, canonical) = services
                    .keys
                    .generation_context(
                        record.scope(),
                        selector,
                        &request.request_id,
                        identity,
                        delegated,
                    )
                    .await
                    .map_err(kms_error)?;
                if services
                    .keys
                    .key_arn(record.scope(), record.envelope())
                    .map_err(kms_error)?
                    != canonical
                {
                    return Err(busy());
                }
                (record, None)
            }
            None => {
                let (status, response) = pool
                    .query_raw(
                        account,
                        region,
                        "DescribeTable".into(),
                        json!({"TableName":name}),
                    )
                    .await
                    .map_err(transport)?;
                if status == 200 {
                    return Err(busy());
                }
                if status != 400 || !is_exception(&response, "ResourceNotFoundException") {
                    return Ok((status, response));
                }
                let scope = TableKeyScope::new(account, region, name, uuid::Uuid::new_v4())?;
                let (identity, delegated) = Self::identity(request);
                let (call, canonical) = services
                    .keys
                    .generation_context(&scope, selector, &request.request_id, identity, delegated)
                    .await
                    .map_err(kms_error)?;
                let material = services
                    .keys
                    .generate(&scope, call, Some(&canonical))
                    .await
                    .map_err(kms_error)?;
                let encoded = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD.encode(material.plaintext.as_slice()),
                );
                let record = services
                    .catalog
                    .reserve_with_intent(scope, material.envelope, intent.clone())
                    .await?;
                (record, Some(encoded))
            }
        };
        let reply = pool
            .query_table(
                self.creation_call(
                    record.clone(),
                    request,
                    key.as_ref().map(|key| Zeroizing::new(key.to_string())),
                ),
                "CreateTable".into(),
                intent,
            )
            .await
            .map_err(transport)?;
        if reply.0 != 200 && !is_exception(&reply.1, "ResourceInUseException") {
            if is_exception(&reply.1, "ValidationException")
                || is_exception(&reply.1, "SerializationException")
            {
                self.remove_generation(pool, &record).await?;
            }
            return Ok(reply);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut last = reply;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let probe = tokio::time::timeout(
                remaining,
                pool.query_table(
                    self.creation_call(
                        record.clone(),
                        request,
                        key.as_ref().map(|key| Zeroizing::new(key.to_string())),
                    ),
                    "DescribeTable".into(),
                    json!({"TableName":name}),
                ),
            )
            .await;
            match probe {
                Ok(Ok((200, response))) => {
                    let description = response.get("Table").cloned().ok_or_else(unavailable)?;
                    if description.get("TableStatus").and_then(Value::as_str) == Some("ACTIVE") {
                        services
                            .catalog
                            .activate(&record, description.clone())
                            .await?;
                        return Ok((
                            200,
                            json!({"TableDescription":self.sse_description(&record, description).await?}),
                        ));
                    }
                    last = (
                        200,
                        json!({"TableDescription":self.sse_description(&record, description).await?}),
                    );
                }
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(error)) => return Err(transport(error)),
                Err(_) => break,
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if let Some(description) = last.1.get("TableDescription").cloned() {
            last.1 = json!({"TableDescription":self.sse_description(&record, description).await?});
        }
        Ok(last)
    }

    async fn remove_generation(
        &self,
        pool: &WorkerPool,
        record: &TableFileRecord,
    ) -> Result<(), DdbError> {
        let services = self.services().await?;
        let deleting = match record.phase() {
            FilePhase::Deleting => record.clone(),
            _ => {
                services
                    .catalog
                    .transition(record, FilePhase::Deleting)
                    .await?
            }
        };
        let scope = (
            record.scope().account().to_owned(),
            record.scope().region().to_owned(),
            Some(record.scope().storage_id()),
        );
        pool.stop_worker(&scope).await.map_err(|_| unavailable())?;
        let path = pool
            .data
            .join(record.scope().account())
            .join(record.scope().region())
            .join(record.file_name());
        for suffix in ["", "-wal", "-shm"] {
            let mut file = path.as_os_str().to_owned();
            file.push(suffix);
            match tokio::fs::remove_file(std::path::PathBuf::from(file)).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(unavailable()),
            }
        }
        services.catalog.forget_deleted(&deleting).await?;
        pool.retire_stopped_generation(&scope)
            .map_err(|_| unavailable())?;
        Ok(())
    }

    async fn delete_table(
        &self,
        pool: &WorkerPool,
        record: TableFileRecord,
    ) -> Result<Response, DdbError> {
        if record.phase() == FilePhase::Updating {
            return Err(busy());
        }
        if record.phase() != FilePhase::Deleting
            && record
                .description()
                .and_then(|value| value.get("DeletionProtectionEnabled"))
                .or_else(|| {
                    record
                        .create_intent()
                        .and_then(|value| value.get("DeletionProtectionEnabled"))
                })
                .and_then(Value::as_bool)
                == Some(true)
        {
            return Err(validation("Table is protected from deletion"));
        }
        let description = status_description(&record, "DELETING")?;
        let description = self.sse_description(&record, description).await?;
        self.remove_generation(pool, &record).await?;
        Ok((200, json!({"TableDescription":description})))
    }

    async fn update_table(
        self: &Arc<Self>,
        pool: &WorkerPool,
        record: TableFileRecord,
        body: &Value,
        request: &ServiceRequest,
    ) -> Result<Response, DdbError> {
        if !matches!(record.phase(), FilePhase::Active | FilePhase::Updating) {
            return Err(busy());
        }
        let object = body
            .as_object()
            .ok_or_else(|| validation("Request must be an object"))?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "TableName" | "SSESpecification" | "DeletionProtectionEnabled"
            )
        }) {
            return Err(validation("Only deletion protection and same-key SSE updates are supported for encrypted tables"));
        }
        if body.get("DeletionProtectionEnabled").is_none() && body.get("SSESpecification").is_none()
        {
            return Err(validation("UpdateTable requires a supported update"));
        }
        if let Some(value) = body.get("DeletionProtectionEnabled") {
            if !value.is_boolean() {
                return Err(validation("DeletionProtectionEnabled must be a boolean"));
            }
        }
        if body.get("SSESpecification").is_some() {
            let selector = cmk_selector(body)?;
            let services = self.services().await?;
            let (identity, delegated) = Self::identity(request);
            let (_, canonical) = services
                .keys
                .generation_context(
                    record.scope(),
                    selector,
                    &request.request_id,
                    identity,
                    delegated,
                )
                .await
                .map_err(kms_error)?;
            if services
                .keys
                .key_arn(record.scope(), record.envelope())
                .map_err(kms_error)?
                != canonical
            {
                return Err(validation(
                    "Changing an encrypted table's KMS key is not supported",
                ));
            }
        }
        let Some(protection) = body.get("DeletionProtectionEnabled") else {
            if record.phase() == FilePhase::Updating {
                return Err(busy());
            }
            let (status, response) = self.describe_table(pool, record, request).await?;
            return Ok((
                status,
                json!({"TableDescription":response.get("Table").ok_or_else(unavailable)?}),
            ));
        };
        let intent =
            json!({"TableName":record.scope().table_name(),"DeletionProtectionEnabled":protection});
        let updating = match record.phase() {
            FilePhase::Active => {
                self.control_call(record.clone(), request)
                    .authorize()
                    .await?;
                self.services()
                    .await?
                    .catalog
                    .begin_update(&record, intent.clone())
                    .await?
            }
            FilePhase::Updating if record.pending_update() == Some(&intent) => record,
            FilePhase::Updating | FilePhase::Creating | FilePhase::Deleting => return Err(busy()),
        };
        let response = pool
            .query_table(
                self.control_call(updating.clone(), request),
                "UpdateTable".into(),
                intent,
            )
            .await
            .map_err(transport)?;
        if response.0 != 200 {
            return Ok(response);
        }
        let (status, output) = self.describe_updating(pool, updating, request).await?;
        Ok((
            status,
            json!({"TableDescription":output.get("Table").ok_or_else(unavailable)?}),
        ))
    }

    async fn describe_updating(
        self: &Arc<Self>,
        pool: &WorkerPool,
        record: TableFileRecord,
        request: &ServiceRequest,
    ) -> Result<Response, DdbError> {
        let (status, output) = pool
            .query_table(
                self.control_call(record.clone(), request),
                "DescribeTable".into(),
                json!({"TableName":record.scope().table_name()}),
            )
            .await
            .map_err(transport)?;
        if status != 200 {
            return Ok((
                200,
                json!({"Table":self.sse_description(&record, status_description(&record, "UPDATING")?).await?}),
            ));
        }
        let mut description = output.get("Table").cloned().ok_or_else(unavailable)?;
        let expected = record
            .pending_update()
            .and_then(|value| value.get("DeletionProtectionEnabled"))
            .and_then(Value::as_bool);
        if description.get("TableStatus").and_then(Value::as_str) == Some("ACTIVE")
            && expected.is_some()
            && description
                .get("DeletionProtectionEnabled")
                .and_then(Value::as_bool)
                == expected
        {
            self.services()
                .await?
                .catalog
                .complete_update(&record, description.clone())
                .await?;
        } else {
            description
                .as_object_mut()
                .ok_or_else(unavailable)?
                .insert("TableStatus".into(), json!("UPDATING"));
        }
        Ok((
            200,
            json!({"Table":self.sse_description(&record, description).await?}),
        ))
    }

    async fn list_tables(
        &self,
        pool: &WorkerPool,
        account: &str,
        region: &str,
        body: &Value,
    ) -> Result<Response, DdbError> {
        let limit = match body.get("Limit") {
            None => 100,
            Some(value) => value
                .as_u64()
                .filter(|limit| (1..=100).contains(limit))
                .ok_or_else(|| validation("Limit must be between 1 and 100"))?
                as usize,
        };
        let after = table_name(body, "ExclusiveStartTableName", account, region)?;
        let mut names = BTreeSet::new();
        let mut raw_cursor = after.map(str::to_owned);
        loop {
            let mut query = json!({"Limit":limit});
            if let Some(cursor) = &raw_cursor {
                query["ExclusiveStartTableName"] = json!(cursor);
            }
            let (status, response) = pool
                .query_raw(account, region, "ListTables".into(), query)
                .await
                .map_err(transport)?;
            if status != 200 {
                return Ok((status, response));
            }
            let page = response
                .get("TableNames")
                .and_then(Value::as_array)
                .ok_or_else(unavailable)?;
            for name in page {
                let name = name.as_str().ok_or_else(unavailable)?;
                if after.is_none_or(|after| name > after) {
                    names.insert(name.to_owned());
                }
            }
            let next = response
                .get("LastEvaluatedTableName")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if names.len() >= limit || next.is_none() {
                break;
            }
            if next == raw_cursor {
                return Err(unavailable());
            }
            raw_cursor = next;
        }
        let catalog = &self.services().await?.catalog;
        let mut cursor = after.map(str::to_owned);
        let mut count = 0;
        while count < limit {
            let page = catalog
                .page_scope(account, region, cursor.as_deref(), limit - count)
                .await?;
            if page.is_empty() {
                break;
            }
            count += page.len();
            for record in page {
                let name = record.scope().table_name().to_owned();
                cursor = Some(name.clone());
                names.insert(name);
            }
        }
        let names: Vec<_> = names.into_iter().take(limit).collect();
        let mut response = json!({"TableNames":names});
        if names.len() == limit {
            if let Some(last) = names.last() {
                response["LastEvaluatedTableName"] = json!(last);
            }
        }
        Ok((200, response))
    }
}
