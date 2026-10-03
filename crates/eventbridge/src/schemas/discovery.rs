use std::collections::HashMap;

use http::{Method, StatusCode};
use locallycloud_core::handler::ServiceRequest;
use locallycloud_state::StateDb;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use super::{SchemaResult, SchemasError, SchemasService};

pub(super) fn init(state: &StateDb) -> Result<(), String> {
    state
        .connection()
        .map_err(|e| e.to_string())?
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schemas_discoverers (
                account TEXT NOT NULL, region TEXT NOT NULL, id TEXT NOT NULL,
                source_arn TEXT NOT NULL, description TEXT NOT NULL,
                cross_account INTEGER NOT NULL, state TEXT NOT NULL, tags TEXT NOT NULL,
                PRIMARY KEY(account, region, id), UNIQUE(account, region, source_arn)
            );",
        )
        .map_err(|e| e.to_string())
}

pub(super) fn dispatch(
    service: &SchemasService,
    req: &ServiceRequest,
    segments: &[&str],
    body: &Value,
    query: &HashMap<String, String>,
) -> Option<SchemaResult> {
    let account = &req.account_id;
    let region = &req.region;
    let conn = match service.state.connection() {
        Ok(conn) => conn,
        Err(e) => return Some(Err(SchemasError::Internal(e.to_string()))),
    };
    let db_err = |e: rusqlite::Error| SchemasError::Internal(e.to_string());
    match (req.method.clone(), segments) {
        (Method::POST, ["v1", "discover"]) => Some(discover(body)),
        (Method::POST, ["v1", "discoverers"]) => {
            let result = (|| {
                let source = body
                    .get("SourceArn")
                    .and_then(Value::as_str)
                    .ok_or_else(|| SchemasError::Validation("SourceArn is required".into()))?;
                if !source.starts_with(&format!("arn:aws:events:{region}:{account}:event-bus/"))
                    || source.ends_with('/')
                {
                    return Err(SchemasError::Validation(
                        "SourceArn must identify an event bus in this account and region".into(),
                    ));
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
                let cross_account = body
                    .get("CrossAccount")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let tags = body.get("tags").cloned().unwrap_or_else(|| json!({}));
                if !tags.is_object() {
                    return Err(SchemasError::Validation("tags must be an object".into()));
                }
                let id = Uuid::new_v4().to_string();
                match conn.execute("INSERT INTO schemas_discoverers(account, region, id, source_arn, description, cross_account, state, tags) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'STARTED', ?7)", params![account, region, id, source, description, cross_account, tags.to_string()]) {
                    Ok(_) => Ok((StatusCode::CREATED, json!({"DiscovererArn": format!("arn:aws:schemas:{region}:{account}:discoverer/{id}"), "DiscovererId": id, "SourceArn": source, "Description": description, "CrossAccount": cross_account, "State":"STARTED", "tags": tags}))),
                    Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => Err(SchemasError::Conflict("a discoverer already exists for this event bus".into())),
                    Err(e) => Err(db_err(e)),
                }
            })();
            Some(result)
        }
        (Method::GET, ["v1", "discoverers"]) => Some((|| {
            let mut stmt = conn.prepare("SELECT id, source_arn, cross_account, state, tags FROM schemas_discoverers WHERE account=?1 AND region=?2 ORDER BY id").map_err(db_err)?;
            let rows = stmt
                .query_map(params![account, region], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(db_err)?;
            let mut discoverers = Vec::new();
            for row in rows {
                let (id, source, cross_account, state, tags) = row.map_err(db_err)?;
                if query
                    .get("discovererIdPrefix")
                    .is_some_and(|prefix| !id.starts_with(prefix))
                    || query
                        .get("sourceArnPrefix")
                        .is_some_and(|prefix| !source.starts_with(prefix))
                {
                    continue;
                }
                discoverers.push(json!({"DiscovererArn": format!("arn:aws:schemas:{region}:{account}:discoverer/{id}"), "DiscovererId": id, "SourceArn": source, "CrossAccount": cross_account, "State": state, "tags": serde_json::from_str::<Value>(&tags).unwrap_or_else(|_| json!({}))}));
            }
            let (discoverers, next) = super::paginate(discoverers, query)?;
            let mut response = json!({"Discoverers": discoverers});
            if let Some(next) = next {
                response["NextToken"] = json!(next);
            }
            Ok((StatusCode::OK, response))
        })()),
        (method, ["v1", "discoverers", "id", id])
            if matches!(method, Method::GET | Method::PUT | Method::DELETE) =>
        {
            Some((|| {
                let found: Option<(String, String, bool, String, String)> = conn.query_row("SELECT source_arn, description, cross_account, state, tags FROM schemas_discoverers WHERE account=?1 AND region=?2 AND id=?3", params![account, region, id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).optional().map_err(db_err)?;
                let (source, mut description, mut cross_account, state, tags) =
                    found.ok_or_else(|| SchemasError::NotFound("discoverer not found".into()))?;
                if method == Method::DELETE {
                    conn.execute(
                        "DELETE FROM schemas_discoverers WHERE account=?1 AND region=?2 AND id=?3",
                        params![account, region, id],
                    )
                    .map_err(db_err)?;
                    return Ok((StatusCode::NO_CONTENT, Value::Null));
                }
                if method == Method::PUT {
                    if let Some(value) = body.get("Description") {
                        description = value
                            .as_str()
                            .ok_or_else(|| {
                                SchemasError::Validation("Description must be a string".into())
                            })?
                            .to_owned();
                    }
                    if description.len() > 256 {
                        return Err(SchemasError::Validation(
                            "Description exceeds 256 characters".into(),
                        ));
                    }
                    if let Some(value) = body.get("CrossAccount") {
                        cross_account = value.as_bool().ok_or_else(|| {
                            SchemasError::Validation("CrossAccount must be a boolean".into())
                        })?;
                    }
                    conn.execute("UPDATE schemas_discoverers SET description=?4, cross_account=?5 WHERE account=?1 AND region=?2 AND id=?3", params![account, region, id, description, cross_account]).map_err(db_err)?;
                }
                Ok((
                    StatusCode::OK,
                    json!({"DiscovererArn": format!("arn:aws:schemas:{region}:{account}:discoverer/{id}"), "DiscovererId": id, "SourceArn": source, "Description": description, "CrossAccount": cross_account, "State":state, "tags":serde_json::from_str::<Value>(&tags).unwrap_or_else(|_| json!({}))}),
                ))
            })())
        }
        (Method::POST, ["v1", "discoverers", "id", id, action])
            if *action == "start" || *action == "stop" =>
        {
            Some((|| {
                let state = if *action == "start" {
                    "STARTED"
                } else {
                    "STOPPED"
                };
                let changed = conn.execute("UPDATE schemas_discoverers SET state=?4 WHERE account=?1 AND region=?2 AND id=?3", params![account, region, id, state]).map_err(db_err)?;
                if changed == 0 {
                    return Err(SchemasError::NotFound("discoverer not found".into()));
                }
                Ok((StatusCode::OK, json!({"DiscovererId": id, "State": state})))
            })())
        }
        _ => None,
    }
}

fn discover(body: &Value) -> SchemaResult {
    let schema_type = body
        .get("Type")
        .and_then(Value::as_str)
        .ok_or_else(|| SchemasError::Validation("Type is required".into()))?;
    if !matches!(schema_type, "OpenApi3" | "JSONSchemaDraft4") {
        return Err(SchemasError::Validation("unsupported schema Type".into()));
    }
    let events = body
        .get("Events")
        .and_then(Value::as_array)
        .ok_or_else(|| SchemasError::Validation("Events is required".into()))?;
    if events.is_empty() || events.len() > 10 {
        return Err(SchemasError::Validation(
            "Events must contain between 1 and 10 JSON strings".into(),
        ));
    }
    let values: Vec<Value> = events
        .iter()
        .map(|event| {
            event
                .as_str()
                .ok_or_else(|| SchemasError::Validation("Events must contain JSON strings".into()))
                .and_then(|event| {
                    serde_json::from_str(event).map_err(|e| SchemasError::Validation(e.to_string()))
                })
        })
        .collect::<Result<_, _>>()?;
    let inferred = infer_values(&values);
    let content = if schema_type == "OpenApi3" {
        json!({"openapi":"3.0.0", "info":{"title":"Discovered Event", "version":"1"}, "paths":{}, "components":{"schemas":{"Event":inferred}}})
    } else {
        let mut value = inferred;
        value["$schema"] = json!("http://json-schema.org/draft-04/schema#");
        value
    };
    Ok((StatusCode::OK, json!({"Content":content.to_string()})))
}

fn infer_values(values: &[Value]) -> Value {
    if values.is_empty() {
        return json!({});
    }
    if values.iter().all(Value::is_object) {
        let mut properties = Map::new();
        let mut keys = std::collections::BTreeSet::new();
        for value in values {
            keys.extend(value.as_object().unwrap().keys().cloned());
        }
        let mut required = Vec::new();
        for key in keys {
            let present: Vec<Value> = values.iter().filter_map(|v| v.get(&key).cloned()).collect();
            if present.len() == values.len() {
                required.push(key.clone());
            }
            properties.insert(key, infer_values(&present));
        }
        return json!({"type":"object", "properties": properties, "required": required});
    }
    if values.iter().all(Value::is_array) {
        let items: Vec<Value> = values
            .iter()
            .flat_map(|v| v.as_array().unwrap().clone())
            .collect();
        return json!({"type":"array", "items":infer_values(&items)});
    }
    let mut types = std::collections::BTreeSet::new();
    for value in values {
        types.insert(match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            _ => "object",
        });
    }
    if types.len() == 1 {
        json!({"type":types.first().unwrap()})
    } else {
        json!({"type":types})
    }
}

/// Sample the original event before any rule target input transformation.
pub(crate) fn on_event(
    state: &StateDb,
    account: &str,
    region: &str,
    bus: &str,
    event: &Value,
) -> Result<(), String> {
    if event.to_string().len() > 1_000 * 1024 {
        return Ok(());
    }
    let Some(source) = event.get("source").and_then(Value::as_str) else {
        return Ok(());
    };
    let Some(detail_type) = event.get("detail-type").and_then(Value::as_str) else {
        return Ok(());
    };
    let mut conn = state.connection().map_err(|e| e.to_string())?;
    let source_arn = format!("arn:aws:events:{region}:{account}:event-bus/{bus}");
    let discoverer: Option<bool> = conn.query_row(
        "SELECT cross_account FROM schemas_discoverers WHERE account=?1 AND region=?2 AND source_arn=?3 AND state='STARTED'",
        params![account,region,source_arn], |row|row.get(0),
    ).optional().map_err(|e|e.to_string())?;
    let Some(cross_account) = discoverer else {
        return Ok(());
    };
    if !cross_account
        && event
            .get("account")
            .and_then(Value::as_str)
            .is_some_and(|origin| origin != account)
    {
        return Ok(());
    }
    let name = format!("{source}@{detail_type}");
    let mut inferred = infer_values(std::slice::from_ref(event));
    inferred["x-amazon-events-source"] = json!(source);
    inferred["x-amazon-events-detail-type"] = json!(detail_type);
    let content=json!({"openapi":"3.0.0","info":{"title":detail_type,"version":"1.0.0"},"paths":{},"components":{"schemas":{"AWSEvent":inferred}}}).to_string();
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| e.to_string())?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("INSERT OR IGNORE INTO schemas_registries(account,region,name,description,tags) VALUES (?1,?2,'discovered-schemas','Discovered event schemas','{}')",params![account,region]).map_err(|e|e.to_string())?;
    tx.execute("INSERT OR IGNORE INTO schemas_items(account,region,registry,name,description,schema_type,tags,modified) VALUES (?1,?2,'discovered-schemas',?3,'','OpenApi3','{}',?4)",params![account,region,name,now]).map_err(|e|e.to_string())?;
    let latest: Option<(i64,String)>=tx.query_row("SELECT version,content FROM schemas_versions WHERE account=?1 AND region=?2 AND registry='discovered-schemas' AND name=?3 ORDER BY version DESC LIMIT 1",params![account,region,name],|row|Ok((row.get(0)?,row.get(1)?))).optional().map_err(|e|e.to_string())?;
    if latest.as_ref().is_none_or(|(_, old)| *old != content) {
        let next = latest.map_or(1, |(version, _)| version + 1);
        tx.execute("INSERT INTO schemas_versions(account,region,registry,name,version,content,created) VALUES (?1,?2,'discovered-schemas',?3,?4,?5,?6)",params![account,region,name,next,content,now]).map_err(|e|e.to_string())?;
        tx.execute("UPDATE schemas_items SET modified=?4 WHERE account=?1 AND region=?2 AND registry='discovered-schemas' AND name=?3",params![account,region,name,now]).map_err(|e|e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_event_creates_versioned_schema_only_for_started_discoverer() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = StateDb::open(dir.path().join("state.sqlite3")).unwrap();
        crate::schemas::initialize(&state).unwrap();
        init(&state).unwrap();
        let conn = state.connection().unwrap();
        conn.execute("INSERT INTO schemas_discoverers(account,region,id,source_arn,description,cross_account,state,tags) VALUES ('111','us-east-1','d','arn:aws:events:us-east-1:111:event-bus/default','',1,'STARTED','{}')", []).unwrap();
        let first =
            json!({"source":"orders", "detail-type":"Created", "account":"111", "detail":{"id":1}});
        on_event(&state, "111", "us-east-1", "default", &first).unwrap();
        on_event(&state, "111", "us-east-1", "default", &first).unwrap();
        let changed = json!({"source":"orders", "detail-type":"Created", "account":"111", "detail":{"id":1,"name":"A"}});
        on_event(&state, "111", "us-east-1", "default", &changed).unwrap();
        let versions:i64=conn.query_row("SELECT count(*) FROM schemas_versions WHERE account='111' AND region='us-east-1' AND name='orders@Created'",[],|row|row.get(0)).unwrap();
        assert_eq!(versions, 2);
        conn.execute(
            "UPDATE schemas_discoverers SET state='STOPPED' WHERE id='d'",
            [],
        )
        .unwrap();
        on_event(
            &state,
            "111",
            "us-east-1",
            "default",
            &json!({"source":"orders", "detail-type":"Created", "detail":{"extra":true}}),
        )
        .unwrap();
        let after:i64=conn.query_row("SELECT count(*) FROM schemas_versions WHERE account='111' AND region='us-east-1' AND name='orders@Created'",[],|row|row.get(0)).unwrap();
        assert_eq!(after, 2);
    }

    #[test]
    fn discovery_infers_nested_fields_and_merges_samples() {
        let (status, response) = discover(&json!({"Type":"JSONSchemaDraft4","Events":["{\"detail\":{\"id\":1}}","{\"detail\":{\"id\":2,\"name\":\"ok\"}}"]})).unwrap();
        assert_eq!(status, StatusCode::OK);
        let schema: Value = serde_json::from_str(response["Content"].as_str().unwrap()).unwrap();
        assert_eq!(
            schema["properties"]["detail"]["properties"]["id"]["type"],
            "integer"
        );
        assert_eq!(
            schema["properties"]["detail"]["properties"]["name"]["type"],
            "string"
        );
        assert_eq!(schema["properties"]["detail"]["required"], json!(["id"]));
    }
}
