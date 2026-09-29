use std::collections::HashMap;
use std::io::{Cursor, Write};

use http::{Method, StatusCode};
use localcloud_core::handler::ServiceRequest;
use localcloud_state::StateDb;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use zip::write::SimpleFileOptions;

use super::{SchemaResult, SchemasError, SchemasService};

pub(super) fn init(state: &StateDb) -> Result<(), String> {
    state
        .connection()
        .map_err(|e| e.to_string())?
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schemas_bindings (
            account TEXT NOT NULL, region TEXT NOT NULL, registry TEXT NOT NULL,
            name TEXT NOT NULL, language TEXT NOT NULL, version INTEGER NOT NULL,
            created TEXT NOT NULL, PRIMARY KEY(account,region,registry,name,language,version)
        );",
        )
        .map_err(|e| e.to_string())
}

fn path<'a>(segments: &'a [&'a str]) -> Option<(&'a str, &'a str, &'a str, bool)> {
    match segments {
        ["v1", "registries", "name", registry, "schemas", "name", name, "language", language] => {
            Some((registry, name, language, false))
        }
        ["v1", "registries", "name", registry, "schemas", "name", name, "language", language, "source"] => {
            Some((registry, name, language, true))
        }
        _ => None,
    }
}

fn valid_language(language: &str) -> bool {
    matches!(language, "Java8" | "Python36" | "TypeScript3" | "Go1")
}

fn resolve_version(
    service: &SchemasService,
    req: &ServiceRequest,
    registry: &str,
    name: &str,
    query: &HashMap<String, String>,
) -> Result<(i64, String), SchemasError> {
    let connection = service
        .state
        .connection()
        .map_err(|e| SchemasError::Internal(e.to_string()))?;
    let requested = query
        .get("schemaVersion")
        .map(|version| {
            version.parse::<i64>().map_err(|_| {
                SchemasError::Validation("schemaVersion must be a positive integer".into())
            })
        })
        .transpose()?;
    if requested.is_some_and(|version| version < 1) {
        return Err(SchemasError::Validation(
            "schemaVersion must be a positive integer".into(),
        ));
    }
    let result = if let Some(version) = requested {
        connection.query_row("SELECT version,content FROM schemas_versions WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4 AND version=?5",params![req.account_id,req.region,registry,name,version],|row|Ok((row.get(0)?,row.get(1)?)))
    } else {
        connection.query_row("SELECT version,content FROM schemas_versions WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4 ORDER BY version DESC LIMIT 1",params![req.account_id,req.region,registry,name],|row|Ok((row.get(0)?,row.get(1)?)))
    };
    result
        .optional()
        .map_err(|e| SchemasError::Internal(e.to_string()))?
        .ok_or_else(|| SchemasError::NotFound("schema version not found".into()))
}

pub(super) fn dispatch(
    service: &SchemasService,
    req: &ServiceRequest,
    segments: &[&str],
    _body: &Value,
    query: &HashMap<String, String>,
) -> Option<SchemaResult> {
    let (registry, name, language, is_source) = path(segments)?;
    if is_source {
        return None;
    }
    if !matches!(req.method, Method::GET | Method::POST) {
        return None;
    }
    Some((|| {
        if !valid_language(language) {
            return Err(SchemasError::Validation(
                "unsupported code binding language".into(),
            ));
        }
        let (version, _) = resolve_version(service, req, registry, name, query)?;
        let connection = service
            .state
            .connection()
            .map_err(|e| SchemasError::Internal(e.to_string()))?;
        if req.method == Method::POST {
            let now = OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|e| SchemasError::Internal(e.to_string()))?;
            connection.execute("INSERT OR IGNORE INTO schemas_bindings(account,region,registry,name,language,version,created) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![req.account_id,req.region,registry,name,language,version,now]).map_err(|e|SchemasError::Internal(e.to_string()))?;
        }
        let created: Option<String>=connection.query_row("SELECT created FROM schemas_bindings WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4 AND language=?5 AND version=?6",params![req.account_id,req.region,registry,name,language,version],|row|row.get(0)).optional().map_err(|e|SchemasError::Internal(e.to_string()))?;
        let created =
            created.ok_or_else(|| SchemasError::NotFound("code binding not found".into()))?;
        Ok((
            if req.method == Method::POST {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            },
            json!({"Status":"CREATE_COMPLETE","SchemaVersion":version.to_string(),"CreationDate":created,"LastModified":created}),
        ))
    })())
}

pub(super) fn source(
    service: &SchemasService,
    req: &ServiceRequest,
    segments: &[&str],
    query: &HashMap<String, String>,
) -> Option<Result<Vec<u8>, SchemasError>> {
    let (registry, name, language, is_source) = path(segments)?;
    if !is_source || req.method != Method::GET {
        return None;
    }
    Some((|| {
        if !valid_language(language) {
            return Err(SchemasError::Validation(
                "unsupported code binding language".into(),
            ));
        }
        let (version, content) = resolve_version(service, req, registry, name, query)?;
        let connection = service
            .state
            .connection()
            .map_err(|e| SchemasError::Internal(e.to_string()))?;
        let exists: bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM schemas_bindings WHERE account=?1 AND region=?2 AND registry=?3 AND name=?4 AND language=?5 AND version=?6)",params![req.account_id,req.region,registry,name,language,version],|row|row.get(0)).map_err(|e|SchemasError::Internal(e.to_string()))?;
        if !exists {
            return Err(SchemasError::NotFound("code binding not found".into()));
        }
        make_zip(name, language, &content)
    })())
}

fn make_zip(name: &str, language: &str, content: &str) -> Result<Vec<u8>, SchemasError> {
    let document: Value = serde_json::from_str(content)
        .map_err(|e| SchemasError::Validation(format!("schema content is not JSON: {e}")))?;
    let fields = document
        .pointer("/components/schemas/AWSEvent/properties/detail/properties")
        .or_else(|| document.pointer("/components/schemas/Event/properties/detail/properties"))
        .or_else(|| document.pointer("/properties/detail/properties"))
        .or_else(|| document.pointer("/properties"))
        .and_then(Value::as_object);
    let fields = fields.cloned().unwrap_or_default();
    let stem: String = name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect();
    let stem = if stem.is_empty() {
        "Event".to_owned()
    } else {
        stem
    };
    let (file, source) = generate(language, &stem, &fields);
    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    writer
        .start_file(file, options)
        .map_err(|e| SchemasError::Internal(e.to_string()))?;
    writer
        .write_all(source.as_bytes())
        .map_err(|e| SchemasError::Internal(e.to_string()))?;
    writer
        .start_file("schema.json", options)
        .map_err(|e| SchemasError::Internal(e.to_string()))?;
    writer
        .write_all(content.as_bytes())
        .map_err(|e| SchemasError::Internal(e.to_string()))?;
    writer
        .finish()
        .map(|cursor| cursor.into_inner())
        .map_err(|e| SchemasError::Internal(e.to_string()))
}

fn generate(
    language: &str,
    stem: &str,
    fields: &serde_json::Map<String, Value>,
) -> (String, String) {
    let mut source = String::new();
    match language {
        "TypeScript3" => {
            source.push_str("export interface EventDetail {\n");
            for (key, value) in fields {
                source.push_str(&format!(
                    "  {}?: {};\n",
                    serde_json::to_string(key).unwrap(),
                    ts_type(value)
                ));
            }
            source.push_str("}\n");
            (format!("{stem}.ts"), source)
        }
        "Python36" => {
            source.push_str("from typing import Any, Dict, List\n\nclass EventDetail:\n");
            if fields.is_empty() {
                source.push_str("    pass\n");
            }
            for (key, value) in fields {
                source.push_str(&format!(
                    "    {}: {}\n",
                    safe_ident(key),
                    python_type(value)
                ));
            }
            (format!("{stem}.py"), source)
        }
        "Go1" => {
            source.push_str(
                "package event\n\nimport \"encoding/json\"\n\ntype EventDetail struct {\n",
            );
            for (key, value) in fields {
                source.push_str(&format!(
                    "    {} {} `json:\"{},omitempty\"`\n",
                    go_ident(key),
                    go_type(value),
                    key.replace(['`', '\"'], "_")
                ));
            }
            source.push_str("}\n");
            // json.RawMessage is also useful when schemas contain nested objects.
            if !source.contains("json.RawMessage") {
                source.push_str("\nvar _ json.RawMessage\n");
            }
            (format!("{stem}.go"), source)
        }
        _ => {
            source.push_str("import java.util.Map;\n\npublic class EventDetail {\n");
            for (key, value) in fields {
                source.push_str(&format!(
                    "    public {} {};\n",
                    java_type(value),
                    safe_ident(key)
                ));
            }
            source.push_str("}\n");
            if !source.contains("Map<") {
                source = source.replacen("import java.util.Map;\n\n", "", 1);
            }
            ("EventDetail.java".to_owned(), source)
        }
    }
}

fn schema_type(value: &Value) -> &str {
    value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("object")
}
fn ts_type(value: &Value) -> &str {
    match schema_type(value) {
        "string" => "string",
        "integer" | "number" => "number",
        "boolean" => "boolean",
        "array" => "unknown[]",
        _ => "Record<string, unknown>",
    }
}
fn python_type(value: &Value) -> &str {
    match schema_type(value) {
        "string" => "str",
        "integer" => "int",
        "number" => "float",
        "boolean" => "bool",
        "array" => "List[Any]",
        _ => "Dict[str, Any]",
    }
}
fn go_type(value: &Value) -> &str {
    match schema_type(value) {
        "string" => "string",
        "integer" => "int64",
        "number" => "float64",
        "boolean" => "bool",
        "array" => "[]json.RawMessage",
        _ => "json.RawMessage",
    }
}
fn java_type(value: &Value) -> &str {
    match schema_type(value) {
        "string" => "String",
        "integer" => "Long",
        "number" => "Double",
        "boolean" => "Boolean",
        "array" => "Object[]",
        _ => "Map<String, Object>",
    }
}
fn safe_ident(key: &str) -> String {
    let mut out: String = key
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty()
        || out.starts_with(|ch: char| ch.is_ascii_digit())
        || matches!(
            out.as_str(),
            "class"
                | "def"
                | "for"
                | "if"
                | "in"
                | "return"
                | "type"
                | "public"
                | "private"
                | "package"
                | "import"
        )
    {
        out.insert(0, '_');
    }
    out
}
fn go_ident(key: &str) -> String {
    let name = safe_ident(key);
    let mut chars = name.chars();
    match chars.next() {
        Some(ch) => ch.to_uppercase().chain(chars).collect(),
        None => "Field".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_is_a_downloadable_zip() {
        let archive = make_zip(
            "orders@Created",
            "TypeScript3",
            r#"{"properties":{"detail":{"properties":{"orderId":{"type":"string"}}}}}"#,
        )
        .unwrap();
        let mut zip = zip::ZipArchive::new(Cursor::new(archive)).unwrap();
        let mut source = String::new();
        std::io::Read::read_to_string(&mut zip.by_name("ordersCreated.ts").unwrap(), &mut source)
            .unwrap();
        assert!(source.contains("\"orderId\"?: string"));
    }
}
