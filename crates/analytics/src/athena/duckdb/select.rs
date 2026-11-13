//! Broader SELECT execution using DuckDB's parser, over authorized Glue snapshots only.
use super::*;
use std::collections::BTreeMap;

impl DuckDbEngine {
    pub(super) async fn select_in(
        &self,
        work: &Path,
        access: QueryAccess<'_>,
        sql: &str,
        database: Option<&str>,
    ) -> Result<(QueryResult, u64), WorkerFailure> {
        // Parse a quoted string, never execute client SQL to discover its dependencies.
        let discovery = format!(
            "SET threads=2; SET memory_limit='128MiB'; SET autoinstall_known_extensions=false; SET autoload_known_extensions=false; SET enable_external_access=false; SET lock_configuration=true; SELECT json_serialize_sql({sql}) AS ast, json_deserialize_sql(json_serialize_sql({sql})) AS statement;",
            sql = sql_literal(sql)
        );
        let discovery = self.execute(work, &discovery, access.record, 0).await?;
        let ast = &discovery[0]["ast"];
        let tables = dependencies(ast, database)?;
        let statement = discovery[0]["statement"]
            .as_str()
            .ok_or_else(|| failure("DuckDB did not return a SELECT statement", 0))?;
        let mut setup = String::new();
        let mut allowed = Vec::new();
        let mut scanned = 0;
        let mut manifests = 0;
        for (index, ((database, name), unqualified)) in tables.iter().enumerate() {
            let table =
                glue_table_snapshot(access.registry, access.scope, access.caller, database, name)
                    .await?;
            if !is_iceberg_table(&table) {
                return Err(failure("DuckDB SELECT requires Iceberg tables", scanned));
            }
            let (metadata, body, list, bytes) = iceberg_snapshot_objects(
                access.registry,
                access.scope,
                access.caller,
                access.record,
                &table,
                scanned,
            )
            .await?;
            let directory = work.join(format!("snapshot-{index}"));
            let mut mirror = SnapshotMirror::new(&directory, &metadata, bytes)?;
            mirror.object_limit = MAX_MIRROR_OBJECTS.saturating_sub(allowed.len());
            mirror.manifest_limit = MAX_MIRROR_MANIFESTS.saturating_sub(manifests);
            let uri = table
                .parameters
                .get("metadata_location")
                .and_then(Value::as_str)
                .ok_or_else(|| failure("Iceberg metadata_location is missing", bytes))?;
            let path = mirror.save(uri, body).await?;
            mirror.prepare(access, &metadata, list, &[]).await?;
            scanned = mirror.scanned;
            manifests += mirror.manifests;
            allowed.extend(mirror.allowed_paths);
            let qualified = format!("{}.{}", identifier(database), identifier(name));
            setup.push_str(&format!(
                "CREATE SCHEMA IF NOT EXISTS {}; CREATE VIEW {qualified} AS SELECT * FROM {};\n",
                identifier(database),
                snapshot_scan(&path)?
            ));
            if *unqualified {
                // The query context resolves unqualified names; do not use DuckDB's search path.
                if database != "main" {
                    setup.push_str(&format!(
                        "CREATE TEMP VIEW {} AS SELECT * FROM {qualified};\n",
                        identifier(name)
                    ));
                }
            }
        }
        let query = format!("SELECT * FROM ({statement}) AS lc_result");
        let describe = self
            .execute(
                work,
                &self.script(work, &allowed, &format!("{setup} DESCRIBE {query}"))?,
                access.record,
                scanned,
            )
            .await?;
        let fields = describe
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= 1024)
            .ok_or_else(|| failure("DuckDB returned invalid result columns", scanned))?;
        let columns = fields
            .iter()
            .map(|field| {
                let name = field["column_name"]
                    .as_str()
                    .ok_or_else(|| failure("DuckDB column name is missing", scanned))?;
                let kind =
                    result_kind(field["column_type"].as_str().unwrap_or("")).ok_or_else(|| {
                        failure(
                            "DuckDB SELECT returned an unsupported Athena result type",
                            scanned,
                        )
                    })?;
                Ok(ResultColumn {
                    name: name.to_owned(),
                    kind,
                })
            })
            .collect::<Result<Vec<_>, WorkerFailure>>()?;
        let select = columns
            .iter()
            .enumerate()
            .map(|(i, column)| {
                let value = identifier(&column.name);
                let value = match column.kind {
                    "timestamp" | "timestamptz" => format!("epoch_us({value})"),
                    // Athena SUM(bigint) is bigint: reject overflow instead of advertising a wider result.
                    "bigint" => format!("CAST({value} AS BIGINT)"),
                    _ => value,
                };
                format!("CAST({value} AS VARCHAR) AS c{i}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let result = self
            .execute(
                work,
                &self.script(
                    work,
                    &allowed,
                    &format!("{setup} SELECT {select} FROM ({statement}) AS lc_result"),
                )?,
                access.record,
                scanned,
            )
            .await?;
        let values = result
            .as_array()
            .filter(|rows| rows.len() <= MAX_RESULT_ROWS)
            .ok_or_else(|| failure("DuckDB SELECT exceeded the result row limit", scanned))?;
        let mut rows = vec![columns.iter().map(|c| Some(c.name.clone())).collect()];
        for row in values {
            rows.push(
                columns
                    .iter()
                    .enumerate()
                    .map(|(i, column)| {
                        let value = row
                            .get(format!("c{i}"))
                            .ok_or_else(|| failure("DuckDB result column is missing", scanned))?;
                        decode_value(column.kind, value).map_err(|reason| failure(reason, scanned))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        Ok((QueryResult { columns, rows }, scanned))
    }
}

fn result_kind(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "BIGINT" | "HUGEINT" => "bigint",
        "INTEGER" => "integer",
        "SMALLINT" => "smallint",
        "TINYINT" => "tinyint",
        "VARCHAR" => "varchar",
        "BOOLEAN" => "boolean",
        "DATE" => "date",
        "TIMESTAMP" | "TIMESTAMP_NS" | "TIMESTAMP_MS" | "TIMESTAMP_S" => "timestamp",
        "TIMESTAMP WITH TIME ZONE" => "timestamptz",
        "DECIMAL(18,2)" => "decimal(18,2)",
        "DECIMAL(38,2)" => "decimal(38,2)",
        "DOUBLE" => "double",
        "FLOAT" => "float",
        _ => return None,
    })
}

fn dependencies(
    ast: &Value,
    database: Option<&str>,
) -> Result<BTreeMap<(String, String), bool>, WorkerFailure> {
    if ast["statements"][0]["node"]["type"] != "SELECT_NODE"
        || ast["error"] != false
        || ast["statements"].as_array().is_none_or(|v| v.len() != 1)
    {
        return Err(failure("DuckDB requires exactly one SELECT statement", 0));
    }
    let mut tables = BTreeMap::new();
    visit(ast, database, &mut tables, 0)?;
    if tables.is_empty() {
        return Err(failure("SELECT must reference a Glue Iceberg table", 0));
    }
    Ok(tables)
}

fn visit(
    value: &Value,
    database: Option<&str>,
    tables: &mut BTreeMap<(String, String), bool>,
    depth: usize,
) -> Result<(), WorkerFailure> {
    if depth > 48 {
        return Err(failure("DuckDB SELECT exceeds the AST depth limit", 0));
    }
    match value {
        Value::Object(object) => {
            if object
                .get("cte_map")
                .and_then(|v| v["map"].as_array())
                .is_some_and(|v| !v.is_empty())
            {
                return Err(failure("DuckDB CTEs are not supported", 0));
            }
            if object.contains_key("sample")
                && object.contains_key("query_location")
                && !matches!(
                    object.get("type").and_then(Value::as_str),
                    Some("BASE_TABLE" | "JOIN" | "SUBQUERY" | "EMPTY")
                )
            {
                return Err(failure("Unsupported table reference in DuckDB SELECT", 0));
            }
            match object.get("type").and_then(Value::as_str) {
                Some(
                    "TABLE_FUNCTION" | "PIVOT" | "EXPRESSION_LIST" | "SHOW_REF" | "COLUMN_DATA"
                    | "DELIM_GET",
                ) => {
                    return Err(failure(
                        "Only Glue table references, joins and SELECT subqueries are supported",
                        0,
                    ))
                }
                Some("BASE_TABLE") => {
                    let name = object
                        .get("table_name")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let schema = object
                        .get("schema_name")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let db = if schema.is_empty() {
                        database.unwrap_or("")
                    } else {
                        schema
                    };
                    if !valid_name(name)
                        || !valid_name(db)
                        || object
                            .get("catalog_name")
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.is_empty())
                        || object.get("at_clause").is_some_and(|v| !v.is_null())
                    {
                        return Err(failure("Invalid Glue table reference in SELECT", 0));
                    }
                    tables
                        .entry((db.to_owned(), name.to_owned()))
                        .and_modify(|unqualified| *unqualified |= schema.is_empty())
                        .or_insert(schema.is_empty());
                    if tables.len() > 16 {
                        return Err(failure("SELECT exceeds the 16 table reference limit", 0));
                    }
                }
                Some("FUNCTION")
                    if object.get("class").and_then(Value::as_str) == Some("FUNCTION") =>
                {
                    let name = object
                        .get("function_name")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if !matches!(
                        name,
                        "count"
                            | "count_star"
                            | "sum"
                            | "avg"
                            | "min"
                            | "max"
                            | "concat"
                            | "concat_ws"
                            | "coalesce"
                            | "nullif"
                            | "if"
                            | "lower"
                            | "upper"
                            | "length"
                            | "substring"
                            | "substr"
                            | "trim"
                            | "ltrim"
                            | "rtrim"
                            | "replace"
                            | "abs"
                            | "round"
                            | "floor"
                            | "ceil"
                            | "date_trunc"
                            | "date_part"
                            | "year"
                            | "month"
                            | "day"
                            | "+"
                            | "-"
                            | "*"
                            | "/"
                            | "%"
                            | "~~"
                            | "!~~"
                    ) || ["schema", "catalog"].iter().any(|key| {
                        object
                            .get(*key)
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.is_empty())
                    }) {
                        return Err(failure("Unsupported function in DuckDB SELECT", 0));
                    }
                }
                _ => {}
            }
            for value in object.values() {
                visit(value, database, tables, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                visit(value, database, tables, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_discovery_rejects_external_access_and_binds_nested_tables() {
        let base = |schema: &str, name: &str| json!({"type":"BASE_TABLE","schema_name":schema,"table_name":name,"catalog_name":""});
        let wrap = |node: Value| json!({"error":false,"statements":[{"node":{"type":"SELECT_NODE","from_table":node}}]});
        let ast = wrap(
            json!({"type":"JOIN", "left":base("lake","ledger"),"right":{"type":"SUBQUERY","subquery":{"node":{"type":"SELECT_NODE","from_table":base("","ledger")}}}}),
        );
        let dependencies = dependencies(&ast, Some("lake")).unwrap();
        assert_eq!(dependencies.len(), 1);
        assert_eq!(
            dependencies.get(&("lake".into(), "ledger".into())),
            Some(&true)
        );
        for reference in [
            base("", "/etc/passwd"),
            base("lake", "../secret"),
            json!({"type":"TABLE_FUNCTION","function":{"function_name":"read_csv"}}),
            json!({"type":"FUTURE_REF","sample":null,"query_location":1}),
        ] {
            assert!(super::dependencies(&wrap(reference), Some("lake")).is_err());
        }
        let mut ast = ast;
        ast["statements"][0]["node"]["select_list"] =
            json!([{"class":"FUNCTION","type":"FUNCTION","function_name":"count_star"}]);
        assert!(super::dependencies(&ast, Some("lake")).is_ok());
        ast["statements"][0]["node"]["cte_map"] = json!({"map":[{"key":"hidden"}]});
        assert!(super::dependencies(&ast, Some("lake")).is_err());
        ast["statements"].as_array_mut().unwrap().push(json!({}));
        assert!(super::dependencies(&ast, Some("lake")).is_err());
        for name in [
            "read_text",
            "getenv",
            "json_execute_serialized_sql",
            "query",
        ] {
            let ast = wrap(json!({"class":"FUNCTION","type":"FUNCTION","function_name":name}));
            assert!(super::dependencies(&ast, Some("lake")).is_err());
        }
    }
}
