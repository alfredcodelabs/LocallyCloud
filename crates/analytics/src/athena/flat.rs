//! Bounded Glue text-table reads through the same authorized S3 path as Iceberg.
use super::*;

pub(super) const LAZY_SERDE: &str = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe";
const CSV_SERDE: &str = "org.apache.hadoop.hive.serde2.OpenCSVSerde";

fn descriptor(table: &GlueTableOutput) -> Result<&Value, WorkerFailure> {
    table
        .storage_descriptor
        .as_ref()
        .ok_or_else(|| WorkerFailure::failed("Glue StorageDescriptor is missing", 0))
}

pub(super) fn columns(table: &GlueTableOutput) -> Result<Vec<ResultColumn>, WorkerFailure> {
    let fields = descriptor(table)?["Columns"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 1024)
        .ok_or_else(|| {
            WorkerFailure::failed("Glue table columns are missing or exceed the limit", 0)
        })?;
    let mut columns = Vec::new();
    for field in fields {
        let name = field["Name"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 255)
            .ok_or_else(|| WorkerFailure::failed("Invalid Glue column name", 0))?;
        if columns
            .iter()
            .any(|column: &ResultColumn| column.name == name)
        {
            return Err(WorkerFailure::failed("Duplicate Glue column name", 0));
        }
        let kind = match field["Type"].as_str() {
            Some("string" | "varchar" | "char") => "varchar",
            Some("int" | "integer") => "integer",
            Some("bigint") => "bigint",
            Some("boolean") => "boolean",
            _ => {
                return Err(WorkerFailure::failed(
                    "Unsupported Glue text column type",
                    0,
                ))
            }
        };
        columns.push(ResultColumn {
            name: name.into(),
            kind,
        });
    }
    Ok(columns)
}

fn scalar(
    value: Option<String>,
    kind: &str,
    scanned: u64,
) -> Result<Option<String>, WorkerFailure> {
    let Some(value) = value else {
        return Ok(None);
    };
    let result = match kind {
        "integer" => value.parse::<i32>().map(|v| v.to_string()).ok(),
        "bigint" => value.parse::<i64>().map(|v| v.to_string()).ok(),
        "boolean" if value.eq_ignore_ascii_case("true") => Some("true".into()),
        "boolean" if value.eq_ignore_ascii_case("false") => Some("false".into()),
        "varchar" => Some(value),
        _ => None,
    };
    result.map(Some).ok_or_else(|| {
        WorkerFailure::failed(
            "HIVE_BAD_DATA: value does not match the Glue column type",
            scanned,
        )
    })
}

pub(super) async fn query(
    registry: &Weak<ServiceRegistry>,
    scope: &Scope,
    caller: Option<&AthenaCaller>,
    record: &Arc<Mutex<QueryRecord>>,
    table: &GlueTableOutput,
    parsed: &sql::ParsedQuery,
) -> Result<(QueryResult, u64), WorkerFailure> {
    let columns = columns(table)?;
    let location = table_location(table)?;
    let descriptor = descriptor(table)?;
    let serde = descriptor["SerdeInfo"]["SerializationLibrary"]
        .as_str()
        .unwrap_or("");
    let parameters = &descriptor["SerdeInfo"]["Parameters"];
    if serde == CSV_SERDE
        && ["separatorChar", "quoteChar", "escapeChar"]
            .iter()
            .any(|key| parameters.get(*key).is_some())
    {
        return Err(WorkerFailure::failed(
            "Custom OpenCSVSerde separators and escaping are unsupported",
            0,
        ));
    }
    let delimiter = parameters["field.delim"].as_str().unwrap_or("\u{1}");
    if serde == LAZY_SERDE
        && (delimiter.len() != 1 || matches!(delimiter.as_bytes().first(), Some(b'\n' | b'\r' | 0)))
    {
        return Err(WorkerFailure::failed("Invalid text field delimiter", 0));
    }
    let skip = table
        .parameters
        .get("skip.header.line.count")
        .and_then(Value::as_str)
        .unwrap_or("0")
        .parse::<usize>()
        .ok()
        .filter(|v| *v <= 1000)
        .ok_or_else(|| WorkerFailure::failed("Invalid skip.header.line.count", 0))?;
    let mut result = QueryResult {
        rows: vec![columns.iter().map(|c| Some(c.name.clone())).collect()],
        columns,
    };
    let mut scanned = 0;
    for key in list_objects(registry, scope, caller, &location).await? {
        ensure_running(record)?;
        if !key.starts_with(&location.key) {
            continue;
        }
        let body = get_object(registry, scope, caller, &location.bucket, &key, scanned).await?;
        scanned = add_scan(record, scanned, body.len())?;
        let rows = if serde == CSV_SERDE {
            sql::result_csv_rows(&body, result.columns.len())
                .map_err(|reason| WorkerFailure::failed(reason, scanned))?
        } else {
            let text = std::str::from_utf8(&body)
                .map_err(|_| WorkerFailure::failed("Invalid UTF-8 text object", scanned))?;
            let mut rows = Vec::new();
            for line in text
                .lines()
                .filter(|line| serde != JSON_SERDE || !line.trim().is_empty())
            {
                if (rows.len() + 1).saturating_mul(result.columns.len()) > 4_000_000
                    || rows.len() >= MAX_RESULT_ROWS
                {
                    return Err(WorkerFailure::failed(
                        "Text object exceeds the result cell limit",
                        scanned,
                    ));
                }
                let row = if serde == JSON_SERDE {
                    let value: Value = serde_json::from_str(line)
                        .map_err(|_| WorkerFailure::failed("Invalid JSON line", scanned))?;
                    let value = value.as_object().ok_or_else(|| {
                        WorkerFailure::failed("JSON table rows must be objects", scanned)
                    })?;
                    result
                        .columns
                        .iter()
                        .map(|column| match value.get(&column.name) {
                            None | Some(Value::Null) => Ok(None),
                            Some(Value::String(v)) => Ok(Some(v.clone())),
                            Some(v) if v.is_number() || v.is_boolean() => Ok(Some(v.to_string())),
                            _ => Err(WorkerFailure::failed(
                                "Nested JSON columns are unsupported",
                                scanned,
                            )),
                        })
                        .collect::<Result<Vec<_>, _>>()?
                } else {
                    line.split(delimiter)
                        .map(|v| if v == "\\N" { None } else { Some(v.to_owned()) })
                        .collect()
                };
                if row.len() != result.columns.len() {
                    return Err(WorkerFailure::failed(
                        "Text row column count differs from Glue metadata",
                        scanned,
                    ));
                }
                rows.push(row);
            }
            rows
        };
        for row in rows.into_iter().skip(skip) {
            if result.rows.len() > MAX_RESULT_ROWS
                || (result.rows.len() + 1).saturating_mul(result.columns.len()) > 4_000_000
            {
                return Err(WorkerFailure::failed(
                    "Query exceeded the result cell limit",
                    scanned,
                ));
            }
            result.rows.push(
                row.into_iter()
                    .zip(&result.columns)
                    .map(|(v, c)| scalar(v, c.kind, scanned))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
    }
    apply_predicates(&mut result, &parsed.predicates)
        .map_err(|reason| WorkerFailure::failed(reason, scanned))?;
    match &parsed.projection {
        Projection::Count(alias) => Ok((
            QueryResult::count(alias.clone(), result.rows.len().saturating_sub(1) as u64),
            scanned,
        )),
        Projection::Sum { column, alias } => {
            let index = result
                .columns
                .iter()
                .position(|c| c.name == *column)
                .ok_or_else(|| WorkerFailure::failed("SUM column not found", scanned))?;
            let selected = QueryResult {
                columns: vec![result.columns.remove(index)],
                rows: result
                    .rows
                    .into_iter()
                    .map(|row| vec![row[index].clone()])
                    .collect(),
            };
            Ok((
                sum_result(&selected, alias)
                    .map_err(|reason| WorkerFailure::failed(reason, scanned))?,
                scanned,
            ))
        }
        Projection::All => Ok((result, scanned)),
        Projection::Columns(names) => {
            let indices = names
                .iter()
                .map(|name| {
                    result
                        .columns
                        .iter()
                        .position(|c| c.name == *name)
                        .ok_or_else(|| WorkerFailure::failed("Projected column not found", scanned))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let columns = indices
                .iter()
                .map(|i| ResultColumn {
                    name: result.columns[*i].name.clone(),
                    kind: result.columns[*i].kind,
                })
                .collect();
            // Repeated projections can amplify a single large source column.
            let mut bytes = 0usize;
            let mut rows = Vec::with_capacity(result.rows.len());
            for row in result.rows {
                let mut projected = Vec::with_capacity(indices.len());
                for index in &indices {
                    bytes = bytes
                        .checked_add(row[*index].as_ref().map_or(0, String::len))
                        .filter(|total| *total <= MAX_RESULT_BYTES)
                        .ok_or_else(|| {
                            WorkerFailure::failed("Query exceeded the result byte limit", scanned)
                        })?;
                    projected.push(row[*index].clone());
                }
                rows.push(projected);
            }
            Ok((QueryResult { columns, rows }, scanned))
        }
    }
}
