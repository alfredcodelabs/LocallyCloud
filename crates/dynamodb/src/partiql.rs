//! PartiQL for DynamoDB (`ExecuteStatement`/`ExecuteTransaction`/`BatchExecuteStatement`).
//!
//! Statements are parsed and lowered onto the classic item/scan/transaction engines so all
//! validation, conditions, streams, indexes, and TTL behave identically. Positional `?`
//! parameters are filled from the `Parameters` list (AttributeValues).
//!
//! Supported grammar:
//!
//! - `INSERT INTO <table> VALUE {'k': <v>, ...}`
//! - `SELECT * FROM <table> [WHERE <attr> <op> <v> [AND ...]]`
//! - `UPDATE <table> SET <attr> = <v> [, ...] [REMOVE <attr> [, ...]] WHERE <key> = <v> [AND ...]`
//! - `DELETE FROM <table> WHERE <key> = <v> [AND ...]`
//!
//! Values are `?`, single-quoted strings, integer/decimal numbers, `true`/`false`, or `null`.
//! Complex (M/L) values are supplied via `?` parameters.

use base64::Engine;
use serde_json::{json, Map, Value};

use crate::error::DdbError;
use crate::ops::{self, Ctx};

// ============================ public entry points ==============================

pub async fn execute_statement(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let statement = req
        .get("Statement")
        .and_then(Value::as_str)
        .ok_or_else(|| DdbError::Validation("Statement is required".into()))?;
    let params = parse_parameters(req)?;
    let stmt = parse(statement, &params)?;
    run(ctx, stmt, req).await
}

pub async fn execute_transaction(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let statements = req
        .get("TransactStatements")
        .and_then(Value::as_array)
        .ok_or_else(|| DdbError::Validation("TransactStatements is required".into()))?;
    let mut actions = Vec::new();
    for entry in statements {
        let statement = entry
            .get("Statement")
            .and_then(Value::as_str)
            .ok_or_else(|| DdbError::Validation("Statement is required".into()))?;
        let params = parse_parameters(entry)?;
        actions.push(parse(statement, &params)?.into_transact_action()?);
    }
    let mut transaction = json!({ "TransactItems": actions });
    if let Some(token) = req.get("ClientRequestToken") {
        transaction["ClientRequestToken"] = token.clone();
    }
    ops::transact_write_items(ctx, &transaction).await?;
    Ok(json!({}))
}

pub async fn batch_execute_statement(ctx: &Ctx<'_>, req: &Value) -> Result<Value, DdbError> {
    let statements = batch_entries(req)?;
    // Reject invalid request structure or a mixed batch before any statement mutates state.
    let mut parsed = Vec::with_capacity(statements.len());
    for entry in statements {
        let statement = batch_statement(entry)?;
        let params = parse_parameters(entry)?;
        parsed.push(parse(statement, &params));
    }
    let reads = parsed
        .iter()
        .any(|statement| matches!(statement, Ok(Stmt::Select { .. })));
    let writes = parsed.iter().any(|statement| {
        matches!(
            statement,
            Ok(Stmt::Insert { .. } | Stmt::Delete { .. } | Stmt::Update { .. })
        )
    });
    if reads && writes {
        return Err(DdbError::Validation(
            "Read and write statements cannot be mixed in one batch".into(),
        ));
    }
    let mut responses = Vec::with_capacity(statements.len());
    for (entry, statement) in statements.iter().zip(parsed) {
        let result = match statement {
            Ok(Stmt::Select { table, wheres }) => batch_select(ctx, &table, &wheres, entry).await,
            Ok(statement) => run(ctx, statement, entry).await,
            Err(error) => Err(error),
        };
        match result {
            Ok(response) => responses.push(response),
            Err(error) => responses
                .push(json!({"Error":{"Code":error.batch_code(),"Message":error.to_string()}})),
        }
    }
    Ok(json!({ "Responses": responses }))
}

fn batch_entries(request: &Value) -> Result<&[Value], DdbError> {
    let entries = request
        .get("Statements")
        .and_then(Value::as_array)
        .ok_or_else(|| DdbError::Validation("Statements is required".into()))?;
    if !(1..=25).contains(&entries.len()) {
        return Err(DdbError::Validation(
            "Statements must contain between 1 and 25 entries".into(),
        ));
    }
    Ok(entries)
}

fn batch_statement(entry: &Value) -> Result<&str, DdbError> {
    let fields = entry
        .as_object()
        .ok_or_else(|| DdbError::Validation("Each Statements entry must be an object".into()))?;
    let statement = fields
        .get("Statement")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            DdbError::Validation("Each Statements entry requires a string Statement".into())
        })?;
    if !(1..=8192).contains(&statement.chars().take(8193).count()) {
        return Err(DdbError::Validation(
            "Statement must contain between 1 and 8192 characters".into(),
        ));
    }
    if fields
        .get("ConsistentRead")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(DdbError::Validation(
            "ConsistentRead must be a boolean".into(),
        ));
    }
    if let Some(values) = fields.get("Parameters") {
        if values.as_array().is_none_or(|values| values.is_empty()) {
            return Err(DdbError::Validation(
                "Parameters must be a non-empty array".into(),
            ));
        }
    }
    if let Some(mode) = fields.get("ReturnValuesOnConditionCheckFailure") {
        if !matches!(mode.as_str(), Some("ALL_OLD" | "NONE")) {
            return Err(DdbError::Validation(
                "ReturnValuesOnConditionCheckFailure must be ALL_OLD or NONE".into(),
            ));
        }
    }
    Ok(statement)
}

/// Batch SELECT is a point read: every primary-key attribute must have an equality term.
async fn batch_select(
    ctx: &Ctx<'_>,
    table_name: &str,
    wheres: &[(String, String, Value)],
    req: &Value,
) -> Result<Value, DdbError> {
    let key_names = {
        let table = ctx
            .store
            .get(ctx.account, ctx.region, table_name)
            .ok_or_else(|| {
                DdbError::ResourceNotFound(format!(
                    "Requested resource not found: Table: {table_name} not found"
                ))
            })?;
        let guard = table.read().await;
        guard
            .def
            .key_schema
            .iter()
            .map(|key| key.name.clone())
            .collect::<Vec<_>>()
    };
    let mut key = Map::new();
    for name in key_names {
        let value = wheres
            .iter()
            .find(|(attribute, operator, _)| attribute == &name && operator == "=")
            .map(|(_, _, value)| value)
            .ok_or_else(|| {
                DdbError::Validation(
                    "Batch SELECT requires equality on every primary-key attribute".into(),
                )
            })?;
        key.insert(name, value.clone());
    }
    let (filter, names, values) = build_filter(wheres);
    let names = serde_json::from_value(names)
        .map_err(|_| DdbError::Internal("Could not prepare batch predicate".into()))?;
    let values = values
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, value)| {
            Ok((
                name.clone(),
                crate::value::AttributeValue::from_json(value)?,
            ))
        })
        .collect::<Result<std::collections::HashMap<_, _>, DdbError>>()?;
    let predicate = crate::expression::ConditionExpression::parse(&filter, &names, &values)?;
    let mut get = json!({"TableName":table_name,"Key":key});
    if let Some(consistent) = req.get("ConsistentRead") {
        get["ConsistentRead"] = consistent.clone();
    }
    let response = ops::get_item(ctx, &get).await?;
    let Some(item) = response.get("Item") else {
        return Ok(json!({}));
    };
    let decoded = crate::value::item_from_json(item)?;
    if predicate.matches(&decoded) {
        Ok(json!({"Item":item}))
    } else {
        Ok(json!({}))
    }
}

fn parse_parameters(req: &Value) -> Result<Vec<Value>, DdbError> {
    match req.get("Parameters") {
        Some(Value::Array(arr)) => {
            for p in arr {
                if !p.is_object() {
                    return Err(DdbError::Validation(
                        "each Parameter must be an AttributeValue".into(),
                    ));
                }
            }
            Ok(arr.clone())
        }
        Some(_) => Err(DdbError::Validation("Parameters must be an array".into())),
        None => Ok(Vec::new()),
    }
}

// ============================ parsed statement =================================

enum Stmt {
    Insert {
        table: String,
        item: Value,
    },
    Delete {
        table: String,
        key: Value,
    },
    Update {
        table: String,
        key: Value,
        set: Vec<(String, Value)>,
        remove: Vec<String>,
    },
    Select {
        table: String,
        wheres: Vec<(String, String, Value)>,
    },
}

/// Parse once for IAM before any statement in a batch can mutate data.
pub(crate) fn authorization_targets(
    op: &str,
    request: &Value,
) -> Result<Vec<(String, String)>, DdbError> {
    let entries: Vec<&Value> = match op {
        "ExecuteStatement" => vec![request],
        "ExecuteTransaction" => request
            .get("TransactStatements")
            .and_then(Value::as_array)
            .ok_or_else(|| DdbError::Validation("TransactStatements is required".into()))?
            .iter()
            .collect(),
        "BatchExecuteStatement" => batch_entries(request)?.iter().collect(),
        _ => return Ok(Vec::new()),
    };
    let mut targets = Vec::new();
    for entry in entries {
        let statement = if op == "BatchExecuteStatement" {
            batch_statement(entry)?
        } else {
            entry
                .get("Statement")
                .and_then(Value::as_str)
                .ok_or_else(|| DdbError::Validation("Statement is required".into()))?
        };
        let params = parse_parameters(entry)?;
        let parsed = match parse(statement, &params) {
            Ok(parsed) => parsed,
            Err(_) if op == "BatchExecuteStatement" => continue,
            Err(error) => return Err(error),
        };
        let target = match parsed {
            Stmt::Insert { table, .. } => ("PartiQLInsert", table),
            Stmt::Delete { table, .. } => ("PartiQLDelete", table),
            Stmt::Update { table, .. } => ("PartiQLUpdate", table),
            Stmt::Select { table, .. } => ("PartiQLSelect", table),
        };
        targets.push((target.0.to_string(), target.1));
    }
    Ok(targets)
}

impl Stmt {
    fn into_transact_action(self) -> Result<Value, DdbError> {
        match self {
            Stmt::Insert { table, item } => {
                Ok(json!({ "Put": { "TableName": table, "Item": item } }))
            }
            Stmt::Delete { table, key } => {
                Ok(json!({ "Delete": { "TableName": table, "Key": key } }))
            }
            Stmt::Update {
                table,
                key,
                set,
                remove,
            } => {
                let (expr, names, values) = build_update(&set, &remove);
                let mut inner = json!({ "TableName": table, "Key": key, "UpdateExpression": expr });
                inner["ExpressionAttributeNames"] = names;
                inner["ExpressionAttributeValues"] = values;
                Ok(json!({ "Update": inner }))
            }
            Stmt::Select { .. } => Err(DdbError::Validation(
                "SELECT is not allowed inside a transaction".into(),
            )),
        }
    }
}

async fn run(ctx: &Ctx<'_>, stmt: Stmt, req: &Value) -> Result<Value, DdbError> {
    match stmt {
        Stmt::Insert { table, item } => {
            ops::put_item(ctx, &json!({ "TableName": table, "Item": item })).await?;
            Ok(json!({}))
        }
        Stmt::Delete { table, key } => {
            ops::delete_item(ctx, &json!({ "TableName": table, "Key": key })).await?;
            Ok(json!({}))
        }
        Stmt::Update {
            table,
            key,
            set,
            remove,
        } => {
            let (expr, names, values) = build_update(&set, &remove);
            let mut ureq = json!({ "TableName": table, "Key": key, "UpdateExpression": expr });
            ureq["ExpressionAttributeNames"] = names;
            ureq["ExpressionAttributeValues"] = values;
            ops::update_item(ctx, &ureq).await?;
            Ok(json!({}))
        }
        Stmt::Select { table, wheres } => {
            let mut sreq = json!({ "TableName": table });
            let hash_key = {
                let state = ctx
                    .store
                    .get(ctx.account, ctx.region, &table)
                    .ok_or_else(|| {
                        DdbError::ResourceNotFound(format!(
                            "Requested resource not found: Table: {table} not found"
                        ))
                    })?;
                let hash_key = state.read().await.def.hash_key().to_string();
                hash_key
            };
            let use_query = wheres
                .iter()
                .any(|(attribute, operator, _)| attribute == &hash_key && operator == "=");
            if !wheres.is_empty() {
                let (expr, names, values) = build_filter(&wheres);
                let expression_field = if use_query {
                    "KeyConditionExpression"
                } else {
                    "FilterExpression"
                };
                sreq[expression_field] = json!(expr);
                sreq["ExpressionAttributeNames"] = names;
                sreq["ExpressionAttributeValues"] = values;
            }
            if let Some(limit) = req.get("Limit").and_then(Value::as_u64) {
                sreq["Limit"] = json!(limit);
            }
            if let Some(token) = req.get("NextToken").and_then(Value::as_str) {
                sreq["ExclusiveStartKey"] = decode_token(token)?;
            }
            let resp = if use_query {
                ops::query(ctx, &sreq).await?
            } else {
                ops::scan(ctx, &sreq).await?
            };
            let mut out = Map::new();
            out.insert(
                "Items".into(),
                resp.get("Items").cloned().unwrap_or_else(|| json!([])),
            );
            if let Some(lek) = resp.get("LastEvaluatedKey") {
                out.insert("NextToken".into(), json!(encode_token(lek)));
            }
            Ok(Value::Object(out))
        }
    }
}

/// Build `SET`/`REMOVE` update expression with `#k`/`:v` aliases.
fn build_update(set: &[(String, Value)], remove: &[String]) -> (String, Value, Value) {
    let mut names = Map::new();
    let mut values = Map::new();
    let mut clauses = Vec::new();
    if !set.is_empty() {
        let parts: Vec<String> = set
            .iter()
            .enumerate()
            .map(|(i, (attr, val))| {
                names.insert(format!("#s{i}"), json!(attr));
                values.insert(format!(":s{i}"), val.clone());
                format!("#s{i} = :s{i}")
            })
            .collect();
        clauses.push(format!("SET {}", parts.join(", ")));
    }
    if !remove.is_empty() {
        let parts: Vec<String> = remove
            .iter()
            .enumerate()
            .map(|(i, attr)| {
                names.insert(format!("#r{i}"), json!(attr));
                format!("#r{i}")
            })
            .collect();
        clauses.push(format!("REMOVE {}", parts.join(", ")));
    }
    (
        clauses.join(" "),
        Value::Object(names),
        Value::Object(values),
    )
}

/// Build a `FilterExpression` with `#k`/`:v` aliases from WHERE terms.
fn build_filter(wheres: &[(String, String, Value)]) -> (String, Value, Value) {
    let mut names = Map::new();
    let mut values = Map::new();
    let parts: Vec<String> = wheres
        .iter()
        .enumerate()
        .map(|(i, (attr, op, val))| {
            names.insert(format!("#k{i}"), json!(attr));
            values.insert(format!(":v{i}"), val.clone());
            format!("#k{i} {op} :v{i}")
        })
        .collect();
    (
        parts.join(" AND "),
        Value::Object(names),
        Value::Object(values),
    )
}

// ============================ parser ===========================================

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Str(String),
    Sym(char),
    Param,
}

fn lex(s: &str) -> Result<Vec<Tok>, DdbError> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '\'' {
            // Single-quoted string; '' is an escaped quote.
            let mut buf = String::new();
            i += 1;
            while i < chars.len() {
                if chars[i] == '\'' {
                    if i + 1 < chars.len() && chars[i + 1] == '\'' {
                        buf.push('\'');
                        i += 2;
                    } else {
                        i += 1;
                        break;
                    }
                } else {
                    buf.push(chars[i]);
                    i += 1;
                }
            }
            out.push(Tok::Str(buf));
        } else if c == '"' {
            // Double-quoted identifier.
            let mut buf = String::new();
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                buf.push(chars[i]);
                i += 1;
            }
            i += 1;
            out.push(Tok::Word(buf));
        } else if c == '?' {
            out.push(Tok::Param);
            i += 1;
        } else if matches!(c, '{' | '}' | '(' | ')' | ',' | ':' | '*') {
            out.push(Tok::Sym(c));
            i += 1;
        } else if c == '=' {
            out.push(Tok::Word("=".into()));
            i += 1;
        } else if c == '<' {
            if i + 1 < chars.len() && chars[i + 1] == '=' {
                out.push(Tok::Word("<=".into()));
                i += 2;
            } else if i + 1 < chars.len() && chars[i + 1] == '>' {
                out.push(Tok::Word("<>".into()));
                i += 2;
            } else {
                out.push(Tok::Word("<".into()));
                i += 1;
            }
        } else if c == '>' {
            if i + 1 < chars.len() && chars[i + 1] == '=' {
                out.push(Tok::Word(">=".into()));
                i += 2;
            } else {
                out.push(Tok::Word(">".into()));
                i += 1;
            }
        } else if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
            let mut buf = String::new();
            while i < chars.len()
                && (chars[i].is_alphanumeric() || matches!(chars[i], '_' | '-' | '.'))
            {
                buf.push(chars[i]);
                i += 1;
            }
            out.push(Tok::Word(buf));
        } else {
            return Err(DdbError::Validation(format!(
                "unexpected character in statement: {c}"
            )));
        }
    }
    Ok(out)
}

struct Parser<'a> {
    toks: Vec<Tok>,
    pos: usize,
    params: &'a [Value],
    pidx: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn expect_word(&mut self, kw: &str) -> Result<(), DdbError> {
        match self.next() {
            Some(Tok::Word(w)) if w.eq_ignore_ascii_case(kw) => Ok(()),
            other => Err(DdbError::Validation(format!(
                "expected `{kw}`, found {other:?}"
            ))),
        }
    }
    fn ident(&mut self) -> Result<String, DdbError> {
        match self.next() {
            Some(Tok::Word(w)) => Ok(w),
            Some(Tok::Str(s)) => Ok(s),
            other => Err(DdbError::Validation(format!(
                "expected identifier, found {other:?}"
            ))),
        }
    }
    fn expect_sym(&mut self, c: char) -> Result<(), DdbError> {
        match self.next() {
            Some(Tok::Sym(s)) if s == c => Ok(()),
            other => Err(DdbError::Validation(format!(
                "expected `{c}`, found {other:?}"
            ))),
        }
    }
    /// Parse a value token into an AttributeValue JSON.
    fn value(&mut self) -> Result<Value, DdbError> {
        match self.next() {
            Some(Tok::Param) => {
                let v = self.params.get(self.pidx).cloned().ok_or_else(|| {
                    DdbError::Validation("not enough parameters for placeholders".into())
                })?;
                self.pidx += 1;
                Ok(v)
            }
            Some(Tok::Str(s)) => Ok(json!({ "S": s })),
            Some(Tok::Word(w)) => {
                let lower = w.to_ascii_lowercase();
                if lower == "true" || lower == "false" {
                    Ok(json!({ "BOOL": lower == "true" }))
                } else if lower == "null" {
                    Ok(json!({ "NULL": true }))
                } else if w.parse::<f64>().is_ok() {
                    Ok(json!({ "N": w }))
                } else {
                    Err(DdbError::Validation(format!("invalid value literal: {w}")))
                }
            }
            other => Err(DdbError::Validation(format!(
                "expected value, found {other:?}"
            ))),
        }
    }
}

fn parse(statement: &str, params: &[Value]) -> Result<Stmt, DdbError> {
    let toks = lex(statement)?;
    let mut p = Parser {
        toks,
        pos: 0,
        params,
        pidx: 0,
    };
    let verb = match p.next() {
        Some(Tok::Word(w)) => w.to_ascii_uppercase(),
        other => {
            return Err(DdbError::Validation(format!(
                "expected a statement verb, found {other:?}"
            )))
        }
    };
    match verb.as_str() {
        "INSERT" => parse_insert(&mut p),
        "SELECT" => parse_select(&mut p),
        "UPDATE" => parse_update(&mut p),
        "DELETE" => parse_delete(&mut p),
        other => Err(DdbError::Validation(format!(
            "unsupported PartiQL statement: {other}"
        ))),
    }
}

fn parse_insert(p: &mut Parser) -> Result<Stmt, DdbError> {
    p.expect_word("INTO")?;
    let table = p.ident()?;
    p.expect_word("VALUE")?;
    p.expect_sym('{')?;
    let mut item = Map::new();
    if p.peek() != Some(&Tok::Sym('}')) {
        loop {
            let key = match p.next() {
                Some(Tok::Str(s)) => s,
                other => {
                    return Err(DdbError::Validation(format!(
                        "expected attribute name string, found {other:?}"
                    )))
                }
            };
            p.expect_sym(':')?;
            let val = p.value()?;
            item.insert(key, val);
            match p.next() {
                Some(Tok::Sym(',')) => continue,
                Some(Tok::Sym('}')) => break,
                other => {
                    return Err(DdbError::Validation(format!(
                        "expected `,` or `}}`, found {other:?}"
                    )))
                }
            }
        }
    } else {
        p.expect_sym('}')?;
    }
    Ok(Stmt::Insert {
        table,
        item: Value::Object(item),
    })
}

fn parse_select(p: &mut Parser) -> Result<Stmt, DdbError> {
    // Projection list is consumed but only `*` is honored; specific projections fall back to
    // returning the full item (documented).
    loop {
        match p.next() {
            Some(Tok::Word(w)) if w.eq_ignore_ascii_case("FROM") => break,
            Some(_) => continue,
            None => return Err(DdbError::Validation("expected FROM in SELECT".into())),
        }
    }
    let table = p.ident()?;
    let wheres = parse_where(p, true)?;
    Ok(Stmt::Select { table, wheres })
}

fn parse_update(p: &mut Parser) -> Result<Stmt, DdbError> {
    let table = p.ident()?;
    p.expect_word("SET")?;
    let mut set = Vec::new();
    loop {
        let attr = p.ident()?;
        p.expect_word("=")?;
        let val = p.value()?;
        set.push((attr, val));
        match p.peek() {
            Some(Tok::Sym(',')) => {
                p.next();
            }
            _ => break,
        }
    }
    let mut remove = Vec::new();
    if matches!(p.peek(), Some(Tok::Word(w)) if w.eq_ignore_ascii_case("REMOVE")) {
        p.next();
        loop {
            remove.push(p.ident()?);
            match p.peek() {
                Some(Tok::Sym(',')) => {
                    p.next();
                }
                _ => break,
            }
        }
    }
    let wheres = parse_where(p, false)?;
    let key = where_to_key(&wheres)?;
    Ok(Stmt::Update {
        table,
        key,
        set,
        remove,
    })
}

fn parse_delete(p: &mut Parser) -> Result<Stmt, DdbError> {
    p.expect_word("FROM")?;
    let table = p.ident()?;
    let wheres = parse_where(p, false)?;
    let key = where_to_key(&wheres)?;
    Ok(Stmt::Delete { table, key })
}

/// Parse an optional `WHERE <attr> <op> <value> [AND ...]`. When `allow_ops` is false only
/// equality is permitted (key specification for UPDATE/DELETE).
fn parse_where(p: &mut Parser, allow_ops: bool) -> Result<Vec<(String, String, Value)>, DdbError> {
    let mut out = Vec::new();
    if !matches!(p.peek(), Some(Tok::Word(w)) if w.eq_ignore_ascii_case("WHERE")) {
        return Ok(out);
    }
    p.next(); // WHERE
    loop {
        let attr = p.ident()?;
        let op = match p.next() {
            Some(Tok::Word(w)) if ["=", "<>", "<", "<=", ">", ">="].contains(&w.as_str()) => w,
            other => {
                return Err(DdbError::Validation(format!(
                    "expected comparison operator, found {other:?}"
                )))
            }
        };
        if !allow_ops && op != "=" {
            return Err(DdbError::Validation(
                "UPDATE/DELETE WHERE supports only equality".into(),
            ));
        }
        let val = p.value()?;
        out.push((attr, op, val));
        match p.peek() {
            Some(Tok::Word(w)) if w.eq_ignore_ascii_case("AND") => {
                p.next();
            }
            _ => break,
        }
    }
    Ok(out)
}

/// Convert equality WHERE terms into a `Key` object.
fn where_to_key(wheres: &[(String, String, Value)]) -> Result<Value, DdbError> {
    if wheres.is_empty() {
        return Err(DdbError::Validation(
            "WHERE clause specifying the primary key is required".into(),
        ));
    }
    let mut key = Map::new();
    for (attr, op, val) in wheres {
        if op != "=" {
            return Err(DdbError::Validation(
                "primary key WHERE must use equality".into(),
            ));
        }
        key.insert(attr.clone(), val.clone());
    }
    Ok(Value::Object(key))
}

// ============================ NextToken codec ==================================

fn encode_token(last_evaluated_key: &Value) -> String {
    base64::engine::general_purpose::STANDARD.encode(last_evaluated_key.to_string())
}

fn decode_token(token: &str) -> Result<Value, DdbError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(token)
        .map_err(|_| DdbError::Validation("invalid NextToken".into()))?;
    serde_json::from_slice(&bytes).map_err(|_| DdbError::Validation("invalid NextToken".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn batch_statement_count_is_validated_before_any_write() {
        let store = crate::store::TableStore::new();
        let ctx = Ctx {
            store: &store,
            account: "000000000000",
            region: "us-east-1",
        };
        ops::create_table(&ctx, &json!({"TableName":"batch-limit","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"})).await.unwrap();
        assert!(matches!(
            batch_execute_statement(&ctx, &json!({"Statements":[]})).await,
            Err(DdbError::Validation(_))
        ));
        let statements: Vec<_> = (0..26).map(|index| json!({"Statement":"INSERT INTO \"batch-limit\" VALUE {'id': ?}","Parameters":[{"S":format!("key-{index}")}]})).collect();
        assert!(matches!(
            batch_execute_statement(&ctx, &json!({"Statements":statements})).await,
            Err(DdbError::Validation(_))
        ));
        let empty = ops::scan(&ctx, &json!({"TableName":"batch-limit"}))
            .await
            .unwrap();
        assert_eq!(empty["Count"], 0);
        let response = batch_execute_statement(&ctx, &json!({"Statements":&statements[..25]}))
            .await
            .unwrap();
        let responses = response["Responses"].as_array().unwrap();
        assert_eq!(responses.len(), 25);
        assert!(responses.iter().all(|entry| entry.get("Error").is_none()));
        let full = ops::scan(&ctx, &json!({"TableName":"batch-limit"}))
            .await
            .unwrap();
        assert_eq!(full["Count"], 25);
    }

    #[tokio::test]
    async fn malformed_batch_entries_fail_before_writes_but_sql_errors_remain_per_statement() {
        let store = crate::store::TableStore::new();
        let ctx = Ctx {
            store: &store,
            account: "000000000000",
            region: "us-east-1",
        };
        ops::create_table(&ctx, &json!({"TableName":"batch-shape","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"})).await.unwrap();
        let insert = json!({"Statement":"INSERT INTO \"batch-shape\" VALUE {'id': 'new'}"});
        let invalid = [
            json!({}),
            Value::Null,
            json!("not-a-structure"),
            json!([]),
            json!({"Statement":null}),
            json!({"Statement":42}),
            json!({"Statement":""}),
            json!({"Statement":"x".repeat(8193)}),
            json!({"Statement":"SELECT * FROM tbl","ConsistentRead":"yes"}),
            json!({"Statement":"SELECT * FROM tbl","Parameters":[]}),
            json!({"Statement":"SELECT * FROM tbl","ReturnValuesOnConditionCheckFailure":"invalid"}),
        ];
        for malformed in invalid {
            for statements in [
                vec![insert.clone(), malformed.clone()],
                vec![malformed.clone(), insert.clone()],
            ] {
                let batch = json!({"Statements":statements});
                assert!(matches!(
                    authorization_targets("BatchExecuteStatement", &batch),
                    Err(DdbError::Validation(_))
                ));
                assert!(matches!(
                    batch_execute_statement(&ctx, &batch).await,
                    Err(DdbError::Validation(_))
                ));
                let item = ops::get_item(
                    &ctx,
                    &json!({"TableName":"batch-shape","Key":{"id":{"S":"new"}}}),
                )
                .await
                .unwrap();
                assert!(item.get("Item").is_none());
            }
        }
        assert!(batch_statement(&json!({"Statement":"é".repeat(8192)})).is_ok());
        let response = batch_execute_statement(
            &ctx,
            &json!({"Statements":[insert,{"Statement":"NOT_A_SUPPORTED_SQL_STATEMENT"}]}),
        )
        .await
        .unwrap();
        assert_eq!(response["Responses"][0], json!({}));
        assert_eq!(response["Responses"][1]["Error"]["Code"], "ValidationError");
        let item = ops::get_item(
            &ctx,
            &json!({"TableName":"batch-shape","Key":{"id":{"S":"new"}}}),
        )
        .await
        .unwrap();
        assert!(item.get("Item").is_some());
    }

    #[tokio::test]
    async fn mixed_batches_are_rejected_before_writes_in_either_order() {
        let store = crate::store::TableStore::new();
        let ctx = Ctx {
            store: &store,
            account: "000000000000",
            region: "us-east-1",
        };
        ops::create_table(&ctx, &json!({"TableName":"mixed-batch","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PAY_PER_REQUEST"})).await.unwrap();
        let write = json!({"Statement":"INSERT INTO \"mixed-batch\" VALUE {'id': 'new'}"});
        let read = json!({"Statement":"SELECT * FROM \"mixed-batch\" WHERE id = 'new'"});
        for statements in [vec![write.clone(), read.clone()], vec![read, write]] {
            assert!(matches!(
                batch_execute_statement(&ctx, &json!({"Statements":statements})).await,
                Err(DdbError::Validation(_))
            ));
            let response = ops::get_item(
                &ctx,
                &json!({"TableName":"mixed-batch","Key":{"id":{"S":"new"}}}),
            )
            .await
            .unwrap();
            assert!(response.get("Item").is_none());
        }
    }

    #[tokio::test]
    async fn batch_select_uses_the_complete_key_and_preserves_additional_conditions() {
        let store = crate::store::TableStore::new();
        let ctx = Ctx {
            store: &store,
            account: "000000000000",
            region: "us-east-1",
        };
        ops::create_table(&ctx, &json!({"TableName":"point-reads","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"},{"AttributeName":"sk","KeyType":"RANGE"}],"AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"},{"AttributeName":"sk","AttributeType":"N"}],"BillingMode":"PAY_PER_REQUEST"})).await.unwrap();
        for item in [
            json!({"pk":{"S":"p"},"sk":{"N":"1"},"flag":{"S":"keep"}}),
            json!({"pk":{"S":"p"},"sk":{"N":"2"},"flag":{"S":"drop"}}),
            json!({"pk":{"S":"q"},"sk":{"N":"1"},"flag":{"S":"keep"}}),
        ] {
            ops::put_item(&ctx, &json!({"TableName":"point-reads","Item":item}))
                .await
                .unwrap();
        }
        let result = batch_execute_statement(&ctx, &json!({"Statements":[
            {"Statement":"SELECT * FROM \"point-reads\" WHERE pk = 'p' AND sk = 2 AND flag = 'drop'"},
            {"Statement":"SELECT * FROM \"point-reads\" WHERE pk = 'p' AND sk = 1 AND flag = 'drop'"},
            {"Statement":"SELECT * FROM \"point-reads\" WHERE pk = 'p'"},
            {"Statement":"SELECT * FROM \"point-reads\" WHERE pk = 'p' AND sk > 0"},
            {"Statement":"SELECT * FROM \"point-reads\" WHERE pk = 'q' AND sk = 1"},
            {"Statement":"SELECT * FROM \"point-reads\" WHERE pk = 'absent' AND sk = 1"}
        ]})).await.unwrap();
        let responses = result["Responses"].as_array().unwrap();
        assert_eq!(responses[0]["Item"]["sk"]["N"], "2");
        assert_eq!(responses[1], json!({}));
        assert_eq!(responses[2]["Error"]["Code"], "ValidationError");
        assert_eq!(responses[3]["Error"]["Code"], "ValidationError");
        assert_eq!(responses[4]["Item"]["pk"]["S"], "q");
        assert_eq!(responses[5], json!({}));
    }

    #[test]
    fn lex_insert() {
        let toks = lex("INSERT INTO \"t\" VALUE {'id': ?, 'n': 5}").unwrap();
        assert_eq!(toks[0], Tok::Word("INSERT".into()));
        assert!(toks.contains(&Tok::Param));
    }

    #[test]
    fn parse_insert_with_param_and_literal() {
        let params = vec![json!({"S": "a"})];
        let stmt = parse("INSERT INTO t VALUE {'id': ?, 'n': 5, 'ok': true}", &params).unwrap();
        match stmt {
            Stmt::Insert { table, item } => {
                assert_eq!(table, "t");
                assert_eq!(item["id"]["S"], "a");
                assert_eq!(item["n"]["N"], "5");
                assert_eq!(item["ok"]["BOOL"], true);
            }
            _ => panic!("expected insert"),
        }
    }

    #[test]
    fn parse_select_where_builds_filter() {
        let params = vec![json!({"N": "3"})];
        let stmt = parse("SELECT * FROM t WHERE n > ?", &params).unwrap();
        match stmt {
            Stmt::Select { wheres, .. } => {
                assert_eq!(wheres.len(), 1);
                assert_eq!(wheres[0].1, ">");
            }
            _ => panic!("expected select"),
        }
    }

    #[test]
    fn parse_update_and_delete_keys() {
        let p = vec![json!({"S": "k"})];
        let upd = parse("UPDATE t SET v = 9 WHERE id = ?", &p).unwrap();
        assert!(matches!(upd, Stmt::Update { .. }));
        let del = parse("DELETE FROM t WHERE id = ?", &p).unwrap();
        assert!(matches!(del, Stmt::Delete { .. }));
    }

    #[test]
    fn token_round_trip() {
        let lek = json!({ "id": { "S": "a" } });
        let t = encode_token(&lek);
        assert_eq!(decode_token(&t).unwrap(), lek);
    }
}
