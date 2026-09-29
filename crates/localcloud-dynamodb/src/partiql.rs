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
    let statements = req
        .get("Statements")
        .and_then(Value::as_array)
        .ok_or_else(|| DdbError::Validation("Statements is required".into()))?;
    let mut responses = Vec::new();
    for entry in statements {
        let statement = match entry.get("Statement").and_then(Value::as_str) {
            Some(s) => s,
            None => {
                responses.push(json!({ "Error": { "Code": "ValidationError", "Message": "Statement is required" } }));
                continue;
            }
        };
        let params = parse_parameters(entry)?;
        let result = match parse(statement, &params) {
            Ok(stmt) => run(ctx, stmt, entry).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(v) => {
                let mut item = Map::new();
                if let Some(items) = v.get("Items").and_then(Value::as_array) {
                    // SELECT returns multiple; batch reports the first matched item per statement.
                    if let Some(first) = items.first() {
                        item.insert("Item".into(), first.clone());
                    }
                }
                responses.push(Value::Object(item));
            }
            Err(e) => responses
                .push(json!({ "Error": { "Code": e.batch_code(), "Message": e.to_string() } })),
        }
    }
    Ok(json!({ "Responses": responses }))
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
