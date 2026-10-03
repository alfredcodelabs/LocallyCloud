//! DynamoDB expression engine: tokenizer, parser, and evaluators for condition/filter,
//! update, projection, and key-condition expressions.
//!
//! Placeholders `#name`/`:value` are resolved against `ExpressionAttributeNames`/`Values`
//! at parse time, so the AST carries real attribute names and concrete values.

use std::cmp::Ordering;
use std::collections::HashMap;

use crate::error::DdbError;
use crate::value::{number_cmp, AttributeValue, Item};

// ============================ Tokens ===========================================

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Name(String),             // bare identifier (may be a keyword/function)
    NamePlaceholder(String),  // #x (with the '#')
    ValuePlaceholder(String), // :x (with the ':')
    Index(usize),
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Dot,
}

fn tokenize(input: &str) -> Result<Vec<Token>, DdbError> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\n' | '\r' => i += 1,
            '=' => {
                tokens.push(Token::Eq);
                i += 1;
            }
            '<' => {
                if chars.get(i + 1) == Some(&'=') {
                    tokens.push(Token::Le);
                    i += 2;
                } else if chars.get(i + 1) == Some(&'>') {
                    tokens.push(Token::Ne);
                    i += 2;
                } else {
                    tokens.push(Token::Lt);
                    i += 1;
                }
            }
            '>' => {
                if chars.get(i + 1) == Some(&'=') {
                    tokens.push(Token::Ge);
                    i += 2;
                } else {
                    tokens.push(Token::Gt);
                    i += 1;
                }
            }
            '+' => {
                tokens.push(Token::Plus);
                i += 1;
            }
            '-' => {
                tokens.push(Token::Minus);
                i += 1;
            }
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            ']' => {
                tokens.push(Token::RBracket);
                i += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                i += 1;
            }
            '.' => {
                tokens.push(Token::Dot);
                i += 1;
            }
            '[' => {
                // [index]
                let mut j = i + 1;
                let mut num = String::new();
                while j < chars.len() && chars[j].is_ascii_digit() {
                    num.push(chars[j]);
                    j += 1;
                }
                if num.is_empty() || chars.get(j) != Some(&']') {
                    return Err(DdbError::Validation("invalid list index".into()));
                }
                let idx = num
                    .parse::<usize>()
                    .map_err(|_| DdbError::Validation("invalid list index".into()))?;
                tokens.push(Token::LBracket);
                tokens.push(Token::Index(idx));
                tokens.push(Token::RBracket);
                i = j + 1;
            }
            '#' => {
                let (ident, next) = read_ident(&chars, i + 1);
                if ident.is_empty() {
                    return Err(DdbError::Validation("empty #name placeholder".into()));
                }
                tokens.push(Token::NamePlaceholder(format!("#{ident}")));
                i = next;
            }
            ':' => {
                let (ident, next) = read_ident(&chars, i + 1);
                if ident.is_empty() {
                    return Err(DdbError::Validation("empty :value placeholder".into()));
                }
                tokens.push(Token::ValuePlaceholder(format!(":{ident}")));
                i = next;
            }
            c if c.is_alphabetic() || c == '_' => {
                let (ident, next) = read_ident(&chars, i);
                tokens.push(Token::Name(ident));
                i = next;
            }
            other => {
                return Err(DdbError::Validation(format!(
                    "unexpected character {other:?}"
                )))
            }
        }
    }
    Ok(tokens)
}

fn read_ident(chars: &[char], start: usize) -> (String, usize) {
    let mut s = String::new();
    let mut i = start;
    while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
        s.push(chars[i]);
        i += 1;
    }
    (s, i)
}

// ============================ AST ==============================================

#[derive(Debug, Clone, PartialEq)]
pub enum Segment {
    Attr(String),
    Index(usize),
}

/// A resolved document path (first segment is always an attribute).
#[derive(Debug, Clone, PartialEq)]
pub struct Path {
    pub segments: Vec<Segment>,
}

#[derive(Debug, Clone)]
enum Operand {
    Path(Path),
    Value(AttributeValue),
    Size(Path),
}

#[derive(Debug, Clone, Copy)]
enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
enum Condition {
    Compare(Operand, CmpOp, Operand),
    Between(Operand, Operand, Operand),
    In(Operand, Vec<Operand>),
    AttributeExists(Path),
    AttributeNotExists(Path),
    BeginsWith(Operand, Operand),
    Contains(Operand, Operand),
    AttributeType(Operand, Operand),
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    Not(Box<Condition>),
}

// ============================ Parser ===========================================

struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    names: &'a HashMap<String, String>,
    values: &'a HashMap<String, AttributeValue>,
}

impl<'a> Parser<'a> {
    fn new(
        tokens: Vec<Token>,
        names: &'a HashMap<String, String>,
        values: &'a HashMap<String, AttributeValue>,
    ) -> Self {
        Parser {
            tokens,
            pos: 0,
            names,
            values,
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, tok: &Token) -> Result<(), DdbError> {
        if self.peek() == Some(tok) {
            self.pos += 1;
            Ok(())
        } else {
            Err(DdbError::Validation(format!("expected {tok:?}")))
        }
    }

    fn is_keyword(&self, kw: &str) -> bool {
        matches!(self.peek(), Some(Token::Name(n)) if n.eq_ignore_ascii_case(kw))
    }

    fn eat_keyword(&mut self, kw: &str) -> bool {
        if self.is_keyword(kw) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn resolve_name(&mut self, raw: &str) -> Result<String, DdbError> {
        if raw.starts_with('#') {
            self.names
                .get(raw)
                .cloned()
                .ok_or_else(|| DdbError::Validation(format!("undefined name placeholder {raw}")))
        } else {
            Ok(raw.to_string())
        }
    }

    fn resolve_value(&mut self, raw: &str) -> Result<AttributeValue, DdbError> {
        self.values
            .get(raw)
            .cloned()
            .ok_or_else(|| DdbError::Validation(format!("undefined value placeholder {raw}")))
    }

    /// Parse a document path starting at a name/#name token.
    fn parse_path(&mut self) -> Result<Path, DdbError> {
        let first = match self.next() {
            Some(Token::Name(n)) => self.resolve_name(&n)?,
            Some(Token::NamePlaceholder(n)) => self.resolve_name(&n)?,
            other => {
                return Err(DdbError::Validation(format!(
                    "expected path, got {other:?}"
                )))
            }
        };
        let mut segments = vec![Segment::Attr(first)];
        loop {
            match self.peek() {
                Some(Token::Dot) => {
                    self.pos += 1;
                    let seg = match self.next() {
                        Some(Token::Name(n)) => self.resolve_name(&n)?,
                        Some(Token::NamePlaceholder(n)) => self.resolve_name(&n)?,
                        other => {
                            return Err(DdbError::Validation(format!(
                                "expected attribute after '.', got {other:?}"
                            )))
                        }
                    };
                    segments.push(Segment::Attr(seg));
                }
                Some(Token::LBracket) => {
                    self.pos += 1;
                    let idx = match self.next() {
                        Some(Token::Index(i)) => i,
                        other => {
                            return Err(DdbError::Validation(format!(
                                "expected index, got {other:?}"
                            )))
                        }
                    };
                    self.expect(&Token::RBracket)?;
                    segments.push(Segment::Index(idx));
                }
                _ => break,
            }
        }
        Ok(Path { segments })
    }

    fn parse_operand(&mut self) -> Result<Operand, DdbError> {
        match self.peek() {
            Some(Token::ValuePlaceholder(v)) => {
                let v = v.clone();
                self.pos += 1;
                Ok(Operand::Value(self.resolve_value(&v)?))
            }
            Some(Token::Name(n)) if n.eq_ignore_ascii_case("size") => {
                self.pos += 1;
                self.expect(&Token::LParen)?;
                let path = self.parse_path()?;
                self.expect(&Token::RParen)?;
                Ok(Operand::Size(path))
            }
            _ => Ok(Operand::Path(self.parse_path()?)),
        }
    }

    // condition := or
    fn parse_condition(&mut self) -> Result<Condition, DdbError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Condition, DdbError> {
        let mut left = self.parse_and()?;
        while self.eat_keyword("OR") {
            let right = self.parse_and()?;
            left = Condition::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Condition, DdbError> {
        let mut left = self.parse_not()?;
        while self.eat_keyword("AND") {
            let right = self.parse_not()?;
            left = Condition::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Condition, DdbError> {
        if self.eat_keyword("NOT") {
            let inner = self.parse_not()?;
            Ok(Condition::Not(Box::new(inner)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<Condition, DdbError> {
        if self.peek() == Some(&Token::LParen) {
            self.pos += 1;
            let cond = self.parse_condition()?;
            self.expect(&Token::RParen)?;
            return Ok(cond);
        }
        // Function-style boolean conditions.
        if let Some(Token::Name(n)) = self.peek() {
            let lname = n.to_ascii_lowercase();
            match lname.as_str() {
                "attribute_exists" => {
                    self.pos += 1;
                    self.expect(&Token::LParen)?;
                    let p = self.parse_path()?;
                    self.expect(&Token::RParen)?;
                    return Ok(Condition::AttributeExists(p));
                }
                "attribute_not_exists" => {
                    self.pos += 1;
                    self.expect(&Token::LParen)?;
                    let p = self.parse_path()?;
                    self.expect(&Token::RParen)?;
                    return Ok(Condition::AttributeNotExists(p));
                }
                "begins_with" | "contains" | "attribute_type" => {
                    self.pos += 1;
                    self.expect(&Token::LParen)?;
                    let a = self.parse_operand()?;
                    self.expect(&Token::Comma)?;
                    let b = self.parse_operand()?;
                    self.expect(&Token::RParen)?;
                    return Ok(match lname.as_str() {
                        "begins_with" => Condition::BeginsWith(a, b),
                        "contains" => Condition::Contains(a, b),
                        _ => Condition::AttributeType(a, b),
                    });
                }
                _ => {}
            }
        }
        // Comparison / BETWEEN / IN.
        let left = self.parse_operand()?;
        if self.eat_keyword("BETWEEN") {
            let lo = self.parse_operand()?;
            if !self.eat_keyword("AND") {
                return Err(DdbError::Validation("BETWEEN requires AND".into()));
            }
            let hi = self.parse_operand()?;
            return Ok(Condition::Between(left, lo, hi));
        }
        if self.eat_keyword("IN") {
            self.expect(&Token::LParen)?;
            let mut list = vec![self.parse_operand()?];
            while self.peek() == Some(&Token::Comma) {
                self.pos += 1;
                list.push(self.parse_operand()?);
            }
            self.expect(&Token::RParen)?;
            return Ok(Condition::In(left, list));
        }
        let op = match self.next() {
            Some(Token::Eq) => CmpOp::Eq,
            Some(Token::Ne) => CmpOp::Ne,
            Some(Token::Lt) => CmpOp::Lt,
            Some(Token::Le) => CmpOp::Le,
            Some(Token::Gt) => CmpOp::Gt,
            Some(Token::Ge) => CmpOp::Ge,
            other => {
                return Err(DdbError::Validation(format!(
                    "expected comparator, got {other:?}"
                )))
            }
        };
        let right = self.parse_operand()?;
        Ok(Condition::Compare(left, op, right))
    }
}

// ============================ Path access ======================================

/// Resolve a document path against an item, returning the referenced value if present.
pub fn get_path<'a>(item: &'a Item, path: &Path) -> Option<&'a AttributeValue> {
    let mut current: Option<&AttributeValue> = None;
    for (i, seg) in path.segments.iter().enumerate() {
        match seg {
            Segment::Attr(name) => {
                current = if i == 0 {
                    item.get(name)
                } else {
                    match current {
                        Some(AttributeValue::M(m)) => m.get(name),
                        _ => None,
                    }
                };
            }
            Segment::Index(idx) => {
                current = match current {
                    Some(AttributeValue::L(l)) => l.get(*idx),
                    _ => None,
                };
            }
        }
        current?;
    }
    current
}

// ============================ Evaluation =======================================

fn eval_operand(op: &Operand, item: &Item) -> Option<AttributeValue> {
    match op {
        Operand::Value(v) => Some(v.clone()),
        Operand::Path(p) => get_path(item, p).cloned(),
        Operand::Size(p) => get_path(item, p).map(|v| AttributeValue::N(size_of(v).to_string())),
    }
}

fn size_of(v: &AttributeValue) -> usize {
    match v {
        AttributeValue::S(s) => s.chars().count(),
        AttributeValue::B(b) => b.len(),
        AttributeValue::L(l) => l.len(),
        AttributeValue::M(m) => m.len(),
        AttributeValue::Ss(s) => s.len(),
        AttributeValue::Ns(s) => s.len(),
        AttributeValue::Bs(s) => s.len(),
        _ => 0,
    }
}

/// Compare two scalar values; `None` if not order-comparable.
fn compare(a: &AttributeValue, b: &AttributeValue) -> Option<Ordering> {
    match (a, b) {
        (AttributeValue::S(x), AttributeValue::S(y)) => Some(x.cmp(y)),
        (AttributeValue::N(x), AttributeValue::N(y)) => Some(number_cmp(x, y)),
        (AttributeValue::B(x), AttributeValue::B(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

fn type_tag(v: &AttributeValue) -> &'static str {
    match v {
        AttributeValue::S(_) => "S",
        AttributeValue::N(_) => "N",
        AttributeValue::B(_) => "B",
        AttributeValue::Bool(_) => "BOOL",
        AttributeValue::Null => "NULL",
        AttributeValue::M(_) => "M",
        AttributeValue::L(_) => "L",
        AttributeValue::Ss(_) => "SS",
        AttributeValue::Ns(_) => "NS",
        AttributeValue::Bs(_) => "BS",
    }
}

fn eval_condition(cond: &Condition, item: &Item) -> bool {
    match cond {
        Condition::And(a, b) => eval_condition(a, item) && eval_condition(b, item),
        Condition::Or(a, b) => eval_condition(a, item) || eval_condition(b, item),
        Condition::Not(a) => !eval_condition(a, item),
        Condition::AttributeExists(p) => get_path(item, p).is_some(),
        Condition::AttributeNotExists(p) => get_path(item, p).is_none(),
        Condition::Compare(l, op, r) => match (eval_operand(l, item), eval_operand(r, item)) {
            (Some(a), Some(b)) => eval_compare(&a, *op, &b),
            _ => false,
        },
        Condition::Between(v, lo, hi) => {
            match (
                eval_operand(v, item),
                eval_operand(lo, item),
                eval_operand(hi, item),
            ) {
                (Some(v), Some(lo), Some(hi)) => {
                    matches!(compare(&v, &lo), Some(Ordering::Greater | Ordering::Equal))
                        && matches!(compare(&v, &hi), Some(Ordering::Less | Ordering::Equal))
                }
                _ => false,
            }
        }
        Condition::In(v, list) => match eval_operand(v, item) {
            Some(v) => list
                .iter()
                .filter_map(|o| eval_operand(o, item))
                .any(|candidate| v == candidate),
            None => false,
        },
        Condition::BeginsWith(p, prefix) => {
            match (eval_operand(p, item), eval_operand(prefix, item)) {
                (Some(AttributeValue::S(s)), Some(AttributeValue::S(pre))) => s.starts_with(&pre),
                (Some(AttributeValue::B(s)), Some(AttributeValue::B(pre))) => s.starts_with(&pre),
                _ => false,
            }
        }
        Condition::Contains(p, operand) => {
            match (eval_operand(p, item), eval_operand(operand, item)) {
                (Some(AttributeValue::S(s)), Some(AttributeValue::S(sub))) => s.contains(&sub),
                (Some(AttributeValue::Ss(set)), Some(AttributeValue::S(m))) => set.contains(&m),
                (Some(AttributeValue::Ns(set)), Some(AttributeValue::N(m))) => set.contains(&m),
                (Some(AttributeValue::Bs(set)), Some(AttributeValue::B(m))) => set.contains(&m),
                (Some(AttributeValue::L(list)), Some(v)) => list.contains(&v),
                _ => false,
            }
        }
        Condition::AttributeType(p, t) => match (eval_operand(p, item), eval_operand(t, item)) {
            (Some(v), Some(AttributeValue::S(tag))) => type_tag(&v) == tag,
            _ => false,
        },
    }
}

fn eval_compare(a: &AttributeValue, op: CmpOp, b: &AttributeValue) -> bool {
    match op {
        CmpOp::Eq => a == b,
        CmpOp::Ne => a != b,
        CmpOp::Lt => matches!(compare(a, b), Some(Ordering::Less)),
        CmpOp::Le => matches!(compare(a, b), Some(Ordering::Less | Ordering::Equal)),
        CmpOp::Gt => matches!(compare(a, b), Some(Ordering::Greater)),
        CmpOp::Ge => matches!(compare(a, b), Some(Ordering::Greater | Ordering::Equal)),
    }
}

// ============================ Public API =======================================

/// A parsed condition/filter expression.
pub struct ConditionExpression {
    cond: Condition,
}

impl ConditionExpression {
    /// Parse a condition or filter expression with its placeholder maps.
    pub fn parse(
        expr: &str,
        names: &HashMap<String, String>,
        values: &HashMap<String, AttributeValue>,
    ) -> Result<ConditionExpression, DdbError> {
        let tokens = tokenize(expr)?;
        let mut parser = Parser::new(tokens, names, values);
        let cond = parser.parse_condition()?;
        // Note: do not enforce unused-placeholder here; names/values may be shared across
        // several expressions in one request. Callers that own the maps validate usage.
        if parser.pos != parser.tokens.len() {
            return Err(DdbError::Validation(
                "unexpected trailing tokens in expression".into(),
            ));
        }
        Ok(ConditionExpression { cond })
    }

    /// Evaluate against an item.
    pub fn matches(&self, item: &Item) -> bool {
        eval_condition(&self.cond, item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn names() -> HashMap<String, String> {
        HashMap::new()
    }

    fn item() -> Item {
        let mut m = BTreeMap::new();
        m.insert("id".to_string(), AttributeValue::S("a".into()));
        m.insert("count".to_string(), AttributeValue::N("5".into()));
        m.insert(
            "tags".to_string(),
            AttributeValue::Ss(["x".into(), "y".into()].into()),
        );
        m
    }

    fn vmap(pairs: &[(&str, AttributeValue)]) -> HashMap<String, AttributeValue> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn comparison_and_logic() {
        let v = vmap(&[(":n", AttributeValue::N("3".into()))]);
        let e = ConditionExpression::parse("count > :n", &names(), &v).unwrap();
        assert!(e.matches(&item()));
        let e = ConditionExpression::parse("count < :n", &names(), &v).unwrap();
        assert!(!e.matches(&item()));
    }

    #[test]
    fn attribute_exists_and_not_exists() {
        let e =
            ConditionExpression::parse("attribute_exists(id)", &names(), &HashMap::new()).unwrap();
        assert!(e.matches(&item()));
        let e =
            ConditionExpression::parse("attribute_not_exists(missing)", &names(), &HashMap::new())
                .unwrap();
        assert!(e.matches(&item()));
    }

    #[test]
    fn begins_with_and_contains_and_size() {
        let v = vmap(&[(":p", AttributeValue::S("a".into()))]);
        let e = ConditionExpression::parse("begins_with(id, :p)", &names(), &v).unwrap();
        assert!(e.matches(&item()));
        let v = vmap(&[(":m", AttributeValue::S("x".into()))]);
        let e = ConditionExpression::parse("contains(tags, :m)", &names(), &v).unwrap();
        assert!(e.matches(&item()));
        let v = vmap(&[(":two", AttributeValue::N("2".into()))]);
        let e = ConditionExpression::parse("size(tags) = :two", &names(), &v).unwrap();
        assert!(e.matches(&item()));
    }

    #[test]
    fn between_and_in_and_not() {
        let v = vmap(&[
            (":lo", AttributeValue::N("1".into())),
            (":hi", AttributeValue::N("10".into())),
        ]);
        let e = ConditionExpression::parse("count BETWEEN :lo AND :hi", &names(), &v).unwrap();
        assert!(e.matches(&item()));
        let v = vmap(&[
            (":a", AttributeValue::S("a".into())),
            (":b", AttributeValue::S("b".into())),
        ]);
        let e = ConditionExpression::parse("id IN (:a, :b)", &names(), &v).unwrap();
        assert!(e.matches(&item()));
        let e = ConditionExpression::parse("NOT id = :a", &names(), &v).unwrap();
        assert!(!e.matches(&item()));
    }

    #[test]
    fn name_placeholder_resolution() {
        let mut n = HashMap::new();
        n.insert("#c".to_string(), "count".to_string());
        let v = vmap(&[(":n", AttributeValue::N("5".into()))]);
        let e = ConditionExpression::parse("#c = :n", &n, &v).unwrap();
        assert!(e.matches(&item()));
    }

    #[test]
    fn undefined_placeholder_is_error() {
        assert!(ConditionExpression::parse("#x = :y", &HashMap::new(), &HashMap::new()).is_err());
    }

    #[test]
    fn update_set_add_remove() {
        let mut it = item();
        let v = vmap(&[(":inc", AttributeValue::N("3".into()))]);
        UpdateExpression::parse("SET count = count + :inc", &names(), &v)
            .unwrap()
            .apply(&mut it)
            .unwrap();
        assert_eq!(it.get("count"), Some(&AttributeValue::N("8".into())));

        let v = vmap(&[(":one", AttributeValue::N("1".into()))]);
        UpdateExpression::parse("ADD count :one", &names(), &v)
            .unwrap()
            .apply(&mut it)
            .unwrap();
        assert_eq!(it.get("count"), Some(&AttributeValue::N("9".into())));

        UpdateExpression::parse("REMOVE tags", &names(), &HashMap::new())
            .unwrap()
            .apply(&mut it)
            .unwrap();
        assert!(!it.contains_key("tags"));
    }

    #[test]
    fn update_if_not_exists_and_list_append() {
        let mut it = item();
        it.insert(
            "items".into(),
            AttributeValue::L(vec![AttributeValue::N("1".into())]),
        );
        let v = vmap(&[
            (":zero", AttributeValue::N("0".into())),
            (
                ":more",
                AttributeValue::L(vec![AttributeValue::N("2".into())]),
            ),
        ]);
        UpdateExpression::parse(
            "SET counter = if_not_exists(counter, :zero), items = list_append(items, :more)",
            &names(),
            &v,
        )
        .unwrap()
        .apply(&mut it)
        .unwrap();
        assert_eq!(it.get("counter"), Some(&AttributeValue::N("0".into())));
        assert_eq!(
            it.get("items"),
            Some(&AttributeValue::L(vec![
                AttributeValue::N("1".into()),
                AttributeValue::N("2".into())
            ]))
        );
    }

    #[test]
    fn delete_set_member_drops_when_empty() {
        let mut it = item();
        let v = vmap(&[(":rm", AttributeValue::Ss(["x".into(), "y".into()].into()))]);
        UpdateExpression::parse("DELETE tags :rm", &names(), &v)
            .unwrap()
            .apply(&mut it)
            .unwrap();
        assert!(!it.contains_key("tags"));
    }

    #[test]
    fn projection_selects_paths() {
        let proj = ProjectionExpression::parse("id, count", &names()).unwrap();
        let projected = proj.project(&item());
        assert_eq!(projected.len(), 2);
        assert!(projected.contains_key("id"));
        assert!(projected.contains_key("count"));
        assert!(!projected.contains_key("tags"));
    }
}

// ============================ Update expressions ===============================

#[derive(Debug, Clone)]
enum SetOperand {
    Path(Path),
    Value(AttributeValue),
    IfNotExists(Path, Box<SetOperand>),
    ListAppend(Box<SetOperand>, Box<SetOperand>),
}

#[derive(Debug, Clone)]
enum SetValue {
    Single(SetOperand),
    Plus(SetOperand, SetOperand),
    Minus(SetOperand, SetOperand),
}

#[derive(Debug, Clone)]
enum UpdateAction {
    Set(Path, SetValue),
    Remove(Path),
    Add(Path, AttributeValue),
    Delete(Path, AttributeValue),
}

impl<'a> Parser<'a> {
    fn parse_set_operand(&mut self) -> Result<SetOperand, DdbError> {
        if let Some(Token::Name(n)) = self.peek() {
            let lname = n.to_ascii_lowercase();
            if lname == "if_not_exists" {
                self.pos += 1;
                self.expect(&Token::LParen)?;
                let path = self.parse_path()?;
                self.expect(&Token::Comma)?;
                let default = self.parse_set_operand()?;
                self.expect(&Token::RParen)?;
                return Ok(SetOperand::IfNotExists(path, Box::new(default)));
            }
            if lname == "list_append" {
                self.pos += 1;
                self.expect(&Token::LParen)?;
                let a = self.parse_set_operand()?;
                self.expect(&Token::Comma)?;
                let b = self.parse_set_operand()?;
                self.expect(&Token::RParen)?;
                return Ok(SetOperand::ListAppend(Box::new(a), Box::new(b)));
            }
        }
        if let Some(Token::ValuePlaceholder(v)) = self.peek() {
            let v = v.clone();
            self.pos += 1;
            return Ok(SetOperand::Value(self.resolve_value(&v)?));
        }
        Ok(SetOperand::Path(self.parse_path()?))
    }

    fn parse_set_value(&mut self) -> Result<SetValue, DdbError> {
        let left = self.parse_set_operand()?;
        match self.peek() {
            Some(Token::Plus) => {
                self.pos += 1;
                Ok(SetValue::Plus(left, self.parse_set_operand()?))
            }
            Some(Token::Minus) => {
                self.pos += 1;
                Ok(SetValue::Minus(left, self.parse_set_operand()?))
            }
            _ => Ok(SetValue::Single(left)),
        }
    }

    fn parse_update(&mut self) -> Result<Vec<UpdateAction>, DdbError> {
        let mut actions = Vec::new();
        while self.peek().is_some() {
            let clause = match self.next() {
                Some(Token::Name(n)) => n.to_ascii_uppercase(),
                other => {
                    return Err(DdbError::Validation(format!(
                        "expected SET/REMOVE/ADD/DELETE, got {other:?}"
                    )))
                }
            };
            match clause.as_str() {
                "SET" => loop {
                    let path = self.parse_path()?;
                    self.expect(&Token::Eq)?;
                    let value = self.parse_set_value()?;
                    actions.push(UpdateAction::Set(path, value));
                    if !self.eat_comma() {
                        break;
                    }
                },
                "REMOVE" => loop {
                    let path = self.parse_path()?;
                    actions.push(UpdateAction::Remove(path));
                    if !self.eat_comma() {
                        break;
                    }
                },
                "ADD" => loop {
                    let path = self.parse_path()?;
                    let value = self.parse_value_token()?;
                    actions.push(UpdateAction::Add(path, value));
                    if !self.eat_comma() {
                        break;
                    }
                },
                "DELETE" => loop {
                    let path = self.parse_path()?;
                    let value = self.parse_value_token()?;
                    actions.push(UpdateAction::Delete(path, value));
                    if !self.eat_comma() {
                        break;
                    }
                },
                other => {
                    return Err(DdbError::Validation(format!(
                        "unknown update clause {other}"
                    )))
                }
            }
        }
        Ok(actions)
    }

    fn eat_comma(&mut self) -> bool {
        if self.peek() == Some(&Token::Comma) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_value_token(&mut self) -> Result<AttributeValue, DdbError> {
        match self.next() {
            Some(Token::ValuePlaceholder(v)) => self.resolve_value(&v),
            other => Err(DdbError::Validation(format!(
                "expected :value, got {other:?}"
            ))),
        }
    }
}

fn eval_set_operand(op: &SetOperand, item: &Item) -> Result<AttributeValue, DdbError> {
    match op {
        SetOperand::Value(v) => Ok(v.clone()),
        SetOperand::Path(p) => get_path(item, p)
            .cloned()
            .ok_or_else(|| DdbError::Validation("operand path does not exist".into())),
        SetOperand::IfNotExists(p, default) => match get_path(item, p) {
            Some(v) => Ok(v.clone()),
            None => eval_set_operand(default, item),
        },
        SetOperand::ListAppend(a, b) => {
            let va = eval_set_operand(a, item)?;
            let vb = eval_set_operand(b, item)?;
            match (va, vb) {
                (AttributeValue::L(mut x), AttributeValue::L(y)) => {
                    x.extend(y);
                    Ok(AttributeValue::L(x))
                }
                _ => Err(DdbError::Validation(
                    "list_append requires two lists".into(),
                )),
            }
        }
    }
}

fn arithmetic(
    a: &AttributeValue,
    b: &AttributeValue,
    add: bool,
) -> Result<AttributeValue, DdbError> {
    use bigdecimal::BigDecimal;
    use std::str::FromStr;
    match (a, b) {
        (AttributeValue::N(x), AttributeValue::N(y)) => {
            let xn =
                BigDecimal::from_str(x).map_err(|_| DdbError::Validation("bad number".into()))?;
            let yn =
                BigDecimal::from_str(y).map_err(|_| DdbError::Validation("bad number".into()))?;
            let r = if add { xn + yn } else { xn - yn };
            crate::value::normalize_number(&r.to_string()).map(AttributeValue::N)
        }
        _ => Err(DdbError::Validation("arithmetic requires numbers".into())),
    }
}

/// A parsed update expression.
pub struct UpdateExpression {
    actions: Vec<UpdateAction>,
}

impl UpdateExpression {
    pub fn parse(
        expr: &str,
        names: &HashMap<String, String>,
        values: &HashMap<String, AttributeValue>,
    ) -> Result<UpdateExpression, DdbError> {
        let tokens = tokenize(expr)?;
        let mut parser = Parser::new(tokens, names, values);
        let actions = parser.parse_update()?;
        Ok(UpdateExpression { actions })
    }

    /// Apply the update actions to an item in place.
    pub fn apply(&self, item: &mut Item) -> Result<(), DdbError> {
        for action in &self.actions {
            match action {
                UpdateAction::Set(path, value) => {
                    let v = match value {
                        SetValue::Single(op) => eval_set_operand(op, item)?,
                        SetValue::Plus(a, b) => arithmetic(
                            &eval_set_operand(a, item)?,
                            &eval_set_operand(b, item)?,
                            true,
                        )?,
                        SetValue::Minus(a, b) => arithmetic(
                            &eval_set_operand(a, item)?,
                            &eval_set_operand(b, item)?,
                            false,
                        )?,
                    };
                    set_path(item, path, v)?;
                }
                UpdateAction::Remove(path) => {
                    remove_path(item, path);
                }
                UpdateAction::Add(path, value) => apply_add(item, path, value)?,
                UpdateAction::Delete(path, value) => apply_delete(item, path, value),
            }
        }
        Ok(())
    }
}

fn apply_add(item: &mut Item, path: &Path, value: &AttributeValue) -> Result<(), DdbError> {
    let existing = get_path(item, path).cloned();
    let new_value = match (existing, value) {
        (None, v) => v.clone(),
        (Some(AttributeValue::N(x)), AttributeValue::N(y)) => {
            arithmetic(&AttributeValue::N(x), &AttributeValue::N(y.clone()), true)?
        }
        (Some(AttributeValue::Ss(mut s)), AttributeValue::Ss(add)) => {
            s.extend(add.iter().cloned());
            AttributeValue::Ss(s)
        }
        (Some(AttributeValue::Ns(mut s)), AttributeValue::Ns(add)) => {
            s.extend(add.iter().cloned());
            AttributeValue::Ns(s)
        }
        (Some(AttributeValue::Bs(mut s)), AttributeValue::Bs(add)) => {
            s.extend(add.iter().cloned());
            AttributeValue::Bs(s)
        }
        _ => return Err(DdbError::Validation("ADD type mismatch".into())),
    };
    set_path(item, path, new_value)
}

fn apply_delete(item: &mut Item, path: &Path, value: &AttributeValue) {
    let existing = get_path(item, path).cloned();
    let new_value = match (existing, value) {
        (Some(AttributeValue::Ss(mut s)), AttributeValue::Ss(rm)) => {
            s.retain(|m| !rm.contains(m));
            if s.is_empty() {
                None
            } else {
                Some(AttributeValue::Ss(s))
            }
        }
        (Some(AttributeValue::Ns(mut s)), AttributeValue::Ns(rm)) => {
            s.retain(|m| !rm.contains(m));
            if s.is_empty() {
                None
            } else {
                Some(AttributeValue::Ns(s))
            }
        }
        (Some(AttributeValue::Bs(mut s)), AttributeValue::Bs(rm)) => {
            s.retain(|m| !rm.contains(m));
            if s.is_empty() {
                None
            } else {
                Some(AttributeValue::Bs(s))
            }
        }
        _ => return,
    };
    match new_value {
        Some(v) => {
            let _ = set_path(item, path, v);
        }
        None => {
            remove_path(item, path);
        }
    }
}

fn set_path(item: &mut Item, path: &Path, value: AttributeValue) -> Result<(), DdbError> {
    if path.segments.len() == 1 {
        return match &path.segments[0] {
            Segment::Attr(name) => {
                item.insert(name.clone(), value);
                Ok(())
            }
            Segment::Index(_) => Err(DdbError::Validation("cannot index a top-level item".into())),
        };
    }
    let (parents, last) = path.segments.split_at(path.segments.len() - 1);
    let parent = get_path_mut(item, parents)?;
    match (&last[0], parent) {
        (Segment::Attr(name), AttributeValue::M(m)) => {
            m.insert(name.clone(), value);
            Ok(())
        }
        (Segment::Index(i), AttributeValue::L(l)) => {
            if *i < l.len() {
                l[*i] = value;
            } else {
                l.push(value);
            }
            Ok(())
        }
        _ => Err(DdbError::Validation("path parent type mismatch".into())),
    }
}

fn remove_path(item: &mut Item, path: &Path) {
    if path.segments.len() == 1 {
        if let Segment::Attr(name) = &path.segments[0] {
            item.remove(name);
        }
        return;
    }
    let (parents, last) = path.segments.split_at(path.segments.len() - 1);
    if let Ok(parent) = get_path_mut(item, parents) {
        match (&last[0], parent) {
            (Segment::Attr(name), AttributeValue::M(m)) => {
                m.remove(name);
            }
            (Segment::Index(i), AttributeValue::L(l)) if *i < l.len() => {
                l.remove(*i);
            }
            _ => {}
        }
    }
}

fn get_path_mut<'a>(
    item: &'a mut Item,
    segs: &[Segment],
) -> Result<&'a mut AttributeValue, DdbError> {
    let mut current: &mut AttributeValue = match &segs[0] {
        Segment::Attr(n) => item
            .get_mut(n)
            .ok_or_else(|| DdbError::Validation(format!("path attribute {n} does not exist")))?,
        Segment::Index(_) => {
            return Err(DdbError::Validation(
                "path must start with an attribute".into(),
            ))
        }
    };
    for seg in &segs[1..] {
        current = match (seg, current) {
            (Segment::Attr(n), AttributeValue::M(m)) => m.get_mut(n).ok_or_else(|| {
                DdbError::Validation(format!("path attribute {n} does not exist"))
            })?,
            (Segment::Index(i), AttributeValue::L(l)) => l
                .get_mut(*i)
                .ok_or_else(|| DdbError::Validation("path index out of range".into()))?,
            _ => return Err(DdbError::Validation("path type mismatch".into())),
        };
    }
    Ok(current)
}

// ============================ Projection =======================================

/// A parsed projection expression (list of paths).
pub struct ProjectionExpression {
    paths: Vec<Path>,
}

impl ProjectionExpression {
    pub fn parse(
        expr: &str,
        names: &HashMap<String, String>,
    ) -> Result<ProjectionExpression, DdbError> {
        let tokens = tokenize(expr)?;
        let values = HashMap::new();
        let mut parser = Parser::new(tokens, names, &values);
        let mut paths = vec![parser.parse_path()?];
        while parser.eat_comma() {
            paths.push(parser.parse_path()?);
        }
        if parser.pos != parser.tokens.len() {
            return Err(DdbError::Validation(
                "unexpected trailing tokens in projection".into(),
            ));
        }
        Ok(ProjectionExpression { paths })
    }

    /// Project an item to only the referenced paths, reconstructing nesting.
    pub fn project(&self, item: &Item) -> Item {
        let mut result: Item = std::collections::BTreeMap::new();
        for path in &self.paths {
            if let Some(value) = get_path(item, path) {
                insert_projected(&mut result, &path.segments, value.clone());
            }
        }
        result
    }
}

fn insert_projected(result: &mut Item, segs: &[Segment], value: AttributeValue) {
    // Only attribute-segment nesting is reconstructed; index segments project the whole
    // top-level attribute (the common, well-defined case).
    match segs {
        [Segment::Attr(name)] => {
            result.insert(name.clone(), value);
        }
        [Segment::Attr(name), rest @ ..] if rest.iter().all(|s| matches!(s, Segment::Attr(_))) => {
            let entry = result
                .entry(name.clone())
                .or_insert_with(|| AttributeValue::M(std::collections::BTreeMap::new()));
            if let AttributeValue::M(m) = entry {
                insert_projected(m, rest, value);
            }
        }
        [Segment::Attr(name), ..] => {
            result.entry(name.clone()).or_insert(value);
        }
        _ => {}
    }
}
