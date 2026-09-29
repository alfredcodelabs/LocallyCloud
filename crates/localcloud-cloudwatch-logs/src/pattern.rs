use regex::Regex;
use serde_json::Value;

use crate::error::LogsError;

const MAX_PATTERN_CHARS: usize = 1_024;
const MAX_TOKENS: usize = 256;
const MAX_JSON_DEPTH: usize = 16;
const MAX_SELECTOR_CHARS: usize = 256;
const MAX_SELECTOR_SEGMENTS: usize = 32;
const MAX_REGEX_FRAGMENTS: usize = 2;

pub struct FilterPattern {
    matcher: PatternMatcher,
    regex_count: usize,
}

enum PatternMatcher {
    MatchAll,
    Unstructured(Vec<TextClause>),
    Json(JsonExpr),
    Delimited(Vec<DelimitedField>),
}

struct TextClause {
    excluded: bool,
    matcher: ScalarMatcher,
}

enum ScalarMatcher {
    Literal(String),
    Wildcard(String),
    Regex(Regex),
    Number(f64),
    Bool(bool),
    Null,
}

#[derive(Clone, Copy)]
enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

enum JsonExpr {
    And(Box<JsonExpr>, Box<JsonExpr>),
    Or(Box<JsonExpr>, Box<JsonExpr>),
    Compare(Selector, CompareOp, ScalarMatcher),
    IsNull(Selector),
    NotExists(Selector),
}

struct Selector(Vec<SelectorSegment>);

enum SelectorSegment {
    Key(String),
    Index(usize),
    Wildcard,
}

enum DelimitedField {
    Any,
    Compare(CompareOp, ScalarMatcher),
}

#[derive(Clone)]
enum JsonToken {
    Selector(String),
    String(String),
    Regex(String),
    Number(f64),
    Bool(bool),
    Null,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    LParen,
    RParen,
    Is,
    Not,
    Exists,
}

impl FilterPattern {
    pub fn compile(pattern: Option<&str>) -> Result<Self, LogsError> {
        let pattern = pattern.unwrap_or_default().trim();
        if pattern.chars().count() > MAX_PATTERN_CHARS {
            return Err(LogsError::InvalidParameter(
                "filterPattern exceeds 1024 characters".into(),
            ));
        }
        if pattern.is_empty() {
            return Ok(Self {
                matcher: PatternMatcher::MatchAll,
                regex_count: 0,
            });
        }

        let mut regex_count = 0;
        let matcher = if pattern.starts_with('{') {
            PatternMatcher::Json(parse_json_pattern(pattern, &mut regex_count)?)
        } else if pattern.starts_with('[') {
            PatternMatcher::Delimited(parse_delimited_pattern(pattern, &mut regex_count)?)
        } else {
            PatternMatcher::Unstructured(parse_unstructured(pattern, &mut regex_count)?)
        };
        Ok(Self {
            matcher,
            regex_count,
        })
    }

    pub fn regex_count(&self) -> usize {
        self.regex_count
    }

    pub fn matches(&self, message: &str) -> bool {
        match &self.matcher {
            PatternMatcher::MatchAll => true,
            PatternMatcher::Unstructured(clauses) => clauses
                .iter()
                .all(|clause| clause.matcher.matches_text(message) != clause.excluded),
            PatternMatcher::Json(expression) => serde_json::from_str(message)
                .ok()
                .is_some_and(|value| expression.matches(&value)),
            PatternMatcher::Delimited(fields) => {
                let values = split_message_fields(message);
                fields.iter().enumerate().all(|(index, field)| match field {
                    DelimitedField::Any => true,
                    DelimitedField::Compare(operator, expected) => values
                        .get(index)
                        .is_some_and(|value| compare_text(value, *operator, expected)),
                })
            }
        }
    }
}

impl ScalarMatcher {
    fn matches_text(&self, value: &str) -> bool {
        match self {
            Self::Literal(expected) => value.contains(expected),
            Self::Wildcard(expected) => wildcard_matches(expected, value),
            Self::Regex(regex) => regex.is_match(value),
            Self::Number(expected) => value
                .parse::<f64>()
                .is_ok_and(|actual| actual.is_finite() && actual == *expected),
            Self::Bool(expected) => value
                .parse::<bool>()
                .is_ok_and(|actual| actual == *expected),
            Self::Null => value == "null",
        }
    }

    fn matches_json(&self, value: &Value) -> bool {
        match (self, value) {
            (Self::Literal(expected), Value::String(actual)) => actual == expected,
            (Self::Wildcard(expected), Value::String(actual)) => wildcard_matches(expected, actual),
            (Self::Regex(regex), Value::String(actual)) => regex.is_match(actual),
            (Self::Number(expected), Value::Number(actual)) => {
                actual.as_f64().is_some_and(|actual| actual == *expected)
            }
            (Self::Bool(expected), Value::Bool(actual)) => actual == expected,
            (Self::Null, Value::Null) => true,
            _ => false,
        }
    }
}

impl JsonExpr {
    fn matches(&self, root: &Value) -> bool {
        match self {
            Self::And(left, right) => left.matches(root) && right.matches(root),
            Self::Or(left, right) => left.matches(root) || right.matches(root),
            Self::Compare(selector, operator, expected) => {
                let values = selector_values(root, selector);
                values
                    .iter()
                    .any(|value| compare_json(value, *operator, expected))
            }
            Self::IsNull(selector) => selector_values(root, selector)
                .iter()
                .any(|value| value.is_null()),
            Self::NotExists(selector) => selector_values(root, selector).is_empty(),
        }
    }
}

fn parse_unstructured(
    pattern: &str,
    regex_count: &mut usize,
) -> Result<Vec<TextClause>, LogsError> {
    let mut clauses = Vec::new();
    let bytes = pattern.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        if clauses.len() >= MAX_TOKENS {
            return Err(invalid_pattern());
        }
        let excluded = bytes[index] == b'-';
        if excluded {
            index += 1;
            if index == bytes.len() || bytes[index].is_ascii_whitespace() {
                return Err(invalid_pattern());
            }
        }
        let matcher = match bytes[index] {
            b'"' => {
                let (value, next) = parse_quoted(pattern, index)?;
                index = next;
                ScalarMatcher::Literal(value)
            }
            b'%' => {
                let (expression, next) = parse_regex_fragment(pattern, index)?;
                index = next;
                ScalarMatcher::Regex(compile_regex(&expression, regex_count)?)
            }
            _ => {
                let start = index;
                while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                    if matches!(bytes[index], b'"' | b'%') {
                        return Err(invalid_pattern());
                    }
                    index += 1;
                }
                if index == start {
                    return Err(invalid_pattern());
                }
                ScalarMatcher::Literal(pattern[start..index].to_owned())
            }
        };
        if index < bytes.len() && !bytes[index].is_ascii_whitespace() {
            return Err(invalid_pattern());
        }
        clauses.push(TextClause { excluded, matcher });
    }
    Ok(clauses)
}

fn parse_json_pattern(pattern: &str, regex_count: &mut usize) -> Result<JsonExpr, LogsError> {
    if !pattern.ends_with('}') || pattern.len() < 3 {
        return Err(invalid_pattern());
    }
    let tokens = lex_json(&pattern[1..pattern.len() - 1])?;
    let mut parser = JsonParser {
        tokens,
        position: 0,
        regex_count,
    };
    let expression = parser.parse_or(0)?;
    if parser.position != parser.tokens.len() {
        return Err(invalid_pattern());
    }
    Ok(expression)
}

struct JsonParser<'a> {
    tokens: Vec<JsonToken>,
    position: usize,
    regex_count: &'a mut usize,
}

impl JsonParser<'_> {
    fn parse_or(&mut self, depth: usize) -> Result<JsonExpr, LogsError> {
        let mut expression = self.parse_and(depth)?;
        while self.consume(|token| matches!(token, JsonToken::Or)) {
            expression = JsonExpr::Or(Box::new(expression), Box::new(self.parse_and(depth)?));
        }
        Ok(expression)
    }

    fn parse_and(&mut self, depth: usize) -> Result<JsonExpr, LogsError> {
        let mut expression = self.parse_primary(depth)?;
        while self.consume(|token| matches!(token, JsonToken::And)) {
            expression = JsonExpr::And(Box::new(expression), Box::new(self.parse_primary(depth)?));
        }
        Ok(expression)
    }

    fn parse_primary(&mut self, depth: usize) -> Result<JsonExpr, LogsError> {
        if depth >= MAX_JSON_DEPTH {
            return Err(invalid_pattern());
        }
        if self.consume(|token| matches!(token, JsonToken::LParen)) {
            let expression = self.parse_or(depth + 1)?;
            self.expect(|token| matches!(token, JsonToken::RParen))?;
            return Ok(expression);
        }
        self.parse_predicate()
    }

    fn parse_predicate(&mut self) -> Result<JsonExpr, LogsError> {
        let selector = match self.next() {
            Some(JsonToken::Selector(value)) => parse_selector(&value)?,
            _ => return Err(invalid_pattern()),
        };
        if self.consume(|token| matches!(token, JsonToken::Is)) {
            self.expect(|token| matches!(token, JsonToken::Null))?;
            return Ok(JsonExpr::IsNull(selector));
        }
        if self.consume(|token| matches!(token, JsonToken::Not)) {
            self.expect(|token| matches!(token, JsonToken::Exists))?;
            return Ok(JsonExpr::NotExists(selector));
        }
        let operator = match self.next() {
            Some(JsonToken::Eq) => CompareOp::Eq,
            Some(JsonToken::Ne) => CompareOp::Ne,
            Some(JsonToken::Lt) => CompareOp::Lt,
            Some(JsonToken::Le) => CompareOp::Le,
            Some(JsonToken::Gt) => CompareOp::Gt,
            Some(JsonToken::Ge) => CompareOp::Ge,
            _ => return Err(invalid_pattern()),
        };
        let expected = match self.next() {
            Some(JsonToken::String(value)) => string_matcher(value),
            Some(JsonToken::Regex(value)) => {
                ScalarMatcher::Regex(compile_regex(&value, self.regex_count)?)
            }
            Some(JsonToken::Number(value)) => ScalarMatcher::Number(value),
            Some(JsonToken::Bool(value)) => ScalarMatcher::Bool(value),
            Some(JsonToken::Null) => ScalarMatcher::Null,
            _ => return Err(invalid_pattern()),
        };
        if !matches!(operator, CompareOp::Eq | CompareOp::Ne)
            && !matches!(expected, ScalarMatcher::Number(_))
        {
            return Err(invalid_pattern());
        }
        Ok(JsonExpr::Compare(selector, operator, expected))
    }

    fn consume(&mut self, predicate: impl FnOnce(&JsonToken) -> bool) -> bool {
        if self.tokens.get(self.position).is_some_and(predicate) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, predicate: impl FnOnce(&JsonToken) -> bool) -> Result<(), LogsError> {
        if self.consume(predicate) {
            Ok(())
        } else {
            Err(invalid_pattern())
        }
    }

    fn next(&mut self) -> Option<JsonToken> {
        let token = self.tokens.get(self.position)?.clone();
        self.position += 1;
        Some(token)
    }
}

fn lex_json(input: &str) -> Result<Vec<JsonToken>, LogsError> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        if tokens.len() >= MAX_TOKENS {
            return Err(invalid_pattern());
        }
        let (token, next) = match bytes[index] {
            b'(' => (JsonToken::LParen, index + 1),
            b')' => (JsonToken::RParen, index + 1),
            b'&' if bytes.get(index + 1) == Some(&b'&') => (JsonToken::And, index + 2),
            b'|' if bytes.get(index + 1) == Some(&b'|') => (JsonToken::Or, index + 2),
            b'=' => (JsonToken::Eq, index + 1),
            b'!' if bytes.get(index + 1) == Some(&b'=') => (JsonToken::Ne, index + 2),
            b'<' if bytes.get(index + 1) == Some(&b'=') => (JsonToken::Le, index + 2),
            b'>' if bytes.get(index + 1) == Some(&b'=') => (JsonToken::Ge, index + 2),
            b'<' => (JsonToken::Lt, index + 1),
            b'>' => (JsonToken::Gt, index + 1),
            b'"' => {
                let (value, next) = parse_quoted(input, index)?;
                (JsonToken::String(value), next)
            }
            b'%' => {
                let (value, next) = parse_regex_fragment(input, index)?;
                (JsonToken::Regex(value), next)
            }
            b'$' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && !bytes[index].is_ascii_whitespace()
                    && !matches!(
                        bytes[index],
                        b'=' | b'!' | b'<' | b'>' | b'(' | b')' | b'&' | b'|'
                    )
                {
                    index += 1;
                }
                (JsonToken::Selector(input[start..index].to_owned()), index)
            }
            b'-' | b'0'..=b'9' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && matches!(bytes[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    index += 1;
                }
                let value = input[start..index]
                    .parse::<f64>()
                    .map_err(|_| invalid_pattern())?;
                if !value.is_finite() {
                    return Err(invalid_pattern());
                }
                (JsonToken::Number(value), index)
            }
            _ => {
                let start = index;
                while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
                    index += 1;
                }
                let token = match &input[start..index] {
                    "true" => JsonToken::Bool(true),
                    "false" => JsonToken::Bool(false),
                    "null" | "NULL" => JsonToken::Null,
                    "IS" => JsonToken::Is,
                    "NOT" => JsonToken::Not,
                    "EXISTS" => JsonToken::Exists,
                    _ => return Err(invalid_pattern()),
                };
                (token, index)
            }
        };
        tokens.push(token);
        index = next;
    }
    if tokens.is_empty() {
        return Err(invalid_pattern());
    }
    Ok(tokens)
}

fn parse_selector(raw: &str) -> Result<Selector, LogsError> {
    if raw.len() > MAX_SELECTOR_CHARS || !raw.starts_with('$') {
        return Err(invalid_pattern());
    }
    let bytes = raw.as_bytes();
    let mut segments = Vec::new();
    let mut index = 1;
    while index < bytes.len() {
        if segments.len() >= MAX_SELECTOR_SEGMENTS {
            return Err(invalid_pattern());
        }
        match bytes[index] {
            b'.' => {
                index += 1;
                let start = index;
                while index < bytes.len() && !matches!(bytes[index], b'.' | b'[') {
                    index += 1;
                }
                if start == index {
                    return Err(invalid_pattern());
                }
                let key = &raw[start..index];
                if key == "*" {
                    segments.push(SelectorSegment::Wildcard);
                } else if key.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'#' | b'@')
                }) {
                    segments.push(SelectorSegment::Key(key.to_owned()));
                } else {
                    return Err(invalid_pattern());
                }
            }
            b'[' => {
                let close = raw[index + 1..]
                    .find(']')
                    .map(|relative| index + 1 + relative)
                    .ok_or_else(invalid_pattern)?;
                let value = &raw[index + 1..close];
                if value == "*" {
                    segments.push(SelectorSegment::Wildcard);
                } else if let Ok(position) = value.parse::<usize>() {
                    segments.push(SelectorSegment::Index(position));
                } else if value.len() >= 2
                    && ((value.starts_with('\'') && value.ends_with('\''))
                        || (value.starts_with('"') && value.ends_with('"')))
                {
                    let key = &value[1..value.len() - 1];
                    if key.is_empty() {
                        return Err(invalid_pattern());
                    }
                    segments.push(SelectorSegment::Key(key.to_owned()));
                } else {
                    return Err(invalid_pattern());
                }
                index = close + 1;
            }
            _ => return Err(invalid_pattern()),
        }
    }
    if segments.is_empty() {
        return Err(invalid_pattern());
    }
    Ok(Selector(segments))
}

fn selector_values<'a>(root: &'a Value, selector: &Selector) -> Vec<&'a Value> {
    let mut values = vec![root];
    for segment in &selector.0 {
        let mut next = Vec::new();
        for value in values {
            match (segment, value) {
                (SelectorSegment::Key(key), Value::Object(object)) => {
                    next.extend(object.get(key));
                }
                (SelectorSegment::Index(index), Value::Array(array)) => {
                    next.extend(array.get(*index));
                }
                (SelectorSegment::Wildcard, Value::Object(object)) => {
                    next.extend(object.values());
                }
                (SelectorSegment::Wildcard, Value::Array(array)) => {
                    next.extend(array.iter());
                }
                _ => {}
            }
        }
        values = next;
        if values.is_empty() {
            break;
        }
    }
    values
}

fn parse_delimited_pattern(
    pattern: &str,
    regex_count: &mut usize,
) -> Result<Vec<DelimitedField>, LogsError> {
    if !pattern.ends_with(']') || pattern.len() < 2 {
        return Err(invalid_pattern());
    }
    let parts = split_delimited_clauses(&pattern[1..pattern.len() - 1])?;
    if parts.len() > MAX_TOKENS {
        return Err(invalid_pattern());
    }
    parts
        .into_iter()
        .map(|part| parse_delimited_field(&part, regex_count))
        .collect()
}

fn parse_delimited_field(
    field: &str,
    regex_count: &mut usize,
) -> Result<DelimitedField, LogsError> {
    let field = field.trim();
    if field.is_empty() {
        return Ok(DelimitedField::Any);
    }
    let Some((position, operator, width)) = find_comparison(field) else {
        if field
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
        {
            return Ok(DelimitedField::Any);
        }
        return Err(invalid_pattern());
    };
    let name = field[..position].trim();
    let value = field[position + width..].trim();
    if name.is_empty()
        || value.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
    {
        return Err(invalid_pattern());
    }
    let matcher = if value.starts_with('"') {
        let (value, end) = parse_quoted(value, 0)?;
        if end != field[position + width..].trim().len() {
            return Err(invalid_pattern());
        }
        string_matcher(value)
    } else if value.starts_with('%') {
        let (value, end) = parse_regex_fragment(value, 0)?;
        if end != field[position + width..].trim().len() {
            return Err(invalid_pattern());
        }
        ScalarMatcher::Regex(compile_regex(&value, regex_count)?)
    } else if value == "true" || value == "false" {
        ScalarMatcher::Bool(value == "true")
    } else if value == "null" {
        ScalarMatcher::Null
    } else if let Ok(number) = value.parse::<f64>() {
        if !number.is_finite() {
            return Err(invalid_pattern());
        }
        ScalarMatcher::Number(number)
    } else {
        string_matcher(value.to_owned())
    };
    if !matches!(operator, CompareOp::Eq | CompareOp::Ne)
        && !matches!(matcher, ScalarMatcher::Number(_))
    {
        return Err(invalid_pattern());
    }
    Ok(DelimitedField::Compare(operator, matcher))
}

fn split_delimited_clauses(input: &str) -> Result<Vec<String>, LogsError> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quote = false;
    let mut regex = false;
    let mut escaped = false;
    for (index, character) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote {
            escaped = true;
        } else if character == '"' && !regex {
            quote = !quote;
        } else if character == '%' && !quote {
            regex = !regex;
        } else if character == ',' && !quote && !regex {
            parts.push(input[start..index].to_owned());
            start = index + 1;
        }
    }
    if quote || regex || escaped {
        return Err(invalid_pattern());
    }
    parts.push(input[start..].to_owned());
    Ok(parts)
}

fn split_message_fields(message: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in message.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' && quoted {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character.is_whitespace() && !quoted {
            if !current.is_empty() {
                fields.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if !current.is_empty() {
        fields.push(current);
    }
    fields
}

fn find_comparison(value: &str) -> Option<(usize, CompareOp, usize)> {
    let bytes = value.as_bytes();
    let mut quote = false;
    let mut regex = false;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' if !regex => quote = !quote,
            b'%' if !quote => regex = !regex,
            _ if quote || regex => {}
            b'!' if bytes.get(index + 1) == Some(&b'=') => {
                return Some((index, CompareOp::Ne, 2));
            }
            b'<' if bytes.get(index + 1) == Some(&b'=') => {
                return Some((index, CompareOp::Le, 2));
            }
            b'>' if bytes.get(index + 1) == Some(&b'=') => {
                return Some((index, CompareOp::Ge, 2));
            }
            b'=' => return Some((index, CompareOp::Eq, 1)),
            b'<' => return Some((index, CompareOp::Lt, 1)),
            b'>' => return Some((index, CompareOp::Gt, 1)),
            _ => {}
        }
        index += 1;
    }
    None
}

fn parse_quoted(input: &str, start: usize) -> Result<(String, usize), LogsError> {
    let bytes = input.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return Err(invalid_pattern());
    }
    let mut index = start + 1;
    let mut escaped = false;
    while index < bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == b'"' {
            let encoded = &input[start..=index];
            let value = serde_json::from_str(encoded).map_err(|_| invalid_pattern())?;
            return Ok((value, index + 1));
        }
        index += 1;
    }
    Err(invalid_pattern())
}

fn parse_regex_fragment(input: &str, start: usize) -> Result<(String, usize), LogsError> {
    let bytes = input.as_bytes();
    if bytes.get(start) != Some(&b'%') {
        return Err(invalid_pattern());
    }
    let mut index = start + 1;
    while index < bytes.len() && bytes[index] != b'%' {
        index += 1;
    }
    if index == bytes.len() || index == start + 1 {
        return Err(invalid_pattern());
    }
    Ok((input[start + 1..index].to_owned(), index + 1))
}

fn compile_regex(expression: &str, count: &mut usize) -> Result<Regex, LogsError> {
    if *count >= MAX_REGEX_FRAGMENTS
        || !expression.is_ascii()
        || expression.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b':' | b'_'
                        | b'#'
                        | b'='
                        | b'@'
                        | b'/'
                        | b';'
                        | b','
                        | b'-'
                        | b'^'
                        | b'$'
                        | b'?'
                        | b'['
                        | b']'
                        | b'{'
                        | b'}'
                        | b'|'
                        | b'\\'
                        | b'*'
                        | b'+'
                        | b'.'
                ))
        })
    {
        return Err(invalid_pattern());
    }
    let regex = Regex::new(expression).map_err(|_| invalid_pattern())?;
    *count += 1;
    Ok(regex)
}

fn string_matcher(value: String) -> ScalarMatcher {
    if value.contains('*') {
        ScalarMatcher::Wildcard(value)
    } else {
        ScalarMatcher::Literal(value)
    }
}

fn compare_json(actual: &Value, operator: CompareOp, expected: &ScalarMatcher) -> bool {
    match operator {
        CompareOp::Eq => expected.matches_json(actual),
        CompareOp::Ne => !expected.matches_json(actual),
        CompareOp::Lt | CompareOp::Le | CompareOp::Gt | CompareOp::Ge => {
            let (Some(actual), ScalarMatcher::Number(expected)) = (actual.as_f64(), expected)
            else {
                return false;
            };
            compare_numbers(actual, operator, *expected)
        }
    }
}

fn compare_text(actual: &str, operator: CompareOp, expected: &ScalarMatcher) -> bool {
    match operator {
        CompareOp::Eq => matches_field(expected, actual),
        CompareOp::Ne => !matches_field(expected, actual),
        CompareOp::Lt | CompareOp::Le | CompareOp::Gt | CompareOp::Ge => {
            let (Ok(actual), ScalarMatcher::Number(expected)) = (actual.parse::<f64>(), expected)
            else {
                return false;
            };
            compare_numbers(actual, operator, *expected)
        }
    }
}

fn matches_field(expected: &ScalarMatcher, actual: &str) -> bool {
    match expected {
        ScalarMatcher::Literal(expected) => actual == expected,
        ScalarMatcher::Wildcard(expected) => wildcard_matches(expected, actual),
        ScalarMatcher::Regex(regex) => regex.is_match(actual),
        ScalarMatcher::Number(expected) => actual
            .parse::<f64>()
            .is_ok_and(|actual| actual.is_finite() && actual == *expected),
        ScalarMatcher::Bool(expected) => actual
            .parse::<bool>()
            .is_ok_and(|actual| actual == *expected),
        ScalarMatcher::Null => actual == "null",
    }
}

fn compare_numbers(actual: f64, operator: CompareOp, expected: f64) -> bool {
    match operator {
        CompareOp::Eq => actual == expected,
        CompareOp::Ne => actual != expected,
        CompareOp::Lt => actual < expected,
        CompareOp::Le => actual <= expected,
        CompareOp::Gt => actual > expected,
        CompareOp::Ge => actual >= expected,
    }
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let (mut pattern_index, mut value_index) = (0, 0);
    let (mut star_index, mut star_value_index) = (None, 0);
    while value_index < value.len() {
        if pattern.get(pattern_index) == Some(&'*') {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if pattern.get(pattern_index) == value.get(value_index) {
            pattern_index += 1;
            value_index += 1;
        } else if let Some(star) = star_index {
            star_value_index += 1;
            value_index = star_value_index;
            pattern_index = star + 1;
        } else {
            return false;
        }
    }
    while pattern.get(pattern_index) == Some(&'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn invalid_pattern() -> LogsError {
    LogsError::InvalidParameter("filterPattern is invalid or unsupported".into())
}
