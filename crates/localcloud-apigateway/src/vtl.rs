//! Deterministic evaluator for the API Gateway mapping-template VTL subset.
//!
//! Supported syntax is deliberately small: references, `#set`, conditional directives,
//! and `#foreach`. Unknown directives, reference roots, methods, and JSONPath operators are
//! rejected instead of being copied silently into an integration request.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine as _;
use http::{HeaderName, HeaderValue};
use serde_json::{Map, Number, Value};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VtlError {
    #[error("invalid VTL syntax: {0}")]
    Parse(String),
    #[error("VTL evaluation failed: {0}")]
    Evaluation(String),
    #[error("unsupported VTL construct: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, Copy)]
pub struct InputBinding<'a> {
    pub body: &'a str,
    pub querystring: &'a BTreeMap<String, String>,
    pub path: &'a BTreeMap<String, String>,
    pub header: &'a BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UtilBinding;

#[derive(Debug, Clone, Copy)]
pub struct ContextBinding<'a> {
    pub values: &'a BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy)]
pub struct VtlContext<'a> {
    pub input: InputBinding<'a>,
    pub util: UtilBinding,
    pub context: ContextBinding<'a>,
    pub stage_variables: &'a BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatedTemplate {
    pub output: String,
    pub status_override: Option<u16>,
    pub header_overrides: BTreeMap<String, String>,
}

impl AsRef<str> for EvaluatedTemplate {
    fn as_ref(&self) -> &str {
        &self.output
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct VtlEngine;

impl VtlEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn select_template<'a>(
        &self,
        templates: &'a BTreeMap<String, String>,
        content_type: Option<&str>,
    ) -> Option<&'a str> {
        let requested = content_type
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .filter(|value| !value.is_empty());

        requested
            .and_then(|requested| {
                templates
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(requested))
                    .map(|(_, template)| template.as_str())
            })
            .or_else(|| {
                templates
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case("application/json"))
                    .map(|(_, template)| template.as_str())
            })
    }

    pub fn evaluate_selected(
        &self,
        templates: &BTreeMap<String, String>,
        content_type: Option<&str>,
        context: &VtlContext<'_>,
    ) -> Result<Option<EvaluatedTemplate>, VtlError> {
        self.select_template(templates, content_type)
            .map(|template| self.evaluate(template, context))
            .transpose()
    }

    pub fn evaluate(
        &self,
        template: &str,
        context: &VtlContext<'_>,
    ) -> Result<EvaluatedTemplate, VtlError> {
        let mut parser = TemplateParser::new(template);
        let (nodes, stop) = parser.parse_nodes(&[])?;
        if stop.is_some() {
            return Err(VtlError::Parse("unexpected closing directive".into()));
        }

        let mut evaluator = Evaluator::new(context);
        let mut output = String::new();
        evaluator.render_nodes(&nodes, &mut output)?;
        Ok(EvaluatedTemplate {
            output,
            status_override: evaluator.status_override,
            header_overrides: evaluator.header_overrides,
        })
    }
}

#[derive(Debug, Clone)]
enum SetTarget {
    Variable(String),
    ResponseOverrideStatus,
    ResponseOverrideHeader(String),
}

#[derive(Debug, Clone)]
enum Node {
    Text(String),
    Set {
        target: SetTarget,
        expression: Expr,
    },
    If {
        branches: Vec<(Expr, Vec<Node>)>,
        otherwise: Vec<Node>,
    },
    Foreach {
        name: String,
        expression: Expr,
        body: Vec<Node>,
    },
}

#[derive(Debug, Clone)]
enum Expr {
    Literal(Value),
    Array(Vec<Expr>),
    Object(Vec<(String, Expr)>),
    Reference(Reference),
    UnaryNot(Box<Expr>),
    Binary(Box<Expr>, BinaryOp, Box<Expr>),
}

#[derive(Debug, Clone, Copy)]
enum BinaryOp {
    Or,
    And,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

#[derive(Debug, Clone)]
struct Reference {
    root: String,
    segments: Vec<RefSegment>,
}

#[derive(Debug, Clone)]
enum RefSegment {
    Property(String),
    Call(String, Vec<Expr>),
    Index(Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopDirective {
    ElseIf,
    Else,
    End,
}

struct TemplateParser<'a> {
    source: &'a str,
    position: usize,
}

impl<'a> TemplateParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    fn parse_nodes(
        &mut self,
        stops: &[StopDirective],
    ) -> Result<(Vec<Node>, Option<StopDirective>), VtlError> {
        let mut nodes = Vec::new();
        let mut text_start = self.position;

        while self.position < self.source.len() {
            if self.current_byte() != Some(b'#') {
                self.position += self.current_char_len();
                continue;
            }

            let Some((name, after_name)) = self.peek_directive() else {
                if matches!(
                    self.source.as_bytes().get(self.position + 1),
                    Some(b'#' | b'*')
                ) {
                    return Err(VtlError::Unsupported("VTL comments".into()));
                }
                self.position += 1;
                continue;
            };
            let stop = match name {
                "elseif" => Some(StopDirective::ElseIf),
                "else" => Some(StopDirective::Else),
                "end" => Some(StopDirective::End),
                _ => None,
            };
            if let Some(stop) = stop {
                if stops.contains(&stop) {
                    self.push_text(&mut nodes, text_start, self.position);
                    self.position = after_name;
                    return Ok((nodes, Some(stop)));
                }
                return Err(VtlError::Parse(format!("unexpected #{name}")));
            }

            self.push_text(&mut nodes, text_start, self.position);
            self.position = after_name;
            match name {
                "set" => nodes.push(self.parse_set()?),
                "if" => nodes.push(self.parse_if()?),
                "foreach" => nodes.push(self.parse_foreach()?),
                other => {
                    return Err(VtlError::Unsupported(format!("directive #{other}")));
                }
            }
            text_start = self.position;
        }

        self.push_text(&mut nodes, text_start, self.position);
        Ok((nodes, None))
    }

    fn parse_set(&mut self) -> Result<Node, VtlError> {
        let arguments = self.take_parenthesized("#set")?;
        let mut expression = ExpressionParser::new(arguments);
        expression.skip_whitespace();
        expression.expect_byte(b'$', "#set target")?;
        let root = expression.take_identifier("#set target")?;
        let target = if root == "context"
            && expression.source[expression.position..].starts_with(".responseOverride")
        {
            expression.expect_byte(b'.', "#set target")?;
            let response_override = expression.take_identifier("#set target")?;
            if response_override != "responseOverride" {
                return Err(VtlError::Unsupported(format!(
                    "#set target `$context.{response_override}`"
                )));
            }
            expression.expect_byte(b'.', "#set target")?;
            match expression.take_identifier("#set target")?.as_str() {
                "status" => SetTarget::ResponseOverrideStatus,
                "header" => {
                    expression.expect_byte(b'.', "#set response override header")?;
                    expression.skip_whitespace();
                    let start = expression.position;
                    while expression.current_byte().is_some_and(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
                    }) {
                        expression.position += 1;
                    }
                    if start == expression.position {
                        return Err(VtlError::Parse(
                            "expected header name in #set target".into(),
                        ));
                    }
                    SetTarget::ResponseOverrideHeader(
                        expression.source[start..expression.position].to_owned(),
                    )
                }
                name => {
                    return Err(VtlError::Unsupported(format!(
                        "#set target `$context.responseOverride.{name}`"
                    )));
                }
            }
        } else {
            SetTarget::Variable(root)
        };
        expression.skip_whitespace();
        expression.expect_byte(b'=', "#set assignment")?;
        let value = expression.parse_expression()?;
        expression.finish()?;
        Ok(Node::Set {
            target,
            expression: value,
        })
    }

    fn parse_if(&mut self) -> Result<Node, VtlError> {
        let condition = parse_complete_expression(self.take_parenthesized("#if")?)?;
        let mut branches = Vec::new();
        let (body, mut stop) = self.parse_nodes(&[
            StopDirective::ElseIf,
            StopDirective::Else,
            StopDirective::End,
        ])?;
        branches.push((condition, body));

        while stop == Some(StopDirective::ElseIf) {
            let condition = parse_complete_expression(self.take_parenthesized("#elseif")?)?;
            let (body, next) = self.parse_nodes(&[
                StopDirective::ElseIf,
                StopDirective::Else,
                StopDirective::End,
            ])?;
            branches.push((condition, body));
            stop = next;
        }

        let otherwise = if stop == Some(StopDirective::Else) {
            let (body, next) = self.parse_nodes(&[StopDirective::End])?;
            stop = next;
            body
        } else {
            Vec::new()
        };
        if stop != Some(StopDirective::End) {
            return Err(VtlError::Parse("unterminated #if".into()));
        }
        Ok(Node::If {
            branches,
            otherwise,
        })
    }

    fn parse_foreach(&mut self) -> Result<Node, VtlError> {
        let arguments = self.take_parenthesized("#foreach")?;
        let mut expression = ExpressionParser::new(arguments);
        expression.skip_whitespace();
        expression.expect_byte(b'$', "#foreach variable")?;
        let name = expression.take_identifier("#foreach variable")?;
        expression.skip_whitespace();
        let keyword = expression.take_identifier("#foreach")?;
        if keyword != "in" {
            return Err(VtlError::Parse("#foreach requires `in`".into()));
        }
        let iterable = expression.parse_expression()?;
        expression.finish()?;
        let (body, stop) = self.parse_nodes(&[StopDirective::End])?;
        if stop != Some(StopDirective::End) {
            return Err(VtlError::Parse("unterminated #foreach".into()));
        }
        Ok(Node::Foreach {
            name,
            expression: iterable,
            body,
        })
    }

    fn take_parenthesized(&mut self, directive: &str) -> Result<&'a str, VtlError> {
        while self
            .current_byte()
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            self.position += 1;
        }
        if self.current_byte() != Some(b'(') {
            return Err(VtlError::Parse(format!("{directive} requires parentheses")));
        }
        let open = self.position;
        let mut depth = 0usize;
        let mut quote = None;
        let mut escaped = false;
        while self.position < self.source.len() {
            let byte = self.source.as_bytes()[self.position];
            self.position += 1;
            if let Some(active_quote) = quote {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == active_quote {
                    quote = None;
                }
                continue;
            }
            match byte {
                b'\'' | b'"' => quote = Some(byte),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(&self.source[open + 1..self.position - 1]);
                    }
                }
                _ => {}
            }
        }
        Err(VtlError::Parse(format!("unterminated {directive}")))
    }

    fn peek_directive(&self) -> Option<(&'a str, usize)> {
        let tail = &self.source[self.position + 1..];
        for directive in ["elseif", "foreach", "else", "set", "if", "end"] {
            if tail.starts_with(directive) {
                return Some((directive, self.position + 1 + directive.len()));
            }
        }
        let mut end = self.position + 1;
        while self
            .source
            .as_bytes()
            .get(end)
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        {
            end += 1;
        }
        (end > self.position + 1).then(|| (&self.source[self.position + 1..end], end))
    }

    fn push_text(&self, nodes: &mut Vec<Node>, start: usize, end: usize) {
        if start < end {
            nodes.push(Node::Text(self.source[start..end].to_owned()));
        }
    }

    fn current_byte(&self) -> Option<u8> {
        self.source.as_bytes().get(self.position).copied()
    }

    fn current_char_len(&self) -> usize {
        self.source[self.position..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(1)
    }
}

fn parse_complete_expression(source: &str) -> Result<Expr, VtlError> {
    let mut parser = ExpressionParser::new(source);
    let expression = parser.parse_expression()?;
    parser.finish()?;
    Ok(expression)
}

struct ExpressionParser<'a> {
    source: &'a str,
    position: usize,
}

impl<'a> ExpressionParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    fn parse_expression(&mut self) -> Result<Expr, VtlError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr, VtlError> {
        let mut expression = self.parse_and()?;
        while self.consume_operator("||") {
            expression = Expr::Binary(
                Box::new(expression),
                BinaryOp::Or,
                Box::new(self.parse_and()?),
            );
        }
        Ok(expression)
    }

    fn parse_and(&mut self) -> Result<Expr, VtlError> {
        let mut expression = self.parse_equality()?;
        while self.consume_operator("&&") {
            expression = Expr::Binary(
                Box::new(expression),
                BinaryOp::And,
                Box::new(self.parse_equality()?),
            );
        }
        Ok(expression)
    }

    fn parse_equality(&mut self) -> Result<Expr, VtlError> {
        let mut expression = self.parse_comparison()?;
        loop {
            let operation = if self.consume_operator("==") {
                Some(BinaryOp::Equal)
            } else if self.consume_operator("!=") {
                Some(BinaryOp::NotEqual)
            } else {
                None
            };
            let Some(operation) = operation else { break };
            expression = Expr::Binary(
                Box::new(expression),
                operation,
                Box::new(self.parse_comparison()?),
            );
        }
        Ok(expression)
    }

    fn parse_comparison(&mut self) -> Result<Expr, VtlError> {
        let mut expression = self.parse_unary()?;
        loop {
            let operation = if self.consume_operator("<=") {
                Some(BinaryOp::LessEqual)
            } else if self.consume_operator(">=") {
                Some(BinaryOp::GreaterEqual)
            } else if self.consume_operator("<") {
                Some(BinaryOp::Less)
            } else if self.consume_operator(">") {
                Some(BinaryOp::Greater)
            } else {
                None
            };
            let Some(operation) = operation else { break };
            expression = Expr::Binary(
                Box::new(expression),
                operation,
                Box::new(self.parse_unary()?),
            );
        }
        Ok(expression)
    }

    fn parse_unary(&mut self) -> Result<Expr, VtlError> {
        if self.consume_operator("!") {
            return Ok(Expr::UnaryNot(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, VtlError> {
        self.skip_whitespace();
        match self.current_byte() {
            Some(b'$') => Ok(Expr::Reference(self.parse_reference()?)),
            Some(b'\'') | Some(b'"') => Ok(Expr::Literal(Value::String(self.parse_string()?))),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'(') => {
                self.position += 1;
                let expression = self.parse_expression()?;
                self.skip_whitespace();
                self.expect_byte(b')', "expression")?;
                Ok(expression)
            }
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(_) => {
                let identifier = self.take_identifier("expression")?;
                match identifier.as_str() {
                    "true" => Ok(Expr::Literal(Value::Bool(true))),
                    "false" => Ok(Expr::Literal(Value::Bool(false))),
                    "null" => Ok(Expr::Literal(Value::Null)),
                    _ => Err(VtlError::Unsupported(format!(
                        "bare expression `{identifier}`"
                    ))),
                }
            }
            None => Err(VtlError::Parse("expected expression".into())),
        }
    }

    fn parse_array(&mut self) -> Result<Expr, VtlError> {
        self.position += 1;
        let mut values = Vec::new();
        loop {
            self.skip_whitespace();
            if self.consume_byte(b']') {
                break;
            }
            values.push(self.parse_expression()?);
            self.skip_whitespace();
            if self.consume_byte(b']') {
                break;
            }
            self.expect_byte(b',', "array")?;
        }
        Ok(Expr::Array(values))
    }

    fn parse_object(&mut self) -> Result<Expr, VtlError> {
        self.position += 1;
        let mut entries = Vec::new();
        loop {
            self.skip_whitespace();
            if self.consume_byte(b'}') {
                break;
            }
            let key = match self.current_byte() {
                Some(b'\'') | Some(b'"') => self.parse_string()?,
                _ => self.take_identifier("object key")?,
            };
            self.skip_whitespace();
            self.expect_byte(b':', "object")?;
            entries.push((key, self.parse_expression()?));
            self.skip_whitespace();
            if self.consume_byte(b'}') {
                break;
            }
            self.expect_byte(b',', "object")?;
        }
        Ok(Expr::Object(entries))
    }

    fn parse_number(&mut self) -> Result<Expr, VtlError> {
        self.skip_whitespace();
        let start = self.position;
        while self.current_byte().is_some_and(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E')
        }) {
            self.position += 1;
        }
        let text = &self.source[start..self.position];
        let value = serde_json::from_str::<Value>(text)
            .map_err(|_| VtlError::Parse(format!("invalid number `{text}`")))?;
        if !value.is_number() {
            return Err(VtlError::Parse(format!("invalid number `{text}`")));
        }
        Ok(Expr::Literal(value))
    }

    fn parse_reference(&mut self) -> Result<Reference, VtlError> {
        self.expect_byte(b'$', "reference")?;
        let mut braced = self.consume_byte(b'{');
        let root = self.take_identifier("reference")?;
        let mut segments = Vec::new();
        loop {
            if braced && self.consume_byte(b'}') {
                braced = false;
                continue;
            }
            if self.consume_byte(b'.') {
                let name = self.take_identifier("reference property")?;
                if self.consume_byte(b'(') {
                    segments.push(RefSegment::Call(name, self.parse_arguments()?));
                } else {
                    segments.push(RefSegment::Property(name));
                }
            } else if self.consume_byte(b'[') {
                let index = self.parse_expression()?;
                self.skip_whitespace();
                self.expect_byte(b']', "reference index")?;
                segments.push(RefSegment::Index(Box::new(index)));
            } else if braced {
                return Err(VtlError::Parse("unterminated braced reference".into()));
            } else {
                break;
            }
        }
        Ok(Reference { root, segments })
    }

    fn parse_arguments(&mut self) -> Result<Vec<Expr>, VtlError> {
        let mut arguments = Vec::new();
        self.skip_whitespace();
        if self.consume_byte(b')') {
            return Ok(arguments);
        }
        loop {
            arguments.push(self.parse_expression()?);
            self.skip_whitespace();
            if self.consume_byte(b')') {
                return Ok(arguments);
            }
            self.expect_byte(b',', "method arguments")?;
        }
    }

    fn parse_string(&mut self) -> Result<String, VtlError> {
        let quote = self
            .current_byte()
            .ok_or_else(|| VtlError::Parse("expected string".into()))?;
        self.position += 1;
        let mut output = String::new();
        while self.position < self.source.len() {
            let character = self.source[self.position..]
                .chars()
                .next()
                .ok_or_else(|| VtlError::Parse("unterminated string".into()))?;
            self.position += character.len_utf8();
            if character as u32 == quote as u32 {
                return Ok(output);
            }
            if character != '\\' {
                output.push(character);
                continue;
            }
            let escaped = self.source[self.position..]
                .chars()
                .next()
                .ok_or_else(|| VtlError::Parse("unterminated string escape".into()))?;
            self.position += escaped.len_utf8();
            output.push(match escaped {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'b' => '\u{0008}',
                'f' => '\u{000c}',
                '\\' => '\\',
                '\'' => '\'',
                '"' => '"',
                other => other,
            });
        }
        Err(VtlError::Parse("unterminated string".into()))
    }

    fn consume_operator(&mut self, operator: &str) -> bool {
        self.skip_whitespace();
        if self.source[self.position..].starts_with(operator) {
            self.position += operator.len();
            true
        } else {
            false
        }
    }

    fn take_identifier(&mut self, location: &str) -> Result<String, VtlError> {
        self.skip_whitespace();
        let start = self.position;
        while self
            .current_byte()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            self.position += 1;
        }
        if start == self.position || self.source.as_bytes()[start].is_ascii_digit() {
            return Err(VtlError::Parse(format!(
                "expected identifier in {location}"
            )));
        }
        Ok(self.source[start..self.position].to_owned())
    }

    fn expect_byte(&mut self, expected: u8, location: &str) -> Result<(), VtlError> {
        self.skip_whitespace();
        if self.consume_byte(expected) {
            Ok(())
        } else {
            Err(VtlError::Parse(format!(
                "expected `{}` in {location}",
                expected as char
            )))
        }
    }

    fn consume_byte(&mut self, expected: u8) -> bool {
        if self.current_byte() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while self
            .current_byte()
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            self.position += 1;
        }
    }

    fn finish(&mut self) -> Result<(), VtlError> {
        self.skip_whitespace();
        if self.position == self.source.len() {
            Ok(())
        } else {
            Err(VtlError::Parse(format!(
                "unexpected expression input `{}`",
                &self.source[self.position..]
            )))
        }
    }

    fn current_byte(&self) -> Option<u8> {
        self.source.as_bytes().get(self.position).copied()
    }
}

struct Evaluator<'a, 'ctx> {
    context: &'ctx VtlContext<'a>,
    variables: BTreeMap<String, Value>,
    status_override: Option<u16>,
    header_overrides: BTreeMap<String, String>,
}

impl<'a, 'ctx> Evaluator<'a, 'ctx> {
    fn new(context: &'ctx VtlContext<'a>) -> Self {
        Self {
            context,
            variables: BTreeMap::new(),
            status_override: None,
            header_overrides: BTreeMap::new(),
        }
    }

    fn render_nodes(&mut self, nodes: &[Node], output: &mut String) -> Result<(), VtlError> {
        for node in nodes {
            match node {
                Node::Text(text) => self.render_text(text, output)?,
                Node::Set { target, expression } => {
                    let value = self.evaluate(expression)?;
                    match target {
                        SetTarget::Variable(name) => {
                            self.variables.insert(name.clone(), value);
                        }
                        SetTarget::ResponseOverrideStatus => {
                            let status = value_as_string(&value).parse::<u16>().map_err(|_| {
                                VtlError::Evaluation(
                                    "response status override must be an unsigned integer".into(),
                                )
                            })?;
                            if !(100..=599).contains(&status) {
                                return Err(VtlError::Evaluation(
                                    "response status override must be between 100 and 599".into(),
                                ));
                            }
                            self.status_override = Some(status);
                        }
                        SetTarget::ResponseOverrideHeader(name) => {
                            let value = value_as_string(&value);
                            HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                                VtlError::Evaluation("invalid response override header name".into())
                            })?;
                            HeaderValue::from_str(&value).map_err(|_| {
                                VtlError::Evaluation(
                                    "invalid response override header value".into(),
                                )
                            })?;
                            self.header_overrides.insert(name.clone(), value);
                        }
                    }
                }
                Node::If {
                    branches,
                    otherwise,
                } => {
                    let mut selected = None;
                    for (condition, body) in branches {
                        if truthy(&self.evaluate(condition)?) {
                            selected = Some(body.as_slice());
                            break;
                        }
                    }
                    self.render_nodes(selected.unwrap_or(otherwise), output)?;
                }
                Node::Foreach {
                    name,
                    expression,
                    body,
                } => {
                    let values = match self.evaluate(expression)? {
                        Value::Array(values) => values,
                        Value::Object(values) => {
                            let sorted = values.into_iter().collect::<BTreeMap<_, _>>();
                            sorted.into_values().collect()
                        }
                        Value::Null => Vec::new(),
                        other => {
                            return Err(VtlError::Evaluation(format!(
                                "#foreach requires an array or object, got {}",
                                value_kind(&other)
                            )));
                        }
                    };
                    let previous_value = self.variables.get(name).cloned();
                    let previous_foreach = self.variables.get("foreach").cloned();
                    let length = values.len();
                    for (index, value) in values.into_iter().enumerate() {
                        self.variables.insert(name.clone(), value);
                        self.variables.insert(
                            "foreach".into(),
                            object_value([
                                ("index", Value::Number(Number::from(index))),
                                ("count", Value::Number(Number::from(index + 1))),
                                ("hasNext", Value::Bool(index + 1 < length)),
                            ]),
                        );
                        self.render_nodes(body, output)?;
                    }
                    restore_variable(&mut self.variables, name, previous_value);
                    restore_variable(&mut self.variables, "foreach", previous_foreach);
                }
            }
        }
        Ok(())
    }

    fn render_text(&mut self, text: &str, output: &mut String) -> Result<(), VtlError> {
        let mut position = 0;
        while position < text.len() {
            let Some(relative) = text[position..].find('$') else {
                output.push_str(&text[position..]);
                break;
            };
            let reference_start = position + relative;
            output.push_str(&text[position..reference_start]);
            let after_dollar = text.as_bytes().get(reference_start + 1).copied();
            if after_dollar == Some(b'!') {
                return Err(VtlError::Unsupported("quiet references".into()));
            }
            if !after_dollar
                .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_' || byte == b'{')
            {
                output.push('$');
                position = reference_start + 1;
                continue;
            }
            let mut parser = ExpressionParser::new(&text[reference_start..]);
            let reference = parser.parse_reference()?;
            let value = self.evaluate_reference(&reference)?;
            output.push_str(&render_value(&value));
            position = reference_start + parser.position;
        }
        Ok(())
    }

    fn evaluate(&mut self, expression: &Expr) -> Result<Value, VtlError> {
        match expression {
            Expr::Literal(value) => Ok(value.clone()),
            Expr::Array(values) => values
                .iter()
                .map(|value| self.evaluate(value))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            Expr::Object(entries) => {
                let mut object = Map::new();
                for (key, value) in entries {
                    object.insert(key.clone(), self.evaluate(value)?);
                }
                Ok(Value::Object(object))
            }
            Expr::Reference(reference) => self.evaluate_reference(reference),
            Expr::UnaryNot(inner) => Ok(Value::Bool(!truthy(&self.evaluate(inner)?))),
            Expr::Binary(left, BinaryOp::Or, right) => {
                if truthy(&self.evaluate(left)?) {
                    Ok(Value::Bool(true))
                } else {
                    Ok(Value::Bool(truthy(&self.evaluate(right)?)))
                }
            }
            Expr::Binary(left, BinaryOp::And, right) => {
                if !truthy(&self.evaluate(left)?) {
                    Ok(Value::Bool(false))
                } else {
                    Ok(Value::Bool(truthy(&self.evaluate(right)?)))
                }
            }
            Expr::Binary(left, operation, right) => {
                let left = self.evaluate(left)?;
                let right = self.evaluate(right)?;
                Ok(Value::Bool(compare_values(&left, *operation, &right)?))
            }
        }
    }

    fn evaluate_reference(&mut self, reference: &Reference) -> Result<Value, VtlError> {
        match reference.root.as_str() {
            "input" => self.evaluate_input(&reference.segments),
            "util" => self.evaluate_util(&reference.segments),
            "context" => {
                let value = map_from_btree(self.context.context.values);
                self.apply_segments(value, &reference.segments)
            }
            "stageVariables" => {
                let value = string_map_value(self.context.stage_variables);
                self.apply_segments(value, &reference.segments)
            }
            root => {
                let value =
                    self.variables.get(root).cloned().ok_or_else(|| {
                        VtlError::Unsupported(format!("reference root `${root}`"))
                    })?;
                self.apply_segments(value, &reference.segments)
            }
        }
    }

    fn evaluate_input(&mut self, segments: &[RefSegment]) -> Result<Value, VtlError> {
        let Some((first, remaining)) = segments.split_first() else {
            return Err(VtlError::Unsupported("bare `$input` reference".into()));
        };
        let value = match first {
            RefSegment::Property(name) if name == "body" => {
                Value::String(self.context.input.body.to_owned())
            }
            RefSegment::Call(name, arguments) if name == "json" || name == "path" => {
                require_arity(name, arguments, 1)?;
                let path = value_as_string(&self.evaluate(&arguments[0])?);
                let body: Value =
                    serde_json::from_str(self.context.input.body).map_err(|error| {
                        VtlError::Evaluation(format!("invalid JSON input: {error}"))
                    })?;
                let selected = select_json_path(&body, &path)?
                    .cloned()
                    .unwrap_or(Value::Null);
                if name == "json" {
                    Value::String(serde_json::to_string(&selected).map_err(|error| {
                        VtlError::Evaluation(format!(
                            "could not serialize JSON path result: {error}"
                        ))
                    })?)
                } else {
                    selected
                }
            }
            RefSegment::Call(name, arguments) if name == "params" => {
                if arguments.len() > 1 {
                    return Err(VtlError::Evaluation(
                        "$input.params accepts zero or one argument".into(),
                    ));
                }
                if let Some(argument) = arguments.first() {
                    let name = value_as_string(&self.evaluate(argument)?);
                    Value::String(self.find_parameter(&name).unwrap_or_default())
                } else {
                    object_value([
                        (
                            "querystring",
                            string_map_value(self.context.input.querystring),
                        ),
                        ("path", string_map_value(self.context.input.path)),
                        ("header", string_map_value(self.context.input.header)),
                    ])
                }
            }
            RefSegment::Property(name) | RefSegment::Call(name, _) => {
                return Err(VtlError::Unsupported(format!("$input.{name}")));
            }
            RefSegment::Index(_) => {
                return Err(VtlError::Unsupported("index directly on `$input`".into()));
            }
        };
        self.apply_segments(value, remaining)
    }

    fn evaluate_util(&mut self, segments: &[RefSegment]) -> Result<Value, VtlError> {
        let [RefSegment::Call(name, arguments), remaining @ ..] = segments else {
            return Err(VtlError::Unsupported(
                "`$util` must be followed by a supported method".into(),
            ));
        };
        require_arity(name, arguments, 1)?;
        let argument = self.evaluate(&arguments[0])?;
        let value = match name.as_str() {
            "escapeJavaScript" => Value::String(escape_javascript(&value_as_string(&argument))),
            "urlEncode" => Value::String(url_encode(&value_as_string(&argument))),
            "urlDecode" => Value::String(url_decode(&value_as_string(&argument))?),
            "base64Encode" => Value::String(
                base64::engine::general_purpose::STANDARD.encode(value_as_string(&argument)),
            ),
            "base64Decode" => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(value_as_string(&argument))
                    .map_err(|error| VtlError::Evaluation(format!("invalid base64: {error}")))?;
                Value::String(
                    String::from_utf8(bytes)
                        .map_err(|_| VtlError::Evaluation("decoded base64 is not UTF-8".into()))?,
                )
            }
            "parseJson" => serde_json::from_str(&value_as_string(&argument))
                .map_err(|error| VtlError::Evaluation(format!("invalid JSON: {error}")))?,
            _ => return Err(VtlError::Unsupported(format!("$util.{name}"))),
        };
        self.apply_segments(value, remaining)
    }

    fn apply_segments(
        &mut self,
        mut value: Value,
        segments: &[RefSegment],
    ) -> Result<Value, VtlError> {
        for segment in segments {
            value = match segment {
                RefSegment::Property(name) => match value {
                    Value::Object(object) => object.get(name).cloned().unwrap_or_default(),
                    Value::Null => Value::Null,
                    other => {
                        return Err(VtlError::Evaluation(format!(
                            "cannot read property `{name}` from {}",
                            value_kind(&other)
                        )));
                    }
                },
                RefSegment::Index(expression) => {
                    let index = self.evaluate(expression)?;
                    match (value, index) {
                        (Value::Array(values), Value::Number(index)) => index
                            .as_u64()
                            .and_then(|index| values.get(index as usize).cloned())
                            .unwrap_or_default(),
                        (Value::Object(object), Value::String(key)) => {
                            object.get(&key).cloned().unwrap_or_default()
                        }
                        (Value::Null, _) => Value::Null,
                        (other, _) => {
                            return Err(VtlError::Evaluation(format!(
                                "cannot index {} with that value",
                                value_kind(&other)
                            )));
                        }
                    }
                }
                RefSegment::Call(name, _) => {
                    return Err(VtlError::Unsupported(format!("method `{name}` on a value")));
                }
            };
        }
        Ok(value)
    }

    fn find_parameter(&self, name: &str) -> Option<String> {
        self.context
            .input
            .querystring
            .get(name)
            .or_else(|| self.context.input.path.get(name))
            .or_else(|| self.context.input.header.get(name))
            .or_else(|| {
                self.context
                    .input
                    .header
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value)
            })
            .cloned()
    }
}

fn restore_variable(variables: &mut BTreeMap<String, Value>, name: &str, previous: Option<Value>) {
    if let Some(value) = previous {
        variables.insert(name.to_owned(), value);
    } else {
        variables.remove(name);
    }
}

fn require_arity(name: &str, arguments: &[Expr], expected: usize) -> Result<(), VtlError> {
    if arguments.len() == expected {
        Ok(())
    } else {
        Err(VtlError::Evaluation(format!(
            "{name} expects {expected} argument(s), got {}",
            arguments.len()
        )))
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        Value::Number(_) => true,
    }
}

fn compare_values(left: &Value, operation: BinaryOp, right: &Value) -> Result<bool, VtlError> {
    match operation {
        BinaryOp::Equal => Ok(left == right),
        BinaryOp::NotEqual => Ok(left != right),
        BinaryOp::Less | BinaryOp::LessEqual | BinaryOp::Greater | BinaryOp::GreaterEqual => {
            let ordering = match (left, right) {
                (Value::Number(left), Value::Number(right)) => left
                    .as_f64()
                    .and_then(|left| right.as_f64().and_then(|right| left.partial_cmp(&right))),
                (Value::String(left), Value::String(right)) => Some(left.cmp(right)),
                _ => None,
            }
            .ok_or_else(|| {
                VtlError::Evaluation("ordered comparison requires two numbers or strings".into())
            })?;
            Ok(match operation {
                BinaryOp::Less => ordering.is_lt(),
                BinaryOp::LessEqual => ordering.is_le(),
                BinaryOp::Greater => ordering.is_gt(),
                BinaryOp::GreaterEqual => ordering.is_ge(),
                _ => unreachable!(),
            })
        }
        BinaryOp::Or | BinaryOp::And => unreachable!(),
    }
}

fn select_json_path<'a>(root: &'a Value, path: &str) -> Result<Option<&'a Value>, VtlError> {
    if !path.starts_with('$') {
        return Err(VtlError::Unsupported(format!(
            "JSONPath `{path}` must start with `$`"
        )));
    }
    let bytes = path.as_bytes();
    let mut position = 1;
    let mut current = Some(root);
    while position < bytes.len() {
        match bytes[position] {
            b'.' => {
                position += 1;
                let start = position;
                while position < bytes.len() && !matches!(bytes[position], b'.' | b'[' | b']') {
                    position += 1;
                }
                if start == position || path[start..position].contains('*') {
                    return Err(VtlError::Unsupported(format!("JSONPath `{path}`")));
                }
                let key = &path[start..position];
                current = current.and_then(|value| value.as_object()?.get(key));
            }
            b'[' => {
                position += 1;
                if position >= bytes.len() {
                    return Err(VtlError::Parse(format!("unterminated JSONPath `{path}`")));
                }
                if matches!(bytes[position], b'\'' | b'"') {
                    let quote = bytes[position];
                    position += 1;
                    let start = position;
                    while position < bytes.len() && bytes[position] != quote {
                        if bytes[position] == b'\\' {
                            return Err(VtlError::Unsupported(format!(
                                "escaped JSONPath property in `{path}`"
                            )));
                        }
                        position += 1;
                    }
                    if position >= bytes.len() {
                        return Err(VtlError::Parse(format!(
                            "unterminated JSONPath property in `{path}`"
                        )));
                    }
                    let key = &path[start..position];
                    position += 1;
                    if bytes.get(position) != Some(&b']') {
                        return Err(VtlError::Parse(format!("invalid JSONPath `{path}`")));
                    }
                    position += 1;
                    current = current.and_then(|value| value.as_object()?.get(key));
                } else {
                    let start = position;
                    while position < bytes.len() && bytes[position].is_ascii_digit() {
                        position += 1;
                    }
                    if start == position || bytes.get(position) != Some(&b']') {
                        return Err(VtlError::Unsupported(format!("JSONPath `{path}`")));
                    }
                    let index = path[start..position]
                        .parse::<usize>()
                        .map_err(|_| VtlError::Parse(format!("invalid JSONPath `{path}`")))?;
                    position += 1;
                    current = current.and_then(|value| value.as_array()?.get(index));
                }
            }
            _ => return Err(VtlError::Unsupported(format!("JSONPath `{path}`"))),
        }
    }
    Ok(current)
}

fn escape_javascript(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\'' => output.push_str("\\'"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            character if character <= '\u{001f}' => {
                use fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output
}

fn url_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else {
            use fmt::Write as _;
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

fn url_decode(value: &str) -> Result<String, VtlError> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut position = 0;
    while position < bytes.len() {
        match bytes[position] {
            b'%' => {
                if position + 2 >= bytes.len() {
                    return Err(VtlError::Evaluation("incomplete percent escape".into()));
                }
                let high = decode_hex(bytes[position + 1])?;
                let low = decode_hex(bytes[position + 2])?;
                output.push((high << 4) | low);
                position += 3;
            }
            b'+' => {
                output.push(b' ');
                position += 1;
            }
            byte => {
                output.push(byte);
                position += 1;
            }
        }
    }
    String::from_utf8(output)
        .map_err(|_| VtlError::Evaluation("URL-decoded value is not UTF-8".into()))
}

fn decode_hex(byte: u8) -> Result<u8, VtlError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(VtlError::Evaluation("invalid percent escape".into())),
    }
}

fn render_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn value_as_string(value: &Value) -> String {
    render_value(value)
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn string_map_value(values: &BTreeMap<String, String>) -> Value {
    Value::Object(
        values
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect(),
    )
}

fn map_from_btree(values: &BTreeMap<String, Value>) -> Value {
    Value::Object(
        values
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

fn object_value<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn maps<const N: usize>(entries: [(&str, &str); N]) -> BTreeMap<String, String> {
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect()
    }

    fn evaluate_template(
        template: &str,
        body: &str,
        query: &BTreeMap<String, String>,
        path: &BTreeMap<String, String>,
        headers: &BTreeMap<String, String>,
        context_values: &BTreeMap<String, Value>,
        stage_variables: &BTreeMap<String, String>,
    ) -> Result<EvaluatedTemplate, VtlError> {
        let context = VtlContext {
            input: InputBinding {
                body,
                querystring: query,
                path,
                header: headers,
            },
            util: UtilBinding,
            context: ContextBinding {
                values: context_values,
            },
            stage_variables,
        };
        VtlEngine::new().evaluate(template, &context)
    }

    fn evaluate(
        template: &str,
        body: &str,
        query: &BTreeMap<String, String>,
        path: &BTreeMap<String, String>,
        headers: &BTreeMap<String, String>,
        context_values: &BTreeMap<String, Value>,
        stage_variables: &BTreeMap<String, String>,
    ) -> Result<String, VtlError> {
        evaluate_template(
            template,
            body,
            query,
            path,
            headers,
            context_values,
            stage_variables,
        )
        .map(|result| result.output)
    }

    fn empty_values() -> BTreeMap<String, Value> {
        BTreeMap::new()
    }

    #[test]
    fn resolves_input_context_stage_variables_and_missing_values() {
        let query = maps([("id", "query")]);
        let path = maps([("id", "path")]);
        let headers = maps([("X-Name", "header")]);
        let context = BTreeMap::from([
            ("requestId".into(), json!("request-1")),
            ("identity".into(), json!({"sourceIp": "127.0.0.1"})),
        ]);
        let stage = maps([("target", "orders")]);

        let output = evaluate(
            "$input.body|$input.json('$.name')|$input.path('$.items')[1].id|\
             $input.params('id')|$input.params('x-name')|${context.requestId}|\
             $context.identity.sourceIp|$stageVariables.target|$stageVariables.missing",
            r#"{"name":"Ada","items":[{"id":1},{"id":2}]}"#,
            &query,
            &path,
            &headers,
            &context,
            &stage,
        )
        .unwrap();

        assert_eq!(
            output,
            concat!(
                r#"{"name":"Ada","items":[{"id":1},{"id":2}]}"#,
                "|\"Ada\"|2|query|header|request-1|127.0.0.1|orders|"
            )
        );
    }

    #[test]
    fn set_conditionals_and_foreach_are_nested_and_deterministic() {
        let template = "#set($limit = 2)#if($limit == 1)one\
#elseif($limit >= 2 && $limit < 3)#foreach($item in $input.path('$.items'))\
#if($item.enabled)$item.name#if($foreach.hasNext),#end#end#end#elseother#end";
        let body = r#"{"items":[{"name":"a","enabled":true},{"name":"b","enabled":false}]}"#;
        let empty = maps([]);
        let values = empty_values();

        let first = evaluate(template, body, &empty, &empty, &empty, &values, &empty).unwrap();
        let second = evaluate(template, body, &empty, &empty, &empty, &values, &empty).unwrap();

        assert_eq!(first, "a,");
        assert_eq!(first, second);
    }

    #[test]
    fn captures_response_status_override_without_changing_output() {
        let empty = maps([]);
        let values = empty_values();

        let result = evaluate_template(
            "#set($context.responseOverride.status = 201)created",
            "",
            &empty,
            &empty,
            &empty,
            &values,
            &empty,
        )
        .unwrap();

        assert_eq!(result.output, "created");
        assert_eq!(result.status_override, Some(201));
        assert!(result.header_overrides.is_empty());
    }

    #[test]
    fn captures_response_header_overrides_with_rendered_values() {
        let query = maps([("trace", "request-1")]);
        let empty = maps([]);
        let values = empty_values();

        let result = evaluate_template(
            "#set($trace = $input.params('trace'))\
#set($context.responseOverride.header.X-Trace = $trace)\
#set($context.responseOverride.header.Content_Type = 'json')ok",
            "",
            &query,
            &empty,
            &empty,
            &values,
            &empty,
        )
        .unwrap();

        assert_eq!(result.output, "ok");
        assert_eq!(result.status_override, None);
        assert_eq!(
            result.header_overrides,
            maps([("Content_Type", "json"), ("X-Trace", "request-1")])
        );
    }

    #[test]
    fn params_without_name_are_grouped_in_stable_key_order() {
        let query = maps([("q", "1")]);
        let path = maps([("p", "2")]);
        let headers = maps([("H", "3")]);
        let values = empty_values();
        let empty = maps([]);

        let output = evaluate(
            "$input.params()",
            "",
            &query,
            &path,
            &headers,
            &values,
            &empty,
        )
        .unwrap();

        assert_eq!(
            serde_json::from_str::<Value>(&output).unwrap(),
            json!({"querystring":{"q":"1"},"path":{"p":"2"},"header":{"H":"3"}})
        );
    }

    #[test]
    fn utility_functions_transform_values() {
        let empty = maps([]);
        let values = empty_values();
        let template = concat!(
            "$util.escapeJavaScript(\"a'b\\n\")|",
            "$util.urlEncode('a b/ñ')|",
            "$util.urlDecode('a%20b%2F%C3%B1')|",
            "$util.base64Encode('hello')|",
            "$util.base64Decode('aGVsbG8=')|",
            "$util.parseJson('{\"items\":[7]}').items[0]"
        );

        let output = evaluate(template, "", &empty, &empty, &empty, &values, &empty).unwrap();

        assert_eq!(output, "a\\'b\\n|a%20b%2F%C3%B1|a b/ñ|aGVsbG8=|hello|7");
    }

    #[test]
    fn selects_content_type_case_insensitively_then_json_fallback() {
        let engine = VtlEngine::new();
        let templates = BTreeMap::from([
            ("application/json".into(), "json".into()),
            ("text/plain".into(), "text".into()),
        ]);

        assert_eq!(
            engine.select_template(&templates, Some("Text/Plain; charset=utf-8")),
            Some("text")
        );
        assert_eq!(
            engine.select_template(&templates, Some("application/xml")),
            Some("json")
        );
        assert_eq!(engine.select_template(&BTreeMap::new(), None), None);
    }

    #[test]
    fn rejects_unknown_directives_references_methods_and_jsonpath() {
        let empty = maps([]);
        let values = empty_values();
        for template in [
            "#macro(x)y#end",
            "$request.body",
            "$util.toJson('x')",
            "$input.path('$..name')",
            "$!context.requestId",
            "## comment",
        ] {
            assert!(matches!(
                evaluate(template, "{}", &empty, &empty, &empty, &values, &empty),
                Err(VtlError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn malformed_templates_and_invalid_utility_input_are_errors() {
        let empty = maps([]);
        let values = empty_values();

        assert!(matches!(
            evaluate("#if(true)x", "", &empty, &empty, &empty, &values, &empty),
            Err(VtlError::Parse(_))
        ));
        assert!(matches!(
            evaluate(
                "$util.base64Decode('%%%')",
                "",
                &empty,
                &empty,
                &empty,
                &values,
                &empty,
            ),
            Err(VtlError::Evaluation(_))
        ));
    }
}
