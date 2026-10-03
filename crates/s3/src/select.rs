//! Minimal S3 Select engine for CSV and JSON objects.

use std::cmp::Ordering;
use std::collections::HashMap;

use bytes::Bytes;
use quick_xml::events::Event;
use quick_xml::Reader;
use serde_json::{Map, Number, Value};

use crate::error::S3Error;

type Result<T> = std::result::Result<T, S3Error>;

/// Executes a `SelectObjectContentRequest` against an object and returns an AWS event stream.
pub fn execute(request_xml: &[u8], object: &[u8]) -> Result<Bytes> {
    let request = Request::parse(request_xml).map_err(map_request_error)?;
    let query = Parser::new(&request.expression)
        .and_then(Parser::parse)
        .map_err(map_expression_error)?;
    let records = parse_input(object, &request.input)
        .map_err(|error| map_input_error(error, &request.input))?;
    let mut output = Vec::new();
    let mut emitted = 0_u64;

    for record in &records {
        if query.limit == Some(emitted) {
            break;
        }
        if query
            .filter
            .as_ref()
            .map(|expr| truthy(&eval(expr, record, &query.alias)))
            .unwrap_or(true)
        {
            serialize_projection(&query, record, &request.output, &mut output)?;
            emitted += 1;
        }
    }

    let mut stream = Vec::new();
    append_message(
        &mut stream,
        "Records",
        Some("application/octet-stream"),
        &output,
    )?;
    let stats = format!(
        "<Stats><Details><BytesScanned>{}</BytesScanned><BytesProcessed>{}</BytesProcessed><BytesReturned>{}</BytesReturned></Details></Stats>",
        object.len(), object.len(), output.len()
    );
    append_message(&mut stream, "Stats", Some("text/xml"), stats.as_bytes())?;
    append_message(&mut stream, "End", None, &[])?;
    Ok(Bytes::from(stream))
}

#[derive(Debug)]
struct Request {
    expression: String,
    input: Input,
    output: Output,
}

#[derive(Debug)]
enum Input {
    Csv(CsvInput),
    Json(JsonInput),
}

#[derive(Debug)]
struct CsvInput {
    field: String,
    record: String,
    quote: u8,
    header: HeaderMode,
}

#[derive(Debug, Clone, Copy)]
enum HeaderMode {
    Use,
    Ignore,
    None,
}

#[derive(Debug)]
struct JsonInput {
    lines: bool,
}

#[derive(Debug)]
enum Output {
    Csv(CsvOutput),
    Json { record: String },
}

#[derive(Debug)]
struct CsvOutput {
    field: String,
    record: String,
    quote: u8,
    always_quote: bool,
}

impl Request {
    fn parse(xml: &[u8]) -> Result<Self> {
        let root = parse_xml(xml)?;
        if root.name != "SelectObjectContentRequest" {
            return invalid("expected SelectObjectContentRequest as the XML root");
        }
        root.ensure_children(&[
            "Expression",
            "ExpressionType",
            "InputSerialization",
            "OutputSerialization",
            "RequestProgress",
        ])?;
        let expression = root.required_text("Expression")?;
        if !root
            .required_text("ExpressionType")?
            .eq_ignore_ascii_case("SQL")
        {
            return invalid("ExpressionType must be SQL");
        }
        if let Some(progress) = root.optional("RequestProgress")? {
            progress.ensure_children(&["Enabled"])?;
            let enabled = progress.required_text("Enabled")?;
            if enabled != "true" && enabled != "false" {
                return invalid("RequestProgress.Enabled must be true or false");
            }
        }
        Ok(Self {
            expression,
            input: parse_input_config(root.required("InputSerialization")?)?,
            output: parse_output_config(root.required("OutputSerialization")?)?,
        })
    }
}

fn parse_input_config(node: &Node) -> Result<Input> {
    node.ensure_children(&["CSV", "JSON", "CompressionType"])?;
    if let Some(compression) = node.optional_text("CompressionType")? {
        if !compression.eq_ignore_ascii_case("NONE") {
            return invalid("compressed S3 Select input is not supported");
        }
    }
    match (node.optional("CSV")?, node.optional("JSON")?) {
        (Some(csv), None) => Ok(Input::Csv(parse_csv_input(csv)?)),
        (None, Some(json)) => Ok(Input::Json(parse_json_input(json)?)),
        _ => invalid("InputSerialization must contain exactly one of CSV or JSON"),
    }
}

fn parse_csv_input(node: &Node) -> Result<CsvInput> {
    node.ensure_children(&[
        "FileHeaderInfo",
        "FieldDelimiter",
        "RecordDelimiter",
        "QuoteCharacter",
    ])?;
    let header = match node
        .optional_text("FileHeaderInfo")?
        .unwrap_or_else(|| "NONE".to_owned())
        .to_ascii_uppercase()
        .as_str()
    {
        "USE" => HeaderMode::Use,
        "IGNORE" => HeaderMode::Ignore,
        "NONE" => HeaderMode::None,
        _ => return invalid("FileHeaderInfo must be USE, IGNORE, or NONE"),
    };
    Ok(CsvInput {
        field: delimiter(node.optional_text("FieldDelimiter")?, ",", "FieldDelimiter")?,
        record: delimiter(
            node.optional_text("RecordDelimiter")?,
            "\n",
            "RecordDelimiter",
        )?,
        quote: quote_byte(
            node.optional_text("QuoteCharacter")?,
            b'"',
            "QuoteCharacter",
        )?,
        header,
    })
}

fn parse_json_input(node: &Node) -> Result<JsonInput> {
    node.ensure_children(&["Type"])?;
    let kind = node.required_text("Type")?;
    match kind.to_ascii_uppercase().as_str() {
        "DOCUMENT" => Ok(JsonInput { lines: false }),
        "LINES" => Ok(JsonInput { lines: true }),
        _ => invalid("JSON Type must be DOCUMENT or LINES"),
    }
}

fn parse_output_config(node: &Node) -> Result<Output> {
    node.ensure_children(&["CSV", "JSON"])?;
    match (node.optional("CSV")?, node.optional("JSON")?) {
        (Some(csv), None) => {
            csv.ensure_children(&[
                "FieldDelimiter",
                "RecordDelimiter",
                "QuoteCharacter",
                "QuoteFields",
            ])?;
            let quote_fields = csv
                .optional_text("QuoteFields")?
                .unwrap_or_else(|| "ASNEEDED".to_owned());
            let always_quote = match quote_fields.to_ascii_uppercase().as_str() {
                "ALWAYS" => true,
                "ASNEEDED" => false,
                _ => return invalid("CSV QuoteFields must be ALWAYS or ASNEEDED"),
            };
            Ok(Output::Csv(CsvOutput {
                field: delimiter(csv.optional_text("FieldDelimiter")?, ",", "FieldDelimiter")?,
                record: delimiter(
                    csv.optional_text("RecordDelimiter")?,
                    "\n",
                    "RecordDelimiter",
                )?,
                quote: quote_byte(csv.optional_text("QuoteCharacter")?, b'"', "QuoteCharacter")?,
                always_quote,
            }))
        }
        (None, Some(json)) => {
            json.ensure_children(&["RecordDelimiter"])?;
            Ok(Output::Json {
                record: delimiter(
                    json.optional_text("RecordDelimiter")?,
                    "\n",
                    "RecordDelimiter",
                )?,
            })
        }
        _ => invalid("OutputSerialization must contain exactly one of CSV or JSON"),
    }
}

fn delimiter(value: Option<String>, default: &str, name: &str) -> Result<String> {
    let value = value.unwrap_or_else(|| default.to_owned());
    if value.is_empty() {
        return invalid(&format!("{name} must not be empty"));
    }
    Ok(value)
}

fn quote_byte(value: Option<String>, default: u8, name: &str) -> Result<u8> {
    let value = value.unwrap_or_else(|| char::from(default).to_string());
    if value.len() != 1 || !value.is_ascii() {
        return invalid(&format!("{name} must be one ASCII character"));
    }
    Ok(value.as_bytes()[0])
}

#[derive(Debug)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn ensure_children(&self, allowed: &[&str]) -> Result<()> {
        if !self.text.trim().is_empty() {
            return invalid(&format!("unexpected text in {}", self.name));
        }
        for child in &self.children {
            if !allowed.contains(&child.name.as_str()) {
                return invalid(&format!("unexpected XML element {}", child.name));
            }
        }
        Ok(())
    }

    fn optional(&self, name: &str) -> Result<Option<&Node>> {
        let mut matching = self.children.iter().filter(|child| child.name == name);
        let first = matching.next();
        if matching.next().is_some() {
            return invalid(&format!("duplicate XML element {name}"));
        }
        Ok(first)
    }

    fn required(&self, name: &str) -> Result<&Node> {
        self.optional(name)?
            .ok_or_else(|| S3Error::InvalidRequest(format!("missing XML element {name}")))
    }

    fn optional_text(&self, name: &str) -> Result<Option<String>> {
        self.optional(name)?.map(Node::leaf_text).transpose()
    }

    fn required_text(&self, name: &str) -> Result<String> {
        self.required(name)?.leaf_text()
    }

    fn leaf_text(&self) -> Result<String> {
        if !self.children.is_empty() {
            return invalid(&format!("{} must contain only text", self.name));
        }
        Ok(self.text.clone())
    }
}

fn parse_xml(xml: &[u8]) -> Result<Node> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(event)) => {
                validate_attributes(&event, stack.is_empty() && root.is_none())?;
                let name = xml_name(event.name().as_ref())?;
                stack.push(Node {
                    name,
                    text: String::new(),
                    children: Vec::new(),
                });
            }
            Ok(Event::Empty(event)) => {
                validate_attributes(&event, stack.is_empty() && root.is_none())?;
                let node = Node {
                    name: xml_name(event.name().as_ref())?,
                    text: String::new(),
                    children: Vec::new(),
                };
                attach_node(node, &mut stack, &mut root)?;
            }
            Ok(Event::Text(event)) => {
                let parent = stack
                    .last_mut()
                    .ok_or_else(|| S3Error::InvalidRequest("text outside XML root".to_owned()))?;
                let text = quick_xml::escape::unescape(event.as_ref()).map_err(|error| {
                    S3Error::InvalidRequest(format!("invalid XML text: {error}"))
                })?;
                parent.text.push_str(&text);
            }
            Ok(Event::CData(event)) => {
                let parent = stack
                    .last_mut()
                    .ok_or_else(|| S3Error::InvalidRequest("CDATA outside XML root".to_owned()))?;
                let text = event.as_ref();
                parent.text.push_str(text);
            }
            Ok(Event::End(event)) => {
                let node = stack
                    .pop()
                    .ok_or_else(|| S3Error::InvalidRequest("unbalanced XML end tag".to_owned()))?;
                if node.name != xml_name(event.name().as_ref())? {
                    return invalid("mismatched XML end tag");
                }
                attach_node(node, &mut stack, &mut root)?;
            }
            Ok(Event::Decl(_)) => {
                if root.is_some() || !stack.is_empty() {
                    return invalid("XML declaration must precede the root element");
                }
            }
            Ok(Event::Comment(_)) => {}
            Ok(Event::Eof) => break,
            Ok(_) => return invalid("unsupported XML construct in SelectObjectContentRequest"),
            Err(error) => return invalid(&format!("malformed XML: {error}")),
        }
        buffer.clear();
    }
    if !stack.is_empty() {
        return invalid("unclosed XML element");
    }
    root.ok_or_else(|| S3Error::InvalidRequest("empty XML request".to_owned()))
}

fn validate_attributes(event: &quick_xml::events::BytesStart<'_>, root: bool) -> Result<()> {
    for attribute in event.attributes().with_checks(true) {
        let attribute = attribute
            .map_err(|error| S3Error::InvalidRequest(format!("invalid XML attribute: {error}")))?;
        let key = attribute.key.as_ref();
        if !(root && (key == "xmlns" || key.starts_with("xmlns:"))) {
            return invalid("XML attributes are not allowed in SelectObjectContentRequest");
        }
    }
    Ok(())
}

fn xml_name(name: &str) -> Result<String> {
    if name.contains(':') {
        return invalid("prefixed XML elements are not supported");
    }
    Ok(name.to_owned())
}

fn attach_node(node: Node, stack: &mut [Node], root: &mut Option<Node>) -> Result<()> {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else if root.replace(node).is_some() {
        return invalid("XML request must have exactly one root element");
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(S3Error::InvalidRequest(message.to_owned()))
}

fn invalid_message(error: S3Error) -> String {
    match error {
        S3Error::InvalidRequest(message) => message,
        other => other.to_string(),
    }
}

fn map_request_error(error: S3Error) -> S3Error {
    S3Error::InvalidRequestParameter(invalid_message(error))
}

fn map_expression_error(error: S3Error) -> S3Error {
    let message = invalid_message(error);
    if message.contains("not supported") || message.contains("unsupported") {
        S3Error::UnsupportedSqlOperation(message)
    } else {
        S3Error::InvalidExpression(message)
    }
}

fn map_input_error(error: S3Error, input: &Input) -> S3Error {
    let message = invalid_message(error);
    match input {
        Input::Csv(_) => S3Error::CsvParsingError(message),
        Input::Json(_) => S3Error::JsonParsingError(message),
    }
}

#[derive(Debug)]
struct Record {
    value: Value,
    fields: Vec<Value>,
    named: HashMap<String, Value>,
}

fn parse_input(object: &[u8], input: &Input) -> Result<Vec<Record>> {
    match input {
        Input::Csv(config) => parse_csv(object, config),
        Input::Json(config) => parse_json(object, config),
    }
}

fn parse_csv(object: &[u8], config: &CsvInput) -> Result<Vec<Record>> {
    let text = std::str::from_utf8(object)
        .map_err(|_| S3Error::InvalidRequest("CSV input must be UTF-8".to_owned()))?;
    if config.field == config.record {
        return invalid("CSV field and record delimiters must differ");
    }
    let rows = split_csv(text.as_bytes(), config)?;
    let (headers, start) = match config.header {
        HeaderMode::Use => {
            let row = rows
                .first()
                .ok_or_else(|| S3Error::InvalidRequest("CSV header row is missing".to_owned()))?;
            (Some(row.clone()), 1)
        }
        HeaderMode::Ignore => (None, usize::from(!rows.is_empty())),
        HeaderMode::None => (None, 0),
    };
    let mut records = Vec::new();
    for row in rows.into_iter().skip(start) {
        let fields: Vec<Value> = row.into_iter().map(Value::String).collect();
        let mut named = HashMap::new();
        if let Some(headers) = &headers {
            for (index, header) in headers.iter().enumerate() {
                named.insert(
                    header.clone(),
                    fields.get(index).cloned().unwrap_or(Value::Null),
                );
            }
        }
        records.push(Record {
            value: Value::Array(fields.clone()),
            fields,
            named,
        });
    }
    Ok(records)
}

fn split_csv(bytes: &[u8], config: &CsvInput) -> Result<Vec<Vec<String>>> {
    let field_delimiter = config.field.as_bytes();
    let record_delimiter = config.record.as_bytes();
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = Vec::new();
    let mut index = 0;
    let mut quoted = false;
    let mut closed_quote = false;
    let mut touched = false;

    while index < bytes.len() {
        if quoted {
            if bytes[index] == config.quote {
                if bytes.get(index + 1) == Some(&config.quote) {
                    field.push(config.quote);
                    index += 2;
                } else {
                    quoted = false;
                    closed_quote = true;
                    index += 1;
                }
            } else {
                field.push(bytes[index]);
                index += 1;
            }
        } else if bytes[index..].starts_with(field_delimiter) {
            push_csv_field(&mut row, &mut field)?;
            touched = true;
            closed_quote = false;
            index += field_delimiter.len();
        } else if bytes[index..].starts_with(record_delimiter) {
            push_csv_field(&mut row, &mut field)?;
            rows.push(std::mem::take(&mut row));
            touched = false;
            closed_quote = false;
            index += record_delimiter.len();
        } else if bytes[index] == config.quote {
            if field.is_empty() && !closed_quote {
                quoted = true;
                touched = true;
                index += 1;
            } else {
                return invalid("malformed CSV: quote in an unquoted field");
            }
        } else if closed_quote {
            return invalid("malformed CSV: data follows a closing quote");
        } else {
            field.push(bytes[index]);
            touched = true;
            index += 1;
        }
    }
    if quoted {
        return invalid("malformed CSV: unterminated quoted field");
    }
    if touched || !field.is_empty() || !row.is_empty() {
        push_csv_field(&mut row, &mut field)?;
        rows.push(row);
    }
    Ok(rows)
}

fn push_csv_field(row: &mut Vec<String>, field: &mut Vec<u8>) -> Result<()> {
    let bytes = std::mem::take(field);
    let value = String::from_utf8(bytes)
        .map_err(|_| S3Error::InvalidRequest("CSV input must be UTF-8".to_owned()))?;
    row.push(value);
    Ok(())
}

fn parse_json(object: &[u8], config: &JsonInput) -> Result<Vec<Record>> {
    let text = std::str::from_utf8(object)
        .map_err(|_| S3Error::InvalidRequest("JSON input must be UTF-8".to_owned()))?;
    let values = if config.lines {
        let mut values = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            values.push(serde_json::from_str(line).map_err(|error| {
                S3Error::InvalidRequest(format!("invalid JSON on line {}: {error}", index + 1))
            })?);
        }
        values
    } else {
        let document: Value = serde_json::from_str(text)
            .map_err(|error| S3Error::InvalidRequest(format!("invalid JSON document: {error}")))?;
        match document {
            Value::Array(values) => values,
            value => vec![value],
        }
    };
    Ok(values.into_iter().map(record_from_json).collect())
}

fn record_from_json(value: Value) -> Record {
    let fields = match &value {
        Value::Object(map) => map.values().cloned().collect(),
        Value::Array(values) => values.clone(),
        value => vec![value.clone()],
    };
    let named = match &value {
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        _ => HashMap::new(),
    };
    Record {
        value,
        fields,
        named,
    }
}

#[derive(Debug)]
struct Query {
    projection: Vec<SelectItem>,
    filter: Option<Expr>,
    alias: String,
    limit: Option<u64>,
}

#[derive(Debug)]
enum SelectItem {
    Wildcard,
    Expr { expr: Expr, name: String },
}

#[derive(Debug, Clone)]
enum Expr {
    Literal(Value),
    Column {
        qualifier: Option<String>,
        name: String,
    },
    Function {
        name: String,
        args: Vec<Expr>,
    },
    Cast {
        value: Box<Expr>,
        kind: CastKind,
    },
    Not(Box<Expr>),
    Binary {
        left: Box<Expr>,
        op: BinaryOp,
        right: Box<Expr>,
    },
    Between {
        value: Box<Expr>,
        low: Box<Expr>,
        high: Box<Expr>,
        negated: bool,
    },
    In {
        value: Box<Expr>,
        choices: Vec<Expr>,
        negated: bool,
    },
    Like {
        value: Box<Expr>,
        pattern: Box<Expr>,
        negated: bool,
    },
    IsNull {
        value: Box<Expr>,
        negated: bool,
    },
}

#[derive(Debug, Clone, Copy)]
enum CastKind {
    String,
    Integer,
    Float,
    Boolean,
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

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(String),
    String(String),
    Number(String),
    Comma,
    Dot,
    Star,
    LeftParen,
    RightParen,
    Operator(String),
}

fn tokenize(sql: &str) -> Result<Vec<Token>> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => index += 1,
            b',' => {
                tokens.push(Token::Comma);
                index += 1;
            }
            b'.' => {
                tokens.push(Token::Dot);
                index += 1;
            }
            b'*' => {
                tokens.push(Token::Star);
                index += 1;
            }
            b'(' => {
                tokens.push(Token::LeftParen);
                index += 1;
            }
            b')' => {
                tokens.push(Token::RightParen);
                index += 1;
            }
            b'\'' => {
                index += 1;
                let mut value = Vec::new();
                let mut closed = false;
                while index < bytes.len() {
                    if bytes[index] == b'\'' {
                        if bytes.get(index + 1) == Some(&b'\'') {
                            value.push(b'\'');
                            index += 2;
                        } else {
                            index += 1;
                            closed = true;
                            break;
                        }
                    } else {
                        value.push(bytes[index]);
                        index += 1;
                    }
                }
                if !closed {
                    return invalid("unterminated SQL string literal");
                }
                tokens.push(Token::String(String::from_utf8(value).map_err(|_| {
                    S3Error::InvalidRequest("SQL string literals must be UTF-8".to_owned())
                })?));
            }
            b'=' | b'<' | b'>' => {
                let start = index;
                index += 1;
                if index < bytes.len()
                    && matches!(
                        (bytes[start], bytes[index]),
                        (b'<', b'=') | (b'>', b'=') | (b'<', b'>')
                    )
                {
                    index += 1;
                }
                tokens.push(Token::Operator(sql[start..index].to_owned()));
            }
            b'-' | b'0'..=b'9' => {
                let start = index;
                if bytes[index] == b'-' {
                    index += 1;
                    if index == bytes.len() || !bytes[index].is_ascii_digit() {
                        return invalid("unsupported '-' in SQL expression");
                    }
                }
                while index < bytes.len() && bytes[index].is_ascii_digit() {
                    index += 1;
                }
                if bytes.get(index) == Some(&b'.') {
                    index += 1;
                    while index < bytes.len() && bytes[index].is_ascii_digit() {
                        index += 1;
                    }
                }
                tokens.push(Token::Number(sql[start..index].to_owned()));
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$'))
                {
                    index += 1;
                }
                tokens.push(Token::Word(sql[start..index].to_owned()));
            }
            other => {
                return invalid(&format!(
                    "unsupported character '{}' in SQL expression",
                    char::from(other)
                ));
            }
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    index: usize,
}

impl Parser {
    fn new(sql: &str) -> Result<Self> {
        Ok(Self {
            tokens: tokenize(sql)?,
            index: 0,
        })
    }

    fn parse(mut self) -> Result<Query> {
        self.expect_word("SELECT")?;
        let projection = self.parse_projection()?;
        self.expect_word("FROM")?;
        let source = self.take_word()?;
        if !source.eq_ignore_ascii_case("S3Object") {
            return invalid("FROM must reference S3Object");
        }
        let alias = if self.consume_word("AS") {
            self.take_word()?
        } else if let Some(word) = self.peek_word() {
            if is_clause_or_unsupported(word) {
                "s3object".to_owned()
            } else {
                self.take_word()?
            }
        } else {
            "s3object".to_owned()
        };
        let filter = if self.consume_word("WHERE") {
            Some(self.parse_or()?)
        } else {
            None
        };
        let limit = if self.consume_word("LIMIT") {
            let value = match self.next() {
                Some(Token::Number(value)) if !value.contains('.') && !value.starts_with('-') => {
                    value
                }
                _ => return invalid("LIMIT must be a non-negative integer"),
            };
            Some(
                value
                    .parse()
                    .map_err(|_| S3Error::InvalidRequest("LIMIT is too large".to_owned()))?,
            )
        } else {
            None
        };
        if let Some(token) = self.peek() {
            let feature = match token {
                Token::Word(word) => word.to_ascii_uppercase(),
                _ => format!("{token:?}"),
            };
            return invalid(&format!("unsupported SQL syntax or feature: {feature}"));
        }
        Ok(Query {
            projection,
            filter,
            alias,
            limit,
        })
    }

    fn parse_projection(&mut self) -> Result<Vec<SelectItem>> {
        let mut items = Vec::new();
        loop {
            if self.consume(&Token::Star) {
                items.push(SelectItem::Wildcard);
            } else {
                let expr = self.parse_scalar()?;
                let name = match &expr {
                    Expr::Column { name, .. } => name.clone(),
                    _ => format!("_{}", items.len() + 1),
                };
                items.push(SelectItem::Expr { expr, name });
            }
            if !self.consume(&Token::Comma) {
                break;
            }
        }
        if items.is_empty() {
            return invalid("SELECT projection must not be empty");
        }
        Ok(items)
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut expr = self.parse_and()?;
        while self.consume_word("OR") {
            expr = Expr::Binary {
                left: Box::new(expr),
                op: BinaryOp::Or,
                right: Box::new(self.parse_and()?),
            };
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut expr = self.parse_not()?;
        while self.consume_word("AND") {
            expr = Expr::Binary {
                left: Box::new(expr),
                op: BinaryOp::And,
                right: Box::new(self.parse_not()?),
            };
        }
        Ok(expr)
    }

    fn parse_not(&mut self) -> Result<Expr> {
        if self.consume_word("NOT") {
            Ok(Expr::Not(Box::new(self.parse_not()?)))
        } else {
            self.parse_predicate()
        }
    }

    fn parse_predicate(&mut self) -> Result<Expr> {
        let value = self.parse_scalar()?;
        if let Some(operator) = self.take_operator() {
            let op = match operator.as_str() {
                "=" => BinaryOp::Equal,
                "<>" => BinaryOp::NotEqual,
                "<" => BinaryOp::Less,
                "<=" => BinaryOp::LessEqual,
                ">" => BinaryOp::Greater,
                ">=" => BinaryOp::GreaterEqual,
                _ => return invalid("unsupported comparison operator"),
            };
            return Ok(Expr::Binary {
                left: Box::new(value),
                op,
                right: Box::new(self.parse_scalar()?),
            });
        }
        if self.consume_word("IS") {
            let negated = self.consume_word("NOT");
            self.expect_word("NULL")?;
            return Ok(Expr::IsNull {
                value: Box::new(value),
                negated,
            });
        }
        let negated = self.consume_word("NOT");
        if self.consume_word("BETWEEN") {
            let low = self.parse_scalar()?;
            self.expect_word("AND")?;
            let high = self.parse_scalar()?;
            return Ok(Expr::Between {
                value: Box::new(value),
                low: Box::new(low),
                high: Box::new(high),
                negated,
            });
        }
        if self.consume_word("IN") {
            self.expect(&Token::LeftParen)?;
            if self
                .peek_word()
                .is_some_and(|word| word.eq_ignore_ascii_case("SELECT"))
            {
                return invalid("subqueries are not supported");
            }
            let mut choices = vec![self.parse_scalar()?];
            while self.consume(&Token::Comma) {
                choices.push(self.parse_scalar()?);
            }
            self.expect(&Token::RightParen)?;
            return Ok(Expr::In {
                value: Box::new(value),
                choices,
                negated,
            });
        }
        if self.consume_word("LIKE") {
            return Ok(Expr::Like {
                value: Box::new(value),
                pattern: Box::new(self.parse_scalar()?),
                negated,
            });
        }
        if negated {
            return invalid("NOT must precede BETWEEN, IN, or LIKE");
        }
        Ok(value)
    }

    fn parse_scalar(&mut self) -> Result<Expr> {
        match self.next() {
            Some(Token::String(value)) => Ok(Expr::Literal(Value::String(value))),
            Some(Token::Number(value)) => {
                let number: Number = serde_json::from_str(&value).map_err(|_| {
                    S3Error::InvalidRequest(format!("invalid numeric literal {value}"))
                })?;
                Ok(Expr::Literal(Value::Number(number)))
            }
            Some(Token::Word(word)) if word.eq_ignore_ascii_case("NULL") => {
                Ok(Expr::Literal(Value::Null))
            }
            Some(Token::Word(word)) if word.eq_ignore_ascii_case("TRUE") => {
                Ok(Expr::Literal(Value::Bool(true)))
            }
            Some(Token::Word(word)) if word.eq_ignore_ascii_case("FALSE") => {
                Ok(Expr::Literal(Value::Bool(false)))
            }
            Some(Token::Word(word)) => self.parse_word_expression(word),
            Some(Token::LeftParen) => {
                if self
                    .peek_word()
                    .is_some_and(|word| word.eq_ignore_ascii_case("SELECT"))
                {
                    return invalid("subqueries are not supported");
                }
                let expression = self.parse_or()?;
                self.expect(&Token::RightParen)?;
                Ok(expression)
            }
            Some(token) => invalid(&format!("expected SQL expression, found {token:?}")),
            None => invalid("unexpected end of SQL expression"),
        }
    }

    fn parse_word_expression(&mut self, word: String) -> Result<Expr> {
        if self.consume(&Token::LeftParen) {
            let upper = word.to_ascii_uppercase();
            if matches!(upper.as_str(), "COUNT" | "SUM" | "AVG" | "MIN" | "MAX") {
                return invalid(&format!("aggregate function {upper} is not supported"));
            }
            if upper == "CAST" {
                let value = self.parse_scalar()?;
                self.expect_word("AS")?;
                let kind_name = self.take_word()?.to_ascii_uppercase();
                let kind = match kind_name.as_str() {
                    "STRING" | "VARCHAR" | "CHAR" => CastKind::String,
                    "INT" | "INTEGER" | "BIGINT" => CastKind::Integer,
                    "FLOAT" | "DOUBLE" | "DECIMAL" => CastKind::Float,
                    "BOOL" | "BOOLEAN" => CastKind::Boolean,
                    _ => return invalid(&format!("unsupported CAST type {kind_name}")),
                };
                self.expect(&Token::RightParen)?;
                return Ok(Expr::Cast {
                    value: Box::new(value),
                    kind,
                });
            }
            if !matches!(
                upper.as_str(),
                "LOWER" | "UPPER" | "SUBSTRING" | "CHAR_LENGTH" | "TRIM"
            ) {
                return invalid(&format!("unsupported SQL function {upper}"));
            }
            let mut args = Vec::new();
            if !self.consume(&Token::RightParen) {
                args.push(self.parse_scalar()?);
                while self.consume(&Token::Comma) {
                    args.push(self.parse_scalar()?);
                }
                self.expect(&Token::RightParen)?;
            }
            let valid_arity = if upper == "SUBSTRING" {
                matches!(args.len(), 2 | 3)
            } else {
                args.len() == 1
            };
            if !valid_arity {
                return invalid(&format!("invalid argument count for {upper}"));
            }
            return Ok(Expr::Function { name: upper, args });
        }
        if self.consume(&Token::Dot) {
            let name = self.take_word()?;
            Ok(Expr::Column {
                qualifier: Some(word),
                name,
            })
        } else {
            Ok(Expr::Column {
                qualifier: None,
                name: word,
            })
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn peek_word(&self) -> Option<&str> {
        match self.peek() {
            Some(Token::Word(word)) => Some(word),
            _ => None,
        }
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.index).cloned();
        if token.is_some() {
            self.index += 1;
        }
        token
    }

    fn consume(&mut self, expected: &Token) -> bool {
        if self.peek() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        if self.consume(expected) {
            Ok(())
        } else {
            invalid(&format!("expected {expected:?}"))
        }
    }

    fn consume_word(&mut self, expected: &str) -> bool {
        if self
            .peek_word()
            .is_some_and(|word| word.eq_ignore_ascii_case(expected))
        {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect_word(&mut self, expected: &str) -> Result<()> {
        if self.consume_word(expected) {
            Ok(())
        } else {
            invalid(&format!("expected SQL keyword {expected}"))
        }
    }

    fn take_word(&mut self) -> Result<String> {
        match self.next() {
            Some(Token::Word(word)) => Ok(word),
            _ => invalid("expected SQL identifier"),
        }
    }

    fn take_operator(&mut self) -> Option<String> {
        match self.peek().cloned() {
            Some(Token::Operator(operator)) => {
                self.index += 1;
                Some(operator)
            }
            _ => None,
        }
    }
}

fn is_clause_or_unsupported(word: &str) -> bool {
    [
        "WHERE", "LIMIT", "JOIN", "GROUP", "ORDER", "HAVING", "UNION",
    ]
    .iter()
    .any(|keyword| word.eq_ignore_ascii_case(keyword))
}

fn eval(expr: &Expr, record: &Record, alias: &str) -> Value {
    match expr {
        Expr::Literal(value) => value.clone(),
        Expr::Column { qualifier, name } => {
            if qualifier.as_ref().is_some_and(|value| {
                !value.eq_ignore_ascii_case(alias)
                    && !value.eq_ignore_ascii_case("s")
                    && !value.eq_ignore_ascii_case("s3object")
            }) {
                return Value::Null;
            }
            if let Some(index) = name
                .strip_prefix('_')
                .and_then(|number| number.parse::<usize>().ok())
            {
                return index
                    .checked_sub(1)
                    .and_then(|index| record.fields.get(index))
                    .cloned()
                    .unwrap_or(Value::Null);
            }
            record
                .named
                .get(name)
                .or_else(|| {
                    record
                        .named
                        .iter()
                        .find(|(key, _)| key.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value)
                })
                .cloned()
                .unwrap_or(Value::Null)
        }
        Expr::Function { name, args } => eval_function(name, args, record, alias),
        Expr::Cast { value, kind } => cast_value(eval(value, record, alias), *kind),
        Expr::Not(value) => Value::Bool(!truthy(&eval(value, record, alias))),
        Expr::Binary { left, op, right } => {
            if matches!(op, BinaryOp::And) {
                return Value::Bool(
                    truthy(&eval(left, record, alias)) && truthy(&eval(right, record, alias)),
                );
            }
            if matches!(op, BinaryOp::Or) {
                return Value::Bool(
                    truthy(&eval(left, record, alias)) || truthy(&eval(right, record, alias)),
                );
            }
            let left = eval(left, record, alias);
            let right = eval(right, record, alias);
            Value::Bool(compare_values(&left, &right, *op))
        }
        Expr::Between {
            value,
            low,
            high,
            negated,
        } => {
            let value = eval(value, record, alias);
            let included =
                compare_values(&value, &eval(low, record, alias), BinaryOp::GreaterEqual)
                    && compare_values(&value, &eval(high, record, alias), BinaryOp::LessEqual);
            Value::Bool(if *negated { !included } else { included })
        }
        Expr::In {
            value,
            choices,
            negated,
        } => {
            let value = eval(value, record, alias);
            let included = choices.iter().any(|choice| {
                compare_values(&value, &eval(choice, record, alias), BinaryOp::Equal)
            });
            Value::Bool(if *negated { !included } else { included })
        }
        Expr::Like {
            value,
            pattern,
            negated,
        } => {
            let value = scalar_string(&eval(value, record, alias));
            let pattern = scalar_string(&eval(pattern, record, alias));
            let matched = match (value, pattern) {
                (Some(value), Some(pattern)) => like_matches(&value, &pattern),
                _ => false,
            };
            Value::Bool(if *negated { !matched } else { matched })
        }
        Expr::IsNull { value, negated } => {
            let is_null = eval(value, record, alias).is_null();
            Value::Bool(if *negated { !is_null } else { is_null })
        }
    }
}

fn eval_function(name: &str, args: &[Expr], record: &Record, alias: &str) -> Value {
    let first = eval(&args[0], record, alias);
    match name {
        "LOWER" => scalar_string(&first)
            .map(|value| Value::String(value.to_lowercase()))
            .unwrap_or(Value::Null),
        "UPPER" => scalar_string(&first)
            .map(|value| Value::String(value.to_uppercase()))
            .unwrap_or(Value::Null),
        "TRIM" => scalar_string(&first)
            .map(|value| Value::String(value.trim().to_owned()))
            .unwrap_or(Value::Null),
        "CHAR_LENGTH" => scalar_string(&first)
            .and_then(|value| u64::try_from(value.chars().count()).ok())
            .map(|length| Value::Number(Number::from(length)))
            .unwrap_or(Value::Null),
        "SUBSTRING" => {
            let Some(value) = scalar_string(&first) else {
                return Value::Null;
            };
            let start = integer_value(&eval(&args[1], record, alias)).unwrap_or(1);
            let skip = usize::try_from(start.saturating_sub(1).max(0)).unwrap_or(usize::MAX);
            let mut chars = value.chars().skip(skip);
            let result: String = if let Some(length) = args.get(2) {
                let length = integer_value(&eval(length, record, alias))
                    .unwrap_or(0)
                    .max(0);
                chars
                    .by_ref()
                    .take(usize::try_from(length).unwrap_or(usize::MAX))
                    .collect()
            } else {
                chars.collect()
            };
            Value::String(result)
        }
        _ => Value::Null,
    }
}

fn cast_value(value: Value, kind: CastKind) -> Value {
    match kind {
        CastKind::String => scalar_string(&value)
            .map(Value::String)
            .unwrap_or(Value::Null),
        CastKind::Integer => integer_value(&value)
            .map(|value| Value::Number(Number::from(value)))
            .unwrap_or(Value::Null),
        CastKind::Float => numeric_value(&value)
            .and_then(Number::from_f64)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        CastKind::Boolean => match value {
            Value::Bool(value) => Value::Bool(value),
            Value::String(value) if value.eq_ignore_ascii_case("true") => Value::Bool(true),
            Value::String(value) if value.eq_ignore_ascii_case("false") => Value::Bool(false),
            Value::Number(value) => Value::Bool(value.as_f64().unwrap_or(0.0) != 0.0),
            _ => Value::Null,
        },
    }
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::Null | Value::Array(_) | Value::Object(_) => None,
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
    }
}

fn integer_value(value: &Value) -> Option<i64> {
    match value {
        Value::Number(value) => value.as_i64().or_else(|| value.as_f64().map(|v| v as i64)),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn numeric_value(value: &Value) -> Option<f64> {
    match value {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn compare_values(left: &Value, right: &Value, operator: BinaryOp) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    let ordering = if let (Some(left), Some(right)) = (numeric_value(left), numeric_value(right)) {
        left.partial_cmp(&right)
    } else if let (Some(left), Some(right)) = (scalar_string(left), scalar_string(right)) {
        Some(left.cmp(&right))
    } else {
        None
    };
    match (operator, ordering) {
        (BinaryOp::Equal, Some(Ordering::Equal)) => true,
        (BinaryOp::NotEqual, Some(ordering)) => ordering != Ordering::Equal,
        (BinaryOp::Less, Some(Ordering::Less)) => true,
        (BinaryOp::LessEqual, Some(Ordering::Less | Ordering::Equal)) => true,
        (BinaryOp::Greater, Some(Ordering::Greater)) => true,
        (BinaryOp::GreaterEqual, Some(Ordering::Greater | Ordering::Equal)) => true,
        _ => false,
    }
}

fn truthy(value: &Value) -> bool {
    matches!(value, Value::Bool(true))
}

fn like_matches(value: &str, pattern: &str) -> bool {
    let value: Vec<char> = value.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    let mut matches = vec![vec![false; value.len() + 1]; pattern.len() + 1];
    matches[0][0] = true;
    for pattern_index in 1..=pattern.len() {
        if pattern[pattern_index - 1] == '%' {
            matches[pattern_index][0] = matches[pattern_index - 1][0];
        }
        for value_index in 1..=value.len() {
            matches[pattern_index][value_index] = match pattern[pattern_index - 1] {
                '%' => {
                    matches[pattern_index - 1][value_index]
                        || matches[pattern_index][value_index - 1]
                }
                '_' => matches[pattern_index - 1][value_index - 1],
                character => {
                    character == value[value_index - 1]
                        && matches[pattern_index - 1][value_index - 1]
                }
            };
        }
    }
    matches[pattern.len()][value.len()]
}

fn serialize_projection(
    query: &Query,
    record: &Record,
    output: &Output,
    destination: &mut Vec<u8>,
) -> Result<()> {
    match output {
        Output::Csv(config) => {
            let mut values = Vec::new();
            for item in &query.projection {
                match item {
                    SelectItem::Wildcard => values.extend(record.fields.iter().cloned()),
                    SelectItem::Expr { expr, .. } => values.push(eval(expr, record, &query.alias)),
                }
            }
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    destination.extend_from_slice(config.field.as_bytes());
                }
                write_csv_value(value, config, destination);
            }
            destination.extend_from_slice(config.record.as_bytes());
        }
        Output::Json {
            record: record_delimiter,
        } => {
            let only_wildcard = matches!(query.projection.as_slice(), [SelectItem::Wildcard]);
            let value = if only_wildcard {
                record.value.clone()
            } else {
                let mut object = Map::new();
                for item in &query.projection {
                    match item {
                        SelectItem::Wildcard => add_wildcard_fields(record, &mut object),
                        SelectItem::Expr { expr, name } => {
                            object.insert(name.clone(), eval(expr, record, &query.alias));
                        }
                    }
                }
                Value::Object(object)
            };
            let encoded = serde_json::to_vec(&value).map_err(|error| {
                S3Error::InvalidRequest(format!("could not serialize JSON result: {error}"))
            })?;
            destination.extend_from_slice(&encoded);
            destination.extend_from_slice(record_delimiter.as_bytes());
        }
    }
    Ok(())
}

fn add_wildcard_fields(record: &Record, destination: &mut Map<String, Value>) {
    if let Value::Object(object) = &record.value {
        destination.extend(object.clone());
    } else {
        for (index, value) in record.fields.iter().enumerate() {
            destination.insert(format!("_{}", index + 1), value.clone());
        }
    }
}

fn write_csv_value(value: &Value, config: &CsvOutput, destination: &mut Vec<u8>) {
    let text = scalar_string(value).unwrap_or_default();
    let quote = char::from(config.quote);
    let needs_quote = config.always_quote
        || text.contains(&config.field)
        || text.contains(&config.record)
        || text.contains(quote)
        || text.contains(['\r', '\n']);
    if needs_quote {
        destination.push(config.quote);
        for byte in text.bytes() {
            if byte == config.quote {
                destination.push(config.quote);
            }
            destination.push(byte);
        }
        destination.push(config.quote);
    } else {
        destination.extend_from_slice(text.as_bytes());
    }
}

fn append_message(
    destination: &mut Vec<u8>,
    event_type: &str,
    content_type: Option<&str>,
    payload: &[u8],
) -> Result<()> {
    let mut headers = Vec::new();
    append_header(&mut headers, ":message-type", "event")?;
    append_header(&mut headers, ":event-type", event_type)?;
    if let Some(content_type) = content_type {
        append_header(&mut headers, ":content-type", content_type)?;
    }
    let total_length = 16_usize
        .checked_add(headers.len())
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or_else(|| S3Error::InvalidRequest("S3 Select result is too large".to_owned()))?;
    let total_length_u32 = u32::try_from(total_length)
        .map_err(|_| S3Error::InvalidRequest("S3 Select result is too large".to_owned()))?;
    let headers_length = u32::try_from(headers.len())
        .map_err(|_| S3Error::InvalidRequest("event headers are too large".to_owned()))?;
    let mut message = Vec::with_capacity(total_length);
    message.extend_from_slice(&total_length_u32.to_be_bytes());
    message.extend_from_slice(&headers_length.to_be_bytes());
    message.extend_from_slice(&crc32(&message).to_be_bytes());
    message.extend_from_slice(&headers);
    message.extend_from_slice(payload);
    let checksum = crc32(&message);
    message.extend_from_slice(&checksum.to_be_bytes());
    destination.extend_from_slice(&message);
    Ok(())
}

fn append_header(destination: &mut Vec<u8>, name: &str, value: &str) -> Result<()> {
    let name_length = u8::try_from(name.len())
        .map_err(|_| S3Error::InvalidRequest("event header name is too long".to_owned()))?;
    let value_length = u16::try_from(value.len())
        .map_err(|_| S3Error::InvalidRequest("event header value is too long".to_owned()))?;
    destination.push(name_length);
    destination.extend_from_slice(name.as_bytes());
    destination.push(7); // AWS event-stream string header
    destination.extend_from_slice(&value_length.to_be_bytes());
    destination.extend_from_slice(value.as_bytes());
    Ok(())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(expression: &str, input: &str, output: &str) -> Vec<u8> {
        format!(
            "<SelectObjectContentRequest><Expression>{expression}</Expression>\
             <ExpressionType>SQL</ExpressionType><InputSerialization>{input}</InputSerialization>\
             <OutputSerialization>{output}</OutputSerialization></SelectObjectContentRequest>"
        )
        .into_bytes()
    }

    fn messages(stream: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut result = Vec::new();
        let mut offset = 0;
        while offset < stream.len() {
            let total = u32::from_be_bytes(stream[offset..offset + 4].try_into().unwrap()) as usize;
            let headers_length =
                u32::from_be_bytes(stream[offset + 4..offset + 8].try_into().unwrap()) as usize;
            let prelude_crc =
                u32::from_be_bytes(stream[offset + 8..offset + 12].try_into().unwrap());
            assert_eq!(prelude_crc, crc32(&stream[offset..offset + 8]));
            let message_crc = u32::from_be_bytes(
                stream[offset + total - 4..offset + total]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(message_crc, crc32(&stream[offset..offset + total - 4]));

            let headers_end = offset + 12 + headers_length;
            let mut cursor = offset + 12;
            let mut event_type = None;
            while cursor < headers_end {
                let name_length = usize::from(stream[cursor]);
                cursor += 1;
                let name = std::str::from_utf8(&stream[cursor..cursor + name_length]).unwrap();
                cursor += name_length;
                assert_eq!(stream[cursor], 7);
                cursor += 1;
                let value_length =
                    u16::from_be_bytes(stream[cursor..cursor + 2].try_into().unwrap()) as usize;
                cursor += 2;
                let value = std::str::from_utf8(&stream[cursor..cursor + value_length]).unwrap();
                cursor += value_length;
                if name == ":event-type" {
                    event_type = Some(value.to_owned());
                }
            }
            let payload = stream[headers_end..offset + total - 4].to_vec();
            result.push((event_type.unwrap(), payload));
            offset += total;
        }
        result
    }

    #[test]
    fn selects_csv_with_headers_functions_and_custom_output() {
        let xml = request(
            "SELECT UPPER(s.name), CAST(s.age AS INT) FROM S3Object AS s \
             WHERE CAST(s.age AS INT) BETWEEN 10 AND 20 AND s.name LIKE 'A%' LIMIT 1",
            "<CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>",
            "<CSV><FieldDelimiter>;</FieldDelimiter><RecordDelimiter>|</RecordDelimiter></CSV>",
        );
        let stream = execute(&xml, b"name,age\nAlice,10\nBob,20\n").unwrap();
        let decoded = messages(&stream);
        assert_eq!(decoded[0].0, "Records");
        assert_eq!(decoded[0].1, b"ALICE;10|");
        assert_eq!(decoded[1].0, "Stats");
        assert_eq!(decoded[2].0, "End");
    }

    #[test]
    fn selects_json_lines_to_json() {
        let xml = request(
            "SELECT s.name FROM S3Object s WHERE s.id IN (2, 3) AND s.name IS NOT NULL",
            "<JSON><Type>LINES</Type></JSON>",
            "<JSON><RecordDelimiter>|</RecordDelimiter></JSON>",
        );
        let object = br#"{"id":1,"name":"Ann"}
{"id":2,"name":"Bob"}
{"id":3,"name":null}
"#;
        let stream = execute(&xml, object).unwrap();
        let decoded = messages(&stream);
        assert_eq!(decoded[0].1, br#"{"name":"Bob"}|"#);
    }

    #[test]
    fn supports_json_document_wildcard() {
        let xml = request(
            "SELECT * FROM S3Object WHERE NOT _1 = 0",
            "<JSON><Type>DOCUMENT</Type></JSON>",
            "<JSON><RecordDelimiter>\n</RecordDelimiter></JSON>",
        );
        let stream = execute(&xml, br#"[[0,"x"],[1,"y"]]"#).unwrap();
        assert_eq!(messages(&stream)[0].1, b"[1,\"y\"]\n");
    }

    #[test]
    fn rejects_unknown_xml_and_unsupported_sql() {
        let xml = request("SELECT * FROM S3Object", "<CSV/><Unexpected/>", "<CSV/>");
        assert!(
            matches!(execute(&xml, b"a"), Err(S3Error::InvalidRequestParameter(message)) if message.contains("Unexpected"))
        );

        let xml = request(
            "SELECT * FROM S3Object JOIN S3Object AS other",
            "<CSV/>",
            "<CSV/>",
        );
        assert!(
            matches!(execute(&xml, b"a"), Err(S3Error::UnsupportedSqlOperation(message)) if message.contains("JOIN"))
        );

        let xml = request("SELECT COUNT(_1) FROM S3Object", "<CSV/>", "<CSV/>");
        assert!(
            matches!(execute(&xml, b"a"), Err(S3Error::UnsupportedSqlOperation(message)) if message.contains("aggregate"))
        );
    }

    #[test]
    fn rejects_malformed_csv_without_fallback() {
        let xml = request("SELECT * FROM S3Object", "<CSV/>", "<CSV/>");
        assert!(matches!(
            execute(&xml, b"\"unterminated"),
            Err(S3Error::CsvParsingError(message)) if message.contains("unterminated")
        ));
    }

    #[test]
    fn event_stream_has_valid_lengths_headers_and_crcs() {
        let xml = request("SELECT _1 FROM S3Object", "<CSV/>", "<CSV/>");
        let stream = execute(&xml, b"one\ntwo\n").unwrap();
        let decoded = messages(&stream);
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], ("Records".to_owned(), b"one\ntwo\n".to_vec()));
        assert!(std::str::from_utf8(&decoded[1].1)
            .unwrap()
            .contains("<BytesReturned>8</BytesReturned>"));
        assert_eq!(decoded[2], ("End".to_owned(), Vec::new()));
    }
}
