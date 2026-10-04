//! Bounded SQL grammar and exact typed results shared by the Athena worker.

pub(super) struct ParsedQuery {
    pub(super) database: Option<String>,
    pub(super) table: String,
    pub(super) projection: Projection,
    pub(super) predicates: Vec<Predicate>,
}

pub(super) struct Predicate {
    pub(super) column: String,
    pub(super) operator: String,
    pub(super) value: String,
}

fn decimal_comparable(value: &str) -> Option<i128> {
    let negative = value.starts_with('-');
    let value = value.strip_prefix('-').unwrap_or(value);
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || fraction.len() > 18
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let scaled = whole
        .parse::<i128>()
        .ok()?
        .checked_mul(1_000_000_000_000_000_000)?
        .checked_add(format!("{fraction:0<18}").parse::<i128>().ok()?)?;
    Some(if negative { -scaled } else { scaled })
}

fn predicate_comparable(kind: &str, value: &str) -> Option<i128> {
    match kind {
        "bigint" | "integer" | "decimal(18,2)" => decimal_comparable(value),
        "date" => time::Date::parse(
            value,
            &time::format_description::parse_borrowed::<2>("[year]-[month]-[day]").ok()?,
        )
        .ok()
        .map(|date| i128::from(date.to_julian_day())),
        "timestamp" | "timestamptz" => {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .ok()
                .map(|time| time.unix_timestamp_nanos())
        }
        "boolean" => match value {
            "true" => Some(1),
            "false" => Some(0),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn apply_predicates(
    result: &mut QueryResult,
    predicates: &[Predicate],
) -> Result<(), String> {
    let indices = predicates
        .iter()
        .map(|p| {
            result
                .columns
                .iter()
                .position(|c| c.name == p.column)
                .ok_or("Filter column not found")
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (p, index) in predicates.iter().zip(&indices) {
        if matches!(
            result.columns[*index].kind,
            "bigint"
                | "integer"
                | "decimal(18,2)"
                | "date"
                | "timestamp"
                | "timestamptz"
                | "boolean"
        ) && predicate_comparable(result.columns[*index].kind, &p.value).is_none()
        {
            return Err("Invalid numeric predicate".into());
        }
    }
    let header = result.rows.remove(0);
    result.rows.retain(|row| {
        predicates.iter().zip(&indices).all(|(p, index)| {
            let Some(value) = row[*index].as_deref() else {
                return false;
            };
            let order = if matches!(
                result.columns[*index].kind,
                "bigint"
                    | "integer"
                    | "decimal(18,2)"
                    | "date"
                    | "timestamp"
                    | "timestamptz"
                    | "boolean"
            ) {
                predicate_comparable(result.columns[*index].kind, value)
                    .cmp(&predicate_comparable(result.columns[*index].kind, &p.value))
            } else {
                value.cmp(&p.value)
            };
            match p.operator.as_str() {
                "=" => order.is_eq(),
                "!=" | "<>" => !order.is_eq(),
                "<" => order.is_lt(),
                ">" => order.is_gt(),
                "<=" => !order.is_gt(),
                ">=" => !order.is_lt(),
                _ => false,
            }
        })
    });
    result.rows.insert(0, header);
    Ok(())
}

#[derive(Clone)]
pub(super) enum Projection {
    Count(String),
    Sum { column: String, alias: String },
    Columns(Vec<String>),
}

pub(super) struct ResultColumn {
    pub(super) name: String,
    pub(super) kind: &'static str,
}

pub(super) struct QueryResult {
    pub(super) columns: Vec<ResultColumn>,
    pub(super) rows: Vec<Vec<Option<String>>>,
}

impl QueryResult {
    pub(super) fn count(alias: String, count: u64) -> Self {
        Self {
            columns: vec![ResultColumn {
                name: alias.clone(),
                kind: "bigint",
            }],
            rows: vec![vec![Some(alias)], vec![Some(count.to_string())]],
        }
    }

    pub(super) fn csv(&self) -> String {
        self.rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|value| csv_field(value.as_deref().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join(",")
                    + "\n"
            })
            .collect()
    }
}

pub(super) fn sum_result(result: &QueryResult, alias: &str) -> Result<QueryResult, String> {
    let decimal = result.columns[0].kind == "decimal(18,2)";
    if !decimal && !matches!(result.columns[0].kind, "bigint" | "integer") {
        return Err("SUM requires an exact numeric column".into());
    }
    let mut sum = None::<i128>;
    for row in result.rows.iter().skip(1) {
        if let Some(value) = &row[0] {
            let value = if decimal {
                decimal_comparable(value).ok_or("Invalid decimal")? / 10_000_000_000_000_000
            } else {
                value.parse::<i128>().map_err(|_| "Invalid integer")?
            };
            sum = Some(sum.unwrap_or(0).checked_add(value).ok_or("SUM overflow")?);
        }
    }
    let value = sum
        .map(|value| {
            if decimal {
                Ok(format!(
                    "{}{}.{:02}",
                    if value < 0 { "-" } else { "" },
                    value.unsigned_abs() / 100,
                    value.unsigned_abs() % 100
                ))
            } else {
                i64::try_from(value)
                    .map(|value| value.to_string())
                    .map_err(|_| "SUM bigint overflow")
            }
        })
        .transpose()?;
    Ok(QueryResult {
        columns: vec![ResultColumn {
            name: alias.into(),
            kind: if decimal { "decimal(38,2)" } else { "bigint" },
        }],
        rows: vec![vec![Some(alias.into())], vec![value]],
    })
}

pub(super) struct SqlParser<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> SqlParser<'a> {
    pub(super) fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            position: 0,
        }
    }

    pub(super) fn parse(mut self) -> Result<ParsedQuery, String> {
        self.keyword("SELECT")?;
        let projection = if self.try_keyword("SUM") {
            self.punctuation(b'(')?;
            let column = self.identifier()?;
            self.punctuation(b')')?;
            let alias = if self.try_keyword("AS") {
                self.identifier()?
            } else {
                "_col0".into()
            };
            Projection::Sum { column, alias }
        } else if self.try_keyword("COUNT") {
            self.punctuation(b'(')?;
            self.punctuation(b'*')?;
            self.punctuation(b')')?;
            Projection::Count(if self.try_keyword("AS") {
                self.identifier()?
            } else {
                "_col0".into()
            })
        } else {
            let mut columns = vec![self.identifier()?];
            while self.try_punctuation(b',') {
                columns.push(self.identifier()?);
            }
            if columns.len() > 32 {
                return Err("too many selected columns".into());
            }
            Projection::Columns(columns)
        };
        self.keyword("FROM")?;
        let first = self.identifier()?;
        self.skip_whitespace();
        let (database, table) = if self.peek() == Some(b'.') {
            self.position += 1;
            (Some(first), self.identifier()?)
        } else {
            (None, first)
        };
        let mut predicates = Vec::new();
        if self.try_keyword("WHERE") {
            loop {
                let column = self.identifier()?;
                self.skip_whitespace();
                let start = self.position;
                while self
                    .peek()
                    .is_some_and(|b| matches!(b, b'=' | b'<' | b'>' | b'!'))
                {
                    self.position += 1;
                }
                let operator =
                    String::from_utf8_lossy(&self.input[start..self.position]).to_string();
                if !matches!(
                    operator.as_str(),
                    "=" | "!=" | "<>" | "<" | ">" | "<=" | ">="
                ) {
                    return Err("Unsupported predicate operator".into());
                }
                self.skip_whitespace();
                let mut literal = Vec::new();
                if self.try_punctuation(b'\'') {
                    loop {
                        let byte = self.peek().ok_or("Unterminated SQL literal")?;
                        self.position += 1;
                        if byte == b'\'' {
                            if self.peek() == Some(b'\'') {
                                self.position += 1;
                            } else {
                                break;
                            }
                        }
                        literal.push(byte);
                    }
                } else {
                    while self
                        .peek()
                        .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
                    {
                        literal.push(self.peek().unwrap());
                        self.position += 1;
                    }
                    let raw = String::from_utf8_lossy(&literal);
                    if !raw.eq_ignore_ascii_case("true")
                        && !raw.eq_ignore_ascii_case("false")
                        && decimal_comparable(&raw).is_none()
                    {
                        return Err("Expected a number, Boolean or quoted SQL literal".into());
                    }
                    if raw.eq_ignore_ascii_case("true") || raw.eq_ignore_ascii_case("false") {
                        literal.make_ascii_lowercase();
                    }
                }
                predicates.push(Predicate {
                    column,
                    operator,
                    value: String::from_utf8(literal).map_err(|_| "Invalid UTF-8 literal")?,
                });
                if predicates.len() > 32 {
                    return Err("Too many predicates".into());
                }
                if !self.try_keyword("AND") {
                    break;
                }
            }
        }
        self.skip_whitespace();
        if self.peek() == Some(b';') {
            self.position += 1;
        }
        self.skip_whitespace();
        if self.position != self.input.len() {
            return Err("unexpected trailing SQL".into());
        }
        Ok(ParsedQuery {
            database,
            table,
            projection,
            predicates,
        })
    }

    fn keyword(&mut self, expected: &str) -> Result<(), String> {
        self.skip_whitespace();
        let bytes = expected.as_bytes();
        let end = self.position + bytes.len();
        if end > self.input.len()
            || !self.input[self.position..end].eq_ignore_ascii_case(bytes)
            || self
                .input
                .get(end)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return Err(format!("expected {expected}"));
        }
        self.position = end;
        Ok(())
    }

    fn try_keyword(&mut self, expected: &str) -> bool {
        let original = self.position;
        if self.keyword(expected).is_ok() {
            true
        } else {
            self.position = original;
            false
        }
    }

    fn punctuation(&mut self, expected: u8) -> Result<(), String> {
        self.skip_whitespace();
        if self.peek() != Some(expected) {
            return Err(format!("expected {}", expected as char));
        }
        self.position += 1;
        Ok(())
    }

    fn try_punctuation(&mut self, expected: u8) -> bool {
        self.skip_whitespace();
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn identifier(&mut self) -> Result<String, String> {
        self.skip_whitespace();
        if self.peek() == Some(b'"') {
            self.position += 1;
            let mut value = Vec::new();
            loop {
                let Some(byte) = self.peek() else {
                    return Err("unterminated quoted identifier".into());
                };
                self.position += 1;
                if byte == b'"' {
                    if self.peek() == Some(b'"') {
                        value.push(b'"');
                        self.position += 1;
                        continue;
                    }
                    break;
                }
                value.push(byte);
            }
            if value.is_empty() {
                return Err("identifier must not be empty".into());
            }
            return String::from_utf8(value).map_err(|_| "identifier is not UTF-8".into());
        }
        let start = self.position;
        if !self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        {
            return Err("expected identifier".into());
        }
        self.position += 1;
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            self.position += 1;
        }
        Ok(String::from_utf8_lossy(&self.input[start..self.position]).to_ascii_lowercase())
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.position += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}
