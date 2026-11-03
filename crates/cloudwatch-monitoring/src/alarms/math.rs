//! Bounded, point-wise alarm math. Unsupported functions and mixed periods fail at write time.
use super::*;
use std::collections::BTreeSet;

pub(super) struct Plan {
    pub(super) period: u64,
    queries: BTreeMap<String, Query>,
    output: String,
    order: Vec<String>,
}
enum Query {
    Metric(crate::metric_data::MetricStatQuery),
    Expression(Expr),
}
#[derive(Debug)]
enum Expr {
    Number(f64),
    Reference(String),
    Binary(BinaryOp, Box<Expr>, Box<Expr>),
    If(Box<Expr>, Box<Expr>, Box<Expr>),
    Fill(Box<Expr>, f64),
}
#[derive(Debug, Clone, Copy)]
enum BinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
    Equal,
    NotEqual,
    And,
    Or,
}
impl BinaryOp {
    fn parse(token: &str) -> Option<(Self, u8)> {
        Some(match token {
            "+" => (Self::Add, 4),
            "-" => (Self::Subtract, 4),
            "*" => (Self::Multiply, 5),
            "/" => (Self::Divide, 5),
            ">" => (Self::Greater, 3),
            ">=" => (Self::GreaterEqual, 3),
            "<" => (Self::Less, 3),
            "<=" => (Self::LessEqual, 3),
            "==" => (Self::Equal, 3),
            "!=" => (Self::NotEqual, 3),
            "AND" => (Self::And, 2),
            "OR" => (Self::Or, 1),
            _ => return None,
        })
    }
}
impl Expr {
    fn references(&self, names: &mut BTreeSet<String>) {
        match self {
            Self::Reference(name) => {
                names.insert(name.clone());
            }
            Self::Number(_) => {}
            Self::Binary(_, a, b) => {
                a.references(names);
                b.references(names);
            }
            Self::If(a, b, c) => {
                a.references(names);
                b.references(names);
                c.references(names);
            }
            Self::Fill(a, _) => a.references(names),
        }
    }
    fn value(&self, resolve: &impl Fn(&str) -> Option<f64>) -> Option<f64> {
        let value = match self {
            Self::Number(value) => *value,
            Self::Reference(name) => return resolve(name),
            Self::If(condition, yes, no) => {
                return if condition.value(resolve)? != 0.0 {
                    yes.value(resolve)
                } else {
                    no.value(resolve)
                };
            }
            Self::Fill(series, fill) => series.value(resolve).unwrap_or(*fill),
            Self::Binary(op, left, right) => {
                // CloudWatch treats missing operands in arithmetic/comparisons as zero.
                let a = left.value(resolve).unwrap_or(0.0);
                let b = right.value(resolve).unwrap_or(0.0);
                match op {
                    BinaryOp::Add => a + b,
                    BinaryOp::Subtract => a - b,
                    BinaryOp::Multiply => a * b,
                    BinaryOp::Divide => {
                        if b == 0.0 {
                            return None;
                        }
                        a / b
                    }
                    BinaryOp::Greater => f64::from(a > b),
                    BinaryOp::GreaterEqual => f64::from(a >= b),
                    BinaryOp::Less => f64::from(a < b),
                    BinaryOp::LessEqual => f64::from(a <= b),
                    BinaryOp::Equal => f64::from(a == b),
                    BinaryOp::NotEqual => f64::from(a != b),
                    BinaryOp::And => f64::from(a != 0.0 && b != 0.0),
                    BinaryOp::Or => f64::from(a != 0.0 || b != 0.0),
                }
            }
        };
        value.is_finite().then_some(value)
    }
}
struct Parser {
    tokens: Vec<String>,
    index: usize,
}
impl Parser {
    fn parse(text: &str) -> Result<Expr, MonitoringError> {
        if text.is_empty() || text.len() > 1024 || !text.is_ascii() {
            return Err(invalid("Expression must contain 1..1024 ASCII characters"));
        }
        let mut chars = text.chars().peekable();
        let mut tokens = Vec::new();
        while let Some(ch) = chars.next() {
            if ch.is_ascii_whitespace() {
                continue;
            }
            let mut token = ch.to_string();
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
                {
                    if let Some(c) = chars.next() {
                        token.push(c);
                    }
                }
            } else if matches!(ch, '>' | '<' | '=' | '!') && chars.peek() == Some(&'=') {
                chars.next();
                token.push('=');
            } else if !"+-*/(),<>".contains(ch) {
                return Err(invalid("Unsupported metric math operator"));
            }
            tokens.push(token);
            if tokens.len() > 128 {
                return Err(invalid("Metric math expression is too complex"));
            }
        }
        let mut parser = Self { tokens, index: 0 };
        let result = parser.expression(0, 0)?;
        if parser.index != parser.tokens.len() {
            return Err(invalid("Unsupported metric math expression"));
        }
        Ok(result)
    }
    fn take(&mut self) -> Result<String, MonitoringError> {
        let token = self
            .tokens
            .get(self.index)
            .cloned()
            .ok_or_else(|| invalid("Incomplete metric math expression"))?;
        self.index += 1;
        Ok(token)
    }
    fn expect(&mut self, expected: &str) -> Result<(), MonitoringError> {
        if self.take()? != expected {
            return Err(invalid("Malformed metric math expression"));
        }
        Ok(())
    }
    fn expression(&mut self, minimum: u8, depth: usize) -> Result<Expr, MonitoringError> {
        if depth > 32 {
            return Err(invalid("Metric math expression is too deeply nested"));
        }
        let token = self.take()?;
        let mut left = match token.as_str() {
            "(" => {
                let value = self.expression(0, depth + 1)?;
                self.expect(")")?;
                value
            }
            "-" => Expr::Binary(
                BinaryOp::Subtract,
                Box::new(Expr::Number(0.0)),
                Box::new(self.expression(6, depth + 1)?),
            ),
            "IF" => {
                self.expect("(")?;
                let a = self.expression(0, depth + 1)?;
                self.expect(",")?;
                let b = self.expression(0, depth + 1)?;
                self.expect(",")?;
                let c = self.expression(0, depth + 1)?;
                self.expect(")")?;
                let mut branches = BTreeSet::new();
                b.references(&mut branches);
                c.references(&mut branches);
                if !branches.is_empty() {
                    return Err(invalid(
                        "Only scalar IF branches are supported in alarm math",
                    ));
                }
                Expr::If(Box::new(a), Box::new(b), Box::new(c))
            }
            "FILL" => {
                self.expect("(")?;
                let series = self.expression(0, depth + 1)?;
                self.expect(",")?;
                let fill = self.expression(0, depth + 1)?;
                self.expect(")")?;
                let mut references = BTreeSet::new();
                fill.references(&mut references);
                if !references.is_empty() {
                    return Err(invalid("Only scalar FILL values are supported"));
                }
                let scalar = fill
                    .value(&|_| None)
                    .ok_or_else(|| invalid("Invalid FILL scalar"))?;
                Expr::Fill(Box::new(series), scalar)
            }
            _ => {
                if let Ok(number) = token.parse::<f64>() {
                    if !number.is_finite() {
                        return Err(invalid("Non-finite expression constant"));
                    }
                    Expr::Number(number)
                } else if valid_id(&token) {
                    Expr::Reference(token)
                } else {
                    return Err(invalid("Unsupported metric math function or identifier"));
                }
            }
        };
        while let Some(op) = self.tokens.get(self.index).cloned() {
            let Some((operator, precedence)) = BinaryOp::parse(&op) else {
                break;
            };
            if precedence < minimum {
                break;
            }
            self.index += 1;
            left = Expr::Binary(
                operator,
                Box::new(left),
                Box::new(self.expression(precedence + 1, depth + 1)?),
            );
        }
        Ok(left)
    }
}
fn valid_id(id: &str) -> bool {
    let mut bytes = id.bytes();
    id.len() <= 255
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
impl Plan {
    pub(super) fn parse(values: &[Value], scope: &ScopeKey) -> Result<Self, MonitoringError> {
        if values.is_empty() || values.len() > 20 {
            return Err(invalid("Metrics must contain 1..20 queries"));
        }
        let mut queries = BTreeMap::new();
        let mut output = None;
        let mut period = None;
        let mut metrics = 0;
        let mut expressions = 0;
        for value in values {
            allowed(
                value,
                &[
                    "Id",
                    "Label",
                    "ReturnData",
                    "MetricStat",
                    "Expression",
                    "AccountId",
                ],
            )?;
            let id = json_string(value, "Id")?;
            if !valid_id(id) {
                return Err(invalid(
                    "Metric query Id must match [a-z][a-zA-Z0-9_]* and be at most 255 characters",
                ));
            }
            if value
                .get("Label")
                .is_some_and(|v| !v.as_str().is_some_and(|v| v.len() <= 1024))
            {
                return Err(invalid(
                    "Metric query Label must be a string of at most 1024 characters",
                ));
            }
            if value
                .get("AccountId")
                .is_some_and(|v| v.as_str() != Some(scope.account_id.as_str()))
            {
                return Err(invalid(
                    "Cross-account alarm metric queries are not supported",
                ));
            }
            let returns = match value.get("ReturnData") {
                None => true,
                Some(Value::Bool(flag)) => *flag,
                _ => return Err(invalid("ReturnData must be boolean")),
            };
            if returns && output.replace(id.to_owned()).is_some() {
                return Err(invalid(
                    "Exactly one Metrics query must have ReturnData true",
                ));
            }
            let query = match (value.get("MetricStat"), value.get("Expression")) {
                (Some(stat), None) => {
                    allowed(stat, &["Metric", "Period", "Stat", "Unit"])?;
                    let metric = stat
                        .get("Metric")
                        .ok_or_else(|| invalid("MetricStat requires Metric"))?;
                    allowed(metric, &["Namespace", "MetricName", "Dimensions"])?;
                    if let Some(dimensions) = metric.get("Dimensions").and_then(Value::as_array) {
                        for dimension in dimensions {
                            allowed(dimension, &["Name", "Value"])?;
                        }
                    }
                    let stat = crate::metric_data::parse_metric_stat(stat, id)?;
                    let seconds = (stat.period_ms / 1000) as u64;
                    if !matches!(seconds, 10 | 20 | 30)
                        && (seconds < 60 || !seconds.is_multiple_of(60))
                    {
                        return Err(invalid(
                            "Alarm metric periods must be 10,20,30 or a multiple of 60",
                        ));
                    }
                    if period.replace(seconds).is_some_and(|old| old != seconds) {
                        return Err(invalid("Mixed-period alarm math is not supported"));
                    }
                    metrics += 1;
                    Query::Metric(stat)
                }
                (None, Some(Value::String(expression))) => {
                    expressions += 1;
                    Query::Expression(Parser::parse(expression)?)
                }
                _ => {
                    return Err(invalid(
                        "Each Metrics query requires exactly one MetricStat or Expression",
                    ))
                }
            };
            if queries.insert(id.into(), query).is_some() {
                return Err(invalid("Metrics query Ids must be unique"));
            }
        }
        if metrics > 10 || expressions > 10 {
            return Err(invalid(
                "Metrics supports at most 10 metric and 10 expression queries",
            ));
        }
        let mut plan = Self {
            period: period.ok_or_else(|| invalid("Metric math requires a metric series"))?,
            queries,
            output: output
                .ok_or_else(|| invalid("Exactly one Metrics query must have ReturnData true"))?,
            order: Vec::new(),
        };
        let mut done = BTreeSet::new();
        let mut order = Vec::new();
        for id in plan.queries.keys() {
            plan.check_references(id, &mut BTreeSet::new(), &mut done, &mut order)?;
        }
        plan.order = order;
        for query in plan.queries.values() {
            if let Query::Expression(expression) = query {
                let mut refs = BTreeSet::new();
                expression.references(&mut refs);
                if refs.is_empty() {
                    return Err(invalid("Alarm expressions must reference a time series"));
                }
            }
        }
        Ok(plan)
    }
    fn check_references(
        &self,
        id: &str,
        active: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
        order: &mut Vec<String>,
    ) -> Result<(), MonitoringError> {
        if done.contains(id) {
            return Ok(());
        }
        if !active.insert(id.into()) {
            return Err(invalid("Cyclic metric math references"));
        }
        match self.queries.get(id) {
            Some(Query::Expression(expression)) => {
                let mut refs = BTreeSet::new();
                expression.references(&mut refs);
                for reference in refs {
                    self.check_references(&reference, active, done, order)?;
                }
            }
            Some(Query::Metric(_)) => {}
            None => return Err(invalid("Unknown metric math reference")),
        }
        active.remove(id);
        done.insert(id.to_owned());
        order.push(id.to_owned());
        Ok(())
    }
    pub(super) fn buckets(
        &self,
        domain: &MonitoringDomain,
        scope: &ScopeKey,
        end: i64,
        count: u64,
    ) -> Result<Vec<Option<f64>>, MonitoringError> {
        let period = self.period as i64 * 1000;
        let mut series = BTreeMap::new();
        for (id, query) in &self.queries {
            if let Query::Metric(stat) = query {
                let points = domain.points(
                    scope,
                    &stat.key,
                    end - count as i64 * period,
                    end,
                    stat.unit.map(MetricUnit::as_str),
                )?;
                let values = (0..count)
                    .map(|index| {
                        let upper = end - index as i64 * period;
                        let samples: Vec<_> = points
                            .iter()
                            .filter(|p| p.timestamp_ms >= upper - period && p.timestamp_ms < upper)
                            .map(|p| p.value)
                            .collect();
                        stat.stat.compute(&samples)
                    })
                    .collect::<Vec<_>>();
                series.insert(id.clone(), values);
            }
        }
        Ok((0..count as usize)
            .map(|index| {
                let mut values = BTreeMap::new();
                for id in &self.order {
                    let value = match self.queries.get(id) {
                        Some(Query::Metric(_)) => {
                            series.get(id).and_then(|v| v.get(index)).copied().flatten()
                        }
                        Some(Query::Expression(expr)) => {
                            expr.value(&|name| values.get(name).copied().flatten())
                        }
                        None => None,
                    };
                    values.insert(id.clone(), value);
                }
                values.get(&self.output).copied().flatten()
            })
            .collect())
    }
}
