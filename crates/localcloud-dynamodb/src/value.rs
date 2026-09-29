//! DynamoDB `AttributeValue` model, JSON 1.0 marshalling, number normalization, and
//! item-size accounting.
//!
//! Sets are stored order-independently (`BTreeSet`); numbers are normalized to a canonical
//! decimal form on ingest so equal numbers compare and hash identically.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use base64::Engine;
use bigdecimal::BigDecimal;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::DdbError;

/// Maximum stored item size in bytes (400 KB).
pub const MAX_ITEM_SIZE: usize = 409_600;
/// Maximum significant digits in a DynamoDB number.
const MAX_SIGNIFICANT_DIGITS: u64 = 38;

/// A typed DynamoDB attribute value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttributeValue {
    S(String),
    /// Normalized canonical decimal string.
    N(String),
    B(Vec<u8>),
    Bool(bool),
    Null,
    M(BTreeMap<String, AttributeValue>),
    L(Vec<AttributeValue>),
    Ss(BTreeSet<String>),
    Ns(BTreeSet<String>),
    Bs(BTreeSet<Vec<u8>>),
}

/// A DynamoDB item: attribute name → value.
pub type Item = BTreeMap<String, AttributeValue>;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Normalize a DynamoDB number string to canonical form; reject out-of-range/invalid.
pub fn normalize_number(raw: &str) -> Result<String, DdbError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DdbError::Validation(
            "number value must not be empty".into(),
        ));
    }
    let decimal = BigDecimal::from_str(trimmed)
        .map_err(|_| DdbError::Validation(format!("invalid number: {raw}")))?;
    let normalized = decimal.normalized();
    if normalized.digits() > MAX_SIGNIFICANT_DIGITS {
        return Err(DdbError::Validation(
            "number exceeds 38 significant digits".into(),
        ));
    }
    let zero = BigDecimal::from(0);
    if normalized != zero {
        let abs = normalized.abs();
        let overflow = BigDecimal::from_str("1E+126").unwrap();
        let underflow = BigDecimal::from_str("1E-130").unwrap();
        if abs >= overflow {
            return Err(DdbError::Validation("number overflow".into()));
        }
        if abs < underflow {
            return Err(DdbError::Validation("number underflow".into()));
        }
    }
    // Canonical: normalized() strips trailing zeros; `-0` collapses to `0`.
    if normalized == zero {
        return Ok("0".to_string());
    }
    Ok(plain_decimal(&normalized))
}

/// Format a normalized `BigDecimal` as a plain (non-scientific) decimal string. The input
/// is assumed already trailing-zero-stripped by `normalized()`.
fn plain_decimal(value: &BigDecimal) -> String {
    let (bigint, exp) = value.as_bigint_and_exponent();
    let raw = bigint.to_string();
    let (negative, digits) = match raw.strip_prefix('-') {
        Some(d) => (true, d.to_string()),
        None => (false, raw),
    };
    let body = if exp <= 0 {
        // Integer: value = digits * 10^(-exp); append the trailing zeros.
        format!("{digits}{}", "0".repeat((-exp) as usize))
    } else {
        let exp = exp as usize;
        if digits.len() > exp {
            let point = digits.len() - exp;
            format!("{}.{}", &digits[..point], &digits[point..])
        } else {
            format!("0.{}{}", "0".repeat(exp - digits.len()), digits)
        }
    };
    if negative {
        format!("-{body}")
    } else {
        body
    }
}

/// Compare two normalized number strings numerically.
pub fn number_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    match (BigDecimal::from_str(a), BigDecimal::from_str(b)) {
        (Ok(x), Ok(y)) => x.cmp(&y),
        _ => a.cmp(b),
    }
}

impl AttributeValue {
    /// Parse a single-descriptor JSON 1.0 attribute value (e.g. `{"S":"x"}`).
    pub fn from_json(value: &Value) -> Result<AttributeValue, DdbError> {
        let obj = value
            .as_object()
            .ok_or_else(|| DdbError::Validation("attribute value must be an object".into()))?;
        if obj.len() != 1 {
            return Err(DdbError::Validation(
                "attribute value must have exactly one type descriptor".into(),
            ));
        }
        let (tag, inner) = obj.iter().next().unwrap();
        match tag.as_str() {
            "S" => Ok(AttributeValue::S(as_str(inner, "S")?.to_string())),
            "N" => Ok(AttributeValue::N(normalize_number(as_str(inner, "N")?)?)),
            "B" => Ok(AttributeValue::B(decode_b64(as_str(inner, "B")?)?)),
            "BOOL" => Ok(AttributeValue::Bool(inner.as_bool().ok_or_else(|| {
                DdbError::Validation("BOOL must be a boolean".into())
            })?)),
            "NULL" => Ok(AttributeValue::Null),
            "M" => {
                let map = inner
                    .as_object()
                    .ok_or_else(|| DdbError::Validation("M must be an object".into()))?;
                let mut out = BTreeMap::new();
                for (k, v) in map {
                    out.insert(k.clone(), AttributeValue::from_json(v)?);
                }
                Ok(AttributeValue::M(out))
            }
            "L" => {
                let list = inner
                    .as_array()
                    .ok_or_else(|| DdbError::Validation("L must be an array".into()))?;
                let mut out = Vec::with_capacity(list.len());
                for v in list {
                    out.push(AttributeValue::from_json(v)?);
                }
                Ok(AttributeValue::L(out))
            }
            "SS" => Ok(AttributeValue::Ss(string_set(inner, "SS", |s| {
                Ok(s.to_string())
            })?)),
            "NS" => Ok(AttributeValue::Ns(string_set(
                inner,
                "NS",
                normalize_number,
            )?)),
            "BS" => {
                let arr = inner
                    .as_array()
                    .ok_or_else(|| DdbError::Validation("BS must be an array".into()))?;
                if arr.is_empty() {
                    return Err(DdbError::Validation("BS must not be empty".into()));
                }
                let mut set = BTreeSet::new();
                for v in arr {
                    let bytes = decode_b64(as_str(v, "BS")?)?;
                    if !set.insert(bytes) {
                        return Err(DdbError::Validation("BS has duplicate members".into()));
                    }
                }
                Ok(AttributeValue::Bs(set))
            }
            other => Err(DdbError::Validation(format!(
                "unknown type descriptor {other}"
            ))),
        }
    }

    /// Serialize to the JSON 1.0 attribute-value representation.
    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();
        match self {
            AttributeValue::S(s) => {
                obj.insert("S".into(), Value::String(s.clone()));
            }
            AttributeValue::N(n) => {
                obj.insert("N".into(), Value::String(n.clone()));
            }
            AttributeValue::B(b) => {
                obj.insert("B".into(), Value::String(b64().encode(b)));
            }
            AttributeValue::Bool(b) => {
                obj.insert("BOOL".into(), Value::Bool(*b));
            }
            AttributeValue::Null => {
                obj.insert("NULL".into(), Value::Bool(true));
            }
            AttributeValue::M(m) => {
                let inner: Map<String, Value> =
                    m.iter().map(|(k, v)| (k.clone(), v.to_json())).collect();
                obj.insert("M".into(), Value::Object(inner));
            }
            AttributeValue::L(l) => {
                obj.insert(
                    "L".into(),
                    Value::Array(l.iter().map(|v| v.to_json()).collect()),
                );
            }
            AttributeValue::Ss(s) => {
                obj.insert(
                    "SS".into(),
                    Value::Array(s.iter().map(|v| Value::String(v.clone())).collect()),
                );
            }
            AttributeValue::Ns(s) => {
                obj.insert(
                    "NS".into(),
                    Value::Array(s.iter().map(|v| Value::String(v.clone())).collect()),
                );
            }
            AttributeValue::Bs(s) => {
                obj.insert(
                    "BS".into(),
                    Value::Array(s.iter().map(|v| Value::String(b64().encode(v))).collect()),
                );
            }
        }
        Value::Object(obj)
    }

    /// Size in bytes for item-size accounting.
    pub fn size(&self) -> usize {
        match self {
            AttributeValue::S(s) => s.len(),
            AttributeValue::N(n) => n.len(),
            AttributeValue::B(b) => b.len(),
            AttributeValue::Bool(_) | AttributeValue::Null => 1,
            AttributeValue::M(m) => {
                3 + m.iter().map(|(k, v)| k.len() + v.size() + 1).sum::<usize>()
            }
            AttributeValue::L(l) => 3 + l.iter().map(|v| v.size() + 1).sum::<usize>(),
            AttributeValue::Ss(s) => s.iter().map(|v| v.len()).sum(),
            AttributeValue::Ns(s) => s.iter().map(|v| v.len()).sum(),
            AttributeValue::Bs(s) => s.iter().map(|v| v.len()).sum(),
        }
    }
}

/// Parse an item map from a JSON 1.0 object.
pub fn item_from_json(value: &Value) -> Result<Item, DdbError> {
    let obj = value
        .as_object()
        .ok_or_else(|| DdbError::Validation("item must be an object".into()))?;
    let mut item = BTreeMap::new();
    for (name, v) in obj {
        if name.is_empty() {
            return Err(DdbError::Validation(
                "attribute name must not be empty".into(),
            ));
        }
        item.insert(name.clone(), AttributeValue::from_json(v)?);
    }
    Ok(item)
}

/// Serialize an item map to a JSON 1.0 object.
pub fn item_to_json(item: &Item) -> Value {
    Value::Object(item.iter().map(|(k, v)| (k.clone(), v.to_json())).collect())
}

/// Total stored size of an item (attribute names + values).
pub fn item_size(item: &Item) -> usize {
    item.iter()
        .map(|(name, value)| name.len() + value.size())
        .sum()
}

fn as_str<'a>(value: &'a Value, tag: &str) -> Result<&'a str, DdbError> {
    value
        .as_str()
        .ok_or_else(|| DdbError::Validation(format!("{tag} value must be a string")))
}

fn decode_b64(s: &str) -> Result<Vec<u8>, DdbError> {
    b64()
        .decode(s)
        .map_err(|_| DdbError::Validation("invalid base64 value".into()))
}

fn string_set<F>(value: &Value, tag: &str, map: F) -> Result<BTreeSet<String>, DdbError>
where
    F: Fn(&str) -> Result<String, DdbError>,
{
    let arr = value
        .as_array()
        .ok_or_else(|| DdbError::Validation(format!("{tag} must be an array")))?;
    if arr.is_empty() {
        return Err(DdbError::Validation(format!("{tag} must not be empty")));
    }
    let mut set = BTreeSet::new();
    for v in arr {
        let s = map(as_str(v, tag)?)?;
        if !set.insert(s) {
            return Err(DdbError::Validation(format!("{tag} has duplicate members")));
        }
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_zeros_and_handles_negative_zero() {
        assert_eq!(normalize_number("01.50").unwrap(), "1.5");
        assert_eq!(normalize_number("1.0").unwrap(), "1");
        assert_eq!(normalize_number("-0").unwrap(), "0");
        assert_eq!(normalize_number("100").unwrap(), "100");
        assert_eq!(normalize_number("0.50").unwrap(), "0.5");
    }

    #[test]
    fn normalize_rejects_invalid_and_out_of_range() {
        assert!(normalize_number("abc").is_err());
        assert!(normalize_number("").is_err());
        assert!(normalize_number("1E+126").is_err());
    }

    #[test]
    fn number_comparison_is_numeric() {
        assert_eq!(number_cmp("9", "10"), std::cmp::Ordering::Less);
        assert_eq!(number_cmp("1.0", "1"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn round_trip_all_types() {
        let json = serde_json::json!({
            "s": {"S": "hi"},
            "n": {"N": "1.50"},
            "b": {"B": "aGk="},
            "bool": {"BOOL": true},
            "null": {"NULL": true},
            "m": {"M": {"k": {"S": "v"}}},
            "l": {"L": [{"N": "1"}, {"S": "x"}]},
            "ss": {"SS": ["a", "b"]},
            "ns": {"NS": ["1", "2"]},
            "bs": {"BS": ["aGk="]}
        });
        let item = item_from_json(&json).unwrap();
        assert_eq!(item.get("n"), Some(&AttributeValue::N("1.5".into())));
        // SS is order-independent.
        assert_eq!(
            item.get("ss"),
            Some(&AttributeValue::Ss(["a".into(), "b".into()].into()))
        );
        // Re-serialize and re-parse is stable.
        let again = item_from_json(&item_to_json(&item)).unwrap();
        assert_eq!(item, again);
    }

    #[test]
    fn rejects_multiple_descriptors_and_bad_base64() {
        assert!(AttributeValue::from_json(&serde_json::json!({"S": "a", "N": "1"})).is_err());
        assert!(AttributeValue::from_json(&serde_json::json!({"B": "!!!"})).is_err());
    }

    #[test]
    fn rejects_empty_and_duplicate_sets() {
        assert!(AttributeValue::from_json(&serde_json::json!({"SS": []})).is_err());
        assert!(AttributeValue::from_json(&serde_json::json!({"SS": ["a", "a"]})).is_err());
    }
}
