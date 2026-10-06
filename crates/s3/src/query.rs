//! Query-string parsing for S3 sub-resource markers and listing parameters.

use crate::addr::percent_decode;

/// Parsed query parameters preserving order; values are percent-decoded.
#[derive(Debug, Clone, Default)]
pub struct QueryParams {
    pairs: Vec<(String, String)>,
}

impl QueryParams {
    pub fn parse(query: Option<&str>) -> Self {
        let mut pairs = Vec::new();
        if let Some(q) = query {
            for pair in q.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = match pair.split_once('=') {
                    Some((k, v)) => (
                        percent_decode(&k.replace('+', " ")),
                        percent_decode(&v.replace('+', " ")),
                    ),
                    None => (percent_decode(pair), String::new()),
                };
                pairs.push((k, v));
            }
        }
        QueryParams { pairs }
    }

    /// First value for `key`, if present and non-empty.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }

    /// Operational query allowlist; SDK v3 x-id is advisory and never selects IAM permissions.
    pub fn only_keys(&self, allowed: &[&str]) -> bool {
        self.pairs
            .iter()
            .all(|(key, _)| key == "x-id" || allowed.contains(&key.as_str()))
    }

    /// Whether `key` is present (even with an empty value, e.g. `?acl`).
    pub fn has(&self, key: &str) -> bool {
        self.pairs.iter().any(|(k, _)| k == key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_markers_and_values() {
        let q = QueryParams::parse(Some("uploads&prefix=foo%2Fbar&max-keys=10"));
        assert!(q.has("uploads"));
        assert_eq!(q.get("prefix"), Some("foo/bar"));
        assert_eq!(q.get("max-keys"), Some("10"));
        assert!(!q.has("delimiter"));
    }

    #[test]
    fn empty_value_marker_is_present() {
        let q = QueryParams::parse(Some("acl"));
        assert!(q.has("acl"));
        assert_eq!(q.get("acl"), None);
    }
}
