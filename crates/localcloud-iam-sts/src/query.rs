//! AWS Query-protocol request decoding and response-envelope serialization.
//!
//! IAM and STS speak the Query protocol: requests are `application/x-www-form-urlencoded`
//! with an `Action` field and `member.N`-indexed lists; responses are XML wrapped in
//! `<{Action}Response>/<{Action}Result>` with a trailing `ResponseMetadata`/`RequestId`.

use std::collections::BTreeMap;

use crate::error::IamStsError;

/// IAM Query XML namespace.
pub const IAM_XMLNS: &str = "https://iam.amazonaws.com/doc/2010-05-08/";
/// STS Query XML namespace.
pub const STS_XMLNS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";

/// A decoded Query request: flat parameter map preserving the raw indexed keys.
#[derive(Debug, Clone)]
pub struct QueryRequest {
    params: BTreeMap<String, String>,
}

impl QueryRequest {
    /// Parse a form-urlencoded body into a parameter map.
    pub fn parse(body: &[u8]) -> Self {
        let mut params = BTreeMap::new();
        let text = String::from_utf8_lossy(body);
        for pair in text.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (raw_key, raw_val) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            params.insert(form_decode(raw_key), form_decode(raw_val));
        }
        QueryRequest { params }
    }

    /// The `Action` field, or `None` when absent.
    pub fn action(&self) -> Option<&str> {
        self.params.get("Action").map(String::as_str)
    }

    /// A parameter value, if present and non-empty.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.params
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    /// A required parameter; `ValidationError` when missing or empty.
    pub fn require(&self, key: &str) -> Result<&str, IamStsError> {
        self.get(key).ok_or_else(|| {
            IamStsError::ValidationError(format!("required parameter {key} is missing"))
        })
    }

    /// A `member.N` list (1-based, contiguous): collects `{prefix}.1`, `{prefix}.2`, ...
    /// stopping at the first gap. `prefix` is the part before the index, e.g.
    /// `PolicyArns.member`.
    pub fn list(&self, prefix: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut n = 1usize;
        loop {
            let key = format!("{prefix}.{n}");
            match self.params.get(&key) {
                Some(v) => out.push(v.clone()),
                None => break,
            }
            n += 1;
        }
        out
    }

    /// A tag list under `{prefix}.N.Key` / `{prefix}.N.Value`, e.g. `Tags.member`.
    pub fn tags(&self, prefix: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut n = 1usize;
        loop {
            let key_field = format!("{prefix}.{n}.Key");
            match self.params.get(&key_field) {
                Some(k) => {
                    let value = self
                        .params
                        .get(&format!("{prefix}.{n}.Value"))
                        .cloned()
                        .unwrap_or_default();
                    out.push((k.clone(), value));
                }
                None => break,
            }
            n += 1;
        }
        out
    }
}

/// Wrap a result body in the Query response envelope for `action` in namespace `xmlns`.
/// Pass an empty `result_body` for operations that return only `ResponseMetadata`.
pub fn response_envelope(action: &str, xmlns: &str, result_body: &str, request_id: &str) -> String {
    let result = if result_body.is_empty() {
        String::new()
    } else {
        format!("<{action}Result>{result_body}</{action}Result>")
    };
    format!(
        "<{action}Response xmlns=\"{xmlns}\">{result}<ResponseMetadata><RequestId>{rid}</RequestId></ResponseMetadata></{action}Response>",
        rid = xml_escape(request_id),
    )
}

/// An XML element `<name>content</name>`; content is assumed already-escaped/serialized.
pub fn el(name: &str, content: &str) -> String {
    format!("<{name}>{content}</{name}>")
}

/// An XML element wrapping escaped text.
pub fn text_el(name: &str, text: &str) -> String {
    format!("<{name}>{}</{name}>", xml_escape(text))
}

/// Escape XML text content / attribute-free body.
pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Decode an `application/x-www-form-urlencoded` token (`+` → space, `%XX` → byte).
fn form_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_action_and_params() {
        let q = QueryRequest::parse(b"Action=CreateUser&UserName=alice&Version=2010-05-08");
        assert_eq!(q.action(), Some("CreateUser"));
        assert_eq!(q.get("UserName"), Some("alice"));
        assert_eq!(q.get("Missing"), None);
    }

    #[test]
    fn require_missing_is_validation_error() {
        let q = QueryRequest::parse(b"Action=GetUser");
        assert!(matches!(
            q.require("UserName"),
            Err(IamStsError::ValidationError(_))
        ));
    }

    #[test]
    fn form_decodes_plus_and_percent() {
        let q = QueryRequest::parse(
            b"Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A1%3Arole%2Fr&Name=a+b",
        );
        assert_eq!(q.get("RoleArn"), Some("arn:aws:iam::1:role/r"));
        assert_eq!(q.get("Name"), Some("a b"));
    }

    #[test]
    fn collects_indexed_list_until_gap() {
        let q = QueryRequest::parse(
            b"PolicyArns.member.1=arn:a&PolicyArns.member.2=arn:b&PolicyArns.member.4=arn:d",
        );
        assert_eq!(q.list("PolicyArns.member"), vec!["arn:a", "arn:b"]);
    }

    #[test]
    fn collects_tag_pairs() {
        let q = QueryRequest::parse(
            b"Tags.member.1.Key=env&Tags.member.1.Value=prod&Tags.member.2.Key=team&Tags.member.2.Value=core",
        );
        assert_eq!(
            q.tags("Tags.member"),
            vec![
                ("env".to_string(), "prod".to_string()),
                ("team".to_string(), "core".to_string())
            ]
        );
    }

    #[test]
    fn envelope_wraps_action_and_request_id() {
        let xml = response_envelope(
            "GetUser",
            IAM_XMLNS,
            "<User><UserName>a</UserName></User>",
            "rid-9",
        );
        assert!(xml
            .starts_with("<GetUserResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">"));
        assert!(xml.contains("<GetUserResult><User><UserName>a</UserName></User></GetUserResult>"));
        assert!(xml.contains("<RequestId>rid-9</RequestId>"));
    }

    #[test]
    fn envelope_without_result_body() {
        let xml = response_envelope("DeleteUser", IAM_XMLNS, "", "rid-1");
        assert!(!xml.contains("DeleteUserResult"));
        assert!(xml.contains("<RequestId>rid-1</RequestId>"));
    }
}
