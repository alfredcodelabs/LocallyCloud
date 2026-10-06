//! Query-protocol request parsing (form-urlencoded body with indexed members).

use std::collections::BTreeMap;

/// A parsed Query request: the flat parameter map.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Query {
    pub params: BTreeMap<String, String>,
}

impl Query {
    pub fn parse(body: &[u8]) -> Self {
        Query {
            params: parse_form(body),
        }
    }

    pub fn action(&self) -> Option<String> {
        self.params.get("Action").cloned()
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.params.get(key).cloned().filter(|s| !s.is_empty())
    }

    /// Stack `Parameters.member.<n>.ParameterKey/ParameterValue`.
    pub fn parameters(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let mut n = 1;
        while let Some(key) = self
            .params
            .get(&format!("Parameters.member.{n}.ParameterKey"))
        {
            let value = self
                .params
                .get(&format!("Parameters.member.{n}.ParameterValue"))
                .cloned()
                .unwrap_or_default();
            out.insert(key.clone(), value);
            n += 1;
        }
        out
    }

    /// Stack `Tags.member.<n>.Key/Value`.
    pub fn tags(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut n = 1;
        while let Some(key) = self.params.get(&format!("Tags.member.{n}.Key")) {
            let value = self
                .params
                .get(&format!("Tags.member.{n}.Value"))
                .cloned()
                .unwrap_or_default();
            out.push((key.clone(), value));
            n += 1;
        }
        out
    }
}

/// Parse a form-urlencoded body into a parameter map.
fn parse_form(body: &[u8]) -> BTreeMap<String, String> {
    let text = String::from_utf8_lossy(body);
    let mut map = BTreeMap::new();
    for pair in text.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (form_decode(k), form_decode(v)),
            None => (form_decode(pair), String::new()),
        };
        map.insert(k, v);
    }
    map
}

fn form_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
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

fn hex(b: u8) -> Option<u8> {
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
    fn parses_action_and_stackname() {
        let q = Query::parse(b"Action=DescribeStacks&StackName=lc-compat-dev&Version=2010-05-15");
        assert_eq!(q.action().as_deref(), Some("DescribeStacks"));
        assert_eq!(q.get("StackName").as_deref(), Some("lc-compat-dev"));
    }

    #[test]
    fn parses_parameters_and_tags() {
        let q = Query::parse(
            b"Action=CreateStack&Parameters.member.1.ParameterKey=Env&Parameters.member.1.ParameterValue=dev&Tags.member.1.Key=team&Tags.member.1.Value=core",
        );
        assert_eq!(q.parameters().get("Env"), Some(&"dev".to_string()));
        assert_eq!(q.tags(), vec![("team".to_string(), "core".to_string())]);
    }

    #[test]
    fn url_decodes_template_body() {
        // '%7B' = '{', '%22' = '"'
        let q = Query::parse(b"Action=CreateStack&TemplateBody=%7B%22a%22%3A1%7D");
        assert_eq!(q.get("TemplateBody").as_deref(), Some("{\"a\":1}"));
    }
}
