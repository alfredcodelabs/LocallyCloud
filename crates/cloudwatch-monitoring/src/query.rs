use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct QueryRequest {
    params: BTreeMap<String, String>,
}

impl QueryRequest {
    pub fn parse(body: &[u8]) -> Self {
        let mut params = BTreeMap::new();
        for pair in String::from_utf8_lossy(body).split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            params.insert(form_decode(key), form_decode(value));
        }
        Self { params }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.params
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    pub fn indices(&self, prefix: &str) -> Vec<usize> {
        let mut indices = BTreeSet::new();
        for key in self.params.keys() {
            if let Some(rest) = key.strip_prefix(prefix) {
                if let Some(index) = rest.split('.').next() {
                    if let Ok(index) = index.parse::<usize>() {
                        if index > 0 {
                            indices.insert(index);
                        }
                    }
                }
            }
        }
        indices.into_iter().collect()
    }
}

pub fn response_envelope(action: &str, result: &str, request_id: &str) -> String {
    let result = if result.is_empty() {
        String::new()
    } else {
        format!("<{action}Result>{result}</{action}Result>")
    };
    format!(
        "<{action}Response xmlns=\"{XMLNS}\">{result}<ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></{action}Response>",
        xml_escape(request_id)
    )
}

pub fn text_element(name: &str, value: &str) -> String {
    format!("<{name}>{}</{name}>", xml_escape(value))
}

pub fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub const XMLNS: &str = "http://monitoring.amazonaws.com/doc/2010-08-01/";

fn form_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        output.push((high << 4) | low);
                        index += 3;
                    }
                    _ => {
                        output.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
