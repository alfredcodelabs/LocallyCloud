//! Shared form decoding and XML escaping for Monitoring operations.
use std::collections::BTreeMap;

pub(super) fn text_element(name: &str, value: &str) -> String {
    format!("<{name}>{}</{name}>", xml_escape(value))
}

pub(super) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Debug)]
pub(super) struct QueryRequest {
    pub(super) params: BTreeMap<String, String>,
}

impl QueryRequest {
    pub(super) fn parse(body: &[u8]) -> Self {
        let text = String::from_utf8_lossy(body);
        let params = text
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                (form_decode(key), form_decode(value))
            })
            .collect();
        Self { params }
    }

    pub(super) fn get(&self, key: &str) -> Option<&str> {
        self.params
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    pub(super) fn has_prefix(&self, prefix: &str) -> bool {
        self.params
            .range::<str, _>((
                std::ops::Bound::Included(prefix),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .is_some_and(|(key, _)| key.starts_with(prefix))
    }

    pub(super) fn list(&self, prefix: &str) -> Vec<String> {
        let mut values = Vec::new();
        for index in 1.. {
            let Some(value) = self.get(&format!("{prefix}.{index}")) else {
                break;
            };
            values.push(value.to_owned());
        }
        values
    }
}

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
                if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                    output.push((high << 4) | low);
                    index += 3;
                } else {
                    output.push(bytes[index]);
                    index += 1;
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

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
