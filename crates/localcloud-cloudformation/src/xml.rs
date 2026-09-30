//! XML helpers for the Query-protocol response envelope.

use crate::error::CFN_XMLNS;

/// Escape a string for XML text/attribute content.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// A `<name>escaped-value</name>` element.
pub fn text_el(name: &str, value: &str) -> String {
    format!("<{name}>{}</{name}>", xml_escape(value))
}

/// Wrap a result body in the CloudFormation Query response envelope.
pub fn query_envelope(operation: &str, inner: &str, request_id: &str) -> String {
    let result = format!("<{operation}Result>{inner}</{operation}Result>");
    format!(
        "<{operation}Response xmlns=\"{CFN_XMLNS}\">{result}<ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></{operation}Response>",
        xml_escape(request_id),
    )
}
