//! Minimal XML serialization helpers for SNS Query responses.

/// Escape XML text content.
pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// `<name>escaped-text</name>`.
pub fn text_el(name: &str, text: &str) -> String {
    format!("<{name}>{}</{name}>", xml_escape(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_wraps() {
        assert_eq!(text_el("K", "a&b"), "<K>a&amp;b</K>");
    }
}
