//! Minimal XML serialization helpers for S3 REST-XML responses.

/// Escape XML text content.
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// `<name>escaped-text</name>`.
pub fn text_el(name: &str, text: &str) -> String {
    format!("<{name}>{}</{name}>", escape(text))
}

/// XML declaration prefix for S3 documents.
pub const DECL: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_special_chars() {
        assert_eq!(escape("a&b<c>\"d"), "a&amp;b&lt;c&gt;&quot;d");
    }

    #[test]
    fn text_el_wraps() {
        assert_eq!(text_el("Key", "a&b"), "<Key>a&amp;b</Key>");
    }
}
