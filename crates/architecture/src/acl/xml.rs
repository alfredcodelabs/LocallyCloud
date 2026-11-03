//! A bounded XML tree for Query and REST-XML replies.

use quick_xml::events::Event;
use quick_xml::Reader;

const MAX_DEPTH: usize = 32;
const MAX_ELEMENTS: usize = 100_000;

#[derive(Debug, Default)]
pub(crate) struct Element {
    pub name: String,
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    pub(crate) fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|child| child.name == name)
    }

    pub(crate) fn text_of(&self, name: &str) -> Option<&str> {
        self.child(name).map(|child| child.text.as_str())
    }

    pub(crate) fn members(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter(|child| child.name == "member")
    }
}

/// Parses one document; `None` for malformed, unbounded or entity-declaring input.
pub(crate) fn parse(body: &[u8]) -> Option<Element> {
    let mut reader = Reader::from_reader(body);
    // Entities split text events; trimming each one would corrupt escaped values.
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut stack: Vec<Element> = Vec::new();
    let mut root = None;
    let mut elements = 0usize;
    loop {
        let complete = match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(start)) => {
                elements += 1;
                if stack.len() >= MAX_DEPTH || elements > MAX_ELEMENTS {
                    return None;
                }
                stack.push(Element {
                    name: start.local_name().as_ref().to_owned(),
                    ..Element::default()
                });
                None
            }
            Ok(Event::Empty(empty)) => {
                elements += 1;
                if stack.len() >= MAX_DEPTH || elements > MAX_ELEMENTS {
                    return None;
                }
                Some(Element {
                    name: empty.local_name().as_ref().to_owned(),
                    ..Element::default()
                })
            }
            Ok(Event::Text(text)) => {
                let value = quick_xml::escape::unescape(text.as_ref()).ok()?;
                match stack.last_mut() {
                    Some(element) => element.text.push_str(&value),
                    None if value.trim().is_empty() => {}
                    None => return None,
                }
                None
            }
            Ok(Event::CData(data)) => {
                let value: &str = data.as_ref();
                stack.last_mut()?.text.push_str(value);
                None
            }
            Ok(Event::GeneralRef(reference)) => {
                let encoded = format!("&{};", reference.as_ref());
                let value = quick_xml::escape::unescape(&encoded).ok()?;
                stack.last_mut()?.text.push_str(&value);
                None
            }
            Ok(Event::End(end)) => {
                let mut element = stack.pop()?;
                if element.name != end.local_name().as_ref() {
                    return None;
                }
                if !element.children.is_empty() && element.text.trim().is_empty() {
                    element.text.clear();
                }
                Some(element)
            }
            Ok(Event::Decl(_)) | Ok(Event::Comment(_)) => None,
            Ok(Event::Eof) => break,
            Ok(_) | Err(_) => return None,
        };
        if let Some(element) = complete {
            match stack.last_mut() {
                Some(parent) => parent.children.push(element),
                None if root.is_none() => root = Some(element),
                None => return None,
            }
        }
        buffer.clear();
    }
    if !stack.is_empty() {
        return None;
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_members_and_escaped_text() {
        let root = parse(
            br#"<?xml version="1.0"?><R xmlns="x"><Result><Items><member><V>a &amp; &quot;b&quot;</V></member><member><V/></member></Items></Result></R>"#,
        )
        .unwrap();
        let items = root.child("Result").and_then(|r| r.child("Items")).unwrap();
        let values: Vec<_> = items.members().filter_map(|m| m.text_of("V")).collect();
        assert_eq!(values, ["a & \"b\"", ""]);
    }

    #[test]
    fn rejects_malformed_deep_and_doctype_input() {
        assert!(parse(b"<a><b></a>").is_none());
        assert!(parse(b"<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>").is_none());
        let deep = format!("{}{}", "<a>".repeat(40), "</a>".repeat(40));
        assert!(parse(deep.as_bytes()).is_none());
        assert!(parse(b"<a/><b/>").is_none());
    }
}
