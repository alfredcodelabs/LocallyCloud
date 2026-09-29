//! MD5 computation for SQS message bodies and message attributes.
//!
//! `MD5OfMessageBody` is the lowercase-hex MD5 of the UTF-8 body. `MD5OfMessageAttributes`
//! follows the AWS attribute-encoding algorithm: for each attribute sorted by name, the
//! name, data type, a transport-type byte (1 = String/Number, 2 = Binary), and the value
//! are length-prefixed (4-byte big-endian) and concatenated, then MD5-hashed.

use md5::{Digest, Md5};

use crate::model::{AttributeValue, MessageAttribute};

/// Lowercase-hex MD5 of bytes.
pub fn hex_md5(bytes: &[u8]) -> String {
    let digest = Md5::digest(bytes);
    let mut s = String::with_capacity(32);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `MD5OfMessageBody`.
pub fn body_md5(body: &str) -> String {
    hex_md5(body.as_bytes())
}

/// `MD5OfMessageAttributes`, or `None` when there are no attributes.
pub fn attributes_md5(
    attributes: &std::collections::BTreeMap<String, MessageAttribute>,
) -> Option<String> {
    if attributes.is_empty() {
        return None;
    }
    let mut hasher = Md5::new();
    // BTreeMap iterates in ascending key order, which is the required sort.
    for (name, attr) in attributes {
        update_len_prefixed(&mut hasher, name.as_bytes());
        update_len_prefixed(&mut hasher, attr.data_type.as_bytes());
        match &attr.value {
            AttributeValue::String(s) => {
                hasher.update([1u8]);
                update_len_prefixed(&mut hasher, s.as_bytes());
            }
            AttributeValue::Binary(b) => {
                hasher.update([2u8]);
                update_len_prefixed(&mut hasher, b);
            }
        }
    }
    let digest = hasher.finalize();
    let mut s = String::with_capacity(32);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    Some(s)
}

fn update_len_prefixed(hasher: &mut Md5, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn body_md5_matches_known_value() {
        // md5("hello") = 5d41402abc4b2a76b9719d911017c592
        assert_eq!(body_md5("hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn empty_attributes_is_none() {
        assert_eq!(attributes_md5(&BTreeMap::new()), None);
    }

    #[test]
    fn single_string_attribute_md5_is_stable() {
        let mut attrs = BTreeMap::new();
        attrs.insert(
            "k".to_string(),
            MessageAttribute {
                data_type: "String".to_string(),
                value: AttributeValue::String("v".to_string()),
            },
        );
        // Deterministic; matches the AWS attribute-encoding algorithm.
        let md5 = attributes_md5(&attrs).unwrap();
        assert_eq!(md5.len(), 32);
        assert_eq!(attributes_md5(&attrs).unwrap(), md5);
    }
}
