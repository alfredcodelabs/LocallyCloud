//! Digest computation for SNS: MD5 of the body and SHA-256 for content-based dedup.

use md5::Md5;
use sha2::{Digest, Sha256};

/// Lowercase-hex MD5 of the UTF-8 body.
pub fn md5_hex(body: &str) -> String {
    let digest = Md5::digest(body.as_bytes());
    to_hex(&digest)
}

/// Lowercase-hex SHA-256 of the UTF-8 body (content-based deduplication id).
pub fn sha256_hex(body: &str) -> String {
    let digest = Sha256::digest(body.as_bytes());
    to_hex(&digest)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_known() {
        assert_eq!(md5_hex("hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn sha256_deterministic() {
        assert_eq!(sha256_hex("a"), sha256_hex("a"));
        assert_ne!(sha256_hex("a"), sha256_hex("b"));
        assert_eq!(sha256_hex("a").len(), 64);
    }
}
