//! AWS unique-identifier and credential generation.
//!
//! IAM resources carry a typed unique id with an AWS prefix (`AIDA` users, `AGPA` groups,
//! `AROA` roles, `ANPA` policies, `AIPA` instance profiles, `AKIA` access keys); STS
//! temporary credentials use `ASIA`. Randomness is derived from UUIDv4 bytes so no extra
//! RNG dependency is needed.

use uuid::Uuid;

/// Unique-id prefixes per AWS resource type.
pub const USER: &str = "AIDA";
pub const GROUP: &str = "AGPA";
pub const ROLE: &str = "AROA";
pub const POLICY: &str = "ANPA";
pub const INSTANCE_PROFILE: &str = "AIPA";
pub const ACCESS_KEY: &str = "AKIA";
pub const TEMP_CREDENTIAL: &str = "ASIA";

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A unique id: the AWS prefix followed by 17 uppercase base32 characters.
pub fn unique_id(prefix: &str) -> String {
    let mut s = String::with_capacity(prefix.len() + 17);
    s.push_str(prefix);
    s.push_str(&base32(17));
    s
}

/// A 40-character secret access key over the AWS base64 alphabet.
pub fn secret_access_key() -> String {
    let mut bytes = Vec::with_capacity(48);
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    let mut s = String::with_capacity(40);
    for b in bytes.iter().take(40) {
        s.push(BASE64URL[(*b % 64) as usize] as char);
    }
    s
}

/// An opaque non-empty session token.
pub fn session_token() -> String {
    format!("{}{}", base32(32), base32(32))
}

/// `n` random uppercase base32 characters.
fn base32(n: usize) -> String {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        for b in Uuid::new_v4().as_bytes() {
            if out.len() == n {
                break;
            }
            out.push(BASE32[(*b % 32) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_id_has_prefix_and_length() {
        let id = unique_id(ROLE);
        assert!(id.starts_with("AROA"));
        assert_eq!(id.len(), 4 + 17);
        assert!(id[4..].chars().all(|c| BASE32.contains(&(c as u8))));
    }

    #[test]
    fn unique_ids_are_distinct() {
        assert_ne!(unique_id(USER), unique_id(USER));
    }

    #[test]
    fn secret_is_40_chars() {
        assert_eq!(secret_access_key().len(), 40);
    }

    #[test]
    fn session_token_is_non_empty() {
        assert!(!session_token().is_empty());
    }
}
