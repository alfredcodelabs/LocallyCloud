//! S3 addressing resolution (virtual-hosted vs path-style) and bucket-name validation.

use crate::error::S3Error;

/// The request shape derived from addressing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    /// No bucket — service-level (e.g. ListBuckets).
    Service,
    /// Bucket-level operation.
    Bucket(String),
    /// Object-level operation.
    Object(String, String),
}

/// Resolve `(bucket, key)` from the Host header and request path, supporting both
/// virtual-hosted-style (`<bucket>.s3...`, `<bucket>.localhost`) and path-style
/// (`/<bucket>/<key>`). The key is returned percent-decoded as opaque UTF-8.
pub fn resolve(host: Option<&str>, path: &str) -> Shape {
    if let Some(bucket) = virtual_hosted_bucket(host) {
        let key = path.trim_start_matches('/');
        return if key.is_empty() {
            Shape::Bucket(bucket)
        } else {
            Shape::Object(bucket, percent_decode(key))
        };
    }
    // Path-style: /<bucket>/<key...>
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Shape::Service;
    }
    match trimmed.split_once('/') {
        Some((bucket, key)) if !key.is_empty() => {
            Shape::Object(bucket.to_string(), percent_decode(key))
        }
        _ => Shape::Bucket(trimmed.trim_end_matches('/').to_string()),
    }
}

/// Return the virtual-hosted bucket label if the host is virtual-hosted-style.
fn virtual_hosted_bucket(host: Option<&str>) -> Option<String> {
    let host = host?;
    let host = host.split(':').next().unwrap_or(host); // strip port
    let host = host.to_ascii_lowercase();
    // <bucket>.s3.<...> or <bucket>.s3-<...>
    if let Some(idx) = host.find(".s3.").or_else(|| host.find(".s3-")) {
        let bucket = &host[..idx];
        if !bucket.is_empty() {
            return Some(bucket.to_string());
        }
    }
    // <bucket>.localhost
    if let Some(bucket) = host.strip_suffix(".localhost") {
        if !bucket.is_empty() && bucket != "s3" {
            return Some(bucket.to_string());
        }
    }
    None
}

/// Percent-decode a key once, preserving every `/` and treating the result as opaque UTF-8.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
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

/// Validate an S3 bucket name; `InvalidBucketName` on violation.
pub fn validate_bucket_name(name: &str) -> Result<(), S3Error> {
    let len = name.len();
    if !(3..=63).contains(&len) {
        return Err(S3Error::InvalidBucketName);
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(S3Error::InvalidBucketName);
    }
    let first = name.as_bytes()[0];
    let last = name.as_bytes()[len - 1];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit())
        || !(last.is_ascii_lowercase() || last.is_ascii_digit())
    {
        return Err(S3Error::InvalidBucketName);
    }
    if name.contains("..") || name.contains(".-") || name.contains("-.") {
        return Err(S3Error::InvalidBucketName);
    }
    if is_ipv4(name) {
        return Err(S3Error::InvalidBucketName);
    }
    // Reserved prefixes/suffixes.
    const BAD_PREFIX: &[&str] = &["xn--", "sthree-", "amzn-s3-demo-"];
    if BAD_PREFIX.iter().any(|p| name.starts_with(p)) {
        return Err(S3Error::InvalidBucketName);
    }
    if name.ends_with("-s3alias") || name.ends_with("--ol-s3") {
        return Err(S3Error::InvalidBucketName);
    }
    Ok(())
}

fn is_ipv4(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_style_object() {
        assert_eq!(
            resolve(Some("localhost:4566"), "/mybucket/path/to/key"),
            Shape::Object("mybucket".into(), "path/to/key".into())
        );
    }

    #[test]
    fn path_style_bucket_and_service() {
        assert_eq!(
            resolve(Some("localhost:4566"), "/mybucket"),
            Shape::Bucket("mybucket".into())
        );
        assert_eq!(resolve(Some("localhost:4566"), "/"), Shape::Service);
    }

    #[test]
    fn virtual_hosted_object() {
        assert_eq!(
            resolve(Some("mybucket.s3.us-east-1.amazonaws.com"), "/path/key"),
            Shape::Object("mybucket".into(), "path/key".into())
        );
        assert_eq!(
            resolve(Some("mybucket.localhost:4566"), "/key"),
            Shape::Object("mybucket".into(), "key".into())
        );
    }

    #[test]
    fn key_is_percent_decoded_preserving_slashes() {
        assert_eq!(
            resolve(Some("localhost"), "/b/a%20b/c%2Bd"),
            Shape::Object("b".into(), "a b/c+d".into())
        );
    }

    #[test]
    fn bucket_name_validation() {
        assert!(validate_bucket_name("my-bucket").is_ok());
        assert!(validate_bucket_name("ab").is_err()); // too short
        assert!(validate_bucket_name("My-Bucket").is_err()); // uppercase
        assert!(validate_bucket_name("-bucket").is_err()); // bad first char
        assert!(validate_bucket_name("bucket..name").is_err()); // double dot
        assert!(validate_bucket_name("192.168.0.1").is_err()); // ipv4
    }
}
