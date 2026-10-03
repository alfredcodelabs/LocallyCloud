//! S3 integrity primitives: ETags, additional checksums, and aws-chunked decoding.

use std::collections::BTreeMap;

use base64::Engine;
use bytes::Bytes;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;

use crate::error::S3Error;

/// Algorithms accepted by S3 checksum headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChecksumAlgorithm {
    Crc32,
    Crc32c,
    Crc64Nvme,
    Sha1,
    Sha256,
}

impl ChecksumAlgorithm {
    pub const ALL: [Self; 5] = [
        Self::Crc32,
        Self::Crc32c,
        Self::Crc64Nvme,
        Self::Sha1,
        Self::Sha256,
    ];

    pub fn parse(value: &str) -> Result<Self, S3Error> {
        match value.trim().to_ascii_uppercase().as_str() {
            "CRC32" => Ok(Self::Crc32),
            "CRC32C" => Ok(Self::Crc32c),
            "CRC64NVME" => Ok(Self::Crc64Nvme),
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            _ => Err(S3Error::InvalidRequest(format!(
                "Unsupported checksum algorithm: {value}"
            ))),
        }
    }

    pub fn header_name(self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
        }
    }
}

/// Single-part ETag: quoted lowercase hex MD5 of the bytes.
pub fn etag(bytes: &[u8]) -> String {
    format!("\"{}\"", hex_md5(bytes))
}

/// Lowercase hex MD5 digest.
pub fn hex_md5(bytes: &[u8]) -> String {
    let digest = Md5::digest(bytes);
    let mut s = String::with_capacity(32);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Raw 16-byte MD5 digest (used for the multipart ETag composition).
pub fn md5_raw(bytes: &[u8]) -> [u8; 16] {
    Md5::digest(bytes).into()
}

/// Multipart ETag: `"hex(MD5(concat of part MD5s))-N"`.
pub fn multipart_etag(part_md5s: &[[u8; 16]]) -> String {
    let mut hasher = Md5::new();
    for d in part_md5s {
        hasher.update(d);
    }
    let combined = hasher.finalize();
    let mut hex = String::with_capacity(32);
    for b in combined {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("\"{hex}-{}\"", part_md5s.len())
}

fn reflected_crc(mut crc: u64, bytes: &[u8], polynomial: u64, width: u32) -> u64 {
    for &byte in bytes {
        crc ^= u64::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ polynomial
            } else {
                crc >> 1
            };
        }
    }
    crc ^ if width == 32 {
        u32::MAX as u64
    } else {
        u64::MAX
    }
}

/// Compute the AWS checksum value as base64 of the raw digest bytes.
pub fn checksum_base64(algorithm: ChecksumAlgorithm, bytes: &[u8]) -> String {
    let raw = match algorithm {
        ChecksumAlgorithm::Crc32 => (reflected_crc(u32::MAX as u64, bytes, 0xedb8_8320, 32) as u32)
            .to_be_bytes()
            .to_vec(),
        ChecksumAlgorithm::Crc32c => (reflected_crc(u32::MAX as u64, bytes, 0x82f6_3b78, 32)
            as u32)
            .to_be_bytes()
            .to_vec(),
        ChecksumAlgorithm::Crc64Nvme => reflected_crc(u64::MAX, bytes, 0x9a6c_9329_ac4b_c9b5, 64)
            .to_be_bytes()
            .to_vec(),
        ChecksumAlgorithm::Sha1 => Sha1::digest(bytes).to_vec(),
        ChecksumAlgorithm::Sha256 => Sha256::digest(bytes).to_vec(),
    };
    b64().encode(raw)
}

pub fn validate_checksum(
    algorithm: ChecksumAlgorithm,
    expected: &str,
    body: &[u8],
) -> Result<String, S3Error> {
    let actual = checksum_base64(algorithm, body);
    if expected.trim() != actual {
        return Err(S3Error::BadDigest);
    }
    Ok(actual)
}

/// Decoded data and checksum trailers extracted from an aws-chunked stream.
pub struct DecodedAwsChunked {
    pub body: Bytes,
    pub checksums: BTreeMap<ChecksumAlgorithm, String>,
}

fn invalid_chunked() -> S3Error {
    S3Error::InvalidRequest("Malformed aws-chunked payload".into())
}

fn take_line<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], S3Error> {
    let rest = input.get(*cursor..).ok_or_else(invalid_chunked)?;
    let end = rest
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(invalid_chunked)?;
    *cursor += end + 2;
    Ok(&rest[..end])
}

/// Decode and validate AWS signed chunk framing and trailing checksum headers.
pub fn decode_aws_chunked(
    input: &[u8],
    decoded_content_length: usize,
) -> Result<DecodedAwsChunked, S3Error> {
    let mut cursor = 0;
    let mut decoded = Vec::with_capacity(decoded_content_length);
    loop {
        let line =
            std::str::from_utf8(take_line(input, &mut cursor)?).map_err(|_| invalid_chunked())?;
        let (size, signature) = line
            .split_once(";chunk-signature=")
            .ok_or_else(invalid_chunked)?;
        if size.is_empty()
            || !size.bytes().all(|byte| byte.is_ascii_hexdigit())
            || signature.len() != 64
            || !signature.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid_chunked());
        }
        let size = usize::from_str_radix(size, 16).map_err(|_| invalid_chunked())?;
        if size == 0 {
            break;
        }
        let end = cursor.checked_add(size).ok_or_else(invalid_chunked)?;
        let chunk = input.get(cursor..end).ok_or_else(invalid_chunked)?;
        decoded.extend_from_slice(chunk);
        if input.get(end..end + 2) != Some(b"\r\n") {
            return Err(invalid_chunked());
        }
        cursor = end + 2;
    }

    let mut trailers = BTreeMap::new();
    loop {
        let line = take_line(input, &mut cursor)?;
        if line.is_empty() {
            break;
        }
        let line = std::str::from_utf8(line).map_err(|_| invalid_chunked())?;
        let (name, value) = line.split_once(':').ok_or_else(invalid_chunked)?;
        let suffix = name
            .trim()
            .to_ascii_lowercase()
            .strip_prefix("x-amz-checksum-")
            .map(str::to_string)
            .ok_or_else(invalid_chunked)?;
        let algorithm = ChecksumAlgorithm::parse(&suffix)?;
        if trailers.contains_key(&algorithm) {
            return Err(invalid_chunked());
        }
        trailers.insert(algorithm, value.trim().to_string());
    }
    if cursor != input.len() || decoded.len() != decoded_content_length {
        return Err(invalid_chunked());
    }
    for (&algorithm, expected) in &trailers {
        validate_checksum(algorithm, expected, &decoded)?;
    }
    Ok(DecodedAwsChunked {
        body: Bytes::from(decoded),
        checksums: trailers,
    })
}

/// Standard base64 engine.
fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Validate a `Content-MD5` header against the body.
pub fn validate_content_md5(header: &str, body: &[u8]) -> Result<(), S3Error> {
    let decoded = b64()
        .decode(header.trim())
        .map_err(|_| S3Error::InvalidDigest)?;
    if decoded.len() != 16 {
        return Err(S3Error::InvalidDigest);
    }
    if decoded.as_slice() != md5_raw(body) {
        return Err(S3Error::BadDigest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_is_quoted_hex_md5() {
        assert_eq!(etag(b"hello"), "\"5d41402abc4b2a76b9719d911017c592\"");
    }

    #[test]
    fn multipart_etag_has_part_count_suffix() {
        let parts = [md5_raw(b"a"), md5_raw(b"b")];
        assert!(multipart_etag(&parts).ends_with("-2\""));
    }

    #[test]
    fn checksum_crc_known_vectors() {
        let data = b"123456789";
        let raw = |algorithm| b64().decode(checksum_base64(algorithm, data)).unwrap();
        assert_eq!(raw(ChecksumAlgorithm::Crc32), 0xcbf4_3926_u32.to_be_bytes());
        assert_eq!(
            raw(ChecksumAlgorithm::Crc32c),
            0xe306_9283_u32.to_be_bytes()
        );
        assert_eq!(
            raw(ChecksumAlgorithm::Crc64Nvme),
            0xae8b_1486_0a79_9888_u64.to_be_bytes()
        );
    }

    #[test]
    fn checksum_sha_lengths_are_raw_digest_lengths() {
        assert_eq!(
            b64()
                .decode(checksum_base64(ChecksumAlgorithm::Sha1, b"x"))
                .unwrap()
                .len(),
            20
        );
        assert_eq!(
            b64()
                .decode(checksum_base64(ChecksumAlgorithm::Sha256, b"x"))
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn aws_chunked_decodes_and_validates_trailer() {
        let signature = "0".repeat(64);
        let checksum = checksum_base64(ChecksumAlgorithm::Crc32, b"Wikipedia");
        let wire = format!(
            "4;chunk-signature={signature}\r\nWiki\r\n5;chunk-signature={signature}\r\npedia\r\n0;chunk-signature={signature}\r\nx-amz-checksum-crc32:{checksum}\r\n\r\n"
        );
        let decoded = decode_aws_chunked(wire.as_bytes(), 9).unwrap();
        assert_eq!(decoded.body, Bytes::from_static(b"Wikipedia"));
        assert_eq!(decoded.checksums[&ChecksumAlgorithm::Crc32], checksum);
    }

    #[test]
    fn aws_chunked_rejects_bad_framing_and_length() {
        assert!(matches!(
            decode_aws_chunked(b"4;chunk-signature=nope\r\ntest\r\n", 4),
            Err(S3Error::InvalidRequest(_))
        ));
        let signature = "0".repeat(64);
        let wire = format!("0;chunk-signature={signature}\r\n\r\n");
        assert!(matches!(
            decode_aws_chunked(wire.as_bytes(), 1),
            Err(S3Error::InvalidRequest(_))
        ));
    }

    #[test]
    fn content_md5_validation() {
        let body = b"hello";
        let good = b64().encode(md5_raw(body));
        assert!(validate_content_md5(&good, body).is_ok());
        assert!(matches!(
            validate_content_md5("not-base64-128", body),
            Err(S3Error::InvalidDigest)
        ));
        let wrong = b64().encode(md5_raw(b"other"));
        assert!(matches!(
            validate_content_md5(&wrong, body),
            Err(S3Error::BadDigest)
        ));
    }
}
