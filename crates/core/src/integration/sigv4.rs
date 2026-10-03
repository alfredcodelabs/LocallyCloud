//! SigV4 header verification for ordinary AWS CLI/SDK requests.
//!
//! This verifier intentionally accepts only ordinary, signed, single-request payloads. It
//! rejects presigned requests, streaming payloads, and unsigned payloads. A future broader
//! verifier can add those forms without weakening token issuance.

use hmac::{Hmac, Mac};
use http::{HeaderMap, Method, Uri};
use sha2::{Digest, Sha256};
use time::{format_description, OffsetDateTime};

use super::authorization::SigningCredentials;

type HmacSha256 = Hmac<Sha256>;

pub fn verify(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    expected_region: &str,
    expected_service: &str,
    credentials: impl FnOnce(&str) -> Option<SigningCredentials>,
) -> bool {
    let Some(auth) = header(headers, "authorization") else {
        return false;
    };
    let Some(attrs) = auth.strip_prefix("AWS4-HMAC-SHA256 ") else {
        return false;
    };
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for field in attrs.split(',') {
        let Some((name, value)) = field.trim().split_once('=') else {
            return false;
        };
        match name {
            "Credential" if credential.replace(value).is_none() => {}
            "SignedHeaders" if signed_headers.replace(value).is_none() => {}
            "Signature" if signature.replace(value).is_none() => {}
            _ => return false,
        }
    }
    let (Some(credential), Some(signed_headers), Some(signature)) =
        (credential, signed_headers, signature)
    else {
        return false;
    };
    let parts: Vec<_> = credential.split('/').collect();
    if parts.len() != 5
        || parts[0].is_empty()
        || parts[1].len() != 8
        || !parts[1].bytes().all(|b| b.is_ascii_digit())
        || parts[2] != expected_region
        || parts[3] != expected_service
        || parts[4] != "aws4_request"
    {
        return false;
    }
    let Some(credentials) = credentials(parts[0]) else {
        return false;
    };
    let Some(amz_date) = header(headers, "x-amz-date") else {
        return false;
    };
    if amz_date.len() != 16 || !amz_date.starts_with(parts[1]) {
        return false;
    }
    let Ok(date_format) =
        format_description::parse_borrowed::<3>("[year][month][day]T[hour][minute][second]Z")
    else {
        return false;
    };
    let Ok(request_time) = time::PrimitiveDateTime::parse(amz_date, &date_format) else {
        return false;
    };
    let skew = (OffsetDateTime::now_utc() - request_time.assume_utc())
        .whole_seconds()
        .abs();
    if skew > 900 {
        return false;
    }
    let names: Vec<_> = signed_headers.split(';').collect();
    if names.is_empty()
        || names.windows(2).any(|pair| pair[0] >= pair[1])
        || names.iter().any(|name| {
            name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'-' || b.is_ascii_digit())
        })
        || !names.contains(&"host")
        || !names.contains(&"x-amz-date")
        || (headers.contains_key("x-amz-target") && !names.contains(&"x-amz-target"))
    {
        return false;
    }
    if let Some(token) = credentials.session_token.as_deref() {
        if !names.contains(&"x-amz-security-token")
            || header(headers, "x-amz-security-token") != Some(token)
        {
            return false;
        }
    } else if headers.contains_key("x-amz-security-token") {
        return false;
    }
    let mut canonical_headers = String::new();
    for name in &names {
        let values = headers.get_all(*name);
        let mut iter = values.iter();
        let Some(first) = iter.next() else {
            return false;
        };
        let mut normalized = Vec::new();
        for value in std::iter::once(first).chain(iter) {
            let Ok(value) = value.to_str() else {
                return false;
            };
            normalized.push(value.split_ascii_whitespace().collect::<Vec<_>>().join(" "));
        }
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&normalized.join(","));
        canonical_headers.push('\n');
    }
    let payload_hash = format!("{:x}", Sha256::digest(body));
    if let Some(declared) = header(headers, "x-amz-content-sha256") {
        if declared != payload_hash || !names.contains(&"x-amz-content-sha256") {
            return false;
        }
    }
    let Some(canonical_uri) = canonical_uri(uri.path()) else {
        return false;
    };
    let Some(canonical_query) = canonical_query(uri.query()) else {
        return false;
    };
    // Keep the existing token-issuance surface exact while allowing Query and REST requests
    // for other services to use their normal paths and signed query parameters.
    if expected_service == "ecr"
        && header(headers, "x-amz-target")
            == Some("AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken")
        && (uri.path() != "/" || uri.query().is_some())
    {
        return false;
    }
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash
    );
    let canonical_hash = Sha256::digest(canonical.as_bytes());
    let scope = format!("{}/{}/{}/aws4_request", parts[1], parts[2], parts[3]);
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash:x}");
    let Some(date_key) = hmac(
        format!("AWS4{}", credentials.secret_access_key).as_bytes(),
        parts[1].as_bytes(),
    ) else {
        return false;
    };
    let Some(region_key) = hmac(&date_key, parts[2].as_bytes()) else {
        return false;
    };
    let Some(service_key) = hmac(&region_key, parts[3].as_bytes()) else {
        return false;
    };
    let Some(signing_key) = hmac(&service_key, b"aws4_request") else {
        return false;
    };
    let Ok(signature_bytes) = hex_decode(signature) else {
        return false;
    };
    let Ok(mut verifier) = HmacSha256::new_from_slice(&signing_key) else {
        return false;
    };
    verifier.update(to_sign.as_bytes());
    verifier.verify_slice(&signature_bytes).is_ok()
}

/// Canonicalize an already encoded HTTP path without turning an encoded slash into a path
/// separator. Query/JSON AWS calls normally use `/`; preserving escapes also covers REST paths.
fn canonical_uri(path: &str) -> Option<String> {
    if path.is_empty() {
        return Some("/".to_string());
    }
    percent_encode(path.as_bytes(), true)
}

/// SigV4 sorts encoded query names and values separately. `+` is a literal plus in the URI,
/// not form-urlencoded whitespace. Presigned auth is intentionally outside this verifier.
fn canonical_query(query: Option<&str>) -> Option<String> {
    let Some(query) = query else {
        return Some(String::new());
    };
    if query.is_empty() {
        return Some(String::new());
    }
    let mut pairs = Vec::new();
    for field in query.split('&') {
        let (key, value) = field.split_once('=').unwrap_or((field, ""));
        if key.eq_ignore_ascii_case("X-Amz-Algorithm")
            || key.eq_ignore_ascii_case("X-Amz-Credential")
            || key.eq_ignore_ascii_case("X-Amz-Signature")
        {
            return None;
        }
        pairs.push((
            percent_encode(key.as_bytes(), false)?,
            percent_encode(value.as_bytes(), false)?,
        ));
    }
    pairs.sort_unstable();
    Some(
        pairs
            .into_iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&"),
    )
}

fn percent_encode(input: &[u8], keep_slash: bool) -> Option<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    let mut index = 0;
    while index < input.len() {
        let byte = input[index];
        if byte == b'%' {
            let hi = hex_nibble(*input.get(index + 1)?)?;
            let lo = hex_nibble(*input.get(index + 2)?)?;
            out.push('%');
            out.push(HEX[usize::from(hi)] as char);
            out.push(HEX[usize::from(lo)] as char);
            index += 3;
            continue;
        }
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && byte == b'/')
        {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        index += 1;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn hmac(key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(message);
    Some(mac.finalize().into_bytes().to_vec())
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() != 64 {
        return Err(());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            fn nibble(b: u8) -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    _ => None,
                }
            }
            Ok((nibble(pair[0]).ok_or(())? << 4) | nibble(pair[1]).ok_or(())?)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn signed_request(token: Option<&str>) -> (HeaderMap, Vec<u8>) {
        let date_format =
            format_description::parse_borrowed::<3>("[year][month][day]T[hour][minute][second]Z")
                .unwrap();
        let date = OffsetDateTime::now_utc().format(&date_format).unwrap();
        let day = &date[..8];
        let body = b"{}".to_vec();
        let payload = format!("{:x}", Sha256::digest(&body));
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:4566"));
        headers.insert("x-amz-date", HeaderValue::from_str(&date).unwrap());
        headers.insert(
            "x-amz-target",
            HeaderValue::from_static("AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken"),
        );
        let mut canonical_headers = format!("host:localhost:4566\nx-amz-date:{date}\n");
        let mut signed_headers = "host;x-amz-date;x-amz-target".to_string();
        if let Some(token) = token {
            headers.insert(
                "x-amz-security-token",
                HeaderValue::from_str(token).unwrap(),
            );
            canonical_headers.push_str(&format!("x-amz-security-token:{token}\n"));
            signed_headers = "host;x-amz-date;x-amz-security-token;x-amz-target".into();
        }
        canonical_headers
            .push_str("x-amz-target:AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken\n");
        let canonical = format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload}");
        let scope = format!("{day}/us-east-1/ecr/aws4_request");
        let message = format!(
            "AWS4-HMAC-SHA256\n{date}\n{scope}\n{:x}",
            Sha256::digest(canonical)
        );
        let key = hmac(b"AWS4secret", day.as_bytes()).unwrap();
        let key = hmac(&key, b"us-east-1").unwrap();
        let key = hmac(&key, b"ecr").unwrap();
        let key = hmac(&key, b"aws4_request").unwrap();
        let signature = hmac(&key, message.as_bytes()).unwrap();
        let signature: String = signature.iter().map(|b| format!("{b:02x}")).collect();
        headers.insert("authorization", HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
        )).unwrap());
        (headers, body)
    }

    fn check(headers: &HeaderMap, body: &[u8], token: Option<&str>) -> bool {
        verify(
            &Method::POST,
            &"/".parse().unwrap(),
            headers,
            body,
            "us-east-1",
            "ecr",
            |key| {
                (key == "AKID").then(|| SigningCredentials {
                    secret_access_key: "secret".into(),
                    session_token: token.map(str::to_string),
                })
            },
        )
    }

    fn signed_query_request(uri: &Uri, service: &str) -> HeaderMap {
        let date_format =
            format_description::parse_borrowed::<3>("[year][month][day]T[hour][minute][second]Z")
                .unwrap();
        let date = OffsetDateTime::now_utc().format(&date_format).unwrap();
        let day = &date[..8];
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:4566"));
        headers.insert("x-amz-date", HeaderValue::from_str(&date).unwrap());
        let canonical = format!(
            "GET\n{}\n{}\nhost:localhost:4566\nx-amz-date:{date}\n\nhost;x-amz-date\n{:x}",
            canonical_uri(uri.path()).unwrap(),
            canonical_query(uri.query()).unwrap(),
            Sha256::digest([]),
        );
        let scope = format!("{day}/us-east-1/{service}/aws4_request");
        let message = format!(
            "AWS4-HMAC-SHA256\n{date}\n{scope}\n{:x}",
            Sha256::digest(canonical),
        );
        let key = hmac(b"AWS4secret", day.as_bytes()).unwrap();
        let key = hmac(&key, b"us-east-1").unwrap();
        let key = hmac(&key, service.as_bytes()).unwrap();
        let key = hmac(&key, b"aws4_request").unwrap();
        let signature = hmac(&key, message.as_bytes()).unwrap();
        let signature: String = signature.iter().map(|b| format!("{b:02x}")).collect();
        headers.insert("authorization", HeaderValue::from_str(&format!(
            "AWS4-HMAC-SHA256 Credential=AKID/{scope}, SignedHeaders=host;x-amz-date, Signature={signature}"
        )).unwrap());
        headers
    }

    #[test]
    fn accepts_query_request_and_rejects_query_or_path_changes() {
        let uri: Uri = "/?Version=2010-05-08&Action=ListUsers".parse().unwrap();
        let headers = signed_query_request(&uri, "iam");
        let check = |uri: &Uri, headers: &HeaderMap| {
            verify(&Method::GET, uri, headers, b"", "us-east-1", "iam", |key| {
                (key == "AKID").then(|| SigningCredentials {
                    secret_access_key: "secret".into(),
                    session_token: None,
                })
            })
        };
        assert!(check(&uri, &headers));
        assert!(!check(
            &"/?Version=2010-05-08&Action=DeleteUser".parse().unwrap(),
            &headers
        ));
        assert!(!check(
            &"/different?Version=2010-05-08&Action=ListUsers"
                .parse()
                .unwrap(),
            &headers
        ));
        assert!(!check(
            &"/?X-Amz-Algorithm=AWS4-HMAC-SHA256".parse().unwrap(),
            &headers
        ));
        assert_eq!(
            canonical_query(Some("z=3&a=hello+world&a=%20")),
            Some("a=%20&a=hello%2Bworld&z=3".into())
        );
    }

    #[test]
    fn rejects_unsigned_target_and_invalid_percent_escape() {
        let uri: Uri = "/path%2Fitem?b=2&a=1".parse().unwrap();
        let mut headers = signed_query_request(&uri, "ecs");
        assert!(verify(
            &Method::GET,
            &uri,
            &headers,
            b"",
            "us-east-1",
            "ecs",
            |_| {
                Some(SigningCredentials {
                    secret_access_key: "secret".into(),
                    session_token: None,
                })
            }
        ));
        headers.insert(
            "x-amz-target",
            HeaderValue::from_static("AmazonECS.DescribeClusters"),
        );
        assert!(!verify(
            &Method::GET,
            &uri,
            &headers,
            b"",
            "us-east-1",
            "ecs",
            |_| {
                Some(SigningCredentials {
                    secret_access_key: "secret".into(),
                    session_token: None,
                })
            }
        ));
        assert_eq!(canonical_uri("/bad%XX"), None);
        assert_eq!(canonical_query(Some("a=%XX")), None);
    }

    #[test]
    fn accepts_valid_signature_and_rejects_forged_or_changed_requests() {
        let (mut headers, body) = signed_request(None);
        assert!(check(&headers, &body, None));
        assert!(!check(&headers, b"{\"registryIds\":[]}", None));
        assert!(!verify(
            &Method::POST,
            &"/".parse().unwrap(),
            &headers,
            &body,
            "us-east-1",
            "ecr",
            |_| None
        ));
        headers.insert(
            "x-amz-target",
            HeaderValue::from_static("AmazonEC2ContainerRegistry_V20150921.DescribeRepositories"),
        );
        assert!(!check(&headers, &body, None));
    }

    #[test]
    fn session_token_is_required_and_bound_to_signature() {
        let (mut headers, body) = signed_request(Some("session"));
        assert!(check(&headers, &body, Some("session")));
        assert!(!check(&headers, &body, Some("other")));
        headers.remove("x-amz-security-token");
        assert!(!check(&headers, &body, Some("session")));
    }
}
