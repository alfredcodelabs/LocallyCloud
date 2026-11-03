//! Host-only S3 query signatures; permission and credential revocation remain in IAM.
use super::*;
use std::collections::BTreeMap;

fn decode(value: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let input = value.as_bytes();
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            bytes.push((hex_nibble(*input.get(i + 1)?)? << 4) | hex_nibble(*input.get(i + 2)?)?);
            i += 3;
        } else {
            bytes.push(input[i]);
            i += 1;
        }
    }
    String::from_utf8(bytes).ok()
}

fn parameters(uri: &Uri) -> Option<BTreeMap<String, String>> {
    let query = uri.query()?;
    if query.len() > 16384 {
        return None;
    }
    let mut parameters = BTreeMap::new();
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=')?;
        // Authentication names have one canonical spelling; duplicates fail closed.
        if name.contains('%')
            || parameters.len() >= 32
            || parameters.insert(name.into(), decode(value)?).is_some()
        {
            return None;
        }
    }
    Some(parameters)
}

pub fn query_access_key(uri: &Uri) -> Option<String> {
    let params = parameters(uri)?;
    let credential = params.get("X-Amz-Credential")?;
    let key = credential.split('/').next()?;
    (!key.is_empty() && key.len() <= 256).then(|| key.to_string())
}

fn canonical(query: &str) -> Option<String> {
    let mut pairs = Vec::new();
    for field in query.split('&') {
        let (name, value) = field.split_once('=')?;
        if name == "X-Amz-Signature" {
            continue;
        }
        pairs.push((
            percent_encode(name.as_bytes(), false, true)?,
            percent_encode(value.as_bytes(), false, true)?,
        ));
    }
    pairs.sort_unstable();
    Some(
        pairs
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("&"),
    )
}

fn signing_key(secret: &str, date: &str, region: &str) -> Option<Vec<u8>> {
    let date = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
    let region = hmac(&date, region.as_bytes())?;
    let service = hmac(&region, b"s3")?;
    hmac(&service, b"aws4_request")
}

pub fn presign_s3_put(
    endpoint: &str,
    path: &str,
    region: &str,
    access_key: &str,
    credentials: &SigningCredentials,
    expires: u32,
) -> Option<String> {
    let base: Uri = endpoint.parse().ok()?;
    if !matches!(base.scheme_str(), Some("http" | "https"))
        || base.path() != "/"
        || base.query().is_some()
        || !path.starts_with('/')
        || path.contains('?')
        || !(1..=604800).contains(&expires)
    {
        return None;
    }
    let host = base.authority()?.as_str();
    let date = OffsetDateTime::now_utc()
        .format(
            &format_description::parse_borrowed::<3>("[year][month][day]T[hour][minute][second]Z")
                .ok()?,
        )
        .ok()?;
    let day = date.get(..8)?;
    let scope = format!("{day}/{region}/s3/aws4_request");
    let credential = percent_encode(format!("{access_key}/{scope}").as_bytes(), false, false)?;
    let mut query = format!("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={credential}&X-Amz-Date={date}&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host");
    if let Some(token) = &credentials.session_token {
        query.push_str(&format!(
            "&X-Amz-Security-Token={}",
            percent_encode(token.as_bytes(), false, false)?
        ));
    }
    let request = format!(
        "PUT\n{}\n{}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD",
        canonical_uri(path, "s3")?,
        canonical(&query)?
    );
    let message = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{:x}",
        Sha256::digest(request.as_bytes())
    );
    let signature = hmac(
        &signing_key(&credentials.secret_access_key, day, region)?,
        message.as_bytes(),
    )?
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
    Some(format!(
        "{}{path}?{query}&X-Amz-Signature={signature}",
        endpoint.trim_end_matches('/')
    ))
}

pub(super) fn verify(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    region: &str,
    credentials: impl FnOnce(&str) -> Option<SigningCredentials>,
) -> bool {
    verify_at(
        method,
        uri,
        headers,
        body,
        region,
        credentials,
        OffsetDateTime::now_utc(),
    )
    .unwrap_or(false)
}

fn verify_at(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    region: &str,
    credentials: impl FnOnce(&str) -> Option<SigningCredentials>,
    now: OffsetDateTime,
) -> Option<bool> {
    let params = parameters(uri)?;
    if headers
        .keys()
        .any(|name| name.as_str().starts_with("x-amz-") && name != "x-amz-content-sha256")
    {
        return None;
    }
    if params.get("X-Amz-Algorithm")? != "AWS4-HMAC-SHA256"
        || params.get("X-Amz-SignedHeaders")? != "host"
        || !matches!(*method, Method::GET | Method::PUT)
    {
        return None;
    }
    let fields: Vec<_> = params.get("X-Amz-Credential")?.split('/').collect();
    if fields.len() != 5
        || fields[0].is_empty()
        || fields[1].len() != 8
        || fields[2] != region
        || fields[3] != "s3"
        || fields[4] != "aws4_request"
    {
        return None;
    }
    let credentials = credentials(fields[0])?;
    if params.get("X-Amz-Security-Token").map(String::as_str)
        != credentials.session_token.as_deref()
        || headers.contains_key("x-amz-security-token")
    {
        return None;
    }
    let date = params.get("X-Amz-Date")?;
    if date.len() != 16 || !date.starts_with(fields[1]) {
        return None;
    }
    let time = time::PrimitiveDateTime::parse(
        date,
        &format_description::parse_borrowed::<3>("[year][month][day]T[hour][minute][second]Z")
            .ok()?,
    )
    .ok()?
    .assume_utc();
    let expires = params.get("X-Amz-Expires")?.parse::<i64>().ok()?;
    let age = now - time;
    if !(1..=604800).contains(&expires)
        || age < time::Duration::seconds(-900)
        || age > time::Duration::seconds(expires)
    {
        return None;
    }
    let payload = header(headers, "x-amz-content-sha256").unwrap_or("UNSIGNED-PAYLOAD");
    if payload != "UNSIGNED-PAYLOAD" && payload != format!("{:x}", Sha256::digest(body)) {
        return None;
    }
    let request = format!(
        "{}\n{}\n{}\nhost:{}\n\nhost\n{payload}",
        method,
        canonical_uri(uri.path(), "s3")?,
        canonical(uri.query()?)?,
        header(headers, "host")?
    );
    let message = format!(
        "AWS4-HMAC-SHA256\n{date}\n{}/{region}/s3/aws4_request\n{:x}",
        fields[1],
        Sha256::digest(request.as_bytes())
    );
    let mut verifier = HmacSha256::new_from_slice(&signing_key(
        &credentials.secret_access_key,
        fields[1],
        region,
    )?)
    .ok()?;
    verifier.update(message.as_bytes());
    Some(
        verifier
            .verify_slice(&hex_decode(params.get("X-Amz-Signature")?).ok()?)
            .is_ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> SigningCredentials {
        SigningCredentials {
            secret_access_key: "fixture-secret".into(),
            session_token: Some("temporary+/=".into()),
        }
    }

    #[test]
    fn query_signatures_bind_method_path_host_token_expiry_and_active_issuer() {
        let url = presign_s3_put(
            "http://127.0.0.1:1234",
            "/responses/key%2Bpart",
            "us-east-2",
            "ASIATEST",
            &credentials(),
            60,
        )
        .unwrap();
        let uri: Uri = url.parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("host", "127.0.0.1:1234".parse().unwrap());
        assert_eq!(query_access_key(&uri).as_deref(), Some("ASIATEST"));
        let check = |method: &Method, uri: &Uri, headers: &HeaderMap| {
            verify(
                method,
                uri,
                headers,
                b"provider reply",
                "us-east-2",
                |key| (key == "ASIATEST").then(credentials),
            )
        };
        assert!(check(&Method::PUT, &uri, &headers));
        assert!(!check(&Method::GET, &uri, &headers));
        assert!(!verify(
            &Method::PUT,
            &uri,
            &headers,
            b"",
            "us-east-2",
            |_| None
        ));
        assert!(!verify(
            &Method::PUT,
            &uri,
            &headers,
            b"",
            "us-east-1",
            |_| Some(credentials())
        ));
        for changed in [
            url.replace("/responses/", "/elsewhere/"),
            url.replace("X-Amz-Expires=60", "X-Amz-Expires=600"),
            url.replace("temporary", "forged"),
            format!("{url}&X-Amz-Credential=other"),
        ] {
            assert!(!check(&Method::PUT, &changed.parse().unwrap(), &headers));
        }
        let mut changed_headers = headers.clone();
        for header in ["x-amz-acl", "x-amz-copy-source"] {
            changed_headers.insert(
                http::HeaderName::from_static(header),
                "changed".parse().unwrap(),
            );
            assert!(!check(&Method::PUT, &uri, &changed_headers));
            changed_headers.remove(header);
        }
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            verify_at(
                &Method::PUT,
                &uri,
                &headers,
                b"",
                "us-east-2",
                |_| Some(credentials()),
                now + time::Duration::seconds(61)
            ),
            None
        );
        assert_eq!(
            verify_at(
                &Method::PUT,
                &uri,
                &headers,
                b"",
                "us-east-2",
                |_| Some(credentials()),
                now - time::Duration::seconds(901)
            ),
            None
        );
        headers.insert("host", "127.0.0.1:1235".parse().unwrap());
        assert!(!check(&Method::PUT, &uri, &headers));
        assert!(presign_s3_put(
            "http://127.0.0.1:1234",
            "/responses/key",
            "us-east-2",
            "ASIATEST",
            &credentials(),
            604801
        )
        .is_none());
    }
}
