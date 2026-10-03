//! Bounded DER and PEM validation for the supported RSA import profile.
//! No private-key bytes leave this module. Certificate chains are rejected
//! until full path validation can be performed.

use ring::signature::{KeyPair, RsaKeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use time::{Date, Month, PrimitiveDateTime, Time};

#[derive(Clone)]
pub(super) struct MaterialMetadata {
    pub domain: String,
    pub names: Vec<String>,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub key_algorithm: &'static str,
}

#[derive(Clone, Copy)]
struct Der<'a> {
    tag: u8,
    value: &'a [u8],
    full: &'a [u8],
}

fn take<'a>(input: &mut &'a [u8]) -> Result<Der<'a>, ()> {
    if input.len() < 2 {
        return Err(());
    }
    let start = *input;
    let tag = input[0];
    let mut offset = 2;
    let len = if input[1] & 0x80 == 0 {
        input[1] as usize
    } else {
        let count = (input[1] & 0x7f) as usize;
        if count == 0 || count > 4 || input.len() < 2 + count {
            return Err(());
        }
        offset += count;
        let mut len = 0usize;
        for byte in &input[2..offset] {
            len = (len << 8) | *byte as usize;
        }
        if len < 128 {
            return Err(());
        }
        len
    };
    let end = offset.checked_add(len).ok_or(())?;
    if end > input.len() {
        return Err(());
    }
    *input = &start[end..];
    Ok(Der {
        tag,
        value: &start[offset..end],
        full: &start[..end],
    })
}

fn expect<'a>(input: &mut &'a [u8], tag: u8) -> Result<Der<'a>, ()> {
    let item = take(input)?;
    if item.tag != tag {
        return Err(());
    }
    Ok(item)
}

fn sole(input: &[u8], tag: u8) -> Result<Der<'_>, ()> {
    let mut rest = input;
    let item = expect(&mut rest, tag)?;
    if !rest.is_empty() {
        return Err(());
    }
    Ok(item)
}

fn oid(sequence: &[u8], expected: &[u8]) -> Result<(), ()> {
    let mut rest = sequence;
    let actual = expect(&mut rest, 0x06)?;
    if actual.value != expected {
        return Err(());
    }
    Ok(())
}

fn name_cn(raw: &[u8]) -> Result<String, ()> {
    let name = sole(raw, 0x30)?;
    let mut rdns = name.value;
    while !rdns.is_empty() {
        let set = expect(&mut rdns, 0x31)?;
        let mut attrs = set.value;
        while !attrs.is_empty() {
            let attr = expect(&mut attrs, 0x30)?;
            let mut fields = attr.value;
            let kind = expect(&mut fields, 0x06)?;
            let value = take(&mut fields)?;
            if !fields.is_empty() {
                return Err(());
            }
            if kind.value == [0x55, 0x04, 0x03] {
                if ![0x0c, 0x13, 0x16].contains(&value.tag) {
                    return Err(());
                }
                let cn = std::str::from_utf8(value.value).map_err(|_| ())?;
                if cn.is_empty() || cn.len() > 253 {
                    return Err(());
                }
                return Ok(cn.to_owned());
            }
        }
    }
    Err(())
}

fn utc_timestamp(raw: Der<'_>) -> Result<i64, ()> {
    let text = std::str::from_utf8(raw.value).map_err(|_| ())?;
    let (year, tail) = match raw.tag {
        0x17 if text.len() == 13 && text.ends_with('Z') => {
            let year = text[0..2].parse::<i32>().map_err(|_| ())?;
            (
                if year >= 50 { 1900 + year } else { 2000 + year },
                &text[2..12],
            )
        }
        0x18 if text.len() == 15 && text.ends_with('Z') => {
            (text[0..4].parse::<i32>().map_err(|_| ())?, &text[4..14])
        }
        _ => return Err(()),
    };
    let month = tail[0..2].parse::<u8>().map_err(|_| ())?;
    let day = tail[2..4].parse::<u8>().map_err(|_| ())?;
    let hour = tail[4..6].parse::<u8>().map_err(|_| ())?;
    let minute = tail[6..8].parse::<u8>().map_err(|_| ())?;
    let second = tail[8..10].parse::<u8>().map_err(|_| ())?;
    let date = Date::from_calendar_date(year, Month::try_from(month).map_err(|_| ())?, day)
        .map_err(|_| ())?;
    let time = Time::from_hms(hour, minute, second).map_err(|_| ())?;
    Ok(PrimitiveDateTime::new(date, time)
        .assume_utc()
        .unix_timestamp())
}

fn names_from_extensions(raw: &[u8]) -> Result<Vec<String>, ()> {
    let extensions = sole(raw, 0x30)?;
    let mut entries = extensions.value;
    let mut names = Vec::new();
    while !entries.is_empty() {
        let extension = expect(&mut entries, 0x30)?;
        let mut fields = extension.value;
        let kind = expect(&mut fields, 0x06)?;
        if fields.first() == Some(&0x01) {
            expect(&mut fields, 0x01)?;
        }
        let encoded = expect(&mut fields, 0x04)?;
        if !fields.is_empty() {
            return Err(());
        }
        if kind.value == [0x55, 0x1d, 0x11] {
            let general_names = sole(encoded.value, 0x30)?;
            let mut records = general_names.value;
            while !records.is_empty() {
                let item = take(&mut records)?;
                if item.tag == 0x82 {
                    let name = std::str::from_utf8(item.value).map_err(|_| ())?;
                    names.push(name.to_owned());
                }
            }
        }
    }
    Ok(names)
}

fn valid_dns_name(raw: &str) -> bool {
    let name = raw.strip_prefix("*.").unwrap_or(raw);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

pub(super) fn validate(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    now: i64,
) -> Result<MaterialMetadata, ()> {
    if certificate_pem.is_empty()
        || certificate_pem.len() > 32768
        || private_key_pem.is_empty()
        || private_key_pem.len() > 5120
    {
        return Err(());
    }
    let mut certs = pem::parse_many(certificate_pem).map_err(|_| ())?;
    let mut keys = pem::parse_many(private_key_pem).map_err(|_| ())?;
    if certs.len() != 1 || keys.len() != 1 {
        return Err(());
    }
    let cert_pem = certs.remove(0);
    let key_pem = keys.remove(0);
    if cert_pem.tag() != "CERTIFICATE" || key_pem.tag() != "PRIVATE KEY" {
        return Err(());
    }
    let cert = sole(cert_pem.contents(), 0x30)?;
    let mut envelope = cert.value;
    let tbs = expect(&mut envelope, 0x30)?;
    let sig_alg = expect(&mut envelope, 0x30)?;
    let signature = expect(&mut envelope, 0x03)?;
    if !envelope.is_empty() || signature.value.first() != Some(&0) {
        return Err(());
    }
    const SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    oid(sig_alg.value, SHA256_RSA)?;
    let mut fields = tbs.value;
    let version = expect(&mut fields, 0xa0)?;
    if sole(version.value, 0x02)?.value != [2] {
        return Err(());
    }
    let serial = expect(&mut fields, 0x02)?;
    if serial.value.is_empty() || serial.value.len() > 20 {
        return Err(());
    }
    let tbs_sig_alg = expect(&mut fields, 0x30)?;
    oid(tbs_sig_alg.value, SHA256_RSA)?;
    let issuer = expect(&mut fields, 0x30)?;
    let validity = expect(&mut fields, 0x30)?;
    let subject = expect(&mut fields, 0x30)?;
    let spki = expect(&mut fields, 0x30)?;
    let issuer_cn = name_cn(issuer.full)?;
    let subject_cn = name_cn(subject.full)?;
    // Without a verified chain, only cryptographically valid self-signed leaves are accepted.
    if issuer.full != subject.full {
        return Err(());
    }
    let mut dates = validity.value;
    let not_before = utc_timestamp(take(&mut dates)?)?;
    let not_after = utc_timestamp(take(&mut dates)?)?;
    if !dates.is_empty() || now < not_before || now >= not_after {
        return Err(());
    }
    let mut spki_fields = spki.value;
    let algorithm = expect(&mut spki_fields, 0x30)?;
    const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    oid(algorithm.value, RSA_OID)?;
    let bit_string = expect(&mut spki_fields, 0x03)?;
    if !spki_fields.is_empty() || bit_string.value.first() != Some(&0) {
        return Err(());
    }
    let public_key = &bit_string.value[1..];
    let rsa = sole(public_key, 0x30)?;
    let mut rsa_parts = rsa.value;
    let modulus = expect(&mut rsa_parts, 0x02)?;
    let _exponent = expect(&mut rsa_parts, 0x02)?;
    if !rsa_parts.is_empty() {
        return Err(());
    }
    let bits = modulus
        .value
        .len()
        .saturating_sub(usize::from(modulus.value.first() == Some(&0)))
        * 8;
    let key_algorithm = match bits {
        2048 => "RSA_2048",
        3072 => "RSA_3072",
        4096 => "RSA_4096",
        _ => return Err(()),
    };
    let key = RsaKeyPair::from_pkcs8(key_pem.contents()).map_err(|_| ())?;
    if key.public_key().as_ref() != public_key {
        return Err(());
    }
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key)
        .verify(tbs.full, &signature.value[1..])
        .map_err(|_| ())?;
    let mut names = Vec::new();
    while !fields.is_empty() {
        let field = take(&mut fields)?;
        if field.tag == 0xa3 {
            if !names.is_empty() {
                return Err(());
            }
            names = names_from_extensions(field.value)?;
        } else if ![0x81, 0x82].contains(&field.tag) {
            return Err(());
        }
    }
    if !valid_dns_name(&subject_cn) || names.iter().any(|name| !valid_dns_name(name)) {
        return Err(());
    }
    if names.is_empty() {
        names.push(subject_cn.clone());
    }
    names.sort();
    names.dedup();
    let serial = serial
        .value
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(MaterialMetadata {
        domain: subject_cn.clone(),
        names,
        subject: format!("CN={subject_cn}"),
        issuer: format!("CN={issuer_cn}"),
        serial,
        not_before,
        not_after,
        key_algorithm,
    })
}
