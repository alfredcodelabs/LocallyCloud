//! Persisted lifecycle/logging control plane. This module does not execute lifecycle jobs
//! or deliver access logs. Ownership enforcement is applied by every object-write path.
use super::*;
use std::collections::BTreeSet;

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Lifecycle,
    Logging,
    Ownership,
}
impl Kind {
    fn root(self) -> &'static str {
        match self {
            Self::Lifecycle => "LifecycleConfiguration",
            Self::Logging => "BucketLoggingStatus",
            Self::Ownership => "OwnershipControls",
        }
    }
    fn value(self, state: &BucketState) -> &Option<String> {
        match self {
            Self::Lifecycle => &state.lifecycle,
            Self::Logging => &state.logging,
            Self::Ownership => &state.ownership_controls,
        }
    }
    fn assign(self, state: &mut BucketState, value: Option<String>) {
        match self {
            Self::Lifecycle => state.lifecycle = value,
            Self::Logging => state.logging = value,
            Self::Ownership => state.ownership_controls = value,
        }
    }
}
fn fields(node: &XmlNode, names: &[&str], repeated: &[&str]) -> Result<(), S3Error> {
    if !node.text.trim().is_empty() {
        return Err(S3Error::MalformedXML);
    }
    let mut seen = BTreeSet::new();
    for child in &node.children {
        if !names.contains(&child.name.as_str())
            || (!seen.insert(child.name.as_str()) && !repeated.contains(&child.name.as_str()))
        {
            return Err(S3Error::MalformedXML);
        }
    }
    Ok(())
}
fn required<'a>(node: &'a XmlNode, name: &str) -> Result<&'a str, S3Error> {
    child_text(node, name).ok_or(S3Error::MalformedXML)
}
fn integer(node: &XmlNode, name: &str, minimum: u64, maximum: u64) -> Result<(), S3Error> {
    let value = required(node, name)?
        .parse::<u64>()
        .map_err(|_| S3Error::MalformedXML)?;
    if value < minimum || value > maximum {
        return Err(S3Error::InvalidArgument(format!(
            "Invalid lifecycle {name}"
        )));
    }
    Ok(())
}
fn text(node: &XmlNode, maximum: usize) -> Result<(), S3Error> {
    if !node.children.is_empty() || node.text.len() > maximum {
        return Err(S3Error::MalformedXML);
    }
    Ok(())
}
fn date(node: &XmlNode, name: &str) -> Result<(), S3Error> {
    let date = OffsetDateTime::parse(required(node, name)?, &Rfc3339)
        .map_err(|_| S3Error::MalformedXML)?;
    if date.offset() != time::UtcOffset::UTC || date.time() != time::Time::MIDNIGHT {
        return Err(S3Error::InvalidArgument(
            "Lifecycle Date must be midnight UTC".into(),
        ));
    }
    Ok(())
}
fn filter(node: &XmlNode, conjunction: bool) -> Result<(), S3Error> {
    fields(
        node,
        &["Prefix", "Tag", "And"],
        if conjunction { &["Tag"] } else { &[] },
    )?;
    if (!conjunction && node.children.len() > 1) || (conjunction && node.children.len() < 2) {
        return Err(S3Error::MalformedXML);
    }
    let mut keys = BTreeSet::new();
    for child in &node.children {
        match child.name.as_str() {
            "Prefix" => text(child, 1024)?,
            "Tag" => {
                fields(child, &["Key", "Value"], &[])?;
                let key = required(child, "Key")?;
                if key.is_empty()
                    || key.len() > 128
                    || !keys.insert(key)
                    || required(child, "Value")?.len() > 256
                {
                    return Err(S3Error::MalformedXML);
                }
            }
            "And" if !conjunction => filter(child, true)?,
            _ => return Err(S3Error::MalformedXML),
        }
    }
    Ok(())
}
fn lifecycle(root: &XmlNode) -> Result<(), S3Error> {
    fields(root, &["Rule"], &["Rule"])?;
    if root.children.is_empty() || root.children.len() > 1000 {
        return Err(S3Error::InvalidArgument(
            "Lifecycle requires 1..1000 rules".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    for rule in &root.children {
        fields(
            rule,
            &[
                "ID",
                "Prefix",
                "Filter",
                "Status",
                "Expiration",
                "Transition",
                "NoncurrentVersionExpiration",
                "NoncurrentVersionTransition",
                "AbortIncompleteMultipartUpload",
            ],
            &["Transition", "NoncurrentVersionTransition"],
        )?;
        if !matches!(required(rule, "Status")?, "Enabled" | "Disabled") {
            return Err(S3Error::MalformedXML);
        }
        if child_text(rule, "Prefix").is_some() && rule.children.iter().any(|n| n.name == "Filter")
        {
            return Err(S3Error::MalformedXML);
        }
        if !rule.children.iter().any(|n| {
            matches!(
                n.name.as_str(),
                "Expiration"
                    | "Transition"
                    | "NoncurrentVersionExpiration"
                    | "NoncurrentVersionTransition"
                    | "AbortIncompleteMultipartUpload"
            )
        }) {
            return Err(S3Error::MalformedXML);
        }
        for child in &rule.children {
            match child.name.as_str() {
                "ID" => {
                    text(child, 255)?;
                    if !ids.insert(child.text.as_str()) {
                        return Err(S3Error::InvalidArgument(
                            "Lifecycle rule IDs must be unique".into(),
                        ));
                    }
                }
                "Prefix" => text(child, 1024)?,
                "Filter" => filter(child, false)?,
                "Status" => text(child, 8)?,
                "Expiration" => {
                    fields(child, &["Days", "Date", "ExpiredObjectDeleteMarker"], &[])?;
                    if child.children.len() != 1 {
                        return Err(S3Error::MalformedXML);
                    }
                    match child.children.first().map(|n| n.name.as_str()) {
                        Some("Days") => integer(child, "Days", 1, i32::MAX as u64)?,
                        Some("Date") => date(child, "Date")?,
                        Some("ExpiredObjectDeleteMarker")
                            if matches!(
                                required(child, "ExpiredObjectDeleteMarker")?,
                                "true" | "false"
                            ) => {}
                        _ => return Err(S3Error::MalformedXML),
                    }
                }
                "Transition" | "NoncurrentVersionTransition" => {
                    let noncurrent = child.name == "NoncurrentVersionTransition";
                    fields(
                        child,
                        if noncurrent {
                            &["NoncurrentDays", "StorageClass", "NewerNoncurrentVersions"]
                        } else {
                            &["Days", "Date", "StorageClass"]
                        },
                        &[],
                    )?;
                    if !matches!(
                        required(child, "StorageClass")?,
                        "GLACIER"
                            | "GLACIER_IR"
                            | "DEEP_ARCHIVE"
                            | "STANDARD_IA"
                            | "ONEZONE_IA"
                            | "INTELLIGENT_TIERING"
                    ) {
                        return Err(S3Error::InvalidArgument(
                            "Invalid lifecycle StorageClass".into(),
                        ));
                    }
                    if noncurrent {
                        integer(child, "NoncurrentDays", 1, i32::MAX as u64)?;
                    } else if child_text(child, "Days").is_some()
                        && child_text(child, "Date").is_none()
                    {
                        integer(child, "Days", 0, i32::MAX as u64)?;
                    } else if child_text(child, "Days").is_none() {
                        date(child, "Date")?;
                    } else {
                        return Err(S3Error::MalformedXML);
                    }
                    if child_text(child, "NewerNoncurrentVersions").is_some() {
                        integer(child, "NewerNoncurrentVersions", 1, 100)?;
                    }
                }
                "NoncurrentVersionExpiration" => {
                    fields(child, &["NoncurrentDays", "NewerNoncurrentVersions"], &[])?;
                    integer(child, "NoncurrentDays", 1, i32::MAX as u64)?;
                    if child_text(child, "NewerNoncurrentVersions").is_some() {
                        integer(child, "NewerNoncurrentVersions", 1, 100)?;
                    }
                }
                "AbortIncompleteMultipartUpload" => {
                    fields(child, &["DaysAfterInitiation"], &[])?;
                    integer(child, "DaysAfterInitiation", 1, i32::MAX as u64)?;
                }
                _ => return Err(S3Error::MalformedXML),
            }
        }
    }
    Ok(())
}
pub(super) fn validate_lifecycle(body: &[u8]) -> Result<(), S3Error> {
    let root = parse_xml_with_limits(body, 1_048_576, 20_000)?;
    if root.name != "LifecycleConfiguration" {
        return Err(S3Error::MalformedXML);
    }
    lifecycle(&root)
}
fn render(node: &XmlNode, root: bool) -> String {
    let mut xml = if root {
        format!("{DECL}<{} xmlns=\"{S3_XMLNS}\">", node.name)
    } else {
        format!("<{}>", node.name)
    };
    xml.push_str(&escape(&node.text));
    for child in &node.children {
        xml.push_str(&render(child, false));
    }
    xml.push_str(&format!("</{}>", node.name));
    xml
}
pub(crate) async fn get(ctx: &Ctx<'_>, name: &str, kind: Kind) -> Result<Response, S3Error> {
    let bucket = bucket(ctx, name).await?;
    let xml = kind.value(&*bucket.read().await).clone();
    let xml = match (kind, xml) {
        (_, Some(xml)) => xml,
        (Kind::Lifecycle, None) => return Err(S3Error::NoSuchLifecycleConfiguration),
        (Kind::Ownership, None) => return Err(S3Error::OwnershipControlsNotFoundError),
        (Kind::Logging, None) => format!("{DECL}<BucketLoggingStatus xmlns=\"{S3_XMLNS}\"/>"),
    };
    Ok(xml_ok(xml, ctx.request_id))
}
pub(crate) async fn put(
    ctx: &Ctx<'_>,
    name: &str,
    kind: Kind,
    body: &[u8],
) -> Result<Response, S3Error> {
    let bucket = bucket(ctx, name).await?;
    let root = parse_xml_with_limits(body, 1_048_576, 20_000)?;
    if root.name != kind.root() {
        return Err(S3Error::MalformedXML);
    }
    match kind {
        Kind::Lifecycle => lifecycle(&root)?,
        Kind::Ownership => {
            fields(&root, &["Rule"], &[])?;
            let rule = root.children.first().ok_or(S3Error::MalformedXML)?;
            fields(rule, &["ObjectOwnership"], &[])?;
            if required(rule, "ObjectOwnership")? != "BucketOwnerEnforced" {
                return Err(S3Error::NotImplemented(
                    "Only BucketOwnerEnforced ownership is supported".into(),
                ));
            }
        }
        Kind::Logging => {
            fields(&root, &["LoggingEnabled"], &[])?;
            if let Some(logging) = root.children.first() {
                fields(logging, &["TargetBucket", "TargetPrefix"], &[])?;
                let target = required(logging, "TargetBucket")?;
                if required(logging, "TargetPrefix")?.len() > 1024 {
                    return Err(S3Error::MalformedXML);
                }
                let destination = ctx.store.get(ctx.storage_account, target).ok_or_else(|| {
                    S3Error::InvalidArgument(
                        "Logging target bucket does not exist or is not owned by this account"
                            .into(),
                    )
                })?;
                if destination.read().await.region != ctx.region {
                    return Err(S3Error::InvalidArgument(
                        "Logging target bucket must be in the same region".into(),
                    ));
                }
            }
        }
    }
    let value = if matches!(kind, Kind::Logging) && root.children.is_empty() {
        None
    } else {
        Some(render(&root, true))
    };
    kind.assign(&mut *bucket.write().await, value);
    Ok(status_only(200, ctx.request_id))
}
pub(crate) async fn delete(ctx: &Ctx<'_>, name: &str, kind: Kind) -> Result<Response, S3Error> {
    let bucket = bucket(ctx, name).await?;
    kind.assign(&mut *bucket.write().await, None);
    Ok(status_only(204, ctx.request_id))
}
pub(crate) async fn validate_acl(
    ctx: &Ctx<'_>,
    name: &str,
    headers: &HeaderMap,
) -> Result<(), S3Error> {
    let bucket = bucket(ctx, name).await?;
    if bucket.read().await.ownership_controls.is_some()
        && (headers
            .keys()
            .any(|key| key.as_str().starts_with("x-amz-grant-"))
            || headers
                .get("x-amz-acl")
                .is_some_and(|acl| acl.as_bytes() != b"bucket-owner-full-control"))
    {
        return Err(S3Error::AccessControlListNotSupported);
    }
    Ok(())
}
pub(crate) async fn ownership_enforced(ctx: &Ctx<'_>, name: &str) -> Result<bool, S3Error> {
    let bucket = bucket(ctx, name).await?;
    let enforced = bucket.read().await.ownership_controls.is_some();
    Ok(enforced)
}
