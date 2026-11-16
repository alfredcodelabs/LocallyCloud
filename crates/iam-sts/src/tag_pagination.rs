//! Bounded tag pages over the existing sorted entity maps. Cursors contain no credentials.
use crate::error::IamStsError;
use crate::model::tags_xml;
use crate::query::{text_el, QueryRequest};
use crate::store::IamStore;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Included, Unbounded};

// AWS permits returning fewer than MaxItems. Fifty also bounds responses for legacy stores.
const PAGE_LIMIT: usize = 50;
// Includes a 2,048-byte policy ARN, Unicode tag key and serialized scope metadata.
const MAX_MARKER_BYTES: usize = 8192;

// A valid Unicode key is at most 512 UTF-8 bytes. Avoid another large allocation for
// legacy keys before deciding whether their continuation needs an offset instead.
const MAX_DIRECT_KEY_BYTES: usize = MAX_MARKER_BYTES / 4 * 3;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Position {
    Key(String),
    // Legacy-only fallback: O(N) borrowed traversal, with O(page) materialization.
    Offset(usize),
}

#[derive(Clone, Copy)]
pub(crate) enum TagKind {
    User,
    Role,
    Policy,
    InstanceProfile,
}

impl TagKind {
    fn operation(self) -> &'static str {
        match self {
            Self::User => "ListUserTags",
            Self::Role => "ListRoleTags",
            Self::Policy => "ListPolicyTags",
            Self::InstanceProfile => "ListInstanceProfileTags",
        }
    }

    fn parameter(self) -> &'static str {
        match self {
            Self::User => "UserName",
            Self::Role => "RoleName",
            Self::Policy => "PolicyArn",
            Self::InstanceProfile => "InstanceProfileName",
        }
    }
}

fn invalid_marker() -> IamStsError {
    IamStsError::ValidationError("Invalid Marker for this tag listing".into())
}

fn encode_cursor(
    account: &str,
    kind: TagKind,
    arn: &str,
    position: &Position,
) -> Result<String, IamStsError> {
    let encoded = serde_json::to_vec(&(1u8, account, kind.operation(), arn, position))
        .map_err(|_| IamStsError::InternalFailure("Tag cursor could not be encoded".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(encoded))
}

pub(crate) fn list(
    store: &IamStore,
    account: &str,
    kind: TagKind,
    query: &QueryRequest,
) -> Result<String, IamStsError> {
    let name = query.require(kind.parameter())?;
    let maximum = match query.get_raw("MaxItems") {
        None => 100,
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|value| (1..=1000).contains(value))
            .ok_or_else(|| {
                IamStsError::ValidationError(
                    "MaxItems must be an integer between 1 and 1000".into(),
                )
            })?,
    }
    .min(PAGE_LIMIT);
    let cursor = query
        .get_raw("Marker")
        .map(|marker| {
            if marker.is_empty() || marker.len() > MAX_MARKER_BYTES {
                return Err(invalid_marker());
            }
            let decoded = URL_SAFE_NO_PAD
                .decode(marker)
                .map_err(|_| invalid_marker())?;
            let (version, owner, operation, resource, after): (
                u8,
                String,
                String,
                String,
                Position,
            ) = serde_json::from_slice(&decoded).map_err(|_| invalid_marker())?;
            if version != 1
                || owner != account
                || operation != kind.operation()
                || resource.is_empty()
                || matches!(&after, Position::Key(key) if key.is_empty())
            {
                return Err(invalid_marker());
            }
            Ok((resource, after))
        })
        .transpose()?;
    let (page, marker) = store.read_tags(account, kind, name, |arn, tags| {
        if cursor.as_ref().is_some_and(|(resource, _)| resource != arn) {
            return Err(invalid_marker());
        }
        let start = match cursor.as_ref().map(|(_, position)| position) {
            Some(Position::Key(after)) => Excluded(after.as_str()),
            _ => Unbounded,
        };
        let mut remaining = tags.range::<str, _>((start, Unbounded));
        if let Some((_, Position::Offset(offset))) = &cursor {
            if *offset > tags.len() {
                return Err(invalid_marker());
            }
            if *offset > 0 {
                remaining.nth(*offset - 1);
            }
        }
        let page: BTreeMap<String, String> = remaining
            .by_ref()
            .take(maximum)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let marker = if remaining.next().is_some() {
            page.last_key_value()
                .map(|(key, _)| {
                    let legacy_offset = || {
                        tags.range::<str, _>((Unbounded, Included(key.as_str())))
                            .count()
                    };
                    let position = if key.is_empty() || key.len() > MAX_DIRECT_KEY_BYTES {
                        Position::Offset(legacy_offset())
                    } else {
                        Position::Key(key.clone())
                    };
                    let encoded = encode_cursor(account, kind, arn, &position)?;
                    if encoded.len() <= MAX_MARKER_BYTES {
                        return Ok(encoded);
                    }
                    let encoded =
                        encode_cursor(account, kind, arn, &Position::Offset(legacy_offset()))?;
                    if encoded.len() > MAX_MARKER_BYTES {
                        return Err(IamStsError::InternalFailure(
                            "Stored IAM ARN exceeds the tag cursor scope limit".into(),
                        ));
                    }
                    Ok(encoded)
                })
                .transpose()?
        } else {
            None
        };
        Ok((page, marker))
    })?;
    Ok(format!(
        "{}<IsTruncated>{}</IsTruncated>{}",
        tags_xml(&page),
        marker.is_some(),
        marker
            .map(|marker| text_el("Marker", &marker))
            .unwrap_or_default()
    ))
}

#[cfg(test)]
mod tests;
