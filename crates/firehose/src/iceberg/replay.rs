//! Immutable receipt pages; only a root published by the catalog CAS proves a commit.
use super::{Context, Error, Result, COMMITTED_TOKENS, MAX_REPLAY_TOKENS, MAX_SNAPSHOTS};
use bytes::Bytes;
use iceberg::spec::TableMetadata;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use uuid::Uuid;

pub(super) const PROPERTY: &str = "locallycloud.firehose.replay-index";
const MAX_PAGES: usize = 256;
const MAX_ROOT_BYTES: usize = 128 * 1024;
const MAX_PAGE_BYTES: usize = 16 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Range {
    lower: String,
    upper: String,
    location: String,
    count: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    version: u8,
    table_uuid: Uuid,
    ranges: Vec<Range>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    table_uuid: Uuid,
    tokens: Vec<String>,
}

pub(super) struct Index {
    root: Root,
    prefix: String,
}

pub(super) struct Plan {
    pub properties: HashMap<String, String>,
    pub remove_inline: bool,
    writes: Vec<(String, Bytes)>,
}

fn canonical(token: &str) -> Result<()> {
    if Uuid::parse_str(token)
        .map_err(|_| Error::Unsupported)?
        .to_string()
        != token
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}

impl Index {
    pub fn load(metadata: &TableMetadata) -> Result<Self> {
        let prefix = format!(
            "{}/metadata/firehose-replay/",
            metadata.location().trim_end_matches('/')
        );
        let root = match metadata.properties().get(PROPERTY) {
            Some(value) => {
                if value.len() > MAX_ROOT_BYTES {
                    return Err(Error::Unsupported);
                }
                let root: Root = serde_json::from_str(value).map_err(|_| Error::Unsupported)?;
                if root.version != 1
                    || root.table_uuid != metadata.uuid()
                    || root.ranges.is_empty()
                    || root.ranges.len() > MAX_PAGES
                {
                    return Err(Error::Unsupported);
                }
                root
            }
            None => Root {
                version: 1,
                table_uuid: metadata.uuid(),
                ranges: Vec::new(),
            },
        };
        let mut previous: Option<&Range> = None;
        let mut locations = HashSet::new();
        for range in &root.ranges {
            canonical(&range.lower)?;
            canonical(&range.upper)?;
            let name = range
                .location
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix(".json"))
                .ok_or(Error::Unsupported)?;
            canonical(name)?;
            if range.location.len() > 2048
                || !(1..=MAX_REPLAY_TOKENS).contains(&range.count)
                || range.lower > range.upper
                || !locations.insert(&range.location)
                || previous.is_some_and(|previous| previous.upper >= range.lower)
            {
                return Err(Error::Unsupported);
            }
            previous = Some(range);
        }
        Ok(Self { root, prefix })
    }

    async fn page(&self, ctx: &Context<'_>, range: &Range) -> Result<BTreeSet<String>> {
        let bytes = ctx.get_limited(&range.location, MAX_PAGE_BYTES).await?;
        let page: Page = serde_json::from_slice(&bytes).map_err(|_| Error::Unsupported)?;
        if page.table_uuid != self.root.table_uuid
            || page.tokens.len() != range.count
            || page.tokens.first() != Some(&range.lower)
            || page.tokens.last() != Some(&range.upper)
            || page
                .tokens
                .windows(2)
                .any(|pair| matches!(pair, [a, b] if a >= b))
        {
            return Err(Error::Unsupported);
        }
        for token in &page.tokens {
            canonical(token)?;
        }
        Ok(page.tokens.into_iter().collect())
    }

    pub async fn contains(&self, ctx: &Context<'_>, token: &str) -> Result<bool> {
        let index = self
            .root
            .ranges
            .partition_point(|range| range.upper.as_str() < token);
        let Some(range) = self
            .root
            .ranges
            .get(index)
            .filter(|range| range.lower.as_str() <= token)
        else {
            return Ok(false);
        };
        Ok(self.page(ctx, range).await?.contains(token))
    }

    pub async fn prepare(&self, ctx: &Context<'_>, receipts: BTreeSet<String>) -> Result<Plan> {
        if receipts.len() > MAX_REPLAY_TOKENS + MAX_SNAPSHOTS {
            return Err(Error::Unsupported);
        }
        if self.root.ranges.is_empty() && receipts.len() <= MAX_REPLAY_TOKENS {
            return Ok(Plan {
                properties: if receipts.is_empty() {
                    HashMap::new()
                } else {
                    HashMap::from([(
                        COMMITTED_TOKENS.into(),
                        serde_json::to_string(&receipts).map_err(|_| Error::Transient)?,
                    )])
                },
                remove_inline: false,
                writes: Vec::new(),
            });
        }
        let mut additions: BTreeMap<usize, Vec<String>> = BTreeMap::new();
        for token in receipts {
            canonical(&token)?;
            let index = self
                .root
                .ranges
                .partition_point(|range| range.upper < token)
                .min(self.root.ranges.len().saturating_sub(1));
            additions.entry(index).or_default().push(token);
        }
        let mut ranges = Vec::new();
        let mut writes = Vec::new();
        for i in 0..self.root.ranges.len().max(1) {
            let old = self.root.ranges.get(i);
            let Some(add) = additions.remove(&i) else {
                if let Some(old) = old {
                    ranges.push(old.clone());
                }
                continue;
            };
            let mut tokens = match old {
                Some(old) => self.page(ctx, old).await?,
                None => BTreeSet::new(),
            };
            let previous_count = tokens.len();
            tokens.extend(add);
            if old.is_some() && tokens.len() == previous_count {
                ranges.extend(old.cloned());
                continue;
            }
            let tokens: Vec<_> = tokens.into_iter().collect();
            // Balanced splits keep repeated inserts from producing one nearly-full page per token.
            let chunk_size = tokens
                .len()
                .div_ceil(tokens.len().div_ceil(MAX_REPLAY_TOKENS));
            for chunk in tokens.chunks(chunk_size) {
                let location = format!("{}{}.json", self.prefix, Uuid::new_v4());
                let bytes = serde_json::to_vec(&Page {
                    table_uuid: self.root.table_uuid,
                    tokens: chunk.to_vec(),
                })
                .map_err(|_| Error::Transient)?;
                if bytes.len() > MAX_PAGE_BYTES || location.len() > 2048 {
                    return Err(Error::Unsupported);
                }
                ranges.push(Range {
                    lower: chunk.first().ok_or(Error::Unsupported)?.clone(),
                    upper: chunk.last().ok_or(Error::Unsupported)?.clone(),
                    location: location.clone(),
                    count: chunk.len(),
                });
                writes.push((location, Bytes::from(bytes)));
            }
        }
        if ranges.len() > MAX_PAGES {
            return Err(Error::Unsupported);
        }
        let value = serde_json::to_string(&Root {
            version: 1,
            table_uuid: self.root.table_uuid,
            ranges,
        })
        .map_err(|_| Error::Transient)?;
        if value.len() > MAX_ROOT_BYTES {
            return Err(Error::Unsupported);
        }
        Ok(Plan {
            properties: HashMap::from([(PROPERTY.into(), value)]),
            remove_inline: true,
            writes,
        })
    }
}

impl Plan {
    pub async fn publish(&self, ctx: &Context<'_>) -> Result<()> {
        for (location, body) in &self.writes {
            ctx.put(location, body.clone()).await?;
        }
        Ok(())
    }
}
