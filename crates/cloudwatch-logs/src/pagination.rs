use crate::persistence::Persistence;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::error::LogsError;
use crate::model::{LogGroup, LogStream, PagedEvent, ScopeKey};

const TOKEN_VERSION: u8 = 1;
const TOKEN_LIFETIME_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_TOKEN_BYTES: usize = 4_096;
const MAX_SNAPSHOTS: usize = 1_024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
struct Snapshot {
    scope: ScopeKey,
    prefix: Option<String>,
    limit: usize,
    revision: u64,
    expires_at_ms: i64,
    groups: Vec<LogGroup>,
}

#[derive(Serialize, Deserialize)]
struct TokenPayload {
    version: u8,
    snapshot_id: String,
    revision: u64,
    position: usize,
    expires_at_ms: i64,
}

pub struct Page {
    pub groups: Vec<LogGroup>,
    pub next_token: Option<String>,
}

pub struct DescribePaginator {
    secret: [u8; 32],
    persistence: Option<Arc<Persistence>>,
    snapshots: Mutex<HashMap<String, Snapshot>>,
}

impl Default for DescribePaginator {
    fn default() -> Self {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut secret = [0_u8; 32];
        secret[..16].copy_from_slice(first.as_bytes());
        secret[16..].copy_from_slice(second.as_bytes());
        Self {
            secret,
            persistence: None,
            snapshots: Mutex::new(HashMap::new()),
        }
    }
}

impl DescribePaginator {
    pub(crate) fn with_persistence(
        persistence: Option<Arc<Persistence>>,
    ) -> Result<Self, LogsError> {
        let mut result = Self::default();
        if let Some(persistence) = persistence {
            result.secret = persistence.secret("groups", result.secret)?;
            let records: Vec<(String, Snapshot)> = persistence.records("groups")?;
            *result
                .snapshots
                .get_mut()
                .map_err(|_| crate::persistence::unavailable())? = records.into_iter().collect();
            result.persistence = Some(persistence);
        }
        Ok(result)
    }

    pub fn first_page(
        &self,
        groups: Vec<LogGroup>,
        scope: ScopeKey,
        prefix: Option<String>,
        limit: usize,
        revision: u64,
        now_ms: i64,
    ) -> Result<Page, LogsError> {
        if groups.len() <= limit {
            return Ok(Page {
                groups,
                next_token: None,
            });
        }

        let snapshot_id = Uuid::new_v4().simple().to_string();
        let expires_at_ms = now_ms.saturating_add(TOKEN_LIFETIME_MS);
        let page = groups[..limit].to_vec();
        let token = self.encode(TokenPayload {
            version: TOKEN_VERSION,
            snapshot_id: snapshot_id.clone(),
            revision,
            position: limit,
            expires_at_ms,
        })?;
        let mut snapshots = self.lock()?;
        snapshots.retain(|_, snapshot| snapshot.expires_at_ms > now_ms);
        if snapshots.len() >= MAX_SNAPSHOTS {
            return Err(LogsError::ServiceUnavailable(
                "CloudWatch Logs pagination snapshot capacity is exhausted".into(),
            ));
        }
        snapshots.insert(
            snapshot_id.clone(),
            Snapshot {
                scope,
                prefix,
                limit,
                revision,
                expires_at_ms,
                groups,
            },
        );
        if let Some(persistence) = &self.persistence {
            let snapshot = snapshots.get(&snapshot_id).expect("snapshot inserted");
            let result = persistence.prune_cursors("groups", now_ms).and_then(|_| {
                persistence.commit(vec![persistence.cursor(
                    "groups",
                    &snapshot_id,
                    expires_at_ms,
                    snapshot,
                )?])
            });
            if let Err(error) = result {
                snapshots.remove(&snapshot_id);
                return Err(error);
            }
        }
        Ok(Page {
            groups: page,
            next_token: Some(token),
        })
    }

    pub fn next_page(
        &self,
        token: &str,
        scope: &ScopeKey,
        prefix: Option<&str>,
        limit: usize,
        now_ms: i64,
    ) -> Result<Page, LogsError> {
        let payload = self.decode(token)?;
        if payload.version != TOKEN_VERSION || payload.expires_at_ms <= now_ms {
            return Err(invalid_token());
        }

        let mut snapshots = self.lock()?;
        snapshots.retain(|_, snapshot| snapshot.expires_at_ms > now_ms);
        let snapshot = snapshots
            .get(&payload.snapshot_id)
            .ok_or_else(invalid_token)?;
        if &snapshot.scope != scope
            || snapshot.prefix.as_deref() != prefix
            || snapshot.limit != limit
            || snapshot.revision != payload.revision
            || snapshot.expires_at_ms != payload.expires_at_ms
            || payload.position > snapshot.groups.len()
        {
            return Err(invalid_token());
        }

        let end = payload
            .position
            .saturating_add(limit)
            .min(snapshot.groups.len());
        let groups = snapshot.groups[payload.position..end].to_vec();
        let next_token = if end < snapshot.groups.len() {
            Some(self.encode(TokenPayload {
                version: payload.version,
                snapshot_id: payload.snapshot_id.clone(),
                revision: payload.revision,
                position: end,
                expires_at_ms: payload.expires_at_ms,
            })?)
        } else {
            None
        };
        Ok(Page { groups, next_token })
    }

    fn encode(&self, payload: TokenPayload) -> Result<String, LogsError> {
        let payload = serde_json::to_vec(&payload).map_err(|_| invalid_token())?;
        let mut mac = HmacSha256::new_from_slice(&self.secret).map_err(|_| invalid_token())?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn decode(&self, token: &str) -> Result<TokenPayload, LogsError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(invalid_token());
        }
        let (payload, signature) = token.split_once('.').ok_or_else(invalid_token)?;
        if signature.contains('.') {
            return Err(invalid_token());
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| invalid_token())?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| invalid_token())?;
        let mut mac = HmacSha256::new_from_slice(&self.secret).map_err(|_| invalid_token())?;
        mac.update(&payload);
        mac.verify_slice(&signature).map_err(|_| invalid_token())?;
        serde_json::from_slice(&payload).map_err(|_| invalid_token())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, Snapshot>>, LogsError> {
        self.snapshots.lock().map_err(|_| {
            LogsError::ServiceUnavailable("CloudWatch Logs pagination is unavailable".into())
        })
    }
}

fn invalid_token() -> LogsError {
    LogsError::InvalidParameter("nextToken is invalid or expired".into())
}

#[derive(Serialize, Deserialize)]
struct StreamSnapshot {
    scope: ScopeKey,
    group_name: String,
    prefix: Option<String>,
    order_by: String,
    descending: bool,
    limit: usize,
    revision: u64,
    expires_at_ms: i64,
    streams: Vec<LogStream>,
}

#[derive(Serialize, Deserialize)]
struct StreamTokenPayload {
    version: u8,
    snapshot_id: String,
    revision: u64,
    position: usize,
    expires_at_ms: i64,
}

pub struct StreamPage {
    pub streams: Vec<LogStream>,
    pub next_token: Option<String>,
}

pub struct StreamDescribePaginator {
    secret: [u8; 32],
    persistence: Option<Arc<Persistence>>,
    snapshots: Mutex<HashMap<String, StreamSnapshot>>,
}

impl Default for StreamDescribePaginator {
    fn default() -> Self {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut secret = [0_u8; 32];
        secret[..16].copy_from_slice(first.as_bytes());
        secret[16..].copy_from_slice(second.as_bytes());
        Self {
            secret,
            persistence: None,
            snapshots: Mutex::new(HashMap::new()),
        }
    }
}

impl StreamDescribePaginator {
    pub(crate) fn with_persistence(
        persistence: Option<Arc<Persistence>>,
    ) -> Result<Self, LogsError> {
        let mut result = Self::default();
        if let Some(persistence) = persistence {
            result.secret = persistence.secret("streams", result.secret)?;
            let records: Vec<(String, StreamSnapshot)> = persistence.records("streams")?;
            *result
                .snapshots
                .get_mut()
                .map_err(|_| crate::persistence::unavailable())? = records.into_iter().collect();
            result.persistence = Some(persistence);
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn first_page(
        &self,
        streams: Vec<LogStream>,
        scope: ScopeKey,
        group_name: String,
        prefix: Option<String>,
        order_by: String,
        descending: bool,
        limit: usize,
        revision: u64,
        now_ms: i64,
    ) -> Result<StreamPage, LogsError> {
        if streams.len() <= limit {
            return Ok(StreamPage {
                streams,
                next_token: None,
            });
        }

        let snapshot_id = Uuid::new_v4().simple().to_string();
        let expires_at_ms = now_ms.saturating_add(TOKEN_LIFETIME_MS);
        let page = streams[..limit].to_vec();
        let token = self.encode(StreamTokenPayload {
            version: TOKEN_VERSION,
            snapshot_id: snapshot_id.clone(),
            revision,
            position: limit,
            expires_at_ms,
        })?;
        let mut snapshots = self.lock()?;
        snapshots.retain(|_, snapshot| snapshot.expires_at_ms > now_ms);
        if snapshots.len() >= MAX_SNAPSHOTS {
            return Err(LogsError::ServiceUnavailable(
                "CloudWatch Logs pagination snapshot capacity is exhausted".into(),
            ));
        }
        snapshots.insert(
            snapshot_id.clone(),
            StreamSnapshot {
                scope,
                group_name,
                prefix,
                order_by,
                descending,
                limit,
                revision,
                expires_at_ms,
                streams,
            },
        );
        if let Some(persistence) = &self.persistence {
            let snapshot = snapshots.get(&snapshot_id).expect("snapshot inserted");
            let result = persistence.prune_cursors("streams", now_ms).and_then(|_| {
                persistence.commit(vec![persistence.cursor(
                    "streams",
                    &snapshot_id,
                    expires_at_ms,
                    snapshot,
                )?])
            });
            if let Err(error) = result {
                snapshots.remove(&snapshot_id);
                return Err(error);
            }
        }
        Ok(StreamPage {
            streams: page,
            next_token: Some(token),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn next_page(
        &self,
        token: &str,
        scope: &ScopeKey,
        group_name: &str,
        prefix: Option<&str>,
        order_by: &str,
        descending: bool,
        limit: usize,
        now_ms: i64,
    ) -> Result<StreamPage, LogsError> {
        let payload = self.decode(token)?;
        if payload.version != TOKEN_VERSION || payload.expires_at_ms <= now_ms {
            return Err(invalid_token());
        }

        let mut snapshots = self.lock()?;
        snapshots.retain(|_, snapshot| snapshot.expires_at_ms > now_ms);
        let snapshot = snapshots
            .get(&payload.snapshot_id)
            .ok_or_else(invalid_token)?;
        if &snapshot.scope != scope
            || snapshot.group_name != group_name
            || snapshot.prefix.as_deref() != prefix
            || snapshot.order_by != order_by
            || snapshot.descending != descending
            || snapshot.limit != limit
            || snapshot.revision != payload.revision
            || snapshot.expires_at_ms != payload.expires_at_ms
            || payload.position > snapshot.streams.len()
        {
            return Err(invalid_token());
        }

        let end = payload
            .position
            .saturating_add(limit)
            .min(snapshot.streams.len());
        let streams = snapshot.streams[payload.position..end].to_vec();
        let next_token = if end < snapshot.streams.len() {
            Some(self.encode(StreamTokenPayload {
                version: payload.version,
                snapshot_id: payload.snapshot_id.clone(),
                revision: payload.revision,
                position: end,
                expires_at_ms: payload.expires_at_ms,
            })?)
        } else {
            None
        };
        Ok(StreamPage {
            streams,
            next_token,
        })
    }

    fn encode(&self, payload: StreamTokenPayload) -> Result<String, LogsError> {
        let payload = serde_json::to_vec(&payload).map_err(|_| invalid_token())?;
        let mut mac = HmacSha256::new_from_slice(&self.secret).map_err(|_| invalid_token())?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn decode(&self, token: &str) -> Result<StreamTokenPayload, LogsError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(invalid_token());
        }
        let (payload, signature) = token.split_once('.').ok_or_else(invalid_token)?;
        if signature.contains('.') {
            return Err(invalid_token());
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| invalid_token())?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| invalid_token())?;
        let mut mac = HmacSha256::new_from_slice(&self.secret).map_err(|_| invalid_token())?;
        mac.update(&payload);
        mac.verify_slice(&signature).map_err(|_| invalid_token())?;
        serde_json::from_slice(&payload).map_err(|_| invalid_token())
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, StreamSnapshot>>, LogsError> {
        self.snapshots.lock().map_err(|_| {
            LogsError::ServiceUnavailable("CloudWatch Logs pagination is unavailable".into())
        })
    }
}

const MAX_EVENT_SNAPSHOT_EVENTS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum EventDirection {
    Forward,
    Backward,
}

#[derive(Serialize, Deserialize)]
struct EventSnapshot {
    scope: ScopeKey,
    request_key: String,
    revision: u64,
    expires_at_ms: i64,
    events: Vec<PagedEvent>,
}

#[derive(Serialize, Deserialize)]
struct EventTokenPayload {
    version: u8,
    snapshot_id: String,
    revision: u64,
    position: usize,
    direction: EventDirection,
    expires_at_ms: i64,
}

pub struct EventPage {
    pub events: Vec<PagedEvent>,
    pub next_forward_token: String,
    pub next_backward_token: String,
    pub backward: bool,
    pub has_more: bool,
}

pub(crate) struct EventNextPageRequest<'a> {
    pub token: &'a str,
    pub scope: &'a ScopeKey,
    pub request_key: &'a str,
    pub limit: usize,
    pub max_bytes: usize,
    pub require_forward_head: bool,
    pub start_from_head: bool,
    pub now_ms: i64,
}

pub struct EventPaginator {
    secret: [u8; 32],
    persistence: Option<Arc<Persistence>>,
    snapshots: Mutex<HashMap<String, EventSnapshot>>,
}

impl Default for EventPaginator {
    fn default() -> Self {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut secret = [0_u8; 32];
        secret[..16].copy_from_slice(first.as_bytes());
        secret[16..].copy_from_slice(second.as_bytes());
        Self {
            secret,
            persistence: None,
            snapshots: Mutex::new(HashMap::new()),
        }
    }
}

impl EventPaginator {
    pub(crate) fn with_persistence(
        persistence: Option<Arc<Persistence>>,
    ) -> Result<Self, LogsError> {
        let mut result = Self::default();
        if let Some(persistence) = persistence {
            result.secret = persistence.secret("events", result.secret)?;
            let records: Vec<(String, EventSnapshot)> = persistence.records("events")?;
            *result
                .snapshots
                .get_mut()
                .map_err(|_| crate::persistence::unavailable())? = records.into_iter().collect();
            result.persistence = Some(persistence);
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn first_page(
        &self,
        events: Vec<PagedEvent>,
        scope: ScopeKey,
        request_key: String,
        limit: usize,
        max_bytes: usize,
        revision: u64,
        start_from_head: bool,
        now_ms: i64,
    ) -> Result<EventPage, LogsError> {
        if events.len() > MAX_EVENT_SNAPSHOT_EVENTS {
            return Err(LogsError::ServiceUnavailable(
                "CloudWatch Logs event snapshot is too large".into(),
            ));
        }
        let snapshot_id = Uuid::new_v4().simple().to_string();
        let expires_at_ms = now_ms.saturating_add(TOKEN_LIFETIME_MS);
        let payload = EventTokenPayload {
            version: TOKEN_VERSION,
            snapshot_id: snapshot_id.clone(),
            revision,
            position: if start_from_head { 0 } else { events.len() },
            direction: if start_from_head {
                EventDirection::Forward
            } else {
                EventDirection::Backward
            },
            expires_at_ms,
        };
        let mut snapshots = self.lock()?;
        snapshots.retain(|_, snapshot| snapshot.expires_at_ms > now_ms);
        if snapshots.len() >= MAX_SNAPSHOTS {
            return Err(LogsError::ServiceUnavailable(
                "CloudWatch Logs pagination snapshot capacity is exhausted".into(),
            ));
        }
        snapshots.insert(
            snapshot_id.clone(),
            EventSnapshot {
                scope,
                request_key,
                revision,
                expires_at_ms,
                events,
            },
        );
        if let Some(persistence) = &self.persistence {
            let snapshot = snapshots.get(&snapshot_id).expect("snapshot inserted");
            let result = persistence.prune_cursors("events", now_ms).and_then(|_| {
                persistence.commit(vec![persistence.cursor(
                    "events",
                    &snapshot_id,
                    expires_at_ms,
                    snapshot,
                )?])
            });
            if let Err(error) = result {
                snapshots.remove(&snapshot_id);
                return Err(error);
            }
        }
        let snapshot = snapshots
            .get(&payload.snapshot_id)
            .expect("event snapshot was inserted");
        self.page(snapshot, payload, limit, max_bytes)
    }

    pub fn next_page(&self, request: EventNextPageRequest<'_>) -> Result<EventPage, LogsError> {
        let payload = self.decode(request.token)?;
        if payload.version != TOKEN_VERSION
            || payload.expires_at_ms <= request.now_ms
            || (request.require_forward_head
                && payload.direction == EventDirection::Forward
                && !request.start_from_head)
        {
            return Err(invalid_token());
        }
        let mut snapshots = self.lock()?;
        snapshots.retain(|_, snapshot| snapshot.expires_at_ms > request.now_ms);
        let snapshot = snapshots
            .get(&payload.snapshot_id)
            .ok_or_else(invalid_token)?;
        if &snapshot.scope != request.scope
            || snapshot.request_key != request.request_key
            || snapshot.revision != payload.revision
            || snapshot.expires_at_ms != payload.expires_at_ms
            || payload.position > snapshot.events.len()
        {
            return Err(invalid_token());
        }
        self.page(snapshot, payload, request.limit, request.max_bytes)
    }

    fn page(
        &self,
        snapshot: &EventSnapshot,
        payload: EventTokenPayload,
        limit: usize,
        max_bytes: usize,
    ) -> Result<EventPage, LogsError> {
        let backward = payload.direction == EventDirection::Backward;
        let (start, end) = match payload.direction {
            EventDirection::Forward => {
                let mut end = payload.position;
                let mut bytes = 0_usize;
                while end < snapshot.events.len() && end - payload.position < limit {
                    let charge = snapshot.events[end].event.message.len().saturating_add(26);
                    if bytes.saturating_add(charge) > max_bytes {
                        break;
                    }
                    bytes += charge;
                    end += 1;
                }
                (payload.position, end)
            }
            EventDirection::Backward => {
                let end = payload.position;
                let mut start = end;
                let mut bytes = 0_usize;
                while start > 0 && end - start < limit {
                    let charge = snapshot.events[start - 1]
                        .event
                        .message
                        .len()
                        .saturating_add(26);
                    if bytes.saturating_add(charge) > max_bytes {
                        break;
                    }
                    bytes += charge;
                    start -= 1;
                }
                (start, end)
            }
        };
        let next_forward_token = self.encode(EventTokenPayload {
            version: payload.version,
            snapshot_id: payload.snapshot_id.clone(),
            revision: payload.revision,
            position: end,
            direction: EventDirection::Forward,
            expires_at_ms: payload.expires_at_ms,
        })?;
        let next_backward_token = self.encode(EventTokenPayload {
            version: payload.version,
            snapshot_id: payload.snapshot_id,
            revision: payload.revision,
            position: start,
            direction: EventDirection::Backward,
            expires_at_ms: payload.expires_at_ms,
        })?;
        Ok(EventPage {
            events: snapshot.events[start..end].to_vec(),
            next_forward_token,
            next_backward_token,
            backward,
            has_more: if backward {
                start > 0
            } else {
                end < snapshot.events.len()
            },
        })
    }

    fn encode(&self, payload: EventTokenPayload) -> Result<String, LogsError> {
        let payload = serde_json::to_vec(&payload).map_err(|_| invalid_token())?;
        let mut mac = HmacSha256::new_from_slice(&self.secret).map_err(|_| invalid_token())?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn decode(&self, token: &str) -> Result<EventTokenPayload, LogsError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(invalid_token());
        }
        let (payload, signature) = token.split_once('.').ok_or_else(invalid_token)?;
        if signature.contains('.') {
            return Err(invalid_token());
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| invalid_token())?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| invalid_token())?;
        let mut mac = HmacSha256::new_from_slice(&self.secret).map_err(|_| invalid_token())?;
        mac.update(&payload);
        mac.verify_slice(&signature).map_err(|_| invalid_token())?;
        serde_json::from_slice(&payload).map_err(|_| invalid_token())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, EventSnapshot>>, LogsError> {
        self.snapshots.lock().map_err(|_| {
            LogsError::ServiceUnavailable("CloudWatch Logs pagination is unavailable".into())
        })
    }
}
