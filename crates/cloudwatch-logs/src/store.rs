use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::emf;
use crate::error::LogsError;
use crate::insights::{InsightsQuery, QueryPlan, QuerySnapshotEvent, QueryStatus};
use crate::metric_filters::effects_for_events;
use crate::model::{
    GroupKey, LogClass, LogGroup, LogStream, MetricEffectSource, MetricEffectStatus, MetricFilter,
    PagedEvent, PendingLogEvent, PendingMetricEffect, PendingSubscriptionDelivery, PutEventsResult,
    RejectedEventIndexes, ScopeKey, StoredEvent, SubscriptionDeliveryStatus, SubscriptionFilter,
};
use crate::protocol::PUT_LOG_EVENTS_MAX_SPAN_MS;
use crate::subscriptions::deliveries_for_events;

pub(crate) struct NewQuery {
    pub scope: ScopeKey,
    pub group_names: Vec<String>,
    pub query_string: String,
    pub plan: QueryPlan,
    pub start_ms: i64,
    pub end_ms: i64,
    pub result_limit: usize,
    pub now_ms: i64,
}

#[derive(Default)]
struct StoreState {
    revision: u64,
    next_put_ordinals: BTreeMap<ScopeKey, u64>,
    next_metric_effect_id: u64,
    next_subscription_delivery_id: u64,
    next_query_revision: u64,
    groups: BTreeMap<GroupKey, LogGroup>,
    queries: BTreeMap<(ScopeKey, String), InsightsQuery>,
    metric_effects: BTreeMap<u64, PendingMetricEffect>,
    subscription_deliveries: BTreeMap<u64, PendingSubscriptionDelivery>,
    metric_default_minutes: BTreeSet<(GroupKey, String, u64, i64)>,
}

#[derive(Default)]
pub struct LogsStore {
    state: RwLock<StoreState>,
}

impl LogsStore {
    pub(crate) fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        Ok(self
            .state
            .read()
            .map_err(|_| "log inventory unavailable")?
            .groups
            .keys()
            .filter(|k| k.scope.account_id == account)
            .map(|k| k.scope.region.clone())
            .collect())
    }

    pub fn create_group(&self, key: GroupKey, mut group: LogGroup) -> Result<(), LogsError> {
        let expected_arn = format!(
            "arn:aws:logs:{}:{}:log-group:{}",
            key.scope.region, key.scope.account_id, key.name
        );
        if group.name != key.name
            || group.arn != expected_arn
            || group.creation_time_ms < 0
            || group.retention_days.is_some()
            || group.class != LogClass::Standard
            || group.tags.len() > 50
            || !group.streams.is_empty()
            || !group.metric_filters.is_empty()
            || !group.subscription_filters.is_empty()
            || group.revision != 0
        {
            return Err(LogsError::ServiceUnavailable(
                "invalid log group commit plan".into(),
            ));
        }
        let mut state = self.write()?;
        if state.groups.contains_key(&key) {
            return Err(LogsError::ResourceAlreadyExists(format!(
                "log group '{}' already exists",
                key.name
            )));
        }
        state.revision = next_revision(state.revision)?;
        group.revision = state.revision;
        state.groups.insert(key, group);
        Ok(())
    }

    pub fn describe_groups(
        &self,
        scope: &ScopeKey,
        prefix: Option<&str>,
    ) -> Result<(u64, Vec<LogGroup>), LogsError> {
        let state = self.read()?;
        let groups = state
            .groups
            .iter()
            .filter(|(key, _)| {
                &key.scope == scope && prefix.is_none_or(|prefix| key.name.starts_with(prefix))
            })
            .map(|(_, group)| group.clone())
            .collect();
        Ok((state.revision, groups))
    }

    pub fn delete_group(&self, key: &GroupKey) -> Result<(), LogsError> {
        let mut state = self.write()?;
        if !state.groups.contains_key(key) {
            return Err(LogsError::ResourceNotFound(format!(
                "log group '{}' does not exist",
                key.name
            )));
        }
        let revision = next_revision(state.revision)?;
        state.groups.remove(key);
        state
            .metric_effects
            .retain(|_, effect| &effect.group_key != key);
        state
            .subscription_deliveries
            .retain(|_, delivery| &delivery.group_key != key);
        state
            .metric_default_minutes
            .retain(|(group_key, _, _, _)| group_key != key);
        state.revision = revision;
        Ok(())
    }

    pub fn set_retention(
        &self,
        key: &GroupKey,
        retention_days: Option<u16>,
    ) -> Result<(), LogsError> {
        let mut state = self.write()?;
        let revision = next_revision(state.revision)?;
        let group = state.groups.get_mut(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        group.retention_days = retention_days;
        group.revision = revision;
        state.revision = revision;
        Ok(())
    }

    pub fn tag_group(
        &self,
        key: &GroupKey,
        tags: BTreeMap<String, String>,
    ) -> Result<(), LogsError> {
        let mut state = self.write()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        let tag_count = group
            .tags
            .keys()
            .chain(tags.keys())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        if tag_count > 50 {
            return Err(LogsError::InvalidParameter(
                "a log group cannot have more than 50 tags".into(),
            ));
        }
        let revision = next_revision(state.revision)?;
        let group = state
            .groups
            .get_mut(key)
            .expect("group existence was checked");
        group.tags.extend(tags);
        group.revision = revision;
        state.revision = revision;
        Ok(())
    }

    pub fn untag_group(&self, key: &GroupKey, tag_keys: &[String]) -> Result<(), LogsError> {
        let mut state = self.write()?;
        if !state.groups.contains_key(key) {
            return Err(LogsError::ResourceNotFound(format!(
                "log group '{}' does not exist",
                key.name
            )));
        }
        let revision = next_revision(state.revision)?;
        let group = state
            .groups
            .get_mut(key)
            .expect("group existence was checked");
        for tag_key in tag_keys {
            group.tags.remove(tag_key);
        }
        group.revision = revision;
        state.revision = revision;
        Ok(())
    }

    pub fn list_tags(&self, key: &GroupKey) -> Result<BTreeMap<String, String>, LogsError> {
        let state = self.read()?;
        state
            .groups
            .get(key)
            .map(|group| group.tags.clone())
            .ok_or_else(|| {
                LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
            })
    }

    pub fn create_stream(&self, key: &GroupKey, mut stream: LogStream) -> Result<(), LogsError> {
        let expected_arn = format!(
            "arn:aws:logs:{}:{}:log-group:{}:log-stream:{}",
            key.scope.region, key.scope.account_id, key.name, stream.name
        );
        if stream.arn != expected_arn
            || stream.creation_time_ms < 0
            || !stream.events.is_empty()
            || stream.first_event_timestamp_ms.is_some()
            || stream.last_event_timestamp_ms.is_some()
            || stream.last_ingestion_time_ms.is_some()
            || stream.stored_bytes != 0
            || stream.revision != 0
        {
            return Err(LogsError::ServiceUnavailable(
                "invalid log stream commit plan".into(),
            ));
        }
        let mut state = self.write()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        if group.streams.contains_key(&stream.name) {
            return Err(LogsError::ResourceAlreadyExists(format!(
                "log stream '{}' already exists",
                stream.name
            )));
        }
        let revision = next_revision(state.revision)?;
        stream.revision = revision;
        let group = state
            .groups
            .get_mut(key)
            .expect("group existence was checked");
        group.streams.insert(stream.name.clone(), stream);
        group.revision = revision;
        state.revision = revision;
        Ok(())
    }

    pub fn describe_streams(
        &self,
        key: &GroupKey,
        prefix: Option<&str>,
    ) -> Result<(u64, Vec<LogStream>), LogsError> {
        let state = self.read()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        let streams = group
            .streams
            .values()
            .filter(|stream| prefix.is_none_or(|prefix| stream.name.starts_with(prefix)))
            .cloned()
            .collect();
        Ok((state.revision, streams))
    }

    pub fn put_metric_filter(
        &self,
        key: &GroupKey,
        mut filter: MetricFilter,
        max_filters: usize,
        max_regex: usize,
    ) -> Result<(), LogsError> {
        let mut state = self.write()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        if !group.metric_filters.contains_key(&filter.name)
            && group.metric_filters.len() >= max_filters
        {
            return Err(LogsError::LimitExceeded(
                "a log group cannot have more than 100 metric filters".into(),
            ));
        }
        let regex_count = group
            .metric_filters
            .values()
            .filter(|existing| existing.name != filter.name)
            .map(|existing| existing.pattern.regex_count())
            .sum::<usize>()
            .saturating_add(filter.pattern.regex_count());
        if regex_count > max_regex {
            return Err(LogsError::LimitExceeded(
                "metric filters exceed the per-group regex quota".into(),
            ));
        }
        let revision = next_revision(state.revision)?;
        if let Some(existing) = group.metric_filters.get(&filter.name) {
            filter.creation_time_ms = existing.creation_time_ms;
        }
        filter.revision = revision;
        let filter_name = filter.name.clone();
        let group = state
            .groups
            .get_mut(key)
            .expect("group existence was checked");
        group.metric_filters.insert(filter_name.clone(), filter);
        group.revision = revision;
        state
            .metric_effects
            .retain(|_, effect| &effect.group_key != key || !effect.source.is_filter(&filter_name));
        state
            .metric_default_minutes
            .retain(|(group_key, name, _, _)| group_key != key || name != &filter_name);
        state.revision = revision;
        Ok(())
    }

    pub fn describe_metric_filters(&self, key: &GroupKey) -> Result<Vec<MetricFilter>, LogsError> {
        let state = self.read()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        Ok(group.metric_filters.values().cloned().collect())
    }

    pub fn delete_metric_filter(&self, key: &GroupKey, filter_name: &str) -> Result<(), LogsError> {
        let mut state = self.write()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        if !group.metric_filters.contains_key(filter_name) {
            return Err(LogsError::ResourceNotFound(format!(
                "metric filter '{}' does not exist",
                filter_name
            )));
        }
        let revision = next_revision(state.revision)?;
        let group = state
            .groups
            .get_mut(key)
            .expect("group existence was checked");
        group.metric_filters.remove(filter_name);
        group.revision = revision;
        state
            .metric_effects
            .retain(|_, effect| &effect.group_key != key || !effect.source.is_filter(filter_name));
        state
            .metric_default_minutes
            .retain(|(group_key, name, _, _)| group_key != key || name != filter_name);
        state.revision = revision;
        Ok(())
    }

    pub fn put_subscription_filter(
        &self,
        key: &GroupKey,
        mut filter: SubscriptionFilter,
        max_filters: usize,
        max_regex: usize,
    ) -> Result<(), LogsError> {
        let mut state = self.write()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        if !group.subscription_filters.contains_key(&filter.name)
            && group.subscription_filters.len() >= max_filters
        {
            return Err(LogsError::LimitExceeded(
                "a log group cannot have more than two subscription filters".into(),
            ));
        }
        let regex_count = group
            .subscription_filters
            .values()
            .filter(|existing| existing.name != filter.name)
            .map(|existing| existing.pattern.regex_count())
            .sum::<usize>()
            .saturating_add(filter.pattern.regex_count());
        if regex_count > max_regex {
            return Err(LogsError::LimitExceeded(
                "subscription filters exceed the per-group regex quota".into(),
            ));
        }
        let revision = next_revision(state.revision)?;
        if let Some(existing) = group.subscription_filters.get(&filter.name) {
            filter.creation_time_ms = existing.creation_time_ms;
        }
        filter.revision = revision;
        let filter_name = filter.name.clone();
        let group = state
            .groups
            .get_mut(key)
            .expect("group existence was checked");
        group
            .subscription_filters
            .insert(filter_name.clone(), filter);
        group.revision = revision;
        state.subscription_deliveries.retain(|_, delivery| {
            &delivery.group_key != key || delivery.filter_name != filter_name
        });
        state.revision = revision;
        Ok(())
    }

    pub fn describe_subscription_filters(
        &self,
        key: &GroupKey,
    ) -> Result<Vec<SubscriptionFilter>, LogsError> {
        let state = self.read()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        Ok(group.subscription_filters.values().cloned().collect())
    }

    pub fn delete_subscription_filter(
        &self,
        key: &GroupKey,
        filter_name: &str,
    ) -> Result<(), LogsError> {
        let mut state = self.write()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        if !group.subscription_filters.contains_key(filter_name) {
            return Err(LogsError::ResourceNotFound(format!(
                "subscription filter '{}' does not exist",
                filter_name
            )));
        }
        let revision = next_revision(state.revision)?;
        let group = state
            .groups
            .get_mut(key)
            .expect("group existence was checked");
        group.subscription_filters.remove(filter_name);
        group.revision = revision;
        state.subscription_deliveries.retain(|_, delivery| {
            &delivery.group_key != key || delivery.filter_name != filter_name
        });
        state.revision = revision;
        Ok(())
    }

    pub fn pending_subscription_deliveries(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingSubscriptionDelivery>, LogsError> {
        let state = self.read()?;
        Ok(state
            .subscription_deliveries
            .values()
            .filter(|delivery| delivery.status == SubscriptionDeliveryStatus::Pending)
            .filter(|delivery| {
                state
                    .groups
                    .get(&delivery.group_key)
                    .and_then(|group| group.subscription_filters.get(&delivery.filter_name))
                    .is_some_and(|filter| filter.revision == delivery.filter_revision)
            })
            .take(limit)
            .cloned()
            .collect())
    }

    pub fn finish_subscription_delivery(&self, id: u64, delivered: bool) -> Result<(), LogsError> {
        let mut state = self.write()?;
        if delivered {
            state.subscription_deliveries.remove(&id);
        } else if let Some(delivery) = state.subscription_deliveries.get_mut(&id) {
            delivery.status = SubscriptionDeliveryStatus::Failed;
        }
        Ok(())
    }

    pub fn pending_metric_effects(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingMetricEffect>, LogsError> {
        let state = self.read()?;
        Ok(state
            .metric_effects
            .values()
            .filter(|effect| effect.status == MetricEffectStatus::Pending)
            .filter(|effect| match &effect.source {
                MetricEffectSource::Filter { name, revision } => state
                    .groups
                    .get(&effect.group_key)
                    .and_then(|group| group.metric_filters.get(name))
                    .is_some_and(|filter| filter.revision == *revision),
                MetricEffectSource::EmbeddedMetricFormat => true,
            })
            .take(limit)
            .cloned()
            .collect())
    }

    pub fn finish_metric_effects(&self, ids: &[u64], delivered: bool) -> Result<(), LogsError> {
        let mut state = self.write()?;
        if delivered {
            for id in ids {
                state.metric_effects.remove(id);
            }
        } else {
            for id in ids {
                let Some(effect) = state.metric_effects.get_mut(id) else {
                    continue;
                };
                // EMF effects are never redelivered and nothing references them once failed,
                // so retaining them would only grow memory with every undelivered EMF line.
                if effect.source == MetricEffectSource::EmbeddedMetricFormat {
                    state.metric_effects.remove(id);
                } else {
                    effect.status = MetricEffectStatus::Failed;
                }
            }
        }
        Ok(())
    }

    pub fn put_events(
        &self,
        key: &GroupKey,
        stream_name: &str,
        events: Vec<PendingLogEvent>,
        now_ms: i64,
    ) -> Result<PutEventsResult, LogsError> {
        const DAY_MS: i64 = 24 * 60 * 60 * 1_000;
        const FUTURE_WINDOW_MS: i64 = 2 * 60 * 60 * 1_000;

        let mut state = self.write()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        let stream = group.streams.get(stream_name).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log stream '{}' does not exist", stream_name))
        })?;
        let retention_days = group.retention_days;
        let metric_filters: Vec<_> = group.metric_filters.values().cloned().collect();
        let subscription_filters: Vec<_> = group.subscription_filters.values().cloned().collect();
        let current_stream_revision = stream.revision;
        let current_stored_bytes = stream.stored_bytes;

        let too_old_cutoff = now_ms.saturating_sub(14 * DAY_MS);
        let retention_cutoff = retention_days
            .map(i64::from)
            .map(|days| now_ms.saturating_sub(days.saturating_mul(DAY_MS)));
        let future_cutoff = now_ms.saturating_add(FUTURE_WINDOW_MS);
        let too_old_end = events
            .iter()
            .rposition(|event| event.timestamp_ms < too_old_cutoff)
            .map(index_u32)
            .transpose()?;
        let expired_end = retention_cutoff
            .and_then(|cutoff| events.iter().rposition(|event| event.timestamp_ms < cutoff))
            .map(index_u32)
            .transpose()?;
        let too_new_start = events
            .iter()
            .position(|event| event.timestamp_ms > future_cutoff)
            .map(index_u32)
            .transpose()?;
        let rejected = RejectedEventIndexes {
            too_old_end,
            expired_end,
            too_new_start,
        };
        let accepted_start = too_old_end
            .into_iter()
            .chain(expired_end)
            .max()
            .map_or(0, |index| index as usize + 1);
        let accepted_end = too_new_start.map_or(events.len(), |index| index as usize);
        if accepted_start < accepted_end {
            let first = events[accepted_start].timestamp_ms;
            let last = events[accepted_end - 1].timestamp_ms;
            if last.saturating_sub(first) > PUT_LOG_EVENTS_MAX_SPAN_MS {
                return Err(LogsError::InvalidParameter(
                    "valid logEvents must not span more than 24 hours".into(),
                ));
            }
        }
        if accepted_start >= accepted_end {
            return Ok(PutEventsResult {
                next_sequence_token: sequence_token(current_stream_revision),
                rejected,
            });
        }

        let revision = next_revision(state.revision)?;
        let put_ordinal = state
            .next_put_ordinals
            .get(&key.scope)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| {
                LogsError::ServiceUnavailable(
                    "CloudWatch Logs put ordinal space is exhausted".into(),
                )
            })?;
        let added_bytes =
            events[accepted_start..accepted_end]
                .iter()
                .try_fold(0_u64, |total, event| {
                    total
                        .checked_add(event.message.len() as u64)
                        .ok_or_else(|| {
                            LogsError::ServiceUnavailable(
                                "CloudWatch Logs stored byte count overflow".into(),
                            )
                        })
                })?;
        let stored_bytes = current_stored_bytes
            .checked_add(added_bytes)
            .ok_or_else(|| {
                LogsError::ServiceUnavailable("CloudWatch Logs stored byte count overflow".into())
            })?;
        let accepted: Vec<_> = events[accepted_start..accepted_end]
            .iter()
            .map(|event| StoredEvent {
                id: event_id(key, stream_name, put_ordinal, event.event_ordinal),
                timestamp_ms: event.timestamp_ms,
                ingestion_time_ms: now_ms,
                put_ordinal,
                event_ordinal: event.event_ordinal,
                message: event.message.clone(),
            })
            .collect();
        let metric_candidates: Vec<_> = effects_for_events(key, &metric_filters, &accepted)
            .into_iter()
            .filter(|candidate| {
                candidate.default_minute.is_none_or(|minute| {
                    !state.metric_default_minutes.contains(&(
                        key.clone(),
                        candidate.filter_name.clone(),
                        candidate.filter_revision,
                        minute,
                    ))
                })
            })
            .collect();
        let embedded_observations = emf::observations_for_events(key, &accepted, now_ms);
        let final_effect_id = state
            .next_metric_effect_id
            .checked_add(metric_candidates.len() as u64)
            .and_then(|id| id.checked_add(embedded_observations.len() as u64))
            .ok_or_else(|| {
                LogsError::ServiceUnavailable(
                    "CloudWatch Logs metric effect id space is exhausted".into(),
                )
            })?;
        let subscription_candidates = deliveries_for_events(&subscription_filters, &accepted);
        let final_subscription_delivery_id = state
            .next_subscription_delivery_id
            .checked_add(subscription_candidates.len() as u64)
            .ok_or_else(|| {
                LogsError::ServiceUnavailable(
                    "CloudWatch Logs subscription delivery id space is exhausted".into(),
                )
            })?;

        {
            let group = state
                .groups
                .get_mut(key)
                .expect("group existence was checked");
            let stream = group
                .streams
                .get_mut(stream_name)
                .expect("stream existence was checked");
            stream.events = merge_events(std::mem::take(&mut stream.events), accepted);
            stream.first_event_timestamp_ms = stream.events.first().map(|event| event.timestamp_ms);
            stream.last_event_timestamp_ms = stream.events.last().map(|event| event.timestamp_ms);
            stream.last_ingestion_time_ms = Some(
                stream
                    .last_ingestion_time_ms
                    .map_or(now_ms, |previous| previous.max(now_ms)),
            );
            stream.stored_bytes = stored_bytes;
            stream.revision = revision;
            group.revision = revision;
        }
        state
            .next_put_ordinals
            .insert(key.scope.clone(), put_ordinal);
        let first_effect_id = state.next_metric_effect_id;
        let filter_effect_count = metric_candidates.len();
        for (offset, candidate) in metric_candidates.into_iter().enumerate() {
            let id = first_effect_id + offset as u64 + 1;
            if let Some(minute) = candidate.default_minute {
                state.metric_default_minutes.insert((
                    key.clone(),
                    candidate.filter_name.clone(),
                    candidate.filter_revision,
                    minute,
                ));
            }
            state.metric_effects.insert(
                id,
                PendingMetricEffect {
                    id,
                    group_key: key.clone(),
                    source: MetricEffectSource::Filter {
                        name: candidate.filter_name,
                        revision: candidate.filter_revision,
                    },
                    observation: candidate.observation,
                    status: MetricEffectStatus::Pending,
                },
            );
        }
        let first_embedded_id = first_effect_id + filter_effect_count as u64;
        for (offset, observation) in embedded_observations.into_iter().enumerate() {
            let id = first_embedded_id + offset as u64 + 1;
            state.metric_effects.insert(
                id,
                PendingMetricEffect {
                    id,
                    group_key: key.clone(),
                    source: MetricEffectSource::EmbeddedMetricFormat,
                    observation,
                    status: MetricEffectStatus::Pending,
                },
            );
        }
        state.next_metric_effect_id = final_effect_id;
        let first_delivery_id = state.next_subscription_delivery_id;
        for (offset, candidate) in subscription_candidates.into_iter().enumerate() {
            let id = first_delivery_id + offset as u64 + 1;
            state.subscription_deliveries.insert(
                id,
                PendingSubscriptionDelivery {
                    id,
                    group_key: key.clone(),
                    filter_name: candidate.filter_name,
                    filter_revision: candidate.filter_revision,
                    function_name: candidate.function_name,
                    log_stream_name: stream_name.to_owned(),
                    events: candidate.events,
                    status: SubscriptionDeliveryStatus::Pending,
                },
            );
        }
        state.next_subscription_delivery_id = final_subscription_delivery_id;
        state.revision = revision;
        Ok(PutEventsResult {
            next_sequence_token: sequence_token(revision),
            rejected,
        })
    }

    pub fn start_query(&self, query: NewQuery) -> Result<String, LogsError> {
        let NewQuery {
            scope,
            group_names,
            query_string,
            plan,
            start_ms,
            end_ms,
            result_limit,
            now_ms,
        } = query;
        const DAY_MS: i64 = 24 * 60 * 60 * 1_000;
        const MAX_ACTIVE_QUERIES: usize = 100;
        const MAX_QUERY_HISTORY: usize = 1_000;
        const MAX_SNAPSHOT_BYTES: usize = 64 * 1_024 * 1_024;

        let mut state = self.write()?;
        let scope_queries = state
            .queries
            .values()
            .filter(|query| query.scope == scope)
            .count();
        if scope_queries >= MAX_QUERY_HISTORY {
            return Err(LogsError::LimitExceeded(
                "query history capacity is exhausted".into(),
            ));
        }
        let active = state
            .queries
            .values()
            .filter(|query| query.scope == scope)
            .filter(|query| matches!(query.status, QueryStatus::Scheduled | QueryStatus::Running))
            .count();
        if active >= MAX_ACTIVE_QUERIES {
            return Err(LogsError::LimitExceeded(
                "too many concurrent Logs Insights queries".into(),
            ));
        }
        let mut snapshot = Vec::new();
        let mut snapshot_bytes = 0_usize;
        for group_name in &group_names {
            let key = GroupKey {
                scope: scope.clone(),
                name: group_name.clone(),
            };
            let group = state.groups.get(&key).ok_or_else(|| {
                LogsError::ResourceNotFound(format!("log group '{}' does not exist", group_name))
            })?;
            let retention_cutoff = group
                .retention_days
                .map(|days| now_ms.saturating_sub(i64::from(days).saturating_mul(DAY_MS)));
            for stream in group.streams.values() {
                for event in &stream.events {
                    if event.timestamp_ms < start_ms
                        || event.timestamp_ms > end_ms
                        || retention_cutoff.is_some_and(|cutoff| event.timestamp_ms < cutoff)
                    {
                        continue;
                    }
                    snapshot_bytes =
                        snapshot_bytes
                            .checked_add(event.message.len())
                            .ok_or_else(|| {
                                LogsError::LimitExceeded("query snapshot is too large".into())
                            })?;
                    if snapshot_bytes > MAX_SNAPSHOT_BYTES {
                        return Err(LogsError::LimitExceeded(
                            "query snapshot exceeds the 64 MiB safety limit".into(),
                        ));
                    }
                    snapshot.push(QuerySnapshotEvent {
                        group_name: group_name.clone(),
                        stream_name: stream.name.clone(),
                        timestamp_ms: event.timestamp_ms,
                        put_ordinal: event.put_ordinal,
                        event_ordinal: event.event_ordinal,
                        message: event.message.clone(),
                    });
                }
            }
        }
        snapshot.sort_by(|left, right| {
            left.timestamp_ms
                .cmp(&right.timestamp_ms)
                .then_with(|| left.put_ordinal.cmp(&right.put_ordinal))
                .then_with(|| left.event_ordinal.cmp(&right.event_ordinal))
                .then_with(|| left.group_name.cmp(&right.group_name))
                .then_with(|| left.stream_name.cmp(&right.stream_name))
        });
        let revision = state.next_query_revision.checked_add(1).ok_or_else(|| {
            LogsError::ServiceUnavailable("query revision space is exhausted".into())
        })?;
        let query_id = Uuid::new_v4().to_string();
        state.queries.insert(
            (scope.clone(), query_id.clone()),
            InsightsQuery {
                id: query_id.clone(),
                scope,
                group_names,
                query_string,
                plan,
                status: QueryStatus::Scheduled,
                creation_time_ms: now_ms,
                duration_ms: 0,
                result_limit,
                snapshot,
                rows: Vec::new(),
                statistics: Default::default(),
                revision,
            },
        );
        state.next_query_revision = revision;
        Ok(query_id)
    }

    pub fn claim_scheduled_query(&self) -> Result<Option<InsightsQuery>, LogsError> {
        let mut state = self.write()?;
        let key = state
            .queries
            .iter()
            .filter(|(_, query)| query.status == QueryStatus::Scheduled)
            .min_by(|(_, left), (_, right)| {
                left.creation_time_ms
                    .cmp(&right.creation_time_ms)
                    .then_with(|| left.id.cmp(&right.id))
            })
            .map(|(key, _)| key.clone());
        let Some(key) = key else {
            return Ok(None);
        };
        let revision = state.next_query_revision.checked_add(1).ok_or_else(|| {
            LogsError::ServiceUnavailable("query revision space is exhausted".into())
        })?;
        let query = state.queries.get_mut(&key).expect("scheduled query exists");
        query.status = QueryStatus::Running;
        query.revision = revision;
        let claimed = query.clone();
        state.next_query_revision = revision;
        Ok(Some(claimed))
    }

    pub fn complete_query(
        &self,
        scope: &ScopeKey,
        query_id: &str,
        rows: Vec<Vec<crate::protocol::ResultField>>,
        statistics: crate::protocol::QueryStatistics,
        now_ms: i64,
    ) -> Result<bool, LogsError> {
        let mut state = self.write()?;
        let key = (scope.clone(), query_id.to_owned());
        if state
            .queries
            .get(&key)
            .is_none_or(|query| query.status != QueryStatus::Running)
        {
            return Ok(false);
        }
        let revision = state.next_query_revision.checked_add(1).ok_or_else(|| {
            LogsError::ServiceUnavailable("query revision space is exhausted".into())
        })?;
        let query = state.queries.get_mut(&key).expect("running query exists");
        query.status = QueryStatus::Complete;
        query.rows = rows;
        query.statistics = statistics;
        query.duration_ms = now_ms.saturating_sub(query.creation_time_ms).max(0);
        query.revision = revision;
        state.next_query_revision = revision;
        Ok(true)
    }

    pub fn fail_query(
        &self,
        scope: &ScopeKey,
        query_id: &str,
        now_ms: i64,
    ) -> Result<(), LogsError> {
        self.finish_query_without_results(scope, query_id, QueryStatus::Failed, now_ms)
    }

    pub fn cancel_query(
        &self,
        scope: &ScopeKey,
        query_id: &str,
        now_ms: i64,
    ) -> Result<bool, LogsError> {
        let mut state = self.write()?;
        let key = (scope.clone(), query_id.to_owned());
        let query = state.queries.get(&key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("query '{}' does not exist", query_id))
        })?;
        if query.status.is_terminal() {
            return Ok(false);
        }
        let revision = state.next_query_revision.checked_add(1).ok_or_else(|| {
            LogsError::ServiceUnavailable("query revision space is exhausted".into())
        })?;
        let query = state
            .queries
            .get_mut(&key)
            .expect("query existence was checked");
        query.status = QueryStatus::Cancelled;
        query.rows.clear();
        query.statistics = Default::default();
        query.duration_ms = now_ms.saturating_sub(query.creation_time_ms).max(0);
        query.revision = revision;
        state.next_query_revision = revision;
        Ok(true)
    }

    pub fn query_is_running(&self, scope: &ScopeKey, query_id: &str) -> Result<bool, LogsError> {
        let state = self.read()?;
        Ok(state
            .queries
            .get(&(scope.clone(), query_id.to_owned()))
            .is_some_and(|query| query.status == QueryStatus::Running))
    }

    pub fn get_query(&self, scope: &ScopeKey, query_id: &str) -> Result<InsightsQuery, LogsError> {
        let state = self.read()?;
        state
            .queries
            .get(&(scope.clone(), query_id.to_owned()))
            .cloned()
            .ok_or_else(|| {
                LogsError::ResourceNotFound(format!("query '{}' does not exist", query_id))
            })
    }

    pub fn describe_queries(&self, scope: &ScopeKey) -> Result<Vec<InsightsQuery>, LogsError> {
        let state = self.read()?;
        Ok(state
            .queries
            .values()
            .filter(|query| &query.scope == scope)
            .cloned()
            .collect())
    }

    fn finish_query_without_results(
        &self,
        scope: &ScopeKey,
        query_id: &str,
        status: QueryStatus,
        now_ms: i64,
    ) -> Result<(), LogsError> {
        let mut state = self.write()?;
        let key = (scope.clone(), query_id.to_owned());
        if state
            .queries
            .get(&key)
            .is_none_or(|query| query.status != QueryStatus::Running)
        {
            return Ok(());
        }
        let revision = state.next_query_revision.checked_add(1).ok_or_else(|| {
            LogsError::ServiceUnavailable("query revision space is exhausted".into())
        })?;
        let query = state.queries.get_mut(&key).expect("running query exists");
        query.status = status;
        query.rows.clear();
        query.statistics = Default::default();
        query.duration_ms = now_ms.saturating_sub(query.creation_time_ms).max(0);
        query.revision = revision;
        state.next_query_revision = revision;
        Ok(())
    }

    pub fn purge_expired(&self, now_ms: i64) -> Result<Option<i64>, LogsError> {
        const DAY_MS: i64 = 24 * 60 * 60 * 1_000;

        let mut state = self.write()?;
        let has_expired = state.groups.values().any(|group| {
            group.retention_days.is_some_and(|days| {
                let cutoff = now_ms.saturating_sub(i64::from(days).saturating_mul(DAY_MS));
                group.streams.values().any(|stream| {
                    stream
                        .events
                        .first()
                        .is_some_and(|event| event.timestamp_ms < cutoff)
                })
            })
        });
        let revision = has_expired
            .then(|| next_revision(state.revision))
            .transpose()?;
        let mut next_expiration_ms: Option<i64> = None;

        for group in state.groups.values_mut() {
            let Some(days) = group.retention_days else {
                continue;
            };
            let retention_ms = i64::from(days).saturating_mul(DAY_MS);
            let cutoff = now_ms.saturating_sub(retention_ms);
            let mut group_changed = false;
            for stream in group.streams.values_mut() {
                let first_retained = stream
                    .events
                    .partition_point(|event| event.timestamp_ms < cutoff);
                if first_retained > 0 {
                    stream.events.drain(..first_retained);
                    stream.first_event_timestamp_ms =
                        stream.events.first().map(|event| event.timestamp_ms);
                    stream.last_event_timestamp_ms =
                        stream.events.last().map(|event| event.timestamp_ms);
                    stream.last_ingestion_time_ms = stream
                        .events
                        .iter()
                        .map(|event| event.ingestion_time_ms)
                        .max();
                    stream.stored_bytes = stream
                        .events
                        .iter()
                        .map(|event| event.message.len() as u64)
                        .sum();
                    stream.revision = revision.expect("expired events require a revision");
                    group_changed = true;
                }
                if let Some(event) = stream.events.first() {
                    let expiration = event
                        .timestamp_ms
                        .saturating_add(retention_ms)
                        .saturating_add(1);
                    next_expiration_ms = Some(
                        next_expiration_ms.map_or(expiration, |current| current.min(expiration)),
                    );
                }
            }
            if group_changed {
                group.revision = revision.expect("expired events require a revision");
            }
        }
        if let Some(revision) = revision {
            state.revision = revision;
        }
        Ok(next_expiration_ms)
    }

    pub fn visible_stream_events(
        &self,
        key: &GroupKey,
        stream_name: &str,
        now_ms: i64,
    ) -> Result<(u64, Vec<PagedEvent>), LogsError> {
        self.visible_events(key, Some(&[stream_name.to_string()]), None, now_ms)
    }

    pub fn visible_events(
        &self,
        key: &GroupKey,
        stream_names: Option<&[String]>,
        stream_prefix: Option<&str>,
        now_ms: i64,
    ) -> Result<(u64, Vec<PagedEvent>), LogsError> {
        const DAY_MS: i64 = 24 * 60 * 60 * 1_000;
        let state = self.read()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        if let Some(names) = stream_names {
            if let Some(name) = names
                .iter()
                .find(|name| !group.streams.contains_key(name.as_str()))
            {
                return Err(LogsError::ResourceNotFound(format!(
                    "log stream '{}' does not exist",
                    name
                )));
            }
        }
        let retention_cutoff = group
            .retention_days
            .map(|days| now_ms.saturating_sub(i64::from(days).saturating_mul(DAY_MS)));
        let events = group
            .streams
            .values()
            .filter(|stream| {
                stream_names.is_none_or(|names| names.iter().any(|name| name == &stream.name))
                    && stream_prefix.is_none_or(|prefix| stream.name.starts_with(prefix))
            })
            .flat_map(|stream| {
                stream.events.iter().filter_map(|event| {
                    if retention_cutoff.is_some_and(|cutoff| event.timestamp_ms < cutoff) {
                        None
                    } else {
                        Some(PagedEvent {
                            log_stream_name: stream.name.clone(),
                            event: event.clone(),
                        })
                    }
                })
            })
            .collect();
        Ok((state.revision, events))
    }

    pub fn delete_stream(&self, key: &GroupKey, stream_name: &str) -> Result<(), LogsError> {
        let mut state = self.write()?;
        let group = state.groups.get(key).ok_or_else(|| {
            LogsError::ResourceNotFound(format!("log group '{}' does not exist", key.name))
        })?;
        if !group.streams.contains_key(stream_name) {
            return Err(LogsError::ResourceNotFound(format!(
                "log stream '{}' does not exist",
                stream_name
            )));
        }
        let revision = next_revision(state.revision)?;
        let group = state
            .groups
            .get_mut(key)
            .expect("group existence was checked");
        group.streams.remove(stream_name);
        group.revision = revision;
        state.subscription_deliveries.retain(|_, delivery| {
            &delivery.group_key != key || delivery.log_stream_name != stream_name
        });
        state.revision = revision;
        Ok(())
    }

    fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, StoreState>, LogsError> {
        self.state.read().map_err(|_| {
            LogsError::ServiceUnavailable("CloudWatch Logs storage is unavailable".into())
        })
    }

    fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, StoreState>, LogsError> {
        self.state.write().map_err(|_| {
            LogsError::ServiceUnavailable("CloudWatch Logs storage is unavailable".into())
        })
    }
}

fn index_u32(index: usize) -> Result<u32, LogsError> {
    u32::try_from(index)
        .map_err(|_| LogsError::InvalidParameter("too many log events in the batch".into()))
}

fn sequence_token(revision: u64) -> String {
    format!("{revision:032x}")
}

fn event_id(key: &GroupKey, stream_name: &str, put_ordinal: u64, event_ordinal: u32) -> String {
    let mut hash = Sha256::new();
    for part in [
        key.scope.account_id.as_bytes(),
        key.scope.region.as_bytes(),
        key.name.as_bytes(),
        stream_name.as_bytes(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.update(put_ordinal.to_be_bytes());
    hash.update(event_ordinal.to_be_bytes());
    format!("{:x}", hash.finalize())
}

fn merge_events(left: Vec<StoredEvent>, right: Vec<StoredEvent>) -> Vec<StoredEvent> {
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    let mut merged = Vec::with_capacity(left.len().saturating_add(right.len()));
    while let (Some(left_event), Some(right_event)) = (left.peek(), right.peek()) {
        if event_key(left_event) <= event_key(right_event) {
            merged.push(left.next().expect("left event exists"));
        } else {
            merged.push(right.next().expect("right event exists"));
        }
    }
    merged.extend(left);
    merged.extend(right);
    merged
}

fn event_key(event: &StoredEvent) -> (i64, i64, u64, u32) {
    (
        event.timestamp_ms,
        event.ingestion_time_ms,
        event.put_ordinal,
        event.event_ordinal,
    )
}

fn next_revision(current: u64) -> Result<u64, LogsError> {
    current.checked_add(1).ok_or_else(|| {
        LogsError::ServiceUnavailable("CloudWatch Logs revision space is exhausted".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_does_not_mutate_when_revision_cannot_advance() {
        let scope = ScopeKey::new("account", "region");
        let key = GroupKey {
            scope: scope.clone(),
            name: "group".into(),
        };
        let store = LogsStore::default();
        store
            .create_group(
                key.clone(),
                LogGroup {
                    name: "group".into(),
                    arn: "arn:aws:logs:region:account:log-group:group".into(),
                    creation_time_ms: 1,
                    retention_days: None,
                    class: LogClass::Standard,
                    tags: BTreeMap::new(),
                    streams: BTreeMap::new(),
                    metric_filters: BTreeMap::new(),
                    subscription_filters: BTreeMap::new(),
                    revision: 0,
                },
            )
            .unwrap();
        store.state.write().unwrap().revision = u64::MAX;

        assert!(matches!(
            store.delete_group(&key),
            Err(LogsError::ServiceUnavailable(_))
        ));
        assert_eq!(store.describe_groups(&scope, None).unwrap().1.len(), 1);
    }

    #[test]
    fn failed_emf_effects_are_dropped_while_failed_filter_effects_are_kept() {
        use locallycloud_core::integration::metrics::{MetricObservation, MetricOrigin};
        let key = GroupKey {
            scope: ScopeKey::new("account", "region"),
            name: "group".into(),
        };
        let effect = |id, source| PendingMetricEffect {
            id,
            group_key: key.clone(),
            source,
            observation: MetricObservation {
                account_id: "account".into(),
                region: "region".into(),
                namespace: "App".into(),
                metric_name: "m".into(),
                dimensions: BTreeMap::new(),
                timestamp_ms: 1,
                value: 1.0,
                unit: None,
                storage_resolution: 60,
                origin: MetricOrigin::CloudWatchLogs,
                correlation_id: "c".into(),
            },
            status: MetricEffectStatus::Pending,
        };
        let store = LogsStore::default();
        {
            let mut state = store.state.write().unwrap();
            state
                .metric_effects
                .insert(1, effect(1, MetricEffectSource::EmbeddedMetricFormat));
            state.metric_effects.insert(
                2,
                effect(
                    2,
                    MetricEffectSource::Filter {
                        name: "f".into(),
                        revision: 1,
                    },
                ),
            );
        }

        store.finish_metric_effects(&[1, 2], false).unwrap();

        let state = store.state.read().unwrap();
        assert!(!state.metric_effects.contains_key(&1));
        assert_eq!(state.metric_effects[&2].status, MetricEffectStatus::Failed);
    }
}
