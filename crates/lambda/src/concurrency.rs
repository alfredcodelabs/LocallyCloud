//! Concurrency limiter: reserved vs unreserved accounting partitioned by region.
//!
//! Enforces an account/region concurrency cap and per-function reserved concurrency. An
//! acquisition returns an RAII [`ConcurrencyGuard`] that releases exactly once on drop, so an
//! invocation cannot leak a slot even on early return. A function with reserved concurrency is
//! bounded by its reservation and draws from a dedicated allotment; unreserved functions share
//! the pool left after all reservations. Over-limit synchronous invocations are rejected with
//! `TooManyRequestsException` (Requirements 30.1–30.7).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::LambdaError;
use locallycloud_core::config::LambdaConcurrencyConfig;

/// Default account/region concurrent-execution cap (AWS default is 1000).
pub const DEFAULT_REGION_LIMIT: u32 = 1000;

#[derive(Default)]
struct State {
    /// Total in-flight across the region.
    total: u32,
    /// Per-function in-flight counts (keyed by function ARN).
    per_function: HashMap<String, u32>,
    /// Per-function reserved concurrency (keyed by function ARN).
    reserved: HashMap<String, u32>,
    reserved_total: u64,
}

pub struct ConcurrencyLimiter {
    region_limit: u32,
    min_unreserved: u32,
    state: Mutex<HashMap<String, State>>,
    metrics: Option<Arc<crate::metrics::MetricsRecorder>>,
}

impl ConcurrencyLimiter {
    pub fn new(region_limit: u32) -> Arc<Self> {
        Self::build(region_limit, 0, None)
    }

    pub fn with_config(config: LambdaConcurrencyConfig) -> Arc<Self> {
        Self::with_metrics(config, None)
    }

    pub(crate) fn with_metrics(
        config: LambdaConcurrencyConfig,
        metrics: Option<Arc<crate::metrics::MetricsRecorder>>,
    ) -> Arc<Self> {
        Self::build(config.account_limit(), config.min_unreserved(), metrics)
    }

    fn build(
        region_limit: u32,
        min_unreserved: u32,
        metrics: Option<Arc<crate::metrics::MetricsRecorder>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            region_limit,
            min_unreserved,
            state: Mutex::new(HashMap::new()),
            metrics,
        })
    }

    // Function ARNs include account and region. Bare keys are used only by unit fixtures.
    fn scope(key: &str) -> &str {
        key.split_once(":function:")
            .map(|(scope, _)| scope)
            .unwrap_or("")
    }

    fn function_key(key: &str) -> &str {
        key.split_once(":function:")
            .and_then(|(_, suffix)| {
                suffix
                    .find(':')
                    .and_then(|index| key.get(..key.len() - suffix.len() + index))
            })
            .unwrap_or(key)
    }

    fn publish(&self, key: &str, state: &State) {
        let Some(metrics) = &self.metrics else {
            return;
        };
        let Some((scope, function)) = key.split_once(":function:") else {
            return;
        };
        let mut fields = scope.split(':');
        let (Some(region), Some(account)) = (fields.nth(3), fields.next()) else {
            return;
        };
        let current = state.per_function.get(key).copied().unwrap_or(0);
        let unreserved = state
            .per_function
            .iter()
            .filter(|(key, _)| !state.reserved.contains_key(*key))
            .map(|(_, count)| *count)
            .sum();
        metrics.record_concurrency(account, region, function, current, state.total, unreserved);
    }

    /// Called under the service metadata gate, before changing either durable or visible state.
    pub(crate) fn validate_reserved(&self, key: &str, value: u32) -> Result<(), LambdaError> {
        let key = Self::function_key(key);
        let states = self.state.lock().map_err(|_| {
            LambdaError::InternalError("Lambda concurrency state lock poisoned".into())
        })?;
        let others = states
            .get(Self::scope(key))
            .map(|state| {
                state
                    .reserved_total
                    .saturating_sub(u64::from(state.reserved.get(key).copied().unwrap_or(0)))
            })
            .unwrap_or(0);
        if others.saturating_add(u64::from(value))
            > u64::from(self.region_limit.saturating_sub(self.min_unreserved))
        {
            return Err(LambdaError::InvalidParameterValue(format!(
                "Specified ReservedConcurrentExecutions decreases account's UnreservedConcurrentExecution below its minimum value of [{}] (account concurrency limit {}).",
                self.min_unreserved, self.region_limit
            )));
        }
        Ok(())
    }

    pub(crate) fn unreserved_concurrency(
        &self,
        account: &str,
        region: &str,
    ) -> Result<u32, LambdaError> {
        let scope = format!("arn:aws:lambda:{region}:{account}");
        let states = self.state.lock().map_err(|_| {
            LambdaError::InternalError("Lambda concurrency state lock poisoned".into())
        })?;
        let reserved = states
            .get(&scope)
            .map(|state| state.reserved_total)
            .unwrap_or(0);
        u32::try_from(u64::from(self.region_limit).saturating_sub(reserved)).map_err(|_| {
            LambdaError::InternalError(
                "Lambda concurrency total is outside supported limits".into(),
            )
        })
    }

    /// Register/replace a function's reserved concurrency.
    pub fn set_reserved(&self, key: &str, value: u32) {
        let key = Self::function_key(key);
        let mut scopes = self.state.lock().unwrap();
        let state = scopes.entry(Self::scope(key).to_owned()).or_default();
        let previous = state.reserved.insert(key.to_owned(), value);
        state.reserved_total = state
            .reserved_total
            .saturating_sub(u64::from(previous.unwrap_or(0)))
            .saturating_add(u64::from(value));
        if previous.is_none() && state.total > 0 {
            self.publish(key, state);
        }
    }

    /// Clear a function's reserved concurrency.
    pub fn clear_reserved(&self, key: &str) {
        let key = Self::function_key(key);
        let mut scopes = self.state.lock().unwrap();
        if let Some(state) = scopes.get_mut(Self::scope(key)) {
            let previous = state.reserved.remove(key);
            state.reserved_total = state
                .reserved_total
                .saturating_sub(u64::from(previous.unwrap_or(0)));
            if previous.is_some() && state.total > 0 {
                self.publish(key, state);
            }
            if state.total == 0 && state.reserved.is_empty() {
                scopes.remove(Self::scope(key));
            }
        }
    }

    /// Attempt to acquire an execution slot for `key`. Returns `None` when the region cap or
    /// the function's effective limit is reached.
    pub fn acquire(self: &Arc<Self>, key: &str) -> Option<ConcurrencyGuard> {
        let key = Self::function_key(key);
        let mut scopes = self.state.lock().unwrap();
        let s = scopes.entry(Self::scope(key).to_owned()).or_default();
        if s.total >= self.region_limit {
            return None;
        }
        let current = *s.per_function.get(key).unwrap_or(&0);
        match s.reserved.get(key).copied() {
            Some(reserved) => {
                if current >= reserved {
                    return None;
                }
            }
            None => {
                // Unreserved functions share the pool left after every reservation.
                let unreserved_in_use: u32 = s
                    .per_function
                    .iter()
                    .filter(|(k, _)| !s.reserved.contains_key(k.as_str()))
                    .map(|(_, v)| *v)
                    .sum();
                let unreserved_cap = u64::from(self.region_limit).saturating_sub(s.reserved_total);
                if u64::from(unreserved_in_use) >= unreserved_cap {
                    return None;
                }
            }
        }
        s.total += 1;
        *s.per_function.entry(key.to_string()).or_insert(0) += 1;
        self.publish(key, s);
        Some(ConcurrencyGuard {
            limiter: self.clone(),
            key: key.to_string(),
        })
    }

    fn release(&self, key: &str) {
        let mut scopes = self.state.lock().unwrap();
        let Some(s) = scopes.get_mut(Self::scope(key)) else {
            return;
        };
        if s.total > 0 {
            s.total -= 1;
        }
        if let Some(count) = s.per_function.get_mut(key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                s.per_function.remove(key);
            }
        }
        self.publish(key, s);
        if s.total == 0 && s.reserved.is_empty() {
            scopes.remove(Self::scope(key));
        }
    }
}

/// RAII slot held for the duration of an invocation; releases on drop.
pub struct ConcurrencyGuard {
    limiter: Arc<ConcurrencyLimiter>,
    key: String,
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        self.limiter.release(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_quota_preserves_the_floor_and_limits_the_shared_pool() {
        let limiter = ConcurrencyLimiter::with_config(LambdaConcurrencyConfig::new(20, 2).unwrap());
        let first = "arn:aws:lambda:us-east-1:000000000000:function:reserved";
        let second = "arn:aws:lambda:us-east-1:000000000000:function:second";
        limiter.validate_reserved(first, 15).unwrap();
        limiter.set_reserved(first, 15);
        limiter.validate_reserved(first, 15).unwrap();
        assert!(limiter.validate_reserved(second, 4).is_err());
        limiter.validate_reserved(second, 3).unwrap();
        limiter.set_reserved(second, 3);
        assert_eq!(
            limiter
                .unreserved_concurrency("000000000000", "us-east-1")
                .unwrap(),
            2
        );
        let key = "arn:aws:lambda:us-east-1:000000000000:function:shared";
        let a = limiter.acquire(key).unwrap();
        let b = limiter.acquire(key).unwrap();
        assert!(limiter.acquire(key).is_none());
        assert!(limiter.acquire(first).is_some());
        assert_eq!(
            limiter
                .unreserved_concurrency("111111111111", "us-east-1")
                .unwrap(),
            20
        );
        drop((a, b));
        limiter.clear_reserved(second);
        assert_eq!(
            limiter
                .unreserved_concurrency("000000000000", "us-east-1")
                .unwrap(),
            5
        );
    }

    #[test]
    fn reservations_and_execution_caps_are_isolated_by_account_and_region() {
        let limiter = ConcurrencyLimiter::new(2);
        let first = "arn:aws:lambda:us-east-1:000000000000:function:reserved";
        limiter.set_reserved(first, 2);
        assert!(limiter
            .acquire("arn:aws:lambda:us-east-1:000000000000:function:shared")
            .is_none());
        let a = limiter.acquire(&format!("{first}:1")).unwrap();
        let b = limiter.acquire(first).unwrap();
        assert!(limiter.acquire(&format!("{first}:live")).is_none());
        let other_account = limiter
            .acquire("arn:aws:lambda:us-east-1:111111111111:function:shared")
            .unwrap();
        let other_region = limiter
            .acquire("arn:aws:lambda:eu-west-1:000000000000:function:shared")
            .unwrap();
        drop((a, b, other_account, other_region));
        assert!(limiter.acquire(first).is_some());
    }

    #[test]
    fn region_cap_rejects_over_limit() {
        let limiter = ConcurrencyLimiter::new(2);
        let _a = limiter.acquire("fn").unwrap();
        let _b = limiter.acquire("fn").unwrap();
        assert!(
            limiter.acquire("fn").is_none(),
            "third acquire exceeds the region cap"
        );
    }

    #[test]
    fn guard_releases_on_drop() {
        let limiter = ConcurrencyLimiter::new(1);
        {
            let _g = limiter.acquire("fn").unwrap();
            assert!(limiter.acquire("fn").is_none());
        }
        // Slot freed on drop.
        assert!(limiter.acquire("fn").is_some());
    }

    #[test]
    fn reserved_caps_a_function() {
        let limiter = ConcurrencyLimiter::new(100);
        limiter.set_reserved("fn", 1);
        let _g = limiter.acquire("fn").unwrap();
        assert!(
            limiter.acquire("fn").is_none(),
            "reserved=1 allows only one in-flight"
        );
    }

    #[test]
    fn unreserved_pool_excludes_reservations() {
        // Region 3, one function reserves 2 → unreserved pool is 1.
        let limiter = ConcurrencyLimiter::new(3);
        limiter.set_reserved("reserved", 2);
        let _u = limiter.acquire("other").unwrap();
        assert!(
            limiter.acquire("another").is_none(),
            "unreserved pool of 1 is exhausted"
        );
        // The reserved function still has its allotment.
        let _r = limiter.acquire("reserved").unwrap();
    }

    #[test]
    fn clear_reserved_returns_to_pool() {
        let limiter = ConcurrencyLimiter::new(1);
        limiter.set_reserved("fn", 1);
        limiter.clear_reserved("fn");
        assert!(limiter.acquire("fn").is_some());
    }
}
