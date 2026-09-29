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

/// Default account/region concurrent-execution cap (AWS default is 1000).
pub const DEFAULT_REGION_LIMIT: u32 = 1000;

struct State {
    /// Total in-flight across the region.
    total: u32,
    /// Per-function in-flight counts (keyed by function ARN).
    per_function: HashMap<String, u32>,
    /// Per-function reserved concurrency (keyed by function ARN).
    reserved: HashMap<String, u32>,
}

pub struct ConcurrencyLimiter {
    region_limit: u32,
    state: Mutex<State>,
}

impl ConcurrencyLimiter {
    pub fn new(region_limit: u32) -> Arc<Self> {
        Arc::new(ConcurrencyLimiter {
            region_limit,
            state: Mutex::new(State {
                total: 0,
                per_function: HashMap::new(),
                reserved: HashMap::new(),
            }),
        })
    }

    /// Register/replace a function's reserved concurrency.
    pub fn set_reserved(&self, key: &str, value: u32) {
        self.state
            .lock()
            .unwrap()
            .reserved
            .insert(key.to_string(), value);
    }

    /// Clear a function's reserved concurrency.
    pub fn clear_reserved(&self, key: &str) {
        self.state.lock().unwrap().reserved.remove(key);
    }

    /// Attempt to acquire an execution slot for `key`. Returns `None` when the region cap or
    /// the function's effective limit is reached.
    pub fn acquire(self: &Arc<Self>, key: &str) -> Option<ConcurrencyGuard> {
        let mut s = self.state.lock().unwrap();
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
                let total_reserved: u32 = s.reserved.values().copied().sum();
                let unreserved_in_use: u32 = s
                    .per_function
                    .iter()
                    .filter(|(k, _)| !s.reserved.contains_key(k.as_str()))
                    .map(|(_, v)| *v)
                    .sum();
                let unreserved_cap = self.region_limit.saturating_sub(total_reserved);
                if unreserved_in_use >= unreserved_cap {
                    return None;
                }
            }
        }
        s.total += 1;
        *s.per_function.entry(key.to_string()).or_insert(0) += 1;
        Some(ConcurrencyGuard {
            limiter: self.clone(),
            key: key.to_string(),
        })
    }

    fn release(&self, key: &str) {
        let mut s = self.state.lock().unwrap();
        if s.total > 0 {
            s.total -= 1;
        }
        if let Some(count) = s.per_function.get_mut(key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                s.per_function.remove(key);
            }
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
