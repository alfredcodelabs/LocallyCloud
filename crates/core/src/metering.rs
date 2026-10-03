//! Per-service usage metering.
//!
//! The single dispatch path records one observation per request, so usage is metered in one
//! cohesive place regardless of how many services exist. The meter is the substrate for cost
//! estimation and (later) quota detection. It counts *real* requests and request bytes; it
//! does not infer anything it cannot observe.

use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

/// Thread-safe per-service counters.
#[derive(Default)]
pub struct Meter {
    services: DashMap<String, Counters>,
}

#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    bytes_in: AtomicU64,
}

/// A point-in-time view of one service's metered usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMetrics {
    pub service: String,
    pub requests: u64,
    pub bytes_in: u64,
}

impl Meter {
    pub fn new() -> Self {
        Meter {
            services: DashMap::new(),
        }
    }

    /// Record one request to `service` carrying `bytes_in` request-body bytes.
    pub fn record(&self, service: &str, bytes_in: u64) {
        let entry = self.services.entry(service.to_string()).or_default();
        entry.requests.fetch_add(1, Ordering::Relaxed);
        entry.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
    }

    /// A name-sorted snapshot of all metered services.
    pub fn snapshot(&self) -> Vec<ServiceMetrics> {
        let mut out: Vec<ServiceMetrics> = self
            .services
            .iter()
            .map(|e| ServiceMetrics {
                service: e.key().clone(),
                requests: e.value().requests.load(Ordering::Relaxed),
                bytes_in: e.value().bytes_in.load(Ordering::Relaxed),
            })
            .collect();
        out.sort_by(|a, b| a.service.cmp(&b.service));
        out
    }

    /// Total requests across all services.
    pub fn total_requests(&self) -> u64 {
        self.services
            .iter()
            .map(|e| e.value().requests.load(Ordering::Relaxed))
            .sum()
    }

    /// Clear all counters (e.g. to start a fresh traffic run).
    pub fn reset(&self) {
        self.services.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_accumulates_per_service() {
        let m = Meter::new();
        m.record("sqs", 10);
        m.record("sqs", 5);
        m.record("dynamodb", 20);
        let snap = m.snapshot();
        assert_eq!(snap.len(), 2);
        // sorted: dynamodb before sqs
        assert_eq!(snap[0].service, "dynamodb");
        assert_eq!(snap[0].requests, 1);
        assert_eq!(snap[0].bytes_in, 20);
        assert_eq!(snap[1].service, "sqs");
        assert_eq!(snap[1].requests, 2);
        assert_eq!(snap[1].bytes_in, 15);
        assert_eq!(m.total_requests(), 3);
    }

    #[test]
    fn reset_clears() {
        let m = Meter::new();
        m.record("s3", 1);
        m.reset();
        assert_eq!(m.total_requests(), 0);
        assert!(m.snapshot().is_empty());
    }

    #[tokio::test]
    async fn concurrent_records_are_counted() {
        let m = std::sync::Arc::new(Meter::new());
        let mut handles = Vec::new();
        for _ in 0..100u32 {
            let m = m.clone();
            handles.push(tokio::spawn(async move { m.record("lambda", 1) }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(m.total_requests(), 100);
    }
}
