//! Bounded metadata for the local activity dashboard. No payloads or credentials.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::audit::DispatchOutcome;

const CAPACITY: usize = 500;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityRecord {
    started_at: u64,
    completed_at: u64,
    duration_ms: u64,
    service: String,
    operation: String,
    account_id: String,
    region: String,
    request_id: String,
    http_status: u16,
    error_code: Option<String>,
    resource: Option<String>,
}

#[derive(Default)]
struct Entries {
    sequence: u64,
    records: VecDeque<ActivityRecord>,
}

#[derive(Default)]
pub struct ActivityLog(Mutex<Entries>);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivitySnapshot {
    pub records: Vec<ActivityRecord>,
    capacity: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    evicted: Option<u64>,
}

fn epoch_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

impl ActivityLog {
    pub fn record(&self, outcome: &DispatchOutcome, resource: Option<String>) {
        let mut entries = self.0.lock().unwrap_or_else(|error| error.into_inner());
        entries.sequence = entries.sequence.saturating_add(1);
        if entries.records.len() == CAPACITY {
            entries.records.pop_front();
        }
        entries.records.push_back(ActivityRecord {
            started_at: epoch_ms(outcome.started_at),
            completed_at: epoch_ms(outcome.completed_at),
            duration_ms: outcome
                .completed_at
                .duration_since(outcome.started_at)
                .unwrap_or_default()
                .as_millis()
                .min(u64::MAX as u128) as u64,
            service: outcome.service.clone(),
            operation: outcome.operation.clone(),
            account_id: outcome.account_id.clone(),
            region: outcome.region.clone(),
            request_id: outcome.request_id.clone(),
            http_status: outcome.http_status,
            error_code: outcome.error_code.clone(),
            resource,
        });
    }

    pub fn snapshot(&self) -> ActivitySnapshot {
        let entries = self.0.lock().unwrap_or_else(|error| error.into_inner());
        ActivitySnapshot {
            records: entries.records.iter().rev().cloned().collect(),
            capacity: CAPACITY,
            evicted: Some(
                entries
                    .sequence
                    .saturating_sub(entries.records.len() as u64),
            ),
        }
    }
    pub fn snapshot_scoped(&self, account: &str, region: &str) -> ActivitySnapshot {
        let mut snapshot = self.snapshot();
        snapshot.records.retain(|record| {
            record.account_id == account
                && (record.region == region
                    || matches!(
                        record.service.as_str(),
                        "iam" | "sts" | "route53" | "cloudfront"
                    ))
        });
        // Eviction accounting is global; it must not expose another account's count.
        snapshot.evicted = None;
        snapshot
    }
}

/// Only resource identifiers needed to navigate to a service explorer are retained.
pub fn resource_name(service: &str, path: &str, body: &[u8]) -> Option<String> {
    let value = if service == "lambda" {
        path.split_once("/functions/")
            .and_then(|(_, suffix)| suffix.split('/').next())
            .map(str::to_owned)
    } else {
        let key = match service {
            "states" => "stateMachineArn",
            "dynamodb" => "TableName",
            "sqs" => "QueueUrl",
            "logs" => "logGroupName",
            _ => return None,
        };
        serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|value| value.get(key).and_then(|v| v.as_str()).map(str::to_owned))
    };
    value.filter(|value| {
        !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{AwsProtocol, Disposition};

    #[test]
    fn activity_is_bounded_and_keeps_failures_without_payloads() {
        let log = ActivityLog::default();
        let outcome = DispatchOutcome {
            dispatch_id: "dispatch".into(),
            request_id: "request".into(),
            account_id: "account".into(),
            region: "us-east-1".into(),
            service: "sqs".into(),
            operation: "SendMessage".into(),
            protocol: AwsProtocol::Json10,
            disposition: Disposition::Native,
            started_at: UNIX_EPOCH,
            completed_at: UNIX_EPOCH,
            http_status: 400,
            error_code: Some("QueueDoesNotExist".into()),
        };
        let resource = resource_name(
            "sqs",
            "/",
            br#"{"QueueUrl":"http://localhost/queue","MessageBody":"private-payload"}"#,
        );
        for _ in 0..=CAPACITY {
            log.record(&outcome, resource.clone());
        }
        let snapshot = log.snapshot();
        assert_eq!(snapshot.records.len(), CAPACITY);
        assert_eq!(snapshot.evicted, Some(1));
        assert_eq!(log.0.lock().unwrap().sequence, 501);
        let rendered = serde_json::to_string(&snapshot).unwrap();
        assert!(rendered.contains("QueueDoesNotExist"));
        assert!(!rendered.contains("private-payload"));
        let mut elsewhere = outcome.clone();
        elsewhere.account_id = "other".into();
        log.record(&elsewhere, Some("hidden-resource".into()));
        elsewhere.account_id = "account".into();
        elsewhere.region = "eu-west-1".into();
        log.record(&elsewhere, Some("other-region".into()));
        elsewhere.service = "iam".into();
        log.record(&elsewhere, Some("global-role".into()));
        let scoped = log.snapshot_scoped("account", "us-east-1");
        let rendered = serde_json::to_string(&scoped).unwrap();
        assert!(rendered.contains("global-role"));
        assert!(!rendered.contains("hidden-resource"));
        assert!(!rendered.contains("other-region"));
        assert!(!rendered.contains("sequence"));
        assert!(!rendered.contains("evicted"));
        assert_eq!(scoped.evicted, None);
        assert!(log
            .snapshot_scoped("absent", "us-east-1")
            .records
            .is_empty());
    }
}
