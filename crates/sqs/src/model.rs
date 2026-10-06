//! SQS domain model: queue ARN/URL, messages, and message attributes.

use std::collections::BTreeMap;
use std::time::Instant;

use crate::error::SqsError;

/// A queue ARN and its URL form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueArn {
    pub region: String,
    pub account: String,
    pub name: String,
}

impl QueueArn {
    pub fn new(region: &str, account: &str, name: &str) -> Self {
        QueueArn {
            region: region.to_string(),
            account: account.to_string(),
            name: name.to_string(),
        }
    }

    pub fn to_arn(&self) -> String {
        format!("arn:aws:sqs:{}:{}:{}", self.region, self.account, self.name)
    }

    pub fn to_url(&self) -> String {
        format!(
            "https://sqs.{}.amazonaws.com/{}/{}",
            self.region, self.account, self.name
        )
    }

    /// Parse a queue URL of the form `https://sqs.<region>.amazonaws.com/<account>/<name>`
    /// or a path-style `.../<account>/<name>`; the last two path segments are account/name.
    pub fn from_url(url: &str) -> Result<QueueArn, SqsError> {
        let without_scheme = url.split("://").last().unwrap_or(url);
        let (host, path) = without_scheme.split_once('/').ok_or_else(|| {
            SqsError::InvalidParameterValue(format!("malformed queue URL: {url}"))
        })?;
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() < 2 {
            return Err(SqsError::InvalidParameterValue(format!(
                "malformed queue URL: {url}"
            )));
        }
        let name = segments[segments.len() - 1].to_string();
        let account = segments[segments.len() - 2].to_string();
        // Region from `sqs.<region>.amazonaws.com` when present, else a placeholder.
        let region = host
            .strip_prefix("sqs.")
            .and_then(|h| h.split('.').next())
            .unwrap_or("us-east-1")
            .to_string();
        Ok(QueueArn {
            region,
            account,
            name,
        })
    }
}

/// A message attribute value: String/Number (string transport) or Binary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AttributeValue {
    String(String),
    Binary(Vec<u8>),
}

/// A typed message attribute.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MessageAttribute {
    pub data_type: String,
    pub value: AttributeValue,
}

/// Encrypted body and its KMS-wrapped data key. Neither field contains plaintext.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedBody {
    /// Queue ARN used as the KMS encryption context and AEAD associated data.
    /// Automatic dead-letter transfer retains this original context.
    pub encryption_context_arn: String,
    #[serde(default)]
    pub ciphertext: Vec<u8>,
    pub encrypted_data_key: Vec<u8>,
    pub nonce: [u8; 12],
    pub key_id: String,
}

/// A stored message.
#[derive(Debug, Clone)]
pub struct Message {
    pub id: String,
    pub body: String,
    /// Internal payload locator: only committed durable rows may be offloaded.
    pub body_on_disk: bool,
    pub encrypted_body: Option<EncryptedBody>,
    pub md5_body: String,
    pub attributes: BTreeMap<String, MessageAttribute>,
    pub md5_attributes: Option<String>,
    /// System attributes such as `AWSTraceHeader`.
    pub system_attributes: BTreeMap<String, String>,
    pub group_id: Option<String>,
    pub dedup_id: Option<String>,
    pub sequence_number: Option<u128>,
    pub sent_timestamp_ms: i64,
    /// Arrival in the current queue; Standard DLQ retention still uses SentTimestamp.
    pub queue_arrival_ms: Option<i64>,
    pub receive_count: u32,
    pub first_receive_ms: Option<i64>,
    /// Monotonic instant at which the message becomes visible (delay/visibility deadline).
    pub visible_at: Instant,
    /// The receipt handle issued by the most recent receive, if currently in flight.
    pub receipt_handle: Option<String>,
}

impl Message {
    pub fn enter_queue(&mut self, timestamp_ms: i64, reset_enqueue: bool) {
        self.queue_arrival_ms = Some(timestamp_ms);
        if reset_enqueue {
            self.sent_timestamp_ms = timestamp_ms;
        }
    }

    pub fn offload_body(&mut self) {
        self.body = String::new();
        if let Some(encrypted) = &mut self.encrypted_body {
            encrypted.ciphertext = Vec::new();
        }
        self.body_on_disk = true;
    }

    /// Whether the message is currently visible for delivery.
    pub fn is_visible(&self, now: Instant) -> bool {
        now >= self.visible_at
    }

    /// Whether the message is currently in flight (received, not yet visible again).
    pub fn is_in_flight(&self, now: Instant) -> bool {
        self.receipt_handle.is_some() && now < self.visible_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_and_arn_round_trip() {
        let arn = QueueArn::new("us-east-1", "000000000000", "my-queue");
        assert_eq!(
            arn.to_url(),
            "https://sqs.us-east-1.amazonaws.com/000000000000/my-queue"
        );
        assert_eq!(arn.to_arn(), "arn:aws:sqs:us-east-1:000000000000:my-queue");
        let parsed = QueueArn::from_url(&arn.to_url()).unwrap();
        assert_eq!(parsed, arn);
    }

    #[test]
    fn from_url_rejects_malformed() {
        assert!(QueueArn::from_url("https://sqs.us-east-1.amazonaws.com/").is_err());
    }
}
