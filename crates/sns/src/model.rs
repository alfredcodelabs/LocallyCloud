//! SNS domain model: ARNs, topics, subscriptions, and message attributes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A topic ARN: `arn:aws:sns:<region>:<account>:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicArn {
    pub region: String,
    pub account: String,
    pub name: String,
}

impl TopicArn {
    pub fn new(region: &str, account: &str, name: &str) -> Self {
        TopicArn {
            region: region.to_string(),
            account: account.to_string(),
            name: name.to_string(),
        }
    }

    pub fn to_arn(&self) -> String {
        format!("arn:aws:sns:{}:{}:{}", self.region, self.account, self.name)
    }

    /// Parse `arn:aws:sns:<region>:<account>:<name>`.
    pub fn parse(arn: &str) -> Option<TopicArn> {
        let p: Vec<&str> = arn.split(':').collect();
        if p.len() == 6 && p[0] == "arn" && p[2] == "sns" {
            Some(TopicArn::new(p[3], p[4], p[5]))
        } else {
            None
        }
    }
}

/// A message attribute value (string transport for String/Number, or binary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributeValue {
    String(String),
    Binary(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageAttribute {
    pub data_type: String,
    pub value: AttributeValue,
}

/// A subscription, stored within its topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub arn: String,
    pub topic_arn: String,
    pub protocol: String,
    pub endpoint: String,
    pub owner: String,
    pub confirmed: bool,
    pub pending_token: Option<String>,
    pub attributes: BTreeMap<String, String>,
}

impl Subscription {
    /// The ARN to report: the real ARN once confirmed, else `pending confirmation`.
    pub fn reported_arn(&self, return_real: bool) -> String {
        if self.confirmed || return_real {
            self.arn.clone()
        } else {
            "pending confirmation".to_string()
        }
    }

    pub fn raw_delivery(&self) -> bool {
        self.attributes
            .get("RawMessageDelivery")
            .map(|v| v == "true")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_arn_round_trip() {
        let arn = TopicArn::new("us-east-1", "000000000000", "events");
        assert_eq!(arn.to_arn(), "arn:aws:sns:us-east-1:000000000000:events");
        assert_eq!(TopicArn::parse(&arn.to_arn()), Some(arn));
    }

    #[test]
    fn parse_rejects_non_sns() {
        assert!(TopicArn::parse("arn:aws:sqs:us-east-1:0:q").is_none());
    }

    #[test]
    fn reported_arn_pending() {
        let sub = Subscription {
            arn: "arn:aws:sns:us-east-1:0:t:uuid".into(),
            topic_arn: "arn:aws:sns:us-east-1:0:t".into(),
            protocol: "http".into(),
            endpoint: "https://x".into(),
            owner: "0".into(),
            confirmed: false,
            pending_token: Some("tok".into()),
            attributes: BTreeMap::new(),
        };
        assert_eq!(sub.reported_arn(false), "pending confirmation");
        assert_eq!(sub.reported_arn(true), sub.arn);
    }
}
