//! SNS message envelope and target-event builders.
//!
//! The notification envelope is the canonical `Type=Notification` JSON document delivered to
//! non-raw subscribers; the Lambda event wraps it in the `Records`/`aws:sns` shape.

use std::collections::BTreeMap;

use base64::Engine;
use serde_json::{json, Map, Value};

use crate::model::{AttributeValue, MessageAttribute};

/// The fields needed to build an SNS notification.
pub struct Notification<'a> {
    pub message_id: &'a str,
    pub topic_arn: &'a str,
    pub subscription_arn: &'a str,
    pub message: &'a str,
    pub subject: Option<&'a str>,
    pub timestamp: &'a str,
    pub attributes: &'a BTreeMap<String, MessageAttribute>,
}

impl Notification<'_> {
    /// The `Type=Notification` envelope as a JSON value.
    pub fn envelope(&self) -> Value {
        let unsubscribe = format!(
            "https://sns.amazonaws.com/?Action=Unsubscribe&SubscriptionArn={}",
            self.subscription_arn
        );
        let mut obj = Map::new();
        obj.insert("Type".into(), json!("Notification"));
        obj.insert("MessageId".into(), json!(self.message_id));
        obj.insert("TopicArn".into(), json!(self.topic_arn));
        if let Some(subject) = self.subject {
            obj.insert("Subject".into(), json!(subject));
        }
        obj.insert("Message".into(), json!(self.message));
        obj.insert("Timestamp".into(), json!(self.timestamp));
        obj.insert("SignatureVersion".into(), json!("1"));
        obj.insert("Signature".into(), json!("locallycloud-unsigned"));
        obj.insert(
            "SigningCertURL".into(),
            json!("https://sns.amazonaws.com/locallycloud.pem"),
        );
        obj.insert("UnsubscribeURL".into(), json!(unsubscribe));
        if !self.attributes.is_empty() {
            obj.insert(
                "MessageAttributes".into(),
                attributes_value(self.attributes),
            );
        }
        Value::Object(obj)
    }

    /// The envelope serialized as a JSON string (the body delivered to non-raw subscribers).
    pub fn envelope_string(&self) -> String {
        self.envelope().to_string()
    }

    /// The SNS→Lambda `Records` event document.
    pub fn lambda_event(&self, subscription_arn: &str) -> Value {
        let mut sns = self.envelope();
        // The Lambda event uses `MessageAttributes` with {Type, Value}; already in that shape.
        if let Value::Object(map) = &mut sns {
            map.insert("SignatureVersion".into(), json!("1"));
            map.entry("MessageAttributes").or_insert_with(|| json!({}));
        }
        json!({
            "Records": [{
                "EventSource": "aws:sns",
                "EventVersion": "1.0",
                "EventSubscriptionArn": subscription_arn,
                "Sns": sns,
            }]
        })
    }
}

/// The `Type=SubscriptionConfirmation` message POSTed to an http/https endpoint on subscribe.
/// The subscriber confirms by invoking `ConfirmSubscription` with the `Token` (via `SubscribeURL`).
pub fn confirmation_message(
    message_id: &str,
    topic_arn: &str,
    token: &str,
    subscribe_url: &str,
    timestamp: &str,
) -> Value {
    json!({
        "Type": "SubscriptionConfirmation",
        "MessageId": message_id,
        "Token": token,
        "TopicArn": topic_arn,
        "Message": format!(
            "You have chosen to subscribe to the topic {topic_arn}.\nTo confirm the subscription, visit the SubscribeURL included in this message."
        ),
        "SubscribeURL": subscribe_url,
        "Timestamp": timestamp,
        "SignatureVersion": "1",
        "Signature": "locallycloud-unsigned",
        "SigningCertURL": "https://sns.amazonaws.com/locallycloud.pem",
    })
}

/// Serialize message attributes to the SNS `{Type, Value}` map.
pub fn attributes_value(attrs: &BTreeMap<String, MessageAttribute>) -> Value {
    let mut map = Map::new();
    for (name, attr) in attrs {
        let (typ, val) = match &attr.value {
            AttributeValue::String(s) => (attr.data_type.clone(), s.clone()),
            AttributeValue::Binary(b) => (
                attr.data_type.clone(),
                base64::engine::general_purpose::STANDARD.encode(b),
            ),
        };
        map.insert(name.clone(), json!({ "Type": typ, "Value": val }));
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_has_required_fields() {
        let attrs = BTreeMap::new();
        let n = Notification {
            message_id: "mid",
            topic_arn: "arn:aws:sns:us-east-1:0:t",
            subscription_arn: "arn:aws:sns:us-east-1:0:t:sub",
            message: "hello",
            subject: Some("hi"),
            timestamp: "2026-01-01T00:00:00.000Z",
            attributes: &attrs,
        };
        let env = n.envelope();
        assert_eq!(env["Type"], "Notification");
        assert_eq!(env["Message"], "hello");
        assert_eq!(env["Subject"], "hi");
        assert!(env["UnsubscribeURL"]
            .as_str()
            .unwrap()
            .contains("SubscriptionArn=arn:aws:sns:us-east-1:0:t:sub"));
    }

    #[test]
    fn subject_omitted_when_absent() {
        let attrs = BTreeMap::new();
        let n = Notification {
            message_id: "mid",
            topic_arn: "t",
            subscription_arn: "t:sub",
            message: "m",
            subject: None,
            timestamp: "ts",
            attributes: &attrs,
        };
        assert!(n.envelope().get("Subject").is_none());
    }

    #[test]
    fn lambda_event_shape() {
        let attrs = BTreeMap::new();
        let n = Notification {
            message_id: "mid",
            topic_arn: "t",
            subscription_arn: "t:sub",
            message: "m",
            subject: None,
            timestamp: "ts",
            attributes: &attrs,
        };
        let ev = n.lambda_event("subarn");
        assert_eq!(ev["Records"][0]["EventSource"], "aws:sns");
        assert_eq!(ev["Records"][0]["Sns"]["Message"], "m");
    }
}
