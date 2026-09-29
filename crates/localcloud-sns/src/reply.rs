//! Operation results with serialization to both JSON and the Query XML envelope.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::xml::{text_el, xml_escape};

/// A view of a subscription for listing responses.
#[derive(Debug, Clone)]
pub struct SubView {
    pub arn: String,
    pub owner: String,
    pub protocol: String,
    pub endpoint: String,
    pub topic_arn: String,
}

/// A successful operation result, renderable in either protocol.
#[derive(Debug, Clone)]
pub enum Reply {
    Empty,
    /// A single ARN-like field (`TopicArn` or `SubscriptionArn`).
    Field(&'static str, String),
    Publish {
        message_id: String,
        sequence_number: Option<String>,
    },
    Topics {
        arns: Vec<String>,
        next: Option<String>,
    },
    Subscriptions {
        subs: Vec<SubView>,
        next: Option<String>,
    },
    Attributes(BTreeMap<String, String>),
    Tags(Vec<(String, String)>),
    PublishBatch {
        successful: Vec<BatchOk>,
        failed: Vec<BatchErr>,
    },
}

#[derive(Debug, Clone)]
pub struct BatchOk {
    pub id: String,
    pub message_id: String,
    pub sequence_number: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BatchErr {
    pub id: String,
    pub code: String,
    pub message: String,
}

impl Reply {
    /// The JSON response body.
    pub fn to_json(&self) -> Value {
        match self {
            Reply::Empty => json!({}),
            Reply::Field(name, value) => json!({ *name: value }),
            Reply::Publish {
                message_id,
                sequence_number,
            } => {
                let mut o = json!({ "MessageId": message_id });
                if let Some(seq) = sequence_number {
                    o.as_object_mut()
                        .unwrap()
                        .insert("SequenceNumber".into(), json!(seq));
                }
                o
            }
            Reply::Topics { arns, next } => {
                let topics: Vec<Value> = arns.iter().map(|a| json!({ "TopicArn": a })).collect();
                let mut obj = json!({ "Topics": topics });
                if let Some(n) = next {
                    obj.as_object_mut()
                        .unwrap()
                        .insert("NextToken".into(), json!(n));
                }
                obj
            }
            Reply::Subscriptions { subs, next } => {
                let list: Vec<Value> = subs
                    .iter()
                    .map(|s| {
                        json!({
                            "SubscriptionArn": s.arn,
                            "Owner": s.owner,
                            "Protocol": s.protocol,
                            "Endpoint": s.endpoint,
                            "TopicArn": s.topic_arn,
                        })
                    })
                    .collect();
                let mut obj = json!({ "Subscriptions": list });
                if let Some(n) = next {
                    obj.as_object_mut()
                        .unwrap()
                        .insert("NextToken".into(), json!(n));
                }
                obj
            }
            Reply::Attributes(map) => {
                let attrs: Map<String, Value> =
                    map.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
                json!({ "Attributes": attrs })
            }
            Reply::Tags(tags) => {
                let list: Vec<Value> = tags
                    .iter()
                    .map(|(k, v)| json!({ "Key": k, "Value": v }))
                    .collect();
                json!({ "Tags": list })
            }
            Reply::PublishBatch { successful, failed } => {
                let ok: Vec<Value> = successful
                    .iter()
                    .map(|e| {
                        let mut o = json!({ "Id": e.id, "MessageId": e.message_id });
                        if let Some(seq) = &e.sequence_number {
                            o.as_object_mut()
                                .unwrap()
                                .insert("SequenceNumber".into(), json!(seq));
                        }
                        o
                    })
                    .collect();
                let err: Vec<Value> = failed
                    .iter()
                    .map(|e| json!({ "Id": e.id, "Code": e.code, "Message": e.message, "SenderFault": true }))
                    .collect();
                json!({ "Successful": ok, "Failed": err })
            }
        }
    }

    /// The inner XML of the `<{Operation}Result>` element for the Query protocol.
    pub fn to_xml_inner(&self) -> String {
        match self {
            Reply::Empty => String::new(),
            Reply::Field(name, value) => text_el(name, value),
            Reply::Publish {
                message_id,
                sequence_number,
            } => {
                let seq = sequence_number
                    .as_ref()
                    .map(|s| text_el("SequenceNumber", s))
                    .unwrap_or_default();
                format!("{}{}", text_el("MessageId", message_id), seq)
            }
            Reply::Topics { arns, next } => {
                let members: String = arns
                    .iter()
                    .map(|a| format!("<member>{}</member>", text_el("TopicArn", a)))
                    .collect();
                let mut s = format!("<Topics>{members}</Topics>");
                if let Some(n) = next {
                    s.push_str(&text_el("NextToken", n));
                }
                s
            }
            Reply::Subscriptions { subs, next } => {
                let members: String = subs
                    .iter()
                    .map(|s| {
                        format!(
                            "<member>{}{}{}{}{}</member>",
                            text_el("Owner", &s.owner),
                            text_el("Protocol", &s.protocol),
                            text_el("Endpoint", &s.endpoint),
                            text_el("SubscriptionArn", &s.arn),
                            text_el("TopicArn", &s.topic_arn),
                        )
                    })
                    .collect();
                let mut out = format!("<Subscriptions>{members}</Subscriptions>");
                if let Some(n) = next {
                    out.push_str(&text_el("NextToken", n));
                }
                out
            }
            Reply::Attributes(map) => {
                let entries: String = map
                    .iter()
                    .map(|(k, v)| {
                        format!(
                            "<entry>{}{}</entry>",
                            text_el("key", k),
                            text_el("value", v)
                        )
                    })
                    .collect();
                format!("<Attributes>{entries}</Attributes>")
            }
            Reply::Tags(tags) => {
                let members: String = tags
                    .iter()
                    .map(|(k, v)| {
                        format!(
                            "<member>{}{}</member>",
                            text_el("Key", k),
                            text_el("Value", v)
                        )
                    })
                    .collect();
                format!("<Tags>{members}</Tags>")
            }
            Reply::PublishBatch { successful, failed } => {
                let ok: String = successful
                    .iter()
                    .map(|e| {
                        let seq = e
                            .sequence_number
                            .as_ref()
                            .map(|s| text_el("SequenceNumber", s))
                            .unwrap_or_default();
                        format!(
                            "<member>{}{}{}</member>",
                            text_el("Id", &e.id),
                            text_el("MessageId", &e.message_id),
                            seq
                        )
                    })
                    .collect();
                let err: String = failed
                    .iter()
                    .map(|e| {
                        format!(
                            "<member>{}{}{}<SenderFault>true</SenderFault></member>",
                            text_el("Id", &e.id),
                            text_el("Code", &e.code),
                            text_el("Message", &e.message),
                        )
                    })
                    .collect();
                format!("<Successful>{ok}</Successful><Failed>{err}</Failed>")
            }
        }
    }
}

/// Wrap a result body in the Query response envelope.
pub fn query_envelope(operation: &str, inner: &str, request_id: &str) -> String {
    let result = format!("<{operation}Result>{inner}</{operation}Result>");
    format!(
        "<{operation}Response xmlns=\"http://sns.amazonaws.com/doc/2010-03-31/\">{result}<ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></{operation}Response>",
        xml_escape(request_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_query_reply_keeps_operation_result() {
        let xml = query_envelope("TagResource", "", "rid");
        assert!(xml.contains("<TagResourceResult></TagResourceResult>"));
    }
}
