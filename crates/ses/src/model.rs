use crate::error::Error;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub(crate) const MAX_BODY: usize = 10 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Identity {
    pub name: String,
    pub kind: String,
    pub tags: Vec<Value>,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub dkim_tokens: Vec<String>,
}
impl Identity {
    pub fn new(name: &str, tags: Vec<Value>) -> Result<Self, Error> {
        let kind = if name.contains('@') {
            if name.contains(['<', '>']) {
                return Err(Error::BadRequest(
                    "An identity must be an address without a display name",
                ));
            }
            "EMAIL_ADDRESS"
        } else {
            if name.len() > 253
                || !name.contains('.')
                || name.split('.').any(|s| {
                    s.is_empty()
                        || s.len() > 63
                        || s.starts_with('-')
                        || s.ends_with('-')
                        || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return Err(Error::BadRequest("Invalid email identity"));
            }
            "DOMAIN"
        };
        if tags.len() > 50
            || tags.iter().any(|tag| {
                tag.get("Key")
                    .and_then(Value::as_str)
                    .is_none_or(|k| k.is_empty() || k.len() > 128)
                    || tag
                        .get("Value")
                        .and_then(Value::as_str)
                        .is_none_or(|v| v.len() > 256)
            })
        {
            return Err(Error::BadRequest("Invalid identity tags"));
        }
        Ok(Self {
            name: if kind == "DOMAIN" {
                name.to_ascii_lowercase()
            } else {
                address(name)?
            },
            kind: kind.into(),
            tags,
            verified: false,
            dkim_tokens: Vec::new(),
        })
    }
    pub fn created_output(&self) -> Value {
        let mut output = json!({"IdentityType":self.kind,"VerifiedForSendingStatus":self.verified});
        if self.kind == "DOMAIN" {
            output["DkimAttributes"] = json!({"SigningEnabled":true,"Status":if self.verified {"SUCCESS"}else{"PENDING"},"Tokens":self.dkim_tokens});
        }
        output
    }
    pub fn output(&self) -> Value {
        let mut output = self.created_output();
        output["VerificationStatus"] = json!(if self.verified { "SUCCESS" } else { "PENDING" });
        output["FeedbackForwardingStatus"] = json!(true);
        output["Tags"] = json!(self.tags);
        output["Policies"] = json!({});
        output
    }
}

pub(crate) fn address(value: &str) -> Result<String, Error> {
    if value.len() > 320 || !value.is_ascii() || value.bytes().any(|b| b.is_ascii_control()) {
        return Err(Error::BadRequest("Invalid email address"));
    }
    let mailbox = if let Some((display, tail)) = value.rsplit_once('<') {
        if display.contains(['<', '>']) {
            return Err(Error::BadRequest("Invalid email address"));
        }
        tail.strip_suffix('>')
            .ok_or(Error::BadRequest("Invalid email address"))?
    } else {
        value
    };
    if !email_address::EmailAddress::is_valid(mailbox) {
        return Err(Error::BadRequest("Invalid email address"));
    }
    let (local, domain) = mailbox
        .rsplit_once('@')
        .ok_or(Error::BadRequest("Invalid email address"))?;
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Mail {
    pub from: String,
    pub to: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cc: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub bcc: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub reply_to: Vec<String>,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(skip)]
    pub sender: String,
}
fn list(value: Option<&Value>) -> Result<Vec<String>, Error> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) if values.len() <= 50 => values
            .iter()
            .map(|v| {
                let s = v.as_str().ok_or(Error::BadRequest("Invalid destination"))?;
                address(s)?;
                Ok(s.into())
            })
            .collect(),
        _ => Err(Error::BadRequest("Invalid destination")),
    }
}
fn content(value: Option<&Value>) -> Result<Option<String>, Error> {
    let Some(value) = value else { return Ok(None) };
    let data = value
        .get("Data")
        .and_then(Value::as_str)
        .ok_or(Error::BadRequest("Content Data is required"))?;
    if let Some(charset) = value.get("Charset") {
        if !charset
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("utf-8") || s.eq_ignore_ascii_case("us-ascii"))
        {
            return Err(Error::BadRequest(
                "Only UTF-8 and US-ASCII content is supported",
            ));
        }
    }
    Ok(Some(data.into()))
}
impl Mail {
    pub fn parse(v: &Value) -> Result<Self, Error> {
        if !v.is_object() {
            return Err(Error::BadRequest("A JSON object is required"));
        }
        if v.as_object().is_some_and(|o| {
            o.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "FromEmailAddress" | "Destination" | "Content" | "ReplyToAddresses"
                )
            })
        }) {
            return Err(Error::BadRequest("This sending option is not implemented"));
        }
        if v.get("Destination")
            .and_then(Value::as_object)
            .is_some_and(|o| {
                o.keys()
                    .any(|k| !matches!(k.as_str(), "ToAddresses" | "CcAddresses" | "BccAddresses"))
            })
        {
            return Err(Error::BadRequest("Invalid destination field"));
        }
        let from = v
            .get("FromEmailAddress")
            .and_then(Value::as_str)
            .ok_or(Error::BadRequest("FromEmailAddress is required"))?;
        let sender = address(from)?;
        let destination = v
            .get("Destination")
            .ok_or(Error::BadRequest("Destination is required"))?;
        let to = list(destination.get("ToAddresses"))?;
        let cc = list(destination.get("CcAddresses"))?;
        let bcc = list(destination.get("BccAddresses"))?;
        if to.len() + cc.len() + bcc.len() == 0 || to.len() + cc.len() + bcc.len() > 50 {
            return Err(Error::BadRequest(
                "A message requires between 1 and 50 recipients",
            ));
        }
        let simple = v
            .get("Content")
            .and_then(|c| c.get("Simple"))
            .ok_or(Error::BadRequest(
                "This milestone requires Simple email content",
            ))?;
        if simple
            .as_object()
            .is_none_or(|o| o.keys().any(|k| !matches!(k.as_str(), "Subject" | "Body")))
        {
            return Err(Error::BadRequest("Unsupported Simple content field"));
        }
        let subject =
            content(simple.get("Subject"))?.ok_or(Error::BadRequest("Subject is required"))?;
        if subject.contains(['\r', '\n']) {
            return Err(Error::BadRequest("Invalid subject"));
        }
        let body = simple
            .get("Body")
            .ok_or(Error::BadRequest("Body is required"))?;
        let text = content(body.get("Text"))?;
        let html = content(body.get("Html"))?;
        if text.is_none() && html.is_none() {
            return Err(Error::BadRequest("Text or HTML content is required"));
        }
        for field in [
            "ConfigurationSetName",
            "EmailTags",
            "FromEmailAddressIdentityArn",
            "FeedbackForwardingEmailAddress",
            "FeedbackForwardingEmailAddressIdentityArn",
            "EndpointId",
            "TenantName",
            "ListManagementOptions",
        ] {
            if v.get(field).is_some() {
                return Err(Error::BadRequest(
                    "The requested sending option is not supported by this milestone",
                ));
            }
        }
        if simple.get("Attachments").is_some()
            || simple.get("Headers").is_some()
            || v.get("Content")
                .is_some_and(|c| c.get("Raw").is_some() || c.get("Template").is_some())
        {
            return Err(Error::BadRequest("Raw, templates, custom headers and attachments are not supported by this milestone"));
        }
        Ok(Self {
            from: from.into(),
            sender,
            to,
            cc,
            bcc,
            reply_to: list(v.get("ReplyToAddresses"))?,
            subject,
            text,
            html,
        })
    }
}
