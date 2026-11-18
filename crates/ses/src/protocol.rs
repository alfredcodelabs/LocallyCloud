use crate::{error::Error, model::Mail};
use locallycloud_core::handler::ServiceRequest;
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireProtocol {
    Query,
    RestJson,
}
impl WireProtocol {
    pub fn for_request(request: &ServiceRequest) -> Self {
        if request.uri.path() == "/" {
            Self::Query
        } else {
            Self::RestJson
        }
    }
}

pub(crate) enum Operation {
    Create {
        name: String,
        tags: Vec<Value>,
        idempotent: bool,
    },
    Get(String),
    Delete(String),
    List {
        after: String,
        limit: usize,
        kind: Option<String>,
    },
    Send(Mail),
}
pub(crate) struct Call {
    pub operation: Operation,
    pub action: String,
    pub protocol: WireProtocol,
}
fn string(v: &Value, key: &str) -> Result<String, Error> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::BadRequest("A required parameter is missing"))
}
fn json_body(request: &ServiceRequest) -> Result<Value, Error> {
    if !request
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next() == Some("application/json"))
    {
        return Err(Error::BadRequest("Content-Type must be application/json"));
    }
    let value: Value = serde_json::from_slice(&request.body)
        .map_err(|_| Error::BadRequest("Invalid JSON body"))?;
    if !value.is_object() {
        return Err(Error::BadRequest("A JSON object is required"));
    }
    Ok(value)
}
pub(crate) fn decode(request: &ServiceRequest) -> Result<Call, Error> {
    let path = request.uri.path();
    if path == "/" {
        return query(request);
    }
    let (action, operation) = match (request.method.as_str(), path) {
        ("POST", "/v2/email/outbound-emails") => (
            "SendEmail",
            Operation::Send(Mail::parse(&json_body(request)?)?),
        ),
        ("POST", "/v2/email/identities") => {
            let v = json_body(request)?;
            if v.as_object().is_some_and(|o| {
                o.keys()
                    .any(|k| !matches!(k.as_str(), "EmailIdentity" | "Tags"))
            }) {
                return Err(Error::BadRequest("This identity option is not implemented"));
            }
            let tags = match v.get("Tags") {
                None => Vec::new(),
                Some(Value::Array(v)) if v.len() <= 50 => v.clone(),
                _ => return Err(Error::BadRequest("Invalid tags")),
            };
            (
                "CreateEmailIdentity",
                Operation::Create {
                    name: string(&v, "EmailIdentity")?,
                    tags,
                    idempotent: false,
                },
            )
        }
        ("POST", "/v2/email/list-identities") => {
            let v = json_body(request)?;
            let limit = v
                .get("PageSize")
                .map(|v| v.as_u64().ok_or(Error::BadRequest("Invalid PageSize")))
                .transpose()?
                .unwrap_or(100);
            if !(1..=1000).contains(&limit) {
                return Err(Error::BadRequest("PageSize must be between 1 and 1000"));
            }
            if v.get("Filter")
                .is_some_and(|f| f.as_object().is_none_or(|f| !f.is_empty()))
            {
                return Err(Error::BadRequest("Identity filters are not implemented"));
            }
            let after = match v.get("NextToken") {
                None => String::new(),
                Some(Value::String(s)) => s.clone(),
                Some(_) => return Err(Error::BadRequest("Invalid NextToken")),
            };
            (
                "ListEmailIdentities",
                Operation::List {
                    after,
                    limit: limit as usize,
                    kind: None,
                },
            )
        }
        ("GET", "/v2/email/identities") => {
            let values: BTreeMap<_, _> =
                form_urlencoded::parse(request.uri.query().unwrap_or("").as_bytes())
                    .into_owned()
                    .collect();
            let limit = values
                .get("PageSize")
                .map(|v| v.parse::<usize>())
                .transpose()
                .map_err(|_| Error::BadRequest("Invalid PageSize"))?
                .unwrap_or(100);
            if !(1..=1000).contains(&limit) {
                return Err(Error::BadRequest("PageSize must be between 1 and 1000"));
            }
            (
                "ListEmailIdentities",
                Operation::List {
                    after: values.get("NextToken").cloned().unwrap_or_default(),
                    limit,
                    kind: None,
                },
            )
        }
        (method, path) if path.starts_with("/v2/email/identities/") => {
            let raw = path
                .strip_prefix("/v2/email/identities/")
                .ok_or(Error::Unsupported)?;
            let name = percent_encoding::percent_decode_str(raw)
                .decode_utf8()
                .map_err(|_| Error::BadRequest("Invalid identity"))?
                .into_owned();
            crate::model::Identity::new(&name, Vec::new())?;
            match method {
                "GET" => ("GetEmailIdentity", Operation::Get(name)),
                "DELETE" => ("DeleteEmailIdentity", Operation::Delete(name)),
                _ => return Err(Error::Unsupported),
            }
        }
        _ => return Err(Error::Unsupported),
    };
    Ok(Call {
        action: action.into(),
        operation,
        protocol: WireProtocol::RestJson,
    })
}
fn query(request: &ServiceRequest) -> Result<Call, Error> {
    if request.method != http::Method::POST {
        return Err(Error::Unsupported);
    }
    let mut fields = BTreeMap::new();
    for (k, v) in form_urlencoded::parse(&request.body).into_owned() {
        if fields.insert(k, v).is_some() {
            return Err(Error::BadRequest("Duplicate parameter"));
        }
    }
    let required = |key: &str| {
        fields
            .get(key)
            .cloned()
            .ok_or(Error::BadRequest("A required parameter is missing"))
    };
    let action = required("Action")?;
    let operation = match action.as_str() {
        "VerifyEmailIdentity" | "VerifyEmailAddress" => Operation::Create {
            name: required("EmailAddress")?,
            tags: Vec::new(),
            idempotent: true,
        },
        "DeleteIdentity" => Operation::Delete(required("Identity")?),
        "ListIdentities" => {
            let limit = fields
                .get("MaxItems")
                .map(|v| v.parse::<usize>())
                .transpose()
                .map_err(|_| Error::BadRequest("Invalid MaxItems"))?
                .unwrap_or(100);
            if !(1..=1000).contains(&limit) {
                return Err(Error::BadRequest("Invalid MaxItems"));
            }
            Operation::List {
                after: fields.get("NextToken").cloned().unwrap_or_default(),
                limit,
                kind: match fields.get("IdentityType").map(String::as_str) {
                    None => None,
                    Some("EmailAddress") => Some("EMAIL_ADDRESS".into()),
                    Some("Domain") => Some("DOMAIN".into()),
                    _ => return Err(Error::BadRequest("Invalid IdentityType")),
                },
            }
        }
        "SendEmail" => {
            let list = |prefix: &str| -> Result<Vec<String>, Error> {
                let mut items = Vec::new();
                for (k, v) in &fields {
                    if let Some(index) = k.strip_prefix(prefix) {
                        let index = index
                            .parse::<usize>()
                            .map_err(|_| Error::BadRequest("Invalid list index"))?;
                        if !(1..=50).contains(&index) {
                            return Err(Error::BadRequest("Invalid list index"));
                        }
                        items.push((index, v.clone()));
                    }
                }
                items.sort_by_key(|(i, _)| *i);
                Ok(items.into_iter().map(|(_, v)| v).collect())
            };
            let mut input = json!({"FromEmailAddress":required("Source")?,"Destination":{"ToAddresses":list("Destination.ToAddresses.member.")?,"CcAddresses":list("Destination.CcAddresses.member.")?,"BccAddresses":list("Destination.BccAddresses.member.")?},"ReplyToAddresses":list("ReplyToAddresses.member.")?,"Content":{"Simple":{"Subject":{"Data":required("Message.Subject.Data")?},"Body":{}}}});
            for (field, name) in [
                ("Message.Body.Text.Data", "Text"),
                ("Message.Body.Html.Data", "Html"),
            ] {
                if let Some(data) = fields.get(field) {
                    input["Content"]["Simple"]["Body"][name] = json!({"Data":data});
                }
            }
            for (prefix, path) in [
                (
                    "Message.Subject.Charset",
                    vec!["Content", "Simple", "Subject"],
                ),
                (
                    "Message.Body.Text.Charset",
                    vec!["Content", "Simple", "Body", "Text"],
                ),
                (
                    "Message.Body.Html.Charset",
                    vec!["Content", "Simple", "Body", "Html"],
                ),
            ] {
                if let Some(charset) = fields.get(prefix) {
                    let mut value = &mut input;
                    for key in path {
                        value = &mut value[key];
                    }
                    value["Charset"] = json!(charset);
                }
            }
            if fields.keys().any(|k| {
                matches!(
                    k.as_str(),
                    "SourceArn" | "ReturnPath" | "ReturnPathArn" | "ConfigurationSetName"
                ) || k.starts_with("Tags.member.")
            }) {
                return Err(Error::BadRequest("This sending option is not implemented"));
            }
            Operation::Send(Mail::parse(&input)?)
        }
        _ => return Err(Error::Unsupported),
    };
    Ok(Call {
        operation,
        action,
        protocol: WireProtocol::Query,
    })
}
pub(crate) fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
pub(crate) fn query_result(action: &str, v: &Value, request_id: &str) -> String {
    let body = match action {
        "SendEmail" => format!(
            "<MessageId>{}</MessageId>",
            xml(v["MessageId"].as_str().unwrap_or_default())
        ),
        "ListIdentities" => {
            let members = v["EmailIdentities"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|i| i["IdentityName"].as_str())
                        .map(|name| format!("<member>{}</member>", xml(name)))
                        .collect::<String>()
                })
                .unwrap_or_default();
            let token = v
                .get("NextToken")
                .and_then(Value::as_str)
                .map(|t| format!("<NextToken>{}</NextToken>", xml(t)))
                .unwrap_or_default();
            format!("<Identities>{members}</Identities>{token}")
        }
        _ => String::new(),
    };
    let result = format!("<{action}Result>{body}</{action}Result>");
    format!("<{action}Response xmlns=\"http://ses.amazonaws.com/doc/2010-12-01/\">{result}<ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></{action}Response>",xml(request_id))
}
