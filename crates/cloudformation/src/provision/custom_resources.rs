//! Lambda-backed custom resources use ordinary presigned S3 PUT callbacks.
use std::collections::BTreeMap;
use std::time::Duration;

use super::{json_host, Provisioner};
use crate::error::CfnError;
use crate::template::ResolvedResource;
use bytes::Bytes;
use http::{HeaderValue, Method};
use serde_json::{json, Value};

pub(crate) fn is_custom_resource(kind: &str) -> bool {
    kind == "AWS::CloudFormation::CustomResource"
        || kind.strip_prefix("Custom::").is_some_and(|name| {
            !name.is_empty()
                && kind.len() <= 60
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_@-".contains(&c))
        })
}

pub(crate) fn validate_custom_resource(
    logical: &str,
    kind: &str,
    props: &Value,
) -> Result<(), CfnError> {
    if !is_custom_resource(kind) {
        return Ok(());
    }
    if props
        .get("ServiceToken")
        .is_none_or(|v| !(v.is_object() || v.as_str().is_some_and(|s| !s.is_empty())))
    {
        return Err(CfnError::Validation(format!(
            "Custom resource {logical} requires ServiceToken"
        )));
    }
    if let Some(value) = props.get("ServiceTimeout") {
        if !value.is_object() {
            service_timeout(props)?;
        }
    }
    Ok(())
}

fn service_timeout(props: &Value) -> Result<u32, CfnError> {
    let seconds = match props.get("ServiceTimeout") {
        None => Some(3600),
        Some(Value::String(value)) => value.parse::<u32>().ok(),
        Some(value) => value.as_u64().and_then(|v| u32::try_from(v).ok()),
    };
    seconds.filter(|v| (1..=3600).contains(v)).ok_or_else(|| {
        CfnError::Validation("ServiceTimeout must be between 1 and 3600 seconds".into())
    })
}

impl Provisioner {
    pub(crate) async fn deprovision_named(
        &self,
        logical: &str,
        kind: &str,
        physical: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        if is_custom_resource(kind) {
            return self
                .delete_custom_resource(logical, kind, physical, props)
                .await;
        }
        self.deprovision(kind, physical, props).await
    }

    pub(super) async fn delete_custom_resource(
        &self,
        logical: &str,
        kind: &str,
        physical: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        let current = ResolvedResource {
            ref_value: physical.into(),
            attributes: BTreeMap::new(),
        };
        self.custom_request(logical, kind, props, "Delete", Some(&current), None)
            .await
            .map(|_| ())
    }

    pub(super) async fn custom_resource(
        &self,
        logical: &str,
        kind: &str,
        props: &Value,
        current: Option<&ResolvedResource>,
        previous: Option<&Value>,
    ) -> Result<ResolvedResource, CfnError> {
        self.custom_request(
            logical,
            kind,
            props,
            if current.is_some() {
                "Update"
            } else {
                "Create"
            },
            current,
            previous,
        )
        .await
    }

    async fn custom_request(
        &self,
        logical: &str,
        kind: &str,
        props: &Value,
        operation: &str,
        current: Option<&ResolvedResource>,
        previous: Option<&Value>,
    ) -> Result<ResolvedResource, CfnError> {
        let seconds = service_timeout(props)?;
        let token = props
            .get("ServiceToken")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CfnError::ResourceFailed(format!(
                    "{logical}: ServiceToken must resolve to a Lambda ARN"
                ))
            })?;
        let parts: Vec<_> = token.splitn(9, ':').collect();
        if !(7..=8).contains(&parts.len())
            || token.len() > 2048
            || !token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b":_-.$".contains(&c))
            || parts.first() != Some(&"arn")
            || parts.get(2) != Some(&"lambda")
            || parts.get(3) != Some(&self.region.as_str())
            || parts.get(4) != Some(&self.account.as_str())
            || parts.get(5) != Some(&"function")
            || parts.get(6).is_none_or(|v| v.is_empty())
        {
            return Err(CfnError::ResourceFailed(format!("{logical}: ServiceToken must be a Lambda function ARN in the stack account and region")));
        }
        let stack = self.stack_id.as_deref().ok_or_else(|| {
            CfnError::ResourceFailed("Custom resource requires stack identity".into())
        })?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let bucket = format!("cfn-response-{}", uuid::Uuid::new_v4().simple());
        let bucket_path = format!("/{bucket}");
        let path = format!("/{bucket}/{request_id}");
        let (status, _) = self
            .call("s3", Method::PUT, &bucket_path, json_host(), Bytes::new())
            .await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "{logical}: could not create response bucket ({status})"
            )));
        }
        let result = async {
            let evaluator = self.registry.upgrade().and_then(|registry| registry.authorization_evaluator(&locallycloud_core::registry::ServiceName::new("iam")));
            let response_url = match evaluator.filter(|evaluator| evaluator.strict_sigv4_required()) {
                Some(evaluator) => evaluator.presign_s3_put(locallycloud_core::integration::authorization::S3PutPresignRequest {
                    account: self.account.clone(), access_key: self.caller_access_key.clone().ok_or_else(|| CfnError::ResourceFailed("Custom resource callback requires verified caller credentials".into()))?,
                    endpoint: self.response_endpoint.clone(), path: path.clone(), region: self.region.clone(), expires: seconds,
                }).map_err(|_| CfnError::ResourceFailed("Could not sign the custom resource callback with active IAM credentials".into()))?,
                None => locallycloud_s3::presign::presign_local_put(&self.response_endpoint, &path, &self.region, seconds).await.map_err(CfnError::ResourceFailed)?,
            };
            let mut event = json!({"RequestType": operation, "ResponseURL": response_url, "StackId": stack, "RequestId": request_id, "ResourceType": kind, "LogicalResourceId": logical, "ResourceProperties": props});
            if let Some(current) = current { event["PhysicalResourceId"] = json!(current.ref_value); }
            if let Some(previous) = previous { event["OldResourceProperties"] = previous.clone(); }
            let invoke_path = format!("/2015-03-31/functions/{}/invocations", token);
            let mut invoke_headers = json_host();
            invoke_headers.insert("x-amz-invocation-type", HeaderValue::from_static("Event"));
            let invocation = self.call("lambda", Method::POST, &invoke_path, invoke_headers, Bytes::from(event.to_string()));
            tokio::pin!(invocation);
            let mut invoked = false;
            let mut invocation_error = None;
            let wait = async {
                loop {
                    let mut headers = json_host();
                    headers.insert("range", HeaderValue::from_static("bytes=0-4096"));
                    let (status, body) = self.call("s3", Method::GET, &path, headers, Bytes::new()).await?;
                    match status {
                        200 | 206 => return parse_response(&event, &body),
                        404 => {},
                        _ => return Err(CfnError::ResourceFailed(format!("{logical}: reading custom resource response failed ({status})"))),
                    }
                    if let Some(error) = invocation_error.take() { return Err(error); }
                    tokio::select! {
                        result = &mut invocation, if !invoked => {
                            invoked = true;
                            match result {
                                Ok((status, _)) if (200..300).contains(&status) => {},
                                Ok((status, body)) => {
                                    let message = serde_json::from_slice::<Value>(&body).ok()
                                        .and_then(|value| value.get("Message").or_else(|| value.get("message")).and_then(Value::as_str).map(|message| message.chars().take(1024).collect::<String>()))
                                        .unwrap_or_else(|| "See the Lambda invocation error".into());
                                    invocation_error = Some(CfnError::ResourceFailed(format!("{logical}: provider invocation failed ({status}): {message}")));
                                },
                                Err(error) => invocation_error = Some(error),
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(seconds.into()), wait).await.unwrap_or_else(|_| Err(CfnError::ResourceFailed(format!("{logical}: custom resource {operation} timed out after {seconds} seconds without a response"))))
        }.await;
        // Retire the capability even when the provider failed or timed out.
        let object_cleanup = self
            .call("s3", Method::DELETE, &path, json_host(), Bytes::new())
            .await;
        let bucket_cleanup = self
            .call(
                "s3",
                Method::DELETE,
                &bucket_path,
                json_host(),
                Bytes::new(),
            )
            .await;
        for cleanup in [object_cleanup, bucket_cleanup] {
            match cleanup {
                Ok((status, _)) if (200..300).contains(&status) => {}
                _ => {
                    let reason = result
                        .as_ref()
                        .err()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "provider completed".into());
                    return Err(CfnError::ResourceFailed(format!(
                        "{logical}: custom resource response cleanup failed ({reason})"
                    )));
                }
            }
        }
        result
    }
}

fn parse_response(event: &Value, bytes: &[u8]) -> Result<ResolvedResource, CfnError> {
    let fail = |reason: &str| {
        CfnError::ResourceFailed(format!(
            "{}: {reason}",
            event["LogicalResourceId"]
                .as_str()
                .unwrap_or("custom resource")
        ))
    };
    if bytes.len() > 4096 {
        return Err(fail("provider response exceeds 4096 bytes"));
    }
    let response: Value =
        serde_json::from_slice(bytes).map_err(|_| fail("invalid provider response JSON"))?;
    for key in ["StackId", "RequestId", "LogicalResourceId"] {
        if response.get(key) != event.get(key) {
            return Err(fail("provider response identity mismatch"));
        }
    }
    let physical = response
        .get("PhysicalResourceId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 1024)
        .ok_or_else(|| fail("provider response requires PhysicalResourceId (1..1024 bytes)"))?;
    match response.get("Status").and_then(Value::as_str) {
        Some("SUCCESS") => {}
        Some("FAILED") => {
            return Err(fail(
                response
                    .get("Reason")
                    .and_then(Value::as_str)
                    .unwrap_or("provider reported FAILED"),
            ))
        }
        _ => return Err(fail("provider response Status must be SUCCESS or FAILED")),
    }
    let no_echo = match response.get("NoEcho") {
        None => false,
        Some(Value::Bool(value)) => *value,
        _ => return Err(fail("provider response NoEcho must be boolean")),
    };
    let data = match response.get("Data") {
        None | Some(Value::Null) => BTreeMap::new(),
        Some(Value::Object(data)) => data
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    if no_echo {
                        "****".into()
                    } else {
                        v.as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| v.to_string())
                    },
                )
            })
            .collect(),
        _ => return Err(fail("provider response Data must be an object")),
    };
    Ok(ResolvedResource {
        ref_value: physical.into(),
        attributes: data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_contract_bounds_and_no_echo() {
        let event = json!({"StackId":"stack", "RequestId":"request", "LogicalResourceId":"Custom"});
        let mut response = event.clone();
        response["Status"] = json!("SUCCESS");
        response["PhysicalResourceId"] = json!("provider-id");
        response["Data"] = json!({"Secret":"sensitive-value"});
        response["NoEcho"] = json!(true);
        assert_eq!(
            parse_response(&event, response.to_string().as_bytes())
                .unwrap()
                .attributes["Secret"],
            "****"
        );
        for (field, value) in [
            ("Status", json!("UNKNOWN")),
            ("PhysicalResourceId", json!("")),
            ("PhysicalResourceId", json!("x".repeat(1025))),
            ("RequestId", json!("different")),
            ("NoEcho", json!("true")),
            ("Data", json!([])),
        ] {
            let mut invalid = response.clone();
            invalid[field] = value;
            assert!(
                parse_response(&event, invalid.to_string().as_bytes()).is_err(),
                "{field}"
            );
        }
        assert!(parse_response(&event, &[b' '; 4097]).is_err());
    }
}
