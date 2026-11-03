//! Lambda asynchronous configuration is applied to the owning native API, including qualifiers.
use super::*;
const KIND: &str = "AWS::Lambda::EventInvokeConfig";
fn target<'a>(logical: &str, props: &'a Value) -> Result<(&'a str, &'a str), CfnError> {
    ensure_known_properties(
        logical,
        KIND,
        props,
        &[
            "FunctionName",
            "Qualifier",
            "MaximumEventAgeInSeconds",
            "MaximumRetryAttempts",
            "DestinationConfig",
        ],
    )?;
    let name = props
        .get("FunctionName")
        .and_then(Value::as_str)
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 256
                && !name.contains('|')
                && !name.chars().any(char::is_control)
        })
        .ok_or_else(|| CfnError::Validation(format!("{logical} requires valid FunctionName")))?;
    let qualifier = props
        .get("Qualifier")
        .and_then(Value::as_str)
        .filter(|q| {
            !q.is_empty()
                && q.len() <= 128
                && (*q == "$LATEST"
                    || q.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)))
        })
        .ok_or_else(|| CfnError::Validation(format!("{logical} requires a valid Qualifier")))?;
    for (field, min, max) in [
        ("MaximumRetryAttempts", 0, 2),
        ("MaximumEventAgeInSeconds", 60, 21600),
    ] {
        if props.get(field).is_some_and(|value| {
            !value
                .as_u64()
                .is_some_and(|value| (min..=max).contains(&value))
        }) {
            return Err(CfnError::Validation(format!(
                "Invalid {field} for {logical}"
            )));
        }
    }
    if let Some(config) = props.get("DestinationConfig") {
        ensure_known_properties(
            logical,
            "AWS::Lambda::EventInvokeConfig.DestinationConfig",
            config,
            &["OnSuccess", "OnFailure"],
        )?;
        if !config.is_object() {
            return Err(CfnError::Validation(
                "DestinationConfig must be an object".into(),
            ));
        }
        for field in ["OnSuccess", "OnFailure"] {
            if let Some(destination) = config.get(field) {
                ensure_known_properties(
                    logical,
                    "AWS::Lambda::EventInvokeConfig.Destination",
                    destination,
                    &["Destination"],
                )?;
                required_property(destination, "Destination", logical)?;
            }
        }
    }
    Ok((name, qualifier))
}
fn path(name: &str, qualifier: &str) -> String {
    format!(
        "/2019-09-25/functions/{}/event-invoke-config?Qualifier={}",
        enc(name),
        enc(qualifier)
    )
}
fn resolution(name: &str, qualifier: &str) -> ResolvedResource {
    ResolvedResource {
        ref_value: format!("{name}|{qualifier}"),
        attributes: Default::default(),
    }
}
impl Provisioner {
    async fn put_event_invoke_config(
        &self,
        logical: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let (name, qualifier) = target(logical, props)?;
        let body = mapped_properties(
            props,
            &[
                ("MaximumRetryAttempts", "MaximumRetryAttempts"),
                ("MaximumEventAgeInSeconds", "MaximumEventAgeInSeconds"),
                ("DestinationConfig", "DestinationConfig"),
            ],
        );
        let response = self
            .call_json("lambda", Method::PUT, &path(name, qualifier), body, logical)
            .await?;
        if response
            .get("FunctionArn")
            .and_then(Value::as_str)
            .filter(|arn| !arn.is_empty())
            .is_none()
        {
            return Err(CfnError::ResourceFailed(format!(
                "Lambda did not return FunctionArn for {logical}"
            )));
        }
        Ok(resolution(name, qualifier))
    }
    pub(super) async fn event_invoke_config(
        &self,
        logical: &str,
        props: &Value,
        adopt: bool,
    ) -> Result<ResolvedResource, CfnError> {
        self.prepare_event_invoke_config(logical, props, adopt)
            .await
            .map(|(resource, _)| resource)
    }
    async fn prepare_event_invoke_config(
        &self,
        logical: &str,
        props: &Value,
        adopt: bool,
    ) -> Result<(ResolvedResource, bool), CfnError> {
        let (name, qualifier) = target(logical, props)?;
        let (status, body) = self
            .call(
                "lambda",
                Method::GET,
                &path(name, qualifier),
                json_host(),
                Bytes::new(),
            )
            .await?;
        let created = status == 404;
        match status {
            200 if !adopt => {
                return Err(CfnError::ResourceFailed(format!(
                    "EventInvokeConfig {name}:{qualifier} already exists"
                )))
            }
            200 | 404 => {}
            _ => {
                return Err(CfnError::ResourceFailed(format!(
                    "Lambda GetFunctionEventInvokeConfig for {logical} failed ({status}): {}",
                    String::from_utf8_lossy(&body)
                )))
            }
        }
        self.put_event_invoke_config(logical, props)
            .await
            .map(|resource| (resource, created))
    }
    pub(super) async fn update_event_invoke_config(
        &self,
        logical: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
        replacement: Replacement,
    ) -> Result<ResolvedResource, CfnError> {
        let old = target(logical, previous)?;
        let next = target(logical, props)?;
        if old == next {
            return self.put_event_invoke_config(logical, props).await;
        }
        // Re-adopted retained originals must survive failure deleting a replacement.
        let (new, created) = self
            .prepare_event_invoke_config(
                logical,
                props,
                matches!(replacement, Replacement::Rollback),
            )
            .await?;
        if !matches!(replacement, Replacement::Update(ResourcePolicy::Retain)) {
            if let Err(primary) = self.delete_event_invoke_config(&current.ref_value).await {
                if !created {
                    return Err(primary);
                }
                return match self.delete_event_invoke_config(&new.ref_value).await {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
                };
            }
        }
        Ok(new)
    }
    pub(super) async fn delete_event_invoke_config(&self, physical: &str) -> Result<(), CfnError> {
        let (name, qualifier) = physical
            .split_once('|')
            .ok_or_else(|| CfnError::Validation("Invalid EventInvokeConfig identity".into()))?;
        let (status, body) = self
            .call(
                "lambda",
                Method::DELETE,
                &path(name, qualifier),
                json_host(),
                Bytes::new(),
            )
            .await?;
        if (200..300).contains(&status) || status == 404 {
            return Ok(());
        }
        Err(CfnError::ResourceFailed(format!(
            "Lambda DeleteFunctionEventInvokeConfig failed ({status}): {}",
            String::from_utf8_lossy(&body)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    fn function_body(name: &str) -> Value {
        let mut zip = function_code();
        zip["FunctionName"] = json!(name);
        zip
    }
    fn function_code() -> Value {
        json!({"Runtime":"nodejs22.x","Handler":"index.handler","Role":"arn:aws:iam::000000000000:role/r","Code":{"ZipFile":"UEsDBBQAAAAAAAAAIQDr+WUDKgAAACoAAAAIAAAAaW5kZXguanNleHBvcnRzLmhhbmRsZXIgPSBhc3luYyAoKSA9PiAoe29rOnRydWV9KTtQSwECFAMUAAAAAAAAACEA6/llAyoAAAAqAAAACAAAAAAAAAAAAAAAgAEAAAAAaW5kZXguanNQSwUGAAAAAAEAAQA2AAAAUAAAAAAA"}})
    }
    async fn native(
        registry: &Arc<ServiceRegistry>,
        method: Method,
        path: &str,
        body: Value,
    ) -> (u16, Value) {
        let response = registry
            .native_handler(&ServiceName::new("lambda"))
            .unwrap()
            .handle(ServiceRequest {
                method,
                uri: path.parse().unwrap(),
                headers: json_host(),
                body: Bytes::from(body.to_string()),
                region: "us-east-1".into(),
                account_id: "000000000000".into(),
                request_id: "config-test".into(),
            })
            .await;
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    #[tokio::test]
    async fn qualified_event_config_uses_native_lifecycle_and_replacement() {
        let registry = ServiceRegistry::with_known_services();
        locallycloud_lambda::register(&registry);
        assert_eq!(
            native(
                &registry,
                Method::POST,
                "/2015-03-31/functions",
                function_body("worker")
            )
            .await
            .0,
            201
        );
        assert_eq!(
            native(
                &registry,
                Method::POST,
                "/2015-03-31/functions/worker/versions",
                json!({})
            )
            .await
            .0,
            201
        );
        let p = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let old = json!({"FunctionName":"worker","Qualifier":"$LATEST","MaximumRetryAttempts":1,"MaximumEventAgeInSeconds":120,"DestinationConfig":{"OnFailure":{"Destination":"arn:aws:sqs:us-east-1:000000000000:errors"}}});
        let resource = p.event_invoke_config("Config", &old, false).await.unwrap();
        assert_eq!(resource.ref_value, "worker|$LATEST");
        assert!(p
            .event_invoke_config("Duplicate", &old, false)
            .await
            .is_err());
        let updated =
            json!({"FunctionName":"worker","Qualifier":"$LATEST","MaximumRetryAttempts":0});
        p.update_event_invoke_config(
            "Config",
            &resource,
            &old,
            &updated,
            Replacement::Update(ResourcePolicy::Delete),
        )
        .await
        .unwrap();
        let (_, response) = native(
            &registry,
            Method::GET,
            "/2019-09-25/functions/worker/event-invoke-config?Qualifier=%24LATEST",
            Value::Null,
        )
        .await;
        assert_eq!(response["MaximumRetryAttempts"], 0);
        assert_eq!(response["MaximumEventAgeInSeconds"], 21600);
        assert_eq!(response["DestinationConfig"], json!({}));
        let missing =
            json!({"FunctionName":"worker","Qualifier":"missing","MaximumRetryAttempts":0});
        assert!(p
            .update_event_invoke_config(
                "Config",
                &resource,
                &updated,
                &missing,
                Replacement::Update(ResourcePolicy::Delete)
            )
            .await
            .is_err());
        assert_eq!(
            native(
                &registry,
                Method::GET,
                "/2019-09-25/functions/worker/event-invoke-config",
                Value::Null
            )
            .await
            .0,
            200
        );
        let next = json!({"FunctionName":"worker","Qualifier":"1","MaximumRetryAttempts":2});
        let replaced = p
            .update_event_invoke_config(
                "Config",
                &resource,
                &updated,
                &next,
                Replacement::Update(ResourcePolicy::Retain),
            )
            .await
            .unwrap();
        assert_eq!(replaced.ref_value, "worker|1");
        let rolled = p
            .update_event_invoke_config("Config", &replaced, &next, &updated, Replacement::Rollback)
            .await
            .unwrap();
        assert_eq!(rolled.ref_value, resource.ref_value);
        assert_eq!(
            native(
                &registry,
                Method::GET,
                "/2019-09-25/functions/worker/event-invoke-config?Qualifier=1",
                Value::Null
            )
            .await
            .0,
            404
        );
        p.delete_event_invoke_config(&rolled.ref_value)
            .await
            .unwrap();
        p.delete_event_invoke_config(&rolled.ref_value)
            .await
            .unwrap();
        assert_eq!(
            native(
                &registry,
                Method::GET,
                "/2019-09-25/functions/worker/event-invoke-config",
                Value::Null
            )
            .await
            .0,
            404
        );
        for malformed in [
            json!({"FunctionName":"worker"}),
            json!({"FunctionName":"worker","Qualifier":"$LATEST","MaximumRetryAttempts":-1}),
            json!({"FunctionName":"worker","Qualifier":"$LATEST","DestinationConfig":{"OnFailure":{"Destination":false}}}),
        ] {
            assert!(p
                .event_invoke_config("Bad", &malformed, false)
                .await
                .is_err());
        }
    }
    #[tokio::test]
    async fn failed_rollback_delete_preserves_retained_original_configuration() {
        use locallycloud_core::{
            handler::NativeHandler,
            registry::{AwsProtocol, ServiceMetadata},
        };
        struct FailDelete {
            inner: Arc<dyn NativeHandler>,
        }
        #[async_trait::async_trait]
        impl NativeHandler for FailDelete {
            async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
                if request.method == Method::DELETE && request.uri.query() == Some("Qualifier=1") {
                    return http::Response::builder()
                        .status(500)
                        .body(axum::body::Body::from("forced delete failure"))
                        .unwrap();
                }
                self.inner.handle(request).await
            }
        }
        let registry = ServiceRegistry::with_known_services();
        locallycloud_lambda::register(&registry);
        assert_eq!(
            native(
                &registry,
                Method::POST,
                "/2015-03-31/functions",
                function_body("worker")
            )
            .await
            .0,
            201
        );
        assert_eq!(
            native(
                &registry,
                Method::POST,
                "/2015-03-31/functions/worker/versions",
                json!({})
            )
            .await
            .0,
            201
        );
        let p = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let original =
            json!({"FunctionName":"worker","Qualifier":"$LATEST","MaximumRetryAttempts":0});
        let replacement = json!({"FunctionName":"worker","Qualifier":"1","MaximumRetryAttempts":1});
        let old = p
            .event_invoke_config("Config", &original, false)
            .await
            .unwrap();
        let new = p
            .update_event_invoke_config(
                "Config",
                &old,
                &original,
                &replacement,
                Replacement::Update(ResourcePolicy::Retain),
            )
            .await
            .unwrap();
        let inner = registry
            .native_handler(&ServiceName::new("lambda"))
            .unwrap();
        registry.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            Arc::new(FailDelete { inner }),
        );
        assert!(p
            .update_event_invoke_config(
                "Config",
                &new,
                &replacement,
                &original,
                Replacement::Rollback
            )
            .await
            .is_err());
        for qualifier in ["%24LATEST", "1"] {
            assert_eq!(
                native(
                    &registry,
                    Method::GET,
                    &format!(
                        "/2019-09-25/functions/worker/event-invoke-config?Qualifier={qualifier}"
                    ),
                    Value::Null
                )
                .await
                .0,
                200
            );
        }
    }
}
