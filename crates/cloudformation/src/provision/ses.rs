//! SES resources use the same native dispatcher as external SDK requests.
use super::*;

impl Provisioner {
    pub(super) async fn ses_identity(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(
            logical_id,
            "AWS::SES::EmailIdentity",
            props,
            &["EmailIdentity", "Tags"],
        )?;
        let name = required_property(props, "EmailIdentity", logical_id)?;
        let mut body = json!({"EmailIdentity": name});
        if let Some(tags) = props.get("Tags") {
            body["Tags"] = tags.clone();
        }
        let response = self
            .call_json(
                "ses",
                Method::POST,
                "/v2/email/identities",
                body,
                logical_id,
            )
            .await?;
        let mut attributes = std::collections::BTreeMap::new();
        if let Some(tokens) = response
            .pointer("/DkimAttributes/Tokens")
            .and_then(Value::as_array)
        {
            for (i, token) in tokens.iter().take(3).enumerate() {
                let token = token.as_str().ok_or(CfnError::Internal)?;
                attributes.insert(
                    format!("DkimDNSTokenName{}", i + 1),
                    format!("{token}._domainkey.{name}"),
                );
                attributes.insert(
                    format!("DkimDNSTokenValue{}", i + 1),
                    format!("{token}.dkim.amazonses.com"),
                );
            }
        }
        Ok(ResolvedResource {
            ref_value: name,
            attributes,
        })
    }
    pub(super) async fn delete_ses_identity(&self, name: &str) -> Result<(), CfnError> {
        let path = format!("/v2/email/identities/{}", enc(name));
        let (status, _) = self
            .call("ses", Method::DELETE, &path, json_host(), Bytes::new())
            .await?;
        if (200..300).contains(&status) || status == 404 {
            return Ok(());
        }
        Err(CfnError::ResourceFailed(format!(
            "SES identity deletion failed ({status})"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::{
        handler::NativeHandler,
        registry::{AwsProtocol, ServiceMetadata},
    };
    use std::sync::{Arc, Mutex};
    struct Recorder(Mutex<Vec<(Method, String, Value)>>);
    #[async_trait::async_trait]
    impl NativeHandler for Recorder {
        async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
            let body = if request.body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&request.body).unwrap()
            };
            self.0
                .lock()
                .unwrap()
                .push((request.method, request.uri.to_string(), body));
            axum::response::Response::new(axum::body::Body::from(
                json!({"DkimAttributes":{"Tokens":["one","two","three"]}}).to_string(),
            ))
        }
    }
    #[tokio::test]
    async fn identity_ref_dkim_and_delete_use_native_ses_contract() {
        let registry = ServiceRegistry::with_known_services();
        let recorder = Arc::new(Recorder(Mutex::new(vec![])));
        registry.register_native(
            ServiceName::new("ses"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            recorder.clone(),
        );
        let p = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let r = p
            .ses_identity("Mail", &json!({"EmailIdentity":"example.com"}))
            .await
            .unwrap();
        assert_eq!(r.ref_value, "example.com");
        assert_eq!(
            r.attributes["DkimDNSTokenName1"],
            "one._domainkey.example.com"
        );
        assert_eq!(
            r.attributes["DkimDNSTokenValue3"],
            "three.dkim.amazonses.com"
        );
        p.delete_ses_identity("sender@example.com").await.unwrap();
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls[0].1, "/v2/email/identities");
        assert_eq!(calls[0].2["EmailIdentity"], "example.com");
        assert_eq!(calls[1].0, Method::DELETE);
        assert_eq!(calls[1].1, "/v2/email/identities/sender%40example.com");
    }
}
