//! REST authorizers use API Gateway's native lifecycle and validation.
use super::*;

const FIELDS: &[(&str, &str)] = &[
    ("Name", "name"),
    ("Type", "type"),
    ("AuthorizerUri", "authorizerUri"),
    ("AuthorizerCredentials", "authorizerCredentials"),
    ("IdentitySource", "identitySource"),
    (
        "IdentityValidationExpression",
        "identityValidationExpression",
    ),
    (
        "AuthorizerResultTtlInSeconds",
        "authorizerResultTtlInSeconds",
    ),
    ("AuthType", "authType"),
    ("ProviderARNs", "providerARNs"),
];

fn body(logical: &str, props: &Value) -> Result<Value, CfnError> {
    let allowed: Vec<_> = std::iter::once("RestApiId")
        .chain(FIELDS.iter().map(|(key, _)| *key))
        .collect();
    ensure_known_properties(logical, "AWS::ApiGateway::Authorizer", props, &allowed)?;
    for key in ["RestApiId", "Name", "Type"] {
        required_property(props, key, logical)?;
    }
    Ok(mapped_properties(props, FIELDS))
}

impl Provisioner {
    pub(super) async fn apigateway_authorizer(
        &self,
        logical: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let payload = body(logical, props)?;
        let api = required_property(props, "RestApiId", logical)?;
        let response = self
            .call_json(
                "apigateway",
                Method::POST,
                &format!("/restapis/{}/authorizers", enc(&api)),
                payload,
                logical,
            )
            .await?;
        let id = required_response_string(&response, "id", logical)?;
        Ok(ResolvedResource {
            ref_value: id.clone(),
            attributes: [("AuthorizerId".into(), id)].into(),
        })
    }

    pub(super) async fn update_apigateway_authorizer(
        &self,
        logical: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        body(logical, previous)?;
        let desired = body(logical, props)?;
        if previous.get("RestApiId") != props.get("RestApiId") {
            return Err(CfnError::ResourceFailed(format!(
                "Authorizer RestApiId replacement is not implemented for {logical}"
            )));
        }
        let api = required_property(props, "RestApiId", logical)?;
        let path = format!(
            "/restapis/{}/authorizers/{}",
            enc(&api),
            enc(&current.ref_value)
        );
        let observed = self
            .call_json("apigateway", Method::GET, &path, json!({}), logical)
            .await?;
        let mut patches = Vec::new();
        for (property, field) in FIELDS {
            if previous.get(*property) == props.get(*property) {
                continue;
            }
            match desired.get(*field) {
                Some(value) => patches.push(json!({"op": if observed.get(*field).is_some() { "replace" } else { "add" }, "path":format!("/{field}"), "value":if let Some(value)=value.as_str() {value.to_string()} else {value.to_string()}})),
                None if *property == "AuthorizerResultTtlInSeconds" => patches.push(json!({"op":"replace","path":format!("/{field}"),"value":"300"})),
                None if observed.get(*field).is_some() => patches.push(json!({"op":"remove","path":format!("/{field}")})),
                None => {}
            }
        }
        if !patches.is_empty() {
            self.call_json(
                "apigateway",
                Method::PATCH,
                &path,
                json!({"patchOperations":patches}),
                logical,
            )
            .await?;
        }
        Ok(current.clone())
    }

    pub(super) async fn delete_apigateway_authorizer(
        &self,
        id: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        let api = required_property(props, "RestApiId", id)?;
        self.delete_call(
            "apigateway",
            &format!("/restapis/{}/authorizers/{}", enc(&api), enc(id)),
            id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[tokio::test]
    async fn authorizer_lifecycle_uses_native_configuration() {
        let registry = ServiceRegistry::with_known_services();
        locallycloud_apigateway::register(&registry);
        let p = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let api = p
            .apigateway_rest_api("Api", &json!({"Name":"review"}))
            .await
            .unwrap();
        let props = json!({"RestApiId":api.ref_value,"Name":"token","Type":"TOKEN","IdentitySource":"method.request.header.Auth","AuthorizerUri":"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:000000000000:function:auth/invocations","AuthorizerResultTtlInSeconds":0});
        let resource = p.apigateway_authorizer("Auth", &props).await.unwrap();
        assert_eq!(resource.attributes["AuthorizerId"], resource.ref_value);
        let mut updated = props.clone();
        updated["Name"] = json!("request");
        updated["Type"] = json!("REQUEST");
        updated["AuthorizerResultTtlInSeconds"] = json!(60);
        p.update_apigateway_authorizer("Auth", &resource, &props, &updated)
            .await
            .unwrap();
        let path = format!(
            "/restapis/{}/authorizers/{}",
            api.ref_value, resource.ref_value
        );
        let found = p
            .call_json("apigateway", Method::GET, &path, json!({}), "Auth")
            .await
            .unwrap();
        assert_eq!(found["name"], "request");
        assert_eq!(found["type"], "REQUEST");
        assert_eq!(found["authorizerResultTtlInSeconds"], 60);
        p.delete_apigateway_authorizer(&resource.ref_value, &updated)
            .await
            .unwrap();
        p.delete_apigateway_authorizer(&resource.ref_value, &updated)
            .await
            .unwrap();
        assert!(p
            .call_json("apigateway", Method::GET, &path, json!({}), "Auth")
            .await
            .is_err());
    }
}
