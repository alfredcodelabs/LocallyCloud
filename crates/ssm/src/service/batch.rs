//! Batched reads reuse the single-parameter representation and KMS boundary.
use super::*;
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(super) struct Request {
    names: Vec<String>,
    with_decryption: Option<bool>,
}

impl SsmHandler {
    pub(super) async fn get_parameters(
        &self,
        input: Request,
        scope: &Scope,
        request: &ServiceRequest,
    ) -> Result<Value, SsmError> {
        if !(1..=10).contains(&input.names.len()) {
            return Err(SsmError::Validation);
        }
        // Validate all request shapes before reading or invoking KMS.
        for name in &input.names {
            validate_query_name(name)?;
        }
        let mut parameters = Vec::new();
        let mut invalid = Vec::new();
        let mut seen = BTreeSet::new();
        for name in input.names {
            if !seen.insert(name.trim().to_owned()) {
                continue;
            }
            let result = self
                .get_parameter(
                    GetParameterRequest {
                        name: name.clone(),
                        with_decryption: input.with_decryption,
                    },
                    scope,
                    request,
                )
                .await;
            match result {
                Ok(value) => parameters.push(value["Parameter"].clone()),
                Err(SsmError::ParameterNotFound | SsmError::ParameterVersionNotFound) => {
                    invalid.push(name)
                }
                Err(error) => return Err(error),
            }
        }
        parameters.sort_by(|a, b| {
            a["Name"]
                .as_str()
                .cmp(&b["Name"].as_str())
                .then(a["Selector"].as_str().cmp(&b["Selector"].as_str()))
        });
        invalid.sort();
        Ok(json!({"Parameters":parameters,"InvalidParameters":invalid}))
    }
}
fn validate_query_name(name: &str) -> Result<(), SsmError> {
    if name.is_empty()
        || name.len() > 2048
        || name.trim().is_empty()
        || name.trim().chars().any(char::is_whitespace)
    {
        return Err(SsmError::Validation);
    }
    Ok(())
}
// The current store retains its current version only. Unknown versions/labels remain missing.
pub(super) fn query_name(name: &str, scope: &Scope) -> Result<(String, Option<String>), SsmError> {
    validate_query_name(name)?;
    let name = name.trim();
    let name = if name.starts_with("arn:") {
        let prefix = format!(
            "arn:aws:ssm:{}:{}:parameter/",
            scope.region, scope.account_id
        );
        let raw = name
            .strip_prefix(&prefix)
            .ok_or(SsmError::ParameterNotFound)?;
        format!("/{raw}")
    } else {
        name.to_owned()
    };
    let (base, selector) = name
        .rsplit_once(':')
        .map_or((name.as_str(), None), |(base, selector)| {
            (base, Some(format!(":{selector}")))
        });
    validate_name(base)?;
    if selector.as_deref().is_some_and(|s| {
        s.len() <= 1
            || !s[1..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
    }) {
        return Err(SsmError::Validation);
    }
    Ok((base.to_owned(), selector))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn batch_sorts_selectors_missing_and_isolates_region() {
        let handler = SsmHandler::new(Weak::new());
        let scope = Scope::new("000000000000", "us-east-1");
        for name in ["/z", "/a", "plain", "/tree/leaf"] {
            handler
                .store
                .put(
                    &scope,
                    name.into(),
                    ParameterValue::Plain(SecretString::new(name.into())),
                    None,
                    false,
                    None,
                    1.0,
                )
                .unwrap();
        }
        let mut request = ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: Default::default(),
            body: Default::default(),
            region: scope.region.clone(),
            account_id: scope.account_id.clone(),
            request_id: "batch".into(),
        };
        let value = handler
            .get_parameters(
                Request {
                    names: vec![
                        " /z ".into(),
                        "/a:1".into(),
                        "/a:old".into(),
                        "/missing".into(),
                        "/z".into(),
                    ],
                    with_decryption: Some(false),
                },
                &scope,
                &request,
            )
            .await
            .unwrap();
        assert_eq!(value["Parameters"][0]["Name"], "/a");
        assert_eq!(value["Parameters"][0]["Selector"], ":1");
        assert_eq!(value["InvalidParameters"], json!(["/a:old", "/missing"]));
        let arn = scope.parameter_arn("/z");
        assert_eq!(
            handler
                .get_parameters(
                    Request {
                        names: vec![arn.clone()],
                        with_decryption: None
                    },
                    &scope,
                    &request
                )
                .await
                .unwrap()["Parameters"][0]["Value"],
            "/z"
        );
        let aliases = handler
            .get_parameters(
                Request {
                    names: vec![
                        format!("{}:1", scope.parameter_arn("plain")),
                        format!("{}:1", scope.parameter_arn("/tree/leaf")),
                    ],
                    with_decryption: None,
                },
                &scope,
                &request,
            )
            .await
            .unwrap();
        assert_eq!(aliases["InvalidParameters"], json!([]));
        assert_eq!(aliases["Parameters"][0]["Name"], "/tree/leaf");
        assert_eq!(aliases["Parameters"][0]["Value"], "/tree/leaf");
        assert_eq!(aliases["Parameters"][1]["Name"], "plain");
        assert_eq!(aliases["Parameters"][1]["Value"], "plain");
        assert_eq!(aliases["Parameters"][1]["Selector"], ":1");
        request.region = "us-west-2".into();
        let foreign = Scope::new(&scope.account_id, &request.region);
        let value = handler
            .get_parameters(
                Request {
                    names: vec![arn],
                    with_decryption: None,
                },
                &foreign,
                &request,
            )
            .await
            .unwrap();
        assert!(value["Parameters"].as_array().unwrap().is_empty());
        assert!(matches!(
            handler
                .get_parameters(
                    Request {
                        names: vec![],
                        with_decryption: None
                    },
                    &scope,
                    &request
                )
                .await,
            Err(SsmError::Validation)
        ));
        assert!(matches!(
            handler
                .get_parameters(
                    Request {
                        names: vec!["bad name".into()],
                        with_decryption: None
                    },
                    &scope,
                    &request
                )
                .await,
            Err(SsmError::Validation)
        ));
    }
}
