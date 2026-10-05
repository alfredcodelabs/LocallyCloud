use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Request {
    path: String,
    #[serde(default)]
    recursive: bool,
    #[serde(default)]
    with_decryption: bool,
    max_results: Option<usize>,
    next_token: Option<String>,
    #[serde(default)]
    parameter_filters: Vec<Filter>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation: &str, value: Value) -> ServiceRequest {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", protocol::CONTENT_TYPE.parse().unwrap());
        headers.insert(
            "x-amz-target",
            format!("AmazonSSM.{operation}").parse().unwrap(),
        );
        ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers,
            body: value.to_string().into(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "path-test".into(),
        }
    }

    #[tokio::test]
    async fn hierarchy_pages_keep_scope_filters_and_reject_token_reuse() {
        let handler = SsmHandler::new(Weak::new());
        for name in ["/app", "/app/a", "/app/b", "/app/nested/c", "/app-other/z"] {
            handler
                .process(&request(
                    "PutParameter",
                    json!({"Name":name,"Value":name,"Type":"String"}),
                ))
                .await
                .unwrap();
        }
        let first = handler
            .process(&request(
                "GetParametersByPath",
                json!({"Path":"/app/","MaxResults":1}),
            ))
            .await
            .unwrap();
        assert_eq!(first["Parameters"][0]["Name"], "/app/a");
        let token = first["NextToken"].as_str().unwrap();
        let second = handler
            .process(&request(
                "GetParametersByPath",
                json!({"Path":"/app","MaxResults":1,"NextToken":token}),
            ))
            .await
            .unwrap();
        assert_eq!(second["Parameters"][0]["Name"], "/app/b");
        assert!(second.get("NextToken").is_none());
        let recursive = handler.process(&request("GetParametersByPath", json!({"Path":"/app","Recursive":true,"ParameterFilters":[{"Key":"Type","Values":["String"]}]}))).await.unwrap();
        assert_eq!(recursive["Parameters"].as_array().unwrap().len(), 3);
        assert!(matches!(
            handler
                .process(&request(
                    "GetParametersByPath",
                    json!({"Path":"/app","Recursive":true,"NextToken":token})
                ))
                .await,
            Err(SsmError::InvalidNextToken)
        ));
        let mut foreign = request(
            "GetParametersByPath",
            json!({"Path":"/app","NextToken":token}),
        );
        foreign.region = "us-west-2".into();
        assert!(matches!(
            handler.process(&foreign).await,
            Err(SsmError::InvalidNextToken)
        ));
        assert!(matches!(
            handler
                .process(&request(
                    "GetParametersByPath",
                    json!({"Path":"/app","NextToken":"invalid"})
                ))
                .await,
            Err(SsmError::InvalidNextToken)
        ));
        assert!(matches!(
            handler
                .process(&request(
                    "GetParametersByPath",
                    json!({"Path":"/app","ParameterFilters":[{"Key":"Name","Values":["x"]}]})
                ))
                .await,
            Err(SsmError::InvalidFilterKey)
        ));
        assert!(matches!(
            handler
                .process(&request(
                    "GetParametersByPath",
                    json!({"Path":"/app","MaxResults":11})
                ))
                .await,
            Err(SsmError::Validation)
        ));
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Filter {
    key: String,
    option: Option<String>,
    values: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct Cursor {
    query: String,
    last: String,
    expires: f64,
}

pub(super) fn token_cipher() -> locallycloud_state::StateCipher {
    let mut key = [0; 32];
    key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    locallycloud_state::StateCipher::with_key(&key)
}

impl SsmHandler {
    pub(super) async fn get_parameters_by_path(
        &self,
        request: &ServiceRequest,
        scope: &Scope,
    ) -> Result<Value, SsmError> {
        let mut input: Request = decode(&request.body)?;
        if input.path.trim().is_empty() {
            return Err(SsmError::Validation);
        }
        input.path = input.path.trim().trim_end_matches('/').to_owned();
        if input.path.is_empty() {
            input.path = "/".to_owned();
        }
        if !input.path.starts_with('/')
            || input.path.len() > 2048
            || (input.path != "/" && validate_name(&input.path).is_err())
            || input.path.split('/').filter(|s| !s.is_empty()).count() > 14
        {
            return Err(SsmError::Validation);
        }
        let limit = input.max_results.unwrap_or(10);
        if !(1..=10).contains(&limit) {
            return Err(SsmError::Validation);
        }
        for filter in &input.parameter_filters {
            if !matches!(filter.key.as_str(), "Type" | "KeyId" | "Label") {
                return Err(SsmError::InvalidFilterKey);
            }
            let option = filter.option.as_deref().unwrap_or("Equals");
            if !matches!(option, "Equals" | "BeginsWith")
                || (filter.key == "Label" && option != "Equals")
            {
                return Err(SsmError::InvalidFilterOption);
            }
            if filter.values.is_empty()
                || filter.values.len() > 50
                || filter.values.iter().any(|v| v.is_empty() || v.len() > 1024)
            {
                return Err(SsmError::InvalidFilterValue);
            }
        }
        let token = input.next_token.take();
        // Page size may change; identity, filters and decryption mode may not.
        input.max_results = None;
        let query = serde_json::to_string(&input).map_err(|_| SsmError::Internal)?;
        let context = ["ssm-path-token", &scope.account_id, &scope.region];
        let last = if let Some(token) = token {
            if token.len() > 16384 {
                return Err(SsmError::InvalidNextToken);
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| SsmError::InvalidNextToken)?;
            let plain = self
                .path_tokens
                .open(&context, &bytes)
                .map_err(|_| SsmError::InvalidNextToken)?;
            let cursor: Cursor =
                serde_json::from_slice(&plain).map_err(|_| SsmError::InvalidNextToken)?;
            if cursor.query != query || cursor.expires < now_epoch()? {
                return Err(SsmError::InvalidNextToken);
            }
            cursor.last
        } else {
            String::new()
        };
        let prefix = if input.path == "/" {
            "/".to_owned()
        } else {
            format!("{}/", input.path)
        };
        let names: Vec<_> = self
            .store
            .describe(scope, None)
            .into_iter()
            .filter(|p| {
                p.name > last
                    && p.name.strip_prefix(&prefix).is_some_and(|tail| {
                        !tail.is_empty() && (input.recursive || !tail.contains('/'))
                    })
                    && input.parameter_filters.iter().all(|filter| {
                        // Label versions are not modeled; no parameter has a label to match.
                        let value = match filter.key.as_str() {
                            "Type" => Some(p.parameter_type),
                            "KeyId" => p.key_id.as_deref(),
                            _ => None,
                        };
                        value.is_some_and(|value| {
                            filter.values.iter().any(|expected| {
                                if filter.option.as_deref() == Some("BeginsWith") {
                                    value.starts_with(expected)
                                } else {
                                    value == expected
                                }
                            })
                        })
                    })
            })
            .map(|p| p.name)
            .collect();
        let mut parameters = Vec::new();
        for name in names.iter().take(limit) {
            let value = self
                .get_parameter(
                    GetParameterRequest {
                        name: name.clone(),
                        with_decryption: Some(input.with_decryption),
                    },
                    scope,
                    request,
                )
                .await?;
            parameters.push(value["Parameter"].clone());
        }
        let mut output = json!({"Parameters":parameters});
        if names.len() > limit {
            let cursor = Cursor {
                query,
                last: names[limit - 1].clone(),
                expires: now_epoch()? + 3600.0,
            };
            let bytes = self
                .path_tokens
                .seal(
                    &context,
                    &serde_json::to_vec(&cursor).map_err(|_| SsmError::Internal)?,
                )
                .map_err(|_| SsmError::Internal)?;
            output["NextToken"] = URL_SAFE_NO_PAD.encode(bytes).into();
        }
        Ok(output)
    }
}
