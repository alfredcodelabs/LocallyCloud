//! Deliberately bounded AWS::Serverless transform for the native HTTP API path.

use serde_json::{json, Map, Value};

use crate::error::CfnError;

fn unsupported(message: impl Into<String>) -> CfnError {
    CfnError::Validation(format!("AWS::Serverless transform: {}", message.into()))
}

fn only_keys(map: &Map<String, Value>, allowed: &[&str], context: &str) -> Result<(), CfnError> {
    if let Some(key) = map.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(unsupported(format!("unsupported {context} property {key}")));
    }
    Ok(())
}

fn object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>, CfnError> {
    value
        .as_object()
        .ok_or_else(|| unsupported(format!("{context} must be an object")))
}

fn code_uri(value: &Value) -> Result<Value, CfnError> {
    if let Some(uri) = value.as_str() {
        let rest = uri
            .strip_prefix("s3://")
            .ok_or_else(|| unsupported("Function CodeUri must be an S3 URL after packaging"))?;
        let (bucket, key) = rest
            .split_once('/')
            .filter(|(bucket, key)| !bucket.is_empty() && !key.is_empty())
            .ok_or_else(|| unsupported("Function CodeUri needs an S3 bucket and key"))?;
        return Ok(json!({"S3Bucket": bucket, "S3Key": key}));
    }
    let props = object(value, "Function CodeUri")?;
    only_keys(props, &["Bucket", "Key"], "CodeUri")?;
    let bucket = props
        .get("Bucket")
        .ok_or_else(|| unsupported("CodeUri Bucket is required"))?;
    let key = props
        .get("Key")
        .ok_or_else(|| unsupported("CodeUri Key is required"))?;
    Ok(json!({"S3Bucket": bucket, "S3Key": key}))
}

fn add_generated(
    generated: &mut Map<String, Value>,
    id: String,
    resource: Value,
) -> Result<(), CfnError> {
    if generated.insert(id.clone(), resource).is_some() {
        return Err(unsupported(format!(
            "generated resource {id} collides with another resource"
        )));
    }
    Ok(())
}

fn stage_id(api: &str, stage: &str) -> String {
    if stage == "$default" {
        format!("{api}ApiGatewayDefaultStage")
    } else {
        format!("{api}{stage}Stage")
    }
}

fn api_body(title: Value) -> Value {
    json!({
        "info": {"version":"1.0","title":title},
        "paths": {},
        "openapi": "3.0.1",
        "tags": [{"name":"httpapi:createdBy","x-amazon-apigateway-tag-value":"SAM"}]
    })
}

pub fn transform(raw: &mut Value) -> Result<(), CfnError> {
    let Some(transform) = raw.get("Transform") else {
        return Ok(());
    };
    if transform != "AWS::Serverless-2016-10-31" {
        return Err(unsupported("only AWS::Serverless-2016-10-31 is supported"));
    }
    if raw.get("Globals").is_some() {
        return Err(unsupported("Globals are not supported"));
    }
    let root = raw
        .as_object_mut()
        .ok_or_else(|| unsupported("template must be an object"))?;
    let resources = root
        .get_mut("Resources")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| unsupported("Resources must be an object"))?;
    let original = resources.clone();
    let mut generated = Map::new();
    let mut implicit_api = false;
    for (id, declaration) in &original {
        let kind = declaration
            .get("Type")
            .and_then(Value::as_str)
            .unwrap_or("");
        let props = declaration
            .get("Properties")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if kind.starts_with("AWS::Serverless::") {
            only_keys(
                object(declaration, id)?,
                &["Type", "Properties", "Metadata"],
                id,
            )?;
        }
        match kind {
            "AWS::Serverless::SimpleTable" => {
                let p = object(&props, id)?;
                only_keys(p, &["TableName", "PrimaryKey"], id)?;
                let key = p
                    .get("PrimaryKey")
                    .cloned()
                    .unwrap_or_else(|| json!({"Name":"id","Type":"String"}));
                only_keys(object(&key, "PrimaryKey")?, &["Name", "Type"], "PrimaryKey")?;
                let key_name = key
                    .get("Name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| unsupported("PrimaryKey.Name is required"))?;
                if key.get("Type").and_then(Value::as_str) != Some("String") {
                    return Err(unsupported("only String SimpleTable keys are supported"));
                }
                let mut table = json!({"BillingMode":"PAY_PER_REQUEST", "AttributeDefinitions":[{"AttributeName":key_name,"AttributeType":"S"}], "KeySchema":[{"AttributeName":key_name,"KeyType":"HASH"}]});
                if let Some(name) = p.get("TableName") {
                    table["TableName"] = name.clone();
                }
                let mut result = declaration.clone();
                result["Type"] = json!("AWS::DynamoDB::Table");
                result["Properties"] = table;
                resources.insert(id.clone(), result);
            }
            "AWS::Serverless::HttpApi" => {
                let p = object(&props, id)?;
                only_keys(p, &["Name", "StageName"], id)?;
                let mut api = json!({"Body": api_body(p.get("Name").cloned().unwrap_or_else(|| json!({"Ref":"AWS::StackName"})))});
                if let Some(paths) = resources
                    .get(id)
                    .and_then(|resource| resource.pointer("/Properties/Body/paths"))
                {
                    api["Body"]["paths"] = paths.clone();
                }
                let mut result = declaration.clone();
                result["Type"] = json!("AWS::ApiGatewayV2::Api");
                result["Properties"] = api;
                resources.insert(id.clone(), result);
                let stage = p
                    .get("StageName")
                    .map(Value::as_str)
                    .unwrap_or(Some("$default"))
                    .ok_or_else(|| unsupported("HttpApi StageName must be a string"))?;
                add_generated(
                    &mut generated,
                    stage_id(id, stage),
                    json!({"Type":"AWS::ApiGatewayV2::Stage","Properties":{"ApiId":{"Ref":id},"StageName":stage,"AutoDeploy":true}}),
                )?;
            }
            "AWS::Serverless::Function" => {
                let p = object(&props, id)?;
                only_keys(
                    p,
                    &[
                        "CodeUri",
                        "Handler",
                        "Runtime",
                        "Role",
                        "Environment",
                        "VpcConfig",
                        "Timeout",
                        "MemorySize",
                        "Description",
                        "FunctionName",
                        "Events",
                    ],
                    id,
                )?;
                let mut function = Map::new();
                for key in [
                    "Handler",
                    "Runtime",
                    "Role",
                    "Environment",
                    "VpcConfig",
                    "Timeout",
                    "MemorySize",
                    "Description",
                    "FunctionName",
                ] {
                    if let Some(value) = p.get(key) {
                        function.insert(key.into(), value.clone());
                    }
                }
                if !function.contains_key("Role") {
                    let role_id = format!("{id}Role");
                    function.insert("Role".into(), json!({"Fn::GetAtt":[role_id,"Arn"]}));
                    add_generated(
                        &mut generated,
                        role_id,
                        json!({"Type":"AWS::IAM::Role","Properties":{
                            "AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[{
                                "Effect":"Allow","Action":["sts:AssumeRole"],
                                "Principal":{"Service":["lambda.amazonaws.com"]}}]},
                            "ManagedPolicyArns":["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]}}),
                    )?;
                }
                let uri = p
                    .get("CodeUri")
                    .ok_or_else(|| unsupported(format!("{id} requires CodeUri")))?;
                function.insert("Code".into(), code_uri(uri)?);
                let mut result = declaration.clone();
                result["Type"] = json!("AWS::Lambda::Function");
                result["Properties"] = Value::Object(function);
                resources.insert(id.clone(), result);
                if let Some(events) = p.get("Events") {
                    for (event_id, event) in object(events, "Events")? {
                        only_keys(object(event, event_id)?, &["Type", "Properties"], event_id)?;
                        if event.get("Type").and_then(Value::as_str) != Some("HttpApi") {
                            return Err(unsupported(format!(
                                "{id}.{event_id} only HttpApi events are supported"
                            )));
                        }
                        let empty = json!({});
                        let ep = object(
                            event.get("Properties").unwrap_or(&empty),
                            "HttpApi event Properties",
                        )?;
                        only_keys(ep, &["ApiId", "Path", "Method"], "HttpApi event")?;
                        let api = if let Some(api_ref) = ep.get("ApiId") {
                            let reference = object(api_ref, "HttpApi event ApiId")?;
                            only_keys(reference, &["Ref"], "HttpApi event ApiId")?;
                            let api = reference
                                .get("Ref")
                                .and_then(Value::as_str)
                                .ok_or_else(|| unsupported("HttpApi event ApiId must be a Ref"))?;
                            if original
                                .get(api)
                                .and_then(|v| v.get("Type"))
                                .and_then(Value::as_str)
                                != Some("AWS::Serverless::HttpApi")
                            {
                                return Err(unsupported(
                                    "HttpApi event ApiId must reference a Serverless HttpApi",
                                ));
                            }
                            api
                        } else {
                            implicit_api = true;
                            "ServerlessHttpApi"
                        };
                        let (path, method) = match (ep.get("Path"), ep.get("Method")) {
                            (None, None) => ("$default", "ANY".to_string()),
                            (Some(path), Some(method)) => (
                                path.as_str()
                                    .filter(|path| path.starts_with('/'))
                                    .ok_or_else(|| {
                                        unsupported("HttpApi event Path must start with /")
                                    })?,
                                method
                                    .as_str()
                                    .filter(|method| !method.is_empty())
                                    .ok_or_else(|| unsupported("HttpApi event Method is required"))?
                                    .to_ascii_uppercase(),
                            ),
                            _ => {
                                return Err(unsupported(
                                    "HttpApi event requires both Path and Method",
                                ))
                            }
                        };
                        let api_resource =
                            if api == "ServerlessHttpApi" {
                                generated.entry(api).or_insert_with(|| json!({
                                "Type":"AWS::ApiGatewayV2::Api",
                                "Properties":{"Body":api_body(json!({"Ref":"AWS::StackName"}))}
                            }))
                            } else {
                                let api_resource = resources
                                    .get_mut(api)
                                    .ok_or_else(|| unsupported(format!("missing API {api}")))?;
                                if api_resource.pointer("/Properties/Body").is_none() {
                                    let title = original[api]["Properties"]
                                        .get("Name")
                                        .cloned()
                                        .unwrap_or_else(|| json!({"Ref":"AWS::StackName"}));
                                    api_resource["Properties"]["Body"] = api_body(title);
                                }
                                api_resource
                            };
                        let paths = api_resource["Properties"]["Body"]["paths"]
                            .as_object_mut()
                            .ok_or_else(|| unsupported("invalid generated OpenAPI paths"))?;
                        let mut operation = json!({
                            "x-amazon-apigateway-integration":{
                                "httpMethod":"POST",
                                "type":"aws_proxy",
                                "uri":{"Fn::Sub":format!("arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}:lambda:path/2015-03-31/functions/${{{id}.Arn}}/invocations")},
                                "payloadFormatVersion":"2.0"
                            },
                            "responses":{}
                        });
                        if path == "$default" {
                            operation["isDefaultRoute"] = json!(true);
                        }
                        let methods = paths
                            .entry(path)
                            .or_insert_with(|| json!({}))
                            .as_object_mut()
                            .ok_or_else(|| unsupported("invalid generated OpenAPI path"))?;
                        let method_key = if method == "ANY" {
                            "x-amazon-apigateway-any-method".to_string()
                        } else {
                            method.to_ascii_lowercase()
                        };
                        if methods.insert(method_key, operation).is_some() {
                            return Err(unsupported("duplicate HttpApi route"));
                        }
                        add_generated(
                            &mut generated,
                            format!("{id}{event_id}Permission"),
                            json!({"Type":"AWS::Lambda::Permission","Properties":{"Action":"lambda:InvokeFunction","FunctionName":{"Ref":id},"Principal":"apigateway.amazonaws.com",
                            "SourceArn":{"Fn::Sub":[format!("arn:${{AWS::Partition}}:execute-api:${{AWS::Region}}:${{AWS::AccountId}}:${{__ApiId__}}/${{__Stage__}}/{}{}", if method == "ANY" {"*"} else {&method}, if path == "$default" {""} else {path}),
                                {"__ApiId__":{"Ref":api},"__Stage__":"*"}]}}}),
                        )?;
                    }
                }
            }
            kind if kind.starts_with("AWS::Serverless::") => {
                return Err(unsupported(format!("unsupported resource type {kind}")))
            }
            _ => {}
        }
    }
    if implicit_api {
        add_generated(
            &mut generated,
            "ServerlessHttpApiApiGatewayDefaultStage".into(),
            json!({"Type":"AWS::ApiGatewayV2::Stage","Properties":{"ApiId":{"Ref":"ServerlessHttpApi"},"StageName":"$default","AutoDeploy":true}}),
        )?;
    }
    for (id, resource) in generated {
        if resources.insert(id.clone(), resource).is_some() {
            return Err(unsupported(format!(
                "generated resource {id} collides with an existing resource"
            )));
        }
    }
    root.remove("Transform");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_api_after_function_keeps_generated_route() {
        let mut template = json!({
            "Transform":"AWS::Serverless-2016-10-31",
            "Resources":{
                "Fn":{"Type":"AWS::Serverless::Function","Properties":{
                    "CodeUri":"s3://artifacts/fn.zip","Runtime":"nodejs22.x","Handler":"index.handler",
                    "Events":{"Get":{"Type":"HttpApi","Properties":{
                        "ApiId":{"Ref":"ZApi"},"Path":"/items","Method":"GET"
                    }}}
                }},
                "ZApi":{"Type":"AWS::Serverless::HttpApi"}
            }
        });
        transform(&mut template).unwrap();
        assert_eq!(
            template["Resources"]["ZApi"]["Properties"]["Body"]["paths"]["/items"]["get"]
                ["x-amazon-apigateway-integration"]["type"],
            "aws_proxy"
        );
        assert!(template["Resources"].get("FnGetRoute").is_none());
    }
}
