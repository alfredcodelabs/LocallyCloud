//! Deliberately bounded AWS::Serverless transform for the native HTTP API path.

use serde_json::{json, Map, Value};

use crate::error::CfnError;

fn http_api_domain(
    generated: &mut Map<String, Value>,
    api: &str,
    stage: &str,
    domain: &Value,
) -> Result<(), CfnError> {
    let domain = object(domain, "HttpApi.Domain")?;
    only_keys(
        domain,
        &[
            "DomainName",
            "CertificateArn",
            "EndpointConfiguration",
            "SecurityPolicy",
            "BasePath",
            "Route53",
        ],
        "HttpApi.Domain",
    )?;
    let name = domain
        .get("DomainName")
        .ok_or_else(|| unsupported("HttpApi.Domain requires DomainName"))?;
    let certificate = domain
        .get("CertificateArn")
        .ok_or_else(|| unsupported("HttpApi.Domain requires CertificateArn"))?;
    if domain
        .get("EndpointConfiguration")
        .is_some_and(|v| v != "REGIONAL")
        || domain.get("SecurityPolicy").is_some_and(|v| v != "TLS_1_2")
    {
        return Err(unsupported("HttpApi.Domain supports REGIONAL and TLS_1_2"));
    }
    let domain_id = format!("{api}DomainName");
    add_generated(
        generated,
        domain_id.clone(),
        json!({"Type":"AWS::ApiGatewayV2::DomainName","Properties":{"DomainName":name,"DomainNameConfigurations":[{"CertificateArn":certificate,"EndpointType":"REGIONAL","SecurityPolicy":"TLS_1_2"}]}}),
    )?;
    let paths = domain
        .get("BasePath")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| unsupported("HttpApi.Domain.BasePath must be a list"))
        })
        .transpose()?
        .cloned()
        .unwrap_or_else(|| vec![json!("/")]);
    if paths.is_empty() {
        return Err(unsupported("HttpApi.Domain.BasePath must not be empty"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (index, path) in paths.iter().enumerate() {
        let path = path
            .as_str()
            .ok_or_else(|| unsupported("HttpApi.Domain.BasePath entries must be strings"))?
            .trim_matches('/');
        if !seen.insert(path) {
            return Err(unsupported(
                "HttpApi.Domain.BasePath has duplicate mappings",
            ));
        }
        let mut properties =
            json!({"DomainName":{"Ref":domain_id},"ApiId":{"Ref":api},"Stage":stage});
        if !path.is_empty() {
            properties["ApiMappingKey"] = json!(path);
        }
        add_generated(
            generated,
            format!("{api}ApiMapping{index}"),
            json!({"Type":"AWS::ApiGatewayV2::ApiMapping","DependsOn":stage_id(api,stage),"Properties":properties}),
        )?;
    }
    if let Some(route53) = domain.get("Route53") {
        let route53 = object(route53, "HttpApi.Domain.Route53")?;
        only_keys(
            route53,
            &["HostedZoneId", "EvaluateTargetHealth"],
            "HttpApi.Domain.Route53",
        )?;
        let zone = route53
            .get("HostedZoneId")
            .ok_or_else(|| unsupported("HttpApi.Domain.Route53 requires HostedZoneId"))?;
        let health = route53
            .get("EvaluateTargetHealth")
            .cloned()
            .unwrap_or(json!(false));
        if !health.is_boolean() {
            return Err(unsupported(
                "HttpApi.Domain.Route53.EvaluateTargetHealth must be boolean",
            ));
        }
        add_generated(
            generated,
            format!("{api}Route53Record"),
            json!({"Type":"AWS::Route53::RecordSet","Properties":{"HostedZoneId":zone,"Name":name,"Type":"A","AliasTarget":{"DNSName":{"Fn::GetAtt":[domain_id,"RegionalDomainName"]},"HostedZoneId":{"Fn::GetAtt":[domain_id,"RegionalHostedZoneId"]},"EvaluateTargetHealth":health}}}),
        )?;
    }
    Ok(())
}

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

// Intrinsics are expressions, not ordinary maps to merge recursively.
fn intrinsic(value: &Value) -> bool {
    value.as_object().is_some_and(|map| {
        map.len() == 1
            && map
                .keys()
                .any(|key| key == "Ref" || key.starts_with("Fn::"))
    })
}

fn merge_globals(global: &Value, local: &Value) -> Value {
    if intrinsic(global) || intrinsic(local) {
        return local.clone();
    }
    match (global, local) {
        (Value::Object(global), Value::Object(local)) => {
            let mut merged = global.clone();
            for (key, value) in local {
                let value = merged
                    .get(key)
                    .map(|default| merge_globals(default, value))
                    .unwrap_or_else(|| value.clone());
                merged.insert(key.clone(), value);
            }
            Value::Object(merged)
        }
        (Value::Array(global), Value::Array(local)) => {
            Value::Array(global.iter().chain(local).cloned().collect())
        }
        _ => local.clone(),
    }
}

fn validate_function_globals(props: &Map<String, Value>) -> Result<(), CfnError> {
    only_keys(
        props,
        &[
            "CodeUri",
            "Handler",
            "Runtime",
            "Environment",
            "VpcConfig",
            "Timeout",
            "MemorySize",
            "Description",
        ],
        "Globals.Function",
    )?;
    validate_global_values(props)
}

fn validate_global_values(props: &Map<String, Value>) -> Result<(), CfnError> {
    for (key, value) in props {
        if intrinsic(value) {
            continue;
        }
        let valid = match key.as_str() {
            "CodeUri" => value.is_string() || value.is_object(),
            "Timeout" | "MemorySize" => value.is_number() || value.is_string(),
            "Environment" | "VpcConfig" => value.is_object(),
            _ => value.is_string(),
        };
        if !valid {
            return Err(unsupported(format!("invalid Globals.Function.{key}")));
        }
        if key == "Environment" {
            let environment = object(value, "Environment")?;
            only_keys(environment, &["Variables"], "Environment")?;
            if let Some(variables) = environment
                .get("Variables")
                .filter(|value| !intrinsic(value))
            {
                object(variables, "Environment.Variables")?;
            }
        }
        if key == "VpcConfig" {
            let vpc = object(value, "VpcConfig")?;
            only_keys(
                vpc,
                &["SubnetIds", "SecurityGroupIds", "Ipv6AllowedForDualStack"],
                "VpcConfig",
            )?;
            for (field, value) in vpc {
                if !intrinsic(value)
                    && !(if field == "Ipv6AllowedForDualStack" {
                        value.is_boolean()
                    } else {
                        value.is_array()
                    })
                {
                    return Err(unsupported(format!("invalid VpcConfig.{field}")));
                }
            }
        }
    }
    Ok(())
}

fn apply_globals(raw: &mut Value) -> Result<(), CfnError> {
    let Some(globals) = raw.get("Globals").cloned() else {
        return Ok(());
    };
    let globals = object(&globals, "Globals")?;
    only_keys(globals, &["Function", "HttpApi"], "Globals")?;
    for (kind, props) in globals {
        let props = object(props, &format!("Globals.{kind}"))?;
        if kind == "Function" {
            validate_function_globals(props)?;
        } else {
            // No AWS HttpApi Globals property is implemented by the current adapter.
            only_keys(props, &[], "Globals.HttpApi")?;
        }
    }
    let resources = raw
        .get_mut("Resources")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| unsupported("Resources must be an object"))?;
    for declaration in resources.values_mut() {
        let kind = declaration
            .get("Type")
            .and_then(Value::as_str)
            .and_then(|kind| kind.strip_prefix("AWS::Serverless::"));
        let Some(defaults) = kind.and_then(|kind| globals.get(kind)) else {
            continue;
        };
        let props = declaration
            .get("Properties")
            .cloned()
            .unwrap_or_else(|| json!({}));
        object(&props, "SAM resource Properties")?;
        let merged = merge_globals(defaults, &props);
        if kind == Some("Function") {
            let effective = object(&merged, "Function Properties")?
                .iter()
                .filter(|(key, _)| defaults.get(key.as_str()).is_some())
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            validate_global_values(&effective)?;
        }
        declaration["Properties"] = merged;
    }
    raw.as_object_mut()
        .expect("Resources requires object template")
        .remove("Globals");
    Ok(())
}

pub fn transform(raw: &mut Value) -> Result<(), CfnError> {
    if raw.get("Transform").is_none() {
        return Ok(());
    }
    // Commit only a fully validated transform, including generated resource collisions.
    let mut processed = raw.clone();
    transform_inner(&mut processed)?;
    *raw = processed;
    Ok(())
}

fn transform_inner(raw: &mut Value) -> Result<(), CfnError> {
    let Some(transform) = raw.get("Transform") else {
        return Ok(());
    };
    if transform != "AWS::Serverless-2016-10-31" {
        return Err(unsupported("only AWS::Serverless-2016-10-31 is supported"));
    }
    apply_globals(raw)?;
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
                only_keys(p, &["Name", "StageName", "Domain"], id)?;
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
                if let Some(domain) = p.get("Domain") {
                    http_api_domain(&mut generated, id, stage, domain)?;
                }
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
                        "ReservedConcurrentExecutions",
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
                    "ReservedConcurrentExecutions",
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
    fn http_domain_generates_regional_mapping_and_alias_with_dependency() {
        let original = json!({"Transform":"AWS::Serverless-2016-10-31","Resources":{"Api":{"Type":"AWS::Serverless::HttpApi","Properties":{"Domain":{"DomainName":"api.example.test","CertificateArn":{"Ref":"Certificate"},"Route53":{"HostedZoneId":{"Ref":"Zone"}},"BasePath":["/","orders"]}}}}});
        let mut template = original.clone();
        transform(&mut template).unwrap();
        let resources = &template["Resources"];
        assert_eq!(
            resources["ApiDomainName"]["Properties"]["DomainNameConfigurations"][0]
                ["CertificateArn"],
            json!({"Ref":"Certificate"})
        );
        assert_eq!(
            resources["ApiApiMapping0"]["DependsOn"],
            stage_id("Api", "$default")
        );
        assert!(resources["ApiApiMapping0"]["Properties"]
            .get("ApiMappingKey")
            .is_none());
        assert_eq!(
            resources["ApiApiMapping1"]["Properties"]["ApiMappingKey"],
            "orders"
        );
        assert_eq!(
            resources["ApiRoute53Record"]["Properties"]["AliasTarget"]["DNSName"],
            json!({"Fn::GetAtt":["ApiDomainName","RegionalDomainName"]})
        );
        let mut invalid = original;
        invalid["Resources"]["Api"]["Properties"]["Domain"]["EndpointConfiguration"] =
            json!("EDGE");
        let unchanged = invalid.clone();
        assert!(transform(&mut invalid).is_err());
        assert_eq!(invalid, unchanged);
    }

    #[test]
    fn function_preserves_reserved_concurrency() {
        let mut template = json!({"Transform":"AWS::Serverless-2016-10-31", "Resources":{
        "Worker":{"Type":"AWS::Serverless::Function", "Properties":{
            "CodeUri":"s3://artifacts/worker.zip", "Handler":"ledger.post", "Runtime":"python3.12",
            "Role":"arn:aws:iam::000000000000:role/worker", "ReservedConcurrentExecutions":4
        }}}});
        transform(&mut template).unwrap();
        assert_eq!(
            template["Resources"]["Worker"]["Type"],
            "AWS::Lambda::Function"
        );
        assert_eq!(
            template["Resources"]["Worker"]["Properties"]["ReservedConcurrentExecutions"],
            4
        );
    }

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

#[cfg(test)]
mod globals_tests {
    use super::*;

    fn template(globals: Value, properties: Value) -> Value {
        json!({"Transform":"AWS::Serverless-2016-10-31", "Globals":globals,
            "Resources":{"Worker":{"Type":"AWS::Serverless::Function", "Properties":properties}}})
    }

    #[test]
    fn globals_merge_effective_function_and_preserve_intrinsics() {
        let mut raw = template(
            json!({"Function":{
                "CodeUri":"s3://artifacts/worker.zip", "Handler":"index.handler", "Runtime":"nodejs22.x",
                "Timeout":30, "MemorySize":256,
                "Environment":{"Variables":{"GLOBAL":"yes", "SHARED":"global"}},
                "VpcConfig":{"SubnetIds":[{"Ref":"SharedSubnet"}], "SecurityGroupIds":["sg-global"]}
            }}),
            json!({"Runtime":"python3.13", "Timeout":60,
                "Environment":{"Variables":{"SHARED":"local", "TABLE":{"Ref":"Orders"}}},
                "VpcConfig":{"SubnetIds":[{"Ref":"LocalSubnet"}], "SecurityGroupIds":["sg-local"]}
            }),
        );
        transform(&mut raw).unwrap();
        let props = &raw["Resources"]["Worker"]["Properties"];
        assert_eq!(props["Runtime"], "python3.13");
        assert_eq!(props["Timeout"], 60);
        assert_eq!(props["MemorySize"], 256);
        assert_eq!(props["Handler"], "index.handler");
        assert_eq!(
            props["Code"],
            json!({"S3Bucket":"artifacts", "S3Key":"worker.zip"})
        );
        assert_eq!(
            props["Environment"]["Variables"],
            json!({"GLOBAL":"yes", "SHARED":"local", "TABLE":{"Ref":"Orders"}})
        );
        assert_eq!(
            props["VpcConfig"]["SubnetIds"],
            json!([{"Ref":"SharedSubnet"}, {"Ref":"LocalSubnet"}])
        );
        assert_eq!(
            props["VpcConfig"]["SecurityGroupIds"],
            json!(["sg-global", "sg-local"])
        );
        assert!(raw.get("Globals").is_none());
        assert!(raw.get("Transform").is_none());

        // Expressions replace whole values, without combining Ref/Fn::If internals.
        let choice = json!({"Fn::If":["East", {"Variables":{"REGION":"east"}}, {"Variables":{"REGION":"west"}}]});
        let mut raw = template(
            json!({"Function":{"Environment":{"Variables":{"OLD":"value"}}}}),
            json!({"CodeUri":"s3://artifacts/worker.zip", "Environment":choice}),
        );
        transform(&mut raw).unwrap();
        assert_eq!(
            raw["Resources"]["Worker"]["Properties"]["Environment"],
            choice
        );

        let mut raw = template(
            json!({"Function":{"Environment":{"Variables":{"VAR":{"Ref":"GlobalValue"}}}}}),
            json!({"CodeUri":"s3://artifacts/worker.zip", "Environment":{"Variables":{"VAR":{"Fn::Sub":"${LocalValue}"}}}}),
        );
        transform(&mut raw).unwrap();
        assert_eq!(
            raw["Resources"]["Worker"]["Properties"]["Environment"]["Variables"]["VAR"],
            json!({"Fn::Sub":"${LocalValue}"})
        );
    }

    #[test]
    fn invalid_globals_and_late_transform_errors_leave_input_unchanged() {
        for globals in [
            json!(null),
            json!([]),
            json!({"Unknown":{}}),
            json!({"Function":false}),
            json!({"Function":{"Role":"arn:role"}}),
            json!({"Function":{"Events":{}}}),
            json!({"Function":{"Tags":{}}}),
            json!({"HttpApi":{"Name":"invalid-aws-global"}}),
            json!({"HttpApi":{"StageName":"dev"}}),
            json!({"Function":{"Environment":null}}),
            json!({"Function":{"Environment":{"Variables":[]}}}),
            json!({"Function":{"VpcConfig":{"SecurityGroupIds":"sg-invalid"}}}),
        ] {
            let mut raw = template(globals, json!({"CodeUri":"s3://artifacts/worker.zip"}));
            let before = raw.clone();
            assert!(
                transform(&mut raw).is_err(),
                "accepted {}",
                before["Globals"]
            );
            assert_eq!(raw, before);
        }
        let mut raw = template(
            json!({"Function":{"Environment":{"Variables":{"GLOBAL":"yes"}}}}),
            json!({"CodeUri":"s3://artifacts/worker.zip", "Environment":null}),
        );
        let before = raw.clone();
        assert!(transform(&mut raw).is_err());
        assert_eq!(raw, before);

        // Earlier resources must not remain transformed when a later one fails.
        let mut raw = template(
            json!({"Function":{"Runtime":"nodejs22.x"}}),
            json!({"CodeUri":"s3://artifacts/worker.zip"}),
        );
        raw["Resources"]["ZBroken"] =
            json!({"Type":"AWS::Serverless::Function", "Properties":{"CodeUri":"unpackaged/path"}});
        let before = raw.clone();
        assert!(transform(&mut raw).is_err());
        assert_eq!(raw, before);
    }

    #[test]
    fn globals_do_not_change_implicit_api_or_native_resources() {
        let mut raw = template(
            json!({"Function":{"Runtime":"nodejs22.x", "Timeout":20}, "HttpApi":{}}),
            json!({"CodeUri":"s3://artifacts/worker.zip", "Events":{"Get":{"Type":"HttpApi", "Properties":{"Path":"/orders", "Method":"GET"}}}}),
        );
        let queue = json!({"Type":"AWS::SQS::Queue", "Properties":{"QueueName":"orders"}});
        raw["Resources"]["OrdersQueue"] = queue.clone();
        transform(&mut raw).unwrap();
        assert_eq!(raw["Resources"]["OrdersQueue"], queue);
        assert_eq!(
            raw["Resources"]["ServerlessHttpApi"]["Type"],
            "AWS::ApiGatewayV2::Api"
        );
        assert!(
            raw["Resources"]["ServerlessHttpApi"]["Properties"]["Body"]["paths"]["/orders"]
                .get("get")
                .is_some()
        );
    }
}
