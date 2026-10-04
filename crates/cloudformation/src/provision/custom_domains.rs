//! Native public regional custom domains and their Route53 aliases.
use super::*;

impl Provisioner {
    pub(super) async fn custom_domain_resource(
        &self,
        logical: &str,
        kind: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        if kind == "AWS::Route53::HostedZone" {
            ensure_known_properties(logical, kind, props, &["Name", "HostedZoneConfig"])?;
            let name = required_property(props, "Name", logical)?;
            let config = props.get("HostedZoneConfig").cloned().unwrap_or(json!({}));
            ensure_known_properties(logical, "HostedZoneConfig", &config, &["Comment"])?;
            let comment = config.get("Comment").and_then(Value::as_str).unwrap_or("");
            let xml = format!("<CreateHostedZoneRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><Name>{}</Name><CallerReference>{}</CallerReference><HostedZoneConfig><Comment>{}</Comment></HostedZoneConfig></CreateHostedZoneRequest>", xml_escape(&name), uuid::Uuid::new_v4(), xml_escape(comment));
            let response = self
                .call_route53(Method::POST, "/2013-04-01/hostedzone", xml, logical)
                .await?;
            let xml = std::str::from_utf8(&response).map_err(|_| CfnError::Internal)?;
            let id = xml
                .split_once("<Id>")
                .and_then(|(_, tail)| tail.split_once("</Id>"))
                .map(|(id, _)| id.trim_start_matches("/hostedzone/"))
                .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
                .ok_or_else(|| {
                    CfnError::ResourceFailed(format!(
                        "Route53 returned no hosted zone ID for {logical}"
                    ))
                })?;
            return Ok(ResolvedResource {
                ref_value: id.into(),
                attributes: Default::default(),
            });
        }
        let body = custom_domain_body(logical, kind, props)?;
        let path = custom_domain_path(kind, props, None, logical)?;
        let response = self
            .call_json("apigateway", Method::POST, &path, body, logical)
            .await?;
        let mut result = custom_domain_result(logical, kind, props, &response)?;
        if kind.ends_with("::DomainName") {
            result.attributes.insert(
                "DomainNameArn".into(),
                format!(
                    "arn:aws:apigateway:{}::/domainnames/{}",
                    self.region, result.ref_value
                ),
            );
        }
        Ok(result)
    }

    pub(super) async fn update_custom_domain_resource(
        &self,
        logical: &str,
        kind: &str,
        current: &ResolvedResource,
        previous: &Value,
        next: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        if previous == next {
            return Ok(current.clone());
        }
        if kind == "AWS::Route53::HostedZone" {
            return Err(CfnError::Validation(format!(
                "{logical}: hosted-zone updates are not supported"
            )));
        }
        let body = custom_domain_body(logical, kind, next)?;
        for identity in if kind == "AWS::ApiGateway::BasePathMapping" {
            &["DomainName", "BasePath"][..]
        } else {
            &["DomainName"][..]
        } {
            if previous.get(identity) != next.get(identity) {
                return Err(CfnError::Validation(format!(
                    "{logical}: replacing custom-domain identity is not supported"
                )));
            }
        }
        let path = custom_domain_path(kind, next, Some(&current.ref_value), logical)?;
        let body = if kind.starts_with("AWS::ApiGateway::") {
            let operations: Vec<_> = body.as_object().into_iter().flatten().filter(|(key,_)| !matches!(key.as_str(), "domainName" | "basePath" | "endpointConfiguration"))
                .map(|(key,value)| json!({"op":"replace", "path":format!("/{key}"), "value": value.as_str().unwrap_or_default()})).collect();
            if previous.get("EndpointConfiguration") != next.get("EndpointConfiguration") {
                return Err(CfnError::Validation(format!(
                    "{logical}: endpoint configuration updates are not supported"
                )));
            }
            json!({"patchOperations":operations})
        } else {
            body
        };
        let response = self
            .call_json("apigateway", Method::PATCH, &path, body, logical)
            .await?;
        let mut result = custom_domain_result(logical, kind, next, &response)?;
        if kind.ends_with("::DomainName") {
            result.attributes.insert(
                "DomainNameArn".into(),
                format!(
                    "arn:aws:apigateway:{}::/domainnames/{}",
                    self.region, result.ref_value
                ),
            );
        }
        Ok(result)
    }

    pub(super) async fn delete_custom_domain_resource(
        &self,
        kind: &str,
        id: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        if kind == "AWS::Route53::HostedZone" {
            return self
                .delete_call(
                    "route53",
                    &format!("/2013-04-01/hostedzone/{}", enc(id)),
                    id,
                )
                .await;
        }
        self.delete_call(
            "apigateway",
            &custom_domain_path(kind, props, Some(id), id)?,
            id,
        )
        .await
    }
}

fn custom_domain_body(logical: &str, kind: &str, props: &Value) -> Result<Value, CfnError> {
    let fields: &[(&str, &str)] = match kind {
        "AWS::ApiGateway::DomainName" => &[
            ("DomainName", "domainName"),
            ("RegionalCertificateArn", "regionalCertificateArn"),
            ("SecurityPolicy", "securityPolicy"),
        ],
        "AWS::ApiGatewayV2::DomainName" => &[("DomainName", "domainName")],
        "AWS::ApiGateway::BasePathMapping" => &[
            ("DomainName", "domainName"),
            ("RestApiId", "restApiId"),
            ("Stage", "stage"),
            ("BasePath", "basePath"),
        ],
        "AWS::ApiGatewayV2::ApiMapping" => &[
            ("DomainName", "domainName"),
            ("ApiId", "apiId"),
            ("Stage", "stage"),
            ("ApiMappingKey", "apiMappingKey"),
        ],
        _ => return Err(CfnError::Internal),
    };
    let mut allowed: Vec<_> = fields.iter().map(|(key, _)| *key).collect();
    if kind == "AWS::ApiGateway::DomainName" {
        allowed.push("EndpointConfiguration");
    }
    if kind == "AWS::ApiGatewayV2::DomainName" {
        allowed.push("DomainNameConfigurations");
    }
    ensure_known_properties(logical, kind, props, &allowed)?;
    required_property(props, "DomainName", logical)?;
    let mut body = mapped_properties(props, fields);
    if kind == "AWS::ApiGateway::DomainName" {
        required_property(props, "RegionalCertificateArn", logical)?;
        let config = props.get("EndpointConfiguration").ok_or_else(|| {
            CfnError::Validation(format!("{logical} requires REGIONAL EndpointConfiguration"))
        })?;
        ensure_known_properties(logical, "EndpointConfiguration", config, &["Types"])?;
        if config.get("Types") != Some(&json!(["REGIONAL"])) {
            return Err(CfnError::Validation(format!(
                "{logical} supports only REGIONAL domains"
            )));
        }
        body["endpointConfiguration"] = json!({"types":["REGIONAL"]});
    } else if kind == "AWS::ApiGatewayV2::DomainName" {
        let configs = props
            .get("DomainNameConfigurations")
            .and_then(Value::as_array)
            .filter(|c| c.len() == 1)
            .ok_or_else(|| {
                CfnError::Validation(format!(
                    "{logical} requires one REGIONAL domain configuration"
                ))
            })?;
        let config = &configs[0];
        ensure_known_properties(
            logical,
            "DomainNameConfigurations",
            config,
            &["CertificateArn", "EndpointType", "SecurityPolicy"],
        )?;
        required_property(config, "CertificateArn", logical)?;
        if config.get("EndpointType").is_some_and(|v| v != "REGIONAL") {
            return Err(CfnError::Validation(format!(
                "{logical} supports only REGIONAL domains"
            )));
        }
        body["domainNameConfigurations"] = json!([mapped_properties(
            config,
            &[
                ("CertificateArn", "certificateArn"),
                ("EndpointType", "endpointType"),
                ("SecurityPolicy", "securityPolicy")
            ]
        )]);
    } else {
        required_property(
            props,
            if kind == "AWS::ApiGateway::BasePathMapping" {
                "RestApiId"
            } else {
                "ApiId"
            },
            logical,
        )?;
        required_property(props, "Stage", logical)?;
        if kind == "AWS::ApiGatewayV2::ApiMapping" && body.get("apiMappingKey").is_none() {
            body["apiMappingKey"] = json!("");
        }
        // DomainName identifies the request path, not a mapping's body.
        body.as_object_mut()
            .ok_or(CfnError::Internal)?
            .remove("domainName");
    }
    Ok(body)
}

fn custom_domain_path(
    kind: &str,
    props: &Value,
    id: Option<&str>,
    logical: &str,
) -> Result<String, CfnError> {
    let v2 = kind.starts_with("AWS::ApiGatewayV2::");
    let prefix = if v2 {
        "/v2/domainnames"
    } else {
        "/domainnames"
    };
    if kind.ends_with("::DomainName") {
        return Ok(match id {
            Some(id) => format!("{prefix}/{}", enc(id)),
            None => prefix.into(),
        });
    }
    let domain = required_property(props, "DomainName", logical)?;
    let mut path = format!(
        "{prefix}/{}/{}",
        enc(&domain),
        if v2 {
            "apimappings"
        } else {
            "basepathmappings"
        }
    );
    if let Some(id) = id {
        path.push('/');
        path.push_str(&enc(if v2 {
            id
        } else {
            props
                .get("BasePath")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .unwrap_or("(none)")
        }));
    }
    Ok(path)
}

fn custom_domain_result(
    logical: &str,
    kind: &str,
    props: &Value,
    response: &Value,
) -> Result<ResolvedResource, CfnError> {
    let mut attributes = std::collections::BTreeMap::new();
    let ref_value = if kind.ends_with("::DomainName") {
        let name = required_response_string(response, "domainName", logical)?;
        let regional = if kind.starts_with("AWS::ApiGatewayV2") {
            response
                .get("domainNameConfigurations")
                .and_then(Value::as_array)
                .and_then(|v| v.first())
                .ok_or_else(|| {
                    CfnError::ResourceFailed(format!(
                        "{logical} returned no regional domain configuration"
                    ))
                })?
        } else {
            response
        };
        attributes.insert(
            "RegionalDomainName".into(),
            required_response_string(
                regional,
                if kind.starts_with("AWS::ApiGatewayV2") {
                    "apiGatewayDomainName"
                } else {
                    "regionalDomainName"
                },
                logical,
            )?,
        );
        attributes.insert(
            "RegionalHostedZoneId".into(),
            required_response_string(
                regional,
                if kind.starts_with("AWS::ApiGatewayV2") {
                    "hostedZoneId"
                } else {
                    "regionalHostedZoneId"
                },
                logical,
            )?,
        );
        name
    } else if kind == "AWS::ApiGatewayV2::ApiMapping" {
        required_response_string(response, "apiMappingId", logical)?
    } else {
        format!(
            "{}|{}",
            required_property(props, "DomainName", logical)?,
            props
                .get("BasePath")
                .and_then(Value::as_str)
                .unwrap_or("(none)")
        )
    };
    Ok(ResolvedResource {
        ref_value,
        attributes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn regional_domain_wire_alias_and_mapping_contract() {
        let props = json!({"DomainName":"api.example.test", "RegionalCertificateArn":"arn:aws:acm:us-east-1:1:certificate/c", "EndpointConfiguration":{"Types":["REGIONAL"]}});
        let body = custom_domain_body("Domain", "AWS::ApiGateway::DomainName", &props).unwrap();
        assert_eq!(
            body["regionalCertificateArn"],
            props["RegionalCertificateArn"]
        );
        let native = json!({"domainName":"api.example.test","regionalDomainName":"d-id.execute-api.us-east-1.amazonaws.com","regionalHostedZoneId":"Z1UJRXOUMOOFQ8"});
        let facts =
            custom_domain_result("Domain", "AWS::ApiGateway::DomainName", &props, &native).unwrap();
        let alias = json!({"HostedZoneId":"ZUSER","Name":{"Ref":"Domain"},"Type":"A","AliasTarget":{"DNSName":facts.attributes["RegionalDomainName"],"HostedZoneId":facts.attributes["RegionalHostedZoneId"],"EvaluateTargetHealth":false}});
        let mut alias = alias;
        alias["Name"] = json!(facts.ref_value);
        let xml = route53_record_xml("Alias", &alias).unwrap();
        assert!(xml.contains("<AliasTarget>"));
        assert!(!xml.contains("<TTL>"));
        alias["TTL"] = json!(60);
        assert!(route53_record_xml("Alias", &alias).is_err());
        let mapping = json!({"DomainName":"api.example.test", "RestApiId":"api", "Stage":"dev"});
        assert_eq!(
            custom_domain_path(
                "AWS::ApiGateway::BasePathMapping",
                &mapping,
                Some("opaque"),
                "Mapping"
            )
            .unwrap(),
            "/domainnames/api.example.test/basepathmappings/%28none%29"
        );
        assert!(
            custom_domain_body("Mapping", "AWS::ApiGateway::BasePathMapping", &mapping)
                .unwrap()
                .get("domainName")
                .is_none()
        );
        let mut edge = props;
        edge["EndpointConfiguration"]["Types"] = json!(["EDGE"]);
        assert!(custom_domain_body("Domain", "AWS::ApiGateway::DomainName", &edge).is_err());
    }
}
