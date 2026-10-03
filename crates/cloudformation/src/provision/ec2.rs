//! CloudFormation's small EC2 network surface, backed by the native EC2 Query handler.

use super::*;

impl Provisioner {
    pub(super) async fn ec2_vpc(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(
            logical_id,
            "AWS::EC2::VPC",
            props,
            &[
                "CidrBlock",
                "InstanceTenancy",
                "EnableDnsSupport",
                "EnableDnsHostnames",
            ],
        )?;
        let cidr = required_property(props, "CidrBlock", logical_id)?;
        let mut fields = vec![("CidrBlock", cidr.as_str())];
        if let Some(tenancy) = props.get("InstanceTenancy") {
            let tenancy = tenancy.as_str().ok_or_else(|| {
                CfnError::Validation(format!("{logical_id} requires string InstanceTenancy"))
            })?;
            fields.push(("InstanceTenancy", tenancy));
        }
        let xml = self.call_ec2("CreateVpc", &fields, logical_id).await?;
        let id = ec2_id(&xml, "vpcId", "vpc-", logical_id)?;
        for (name, value) in [
            ("EnableDnsSupport", props.get("EnableDnsSupport")),
            ("EnableDnsHostnames", props.get("EnableDnsHostnames")),
        ] {
            if let Some(value) = value {
                let Some(enabled) = value.as_bool() else {
                    let error =
                        CfnError::Validation(format!("{logical_id} requires boolean {name}"));
                    let cleanup = self.delete_ec2("DeleteVpc", "VpcId", &id).await;
                    return Err(match cleanup {
                        Ok(()) => error,
                        Err(cleanup) => with_cleanup_failure(error, cleanup),
                    });
                };
                let key = format!("{name}.Value");
                if let Err(error) = self
                    .call_ec2(
                        "ModifyVpcAttribute",
                        &[("VpcId", &id), (&key, &enabled.to_string())],
                        logical_id,
                    )
                    .await
                {
                    let cleanup = self.delete_ec2("DeleteVpc", "VpcId", &id).await;
                    return Err(match cleanup {
                        Ok(()) => error,
                        Err(cleanup) => with_cleanup_failure(error, cleanup),
                    });
                }
            }
        }
        Ok(ResolvedResource {
            ref_value: id.clone(),
            attributes: [("VpcId".into(), id), ("CidrBlock".into(), cidr)].into(),
        })
    }

    pub(super) async fn ec2_subnet(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(
            logical_id,
            "AWS::EC2::Subnet",
            props,
            &["VpcId", "CidrBlock", "AvailabilityZone"],
        )?;
        let vpc = required_property(props, "VpcId", logical_id)?;
        let cidr = required_property(props, "CidrBlock", logical_id)?;
        let mut fields = vec![("VpcId", vpc.as_str()), ("CidrBlock", cidr.as_str())];
        if let Some(zone) = props.get("AvailabilityZone") {
            let zone = zone
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CfnError::Validation(format!("{logical_id} requires string AvailabilityZone"))
                })?;
            fields.push(("AvailabilityZone", zone));
        }
        let xml = self.call_ec2("CreateSubnet", &fields, logical_id).await?;
        let id = ec2_id(&xml, "subnetId", "subnet-", logical_id)?;
        let zone = ec2_tag(&xml, "availabilityZone").ok_or_else(|| {
            CfnError::ResourceFailed(format!("EC2 returned no availabilityZone for {logical_id}"))
        })?;
        Ok(ResolvedResource {
            ref_value: id.clone(),
            attributes: [
                ("SubnetId".into(), id),
                ("VpcId".into(), vpc),
                ("CidrBlock".into(), cidr),
                ("AvailabilityZone".into(), zone.to_owned()),
            ]
            .into(),
        })
    }

    pub(super) async fn ec2_security_group(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(
            logical_id,
            "AWS::EC2::SecurityGroup",
            props,
            &[
                "VpcId",
                "GroupName",
                "GroupDescription",
                "SecurityGroupIngress",
            ],
        )?;
        let vpc = required_property(props, "VpcId", logical_id)?;
        let description = required_property(props, "GroupDescription", logical_id)?;
        let name = match props.get("GroupName") {
            Some(_) => required_property(props, "GroupName", logical_id)?,
            None => generate_name(stack_name, logical_id, 255),
        };
        let rules = match props.get("SecurityGroupIngress") {
            None => Vec::new(),
            Some(Value::Array(rules)) => rules
                .iter()
                .map(|rule| {
                    ensure_known_properties(
                        logical_id,
                        "AWS::EC2::SecurityGroupIngress",
                        rule,
                        &["IpProtocol", "FromPort", "ToPort", "CidrIp"],
                    )?;
                    let protocol = required_property(rule, "IpProtocol", logical_id)?;
                    let cidr = required_property(rule, "CidrIp", logical_id)?;
                    let port = |name: &str| {
                        rule.get(name)
                            .and_then(Value::as_u64)
                            .filter(|value| *value <= u16::MAX as u64)
                            .map(|value| value.to_string())
                            .ok_or_else(|| {
                                CfnError::Validation(format!(
                                    "{logical_id} requires numeric {name}"
                                ))
                            })
                    };
                    Ok::<_, CfnError>((protocol, port("FromPort")?, port("ToPort")?, cidr))
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => {
                return Err(CfnError::Validation(format!(
                    "{logical_id} requires array SecurityGroupIngress"
                )))
            }
        };
        let xml = self
            .call_ec2(
                "CreateSecurityGroup",
                &[
                    ("VpcId", &vpc),
                    ("GroupName", &name),
                    ("GroupDescription", &description),
                ],
                logical_id,
            )
            .await?;
        let id = ec2_id(&xml, "groupId", "sg-", logical_id)?;
        for (protocol, from, to, cidr) in rules {
            if let Err(error) = self
                .call_ec2(
                    "AuthorizeSecurityGroupIngress",
                    &[
                        ("GroupId", &id),
                        ("IpProtocol", &protocol),
                        ("FromPort", &from),
                        ("ToPort", &to),
                        ("CidrIp", &cidr),
                    ],
                    logical_id,
                )
                .await
            {
                let cleanup = self.delete_ec2("DeleteSecurityGroup", "GroupId", &id).await;
                return Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup) => with_cleanup_failure(error, cleanup),
                });
            }
        }
        Ok(ResolvedResource {
            ref_value: id.clone(),
            attributes: [("GroupId".into(), id), ("VpcId".into(), vpc)].into(),
        })
    }

    async fn call_ec2(
        &self,
        action: &str,
        fields: &[(&str, &str)],
        logical_id: &str,
    ) -> Result<String, CfnError> {
        let mut form = format!("Action={action}&Version=2016-11-15");
        for (key, value) in fields {
            form.push('&');
            form.push_str(key);
            form.push('=');
            form.push_str(&enc(value));
        }
        let (status, response) = self
            .call("ec2", Method::POST, "/", form_host(), Bytes::from(form))
            .await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "EC2 {action} for {logical_id} failed ({status}): {}",
                String::from_utf8_lossy(&response)
            )));
        }
        String::from_utf8(response.to_vec()).map_err(|_| {
            CfnError::ResourceFailed(format!(
                "EC2 {action} returned invalid UTF-8 for {logical_id}"
            ))
        })
    }

    pub(super) async fn delete_ec2(
        &self,
        action: &str,
        key: &str,
        physical_id: &str,
    ) -> Result<(), CfnError> {
        self.call_ec2(action, &[(key, physical_id)], physical_id)
            .await?;
        Ok(())
    }
}

fn ec2_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    xml.split_once(&open)
        .and_then(|(_, tail)| tail.split_once(&close))
        .map(|(value, _)| value)
        .filter(|value| !value.is_empty())
}

fn ec2_id(xml: &str, tag: &str, prefix: &str, logical_id: &str) -> Result<String, CfnError> {
    ec2_tag(xml, tag)
        .filter(|id| {
            id.starts_with(prefix) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        .map(str::to_owned)
        .ok_or_else(|| CfnError::ResourceFailed(format!("EC2 returned no {tag} for {logical_id}")))
}

impl Provisioner {
    pub(super) async fn ec2_route_table(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(logical_id, "AWS::EC2::RouteTable", props, &["VpcId"])?;
        let vpc = required_property(props, "VpcId", logical_id)?;
        let xml = self
            .call_ec2("CreateRouteTable", &[("VpcId", &vpc)], logical_id)
            .await?;
        let id = ec2_id(&xml, "routeTableId", "rtb-", logical_id)?;
        Ok(ResolvedResource {
            ref_value: id.clone(),
            attributes: [("RouteTableId".into(), id), ("VpcId".into(), vpc)].into(),
        })
    }

    pub(super) async fn ec2_route_association(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(
            logical_id,
            "AWS::EC2::SubnetRouteTableAssociation",
            props,
            &["RouteTableId", "SubnetId"],
        )?;
        let table = required_property(props, "RouteTableId", logical_id)?;
        let subnet = required_property(props, "SubnetId", logical_id)?;
        let xml = self
            .call_ec2(
                "AssociateRouteTable",
                &[("RouteTableId", &table), ("SubnetId", &subnet)],
                logical_id,
            )
            .await?;
        let id = ec2_id(&xml, "associationId", "rtbassoc-", logical_id)?;
        Ok(ResolvedResource {
            ref_value: id,
            attributes: Default::default(),
        })
    }

    pub(super) async fn ec2_vpc_endpoint(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(
            logical_id,
            "AWS::EC2::VPCEndpoint",
            props,
            &[
                "VpcId",
                "ServiceName",
                "VpcEndpointType",
                "RouteTableIds",
                "SubnetIds",
                "SecurityGroupIds",
                "PrivateDnsEnabled",
            ],
        )?;
        let vpc = required_property(props, "VpcId", logical_id)?;
        let service = required_property(props, "ServiceName", logical_id)?;
        let kind = props
            .get("VpcEndpointType")
            .map(|_| required_property(props, "VpcEndpointType", logical_id))
            .transpose()?
            .unwrap_or_else(|| "Gateway".into());
        let routes = string_list(props, "RouteTableIds", logical_id)?;
        let subnets = string_list(props, "SubnetIds", logical_id)?;
        let groups = string_list(props, "SecurityGroupIds", logical_id)?;
        let private_dns = props
            .get("PrivateDnsEnabled")
            .map(|value| {
                value.as_bool().ok_or_else(|| {
                    CfnError::Validation(format!("{logical_id} requires boolean PrivateDnsEnabled"))
                })
            })
            .transpose()?;
        let mut fields = vec![
            ("VpcId".to_string(), vpc.clone()),
            ("ServiceName".into(), service),
            ("VpcEndpointType".into(), kind),
        ];
        if let Some(enabled) = private_dns {
            fields.push(("PrivateDnsEnabled".into(), enabled.to_string()));
        }
        for (name, values) in [
            ("RouteTableId", routes),
            ("SubnetId", subnets),
            ("SecurityGroupId", groups),
        ] {
            for (index, value) in values.into_iter().enumerate() {
                fields.push((format!("{name}.{}", index + 1), value));
            }
        }
        let borrowed = fields
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        let xml = self
            .call_ec2("CreateVpcEndpoint", &borrowed, logical_id)
            .await?;
        let id = ec2_id(&xml, "vpcEndpointId", "vpce-", logical_id)?;
        Ok(ResolvedResource {
            ref_value: id.clone(),
            attributes: [("VpcEndpointId".into(), id), ("VpcId".into(), vpc)].into(),
        })
    }
}

fn string_list(props: &Value, name: &str, logical_id: &str) -> Result<Vec<String>, CfnError> {
    match props.get(name) {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        CfnError::Validation(format!(
                            "{logical_id} requires nonempty strings in {name}"
                        ))
                    })
            })
            .collect(),
        _ => Err(CfnError::Validation(format!(
            "{logical_id} requires array {name}"
        ))),
    }
}
