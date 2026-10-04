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
                "SecurityGroupEgress",
            ],
        )?;
        let vpc = required_property(props, "VpcId", logical_id)?;
        let description = required_property(props, "GroupDescription", logical_id)?;
        let name = match props.get("GroupName") {
            Some(_) => required_property(props, "GroupName", logical_id)?,
            None => generate_name(stack_name, logical_id, 255),
        };
        let parse_rules = |direction: &str| {
            Ok(match props.get(direction) {
                None => Vec::new(),
                Some(Value::Array(rules)) => rules
                    .iter()
                    .map(|rule| {
                        ensure_known_properties(
                            logical_id,
                            &format!("AWS::EC2::{direction}"),
                            rule,
                            &["IpProtocol", "FromPort", "ToPort", "CidrIp"],
                        )?;
                        let protocol = required_property(rule, "IpProtocol", logical_id)?;
                        let cidr = required_property(rule, "CidrIp", logical_id)?;
                        let port = |name: &str| {
                            if protocol == "-1" {
                                return Ok("0".to_string());
                            }
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
                        let from = port("FromPort")?;
                        let to = port("ToPort")?;
                        Ok::<_, CfnError>((protocol, from, to, cidr))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => {
                    return Err(CfnError::Validation(format!(
                        "{logical_id} requires array {direction}"
                    )));
                }
            })
        };
        let ingress = parse_rules("SecurityGroupIngress")?;
        let egress = parse_rules("SecurityGroupEgress")?;
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
        let configure = async {
            if !egress.is_empty() {
                self.call_ec2(
                    "RevokeSecurityGroupEgress",
                    &[
                        ("GroupId", &id),
                        ("IpProtocol", "-1"),
                        ("CidrIp", "0.0.0.0/0"),
                    ],
                    logical_id,
                )
                .await?;
            }
            for (action, rules) in [
                ("AuthorizeSecurityGroupIngress", ingress),
                ("AuthorizeSecurityGroupEgress", egress),
            ] {
                for (protocol, from, to, cidr) in rules {
                    self.call_ec2(
                        action,
                        &[
                            ("GroupId", &id),
                            ("IpProtocol", &protocol),
                            ("FromPort", &from),
                            ("ToPort", &to),
                            ("CidrIp", &cidr),
                        ],
                        logical_id,
                    )
                    .await?;
                }
            }
            Ok::<_, CfnError>(())
        }
        .await;
        if let Err(error) = configure {
            let cleanup = self.delete_ec2("DeleteSecurityGroup", "GroupId", &id).await;
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => with_cleanup_failure(error, cleanup),
            });
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

impl Provisioner {
    pub(super) async fn ec2_eip(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_network_properties(logical_id, "AWS::EC2::EIP", props)?;
        let xml = self
            .call_ec2("AllocateAddress", &[("Domain", "vpc")], logical_id)
            .await?;
        let allocation = ec2_id(&xml, "allocationId", "eipalloc-", logical_id)?;
        let ip = ec2_tag(&xml, "publicIp")
            .and_then(|value| value.parse::<std::net::Ipv4Addr>().ok())
            .ok_or_else(|| {
                CfnError::ResourceFailed(format!("EC2 returned no publicIp for {logical_id}"))
            })?
            .to_string();
        Ok(ResolvedResource {
            ref_value: ip.clone(),
            attributes: [("AllocationId".into(), allocation), ("PublicIp".into(), ip)].into(),
        })
    }

    pub(super) async fn ec2_internet_gateway(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_network_properties(logical_id, "AWS::EC2::InternetGateway", props)?;
        let xml = self
            .call_ec2("CreateInternetGateway", &[], logical_id)
            .await?;
        let id = ec2_id(&xml, "internetGatewayId", "igw-", logical_id)?;
        Ok(ResolvedResource {
            ref_value: id.clone(),
            attributes: [("InternetGatewayId".into(), id)].into(),
        })
    }

    pub(super) async fn ec2_nat_gateway(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_network_properties(logical_id, "AWS::EC2::NatGateway", props)?;
        let fields = [
            "AllocationId",
            "AvailabilityMode",
            "ConnectivityType",
            "SubnetId",
            "VpcId",
        ]
        .iter()
        .filter_map(|name| {
            props
                .get(name)
                .and_then(Value::as_str)
                .map(|value| (*name, value))
        })
        .collect::<Vec<_>>();
        let xml = self
            .call_ec2("CreateNatGateway", &fields, logical_id)
            .await?;
        let id = ec2_id(&xml, "natGatewayId", "nat-", logical_id)?;
        Ok(ResolvedResource {
            ref_value: id.clone(),
            attributes: [("NatGatewayId".into(), id)].into(),
        })
    }

    pub(super) async fn ec2_gateway_attachment(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_network_properties(logical_id, "AWS::EC2::VPCGatewayAttachment", props)?;
        let vpc = required_property(props, "VpcId", logical_id)?;
        let gateway = required_property(props, "InternetGatewayId", logical_id)?;
        self.call_ec2(
            "AttachInternetGateway",
            &[("VpcId", &vpc), ("InternetGatewayId", &gateway)],
            logical_id,
        )
        .await?;
        Ok(ResolvedResource {
            ref_value: format!("{vpc}|{gateway}"),
            attributes: Default::default(),
        })
    }

    pub(super) async fn ec2_route(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_network_properties(logical_id, "AWS::EC2::Route", props)?;
        let fields = [
            "RouteTableId",
            "DestinationCidrBlock",
            "GatewayId",
            "NatGatewayId",
            "NetworkInterfaceId",
        ]
        .iter()
        .filter_map(|name| {
            props
                .get(name)
                .and_then(Value::as_str)
                .map(|value| (*name, value))
        })
        .collect::<Vec<_>>();
        self.call_ec2("CreateRoute", &fields, logical_id).await?;
        let table = required_property(props, "RouteTableId", logical_id)?;
        let cidr = required_property(props, "DestinationCidrBlock", logical_id)?;
        Ok(ResolvedResource {
            ref_value: format!("{table}|{cidr}"),
            attributes: Default::default(),
        })
    }

    pub(super) async fn delete_ec2_eip(&self, public_ip: &str) -> Result<(), CfnError> {
        // CloudFormation Ref is the address, not AllocationId; resolve the scoped native address.
        let xml = self
            .call_ec2(
                "DescribeAddresses",
                &[
                    ("Filter.1.Name", "public-ip"),
                    ("Filter.1.Value.1", public_ip),
                ],
                public_ip,
            )
            .await?;
        let allocation = ec2_id(&xml, "allocationId", "eipalloc-", public_ip)?;
        self.delete_ec2("ReleaseAddress", "AllocationId", &allocation)
            .await
    }

    pub(super) async fn delete_ec2_gateway_attachment(
        &self,
        props: &Value,
    ) -> Result<(), CfnError> {
        let vpc = required_property(props, "VpcId", "gateway attachment")?;
        let gateway = required_property(props, "InternetGatewayId", "gateway attachment")?;
        self.call_ec2(
            "DetachInternetGateway",
            &[("VpcId", &vpc), ("InternetGatewayId", &gateway)],
            &gateway,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn delete_ec2_route(&self, props: &Value) -> Result<(), CfnError> {
        let table = required_property(props, "RouteTableId", "route")?;
        let cidr = required_property(props, "DestinationCidrBlock", "route")?;
        self.call_ec2(
            "DeleteRoute",
            &[("RouteTableId", &table), ("DestinationCidrBlock", &cidr)],
            &table,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn update_ec2_network(
        &self,
        logical_id: &str,
        kind: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
        _replacement: Replacement,
    ) -> Result<ResolvedResource, CfnError> {
        validate_network_properties(logical_id, kind, previous)?;
        validate_network_properties(logical_id, kind, props)?;
        if previous == props || kind == "AWS::EC2::EIP" || kind == "AWS::EC2::InternetGateway" {
            return Ok(current.clone());
        }
        // A target change preserves the route's physical identity. Restore it if EC2 rejects the new target.
        if kind == "AWS::EC2::Route"
            && previous.get("RouteTableId") == props.get("RouteTableId")
            && previous.get("DestinationCidrBlock") == props.get("DestinationCidrBlock")
        {
            self.delete_ec2_route(previous).await?;
            return match self.ec2_route(logical_id, props).await {
                Ok(next) => Ok(next),
                Err(error) => match self.ec2_route(logical_id, previous).await {
                    Ok(_) => Err(error),
                    Err(cleanup) => Err(with_cleanup_failure(error, cleanup)),
                },
            };
        }
        // The stack reconciler retains the previous physical resource until dependents have
        // switched successfully, and can re-adopt it unchanged during rollback.
        match kind {
            "AWS::EC2::NatGateway" => self.ec2_nat_gateway(logical_id, props).await,
            "AWS::EC2::Route" => self.ec2_route(logical_id, props).await,
            "AWS::EC2::VPCGatewayAttachment" => {
                self.ec2_gateway_attachment(logical_id, props).await
            }
            _ => unreachable!(),
        }
    }
}

fn validate_network_properties(
    logical_id: &str,
    kind: &str,
    props: &Value,
) -> Result<(), CfnError> {
    let (allowed, required): (&[&str], &[&str]) = match kind {
        "AWS::EC2::EIP" => (&["Domain"], &[]),
        "AWS::EC2::InternetGateway" => (&[], &[]),
        "AWS::EC2::NatGateway" => (
            &[
                "AllocationId",
                "AvailabilityMode",
                "ConnectivityType",
                "SubnetId",
                "VpcId",
            ],
            &[],
        ),
        "AWS::EC2::VPCGatewayAttachment" => (
            &["VpcId", "InternetGatewayId"],
            &["VpcId", "InternetGatewayId"],
        ),
        "AWS::EC2::Route" => (
            &[
                "RouteTableId",
                "DestinationCidrBlock",
                "GatewayId",
                "NatGatewayId",
                "NetworkInterfaceId",
            ],
            &["RouteTableId", "DestinationCidrBlock"],
        ),
        _ => unreachable!(),
    };
    ensure_known_properties(logical_id, kind, props, allowed)?;
    for name in allowed
        .iter()
        .filter(|name| props.get(**name).is_some())
        .chain(required.iter())
    {
        required_property(props, name, logical_id)?;
    }
    match kind {
        "AWS::EC2::EIP" if props.get("Domain").is_some_and(|value| value != "vpc") => {
            return Err(CfnError::Validation(format!(
                "{logical_id} supports only EIP Domain vpc"
            )));
        }
        "AWS::EC2::NatGateway" => {
            if props
                .get("ConnectivityType")
                .is_some_and(|value| value != "public")
            {
                return Err(CfnError::Validation(format!(
                    "{logical_id} supports only public NAT gateways"
                )));
            }
            match props
                .get("AvailabilityMode")
                .and_then(Value::as_str)
                .unwrap_or("zonal")
            {
                "zonal" => {
                    required_property(props, "SubnetId", logical_id)?;
                    required_property(props, "AllocationId", logical_id)?;
                    if props.get("VpcId").is_some() {
                        return Err(CfnError::Validation(format!(
                            "{logical_id} zonal NAT uses SubnetId, not VpcId"
                        )));
                    }
                }
                "regional" => {
                    required_property(props, "VpcId", logical_id)?;
                    if props.get("SubnetId").is_some() || props.get("AllocationId").is_some() {
                        return Err(CfnError::Validation(format!(
                            "{logical_id} regional NAT uses VpcId and automatic addresses"
                        )));
                    }
                }
                _ => {
                    return Err(CfnError::Validation(format!(
                        "{logical_id} requires AvailabilityMode zonal or regional"
                    )));
                }
            }
        }
        "AWS::EC2::Route"
            if ["GatewayId", "NatGatewayId", "NetworkInterfaceId"]
                .iter()
                .filter(|name| props.get(**name).is_some())
                .count()
                != 1 =>
        {
            return Err(CfnError::Validation(format!(
                "{logical_id} requires exactly one supported route target"
            )));
        }
        _ => {}
    }
    Ok(())
}

/// Check the native surface before a stack mutates any resource; intrinsic values resolve later.
pub(crate) fn validate_network_property_names(
    logical_id: &str,
    kind: &str,
    props: &Value,
) -> Result<(), CfnError> {
    let allowed: &[&str] = match kind {
        "AWS::EC2::EIP" => &["Domain"],
        "AWS::EC2::InternetGateway" => &[],
        "AWS::EC2::NatGateway" => &[
            "AllocationId",
            "AvailabilityMode",
            "ConnectivityType",
            "SubnetId",
            "VpcId",
        ],
        "AWS::EC2::VPCGatewayAttachment" => &["VpcId", "InternetGatewayId"],
        "AWS::EC2::Route" => &[
            "RouteTableId",
            "DestinationCidrBlock",
            "GatewayId",
            "NatGatewayId",
            "NetworkInterfaceId",
        ],
        _ => return Ok(()),
    };
    ensure_known_properties(logical_id, kind, props, allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn security_group_explicit_egress_and_failed_rule_cleanup() {
        let registry = Arc::new(ServiceRegistry::new());
        locallycloud_ec2::register(&registry);
        let p = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let vpc = p
            .ec2_vpc("Vpc", &json!({"CidrBlock":"10.54.0.0/16"}))
            .await
            .unwrap();
        let props = json!({"VpcId":vpc.ref_value,"GroupDescription":"outbound denied", "SecurityGroupEgress":[{"IpProtocol":"tcp","FromPort":1,"ToPort":1,"CidrIp":"0.0.0.0/0"}]});
        let sg = p
            .ec2_security_group("Restricted", "test", &props)
            .await
            .unwrap();
        let xml = p
            .call_ec2(
                "DescribeSecurityGroups",
                &[("GroupId.1", &sg.ref_value)],
                "Restricted",
            )
            .await
            .unwrap();
        assert!(xml.contains("<fromPort>1</fromPort>"), "{xml}");
        assert!(
            !xml.contains("<ipProtocol>-1</ipProtocol>"),
            "default all egress survived: {xml}"
        );
        let before = p
            .call_ec2("DescribeSecurityGroups", &[], "Groups")
            .await
            .unwrap();
        let mut malformed = props.clone();
        malformed["SecurityGroupEgress"][0]["CidrIp"] = json!("invalid-cidr");
        assert!(p
            .ec2_security_group("Rollback", "test", &malformed)
            .await
            .is_err());
        let xml = p
            .call_ec2("DescribeSecurityGroups", &[], "Groups")
            .await
            .unwrap();
        assert_eq!(
            xml.matches("<groupId>").count(),
            before.matches("<groupId>").count(),
            "failed group was retained: {xml}"
        );
        p.delete_ec2("DeleteSecurityGroup", "GroupId", &sg.ref_value)
            .await
            .unwrap();
        p.delete_ec2("DeleteVpc", "VpcId", &vpc.ref_value)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn native_nat_topology_ref_scope_routes_and_cleanup() {
        let registry = Arc::new(ServiceRegistry::new());
        locallycloud_ec2::register(&registry);
        let p = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "000000000000".into(),
        );
        let vpc = p
            .ec2_vpc("Vpc", &json!({"CidrBlock":"10.53.0.0/16"}))
            .await
            .unwrap();
        let subnet = p
            .ec2_subnet(
                "PublicSubnet",
                &json!({"VpcId":vpc.ref_value,"CidrBlock":"10.53.1.0/24"}),
            )
            .await
            .unwrap();
        let gateway = p.ec2_internet_gateway("Gateway", &json!({})).await.unwrap();
        let attachment_props = json!({"VpcId":vpc.ref_value,"InternetGatewayId":gateway.ref_value});
        p.ec2_gateway_attachment("Attachment", &attachment_props)
            .await
            .unwrap();
        let eip = p
            .ec2_eip("Address", &json!({"Domain":"vpc"}))
            .await
            .unwrap();
        assert!(eip.ref_value.parse::<std::net::Ipv4Addr>().is_ok());
        assert!(eip.attributes["AllocationId"].starts_with("eipalloc-"));
        assert_eq!(eip.ref_value, eip.attributes["PublicIp"]);
        let nat_props =
            json!({"SubnetId":subnet.ref_value,"AllocationId":eip.attributes["AllocationId"]});
        let nat = p.ec2_nat_gateway("Nat", &nat_props).await.unwrap();
        let table = p
            .ec2_route_table("Table", &json!({"VpcId":vpc.ref_value}))
            .await
            .unwrap();
        let route_props = json!({"RouteTableId":table.ref_value,"DestinationCidrBlock":"0.0.0.0/0","NatGatewayId":nat.ref_value});
        let route = p.ec2_route("Route", &route_props).await.unwrap();
        // Invalid target replacement restores the live route, rather than silently deleting it.
        let mut invalid = route_props.clone();
        invalid["NatGatewayId"] = json!("nat-missing");
        assert!(p
            .update_ec2_network(
                "Route",
                "AWS::EC2::Route",
                &route,
                &route_props,
                &invalid,
                Replacement::Update(ResourcePolicy::Delete)
            )
            .await
            .is_err());
        let xml = p
            .call_ec2(
                "DescribeRouteTables",
                &[("RouteTableId.1", &table.ref_value)],
                "Table",
            )
            .await
            .unwrap();
        assert!(xml.contains(&format!("<natGatewayId>{}</natGatewayId>", nat.ref_value)));
        let other = Provisioner::new(
            Arc::downgrade(&registry),
            "us-west-2".into(),
            "000000000000".into(),
        );
        assert!(other
            .ec2_nat_gateway("OtherRegion", &nat_props)
            .await
            .is_err());
        assert!(p.delete_ec2_eip(&eip.ref_value).await.is_err());
        p.deprovision("AWS::EC2::Route", &route.ref_value, &route_props)
            .await
            .unwrap();
        p.deprovision("AWS::EC2::NatGateway", &nat.ref_value, &nat_props)
            .await
            .unwrap();
        p.deprovision("AWS::EC2::EIP", &eip.ref_value, &json!({"Domain":"vpc"}))
            .await
            .unwrap();
        p.deprovision("AWS::EC2::RouteTable", &table.ref_value, &Value::Null)
            .await
            .unwrap();
        p.deprovision(
            "AWS::EC2::VPCGatewayAttachment",
            "unused",
            &attachment_props,
        )
        .await
        .unwrap();
        p.deprovision(
            "AWS::EC2::InternetGateway",
            &gateway.ref_value,
            &Value::Null,
        )
        .await
        .unwrap();
        p.deprovision("AWS::EC2::Subnet", &subnet.ref_value, &Value::Null)
            .await
            .unwrap();
        p.deprovision("AWS::EC2::VPC", &vpc.ref_value, &Value::Null)
            .await
            .unwrap();
        for action in [
            "DescribeVpcs",
            "DescribeNatGateways",
            "DescribeAddresses",
            "DescribeInternetGateways",
        ] {
            let xml = p.call_ec2(action, &[], action).await.unwrap();
            assert!(!xml.contains("<item>"), "orphan after cleanup: {xml}");
        }
    }
}
