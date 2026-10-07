use super::*;

#[derive(Clone)]
pub(super) struct VpcEndpoint {
    pub(super) id: String,
    pub(super) vpc_id: String,
    pub(super) service_name: String,
    pub(super) service: String,
    pub(super) kind: EndpointKind,
    pub(super) route_table_ids: Vec<String>,
    pub(super) subnet_ids: Vec<String>,
    pub(super) group_ids: Vec<String>,
    pub(super) private_dns: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum EndpointKind {
    Gateway,
    Interface,
}

impl Ec2Handler {
    pub(super) fn create_vpc_endpoint(
        &self,
        key: (String, String),
        region: &str,
        input: &Input,
    ) -> Result<String, Ec2Error> {
        for name in input.fields.keys() {
            if [
                "Action",
                "Version",
                "DryRun",
                "VpcId",
                "ServiceName",
                "VpcEndpointType",
                "PrivateDnsEnabled",
                "ClientToken",
            ]
            .contains(&name.as_str())
                || indexed_key(name, "RouteTableId").is_some()
                || indexed_key(name, "SubnetId").is_some()
                || indexed_key(name, "SecurityGroupId").is_some()
            {
                continue;
            }
            return Err(Ec2Error::unsupported(name));
        }
        input.dry_run()?;
        let vpc_id = input.required("VpcId")?;
        let service_name = input.required("ServiceName")?;
        let service = service_name
            .strip_prefix(&format!("com.amazonaws.{region}."))
            .ok_or_else(|| {
                Ec2Error::new("InvalidServiceName", "Endpoint service must be regional")
            })?;
        let kind = match input.one("VpcEndpointType")?.unwrap_or("Gateway") {
            "Gateway" if matches!(service, "s3" | "dynamodb") => EndpointKind::Gateway,
            "Interface" if matches!(service, "ssm" | "secretsmanager") => EndpointKind::Interface,
            _ => {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Unsupported endpoint service or type",
                ))
            }
        };
        let route_table_ids = input.indexed("RouteTableId")?;
        let subnet_ids = input.indexed("SubnetId")?;
        let group_ids = input.indexed("SecurityGroupId")?;
        let token = input.one("ClientToken")?;
        if token.is_some_and(|value| value.is_empty() || value.len() > 64 || !value.is_ascii()) {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "ClientToken must be 1-64 ASCII characters",
            ));
        }
        let signature = input
            .fields
            .iter()
            .filter(|(key, _)| {
                !["Action", "Version", "DryRun", "ClientToken"].contains(&key.as_str())
            })
            .map(|(key, values)| (key.clone(), values[0].clone()))
            .collect::<BTreeMap<_, _>>();
        let private_dns = match input.one("PrivateDnsEnabled")? {
            Some("true") => true,
            None | Some("false") => false,
            _ => {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "PrivateDnsEnabled must be true or false",
                ))
            }
        };
        let unique = |ids: &[String]| {
            ids.iter().collect::<std::collections::HashSet<_>>().len() == ids.len()
        };
        if !unique(&route_table_ids) || !unique(&subnet_ids) || !unique(&group_ids) {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Duplicate endpoint resource ID",
            ));
        }
        match kind {
            EndpointKind::Gateway
                if route_table_ids.is_empty()
                    || !subnet_ids.is_empty()
                    || !group_ids.is_empty()
                    || private_dns =>
            {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Gateway endpoint requires route tables only",
                ));
            }
            EndpointKind::Interface
                if !route_table_ids.is_empty() || subnet_ids.is_empty() || group_ids.is_empty() =>
            {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Interface endpoint requires subnets and security groups",
                ));
            }
            _ => {}
        }
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        if let Some(token) = token {
            if let Some((previous, id)) = scope.vpc_endpoint_tokens.get(token) {
                if previous != &signature {
                    return Err(Ec2Error::new(
                        "IdempotentParameterMismatch",
                        "ClientToken was already used with different endpoint parameters",
                    ));
                }
                if let Some(endpoint) = scope.vpc_endpoints.get(id) {
                    return Ok(format!(
                        "<vpcEndpoint>{}</vpcEndpoint>",
                        endpoint_xml(endpoint)
                    ));
                }
            }
        }
        if !scope.vpcs.contains_key(vpc_id) {
            return Err(Ec2Error::new(
                "InvalidVpcID.NotFound",
                "The VPC does not exist",
            ));
        }
        if kind == EndpointKind::Interface
            && private_dns
            && !scope.vpc_dns.get(vpc_id).is_some_and(|dns| dns.0 && dns.1)
        {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Private DNS requires VPC DNS support and hostnames",
            ));
        }
        if scope
            .vpc_endpoints
            .values()
            .any(|ep| ep.vpc_id == vpc_id && ep.service_name == service_name && ep.kind == kind)
        {
            return Err(Ec2Error::new(
                "InvalidVpcEndpoint.Duplicate",
                "The endpoint already exists",
            ));
        }
        if route_table_ids.iter().any(|id| {
            !scope.route_tables.get(id).is_some_and(|table| {
                table.vpc_id == vpc_id && !table.endpoint_routes.contains_key(service)
            })
        }) {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Route table is outside the VPC or already has an endpoint route",
            ));
        }
        if subnet_ids.iter().any(|id| {
            scope
                .subnets
                .get(id)
                .is_none_or(|subnet| subnet.vpc_id != vpc_id)
        }) {
            return Err(Ec2Error::new(
                "InvalidSubnetID.NotFound",
                "Endpoint subnet is outside the VPC",
            ));
        }
        if group_ids.iter().any(|id| {
            scope
                .security_groups
                .get(id)
                .is_none_or(|group| group.vpc_id != vpc_id)
        }) {
            return Err(Ec2Error::new(
                "InvalidGroup.NotFound",
                "Endpoint security group is outside the VPC",
            ));
        }
        let id = resource_id("vpce");
        let endpoint = VpcEndpoint {
            id: id.clone(),
            vpc_id: vpc_id.into(),
            service_name: service_name.into(),
            service: service.into(),
            kind,
            route_table_ids,
            subnet_ids,
            group_ids,
            private_dns,
        };
        for table_id in &endpoint.route_table_ids {
            scope
                .route_tables
                .get_mut(table_id)
                .expect("validated route table")
                .endpoint_routes
                .insert(service.into(), id.clone());
        }
        let xml = endpoint_xml(&endpoint);
        scope.vpc_endpoints.insert(id.clone(), endpoint);
        if let Some(token) = token {
            scope
                .vpc_endpoint_tokens
                .insert(token.into(), (signature, id));
        }
        Ok(format!("<vpcEndpoint>{xml}</vpcEndpoint>"))
    }

    pub(super) fn describe_vpc_endpoints(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_describe(
            "VpcEndpointId",
            &[
                "vpc-endpoint-id",
                "vpc-id",
                "service-name",
                "vpc-endpoint-type",
            ],
        )?;
        let ids = input.indexed("VpcEndpointId")?;
        let filters = input.filters()?;
        let state = self.scopes.lock().unwrap();
        let scope = state.get(&key);
        let endpoints = if ids.is_empty() {
            scope
                .into_iter()
                .flat_map(|s| s.vpc_endpoints.values())
                .collect::<Vec<_>>()
        } else {
            ids.iter()
                .map(|id| {
                    scope.and_then(|s| s.vpc_endpoints.get(id)).ok_or_else(|| {
                        Ec2Error::new(
                            "InvalidVpcEndpointId.NotFound",
                            "The VPC endpoint does not exist",
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let body = endpoints
            .into_iter()
            .filter(|ep| {
                filters.iter().all(|(name, values)| match name.as_str() {
                    "vpc-endpoint-id" => values.contains(&ep.id),
                    "vpc-id" => values.contains(&ep.vpc_id),
                    "service-name" => values.contains(&ep.service_name),
                    "vpc-endpoint-type" => {
                        values.iter().any(|value| value == endpoint_kind(ep.kind))
                    }
                    _ => false,
                })
            })
            .map(|ep| format!("<item>{}</item>", endpoint_xml(ep)))
            .collect::<String>();
        Ok(format!("<vpcEndpointSet>{body}</vpcEndpointSet>"))
    }

    pub(super) fn delete_vpc_endpoints(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        for name in input.fields.keys() {
            if ["Action", "Version", "DryRun"].contains(&name.as_str())
                || indexed_key(name, "VpcEndpointId").is_some()
            {
                continue;
            }
            return Err(Ec2Error::unsupported(name));
        }
        input.dry_run()?;
        let ids = input.indexed("VpcEndpointId")?;
        if ids.is_empty() || ids.iter().collect::<std::collections::HashSet<_>>().len() != ids.len()
        {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "VpcEndpointId list must be nonempty and unique",
            ));
        }
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        if ids.iter().any(|id| !scope.vpc_endpoints.contains_key(id)) {
            return Err(Ec2Error::new(
                "InvalidVpcEndpointId.NotFound",
                "The VPC endpoint does not exist",
            ));
        }
        for id in ids {
            let endpoint = scope.vpc_endpoints.remove(&id).expect("validated endpoint");
            scope
                .vpc_endpoint_tokens
                .retain(|_, (_, endpoint_id)| endpoint_id != &id);
            for table_id in endpoint.route_table_ids {
                if let Some(table) = scope.route_tables.get_mut(&table_id) {
                    table.endpoint_routes.remove(&endpoint.service);
                }
            }
        }
        Ok("<unsuccessful/>".into())
    }

    /// Whether a Lambda in `subnet_id` can reach a regional AWS service through a VPC endpoint.
    /// Interface endpoints additionally require their security group to admit HTTPS from the
    /// Lambda's private IP. Lambda security-group egress must cover HTTPS to the service.
    pub fn vpc_endpoint_access(
        &self,
        account: &str,
        region: &str,
        subnet_id: &str,
        source_ip: Ipv4Addr,
        source_group_ids: &[String],
        service: &str,
    ) -> bool {
        let state = self.scopes.lock().unwrap();
        let Some(scope) = state.get(&(account.into(), region.into())) else {
            return false;
        };
        let Some(subnet) = scope.subnets.get(subnet_id) else {
            return false;
        };
        if !subnet.cidr.contains(&source_ip) || source_group_ids.is_empty() {
            return false;
        }
        let source_groups = source_group_ids
            .iter()
            .map(|id| scope.security_groups.get(id))
            .collect::<Option<Vec<_>>>();
        let Some(source_groups) = source_groups else {
            return false;
        };
        if source_groups
            .iter()
            .any(|group| group.vpc_id != subnet.vpc_id)
        {
            return false;
        }
        scope.vpc_endpoints.values().any(|ep| {
            if ep.vpc_id != subnet.vpc_id || ep.service != service {
                return false;
            }
            let destinations = match ep.kind {
                EndpointKind::Gateway => {
                    vec![Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("valid IPv4 default route")]
                }
                EndpointKind::Interface => ep
                    .subnet_ids
                    .iter()
                    .filter_map(|id| scope.subnets.get(id).map(|subnet| subnet.cidr))
                    .collect(),
            };
            if !source_groups.iter().any(|group| {
                group.egress.iter().any(|rule| {
                    (rule.protocol == "-1"
                        || (rule.protocol == "tcp"
                            && rule.from_port.is_some_and(|from| from <= 443)
                            && rule.to_port.is_some_and(|to| to >= 443)))
                        && destinations
                            .iter()
                            .any(|destination| contains_net(rule.cidr, *destination))
                })
            }) {
                return false;
            }
            match ep.kind {
                EndpointKind::Gateway => {
                    let table = scope
                        .route_tables
                        .values()
                        .find(|table| {
                            table.vpc_id == subnet.vpc_id
                                && table
                                    .associations
                                    .values()
                                    .any(|id| id.as_deref() == Some(subnet_id))
                        })
                        .or_else(|| {
                            scope
                                .route_tables
                                .values()
                                .find(|table| table.vpc_id == subnet.vpc_id && table.main)
                        });
                    table.is_some_and(|table| table.endpoint_routes.get(service) == Some(&ep.id))
                }
                EndpointKind::Interface => {
                    ep.private_dns
                        && ep.group_ids.iter().any(|id| {
                            scope.security_groups.get(id).is_some_and(|group| {
                                group.ingress.iter().any(|rule| {
                                    rule.cidr.contains(&source_ip)
                                        && (rule.protocol == "-1"
                                            || (rule.protocol == "tcp"
                                                && rule.from_port.is_some_and(|from| from <= 443)
                                                && rule.to_port.is_some_and(|to| to >= 443)))
                                })
                            })
                        })
                }
            }
        })
    }
}

impl Ec2Handler {
    pub(super) fn describe_prefix_lists(
        &self,
        region: &str,
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_describe("PrefixListId", &["prefix-list-id", "prefix-list-name"])?;
        let ids = input.indexed("PrefixListId")?;
        let filters = input.filters()?;
        let items = [("s3", "pl-00000001"), ("dynamodb", "pl-00000002")]
            .into_iter()
            .filter_map(|(service, id)| {
                let name = format!("com.amazonaws.{region}.{service}");
                if (!ids.is_empty() && !ids.iter().any(|value| value == id))
                    || !filters.iter().all(|(key, values)| {
                        let actual = match key.as_str() {
                            "prefix-list-id" => id,
                            "prefix-list-name" => name.as_str(),
                            _ => unreachable!("validated prefix list filter"),
                        };
                        values.iter().any(|value| value == actual)
                    })
                {
                    return None;
                }
                // Gateway endpoint traffic is routed internally, so no external AWS CIDRs
                // are represented by these local prefix lists.
                Some(format!("<item><prefixListId>{id}</prefixListId><prefixListName>{}</prefixListName><cidrSet/></item>", escape(&name)))
            })
            .collect::<String>();
        Ok(format!("<prefixListSet>{items}</prefixListSet>"))
    }
}

fn endpoint_kind(kind: EndpointKind) -> &'static str {
    match kind {
        EndpointKind::Gateway => "Gateway",
        EndpointKind::Interface => "Interface",
    }
}

fn endpoint_xml(ep: &VpcEndpoint) -> String {
    let routes = ep
        .route_table_ids
        .iter()
        .map(|id| format!("<item>{}</item>", escape(id)))
        .collect::<String>();
    let subnets = ep
        .subnet_ids
        .iter()
        .map(|id| format!("<item>{}</item>", escape(id)))
        .collect::<String>();
    let groups = ep
        .group_ids
        .iter()
        .map(|id| format!("<item><groupId>{}</groupId></item>", escape(id)))
        .collect::<String>();
    format!("<vpcEndpointId>{}</vpcEndpointId><vpcEndpointType>{}</vpcEndpointType><vpcId>{}</vpcId><serviceName>{}</serviceName><state>available</state><routeTableIdSet>{routes}</routeTableIdSet><subnetIdSet>{subnets}</subnetIdSet><groupSet>{groups}</groupSet><privateDnsEnabled>{}</privateDnsEnabled>", escape(&ep.id), endpoint_kind(ep.kind), escape(&ep.vpc_id), escape(&ep.service_name), ep.private_dns)
}

impl Ec2Handler {
    /// Whether AmazonProvidedDNS is enabled for the VPC containing a task ENI.
    pub fn vpc_dns_enabled(&self, account: &str, region: &str, eni_id: &str) -> bool {
        let Ok(state) = self.scopes.lock() else {
            return false;
        };
        let Some(scope) = state.get(&(account.to_owned(), region.to_owned())) else {
            return false;
        };
        let Some(eni) = scope.network_interfaces.get(eni_id) else {
            return false;
        };
        scope.vpc_dns.get(&eni.vpc_id).is_some_and(|dns| dns.0)
    }

    pub(super) fn modify_vpc_attribute(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&[
            "Action",
            "Version",
            "VpcId",
            "EnableDnsHostnames.Value",
            "EnableDnsSupport.Value",
            "EnableNetworkAddressUsageMetrics.Value",
            "DryRun",
        ])?;
        input.dry_run()?;
        let vpc = input.required("VpcId")?;
        let hostnames = input.one("EnableDnsHostnames.Value")?;
        let support = input.one("EnableDnsSupport.Value")?;
        let usage = input.one("EnableNetworkAddressUsageMetrics.Value")?;
        if [hostnames, support, usage]
            .iter()
            .filter(|value| value.is_some())
            .count()
            != 1
        {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Specify exactly one VPC attribute",
            ));
        }
        let value = match hostnames.or(support).or(usage) {
            Some("true") => true,
            Some("false") => false,
            _ => {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "DNS attribute must be boolean",
                ))
            }
        };
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        let dns = scope
            .vpc_dns
            .get_mut(vpc)
            .ok_or_else(|| Ec2Error::new("InvalidVpcID.NotFound", "The VPC does not exist"))?;
        if usage.is_some() {
            if value {
                return Err(Ec2Error::unsupported("EnableNetworkAddressUsageMetrics"));
            }
        } else if hostnames.is_some() {
            dns.1 = value;
        } else {
            dns.0 = value;
        }
        Ok("<return>true</return>".into())
    }

    pub(super) fn describe_vpc_attribute(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "VpcId", "Attribute", "DryRun"])?;
        input.dry_run()?;
        let vpc = input.required("VpcId")?;
        let attr = input.required("Attribute")?;
        let state = self.scopes.lock().unwrap();
        let dns = state
            .get(&key)
            .and_then(|scope| scope.vpc_dns.get(vpc))
            .ok_or_else(|| Ec2Error::new("InvalidVpcID.NotFound", "The VPC does not exist"))?;
        let value = match attr {
            "enableDnsSupport" => dns.0,
            "enableDnsHostnames" => dns.1,
            "enableNetworkAddressUsageMetrics" => false,
            _ => return Err(Ec2Error::unsupported(attr)),
        };
        Ok(format!(
            "<vpcId>{}</vpcId><{attr}><value>{value}</value></{attr}>",
            escape(vpc)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn endpoint_access_tracks_routes_private_dns_and_ingress() {
        let handler = Ec2Handler::default();
        async fn call(handler: &Ec2Handler, form: &str) -> String {
            let response = handler
                .handle(ServiceRequest {
                    method: axum::http::Method::POST,
                    uri: "/".parse().unwrap(),
                    headers: axum::http::HeaderMap::new(),
                    body: form.as_bytes().to_vec().into(),
                    account_id: "111".into(),
                    region: "us-east-1".into(),
                    request_id: "rid".into(),
                })
                .await;
            let status = response.status();
            let body = String::from_utf8(
                axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert_eq!(status, 200, "{body}");
            body
        }
        fn id<'a>(xml: &'a str, tag: &str) -> &'a str {
            xml.split_once(&format!("<{tag}>"))
                .unwrap()
                .1
                .split_once(&format!("</{tag}>"))
                .unwrap()
                .0
        }
        let vpc_xml = call(&handler, "Action=CreateVpc&CidrBlock=10.0.0.0%2F16").await;
        let vpc = id(&vpc_xml, "vpcId");
        let metrics = call(&handler, &format!("Action=DescribeVpcAttribute&VpcId={vpc}&Attribute=enableNetworkAddressUsageMetrics")).await;
        assert!(metrics.contains("<enableNetworkAddressUsageMetrics><value>false</value></enableNetworkAddressUsageMetrics>"));
        let disabled = call(&handler, &format!("Action=ModifyVpcAttribute&VpcId={vpc}&EnableNetworkAddressUsageMetrics.Value=false")).await;
        assert!(disabled.contains("<return>true</return>"));
        let unsupported = Input {
            fields: BTreeMap::from([
                ("VpcId".into(), vec![vpc.into()]),
                (
                    "EnableNetworkAddressUsageMetrics.Value".into(),
                    vec!["true".into()],
                ),
            ]),
        };
        assert!(handler
            .modify_vpc_attribute(("111".into(), "us-east-1".into()), &unsupported)
            .is_err());
        let subnet_xml = call(
            &handler,
            &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.0.1.0%2F24"),
        )
        .await;
        let subnet = id(&subnet_xml, "subnetId");
        let route_xml = call(&handler, &format!("Action=CreateRouteTable&VpcId={vpc}")).await;
        let route = id(&route_xml, "routeTableId");
        call(
            &handler,
            &format!("Action=AssociateRouteTable&RouteTableId={route}&SubnetId={subnet}"),
        )
        .await;
        let source = "10.0.1.4".parse().unwrap();
        let lambda_sg_xml = call(
            &handler,
            &format!(
                "Action=CreateSecurityGroup&VpcId={vpc}&GroupName=lambda&GroupDescription=lambda"
            ),
        )
        .await;
        let lambda_sg = id(&lambda_sg_xml, "groupId").to_owned();
        let lambda_groups = vec![lambda_sg.clone()];
        assert!(!handler.vpc_endpoint_access(
            "111",
            "us-east-1",
            subnet,
            source,
            &lambda_groups,
            "dynamodb"
        ));
        let gateway_request = format!("Action=CreateVpcEndpoint&VpcId={vpc}&ServiceName=com.amazonaws.us-east-1.dynamodb&VpcEndpointType=Gateway&RouteTableId.1={route}&PrivateDnsEnabled=false&ClientToken=terraform-test");
        let gateway_xml = call(&handler, &gateway_request).await;
        let gateway = id(&gateway_xml, "vpcEndpointId");
        let replay = call(&handler, &gateway_request).await;
        assert_eq!(id(&replay, "vpcEndpointId"), gateway);
        let mismatch = Input {
            fields: BTreeMap::from([
                ("VpcId".into(), vec![vpc.into()]),
                (
                    "ServiceName".into(),
                    vec!["com.amazonaws.us-east-1.s3".into()],
                ),
                ("RouteTableId.1".into(), vec![route.into()]),
                ("ClientToken".into(), vec!["terraform-test".into()]),
            ]),
        };
        assert!(handler
            .create_vpc_endpoint(("111".into(), "us-east-1".into()), "us-east-1", &mismatch)
            .is_err());
        assert!(handler.vpc_endpoint_access(
            "111",
            "us-east-1",
            subnet,
            source,
            &lambda_groups,
            "dynamodb"
        ));
        let lists = call(&handler, "Action=DescribePrefixLists&Filter.1.Name=prefix-list-name&Filter.1.Value.1=com.amazonaws.us-east-1.dynamodb").await;
        assert!(lists.contains("<prefixListId>pl-00000002</prefixListId>"));
        assert!(!lists.contains("<prefixListId>pl-00000001</prefixListId>"));
        call(&handler, &format!("Action=RevokeSecurityGroupEgress&GroupId={lambda_sg}&IpPermissions.1.IpProtocol=-1&IpPermissions.1.FromPort=0&IpPermissions.1.ToPort=0&IpPermissions.1.IpRanges.1.CidrIp=0.0.0.0%2F0")).await;
        let ipv6 = Input {
            fields: BTreeMap::from([
                ("GroupId".into(), vec![lambda_sg.clone()]),
                ("IpPermissions.1.IpProtocol".into(), vec!["-1".into()]),
                ("IpPermissions.1.FromPort".into(), vec!["0".into()]),
                ("IpPermissions.1.ToPort".into(), vec!["0".into()]),
                (
                    "IpPermissions.1.Ipv6Ranges.1.CidrIpv6".into(),
                    vec!["::/0".into()],
                ),
            ]),
        };
        assert_eq!(
            handler
                .revoke_security_group_egress(("111".into(), "us-east-1".into()), &ipv6)
                .unwrap_err()
                .code,
            "InvalidPermission.NotFound"
        );
        let denied = call(
            &handler,
            &format!("Action=DescribeSecurityGroups&GroupId.1={lambda_sg}"),
        )
        .await;
        assert!(denied.contains("<ipPermissionsEgress></ipPermissionsEgress>"));
        assert!(!handler.vpc_endpoint_access(
            "111",
            "us-east-1",
            subnet,
            source,
            &lambda_groups,
            "dynamodb"
        ));
        call(&handler, &format!("Action=AuthorizeSecurityGroupEgress&GroupId={lambda_sg}&IpProtocol=tcp&FromPort=443&ToPort=443&CidrIp=0.0.0.0%2F0")).await;
        assert!(handler.vpc_endpoint_access(
            "111",
            "us-east-1",
            subnet,
            source,
            &lambda_groups,
            "dynamodb"
        ));
        let routes = call(
            &handler,
            &format!("Action=DescribeRouteTables&RouteTableId.1={route}"),
        )
        .await;
        assert!(routes.contains(&format!("<vpcEndpointId>{gateway}</vpcEndpointId>")));
        call(
            &handler,
            &format!("Action=ModifyVpcAttribute&VpcId={vpc}&EnableDnsHostnames.Value=true"),
        )
        .await;
        let sg_xml = call(&handler, &format!("Action=CreateSecurityGroup&VpcId={vpc}&GroupName=endpoint&GroupDescription=endpoint")) .await;
        let sg = id(&sg_xml, "groupId");
        let no_dns = call(&handler, &format!("Action=CreateVpcEndpoint&VpcId={vpc}&ServiceName=com.amazonaws.us-east-1.ssm&VpcEndpointType=Interface&SubnetId.1={subnet}&SecurityGroupId.1={sg}&PrivateDnsEnabled=false")).await;
        assert!(no_dns.contains("<privateDnsEnabled>false</privateDnsEnabled>"));
        assert!(!handler.vpc_endpoint_access(
            "111",
            "us-east-1",
            subnet,
            source,
            &lambda_groups,
            "ssm"
        ));
        let interface_xml = call(&handler, &format!("Action=CreateVpcEndpoint&VpcId={vpc}&ServiceName=com.amazonaws.us-east-1.secretsmanager&VpcEndpointType=Interface&SubnetId.1={subnet}&SecurityGroupId.1={sg}&PrivateDnsEnabled=true")).await;
        let interface = id(&interface_xml, "vpcEndpointId");
        assert!(!handler.vpc_endpoint_access(
            "111",
            "us-east-1",
            subnet,
            source,
            &lambda_groups,
            "secretsmanager"
        ));
        call(&handler, &format!("Action=AuthorizeSecurityGroupIngress&GroupId={sg}&IpProtocol=tcp&FromPort=443&ToPort=443&CidrIp=10.0.0.0%2F16")).await;
        assert!(handler.vpc_endpoint_access(
            "111",
            "us-east-1",
            subnet,
            source,
            &lambda_groups,
            "secretsmanager"
        ));
        call(
            &handler,
            &format!(
                "Action=DeleteVpcEndpoints&VpcEndpointId.1={gateway}&VpcEndpointId.2={interface}"
            ),
        )
        .await;
        assert!(!handler.vpc_endpoint_access(
            "111",
            "us-east-1",
            subnet,
            source,
            &lambda_groups,
            "dynamodb"
        ));
        assert!(!handler.vpc_endpoint_access(
            "111",
            "us-east-1",
            subnet,
            source,
            &lambda_groups,
            "secretsmanager"
        ));
    }
}
