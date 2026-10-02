use super::*;

fn route_table_for_subnet<'a>(scope: &'a ScopeState, subnet: &Subnet) -> Option<&'a RouteTable> {
    scope
        .route_tables
        .values()
        .find(|table| {
            table.vpc_id == subnet.vpc_id
                && table
                    .associations
                    .values()
                    .any(|id| id.as_deref() == Some(&subnet.id))
        })
        .or_else(|| {
            scope
                .route_tables
                .values()
                .find(|table| table.vpc_id == subnet.vpc_id && table.main)
        })
}

fn active_route(table: &RouteTable, destination: Ipv4Addr) -> Option<&RouteTarget> {
    table
        .routes
        .iter()
        .filter(|(cidr, _)| cidr.contains(&destination))
        .max_by_key(|(cidr, _)| cidr.prefix_len())
        .map(|(_, target)| target)
}

fn internet_gateway_xml(gateway: &InternetGateway) -> String {
    let attachment = gateway
        .vpc_id
        .as_ref()
        .map(|id| {
            format!(
                "<item><vpcId>{}</vpcId><state>available</state></item>",
                escape(id)
            )
        })
        .unwrap_or_default();
    format!("<internetGatewayId>{}</internetGatewayId><attachmentSet>{attachment}</attachmentSet><tagSet/>", escape(&gateway.id))
}

fn nat_gateway_xml(gateway: &NatGateway, scope: &ScopeState) -> String {
    let subnet = gateway
        .subnet_id
        .as_ref()
        .map(|id| format!("<subnetId>{}</subnetId>", escape(id)))
        .unwrap_or_default();
    let address = gateway
        .allocation_id
        .as_ref()
        .and_then(|id| scope.elastic_ips.get(id))
        .map(|eip| {
            format!(
                "<item><allocationId>{}</allocationId><publicIp>{}</publicIp>{}</item>",
                escape(&eip.allocation_id),
                eip.public_ip,
                gateway
                    .private_ip
                    .map(|ip| format!("<privateIp>{ip}</privateIp>"))
                    .unwrap_or_default()
            )
        })
        .unwrap_or_default();
    let mode = if gateway.regional {
        "regional"
    } else {
        "zonal"
    };
    format!("<natGatewayId>{}</natGatewayId><vpcId>{}</vpcId>{subnet}<state>available</state><connectivityType>public</connectivityType><availabilityMode>{mode}</availabilityMode><natGatewayAddressSet>{address}</natGatewayAddressSet><tagSet/>", escape(&gateway.id), escape(&gateway.vpc_id))
}

impl Ec2Handler {
    pub(super) fn create_internet_gateway(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun"])?;
        input.dry_run()?;
        let gateway = InternetGateway {
            id: resource_id("igw"),
            vpc_id: None,
        };
        let xml = internet_gateway_xml(&gateway);
        self.scopes
            .lock()
            .unwrap()
            .entry(key)
            .or_default()
            .internet_gateways
            .insert(gateway.id.clone(), gateway);
        Ok(format!("<internetGateway>{xml}</internetGateway>"))
    }

    pub(super) fn describe_internet_gateways(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_describe(
            "InternetGatewayId",
            &[
                "internet-gateway-id",
                "attachment.vpc-id",
                "attachment.state",
            ],
        )?;
        let ids = input.indexed("InternetGatewayId")?;
        let filters = input.filters()?;
        let state = self.scopes.lock().unwrap();
        let scope = state.get(&key);
        for id in &ids {
            if !scope.is_some_and(|s| s.internet_gateways.contains_key(id)) {
                return Err(Ec2Error::new(
                    "InvalidInternetGatewayID.NotFound",
                    format!("The internet gateway ID '{id}' does not exist"),
                ));
            }
        }
        let body = scope
            .into_iter()
            .flat_map(|s| s.internet_gateways.values())
            .filter(|g| {
                (ids.is_empty() || ids.contains(&g.id))
                    && filters.iter().all(|(name, values)| match name.as_str() {
                        "internet-gateway-id" => values.contains(&g.id),
                        "attachment.vpc-id" => {
                            g.vpc_id.as_ref().is_some_and(|id| values.contains(id))
                        }
                        "attachment.state" => {
                            g.vpc_id.is_some() && values.iter().any(|v| v == "available")
                        }
                        _ => false,
                    })
            })
            .map(|g| format!("<item>{}</item>", internet_gateway_xml(g)))
            .collect::<String>();
        Ok(format!("<internetGatewaySet>{body}</internetGatewaySet>"))
    }

    pub(super) fn attach_internet_gateway(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "InternetGatewayId", "VpcId"])?;
        input.dry_run()?;
        let id = input.required("InternetGatewayId")?;
        let vpc_id = input.required("VpcId")?;
        let mut states = self.scopes.lock().unwrap();
        let scope = states.entry(key).or_default();
        if !scope.vpcs.contains_key(vpc_id) {
            return Err(Ec2Error::new(
                "InvalidVpcID.NotFound",
                format!("The vpc ID '{vpc_id}' does not exist"),
            ));
        }
        if scope
            .internet_gateways
            .values()
            .any(|g| g.vpc_id.as_deref() == Some(vpc_id))
        {
            return Err(Ec2Error::new(
                "Resource.AlreadyAssociated",
                "The VPC already has an internet gateway",
            ));
        }
        let gateway = scope.internet_gateways.get_mut(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidInternetGatewayID.NotFound",
                format!("The internet gateway ID '{id}' does not exist"),
            )
        })?;
        if gateway.vpc_id.is_some() {
            return Err(Ec2Error::new(
                "Resource.AlreadyAssociated",
                "The internet gateway is already attached",
            ));
        }
        gateway.vpc_id = Some(vpc_id.into());
        Ok("<return>true</return>".into())
    }

    pub(super) fn detach_internet_gateway(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "InternetGatewayId", "VpcId"])?;
        input.dry_run()?;
        let id = input.required("InternetGatewayId")?;
        let vpc_id = input.required("VpcId")?;
        let mut states = self.scopes.lock().unwrap();
        let scope = states.entry(key).or_default();
        let gateway = scope.internet_gateways.get(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidInternetGatewayID.NotFound",
                format!("The internet gateway ID '{id}' does not exist"),
            )
        })?;
        if gateway.vpc_id.as_deref() != Some(vpc_id) {
            return Err(Ec2Error::new(
                "Gateway.NotAttached",
                "The internet gateway is not attached to the VPC",
            ));
        }
        if scope.route_tables.values().any(|t| t.vpc_id == vpc_id && t.routes.values().any(|target| matches!(target, RouteTarget::InternetGateway(route_id) if route_id == id))) { return Err(Ec2Error::new("DependencyViolation", "The internet gateway is a route target")); }
        if scope
            .nat_gateways
            .values()
            .any(|nat| nat.vpc_id == vpc_id && nat.regional)
        {
            return Err(Ec2Error::new(
                "DependencyViolation",
                "A regional NAT gateway depends on the internet gateway",
            ));
        }
        scope.internet_gateways.get_mut(id).unwrap().vpc_id = None;
        Ok("<return>true</return>".into())
    }

    pub(super) fn delete_internet_gateway(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "InternetGatewayId"])?;
        input.dry_run()?;
        let id = input.required("InternetGatewayId")?;
        let mut states = self.scopes.lock().unwrap();
        let scope = states.entry(key).or_default();
        let gateway = scope.internet_gateways.get(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidInternetGatewayID.NotFound",
                format!("The internet gateway ID '{id}' does not exist"),
            )
        })?;
        if gateway.vpc_id.is_some() {
            return Err(Ec2Error::new(
                "DependencyViolation",
                "The internet gateway is attached to a VPC",
            ));
        }
        scope.internet_gateways.remove(id);
        Ok("<return>true</return>".into())
    }

    pub(super) fn allocate_address(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "Domain"])?;
        input.dry_run()?;
        if input.one("Domain")?.is_some_and(|domain| domain != "vpc") {
            return Err(Ec2Error::unsupported("Domain"));
        }
        let id = resource_id("eipalloc");
        let bytes = Uuid::new_v4().into_bytes();
        let ip = Ipv4Addr::new(198, 51, 100, bytes[0].max(1));
        self.scopes
            .lock()
            .unwrap()
            .entry(key)
            .or_default()
            .elastic_ips
            .insert(
                id.clone(),
                ElasticIp {
                    allocation_id: id.clone(),
                    public_ip: ip,
                    nat_gateway_id: None,
                },
            );
        Ok(format!(
            "<allocationId>{id}</allocationId><publicIp>{ip}</publicIp><domain>vpc</domain>"
        ))
    }

    pub(super) fn describe_addresses(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_describe("AllocationId", &["allocation-id", "public-ip", "domain"])?;
        let ids = input.indexed("AllocationId")?;
        let filters = input.filters()?;
        let states = self.scopes.lock().unwrap();
        let scope = states.get(&key);
        for id in &ids {
            if !scope.is_some_and(|s| s.elastic_ips.contains_key(id)) {
                return Err(Ec2Error::new(
                    "InvalidAllocationID.NotFound",
                    format!("The allocation ID '{id}' does not exist"),
                ));
            }
        }
        let body = scope.into_iter().flat_map(|s| s.elastic_ips.values()).filter(|eip| (ids.is_empty() || ids.contains(&eip.allocation_id)) && filters.iter().all(|(name, vals)| match name.as_str() { "allocation-id" => vals.contains(&eip.allocation_id), "public-ip" => vals.contains(&eip.public_ip.to_string()), "domain" => vals.iter().any(|v| v == "vpc"), _ => false })).map(|eip| format!("<item><allocationId>{}</allocationId><publicIp>{}</publicIp><domain>vpc</domain></item>", escape(&eip.allocation_id), eip.public_ip)).collect::<String>();
        Ok(format!("<addressesSet>{body}</addressesSet>"))
    }

    pub(super) fn describe_addresses_attribute(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        for name in input.fields.keys() {
            if [
                "Action",
                "Version",
                "DryRun",
                "Attribute",
                "MaxResults",
                "NextToken",
            ]
            .contains(&name.as_str())
                || indexed_key(name, "AllocationId").is_some()
            {
                continue;
            }
            return Err(Ec2Error::unsupported(name));
        }
        input.dry_run()?;
        if input
            .one("Attribute")?
            .is_some_and(|attribute| attribute != "domain-name")
        {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Attribute must be domain-name",
            ));
        }
        let ids = input.indexed("AllocationId")?;
        let limit = input
            .one("MaxResults")?
            .map(|value| {
                value
                    .parse::<usize>()
                    .ok()
                    .filter(|n| (1..=1000).contains(n))
                    .ok_or_else(|| {
                        Ec2Error::new(
                            "InvalidParameterValue",
                            "MaxResults must be between 1 and 1000",
                        )
                    })
            })
            .transpose()?
            .unwrap_or(1000);
        let offset = input
            .one("NextToken")?
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| Ec2Error::new("InvalidNextToken", "Invalid pagination token"))
            })
            .transpose()?
            .unwrap_or(0);
        let states = self.scopes.lock().unwrap();
        let scope = states.get(&key);
        for id in &ids {
            if !scope.is_some_and(|s| s.elastic_ips.contains_key(id)) {
                return Err(Ec2Error::new(
                    "InvalidAllocationID.NotFound",
                    format!("The allocation ID '{id}' does not exist"),
                ));
            }
        }
        let addresses = scope
            .into_iter()
            .flat_map(|s| s.elastic_ips.values())
            .filter(|eip| ids.is_empty() || ids.contains(&eip.allocation_id))
            .collect::<Vec<_>>();
        if offset > addresses.len() {
            return Err(Ec2Error::new(
                "InvalidNextToken",
                "Invalid pagination token",
            ));
        }
        let body = addresses
            .iter()
            .skip(offset)
            .take(limit)
            .map(|eip| {
                format!(
                    "<item><allocationId>{}</allocationId><publicIp>{}</publicIp></item>",
                    escape(&eip.allocation_id),
                    eip.public_ip
                )
            })
            .collect::<String>();
        let end = offset.saturating_add(limit);
        let next = if end < addresses.len() {
            format!("<nextToken>{end}</nextToken>")
        } else {
            String::new()
        };
        Ok(format!("<addressSet>{body}</addressSet>{next}"))
    }

    pub(super) fn release_address(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "AllocationId"])?;
        input.dry_run()?;
        let id = input.required("AllocationId")?;
        let mut states = self.scopes.lock().unwrap();
        let scope = states.entry(key).or_default();
        let eip = scope.elastic_ips.get(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidAllocationID.NotFound",
                format!("The allocation ID '{id}' does not exist"),
            )
        })?;
        if eip.nat_gateway_id.is_some() {
            return Err(Ec2Error::new(
                "InvalidIPAddress.InUse",
                "The address is associated with a NAT gateway",
            ));
        }
        scope.elastic_ips.remove(id);
        Ok("<return>true</return>".into())
    }

    pub(super) fn create_nat_gateway(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&[
            "Action",
            "Version",
            "DryRun",
            "AvailabilityMode",
            "ConnectivityType",
            "SubnetId",
            "VpcId",
            "AllocationId",
            "ClientToken",
        ])?;
        input.dry_run()?;
        let regional = match input.one("AvailabilityMode")?.unwrap_or("zonal") {
            "regional" => true,
            "zonal" => false,
            _ => {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "AvailabilityMode must be zonal or regional",
                ))
            }
        };
        if input
            .one("ConnectivityType")?
            .is_some_and(|kind| kind != "public")
        {
            return Err(Ec2Error::unsupported("ConnectivityType"));
        }
        let token = input.one("ClientToken")?;
        if token.is_some_and(|value| value.is_empty() || value.len() > 64 || !value.is_ascii()) {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "ClientToken must be 1-64 ASCII characters",
            ));
        }
        let params = input
            .fields
            .iter()
            .filter(|(name, _)| {
                !["Action", "Version", "DryRun", "ClientToken"].contains(&name.as_str())
            })
            .map(|(name, value)| (name.clone(), value[0].clone()))
            .collect::<BTreeMap<_, _>>();
        let mut states = self.scopes.lock().unwrap();
        let scope = states.entry(key).or_default();
        if let Some(token) = token {
            if let Some((previous, id)) = scope.nat_gateway_tokens.get(token) {
                if previous != &params {
                    return Err(Ec2Error::new(
                        "IdempotentParameterMismatch",
                        "ClientToken was already used with different parameters",
                    ));
                }
                if let Some(gateway) = scope.nat_gateways.get(id) {
                    return Ok(format!(
                        "<natGateway>{}</natGateway><clientToken>{}</clientToken>",
                        nat_gateway_xml(gateway, scope),
                        escape(token)
                    ));
                }
            }
        }
        let (vpc_id, subnet_id, allocation_id, private_ip) = if regional {
            if input.one("SubnetId")?.is_some() || input.one("AllocationId")?.is_some() {
                return Err(Ec2Error::new(
                    "InvalidParameterCombination",
                    "Regional NAT gateways use VpcId and automatic addresses",
                ));
            }
            let id = input.required("VpcId")?;
            if !scope.vpcs.contains_key(id) {
                return Err(Ec2Error::new(
                    "InvalidVpcID.NotFound",
                    format!("The vpc ID '{id}' does not exist"),
                ));
            }
            if !scope
                .internet_gateways
                .values()
                .any(|g| g.vpc_id.as_deref() == Some(id))
            {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "A regional NAT gateway requires an attached internet gateway",
                ));
            }
            (id.to_owned(), None, None, None)
        } else {
            if input.one("VpcId")?.is_some() {
                return Err(Ec2Error::new(
                    "InvalidParameterCombination",
                    "Zonal NAT gateways use SubnetId",
                ));
            }
            let subnet_id = input.required("SubnetId")?;
            let subnet = scope.subnets.get(subnet_id).ok_or_else(|| {
                Ec2Error::new(
                    "InvalidSubnetID.NotFound",
                    format!("The subnet ID '{subnet_id}' does not exist"),
                )
            })?;
            let allocation_id = input.required("AllocationId")?;
            let eip = scope.elastic_ips.get(allocation_id).ok_or_else(|| {
                Ec2Error::new(
                    "InvalidAllocationID.NotFound",
                    format!("The allocation ID '{allocation_id}' does not exist"),
                )
            })?;
            if eip.nat_gateway_id.is_some() {
                return Err(Ec2Error::new(
                    "Resource.AlreadyAssociated",
                    "The Elastic IP is already associated",
                ));
            }
            let private_ip = subnet
                .cidr
                .hosts()
                .skip(3)
                .find(|ip| {
                    !scope
                        .network_interfaces
                        .values()
                        .any(|eni| eni.subnet_id == subnet_id && eni.private_ip == *ip)
                        && !scope.nat_gateways.values().any(|nat| {
                            nat.subnet_id.as_deref() == Some(subnet_id)
                                && nat.private_ip == Some(*ip)
                        })
                })
                .ok_or_else(|| {
                    Ec2Error::new(
                        "InsufficientFreeAddressesInSubnet",
                        "The subnet has no free addresses",
                    )
                })?;
            (
                subnet.vpc_id.clone(),
                Some(subnet_id.to_owned()),
                Some(allocation_id.to_owned()),
                Some(private_ip),
            )
        };
        let gateway = NatGateway {
            id: resource_id("nat"),
            vpc_id,
            subnet_id,
            allocation_id: allocation_id.clone(),
            private_ip,
            regional,
        };
        if let Some(id) = allocation_id {
            scope.elastic_ips.get_mut(&id).unwrap().nat_gateway_id = Some(gateway.id.clone());
        }
        let xml = nat_gateway_xml(&gateway, scope);
        if let Some(token) = token {
            scope
                .nat_gateway_tokens
                .insert(token.into(), (params, gateway.id.clone()));
        }
        scope.nat_gateways.insert(gateway.id.clone(), gateway);
        let token_xml = token
            .map(|value| format!("<clientToken>{}</clientToken>", escape(value)))
            .unwrap_or_default();
        Ok(format!("<natGateway>{xml}</natGateway>{token_xml}"))
    }

    pub(super) fn describe_nat_gateways(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_describe(
            "NatGatewayId",
            &["nat-gateway-id", "vpc-id", "subnet-id", "state"],
        )?;
        let ids = input.indexed("NatGatewayId")?;
        let filters = input.filters()?;
        let states = self.scopes.lock().unwrap();
        let scope = states.get(&key);
        for id in &ids {
            if !scope.is_some_and(|s| s.nat_gateways.contains_key(id)) {
                return Err(Ec2Error::new(
                    "NatGatewayNotFound",
                    format!("The NAT gateway ID '{id}' does not exist"),
                ));
            }
        }
        let body = scope
            .into_iter()
            .flat_map(|s| s.nat_gateways.values().map(move |g| (g, s)))
            .filter(|(g, _)| {
                (ids.is_empty() || ids.contains(&g.id))
                    && filters.iter().all(|(name, vals)| match name.as_str() {
                        "nat-gateway-id" => vals.contains(&g.id),
                        "vpc-id" => vals.contains(&g.vpc_id),
                        "subnet-id" => g.subnet_id.as_ref().is_some_and(|id| vals.contains(id)),
                        "state" => vals.iter().any(|v| v == "available"),
                        _ => false,
                    })
            })
            .map(|(g, s)| format!("<item>{}</item>", nat_gateway_xml(g, s)))
            .collect::<String>();
        Ok(format!("<natGatewaySet>{body}</natGatewaySet>"))
    }

    pub(super) fn delete_nat_gateway(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "NatGatewayId"])?;
        input.dry_run()?;
        let id = input.required("NatGatewayId")?;
        let mut states = self.scopes.lock().unwrap();
        let scope = states.entry(key).or_default();
        if !scope.nat_gateways.contains_key(id) {
            return Err(Ec2Error::new(
                "NatGatewayNotFound",
                format!("The NAT gateway ID '{id}' does not exist"),
            ));
        }
        for table in scope.route_tables.values_mut() {
            for target in table.routes.values_mut() {
                if matches!(target, RouteTarget::NatGateway(route_id) if route_id == id) {
                    *target = RouteTarget::BlackholeNatGateway(id.into());
                }
            }
        }
        let gateway = scope.nat_gateways.remove(id).unwrap();
        scope
            .nat_gateway_tokens
            .retain(|_, (_, gateway_id)| gateway_id != id);
        if let Some(eip_id) = gateway.allocation_id {
            scope.elastic_ips.get_mut(&eip_id).unwrap().nat_gateway_id = None;
        }
        Ok(format!("<natGatewayId>{}</natGatewayId>", escape(id)))
    }

    fn public_access(
        &self,
        account: &str,
        region: &str,
        eni_id: &str,
        destination: Ipv4Addr,
        protocol: &str,
        port: u16,
    ) -> bool {
        let [a, b, _, _] = destination.octets();
        if port == 0
            || destination.is_private()
            || destination.is_loopback()
            || destination.is_link_local()
            || destination.is_multicast()
            || destination.is_broadcast()
            || destination.is_unspecified()
            || a == 0
            || a >= 240
            || (a == 100 && (64..=127).contains(&b))
        {
            return false;
        }
        let states = self.scopes.lock().unwrap();
        let Some(scope) = states.get(&(account.to_owned(), region.to_owned())) else {
            return false;
        };
        let Some(eni) = scope.network_interfaces.get(eni_id) else {
            return false;
        };
        let Some(subnet) = scope.subnets.get(&eni.subnet_id) else {
            return false;
        };
        if subnet.vpc_id != eni.vpc_id {
            return false;
        }
        let egress_allowed = eni.group_ids.iter().any(|id| {
            scope.security_groups.get(id).is_some_and(|group| {
                group.vpc_id == eni.vpc_id
                    && group.egress.iter().any(|rule| {
                        rule.cidr.contains(&destination)
                            && (rule.protocol == "-1"
                                || (rule.protocol == protocol
                                    && rule.from_port.is_some_and(|from| from <= port)
                                    && rule.to_port.is_some_and(|to| port <= to)))
                    })
            })
        });
        if !egress_allowed {
            return false;
        }
        let Some(RouteTarget::NatGateway(nat_id)) = route_table_for_subnet(scope, subnet)
            .and_then(|table| active_route(table, destination))
        else {
            return false;
        };
        let Some(nat) = scope.nat_gateways.get(nat_id) else {
            return false;
        };
        if nat.vpc_id != eni.vpc_id {
            return false;
        }
        let igw = scope
            .internet_gateways
            .values()
            .find(|g| g.vpc_id.as_deref() == Some(&nat.vpc_id));
        if igw.is_none() {
            return false;
        }
        if nat.regional {
            return true;
        }
        if !nat.allocation_id.as_ref().is_some_and(|id| {
            scope
                .elastic_ips
                .get(id)
                .is_some_and(|eip| eip.nat_gateway_id.as_deref() == Some(&nat.id))
        }) {
            return false;
        }
        nat.subnet_id.as_ref().and_then(|id| scope.subnets.get(id)).and_then(|subnet| route_table_for_subnet(scope, subnet)).and_then(|table| active_route(table, destination)).is_some_and(|target| matches!(target, RouteTarget::InternetGateway(id) if igw.is_some_and(|g| g.id == *id)))
    }

    pub fn public_nat_route(&self, account: &str, region: &str, eni_id: &str) -> bool {
        let states = self.scopes.lock().unwrap();
        let Some(scope) = states.get(&(account.to_owned(), region.to_owned())) else {
            return false;
        };
        let Some(eni) = scope.network_interfaces.get(eni_id) else {
            return false;
        };
        let Some(subnet) = scope.subnets.get(&eni.subnet_id) else {
            return false;
        };
        if subnet.vpc_id != eni.vpc_id {
            return false;
        }
        let default = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("valid default route");
        let Some(RouteTarget::NatGateway(id)) =
            route_table_for_subnet(scope, subnet).and_then(|table| table.routes.get(&default))
        else {
            return false;
        };
        let Some(nat) = scope.nat_gateways.get(id) else {
            return false;
        };
        if nat.vpc_id != eni.vpc_id {
            return false;
        }
        let Some(igw) = scope
            .internet_gateways
            .values()
            .find(|gateway| gateway.vpc_id.as_deref() == Some(&nat.vpc_id))
        else {
            return false;
        };
        if nat.regional {
            return true;
        }
        if !nat.allocation_id.as_ref().is_some_and(|id| {
            scope
                .elastic_ips
                .get(id)
                .is_some_and(|eip| eip.nat_gateway_id.as_deref() == Some(&nat.id))
        }) {
            return false;
        }
        nat.subnet_id
            .as_ref()
            .and_then(|id| scope.subnets.get(id))
            .and_then(|subnet| route_table_for_subnet(scope, subnet))
            .and_then(|table| table.routes.get(&default))
            .is_some_and(
                |target| matches!(target, RouteTarget::InternetGateway(id) if id == &igw.id),
            )
    }

    pub fn public_tcp_access(
        &self,
        account: &str,
        region: &str,
        eni_id: &str,
        destination: Ipv4Addr,
        port: u16,
    ) -> bool {
        self.public_access(account, region, eni_id, destination, "tcp", port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn describe_addresses_attribute_matches_ec2_query_and_paginates() {
        use axum::body::to_bytes;
        async fn query(h: &Ec2Handler, form: &str) -> (u16, String) {
            let request = ServiceRequest {
                method: axum::http::Method::POST,
                uri: "/".parse().unwrap(),
                headers: axum::http::HeaderMap::new(),
                body: form.to_owned().into(),
                account_id: "111".into(),
                region: "us-east-1".into(),
                request_id: "rid".into(),
            };
            let response = h.handle(request).await;
            let status = response.status().as_u16();
            let body = String::from_utf8(
                to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            (status, body)
        }
        let h = Ec2Handler::default();
        let (_, first) = query(&h, "Action=AllocateAddress&Domain=vpc").await;
        let id = first
            .split("<allocationId>")
            .nth(1)
            .unwrap()
            .split("</allocationId>")
            .next()
            .unwrap();
        let ip = first
            .split("<publicIp>")
            .nth(1)
            .unwrap()
            .split("</publicIp>")
            .next()
            .unwrap();
        let (_, second) = query(&h, "Action=AllocateAddress&Domain=vpc").await;
        let second_id = second
            .split("<allocationId>")
            .nth(1)
            .unwrap()
            .split("</allocationId>")
            .next()
            .unwrap();
        let (status, body) = query(
            &h,
            &format!("Action=DescribeAddressesAttribute&AllocationId.1={id}&Attribute=domain-name"),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("<DescribeAddressesAttributeResponse"));
        assert!(body.contains(&format!("<addressSet><item><allocationId>{id}</allocationId><publicIp>{ip}</publicIp></item></addressSet>")));
        assert!(!body.contains("<ptrRecord>"));
        assert!(!body.contains(second_id));
        let (_, page) = query(&h, "Action=DescribeAddressesAttribute&MaxResults=1").await;
        assert!(page.contains("<nextToken>1</nextToken>"));
        let (_, last) = query(
            &h,
            "Action=DescribeAddressesAttribute&MaxResults=1&NextToken=1",
        )
        .await;
        assert!(last.contains("<addressSet><item>"));
        assert!(!last.contains("<nextToken>"));
        let (status, body) = query(
            &h,
            "Action=DescribeAddressesAttribute&AllocationId.1=eipalloc-missing",
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("InvalidAllocationID.NotFound"));
        let (status, body) = query(&h, "Action=DescribeAddressesAttribute&MaxResults=0").await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("InvalidParameterValue"));
    }

    #[test]
    fn public_nat_route_requires_default_routes_and_active_dependencies() {
        let h = Ec2Handler::default();
        let destination = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();
        let private_cidr = "10.1.1.0/24".parse().unwrap();
        let public_cidr = "10.1.2.0/24".parse().unwrap();
        let key = ("111".to_owned(), "us-east-1".to_owned());
        let mut states = h.scopes.lock().unwrap();
        let scope = states.entry(key).or_default();
        for (id, cidr) in [
            ("subnet-private", private_cidr),
            ("subnet-public", public_cidr),
        ] {
            scope.subnets.insert(
                id.into(),
                Subnet {
                    id: id.into(),
                    vpc_id: "vpc-1".into(),
                    cidr,
                    zone: "us-east-1a".into(),
                    owner: "111".into(),
                    guard: Arc::new(()),
                },
            );
        }
        scope.network_interfaces.insert(
            "eni-1".into(),
            NetworkInterface {
                id: "eni-1".into(),
                subnet_id: "subnet-private".into(),
                vpc_id: "vpc-1".into(),
                zone: "us-east-1a".into(),
                private_ip: "10.1.1.4".parse().unwrap(),
                description: String::new(),
                owner: "111".into(),
                group_ids: Vec::new(),
            },
        );
        for (id, subnet, cidr) in [
            ("rtb-private", "subnet-private", private_cidr),
            ("rtb-public", "subnet-public", public_cidr),
        ] {
            scope.route_tables.insert(
                id.into(),
                RouteTable {
                    id: id.into(),
                    vpc_id: "vpc-1".into(),
                    owner: "111".into(),
                    main: false,
                    routes: BTreeMap::from([(cidr, RouteTarget::Local)]),
                    endpoint_routes: BTreeMap::new(),
                    associations: BTreeMap::from([(format!("assoc-{id}"), Some(subnet.into()))]),
                },
            );
        }
        scope.internet_gateways.insert(
            "igw-1".into(),
            InternetGateway {
                id: "igw-1".into(),
                vpc_id: Some("vpc-1".into()),
            },
        );
        scope.elastic_ips.insert(
            "eipalloc-1".into(),
            ElasticIp {
                allocation_id: "eipalloc-1".into(),
                public_ip: "198.51.100.1".parse().unwrap(),
                nat_gateway_id: Some("nat-1".into()),
            },
        );
        scope.nat_gateways.insert(
            "nat-1".into(),
            NatGateway {
                id: "nat-1".into(),
                vpc_id: "vpc-1".into(),
                subnet_id: Some("subnet-public".into()),
                allocation_id: Some("eipalloc-1".into()),
                private_ip: Some("10.1.2.4".parse().unwrap()),
                regional: false,
            },
        );
        drop(states);
        let ready = || h.public_nat_route("111", "us-east-1", "eni-1");
        assert!(!ready());
        {
            let mut states = h.scopes.lock().unwrap();
            let scope = states.get_mut(&("111".into(), "us-east-1".into())).unwrap();
            scope
                .route_tables
                .get_mut("rtb-private")
                .unwrap()
                .routes
                .insert(destination, RouteTarget::NatGateway("nat-1".into()));
        }
        assert!(!ready());
        {
            let mut states = h.scopes.lock().unwrap();
            let scope = states.get_mut(&("111".into(), "us-east-1".into())).unwrap();
            scope
                .route_tables
                .get_mut("rtb-public")
                .unwrap()
                .routes
                .insert(destination, RouteTarget::InternetGateway("igw-1".into()));
        }
        assert!(ready());
        {
            let mut states = h.scopes.lock().unwrap();
            let scope = states.get_mut(&("111".into(), "us-east-1".into())).unwrap();
            scope
                .elastic_ips
                .get_mut("eipalloc-1")
                .unwrap()
                .nat_gateway_id = None;
        }
        assert!(!ready());
    }
}
