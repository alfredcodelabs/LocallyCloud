use super::*;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
    // Records from 0.1.2 lack both fields; restore allocates the missing interface ENIs.
    #[serde(default)]
    pub(super) network_interface_ids: Vec<String>,
    #[serde(default = "default_endpoint_policy")]
    pub(super) policy_document: String,
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) enum EndpointKind {
    Gateway,
    Interface,
}

const DEFAULT_ENDPOINT_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}"#;

fn default_endpoint_policy() -> String {
    DEFAULT_ENDPOINT_POLICY.into()
}

pub(super) fn endpoint_policy(document: Option<&str>) -> Result<String, Ec2Error> {
    let document = document.unwrap_or(DEFAULT_ENDPOINT_POLICY);
    if document.len() > 20_480 {
        return Err(Ec2Error::new(
            "InvalidPolicyDocument",
            "Endpoint policy exceeds 20480 bytes",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(document).map_err(|_| {
        Ec2Error::new(
            "InvalidPolicyDocument",
            "Endpoint policy must be valid JSON",
        )
    })?;
    let statements = value
        .get("Statement")
        .filter(|statements| statements.is_object() || statements.is_array());
    if !value.is_object() || statements.is_none() {
        return Err(Ec2Error::new(
            "InvalidPolicyDocument",
            "Endpoint policy requires Statement",
        ));
    }
    Ok(document.into())
}

pub(super) fn endpoint_enis(
    scope: &ScopeState,
    account: &str,
    vpc_id: &str,
    subnet_ids: &[String],
    groups: &[String],
) -> Result<Vec<NetworkInterface>, Ec2Error> {
    let mut zones = std::collections::HashSet::new();
    let mut enis = Vec::with_capacity(subnet_ids.len());
    for subnet_id in subnet_ids {
        let subnet = scope
            .subnets
            .get(subnet_id)
            .filter(|subnet| subnet.vpc_id == vpc_id)
            .ok_or_else(|| {
                Ec2Error::new(
                    "InvalidSubnetID.NotFound",
                    "Endpoint subnet is outside the VPC",
                )
            })?;
        if !zones.insert(subnet.zone.as_str()) {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "An interface endpoint supports one subnet per Availability Zone",
            ));
        }
        let ip = first_available_private_ip(
            subnet.cidr,
            scope
                .network_interfaces
                .values()
                .filter(|eni| eni.vpc_id == vpc_id)
                .map(|eni| eni.private_ip),
        )
        .ok_or_else(|| {
            Ec2Error::new(
                "InsufficientFreeAddressesInSubnet",
                "Endpoint subnet has no available private addresses",
            )
        })?;
        enis.push(NetworkInterface {
            id: resource_id("eni"),
            subnet_id: subnet.id.clone(),
            vpc_id: vpc_id.into(),
            zone: subnet.zone.clone(),
            private_ip: ip,
            description: "VPC Endpoint Interface".into(),
            owner: account.into(),
            group_ids: groups.to_vec(),
        });
    }
    Ok(enis)
}

fn endpoint_dns_name(endpoint: &VpcEndpoint, zone: Option<&str>) -> String {
    let region = endpoint
        .service_name
        .strip_prefix("com.amazonaws.")
        .and_then(|value| value.split_once('.'))
        .map(|(region, _)| region)
        .unwrap_or_default();
    let opaque = endpoint.id.strip_prefix("vpce-").unwrap_or(&endpoint.id);
    let suffix = match zone {
        Some(zone) => format!("-{zone}"),
        None => String::new(),
    };
    format!(
        "{}-{}{suffix}.{}.{region}.vpce.amazonaws.com",
        endpoint.id, opaque, endpoint.service
    )
}

fn updated_ids(
    current: &[String],
    add: &[String],
    remove: &[String],
) -> Result<Vec<String>, Ec2Error> {
    let unique =
        |ids: &[String]| ids.iter().collect::<std::collections::HashSet<_>>().len() == ids.len();
    if !unique(add)
        || !unique(remove)
        || add.iter().any(|id| remove.contains(id))
        || remove.iter().any(|id| !current.contains(id))
    {
        return Err(Ec2Error::new(
            "InvalidParameterValue",
            "Invalid endpoint resource changes",
        ));
    }
    let mut result: Vec<_> = current
        .iter()
        .filter(|id| !remove.contains(id))
        .cloned()
        .collect();
    for id in add {
        if !result.contains(id) {
            result.push(id.clone());
        }
    }
    Ok(result)
}

/// Verified topology of the exact interface endpoint reached by a retained source lease.
#[derive(Clone)]
pub struct InterfaceEndpointContext {
    pub endpoint_id: String,
    pub vpc_id: String,
    pub endpoint_eni_id: String,
    pub source_private_ip: Ipv4Addr,
    pub service: String,
    pub policy_document: String,
    pub endpoint_account: String,
    pub endpoint_region: String,
}

impl Ec2Handler {
    fn validated_endpoint_policy(&self, document: Option<&str>) -> Result<String, Ec2Error> {
        let policy = endpoint_policy(document)?;
        if document.is_some() {
            if let Some(evaluator) = self
                .registry
                .as_ref()
                .and_then(Weak::upgrade)
                .and_then(|registry| registry.authorization_evaluator(&ServiceName::new("iam")))
            {
                evaluator.validate_resource_policy(&policy).map_err(|_| {
                    Ec2Error::new(
                        "InvalidPolicyDocument",
                        "Endpoint policy is invalid or unsupported",
                    )
                })?;
            }
        }
        Ok(policy)
    }

    pub fn interface_endpoint_access(
        &self,
        account: &str,
        region: &str,
        source: &TaskNetworkLease,
        target_ip: Ipv4Addr,
        port: u16,
    ) -> Option<InterfaceEndpointContext> {
        let key = (account.to_owned(), region.to_owned());
        if port != 443 || source.key != key || !Arc::ptr_eq(&source.scopes, &self.scopes) {
            return None;
        }
        let state = self.scopes.lock().ok()?;
        let scope = state.get(&key)?;
        if scope.task_networks.get(&source.eni_id) != Some(&source.task_id) {
            return None;
        }
        let source_eni = scope.network_interfaces.get(&source.eni_id)?;
        let (endpoint, target) = scope
            .vpc_endpoints
            .values()
            .filter(|endpoint| {
                endpoint.kind == EndpointKind::Interface && endpoint.vpc_id == source_eni.vpc_id
            })
            .find_map(|endpoint| {
                endpoint.network_interface_ids.iter().find_map(|id| {
                    let eni = scope.network_interfaces.get(id)?;
                    (eni.private_ip == target_ip && eni.vpc_id == endpoint.vpc_id)
                        .then_some((endpoint, eni))
                })
            })?;
        if !scope.direct_route(source_eni, target)
            || !scope.groups_allow_tcp(
                &source_eni.group_ids,
                target,
                port,
                true,
                &source_eni.vpc_id,
            )
            || !scope.groups_allow_tcp(
                &target.group_ids,
                source_eni,
                port,
                false,
                &source_eni.vpc_id,
            )
        {
            return None;
        }
        Some(InterfaceEndpointContext {
            endpoint_id: endpoint.id.clone(),
            vpc_id: endpoint.vpc_id.clone(),
            endpoint_eni_id: target.id.clone(),
            source_private_ip: source_eni.private_ip,
            service: endpoint.service.clone(),
            policy_document: endpoint.policy_document.clone(),
            endpoint_account: account.into(),
            endpoint_region: region.into(),
        })
    }

    /// Live managed DNS records; no host cache and no runtime socket ownership required.
    pub fn private_endpoint_dns_addresses(
        &self,
        account: &str,
        region: &str,
        source_eni_id: &str,
        name: &str,
    ) -> Vec<Ipv4Addr> {
        let Ok(state) = self.scopes.lock() else {
            return Vec::new();
        };
        let Some(scope) = state.get(&(account.into(), region.into())) else {
            return Vec::new();
        };
        let Some(source) = scope.network_interfaces.get(source_eni_id) else {
            return Vec::new();
        };
        let mut addresses = Vec::new();
        for endpoint in scope.vpc_endpoints.values().filter(|endpoint| {
            endpoint.kind == EndpointKind::Interface && endpoint.vpc_id == source.vpc_id
        }) {
            let regional = endpoint_dns_name(endpoint, None);
            let service_host = format!("{}.{}.amazonaws.com", endpoint.service, region);
            let private_name = endpoint.private_dns
                && scope
                    .vpc_dns
                    .get(&endpoint.vpc_id)
                    .is_some_and(|dns| dns.0 && dns.1)
                && (name.eq_ignore_ascii_case(&service_host)
                    || (endpoint.service == "execute-api"
                        && name
                            .to_ascii_lowercase()
                            .strip_suffix(&format!(".{service_host}"))
                            .is_some_and(|api| !api.is_empty() && !api.contains('.'))));
            for id in &endpoint.network_interface_ids {
                if let Some(eni) = scope.network_interfaces.get(id) {
                    if private_name
                        || name.eq_ignore_ascii_case(&regional)
                        || name.eq_ignore_ascii_case(&endpoint_dns_name(endpoint, Some(&eni.zone)))
                    {
                        addresses.push(eni.private_ip);
                    }
                }
            }
        }
        addresses.sort_unstable();
        addresses.dedup();
        addresses
    }

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
                "PolicyDocument",
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
            "Interface"
                if matches!(
                    service,
                    "ssm" | "secretsmanager" | "logs" | "sts" | "sqs" | "kms" | "execute-api"
                ) =>
            {
                EndpointKind::Interface
            }
            _ => {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Unsupported endpoint service or type",
                ))
            }
        };
        let policy_document = self.validated_endpoint_policy(input.one("PolicyDocument")?)?;
        let route_table_ids = input.indexed("RouteTableId")?;
        let subnet_ids = input.indexed("SubnetId")?;
        let mut group_ids = input.indexed("SecurityGroupId")?;
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
            EndpointKind::Interface if !route_table_ids.is_empty() || subnet_ids.is_empty() => {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Interface endpoint requires subnets and security groups",
                ));
            }
            _ => {}
        }
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key.clone()).or_default();
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
                        endpoint_xml(endpoint, scope)
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
        if scope.vpc_endpoints.values().any(|ep| {
            ep.vpc_id == vpc_id
                && ep.service_name == service_name
                && ep.kind == kind
                && (kind == EndpointKind::Gateway || (private_dns && ep.private_dns))
        }) {
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
        if kind == EndpointKind::Interface && group_ids.is_empty() {
            group_ids.push(
                scope
                    .security_groups
                    .values()
                    .find(|group| group.vpc_id == vpc_id && group.is_default)
                    .ok_or_else(|| {
                        Ec2Error::new(
                            "InvalidGroup.NotFound",
                            "Default security group is unavailable",
                        )
                    })?
                    .id
                    .clone(),
            );
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
        let id = input.resource_id("vpce");
        let enis = endpoint_enis(scope, &key.0, vpc_id, &subnet_ids, &group_ids)?;
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
            network_interface_ids: enis.iter().map(|eni| eni.id.clone()).collect(),
            policy_document,
        };
        let mut changes = vec![Change::put("endpoint", &id, &endpoint)?];
        for eni in &enis {
            changes.push(Change::put("eni", &eni.id, eni)?);
        }
        let mut tables = Vec::new();
        for table_id in &endpoint.route_table_ids {
            let mut table = scope
                .route_tables
                .get(table_id)
                .expect("validated route table")
                .clone();
            table.endpoint_routes.insert(service.into(), id.clone());
            changes.push(Change::put("route-table", table_id, &table)?);
            tables.push(table);
        }
        if let Some(token) = token {
            changes.push(Change::put(
                "endpoint-token",
                token,
                &(signature.clone(), id.clone()),
            )?);
        }
        self.persist(&key, &changes)?;
        for table in tables {
            scope.route_tables.insert(table.id.clone(), table);
        }
        for eni in enis {
            scope.network_interfaces.insert(eni.id.clone(), eni);
        }
        let xml = endpoint_xml(&endpoint, scope);
        scope.vpc_endpoints.insert(id.clone(), endpoint);
        if let Some(token) = token {
            scope
                .vpc_endpoint_tokens
                .insert(token.into(), (signature, id));
        }
        Ok(format!("<vpcEndpoint>{xml}</vpcEndpoint>"))
    }

    pub(super) fn modify_vpc_endpoint(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        for name in input.fields.keys() {
            if [
                "Action",
                "Version",
                "DryRun",
                "VpcEndpointId",
                "PolicyDocument",
                "PrivateDnsEnabled",
                "ResetPolicy",
            ]
            .contains(&name.as_str())
                || [
                    "AddSubnetId",
                    "RemoveSubnetId",
                    "AddSecurityGroupId",
                    "RemoveSecurityGroupId",
                    "AddRouteTableId",
                    "RemoveRouteTableId",
                ]
                .iter()
                .any(|prefix| indexed_key(name, prefix).is_some())
            {
                continue;
            }
            return Err(Ec2Error::unsupported(name));
        }
        input.dry_run()?;
        let id = input.required("VpcEndpointId")?;
        let mut state = self
            .scopes
            .lock()
            .map_err(|_| Ec2Error::new("InternalError", "EC2 topology unavailable"))?;
        let scope = state.get_mut(&key).ok_or_else(|| {
            Ec2Error::new(
                "InvalidVpcEndpointId.NotFound",
                "The VPC endpoint does not exist",
            )
        })?;
        let mut endpoint = scope.vpc_endpoints.get(id).cloned().ok_or_else(|| {
            Ec2Error::new(
                "InvalidVpcEndpointId.NotFound",
                "The VPC endpoint does not exist",
            )
        })?;
        let add_subnets = input.indexed("AddSubnetId")?;
        let remove_subnets = input.indexed("RemoveSubnetId")?;
        let add_groups = input.indexed("AddSecurityGroupId")?;
        let remove_groups = input.indexed("RemoveSecurityGroupId")?;
        let add_routes = input.indexed("AddRouteTableId")?;
        let remove_routes = input.indexed("RemoveRouteTableId")?;
        let final_subnets = updated_ids(&endpoint.subnet_ids, &add_subnets, &remove_subnets)?;
        let final_groups = updated_ids(&endpoint.group_ids, &add_groups, &remove_groups)?;
        let final_routes = updated_ids(&endpoint.route_table_ids, &add_routes, &remove_routes)?;
        if let Some(value) = input.one("PolicyDocument")? {
            endpoint.policy_document = self.validated_endpoint_policy(Some(value))?;
        }
        match input.one("ResetPolicy")? {
            Some("true") if endpoint.kind == EndpointKind::Gateway => {
                if input.one("PolicyDocument")?.is_some() {
                    return Err(Ec2Error::new(
                        "InvalidParameterCombination",
                        "PolicyDocument and ResetPolicy are mutually exclusive",
                    ));
                }
                endpoint.policy_document = DEFAULT_ENDPOINT_POLICY.into();
            }
            None | Some("false") => {}
            Some("true") => {
                return Err(Ec2Error::unsupported("ResetPolicy for interface endpoints"))
            }
            _ => {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "ResetPolicy must be boolean",
                ))
            }
        }
        if let Some(value) = input.one("PrivateDnsEnabled")? {
            if endpoint.kind != EndpointKind::Interface {
                return Err(Ec2Error::unsupported(
                    "PrivateDnsEnabled for gateway endpoints",
                ));
            }
            endpoint.private_dns = match value {
                "true" => true,
                "false" => false,
                _ => {
                    return Err(Ec2Error::new(
                        "InvalidParameterValue",
                        "PrivateDnsEnabled must be boolean",
                    ))
                }
            };
        }
        let mut enis = Vec::new();
        let mut removed_enis = Vec::new();
        let mut tables = Vec::new();
        match endpoint.kind {
            EndpointKind::Interface => {
                if !add_routes.is_empty()
                    || !remove_routes.is_empty()
                    || final_subnets.is_empty()
                    || final_groups.is_empty()
                {
                    return Err(Ec2Error::new("InvalidParameterValue", "Interface endpoint requires subnets and security groups, without route tables"));
                }
                let mut zones = std::collections::HashSet::new();
                for subnet_id in &final_subnets {
                    let subnet = scope
                        .subnets
                        .get(subnet_id)
                        .filter(|subnet| subnet.vpc_id == endpoint.vpc_id)
                        .ok_or_else(|| {
                            Ec2Error::new(
                                "InvalidSubnetID.NotFound",
                                "Endpoint subnet is outside the VPC",
                            )
                        })?;
                    if !zones.insert(&subnet.zone) {
                        return Err(Ec2Error::new(
                            "InvalidParameterValue",
                            "An interface endpoint supports one subnet per Availability Zone",
                        ));
                    }
                }
                if final_groups.iter().any(|id| {
                    scope
                        .security_groups
                        .get(id)
                        .is_none_or(|group| group.vpc_id != endpoint.vpc_id)
                }) {
                    return Err(Ec2Error::new(
                        "InvalidGroup.NotFound",
                        "Endpoint security group is outside the VPC",
                    ));
                }
                if endpoint.private_dns
                    && (!scope
                        .vpc_dns
                        .get(&endpoint.vpc_id)
                        .is_some_and(|dns| dns.0 && dns.1)
                        || scope.vpc_endpoints.values().any(|other| {
                            other.id != endpoint.id
                                && other.vpc_id == endpoint.vpc_id
                                && other.service == endpoint.service
                                && other.private_dns
                        }))
                {
                    return Err(Ec2Error::new(
                        "InvalidParameterValue",
                        "Private DNS is unavailable or already associated with another endpoint",
                    ));
                }
                for eni_id in &endpoint.network_interface_ids {
                    let mut eni =
                        scope
                            .network_interfaces
                            .get(eni_id)
                            .cloned()
                            .ok_or_else(|| {
                                Ec2Error::new(
                                    "InternalError",
                                    "Endpoint network interface is unavailable",
                                )
                            })?;
                    if final_subnets.contains(&eni.subnet_id) {
                        eni.group_ids = final_groups.clone();
                        enis.push(eni);
                    } else {
                        removed_enis.push(eni_id.clone());
                    }
                }
                let new_subnets: Vec<_> = final_subnets
                    .iter()
                    .filter(|id| !endpoint.subnet_ids.contains(id))
                    .cloned()
                    .collect();
                enis.extend(endpoint_enis(
                    scope,
                    &key.0,
                    &endpoint.vpc_id,
                    &new_subnets,
                    &final_groups,
                )?);
                endpoint.network_interface_ids = enis.iter().map(|eni| eni.id.clone()).collect();
            }
            EndpointKind::Gateway => {
                if !add_subnets.is_empty()
                    || !remove_subnets.is_empty()
                    || !add_groups.is_empty()
                    || !remove_groups.is_empty()
                {
                    return Err(Ec2Error::new(
                        "InvalidParameterValue",
                        "Gateway endpoints support route tables only",
                    ));
                }
                for route_id in endpoint
                    .route_table_ids
                    .iter()
                    .chain(final_routes.iter())
                    .collect::<std::collections::BTreeSet<_>>()
                {
                    let mut table = scope
                        .route_tables
                        .get(route_id)
                        .filter(|table| table.vpc_id == endpoint.vpc_id)
                        .cloned()
                        .ok_or_else(|| {
                            Ec2Error::new(
                                "InvalidRouteTableID.NotFound",
                                "Endpoint route table is outside the VPC",
                            )
                        })?;
                    if final_routes.contains(route_id) {
                        if table
                            .endpoint_routes
                            .get(&endpoint.service)
                            .is_some_and(|owner| owner != id)
                        {
                            return Err(Ec2Error::new(
                                "InvalidParameterValue",
                                "Route table already has a different endpoint",
                            ));
                        }
                        table
                            .endpoint_routes
                            .insert(endpoint.service.clone(), id.into());
                    } else {
                        table.endpoint_routes.remove(&endpoint.service);
                    }
                    tables.push(table);
                }
            }
        }
        endpoint.subnet_ids = final_subnets;
        endpoint.group_ids = final_groups;
        endpoint.route_table_ids = final_routes;
        let mut changes = vec![Change::put("endpoint", id, &endpoint)?];
        for eni in &enis {
            changes.push(Change::put("eni", &eni.id, eni)?);
        }
        for eni in &removed_enis {
            changes.push(Change::delete("eni", eni));
        }
        for table in &tables {
            changes.push(Change::put("route-table", &table.id, table)?);
        }
        self.persist(&key, &changes)?;
        for eni in enis {
            scope.network_interfaces.insert(eni.id.clone(), eni);
        }
        for eni in removed_enis {
            scope.network_interfaces.remove(&eni);
        }
        for table in tables {
            scope.route_tables.insert(table.id.clone(), table);
        }
        scope.vpc_endpoints.insert(id.into(), endpoint);
        Ok("<return>true</return>".into())
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
        let empty_scope = ScopeState::default();
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
            .map(|ep| {
                format!(
                    "<item>{}</item>",
                    endpoint_xml(ep, scope.unwrap_or(&empty_scope))
                )
            })
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
        let scope = state.entry(key.clone()).or_default();
        if ids.iter().any(|id| !scope.vpc_endpoints.contains_key(id)) {
            return Err(Ec2Error::new(
                "InvalidVpcEndpointId.NotFound",
                "The VPC endpoint does not exist",
            ));
        }
        let mut changes = Vec::new();
        let mut tables = BTreeMap::new();
        for id in &ids {
            let endpoint = scope.vpc_endpoints.get(id).expect("validated endpoint");
            changes.push(Change::delete("endpoint", id));
            changes.extend(
                endpoint
                    .network_interface_ids
                    .iter()
                    .map(|eni| Change::delete("eni", eni)),
            );
            changes.extend(
                scope
                    .vpc_endpoint_tokens
                    .iter()
                    .filter(|(_, (_, endpoint_id))| endpoint_id == id)
                    .map(|(token, _)| Change::delete("endpoint-token", token)),
            );
            for table_id in &endpoint.route_table_ids {
                if let Some(existing) = scope.route_tables.get(table_id) {
                    let table = tables
                        .entry(table_id.clone())
                        .or_insert_with(|| existing.clone());
                    table.endpoint_routes.remove(&endpoint.service);
                }
            }
        }
        for (id, table) in &tables {
            changes.push(Change::put("route-table", id, table)?);
        }
        self.persist(&key, &changes)?;
        for (id, table) in tables {
            scope.route_tables.insert(id, table);
        }
        for id in ids {
            if let Some(endpoint) = scope.vpc_endpoints.remove(&id) {
                for eni in endpoint.network_interface_ids {
                    scope.network_interfaces.remove(&eni);
                }
            }
            scope
                .vpc_endpoint_tokens
                .retain(|_, (_, endpoint_id)| endpoint_id != &id);
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
                    .network_interface_ids
                    .iter()
                    .filter_map(|id| scope.network_interfaces.get(id))
                    .filter_map(|eni| Ipv4Net::new(eni.private_ip, 32).ok())
                    .collect(),
            };
            if !source_groups.iter().any(|group| {
                group.egress.iter().any(|rule| {
                    (rule.protocol == "-1"
                        || (rule.protocol == "tcp"
                            && rule.from_port.is_some_and(|from| from <= 443)
                            && rule.to_port.is_some_and(|to| to >= 443)))
                        && destinations.iter().any(|destination| match &rule.peer {
                            RulePeer::Cidr(cidr) => contains_net(*cidr, *destination),
                            RulePeer::Group(id) => {
                                ep.kind == EndpointKind::Interface && ep.group_ids.contains(id)
                            }
                        })
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
                                    rule.peer.matches(source_ip, source_group_ids)
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

fn endpoint_xml(ep: &VpcEndpoint, scope: &ScopeState) -> String {
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
    let enis = ep
        .network_interface_ids
        .iter()
        .map(|id| format!("<item>{}</item>", escape(id)))
        .collect::<String>();
    let mut dns = String::new();
    if ep.kind == EndpointKind::Interface {
        let zone_id = format!(
            "Z{}",
            ep.id.trim_start_matches("vpce-").to_ascii_uppercase()
        );
        for name in std::iter::once(endpoint_dns_name(ep, None)).chain(
            ep.network_interface_ids
                .iter()
                .filter_map(|id| scope.network_interfaces.get(id))
                .map(|eni| endpoint_dns_name(ep, Some(&eni.zone))),
        ) {
            dns.push_str(&format!(
                "<item><dnsName>{}</dnsName><hostedZoneId>{}</hostedZoneId></item>",
                escape(&name),
                escape(&zone_id)
            ));
        }
    }
    format!("<vpcEndpointId>{}</vpcEndpointId><vpcEndpointType>{}</vpcEndpointType><vpcId>{}</vpcId><serviceName>{}</serviceName><state>available</state><routeTableIdSet>{routes}</routeTableIdSet><subnetIdSet>{subnets}</subnetIdSet><groupSet>{groups}</groupSet><networkInterfaceIdSet>{enis}</networkInterfaceIdSet><dnsEntrySet>{dns}</dnsEntrySet><policyDocument>{}</policyDocument><privateDnsEnabled>{}</privateDnsEnabled>", escape(&ep.id), endpoint_kind(ep.kind), escape(&ep.vpc_id), escape(&ep.service_name), escape(&ep.policy_document), ep.private_dns)
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
        let scope = state.entry(key.clone()).or_default();
        let mut dns = *scope
            .vpc_dns
            .get(vpc)
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
        self.persist(&key, &[Change::put("dns", vpc, &dns)?])?;
        scope.vpc_dns.insert(vpc.into(), dns);
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
    async fn interface_endpoints_own_persistent_enis_and_resolve_exact_live_policy() {
        use crate::tests::{call, id};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../compatibility-tests/.work/ec2-interface-endpoints")
            .join(Uuid::new_v4().to_string());
        let database = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let persistence =
            Arc::new(Persistence::new(database.clone(), StateCipher::with_key(&[91; 32])).unwrap());
        let handler = Ec2Handler {
            persistence: Some(persistence.clone()),
            ..Ec2Handler::default()
        };
        async fn ok(handler: &Ec2Handler, form: &str) -> String {
            let (status, body) = crate::tests::call(handler, "111", "us-east-1", form).await;
            assert_eq!(status, 200, "{body}");
            body
        }
        let vpc = id(
            &ok(&handler, "Action=CreateVpc&CidrBlock=10.8.0.0%2F16").await,
            "vpcId",
        );
        ok(
            &handler,
            &format!("Action=ModifyVpcAttribute&VpcId={vpc}&EnableDnsHostnames.Value=true"),
        )
        .await;
        let mut subnets = Vec::new();
        for (index, zone) in ["us-east-1a", "us-east-1b", "us-east-1c"]
            .iter()
            .enumerate()
        {
            subnets.push(id(&ok(&handler, &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.8.{index}.0%2F24&AvailabilityZone={zone}")).await, "subnetId"));
        }
        let group = id(&ok(&handler, &format!("Action=CreateSecurityGroup&VpcId={vpc}&GroupName=endpoint&GroupDescription=endpoint")).await, "groupId");
        ok(&handler, &format!("Action=AuthorizeSecurityGroupIngress&GroupId={group}&IpProtocol=tcp&FromPort=443&ToPort=443&CidrIp=10.8.0.0%2F16")).await;
        let source_group = {
            let state = handler.scopes.lock().unwrap();
            state[&("111".into(), "us-east-1".into())]
                .security_groups
                .values()
                .find(|group| group.is_default)
                .unwrap()
                .id
                .clone()
        };
        let source = handler
            .reserve_task_network(
                "111",
                "us-east-1",
                &subnets[0],
                std::slice::from_ref(&source_group),
                "source",
            )
            .unwrap();
        let create = format!("Action=CreateVpcEndpoint&VpcId={vpc}&ServiceName=com.amazonaws.us-east-1.execute-api&VpcEndpointType=Interface&SubnetId.1={}&SubnetId.2={}&SecurityGroupId.1={group}", subnets[0], subnets[1]);
        let first_xml = ok(&handler, &create).await;
        assert!(first_xml.contains("<networkInterfaceIdSet><item>eni-"));
        assert!(first_xml.contains("<dnsEntrySet><item><dnsName>vpce-"));
        let first = id(&first_xml, "vpcEndpointId");
        let second = id(&ok(&handler, &create).await, "vpcEndpointId");
        let snapshot = |id: &str| {
            let state = handler.scopes.lock().unwrap();
            let scope = &state[&("111".into(), "us-east-1".into())];
            let endpoint = scope.vpc_endpoints[id].clone();
            let enis: Vec<_> = endpoint
                .network_interface_ids
                .iter()
                .map(|id| scope.network_interfaces[id].clone())
                .collect();
            (endpoint, enis)
        };
        let (first_ep, first_enis) = snapshot(&first);
        let (_, second_enis) = snapshot(&second);
        assert_ne!(first_enis[0].private_ip, second_enis[0].private_ip);
        for (id, enis) in [(&first, &first_enis), (&second, &second_enis)] {
            let context = handler
                .interface_endpoint_access("111", "us-east-1", &source, enis[0].private_ip, 443)
                .unwrap();
            assert_eq!(&context.endpoint_id, id);
            assert_eq!(context.source_private_ip, source.private_ip);
            assert_eq!(context.service, "execute-api");
            assert!(handler
                .interface_endpoint_access("111", "us-east-1", &source, enis[0].private_ip, 80)
                .is_none());
            assert!(handler
                .interface_endpoint_access("222", "us-east-1", &source, enis[0].private_ip, 443)
                .is_none());
        }
        ok(&handler, &format!("Action=RevokeSecurityGroupEgress&GroupId={source_group}&IpPermissions.1.IpProtocol=-1&IpPermissions.1.IpRanges.1.CidrIp=0.0.0.0%2F0")).await;
        ok(&handler, &format!("Action=AuthorizeSecurityGroupEgress&GroupId={source_group}&IpProtocol=tcp&FromPort=443&ToPort=443&CidrIp={}%2F32", first_enis[0].private_ip)).await;
        assert!(handler
            .interface_endpoint_access("111", "us-east-1", &source, first_enis[0].private_ip, 443)
            .is_some());
        assert!(handler
            .interface_endpoint_access("111", "us-east-1", &source, second_enis[0].private_ip, 443)
            .is_none());
        ok(&handler, &format!("Action=AuthorizeSecurityGroupEgress&GroupId={source_group}&IpPermissions.1.IpProtocol=-1&IpPermissions.1.IpRanges.1.CidrIp=0.0.0.0%2F0")).await;
        let before_enis = handler.scopes.lock().unwrap()[&("111".into(), "us-east-1".into())]
            .network_interfaces
            .len();
        database.connection().unwrap().execute_batch("CREATE TRIGGER reject_interface BEFORE INSERT ON ec2_records WHEN NEW.kind='endpoint' BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        assert_eq!(call(&handler, "111", "us-east-1", &create).await.0, 500);
        database
            .connection()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_interface;")
            .unwrap();
        assert_eq!(
            handler.scopes.lock().unwrap()[&("111".into(), "us-east-1".into())]
                .network_interfaces
                .len(),
            before_enis
        );
        let deny = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"execute-api:Invoke","Resource":"*"}]}"#;
        let encoded: String = form_urlencoded::byte_serialize(deny.as_bytes()).collect();
        ok(&handler, &format!("Action=ModifyVpcEndpoint&VpcEndpointId={first}&PolicyDocument={encoded}&PrivateDnsEnabled=true")).await;
        assert_eq!(
            handler
                .interface_endpoint_access(
                    "111",
                    "us-east-1",
                    &source,
                    first_enis[0].private_ip,
                    443
                )
                .unwrap()
                .policy_document,
            deny
        );
        assert_eq!(
            handler
                .interface_endpoint_access(
                    "111",
                    "us-east-1",
                    &source,
                    second_enis[0].private_ip,
                    443
                )
                .unwrap()
                .policy_document,
            DEFAULT_ENDPOINT_POLICY
        );
        let addresses = handler.private_endpoint_dns_addresses(
            "111",
            "us-east-1",
            &source.eni_id,
            "owned.execute-api.us-east-1.amazonaws.com",
        );
        assert_eq!(addresses.len(), 2);
        assert!(first_enis
            .iter()
            .all(|eni| addresses.contains(&eni.private_ip)));
        let (status, _) = call(
            &handler,
            "111",
            "us-east-1",
            &format!("Action=ModifyVpcEndpoint&VpcEndpointId={second}&PrivateDnsEnabled=true"),
        )
        .await;
        assert_eq!(status, 400);
        let (status, _) = call(
            &handler,
            "111",
            "us-east-1",
            &format!(
                "Action=DeleteNetworkInterface&NetworkInterfaceId={}",
                first_enis[0].id
            ),
        )
        .await;
        assert_eq!(status, 400);
        ok(&handler, &format!("Action=RevokeSecurityGroupIngress&GroupId={group}&IpProtocol=tcp&FromPort=443&ToPort=443&CidrIp=10.8.0.0%2F16")).await;
        assert!(handler
            .interface_endpoint_access("111", "us-east-1", &source, first_enis[0].private_ip, 443)
            .is_none());
        ok(&handler, &format!("Action=AuthorizeSecurityGroupIngress&GroupId={group}&IpProtocol=tcp&FromPort=443&ToPort=443&CidrIp=10.8.0.0%2F16")).await;
        ok(&handler, &format!("Action=ModifyVpcEndpoint&VpcEndpointId={first}&RemoveSubnetId.1={}&AddSubnetId.1={}", subnets[0], subnets[2])).await;
        assert!(handler
            .interface_endpoint_access("111", "us-east-1", &source, first_enis[0].private_ip, 443)
            .is_none());
        let (modified, modified_enis) = snapshot(&first);
        assert!(modified.network_interface_ids.contains(&first_enis[1].id));
        assert!(modified_enis.iter().any(|eni| eni.subnet_id == subnets[2]));
        let restored = Ec2Handler {
            persistence: Some(persistence.clone()),
            ..Ec2Handler::default()
        };
        persistence.restore(&restored).unwrap();
        {
            let state = restored.scopes.lock().unwrap();
            let scope = &state[&("111".into(), "us-east-1".into())];
            assert_eq!(
                scope.vpc_endpoints[&first].network_interface_ids,
                modified.network_interface_ids
            );
            assert_eq!(scope.vpc_endpoints[&first].policy_document, deny);
            assert!(modified_enis
                .iter()
                .all(|eni| scope.network_interfaces[&eni.id].private_ip == eni.private_ip));
        }
        ok(
            &handler,
            &format!("Action=DeleteVpcEndpoints&VpcEndpointId.1={first}&VpcEndpointId.2={second}"),
        )
        .await;
        {
            let state = handler.scopes.lock().unwrap();
            let scope = &state[&("111".into(), "us-east-1".into())];
            assert!(modified
                .network_interface_ids
                .iter()
                .chain(first_ep.network_interface_ids.iter())
                .chain(second_enis.iter().map(|eni| &eni.id))
                .all(|id| !scope.network_interfaces.contains_key(id)));
        }
        drop(source);
        drop(restored);
        drop(handler);
        drop(persistence);
        drop(database);
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

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
            planned_ids: BTreeMap::new(),
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
            planned_ids: BTreeMap::new(),
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
            planned_ids: BTreeMap::new(),
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
