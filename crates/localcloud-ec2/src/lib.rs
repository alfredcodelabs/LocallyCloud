//! EC2 Query control plane for IPv4 VPCs and subnets.

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use ipnet::Ipv4Net;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use uuid::Uuid;

const XMLNS: &str = "http://ec2.amazonaws.com/doc/2016-11-15/";

mod endpoints;
mod nat;
mod private_tcp;
mod security_group_egress;
use endpoints::VpcEndpoint;
use security_group_egress::default_egress;

#[derive(Clone, Debug)]
struct Vpc {
    id: String,
    cidr: Ipv4Net,
    owner: String,
}

#[derive(Clone)]
struct Subnet {
    id: String,
    vpc_id: String,
    cidr: Ipv4Net,
    zone: String,
    owner: String,
    guard: Arc<()>,
}

#[derive(Clone)]
struct IngressRule {
    protocol: String,
    from_port: Option<u16>,
    to_port: Option<u16>,
    cidr: Ipv4Net,
}

#[derive(Clone)]
struct SecurityGroup {
    id: String,
    vpc_id: String,
    name: String,
    description: String,
    owner: String,
    is_default: bool,
    ingress: Vec<IngressRule>,
    egress: Vec<IngressRule>,
    guard: Arc<()>,
}

#[derive(Clone)]
struct NetworkInterface {
    id: String,
    subnet_id: String,
    vpc_id: String,
    zone: String,
    private_ip: Ipv4Addr,
    description: String,
    owner: String,
    group_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkSelection {
    pub vpc_id: String,
    pub subnet_id: String,
    pub subnet_cidr: Ipv4Net,
    pub availability_zone: String,
    pub security_group_ids: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct InstanceSpec {
    pub instance_id: String,
    pub image_id: String,
    pub instance_type: String,
    pub vpc_id: String,
    pub subnet_id: String,
    pub private_ip: Ipv4Addr,
    pub security_group_ids: Vec<String>,
    pub guest_port: u16,
}

#[async_trait]
pub trait InstanceRuntime: Send + Sync {
    async fn start_instance(&self, spec: &InstanceSpec) -> Result<(), String>;
    async fn connect_instance(
        &self,
        instance_id: &str,
        guest_port: u16,
    ) -> Result<TcpStream, String>;
    async fn stop_instance(&self, instance_id: &str) -> Result<(), String>;
    async fn instance_running(&self, instance_id: &str) -> bool;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InstanceState {
    Pending,
    Running,
    ShuttingDown,
    Terminated,
}

#[derive(Clone)]
struct Instance {
    spec: InstanceSpec,
    eni_id: String,
    state: InstanceState,
    endpoint: Option<SocketAddr>,
}

struct IdempotentInstance {
    params: BTreeMap<String, String>,
    instance_id: String,
}

struct IdempotentEni {
    params: BTreeMap<String, String>,
    eni_id: String,
}

#[derive(Clone)]
struct RouteTable {
    id: String,
    vpc_id: String,
    owner: String,
    main: bool,
    routes: BTreeMap<Ipv4Net, RouteTarget>,
    endpoint_routes: BTreeMap<String, String>,
    associations: BTreeMap<String, Option<String>>,
}

#[derive(Clone)]
enum RouteTarget {
    Local,
    NetworkInterface(String),
    InternetGateway(String),
    NatGateway(String),
    BlackholeNatGateway(String),
}

#[derive(Clone)]
struct InternetGateway {
    id: String,
    vpc_id: Option<String>,
}

#[derive(Clone)]
struct ElasticIp {
    allocation_id: String,
    public_ip: Ipv4Addr,
    nat_gateway_id: Option<String>,
}

#[derive(Clone)]
struct NatGateway {
    id: String,
    vpc_id: String,
    subnet_id: Option<String>,
    allocation_id: Option<String>,
    private_ip: Option<Ipv4Addr>,
    regional: bool,
}

#[derive(Default)]
struct ScopeState {
    vpcs: BTreeMap<String, Arc<Vpc>>,
    vpc_dns: BTreeMap<String, (bool, bool)>,
    subnets: BTreeMap<String, Subnet>,
    security_groups: BTreeMap<String, SecurityGroup>,
    network_interfaces: BTreeMap<String, NetworkInterface>,
    eni_tokens: BTreeMap<String, IdempotentEni>,
    instances: BTreeMap<String, Instance>,
    instance_tokens: BTreeMap<String, IdempotentInstance>,
    route_tables: BTreeMap<String, RouteTable>,
    internet_gateways: BTreeMap<String, InternetGateway>,
    elastic_ips: BTreeMap<String, ElasticIp>,
    nat_gateways: BTreeMap<String, NatGateway>,
    nat_gateway_tokens: BTreeMap<String, (BTreeMap<String, String>, String)>,
    route_table_tokens: BTreeMap<String, (String, String)>,
    vpc_endpoints: BTreeMap<String, VpcEndpoint>,
    vpc_endpoint_tokens: BTreeMap<String, (BTreeMap<String, String>, String)>,
    task_networks: BTreeMap<String, String>,
    task_dns: BTreeMap<String, String>,
    task_endpoints: BTreeMap<(Ipv4Addr, u16), (String, SocketAddr)>,
}

/// An opaque dependency that prevents VPC deletion while a consumer retains it.
#[derive(Clone)]
pub struct VpcLease {
    vpc: Arc<Vpc>,
}

impl VpcLease {
    pub fn vpc_id(&self) -> &str {
        &self.vpc.id
    }
}

/// Task-owned private ENI. Its address resolves to a local ingress proxy only
/// while the task is running; dropping the lease releases the ENI and endpoint.
pub struct TaskNetworkLease {
    pub eni_id: String,
    pub vpc_id: String,
    pub subnet_id: String,
    pub private_ip: Ipv4Addr,
    pub security_group_ids: Vec<String>,
    task_id: String,
    key: (String, String),
    scopes: Arc<Mutex<HashMap<(String, String), ScopeState>>>,
}

impl TaskNetworkLease {
    pub fn set_dns_name(&self, name: &str) -> bool {
        if name.len() > 253
            || name.is_empty()
            || name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return false;
        }
        let Ok(mut state) = self.scopes.lock() else {
            return false;
        };
        let Some(scope) = state.get_mut(&self.key) else {
            return false;
        };
        if scope.task_networks.get(&self.eni_id) != Some(&self.task_id) {
            return false;
        }
        scope
            .task_dns
            .insert(self.eni_id.clone(), name.to_ascii_lowercase());
        true
    }

    pub fn set_endpoint(&self, port: u16, endpoint: SocketAddr) -> bool {
        if endpoint.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return false;
        }
        let Ok(mut state) = self.scopes.lock() else {
            return false;
        };
        let Some(scope) = state.get_mut(&self.key) else {
            return false;
        };
        if scope.task_networks.get(&self.eni_id) != Some(&self.task_id) {
            return false;
        }
        scope
            .task_endpoints
            .insert((self.private_ip, port), (self.task_id.clone(), endpoint));
        true
    }
}

impl Drop for TaskNetworkLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.scopes.lock() {
            if let Some(scope) = state.get_mut(&self.key) {
                if scope.task_networks.get(&self.eni_id) == Some(&self.task_id) {
                    scope.task_networks.remove(&self.eni_id);
                    scope.task_dns.remove(&self.eni_id);
                    scope.network_interfaces.remove(&self.eni_id);
                    scope
                        .task_endpoints
                        .retain(|_, (id, _)| id != &self.task_id);
                }
            }
        }
    }
}

/// Retains Lambda VPC dependencies until the function or its versions are removed.
#[derive(Clone, Debug)]
pub struct LambdaNetworkLease {
    pub vpc_id: String,
    pub subnet_ids: Vec<String>,
    pub security_group_ids: Vec<String>,
    _vpc: Arc<Vpc>,
    _subnet_guards: Vec<Arc<()>>,
    _group_guards: Vec<Arc<()>>,
}

/// Atomic reference to an ALB network selection. Dropping all clones releases its dependencies.
#[derive(Clone)]
pub struct AlbNetworkLease {
    pub vpc_id: String,
    /// Subnet ID and availability zone pairs.
    pub subnets: Vec<(String, String)>,
    pub security_group_ids: Vec<String>,
    _vpc: Arc<Vpc>,
    _subnet_guards: Vec<Arc<()>>,
    _group_guards: Vec<Arc<()>>,
}

#[derive(Default)]
pub struct Ec2Handler {
    scopes: Arc<Mutex<HashMap<(String, String), ScopeState>>>,
    runtime: Option<Arc<dyn InstanceRuntime>>,
}

impl Ec2Handler {
    pub fn with_instance_runtime(runtime: Arc<dyn InstanceRuntime>) -> Self {
        Self {
            scopes: Arc::default(),
            runtime: Some(runtime),
        }
    }

    pub fn resolve_target(
        &self,
        account: &str,
        region: &str,
        vpc_id: &str,
        private_ip: Ipv4Addr,
        port: u16,
    ) -> Option<SocketAddr> {
        let state = self.scopes.lock().unwrap();
        let scope = state.get(&(account.to_owned(), region.to_owned()))?;
        scope.resolve_target(vpc_id, private_ip, port)
    }

    /// Whether at least one ALB subnet has a direct route to the target ENI.
    /// A route to another ENI represents an appliance path that this runtime
    /// does not forward, so the local loopback shortcut must not bypass it.
    pub fn alb_can_reach_target(
        &self,
        account: &str,
        region: &str,
        vpc_id: &str,
        source_subnet_ids: &[String],
        target_ip: Ipv4Addr,
    ) -> bool {
        let state = self.scopes.lock().unwrap();
        let Some(scope) = state.get(&(account.to_owned(), region.to_owned())) else {
            return false;
        };
        let Some(target) = scope
            .network_interfaces
            .values()
            .find(|eni| eni.vpc_id == vpc_id && eni.private_ip == target_ip)
        else {
            return false;
        };
        !source_subnet_ids.is_empty()
            && source_subnet_ids.iter().any(|subnet_id| {
                let Some(subnet) = scope.subnets.get(subnet_id) else {
                    return false;
                };
                if subnet.vpc_id != target.vpc_id {
                    return false;
                }
                if subnet.cidr.contains(&target_ip) {
                    return true;
                }
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
                let Some(table) = table else {
                    return false;
                };
                table
                    .routes
                    .iter()
                    .filter(|(cidr, _)| cidr.contains(&target_ip))
                    .max_by_key(|(cidr, _)| cidr.prefix_len())
                    .is_some_and(|(_, next_hop)| {
                        matches!(next_hop, RouteTarget::Local) || matches!(next_hop, RouteTarget::NetworkInterface(eni_id) if eni_id == &target.id)
                    })
            })
    }

    /// Read-only, scoped VPC check for typed consumers such as ELBv2.
    pub fn vpc_exists(&self, account: &str, region: &str, vpc_id: &str) -> bool {
        self.scopes
            .lock()
            .unwrap()
            .get(&(account.to_owned(), region.to_owned()))
            .is_some_and(|scope| scope.vpcs.contains_key(vpc_id))
    }

    /// Acquire a scoped dependency atomically with `DeleteVpc`.
    pub fn vpc_lease(&self, account: &str, region: &str, vpc_id: &str) -> Option<VpcLease> {
        self.scopes
            .lock()
            .unwrap()
            .get(&(account.to_owned(), region.to_owned()))
            .and_then(|scope| scope.vpcs.get(vpc_id))
            .map(|vpc| VpcLease { vpc: vpc.clone() })
    }

    /// Reserve a private ENI for a running isolated task.
    pub fn reserve_task_network(
        &self,
        account: &str,
        region: &str,
        subnet_id: &str,
        group_ids: &[String],
        task_id: &str,
    ) -> Option<TaskNetworkLease> {
        if task_id.is_empty() || group_ids.is_empty() {
            return None;
        }
        let key = (account.to_owned(), region.to_owned());
        let mut state = self.scopes.lock().ok()?;
        let scope = state.get_mut(&key)?;
        let subnet = scope.subnets.get(subnet_id)?.clone();
        if group_ids.iter().any(|id| {
            !scope
                .security_groups
                .get(id)
                .is_some_and(|group| group.vpc_id == subnet.vpc_id)
        }) {
            return None;
        }
        if group_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != group_ids.len()
        {
            return None;
        }
        let base = u32::from(subnet.cidr.network());
        let size = 1_u32 << (32 - subnet.cidr.prefix_len());
        let private_ip = (4..size - 1)
            .map(|offset| Ipv4Addr::from(base + offset))
            .find(|ip| {
                !scope
                    .network_interfaces
                    .values()
                    .any(|eni| eni.subnet_id == subnet_id && eni.private_ip == *ip)
            })?;
        let eni_id = resource_id("eni");
        scope.network_interfaces.insert(
            eni_id.clone(),
            NetworkInterface {
                id: eni_id.clone(),
                subnet_id: subnet.id.clone(),
                vpc_id: subnet.vpc_id.clone(),
                zone: subnet.zone,
                private_ip,
                description: format!("Primary network interface for managed service {task_id}"),
                owner: account.into(),
                group_ids: group_ids.to_vec(),
            },
        );
        scope.task_networks.insert(eni_id.clone(), task_id.into());
        Some(TaskNetworkLease {
            eni_id,
            vpc_id: subnet.vpc_id,
            subnet_id: subnet.id,
            private_ip,
            security_group_ids: group_ids.to_vec(),
            task_id: task_id.into(),
            key,
            scopes: self.scopes.clone(),
        })
    }

    /// Read-only scoped metadata for VPC-aware service adapters.
    pub fn subnet_description(
        &self,
        account: &str,
        region: &str,
        subnet_id: &str,
    ) -> Option<(String, String, Ipv4Net)> {
        let state = self.scopes.lock().ok()?;
        let subnet = state
            .get(&(account.to_owned(), region.to_owned()))?
            .subnets
            .get(subnet_id)?;
        Some((subnet.vpc_id.clone(), subnet.zone.clone(), subnet.cidr))
    }

    pub fn security_group_vpc_id(
        &self,
        account: &str,
        region: &str,
        group_id: &str,
    ) -> Option<String> {
        self.scopes
            .lock()
            .ok()?
            .get(&(account.to_owned(), region.to_owned()))?
            .security_groups
            .get(group_id)
            .map(|group| group.vpc_id.clone())
    }

    pub fn default_security_group_id(
        &self,
        account: &str,
        region: &str,
        vpc_id: &str,
    ) -> Option<String> {
        self.scopes
            .lock()
            .ok()?
            .get(&(account.to_owned(), region.to_owned()))?
            .security_groups
            .values()
            .find(|group| group.vpc_id == vpc_id && group.is_default)
            .map(|group| group.id.clone())
    }

    /// Snapshot of a scoped subnet and security-group selection for future runtimes.
    /// Consumers that need stable ownership across operations must retain a VPC lease too.
    pub fn network_selection(
        &self,
        account: &str,
        region: &str,
        subnet_id: &str,
        group_ids: &[String],
    ) -> Option<NetworkSelection> {
        let state = self.scopes.lock().unwrap();
        let scope = state.get(&(account.to_owned(), region.to_owned()))?;
        let subnet = scope.subnets.get(subnet_id)?;
        if !group_ids.iter().all(|id| {
            scope
                .security_groups
                .get(id)
                .is_some_and(|group| group.vpc_id == subnet.vpc_id)
        }) {
            return None;
        }
        Some(NetworkSelection {
            vpc_id: subnet.vpc_id.clone(),
            subnet_id: subnet.id.clone(),
            subnet_cidr: subnet.cidr,
            availability_zone: subnet.zone.clone(),
            security_group_ids: group_ids.to_vec(),
        })
    }

    /// Validate Lambda's VPC selection and retain every network dependency atomically.
    pub fn network_selection_lease(
        &self,
        account: &str,
        region: &str,
        subnet_ids: &[String],
        group_ids: &[String],
    ) -> Option<LambdaNetworkLease> {
        if subnet_ids.is_empty() || group_ids.is_empty() {
            return None;
        }
        let unique = |ids: &[String]| {
            ids.iter().collect::<std::collections::HashSet<_>>().len() == ids.len()
        };
        if !unique(subnet_ids) || !unique(group_ids) {
            return None;
        }
        let state = self.scopes.lock().ok()?;
        let scope = state.get(&(account.to_owned(), region.to_owned()))?;
        let first = scope.subnets.get(&subnet_ids[0])?;
        let vpc_id = first.vpc_id.clone();
        let vpc = scope.vpcs.get(&vpc_id)?.clone();
        let subnet_guards = subnet_ids
            .iter()
            .map(|id| {
                let subnet = scope.subnets.get(id)?;
                (subnet.vpc_id == vpc_id).then(|| subnet.guard.clone())
            })
            .collect::<Option<Vec<_>>>()?;
        let group_guards = group_ids
            .iter()
            .map(|id| {
                let group = scope.security_groups.get(id)?;
                (group.vpc_id == vpc_id).then(|| group.guard.clone())
            })
            .collect::<Option<Vec<_>>>()?;
        Some(LambdaNetworkLease {
            vpc_id,
            subnet_ids: subnet_ids.to_vec(),
            security_group_ids: group_ids.to_vec(),
            _vpc: vpc,
            _subnet_guards: subnet_guards,
            _group_guards: group_guards,
        })
    }

    /// Evaluate the current IPv4 ingress policy of scoped security groups.
    /// Any missing group denies the selection; matching rules are ORed across groups.
    pub fn security_groups_allow_ingress(
        &self,
        account: &str,
        region: &str,
        group_ids: &[String],
        source: Ipv4Addr,
        port: u16,
    ) -> bool {
        if group_ids.is_empty() {
            return false;
        }
        let state = self.scopes.lock().unwrap();
        let Some(scope) = state.get(&(account.to_owned(), region.to_owned())) else {
            return false;
        };
        let groups = group_ids
            .iter()
            .map(|id| scope.security_groups.get(id))
            .collect::<Option<Vec<_>>>();
        let Some(groups) = groups else {
            return false;
        };
        groups.iter().any(|group| {
            group.ingress.iter().any(|rule| {
                rule.cidr.contains(&source)
                    && (rule.protocol == "-1"
                        || (rule.protocol == "tcp"
                            && rule.from_port.is_some_and(|from| from <= port)
                            && rule.to_port.is_some_and(|to| port <= to)))
            })
        })
    }

    /// Validate and retain a VPC, at least two subnets in distinct AZs, and security groups.
    /// Validation and guard capture are serialized with EC2 delete operations.
    pub fn alb_network_lease(
        &self,
        account: &str,
        region: &str,
        subnet_ids: &[String],
        security_group_ids: &[String],
    ) -> Option<AlbNetworkLease> {
        if subnet_ids.len() < 2 || security_group_ids.is_empty() {
            return None;
        }
        let state = self.scopes.lock().unwrap();
        let scope = state.get(&(account.to_owned(), region.to_owned()))?;
        let mut vpc_id: Option<&str> = None;
        let mut zones = std::collections::HashSet::new();
        let mut subnets = Vec::with_capacity(subnet_ids.len());
        let mut subnet_guards = Vec::with_capacity(subnet_ids.len());
        for id in subnet_ids {
            let subnet = scope.subnets.get(id)?;
            if vpc_id.is_some_and(|vpc| vpc != subnet.vpc_id) || !zones.insert(subnet.zone.as_str())
            {
                return None;
            }
            vpc_id = Some(&subnet.vpc_id);
            subnets.push((subnet.id.clone(), subnet.zone.clone()));
            subnet_guards.push(subnet.guard.clone());
        }
        let vpc_id = vpc_id?;
        let vpc = scope.vpcs.get(vpc_id)?.clone();
        let mut seen_groups = std::collections::HashSet::new();
        let mut group_guards = Vec::with_capacity(security_group_ids.len());
        for id in security_group_ids {
            if !seen_groups.insert(id.as_str()) {
                return None;
            }
            let group = scope.security_groups.get(id)?;
            if group.vpc_id != vpc_id {
                return None;
            }
            group_guards.push(group.guard.clone());
        }
        Some(AlbNetworkLease {
            vpc_id: vpc_id.to_owned(),
            subnets,
            security_group_ids: security_group_ids.to_vec(),
            _vpc: vpc,
            _subnet_guards: subnet_guards,
            _group_guards: group_guards,
        })
    }

    fn dispatch(&self, req: &ServiceRequest, input: &Input) -> Result<String, Ec2Error> {
        let action = input
            .one("Action")?
            .ok_or_else(|| Ec2Error::new("MissingAction", "Missing Action"))?;
        if let Some(version) = input.one("Version")? {
            if version != "2016-11-15" {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Unsupported API Version",
                ));
            }
        }
        let key = (req.account_id.clone(), req.region.clone());
        match action {
            "CreateVpc" => {
                input.allow(&[
                    "Action",
                    "Version",
                    "CidrBlock",
                    "DryRun",
                    "InstanceTenancy",
                    "AmazonProvidedIpv6CidrBlock",
                ])?;
                input.dry_run()?;
                match input.one("AmazonProvidedIpv6CidrBlock")? {
                    None | Some("false") => {}
                    Some("true") => {
                        return Err(Ec2Error::unsupported("AmazonProvidedIpv6CidrBlock"))
                    }
                    Some(_) => {
                        return Err(Ec2Error::new(
                            "InvalidParameterValue",
                            "AmazonProvidedIpv6CidrBlock must be boolean",
                        ))
                    }
                }
                let tenancy = input.one("InstanceTenancy")?.unwrap_or("default");
                if tenancy != "default" {
                    return Err(Ec2Error::unsupported("InstanceTenancy"));
                }
                let cidr = parse_cidr(input.required("CidrBlock")?, "CidrBlock")?;
                let id = resource_id("vpc");
                let vpc = Vpc {
                    id: id.clone(),
                    cidr,
                    owner: req.account_id.clone(),
                };
                let mut state = self.scopes.lock().unwrap();
                let scope = state.entry(key).or_default();
                scope.vpcs.insert(id.clone(), Arc::new(vpc.clone()));
                scope.vpc_dns.insert(id.clone(), (true, false));
                let main_table = RouteTable {
                    id: resource_id("rtb"),
                    vpc_id: id.clone(),
                    owner: req.account_id.clone(),
                    main: true,
                    routes: BTreeMap::from([(cidr, RouteTarget::Local)]),
                    endpoint_routes: BTreeMap::new(),
                    associations: BTreeMap::from([(resource_id("rtbassoc"), None)]),
                };
                scope.route_tables.insert(main_table.id.clone(), main_table);
                let default_id = resource_id("sg");
                scope.security_groups.insert(
                    default_id.clone(),
                    SecurityGroup {
                        id: default_id,
                        vpc_id: id,
                        name: "default".into(),
                        description: "default VPC security group".into(),
                        owner: req.account_id.clone(),
                        is_default: true,
                        ingress: Vec::new(),
                        egress: default_egress(),
                        guard: Arc::new(()),
                    },
                );
                Ok(format!("<vpc>{}</vpc>", vpc_xml(&vpc)))
            }
            "ModifyVpcAttribute" => self.modify_vpc_attribute(key, input),
            "DescribeVpcAttribute" => self.describe_vpc_attribute(key, input),
            "DescribeVpcs" => {
                input.allow_describe("VpcId", &["vpc-id", "cidr", "state", "owner-id"])?;
                let ids = input.indexed("VpcId")?;
                let filters = input.filters()?;
                let state = self.scopes.lock().unwrap();
                let scope = state.get(&key);
                let mut result = Vec::new();
                for id in &ids {
                    let vpc = scope.and_then(|s| s.vpcs.get(id)).ok_or_else(|| {
                        Ec2Error::new(
                            "InvalidVpcID.NotFound",
                            format!("The vpc ID '{id}' does not exist"),
                        )
                    })?;
                    result.push(vpc.clone());
                }
                if ids.is_empty() {
                    result.extend(scope.into_iter().flat_map(|s| s.vpcs.values().cloned()));
                }
                let body = result
                    .iter()
                    .filter(|vpc| {
                        filters.iter().all(|(name, vals)| match name.as_str() {
                            "vpc-id" => vals.contains(&vpc.id),
                            "cidr" => vals.contains(&vpc.cidr.to_string()),
                            "state" => vals.iter().any(|v| v == "available"),
                            "owner-id" => vals.contains(&vpc.owner),
                            _ => false,
                        })
                    })
                    .map(|vpc| format!("<item>{}</item>", vpc_xml(vpc)))
                    .collect::<String>();
                Ok(format!("<vpcSet>{body}</vpcSet>"))
            }
            "DeleteVpc" => {
                input.allow(&["Action", "Version", "VpcId", "DryRun"])?;
                input.dry_run()?;
                let id = input.required("VpcId")?;
                let mut state = self.scopes.lock().unwrap();
                let scope = state.entry(key).or_default();
                if !scope.vpcs.contains_key(id) {
                    return Err(Ec2Error::new(
                        "InvalidVpcID.NotFound",
                        format!("The vpc ID '{id}' does not exist"),
                    ));
                }
                if scope.subnets.values().any(|subnet| subnet.vpc_id == id)
                    || scope
                        .route_tables
                        .values()
                        .any(|table| table.vpc_id == id && !table.main)
                    || scope
                        .security_groups
                        .values()
                        .any(|group| group.vpc_id == id && !group.is_default)
                    || scope
                        .network_interfaces
                        .values()
                        .any(|eni| eni.vpc_id == id)
                    || scope
                        .internet_gateways
                        .values()
                        .any(|gateway| gateway.vpc_id.as_deref() == Some(id))
                    || scope
                        .nat_gateways
                        .values()
                        .any(|gateway| gateway.vpc_id == id)
                    || scope
                        .vpc_endpoints
                        .values()
                        .any(|endpoint| endpoint.vpc_id == id)
                    || scope
                        .vpcs
                        .get(id)
                        .is_some_and(|vpc| Arc::strong_count(vpc) > 1)
                {
                    return Err(Ec2Error::new(
                        "DependencyViolation",
                        "The vpc has dependencies and cannot be deleted",
                    ));
                }
                scope.vpcs.remove(id);
                scope.vpc_dns.remove(id);
                scope.route_tables.retain(|_, table| table.vpc_id != id);
                scope.security_groups.retain(|_, group| group.vpc_id != id);
                Ok("<return>true</return>".into())
            }
            "CreateSubnet" => {
                input.allow(&[
                    "Action",
                    "Version",
                    "VpcId",
                    "CidrBlock",
                    "AvailabilityZone",
                    "DryRun",
                ])?;
                input.dry_run()?;
                let vpc_id = input.required("VpcId")?;
                let cidr = parse_cidr(input.required("CidrBlock")?, "CidrBlock")?;
                let zone = input
                    .one("AvailabilityZone")?
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("{}a", req.region));
                if !zone.starts_with(&req.region)
                    || zone.len() != req.region.len() + 1
                    || !zone.ends_with(|c: char| c.is_ascii_lowercase())
                {
                    return Err(Ec2Error::new(
                        "InvalidParameterValue",
                        "Invalid availability zone",
                    ));
                }
                let mut state = self.scopes.lock().unwrap();
                let scope = state.entry(key).or_default();
                let vpc = scope.vpcs.get(vpc_id).ok_or_else(|| {
                    Ec2Error::new(
                        "InvalidVpcID.NotFound",
                        format!("The vpc ID '{vpc_id}' does not exist"),
                    )
                })?;
                if !contains_net(vpc.cidr, cidr) {
                    return Err(Ec2Error::new(
                        "InvalidSubnet.Range",
                        "The CIDR is outside the VPC range",
                    ));
                }
                if scope
                    .subnets
                    .values()
                    .any(|subnet| subnet.vpc_id == vpc_id && overlaps(subnet.cidr, cidr))
                {
                    return Err(Ec2Error::new(
                        "InvalidSubnet.Conflict",
                        "The CIDR conflicts with an existing subnet",
                    ));
                }
                let id = resource_id("subnet");
                let subnet = Subnet {
                    id: id.clone(),
                    vpc_id: vpc_id.to_owned(),
                    cidr,
                    zone,
                    owner: req.account_id.clone(),
                    guard: Arc::new(()),
                };
                scope.subnets.insert(id, subnet.clone());
                Ok(format!(
                    "<subnet>{}</subnet>",
                    subnet_xml(&subnet, &req.region, scope)
                ))
            }
            "DescribeSubnets" => {
                input.allow_describe(
                    "SubnetId",
                    &[
                        "subnet-id",
                        "vpc-id",
                        "cidr-block",
                        "state",
                        "availability-zone",
                    ],
                )?;
                let ids = input.indexed("SubnetId")?;
                let filters = input.filters()?;
                let state = self.scopes.lock().unwrap();
                let scope = state.get(&key);
                let mut result = Vec::new();
                for id in &ids {
                    let subnet = scope.and_then(|s| s.subnets.get(id)).ok_or_else(|| {
                        Ec2Error::new(
                            "InvalidSubnetID.NotFound",
                            format!("The subnet ID '{id}' does not exist"),
                        )
                    })?;
                    result.push(subnet.clone());
                }
                if ids.is_empty() {
                    result.extend(scope.into_iter().flat_map(|s| s.subnets.values().cloned()));
                }
                let body = result
                    .iter()
                    .filter(|subnet| {
                        filters.iter().all(|(name, vals)| match name.as_str() {
                            "subnet-id" => vals.contains(&subnet.id),
                            "vpc-id" => vals.contains(&subnet.vpc_id),
                            "cidr-block" => vals.contains(&subnet.cidr.to_string()),
                            "state" => vals.iter().any(|v| v == "available"),
                            "availability-zone" => vals.contains(&subnet.zone),
                            _ => false,
                        })
                    })
                    .map(|subnet| {
                        format!(
                            "<item>{}</item>",
                            subnet_xml(subnet, &req.region, scope.expect("result implies scope"))
                        )
                    })
                    .collect::<String>();
                Ok(format!("<subnetSet>{body}</subnetSet>"))
            }
            "DeleteSubnet" => {
                input.allow(&["Action", "Version", "SubnetId", "DryRun"])?;
                input.dry_run()?;
                let id = input.required("SubnetId")?;
                let mut state = self.scopes.lock().unwrap();
                let scope = state.entry(key).or_default();
                if !scope.subnets.contains_key(id) {
                    return Err(Ec2Error::new(
                        "InvalidSubnetID.NotFound",
                        format!("The subnet ID '{id}' does not exist"),
                    ));
                }
                if scope
                    .nat_gateways
                    .values()
                    .any(|gateway| gateway.subnet_id.as_deref() == Some(id))
                    || scope.route_tables.values().any(|table| {
                        table
                            .associations
                            .values()
                            .any(|subnet| subnet.as_deref() == Some(id))
                    })
                    || scope
                        .network_interfaces
                        .values()
                        .any(|eni| eni.subnet_id == id)
                    || scope
                        .vpc_endpoints
                        .values()
                        .any(|endpoint| endpoint.subnet_ids.iter().any(|subnet| subnet == id))
                    || scope
                        .subnets
                        .get(id)
                        .is_some_and(|subnet| Arc::strong_count(&subnet.guard) > 1)
                {
                    return Err(Ec2Error::new(
                        "DependencyViolation",
                        "The subnet has dependencies and cannot be deleted",
                    ));
                }
                if scope.subnets.remove(id).is_none() {
                    return Err(Ec2Error::new(
                        "InvalidSubnetID.NotFound",
                        format!("The subnet ID '{id}' does not exist"),
                    ));
                }
                Ok("<return>true</return>".into())
            }
            "CreateSecurityGroup" => {
                self.create_security_group(key, &req.account_id, &req.region, input)
            }
            "DescribeSecurityGroups" => self.describe_security_groups(key, input),
            "DeleteSecurityGroup" => self.delete_security_group(key, input),
            "AuthorizeSecurityGroupIngress" => self.authorize_security_group_ingress(key, input),
            "RevokeSecurityGroupIngress" => self.revoke_security_group_ingress(key, input),
            "AuthorizeSecurityGroupEgress" => self.authorize_security_group_egress(key, input),
            "RevokeSecurityGroupEgress" => self.revoke_security_group_egress(key, input),
            "CreateNetworkInterface" => {
                self.create_network_interface(key, &req.account_id, &req.region, input)
            }
            "DescribeNetworkInterfaces" => {
                self.describe_network_interfaces(key, &req.region, input)
            }
            "DeleteNetworkInterface" => self.delete_network_interface(key, input),
            "CreateInternetGateway" => self.create_internet_gateway(key, input),
            "DescribeInternetGateways" => self.describe_internet_gateways(key, input),
            "AttachInternetGateway" => self.attach_internet_gateway(key, input),
            "DetachInternetGateway" => self.detach_internet_gateway(key, input),
            "DeleteInternetGateway" => self.delete_internet_gateway(key, input),
            "AllocateAddress" => self.allocate_address(key, input),
            "DescribeAddresses" => self.describe_addresses(key, input),
            "DescribeAddressesAttribute" => self.describe_addresses_attribute(key, input),
            "ReleaseAddress" => self.release_address(key, input),
            "CreateNatGateway" => self.create_nat_gateway(key, input),
            "DescribeNatGateways" => self.describe_nat_gateways(key, input),
            "DeleteNatGateway" => self.delete_nat_gateway(key, input),
            "CreateRouteTable" => self.create_route_table(key, &req.account_id, input),
            "DescribeRouteTables" => self.describe_route_tables(key, input),
            "DeleteRouteTable" => self.delete_route_table(key, input),
            "CreateRoute" => self.create_route(key, input),
            "DeleteRoute" => self.delete_route(key, input),
            "AssociateRouteTable" => self.associate_route_table(key, input),
            "DisassociateRouteTable" => self.disassociate_route_table(key, input),
            "CreateVpcEndpoint" => self.create_vpc_endpoint(key, &req.region, input),
            "DescribeVpcEndpoints" => self.describe_vpc_endpoints(key, input),
            "DescribePrefixLists" => self.describe_prefix_lists(&req.region, input),
            "DeleteVpcEndpoints" => self.delete_vpc_endpoints(key, input),
            _ => Err(Ec2Error::new(
                "InvalidAction",
                format!("The action {action} is not valid for this endpoint"),
            )),
        }
    }
}

impl Ec2Handler {
    fn create_security_group(
        &self,
        key: (String, String),
        account: &str,
        region: &str,
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&[
            "Action",
            "Version",
            "DryRun",
            "VpcId",
            "GroupName",
            "GroupDescription",
        ])?;
        input.dry_run()?;
        let vpc_id = input.required("VpcId")?;
        let name = input.required("GroupName")?;
        let description = input.required("GroupDescription")?;
        if name.len() > 255
            || name.to_ascii_lowercase().starts_with("sg-")
            || !valid_group_text(name)
            || description.len() > 255
            || !valid_group_text(description)
        {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Invalid security group name or description",
            ));
        }
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        if !scope.vpcs.contains_key(vpc_id) {
            return Err(Ec2Error::new(
                "InvalidVpcID.NotFound",
                format!("The vpc ID '{vpc_id}' does not exist"),
            ));
        }
        if scope
            .security_groups
            .values()
            .any(|group| group.vpc_id == vpc_id && group.name.eq_ignore_ascii_case(name))
        {
            return Err(Ec2Error::new(
                "InvalidGroup.Duplicate",
                "The security group already exists",
            ));
        }
        let id = resource_id("sg");
        scope.security_groups.insert(
            id.clone(),
            SecurityGroup {
                id: id.clone(),
                vpc_id: vpc_id.into(),
                name: name.into(),
                description: description.into(),
                owner: account.into(),
                is_default: false,
                ingress: Vec::new(),
                egress: default_egress(),
                guard: Arc::new(()),
            },
        );
        Ok(format!("<return>true</return><groupId>{}</groupId><securityGroupArn>arn:aws:ec2:{}:{}:security-group/{}</securityGroupArn>", escape(&id), escape(region), escape(account), escape(&id)))
    }

    fn describe_security_groups(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_describe(
            "GroupId",
            &["group-id", "group-name", "vpc-id", "description"],
        )?;
        let ids = input.indexed("GroupId")?;
        let filters = input.filters()?;
        let state = self.scopes.lock().unwrap();
        let scope = state.get(&key);
        let mut result = Vec::new();
        for id in &ids {
            let group = scope
                .and_then(|s| s.security_groups.get(id))
                .ok_or_else(|| {
                    Ec2Error::new(
                        "InvalidGroup.NotFound",
                        format!("The security group '{id}' does not exist"),
                    )
                })?;
            result.push(group.clone());
        }
        if ids.is_empty() {
            result.extend(
                scope
                    .into_iter()
                    .flat_map(|s| s.security_groups.values().cloned()),
            );
        }
        let body = result
            .iter()
            .filter(|group| {
                filters.iter().all(|(name, vals)| match name.as_str() {
                    "group-id" => vals.contains(&group.id),
                    "group-name" => vals.contains(&group.name),
                    "vpc-id" => vals.contains(&group.vpc_id),
                    "description" => vals.contains(&group.description),
                    _ => false,
                })
            })
            .map(|group| format!("<item>{}</item>", group_xml(group)))
            .collect::<String>();
        Ok(format!("<securityGroupInfo>{body}</securityGroupInfo>"))
    }

    fn delete_security_group(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "GroupId"])?;
        input.dry_run()?;
        let id = input.required("GroupId")?;
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        let group = scope.security_groups.get(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidGroup.NotFound",
                format!("The security group '{id}' does not exist"),
            )
        })?;
        if group.is_default {
            return Err(Ec2Error::new(
                "Client.CannotDelete",
                "The default security group cannot be deleted",
            ));
        }
        if scope
            .network_interfaces
            .values()
            .any(|eni| eni.group_ids.iter().any(|group_id| group_id == id))
            || scope
                .vpc_endpoints
                .values()
                .any(|endpoint| endpoint.group_ids.iter().any(|group| group == id))
            || Arc::strong_count(&group.guard) > 1
        {
            return Err(Ec2Error::new(
                "DependencyViolation",
                "The security group has dependencies and cannot be deleted",
            ));
        }
        scope.security_groups.remove(id);
        Ok("<return>true</return>".into())
    }

    fn authorize_security_group_ingress(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_ingress()?;
        input.dry_run()?;
        let id = input.required("GroupId")?;
        let (protocol, from_port, to_port, cidr) = input.ingress_rule()?;
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        let group = scope.security_groups.get_mut(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidGroup.NotFound",
                format!("The security group '{id}' does not exist"),
            )
        })?;
        if group.ingress.iter().any(|r| {
            r.protocol == protocol
                && r.from_port == from_port
                && r.to_port == to_port
                && r.cidr == cidr
        }) {
            return Err(Ec2Error::new(
                "InvalidPermission.Duplicate",
                "The specified rule already exists",
            ));
        }
        let rule_id = resource_id("sgr");
        group.ingress.push(IngressRule {
            protocol: protocol.clone(),
            from_port,
            to_port,
            cidr,
        });
        Ok(format!("<return>true</return><securityGroupRuleSet><item><groupId>{}</groupId><securityGroupRuleId>{}</securityGroupRuleId><isEgress>false</isEgress><ipProtocol>{}</ipProtocol>{}<cidrIpv4>{}</cidrIpv4></item></securityGroupRuleSet>", escape(id), escape(&rule_id), escape(&protocol), ports_xml(from_port, to_port), cidr))
    }

    fn revoke_security_group_ingress(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_ingress()?;
        input.dry_run()?;
        let id = input.required("GroupId")?;
        let (protocol, from_port, to_port, cidr) = input.ingress_rule()?;
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        let group = scope.security_groups.get_mut(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidGroup.NotFound",
                format!("The security group '{id}' does not exist"),
            )
        })?;
        let before = group.ingress.len();
        group.ingress.retain(|rule| {
            !(rule.protocol == protocol
                && rule.from_port == from_port
                && rule.to_port == to_port
                && rule.cidr == cidr)
        });
        if group.ingress.len() == before {
            return Err(Ec2Error::new(
                "InvalidPermission.NotFound",
                "The specified rule does not exist",
            ));
        }
        Ok("<return>true</return>".into())
    }

    fn create_network_interface(
        &self,
        key: (String, String),
        account: &str,
        region: &str,
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_eni_create()?;
        input.dry_run()?;
        let subnet_id = input.required("SubnetId")?;
        let requested_ip = input
            .one("PrivateIpAddress")?
            .map(|value| {
                value
                    .parse::<Ipv4Addr>()
                    .map_err(|_| Ec2Error::new("InvalidParameterValue", "Invalid PrivateIpAddress"))
            })
            .transpose()?;
        let group_ids = input.indexed("SecurityGroupId")?;
        let token = input.one("ClientToken")?.filter(|value| !value.is_empty());
        if input.one("ClientToken")?.is_some()
            && token.is_none_or(|value| value.len() > 64 || !value.is_ascii())
        {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "ClientToken must be 1-64 ASCII characters",
            ));
        }
        let params = input.eni_idempotency_params();
        let description = input.one("Description")?.unwrap_or("");
        if description.len() > 255 {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Description is too long",
            ));
        }
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        if let Some(token) = token {
            if let Some(previous) = scope.eni_tokens.get(token) {
                if previous.params != params {
                    return Err(Ec2Error::new(
                        "IdempotentParameterMismatch",
                        "ClientToken was already used with different parameters",
                    ));
                }
                if let Some(eni) = scope.network_interfaces.get(&previous.eni_id) {
                    return Ok(format!(
                        "<networkInterface>{}</networkInterface>",
                        eni_xml(eni, scope, region)
                    ));
                }
            }
        }
        let subnet = scope.subnets.get(subnet_id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidSubnetID.NotFound",
                format!("The subnet ID '{subnet_id}' does not exist"),
            )
        })?;
        let group_ids = if group_ids.is_empty() {
            vec![scope
                .security_groups
                .values()
                .find(|g| g.vpc_id == subnet.vpc_id && g.is_default)
                .ok_or_else(|| {
                    Ec2Error::new("InvalidGroup.NotFound", "Default security group is missing")
                })?
                .id
                .clone()]
        } else {
            group_ids
        };
        for id in &group_ids {
            let group = scope.security_groups.get(id).ok_or_else(|| {
                Ec2Error::new(
                    "InvalidGroup.NotFound",
                    format!("The security group '{id}' does not exist"),
                )
            })?;
            if group.vpc_id != subnet.vpc_id {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Security group is not in the subnet VPC",
                ));
            }
        }
        if group_ids.len()
            != group_ids
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
        {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Duplicate security group",
            ));
        }
        let base = u32::from(subnet.cidr.network());
        let size = 1_u32 << (32 - subnet.cidr.prefix_len());
        let is_usable = |ip: Ipv4Addr| {
            let offset = u32::from(ip).wrapping_sub(base);
            offset >= 4 && offset < size - 1
        };
        let is_free = |ip: Ipv4Addr| {
            !scope
                .network_interfaces
                .values()
                .any(|eni| eni.subnet_id == subnet_id && eni.private_ip == ip)
        };
        let private_ip = match requested_ip {
            Some(ip) if !is_usable(ip) => {
                return Err(Ec2Error::new(
                    "InvalidIPAddress.InUse",
                    "Private IP is reserved or outside subnet",
                ))
            }
            Some(ip) if !is_free(ip) => {
                return Err(Ec2Error::new(
                    "InvalidIPAddress.InUse",
                    "Private IP is already in use",
                ))
            }
            Some(ip) => ip,
            None => (4..size - 1)
                .map(|offset| Ipv4Addr::from(base + offset))
                .find(|ip| is_free(*ip))
                .ok_or_else(|| {
                    Ec2Error::new(
                        "InsufficientFreeAddressesInSubnet",
                        "No private IP addresses available",
                    )
                })?,
        };
        let id = resource_id("eni");
        let eni = NetworkInterface {
            id: id.clone(),
            subnet_id: subnet_id.into(),
            vpc_id: subnet.vpc_id.clone(),
            zone: subnet.zone.clone(),
            private_ip,
            description: description.into(),
            owner: account.into(),
            group_ids,
        };
        scope.network_interfaces.insert(id.clone(), eni.clone());
        if let Some(token) = token {
            scope
                .eni_tokens
                .insert(token.to_owned(), IdempotentEni { params, eni_id: id });
        }
        Ok(format!(
            "<networkInterface>{}</networkInterface>",
            eni_xml(&eni, scope, region)
        ))
    }

    fn describe_network_interfaces(
        &self,
        key: (String, String),
        region: &str,
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_describe(
            "NetworkInterfaceId",
            &[
                "network-interface-id",
                "subnet-id",
                "vpc-id",
                "private-ip-address",
                "group-id",
                "status",
                "availability-zone",
            ],
        )?;
        let ids = input.indexed("NetworkInterfaceId")?;
        let filters = input.filters()?;
        let state = self.scopes.lock().unwrap();
        let scope = state.get(&key);
        let mut result = Vec::new();
        for id in &ids {
            let eni = scope
                .and_then(|s| s.network_interfaces.get(id))
                .ok_or_else(|| {
                    Ec2Error::new(
                        "InvalidNetworkInterfaceID.NotFound",
                        format!("The network interface '{id}' does not exist"),
                    )
                })?;
            result.push(eni.clone());
        }
        if ids.is_empty() {
            result.extend(
                scope
                    .into_iter()
                    .flat_map(|s| s.network_interfaces.values().cloned()),
            );
        }
        let body = result
            .iter()
            .filter(|eni| {
                filters.iter().all(|(name, vals)| match name.as_str() {
                    "network-interface-id" => vals.contains(&eni.id),
                    "subnet-id" => vals.contains(&eni.subnet_id),
                    "vpc-id" => vals.contains(&eni.vpc_id),
                    "private-ip-address" => vals.contains(&eni.private_ip.to_string()),
                    "group-id" => eni.group_ids.iter().any(|id| vals.contains(id)),
                    "status" => vals.iter().any(|v| {
                        let status = if scope
                            .expect("result implies scope")
                            .task_networks
                            .contains_key(&eni.id)
                        {
                            "in-use"
                        } else {
                            "available"
                        };
                        v == status
                    }),
                    "availability-zone" => vals.contains(&eni.zone),
                    _ => false,
                })
            })
            .map(|eni| {
                format!(
                    "<item>{}</item>",
                    eni_xml(eni, scope.expect("result implies scope"), region)
                )
            })
            .collect::<String>();
        Ok(format!("<networkInterfaceSet>{body}</networkInterfaceSet>"))
    }

    fn delete_network_interface(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "NetworkInterfaceId"])?;
        input.dry_run()?;
        let id = input.required("NetworkInterfaceId")?;
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        if !scope.network_interfaces.contains_key(id) {
            return Err(Ec2Error::new(
                "InvalidNetworkInterfaceID.NotFound",
                format!("The network interface '{id}' does not exist"),
            ));
        }
        if scope.task_networks.contains_key(id)
            || scope.instances.values().any(|instance| {
                instance.eni_id == id && instance.state != InstanceState::Terminated
            })
        {
            return Err(Ec2Error::new(
                "DependencyViolation",
                "The network interface is attached to an instance",
            ));
        }
        if scope.route_tables.values().any(|table| {
            table.routes.values().any(
                |target| matches!(target, RouteTarget::NetworkInterface(eni_id) if eni_id == id),
            )
        }) {
            return Err(Ec2Error::new(
                "DependencyViolation",
                "The network interface is a route target",
            ));
        }
        scope.network_interfaces.remove(id);
        scope.eni_tokens.retain(|_, record| record.eni_id != id);
        Ok("<return>true</return>".into())
    }
}

impl Ec2Handler {
    fn create_route_table(
        &self,
        key: (String, String),
        account: &str,
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "VpcId", "ClientToken"])?;
        input.dry_run()?;
        let vpc_id = input.required("VpcId")?;
        let token = input.one("ClientToken")?;
        if token.is_some_and(|value| value.is_empty() || value.len() > 64 || !value.is_ascii()) {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "ClientToken must be 1-64 ASCII characters",
            ));
        }
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        if let Some(token) = token {
            if let Some((previous_vpc, table_id)) = scope.route_table_tokens.get(token) {
                if previous_vpc != vpc_id {
                    return Err(Ec2Error::new(
                        "IdempotentParameterMismatch",
                        "ClientToken was already used with a different VpcId",
                    ));
                }
                if let Some(table) = scope.route_tables.get(table_id) {
                    return Ok(format!(
                        "<routeTable>{}</routeTable><clientToken>{}</clientToken>",
                        route_table_xml(table),
                        escape(token)
                    ));
                }
            }
        }
        let vpc = scope.vpcs.get(vpc_id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidVpcID.NotFound",
                format!("The vpc ID '{vpc_id}' does not exist"),
            )
        })?;
        let table = RouteTable {
            id: resource_id("rtb"),
            vpc_id: vpc_id.into(),
            owner: account.into(),
            main: false,
            routes: BTreeMap::from([(vpc.cidr, RouteTarget::Local)]),
            endpoint_routes: BTreeMap::new(),
            associations: BTreeMap::new(),
        };
        let xml = route_table_xml(&table);
        if let Some(token) = token {
            scope
                .route_table_tokens
                .insert(token.into(), (vpc_id.into(), table.id.clone()));
        }
        scope.route_tables.insert(table.id.clone(), table);
        let token_xml = token
            .map(|value| format!("<clientToken>{}</clientToken>", escape(value)))
            .unwrap_or_default();
        Ok(format!("<routeTable>{xml}</routeTable>{token_xml}"))
    }

    fn describe_route_tables(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_describe(
            "RouteTableId",
            &[
                "route-table-id",
                "vpc-id",
                "association.main",
                "association.subnet-id",
                "association.route-table-association-id",
                "route.destination-cidr-block",
                "route.network-interface-id",
                "route.gateway-id",
                "route.nat-gateway-id",
            ],
        )?;
        let ids = input.indexed("RouteTableId")?;
        let filters = input.filters()?;
        let state = self.scopes.lock().unwrap();
        let scope = state.get(&key);
        let mut tables = Vec::new();
        for id in &ids {
            tables.push(scope.and_then(|s| s.route_tables.get(id)).ok_or_else(|| {
                Ec2Error::new(
                    "InvalidRouteTableID.NotFound",
                    format!("The route table ID '{id}' does not exist"),
                )
            })?);
        }
        if ids.is_empty() {
            tables.extend(scope.into_iter().flat_map(|s| s.route_tables.values()));
        }
        let body = tables
            .into_iter()
            .filter(|table| {
                filters.iter().all(|(name, vals)| match name.as_str() {
                    "route-table-id" => vals.contains(&table.id),
                    "vpc-id" => vals.contains(&table.vpc_id),
                    "association.main" => vals.contains(&table.main.to_string()),
                    "association.subnet-id" => table
                        .associations
                        .values()
                        .flatten()
                        .any(|id| vals.contains(id)),
                    "association.route-table-association-id" => {
                        table.associations.keys().any(|id| vals.contains(id))
                    }
                    "route.destination-cidr-block" => table
                        .routes
                        .keys()
                        .any(|cidr| vals.contains(&cidr.to_string())),
                    "route.network-interface-id" => table.routes.values().any(|target| matches!(target, RouteTarget::NetworkInterface(id) if vals.contains(id))),
                    "route.gateway-id" => table.routes.values().any(|target| matches!(target, RouteTarget::InternetGateway(id) if vals.contains(id))),
                    "route.nat-gateway-id" => table.routes.values().any(|target| matches!(target, RouteTarget::NatGateway(id) | RouteTarget::BlackholeNatGateway(id) if vals.contains(id))),
                    _ => false,
                })
            })
            .map(|table| format!("<item>{}</item>", route_table_xml(table)))
            .collect::<String>();
        Ok(format!("<routeTableSet>{body}</routeTableSet>"))
    }

    fn delete_route_table(&self, key: (String, String), input: &Input) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "RouteTableId"])?;
        input.dry_run()?;
        let id = input.required("RouteTableId")?;
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        let table = scope.route_tables.get(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidRouteTableID.NotFound",
                format!("The route table ID '{id}' does not exist"),
            )
        })?;
        if table.main || !table.associations.is_empty() || !table.endpoint_routes.is_empty() {
            return Err(Ec2Error::new(
                "DependencyViolation",
                "The route table has associations or is the main route table",
            ));
        }
        scope.route_tables.remove(id);
        scope
            .route_table_tokens
            .retain(|_, (_, table_id)| table_id != id);
        Ok("<return>true</return>".into())
    }

    fn create_route(&self, key: (String, String), input: &Input) -> Result<String, Ec2Error> {
        input.allow(&[
            "Action",
            "Version",
            "DryRun",
            "RouteTableId",
            "DestinationCidrBlock",
            "NetworkInterfaceId",
            "GatewayId",
            "NatGatewayId",
        ])?;
        input.dry_run()?;
        let id = input.required("RouteTableId")?;
        let destination = parse_any_ipv4_cidr(
            input.required("DestinationCidrBlock")?,
            "DestinationCidrBlock",
        )?;
        let targets = [
            input.one("NetworkInterfaceId")?,
            input.one("GatewayId")?,
            input.one("NatGatewayId")?,
        ];
        if targets.iter().filter(|target| target.is_some()).count() != 1 {
            return Err(Ec2Error::new(
                "InvalidParameterCombination",
                "Exactly one route target is required",
            ));
        }
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        let table = scope.route_tables.get(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidRouteTableID.NotFound",
                format!("The route table ID '{id}' does not exist"),
            )
        })?;
        let target = if let Some(eni_id) = targets[0] {
            let eni = scope.network_interfaces.get(eni_id).ok_or_else(|| {
                Ec2Error::new(
                    "InvalidNetworkInterfaceID.NotFound",
                    format!("The network interface '{eni_id}' does not exist"),
                )
            })?;
            if eni.vpc_id != table.vpc_id {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Route target must be in the route table VPC",
                ));
            }
            RouteTarget::NetworkInterface(eni_id.into())
        } else if let Some(gateway_id) = targets[1] {
            let gateway = scope.internet_gateways.get(gateway_id).ok_or_else(|| {
                Ec2Error::new(
                    "InvalidInternetGatewayID.NotFound",
                    format!("The internet gateway ID '{gateway_id}' does not exist"),
                )
            })?;
            if gateway.vpc_id.as_deref() != Some(&table.vpc_id) {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Internet gateway must be attached to the route table VPC",
                ));
            }
            RouteTarget::InternetGateway(gateway_id.into())
        } else {
            let nat_id = targets[2].unwrap();
            let nat = scope.nat_gateways.get(nat_id).ok_or_else(|| {
                Ec2Error::new(
                    "NatGatewayNotFound",
                    format!("The NAT gateway ID '{nat_id}' does not exist"),
                )
            })?;
            if nat.vpc_id != table.vpc_id {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "NAT gateway must be in the route table VPC",
                ));
            }
            RouteTarget::NatGateway(nat_id.into())
        };
        let table = scope.route_tables.get_mut(id).unwrap();
        if table.routes.contains_key(&destination) {
            return Err(Ec2Error::new(
                "RouteAlreadyExists",
                "The route already exists",
            ));
        }
        table.routes.insert(destination, target);
        Ok("<return>true</return>".into())
    }

    fn delete_route(&self, key: (String, String), input: &Input) -> Result<String, Ec2Error> {
        input.allow(&[
            "Action",
            "Version",
            "DryRun",
            "RouteTableId",
            "DestinationCidrBlock",
        ])?;
        input.dry_run()?;
        let id = input.required("RouteTableId")?;
        let destination = parse_any_ipv4_cidr(
            input.required("DestinationCidrBlock")?,
            "DestinationCidrBlock",
        )?;
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        let table = scope.route_tables.get_mut(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidRouteTableID.NotFound",
                format!("The route table ID '{id}' does not exist"),
            )
        })?;
        match table.routes.get(&destination) {
            None => {
                return Err(Ec2Error::new(
                    "InvalidRoute.NotFound",
                    "The route does not exist",
                ))
            }
            Some(RouteTarget::Local) => {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "The local route cannot be deleted",
                ))
            }
            Some(_) => {}
        }
        table.routes.remove(&destination);
        Ok("<return>true</return>".into())
    }

    fn associate_route_table(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "RouteTableId", "SubnetId"])?;
        input.dry_run()?;
        let id = input.required("RouteTableId")?;
        let subnet_id = input.required("SubnetId")?;
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        let subnet = scope.subnets.get(subnet_id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidSubnetID.NotFound",
                format!("The subnet ID '{subnet_id}' does not exist"),
            )
        })?;
        let table = scope.route_tables.get(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidRouteTableID.NotFound",
                format!("The route table ID '{id}' does not exist"),
            )
        })?;
        if subnet.vpc_id != table.vpc_id {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Subnet and route table must be in the same VPC",
            ));
        }
        if scope.route_tables.values().any(|t| {
            t.associations
                .values()
                .any(|s| s.as_deref() == Some(subnet_id))
        }) {
            return Err(Ec2Error::new(
                "Resource.AlreadyAssociated",
                "The subnet already has an explicit route table association",
            ));
        }
        let association_id = resource_id("rtbassoc");
        scope
            .route_tables
            .get_mut(id)
            .unwrap()
            .associations
            .insert(association_id.clone(), Some(subnet_id.into()));
        Ok(format!("<associationId>{association_id}</associationId><associationState><state>associated</state></associationState>"))
    }

    fn disassociate_route_table(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow(&["Action", "Version", "DryRun", "AssociationId"])?;
        input.dry_run()?;
        let id = input.required("AssociationId")?;
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        let table = scope
            .route_tables
            .values_mut()
            .find(|table| table.associations.contains_key(id))
            .ok_or_else(|| {
                Ec2Error::new(
                    "InvalidAssociationID.NotFound",
                    format!("The association ID '{id}' does not exist"),
                )
            })?;
        if table.associations.get(id) == Some(&None) {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "The main route table association cannot be disassociated",
            ));
        }
        table.associations.remove(id);
        Ok("<return>true</return>".into())
    }
}

fn route_table_xml(table: &RouteTable) -> String {
    let routes = table.routes.iter().map(|(cidr, target)| {
        let (tag, id, origin, state) = match target {
            RouteTarget::Local => ("gatewayId", "local", "CreateRouteTable", "active"),
            RouteTarget::NetworkInterface(id) => ("networkInterfaceId", id.as_str(), "CreateRoute", "active"),
            RouteTarget::InternetGateway(id) => ("gatewayId", id.as_str(), "CreateRoute", "active"),
            RouteTarget::NatGateway(id) => ("natGatewayId", id.as_str(), "CreateRoute", "active"),
            RouteTarget::BlackholeNatGateway(id) => ("natGatewayId", id.as_str(), "CreateRoute", "blackhole"),
        };
        format!("<item><destinationCidrBlock>{cidr}</destinationCidrBlock><{tag}>{}</{tag}><state>{state}</state><origin>{origin}</origin></item>", escape(id))
    }).collect::<String>();
    let endpoint_routes = table.endpoint_routes.iter().map(|(service, endpoint_id)| {
        let prefix = match service.as_str() { "s3" => "pl-00000001", "dynamodb" => "pl-00000002", _ => unreachable!("validated gateway service") };
        format!("<item><destinationPrefixListId>{prefix}</destinationPrefixListId><vpcEndpointId>{}</vpcEndpointId><state>active</state><origin>CreateRoute</origin></item>", escape(endpoint_id))
    }).collect::<String>();
    let associations = table.associations.iter().map(|(id, subnet)| {
        let subnet_xml = subnet.as_ref().map(|id| format!("<subnetId>{}</subnetId>", escape(id))).unwrap_or_default();
        format!("<item><routeTableAssociationId>{}</routeTableAssociationId><routeTableId>{}</routeTableId>{subnet_xml}<main>{}</main><associationState><state>associated</state></associationState></item>", escape(id), escape(&table.id), subnet.is_none())
    }).collect::<String>();
    format!("<routeTableId>{}</routeTableId><vpcId>{}</vpcId><ownerId>{}</ownerId><routeSet>{routes}{endpoint_routes}</routeSet><associationSet>{associations}</associationSet><propagatingVgwSet/><tagSet/>", escape(&table.id), escape(&table.vpc_id), escape(&table.owner))
}
impl Ec2Handler {
    async fn run_instances(&self, req: &ServiceRequest, input: &Input) -> Result<String, Ec2Error> {
        for key in input.fields.keys() {
            if [
                "Action",
                "Version",
                "DryRun",
                "ImageId",
                "InstanceType",
                "MinCount",
                "MaxCount",
                "SubnetId",
                "ClientToken",
            ]
            .contains(&key.as_str())
                || indexed_key(key, "SecurityGroupId").is_some()
                || indexed_key(key, "SecurityGroup").is_some()
            {
                continue;
            }
            return Err(Ec2Error::unsupported(key));
        }
        input.dry_run()?;
        let image = input.required("ImageId")?;
        let kind = input.required("InstanceType")?;
        if image != "ami-localcloud-http" || kind != "t3.micro" {
            return Err(Ec2Error::new(
                "UnsupportedOperation",
                "Only ami-localcloud-http with t3.micro is supported",
            ));
        }
        if input.required("MinCount")? != "1" || input.required("MaxCount")? != "1" {
            return Err(Ec2Error::new(
                "UnsupportedOperation",
                "Only one instance per request is supported",
            ));
        }
        let subnet_id = input.required("SubnetId")?;
        let token = input.one("ClientToken")?;
        if token.is_some_and(|s| s.is_empty() || s.len() > 64 || !s.is_ascii()) {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "ClientToken must be 1-64 ASCII characters",
            ));
        }
        let group_ids = input.indexed("SecurityGroupId")?;
        if !input.indexed("SecurityGroup")?.is_empty() {
            return Err(Ec2Error::unsupported("SecurityGroup"));
        }
        let params = input.eni_idempotency_params();
        let key = (req.account_id.clone(), req.region.clone());
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| {
                Ec2Error::new("UnsupportedOperation", "Instance runtime is not configured")
            })?
            .clone();
        let spec = {
            let mut state = self.scopes.lock().unwrap();
            let scope = state.entry(key.clone()).or_default();
            if let Some(token) = token {
                if let Some(previous) = scope.instance_tokens.get(token) {
                    if previous.params != params {
                        return Err(Ec2Error::new(
                            "IdempotentParameterMismatch",
                            "ClientToken was already used with different parameters",
                        ));
                    }
                    if let Some(instance) = scope.instances.get(&previous.instance_id) {
                        return Ok(format!("<reservationId>{}</reservationId><ownerId>{}</ownerId><groupSet/><instancesSet><item>{}</item></instancesSet>", escape(&format!("r-{}", &instance.spec.instance_id[2..])), escape(&req.account_id), instance_xml(instance, scope)));
                    }
                }
            }
            let subnet = scope.subnets.get(subnet_id).ok_or_else(|| {
                Ec2Error::new(
                    "InvalidSubnetID.NotFound",
                    format!("The subnet ID '{subnet_id}' does not exist"),
                )
            })?;
            let ids = if group_ids.is_empty() {
                vec![scope
                    .security_groups
                    .values()
                    .find(|g| g.vpc_id == subnet.vpc_id && g.is_default)
                    .ok_or_else(|| {
                        Ec2Error::new("InvalidGroup.NotFound", "Default security group is missing")
                    })?
                    .id
                    .clone()]
            } else {
                group_ids
            };
            if ids.len() != ids.iter().collect::<std::collections::HashSet<_>>().len() {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Duplicate security group",
                ));
            }
            for id in &ids {
                let group = scope.security_groups.get(id).ok_or_else(|| {
                    Ec2Error::new(
                        "InvalidGroup.NotFound",
                        format!("The security group '{id}' does not exist"),
                    )
                })?;
                if group.vpc_id != subnet.vpc_id {
                    return Err(Ec2Error::new(
                        "InvalidParameterValue",
                        "Security group is not in the subnet VPC",
                    ));
                }
            }
            let base = u32::from(subnet.cidr.network());
            let size = 1_u32 << (32 - subnet.cidr.prefix_len());
            let private_ip = (4..size - 1)
                .map(|offset| Ipv4Addr::from(base + offset))
                .find(|ip| {
                    !scope
                        .network_interfaces
                        .values()
                        .any(|eni| eni.subnet_id == subnet_id && eni.private_ip == *ip)
                })
                .ok_or_else(|| {
                    Ec2Error::new(
                        "InsufficientFreeAddressesInSubnet",
                        "No private IP addresses available",
                    )
                })?;
            let spec = InstanceSpec {
                instance_id: resource_id("i"),
                image_id: image.into(),
                instance_type: kind.into(),
                vpc_id: subnet.vpc_id.clone(),
                subnet_id: subnet.id.clone(),
                private_ip,
                security_group_ids: ids.clone(),
                guest_port: 8080,
            };
            let eni = NetworkInterface {
                id: resource_id("eni"),
                subnet_id: subnet.id.clone(),
                vpc_id: subnet.vpc_id.clone(),
                zone: subnet.zone.clone(),
                private_ip,
                description: format!("Primary network interface for {}", spec.instance_id),
                owner: req.account_id.clone(),
                group_ids: ids,
            };
            let eni_id = eni.id.clone();
            scope.network_interfaces.insert(eni_id.clone(), eni);
            scope.instances.insert(
                spec.instance_id.clone(),
                Instance {
                    spec: spec.clone(),
                    eni_id,
                    state: InstanceState::Pending,
                    endpoint: None,
                },
            );
            if let Some(token) = token {
                scope.instance_tokens.insert(
                    token.into(),
                    IdempotentInstance {
                        params,
                        instance_id: spec.instance_id.clone(),
                    },
                );
            }
            spec
        };
        let started = runtime.start_instance(&spec).await;
        let healthy = if started.is_ok() {
            probe_instance(runtime.as_ref(), &spec).await
        } else {
            false
        };
        if !healthy {
            self.cleanup_failed_start(&key, &spec.instance_id, runtime.as_ref())
                .await;
            return Err(Ec2Error::new(
                "InternalError",
                "Instance runtime failed to start a healthy HTTP service",
            ));
        }
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(_) => {
                self.cleanup_failed_start(&key, &spec.instance_id, runtime.as_ref())
                    .await;
                return Err(Ec2Error::new(
                    "InternalError",
                    "Could not bind instance proxy",
                ));
            }
        };
        let endpoint = listener
            .local_addr()
            .expect("bound TCP listener has an address");
        let xml = {
            let mut state = self.scopes.lock().unwrap();
            let scope = state.get_mut(&key).expect("created scope");
            match scope.instances.get_mut(&spec.instance_id) {
                Some(instance) if instance.state == InstanceState::Pending => {
                    instance.state = InstanceState::Running;
                    instance.endpoint = Some(endpoint);
                    let instance = instance.clone();
                    Some(format!("<reservationId>{}</reservationId><ownerId>{}</ownerId><groupSet/><instancesSet><item>{}</item></instancesSet>", escape(&format!("r-{}", &spec.instance_id[2..])), escape(&req.account_id), instance_xml(&instance, scope)))
                }
                _ => None,
            }
        };
        let Some(xml) = xml else {
            self.cleanup_failed_start(&key, &spec.instance_id, runtime.as_ref())
                .await;
            return Err(Ec2Error::new(
                "InternalError",
                "Instance was terminated during startup",
            ));
        };
        let scopes = self.scopes.clone();
        tokio::spawn(async move {
            serve_instance_proxy(listener, scopes, key, spec, runtime).await;
        });
        Ok(xml)
    }

    async fn describe_instances(
        &self,
        req: &ServiceRequest,
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_describe(
            "InstanceId",
            &[
                "instance-id",
                "image-id",
                "instance-state-name",
                "private-ip-address",
                "subnet-id",
                "vpc-id",
            ],
        )?;
        let ids = input.indexed("InstanceId")?;
        let filters = input.filters()?;
        let key = (req.account_id.clone(), req.region.clone());
        if let Some(runtime) = &self.runtime {
            let running = {
                let state = self.scopes.lock().unwrap();
                state
                    .get(&key)
                    .map(|scope| {
                        scope
                            .instances
                            .values()
                            .filter(|i| i.state == InstanceState::Running)
                            .map(|i| i.spec.instance_id.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };
            for id in running {
                if !runtime.instance_running(&id).await {
                    self.mark_terminated(&key, &id);
                }
            }
        }
        let state = self.scopes.lock().unwrap();
        let scope = state.get(&key);
        let mut instances = Vec::new();
        for id in &ids {
            instances.push(scope.and_then(|s| s.instances.get(id)).ok_or_else(|| {
                Ec2Error::new(
                    "InvalidInstanceID.NotFound",
                    format!("The instance ID '{id}' does not exist"),
                )
            })?);
        }
        if ids.is_empty() {
            instances.extend(scope.into_iter().flat_map(|s| s.instances.values()));
        }
        let body = instances.into_iter().filter(|i| filters.iter().all(|(name, values)| match name.as_str() {
            "instance-id" => values.contains(&i.spec.instance_id), "image-id" => values.contains(&i.spec.image_id),
            "instance-state-name" => values.iter().any(|v| v == instance_state(i.state)), "private-ip-address" => values.contains(&i.spec.private_ip.to_string()),
            "subnet-id" => values.contains(&i.spec.subnet_id), "vpc-id" => values.contains(&i.spec.vpc_id), _ => false,
        })).map(|i| format!("<item><reservationId>r-{}</reservationId><ownerId>{}</ownerId><groupSet/><instancesSet><item>{}</item></instancesSet></item>", escape(&i.spec.instance_id[2..]), escape(&req.account_id), instance_xml(i, scope.expect("instance implies scope")))).collect::<String>();
        Ok(format!("<reservationSet>{body}</reservationSet>"))
    }

    async fn terminate_instances(
        &self,
        req: &ServiceRequest,
        input: &Input,
    ) -> Result<String, Ec2Error> {
        for key in input.fields.keys() {
            if ["Action", "Version", "DryRun"].contains(&key.as_str())
                || indexed_key(key, "InstanceId").is_some()
            {
                continue;
            }
            return Err(Ec2Error::unsupported(key));
        }
        input.dry_run()?;
        let ids = input.indexed("InstanceId")?;
        if ids.is_empty() {
            return Err(Ec2Error::new("MissingParameter", "InstanceId is required"));
        }
        let key = (req.account_id.clone(), req.region.clone());
        let runtime = self.runtime.as_ref().ok_or_else(|| {
            Ec2Error::new("UnsupportedOperation", "Instance runtime is not configured")
        })?;
        let previous = {
            let mut state = self.scopes.lock().unwrap();
            let scope = state.entry(key.clone()).or_default();
            for id in &ids {
                if !scope.instances.contains_key(id) {
                    return Err(Ec2Error::new(
                        "InvalidInstanceID.NotFound",
                        format!("The instance ID '{id}' does not exist"),
                    ));
                }
            }
            let mut previous = Vec::new();
            for id in &ids {
                let instance = scope.instances.get_mut(id).expect("validated");
                let old = instance.state;
                if old == InstanceState::Running || old == InstanceState::Pending {
                    instance.state = InstanceState::ShuttingDown;
                    instance.endpoint = None;
                }
                previous.push(old);
            }
            previous
        };
        let mut body = String::new();
        for (id, old) in ids.iter().zip(previous) {
            if old != InstanceState::Terminated {
                if runtime.stop_instance(id).await.is_err() {
                    return Err(Ec2Error::new("InternalError", "Could not stop instance"));
                }
                self.mark_terminated(&key, id);
            }
            body.push_str(&format!("<item><instanceId>{}</instanceId><currentState><code>48</code><name>terminated</name></currentState><previousState><code>{}</code><name>{}</name></previousState></item>", escape(id), instance_state_code(old), instance_state(old)));
        }
        Ok(format!("<instancesSet>{body}</instancesSet>"))
    }

    async fn cleanup_failed_start(
        &self,
        key: &(String, String),
        id: &str,
        runtime: &dyn InstanceRuntime,
    ) {
        let stopped = runtime.stop_instance(id).await.is_ok();
        let mut state = self.scopes.lock().unwrap();
        if let Some(scope) = state.get_mut(key) {
            if stopped {
                if let Some(instance) = scope.instances.remove(id) {
                    scope.network_interfaces.remove(&instance.eni_id);
                }
                scope
                    .instance_tokens
                    .retain(|_, record| record.instance_id != id);
            } else if let Some(instance) = scope.instances.get_mut(id) {
                instance.state = InstanceState::ShuttingDown;
                instance.endpoint = None;
            }
        }
    }

    fn mark_terminated(&self, key: &(String, String), id: &str) {
        let mut state = self.scopes.lock().unwrap();
        if let Some(scope) = state.get_mut(key) {
            if let Some(instance) = scope.instances.get_mut(id) {
                instance.state = InstanceState::Terminated;
                instance.endpoint = None;
                let eni_id = instance.eni_id.clone();
                scope.network_interfaces.remove(&eni_id);
            }
        }
    }

    pub async fn shutdown(&self) {
        let Some(runtime) = &self.runtime else {
            return;
        };
        let instances = {
            let state = self.scopes.lock().unwrap();
            state
                .iter()
                .flat_map(|(key, scope)| {
                    scope
                        .instances
                        .values()
                        .filter(|i| i.state != InstanceState::Terminated)
                        .map(move |i| (key.clone(), i.spec.instance_id.clone()))
                })
                .collect::<Vec<_>>()
        };
        for (key, id) in instances {
            if runtime.stop_instance(&id).await.is_ok() {
                self.mark_terminated(&key, &id);
            }
        }
    }
}

fn instance_state(state: InstanceState) -> &'static str {
    match state {
        InstanceState::Pending => "pending",
        InstanceState::Running => "running",
        InstanceState::ShuttingDown => "shutting-down",
        InstanceState::Terminated => "terminated",
    }
}
fn instance_state_code(state: InstanceState) -> u16 {
    match state {
        InstanceState::Pending => 0,
        InstanceState::Running => 16,
        InstanceState::ShuttingDown => 32,
        InstanceState::Terminated => 48,
    }
}
fn instance_xml(instance: &Instance, scope: &ScopeState) -> String {
    let spec = &instance.spec;
    let groups = spec
        .security_group_ids
        .iter()
        .filter_map(|id| scope.security_groups.get(id))
        .map(|g| {
            format!(
                "<item><groupId>{}</groupId><groupName>{}</groupName></item>",
                escape(&g.id),
                escape(&g.name)
            )
        })
        .collect::<String>();
    format!("<instanceId>{}</instanceId><imageId>{}</imageId><instanceState><code>{}</code><name>{}</name></instanceState><privateDnsName/><privateIpAddress>{}</privateIpAddress><instanceType>{}</instanceType><placement><availabilityZone>{}</availabilityZone><groupName/><tenancy>default</tenancy></placement><subnetId>{}</subnetId><vpcId>{}</vpcId><groupSet>{groups}</groupSet><networkInterfaceSet><item><networkInterfaceId>{}</networkInterfaceId><privateIpAddress>{}</privateIpAddress><status>in-use</status></item></networkInterfaceSet><tagSet/>", escape(&spec.instance_id), escape(&spec.image_id), instance_state_code(instance.state), instance_state(instance.state), spec.private_ip, escape(&spec.instance_type), escape(scope.subnets.get(&spec.subnet_id).map(|s| s.zone.as_str()).unwrap_or_default()), escape(&spec.subnet_id), escape(&spec.vpc_id), escape(&instance.eni_id), spec.private_ip)
}

async fn probe_instance(runtime: &dyn InstanceRuntime, spec: &InstanceSpec) -> bool {
    for _ in 0..30 {
        if let Ok(Ok(mut stream)) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            runtime.connect_instance(&spec.instance_id, spec.guest_port),
        )
        .await
        {
            if stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .is_ok()
            {
                let mut buf = [0_u8; 128];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut buf))
                        .await
                {
                    if n >= 12 && buf.starts_with(b"HTTP/1.1 200") {
                        return true;
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

async fn serve_instance_proxy(
    listener: TcpListener,
    scopes: Arc<Mutex<HashMap<(String, String), ScopeState>>>,
    key: (String, String),
    spec: InstanceSpec,
    runtime: Arc<dyn InstanceRuntime>,
) {
    loop {
        let accepted =
            tokio::time::timeout(std::time::Duration::from_secs(1), listener.accept()).await;
        let active = {
            let state = scopes.lock().unwrap();
            state
                .get(&key)
                .and_then(|s| s.instances.get(&spec.instance_id))
                .is_some_and(|i| i.state == InstanceState::Running)
        };
        if !active {
            break;
        }
        if !runtime.instance_running(&spec.instance_id).await {
            let mut state = scopes.lock().unwrap();
            if let Some(scope) = state.get_mut(&key) {
                if let Some(instance) = scope.instances.get_mut(&spec.instance_id) {
                    instance.state = InstanceState::Terminated;
                    instance.endpoint = None;
                    let eni_id = instance.eni_id.clone();
                    scope.network_interfaces.remove(&eni_id);
                }
            }
            break;
        }
        let Ok(Ok((mut inbound, peer))) = accepted else {
            continue;
        };
        let allowed = match peer.ip() {
            std::net::IpAddr::V4(source) => {
                let state = scopes.lock().unwrap();
                state.get(&key).is_some_and(|scope| {
                    spec.security_group_ids
                        .iter()
                        .all(|id| scope.security_groups.contains_key(id))
                        && spec.security_group_ids.iter().any(|id| {
                            scope.security_groups.get(id).is_some_and(|group| {
                                group.ingress.iter().any(|rule| {
                                    rule.cidr.contains(&source)
                                        && (rule.protocol == "-1"
                                            || (rule.protocol == "tcp"
                                                && rule
                                                    .from_port
                                                    .is_some_and(|v| v <= spec.guest_port)
                                                && rule
                                                    .to_port
                                                    .is_some_and(|v| spec.guest_port <= v)))
                                })
                            })
                        })
                })
            }
            _ => false,
        };
        if !allowed {
            continue;
        }
        let runtime = runtime.clone();
        let id = spec.instance_id.clone();
        let port = spec.guest_port;
        tokio::spawn(async move {
            if let Ok(mut outbound) = runtime.connect_instance(&id, port).await {
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            }
        });
    }
}

#[async_trait]
impl NativeHandler for Ec2Handler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let input = match Input::parse(&request) {
            Ok(input) => input,
            Err(error) => return error.into_response(&request.request_id),
        };
        let action = input.one("Action").ok().flatten().unwrap_or("Unknown");
        if let Ok(Some(version)) = input.one("Version") {
            if version != "2016-11-15" {
                return Ec2Error::new("InvalidParameterValue", "Unsupported API Version")
                    .into_response(&request.request_id);
            }
        }
        let result = match action {
            "RunInstances" => self.run_instances(&request, &input).await,
            "DescribeInstances" => self.describe_instances(&request, &input).await,
            "TerminateInstances" => self.terminate_instances(&request, &input).await,
            _ => self.dispatch(&request, &input),
        };
        match result {
            Ok(inner) => {
                let body = format!("<{action}Response xmlns=\"{XMLNS}\"><requestId>{}</requestId>{inner}</{action}Response>", escape(&request.request_id));
                Response::builder()
                    .status(200)
                    .header("content-type", "text/xml")
                    .header("x-amzn-RequestId", request.request_id)
                    .body(Body::from(body))
                    .expect("valid EC2 response")
            }
            Err(error) => error.into_response(&request.request_id),
        }
    }
}

pub fn register(registry: &ServiceRegistry) -> Arc<Ec2Handler> {
    register_handler(registry, Arc::new(Ec2Handler::default()))
}

pub fn register_with_instance_runtime(
    registry: &ServiceRegistry,
    runtime: Arc<dyn InstanceRuntime>,
) -> Arc<Ec2Handler> {
    register_handler(
        registry,
        Arc::new(Ec2Handler::with_instance_runtime(runtime)),
    )
}

fn register_handler(registry: &ServiceRegistry, handler: Arc<Ec2Handler>) -> Arc<Ec2Handler> {
    let mut metadata = ServiceMetadata::new(AwsProtocol::Query, None);
    metadata.known_actions = [
        "RunInstances",
        "DescribeInstances",
        "TerminateInstances",
        "CreateVpc",
        "DescribeVpcs",
        "ModifyVpcAttribute",
        "DescribeVpcAttribute",
        "DeleteVpc",
        "CreateSubnet",
        "DescribeSubnets",
        "DeleteSubnet",
        "CreateSecurityGroup",
        "DescribeSecurityGroups",
        "DeleteSecurityGroup",
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupEgress",
        "CreateNetworkInterface",
        "DescribeNetworkInterfaces",
        "DeleteNetworkInterface",
        "CreateInternetGateway",
        "DescribeInternetGateways",
        "AttachInternetGateway",
        "DetachInternetGateway",
        "DeleteInternetGateway",
        "AllocateAddress",
        "DescribeAddresses",
        "DescribeAddressesAttribute",
        "ReleaseAddress",
        "CreateNatGateway",
        "DescribeNatGateways",
        "DeleteNatGateway",
        "CreateRouteTable",
        "DescribeRouteTables",
        "DeleteRouteTable",
        "CreateRoute",
        "DeleteRoute",
        "AssociateRouteTable",
        "DisassociateRouteTable",
        "CreateVpcEndpoint",
        "DescribeVpcEndpoints",
        "DescribePrefixLists",
        "DeleteVpcEndpoints",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    registry.register_native(ServiceName::new("ec2"), metadata, handler.clone());
    handler
}

#[derive(Debug)]
struct Ec2Error {
    code: &'static str,
    message: String,
}

impl Ec2Error {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn unsupported(field: &str) -> Self {
        Self::new("UnsupportedOperation", format!("{field} is not supported"))
    }
    fn into_response(self, request_id: &str) -> Response {
        // EC2 Query errors use a different envelope from the generic AWS Query
        // protocol. The EC2 SDK reads Code only below Response/Errors/Error.
        let body = format!(
            "<Response><Errors><Error><Code>{}</Code><Message>{}</Message></Error></Errors><RequestID>{}</RequestID></Response>",
            escape(self.code),
            escape(&self.message),
            escape(request_id),
        );
        Response::builder()
            .status(400)
            .header("content-type", "text/xml")
            .header("x-amzn-RequestId", request_id)
            .body(Body::from(body))
            .expect("valid EC2 error response")
    }
}

struct Input {
    fields: BTreeMap<String, Vec<String>>,
}

impl Input {
    fn parse(req: &ServiceRequest) -> Result<Self, Ec2Error> {
        let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, value) in form_urlencoded::parse(req.uri.query().unwrap_or("").as_bytes())
            .chain(form_urlencoded::parse(&req.body))
        {
            fields
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        if fields.values().any(|values| values.len() != 1) {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Duplicate query parameter",
            ));
        }
        Ok(Self { fields })
    }
    fn one(&self, name: &str) -> Result<Option<&str>, Ec2Error> {
        Ok(self
            .fields
            .get(name)
            .and_then(|v| v.first())
            .map(String::as_str))
    }
    fn required(&self, name: &str) -> Result<&str, Ec2Error> {
        self.one(name)?.filter(|v| !v.is_empty()).ok_or_else(|| {
            Ec2Error::new(
                "MissingParameter",
                format!("The request must contain the parameter {name}"),
            )
        })
    }
    fn dry_run(&self) -> Result<(), Ec2Error> {
        match self.one("DryRun")? {
            None | Some("false") => Ok(()),
            Some("true") => Err(Ec2Error::new(
                "DryRunOperation",
                "Request would have succeeded, but DryRun flag is set",
            )),
            Some(_) => Err(Ec2Error::new(
                "InvalidParameterValue",
                "DryRun must be true or false",
            )),
        }
    }
    fn allow(&self, allowed: &[&str]) -> Result<(), Ec2Error> {
        for key in self.fields.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(Ec2Error::unsupported(key));
            }
        }
        Ok(())
    }
    fn allow_describe(&self, id_prefix: &str, filters: &[&str]) -> Result<(), Ec2Error> {
        for key in self.fields.keys() {
            if ["Action", "Version", "DryRun"].contains(&key.as_str())
                || indexed_key(key, id_prefix).is_some()
            {
                continue;
            }
            if key.starts_with("Filter.") && (key.ends_with(".Name") || key.contains(".Value.")) {
                continue;
            }
            return Err(Ec2Error::unsupported(key));
        }
        self.dry_run()?;
        for (name, _) in self.filters()? {
            if !filters.contains(&name.as_str()) {
                return Err(Ec2Error::unsupported(&format!("Filter {name}")));
            }
        }
        Ok(())
    }
    fn indexed(&self, prefix: &str) -> Result<Vec<String>, Ec2Error> {
        let mut out = BTreeMap::new();
        for (key, values) in &self.fields {
            if let Some(index) = indexed_key(key, prefix) {
                out.insert(index, values[0].clone());
            }
        }
        if out.keys().enumerate().any(|(i, n)| *n != i + 1) {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "List indexes must be consecutive",
            ));
        }
        Ok(out.into_values().collect())
    }
    fn filters(&self) -> Result<Vec<(String, Vec<String>)>, Ec2Error> {
        let mut groups: BTreeMap<usize, (Option<String>, BTreeMap<usize, String>)> =
            BTreeMap::new();
        for (key, values) in &self.fields {
            let Some(tail) = key.strip_prefix("Filter.") else {
                continue;
            };
            let Some((index, field)) = tail.split_once('.') else {
                return Err(Ec2Error::unsupported(key));
            };
            let index: usize = index.parse().map_err(|_| Ec2Error::unsupported(key))?;
            let group = groups.entry(index).or_default();
            if field == "Name" {
                group.0 = Some(values[0].clone());
            } else if let Some(value_index) = field.strip_prefix("Value.") {
                let n: usize = value_index
                    .parse()
                    .map_err(|_| Ec2Error::unsupported(key))?;
                group.1.insert(n, values[0].clone());
            } else {
                return Err(Ec2Error::unsupported(key));
            }
        }
        let mut out = Vec::new();
        for (i, (key, (name, values))) in groups.into_iter().enumerate() {
            if key != i + 1
                || name.as_deref().unwrap_or("").is_empty()
                || values.is_empty()
                || values.keys().enumerate().any(|(n, key)| *key != n + 1)
            {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Invalid Filter structure",
                ));
            }
            out.push((name.unwrap(), values.into_values().collect()));
        }
        Ok(out)
    }
}

impl Input {
    fn allow_ingress(&self) -> Result<(), Ec2Error> {
        let flat = [
            "Action",
            "Version",
            "DryRun",
            "GroupId",
            "IpProtocol",
            "FromPort",
            "ToPort",
            "CidrIp",
        ];
        let nested = [
            "IpPermissions.1.IpProtocol",
            "IpPermissions.1.FromPort",
            "IpPermissions.1.ToPort",
            "IpPermissions.1.IpRanges.1.CidrIp",
        ];
        for key in self.fields.keys() {
            if !flat.contains(&key.as_str()) && !nested.contains(&key.as_str()) {
                return Err(Ec2Error::unsupported(key));
            }
        }
        Ok(())
    }

    fn ingress_rule(&self) -> Result<(String, Option<u16>, Option<u16>, Ipv4Net), Ec2Error> {
        let nested = self
            .fields
            .keys()
            .any(|key| key.starts_with("IpPermissions."));
        if nested
            && ["IpProtocol", "FromPort", "ToPort", "CidrIp"]
                .iter()
                .any(|key| self.fields.contains_key(*key))
        {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Cannot mix flat and IpPermissions rule parameters",
            ));
        }
        let prefix = if nested { "IpPermissions.1." } else { "" };
        let protocol_key = format!("{prefix}IpProtocol");
        let cidr_key = if nested {
            "IpPermissions.1.IpRanges.1.CidrIp"
        } else {
            "CidrIp"
        };
        let protocol = self.required(&protocol_key)?;
        if !["tcp", "udp", "-1"].contains(&protocol) {
            return Err(Ec2Error::unsupported("IpProtocol"));
        }
        let from_key = format!("{prefix}FromPort");
        let to_key = format!("{prefix}ToPort");
        let (from_port, to_port) = if protocol == "-1" {
            if self.one(&from_key)?.is_some_and(|port| port != "0")
                || self.one(&to_key)?.is_some_and(|port| port != "0")
            {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Ports must be zero for protocol -1",
                ));
            }
            (None, None)
        } else {
            let from = self
                .required(&from_key)?
                .parse::<u16>()
                .map_err(|_| Ec2Error::new("InvalidParameterValue", "Invalid FromPort"))?;
            let to = self
                .required(&to_key)?
                .parse::<u16>()
                .map_err(|_| Ec2Error::new("InvalidParameterValue", "Invalid ToPort"))?;
            if from > to {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "FromPort exceeds ToPort",
                ));
            }
            (Some(from), Some(to))
        };
        let cidr = parse_any_ipv4_cidr(self.required(cidr_key)?, "CidrIp")?;
        Ok((protocol.into(), from_port, to_port, cidr))
    }

    fn eni_idempotency_params(&self) -> BTreeMap<String, String> {
        self.fields
            .iter()
            .filter(|(key, _)| {
                !["Action", "Version", "DryRun", "ClientToken"].contains(&key.as_str())
            })
            .map(|(key, values)| (key.clone(), values[0].clone()))
            .collect()
    }

    fn allow_eni_create(&self) -> Result<(), Ec2Error> {
        for key in self.fields.keys() {
            if [
                "Action",
                "Version",
                "DryRun",
                "SubnetId",
                "PrivateIpAddress",
                "Description",
                "ClientToken",
            ]
            .contains(&key.as_str())
                || indexed_key(key, "SecurityGroupId").is_some()
            {
                continue;
            }
            return Err(Ec2Error::unsupported(key));
        }
        Ok(())
    }
}

fn parse_any_ipv4_cidr(value: &str, field: &str) -> Result<Ipv4Net, Ec2Error> {
    value
        .parse::<Ipv4Net>()
        .map(|net| net.trunc())
        .map_err(|_| Ec2Error::new("InvalidParameterValue", format!("Invalid {field}")))
}

fn valid_group_text(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " ._-:/()#,@[]+=&;{}!$*".contains(c))
}

fn ports_xml(from: Option<u16>, to: Option<u16>) -> String {
    match (from, to) {
        (Some(from), Some(to)) => format!("<fromPort>{from}</fromPort><toPort>{to}</toPort>"),
        _ => String::new(),
    }
}

fn group_xml(group: &SecurityGroup) -> String {
    let mut ingress = if group.is_default {
        format!("<item><ipProtocol>-1</ipProtocol><groups><item><userId>{}</userId><groupId>{}</groupId></item></groups><ipRanges/><ipv6Ranges/><prefixListIds/></item>",
            escape(&group.owner), escape(&group.id))
    } else {
        String::new()
    };
    ingress.push_str(&group.ingress.iter().map(|rule| format!(
        "<item><ipProtocol>{}</ipProtocol>{}<groups/><ipRanges><item><cidrIp>{}</cidrIp></item></ipRanges><ipv6Ranges/><prefixListIds/></item>",
        escape(&rule.protocol), ports_xml(rule.from_port, rule.to_port), rule.cidr
    )).collect::<String>());
    let egress = group.egress.iter().map(|rule| format!("<item><ipProtocol>{}</ipProtocol>{}<groups/><ipRanges><item><cidrIp>{}</cidrIp></item></ipRanges><ipv6Ranges/><prefixListIds/></item>", escape(&rule.protocol), ports_xml(rule.from_port, rule.to_port), rule.cidr)).collect::<String>();
    format!("<ownerId>{}</ownerId><groupId>{}</groupId><groupName>{}</groupName><groupDescription>{}</groupDescription><vpcId>{}</vpcId><ipPermissions>{ingress}</ipPermissions><ipPermissionsEgress>{egress}</ipPermissionsEgress><tagSet/>",
        escape(&group.owner), escape(&group.id), escape(&group.name), escape(&group.description), escape(&group.vpc_id))
}

fn eni_xml(eni: &NetworkInterface, scope: &ScopeState, _region: &str) -> String {
    let groups = eni
        .group_ids
        .iter()
        .filter_map(|id| scope.security_groups.get(id))
        .map(|group| {
            format!(
                "<item><groupId>{}</groupId><groupName>{}</groupName></item>",
                escape(&group.id),
                escape(&group.name)
            )
        })
        .collect::<String>();
    let status = if scope.task_networks.contains_key(&eni.id) {
        "in-use"
    } else {
        "available"
    };
    format!("<networkInterfaceId>{}</networkInterfaceId><subnetId>{}</subnetId><vpcId>{}</vpcId><availabilityZone>{}</availabilityZone><description>{}</description><ownerId>{}</ownerId><requesterManaged>false</requesterManaged><status>{status}</status><privateIpAddress>{}</privateIpAddress><sourceDestCheck>true</sourceDestCheck><groupSet>{groups}</groupSet><tagSet/><privateIpAddressesSet><item><privateIpAddress>{}</privateIpAddress><primary>true</primary></item></privateIpAddressesSet><ipv6AddressesSet/>",
        escape(&eni.id), escape(&eni.subnet_id), escape(&eni.vpc_id), escape(&eni.zone), escape(&eni.description), escape(&eni.owner), eni.private_ip, eni.private_ip)
}

fn indexed_key(key: &str, prefix: &str) -> Option<usize> {
    key.strip_prefix(prefix)?.strip_prefix('.')?.parse().ok()
}

fn parse_cidr(value: &str, field: &str) -> Result<Ipv4Net, Ec2Error> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| Ec2Error::new("InvalidParameterValue", format!("Invalid {field}")))?;
    let ip: Ipv4Addr = ip
        .parse()
        .map_err(|_| Ec2Error::new("InvalidParameterValue", format!("Invalid {field}")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| Ec2Error::new("InvalidParameterValue", format!("Invalid {field}")))?;
    if !(16..=28).contains(&prefix) {
        return Err(Ec2Error::new(
            "InvalidParameterValue",
            format!("Invalid {field} mask"),
        ));
    }
    Ipv4Net::new(ip, prefix)
        .map(|net| net.trunc())
        .map_err(|_| Ec2Error::new("InvalidParameterValue", format!("Invalid {field}")))
}

fn contains_net(outer: Ipv4Net, inner: Ipv4Net) -> bool {
    outer.prefix_len() <= inner.prefix_len() && outer.contains(&inner.network())
}

fn overlaps(a: Ipv4Net, b: Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

fn resource_id(prefix: &str) -> String {
    format!("{prefix}-{}", &Uuid::new_v4().simple().to_string()[..17])
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn vpc_xml(vpc: &Vpc) -> String {
    format!("<vpcId>{}</vpcId><ownerId>{}</ownerId><state>available</state><cidrBlock>{}</cidrBlock><cidrBlockAssociationSet/><ipv6CidrBlockAssociationSet/><instanceTenancy>default</instanceTenancy><isDefault>false</isDefault><tagSet/>",
        escape(&vpc.id), escape(&vpc.owner), vpc.cidr)
}

fn subnet_xml(subnet: &Subnet, region: &str, scope: &ScopeState) -> String {
    let used = (scope
        .network_interfaces
        .values()
        .filter(|eni| eni.subnet_id == subnet.id)
        .count()
        + scope
            .nat_gateways
            .values()
            .filter(|nat| nat.subnet_id.as_deref() == Some(&subnet.id))
            .count()) as u32;
    let available = (1_u32 << (32 - subnet.cidr.prefix_len())) - 5 - used;
    format!("<subnetId>{}</subnetId><subnetArn>arn:aws:ec2:{}:{}:subnet/{}</subnetArn><state>available</state><ownerId>{}</ownerId><vpcId>{}</vpcId><cidrBlock>{}</cidrBlock><availableIpAddressCount>{available}</availableIpAddressCount><availabilityZone>{}</availabilityZone><defaultForAz>false</defaultForAz><mapPublicIpOnLaunch>false</mapPublicIpOnLaunch><assignIpv6AddressOnCreation>false</assignIpv6AddressOnCreation><ipv6CidrBlockAssociationSet/><tagSet/>",
        escape(&subnet.id), escape(region), escape(&subnet.owner), escape(&subnet.id), escape(&subnet.owner), escape(&subnet.vpc_id), subnet.cidr, escape(&subnet.zone))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    fn request(account: &str, region: &str, form: &str) -> ServiceRequest {
        ServiceRequest {
            method: axum::http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: axum::http::HeaderMap::new(),
            body: form.to_owned().into(),
            account_id: account.into(),
            region: region.into(),
            request_id: "rid".into(),
        }
    }

    async fn call(handler: &Ec2Handler, account: &str, region: &str, form: &str) -> (u16, String) {
        let response = handler.handle(request(account, region, form)).await;
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

    fn id(xml: &str, tag: &str) -> String {
        xml.split(&format!("<{tag}>"))
            .nth(1)
            .unwrap()
            .split(&format!("</{tag}>"))
            .next()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn ec2_errors_use_the_service_specific_query_envelope() {
        let handler = Ec2Handler::default();
        let (status, vpc) = call(
            &handler,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.0.0.0%2F16",
        )
        .await;
        assert_eq!(status, 200, "{vpc}");
        let (status, group) = call(
            &handler,
            "111",
            "us-east-1",
            &format!(
                "Action=CreateSecurityGroup&VpcId={}&GroupName=app&GroupDescription=app",
                id(&vpc, "vpcId")
            ),
        )
        .await;
        assert_eq!(status, 200, "{group}");
        let (status, body) = call(&handler, "111", "us-east-1", &format!("Action=RevokeSecurityGroupEgress&GroupId={}&IpPermissions.1.IpProtocol=-1&IpPermissions.1.FromPort=0&IpPermissions.1.ToPort=0&IpPermissions.1.Ipv6Ranges.1.CidrIpv6=%3A%3A%2F0", id(&group, "groupId"))).await;
        assert_eq!(status, 400);
        assert_eq!(body, "<Response><Errors><Error><Code>InvalidPermission.NotFound</Code><Message>The specified IPv6 rule does not exist</Message></Error></Errors><RequestID>rid</RequestID></Response>");
    }

    #[tokio::test]
    async fn vpc_subnet_lifecycle_and_scope() {
        let h = Ec2Handler::default();
        let (status, vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&Version=2016-11-15&CidrBlock=10.0.0.4%2F16",
        )
        .await;
        assert_eq!(status, 200, "{vpc_body}");
        assert!(vpc_body.contains("<cidrBlock>10.0.0.0/16</cidrBlock>"));
        let vpc = id(&vpc_body, "vpcId");
        assert!(h.vpc_exists("111", "us-east-1", &vpc));
        assert!(!h.vpc_exists("222", "us-east-1", &vpc));
        assert!(!h.vpc_exists("111", "us-west-2", &vpc));
        let (status, subnet_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.0.1.0%2F24"),
        )
        .await;
        assert_eq!(status, 200, "{subnet_body}");
        let subnet = id(&subnet_body, "subnetId");
        assert!(subnet_body.contains("<availableIpAddressCount>251</availableIpAddressCount>"));
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.0.1.128%2F25"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("InvalidSubnet.Conflict"));
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DeleteVpc&VpcId={vpc}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("DependencyViolation"));
        let (status, body) = call(
            &h,
            "222",
            "us-east-1",
            &format!("Action=DescribeVpcs&VpcId.1={vpc}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("InvalidVpcID.NotFound"));
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSubnet&SubnetId={subnet}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteVpc&VpcId={vpc}")
            )
            .await
            .0,
            200
        );
        assert!(!h.vpc_exists("111", "us-east-1", &vpc));
    }

    #[tokio::test]
    async fn rejects_unsupported_parameters_without_mutation() {
        let h = Ec2Handler::default();
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.0.0.0%2F16&AmazonProvidedIpv6CidrBlock=true",
        )
        .await;
        assert_eq!(status, 400);
        assert!(body.contains("UnsupportedOperation"));
        let (_, listed) = call(&h, "111", "us-east-1", "Action=DescribeVpcs").await;
        assert!(listed.contains("<vpcSet></vpcSet>"));
        let (status, body) = call(&h, "111", "us-east-1", "Action=RunInstances").await;
        assert_eq!(status, 400);
        assert!(body.contains("MissingParameter"));
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.0.0.0%2F16&DryRun=true",
        )
        .await;
        assert_eq!(status, 400);
        assert!(body.contains("DryRunOperation"));
        let (_, listed) = call(&h, "111", "us-east-1", "Action=DescribeVpcs").await;
        assert!(listed.contains("<vpcSet></vpcSet>"));
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.0.0.0%2F16&AmazonProvidedIpv6CidrBlock=false",
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("<vpcId>vpc-"));
    }

    #[tokio::test]
    async fn filters_are_scoped_and_conjunctive() {
        let h = Ec2Handler::default();
        let (_, vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.0.0.0%2F16",
        )
        .await;
        let vpc = id(&vpc_body, "vpcId");
        let (_, body) = call(&h, "111", "us-east-1", &format!("Action=DescribeVpcs&Filter.1.Name=vpc-id&Filter.1.Value.1={vpc}&Filter.2.Name=state&Filter.2.Value.1=available")).await;
        assert!(body.contains(&vpc));
        let (_, body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=DescribeVpcs&Filter.1.Name=state&Filter.1.Value.1=pending",
        )
        .await;
        assert!(!body.contains(&vpc));
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=DescribeVpcs&Filter.1.Name=banana&Filter.1.Value.1=x",
        )
        .await;
        assert_eq!(status, 400, "{body}");
    }
    #[tokio::test]
    async fn vpc_lease_blocks_delete_until_all_consumers_release_it() {
        let h = Ec2Handler::default();
        let (_, body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.0.0.0%2F16",
        )
        .await;
        let vpc = id(&body, "vpcId");
        assert!(h.vpc_lease("222", "us-east-1", &vpc).is_none());
        assert!(h.vpc_lease("111", "us-west-2", &vpc).is_none());
        let lease = h.vpc_lease("111", "us-east-1", &vpc).unwrap();
        assert_eq!(lease.vpc_id(), vpc);
        let second = lease.clone();
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DeleteVpc&VpcId={vpc}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("DependencyViolation"));
        drop(lease);
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DeleteVpc&VpcId={vpc}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("DependencyViolation"));
        drop(second);
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteVpc&VpcId={vpc}")
            )
            .await
            .0,
            200
        );
        assert!(h.vpc_lease("111", "us-east-1", &vpc).is_none());
    }
    #[tokio::test]
    async fn security_group_eni_lifecycle_and_dependencies() {
        let h = Ec2Handler::default();
        let (_, vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.2.0.0%2F16",
        )
        .await;
        let vpc = id(&vpc_body, "vpcId");
        let (_, subnet_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.2.1.0%2F24"),
        )
        .await;
        let subnet = id(&subnet_body, "subnetId");
        let (status, group_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!(
                "Action=CreateSecurityGroup&VpcId={vpc}&GroupName=web&GroupDescription=Web+servers"
            ),
        )
        .await;
        assert_eq!(status, 200, "{group_body}");
        let group = id(&group_body, "groupId");
        let (status, body) = call(&h, "111", "us-east-1", &format!("Action=AuthorizeSecurityGroupIngress&GroupId={group}&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=80&IpPermissions.1.ToPort=80&IpPermissions.1.IpRanges.1.CidrIp=192.0.2.0%2F24")).await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("<securityGroupRuleId>sgr-"));
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DescribeSecurityGroups&GroupId.1={group}"),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("<fromPort>80</fromPort>"));
        assert!(body.contains("<cidrIp>192.0.2.0/24</cidrIp>"));
        let (status, eni_body) = call(&h, "111", "us-east-1", &format!("Action=CreateNetworkInterface&SubnetId={subnet}&SecurityGroupId.1={group}&PrivateIpAddress=10.2.1.10")).await;
        assert_eq!(status, 200, "{eni_body}");
        let eni = id(&eni_body, "networkInterfaceId");
        assert_eq!(
            h.network_selection("111", "us-east-1", &subnet, std::slice::from_ref(&group))
                .unwrap()
                .vpc_id,
            vpc
        );
        assert!(h
            .network_selection("222", "us-east-1", &subnet, std::slice::from_ref(&group))
            .is_none());
        let (_, subnets) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DescribeSubnets&SubnetId.1={subnet}"),
        )
        .await;
        assert!(subnets.contains("<availableIpAddressCount>250</availableIpAddressCount>"));
        let (status, body) = call(&h, "111", "us-east-1", &format!("Action=CreateNetworkInterface&SubnetId={subnet}&SecurityGroupId.1={group}&PrivateIpAddress=10.2.1.10")).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("InvalidIPAddress.InUse"));
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSecurityGroup&GroupId={group}")
            )
            .await
            .0,
            400
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSubnet&SubnetId={subnet}")
            )
            .await
            .0,
            400
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteNetworkInterface&NetworkInterfaceId={eni}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSecurityGroup&GroupId={group}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSubnet&SubnetId={subnet}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteVpc&VpcId={vpc}")
            )
            .await
            .0,
            200
        );
    }

    #[tokio::test]
    async fn default_group_and_unsupported_ingress_are_honest() {
        let h = Ec2Handler::default();
        let (_, vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.3.0.0%2F16",
        )
        .await;
        let vpc = id(&vpc_body, "vpcId");
        let (_, groups) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DescribeSecurityGroups&Filter.1.Name=vpc-id&Filter.1.Value.1={vpc}"),
        )
        .await;
        assert!(groups.contains("<groupName>default</groupName>"));
        let default_group = id(&groups, "groupId");
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DeleteSecurityGroup&GroupId={default_group}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("Client.CannotDelete"));
        let (status, body) = call(&h, "111", "us-east-1", &format!("Action=AuthorizeSecurityGroupIngress&GroupId={default_group}&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=80&IpPermissions.1.ToPort=80&IpPermissions.1.Ipv6Ranges.1.CidrIpv6=%3A%3A%2F0")).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("UnsupportedOperation"));
        let (_, sub_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.3.1.0%2F24"),
        )
        .await;
        let subnet = id(&sub_body, "subnetId");
        let (status, eni_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateNetworkInterface&SubnetId={subnet}"),
        )
        .await;
        assert_eq!(status, 200, "{eni_body}");
        assert!(eni_body.contains(&default_group));
        let eni = id(&eni_body, "networkInterfaceId");
        let (status, body) = call(
            &h,
            "222",
            "us-east-1",
            &format!("Action=DescribeNetworkInterfaces&NetworkInterfaceId.1={eni}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("InvalidNetworkInterfaceID.NotFound"));
    }
    #[tokio::test]
    async fn eni_client_token_is_idempotent_within_account_and_region() {
        let h = Ec2Handler::default();
        let (_, vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.4.0.0%2F16",
        )
        .await;
        let vpc = id(&vpc_body, "vpcId");
        let (_, sub_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.4.1.0%2F24"),
        )
        .await;
        let subnet = id(&sub_body, "subnetId");
        let create = format!(
            "Action=CreateNetworkInterface&SubnetId={subnet}&ClientToken=token-1&Description=web"
        );
        let (status, first) = call(&h, "111", "us-east-1", &create).await;
        assert_eq!(status, 200, "{first}");
        let eni = id(&first, "networkInterfaceId");
        let ip = id(&first, "privateIpAddress");
        let (status, second) = call(&h, "111", "us-east-1", &create).await;
        assert_eq!(status, 200, "{second}");
        assert_eq!(id(&second, "networkInterfaceId"), eni);
        assert_eq!(id(&second, "privateIpAddress"), ip);
        let (status, mismatch) = call(&h, "111", "us-east-1", &format!("Action=CreateNetworkInterface&SubnetId={subnet}&ClientToken=token-1&Description=changed")).await;
        assert_eq!(status, 400, "{mismatch}");
        assert!(mismatch.contains("IdempotentParameterMismatch"));
        let (_, listed) = call(&h, "111", "us-east-1", &format!("Action=DescribeNetworkInterfaces&Filter.1.Name=subnet-id&Filter.1.Value.1={subnet}")).await;
        assert_eq!(listed.matches("<networkInterfaceId>").count(), 1);
        let (_, subnets) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DescribeSubnets&SubnetId.1={subnet}"),
        )
        .await;
        assert!(subnets.contains("<availableIpAddressCount>250</availableIpAddressCount>"));
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateNetworkInterface&SubnetId={subnet}&ClientToken=bad-ñ"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateNetworkInterface&SubnetId={subnet}&ClientToken="),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteNetworkInterface&NetworkInterfaceId={eni}")
            )
            .await
            .0,
            200
        );
    }
    #[tokio::test]
    async fn alb_network_lease_validates_and_blocks_deletion() {
        let h = Ec2Handler::default();
        let (_, vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.5.0.0%2F16",
        )
        .await;
        let vpc = id(&vpc_body, "vpcId");
        let (_, a_body) = call(&h, "111", "us-east-1", &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.5.1.0%2F24&AvailabilityZone=us-east-1a")).await;
        let a = id(&a_body, "subnetId");
        let (_, b_body) = call(&h, "111", "us-east-1", &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.5.2.0%2F24&AvailabilityZone=us-east-1b")).await;
        let b = id(&b_body, "subnetId");
        let (_, c_body) = call(&h, "111", "us-east-1", &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.5.3.0%2F24&AvailabilityZone=us-east-1a")).await;
        let c = id(&c_body, "subnetId");
        let (_, sg_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSecurityGroup&VpcId={vpc}&GroupName=alb&GroupDescription=ALB"),
        )
        .await;
        let sg = id(&sg_body, "groupId");
        assert!(h
            .alb_network_lease(
                "111",
                "us-east-1",
                std::slice::from_ref(&a),
                std::slice::from_ref(&sg)
            )
            .is_none());
        assert!(h
            .alb_network_lease(
                "111",
                "us-east-1",
                &[a.clone(), c.clone()],
                std::slice::from_ref(&sg)
            )
            .is_none());
        assert!(h
            .alb_network_lease(
                "222",
                "us-east-1",
                &[a.clone(), b.clone()],
                std::slice::from_ref(&sg)
            )
            .is_none());
        assert!(h
            .alb_network_lease(
                "111",
                "us-west-2",
                &[a.clone(), b.clone()],
                std::slice::from_ref(&sg)
            )
            .is_none());
        let lease = h
            .alb_network_lease(
                "111",
                "us-east-1",
                &[a.clone(), b.clone()],
                std::slice::from_ref(&sg),
            )
            .unwrap();
        assert_eq!(lease.vpc_id, vpc);
        assert_eq!(
            lease.subnets,
            vec![
                (a.clone(), "us-east-1a".into()),
                (b.clone(), "us-east-1b".into())
            ]
        );
        let second = lease.clone();
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DeleteSubnet&SubnetId={a}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("DependencyViolation"));
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DeleteSecurityGroup&GroupId={sg}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("DependencyViolation"));
        drop(lease);
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSubnet&SubnetId={b}")
            )
            .await
            .0,
            400
        );
        drop(second);
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSecurityGroup&GroupId={sg}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSubnet&SubnetId={a}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSubnet&SubnetId={b}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSubnet&SubnetId={c}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteVpc&VpcId={vpc}")
            )
            .await
            .0,
            200
        );
    }

    #[tokio::test]
    async fn ingress_evaluator_changes_after_authorize_and_revoke() {
        let h = Ec2Handler::default();
        let (_, vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.6.0.0%2F16",
        )
        .await;
        let vpc = id(&vpc_body, "vpcId");
        let (_, sg_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSecurityGroup&VpcId={vpc}&GroupName=alb&GroupDescription=ALB"),
        )
        .await;
        let sg = id(&sg_body, "groupId");
        let source: Ipv4Addr = "192.0.2.17".parse().unwrap();
        assert!(!h.security_groups_allow_ingress(
            "111",
            "us-east-1",
            std::slice::from_ref(&sg),
            source,
            8080
        ));
        let rule = format!("GroupId={sg}&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=8000&IpPermissions.1.ToPort=9000&IpPermissions.1.IpRanges.1.CidrIp=192.0.2.0%2F24");
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=AuthorizeSecurityGroupIngress&{rule}")
            )
            .await
            .0,
            200
        );
        assert!(h.security_groups_allow_ingress(
            "111",
            "us-east-1",
            std::slice::from_ref(&sg),
            source,
            8080
        ));
        assert!(!h.security_groups_allow_ingress(
            "111",
            "us-east-1",
            std::slice::from_ref(&sg),
            source,
            443
        ));
        assert!(!h.security_groups_allow_ingress(
            "111",
            "us-east-1",
            std::slice::from_ref(&sg),
            "198.51.100.5".parse().unwrap(),
            8080
        ));
        assert!(!h.security_groups_allow_ingress(
            "222",
            "us-east-1",
            std::slice::from_ref(&sg),
            source,
            8080
        ));
        assert!(!h.security_groups_allow_ingress(
            "111",
            "us-west-2",
            std::slice::from_ref(&sg),
            source,
            8080
        ));
        assert!(!h.security_groups_allow_ingress(
            "111",
            "us-east-1",
            &[sg.clone(), "sg-missing".into()],
            source,
            8080
        ));
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=RevokeSecurityGroupIngress&{rule}"),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(!h.security_groups_allow_ingress(
            "111",
            "us-east-1",
            std::slice::from_ref(&sg),
            source,
            8080
        ));
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=RevokeSecurityGroupIngress&{rule}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("InvalidPermission.NotFound"));
    }
    #[tokio::test]
    async fn route_table_lifecycle_and_dependencies() {
        let h = Ec2Handler::default();
        let (_, vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.8.0.0%2F16",
        )
        .await;
        let vpc = id(&vpc_body, "vpcId");
        let (_, main_body) = call(&h, "111", "us-east-1", &format!("Action=DescribeRouteTables&Filter.1.Name=vpc-id&Filter.1.Value.1={vpc}&Filter.2.Name=association.main&Filter.2.Value.1=true")).await;
        let main = id(&main_body, "routeTableId");
        assert!(main_body.contains("<gatewayId>local</gatewayId>"));
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DeleteRouteTable&RouteTableId={main}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("DependencyViolation"));
        let (_, table_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateRouteTable&VpcId={vpc}"),
        )
        .await;
        let table = id(&table_body, "routeTableId");
        assert!(table_body.contains("<associationSet></associationSet>"));
        let (_, sub_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.8.1.0%2F24"),
        )
        .await;
        let subnet = id(&sub_body, "subnetId");
        let (_, eni_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateNetworkInterface&SubnetId={subnet}"),
        )
        .await;
        let eni = id(&eni_body, "networkInterfaceId");
        let route = format!(
            "RouteTableId={table}&DestinationCidrBlock=192.0.2.0%2F24&NetworkInterfaceId={eni}"
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=CreateRoute&{route}")
            )
            .await
            .0,
            200
        );
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateRoute&{route}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("RouteAlreadyExists"));
        let (_, assoc_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=AssociateRouteTable&RouteTableId={table}&SubnetId={subnet}"),
        )
        .await;
        let assoc = id(&assoc_body, "associationId");
        assert!(assoc_body.contains("<state>associated</state>"));
        let (_, described) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DescribeRouteTables&RouteTableId.1={table}"),
        )
        .await;
        assert!(described.contains(&format!("<networkInterfaceId>{eni}</networkInterfaceId>")));
        assert!(described.contains(&format!("<subnetId>{subnet}</subnetId>")));
        for form in [
            format!("Action=DeleteRouteTable&RouteTableId={table}"),
            format!("Action=DeleteNetworkInterface&NetworkInterfaceId={eni}"),
            format!("Action=DeleteVpc&VpcId={vpc}"),
        ] {
            let (status, body) = call(&h, "111", "us-east-1", &form).await;
            assert_eq!(status, 400, "{body}");
            assert!(body.contains("DependencyViolation"));
        }
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DisassociateRouteTable&AssociationId={assoc}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!(
                    "Action=DeleteRoute&RouteTableId={table}&DestinationCidrBlock=192.0.2.0%2F24"
                )
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteNetworkInterface&NetworkInterfaceId={eni}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteRouteTable&RouteTableId={table}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSubnet&SubnetId={subnet}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteVpc&VpcId={vpc}")
            )
            .await
            .0,
            200
        );
    }

    #[tokio::test]
    async fn route_table_client_token_is_scoped_and_idempotent() {
        let h = Ec2Handler::default();
        let (_, first_vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.10.0.0%2F16",
        )
        .await;
        let first_vpc = id(&first_vpc_body, "vpcId");
        let (_, second_vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.11.0.0%2F16",
        )
        .await;
        let second_vpc = id(&second_vpc_body, "vpcId");
        let create = format!("Action=CreateRouteTable&VpcId={first_vpc}&ClientToken=route-token-1");
        let (status, first) = call(&h, "111", "us-east-1", &create).await;
        assert_eq!(status, 200, "{first}");
        assert!(first.contains("<clientToken>route-token-1</clientToken>"));
        let table = id(&first, "routeTableId");
        let (status, second) = call(&h, "111", "us-east-1", &create).await;
        assert_eq!(status, 200, "{second}");
        assert_eq!(id(&second, "routeTableId"), table);
        let (status, mismatch) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateRouteTable&VpcId={second_vpc}&ClientToken=route-token-1"),
        )
        .await;
        assert_eq!(status, 400, "{mismatch}");
        assert!(mismatch.contains("IdempotentParameterMismatch"));
        let (_, listed) = call(
            &h,
            "111",
            "us-east-1",
            &format!(
                "Action=DescribeRouteTables&Filter.1.Name=vpc-id&Filter.1.Value.1={first_vpc}"
            ),
        )
        .await;
        assert_eq!(
            listed
                .matches(&format!("<routeTableId>{table}</routeTableId>"))
                .count(),
            1
        );
        let (status, other_account) = call(&h, "222", "us-east-1", &create).await;
        assert_eq!(status, 400, "{other_account}");
        assert!(other_account.contains("InvalidVpcID.NotFound"));
        let (status, other_region) = call(&h, "111", "us-west-2", &create).await;
        assert_eq!(status, 400, "{other_region}");
        assert!(other_region.contains("InvalidVpcID.NotFound"));
    }

    #[tokio::test]
    async fn route_table_scope_and_rejections_preserve_state() {
        let h = Ec2Handler::default();
        let (_, vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.9.0.0%2F16",
        )
        .await;
        let vpc = id(&vpc_body, "vpcId");
        let (_, table_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateRouteTable&VpcId={vpc}"),
        )
        .await;
        let table = id(&table_body, "routeTableId");
        let (_, sub_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.9.1.0%2F24"),
        )
        .await;
        let subnet = id(&sub_body, "subnetId");
        let (_, eni_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateNetworkInterface&SubnetId={subnet}"),
        )
        .await;
        let eni = id(&eni_body, "networkInterfaceId");
        let (status, body) = call(
            &h,
            "222",
            "us-east-1",
            &format!("Action=DescribeRouteTables&RouteTableId.1={table}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("InvalidRouteTableID.NotFound"));
        let (status, body) = call(
            &h,
            "111",
            "us-west-2",
            &format!("Action=AssociateRouteTable&RouteTableId={table}&SubnetId={subnet}"),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        let (status, body) = call(&h, "111", "us-east-1", &format!("Action=CreateRoute&RouteTableId={table}&DestinationCidrBlock=0.0.0.0%2F0&GatewayId=igw-fake")).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("InvalidInternetGatewayID.NotFound"));
        let (status, body) = call(&h, "111", "us-east-1", &format!("Action=CreateRoute&RouteTableId={table}&DestinationCidrBlock=0.0.0.0%2F0&NetworkInterfaceId={eni}&DryRun=true")).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("DryRunOperation"));
        let (_, described) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DescribeRouteTables&RouteTableId.1={table}"),
        )
        .await;
        assert!(!described.contains("<destinationCidrBlock>0.0.0.0/0</destinationCidrBlock>"));
        assert_eq!(described.matches("<item><destinationCidrBlock>").count(), 1);
    }
    #[tokio::test]
    async fn alb_lease_and_subnet_delete_are_atomic_under_race() {
        let h = Arc::new(Ec2Handler::default());
        let (_, vpc_body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.7.0.0%2F16",
        )
        .await;
        let vpc = id(&vpc_body, "vpcId");
        let (_, a_body) = call(&h, "111", "us-east-1", &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.7.1.0%2F24&AvailabilityZone=us-east-1a")).await;
        let a = id(&a_body, "subnetId");
        let (_, b_body) = call(&h, "111", "us-east-1", &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.7.2.0%2F24&AvailabilityZone=us-east-1b")).await;
        let b = id(&b_body, "subnetId");
        let (_, sg_body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSecurityGroup&VpcId={vpc}&GroupName=alb&GroupDescription=ALB"),
        )
        .await;
        let sg = id(&sg_body, "groupId");
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let (lease, deletion) = std::thread::scope(|scope| {
            let a_ids = [a.clone(), b.clone()];
            let sg_ids = [sg.clone()];
            let h1 = h.clone();
            let first_barrier = barrier.clone();
            let first = scope.spawn(move || {
                first_barrier.wait();
                h1.alb_network_lease("111", "us-east-1", &a_ids, &sg_ids)
            });
            let h2 = h.clone();
            let second_barrier = barrier.clone();
            let a_id = a.clone();
            let second = scope.spawn(move || {
                let req = request(
                    "111",
                    "us-east-1",
                    &format!("Action=DeleteSubnet&SubnetId={a_id}"),
                );
                let input = Input::parse(&req).unwrap();
                second_barrier.wait();
                h2.dispatch(&req, &input)
            });
            (first.join().unwrap(), second.join().unwrap())
        });
        match (lease, deletion) {
            (Some(lease), Err(error)) => {
                assert_eq!(error.code, "DependencyViolation");
                drop(lease);
                assert_eq!(
                    call(
                        &h,
                        "111",
                        "us-east-1",
                        &format!("Action=DeleteSubnet&SubnetId={a}")
                    )
                    .await
                    .0,
                    200
                );
            }
            (None, Ok(_)) => {}
            _ => panic!("lease and subnet deletion must not both succeed or both fail"),
        }
    }
    struct MockInstanceRuntime {
        addr: SocketAddr,
        running: std::sync::atomic::AtomicBool,
        fail_start: bool,
    }

    #[async_trait]
    impl InstanceRuntime for MockInstanceRuntime {
        async fn start_instance(&self, _: &InstanceSpec) -> Result<(), String> {
            if self.fail_start {
                return Err("failed".into());
            }
            self.running
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn connect_instance(&self, _: &str, _: u16) -> Result<TcpStream, String> {
            TcpStream::connect(self.addr)
                .await
                .map_err(|e| e.to_string())
        }
        async fn stop_instance(&self, _: &str) -> Result<(), String> {
            self.running
                .store(false, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn instance_running(&self, _: &str) -> bool {
            self.running.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    async fn mock_runtime(fail_start: bool) -> Arc<MockInstanceRuntime> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0_u8; 256];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        Arc::new(MockInstanceRuntime {
            addr,
            running: std::sync::atomic::AtomicBool::new(false),
            fail_start,
        })
    }

    async fn instance_network(h: &Ec2Handler) -> (String, String, String) {
        let (_, body) = call(
            h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.20.0.0%2F16",
        )
        .await;
        let vpc = id(&body, "vpcId");
        let (_, body) = call(
            h,
            "111",
            "us-east-1",
            &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.20.1.0%2F24"),
        )
        .await;
        let subnet = id(&body, "subnetId");
        let (_, body) = call(
            h,
            "111",
            "us-east-1",
            &format!("Action=CreateSecurityGroup&VpcId={vpc}&GroupName=web&GroupDescription=web"),
        )
        .await;
        (vpc, subnet, id(&body, "groupId"))
    }

    #[tokio::test]
    async fn instance_run_is_scoped_idempotent_and_cleans_up() {
        let runtime = mock_runtime(false).await;
        let h = Ec2Handler::with_instance_runtime(runtime);
        let (vpc, subnet, sg) = instance_network(&h).await;
        let request = format!("Action=RunInstances&ImageId=ami-localcloud-http&InstanceType=t3.micro&MinCount=1&MaxCount=1&SubnetId={subnet}&SecurityGroupId.1={sg}&ClientToken=once");
        let (status, body) = call(&h, "111", "us-east-1", &request).await;
        assert_eq!(status, 200, "{body}");
        let instance = id(&body, "instanceId");
        let ip: Ipv4Addr = id(&body, "privateIpAddress").parse().unwrap();
        assert!(body.contains("<name>running</name>"));
        assert_eq!(
            id(
                &call(&h, "111", "us-east-1", &request).await.1,
                "instanceId"
            ),
            instance
        );
        assert!(h
            .resolve_target("111", "us-east-1", &vpc, ip, 8080)
            .is_some());
        assert!(h
            .resolve_target("222", "us-east-1", &vpc, ip, 8080)
            .is_none());
        assert!(h.resolve_target("111", "us-east-1", &vpc, ip, 80).is_none());
        let (status, body) = call(&h, "111", "us-east-1", &format!("{request}&MaxCount=2")).await;
        assert_eq!(status, 400);
        assert!(body.contains("InvalidParameterValue") || body.contains("UnsupportedOperation"));
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSubnet&SubnetId={subnet}")
            )
            .await
            .0,
            400
        );
        let (status, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=TerminateInstances&InstanceId.1={instance}"),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(h
            .resolve_target("111", "us-east-1", &vpc, ip, 8080)
            .is_none());
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSubnet&SubnetId={subnet}")
            )
            .await
            .0,
            200
        );
    }

    #[tokio::test]
    async fn instance_runtime_failure_rolls_back_eni_and_token() {
        let runtime = mock_runtime(true).await;
        let h = Ec2Handler::with_instance_runtime(runtime);
        let (_, subnet, _) = instance_network(&h).await;
        let request = format!("Action=RunInstances&ImageId=ami-localcloud-http&InstanceType=t3.micro&MinCount=1&MaxCount=1&SubnetId={subnet}&ClientToken=failed");
        assert_eq!(call(&h, "111", "us-east-1", &request).await.0, 400);
        let (_, body) = call(&h, "111", "us-east-1", "Action=DescribeNetworkInterfaces").await;
        assert!(body.contains("<networkInterfaceSet></networkInterfaceSet>"));
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteSubnet&SubnetId={subnet}")
            )
            .await
            .0,
            200
        );
    }

    #[tokio::test]
    async fn public_nat_routes_require_igw_eip_and_egress_then_clean_up() {
        let h = Ec2Handler::default();
        let (_, body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.50.0.0%2F16",
        )
        .await;
        let vpc = id(&body, "vpcId");
        let (_, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.50.1.0%2F24"),
        )
        .await;
        let public_subnet = id(&body, "subnetId");
        let (_, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.50.2.0%2F24"),
        )
        .await;
        let private_subnet = id(&body, "subnetId");
        let (_, body) = call(&h, "111", "us-east-1", "Action=CreateInternetGateway").await;
        let igw = id(&body, "internetGatewayId");
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=AttachInternetGateway&InternetGatewayId={igw}&VpcId={vpc}")
            )
            .await
            .0,
            200
        );
        let (_, body) = call(&h, "111", "us-east-1", "Action=AllocateAddress&Domain=vpc").await;
        let eip = id(&body, "allocationId");
        let create_nat = format!("Action=CreateNatGateway&SubnetId={public_subnet}&AllocationId={eip}&ClientToken=nat-once");
        let (_, body) = call(&h, "111", "us-east-1", &create_nat).await;
        let nat = id(&body, "natGatewayId");
        assert!(body.contains("<availabilityMode>zonal</availabilityMode>"));
        let (_, retry) = call(&h, "111", "us-east-1", &create_nat).await;
        assert_eq!(id(&retry, "natGatewayId"), nat);
        let (_, mismatch) = call(&h, "111", "us-east-1", &format!("Action=CreateNatGateway&SubnetId={private_subnet}&AllocationId={eip}&ClientToken=nat-once")).await;
        assert!(mismatch.contains("IdempotentParameterMismatch"));
        let (_, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateRouteTable&VpcId={vpc}"),
        )
        .await;
        let public_table = id(&body, "routeTableId");
        let (_, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateRouteTable&VpcId={vpc}"),
        )
        .await;
        let private_table = id(&body, "routeTableId");
        assert_eq!(call(&h, "111", "us-east-1", &format!("Action=AssociateRouteTable&RouteTableId={public_table}&SubnetId={public_subnet}")).await.0, 200);
        assert_eq!(call(&h, "111", "us-east-1", &format!("Action=AssociateRouteTable&RouteTableId={private_table}&SubnetId={private_subnet}")).await.0, 200);
        assert_eq!(call(&h, "111", "us-east-1", &format!("Action=CreateRoute&RouteTableId={private_table}&DestinationCidrBlock=0.0.0.0%2F0&NatGatewayId={nat}")).await.0, 200);
        let (_, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateNetworkInterface&SubnetId={private_subnet}"),
        )
        .await;
        let eni = id(&body, "networkInterfaceId");
        let destination = "1.1.1.1".parse().unwrap();
        assert!(!h.public_tcp_access("111", "us-east-1", &eni, destination, 443));
        assert_eq!(call(&h, "111", "us-east-1", &format!("Action=CreateRoute&RouteTableId={public_table}&DestinationCidrBlock=0.0.0.0%2F0&GatewayId={igw}")).await.0, 200);
        assert!(h.public_tcp_access("111", "us-east-1", &eni, destination, 443));
        assert!(!h.public_tcp_access("111", "us-east-1", &eni, "127.0.0.1".parse().unwrap(), 443));
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=ReleaseAddress&AllocationId={eip}")
            )
            .await
            .0,
            400
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteNatGateway&NatGatewayId={nat}")
            )
            .await
            .0,
            200
        );
        let (_, routes) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=DescribeRouteTables&RouteTableId.1={private_table}"),
        )
        .await;
        assert!(routes.contains(&format!(
            "<natGatewayId>{nat}</natGatewayId><state>blackhole</state>"
        )));
        assert!(!h.public_tcp_access("111", "us-east-1", &eni, destination, 443));
        assert!(!h.public_nat_route("111", "us-east-1", &eni));
        assert_eq!(call(&h, "111", "us-east-1", &format!("Action=DeleteRoute&RouteTableId={private_table}&DestinationCidrBlock=0.0.0.0%2F0")).await.0, 200);
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=ReleaseAddress&AllocationId={eip}")
            )
            .await
            .0,
            200
        );
    }

    #[tokio::test]
    async fn regional_nat_uses_vpc_and_automatic_addressing() {
        let h = Ec2Handler::default();
        let (_, body) = call(
            &h,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.60.0.0%2F16",
        )
        .await;
        let vpc = id(&body, "vpcId");
        let (_, body) = call(&h, "111", "us-east-1", "Action=CreateInternetGateway").await;
        let igw = id(&body, "internetGatewayId");
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=AttachInternetGateway&InternetGatewayId={igw}&VpcId={vpc}")
            )
            .await
            .0,
            200
        );
        let (_, body) = call(
            &h,
            "111",
            "us-east-1",
            &format!("Action=CreateNatGateway&AvailabilityMode=regional&VpcId={vpc}"),
        )
        .await;
        assert!(body.contains("<availabilityMode>regional</availabilityMode>"));
        let nat = id(&body, "natGatewayId");
        let (status, body) = call(&h, "111", "us-east-1", &format!("Action=CreateNatGateway&AvailabilityMode=regional&VpcId={vpc}&SubnetId=subnet-fake")).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("InvalidParameterCombination"));
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DetachInternetGateway&InternetGatewayId={igw}&VpcId={vpc}")
            )
            .await
            .0,
            400
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DeleteNatGateway&NatGatewayId={nat}")
            )
            .await
            .0,
            200
        );
        assert_eq!(
            call(
                &h,
                "111",
                "us-east-1",
                &format!("Action=DetachInternetGateway&InternetGatewayId={igw}&VpcId={vpc}")
            )
            .await
            .0,
            200
        );
    }
}
