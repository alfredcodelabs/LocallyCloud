//! ELBv2 Query API: scoped target group control plane.
//! Traffic, listeners, and target registration are rejected until their effects exist.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{timeout, Duration};
use uuid::Uuid;

const XMLNS: &str = "http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/";
const VERSION: &str = "2015-12-01";
const MAX_BODY: usize = 128 * 1024;
const MAX_TARGETS: usize = 16;
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Obtain a scoped VPC lease from EC2. Retaining it prevents VPC deletion
/// while the target group exists. None rejects creation without mutation.
pub trait VpcPreflight: Send + Sync {
    fn vpc_lease(&self, account: &str, region: &str, vpc_id: &str) -> Option<Arc<dyn Send + Sync>>;
}

/// Map an AWS private target address to an endpoint owned by the local runtime.
/// The returned socket must be loopback; arbitrary network destinations are rejected.
pub trait TargetEndpointResolver: Send + Sync {
    fn resolve(
        &self,
        account: &str,
        region: &str,
        vpc_id: &str,
        ip: Ipv4Addr,
        port: u16,
    ) -> Option<SocketAddr>;
}

/// A held EC2 reservation for two subnets in distinct zones and security groups.
/// Its opaque guard must block deletion of every selected network resource.
pub struct AlbNetworkLease {
    pub vpc_id: String,
    pub subnets: Vec<(String, String)>,
    pub security_groups: Vec<String>,
    pub guard: Arc<dyn Send + Sync>,
}

pub trait AlbNetworkPreflight: Send + Sync {
    fn reserve(
        &self,
        account: &str,
        region: &str,
        subnet_ids: &[String],
        group_ids: &[String],
    ) -> Option<AlbNetworkLease>;
    /// Evaluate current ingress rules for each new client connection.
    fn allows_ingress(
        &self,
        account: &str,
        region: &str,
        group_ids: &[String],
        source: Ipv4Addr,
        port: u16,
    ) -> bool;

    /// Check the route selected for a private target from the ALB subnets.
    /// Implementations may reject an appliance path they cannot actually forward.
    fn allows_target_route(
        &self,
        _account: &str,
        _region: &str,
        _vpc_id: &str,
        _source_subnets: &[String],
        _target_ip: Ipv4Addr,
    ) -> bool {
        true
    }
}

/// Locally reachable address reserved for one ALB. DNSName is the literal
/// loopback IPv4 address; no public DNS resolution is implied.
pub struct AlbEndpoint {
    pub bind_ip: Ipv4Addr,
    pub dns_name: String,
    pub guard: Arc<dyn Send + Sync>,
}

pub trait AlbEndpointAllocator: Send + Sync {
    fn reserve(&self, account: &str, region: &str, name: &str) -> Option<AlbEndpoint>;
}
#[derive(Clone, Default)]
pub struct LoopbackAlbEndpointAllocator {
    used: Arc<Mutex<BTreeSet<Ipv4Addr>>>,
}

struct LoopbackReservation {
    ip: Ipv4Addr,
    used: Arc<Mutex<BTreeSet<Ipv4Addr>>>,
}

impl Drop for LoopbackReservation {
    fn drop(&mut self) {
        if let Ok(mut used) = self.used.lock() {
            used.remove(&self.ip);
        }
    }
}

impl AlbEndpointAllocator for LoopbackAlbEndpointAllocator {
    fn reserve(&self, _account: &str, _region: &str, _name: &str) -> Option<AlbEndpoint> {
        let mut used = self.used.lock().ok()?;
        for third in 1..=254u8 {
            for fourth in 1..=254u8 {
                let ip = Ipv4Addr::new(127, 1, third, fourth);
                if used.insert(ip) {
                    return Some(AlbEndpoint {
                        bind_ip: ip,
                        dns_name: ip.to_string(),
                        guard: Arc::new(LoopbackReservation {
                            ip,
                            used: self.used.clone(),
                        }),
                    });
                }
            }
        }
        None
    }
}

struct LoadBalancer {
    arn: String,
    name: String,
    scheme: String,
    network: AlbNetworkLease,
    endpoint: AlbEndpoint,
    listeners: BTreeMap<u16, Listener>,
}

struct Listener {
    arn: String,
    lb_arn: String,
    target_group_arn: String,
    port: u16,
    task: JoinHandle<()>,
}

impl Listener {
    fn xml(&self) -> String {
        format!("<member><ListenerArn>{}</ListenerArn><LoadBalancerArn>{}</LoadBalancerArn><Port>{}</Port><Protocol>HTTP</Protocol><DefaultActions><member><Type>forward</Type><TargetGroupArn>{}</TargetGroupArn><Order>1</Order></member></DefaultActions></member>",
            xml(&self.arn), xml(&self.lb_arn), self.port, xml(&self.target_group_arn))
    }
}

impl LoadBalancer {
    fn xml(&self) -> String {
        let zones = self
            .network
            .subnets
            .iter()
            .map(|(subnet, zone)| {
                format!(
                    "<member><SubnetId>{}</SubnetId><ZoneName>{}</ZoneName></member>",
                    xml(subnet),
                    xml(zone)
                )
            })
            .collect::<String>();
        let groups = self
            .network
            .security_groups
            .iter()
            .map(|group| format!("<member>{}</member>", xml(group)))
            .collect::<String>();
        format!("<member><LoadBalancerArn>{}</LoadBalancerArn><DNSName>{}</DNSName><LoadBalancerName>{}</LoadBalancerName><Scheme>{}</Scheme><VpcId>{}</VpcId><State><Code>active</Code></State><Type>application</Type><AvailabilityZones>{zones}</AvailabilityZones><SecurityGroups>{groups}</SecurityGroups><IpAddressType>ipv4</IpAddressType></member>", xml(&self.arn), xml(&self.endpoint.dns_name), xml(&self.name), xml(&self.scheme), xml(&self.network.vpc_id))
    }
}

#[derive(Default)]
struct AlbState {
    load_balancers: BTreeMap<(String, String), BTreeMap<String, LoadBalancer>>,
}

#[derive(Clone)]
struct RegisteredTarget {
    ip: Ipv4Addr,
    port: u16,
    endpoint: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeHealth {
    Healthy,
    ResponseCodeMismatch,
    Timeout,
    FailedHealthChecks,
}

impl RegisteredTarget {
    fn xml(&self, state: &str, reason: Option<&str>) -> String {
        let reason = reason
            .map(|reason| format!("<Reason>{reason}</Reason>"))
            .unwrap_or_default();
        format!("<member><Target><Id>{}</Id><Port>{}</Port></Target><HealthCheckPort>{}</HealthCheckPort><TargetHealth><State>{state}</State>{reason}</TargetHealth></member>", self.ip, self.port, self.port)
    }
}

struct TargetGroup {
    arn: String,
    name: String,
    vpc_id: String,
    port: u16,
    target_type: String,
    _vpc_lease: Arc<dyn Send + Sync>,
    targets: BTreeMap<(Ipv4Addr, u16), RegisteredTarget>,
    associated_lb: Option<String>,
}

impl TargetGroup {
    fn xml(&self) -> String {
        let attached = self
            .associated_lb
            .as_ref()
            .map(|arn| {
                format!(
                    "<LoadBalancerArns><member>{}</member></LoadBalancerArns>",
                    xml(arn)
                )
            })
            .unwrap_or_default();
        format!(
            "<member><TargetGroupArn>{}</TargetGroupArn><TargetGroupName>{}</TargetGroupName><Protocol>HTTP</Protocol><Port>{}</Port><VpcId>{}</VpcId><HealthCheckProtocol>HTTP</HealthCheckProtocol><HealthCheckPort>traffic-port</HealthCheckPort><HealthCheckEnabled>true</HealthCheckEnabled><HealthCheckIntervalSeconds>30</HealthCheckIntervalSeconds><HealthCheckTimeoutSeconds>6</HealthCheckTimeoutSeconds><HealthyThresholdCount>5</HealthyThresholdCount><UnhealthyThresholdCount>2</UnhealthyThresholdCount><HealthCheckPath>/</HealthCheckPath><Matcher><HttpCode>200</HttpCode></Matcher><TargetType>{}</TargetType><ProtocolVersion>HTTP1</ProtocolVersion><IpAddressType>ipv4</IpAddressType>{attached}</member>",
            xml(&self.arn), xml(&self.name), self.port, xml(&self.vpc_id), xml(&self.target_type)
        )
    }
}

type Scope = (String, String);
type Groups = BTreeMap<String, TargetGroup>;

#[derive(Default)]
pub struct Elbv2Handler {
    groups: Arc<Mutex<BTreeMap<Scope, Groups>>>,
    albs: Mutex<AlbState>,
    vpc: Option<Arc<dyn VpcPreflight>>,
    resolver: Option<Arc<dyn TargetEndpointResolver>>,
    alb_network: Option<Arc<dyn AlbNetworkPreflight>>,
    alb_endpoint: Option<Arc<dyn AlbEndpointAllocator>>,
}

impl Elbv2Handler {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn with_vpc_preflight(vpc: Arc<dyn VpcPreflight>) -> Arc<Self> {
        Arc::new(Self {
            groups: Arc::new(Mutex::new(BTreeMap::new())),
            albs: Mutex::new(AlbState::default()),
            vpc: Some(vpc),
            resolver: None,
            alb_network: None,
            alb_endpoint: None,
        })
    }

    pub fn with_integrations(
        vpc: Arc<dyn VpcPreflight>,
        resolver: Arc<dyn TargetEndpointResolver>,
    ) -> Arc<Self> {
        Arc::new(Self {
            groups: Arc::new(Mutex::new(BTreeMap::new())),
            albs: Mutex::new(AlbState::default()),
            vpc: Some(vpc),
            resolver: Some(resolver),
            alb_network: None,
            alb_endpoint: None,
        })
    }

    pub fn with_alb_integrations(
        vpc: Arc<dyn VpcPreflight>,
        resolver: Arc<dyn TargetEndpointResolver>,
        network: Arc<dyn AlbNetworkPreflight>,
        endpoint: Arc<dyn AlbEndpointAllocator>,
    ) -> Arc<Self> {
        Arc::new(Self {
            groups: Arc::new(Mutex::new(BTreeMap::new())),
            albs: Mutex::new(AlbState::default()),
            vpc: Some(vpc),
            resolver: Some(resolver),
            alb_network: Some(network),
            alb_endpoint: Some(endpoint),
        })
    }

    /// A bounded live probe for the future ALB dataplane. Standalone target
    /// groups still report Target.NotInUse through DescribeTargetHealth.
    pub async fn probe_registered_target(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        ip: Ipv4Addr,
        port: u16,
    ) -> Option<ProbeHealth> {
        let endpoint = {
            let state = self.groups.lock().ok()?;
            state
                .get(&(account.to_owned(), region.to_owned()))?
                .values()
                .find(|g| g.arn == arn)?
                .targets
                .get(&(ip, port))?
                .endpoint
        };
        Some(probe_http(endpoint).await)
    }

    async fn execute(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        match q.required("Action")? {
            "CreateTargetGroup" => self.create(req, q),
            "DescribeTargetGroups" => self.describe(req, q),
            "DeleteTargetGroup" => self.delete(req, q),
            "RegisterTargets" => self.register_targets(req, q),
            "DeregisterTargets" => self.deregister_targets(req, q),
            "DescribeTargetHealth" => self.describe_health(req, q).await,
            "CreateLoadBalancer" => self.create_alb(req, q),
            "DescribeLoadBalancers" => self.describe_albs(req, q),
            "DeleteLoadBalancer" => self.delete_alb(req, q).await,
            "CreateListener" => self.create_listener(req, q),
            "DescribeListeners" => self.describe_listeners(req, q),
            "DeleteListener" => self.delete_listener(req, q).await,
            _ => Err(Error::new("InvalidAction", "The action is not supported")),
        }
    }

    fn create_alb(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only_list(
            &[
                "Action",
                "Version",
                "Name",
                "Type",
                "Scheme",
                "IpAddressType",
            ],
            &["Subnets.member", "SecurityGroups.member"],
        )?;
        let name = q.required("Name")?;
        if !valid_name(name) {
            return Err(Error::invalid("Invalid load balancer name"));
        }
        if q.get("Type").unwrap_or("application") != "application" {
            return Err(Error::invalid(
                "Only application load balancers are supported",
            ));
        }
        if q.get("Scheme") != Some("internal") || q.get("IpAddressType").unwrap_or("ipv4") != "ipv4"
        {
            return Err(Error::invalid(
                "Only internal IPv4 load balancers are supported",
            ));
        }
        let subnets = q.list("Subnets.member")?;
        let security_groups = q.list("SecurityGroups.member")?;
        if subnets.len() < 2
            || security_groups.is_empty()
            || has_duplicates(&subnets)
            || has_duplicates(&security_groups)
        {
            return Err(Error::invalid(
                "Two subnets and a security group are required",
            ));
        }
        let network_provider = self
            .alb_network
            .as_ref()
            .ok_or_else(|| Error::invalid("ALB network integration is unavailable"))?;
        let endpoint_provider = self
            .alb_endpoint
            .as_ref()
            .ok_or_else(|| Error::invalid("ALB endpoint integration is unavailable"))?;
        let network = network_provider
            .reserve(&req.account_id, &req.region, &subnets, &security_groups)
            .ok_or_else(|| Error::invalid("ALB subnet or security group is unavailable"))?;
        if network.vpc_id.is_empty()
            || network.subnets.len() != subnets.len()
            || network.security_groups != security_groups
            || network.subnets.iter().map(|(id, _)| id).collect::<Vec<_>>()
                != subnets.iter().collect::<Vec<_>>()
            || has_duplicates(
                &network
                    .subnets
                    .iter()
                    .map(|(_, az)| az.clone())
                    .collect::<Vec<_>>(),
            )
        {
            return Err(Error::invalid(
                "ALB subnets must be in distinct zones of one VPC",
            ));
        }
        let endpoint = endpoint_provider
            .reserve(&req.account_id, &req.region, name)
            .ok_or_else(|| Error::invalid("ALB endpoint is unavailable"))?;
        if !endpoint.bind_ip.is_loopback()
            || endpoint.dns_name != endpoint.bind_ip.to_string()
            || std::net::TcpListener::bind(SocketAddr::from((endpoint.bind_ip, 0))).is_err()
        {
            return Err(Error::invalid("ALB endpoint is not locally reachable"));
        }
        let scope = (req.account_id.clone(), req.region.clone());
        let mut state = self.albs.lock().map_err(|_| Error::internal())?;
        let albs = state.load_balancers.entry(scope).or_default();
        if albs.contains_key(name) {
            return Err(Error::new(
                "DuplicateLoadBalancerName",
                "A load balancer with this name already exists",
            ));
        }
        let suffix = Uuid::new_v4().simple().to_string();
        let alb = LoadBalancer {
            arn: format!(
                "arn:aws:elasticloadbalancing:{}:{}:loadbalancer/app/{}/{}",
                req.region,
                req.account_id,
                name,
                &suffix[..16]
            ),
            name: name.to_owned(),
            scheme: "internal".to_owned(),
            network,
            endpoint,
            listeners: BTreeMap::new(),
        };
        let result = format!("<LoadBalancers>{}</LoadBalancers>", alb.xml());
        albs.insert(name.to_owned(), alb);
        Ok(envelope("CreateLoadBalancer", &result, &req.request_id))
    }

    fn describe_albs(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only_list(
            &["Action", "Version", "Marker", "PageSize"],
            &["Names.member", "LoadBalancerArns.member"],
        )?;
        let names = q.list("Names.member")?;
        let arns = q.list("LoadBalancerArns.member")?;
        if !names.is_empty() && !arns.is_empty() {
            return Err(Error::invalid("Specify names or ARNs, not both"));
        }
        let size = page_size(q)?;
        let marker = page_marker(q, "lb:")?;
        let state = self.albs.lock().map_err(|_| Error::internal())?;
        let albs = state
            .load_balancers
            .get(&(req.account_id.clone(), req.region.clone()));
        let all = albs
            .into_iter()
            .flat_map(|items| items.values())
            .collect::<Vec<_>>();
        let selected = if !names.is_empty() {
            names
                .into_iter()
                .map(|name| {
                    albs.and_then(|items| items.get(&name)).ok_or_else(|| {
                        Error::new("LoadBalancerNotFound", "Load balancer not found")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        } else if !arns.is_empty() {
            arns.into_iter()
                .map(|arn| {
                    all.iter().copied().find(|lb| lb.arn == arn).ok_or_else(|| {
                        Error::new("LoadBalancerNotFound", "Load balancer not found")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            all
        };
        if marker > selected.len() {
            return Err(Error::invalid("Invalid marker"));
        }
        let end = marker.saturating_add(size).min(selected.len());
        let body = selected[marker..end]
            .iter()
            .map(|lb| lb.xml())
            .collect::<String>();
        let next = if end < selected.len() {
            format!("<NextMarker>lb:{end}</NextMarker>")
        } else {
            String::new()
        };
        Ok(envelope(
            "DescribeLoadBalancers",
            &format!("<LoadBalancers>{body}</LoadBalancers>{next}"),
            &req.request_id,
        ))
    }

    async fn delete_alb(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only(&["Action", "Version", "LoadBalancerArn"])?;
        let arn = q.required("LoadBalancerArn")?;
        let prefix = format!(
            "arn:aws:elasticloadbalancing:{}:{}:loadbalancer/app/",
            req.region, req.account_id
        );
        if !arn.starts_with(&prefix) {
            return Err(Error::new(
                "LoadBalancerNotFound",
                "Load balancer not found",
            ));
        }
        let scope = (req.account_id.clone(), req.region.clone());
        let removed = {
            let mut groups = self.groups.lock().map_err(|_| Error::internal())?;
            let mut state = self.albs.lock().map_err(|_| Error::internal())?;
            let removed = state.load_balancers.get_mut(&scope).and_then(|albs| {
                let name = albs
                    .values()
                    .find(|lb| lb.arn == arn)
                    .map(|lb| lb.name.clone())?;
                albs.remove(&name)
            });
            if removed.is_some() {
                if let Some(tgs) = groups.get_mut(&scope) {
                    for tg in tgs.values_mut() {
                        if tg.associated_lb.as_deref() == Some(arn) {
                            tg.associated_lb = None;
                        }
                    }
                }
            }
            removed
        };
        if let Some(mut alb) = removed {
            for (_, listener) in std::mem::take(&mut alb.listeners) {
                listener.task.abort();
                let _ = listener.task.await;
            }
        }
        Ok(envelope("DeleteLoadBalancer", "", &req.request_id))
    }

    fn create_listener(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only(&[
            "Action",
            "Version",
            "LoadBalancerArn",
            "Protocol",
            "Port",
            "DefaultActions.member.1.Type",
            "DefaultActions.member.1.TargetGroupArn",
        ])?;
        let lb_arn = q.required("LoadBalancerArn")?;
        let tg_arn = q.required("DefaultActions.member.1.TargetGroupArn")?;
        if q.required("Protocol")? != "HTTP"
            || q.required("DefaultActions.member.1.Type")? != "forward"
        {
            return Err(Error::invalid("Only HTTP forward listeners are supported"));
        }
        let port = q
            .required("Port")?
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| Error::invalid("Invalid listener port"))?;
        let network = self
            .alb_network
            .as_ref()
            .ok_or_else(|| Error::invalid("ALB network integration is unavailable"))?
            .clone();
        let scope = (req.account_id.clone(), req.region.clone());
        let mut groups = self.groups.lock().map_err(|_| Error::internal())?;
        let tg = groups
            .get_mut(&scope)
            .and_then(|items| items.values_mut().find(|tg| tg.arn == tg_arn))
            .ok_or_else(Error::not_found)?;
        if tg.target_type != "ip" {
            return Err(Error::new(
                "InvalidTarget",
                "Only IP target groups are supported",
            ));
        }
        if tg
            .associated_lb
            .as_deref()
            .is_some_and(|owner| owner != lb_arn)
        {
            return Err(Error::new(
                "TargetGroupAssociationLimit",
                "Target group is associated with another load balancer",
            ));
        }
        let mut state = self.albs.lock().map_err(|_| Error::internal())?;
        let alb = state
            .load_balancers
            .get_mut(&scope)
            .and_then(|items| items.values_mut().find(|lb| lb.arn == lb_arn))
            .ok_or_else(|| Error::new("LoadBalancerNotFound", "Load balancer not found"))?;
        if tg.vpc_id != alb.network.vpc_id {
            return Err(Error::invalid("Target group and ALB VPC differ"));
        }
        if alb.listeners.contains_key(&port) {
            return Err(Error::new(
                "DuplicateListener",
                "Listener port already in use",
            ));
        }
        let socket = SocketAddr::from((alb.endpoint.bind_ip, port));
        let bound = std::net::TcpListener::bind(socket)
            .map_err(|_| Error::invalid("Listener endpoint cannot bind"))?;
        bound.set_nonblocking(true).map_err(|_| Error::internal())?;
        let listener = TcpListener::from_std(bound).map_err(|_| Error::internal())?;
        let suffix = Uuid::new_v4().simple().to_string();
        let arn = format!(
            "arn:aws:elasticloadbalancing:{}:{}:listener/app/{}/{}/{}",
            req.region,
            req.account_id,
            alb.name,
            alb.arn.rsplit('/').next().unwrap_or(""),
            &suffix[..16]
        );
        let target_group_arn = tg.arn.clone();
        let lb_arn_owned = alb.arn.clone();
        let context = ListenerContext {
            groups: self.groups.clone(),
            network,
            account: req.account_id.clone(),
            region: req.region.clone(),
            group_ids: alb.network.security_groups.clone(),
            vpc_id: alb.network.vpc_id.clone(),
            source_subnets: alb
                .network
                .subnets
                .iter()
                .map(|(id, _)| id.clone())
                .collect(),
            target_group_arn: target_group_arn.clone(),
            port,
        };
        let task = tokio::spawn(run_listener(listener, context));
        let listener = Listener {
            arn,
            lb_arn: lb_arn_owned.clone(),
            target_group_arn,
            port,
            task,
        };
        let result = format!("<Listeners>{}</Listeners>", listener.xml());
        alb.listeners.insert(port, listener);
        tg.associated_lb = Some(lb_arn_owned);
        Ok(envelope("CreateListener", &result, &req.request_id))
    }

    fn describe_listeners(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only_list(
            &["Action", "Version", "LoadBalancerArn", "Marker", "PageSize"],
            &["ListenerArns.member"],
        )?;
        let lb_arn = q.get("LoadBalancerArn");
        let listener_arns = q.list("ListenerArns.member")?;
        if lb_arn.is_some() == !listener_arns.is_empty() {
            return Err(Error::invalid("Specify load balancer ARN or listener ARNs"));
        }
        let size = page_size(q)?;
        let marker = page_marker(q, "ls:")?;
        let state = self.albs.lock().map_err(|_| Error::internal())?;
        let albs = state
            .load_balancers
            .get(&(req.account_id.clone(), req.region.clone()));
        let all = albs
            .into_iter()
            .flat_map(|items| items.values())
            .flat_map(|lb| lb.listeners.values())
            .collect::<Vec<_>>();
        let selected = if let Some(lb_arn) = lb_arn {
            let lb = albs
                .and_then(|items| items.values().find(|lb| lb.arn == lb_arn))
                .ok_or_else(|| Error::new("LoadBalancerNotFound", "Load balancer not found"))?;
            lb.listeners.values().collect::<Vec<_>>()
        } else {
            listener_arns
                .into_iter()
                .map(|arn| {
                    all.iter()
                        .copied()
                        .find(|ls| ls.arn == arn)
                        .ok_or_else(|| Error::new("ListenerNotFound", "Listener not found"))
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        if marker > selected.len() {
            return Err(Error::invalid("Invalid marker"));
        }
        let end = marker.saturating_add(size).min(selected.len());
        let body = selected[marker..end]
            .iter()
            .map(|ls| ls.xml())
            .collect::<String>();
        let next = if end < selected.len() {
            format!("<NextMarker>ls:{end}</NextMarker>")
        } else {
            String::new()
        };
        Ok(envelope(
            "DescribeListeners",
            &format!("<Listeners>{body}</Listeners>{next}"),
            &req.request_id,
        ))
    }

    async fn delete_listener(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only(&["Action", "Version", "ListenerArn"])?;
        let arn = q.required("ListenerArn")?;
        let scope = (req.account_id.clone(), req.region.clone());
        let listener = {
            let mut groups = self.groups.lock().map_err(|_| Error::internal())?;
            let mut state = self.albs.lock().map_err(|_| Error::internal())?;
            let albs = state
                .load_balancers
                .get_mut(&scope)
                .ok_or_else(|| Error::new("ListenerNotFound", "Listener not found"))?;
            let (lb_name, port) = albs
                .iter()
                .find_map(|(name, lb)| {
                    lb.listeners
                        .iter()
                        .find(|(_, ls)| ls.arn == arn)
                        .map(|(port, _)| (name.clone(), *port))
                })
                .ok_or_else(|| Error::new("ListenerNotFound", "Listener not found"))?;
            let lb = albs.get_mut(&lb_name).expect("selected load balancer");
            let listener = lb.listeners.remove(&port).expect("selected listener");
            if !lb
                .listeners
                .values()
                .any(|other| other.target_group_arn == listener.target_group_arn)
            {
                if let Some(tg) = groups.get_mut(&scope).and_then(|items| {
                    items
                        .values_mut()
                        .find(|tg| tg.arn == listener.target_group_arn)
                }) {
                    tg.associated_lb = None;
                }
            }
            listener
        };
        listener.task.abort();
        let _ = listener.task.await;
        Ok(envelope("DeleteListener", "", &req.request_id))
    }

    fn create(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only(&[
            "Action",
            "Version",
            "Name",
            "Protocol",
            "Port",
            "VpcId",
            "TargetType",
        ])?;
        let name = q.required("Name")?;
        if name.len() > 32
            || name.is_empty()
            || name.starts_with('-')
            || name.ends_with('-')
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err(Error::invalid("Invalid target group name"));
        }
        if q.required("Protocol")? != "HTTP" {
            return Err(Error::invalid("Only HTTP target groups are supported"));
        }
        let port = q
            .required("Port")?
            .parse::<u16>()
            .map_err(|_| Error::invalid("Invalid target group port"))?;
        if port == 0 {
            return Err(Error::invalid("Invalid target group port"));
        }
        let target_type = q.get("TargetType").unwrap_or("instance");
        if target_type != "instance" && target_type != "ip" {
            return Err(Error::invalid("Unsupported target type"));
        }
        let vpc_id = q.required("VpcId")?;
        if !vpc_id.starts_with("vpc-")
            || vpc_id.len() < 9
            || !vpc_id[4..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::invalid("Invalid VPC ID"));
        }
        let Some(vpc) = self.vpc.as_ref() else {
            return Err(Error::invalid("VPC integration is unavailable"));
        };
        let lease = vpc
            .vpc_lease(&req.account_id, &req.region, vpc_id)
            .ok_or_else(|| Error::invalid("VPC does not exist"))?;
        let scope = (req.account_id.clone(), req.region.clone());
        let mut state = self.groups.lock().map_err(|_| Error::internal())?;
        let groups = state.entry(scope).or_default();
        if let Some(existing) = groups.get(name) {
            if existing.vpc_id != vpc_id
                || existing.port != port
                || existing.target_type != target_type
            {
                return Err(Error::new(
                    "DuplicateTargetGroupName",
                    "A target group with this name already exists",
                ));
            }
            return Ok(envelope(
                "CreateTargetGroup",
                &format!("<TargetGroups>{}</TargetGroups>", existing.xml()),
                &req.request_id,
            ));
        }
        let suffix = Uuid::new_v4().simple().to_string();
        let group = TargetGroup {
            arn: format!(
                "arn:aws:elasticloadbalancing:{}:{}:targetgroup/{}/{}",
                req.region,
                req.account_id,
                name,
                &suffix[..16]
            ),
            name: name.to_owned(),
            vpc_id: vpc_id.to_owned(),
            port,
            target_type: target_type.to_owned(),
            _vpc_lease: lease,
            targets: BTreeMap::new(),
            associated_lb: None,
        };
        let result = format!("<TargetGroups>{}</TargetGroups>", group.xml());
        groups.insert(name.to_owned(), group);
        Ok(envelope("CreateTargetGroup", &result, &req.request_id))
    }

    fn describe(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only_list(
            &["Action", "Version", "Marker", "PageSize", "LoadBalancerArn"],
            &["Names.member", "TargetGroupArns.member"],
        )?;
        if q.get("LoadBalancerArn").is_some() {
            return Err(Error::invalid("Load balancer filtering is unavailable"));
        }
        let names = q.list("Names.member")?;
        let arns = q.list("TargetGroupArns.member")?;
        if !names.is_empty() && !arns.is_empty() {
            return Err(Error::invalid("Specify names or ARNs, not both"));
        }
        let size = match q.get("PageSize") {
            Some(s) => {
                let n = s
                    .parse::<usize>()
                    .map_err(|_| Error::invalid("Invalid PageSize"))?;
                if !(1..=400).contains(&n) {
                    return Err(Error::invalid("Invalid PageSize"));
                }
                n
            }
            None => 400,
        };
        let marker = match q.get("Marker") {
            Some(s) => s
                .strip_prefix("tg:")
                .and_then(|x| x.parse::<usize>().ok())
                .ok_or_else(|| Error::invalid("Invalid marker"))?,
            None => 0,
        };
        let state = self.groups.lock().map_err(|_| Error::internal())?;
        let groups = state.get(&(req.account_id.clone(), req.region.clone()));
        let all: Vec<&TargetGroup> = groups.into_iter().flat_map(|g| g.values()).collect();
        let selected: Vec<&TargetGroup> = if !names.is_empty() {
            let mut selected = Vec::new();
            for name in names {
                let group = groups
                    .and_then(|g| g.get(&name))
                    .ok_or_else(Error::not_found)?;
                selected.push(group);
            }
            selected
        } else if !arns.is_empty() {
            let mut selected = Vec::new();
            for arn in arns {
                let group = all
                    .iter()
                    .copied()
                    .find(|g| g.arn == arn)
                    .ok_or_else(Error::not_found)?;
                selected.push(group);
            }
            selected
        } else {
            all
        };
        if marker > selected.len() {
            return Err(Error::invalid("Invalid marker"));
        }
        let end = marker.saturating_add(size).min(selected.len());
        let body = selected[marker..end]
            .iter()
            .map(|g| g.xml())
            .collect::<String>();
        let next = if end < selected.len() {
            format!("<NextMarker>tg:{end}</NextMarker>")
        } else {
            String::new()
        };
        Ok(envelope(
            "DescribeTargetGroups",
            &format!("<TargetGroups>{body}</TargetGroups>{next}"),
            &req.request_id,
        ))
    }

    fn register_targets(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only_target_fields()?;
        let arn = q.required("TargetGroupArn")?;
        let targets = q.targets(true)?;
        if targets.len() > MAX_TARGETS {
            return Err(Error::new("TooManyTargets", "Target limit exceeded"));
        }
        let resolver = self
            .resolver
            .as_ref()
            .ok_or_else(|| Error::invalid("Target endpoint integration is unavailable"))?;
        let scope = (req.account_id.clone(), req.region.clone());
        let (vpc_id, default_port) = {
            let state = self.groups.lock().map_err(|_| Error::internal())?;
            let group = state
                .get(&scope)
                .and_then(|groups| groups.values().find(|g| g.arn == arn))
                .ok_or_else(Error::not_found)?;
            if group.target_type != "ip" {
                return Err(Error::new("InvalidTarget", "Only IP targets are supported"));
            }
            (group.vpc_id.clone(), group.port)
        };
        let mut resolved = Vec::new();
        for target in targets {
            let ip = private_target_ip(&target.id)?;
            let port = target.port.unwrap_or(default_port);
            let endpoint = resolver
                .resolve(&req.account_id, &req.region, &vpc_id, ip, port)
                .ok_or_else(|| Error::new("InvalidTarget", "Target endpoint is unavailable"))?;
            if endpoint.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) {
                return Err(Error::new("InvalidTarget", "Target endpoint must be local"));
            }
            resolved.push(RegisteredTarget { ip, port, endpoint });
        }
        let mut state = self.groups.lock().map_err(|_| Error::internal())?;
        let group = state
            .get_mut(&scope)
            .and_then(|groups| groups.values_mut().find(|g| g.arn == arn))
            .ok_or_else(Error::not_found)?;
        if group.targets.len()
            + resolved
                .iter()
                .filter(|t| !group.targets.contains_key(&(t.ip, t.port)))
                .count()
            > MAX_TARGETS
        {
            return Err(Error::new("TooManyTargets", "Target limit exceeded"));
        }
        for target in resolved {
            group.targets.insert((target.ip, target.port), target);
        }
        Ok(envelope("RegisterTargets", "", &req.request_id))
    }

    fn deregister_targets(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only_target_fields()?;
        let arn = q.required("TargetGroupArn")?;
        let targets = q.targets(true)?;
        let scope = (req.account_id.clone(), req.region.clone());
        let mut state = self.groups.lock().map_err(|_| Error::internal())?;
        let group = state
            .get_mut(&scope)
            .and_then(|groups| groups.values_mut().find(|g| g.arn == arn))
            .ok_or_else(Error::not_found)?;
        if group.target_type != "ip" {
            return Err(Error::new("InvalidTarget", "Only IP targets are supported"));
        }
        let keys = targets
            .into_iter()
            .map(|target| {
                let ip = private_target_ip(&target.id)?;
                Ok((ip, target.port.unwrap_or(group.port)))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        for key in keys {
            group.targets.remove(&key);
        }
        Ok(envelope("DeregisterTargets", "", &req.request_id))
    }

    async fn describe_health(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only_target_fields()?;
        let arn = q.required("TargetGroupArn")?;
        let targets = q.targets(false)?;
        let selected = {
            let state = self.groups.lock().map_err(|_| Error::internal())?;
            let group = state
                .get(&(req.account_id.clone(), req.region.clone()))
                .and_then(|groups| groups.values().find(|g| g.arn == arn))
                .ok_or_else(Error::not_found)?;
            if targets.is_empty() {
                group
                    .targets
                    .values()
                    .cloned()
                    .map(|target| (target, true, group.associated_lb.is_some()))
                    .collect::<Vec<_>>()
            } else {
                let mut selected = Vec::new();
                for target in targets {
                    let ip = private_target_ip(&target.id)?;
                    let port = target.port.unwrap_or(group.port);
                    if let Some(registered) = group.targets.get(&(ip, port)) {
                        selected.push((registered.clone(), true, group.associated_lb.is_some()));
                    } else {
                        selected.push((
                            RegisteredTarget {
                                ip,
                                port,
                                endpoint: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
                            },
                            false,
                            false,
                        ));
                    }
                }
                selected
            }
        };
        let owner = {
            let groups = self.groups.lock().map_err(|_| Error::internal())?;
            groups
                .get(&(req.account_id.clone(), req.region.clone()))
                .and_then(|groups| groups.values().find(|g| g.arn == arn))
                .and_then(|group| group.associated_lb.clone())
        };
        let route_context = if let Some(owner) = owner {
            let state = self.albs.lock().map_err(|_| Error::internal())?;
            state
                .load_balancers
                .get(&(req.account_id.clone(), req.region.clone()))
                .and_then(|albs| albs.values().find(|alb| alb.arn == owner))
                .map(|alb| {
                    (
                        alb.network.vpc_id.clone(),
                        alb.network
                            .subnets
                            .iter()
                            .map(|(id, _)| id.clone())
                            .collect::<Vec<_>>(),
                    )
                })
        } else {
            None
        };
        let mut body = String::new();
        for (target, registered, attached) in selected {
            let (state, reason) = if !registered {
                ("unused", Some("Target.NotRegistered"))
            } else if !attached {
                ("unused", Some("Target.NotInUse"))
            } else if route_context.as_ref().is_some_and(|(vpc_id, subnets)| {
                self.alb_network.as_ref().is_some_and(|network| {
                    !network.allows_target_route(
                        &req.account_id,
                        &req.region,
                        vpc_id,
                        subnets,
                        target.ip,
                    )
                })
            }) {
                ("unhealthy", Some("Target.FailedHealthChecks"))
            } else {
                match probe_http(target.endpoint).await {
                    ProbeHealth::Healthy => ("healthy", None),
                    ProbeHealth::ResponseCodeMismatch => {
                        ("unhealthy", Some("Target.ResponseCodeMismatch"))
                    }
                    ProbeHealth::Timeout => ("unhealthy", Some("Target.Timeout")),
                    ProbeHealth::FailedHealthChecks => {
                        ("unhealthy", Some("Target.FailedHealthChecks"))
                    }
                }
            };
            body.push_str(&target.xml(state, reason));
        }
        Ok(envelope(
            "DescribeTargetHealth",
            &format!("<TargetHealthDescriptions>{body}</TargetHealthDescriptions>"),
            &req.request_id,
        ))
    }

    fn delete(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only(&["Action", "Version", "TargetGroupArn"])?;
        let arn = q.required("TargetGroupArn")?;
        let prefix = format!(
            "arn:aws:elasticloadbalancing:{}:{}:targetgroup/",
            req.region, req.account_id
        );
        if !arn.starts_with(&prefix) {
            return Err(Error::not_found());
        }
        let mut state = self.groups.lock().map_err(|_| Error::internal())?;
        if let Some(groups) = state.get_mut(&(req.account_id.clone(), req.region.clone())) {
            if let Some(group) = groups.values().find(|g| g.arn == arn) {
                if group.associated_lb.is_some() {
                    return Err(Error::new(
                        "ResourceInUse",
                        "Target group is in use by a listener",
                    ));
                }
                let name = group.name.clone();
                groups.remove(&name);
            }
        }
        Ok(envelope("DeleteTargetGroup", "", &req.request_id))
    }
}

#[async_trait]
impl NativeHandler for Elbv2Handler {
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        let mut regions: Vec<_> = self
            .groups
            .lock()
            .map_err(|_| "ELB inventory unavailable")?
            .iter()
            .filter(|(k, v)| k.0 == account && !v.is_empty())
            .map(|(k, _)| k.1.clone())
            .collect();
        regions.extend(
            self.albs
                .lock()
                .map_err(|_| "ELB inventory unavailable")?
                .load_balancers
                .iter()
                .filter(|(k, v)| k.0 == account && !v.is_empty())
                .map(|(k, _)| k.1.clone()),
        );
        Ok(regions)
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let result = if request.method != http::Method::POST || request.body.len() > MAX_BODY {
            Err(Error::invalid("Invalid ELBv2 Query request"))
        } else {
            match Query::parse(&request.body) {
                Err(error) => Err(error),
                Ok(q) if q.get("Version") != Some(VERSION) => {
                    Err(Error::invalid("Unsupported API version"))
                }
                Ok(q) => self.execute(&request, &q).await,
            }
        };
        match result {
            Ok(xml_body) => response(200, xml_body, &request.request_id),
            Err(error) => response(
                error.status,
                error.xml(&request.request_id),
                &request.request_id,
            ),
        }
    }
}

/// Register the ALB slice with explicit network, target and local endpoint owners.
pub fn register_with_alb_integrations(
    registry: &ServiceRegistry,
    vpc: Arc<dyn VpcPreflight>,
    resolver: Arc<dyn TargetEndpointResolver>,
    network: Arc<dyn AlbNetworkPreflight>,
    endpoint: Arc<dyn AlbEndpointAllocator>,
) -> Arc<Elbv2Handler> {
    let handler = Elbv2Handler::with_alb_integrations(vpc, resolver, network, endpoint);
    register_handler(registry, handler.clone());
    handler
}

/// Register with both a scoped VPC lease and an owned local target resolver.
pub fn register_with_integrations(
    registry: &ServiceRegistry,
    vpc: Arc<dyn VpcPreflight>,
    resolver: Arc<dyn TargetEndpointResolver>,
) -> Arc<Elbv2Handler> {
    let handler = Elbv2Handler::with_integrations(vpc, resolver);
    register_handler(registry, handler.clone());
    handler
}

/// Register the control plane without VPC integration. VPC-backed creates fail closed.
pub fn register(registry: &ServiceRegistry) -> Arc<Elbv2Handler> {
    let handler = Elbv2Handler::new();
    register_handler(registry, handler.clone());
    handler
}

pub fn register_with_vpc_preflight(
    registry: &ServiceRegistry,
    vpc: Arc<dyn VpcPreflight>,
) -> Arc<Elbv2Handler> {
    let handler = Elbv2Handler::with_vpc_preflight(vpc);
    register_handler(registry, handler.clone());
    handler
}

fn register_handler(registry: &ServiceRegistry, handler: Arc<Elbv2Handler>) {
    registry.register_native(
        ServiceName::new("elasticloadbalancing"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        handler,
    );
}

fn response(status: u16, body: String, request_id: &str) -> Response {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/xml")
        .header("x-amzn-RequestId", request_id)
        .body(Body::from(body))
        .expect("static ELBv2 XML headers")
}

fn envelope(action: &str, result: &str, request_id: &str) -> String {
    format!("<{action}Response xmlns=\"{XMLNS}\"><{action}Result>{result}</{action}Result><ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata></{action}Response>", xml(request_id))
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

struct Error {
    code: &'static str,
    message: &'static str,
    status: u16,
}
impl Error {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            status: 400,
        }
    }
    fn invalid(message: &'static str) -> Self {
        Self::new("InvalidConfigurationRequest", message)
    }
    fn not_found() -> Self {
        Self::new("TargetGroupNotFound", "Target group not found")
    }
    fn internal() -> Self {
        Self {
            code: "InternalFailure",
            message: "ELBv2 state unavailable",
            status: 500,
        }
    }
    fn xml(&self, id: &str) -> String {
        format!("<ErrorResponse xmlns=\"{XMLNS}\"><Error><Type>Sender</Type><Code>{}</Code><Message>{}</Message></Error><RequestId>{}</RequestId></ErrorResponse>",
            self.code, xml(self.message), xml(id))
    }
}

#[derive(Clone)]
struct TargetInput {
    id: String,
    port: Option<u16>,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn page_size(q: &Query) -> Result<usize, Error> {
    match q.get("PageSize") {
        Some(raw) => raw
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=400).contains(n))
            .ok_or_else(|| Error::invalid("Invalid PageSize")),
        None => Ok(400),
    }
}

fn page_marker(q: &Query, prefix: &str) -> Result<usize, Error> {
    match q.get("Marker") {
        Some(raw) => raw
            .strip_prefix(prefix)
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| Error::invalid("Invalid marker")),
        None => Ok(0),
    }
}

fn private_target_ip(value: &str) -> Result<Ipv4Addr, Error> {
    let ip = value
        .parse::<Ipv4Addr>()
        .map_err(|_| Error::new("InvalidTarget", "Invalid target IP"))?;
    let [a, b, _, _] = ip.octets();
    let allowed = a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b));
    if !allowed {
        return Err(Error::new("InvalidTarget", "Target IP must be private"));
    }
    Ok(ip)
}

struct ListenerContext {
    groups: Arc<Mutex<BTreeMap<Scope, Groups>>>,
    network: Arc<dyn AlbNetworkPreflight>,
    account: String,
    region: String,
    group_ids: Vec<String>,
    vpc_id: String,
    source_subnets: Vec<String>,
    target_group_arn: String,
    port: u16,
}

async fn run_listener(listener: TcpListener, context: ListenerContext) {
    let ListenerContext {
        groups,
        network,
        account,
        region,
        group_ids,
        vpc_id,
        source_subnets,
        target_group_arn,
        port,
    } = context;
    let mut tasks = JoinSet::new();
    let next = Arc::new(AtomicUsize::new(0));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((mut client, source)) = accepted else { break; };
                if tasks.len() >= 64 {
                    let _ = client.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    continue;
                }
                let (std::net::IpAddr::V4(source_ip), _) = (source.ip(), source.port()) else { continue; };
                let groups = groups.clone();
                let network = network.clone();
                let account = account.clone();
                let region = region.clone();
                let group_ids = group_ids.clone();
                let target_group_arn = target_group_arn.clone();
                let vpc_id = vpc_id.clone();
                let source_subnets = source_subnets.clone();
                let next = next.clone();
                tasks.spawn(async move {
                    if !network.allows_ingress(&account, &region, &group_ids, source_ip, port) {
                        return;
                    }
                    let Some(initial) = read_http_head(&mut client).await else {
                        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                        return;
                    };
                    let targets = {
                        let Ok(state) = groups.lock() else { return; };
                        state.get(&(account.clone(), region.clone()))
                            .and_then(|items| items.values().find(|tg| tg.arn == target_group_arn))
                            .map(|tg| tg.targets.values().cloned().collect::<Vec<_>>())
                            .unwrap_or_default()
                    };
                    let mut healthy = Vec::new();
                    for target in targets {
                        if !network.allows_target_route(
                            &account,
                            &region,
                            &vpc_id,
                            &source_subnets,
                            target.ip,
                        ) {
                            continue;
                        }
                        if probe_http(target.endpoint).await == ProbeHealth::Healthy {
                            healthy.push(target.endpoint);
                        }
                    }
                    if healthy.is_empty() {
                        let _ = client.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                        return;
                    }
                    let endpoint = healthy[next.fetch_add(1, Ordering::Relaxed) % healthy.len()];
                    let Ok(Ok(mut backend)) = timeout(Duration::from_millis(500), TcpStream::connect(endpoint)).await else {
                        let _ = client.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                        return;
                    };
                    if backend.write_all(&initial).await.is_err() { return; }
                    let _ = timeout(Duration::from_secs(30), tokio::io::copy_bidirectional(&mut client, &mut backend)).await;
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

async fn read_http_head(client: &mut TcpStream) -> Option<Vec<u8>> {
    let read = async {
        let mut bytes = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        while bytes.len() < 16 * 1024 {
            let n = client.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            bytes.extend_from_slice(&chunk[..n]);
            if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        if !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            return None;
        }
        let line = bytes.split(|b| *b == b'\r').next()?;
        let line = std::str::from_utf8(line).ok()?;
        if !line.ends_with(" HTTP/1.1") && !line.ends_with(" HTTP/1.0") {
            return None;
        }
        if line.bytes().any(|b| b < 0x20) {
            return None;
        }
        Some(bytes)
    };
    timeout(Duration::from_secs(2), read).await.ok().flatten()
}

async fn probe_http(endpoint: SocketAddr) -> ProbeHealth {
    if endpoint.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return ProbeHealth::FailedHealthChecks;
    }
    let check = async {
        let mut stream = TcpStream::connect(endpoint).await?;
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut bytes = Vec::with_capacity(128);
        let mut chunk = [0u8; 64];
        while bytes.len() < 256 {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..n]);
            if bytes.windows(2).any(|w| w == b"\r\n") {
                break;
            }
        }
        let line = bytes.split(|b| *b == b'\r').next().unwrap_or(&[]);
        let line = std::str::from_utf8(line).unwrap_or("");
        let status = line
            .strip_prefix("HTTP/1.1 ")
            .or_else(|| line.strip_prefix("HTTP/1.0 "))
            .and_then(|rest| rest.get(..3))
            .and_then(|code| code.parse::<u16>().ok());
        Ok::<_, std::io::Error>(match status {
            Some(200) => ProbeHealth::Healthy,
            Some(100..=599) => ProbeHealth::ResponseCodeMismatch,
            _ => ProbeHealth::FailedHealthChecks,
        })
    };
    match timeout(PROBE_TIMEOUT, check).await {
        Ok(Ok(health)) => health,
        Ok(Err(_)) => ProbeHealth::FailedHealthChecks,
        Err(_) => ProbeHealth::Timeout,
    }
}

struct Query {
    params: BTreeMap<String, String>,
}
impl Query {
    fn parse(body: &[u8]) -> Result<Self, Error> {
        let text =
            std::str::from_utf8(body).map_err(|_| Error::invalid("Invalid Query encoding"))?;
        let mut params = BTreeMap::new();
        for pair in text.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = decode(key)?;
            let value = decode(value)?;
            if params.insert(key, value).is_some() {
                return Err(Error::invalid("Duplicate Query parameter"));
            }
        }
        Ok(Self { params })
    }
    fn get(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }
    fn required(&self, key: &str) -> Result<&str, Error> {
        self.get(key)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::invalid("Missing required parameter"))
    }
    fn only(&self, allowed: &[&str]) -> Result<(), Error> {
        self.only_list(allowed, &[])
    }
    fn only_list(&self, allowed: &[&str], lists: &[&str]) -> Result<(), Error> {
        for key in self.params.keys() {
            if allowed.contains(&key.as_str()) {
                continue;
            }
            if lists.iter().any(|p| {
                key.strip_prefix(&format!("{p}."))
                    .is_some_and(|n| n.parse::<usize>().is_ok_and(|i| i > 0))
            }) {
                continue;
            }
            return Err(Error::invalid("Unsupported Query parameter"));
        }
        Ok(())
    }
    fn only_target_fields(&self) -> Result<(), Error> {
        for key in self.params.keys() {
            if ["Action", "Version", "TargetGroupArn"].contains(&key.as_str()) {
                continue;
            }
            let parts = key.split('.').collect::<Vec<_>>();
            if parts.len() == 4
                && parts[0] == "Targets"
                && parts[1] == "member"
                && parts[2].parse::<usize>().is_ok_and(|n| n > 0)
                && ["Id", "Port", "AvailabilityZone"].contains(&parts[3])
            {
                continue;
            }
            return Err(Error::invalid("Unsupported Query parameter"));
        }
        Ok(())
    }
    fn targets(&self, required: bool) -> Result<Vec<TargetInput>, Error> {
        let mut indices = self
            .params
            .keys()
            .filter_map(|key| {
                key.strip_prefix("Targets.member.")?
                    .split('.')
                    .next()?
                    .parse::<usize>()
                    .ok()
            })
            .collect::<Vec<_>>();
        indices.sort_unstable();
        indices.dedup();
        if indices.is_empty() {
            if required {
                return Err(Error::invalid("Missing targets"));
            }
            return Ok(Vec::new());
        }
        if indices.len() > MAX_TARGETS {
            return Err(Error::new("TooManyTargets", "Target limit exceeded"));
        }
        let mut out = Vec::new();
        for (offset, index) in indices.into_iter().enumerate() {
            if index != offset + 1 {
                return Err(Error::invalid("Noncontiguous target list"));
            }
            let id = self
                .required(&format!("Targets.member.{index}.Id"))?
                .to_owned();
            let port = match self.get(&format!("Targets.member.{index}.Port")) {
                Some(raw) => {
                    let value = raw
                        .parse::<u16>()
                        .map_err(|_| Error::invalid("Invalid target port"))?;
                    if value == 0 {
                        return Err(Error::invalid("Invalid target port"));
                    }
                    Some(value)
                }
                None => None,
            };
            if self
                .get(&format!("Targets.member.{index}.AvailabilityZone"))
                .is_some_and(|zone| zone != "all")
            {
                return Err(Error::invalid("Unsupported AvailabilityZone"));
            }
            out.push(TargetInput { id, port });
        }
        Ok(out)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>, Error> {
        let mut out = Vec::new();
        let mut index = 1;
        loop {
            let key = format!("{prefix}.{index}");
            match self.get(&key) {
                Some(value) if !value.is_empty() => out.push(value.to_owned()),
                Some(_) => return Err(Error::invalid("Empty list member")),
                None => break,
            }
            index += 1;
        }
        if self.params.keys().any(|key| {
            key.strip_prefix(&format!("{prefix}."))
                .and_then(|n| n.parse::<usize>().ok())
                .is_some_and(|n| n >= index)
        }) {
            return Err(Error::invalid("Noncontiguous list"));
        }
        Ok(out)
    }
}

fn decode(raw: &str) -> Result<String, Error> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => decoded.push(b' '),
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(Error::invalid("Invalid percent encoding"));
                }
                let hex = |b: u8| -> Option<u8> {
                    match b {
                        b'0'..=b'9' => Some(b - b'0'),
                        b'a'..=b'f' => Some(b - b'a' + 10),
                        b'A'..=b'F' => Some(b - b'A' + 10),
                        _ => None,
                    }
                };
                let hi =
                    hex(bytes[i + 1]).ok_or_else(|| Error::invalid("Invalid percent encoding"))?;
                let lo =
                    hex(bytes[i + 2]).ok_or_else(|| Error::invalid("Invalid percent encoding"))?;
                decoded.push((hi << 4) | lo);
                i += 2;
            }
            byte => decoded.push(byte),
        }
        i += 1;
    }
    String::from_utf8(decoded).map_err(|_| Error::invalid("Invalid Query encoding"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use http::{HeaderMap, Method, Uri};

    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct TestVpc {
        active: Arc<AtomicUsize>,
    }
    struct TestLease(Arc<AtomicUsize>);
    impl Drop for TestLease {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl VpcPreflight for TestVpc {
        fn vpc_lease(
            &self,
            account: &str,
            region: &str,
            vpc_id: &str,
        ) -> Option<Arc<dyn Send + Sync>> {
            if account != "111111111111" || region != "us-east-1" || vpc_id != "vpc-12345678" {
                return None;
            }
            self.active.fetch_add(1, Ordering::SeqCst);
            Some(Arc::new(TestLease(self.active.clone())))
        }
    }

    fn request(body: &str, account: &str, region: &str) -> ServiceRequest {
        ServiceRequest {
            method: Method::POST,
            uri: Uri::from_static("/"),
            headers: HeaderMap::new(),
            body: body.as_bytes().to_vec().into(),
            account_id: account.into(),
            region: region.into(),
            request_id: "rid-1".into(),
        }
    }

    async fn run(handler: &Elbv2Handler, body: &str, account: &str, region: &str) -> (u16, String) {
        let response = handler.handle(request(body, account, region)).await;
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    const CREATE: &str = "Action=CreateTargetGroup&Version=2015-12-01&Name=web&Protocol=HTTP&Port=8080&VpcId=vpc-12345678&TargetType=ip";
    const DESCRIBE: &str = "Action=DescribeTargetGroups&Version=2015-12-01";

    #[tokio::test]
    async fn target_group_create_describe_idempotence_and_delete() {
        let handler = Elbv2Handler::with_vpc_preflight(Arc::new(TestVpc::default()));
        let (status, first) = run(&handler, CREATE, "111111111111", "us-east-1").await;
        assert_eq!(status, 200);
        assert!(first.contains("<TargetGroupName>web</TargetGroupName>"));
        assert!(first.contains("<TargetType>ip</TargetType>"));
        let (_, second) = run(&handler, CREATE, "111111111111", "us-east-1").await;
        assert_eq!(first, second);
        let arn = first
            .split("<TargetGroupArn>")
            .nth(1)
            .unwrap()
            .split("</TargetGroupArn>")
            .next()
            .unwrap();
        let (_, listed) = run(&handler, DESCRIBE, "111111111111", "us-east-1").await;
        assert!(listed.contains(arn));
        let (status, scoped) = run(&handler, DESCRIBE, "222222222222", "us-east-1").await;
        assert_eq!(status, 200);
        assert!(!scoped.contains(arn));
        let (status, scoped) = run(&handler, DESCRIBE, "111111111111", "eu-west-1").await;
        assert_eq!(status, 200);
        assert!(!scoped.contains(arn));
        let delete = format!("Action=DeleteTargetGroup&Version=2015-12-01&TargetGroupArn={arn}");
        let (status, _) = run(&handler, &delete, "111111111111", "us-east-1").await;
        assert_eq!(status, 200);
        let (_, listed) = run(&handler, DESCRIBE, "111111111111", "us-east-1").await;
        assert!(!listed.contains(arn));
    }

    #[tokio::test]
    async fn rejects_unsupported_and_invalid_vpc_without_mutation() {
        let handler = Elbv2Handler::new();
        let (status, body) = run(&handler, CREATE, "111111111111", "us-east-1").await;
        assert_eq!(status, 400);
        assert!(body.contains("InvalidConfigurationRequest"));
        let handler = Elbv2Handler::with_vpc_preflight(Arc::new(TestVpc::default()));
        for body in [
            "Action=CreateLoadBalancer&Version=2015-12-01&Name=fake",
            "Action=CreateTargetGroup&Version=2015-12-01&Name=web&Protocol=HTTP&Port=8080&VpcId=vpc-ffffffff&TargetType=ip",
            "Action=CreateTargetGroup&Version=2015-12-01&Name=web&Protocol=TCP&Port=8080&VpcId=vpc-12345678&TargetType=ip",
            "Action=CreateTargetGroup&Version=2015-12-01&Name=web&Protocol=HTTP&Port=8080&VpcId=vpc-12345678&TargetType=ip&Tags.member.1.Key=team",
            "Action=CreateTargetGroup&Version=2015-12-01&Name=web&Protocol=HTTP&Port=8080&VpcId=vpc-12345678&TargetType=ip&Name=again",
        ] {
            let (status, _) = run(&handler, body, "111111111111", "us-east-1").await;
            assert_eq!(status, 400);
        }
        let (_, listed) = run(&handler, DESCRIBE, "111111111111", "us-east-1").await;
        assert!(!listed.contains("<member>"));
    }

    #[tokio::test]
    async fn vpc_lease_lives_with_target_group_and_drops_on_delete() {
        let vpc = Arc::new(TestVpc::default());
        let handler = Elbv2Handler::with_vpc_preflight(vpc.clone());
        let (status, first) = run(&handler, CREATE, "111111111111", "us-east-1").await;
        assert_eq!(status, 200);
        assert_eq!(vpc.active.load(Ordering::SeqCst), 1);
        let (_, second) = run(&handler, CREATE, "111111111111", "us-east-1").await;
        assert_eq!(first, second);
        assert_eq!(vpc.active.load(Ordering::SeqCst), 1);
        let arn = first
            .split("<TargetGroupArn>")
            .nth(1)
            .unwrap()
            .split("</TargetGroupArn>")
            .next()
            .unwrap();
        let delete = format!("Action=DeleteTargetGroup&Version=2015-12-01&TargetGroupArn={arn}");
        assert_eq!(
            run(&handler, &delete, "111111111111", "us-east-1").await.0,
            200
        );
        assert_eq!(vpc.active.load(Ordering::SeqCst), 0);
    }

    struct TestResolver(SocketAddr);
    impl TargetEndpointResolver for TestResolver {
        fn resolve(
            &self,
            account: &str,
            region: &str,
            vpc_id: &str,
            ip: Ipv4Addr,
            port: u16,
        ) -> Option<SocketAddr> {
            (account == "111111111111"
                && region == "us-east-1"
                && vpc_id == "vpc-12345678"
                && ip == Ipv4Addr::new(10, 0, 0, 10)
                && port == 8080)
                .then_some(self.0)
        }
    }

    #[tokio::test]
    async fn private_target_registration_and_real_http_probe() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 512];
            let n = stream.read(&mut req).await.unwrap();
            assert!(std::str::from_utf8(&req[..n])
                .unwrap()
                .starts_with("GET / HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let handler = Elbv2Handler::with_integrations(
            Arc::new(TestVpc::default()),
            Arc::new(TestResolver(endpoint)),
        );
        let (_, created) = run(&handler, CREATE, "111111111111", "us-east-1").await;
        let arn = created
            .split("<TargetGroupArn>")
            .nth(1)
            .unwrap()
            .split("</TargetGroupArn>")
            .next()
            .unwrap();
        let register = format!("Action=RegisterTargets&Version=2015-12-01&TargetGroupArn={arn}&Targets.member.1.Id=10.0.0.10");
        assert_eq!(
            run(&handler, &register, "111111111111", "us-east-1")
                .await
                .0,
            200
        );
        let health = format!("Action=DescribeTargetHealth&Version=2015-12-01&TargetGroupArn={arn}");
        let (_, described) = run(&handler, &health, "111111111111", "us-east-1").await;
        assert!(described.contains("<State>unused</State><Reason>Target.NotInUse</Reason>"));
        assert!(!described.contains("<State>healthy</State>"));
        assert_eq!(
            handler
                .probe_registered_target(
                    "111111111111",
                    "us-east-1",
                    arn,
                    Ipv4Addr::new(10, 0, 0, 10),
                    8080
                )
                .await,
            Some(ProbeHealth::Healthy)
        );
        server.await.unwrap();
        let deregister = format!("Action=DeregisterTargets&Version=2015-12-01&TargetGroupArn={arn}&Targets.member.1.Id=10.0.0.10");
        assert_eq!(
            run(&handler, &deregister, "111111111111", "us-east-1")
                .await
                .0,
            200
        );
        assert_eq!(
            handler
                .probe_registered_target(
                    "111111111111",
                    "us-east-1",
                    arn,
                    Ipv4Addr::new(10, 0, 0, 10),
                    8080
                )
                .await,
            None
        );
    }

    #[tokio::test]
    async fn probe_distinguishes_http_failure_and_timeout() {
        let mismatch_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mismatch_addr = mismatch_listener.local_addr().unwrap();
        let mismatch_server = tokio::spawn(async move {
            let (mut stream, _) = mismatch_listener.accept().await.unwrap();
            let mut request = [0u8; 128];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        assert_eq!(
            probe_http(mismatch_addr).await,
            ProbeHealth::ResponseCodeMismatch
        );
        mismatch_server.await.unwrap();

        let timeout_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let timeout_addr = timeout_listener.local_addr().unwrap();
        let timeout_server = tokio::spawn(async move {
            let (_stream, _) = timeout_listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        assert_eq!(probe_http(timeout_addr).await, ProbeHealth::Timeout);
        timeout_server.abort();
    }

    #[tokio::test]
    async fn unsafe_or_unresolved_targets_do_not_mutate() {
        let handler = Elbv2Handler::with_vpc_preflight(Arc::new(TestVpc::default()));
        let (_, created) = run(&handler, CREATE, "111111111111", "us-east-1").await;
        let arn = created
            .split("<TargetGroupArn>")
            .nth(1)
            .unwrap()
            .split("</TargetGroupArn>")
            .next()
            .unwrap();
        let register = format!("Action=RegisterTargets&Version=2015-12-01&TargetGroupArn={arn}&Targets.member.1.Id=10.0.0.10");
        assert_eq!(
            run(&handler, &register, "111111111111", "us-east-1")
                .await
                .0,
            400
        );
        let handler = Elbv2Handler::with_integrations(
            Arc::new(TestVpc::default()),
            Arc::new(TestResolver("10.0.0.1:8080".parse().unwrap())),
        );
        let (_, created) = run(&handler, CREATE, "111111111111", "us-east-1").await;
        let arn = created
            .split("<TargetGroupArn>")
            .nth(1)
            .unwrap()
            .split("</TargetGroupArn>")
            .next()
            .unwrap();
        for ip in ["10.0.0.10", "127.0.0.1", "8.8.8.8", "169.254.169.254"] {
            let register = format!("Action=RegisterTargets&Version=2015-12-01&TargetGroupArn={arn}&Targets.member.1.Id={ip}");
            assert_eq!(
                run(&handler, &register, "111111111111", "us-east-1")
                    .await
                    .0,
                400
            );
        }
        let health = format!("Action=DescribeTargetHealth&Version=2015-12-01&TargetGroupArn={arn}");
        let (_, described) = run(&handler, &health, "111111111111", "us-east-1").await;
        assert!(!described.contains("<member>"));
    }

    struct TestAlbNetwork;
    impl AlbNetworkPreflight for TestAlbNetwork {
        fn reserve(
            &self,
            account: &str,
            region: &str,
            subnet_ids: &[String],
            group_ids: &[String],
        ) -> Option<AlbNetworkLease> {
            if account != "111111111111"
                || region != "us-east-1"
                || subnet_ids != ["subnet-a", "subnet-b"]
                || group_ids != ["sg-1"]
            {
                return None;
            }
            Some(AlbNetworkLease {
                vpc_id: "vpc-12345678".into(),
                subnets: vec![
                    ("subnet-a".into(), "us-east-1a".into()),
                    ("subnet-b".into(), "us-east-1b".into()),
                ],
                security_groups: vec!["sg-1".into()],
                guard: Arc::new(()),
            })
        }
        fn allows_ingress(
            &self,
            account: &str,
            region: &str,
            group_ids: &[String],
            source: Ipv4Addr,
            _port: u16,
        ) -> bool {
            account == "111111111111"
                && region == "us-east-1"
                && group_ids == ["sg-1"]
                && source.is_loopback()
        }
    }

    #[tokio::test]
    async fn alb_listener_routes_only_healthy_target_and_closes_socket_on_delete() {
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = backend.accept().await.unwrap();
                let mut request = [0u8; 512];
                let n = stream.read(&mut request).await.unwrap();
                assert!(std::str::from_utf8(&request[..n])
                    .unwrap()
                    .starts_with("GET / HTTP/1.1"));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await
                    .unwrap();
            }
        });
        let allocator = Arc::new(LoopbackAlbEndpointAllocator::default());
        let handler = Elbv2Handler::with_alb_integrations(
            Arc::new(TestVpc::default()),
            Arc::new(TestResolver(backend_addr)),
            Arc::new(TestAlbNetwork),
            allocator,
        );
        let free = std::net::TcpListener::bind("127.1.1.1:0").unwrap();
        let listener_port = free.local_addr().unwrap().port();
        drop(free);
        let create_lb = "Action=CreateLoadBalancer&Version=2015-12-01&Name=my-alb&Type=application&Scheme=internal&IpAddressType=ipv4&Subnets.member.1=subnet-a&Subnets.member.2=subnet-b&SecurityGroups.member.1=sg-1";
        let (status, lb) = run(&handler, create_lb, "111111111111", "us-east-1").await;
        assert_eq!(status, 200, "{lb}");
        assert!(lb.contains("<DNSName>127.1.1.1</DNSName>"));
        let lb_arn = lb
            .split("<LoadBalancerArn>")
            .nth(1)
            .unwrap()
            .split("</LoadBalancerArn>")
            .next()
            .unwrap();
        let (_, tg) = run(&handler, CREATE, "111111111111", "us-east-1").await;
        let tg_arn = tg
            .split("<TargetGroupArn>")
            .nth(1)
            .unwrap()
            .split("</TargetGroupArn>")
            .next()
            .unwrap();
        let create_listener = format!("Action=CreateListener&Version=2015-12-01&LoadBalancerArn={lb_arn}&Protocol=HTTP&Port={listener_port}&DefaultActions.member.1.Type=forward&DefaultActions.member.1.TargetGroupArn={tg_arn}");
        let (status, created) = run(&handler, &create_listener, "111111111111", "us-east-1").await;
        assert_eq!(status, 200, "{created}");
        let listener_arn = created
            .split("<ListenerArn>")
            .nth(1)
            .unwrap()
            .split("</ListenerArn>")
            .next()
            .unwrap();
        let socket = SocketAddr::from((Ipv4Addr::new(127, 1, 1, 1), listener_port));
        let mut client = TcpStream::connect(socket).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 503"));
        let register = format!("Action=RegisterTargets&Version=2015-12-01&TargetGroupArn={tg_arn}&Targets.member.1.Id=10.0.0.10");
        assert_eq!(
            run(&handler, &register, "111111111111", "us-east-1")
                .await
                .0,
            200
        );
        let mut client = TcpStream::connect(socket).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert!(response.ends_with(b"OK"));
        let health =
            format!("Action=DescribeTargetHealth&Version=2015-12-01&TargetGroupArn={tg_arn}");
        let (_, described) = run(&handler, &health, "111111111111", "us-east-1").await;
        assert!(described.contains("<State>healthy</State>"));
        let delete_tg =
            format!("Action=DeleteTargetGroup&Version=2015-12-01&TargetGroupArn={tg_arn}");
        assert_eq!(
            run(&handler, &delete_tg, "111111111111", "us-east-1")
                .await
                .0,
            400
        );
        let delete_listener =
            format!("Action=DeleteListener&Version=2015-12-01&ListenerArn={listener_arn}");
        assert_eq!(
            run(&handler, &delete_listener, "111111111111", "us-east-1")
                .await
                .0,
            200
        );
        assert!(TcpStream::connect(socket).await.is_err());
        assert_eq!(
            run(&handler, &delete_tg, "111111111111", "us-east-1")
                .await
                .0,
            200
        );
        let delete_lb =
            format!("Action=DeleteLoadBalancer&Version=2015-12-01&LoadBalancerArn={lb_arn}");
        assert_eq!(
            run(&handler, &delete_lb, "111111111111", "us-east-1")
                .await
                .0,
            200
        );
        backend_task.await.unwrap();
    }

    #[tokio::test]
    async fn pagination_and_missing_filters() {
        let handler = Elbv2Handler::with_vpc_preflight(Arc::new(TestVpc::default()));
        for name in ["alpha", "beta"] {
            let body = CREATE.replace("Name=web", &format!("Name={name}"));
            assert_eq!(
                run(&handler, &body, "111111111111", "us-east-1").await.0,
                200
            );
        }
        let (_, page) = run(
            &handler,
            &format!("{DESCRIBE}&PageSize=1"),
            "111111111111",
            "us-east-1",
        )
        .await;
        assert!(page.contains("<NextMarker>tg:1</NextMarker>"));
        let (_, page) = run(
            &handler,
            &format!("{DESCRIBE}&PageSize=1&Marker=tg%3A1"),
            "111111111111",
            "us-east-1",
        )
        .await;
        assert!(page.contains("<TargetGroupName>beta</TargetGroupName>"));
        let (status, body) = run(
            &handler,
            &format!("{DESCRIBE}&Names.member.1=missing"),
            "111111111111",
            "us-east-1",
        )
        .await;
        assert_eq!(status, 400);
        assert!(body.contains("TargetGroupNotFound"));
    }
}
