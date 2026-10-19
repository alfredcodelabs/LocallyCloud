//! Scoped ELBv2 Query API with owned HTTP listeners, periodic health and durable configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::identity::trusted_role;
use locallycloud_core::integration::RequestIdentity;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{timeout, Duration, Instant};
use uuid::Uuid;
mod persistence;
pub use persistence::PersistError;
use persistence::{Persistence, SavedAlb, SavedGroup, SavedListener};

const XMLNS: &str = "http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/";
const VERSION: &str = "2015-12-01";
const MAX_BODY: usize = 128 * 1024;
const MAX_TARGETS: usize = 16;
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

macro_rules! elb_actions {
    ($($name:ident),+ $(,)?) => {
        #[derive(Clone,Copy)]
        enum ElbAction { $($name),+ }
        impl ElbAction {
            fn parse(value:&str)->Result<Self,Error> { match value { $(stringify!($name)=>Ok(Self::$name),)+ _=>Err(Error::new("InvalidAction","The action is not supported")) } }
            fn name(self)->&'static str {match self { $(Self::$name=>stringify!($name),)+ }}
        }
    }
}
elb_actions!(
    CreateTargetGroup,
    DescribeTargetGroups,
    DeleteTargetGroup,
    RegisterTargets,
    DeregisterTargets,
    DescribeTargetHealth,
    DescribeTargetGroupAttributes,
    ModifyTargetGroupAttributes,
    CreateLoadBalancer,
    DescribeLoadBalancers,
    DeleteLoadBalancer,
    CreateListener,
    DescribeListeners,
    DeleteListener
);

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
    pub network_id: String,
    pub vpc_id: String,
    pub subnets: Vec<(String, String)>,
    pub security_groups: Vec<String>,
    pub guard: Arc<dyn Send + Sync>,
}

pub struct AlbTargetConnection<'a> {
    pub network_id: &'a str,
    pub account: &'a str,
    pub region: &'a str,
    pub vpc_id: &'a str,
    pub source_subnets: &'a [String],
    pub source_security_groups: &'a [String],
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
}

#[async_trait]
pub trait AlbNetworkPreflight: Send + Sync {
    fn allows_target_connection(&self, _connection: &AlbTargetConnection<'_>) -> bool {
        false
    }

    /// Connect through a trusted runtime boundary after current policy and endpoint ownership checks.
    async fn connect_target(
        &self,
        _connection: &AlbTargetConnection<'_>,
        _endpoint: SocketAddr,
    ) -> std::io::Result<TcpStream> {
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    }

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
    fn restore(
        &self,
        account: &str,
        region: &str,
        name: &str,
        ip: Ipv4Addr,
    ) -> Option<AlbEndpoint> {
        self.reserve(account, region, name)
            .filter(|endpoint| endpoint.bind_ip == ip)
    }
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
    fn restore(
        &self,
        _account: &str,
        _region: &str,
        _name: &str,
        ip: Ipv4Addr,
    ) -> Option<AlbEndpoint> {
        let [a, b, c, d] = ip.octets();
        if a != 127 || b != 1 || c == 0 || c == 255 || d == 0 || d == 255 {
            return None;
        }
        if !self.used.lock().ok()?.insert(ip) {
            return None;
        }
        Some(AlbEndpoint {
            bind_ip: ip,
            dns_name: ip.to_string(),
            guard: Arc::new(LoopbackReservation {
                ip,
                used: self.used.clone(),
            }),
        })
    }
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
    generation: Uuid,
    health: HealthState,
    successes: u8,
    failures: u8,
    next_probe: Instant,
    probing: bool,
    draining_until: Option<Instant>,
    confirmed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HealthState {
    Initial,
    Healthy,
    Unhealthy(ProbeHealth),
}

impl HealthState {
    fn wire(self) -> (&'static str, Option<&'static str>) {
        match self {
            Self::Initial => ("initial", Some("Elb.InitialHealthChecking")),
            Self::Healthy => ("healthy", None),
            Self::Unhealthy(ProbeHealth::ResponseCodeMismatch) => {
                ("unhealthy", Some("Target.ResponseCodeMismatch"))
            }
            Self::Unhealthy(ProbeHealth::Timeout) => ("unhealthy", Some("Target.Timeout")),
            Self::Unhealthy(_) => ("unhealthy", Some("Target.FailedHealthChecks")),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HealthSettings {
    path: String,
    port: Option<u16>,
    interval: u64,
    timeout: u64,
    healthy: u8,
    unhealthy: u8,
    codes: Vec<(u16, u16)>,
    matcher: String,
}

impl Default for HealthSettings {
    fn default() -> Self {
        Self {
            path: "/".into(),
            port: None,
            interval: 30,
            timeout: 6,
            healthy: 5,
            unhealthy: 2,
            codes: vec![(200, 200)],
            matcher: "200".into(),
        }
    }
}

impl HealthSettings {
    fn parse(q: &Query) -> Result<Self, Error> {
        let mut result = Self::default();
        if q.get("HealthCheckProtocol").unwrap_or("HTTP") != "HTTP"
            || q.get("HealthCheckEnabled").unwrap_or("true") != "true"
        {
            return Err(Error::invalid(
                "Only enabled HTTP health checks are supported",
            ));
        }
        result.path = q.get("HealthCheckPath").unwrap_or("/").to_owned();
        if !result.path.starts_with('/')
            || result.path.len() > 1024
            || !result.path.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(Error::invalid("Invalid health check path"));
        }
        result.port = match q.get("HealthCheckPort").unwrap_or("traffic-port") {
            "traffic-port" => None,
            raw => Some(
                raw.parse::<u16>()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| Error::invalid("Invalid health check port"))?,
            ),
        };
        for (key, slot, low, high) in [
            ("HealthCheckIntervalSeconds", &mut result.interval, 5, 300),
            ("HealthCheckTimeoutSeconds", &mut result.timeout, 2, 120),
        ] {
            if let Some(raw) = q.get(key) {
                *slot = raw
                    .parse::<u64>()
                    .ok()
                    .filter(|n| (low..=high).contains(n))
                    .ok_or_else(|| Error::invalid("Invalid health check timing"))?;
            }
        }
        for (key, slot) in [
            ("HealthyThresholdCount", &mut result.healthy),
            ("UnhealthyThresholdCount", &mut result.unhealthy),
        ] {
            if let Some(raw) = q.get(key) {
                *slot = raw
                    .parse::<u8>()
                    .ok()
                    .filter(|n| (2..=10).contains(n))
                    .ok_or_else(|| Error::invalid("Invalid health threshold"))?;
            }
        }
        result.matcher = q.get("Matcher.HttpCode").unwrap_or("200").to_owned();
        if result.matcher.len() > 1024 {
            return Err(Error::invalid("Invalid health matcher"));
        }
        result.codes.clear();
        for part in result.matcher.split(',') {
            let mut range = part.split('-');
            let low = range
                .next()
                .and_then(|s| s.parse::<u16>().ok())
                .filter(|n| (200..=499).contains(n))
                .ok_or_else(|| Error::invalid("Invalid health matcher"))?;
            let high = match range.next() {
                Some(raw) => raw
                    .parse::<u16>()
                    .ok()
                    .filter(|n| (low..=499).contains(n))
                    .ok_or_else(|| Error::invalid("Invalid health matcher"))?,
                None => low,
            };
            if range.next().is_some() {
                return Err(Error::invalid("Invalid health matcher"));
            }
            result.codes.push((low, high));
        }
        Ok(result)
    }
}

impl RegisteredTarget {
    fn new(ip: Ipv4Addr, port: u16, _endpoint: SocketAddr) -> Self {
        Self {
            ip,
            port,
            generation: Uuid::new_v4(),
            health: HealthState::Initial,
            successes: 0,
            failures: 0,
            next_probe: Instant::now(),
            probing: false,
            draining_until: None,
            confirmed: true,
        }
    }
    fn observe(&mut self, result: ProbeHealth, settings: &HealthSettings) {
        if result == ProbeHealth::Healthy {
            self.failures = 0;
            self.successes = self.successes.saturating_add(1);
            if self.health == HealthState::Initial || self.successes >= settings.healthy {
                self.health = HealthState::Healthy;
            }
        } else {
            self.successes = 0;
            self.failures = self.failures.saturating_add(1);
            if self.failures >= settings.unhealthy {
                self.health = HealthState::Unhealthy(result);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeHealth {
    Healthy,
    ResponseCodeMismatch,
    Timeout,
    FailedHealthChecks,
}

impl RegisteredTarget {
    fn xml(&self, state: &str, reason: Option<&str>, health_port: u16) -> String {
        let reason = reason
            .map(|reason| format!("<Reason>{reason}</Reason>"))
            .unwrap_or_default();
        format!("<member><Target><Id>{}</Id><Port>{}</Port></Target><HealthCheckPort>{}</HealthCheckPort><TargetHealth><State>{state}</State>{reason}</TargetHealth></member>", self.ip, self.port, health_port)
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
    health: HealthSettings,
    deregistration_delay: u64,
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
        let h = &self.health;
        let health_port = h
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "traffic-port".into());
        format!(
            "<member><TargetGroupArn>{}</TargetGroupArn><TargetGroupName>{}</TargetGroupName><Protocol>HTTP</Protocol><Port>{}</Port><VpcId>{}</VpcId><HealthCheckProtocol>HTTP</HealthCheckProtocol><HealthCheckPort>{health_port}</HealthCheckPort><HealthCheckEnabled>true</HealthCheckEnabled><HealthCheckIntervalSeconds>{}</HealthCheckIntervalSeconds><HealthCheckTimeoutSeconds>{}</HealthCheckTimeoutSeconds><HealthyThresholdCount>{}</HealthyThresholdCount><UnhealthyThresholdCount>{}</UnhealthyThresholdCount><HealthCheckPath>{}</HealthCheckPath><Matcher><HttpCode>{}</HttpCode></Matcher><TargetType>{}</TargetType><ProtocolVersion>HTTP1</ProtocolVersion><IpAddressType>ipv4</IpAddressType>{attached}</member>",
            xml(&self.arn), xml(&self.name), self.port, xml(&self.vpc_id),h.interval,h.timeout,h.healthy,h.unhealthy,xml(&h.path),xml(&h.matcher),xml(&self.target_type)
        )
    }
}

type Scope = (String, String);
type Groups = BTreeMap<String, TargetGroup>;

#[derive(Clone)]
pub struct Elbv2Handler {
    groups: Arc<Mutex<BTreeMap<Scope, Groups>>>,
    albs: Arc<Mutex<AlbState>>,
    persistence: Option<Arc<Persistence>>,
    ready: Arc<AtomicBool>,
    operation_limit: Arc<tokio::sync::Semaphore>,
    registry: Weak<ServiceRegistry>,
    vpc: Option<Arc<dyn VpcPreflight>>,
    resolver: Option<Arc<dyn TargetEndpointResolver>>,
    alb_network: Option<Arc<dyn AlbNetworkPreflight>>,
    alb_endpoint: Option<Arc<dyn AlbEndpointAllocator>>,
}

impl Default for Elbv2Handler {
    fn default() -> Self {
        Self {
            groups: Arc::new(Mutex::new(BTreeMap::new())),
            albs: Arc::new(Mutex::new(AlbState::default())),
            persistence: None,
            ready: Arc::new(AtomicBool::new(true)),
            operation_limit: Arc::new(tokio::sync::Semaphore::new(32)),
            registry: Weak::new(),
            vpc: None,
            resolver: None,
            alb_network: None,
            alb_endpoint: None,
        }
    }
}

impl Elbv2Handler {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn with_vpc_preflight(vpc: Arc<dyn VpcPreflight>) -> Arc<Self> {
        Arc::new(Self {
            groups: Arc::new(Mutex::new(BTreeMap::new())),
            albs: Arc::new(Mutex::new(AlbState::default())),
            persistence: None,
            ready: Arc::new(AtomicBool::new(true)),
            operation_limit: Arc::new(tokio::sync::Semaphore::new(32)),
            registry: Weak::new(),
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
            albs: Arc::new(Mutex::new(AlbState::default())),
            persistence: None,
            ready: Arc::new(AtomicBool::new(true)),
            operation_limit: Arc::new(tokio::sync::Semaphore::new(32)),
            registry: Weak::new(),
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
            albs: Arc::new(Mutex::new(AlbState::default())),
            persistence: None,
            ready: Arc::new(AtomicBool::new(true)),
            operation_limit: Arc::new(tokio::sync::Semaphore::new(32)),
            registry: Weak::new(),
            vpc: Some(vpc),
            resolver: Some(resolver),
            alb_network: Some(network),
            alb_endpoint: Some(endpoint),
        })
    }

    fn restore_group(
        &self,
        scope: &Scope,
        name: &str,
        saved: SavedGroup,
    ) -> Result<(), PersistError> {
        let prefix = format!(
            "arn:aws:elasticloadbalancing:{}:{}:targetgroup/{}/",
            scope.1, scope.0, name
        );
        if saved.name != name
            || !valid_name(name)
            || !saved.arn.starts_with(&prefix)
            || saved.port == 0
            || saved.targets.len() > MAX_TARGETS
            || saved.delay > 3600
            || !matches!(saved.target_type.as_str(), "ip" | "instance")
        {
            return Err("invalid restored target group".into());
        }
        let lease = self
            .vpc
            .as_ref()
            .and_then(|v| v.vpc_lease(&scope.0, &scope.1, &saved.vpc_id))
            .ok_or("restored target group VPC is unavailable")?;
        let mut targets = BTreeMap::new();
        for (ip, port) in saved.targets {
            private_target_ip(&ip.to_string())?;
            if port == 0 {
                return Err("invalid restored target port".into());
            }
            let mut target =
                RegisteredTarget::new(ip, port, SocketAddr::from((Ipv4Addr::LOCALHOST, 1)));
            target.confirmed = false;
            if targets.insert((ip, port), target).is_some() {
                return Err("duplicate restored target".into());
            }
        }
        let group = TargetGroup {
            arn: saved.arn,
            name: saved.name,
            vpc_id: saved.vpc_id,
            port: saved.port,
            target_type: saved.target_type,
            _vpc_lease: lease,
            targets,
            associated_lb: None,
            health: saved.health,
            deregistration_delay: saved.delay,
        };
        self.groups
            .lock()
            .map_err(|_| Error::internal())?
            .entry(scope.clone())
            .or_default()
            .insert(name.to_owned(), group);
        Ok(())
    }

    fn restore_alb(&self, scope: &Scope, name: &str, saved: SavedAlb) -> Result<(), PersistError> {
        let prefix = format!(
            "arn:aws:elasticloadbalancing:{}:{}:loadbalancer/app/{}/",
            scope.1, scope.0, name
        );
        if saved.name != name
            || !valid_name(name)
            || !saved.arn.starts_with(&prefix)
            || !saved.bind_ip.is_loopback()
        {
            return Err("invalid restored ALB".into());
        }
        let network = self
            .alb_network
            .as_ref()
            .and_then(|n| n.reserve(&scope.0, &scope.1, &saved.subnets, &saved.groups))
            .ok_or("restored ALB network is unavailable")?;
        let endpoint = self
            .alb_endpoint
            .as_ref()
            .and_then(|e| e.restore(&scope.0, &scope.1, name, saved.bind_ip))
            .ok_or("restored ALB endpoint is unavailable")?;
        let alb = LoadBalancer {
            arn: saved.arn.clone(),
            name: saved.name.clone(),
            scheme: "internal".into(),
            network,
            endpoint,
            listeners: BTreeMap::new(),
        };
        self.albs
            .lock()
            .map_err(|_| Error::internal())?
            .load_balancers
            .entry(scope.clone())
            .or_default()
            .insert(name.to_owned(), alb);
        let req = ServiceRequest {
            method: http::Method::POST,
            uri: http::Uri::from_static("/"),
            headers: http::HeaderMap::new(),
            body: Default::default(),
            account_id: scope.0.clone(),
            region: scope.1.clone(),
            request_id: "restore".into(),
        };
        for listener in saved.listeners {
            let listener_prefix = format!(
                "arn:aws:elasticloadbalancing:{}:{}:listener/app/{}/{}/",
                scope.1,
                scope.0,
                name,
                saved.arn.rsplit('/').next().unwrap_or("")
            );
            if !listener.arn.starts_with(&listener_prefix) {
                return Err("invalid restored listener ARN".into());
            }
            let q = Query {
                params: BTreeMap::from([
                    ("Action".into(), "CreateListener".into()),
                    ("Version".into(), VERSION.into()),
                    ("LoadBalancerArn".into(), saved.arn.clone()),
                    ("Protocol".into(), "HTTP".into()),
                    ("Port".into(), listener.port.to_string()),
                    ("DefaultActions.member.1.Type".into(), "forward".into()),
                    (
                        "DefaultActions.member.1.TargetGroupArn".into(),
                        listener.target_group_arn,
                    ),
                ]),
            };
            self.create_listener(&req, &q)?;
            let mut state = self.albs.lock().map_err(|_| Error::internal())?;
            let actual = state
                .load_balancers
                .get_mut(scope)
                .and_then(|a| a.get_mut(name))
                .and_then(|a| a.listeners.get_mut(&listener.port))
                .ok_or("restored listener missing")?;
            actual.arn = listener.arn;
        }
        Ok(())
    }

    /// Explicit diagnostic probe; DescribeTargetHealth only reads periodic cached state.
    /// Standalone target groups report Target.NotInUse.
    pub async fn probe_registered_target(
        &self,
        account: &str,
        region: &str,
        arn: &str,
        ip: Ipv4Addr,
        port: u16,
    ) -> Option<ProbeHealth> {
        let vpc_id = {
            let state = self.groups.lock().ok()?;
            let group = state
                .get(&(account.to_owned(), region.to_owned()))?
                .values()
                .find(|g| g.arn == arn)?;
            group
                .targets
                .get(&(ip, port))
                .filter(|t| t.draining_until.is_none() && t.confirmed)?;
            group.vpc_id.clone()
        };
        let endpoint = self
            .resolver
            .as_ref()?
            .resolve(account, region, &vpc_id, ip, port)?;
        Some(probe_http(endpoint).await)
    }

    async fn execute(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        let permit = self
            .operation_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::new("Throttling", "Too many concurrent ELBv2 operations"))?;
        let handler = self.clone();
        let req = req.clone();
        let q = q.clone();
        let (body, retired) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            handler.execute_blocking(&req, &q)
        })
        .await
        .map_err(|_| Error::internal())??;
        for task in retired {
            let _ = task.await;
        }
        Ok(body)
    }

    fn execute_blocking(
        &self,
        req: &ServiceRequest,
        q: &Query,
    ) -> Result<(String, Vec<JoinHandle<()>>), Error> {
        let action = ElbAction::parse(q.required("Action")?)?;
        let planned = match action {
            ElbAction::CreateTargetGroup => Some(self.planned_group_arn(req, q)?),
            ElbAction::CreateLoadBalancer => Some(self.planned_alb_arn(req, q)?),
            _ => None,
        };
        self.authorize_operator(req, q, action, planned.as_deref())?;
        let result = match action {
            ElbAction::CreateTargetGroup => {
                self.create(req, q, planned.as_deref().ok_or_else(Error::internal)?)
            }
            ElbAction::CreateLoadBalancer => {
                self.create_alb(req, q, planned.as_deref().ok_or_else(Error::internal)?)
            }
            ElbAction::DescribeTargetGroups => self.describe(req, q),
            ElbAction::DeleteTargetGroup => self.delete(req, q),
            ElbAction::RegisterTargets => self.register_targets(req, q),
            ElbAction::DeregisterTargets => self.deregister_targets(req, q),
            ElbAction::DescribeTargetHealth => self.describe_health(req, q),
            ElbAction::DescribeTargetGroupAttributes => self.target_attributes(req, q, false),
            ElbAction::ModifyTargetGroupAttributes => self.target_attributes(req, q, true),
            ElbAction::DescribeLoadBalancers => self.describe_albs(req, q),
            ElbAction::DeleteLoadBalancer => return self.delete_alb(req, q),
            ElbAction::CreateListener => self.create_listener(req, q),
            ElbAction::DescribeListeners => self.describe_listeners(req, q),
            ElbAction::DeleteListener => return self.delete_listener(req, q),
        };
        result.map(|body| (body, Vec::new()))
    }

    fn planned_group_arn(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        let name = q.required("Name")?;
        if !valid_name(name) {
            return Err(Error::invalid("Invalid target group name"));
        }
        if let Some(group) = self
            .groups
            .lock()
            .map_err(|_| Error::internal())?
            .get(&(req.account_id.clone(), req.region.clone()))
            .and_then(|groups| groups.get(name))
        {
            return Ok(group.arn.clone());
        }
        let suffix = Uuid::new_v4().simple().to_string();
        Ok(format!(
            "arn:aws:elasticloadbalancing:{}:{}:targetgroup/{name}/{}",
            req.region,
            req.account_id,
            &suffix[..16]
        ))
    }

    fn planned_alb_arn(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        let name = q.required("Name")?;
        if !valid_name(name) {
            return Err(Error::invalid("Invalid load balancer name"));
        }
        let suffix = Uuid::new_v4().simple().to_string();
        Ok(format!(
            "arn:aws:elasticloadbalancing:{}:{}:loadbalancer/app/{name}/{}",
            req.region,
            req.account_id,
            &suffix[..16]
        ))
    }

    fn authorize_operator(
        &self,
        req: &ServiceRequest,
        q: &Query,
        action: ElbAction,
        planned: Option<&str>,
    ) -> Result<(), Error> {
        let Some(evaluator) = self
            .registry
            .upgrade()
            .and_then(|registry| registry.authorization_evaluator(&ServiceName::new("iam")))
        else {
            return Ok(());
        };
        if evaluator.strict_sigv4_required()
            && ![
                "x-locallycloud-verified-external-sigv4",
                "x-locallycloud-verified-internal-scope",
            ]
            .iter()
            .any(|header| req.headers.get(*header) == Some(&http::HeaderValue::from_static("1")))
        {
            return Err(Error {
                code: "AccessDenied",
                message: "Verified caller identity is required",
                status: 403,
            });
        }
        let resource = match action {
            ElbAction::CreateLoadBalancer | ElbAction::CreateTargetGroup => {
                planned.ok_or_else(Error::internal)?
            }
            ElbAction::RegisterTargets
            | ElbAction::DeregisterTargets
            | ElbAction::DeleteTargetGroup
            | ElbAction::ModifyTargetGroupAttributes => q.required("TargetGroupArn")?,
            ElbAction::CreateListener | ElbAction::DeleteLoadBalancer => {
                q.required("LoadBalancerArn")?
            }
            ElbAction::DeleteListener => q.required("ListenerArn")?,
            ElbAction::DescribeLoadBalancers
            | ElbAction::DescribeListeners
            | ElbAction::DescribeTargetGroups
            | ElbAction::DescribeTargetHealth
            | ElbAction::DescribeTargetGroupAttributes => "*",
        };
        let mut context = BTreeMap::new();
        if matches!(action, ElbAction::CreateLoadBalancer) {
            context.insert(
                "elasticloadbalancing:scheme".into(),
                vec![q.get("Scheme").unwrap_or("internet-facing").into()],
            );
            context.insert(
                "elasticloadbalancing:subnet".into(),
                q.list("Subnets.member")?,
            );
            context.insert(
                "elasticloadbalancing:securitygroup".into(),
                q.list("SecurityGroups.member")?,
            );
        }
        evaluator
            .authorize(AuthorizationRequest {
                request_identity: RequestIdentity {
                    account_id: req.account_id.clone(),
                    access_key_id: req
                        .headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .and_then(RequestIdentity::access_key_from_authorization),
                    arn: None,
                },
                delegated_identity: trusted_role(req),
                source_service: "elasticloadbalancing".into(),
                action: format!("elasticloadbalancing:{}", action.name()),
                resource: resource.into(),
                context,
            })
            .map_err(|_| Error {
                code: "AccessDenied",
                message: "Not authorized for this ELBv2 operation",
                status: 403,
            })
    }

    fn create_alb(
        &self,
        req: &ServiceRequest,
        q: &Query,
        planned_arn: &str,
    ) -> Result<String, Error> {
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
        if network.network_id.is_empty()
            || network.vpc_id.is_empty()
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
        let alb = LoadBalancer {
            arn: planned_arn.to_owned(),
            name: name.to_owned(),
            scheme: "internal".to_owned(),
            network,
            endpoint,
            listeners: BTreeMap::new(),
        };
        let result = format!("<LoadBalancers>{}</LoadBalancers>", alb.xml());
        if let Some(persistence) = &self.persistence {
            persistence.save(
                &(req.account_id.clone(), req.region.clone()),
                "alb",
                name,
                &SavedAlb::from_alb(&alb),
            )?;
        }
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

    fn delete_alb(
        &self,
        req: &ServiceRequest,
        q: &Query,
    ) -> Result<(String, Vec<JoinHandle<()>>), Error> {
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
            let selected_name = state.load_balancers.get(&scope).and_then(|albs| {
                albs.values()
                    .find(|lb| lb.arn == arn)
                    .map(|lb| lb.name.clone())
            });
            if let (Some(persistence), Some(name)) = (&self.persistence, &selected_name) {
                persistence.delete(&scope, "alb", name)?;
            }
            let removed = selected_name.and_then(|name| {
                state
                    .load_balancers
                    .get_mut(&scope)
                    .and_then(|albs| albs.remove(&name))
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
        let mut retired = Vec::new();
        if let Some(mut alb) = removed {
            for (_, listener) in std::mem::take(&mut alb.listeners) {
                listener.task.abort();
                retired.push(listener.task);
            }
        }
        Ok((envelope("DeleteLoadBalancer", "", &req.request_id), retired))
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
            resolver: self
                .resolver
                .clone()
                .ok_or_else(|| Error::invalid("Target endpoint integration is unavailable"))?,
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
            network_id: alb.network.network_id.clone(),
            ready: self.ready.clone(),
            target_group_arn: target_group_arn.clone(),
            port,
        };
        if let Some(persistence) = &self.persistence {
            let mut saved = SavedAlb::from_alb(alb);
            saved.listeners.push(SavedListener {
                arn: arn.clone(),
                port,
                target_group_arn: target_group_arn.clone(),
            });
            persistence.save(&scope, "alb", &alb.name, &saved)?;
        }
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
        if lb_arn.is_some() != listener_arns.is_empty() {
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

    fn delete_listener(
        &self,
        req: &ServiceRequest,
        q: &Query,
    ) -> Result<(String, Vec<JoinHandle<()>>), Error> {
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
            if let Some(persistence) = &self.persistence {
                let mut saved = SavedAlb::from_alb(lb);
                saved.listeners.retain(|l| l.port != port);
                persistence.save(&scope, "alb", &lb.name, &saved)?;
            }
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
        Ok((
            envelope("DeleteListener", "", &req.request_id),
            vec![listener.task],
        ))
    }

    fn create(&self, req: &ServiceRequest, q: &Query, planned_arn: &str) -> Result<String, Error> {
        q.only(&[
            "Action",
            "Version",
            "Name",
            "Protocol",
            "Port",
            "VpcId",
            "TargetType",
            "HealthCheckProtocol",
            "HealthCheckPort",
            "HealthCheckEnabled",
            "HealthCheckPath",
            "HealthCheckIntervalSeconds",
            "HealthCheckTimeoutSeconds",
            "HealthyThresholdCount",
            "UnhealthyThresholdCount",
            "Matcher.HttpCode",
        ])?;
        let health = HealthSettings::parse(q)?;
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
            if existing.arn != planned_arn {
                self.authorize_operator(req, q, ElbAction::CreateTargetGroup, Some(&existing.arn))?;
            }
            if existing.vpc_id != vpc_id
                || existing.port != port
                || existing.target_type != target_type
                || existing.health != health
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
        let group = TargetGroup {
            arn: planned_arn.to_owned(),
            name: name.to_owned(),
            vpc_id: vpc_id.to_owned(),
            port,
            target_type: target_type.to_owned(),
            _vpc_lease: lease,
            targets: BTreeMap::new(),
            associated_lb: None,
            health,
            deregistration_delay: 300,
        };
        let result = format!("<TargetGroups>{}</TargetGroups>", group.xml());
        if let Some(persistence) = &self.persistence {
            persistence.save(
                &(req.account_id.clone(), req.region.clone()),
                "group",
                name,
                &SavedGroup::from_group(&group),
            )?;
        }
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
            resolved.push(RegisteredTarget::new(ip, port, endpoint));
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
        let changed = resolved.iter().any(|target| {
            !group
                .targets
                .get(&(target.ip, target.port))
                .is_some_and(|old| old.confirmed && old.draining_until.is_none())
        });
        if !changed {
            return Ok(envelope("RegisterTargets", "", &req.request_id));
        }
        if let Some(persistence) = &self.persistence {
            let mut saved = SavedGroup::from_group(group);
            for target in &resolved {
                if !saved.targets.contains(&(target.ip, target.port)) {
                    saved.targets.push((target.ip, target.port));
                }
            }
            persistence.save(&scope, "group", &group.name, &saved)?;
        }
        for target in resolved {
            let key = (target.ip, target.port);
            if !group
                .targets
                .get(&key)
                .is_some_and(|t| t.draining_until.is_none() && t.confirmed)
            {
                group.targets.insert(key, target);
            }
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
        if !keys.iter().any(|key| {
            group
                .targets
                .get(key)
                .is_some_and(|target| target.draining_until.is_none())
        }) {
            return Ok(envelope("DeregisterTargets", "", &req.request_id));
        }
        if let Some(persistence) = &self.persistence {
            let mut saved = SavedGroup::from_group(group);
            saved.targets.retain(|key| !keys.contains(key));
            persistence.save(&scope, "group", &group.name, &saved)?;
        }
        for key in keys {
            if let Some(target) = group.targets.get_mut(&key) {
                if target.draining_until.is_none() {
                    target.draining_until =
                        Some(Instant::now() + Duration::from_secs(group.deregistration_delay));
                }
            }
        }
        Ok(envelope("DeregisterTargets", "", &req.request_id))
    }

    fn describe_health(&self, req: &ServiceRequest, q: &Query) -> Result<String, Error> {
        q.only_target_fields()?;
        let arn = q.required("TargetGroupArn")?;
        let targets = q.targets(false)?;
        let mut state = self.groups.lock().map_err(|_| Error::internal())?;
        let group = state
            .get_mut(&(req.account_id.clone(), req.region.clone()))
            .and_then(|g| g.values_mut().find(|g| g.arn == arn))
            .ok_or_else(Error::not_found)?;
        group.targets.retain(|_, t| {
            !t.draining_until
                .is_some_and(|until| until <= Instant::now())
        });
        let keys = if targets.is_empty() {
            group.targets.keys().copied().collect::<Vec<_>>()
        } else {
            targets
                .into_iter()
                .map(|t| Ok((private_target_ip(&t.id)?, t.port.unwrap_or(group.port))))
                .collect::<Result<Vec<_>, Error>>()?
        };
        let mut body = String::new();
        for (ip, port) in keys {
            let (target, health) = match group.targets.get(&(ip, port)) {
                None => (
                    RegisteredTarget::new(ip, port, SocketAddr::from((Ipv4Addr::LOCALHOST, 1))),
                    ("unused", Some("Target.NotRegistered")),
                ),
                Some(t) => {
                    let state = if t.draining_until.is_some() {
                        ("draining", Some("Target.DeregistrationInProgress"))
                    } else if !t.confirmed {
                        ("unused", Some("Target.NotRegistered"))
                    } else if group.associated_lb.is_none() {
                        ("unused", Some("Target.NotInUse"))
                    } else {
                        t.health.wire()
                    };
                    (t.clone(), state)
                }
            };
            body.push_str(&target.xml(health.0, health.1, group.health.port.unwrap_or(port)));
        }
        Ok(envelope(
            "DescribeTargetHealth",
            &format!("<TargetHealthDescriptions>{body}</TargetHealthDescriptions>"),
            &req.request_id,
        ))
    }

    fn target_attributes(
        &self,
        req: &ServiceRequest,
        q: &Query,
        modify: bool,
    ) -> Result<String, Error> {
        if modify {
            q.only(&[
                "Action",
                "Version",
                "TargetGroupArn",
                "Attributes.member.1.Key",
                "Attributes.member.1.Value",
            ])?;
            if q.required("Attributes.member.1.Key")? != "deregistration_delay.timeout_seconds" {
                return Err(Error::invalid("Unsupported target group attribute"));
            }
        } else {
            q.only(&["Action", "Version", "TargetGroupArn"])?;
        }
        let delay = if modify {
            Some(
                q.required("Attributes.member.1.Value")?
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n <= 3600)
                    .ok_or_else(|| Error::invalid("Invalid deregistration delay"))?,
            )
        } else {
            None
        };
        let arn = q.required("TargetGroupArn")?;
        let mut state = self.groups.lock().map_err(|_| Error::internal())?;
        let group = state
            .get_mut(&(req.account_id.clone(), req.region.clone()))
            .and_then(|gs| gs.values_mut().find(|g| g.arn == arn))
            .ok_or_else(Error::not_found)?;
        if let Some(delay) = delay {
            if let Some(persistence) = &self.persistence {
                let mut saved = SavedGroup::from_group(group);
                saved.delay = delay;
                persistence.save(
                    &(req.account_id.clone(), req.region.clone()),
                    "group",
                    &group.name,
                    &saved,
                )?;
            }
            group.deregistration_delay = delay;
        }
        let body = format!("<Attributes><member><Key>deregistration_delay.timeout_seconds</Key><Value>{}</Value></member></Attributes>",group.deregistration_delay);
        Ok(envelope(
            if modify {
                "ModifyTargetGroupAttributes"
            } else {
                "DescribeTargetGroupAttributes"
            },
            &body,
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
                if let Some(persistence) = &self.persistence {
                    persistence.delete(
                        &(req.account_id.clone(), req.region.clone()),
                        "group",
                        &name,
                    )?;
                }
                groups.remove(&name);
            }
        }
        Ok(envelope("DeleteTargetGroup", "", &req.request_id))
    }
}

impl Drop for LoadBalancer {
    fn drop(&mut self) {
        for listener in self.listeners.values() {
            listener.task.abort();
        }
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

/// Restore encrypted configuration before exposing the ALB control and data planes.
pub async fn register_with_state_and_alb_integrations(
    registry: &Arc<ServiceRegistry>,
    vpc: Arc<dyn VpcPreflight>,
    resolver: Arc<dyn TargetEndpointResolver>,
    network: Arc<dyn AlbNetworkPreflight>,
    endpoint: Arc<dyn AlbEndpointAllocator>,
    state: Arc<locallycloud_state::StateDb>,
) -> Result<Arc<Elbv2Handler>, PersistError> {
    let handler = Elbv2Handler::with_alb_integrations(vpc, resolver, network, endpoint);
    handler.ready.store(false, Ordering::Release);
    let restored = tokio::task::spawn_blocking(move || -> Result<Elbv2Handler, PersistError> {
        let persistence = Arc::new(Persistence::new(
            state,
            locallycloud_state::StateCipher::from_env()?,
        )?);
        persistence.restore(&handler)?;
        let mut result = (*handler).clone();
        result.persistence = Some(persistence);
        Ok(result)
    })
    .await??;
    restored.ready.store(true, Ordering::Release);
    let handler = Arc::new(restored);
    Ok(register_handler(registry, handler))
}

/// Register the ALB slice with explicit network, target and local endpoint owners.
pub fn register_with_alb_integrations(
    registry: &Arc<ServiceRegistry>,
    vpc: Arc<dyn VpcPreflight>,
    resolver: Arc<dyn TargetEndpointResolver>,
    network: Arc<dyn AlbNetworkPreflight>,
    endpoint: Arc<dyn AlbEndpointAllocator>,
) -> Arc<Elbv2Handler> {
    let handler = Elbv2Handler::with_alb_integrations(vpc, resolver, network, endpoint);
    register_handler(registry, handler)
}

/// Register with both a scoped VPC lease and an owned local target resolver.
pub fn register_with_integrations(
    registry: &Arc<ServiceRegistry>,
    vpc: Arc<dyn VpcPreflight>,
    resolver: Arc<dyn TargetEndpointResolver>,
) -> Arc<Elbv2Handler> {
    let handler = Elbv2Handler::with_integrations(vpc, resolver);
    register_handler(registry, handler)
}

/// Register the control plane without VPC integration. VPC-backed creates fail closed.
pub fn register(registry: &Arc<ServiceRegistry>) -> Arc<Elbv2Handler> {
    let handler = Elbv2Handler::new();
    register_handler(registry, handler)
}

pub fn register_with_vpc_preflight(
    registry: &Arc<ServiceRegistry>,
    vpc: Arc<dyn VpcPreflight>,
) -> Arc<Elbv2Handler> {
    let handler = Elbv2Handler::with_vpc_preflight(vpc);
    register_handler(registry, handler)
}

fn register_handler(
    registry: &Arc<ServiceRegistry>,
    handler: Arc<Elbv2Handler>,
) -> Arc<Elbv2Handler> {
    let mut wired = (*handler).clone();
    wired.registry = Arc::downgrade(registry);
    let wired = Arc::new(wired);
    registry.register_native(
        ServiceName::new("elasticloadbalancing"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        wired.clone(),
    );
    wired
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

#[derive(Debug)]
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

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for Error {}

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

fn routing_targets(targets: Vec<RegisteredTarget>) -> Vec<RegisteredTarget> {
    let active = targets
        .into_iter()
        .filter(|t| t.draining_until.is_none() && t.confirmed)
        .collect::<Vec<_>>();
    let all_unhealthy = !active.is_empty()
        && active
            .iter()
            .all(|t| matches!(t.health, HealthState::Unhealthy(_)));
    // Fail-open selects registered unhealthy targets; current network and endpoint checks still apply.
    active
        .into_iter()
        .filter(|t| t.health == HealthState::Healthy || all_unhealthy)
        .collect()
}

struct ProbeReset {
    groups: Arc<Mutex<BTreeMap<Scope, Groups>>>,
    scope: Scope,
    arn: String,
    key: (Ipv4Addr, u16),
    generation: Uuid,
}
impl Drop for ProbeReset {
    fn drop(&mut self) {
        if let Ok(mut state) = self.groups.lock() {
            if let Some(target) = state
                .get_mut(&self.scope)
                .and_then(|gs| gs.values_mut().find(|g| g.arn == self.arn))
                .and_then(|g| g.targets.get_mut(&self.key))
            {
                if target.generation == self.generation {
                    target.probing = false;
                }
            }
        }
    }
}

struct ListenerContext {
    groups: Arc<Mutex<BTreeMap<Scope, Groups>>>,
    network: Arc<dyn AlbNetworkPreflight>,
    resolver: Arc<dyn TargetEndpointResolver>,
    account: String,
    region: String,
    group_ids: Vec<String>,
    vpc_id: String,
    source_subnets: Vec<String>,
    network_id: String,
    ready: Arc<AtomicBool>,
    target_group_arn: String,
    port: u16,
}

async fn run_listener(listener: TcpListener, context: ListenerContext) {
    let ListenerContext {
        groups,
        network,
        resolver,
        account,
        region,
        group_ids,
        vpc_id,
        source_subnets,
        network_id,
        ready,
        target_group_arn,
        port,
    } = context;
    while !ready.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut tasks = JoinSet::new();
    let next = Arc::new(AtomicUsize::new(0));
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let due = {
                    let Ok(mut state) = groups.lock() else { break; };
                    let Some(group) = state.get_mut(&(account.clone(),region.clone())).and_then(|gs|gs.values_mut().find(|g|g.arn == target_group_arn)) else { break; };
                    group.targets.retain(|_,t| !t.draining_until.is_some_and(|until|until <= Instant::now()));
                    let mut due = Vec::new();
                    for target in group.targets.values_mut() {
                        if tasks.len() + due.len() >= 64 { break; }
                        if target.confirmed && target.draining_until.is_none() && !target.probing && target.next_probe <= Instant::now() {
                            target.next_probe = Instant::now() + Duration::from_secs(group.health.interval);
                            target.probing = true;
                            due.push((target.clone(),group.health.clone()));
                        }
                    }
                    due
                };
                for (target,settings) in due {
                    let groups = groups.clone(); let network = network.clone(); let resolver = resolver.clone();
                    let account = account.clone(); let region = region.clone(); let group_ids = group_ids.clone();
                    let vpc_id = vpc_id.clone(); let network_id = network_id.clone(); let source_subnets = source_subnets.clone(); let arn = target_group_arn.clone();
                    let reset = ProbeReset { groups: groups.clone(), scope: (account.clone(),region.clone()), arn: arn.clone(), key: (target.ip,target.port), generation: target.generation };
                    tasks.spawn(async move {
                        let _reset = reset;
                        let port = settings.port.unwrap_or(target.port);
                        let connection = AlbTargetConnection { network_id: &network_id, account: &account, region: &region, vpc_id: &vpc_id,source_subnets: &source_subnets,source_security_groups: &group_ids,target_ip:target.ip,target_port:port };
                        let endpoint = resolver.resolve(&account,&region,&vpc_id,target.ip,port).filter(|s|s.ip() == std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
                        let result = match endpoint {
                            Some(endpoint) if network.allows_target_route(&account,&region,&vpc_id,&source_subnets,target.ip) && network.allows_target_connection(&connection) => {
                                let check = async {
                                    match network.connect_target(&connection,endpoint).await {
                                        Ok(stream) => probe_stream(stream,&settings).await,
                                        Err(_) => ProbeHealth::FailedHealthChecks,
                                    }
                                };
                                timeout(Duration::from_secs(settings.timeout),check).await.unwrap_or(ProbeHealth::Timeout)
                            },
                            _ => ProbeHealth::FailedHealthChecks,
                        };
                        if let Ok(mut state) = groups.lock() {
                            if let Some(current) = state.get_mut(&(account,region)).and_then(|gs|gs.values_mut().find(|g|g.arn == arn)).and_then(|g|g.targets.get_mut(&(target.ip,target.port))) {
                                if current.generation == target.generation && current.draining_until.is_none() { current.probing = false; current.observe(result,&settings); }
                            }
                        }
                    });
                }
            }
            accepted = listener.accept() => {
                let Ok((mut client, source)) = accepted else { break; };
                if tasks.len() >= 64 {
                    let _ = client.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    continue;
                }
                let (std::net::IpAddr::V4(source_ip), _) = (source.ip(), source.port()) else { continue; };
                let groups = groups.clone();
                let network = network.clone();
                let resolver = resolver.clone();
                let account = account.clone();
                let region = region.clone();
                let group_ids = group_ids.clone();
                let target_group_arn = target_group_arn.clone();
                let vpc_id = vpc_id.clone();
                let source_subnets = source_subnets.clone();
                let network_id = network_id.clone();
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
                    let eligible = routing_targets(targets);
                    if eligible.is_empty() {
                        let _ = client.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                        return;
                    }
                    let target = &eligible[next.fetch_add(1, Ordering::Relaxed) % eligible.len()];
                    let connection = AlbTargetConnection { network_id: &network_id, account: &account, region: &region, vpc_id: &vpc_id, source_subnets: &source_subnets,source_security_groups: &group_ids,target_ip:target.ip,target_port:target.port };
                    let endpoint = resolver.resolve(&account,&region,&vpc_id,target.ip,target.port).filter(|s| s.ip() == std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
                    let Some(endpoint) = endpoint.filter(|_| network.allows_target_route(&account,&region,&vpc_id,&source_subnets,target.ip) && network.allows_target_connection(&connection)) else {
                        let _ = client.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                        return;
                    };
                    let Ok(Ok(mut backend)) = timeout(Duration::from_secs(2), network.connect_target(&connection,endpoint)).await else {
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
    let Ok(Ok(stream)) = timeout(PROBE_TIMEOUT, TcpStream::connect(endpoint)).await else {
        return ProbeHealth::FailedHealthChecks;
    };
    probe_stream_with_timeout(stream, &HealthSettings::default(), PROBE_TIMEOUT).await
}

async fn probe_stream(stream: TcpStream, settings: &HealthSettings) -> ProbeHealth {
    probe_stream_with_timeout(stream, settings, Duration::from_secs(settings.timeout)).await
}

async fn probe_stream_with_timeout(
    mut stream: TcpStream,
    settings: &HealthSettings,
    limit: Duration,
) -> ProbeHealth {
    let check = async {
        stream
            .write_all(
                format!(
                    "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    settings.path
                )
                .as_bytes(),
            )
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
            Some(code)
                if settings
                    .codes
                    .iter()
                    .any(|(low, high)| (*low..=*high).contains(&code)) =>
            {
                ProbeHealth::Healthy
            }
            Some(100..=599) => ProbeHealth::ResponseCodeMismatch,
            _ => ProbeHealth::FailedHealthChecks,
        })
    };
    match timeout(limit, check).await {
        Ok(Ok(health)) => health,
        Ok(Err(_)) => ProbeHealth::FailedHealthChecks,
        Err(_) => ProbeHealth::Timeout,
    }
}

#[derive(Clone)]
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

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
    #[async_trait]
    impl AlbNetworkPreflight for TestAlbNetwork {
        fn allows_target_connection(&self, _: &AlbTargetConnection<'_>) -> bool {
            true
        }
        async fn connect_target(
            &self,
            _: &AlbTargetConnection<'_>,
            endpoint: SocketAddr,
        ) -> std::io::Result<TcpStream> {
            TcpStream::connect(endpoint).await
        }

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
                network_id: "test-alb".into(),
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
            for _ in 0..2 {
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
        let health_query =
            format!("Action=DescribeTargetHealth&Version=2015-12-01&TargetGroupArn={tg_arn}");
        timeout(Duration::from_secs(3), async {
            loop {
                let (_, health) = run(&handler, &health_query, "111111111111", "us-east-1").await;
                if health.contains("<State>healthy</State>") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
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
    #[test]
    fn health_settings_and_thresholds_are_actual_state_not_describe_probes() {
        let query = Query::parse(b"HealthCheckPath=%2Fready&HealthCheckIntervalSeconds=5&HealthCheckTimeoutSeconds=2&HealthyThresholdCount=3&UnhealthyThresholdCount=2&Matcher.HttpCode=200-204%2C301").unwrap_or_else(|_|panic!("settings"));
        let settings = HealthSettings::parse(&query).unwrap_or_else(|_| panic!("settings"));
        assert_eq!(settings.path, "/ready");
        let mut target = RegisteredTarget::new(
            "10.0.0.1".parse().unwrap(),
            80,
            "127.0.0.1:10".parse().unwrap(),
        );
        target.observe(ProbeHealth::Healthy, &settings);
        assert_eq!(target.health, HealthState::Healthy);
        target.observe(ProbeHealth::ResponseCodeMismatch, &settings);
        assert_eq!(target.health, HealthState::Healthy);
        target.observe(ProbeHealth::Timeout, &settings);
        assert_eq!(target.health, HealthState::Unhealthy(ProbeHealth::Timeout));
        for _ in 0..2 {
            target.observe(ProbeHealth::Healthy, &settings);
        }
        assert_eq!(target.health, HealthState::Unhealthy(ProbeHealth::Timeout));
        target.observe(ProbeHealth::Healthy, &settings);
        assert_eq!(target.health, HealthState::Healthy);
        for input in [
            "HealthCheckPath=%2Fready%0D%0AX-Foo%3Abad",
            "HealthCheckIntervalSeconds=4",
            "HealthCheckTimeoutSeconds=1",
            "Matcher.HttpCode=500",
            "Matcher.HttpCode=204-200",
            "Matcher.HttpCode=200-201-202",
            "HealthyThresholdCount=11",
            "HealthCheckProtocol=HTTPS",
        ] {
            assert!(
                HealthSettings::parse(
                    &Query::parse(input.as_bytes()).unwrap_or_else(|_| panic!("query"))
                )
                .is_err(),
                "{input}"
            );
        }
    }

    #[tokio::test]
    async fn configured_probe_path_and_matcher_use_real_http_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0u8; 512];
            let n = stream.read(&mut bytes).await.unwrap();
            assert!(bytes[..n].starts_with(b"GET /ready HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let settings = HealthSettings {
            path: "/ready".into(),
            codes: vec![(200, 204)],
            ..HealthSettings::default()
        };
        assert_eq!(
            probe_stream(TcpStream::connect(addr).await.unwrap(), &settings).await,
            ProbeHealth::Healthy
        );
        task.await.unwrap();
    }
    #[test]
    fn routing_distinguishes_empty_initial_healthy_unhealthy_and_draining() {
        let mut first = RegisteredTarget::new(
            "10.0.0.1".parse().unwrap(),
            80,
            "127.0.0.1:10".parse().unwrap(),
        );
        let mut second = RegisteredTarget::new(
            "10.0.0.2".parse().unwrap(),
            80,
            "127.0.0.1:11".parse().unwrap(),
        );
        assert!(routing_targets(Vec::new()).is_empty());
        assert!(routing_targets(vec![first.clone(), second.clone()]).is_empty());
        first.health = HealthState::Healthy;
        second.health = HealthState::Unhealthy(ProbeHealth::ResponseCodeMismatch);
        let selected = routing_targets(vec![first.clone(), second.clone()]);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].ip, first.ip);
        first.health = HealthState::Unhealthy(ProbeHealth::FailedHealthChecks);
        assert_eq!(
            routing_targets(vec![first.clone(), second.clone()]).len(),
            2
        );
        first.draining_until = Some(Instant::now() + Duration::from_secs(300));
        let selected = routing_targets(vec![first, second.clone()]);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].ip, second.ip);
        second.draining_until = Some(Instant::now() + Duration::from_secs(300));
        assert!(routing_targets(vec![second]).is_empty());
    }
    struct LiveResolver(Mutex<Option<SocketAddr>>);
    impl TargetEndpointResolver for LiveResolver {
        fn resolve(&self, _: &str, _: &str, _: &str, _: Ipv4Addr, _: u16) -> Option<SocketAddr> {
            *self.0.lock().ok()?
        }
    }

    #[tokio::test]
    async fn periodic_health_recovers_without_reads_and_stale_endpoint_cannot_fail_open() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let status = Arc::new(AtomicUsize::new(200));
        let calls = Arc::new(AtomicUsize::new(0));
        let backend_task = {
            let status = status.clone();
            let calls = calls.clone();
            tokio::spawn(async move {
                loop {
                    let (mut stream, _) = backend.accept().await.unwrap();
                    let mut bytes = [0u8; 1024];
                    let n = stream.read(&mut bytes).await.unwrap();
                    assert!(n > 0);
                    calls.fetch_add(1, Ordering::SeqCst);
                    let response = format!(
                        "HTTP/1.1 {} Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        status.load(Ordering::SeqCst)
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            })
        };
        let resolver = Arc::new(LiveResolver(Mutex::new(Some(backend_addr))));
        let handler =
            Elbv2Handler::with_integrations(Arc::new(TestVpc::default()), resolver.clone());
        assert_eq!(
            run(&handler, CREATE, "111111111111", "us-east-1").await.0,
            200
        );
        let scope = ("111111111111".to_owned(), "us-east-1".to_owned());
        let arn = {
            let mut state = handler.groups.lock().unwrap();
            let group = state.get_mut(&scope).unwrap().get_mut("web").unwrap();
            group.associated_lb = Some("test-alb".into());
            // Shorten only the in-process test clock; the API still enforces AWS's five-second minimum.
            group.health.interval = 1;
            group.health.timeout = 2;
            group.health.healthy = 2;
            group.targets.insert(
                ("10.0.0.10".parse().unwrap(), 8080),
                RegisteredTarget::new("10.0.0.10".parse().unwrap(), 8080, backend_addr),
            );
            group.arn.clone()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = listener.local_addr().unwrap();
        let listener_task = tokio::spawn(run_listener(
            listener,
            ListenerContext {
                groups: handler.groups.clone(),
                network: Arc::new(TestAlbNetwork),
                resolver: resolver.clone(),
                account: scope.0.clone(),
                region: scope.1.clone(),
                group_ids: vec!["sg-1".into()],
                vpc_id: "vpc-12345678".into(),
                source_subnets: vec!["subnet-a".into(), "subnet-b".into()],
                network_id: "test-alb".into(),
                ready: Arc::new(AtomicBool::new(true)),
                target_group_arn: arn.clone(),
                port: socket.port(),
            },
        ));
        async fn wait_health(handler: &Elbv2Handler, expected: HealthState) {
            timeout(Duration::from_secs(5), async {
                loop {
                    let health = handler
                        .groups
                        .lock()
                        .unwrap()
                        .values()
                        .next()
                        .unwrap()
                        .values()
                        .next()
                        .unwrap()
                        .targets
                        .values()
                        .next()
                        .unwrap()
                        .health;
                    if health == expected {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
        wait_health(&handler, HealthState::Healthy).await;
        {
            let mut state = handler.groups.lock().unwrap();
            state
                .get_mut(&scope)
                .unwrap()
                .values_mut()
                .next()
                .unwrap()
                .targets
                .values_mut()
                .next()
                .unwrap()
                .next_probe = Instant::now() + Duration::from_secs(60);
        }
        let before = calls.load(Ordering::SeqCst);
        for _ in 0..20 {
            let query =
                format!("Action=DescribeTargetHealth&Version=2015-12-01&TargetGroupArn={arn}");
            assert!(run(&handler, &query, "111111111111", "us-east-1")
                .await
                .1
                .contains("<State>healthy</State>"));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before,
            "Describe must not probe"
        );
        {
            let mut state = handler.groups.lock().unwrap();
            state
                .get_mut(&scope)
                .unwrap()
                .values_mut()
                .next()
                .unwrap()
                .targets
                .values_mut()
                .next()
                .unwrap()
                .next_probe = Instant::now();
        }
        status.store(500, Ordering::SeqCst);
        wait_health(
            &handler,
            HealthState::Unhealthy(ProbeHealth::ResponseCodeMismatch),
        )
        .await;
        async fn request(socket: SocketAddr) -> Vec<u8> {
            let mut stream = TcpStream::connect(socket).await.unwrap();
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut bytes = Vec::new();
            timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            bytes
        }
        assert!(
            request(socket).await.starts_with(b"HTTP/1.1 500"),
            "all-unhealthy must fail open to the backend"
        );
        *resolver.0.lock().unwrap() = None;
        assert!(
            request(socket).await.starts_with(b"HTTP/1.1 503"),
            "stale owned socket must never be reused"
        );
        *resolver.0.lock().unwrap() = Some(backend_addr);
        status.store(200, Ordering::SeqCst);
        wait_health(&handler, HealthState::Healthy).await;
        listener_task.abort();
        let _ = listener_task.await;
        assert!(TcpStream::connect(socket).await.is_err());
        backend_task.abort();
        let _ = backend_task.await;
    }
    async fn persistent_handler(
        db: Arc<locallycloud_state::StateDb>,
        key: u8,
    ) -> Result<Arc<Elbv2Handler>, PersistError> {
        tokio::task::spawn_blocking(move || {
            let handler = Elbv2Handler::with_alb_integrations(
                Arc::new(TestVpc::default()),
                Arc::new(TestResolver("127.0.0.1:9".parse().unwrap())),
                Arc::new(TestAlbNetwork),
                Arc::new(LoopbackAlbEndpointAllocator::default()),
            );
            handler.ready.store(false, Ordering::Release);
            let persistence = Arc::new(Persistence::new(
                db,
                locallycloud_state::StateCipher::with_key(&[key; 32]),
            )?);
            persistence.restore(&handler)?;
            let mut restored = (*handler).clone();
            restored.persistence = Some(persistence);
            restored.ready.store(true, Ordering::Release);
            Ok(Arc::new(restored))
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn encrypted_graph_restart_and_failed_persistence_preserve_live_state() {
        let (db, directory) = tokio::task::spawn_blocking(|| {
            let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target")
                .canonicalize()
                .unwrap()
                .join(format!("alb-state-{}", Uuid::new_v4().simple()));
            let db = locallycloud_state::StateDb::open(directory.join("state.sqlite3")).unwrap();
            (Arc::new(db), directory)
        })
        .await
        .unwrap();
        let handler = persistent_handler(db.clone(), 7).await.unwrap();
        let (_, created) = run(&handler, CREATE, "111111111111", "us-east-1").await;
        let group_arn = created
            .split("<TargetGroupArn>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned();
        let create_lb = "Action=CreateLoadBalancer&Version=2015-12-01&Name=my-alb&Type=application&Scheme=internal&IpAddressType=ipv4&Subnets.member.1=subnet-a&Subnets.member.2=subnet-b&SecurityGroups.member.1=sg-1";
        let (_, created) = run(&handler, create_lb, "111111111111", "us-east-1").await;
        let lb_arn = created
            .split("<LoadBalancerArn>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned();
        let free = std::net::TcpListener::bind("127.1.1.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let listener_query = format!("Action=CreateListener&Version=2015-12-01&LoadBalancerArn={lb_arn}&Protocol=HTTP&Port={port}&DefaultActions.member.1.Type=forward&DefaultActions.member.1.TargetGroupArn={group_arn}");
        let (code, listener) = run(&handler, &listener_query, "111111111111", "us-east-1").await;
        assert_eq!(code, 200, "{listener}");
        let listener_arn = listener
            .split("<ListenerArn>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned();
        let register = format!("Action=RegisterTargets&Version=2015-12-01&TargetGroupArn={group_arn}&Targets.member.1.Id=10.0.0.10");
        assert_eq!(
            run(&handler, &register, "111111111111", "us-east-1")
                .await
                .0,
            200
        );
        let db_copy = db.clone();
        tokio::task::spawn_blocking(move || {
            let conn = db_copy.connection().unwrap();
            conn.execute_batch("CREATE TRIGGER reject_alb_update BEFORE UPDATE ON elbv2_resources BEGIN SELECT RAISE(FAIL,'test failure'); END; CREATE TRIGGER reject_alb_delete BEFORE DELETE ON elbv2_resources BEGIN SELECT RAISE(FAIL,'test failure'); END;").unwrap();
            let bytes:Vec<u8> = conn.query_row("SELECT payload FROM elbv2_resources WHERE kind='group'",[],|row|row.get(0)).unwrap();
            assert!(!bytes.windows(b"vpc-12345678".len()).any(|w|w == b"vpc-12345678"));
        }).await.unwrap();
        assert_eq!(
            run(&handler, &register, "111111111111", "us-east-1")
                .await
                .0,
            200,
            "idempotent registrations must neither rewrite state nor reset health"
        );
        let free = std::net::TcpListener::bind("127.1.1.1:0").unwrap();
        let rejected_port = free.local_addr().unwrap().port();
        drop(free);
        let rejected_listener =
            listener_query.replace(&format!("Port={port}&"), &format!("Port={rejected_port}&"));
        assert_eq!(
            run(&handler, &rejected_listener, "111111111111", "us-east-1")
                .await
                .0,
            500
        );
        assert!(
            std::net::TcpListener::bind((Ipv4Addr::new(127, 1, 1, 1), rejected_port)).is_ok(),
            "failed listener publication must release its socket"
        );
        let attrs = format!("Action=ModifyTargetGroupAttributes&Version=2015-12-01&TargetGroupArn={group_arn}&Attributes.member.1.Key=deregistration_delay.timeout_seconds&Attributes.member.1.Value=1");
        assert_eq!(
            run(&handler, &attrs, "111111111111", "us-east-1").await.0,
            500
        );
        let deregister = register.replace("Action=RegisterTargets", "Action=DeregisterTargets");
        assert_eq!(
            run(&handler, &deregister, "111111111111", "us-east-1")
                .await
                .0,
            500
        );
        let delete_lb =
            format!("Action=DeleteLoadBalancer&Version=2015-12-01&LoadBalancerArn={lb_arn}");
        assert_eq!(
            run(&handler, &delete_lb, "111111111111", "us-east-1")
                .await
                .0,
            500
        );
        {
            let state = handler.groups.lock().unwrap();
            let group = state.values().next().unwrap().values().next().unwrap();
            assert_eq!(group.deregistration_delay, 300);
            assert!(group
                .targets
                .values()
                .next()
                .unwrap()
                .draining_until
                .is_none());
        }
        assert!(TcpStream::connect((Ipv4Addr::new(127, 1, 1, 1), port))
            .await
            .is_ok());
        drop(handler);
        timeout(Duration::from_secs(2), async {
            while TcpStream::connect((Ipv4Addr::new(127, 1, 1, 1), port))
                .await
                .is_ok()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            persistent_handler(db.clone(), 8).await.is_err(),
            "wrong key must fail startup"
        );
        let restored = persistent_handler(db.clone(), 7).await.unwrap();
        let query =
            format!("Action=DescribeTargetHealth&Version=2015-12-01&TargetGroupArn={group_arn}");
        assert!(run(&restored, &query, "111111111111", "us-east-1")
            .await
            .1
            .contains("Target.NotRegistered"));
        let listeners =
            format!("Action=DescribeListeners&Version=2015-12-01&LoadBalancerArn={lb_arn}");
        assert!(run(&restored, &listeners, "111111111111", "us-east-1")
            .await
            .1
            .contains(&listener_arn));
        let db_copy = db.clone();
        tokio::task::spawn_blocking(move || {
            db_copy
                .connection()
                .unwrap()
                .execute_batch("DROP TRIGGER reject_alb_update; DROP TRIGGER reject_alb_delete;")
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            run(&restored, &register, "111111111111", "us-east-1")
                .await
                .0,
            200
        );
        assert!(!run(&restored, &query, "111111111111", "us-east-1")
            .await
            .1
            .contains("Target.NotRegistered"));
        assert_eq!(
            run(&restored, &delete_lb, "111111111111", "us-east-1")
                .await
                .0,
            200
        );
        let delete_group =
            format!("Action=DeleteTargetGroup&Version=2015-12-01&TargetGroupArn={group_arn}");
        assert_eq!(
            run(&restored, &delete_group, "111111111111", "us-east-1")
                .await
                .0,
            200
        );
        drop(restored);
        let restored = persistent_handler(db, 7).await.unwrap();
        assert!(restored
            .groups
            .lock()
            .unwrap()
            .values()
            .all(|groups| groups.is_empty()));
        assert!(restored
            .albs
            .lock()
            .unwrap()
            .load_balancers
            .values()
            .all(|albs| albs.is_empty()));
        drop(restored);
        tokio::task::spawn_blocking(move || std::fs::remove_dir_all(directory))
            .await
            .unwrap()
            .unwrap();
    }
    fn form_encoded(text: &str) -> String {
        text.bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                    (byte as char).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect()
    }
    fn operator_policy(store: &locallycloud_iam_sts::store::IamStore, document: serde_json::Value) {
        let query = locallycloud_iam_sts::query::QueryRequest::parse(
            format!(
                "UserName=operator&PolicyName=policy&PolicyDocument={}",
                form_encoded(&document.to_string())
            )
            .as_bytes(),
        );
        locallycloud_iam_sts::iam::put_inline_policy(
            store,
            "111111111111",
            locallycloud_iam_sts::iam::Entity::User,
            &query,
        )
        .unwrap();
    }
    async fn operator_call(
        handler: &Elbv2Handler,
        body: &str,
        key: &str,
        delegate: Option<(&str, bool)>,
    ) -> (u16, String) {
        let mut req = request(body, "111111111111", "us-east-1");
        req.headers.insert("authorization",format!("AWS4-HMAC-SHA256 Credential={key}/20261019/us-east-1/elasticloadbalancing/aws4_request, SignedHeaders=host, Signature=not-a-transport-signature").parse().unwrap());
        req.headers.insert(
            "x-locallycloud-verified-external-sigv4",
            http::HeaderValue::from_static("1"),
        );
        if let Some((role, trusted)) = delegate {
            req.headers.insert(
                "x-locallycloud-caller-principal",
                format!("{role}/session").parse().unwrap(),
            );
            if trusted {
                req.headers.insert(
                    "x-locallycloud-verified-internal-scope",
                    http::HeaderValue::from_static("1"),
                );
            }
        }
        let response = handler.handle(req).await;
        let code = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        (code, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn strict_operator_authorization_precedes_allocation_and_preserves_attested_roles() {
        use locallycloud_iam_sts::{iam, query::QueryRequest};
        use serde_json::json;
        let registry = Arc::new(ServiceRegistry::new());
        let store = Arc::new(locallycloud_iam_sts::store::IamStore::new());
        iam::create_user(
            &store,
            "111111111111",
            &QueryRequest::parse(b"UserName=operator"),
        )
        .unwrap();
        let access = iam::create_access_key(
            &store,
            "111111111111",
            &QueryRequest::parse(b"UserName=operator"),
        )
        .unwrap();
        let key = access
            .split("<AccessKeyId>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned();
        locallycloud_iam_sts::register_with_store_and_mode(
            &registry,
            store.clone(),
            Arc::new(locallycloud_iam_sts::sts::SessionStore::new()),
            locallycloud_iam_sts::enforcement::EnforcementMode::Strict,
        );
        let vpc = Arc::new(TestVpc::default());
        let allocator = Arc::new(LoopbackAlbEndpointAllocator::default());
        let handler = register_with_alb_integrations(
            &registry,
            vpc.clone(),
            Arc::new(TestResolver("127.0.0.1:9".parse().unwrap())),
            Arc::new(TestAlbNetwork),
            allocator.clone(),
        );
        operator_policy(
            &store,
            json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"elasticloadbalancing:*","Resource":"*"},{"Effect":"Deny","Action":["elasticloadbalancing:CreateTargetGroup","elasticloadbalancing:CreateLoadBalancer"],"Resource":"*"}]}),
        );
        let create_lb="Action=CreateLoadBalancer&Version=2015-12-01&Name=my-alb&Type=application&Scheme=internal&Subnets.member.1=subnet-a&Subnets.member.2=subnet-b&SecurityGroups.member.1=sg-1";
        assert_eq!(operator_call(&handler, CREATE, &key, None).await.0, 403);
        assert_eq!(operator_call(&handler, create_lb, &key, None).await.0, 403);
        assert_eq!(vpc.active.load(Ordering::SeqCst), 0);
        assert!(allocator.used.lock().unwrap().is_empty());
        assert!(handler.groups.lock().unwrap().is_empty());
        operator_policy(
            &store,
            json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"elasticloadbalancing:CreateTargetGroup","Resource":"arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/web/*"},{"Effect":"Allow","Action":"elasticloadbalancing:CreateLoadBalancer","Resource":"arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/my-alb/*","Condition":{"StringEquals":{"elasticloadbalancing:Scheme":"internal","elasticloadbalancing:SecurityGroup":"sg-1"}}}]}),
        );
        let (code, group) = operator_call(&handler, CREATE, &key, None).await;
        assert_eq!(code, 200, "{group}");
        let group_arn = group
            .split("<TargetGroupArn>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(
            operator_call(
                &handler,
                &CREATE.replace("Name=web", "Name=other"),
                &key,
                None
            )
            .await
            .0,
            403
        );
        assert_eq!(vpc.active.load(Ordering::SeqCst), 1);
        let (code, alb) = operator_call(&handler, create_lb, &key, None).await;
        assert_eq!(code, 200, "{alb}");
        let alb_arn = alb
            .split("<LoadBalancerArn>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(
            operator_call(
                &handler,
                &create_lb.replace("Name=my-alb", "Name=other"),
                &key,
                None
            )
            .await
            .0,
            403
        );
        assert_eq!(allocator.used.lock().unwrap().len(), 1);
        let free = std::net::TcpListener::bind("127.1.1.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let listener_query=format!("Action=CreateListener&Version=2015-12-01&LoadBalancerArn={alb_arn}&Protocol=HTTP&Port={port}&DefaultActions.member.1.Type=forward&DefaultActions.member.1.TargetGroupArn={group_arn}");
        assert_eq!(
            operator_call(&handler, &listener_query, &key, None).await.0,
            403
        );
        assert!(std::net::TcpListener::bind((Ipv4Addr::new(127, 1, 1, 1), port)).is_ok());
        operator_policy(
            &store,
            json!({"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"elasticloadbalancing:CreateListener","Resource":alb_arn}}),
        );
        let (code, listener) = operator_call(&handler, &listener_query, &key, None).await;
        assert_eq!(code, 200, "{listener}");
        let listener_arn = listener
            .split("<ListenerArn>")
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .to_owned();
        operator_policy(
            &store,
            json!({"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"elasticloadbalancing:Describe*","Resource":"*"}}),
        );
        let register=format!("Action=RegisterTargets&Version=2015-12-01&TargetGroupArn={group_arn}&Targets.member.1.Id=10.0.0.10");
        assert_eq!(operator_call(&handler, &register, &key, None).await.0, 403);
        let delete_lb =
            format!("Action=DeleteLoadBalancer&Version=2015-12-01&LoadBalancerArn={alb_arn}");
        let delete_listener =
            format!("Action=DeleteListener&Version=2015-12-01&ListenerArn={listener_arn}");
        assert_eq!(operator_call(&handler, &delete_lb, &key, None).await.0, 403);
        assert_eq!(
            operator_call(&handler, &delete_listener, &key, None)
                .await
                .0,
            403
        );
        assert!(std::net::TcpListener::bind((Ipv4Addr::new(127, 1, 1, 1), port)).is_err());
        assert!(handler
            .groups
            .lock()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .targets
            .is_empty());
        let health =
            format!("Action=DescribeTargetHealth&Version=2015-12-01&TargetGroupArn={group_arn}");
        assert_eq!(operator_call(&handler, &health, &key, None).await.0, 200);
        let role = "arn:aws:iam::111111111111:role/service";
        iam::create_role(&store,"111111111111",&QueryRequest::parse(format!("RoleName=service&AssumeRolePolicyDocument={}",form_encoded(r#"{"Statement":{"Effect":"Allow","Principal":{"Service":"ecs.amazonaws.com"},"Action":"sts:AssumeRole"}}"#)).as_bytes())).unwrap();
        let role_policy = json!({"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"elasticloadbalancing:RegisterTargets","Resource":group_arn}});
        iam::put_inline_policy(
            &store,
            "111111111111",
            iam::Entity::Role,
            &QueryRequest::parse(
                format!(
                    "RoleName=service&PolicyName=targets&PolicyDocument={}",
                    form_encoded(&role_policy.to_string())
                )
                .as_bytes(),
            ),
        )
        .unwrap();
        assert_eq!(
            operator_call(&handler, &register, &key, Some((role, false)))
                .await
                .0,
            403,
            "unattested public principal must not grant permissions"
        );
        assert_eq!(
            operator_call(&handler, &register, &key, Some((role, true)))
                .await
                .0,
            200,
            "attested service role must use its own scoped policy"
        );
        operator_policy(
            &store,
            json!({"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"elasticloadbalancing:*","Resource":"*"}}),
        );
        assert_eq!(operator_call(&handler, &delete_lb, &key, None).await.0, 200);
        let delete_group =
            format!("Action=DeleteTargetGroup&Version=2015-12-01&TargetGroupArn={group_arn}");
        assert_eq!(
            operator_call(&handler, &delete_group, &key, None).await.0,
            200
        );
    }
}
