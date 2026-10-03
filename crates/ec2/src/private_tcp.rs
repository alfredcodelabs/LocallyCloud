use super::*;

impl ScopeState {
    pub(super) fn resolve_target(
        &self,
        vpc_id: &str,
        private_ip: Ipv4Addr,
        port: u16,
    ) -> Option<SocketAddr> {
        self.instances
            .values()
            .find(|instance| {
                instance.state == InstanceState::Running
                    && instance.spec.vpc_id == vpc_id
                    && instance.spec.private_ip == private_ip
                    && instance.spec.guest_port == port
            })
            .and_then(|instance| instance.endpoint)
            .or_else(|| {
                let (task_id, endpoint) = self.task_endpoints.get(&(private_ip, port))?;
                self.network_interfaces
                    .values()
                    .any(|eni| {
                        eni.vpc_id == vpc_id
                            && eni.private_ip == private_ip
                            && self.task_networks.get(&eni.id) == Some(task_id)
                    })
                    .then_some(*endpoint)
            })
    }

    fn groups_allow_tcp(
        &self,
        group_ids: &[String],
        peer: Ipv4Addr,
        port: u16,
        egress: bool,
        vpc_id: &str,
    ) -> bool {
        !group_ids.is_empty()
            && group_ids.iter().all(|id| {
                self.security_groups
                    .get(id)
                    .is_some_and(|group| group.vpc_id == vpc_id)
            })
            && group_ids.iter().any(|id| {
                let group = &self.security_groups[id];
                let rules = if egress {
                    &group.egress
                } else {
                    &group.ingress
                };
                rules.iter().any(|rule| {
                    rule.cidr.contains(&peer)
                        && (rule.protocol == "-1"
                            || (rule.protocol == "tcp"
                                && rule.from_port.is_some_and(|from| from <= port)
                                && rule.to_port.is_some_and(|to| port <= to)))
                })
            })
    }

    fn direct_route(&self, source: &NetworkInterface, target: &NetworkInterface) -> bool {
        let table = self
            .route_tables
            .values()
            .find(|table| {
                table.vpc_id == source.vpc_id
                    && table
                        .associations
                        .values()
                        .any(|id| id.as_deref() == Some(&source.subnet_id))
            })
            .or_else(|| {
                self.route_tables
                    .values()
                    .find(|table| table.vpc_id == source.vpc_id && table.main)
            });
        table
            .and_then(|table| {
                table
                    .routes
                    .iter()
                    .filter(|(cidr, _)| cidr.contains(&target.private_ip))
                    .max_by_key(|(cidr, _)| cidr.prefix_len())
            })
            .is_some_and(|(_, next_hop)| {
                matches!(next_hop, RouteTarget::Local) || matches!(next_hop, RouteTarget::NetworkInterface(eni_id) if eni_id == &target.id)
            })
    }

    fn private_tcp_access(
        &self,
        source_eni_id: &str,
        target_ip: Ipv4Addr,
        port: u16,
    ) -> Option<SocketAddr> {
        let source = self.network_interfaces.get(source_eni_id)?;
        let target = self
            .network_interfaces
            .values()
            .find(|eni| eni.vpc_id == source.vpc_id && eni.private_ip == target_ip)?;
        if !self.direct_route(source, target)
            || !self.groups_allow_tcp(
                &source.group_ids,
                target.private_ip,
                port,
                true,
                &source.vpc_id,
            )
            || !self.groups_allow_tcp(
                &target.group_ids,
                source.private_ip,
                port,
                false,
                &target.vpc_id,
            )
        {
            return None;
        }
        self.resolve_target(&source.vpc_id, target_ip, port)
    }
}

impl Ec2Handler {
    /// Resolve an active private TCP listener only when both ENIs share a VPC,
    /// the source subnet routes directly to the destination, and both current
    /// security-group policies allow the flow. A missing listener fails closed.
    pub fn private_tcp_access(
        &self,
        account: &str,
        region: &str,
        source_eni_id: &str,
        target_ip: Ipv4Addr,
        port: u16,
    ) -> Option<SocketAddr> {
        let state = self.scopes.lock().ok()?;
        let scope = state.get(&(account.to_owned(), region.to_owned()))?;
        scope.private_tcp_access(source_eni_id, target_ip, port)
    }

    /// Active listeners in the source VPC, including those currently denied by policy.
    /// Call `private_tcp_access` again before forwarding each connection.
    pub fn private_tcp_destinations(
        &self,
        account: &str,
        region: &str,
        source_eni_id: &str,
    ) -> Vec<(Ipv4Addr, u16)> {
        let Ok(state) = self.scopes.lock() else {
            return Vec::new();
        };
        let Some(scope) = state.get(&(account.to_owned(), region.to_owned())) else {
            return Vec::new();
        };
        let Some(source) = scope.network_interfaces.get(source_eni_id) else {
            return Vec::new();
        };
        let candidates = scope
            .instances
            .values()
            .filter(|instance| {
                instance.state == InstanceState::Running && instance.endpoint.is_some()
            })
            .map(|instance| (instance.spec.private_ip, instance.spec.guest_port))
            .chain(scope.task_endpoints.keys().copied());
        candidates
            .filter(|(ip, port)| scope.resolve_target(&source.vpc_id, *ip, *port).is_some())
            .collect()
    }
    /// DNS records for active managed services in the source ENI's VPC.
    pub fn private_tcp_dns(
        &self,
        account: &str,
        region: &str,
        source_eni_id: &str,
    ) -> Vec<(String, Ipv4Addr)> {
        let Ok(state) = self.scopes.lock() else {
            return Vec::new();
        };
        let Some(scope) = state.get(&(account.to_owned(), region.to_owned())) else {
            return Vec::new();
        };
        let Some(source) = scope.network_interfaces.get(source_eni_id) else {
            return Vec::new();
        };
        scope
            .task_dns
            .iter()
            .filter_map(|(eni_id, name)| {
                let eni = scope.network_interfaces.get(eni_id)?;
                (eni.vpc_id == source.vpc_id
                    && scope
                        .task_endpoints
                        .keys()
                        .any(|(ip, _)| *ip == eni.private_ip)
                    && scope.task_networks.contains_key(eni_id))
                .then(|| (name.clone(), eni.private_ip))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_tcp_requires_direct_route_and_both_security_groups() {
        let handler = Ec2Handler::default();
        let source_ip: Ipv4Addr = "10.7.1.4".parse().unwrap();
        let target_ip: Ipv4Addr = "10.7.2.4".parse().unwrap();
        let endpoint: SocketAddr = "127.0.0.1:15432".parse().unwrap();
        let all: Ipv4Net = "0.0.0.0/0".parse().unwrap();
        let vpc_cidr: Ipv4Net = "10.7.0.0/16".parse().unwrap();
        let mut scope = ScopeState::default();
        for (id, subnet, ip, group) in [
            ("eni-source", "subnet-source", source_ip, "sg-source"),
            ("eni-target", "subnet-target", target_ip, "sg-target"),
        ] {
            scope.network_interfaces.insert(
                id.into(),
                NetworkInterface {
                    id: id.into(),
                    subnet_id: subnet.into(),
                    vpc_id: "vpc-one".into(),
                    zone: "us-east-1a".into(),
                    private_ip: ip,
                    description: String::new(),
                    owner: "111".into(),
                    group_ids: vec![group.into()],
                },
            );
        }
        for id in ["sg-source", "sg-target"] {
            scope.security_groups.insert(
                id.into(),
                SecurityGroup {
                    id: id.into(),
                    vpc_id: "vpc-one".into(),
                    name: id.into(),
                    description: String::new(),
                    owner: "111".into(),
                    is_default: false,
                    ingress: Vec::new(),
                    egress: default_egress(),
                    guard: Arc::new(()),
                },
            );
        }
        scope.route_tables.insert(
            "rtb-main".into(),
            RouteTable {
                id: "rtb-main".into(),
                vpc_id: "vpc-one".into(),
                owner: "111".into(),
                main: true,
                routes: BTreeMap::from([(vpc_cidr, RouteTarget::Local)]),
                endpoint_routes: BTreeMap::new(),
                associations: BTreeMap::new(),
            },
        );
        scope
            .task_networks
            .insert("eni-target".into(), "rds".into());
        scope
            .task_endpoints
            .insert((target_ip, 5432), ("rds".into(), endpoint));
        handler
            .scopes
            .lock()
            .unwrap()
            .insert(("111".into(), "us-east-1".into()), scope);
        let access =
            || handler.private_tcp_access("111", "us-east-1", "eni-source", target_ip, 5432);
        assert_eq!(access(), None);
        assert_eq!(
            handler.private_tcp_destinations("111", "us-east-1", "eni-source"),
            vec![(target_ip, 5432)]
        );
        {
            let mut state = handler.scopes.lock().unwrap();
            let scope = state.get_mut(&("111".into(), "us-east-1".into())).unwrap();
            scope
                .security_groups
                .get_mut("sg-target")
                .unwrap()
                .ingress
                .push(IngressRule {
                    protocol: "tcp".into(),
                    from_port: Some(5432),
                    to_port: Some(5432),
                    cidr: "10.7.1.0/24".parse().unwrap(),
                });
        }
        assert_eq!(access(), Some(endpoint));
        assert_eq!(
            handler.private_tcp_access("222", "us-east-1", "eni-source", target_ip, 5432),
            None
        );
        assert_eq!(
            handler.private_tcp_access("111", "us-west-2", "eni-source", target_ip, 5432),
            None
        );
        assert_eq!(
            handler.private_tcp_access("111", "us-east-1", "eni-source", target_ip, 5433),
            None
        );
        {
            let mut state = handler.scopes.lock().unwrap();
            let scope = state.get_mut(&("111".into(), "us-east-1".into())).unwrap();
            scope
                .security_groups
                .get_mut("sg-source")
                .unwrap()
                .egress
                .clear();
        }
        assert_eq!(access(), None);
        {
            let mut state = handler.scopes.lock().unwrap();
            let scope = state.get_mut(&("111".into(), "us-east-1".into())).unwrap();
            scope
                .security_groups
                .get_mut("sg-source")
                .unwrap()
                .egress
                .push(IngressRule {
                    protocol: "tcp".into(),
                    from_port: Some(5432),
                    to_port: Some(5432),
                    cidr: all,
                });
            scope
                .route_tables
                .get_mut("rtb-main")
                .unwrap()
                .routes
                .insert(
                    "10.7.2.4/32".parse().unwrap(),
                    RouteTarget::NetworkInterface("eni-appliance".into()),
                );
        }
        assert_eq!(access(), None);
        {
            let mut state = handler.scopes.lock().unwrap();
            let scope = state.get_mut(&("111".into(), "us-east-1".into())).unwrap();
            scope
                .route_tables
                .get_mut("rtb-main")
                .unwrap()
                .routes
                .insert(
                    "10.7.2.4/32".parse().unwrap(),
                    RouteTarget::NetworkInterface("eni-target".into()),
                );
        }
        assert_eq!(access(), Some(endpoint));
        {
            let mut state = handler.scopes.lock().unwrap();
            let scope = state.get_mut(&("111".into(), "us-east-1".into())).unwrap();
            scope
                .network_interfaces
                .get_mut("eni-target")
                .unwrap()
                .vpc_id = "vpc-two".into();
        }
        assert_eq!(access(), None);
    }

    #[test]
    fn private_dns_follows_service_lease() {
        let handler = Ec2Handler::default();
        let mut scope = ScopeState::default();
        let vpc = Arc::new(Vpc {
            id: "vpc-one".into(),
            cidr: "10.7.0.0/16".parse().unwrap(),
            owner: "111".into(),
        });
        scope.vpcs.insert(vpc.id.clone(), vpc);
        scope.subnets.insert(
            "subnet-one".into(),
            Subnet {
                id: "subnet-one".into(),
                vpc_id: "vpc-one".into(),
                cidr: "10.7.1.0/24".parse().unwrap(),
                zone: "us-east-1a".into(),
                owner: "111".into(),
                guard: Arc::new(()),
            },
        );
        scope.security_groups.insert(
            "sg-one".into(),
            SecurityGroup {
                id: "sg-one".into(),
                vpc_id: "vpc-one".into(),
                name: "app".into(),
                description: String::new(),
                owner: "111".into(),
                is_default: false,
                ingress: Vec::new(),
                egress: default_egress(),
                guard: Arc::new(()),
            },
        );
        handler
            .scopes
            .lock()
            .unwrap()
            .insert(("111".into(), "us-east-1".into()), scope);
        let groups = vec!["sg-one".into()];
        let source = handler
            .reserve_task_network("111", "us-east-1", "subnet-one", &groups, "lambda")
            .unwrap();
        let target = handler
            .reserve_task_network("111", "us-east-1", "subnet-one", &groups, "rds")
            .unwrap();
        assert!(!target.set_dns_name("bad\nhost"));
        assert!(target.set_dns_name("orders.us-east-1.rds.amazonaws.com"));
        assert!(target.set_endpoint(5432, "127.0.0.1:15432".parse().unwrap()));
        assert_eq!(
            handler.private_tcp_dns("111", "us-east-1", &source.eni_id),
            vec![(
                "orders.us-east-1.rds.amazonaws.com".into(),
                target.private_ip
            )]
        );
        drop(target);
        assert!(handler
            .private_tcp_dns("111", "us-east-1", &source.eni_id)
            .is_empty());
    }
}
