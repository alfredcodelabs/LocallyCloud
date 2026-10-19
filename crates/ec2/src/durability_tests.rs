use super::tests::{call, id};
use super::*;

struct TestDb {
    root: std::path::PathBuf,
    database: Arc<StateDb>,
}
impl TestDb {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("ec2-state-{}", Uuid::new_v4()));
        StateDb::private_dir(&root).unwrap();
        let database = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        Self { root, database }
    }
    fn handler(&self, key: u8) -> Result<Ec2Handler, Ec2StateError> {
        let persistence = Arc::new(Persistence::new(
            self.database.clone(),
            StateCipher::with_key(&[key; 32]),
        )?);
        let handler = Ec2Handler {
            persistence: Some(persistence.clone()),
            ..Ec2Handler::default()
        };
        persistence.restore(&handler)?;
        Ok(handler)
    }
    fn sql(&self, sql: &str) {
        self.database
            .connection()
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
    fn count(&self) -> i64 {
        self.database
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM ec2_records", [], |row| row.get(0))
            .unwrap()
    }
}
impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
async fn ok(handler: &Ec2Handler, form: &str) -> String {
    let (status, body) = call(handler, "111", "us-east-1", form).await;
    assert_eq!(status, 200, "{form}: {body}");
    body
}
async fn base(handler: &Ec2Handler) -> (String, Vec<String>, Vec<String>) {
    let vpc = id(
        &ok(handler, "Action=CreateVpc&CidrBlock=10.80.0.0%2F16").await,
        "vpcId",
    );
    let mut subnets = Vec::new();
    for (number, zone) in [(1, "a"), (2, "b")] {
        subnets.push(id(&ok(handler,&format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.80.{number}.0%2F24&AvailabilityZone=us-east-1{zone}")).await,"subnetId"));
    }
    let mut groups = Vec::new();
    for name in ["alb", "app"] {
        groups.push(id(&ok(handler,&format!("Action=CreateSecurityGroup&VpcId={vpc}&GroupName={name}&GroupDescription={name}")).await,"groupId"));
    }
    (vpc, subnets, groups)
}

#[tokio::test]
async fn topology_restores_with_scoped_rules_routes_tokens_and_fresh_leases() {
    let db = TestDb::new();
    let handler = db.handler(7).unwrap();
    let (vpc, subnets, groups) = base(&handler).await;
    ok(
        &handler,
        &format!("Action=ModifyVpcAttribute&VpcId={vpc}&EnableDnsHostnames.Value=true"),
    )
    .await;
    let rule=format!("GroupId={}&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=8080&IpPermissions.1.ToPort=8080&IpPermissions.1.Groups.1.GroupId={}",groups[1],groups[0]);
    ok(
        &handler,
        &format!("Action=AuthorizeSecurityGroupIngress&{rule}"),
    )
    .await;
    let eni_request=format!("Action=CreateNetworkInterface&SubnetId={}&SecurityGroupId.1={}&PrivateIpAddress=10.80.2.10&ClientToken=eni-once",subnets[1],groups[1]);
    let eni = id(&ok(&handler, &eni_request).await, "networkInterfaceId");
    let table_request = format!("Action=CreateRouteTable&VpcId={vpc}&ClientToken=rt-once");
    let table = id(&ok(&handler, &table_request).await, "routeTableId");
    let association = id(
        &ok(
            &handler,
            &format!(
                "Action=AssociateRouteTable&RouteTableId={table}&SubnetId={}",
                subnets[1]
            ),
        )
        .await,
        "associationId",
    );
    let igw = id(
        &ok(&handler, "Action=CreateInternetGateway").await,
        "internetGatewayId",
    );
    ok(
        &handler,
        &format!("Action=AttachInternetGateway&InternetGatewayId={igw}&VpcId={vpc}"),
    )
    .await;
    let eip = id(
        &ok(&handler, "Action=AllocateAddress&Domain=vpc").await,
        "allocationId",
    );
    let nat_request = format!(
        "Action=CreateNatGateway&SubnetId={}&AllocationId={eip}&ClientToken=nat-once",
        subnets[0]
    );
    let nat = id(&ok(&handler, &nat_request).await, "natGatewayId");
    ok(&handler,&format!("Action=CreateRoute&RouteTableId={table}&DestinationCidrBlock=0.0.0.0%2F0&NatGatewayId={nat}")).await;
    let endpoint_request=format!("Action=CreateVpcEndpoint&VpcId={vpc}&ServiceName=com.amazonaws.us-east-1.s3&VpcEndpointType=Gateway&RouteTableId.1={table}&ClientToken=endpoint-once");
    let endpoint = id(&ok(&handler, &endpoint_request).await, "vpcEndpointId");
    let interface=id(&ok(&handler,&format!("Action=CreateVpcEndpoint&VpcId={vpc}&ServiceName=com.amazonaws.us-east-1.ssm&VpcEndpointType=Interface&SubnetId.1={}&SecurityGroupId.1={}&PrivateDnsEnabled=true",subnets[0],groups[1])).await,"vpcEndpointId");
    let alb = handler
        .alb_network_lease("111", "us-east-1", &subnets, &groups[..1])
        .unwrap();
    let task = handler
        .reserve_task_network("111", "us-east-1", &subnets[1], &groups[1..], "ecs-task")
        .unwrap();
    assert!(task.set_endpoint(8080, "127.0.0.1:12345".parse().unwrap()));
    assert!(handler
        .alb_target_access("111", "us-east-1", &alb, task.private_ip, 8080)
        .is_some());
    let ephemeral_ids = {
        let state = handler.scopes.lock().unwrap();
        state[&("111".into(), "us-east-1".into())]
            .task_networks
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    let count = db.count();
    drop(task);
    drop(alb);
    drop(handler);
    assert!(db.handler(8).is_err());
    let handler = db.handler(7).unwrap();
    assert_eq!(db.count(), count);
    assert_eq!(
        id(&ok(&handler, &eni_request).await, "networkInterfaceId"),
        eni
    );
    assert_eq!(
        id(&ok(&handler, &table_request).await, "routeTableId"),
        table
    );
    assert_eq!(id(&ok(&handler, &nat_request).await, "natGatewayId"), nat);
    assert_eq!(
        id(&ok(&handler, &endpoint_request).await, "vpcEndpointId"),
        endpoint
    );
    let body = ok(
        &handler,
        &format!("Action=DescribeRouteTables&RouteTableId.1={table}"),
    )
    .await;
    assert!(body.contains(&nat));
    assert!(body.contains(&endpoint));
    assert!(body.contains(&association));
    let body = ok(
        &handler,
        &format!("Action=DescribeSecurityGroups&GroupId.1={}", groups[1]),
    )
    .await;
    assert!(body.contains(&format!(
        "<groups><item><userId>111</userId><groupId>{}</groupId>",
        groups[0]
    )));
    assert!(ok(
        &handler,
        &format!("Action=DescribeVpcAttribute&VpcId={vpc}&Attribute=enableDnsHostnames")
    )
    .await
    .contains("<value>true</value>"));
    assert_eq!(
        call(
            &handler,
            "222",
            "us-east-1",
            &format!("Action=DescribeVpcs&VpcId.1={vpc}")
        )
        .await
        .0,
        400
    );
    assert_eq!(
        call(
            &handler,
            "111",
            "us-west-2",
            &format!("Action=DescribeVpcs&VpcId.1={vpc}")
        )
        .await
        .0,
        400
    );
    {
        let state = handler.scopes.lock().unwrap();
        let scope = &state[&("111".into(), "us-east-1".into())];
        assert!(scope.task_networks.is_empty());
        assert!(scope.task_endpoints.is_empty());
        assert!(ephemeral_ids
            .iter()
            .all(|id| !scope.network_interfaces.contains_key(id)));
    }
    let lease = handler
        .alb_network_lease("111", "us-east-1", &subnets, &groups[..1])
        .unwrap();
    assert_eq!(
        call(
            &handler,
            "111",
            "us-east-1",
            &format!("Action=DeleteSubnet&SubnetId={}", subnets[0])
        )
        .await
        .0,
        400
    );
    drop(lease);
    ok(
        &handler,
        &format!(
            "Action=DeleteVpcEndpoints&VpcEndpointId.1={endpoint}&VpcEndpointId.2={interface}"
        ),
    )
    .await;
    ok(
        &handler,
        &format!("Action=DeleteNatGateway&NatGatewayId={nat}"),
    )
    .await;
    drop(handler);
    let handler = db.handler(7).unwrap();
    let body = ok(
        &handler,
        &format!("Action=DescribeRouteTables&RouteTableId.1={table}"),
    )
    .await;
    assert!(body.contains("<state>blackhole</state>"));
    assert!(!body.contains(&endpoint));
    ok(
        &handler,
        &format!("Action=DeleteRoute&RouteTableId={table}&DestinationCidrBlock=0.0.0.0%2F0"),
    )
    .await;
    ok(
        &handler,
        &format!("Action=ReleaseAddress&AllocationId={eip}"),
    )
    .await;
    ok(
        &handler,
        &format!("Action=DisassociateRouteTable&AssociationId={association}"),
    )
    .await;
    ok(
        &handler,
        &format!("Action=DeleteRouteTable&RouteTableId={table}"),
    )
    .await;
    ok(
        &handler,
        &format!("Action=DeleteNetworkInterface&NetworkInterfaceId={eni}"),
    )
    .await;
    ok(
        &handler,
        &format!("Action=RevokeSecurityGroupIngress&{rule}"),
    )
    .await;
    for group in &groups {
        ok(
            &handler,
            &format!("Action=DeleteSecurityGroup&GroupId={group}"),
        )
        .await;
    }
    for subnet in &subnets {
        ok(&handler, &format!("Action=DeleteSubnet&SubnetId={subnet}")).await;
    }
    ok(
        &handler,
        &format!("Action=DetachInternetGateway&InternetGatewayId={igw}&VpcId={vpc}"),
    )
    .await;
    ok(
        &handler,
        &format!("Action=DeleteInternetGateway&InternetGatewayId={igw}"),
    )
    .await;
    ok(&handler, &format!("Action=DeleteVpc&VpcId={vpc}")).await;
    assert_eq!(db.count(), 0);
    drop(handler);
    assert!(db
        .handler(7)
        .unwrap()
        .scopes
        .lock()
        .unwrap()
        .values()
        .all(|scope| scope.vpcs.is_empty()));
}

#[tokio::test]
async fn persistence_failure_keeps_topology_and_multi_entity_operations_unchanged() {
    let db = TestDb::new();
    let handler = db.handler(7).unwrap();
    db.sql("CREATE TRIGGER fail_default BEFORE INSERT ON ec2_records WHEN NEW.kind='sg' BEGIN SELECT RAISE(ABORT,'injected default SG failure'); END;");
    assert_eq!(
        call(
            &handler,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.80.0.0%2F16"
        )
        .await
        .0,
        500
    );
    assert_eq!(db.count(), 0);
    assert!(!ok(&handler, "Action=DescribeVpcs")
        .await
        .contains("<vpcId>"));
    db.sql("DROP TRIGGER fail_default;");
    let (vpc, subnets, groups) = base(&handler).await;
    let initial = db.count();
    db.sql("CREATE TRIGGER fail_sg BEFORE UPDATE ON ec2_records WHEN NEW.kind='sg' BEGIN SELECT RAISE(ABORT,'injected SG update failure'); END;");
    let rule=format!("Action=AuthorizeSecurityGroupIngress&GroupId={}&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=8080&IpPermissions.1.ToPort=8080&IpPermissions.1.Groups.1.GroupId={}",groups[1],groups[0]);
    assert_eq!(call(&handler, "111", "us-east-1", &rule).await.0, 500);
    assert_eq!(db.count(), initial);
    assert!(!ok(
        &handler,
        &format!("Action=DescribeSecurityGroups&GroupId.1={}", groups[1])
    )
    .await
    .contains("<fromPort>8080</fromPort>"));
    db.sql("DROP TRIGGER fail_sg;");
    let table = id(
        &ok(&handler, &format!("Action=CreateRouteTable&VpcId={vpc}")).await,
        "routeTableId",
    );
    let before = db.count();
    db.sql("CREATE TRIGGER fail_route BEFORE UPDATE ON ec2_records WHEN NEW.kind='route-table' BEGIN SELECT RAISE(ABORT,'injected endpoint route failure'); END;");
    assert_eq!(call(&handler,"111","us-east-1",&format!("Action=CreateVpcEndpoint&VpcId={vpc}&ServiceName=com.amazonaws.us-east-1.s3&RouteTableId.1={table}")).await.0,500);
    assert_eq!(db.count(), before);
    assert!(!ok(&handler, "Action=DescribeVpcEndpoints")
        .await
        .contains("<vpcEndpointId>"));
    db.sql("DROP TRIGGER fail_route;");
    let igw = id(
        &ok(&handler, "Action=CreateInternetGateway").await,
        "internetGatewayId",
    );
    db.sql("CREATE TRIGGER fail_delete BEFORE DELETE ON ec2_records WHEN OLD.kind='igw' BEGIN SELECT RAISE(ABORT,'injected delete failure'); END;");
    assert_eq!(
        call(
            &handler,
            "111",
            "us-east-1",
            &format!("Action=DeleteInternetGateway&InternetGatewayId={igw}")
        )
        .await
        .0,
        500
    );
    assert!(ok(
        &handler,
        &format!("Action=DescribeInternetGateways&InternetGatewayId.1={igw}")
    )
    .await
    .contains(&igw));
    drop(handler);
    let handler = db.handler(7).unwrap();
    assert!(handler.vpc_exists("111", "us-east-1", &vpc));
    assert!(!ok(
        &handler,
        &format!("Action=DescribeSecurityGroups&GroupId.1={}", groups[1])
    )
    .await
    .contains("<fromPort>8080</fromPort>"));
    assert!(ok(
        &handler,
        &format!("Action=DescribeSubnets&SubnetId.1={}", subnets[0])
    )
    .await
    .contains(&subnets[0]));
    db.sql("DROP TRIGGER fail_delete;");
    ok(
        &handler,
        &format!("Action=DeleteInternetGateway&InternetGatewayId={igw}"),
    )
    .await;
    db.sql("UPDATE ec2_records SET version=2 WHERE kind='vpc'");
    assert!(db.handler(7).is_err());
}

struct UnusedRuntime;
#[async_trait]
impl InstanceRuntime for UnusedRuntime {
    async fn start_instance(&self, _: &InstanceSpec) -> Result<(), String> {
        Err("not started by this test".into())
    }
    async fn connect_instance(&self, _: &str, _: u16) -> Result<TcpStream, String> {
        Err("not started by this test".into())
    }
    async fn stop_instance(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    async fn instance_running(&self, _: &str) -> bool {
        false
    }
}

#[tokio::test]
async fn interrupted_instance_restores_stopped_without_runtime_or_endpoint() {
    let db = TestDb::new();
    let mut handler = db.handler(7).unwrap();
    handler.runtime = Some(Arc::new(UnusedRuntime));
    let (_, subnets, groups) = base(&handler).await;
    let form=format!("Action=RunInstances&ImageId=ami-locallycloud-http&InstanceType=t3.micro&MinCount=1&MaxCount=1&SubnetId={}&SecurityGroupId.1={}&ClientToken=interrupted",subnets[0],groups[1]);
    let request = super::tests::request("111", "us-east-1", &form);
    let input = Input::parse(&request).unwrap();
    let spec = match handler.prepare_instance(&request, &input).unwrap() {
        PreparedInstance::Launch(spec) => spec,
        PreparedInstance::Replay(_) => panic!("fresh request"),
    };
    drop(handler);
    let handler = db.handler(7).unwrap();
    let body = ok(
        &handler,
        &format!("Action=DescribeInstances&InstanceId.1={}", spec.instance_id),
    )
    .await;
    assert!(body.contains("<code>80</code><name>stopped</name>"));
    assert_eq!(
        handler.resolve_target("111", "us-east-1", &spec.vpc_id, spec.private_ip, 8080),
        None
    );
    let state = handler.scopes.lock().unwrap();
    let scope = &state[&("111".into(), "us-east-1".into())];
    assert!(scope.network_interfaces.is_empty());
    assert!(scope.instances[&spec.instance_id].endpoint.is_none());
}

#[tokio::test]
async fn logs_interface_endpoint_enforces_live_security_groups_after_restore() {
    let db = TestDb::new();
    let handler = db.handler(7).unwrap();
    let (vpc, subnets, groups) = base(&handler).await;
    ok(
        &handler,
        &format!("Action=ModifyVpcAttribute&VpcId={vpc}&EnableDnsHostnames.Value=true"),
    )
    .await;
    ok(&handler,&format!("Action=CreateVpcEndpoint&VpcId={vpc}&ServiceName=com.amazonaws.us-east-1.logs&VpcEndpointType=Interface&SubnetId.1={}&SecurityGroupId.1={}&PrivateDnsEnabled=true",subnets[0],groups[1])).await;
    let source_ip = "10.80.2.4".parse().unwrap();
    let access = |handler: &Ec2Handler| {
        handler.vpc_endpoint_access(
            "111",
            "us-east-1",
            &subnets[1],
            source_ip,
            &groups[..1],
            "logs",
        )
    };
    assert!(!access(&handler));
    let ingress=format!("GroupId={}&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=443&IpPermissions.1.ToPort=443&IpPermissions.1.Groups.1.GroupId={}",groups[1],groups[0]);
    ok(
        &handler,
        &format!("Action=AuthorizeSecurityGroupIngress&{ingress}"),
    )
    .await;
    assert!(access(&handler));
    ok(
        &handler,
        &format!("Action=RevokeSecurityGroupIngress&{ingress}"),
    )
    .await;
    assert!(!access(&handler));
    ok(
        &handler,
        &format!("Action=AuthorizeSecurityGroupIngress&{ingress}"),
    )
    .await;
    drop(handler);
    let handler = db.handler(7).unwrap();
    assert!(access(&handler));
    assert!(!handler.vpc_endpoint_access(
        "111",
        "us-west-2",
        &subnets[1],
        source_ip,
        &groups[..1],
        "logs"
    ));
    ok(&handler,&format!("Action=RevokeSecurityGroupEgress&GroupId={}&IpPermissions.1.IpProtocol=-1&IpPermissions.1.IpRanges.1.CidrIp=0.0.0.0%2F0",groups[0])).await;
    assert!(!access(&handler));
    ok(&handler,&format!("Action=AuthorizeSecurityGroupEgress&GroupId={}&IpPermissions.1.IpProtocol=tcp&IpPermissions.1.FromPort=443&IpPermissions.1.ToPort=443&IpPermissions.1.Groups.1.GroupId={}",groups[0],groups[1])).await;
    assert!(access(&handler));
}
