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
    let eni_id = &scope.instances[&spec.instance_id].eni_id;
    assert_eq!(scope.network_interfaces[eni_id].private_ip, spec.private_ip);
    assert!(scope.instances[&spec.instance_id].endpoint.is_none());
    drop(state);
    let task = handler
        .reserve_task_network(
            "111",
            "us-east-1",
            &spec.subnet_id,
            &spec.security_group_ids,
            "new-ecs-task",
        )
        .unwrap();
    assert_ne!(task.private_ip, spec.private_ip);
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

async fn stopped_fixture(runtime: Arc<dyn InstanceRuntime>) -> (TestDb, Ec2Handler, InstanceSpec) {
    let db = TestDb::new();
    let mut handler = db.handler(7).unwrap();
    handler.runtime = Some(runtime.clone());
    let (_, subnets, groups) = base(&handler).await;
    let form=format!("Action=RunInstances&ImageId=ami-locallycloud-http&InstanceType=t3.micro&MinCount=1&MaxCount=1&SubnetId={}&SecurityGroupId.1={}",subnets[0],groups[1]);
    let request = super::tests::request("111", "us-east-1", &form);
    let spec = match handler
        .prepare_instance(&request, &Input::parse(&request).unwrap())
        .unwrap()
    {
        PreparedInstance::Launch(spec) => spec,
        _ => panic!("new instance"),
    };
    drop(handler);
    let mut handler = db.handler(7).unwrap();
    handler.runtime = Some(runtime);
    (db, handler, spec)
}

#[tokio::test]
async fn start_instances_restores_same_identity_network_and_is_idempotent_and_scoped() {
    use std::sync::atomic::Ordering;
    let runtime = super::tests::mock_runtime(false).await;
    let (_db, handler, spec) = stopped_fixture(runtime.clone()).await;
    let key = ("111".into(), "us-east-1".into());
    let eni_id = handler.scopes.lock().unwrap()[&key].instances[&spec.instance_id]
        .eni_id
        .clone();
    let request = format!("Action=StartInstances&InstanceId.1={}", spec.instance_id);
    for (account, region) in [("222", "us-east-1"), ("111", "us-west-2")] {
        let (status, body) = call(&handler, account, region, &request).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("InvalidInstanceID.NotFound"));
    }
    let body = ok(&handler, &request).await;
    assert!(body.contains("<previousState><code>80</code><name>stopped</name>"));
    assert!(body.contains("<currentState><code>16</code><name>running</name>"));
    assert!(ok(&handler, &request)
        .await
        .contains("<previousState><code>16</code><name>running</name>"));
    assert_eq!(runtime.starts.load(Ordering::SeqCst), 1);
    {
        let states = handler.scopes.lock().unwrap();
        let scope = &states[&key];
        let current = &scope.instances[&spec.instance_id];
        assert_eq!(current.eni_id, eni_id);
        assert_eq!(current.spec.private_ip, spec.private_ip);
        assert_eq!(current.spec.security_group_ids, spec.security_group_ids);
        assert!(current.endpoint.is_some());
    }
    ok(
        &handler,
        &format!(
            "Action=TerminateInstances&InstanceId.1={}",
            spec.instance_id
        ),
    )
    .await;
    let (status, body) = call(&handler, "111", "us-east-1", &request).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("IncorrectInstanceState"));
}

#[tokio::test]
async fn start_failures_retain_stopped_configuration_without_endpoint_and_allow_retry() {
    use std::sync::atomic::Ordering;
    let runtime = super::tests::mock_runtime(true).await;
    let (db, handler, spec) = stopped_fixture(runtime.clone()).await;
    let request = format!("Action=StartInstances&InstanceId.1={}", spec.instance_id);
    assert_eq!(call(&handler, "111", "us-east-1", &request).await.0, 500);
    assert!(ok(
        &handler,
        &format!("Action=DescribeInstances&InstanceId.1={}", spec.instance_id)
    )
    .await
    .contains("<name>stopped</name>"));
    assert!(handler
        .resolve_target(
            "111",
            "us-east-1",
            &spec.vpc_id,
            spec.private_ip,
            spec.guest_port
        )
        .is_none());
    runtime.fail_start.store(false, Ordering::SeqCst);
    db.sql("CREATE TRIGGER deny_start_intent BEFORE UPDATE ON ec2_records WHEN NEW.kind='instance' BEGIN SELECT RAISE(FAIL,'test intent failure'); END;");
    assert_eq!(call(&handler, "111", "us-east-1", &request).await.0, 500);
    assert_eq!(runtime.starts.load(Ordering::SeqCst), 1);
    db.sql("DROP TRIGGER deny_start_intent;");
    *runtime.persistence_failure.lock().unwrap() = Some(db.database.clone());
    assert_eq!(call(&handler, "111", "us-east-1", &request).await.0, 500);
    assert!(!runtime.running.load(Ordering::SeqCst));
    {
        let states = handler.scopes.lock().unwrap();
        let current = &states[&("111".into(), "us-east-1".into())].instances[&spec.instance_id];
        assert!(current.state == InstanceState::Stopped);
        assert!(current.endpoint.is_none());
    }
    let restored = db.handler(7).unwrap();
    assert!(ok(
        &restored,
        &format!("Action=DescribeInstances&InstanceId.1={}", spec.instance_id)
    )
    .await
    .contains("<name>stopped</name>"));
    db.sql("DROP TRIGGER reject_instance_commit;");
    *runtime.persistence_failure.lock().unwrap() = None;
    ok(&handler, &request).await;
    ok(
        &handler,
        &format!(
            "Action=TerminateInstances&InstanceId.1={}",
            spec.instance_id
        ),
    )
    .await;
}

struct BarrierRuntime {
    inner: Arc<dyn InstanceRuntime>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
#[async_trait]
impl InstanceRuntime for BarrierRuntime {
    async fn start_instance(&self, spec: &InstanceSpec) -> Result<(), String> {
        self.entered.notify_one();
        self.release.notified().await;
        self.inner.start_instance(spec).await
    }
    async fn connect_instance(&self, id: &str, port: u16) -> Result<TcpStream, String> {
        self.inner.connect_instance(id, port).await
    }
    async fn stop_instance(&self, id: &str) -> Result<(), String> {
        self.inner.stop_instance(id).await
    }
    async fn instance_running(&self, id: &str) -> bool {
        self.inner.instance_running(id).await
    }
}

#[tokio::test]
async fn cancelled_start_and_run_retain_operation_permit_until_lifecycle_finishes() {
    for action in ["StartInstances", "RunInstances"] {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let runtime = Arc::new(BarrierRuntime {
            inner: super::tests::mock_runtime(false).await,
            entered: entered.clone(),
            release: release.clone(),
        });
        let (_db, handler, spec) = stopped_fixture(runtime).await;
        let handler = Arc::new(handler);
        let form = if action == "StartInstances" {
            format!("Action=StartInstances&InstanceId.1={}", spec.instance_id)
        } else {
            format!("Action=RunInstances&ImageId=ami-locallycloud-http&InstanceType=t3.micro&MinCount=1&MaxCount=1&SubnetId={}&SecurityGroupId.1={}",spec.subnet_id,spec.security_group_ids[0])
        };
        let owner = handler.clone();
        let client = tokio::spawn(async move { call(&owner, "111", "us-east-1", &form).await });
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        let id = handler.scopes.lock().unwrap()[&("111".into(), "us-east-1".into())]
            .instances
            .values()
            .find(|instance| instance.state == InstanceState::Pending)
            .unwrap()
            .spec
            .instance_id
            .clone();
        client.abort();
        assert!(client.await.unwrap_err().is_cancelled());
        let owner = handler.clone();
        let mut terminate = tokio::spawn(async move {
            call(
                &owner,
                "111",
                "us-east-1",
                &format!("Action=TerminateInstances&InstanceId.1={id}"),
            )
            .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut terminate)
                .await
                .is_err()
        );
        release.notify_one();
        let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(3), terminate)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("<previousState><code>16</code><name>running</name>"));
    }
}

#[tokio::test]
async fn start_rejects_missing_multiple_and_nonstartable_states_without_side_effects() {
    let runtime = super::tests::mock_runtime(false).await;
    let (_db, handler, spec) = stopped_fixture(runtime.clone()).await;
    for (form, code) in [
        ("Action=StartInstances".to_owned(), "MissingParameter"),
        (
            format!(
                "Action=StartInstances&InstanceId.1={}&InstanceId.2={}",
                spec.instance_id, spec.instance_id
            ),
            "InvalidParameterValue",
        ),
    ] {
        let (status, body) = call(&handler, "111", "us-east-1", &form).await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains(code));
    }
    for state in [
        InstanceState::Pending,
        InstanceState::ShuttingDown,
        InstanceState::Terminated,
    ] {
        handler
            .scopes
            .lock()
            .unwrap()
            .get_mut(&("111".into(), "us-east-1".into()))
            .unwrap()
            .instances
            .get_mut(&spec.instance_id)
            .unwrap()
            .state = state;
        let (status, body) = call(
            &handler,
            "111",
            "us-east-1",
            &format!("Action=StartInstances&InstanceId.1={}", spec.instance_id),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(body.contains("IncorrectInstanceState"));
    }
    assert_eq!(runtime.starts.load(std::sync::atomic::Ordering::SeqCst), 0);
}

async fn live_fixture(runtime: Arc<dyn InstanceRuntime>) -> (TestDb, Ec2Handler, InstanceSpec) {
    let db = TestDb::new();
    let mut handler = db.handler(7).unwrap();
    handler.runtime = Some(runtime);
    let (_, subnets, groups) = base(&handler).await;
    let body=ok(&handler,&format!("Action=RunInstances&ImageId=ami-locallycloud-http&InstanceType=t3.micro&MinCount=1&MaxCount=1&SubnetId={}&SecurityGroupId.1={}",subnets[0],groups[1])).await;
    let id = id(&body, "instanceId");
    let spec = handler.scopes.lock().unwrap()[&("111".into(), "us-east-1".into())].instances[&id]
        .spec
        .clone();
    (db, handler, spec)
}

#[tokio::test]
async fn genuine_shutdown_restores_stopped_configuration_then_start_creates_fresh_runtime() {
    use std::sync::atomic::Ordering;
    let runtime = super::tests::mock_runtime(false).await;
    let (db, handler, spec) = live_fixture(runtime.clone()).await;
    handler.shutdown().await;
    assert!(!runtime.running.load(Ordering::SeqCst));
    {
        let states = handler.scopes.lock().unwrap();
        let scope = &states[&("111".into(), "us-east-1".into())];
        let instance = &scope.instances[&spec.instance_id];
        assert!(instance.state == InstanceState::Stopped);
        assert!(instance.endpoint.is_none());
        assert_eq!(
            scope.network_interfaces[&instance.eni_id].private_ip,
            spec.private_ip
        );
    }
    drop(handler);
    let fresh = super::tests::mock_runtime(false).await;
    let mut restored = db.handler(7).unwrap();
    restored.runtime = Some(fresh.clone());
    let before = ok(
        &restored,
        &format!("Action=DescribeInstances&InstanceId.1={}", spec.instance_id),
    )
    .await;
    assert!(before.contains("<name>stopped</name>"));
    assert!(restored
        .resolve_target(
            "111",
            "us-east-1",
            &spec.vpc_id,
            spec.private_ip,
            spec.guest_port
        )
        .is_none());
    ok(
        &restored,
        &format!("Action=StartInstances&InstanceId.1={}", spec.instance_id),
    )
    .await;
    assert!(fresh.running.load(Ordering::SeqCst));
    assert_eq!(fresh.starts.load(Ordering::SeqCst), 1);
    let after = ok(
        &restored,
        &format!("Action=DescribeInstances&InstanceId.1={}", spec.instance_id),
    )
    .await;
    assert!(after.contains(&format!(
        "<privateIpAddress>{}</privateIpAddress>",
        spec.private_ip
    )));
    assert!(after.contains("<name>running</name>"));
    ok(
        &restored,
        &format!(
            "Action=TerminateInstances&InstanceId.1={}",
            spec.instance_id
        ),
    )
    .await;
}

#[tokio::test]
async fn shutdown_failures_keep_ownership_without_endpoint_and_never_revive_terminated_instances() {
    use std::sync::atomic::Ordering;
    let runtime = super::tests::mock_runtime(false).await;
    let (db, handler, spec) = live_fixture(runtime.clone()).await;
    runtime.fail_stop.store(true, Ordering::SeqCst);
    handler.shutdown().await;
    {
        let states = handler.scopes.lock().unwrap();
        let scope = &states[&("111".into(), "us-east-1".into())];
        let instance = &scope.instances[&spec.instance_id];
        assert!(instance.state == InstanceState::ShuttingDown);
        assert!(instance.endpoint.is_none());
        assert!(scope.network_interfaces.contains_key(&instance.eni_id));
    }
    assert!(runtime.running.load(Ordering::SeqCst));
    assert!(handler
        .resolve_target(
            "111",
            "us-east-1",
            &spec.vpc_id,
            spec.private_ip,
            spec.guest_port
        )
        .is_none());
    runtime.fail_stop.store(false, Ordering::SeqCst);
    db.sql("CREATE TRIGGER deny_shutdown BEFORE UPDATE ON ec2_records WHEN NEW.kind='instance' BEGIN SELECT RAISE(FAIL,'test shutdown failure'); END;");
    handler.shutdown().await;
    assert!(!runtime.running.load(Ordering::SeqCst));
    assert!(
        handler.scopes.lock().unwrap()[&("111".into(), "us-east-1".into())].instances
            [&spec.instance_id]
            .endpoint
            .is_none()
    );
    let restored = db.handler(7).unwrap();
    assert!(
        restored.scopes.lock().unwrap()[&("111".into(), "us-east-1".into())].instances
            [&spec.instance_id]
            .state
            == InstanceState::Stopped
    );
    db.sql("DROP TRIGGER deny_shutdown;");
    handler.shutdown().await;
    ok(
        &handler,
        &format!(
            "Action=TerminateInstances&InstanceId.1={}",
            spec.instance_id
        ),
    )
    .await;
    handler.shutdown().await;
    let restored = db.handler(7).unwrap();
    let states = restored.scopes.lock().unwrap();
    let scope = &states[&("111".into(), "us-east-1".into())];
    let instance = &scope.instances[&spec.instance_id];
    assert!(instance.state == InstanceState::Terminated);
    assert!(!scope.network_interfaces.contains_key(&instance.eni_id));
}

#[tokio::test]
async fn old_proxy_exit_callback_and_listener_cannot_claim_resumed_generation() {
    let runtime = super::tests::mock_runtime(false).await;
    let (_db, handler, spec) = live_fixture(runtime).await;
    let key = ("111".into(), "us-east-1".into());
    let old = handler.scopes.lock().unwrap()[&key].instances[&spec.instance_id]
        .endpoint
        .unwrap();
    handler.shutdown().await;
    ok(
        &handler,
        &format!("Action=StartInstances&InstanceId.1={}", spec.instance_id),
    )
    .await;
    let fresh = handler.scopes.lock().unwrap()[&key].instances[&spec.instance_id]
        .endpoint
        .unwrap();
    assert_ne!(fresh, old);
    handler
        .mark_terminated(&key, &spec.instance_id, Some(old))
        .await
        .unwrap();
    assert!(
        handler.scopes.lock().unwrap()[&key].instances[&spec.instance_id].state
            == InstanceState::Running
    );
    if let Ok(mut socket) = TcpStream::connect(old).await {
        let _ = socket
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await;
        let mut data = [0u8; 128];
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(2), socket.read(&mut data)).await;
        assert!(!matches!(result,Ok(Ok(size)) if size>0));
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while TcpStream::connect(old).await.is_ok() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("old proxy listener must close instead of serving a fresh generation");
    ok(
        &handler,
        &format!(
            "Action=TerminateInstances&InstanceId.1={}",
            spec.instance_id
        ),
    )
    .await;
}
