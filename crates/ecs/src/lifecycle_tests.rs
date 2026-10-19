use super::*;
use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
use locallycloud_core::registry::{ServiceMetadata, ServiceName, ServiceRegistry};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Default)]
struct Runtime {
    live: Mutex<std::collections::BTreeSet<String>>,
    launches: Mutex<Vec<TaskLaunch>>,
    roles_enabled: bool,
    logs_enabled: bool,
    fail_start: AtomicBool,
}
#[async_trait]
impl TaskRuntime for Runtime {
    fn supports_execution_identity(&self) -> bool {
        self.roles_enabled
    }
    fn supports_awslogs(&self) -> bool {
        self.logs_enabled
    }
    async fn preflight(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &[String],
        _: &[String],
    ) -> Result<(), String> {
        Ok(())
    }
    async fn start(&self, task: &TaskLaunch) -> Result<TaskNetworkInfo, String> {
        let mut live = self.live.lock().unwrap();
        live.insert(task.task_id.clone());
        self.launches.lock().unwrap().push(task.clone());
        if self.fail_start.load(Ordering::SeqCst) {
            return Err("injected task startup failure".into());
        }
        Ok(TaskNetworkInfo {
            eni_id: format!("eni-{}", task.task_id),
            private_ip: std::net::Ipv4Addr::new(10, 0, 0, 10),
            subnet_id: "subnet-test".into(),
        })
    }
    async fn stop(&self, task: &str) -> Result<(), String> {
        self.live.lock().unwrap().remove(task);
        Ok(())
    }
    async fn running(&self, task: &str) -> bool {
        self.live.lock().unwrap().contains(task)
    }
}
#[derive(Default)]
struct QueryHandler {
    fail_register: AtomicBool,
    fail_remove: AtomicBool,
    registered: Mutex<bool>,
    unhealthy: AtomicBool,
    drain_seconds: std::sync::atomic::AtomicU64,
}
#[async_trait]
impl NativeHandler for QueryHandler {
    async fn handle(&self, req: ServiceRequest) -> Response {
        assert_eq!(req.account_id, "111111111111");
        assert_eq!(req.region, "us-east-1");
        let body = String::from_utf8(req.body.to_vec()).unwrap();
        let action = body.split('&').next().unwrap();
        if action == "Action=DescribeTargetGroupAttributes" {
            return Response::new(Body::from(format!(
                "<Key>deregistration_delay.timeout_seconds</Key><Value>{}</Value>",
                self.drain_seconds.load(Ordering::SeqCst)
            )));
        }
        let response = match action {
            "Action=DescribeTargetGroups" => {
                "<VpcId>vpc-test</VpcId><TargetType>ip</TargetType><Protocol>HTTP</Protocol><LoadBalancerArns><member>arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/web/1234</member></LoadBalancerArns>"
            }
            "Action=DescribeSubnets" => "<vpcId>vpc-test</vpcId>",
            "Action=DescribeTargetGroupAttributes" => {
                "<Key>deregistration_delay.timeout_seconds</Key><Value>0</Value>"
            }
            "Action=RegisterTargets" => {
                // Model a lost successful response: side effect precedes failure.
                *self.registered.lock().unwrap() = true;
                if self.fail_register.load(Ordering::SeqCst) {
                    return Response::builder().status(503).body(Body::empty()).unwrap();
                }
                "<ok/>"
            }
            "Action=DeregisterTargets" => {
                if self.fail_remove.load(Ordering::SeqCst) {
                    return Response::builder().status(503).body(Body::empty()).unwrap();
                }
                *self.registered.lock().unwrap() = false;
                "<ok/>"
            }
            "Action=DescribeTargetHealth" => {
                if self.unhealthy.load(Ordering::SeqCst) {
                    "<State>unhealthy</State>"
                } else {
                    "<State>healthy</State>"
                }
            }
            _ => panic!("unexpected action {action}"),
        };
        Response::new(Body::from(response))
    }
}
fn fixture() -> (EcsHandler, Arc<Runtime>, Arc<QueryHandler>) {
    let registry = ServiceRegistry::with_known_services();
    let queries = Arc::new(QueryHandler::default());
    for service in ["ec2", "elasticloadbalancing"] {
        registry.register_native(
            ServiceName::new(service),
            ServiceMetadata::new(AwsProtocol::Query, None),
            queries.clone(),
        );
    }
    let weak_registry = Arc::downgrade(&registry);
    let dispatcher = Arc::new(InternalDispatcher::new(
        registry,
        ProxyConfig {
            backend_url: "http://127.0.0.1:1".into(),
            upstream_timeout: Duration::from_secs(1),
        },
        LegacyHealth::new(false),
        "us-east-1".into(),
        "111111111111".into(),
    ));
    let runtime = Arc::new(Runtime::default());
    let handler = EcsHandler::with_dispatcher(Some(runtime.clone()), dispatcher, weak_registry);
    let scope = scope();
    handler
        .create_cluster(decode(br#"{"clusterName":"web"}"#).unwrap(), &scope)
        .unwrap();
    handler.register_task_definition(decode(br#"{"family":"web","containerDefinitions":[{"name":"app","image":"example.com/app:1","portMappings":[{"containerPort":8080}]}],"requiresCompatibilities":["FARGATE"],"networkMode":"awsvpc","cpu":"256","memory":"512"}"#).unwrap(), &scope).unwrap();
    (handler, runtime, queries)
}
fn scope() -> Scope {
    Scope {
        account: "111111111111".into(),
        region: "us-east-1".into(),
    }
}
fn input() -> Value {
    json!({"cluster":"web","serviceName":"web","taskDefinition":"web","launchType":"FARGATE","desiredCount":1,"networkConfiguration":{"awsvpcConfiguration":{"subnets":["subnet-test"]}},"loadBalancers":[{"targetGroupArn":"arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/web/1234","containerName":"app","containerPort":8080}]})
}
#[tokio::test]
async fn failed_registration_rolls_back_even_after_remote_commit() {
    let (handler, runtime, query) = fixture();
    query.fail_register.store(true, Ordering::SeqCst);
    assert!(handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .is_err());
    assert!(runtime.live.lock().unwrap().is_empty());
    assert!(!*query.registered.lock().unwrap());
    query.fail_register.store(false, Ordering::SeqCst);
    assert!(handler.state.lock().unwrap().services.is_empty());
    handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .unwrap();
    assert_eq!(runtime.live.lock().unwrap().len(), 1);
    handler
        .delete_service(
            serde_json::from_value(json!({"cluster":"web","service":"web","force":true})).unwrap(),
            &scope(),
        )
        .await
        .unwrap();
    assert!(runtime.live.lock().unwrap().is_empty());
    assert!(!*query.registered.lock().unwrap());
}
#[tokio::test]
async fn invalid_association_never_launches_or_registers() {
    let (handler, runtime, query) = fixture();
    let mut body = input();
    body["loadBalancers"][0]["containerPort"] = 80.into();
    assert!(handler
        .create_service(serde_json::from_value(body).unwrap(), &scope())
        .await
        .is_err());
    assert!(runtime.live.lock().unwrap().is_empty());
    assert!(!*query.registered.lock().unwrap());
    assert!(handler.state.lock().unwrap().services.is_empty());
}
#[tokio::test]
async fn lazy_worker_replaces_crashed_task_without_reads_and_stops_on_drop() {
    let (handler, runtime, query) = fixture();
    handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .unwrap();
    let original = runtime.live.lock().unwrap().iter().next().unwrap().clone();
    runtime.live.lock().unwrap().clear();
    handler.start_reconciler();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !runtime.live.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(!runtime.live.lock().unwrap().contains(&original));
    assert!(*query.registered.lock().unwrap());
    let state = Arc::downgrade(&handler.state);
    drop(handler);
    tokio::task::yield_now().await;
    assert!(state.upgrade().is_none());
}
#[tokio::test]
async fn failed_deregistration_preserves_task_and_service_for_retry() {
    let (handler, runtime, query) = fixture();
    handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .unwrap();
    query.fail_remove.store(true, Ordering::SeqCst);
    let deletion =
        || serde_json::from_value(json!({"cluster":"web","service":"web","force":true})).unwrap();
    assert!(handler.delete_service(deletion(), &scope()).await.is_err());
    assert_eq!(runtime.live.lock().unwrap().len(), 1);
    assert_eq!(handler.state.lock().unwrap().services.len(), 1);
    query.fail_remove.store(false, Ordering::SeqCst);
    handler.delete_service(deletion(), &scope()).await.unwrap();
    assert!(runtime.live.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unhealthy_target_is_replaced_and_grace_prevents_startup_churn() {
    let (handler, runtime, query) = fixture();
    let mut body = input();
    body["healthCheckGracePeriodSeconds"] = 300.into();
    handler
        .create_service(serde_json::from_value(body).unwrap(), &scope())
        .await
        .unwrap();
    let original = runtime.live.lock().unwrap().iter().next().unwrap().clone();
    query.unhealthy.store(true, Ordering::SeqCst);
    let key = (scope(), "web".into(), "web".into());
    handler.reconcile_service(&key).await.unwrap();
    assert!(runtime.live.lock().unwrap().contains(&original));
    handler
        .state
        .lock()
        .unwrap()
        .services
        .get_mut(&key)
        .unwrap()
        .health_grace_seconds = 0;
    handler.reconcile_service(&key).await.unwrap();
    assert_eq!(runtime.live.lock().unwrap().len(), 1);
    assert!(!runtime.live.lock().unwrap().contains(&original));
    assert!(handler
        .state
        .lock()
        .unwrap()
        .tasks
        .values()
        .any(|task| task.stopped_reason.as_deref() == Some("Task failed ELB health checks")));
}

async fn persistent_fixture() -> (
    EcsHandler,
    Arc<Runtime>,
    Arc<QueryHandler>,
    tempfile::TempDir,
    Arc<locallycloud_state::StateDb>,
) {
    let (mut handler, runtime, query) = fixture();
    let (directory, database) = tokio::task::spawn_blocking(|| {
        let directory = tempfile::Builder::new()
            .prefix("ecs-state-")
            .tempdir_in(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
            .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let private = directory.path().canonicalize().unwrap();
        locallycloud_state::StateDb::private_dir(&private).unwrap();
        let database =
            Arc::new(locallycloud_state::StateDb::open(private.join("state.sqlite3")).unwrap());
        (directory, database)
    })
    .await
    .unwrap();
    let store = Arc::new(
        Persistence::new(
            database.clone(),
            locallycloud_state::StateCipher::with_key(&[19; 32]),
        )
        .unwrap(),
    );
    {
        let state = handler.state.lock().unwrap();
        for ((scope, name), active) in &state.clusters {
            store.save(scope, "0cluster", name, &json!(active)).unwrap();
        }
        for ((scope, family), definitions) in &state.definitions {
            for definition in definitions {
                store
                    .save(
                        scope,
                        "1definition",
                        &format!("{family}:{}", definition["revision"].as_u64().unwrap()),
                        definition,
                    )
                    .unwrap();
            }
        }
    }
    handler.persistence = Some(store);
    (handler, runtime, query, directory, database)
}
#[tokio::test]
async fn persistent_service_restores_configuration_without_live_process_evidence() {
    let (handler, runtime, _, _directory, database) = persistent_fixture().await;
    handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .unwrap();
    let token_input: RunTask = serde_json::from_value(json!({"cluster":"web","taskDefinition":"web","launchType":"FARGATE","clientToken":"once","networkConfiguration":{"awsvpcConfiguration":{"subnets":["subnet-test"]}}})).unwrap();
    handler.run_task(token_input, &scope()).await.unwrap();
    let database_read = database.clone();
    let state = tokio::task::spawn_blocking(move || {
        Persistence::new(
            database_read,
            locallycloud_state::StateCipher::with_key(&[19; 32]),
        )
        .unwrap()
        .restore()
        .unwrap()
    })
    .await
    .unwrap();
    let service = state
        .services
        .get(&(scope(), "web".into(), "web".into()))
        .unwrap();
    assert_eq!(service.desired, 1);
    assert!(service.tasks.is_empty());
    assert_eq!(service.load_balancers.len(), 1);
    assert_eq!(state.tasks.len(), 1);
    let interrupted = state.tasks.values().next().unwrap();
    assert_eq!(interrupted.status, "STOPPED");
    assert!(interrupted.network.is_none());
    assert!(interrupted
        .stopped_reason
        .as_deref()
        .unwrap()
        .contains("outcome is unknown"));
    assert!(Persistence::new(
        database.clone(),
        locallycloud_state::StateCipher::with_key(&[20; 32])
    )
    .unwrap()
    .restore()
    .is_err());
    handler
        .delete_service(
            serde_json::from_value(json!({"cluster":"web","service":"web","force":true})).unwrap(),
            &scope(),
        )
        .await
        .unwrap();
    let state = Persistence::new(
        database,
        locallycloud_state::StateCipher::with_key(&[19; 32]),
    )
    .unwrap()
    .restore()
    .unwrap();
    assert!(state.services.is_empty());
    assert_eq!(runtime.live.lock().unwrap().len(), 1); // Standalone task is not owned by the deleted service.
}
#[tokio::test]
async fn failed_state_write_never_publishes_or_launches_service() {
    let (handler, runtime, query, _directory, database) = persistent_fixture().await;
    database.connection().unwrap().execute_batch("CREATE TRIGGER reject_ecs_service BEFORE INSERT ON ecs_control WHEN NEW.kind='2service' BEGIN SELECT RAISE(FAIL,'injected state failure'); END;").unwrap();
    assert!(handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .is_err());
    assert!(handler.state.lock().unwrap().services.is_empty());
    assert!(runtime.live.lock().unwrap().is_empty());
    assert!(!*query.registered.lock().unwrap());
}

#[tokio::test]
async fn service_delete_drains_without_blocking_or_losing_cleanup_ownership() {
    let (handler, runtime, query) = fixture();
    handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .unwrap();
    query.drain_seconds.store(1, Ordering::SeqCst);
    let deleted = handler
        .delete_service(
            serde_json::from_value(json!({"cluster":"web","service":"web","force":true})).unwrap(),
            &scope(),
        )
        .await
        .unwrap();
    assert_eq!(deleted["service"]["status"], "DRAINING");
    assert_eq!(runtime.live.lock().unwrap().len(), 1);
    assert!(!*query.registered.lock().unwrap());
    assert_eq!(handler.state.lock().unwrap().services.len(), 1);
    handler.start_reconciler();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if handler.state.lock().unwrap().services.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(runtime.live.lock().unwrap().is_empty());
}

#[tokio::test]
async fn provisioning_intent_never_relaunches_after_publish_and_cleanup_state_failures() {
    let (mut handler, runtime, query, _directory, database) = persistent_fixture().await;
    database.connection().unwrap().execute_batch("CREATE TRIGGER reject_ecs_publish BEFORE UPDATE ON ecs_control WHEN NEW.kind='2service' BEGIN SELECT RAISE(FAIL,'injected publish failure'); END; CREATE TRIGGER reject_ecs_cleanup BEFORE DELETE ON ecs_control WHEN OLD.kind='2service' BEGIN SELECT RAISE(FAIL,'injected cleanup failure'); END;").unwrap();
    assert!(handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .is_err());
    assert!(runtime.live.lock().unwrap().is_empty());
    assert!(!*query.registered.lock().unwrap());
    let store = handler.persistence.as_ref().unwrap();
    let restored = store.restore().unwrap();
    let service = restored
        .services
        .get(&(scope(), "web".into(), "web".into()))
        .unwrap();
    assert_eq!(service.status, "DRAINING");
    assert_eq!(service.desired, 0);
    assert!(service.tasks.is_empty());
    let payload: Vec<u8> = database
        .connection()
        .unwrap()
        .query_row(
            "SELECT payload FROM ecs_control WHERE kind='2service'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let clear = locallycloud_state::StateCipher::with_key(&[19; 32])
        .open(
            &["ecs", "111111111111", "us-east-1", "2service", "web/web"],
            &payload,
        )
        .unwrap();
    let durable: Value = serde_json::from_slice(&clear).unwrap();
    assert_eq!(durable["status"], "PROVISIONING");
    handler.state = Arc::new(Mutex::new(restored));
    handler.start_reconciler();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(runtime.live.lock().unwrap().is_empty());
    assert_eq!(handler.state.lock().unwrap().services.len(), 1);
    database
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_ecs_publish; DROP TRIGGER reject_ecs_cleanup;")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if handler.state.lock().unwrap().services.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(runtime.live.lock().unwrap().is_empty());
    assert!(handler
        .persistence
        .as_ref()
        .unwrap()
        .restore()
        .unwrap()
        .services
        .is_empty());
}

#[derive(Default)]
struct RolePolicy {
    deny_register: AtomicBool,
    deny_deregister: AtomicBool,
    calls: Mutex<Vec<String>>,
    deny_assignment: AtomicBool,
    deny_image: AtomicBool,
    deny_operator: AtomicBool,
    operator_calls: Mutex<Vec<locallycloud_core::integration::authorization::AuthorizationRequest>>,
    assignments: Mutex<Vec<String>>,
}
impl locallycloud_core::integration::authorization::AuthorizationEvaluator for RolePolicy {
    fn strict_sigv4_required(&self) -> bool {
        true
    }
    fn authorize(
        &self,
        request: locallycloud_core::integration::authorization::AuthorizationRequest,
    ) -> Result<(), locallycloud_core::integration::authorization::AuthorizationError> {
        self.operator_calls.lock().unwrap().push(request);
        if self.deny_operator.load(Ordering::SeqCst) {
            return Err(locallycloud_core::integration::authorization::AuthorizationError::Denied);
        }
        Ok(())
    }
    fn authorize_service_role_assignment(
        &self,
        request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), locallycloud_core::integration::authorization::AuthorizationError> {
        assert_eq!(request.service_principal, "ecs-tasks.amazonaws.com");
        assert!(request
            .role_arn
            .starts_with("arn:aws:iam::111111111111:role/"));
        self.assignments.lock().unwrap().push(request.role_arn);
        if self.deny_assignment.load(Ordering::SeqCst) {
            return Err(locallycloud_core::integration::authorization::AuthorizationError::Denied);
        }
        Ok(())
    }
    fn authorize_service_role_execution(
        &self,
        request: ServiceRoleAuthorizationRequest,
    ) -> Result<(), locallycloud_core::integration::authorization::AuthorizationError> {
        if request.action.starts_with("ecr:") {
            assert_eq!(request.role_arn, "arn:aws:iam::111111111111:role/execution");
            assert_eq!(request.service_principal, "ecs-tasks.amazonaws.com");
            assert_eq!(
                request.resource,
                if request.action == "ecr:GetAuthorizationToken" {
                    "*"
                } else {
                    "arn:aws:ecr:us-east-1:111111111111:repository/web"
                }
            );
            self.calls.lock().unwrap().push(request.action);
            return if self.deny_image.load(Ordering::SeqCst) {
                Err(locallycloud_core::integration::authorization::AuthorizationError::Denied)
            } else {
                Ok(())
            };
        }
        assert_eq!(request.role_arn,"arn:aws:iam::111111111111:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS");
        assert_eq!(request.service_principal, "ecs.amazonaws.com");
        if request
            .action
            .split(':')
            .nth(1)
            .is_some_and(|operation| operation.starts_with("Describe"))
        {
            assert_eq!(request.resource, "*");
        }
        self.calls.lock().unwrap().push(request.action.clone());
        if (request.action == "elasticloadbalancing:RegisterTargets"
            && self.deny_register.load(Ordering::SeqCst))
            || (request.action == "elasticloadbalancing:DeregisterTargets"
                && self.deny_deregister.load(Ordering::SeqCst))
        {
            return Err(locallycloud_core::integration::authorization::AuthorizationError::Denied);
        }
        Ok(())
    }
}
#[tokio::test]
async fn strict_service_role_revocation_preserves_cleanup_and_never_uses_task_role() {
    let (mut handler, _, query) = fixture();
    let runtime = enable_execution(&mut handler);
    let policy = Arc::new(RolePolicy::default());
    handler
        .registry
        .upgrade()
        .unwrap()
        .register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            query.clone(),
            policy.clone(),
        );
    policy.deny_register.store(true, Ordering::SeqCst);
    assert!(handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .is_err());
    assert!(runtime.live.lock().unwrap().is_empty());
    assert!(!*query.registered.lock().unwrap());
    policy.deny_register.store(false, Ordering::SeqCst);
    handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .unwrap();
    policy.deny_deregister.store(true, Ordering::SeqCst);
    let deletion =
        || serde_json::from_value(json!({"cluster":"web","service":"web","force":true})).unwrap();
    assert!(handler.delete_service(deletion(), &scope()).await.is_err());
    assert_eq!(runtime.live.lock().unwrap().len(), 1);
    assert_eq!(handler.state.lock().unwrap().services.len(), 1);
    policy.deny_deregister.store(false, Ordering::SeqCst);
    handler.delete_service(deletion(), &scope()).await.unwrap();
    assert!(runtime.live.lock().unwrap().is_empty());
    let calls = policy.calls.lock().unwrap();
    assert!(calls.iter().any(|action| action == "ec2:DescribeSubnets"));
    assert!(calls
        .iter()
        .any(|action| action == "elasticloadbalancing:RegisterTargets"));
    assert!(calls
        .iter()
        .any(|action| action == "elasticloadbalancing:DeregisterTargets"));
}

fn wire_request(operation: &str, body: Value) -> ServiceRequest {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", CONTENT_TYPE.parse().unwrap());
    headers.insert(
        "x-amz-target",
        format!("{TARGET_PREFIX}.{operation}").parse().unwrap(),
    );
    headers.insert(
        "authorization",
        "AWS4-HMAC-SHA256 Credential=operator/19700101/us-east-1/ecs/aws4_request"
            .parse()
            .unwrap(),
    );
    ServiceRequest {
        method: Method::POST,
        uri: "/".parse().unwrap(),
        headers,
        body: bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        account_id: "111111111111".into(),
        region: "us-east-1".into(),
        request_id: "roles-test".into(),
    }
}
#[tokio::test]
async fn roles_and_logs_require_runtime_capabilities_passrole_and_scoped_metadata() {
    let (mut handler, _, query) = fixture();
    let policy = Arc::new(RolePolicy::default());
    handler
        .registry
        .upgrade()
        .unwrap()
        .register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            query,
            policy.clone(),
        );
    let definition = json!({"family":"web","containerDefinitions":[{"name":"app","image":"111111111111.dkr.ecr.us-east-1.amazonaws.com/web:1","portMappings":[{"containerPort":8080}],"logConfiguration":{"logDriver":"awslogs","options":{"awslogs-group":"/ecs/web","awslogs-region":"us-east-1","awslogs-stream-prefix":"web"}}}],"requiresCompatibilities":["FARGATE"],"networkMode":"awsvpc","cpu":"256","memory":"512","taskRoleArn":"arn:aws:iam::111111111111:role/task","executionRoleArn":"arn:aws:iam::111111111111:role/execution"});
    assert!(handler
        .process(&wire_request("RegisterTaskDefinition", definition.clone()))
        .is_err());
    let runtime = Arc::new(Runtime {
        roles_enabled: true,
        logs_enabled: true,
        ..Runtime::default()
    });
    handler.runtime = Some(runtime.clone());
    policy.deny_assignment.store(true, Ordering::SeqCst);
    assert!(handler
        .process(&wire_request("RegisterTaskDefinition", definition.clone()))
        .is_err());
    assert_eq!(
        handler
            .state
            .lock()
            .unwrap()
            .definitions
            .values()
            .next()
            .unwrap()
            .len(),
        1
    );
    policy.deny_assignment.store(false, Ordering::SeqCst);
    handler
        .process(&wire_request("RegisterTaskDefinition", definition.clone()))
        .unwrap();
    let mut wrong_region = definition;
    wrong_region["containerDefinitions"][0]["logConfiguration"]["options"]["awslogs-region"] =
        "eu-west-1".into();
    assert!(handler
        .process(&wire_request("RegisterTaskDefinition", wrong_region))
        .is_err());
    let run = json!({"cluster":"web","taskDefinition":"web","launchType":"FARGATE","networkConfiguration":{"awsvpcConfiguration":{"subnets":["subnet-test"]}}});
    policy.deny_assignment.store(true, Ordering::SeqCst);
    assert!(handler
        .process_async(&wire_request("RunTask", run.clone()))
        .await
        .is_err());
    assert!(runtime.live.lock().unwrap().is_empty());
    policy.deny_assignment.store(false, Ordering::SeqCst);
    handler
        .process_async(&wire_request("RunTask", run))
        .await
        .unwrap();
    let launches = runtime.launches.lock().unwrap();
    assert_eq!(launches.len(), 1);
    assert_eq!(
        launches[0].task_role_arn.as_deref(),
        Some("arn:aws:iam::111111111111:role/task")
    );
    assert_eq!(
        launches[0].execution_role_arn.as_deref(),
        Some("arn:aws:iam::111111111111:role/execution")
    );
    assert_eq!(
        launches[0].log_configuration.as_ref().unwrap().options["awslogs-group"],
        "/ecs/web"
    );
}

#[tokio::test]
async fn deregistered_revision_keeps_existing_service_scaling_but_rejects_new_admission() {
    let (handler, runtime, _) = fixture();
    handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .unwrap();
    let result = handler
        .process(&wire_request(
            "DeregisterTaskDefinition",
            json!({"taskDefinition":"web:1"}),
        ))
        .unwrap();
    assert_eq!(result["taskDefinition"]["status"], "INACTIVE");
    assert!(handler
        .process(&wire_request(
            "DeregisterTaskDefinition",
            json!({"taskDefinition":"web"})
        ))
        .is_err());
    assert_eq!(
        handler
            .process(&wire_request(
                "DescribeTaskDefinition",
                json!({"taskDefinition":"web:1"})
            ))
            .unwrap()["taskDefinition"]["status"],
        "INACTIVE"
    );
    let run = json!({"cluster":"web","taskDefinition":"web:1","launchType":"FARGATE","networkConfiguration":{"awsvpcConfiguration":{"subnets":["subnet-test"]}}});
    assert!(handler
        .process_async(&wire_request("RunTask", run))
        .await
        .is_err());
    let mut new_service = input();
    new_service["serviceName"] = "other".into();
    new_service["taskDefinition"] = "web:1".into();
    assert!(handler
        .create_service(serde_json::from_value(new_service).unwrap(), &scope())
        .await
        .is_err());
    handler
        .update_service(
            serde_json::from_value(json!({"cluster":"web","service":"web","desiredCount":2}))
                .unwrap(),
            &scope(),
        )
        .await
        .unwrap();
    assert_eq!(runtime.live.lock().unwrap().len(), 2);
}

fn enable_execution(handler: &mut EcsHandler) -> Arc<Runtime> {
    let runtime = Arc::new(Runtime {
        roles_enabled: true,
        ..Runtime::default()
    });
    handler.runtime = Some(runtime.clone());
    let mut state = handler.state.lock().unwrap();
    let definition = state
        .definitions
        .values_mut()
        .next()
        .unwrap()
        .first_mut()
        .unwrap();
    definition["executionRoleArn"] = "arn:aws:iam::111111111111:role/execution".into();
    definition["containerDefinitions"][0]["image"] =
        "111111111111.dkr.ecr.us-east-1.amazonaws.com/web:1".into();
    runtime
}
#[tokio::test]
async fn ecr_execution_permissions_are_checked_before_launch_and_revocation_is_effective() {
    let (mut handler, _, query) = fixture();
    let runtime = enable_execution(&mut handler);
    let policy = Arc::new(RolePolicy::default());
    handler
        .registry
        .upgrade()
        .unwrap()
        .register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            query,
            policy.clone(),
        );
    let run = || {
        serde_json::from_value(json!({"cluster":"web","taskDefinition":"web","launchType":"FARGATE","networkConfiguration":{"awsvpcConfiguration":{"subnets":["subnet-test"]}}})).unwrap()
    };
    policy.deny_image.store(true, Ordering::SeqCst);
    assert!(handler.run_task(run(), &scope()).await.is_err());
    assert!(runtime.launches.lock().unwrap().is_empty());
    assert!(handler.state.lock().unwrap().tasks.is_empty());
    policy.deny_image.store(false, Ordering::SeqCst);
    handler.run_task(run(), &scope()).await.unwrap();
    assert_eq!(runtime.launches.lock().unwrap().len(), 1);
    policy.deny_image.store(true, Ordering::SeqCst);
    assert!(handler.run_task(run(), &scope()).await.is_err());
    assert_eq!(runtime.launches.lock().unwrap().len(), 1);
    handler
        .state
        .lock()
        .unwrap()
        .definitions
        .values_mut()
        .next()
        .unwrap()[0]["executionRoleArn"] = Value::Null;
    policy.deny_image.store(false, Ordering::SeqCst);
    assert!(handler.run_task(run(), &scope()).await.is_err());
    let calls = policy.calls.lock().unwrap();
    for action in [
        "ecr:GetAuthorizationToken",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
    ] {
        assert!(calls.iter().any(|actual| actual == action));
    }
}

#[tokio::test]
async fn public_operator_authorization_blocks_control_mutation_and_forged_guest_identity() {
    let (handler, runtime, query) = fixture();
    let policy = Arc::new(RolePolicy::default());
    handler
        .registry
        .upgrade()
        .unwrap()
        .register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            query,
            policy.clone(),
        );
    policy.deny_operator.store(true, Ordering::SeqCst);
    let response = handler
        .handle(wire_request(
            "CreateCluster",
            json!({"clusterName":"blocked"}),
        ))
        .await;
    assert_eq!(response.status(), 400);
    assert!(!handler
        .state
        .lock()
        .unwrap()
        .clusters
        .contains_key(&(scope(), "blocked".into())));
    let mut run = wire_request(
        "RunTask",
        json!({"cluster":"web","taskDefinition":"web","launchType":"FARGATE","networkConfiguration":{"awsvpcConfiguration":{"subnets":["subnet-test"]}}}),
    );
    run.headers.insert(
        "x-locallycloud-caller-principal",
        "arn:aws:iam::111111111111:role/admin/forged"
            .parse()
            .unwrap(),
    );
    assert_eq!(handler.handle(run).await.status(), 400);
    assert!(runtime.launches.lock().unwrap().is_empty());
    {
        let calls = policy.operator_calls.lock().unwrap();
        assert_eq!(calls[0].action, "ecs:CreateCluster");
        assert_eq!(
            calls[0].resource,
            "arn:aws:ecs:us-east-1:111111111111:cluster/blocked"
        );
        assert_eq!(calls[1].action, "ecs:RunTask");
        assert_eq!(
            calls[1].resource,
            "arn:aws:ecs:us-east-1:111111111111:task-definition/web:1"
        );
        assert!(calls[1].delegated_identity.is_none());
        assert_eq!(
            calls[1].context["ecs:cluster"],
            vec!["arn:aws:ecs:us-east-1:111111111111:cluster/web"]
        );
    }
    policy.deny_operator.store(false, Ordering::SeqCst);
    assert_eq!(
        handler
            .handle(wire_request(
                "CreateCluster",
                json!({"clusterName":"allowed"})
            ))
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn stopped_task_listing_preserves_failed_service_ownership_and_diagnostics() {
    let (handler, runtime, _) = fixture();
    let run: RunTask = serde_json::from_value(json!({"cluster":"web","taskDefinition":"web","launchType":"FARGATE","networkConfiguration":{"awsvpcConfiguration":{"subnets":["subnet-test"]}}})).unwrap();
    let standalone = handler.run_task(run, &scope()).await.unwrap()["tasks"][0]["taskArn"]
        .as_str()
        .unwrap()
        .to_owned();
    handler
        .stop_task(
            serde_json::from_value(json!({"cluster":"web","task":standalone})).unwrap(),
            &scope(),
        )
        .await
        .unwrap();
    runtime.fail_start.store(true, Ordering::SeqCst);
    let error = handler
        .create_service(serde_json::from_value(input()).unwrap(), &scope())
        .await
        .unwrap_err();
    assert!(
        matches!(error,EcsError::Client(ref message) if message.contains("injected task startup failure"))
    );
    assert!(runtime.live.lock().unwrap().is_empty());
    let all = handler
        .process_async(&wire_request(
            "ListTasks",
            json!({"cluster":"web","desiredStatus":"STOPPED"}),
        ))
        .await
        .unwrap();
    assert_eq!(all["taskArns"].as_array().unwrap().len(), 2);
    let service = handler
        .process_async(&wire_request(
            "ListTasks",
            json!({"cluster":"web","serviceName":"web","desiredStatus":"STOPPED"}),
        ))
        .await
        .unwrap();
    let arns = service["taskArns"].as_array().unwrap();
    assert_eq!(arns.len(), 1);
    assert_ne!(arns[0], standalone);
    let described = handler
        .process_async(&wire_request(
            "DescribeTasks",
            json!({"cluster":"web","tasks":arns}),
        ))
        .await
        .unwrap();
    assert_eq!(
        described["tasks"][0]["stoppedReason"],
        "injected task startup failure"
    );
    assert_eq!(described["tasks"][0]["desiredStatus"], "STOPPED");
    assert!(handler
        .process_async(&wire_request(
            "ListTasks",
            json!({"cluster":"web","serviceName":"unproven","desiredStatus":"STOPPED"})
        ))
        .await
        .is_err());
    let other = Scope {
        region: "eu-west-1".into(),
        ..scope()
    };
    assert_eq!(
        handler
            .list_tasks(
                serde_json::from_value(json!({"cluster":"web","desiredStatus":"STOPPED"})).unwrap(),
                &other
            )
            .unwrap()["taskArns"],
        json!([])
    );
}
#[tokio::test]
async fn desired_task_status_defaults_and_invalid_values_use_aws_errors() {
    let (handler, _, _) = fixture();
    let run: RunTask = serde_json::from_value(json!({"cluster":"web","taskDefinition":"web","launchType":"FARGATE","networkConfiguration":{"awsvpcConfiguration":{"subnets":["subnet-test"]}}})).unwrap();
    handler.run_task(run, &scope()).await.unwrap();
    let running = handler
        .process_async(&wire_request("ListTasks", json!({"cluster":"web"})))
        .await
        .unwrap();
    assert_eq!(running["taskArns"].as_array().unwrap().len(), 1);
    let pending = handler
        .process_async(&wire_request(
            "ListTasks",
            json!({"cluster":"web","desiredStatus":"PENDING"}),
        ))
        .await
        .unwrap();
    assert_eq!(pending["taskArns"], json!([]));
    let response = handler
        .handle(wire_request(
            "ListTasks",
            json!({"cluster":"web","desiredStatus":"stopped"}),
        ))
        .await;
    assert_eq!(response.status(), 400);
    let body = axum::body::to_bytes(response.into_body(), MAX_BODY)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["__type"],
        "InvalidParameterException"
    );
    let numeric = handler
        .process_async(&wire_request(
            "ListTasks",
            json!({"cluster":"web","desiredStatus":1}),
        ))
        .await;
    assert!(matches!(numeric, Err(EcsError::Serialization(_))));
}
