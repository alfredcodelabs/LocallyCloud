//! locallycloud binary entry point.
//!
//! Wires observability, configuration, endpoint resolution, compute-runtime selection, the
//! service registry, and the Axum server together, then runs until a shutdown signal.

mod cli;
mod domain_tls;
mod ec2_runtime;
mod ecs_guest;
mod ecs_network;
mod ecs_runtime;
mod migration;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, Weak};

use locallycloud_compute::selector::{RuntimeKind, RuntimeSelector, SelectionError};
use locallycloud_core::config::{LocallyCloudConfig, RuntimeChoice, SqsEndpointStrategy};
use locallycloud_core::endpoint::EndpointResolver;
use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::integration::authorization::{
    AuthorizationRequest, ServiceRoleAuthorizationRequest,
};
use locallycloud_core::integration::RequestIdentity;

use locallycloud_core::observability;
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use locallycloud_core::server::LocallyCloudServer;

struct ArcRoutingControls(Arc<locallycloud_arc::ArcService>);

impl locallycloud_region_switch::RoutingControls for ArcRoutingControls {
    fn get(&self, arn: &str) -> Result<bool, String> {
        self.0
            .is_on(arn)
            .ok_or_else(|| "Routing control not found".into())
    }

    fn set(&self, arn: &str, on: bool) -> Result<(), String> {
        self.0.set_state(arn, on)
    }
}

struct IamExecutionRoleAuthorizer(Weak<ServiceRegistry>);

#[async_trait::async_trait]
impl locallycloud_region_switch::ExecutionRoleAuthorizer for IamExecutionRoleAuthorizer {
    async fn authorize_caller(
        &self,
        request: &ServiceRequest,
        operation: &str,
        resource: &str,
    ) -> Result<(), String> {
        let registry = self.0.upgrade().ok_or("IAM registry is unavailable")?;
        let evaluator = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .ok_or("IAM authorization is unavailable")?;
        let caller = RequestIdentity {
            account_id: request.account_id.clone(),
            access_key_id: request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(RequestIdentity::access_key_from_authorization),
            arn: None,
        };
        evaluator
            .authorize(AuthorizationRequest {
                request_identity: caller,
                delegated_identity: None,
                source_service: "arc-region-switch".into(),
                action: format!("arc-region-switch:{operation}"),
                resource: resource.into(),
                context: Default::default(),
            })
            .map_err(|error| error.to_string())
    }

    async fn authorize(
        &self,
        request: &ServiceRequest,
        role_arn: &str,
        routing_control_arn: &str,
        phase: locallycloud_region_switch::RoleAuthorizationPhase,
    ) -> Result<(), String> {
        let registry = self.0.upgrade().ok_or("IAM registry is unavailable")?;
        let evaluator = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .ok_or("IAM authorization is unavailable")?;
        let caller = RequestIdentity {
            account_id: request.account_id.clone(),
            access_key_id: request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(RequestIdentity::access_key_from_authorization),
            arn: None,
        };
        for action in [
            "route53-recovery-cluster:GetRoutingControlState",
            "route53-recovery-cluster:UpdateRoutingControlStates",
        ] {
            let auth = ServiceRoleAuthorizationRequest {
                source_arn: None,
                caller: caller.clone(),
                role_arn: role_arn.into(),
                service_principal: "arc-region-switch.amazonaws.com".into(),
                action: action.into(),
                resource: routing_control_arn.into(),
            };
            let result = match phase {
                locallycloud_region_switch::RoleAuthorizationPhase::PlanCreation => {
                    evaluator.authorize_service_role(auth)
                }
                locallycloud_region_switch::RoleAuthorizationPhase::Execution => {
                    evaluator.authorize_service_role_execution(auth)
                }
            };
            result.map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

struct Ec2VpcPreflight(Arc<locallycloud_ec2::Ec2Handler>);

impl locallycloud_elbv2::VpcPreflight for Ec2VpcPreflight {
    fn vpc_lease(&self, account: &str, region: &str, vpc_id: &str) -> Option<Arc<dyn Send + Sync>> {
        self.0
            .vpc_lease(account, region, vpc_id)
            .map(|lease| Arc::new(lease) as Arc<dyn Send + Sync>)
    }
}

struct OwnedAlbLease {
    account: String,
    region: String,
    lease: Weak<locallycloud_ec2::AlbNetworkLease>,
}

struct Ec2AlbNetworkPreflight {
    ec2: Arc<locallycloud_ec2::Ec2Handler>,
    ecs_runtime: Arc<ecs_runtime::EcsOciRuntime>,
    ec2_runtime: Arc<ec2_runtime::Ec2OciRuntime>,
    leases: Mutex<std::collections::HashMap<String, OwnedAlbLease>>,
}

impl Ec2AlbNetworkPreflight {
    fn owned_lease(
        &self,
        connection: &locallycloud_elbv2::AlbTargetConnection<'_>,
    ) -> Option<Arc<locallycloud_ec2::AlbNetworkLease>> {
        let leases = self.leases.lock().ok()?;
        let owned = leases.get(connection.network_id)?;
        if owned.account != connection.account || owned.region != connection.region {
            return None;
        }
        let lease = owned.lease.upgrade()?;
        if lease.vpc_id != connection.vpc_id
            || lease.security_group_ids != connection.source_security_groups
            || !lease
                .subnets
                .iter()
                .map(|(id, _)| id)
                .eq(connection.source_subnets.iter())
        {
            return None;
        }
        Some(lease)
    }
}

#[async_trait::async_trait]
impl locallycloud_elbv2::AlbNetworkPreflight for Ec2AlbNetworkPreflight {
    fn reserve(
        &self,
        account: &str,
        region: &str,
        subnet_ids: &[String],
        group_ids: &[String],
    ) -> Option<locallycloud_elbv2::AlbNetworkLease> {
        let lease = Arc::new(
            self.ec2
                .alb_network_lease(account, region, subnet_ids, group_ids)?,
        );
        let network_id = uuid::Uuid::new_v4().to_string();
        let mut leases = self.leases.lock().ok()?;
        leases.retain(|_, owned| owned.lease.strong_count() > 0);
        leases.insert(
            network_id.clone(),
            OwnedAlbLease {
                account: account.to_owned(),
                region: region.to_owned(),
                lease: Arc::downgrade(&lease),
            },
        );
        Some(locallycloud_elbv2::AlbNetworkLease {
            network_id,
            vpc_id: lease.vpc_id.clone(),
            subnets: lease.subnets.clone(),
            security_groups: lease.security_group_ids.clone(),
            guard: lease,
        })
    }

    fn allows_ingress(
        &self,
        account: &str,
        region: &str,
        groups: &[String],
        source: Ipv4Addr,
        port: u16,
    ) -> bool {
        self.ec2
            .security_groups_allow_ingress(account, region, groups, source, port)
    }

    fn allows_target_route(
        &self,
        account: &str,
        region: &str,
        vpc_id: &str,
        subnets: &[String],
        ip: Ipv4Addr,
    ) -> bool {
        self.ec2
            .alb_can_reach_target(account, region, vpc_id, subnets, ip)
    }

    fn allows_target_connection(
        &self,
        connection: &locallycloud_elbv2::AlbTargetConnection<'_>,
    ) -> bool {
        self.owned_lease(connection).is_some_and(|lease| {
            self.ec2
                .alb_target_access(
                    connection.account,
                    connection.region,
                    &lease,
                    connection.target_ip,
                    connection.target_port,
                )
                .is_some()
        })
    }

    async fn connect_target(
        &self,
        connection: &locallycloud_elbv2::AlbTargetConnection<'_>,
        endpoint: SocketAddr,
    ) -> std::io::Result<tokio::net::TcpStream> {
        let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let lease = self.owned_lease(connection).ok_or_else(denied)?;
        if self.ec2.alb_target_access(
            connection.account,
            connection.region,
            &lease,
            connection.target_ip,
            connection.target_port,
        ) != Some(endpoint)
        {
            return Err(denied());
        }
        let owner = self
            .ec2
            .private_target_owner(
                connection.account,
                connection.region,
                connection.vpc_id,
                connection.target_ip,
                connection.target_port,
            )
            .ok_or_else(denied)?;
        match owner {
            locallycloud_ec2::PrivateTargetOwner::Task(id) => {
                self.ecs_runtime
                    .connect_registered_task(&id, connection.target_ip, connection.target_port)
                    .await
            }
            locallycloud_ec2::PrivateTargetOwner::HostSocket => {
                tokio::net::TcpStream::connect(endpoint).await
            }
            locallycloud_ec2::PrivateTargetOwner::Instance(id) => {
                locallycloud_ec2::InstanceRuntime::connect_instance(
                    self.ec2_runtime.as_ref(),
                    &id,
                    connection.target_port,
                )
                .await
                .map_err(std::io::Error::other)
            }
        }
    }
}

struct Ec2TargetResolver(Arc<locallycloud_ec2::Ec2Handler>);

impl locallycloud_elbv2::TargetEndpointResolver for Ec2TargetResolver {
    fn resolve(
        &self,
        account: &str,
        region: &str,
        vpc_id: &str,
        ip: Ipv4Addr,
        port: u16,
    ) -> Option<SocketAddr> {
        self.0.resolve_target(account, region, vpc_id, ip, port)
    }
}

#[tokio::main]
async fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = match cli::parse(&arguments) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("locallycloud: {error}\n\n{}", cli::USAGE);
            std::process::exit(2);
        }
    };
    match command {
        cli::Command::Help => {
            println!("{}", cli::USAGE);
            return;
        }
        cli::Command::Version => {
            println!("locallycloud {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        cli::Command::OciSetupGate(ref address) => {
            if let Err(error) = locallycloud_compute::youki::run_oci_setup_hook(address).await {
                eprintln!("OCI guest setup failed: {error}");
                std::process::exit(6);
            }
            return;
        }
        cli::Command::Serve | cli::Command::MigrateS3Encryption => {}
    }

    observability::init_tracing();

    let config = match LocallyCloudConfig::from_env() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(setting = err.setting, reason = %err.reason, "invalid configuration");
            std::process::exit(2);
        }
    };

    if command == cli::Command::MigrateS3Encryption {
        if let Err(error) = migration::s3(&config).await {
            tracing::error!(%error, "S3 encryption migration failed");
            std::process::exit(5);
        }
        return;
    }

    let endpoint =
        EndpointResolver::resolve(config.external_endpoint.as_deref(), config.listen_addr);
    tracing::info!(
        endpoint = endpoint.guest_endpoint(),
        "resolved guest endpoint"
    );

    let kvm_available = RuntimeSelector::check_kvm_availability();
    let runtime_override = config.runtime_override.map(|choice| match choice {
        RuntimeChoice::Firecracker => RuntimeKind::Firecracker,
        RuntimeChoice::Youki => RuntimeKind::Youki,
    });
    match RuntimeSelector::select(runtime_override, kvm_available) {
        Ok(kind) => tracing::info!(?kind, kvm_available, "selected compute runtime"),
        Err(SelectionError::FirecrackerRequiresKvm) => {
            tracing::error!("FirecrackerRuntime was requested but /dev/kvm is unavailable");
            std::process::exit(3);
        }
    }

    let state = match tokio::task::spawn_blocking(|| {
        locallycloud_state::StateDb::default_path().and_then(locallycloud_state::StateDb::open)
    })
    .await
    {
        Ok(Ok(state)) => Arc::new(state),
        Ok(Err(error)) => {
            tracing::error!(%error, "failed to open durable state");
            std::process::exit(4);
        }
        Err(error) => {
            tracing::error!(%error, "durable state startup task failed");
            std::process::exit(4);
        }
    };
    let _state_lock = match state.lock_runtime() {
        Ok(guard) => guard,
        Err(error) => {
            tracing::error!(%error, "state is already in use or cannot be locked");
            std::process::exit(5);
        }
    };
    let registry = ServiceRegistry::with_known_services();
    if let Err(error) = locallycloud_iam_sts::service::register_with_state(
        &registry,
        &config.account_id,
        state.clone(),
    ) {
        tracing::error!(%error, "failed to initialize durable IAM state");
        std::process::exit(2);
    }
    let lambda_handler = locallycloud_lambda::service::register_with_execution_config(
        &registry,
        endpoint.guest_endpoint(),
        config.lambda_concurrency,
        config.sqs_esm_max_pollers,
    )
    .await;
    if let Some(lambda) = &lambda_handler {
        if let Err(error) = lambda.attach_state(state.clone()) {
            tracing::error!(%error, "failed to load durable Lambda state");
            std::process::exit(4);
        }
    }
    if let Err(error) = locallycloud_dynamodb::register_with_state(&registry, state.clone()) {
        tracing::error!(%error, "failed to register DynamoDB");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_s3::register_with_state(&registry, state.clone()) {
        tracing::error!(%error, "failed to register S3");
        std::process::exit(4);
    }
    // Queue URLs use the same base injected into guests as AWS_ENDPOINT_URL, because SDKs
    // send queue operations to the QueueUrl host.
    let queue_urls = match config.sqs_endpoint_strategy {
        SqsEndpointStrategy::Path => {
            locallycloud_sqs::QueueUrlStyle::Endpoint(endpoint.guest_endpoint().to_string())
        }
        SqsEndpointStrategy::Aws => locallycloud_sqs::QueueUrlStyle::Aws,
    };
    if let Err(error) =
        locallycloud_sqs::register_with_state_and_queue_urls(&registry, state.clone(), queue_urls)
    {
        tracing::error!(%error, "failed to register SQS");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_sns::register_with_state(&registry, state.clone()) {
        tracing::error!(%error, "failed to register SNS");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_eventbridge::service::register_with_state_and_retry_timing(
        &registry,
        state.clone(),
        config.events_retry_second,
    ) {
        tracing::error!(%error, "failed to register EventBridge");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_eventbridge::schemas::register(&registry, state.clone()) {
        tracing::error!(%error, "failed to register EventBridge Schemas");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_stepfunctions::register_with_state(&registry, state.clone()) {
        tracing::error!(%error, "failed to load durable Step Functions state");
        std::process::exit(4);
    }
    let acm = match locallycloud_acm::register_with_state(&registry, state.clone()) {
        Ok(acm) => acm,
        Err(error) => {
            tracing::error!(error = %error.message, "failed to load durable ACM state");
            std::process::exit(4);
        }
    };
    let gateway_waf =
        match locallycloud_apigateway::register_with_state(&registry, state.clone(), acm.clone())
            .await
        {
            Ok(gateway) => gateway,
            Err(error) => {
                tracing::error!(%error, "failed to load durable API Gateway state");
                std::process::exit(4);
            }
        };
    if let Err(error) = locallycloud_cloudformation::register_with_state(&registry, state.clone()) {
        tracing::error!(%error, "failed to load durable CloudFormation state");
        std::process::exit(4);
    }
    let ecr = match locallycloud_ecr::register_with_state(&registry, state.clone()).await {
        Ok(handler) => handler,
        Err(error) => {
            tracing::error!(%error, "failed to restore durable ECR state");
            std::process::exit(4);
        }
    };
    let ec2_runtime = Arc::new(ec2_runtime::Ec2OciRuntime::default());
    let ec2 = match locallycloud_ec2::register_with_state_and_instance_runtime(
        &registry,
        state.clone(),
        ec2_runtime.clone(),
    )
    .await
    {
        Ok(handler) => handler,
        Err(error) => {
            tracing::error!(%error, "failed to restore durable EC2 topology");
            std::process::exit(4);
        }
    };
    if let Some(handler) = &lambda_handler {
        handler.attach_ec2(ec2.clone());
    }
    let ecs_runtime = Arc::new(ecs_runtime::EcsOciRuntime::new(
        Arc::downgrade(&registry),
        ecr,
        ec2.clone(),
        ec2_runtime.clone(),
    ));
    let ecs_recovery = match locallycloud_ecs::register_with_state(
        &registry,
        Some(ecs_runtime.clone()),
        state.clone(),
    )
    .await
    {
        Ok(handle) => handle,
        Err(error) => {
            tracing::error!(%error, "failed to restore durable ECS state");
            std::process::exit(4);
        }
    };
    if let Err(error) = locallycloud_elbv2::register_with_state_and_alb_integrations(
        &registry,
        Arc::new(Ec2VpcPreflight(ec2.clone())),
        Arc::new(Ec2TargetResolver(ec2.clone())),
        Arc::new(Ec2AlbNetworkPreflight {
            ec2: ec2.clone(),
            ecs_runtime: ecs_runtime.clone(),
            ec2_runtime,
            leases: Mutex::new(std::collections::HashMap::new()),
        }),
        Arc::new(locallycloud_elbv2::LoopbackAlbEndpointAllocator::default()),
        state.clone(),
    )
    .await
    {
        tracing::error!(%error, "failed to restore durable ALB state");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_kms::register_with_state(&registry, state.clone()) {
        tracing::error!(%error, "failed to register KMS");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_ssm::register_with_state(&registry, state.clone()) {
        tracing::error!(%error, "failed to register SSM");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_secretsmanager::register_with_state(&registry, state.clone()) {
        tracing::error!(%error, "failed to register Secrets Manager");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_analytics::register_with_state(&registry, state.clone()).await
    {
        tracing::error!(%error, "failed to restore Glue catalog; check LOCALLYCLOUD_KMS_MASTER_KEY and state database compatibility");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_kinesis::register_with_state(&registry, state.clone()) {
        tracing::error!(%error, "failed to register Kinesis");
        std::process::exit(4);
    }
    let firehose_handle = match locallycloud_firehose::register_with_state(&registry, state.clone())
    {
        Ok(handle) => handle,
        Err(error) => {
            tracing::error!(%error, "failed to register Firehose");
            std::process::exit(4);
        }
    };
    if let Err(error) =
        locallycloud_cloudwatch_monitoring::register_with_state(&registry, state.clone())
    {
        tracing::error!(%error, "failed to initialize durable CloudWatch Monitoring");
        std::process::exit(4);
    }
    locallycloud_xray::register(&registry);
    let arc = locallycloud_arc::register(&registry);
    registry.register_native(
        ServiceName::new("arc-region-switch"),
        ServiceMetadata::new(AwsProtocol::Json10, Some("ArcRegionSwitch")),
        Arc::new(locallycloud_region_switch::RegionSwitchHandler::new(
            Arc::new(ArcRoutingControls(arc.clone())),
            Arc::new(IamExecutionRoleAuthorizer(Arc::downgrade(&registry))),
        )),
    );
    let route53 = locallycloud_route53::register(&registry);
    route53.set_routing_control_resolver(Arc::new(move |arn| arc.is_on(arn)));
    let alias_gateway = gateway_waf.clone();
    let alias_address = if config.listen_addr.ip().is_unspecified() {
        std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        config.listen_addr.ip()
    };
    route53.set_alias_target_resolver(Arc::new(move |account, target, zone| {
        alias_gateway
            .regional_alias_registered(account, target, zone)
            .then(|| vec![alias_address])
    }));
    let dns = match std::env::var("LOCALLYCLOUD_ROUTE53_DNS_BIND") {
        Ok(value) => {
            let bind: SocketAddr = match value.parse() {
                Ok(bind) => bind,
                Err(error) => {
                    tracing::error!(%error, "invalid LOCALLYCLOUD_ROUTE53_DNS_BIND");
                    std::process::exit(6);
                }
            };
            match locallycloud_route53::DnsServer::start(route53, config.account_id.clone(), bind)
                .await
            {
                Ok(dns) => {
                    tracing::info!(addr = %dns.local_addr(), "Route 53 DNS listening");
                    Some(dns)
                }
                Err(error) => {
                    tracing::error!(%error, "Route 53 DNS failed to bind");
                    std::process::exit(6);
                }
            }
        }
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => {
            tracing::error!(%error, "invalid LOCALLYCLOUD_ROUTE53_DNS_BIND");
            std::process::exit(6);
        }
    };
    let cognito = match locallycloud_cognito::register_with_mailbox(&registry) {
        Ok(handler) => handler,
        Err(error) => {
            tracing::error!(%error, "failed to initialize Cognito confirmation delivery");
            std::process::exit(4);
        }
    };
    gateway_waf.set_cognito_jwks(cognito);
    locallycloud_cloudfront::register(&registry);
    let waf =
        locallycloud_wafv2::WafHandler::new_with_stage_resolver(Arc::new(gateway_waf.clone()));
    gateway_waf.set_waf_evaluator(waf.clone());
    registry.register_native(
        ServiceName::new("wafv2"),
        ServiceMetadata::new(AwsProtocol::Json11, Some("AWSWAF_20190729")),
        waf,
    );
    let cloudtrail = locallycloud_cloudtrail::CloudTrailService::new();
    registry.register_native(
        ServiceName::new("cloudtrail"),
        ServiceMetadata::new(
            AwsProtocol::Json11,
            Some("com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101"),
        ),
        cloudtrail.clone(),
    );
    registry.set_completion_observer(cloudtrail);
    if let Err(error) = locallycloud_cloudwatch_logs::register_with_state(&registry, state.clone())
    {
        tracing::error!(error = %error, "failed to register CloudWatch Logs");
        std::process::exit(4);
    }
    let rds = match locallycloud_rds::register(&registry) {
        Ok(rds) => rds,
        Err(error) => {
            tracing::error!(%error, "failed to register RDS");
            std::process::exit(4);
        }
    };
    rds.attach_ec2(ec2.clone()).await;
    let cluster_resolver = {
        let rds = rds.clone();
        move |account: String, region: String, arn: String| {
            let rds = rds.clone();
            async move {
                rds.resolve_cluster(&account, &region, &arn)
                    .await
                    .map(|cluster| locallycloud_rds_data::PgClusterEndpoint {
                        port: cluster.port,
                        database: cluster.database,
                        username: cluster.username,
                        http_endpoint_enabled: cluster.http_endpoint_enabled,
                        status: cluster.status,
                    })
            }
        }
    };
    let rds_data_config = locallycloud_rds_data::RdsDataConfig {
        state_root: state
            .path()
            .parent()
            .expect("state database has a parent")
            .join("rds-data"),
        ..Default::default()
    };
    let rds_data_handle = match locallycloud_rds_data::register_with_cluster_resolver(
        &registry,
        rds_data_config,
        Some(Arc::new(cluster_resolver)),
    ) {
        Ok(handle) => handle,
        Err(error) => {
            tracing::error!(error = %error, "failed to register RDS Data");
            std::process::exit(5);
        }
    };
    let domain_tls = domain_tls::DomainTls {
        account: config.account_id.clone(),
        gateway: gateway_waf,
        certificates: acm,
    };
    let server = LocallyCloudServer::new(config, registry).with_tls_resolver(Arc::new(domain_tls));

    let restored_lambda = lambda_handler.clone();
    let server_result = server
        .run_with_startup(move || {
            if let Err(error) = ecs_recovery.resume() {
                tracing::error!(%error, "failed to resume durable ECS services");
                std::process::exit(4);
            }
            if let Some(handler) = restored_lambda {
                handler.resume_event_sources();
            }
        })
        .await;
    ecs_runtime.shutdown().await;
    ec2.shutdown().await;
    if let Some(handler) = lambda_handler {
        handler.shutdown().await;
    }
    firehose_handle.shutdown().await;
    rds_data_handle.shutdown().await;
    rds.shutdown().await;
    if let Some(dns) = dns {
        dns.shutdown().await;
    }
    if let Err(err) = server_result {
        tracing::error!(error = %err, "server terminated with error");
        std::process::exit(1);
    }
}
