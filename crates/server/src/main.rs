//! locallycloud binary entry point.
//!
//! Wires observability, configuration, endpoint resolution, compute-runtime selection, the
//! service registry, and the Axum server together, then runs until a shutdown signal.

mod domain_tls;
mod ec2_runtime;
mod ecs_runtime;
mod migration;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Weak};

use locallycloud_compute::selector::{RuntimeKind, RuntimeSelector, SelectionError};
use locallycloud_core::config::{LocallyCloudConfig, RuntimeChoice};
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

struct Ec2AlbNetworkPreflight(Arc<locallycloud_ec2::Ec2Handler>);

impl locallycloud_elbv2::AlbNetworkPreflight for Ec2AlbNetworkPreflight {
    fn reserve(
        &self,
        account: &str,
        region: &str,
        subnet_ids: &[String],
        group_ids: &[String],
    ) -> Option<locallycloud_elbv2::AlbNetworkLease> {
        let lease = self
            .0
            .alb_network_lease(account, region, subnet_ids, group_ids)?;
        Some(locallycloud_elbv2::AlbNetworkLease {
            vpc_id: lease.vpc_id.clone(),
            subnets: lease.subnets.clone(),
            security_groups: lease.security_group_ids.clone(),
            guard: Arc::new(lease),
        })
    }

    fn allows_ingress(
        &self,
        account: &str,
        region: &str,
        group_ids: &[String],
        source: Ipv4Addr,
        port: u16,
    ) -> bool {
        self.0
            .security_groups_allow_ingress(account, region, group_ids, source, port)
    }

    fn allows_target_route(
        &self,
        account: &str,
        region: &str,
        vpc_id: &str,
        source_subnets: &[String],
        target_ip: Ipv4Addr,
    ) -> bool {
        self.0
            .alb_can_reach_target(account, region, vpc_id, source_subnets, target_ip)
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
    observability::init_tracing();

    let config = match LocallyCloudConfig::from_env() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(setting = err.setting, reason = %err.reason, "invalid configuration");
            std::process::exit(2);
        }
    };

    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|argument| argument == "migrate-s3-encryption")
    {
        if arguments.len() != 1 {
            eprintln!("Usage: locallycloud migrate-s3-encryption (uses configured state, account and master key)");
            std::process::exit(2);
        }
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
    let lambda_handler =
        locallycloud_lambda::register_with_execution(&registry, endpoint.guest_endpoint()).await;
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
    if let Err(error) = locallycloud_sqs::register_with_state(&registry, state.clone()) {
        tracing::error!(%error, "failed to register SQS");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_sns::register_with_state(&registry, state.clone()) {
        tracing::error!(%error, "failed to register SNS");
        std::process::exit(4);
    }
    if let Err(error) = locallycloud_eventbridge::register_with_state(&registry, state.clone()) {
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
    let ecr = locallycloud_ecr::register_with_handle(&registry);
    let ec2 = locallycloud_ec2::register_with_instance_runtime(
        &registry,
        Arc::new(ec2_runtime::Ec2OciRuntime::default()),
    );
    if let Some(handler) = &lambda_handler {
        handler.attach_ec2(ec2.clone());
    }
    let ecs_runtime = Arc::new(ecs_runtime::EcsOciRuntime::new(ecr, ec2.clone()));
    locallycloud_ecs::register_with_runtime(&registry, Some(ecs_runtime.clone()));
    locallycloud_elbv2::register_with_alb_integrations(
        &registry,
        Arc::new(Ec2VpcPreflight(ec2.clone())),
        Arc::new(Ec2TargetResolver(ec2.clone())),
        Arc::new(Ec2AlbNetworkPreflight(ec2.clone())),
        Arc::new(locallycloud_elbv2::LoopbackAlbEndpointAllocator::default()),
    );
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
    locallycloud_analytics::register(&registry);
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
