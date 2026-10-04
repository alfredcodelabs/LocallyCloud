//! Resource provisioning: translate a CloudFormation resource into real calls against the
//! owning native service (S3, IAM, Lambda, …) dispatched through the Core registry.
//!
//! The explicit allowlist below is the complete supported resource surface. Every stack entry
//! is validated against it before lifecycle side effects; the provision fallback remains an
//! error as a defensive backstop. `AWS::Logs::LogGroup` and `AWS::Logs::LogStream` are
//! provisioned through the registered native CloudWatch Logs handler so stack status always
//! reflects owning-service state.

use std::sync::Weak;

use base64::Engine;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use serde_json::{json, Value};

use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};

use crate::error::CfnError;
use crate::template::{ResolvedResource, ResourcePolicy};

mod custom_domains;
mod ec2;
pub(crate) use ec2::validate_network_property_names;

/// How an update that changes a resource's physical identity must handle the old instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replacement {
    /// Forward replacement during an update. A `Retain` policy keeps the old physical resource.
    Update(ResourcePolicy),
    /// Rollback of a failed update: restore the previous physical resource (adopting it when the
    /// forward replacement retained it) and delete the physical resource the update created.
    Rollback,
}

/// Complete resource-type surface supported by this provisioner.
pub const SUPPORTED_RESOURCE_TYPES: &[&str] = &[
    "AWS::Route53::HostedZone",
    "AWS::ApiGateway::DomainName",
    "AWS::ApiGateway::BasePathMapping",
    "AWS::ApiGatewayV2::DomainName",
    "AWS::ApiGatewayV2::ApiMapping",
    "AWS::Route53::HealthCheck",
    "AWS::Route53::RecordSet",
    "AWS::S3::Bucket",
    "AWS::S3::BucketPolicy",
    "AWS::SQS::Queue",
    "AWS::SQS::QueuePolicy",
    "AWS::DynamoDB::Table",
    "AWS::DynamoDB::GlobalTable",
    "AWS::Glue::Database",
    "AWS::Glue::Table",
    "AWS::KMS::Key",
    "AWS::KMS::Alias",
    "AWS::SNS::Topic",
    "AWS::SNS::Subscription",
    "AWS::Events::EventBus",
    "AWS::Events::Rule",
    "AWS::Pipes::Pipe",
    "AWS::Logs::LogGroup",
    "AWS::Logs::LogStream",
    "AWS::StepFunctions::StateMachine",
    "AWS::IAM::Role",
    "AWS::Lambda::Function",
    "AWS::Lambda::Version",
    "AWS::Lambda::Permission",
    "AWS::Lambda::EventSourceMapping",
    "AWS::EC2::VPC",
    "AWS::EC2::Subnet",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::RouteTable",
    "AWS::EC2::SubnetRouteTableAssociation",
    "AWS::EC2::VPCEndpoint",
    "AWS::EC2::EIP",
    "AWS::EC2::NatGateway",
    "AWS::EC2::InternetGateway",
    "AWS::EC2::VPCGatewayAttachment",
    "AWS::EC2::Route",
    "AWS::ApiGateway::RestApi",
    "AWS::ApiGateway::Resource",
    "AWS::ApiGateway::Method",
    "AWS::ApiGateway::Deployment",
    "AWS::ApiGatewayV2::Api",
    "AWS::ApiGatewayV2::Integration",
    "AWS::ApiGatewayV2::Route",
    "AWS::ApiGatewayV2::Stage",
];

pub fn is_supported_resource_type(resource_type: &str) -> bool {
    SUPPORTED_RESOURCE_TYPES.contains(&resource_type)
}

pub struct Provisioner {
    registry: Weak<ServiceRegistry>,
    region: String,
    account: String,
    caller_access_key: Option<String>,
}

impl Provisioner {
    pub fn new(registry: Weak<ServiceRegistry>, region: String, account: String) -> Self {
        Provisioner {
            registry,
            region,
            account,
            caller_access_key: None,
        }
    }

    pub(crate) fn with_caller_access_key(mut self, caller_access_key: Option<String>) -> Self {
        self.caller_access_key = caller_access_key;
        self
    }

    /// Provision one resource whose `properties` are already intrinsic-resolved. Returns the
    /// `Ref`/`Fn::GetAtt` facts other resources and outputs resolve against.
    pub async fn provision(
        &self,
        logical_id: &str,
        stack_name: &str,
        resource_type: &str,
        properties: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        match resource_type {
            "AWS::Route53::HostedZone" => {
                self.custom_domain_resource(logical_id, resource_type, properties)
                    .await
            }
            "AWS::ApiGateway::DomainName" => {
                self.custom_domain_resource(logical_id, resource_type, properties)
                    .await
            }
            "AWS::ApiGateway::BasePathMapping" => {
                self.custom_domain_resource(logical_id, resource_type, properties)
                    .await
            }
            "AWS::ApiGatewayV2::DomainName" => {
                self.custom_domain_resource(logical_id, resource_type, properties)
                    .await
            }
            "AWS::ApiGatewayV2::ApiMapping" => {
                self.custom_domain_resource(logical_id, resource_type, properties)
                    .await
            }
            "AWS::Route53::HealthCheck" => self.route53_health_check(logical_id, properties).await,
            "AWS::Route53::RecordSet" => {
                self.route53_record_set(logical_id, properties, "CREATE")
                    .await
            }
            "AWS::S3::Bucket" => self.s3_bucket(logical_id, stack_name, properties).await,
            "AWS::S3::BucketPolicy" => self.s3_bucket_policy(properties).await,
            "AWS::SQS::Queue" => self.sqs_queue(logical_id, stack_name, properties).await,
            "AWS::SQS::QueuePolicy" => {
                self.sqs_queue_policy(logical_id, stack_name, properties)
                    .await
            }
            "AWS::DynamoDB::Table" => {
                self.dynamodb_table(logical_id, stack_name, properties)
                    .await
            }
            "AWS::DynamoDB::GlobalTable" => {
                self.dynamodb_global_table(logical_id, stack_name, properties)
                    .await
            }
            "AWS::Glue::Database" => self.glue_database(logical_id, properties).await,
            "AWS::Glue::Table" => self.glue_table(logical_id, properties).await,
            "AWS::KMS::Key" => self.kms_key(logical_id, properties).await,
            "AWS::KMS::Alias" => self.kms_alias(logical_id, properties).await,
            "AWS::SNS::Topic" => self.sns_topic(logical_id, stack_name, properties).await,
            "AWS::SNS::Subscription" => self.sns_subscription(logical_id, properties).await,
            "AWS::Events::EventBus" => self.events_event_bus(logical_id, properties).await,
            "AWS::Events::Rule" => self.events_rule(logical_id, stack_name, properties).await,
            "AWS::Pipes::Pipe" => self.pipes_pipe(logical_id, stack_name, properties).await,
            "AWS::Logs::LogGroup" => self.logs_group(logical_id, stack_name, properties).await,
            "AWS::Logs::LogStream" => self.logs_stream(logical_id, stack_name, properties).await,
            "AWS::StepFunctions::StateMachine" => {
                self.stepfunctions_state_machine(logical_id, stack_name, properties)
                    .await
            }
            "AWS::IAM::Role" => self.iam_role(logical_id, stack_name, properties).await,
            "AWS::Lambda::Function" => {
                self.lambda_function(logical_id, stack_name, properties)
                    .await
            }
            "AWS::Lambda::Version" => self.lambda_version(properties).await,
            "AWS::Lambda::Permission" => self.lambda_permission(logical_id, properties).await,
            "AWS::Lambda::EventSourceMapping" => {
                self.lambda_event_source_mapping(logical_id, properties)
                    .await
            }
            "AWS::EC2::VPC" => self.ec2_vpc(logical_id, properties).await,
            "AWS::EC2::Subnet" => self.ec2_subnet(logical_id, properties).await,
            "AWS::EC2::SecurityGroup" => {
                self.ec2_security_group(logical_id, stack_name, properties)
                    .await
            }
            "AWS::EC2::RouteTable" => self.ec2_route_table(logical_id, properties).await,
            "AWS::EC2::SubnetRouteTableAssociation" => {
                self.ec2_route_association(logical_id, properties).await
            }
            "AWS::EC2::VPCEndpoint" => self.ec2_vpc_endpoint(logical_id, properties).await,
            "AWS::EC2::EIP" => self.ec2_eip(logical_id, properties).await,
            "AWS::EC2::NatGateway" => self.ec2_nat_gateway(logical_id, properties).await,
            "AWS::EC2::InternetGateway" => self.ec2_internet_gateway(logical_id, properties).await,
            "AWS::EC2::VPCGatewayAttachment" => {
                self.ec2_gateway_attachment(logical_id, properties).await
            }
            "AWS::EC2::Route" => self.ec2_route(logical_id, properties).await,
            "AWS::ApiGateway::RestApi" => self.apigateway_rest_api(logical_id, properties).await,
            "AWS::ApiGateway::Resource" => self.apigateway_resource(logical_id, properties).await,
            "AWS::ApiGateway::Method" => self.apigateway_method(logical_id, properties).await,
            "AWS::ApiGateway::Deployment" => {
                self.apigateway_deployment(logical_id, properties).await
            }
            "AWS::ApiGatewayV2::Api" => self.apigateway_v2_api(logical_id, properties).await,
            "AWS::ApiGatewayV2::Integration" => {
                self.apigateway_v2_integration(logical_id, properties).await
            }
            "AWS::ApiGatewayV2::Route" => self.apigateway_v2_route(logical_id, properties).await,
            "AWS::ApiGatewayV2::Stage" => self.apigateway_v2_stage(logical_id, properties).await,
            other => Err(CfnError::ResourceFailed(format!(
                "resource type {other} is not supported"
            ))),
        }
    }

    /// Apply mutable properties to an existing resource and return its current resolution.
    /// `replacement` governs physical-resource identity changes; resource types without
    /// replacement semantics ignore it.
    pub async fn update(
        &self,
        logical_id: &str,
        resource_type: &str,
        current: &ResolvedResource,
        previous_properties: &Value,
        properties: &Value,
        replacement: Replacement,
    ) -> Result<ResolvedResource, CfnError> {
        match resource_type {
            "AWS::Route53::HostedZone" => {
                self.update_custom_domain_resource(
                    logical_id,
                    resource_type,
                    current,
                    previous_properties,
                    properties,
                )
                .await
            }
            "AWS::ApiGateway::DomainName" => {
                self.update_custom_domain_resource(
                    logical_id,
                    resource_type,
                    current,
                    previous_properties,
                    properties,
                )
                .await
            }
            "AWS::ApiGateway::BasePathMapping" => {
                self.update_custom_domain_resource(
                    logical_id,
                    resource_type,
                    current,
                    previous_properties,
                    properties,
                )
                .await
            }
            "AWS::ApiGatewayV2::DomainName" => {
                self.update_custom_domain_resource(
                    logical_id,
                    resource_type,
                    current,
                    previous_properties,
                    properties,
                )
                .await
            }
            "AWS::ApiGatewayV2::ApiMapping" => {
                self.update_custom_domain_resource(
                    logical_id,
                    resource_type,
                    current,
                    previous_properties,
                    properties,
                )
                .await
            }
            "AWS::EC2::EIP"
            | "AWS::EC2::NatGateway"
            | "AWS::EC2::InternetGateway"
            | "AWS::EC2::VPCGatewayAttachment"
            | "AWS::EC2::Route" => {
                self.update_ec2_network(
                    logical_id,
                    resource_type,
                    current,
                    previous_properties,
                    properties,
                    replacement,
                )
                .await
            }

            "AWS::Route53::HealthCheck" => {
                validate_route53_health_check(logical_id, previous_properties)?;
                validate_route53_health_check(logical_id, properties)?;
                if previous_properties != properties {
                    return Err(CfnError::ResourceFailed(format!(
                        "AWS::Route53::HealthCheck configuration cannot be changed for {logical_id}"
                    )));
                }
                Ok(current.clone())
            }
            "AWS::Route53::RecordSet" => {
                self.update_route53_record_set(
                    logical_id,
                    current,
                    previous_properties,
                    properties,
                    replacement,
                )
                .await
            }
            "AWS::S3::Bucket" => {
                self.update_s3_bucket(
                    logical_id,
                    current,
                    previous_properties,
                    properties,
                    replacement,
                )
                .await
            }
            "AWS::DynamoDB::Table" => {
                self.update_dynamodb_table(logical_id, current, previous_properties, properties)
                    .await
            }
            "AWS::DynamoDB::GlobalTable" => {
                self.update_dynamodb_global_table(
                    logical_id,
                    current,
                    previous_properties,
                    properties,
                )
                .await
            }
            "AWS::Glue::Database" => {
                self.update_glue_database(logical_id, current, previous_properties, properties)
                    .await
            }
            "AWS::Glue::Table" => {
                self.update_glue_table(logical_id, current, previous_properties, properties)
                    .await
            }
            "AWS::KMS::Key" => {
                self.update_kms_key(logical_id, current, previous_properties, properties)
            }
            "AWS::KMS::Alias" => {
                self.update_kms_alias(logical_id, current, previous_properties, properties)
                    .await
            }
            "AWS::SQS::QueuePolicy" => {
                self.update_sqs_queue_policy(logical_id, current, previous_properties, properties)
                    .await
            }
            "AWS::SQS::Queue" => {
                self.update_sqs_queue(
                    logical_id,
                    &current.ref_value,
                    previous_properties,
                    properties,
                )
                .await
            }
            "AWS::SNS::Topic" => {
                self.update_sns_topic(logical_id, current, previous_properties, properties)
                    .await
            }
            "AWS::SNS::Subscription" => {
                self.update_sns_subscription(logical_id, current, previous_properties, properties)
                    .await
            }
            "AWS::Events::EventBus" => {
                self.update_events_event_bus(logical_id, current, previous_properties, properties)
                    .await
            }
            "AWS::Events::Rule" => {
                self.update_events_rule(
                    logical_id,
                    &current.ref_value,
                    previous_properties,
                    properties,
                )
                .await
            }
            "AWS::Pipes::Pipe" => {
                self.update_pipes_pipe(
                    logical_id,
                    &current.ref_value,
                    previous_properties,
                    properties,
                )
                .await
            }
            "AWS::Logs::LogGroup" => {
                self.update_logs_group(logical_id, current, previous_properties, properties)
                    .await
            }
            "AWS::Logs::LogStream" => {
                self.update_logs_stream(logical_id, current, previous_properties, properties)
                    .await
            }
            "AWS::StepFunctions::StateMachine" => {
                self.update_stepfunctions_state_machine(
                    logical_id,
                    current,
                    previous_properties,
                    properties,
                )
                .await
            }
            "AWS::Lambda::Function" => {
                self.update_lambda_function(logical_id, &current.ref_value, properties)
                    .await?;
                Ok(current.clone())
            }
            "AWS::Lambda::Version" => self.lambda_version(properties).await,
            "AWS::Lambda::Permission" => {
                ensure_only_supported_changes(
                    logical_id,
                    resource_type,
                    previous_properties,
                    properties,
                    &[
                        "FunctionName",
                        "Action",
                        "Principal",
                        "SourceArn",
                        "SourceAccount",
                        "EventSourceToken",
                        "FunctionUrlAuthType",
                        "PrincipalOrgID",
                    ],
                )?;
                self.delete_lambda_permission(&current.ref_value).await?;
                self.lambda_permission(logical_id, properties).await
            }
            "AWS::Lambda::EventSourceMapping" => {
                self.update_lambda_event_source_mapping(
                    logical_id,
                    current,
                    previous_properties,
                    properties,
                )
                .await
            }
            "AWS::ApiGateway::RestApi" => {
                self.update_apigateway_rest_api(
                    logical_id,
                    &current.ref_value,
                    previous_properties,
                    properties,
                )
                .await?;
                Ok(current.clone())
            }
            "AWS::ApiGateway::Resource" => {
                ensure_only_supported_changes(
                    logical_id,
                    resource_type,
                    previous_properties,
                    properties,
                    &["RestApiId", "ParentId", "PathPart"],
                )?;
                self.delete_apigateway_resource(&current.ref_value, previous_properties)
                    .await?;
                self.apigateway_resource(logical_id, properties).await
            }
            "AWS::ApiGateway::Method" => {
                ensure_only_supported_changes(
                    logical_id,
                    resource_type,
                    previous_properties,
                    properties,
                    &[
                        "RestApiId",
                        "ResourceId",
                        "HttpMethod",
                        "AuthorizationType",
                        "AuthorizerId",
                        "ApiKeyRequired",
                        "RequestParameters",
                        "RequestModels",
                        "RequestValidatorId",
                        "Integration",
                    ],
                )?;
                let previous_id = apigateway_method_id(previous_properties);
                let next_id = apigateway_method_id(properties);
                if previous_id != next_id {
                    self.delete_apigateway_method(&current.ref_value).await?;
                }
                self.apigateway_method(logical_id, properties).await
            }
            "AWS::ApiGateway::Deployment" => {
                ensure_only_supported_changes(
                    logical_id,
                    resource_type,
                    previous_properties,
                    properties,
                    &["RestApiId", "StageName", "StageDescription", "Description"],
                )?;
                self.delete_apigateway_deployment(&current.ref_value, previous_properties)
                    .await?;
                self.apigateway_deployment(logical_id, properties).await
            }
            "AWS::ApiGatewayV2::Api" => {
                self.update_apigateway_v2_api(
                    logical_id,
                    &current.ref_value,
                    previous_properties,
                    properties,
                )
                .await?;
                Ok(current.clone())
            }
            "AWS::ApiGatewayV2::Integration" => {
                ensure_only_supported_changes(
                    logical_id,
                    resource_type,
                    previous_properties,
                    properties,
                    &[
                        "ApiId",
                        "IntegrationType",
                        "IntegrationUri",
                        "IntegrationMethod",
                        "IntegrationSubtype",
                        "PayloadFormatVersion",
                        "TimeoutInMillis",
                        "RequestParameters",
                    ],
                )?;
                if api_id(previous_properties, "ApiId") != api_id(properties, "ApiId") {
                    self.delete_apigateway_v2_integration(&current.ref_value, previous_properties)
                        .await?;
                    self.apigateway_v2_integration(logical_id, properties).await
                } else {
                    self.update_apigateway_v2_integration(
                        logical_id,
                        &current.ref_value,
                        previous_properties,
                        properties,
                    )
                    .await?;
                    Ok(current.clone())
                }
            }
            "AWS::ApiGatewayV2::Route" => {
                ensure_only_supported_changes(
                    logical_id,
                    resource_type,
                    previous_properties,
                    properties,
                    &[
                        "ApiId",
                        "RouteKey",
                        "Target",
                        "AuthorizationType",
                        "AuthorizerId",
                        "AuthorizationScopes",
                        "ApiKeyRequired",
                    ],
                )?;
                if api_id(previous_properties, "ApiId") != api_id(properties, "ApiId") {
                    self.delete_apigateway_v2_route(&current.ref_value, previous_properties)
                        .await?;
                    self.apigateway_v2_route(logical_id, properties).await
                } else {
                    self.update_apigateway_v2_route(
                        logical_id,
                        &current.ref_value,
                        previous_properties,
                        properties,
                    )
                    .await?;
                    Ok(current.clone())
                }
            }
            "AWS::ApiGatewayV2::Stage" => {
                ensure_only_supported_changes(
                    logical_id,
                    resource_type,
                    previous_properties,
                    properties,
                    &[
                        "ApiId",
                        "StageName",
                        "AutoDeploy",
                        "DeploymentId",
                        "Description",
                        "StageVariables",
                        "DefaultRouteSettings",
                        "AccessLogSettings",
                    ],
                )?;
                let previous_api = api_id(previous_properties, "ApiId");
                let next_api = api_id(properties, "ApiId");
                let previous_name = api_id(previous_properties, "StageName");
                let next_name = api_id(properties, "StageName");
                if previous_api != next_api || previous_name != next_name {
                    self.delete_apigateway_v2_stage(&current.ref_value, previous_properties)
                        .await?;
                    self.apigateway_v2_stage(logical_id, properties).await
                } else {
                    self.update_apigateway_v2_stage(
                        logical_id,
                        &current.ref_value,
                        previous_properties,
                        properties,
                    )
                    .await?;
                    Ok(current.clone())
                }
            }
            _ => Err(CfnError::ResourceFailed(format!(
                "updates for {resource_type} resource {logical_id} are not supported"
            ))),
        }
    }

    /// Tear down one provisioned resource, propagating backend failures to the caller.
    pub async fn deprovision(
        &self,
        resource_type: &str,
        physical_id: &str,
        properties: &Value,
    ) -> Result<(), CfnError> {
        match resource_type {
            "AWS::Route53::HostedZone" => {
                self.delete_custom_domain_resource(resource_type, physical_id, properties)
                    .await
            }
            "AWS::ApiGateway::DomainName" => {
                self.delete_custom_domain_resource(resource_type, physical_id, properties)
                    .await
            }
            "AWS::ApiGateway::BasePathMapping" => {
                self.delete_custom_domain_resource(resource_type, physical_id, properties)
                    .await
            }
            "AWS::ApiGatewayV2::DomainName" => {
                self.delete_custom_domain_resource(resource_type, physical_id, properties)
                    .await
            }
            "AWS::ApiGatewayV2::ApiMapping" => {
                self.delete_custom_domain_resource(resource_type, physical_id, properties)
                    .await
            }
            "AWS::EC2::EIP" => self.delete_ec2_eip(physical_id).await,
            "AWS::EC2::NatGateway" => {
                self.delete_ec2("DeleteNatGateway", "NatGatewayId", physical_id)
                    .await
            }
            "AWS::EC2::InternetGateway" => {
                self.delete_ec2("DeleteInternetGateway", "InternetGatewayId", physical_id)
                    .await
            }
            "AWS::EC2::VPCGatewayAttachment" => {
                self.delete_ec2_gateway_attachment(properties).await
            }
            "AWS::EC2::Route" => self.delete_ec2_route(properties).await,

            "AWS::Route53::HealthCheck" => self.delete_route53_health_check(physical_id).await,
            "AWS::Route53::RecordSet" => {
                self.change_route53_record_set(physical_id, properties, "DELETE")
                    .await
            }
            "AWS::S3::Bucket" => self.delete_bucket(physical_id).await,
            "AWS::S3::BucketPolicy" => self.delete_bucket_policy(physical_id).await,
            "AWS::SQS::Queue" => self.delete_sqs_queue(physical_id).await,
            "AWS::SQS::QueuePolicy" => self.delete_sqs_queue_policy(properties).await,
            "AWS::DynamoDB::Table" => self.delete_dynamodb_table(physical_id).await,
            "AWS::DynamoDB::GlobalTable" => {
                self.delete_dynamodb_global_table(physical_id, properties)
                    .await
            }
            "AWS::Glue::Database" => self.delete_glue_database(physical_id, properties).await,
            "AWS::Glue::Table" => self.delete_glue_table(physical_id, properties).await,
            "AWS::KMS::Key" => self.delete_kms_key(physical_id, properties).await,
            "AWS::KMS::Alias" => self.delete_kms_alias(physical_id).await,
            "AWS::SNS::Topic" => self.delete_sns_topic(physical_id).await,
            "AWS::SNS::Subscription" => self.delete_sns_subscription(physical_id).await,
            "AWS::Events::EventBus" => self.delete_events_event_bus(physical_id).await,
            "AWS::Events::Rule" => self.delete_events_rule(physical_id, properties).await,
            "AWS::Pipes::Pipe" => self.delete_pipes_pipe(physical_id).await,
            "AWS::Logs::LogGroup" => self.delete_logs_group(physical_id).await,
            "AWS::Logs::LogStream" => {
                self.delete_logs_stream(logs_stream_group(properties)?, physical_id)
                    .await
            }
            "AWS::StepFunctions::StateMachine" => {
                self.delete_stepfunctions_state_machine(physical_id).await
            }
            "AWS::IAM::Role" => self.delete_role(physical_id, properties).await,
            "AWS::Lambda::Function" => self.delete_function(physical_id).await,
            // The physical id is only the published-version ARN and the current Lambda backend
            // has no viable version-delete API. Treat teardown as explicitly synthetic.
            "AWS::Lambda::Version" => Ok(()),
            "AWS::Lambda::Permission" => self.delete_lambda_permission(physical_id).await,
            "AWS::Lambda::EventSourceMapping" => {
                self.delete_lambda_event_source_mapping(physical_id).await
            }
            "AWS::EC2::VPC" => self.delete_ec2("DeleteVpc", "VpcId", physical_id).await,
            "AWS::EC2::Subnet" => {
                self.delete_ec2("DeleteSubnet", "SubnetId", physical_id)
                    .await
            }
            "AWS::EC2::SecurityGroup" => {
                self.delete_ec2("DeleteSecurityGroup", "GroupId", physical_id)
                    .await
            }
            "AWS::EC2::RouteTable" => {
                self.delete_ec2("DeleteRouteTable", "RouteTableId", physical_id)
                    .await
            }
            "AWS::EC2::SubnetRouteTableAssociation" => {
                self.delete_ec2("DisassociateRouteTable", "AssociationId", physical_id)
                    .await
            }
            "AWS::EC2::VPCEndpoint" => {
                self.delete_ec2("DeleteVpcEndpoints", "VpcEndpointId.1", physical_id)
                    .await
            }
            "AWS::ApiGateway::RestApi" => self.delete_apigateway_rest_api(physical_id).await,
            "AWS::ApiGateway::Resource" => {
                self.delete_apigateway_resource(physical_id, properties)
                    .await
            }
            "AWS::ApiGateway::Method" => self.delete_apigateway_method(physical_id).await,
            "AWS::ApiGateway::Deployment" => {
                self.delete_apigateway_deployment(physical_id, properties)
                    .await
            }
            "AWS::ApiGatewayV2::Api" => self.delete_apigateway_v2_api(physical_id).await,
            "AWS::ApiGatewayV2::Integration" => {
                self.delete_apigateway_v2_integration(physical_id, properties)
                    .await
            }
            "AWS::ApiGatewayV2::Route" => {
                self.delete_apigateway_v2_route(physical_id, properties)
                    .await
            }
            "AWS::ApiGatewayV2::Stage" => {
                self.delete_apigateway_v2_stage(physical_id, properties)
                    .await
            }
            other => Err(CfnError::ResourceFailed(format!(
                "resource type {other} is not supported"
            ))),
        }
    }

    async fn route53_health_check(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let arn = validate_route53_health_check(logical_id, props)?;
        let xml = format!("<CreateHealthCheckRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><CallerReference>{}</CallerReference><HealthCheckConfig><Type>RECOVERY_CONTROL</Type><RoutingControlArn>{}</RoutingControlArn></HealthCheckConfig></CreateHealthCheckRequest>",
            uuid::Uuid::new_v4(), xml_escape(arn));
        let response = self
            .call_route53(Method::POST, "/2013-04-01/healthcheck", xml, logical_id)
            .await?;
        let id = route53_xml_id(&response, logical_id)?;
        let mut attributes = std::collections::BTreeMap::new();
        attributes.insert("HealthCheckId".into(), id.clone());
        Ok(ResolvedResource {
            ref_value: id,
            attributes,
        })
    }

    async fn delete_route53_health_check(&self, id: &str) -> Result<(), CfnError> {
        self.delete_call("route53", &format!("/2013-04-01/healthcheck/{id}"), id)
            .await
    }

    async fn route53_record_set(
        &self,
        logical_id: &str,
        props: &Value,
        action: &str,
    ) -> Result<ResolvedResource, CfnError> {
        self.change_route53_record_set(logical_id, props, action)
            .await?;
        let name = required_property(props, "Name", logical_id)?;
        Ok(ResolvedResource {
            ref_value: format!("{}.", name.trim_end_matches('.')),
            attributes: Default::default(),
        })
    }

    async fn change_route53_record_set(
        &self,
        logical_id: &str,
        props: &Value,
        action: &str,
    ) -> Result<(), CfnError> {
        let zone = required_property(props, "HostedZoneId", logical_id)?;
        let zone = zone.strip_prefix("/hostedzone/").unwrap_or(&zone);
        if !zone.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(CfnError::Validation(format!(
                "{logical_id} has invalid HostedZoneId"
            )));
        }
        let record = route53_record_xml(logical_id, props)?;
        let xml = format!("<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><ChangeBatch><Changes><Change><Action>{action}</Action>{record}</Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>");
        self.call_route53(
            Method::POST,
            &format!("/2013-04-01/hostedzone/{zone}/rrset"),
            xml,
            logical_id,
        )
        .await?;
        Ok(())
    }

    async fn update_route53_record_set(
        &self,
        logical_id: &str,
        _current: &ResolvedResource,
        previous: &Value,
        next: &Value,
        replacement: Replacement,
    ) -> Result<ResolvedResource, CfnError> {
        route53_record_xml(logical_id, previous)?;
        route53_record_xml(logical_id, next)?;
        let same_identity = ["HostedZoneId", "Name", "Type", "SetIdentifier"]
            .iter()
            .all(|key| previous.get(*key) == next.get(*key));
        if same_identity {
            return self.route53_record_set(logical_id, next, "UPSERT").await;
        }
        if matches!(replacement, Replacement::Update(ResourcePolicy::Retain)) {
            return self.route53_record_set(logical_id, next, "CREATE").await;
        }
        self.change_route53_record_set(logical_id, previous, "DELETE")
            .await?;
        let action = if matches!(replacement, Replacement::Rollback) {
            "UPSERT"
        } else {
            "CREATE"
        };
        match self.route53_record_set(logical_id, next, action).await {
            Ok(new) => Ok(new),
            Err(primary) => match self
                .change_route53_record_set(logical_id, previous, "UPSERT")
                .await
            {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
            },
        }
    }

    async fn call_route53(
        &self,
        method: Method,
        path: &str,
        xml: String,
        logical_id: &str,
    ) -> Result<Bytes, CfnError> {
        let (status, response) = self
            .call("route53", method, path, HeaderMap::new(), Bytes::from(xml))
            .await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "Route53 provisioning for {logical_id} failed ({status}): {}",
                String::from_utf8_lossy(&response)
            )));
        }
        Ok(response)
    }

    // --- resource types -------------------------------------------------------------------

    async fn glue_database(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_glue_database_properties(logical_id, props)?;
        let name = glue_input_name(logical_id, props, "DatabaseInput", "AWS::Glue::Database")?;
        self.call_aws_json_11(
            "glue",
            "AWSGlue.CreateDatabase",
            json!({
                "CatalogId": props["CatalogId"],
                "DatabaseInput": props["DatabaseInput"],
            }),
            logical_id,
        )
        .await?;
        Ok(ResolvedResource {
            ref_value: name.to_string(),
            attributes: Default::default(),
        })
    }

    async fn update_glue_database(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_glue_database_properties(logical_id, previous)?;
        validate_glue_database_properties(logical_id, props)?;
        let previous_name =
            glue_input_name(logical_id, previous, "DatabaseInput", "AWS::Glue::Database")?;
        let next_name = glue_input_name(logical_id, props, "DatabaseInput", "AWS::Glue::Database")?;
        if previous.get("CatalogId") != props.get("CatalogId")
            || previous_name != next_name
            || next_name != current.ref_value
        {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::Glue::Database catalog and name require replacement for {logical_id}"
            )));
        }
        if previous.get("DatabaseInput") != props.get("DatabaseInput") {
            self.call_aws_json_11(
                "glue",
                "AWSGlue.UpdateDatabase",
                json!({
                    "CatalogId": props["CatalogId"],
                    "Name": current.ref_value,
                    "DatabaseInput": props["DatabaseInput"],
                }),
                logical_id,
            )
            .await?;
        }
        Ok(current.clone())
    }

    async fn glue_table(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_glue_table_properties(logical_id, props)?;
        let name = glue_input_name(logical_id, props, "TableInput", "AWS::Glue::Table")?;
        self.call_aws_json_11(
            "glue",
            "AWSGlue.CreateTable",
            json!({
                "CatalogId": props["CatalogId"],
                "DatabaseName": props["DatabaseName"],
                "TableInput": props["TableInput"],
            }),
            logical_id,
        )
        .await?;
        Ok(ResolvedResource {
            ref_value: name.to_string(),
            attributes: Default::default(),
        })
    }

    async fn update_glue_table(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_glue_table_properties(logical_id, previous)?;
        validate_glue_table_properties(logical_id, props)?;
        let previous_name =
            glue_input_name(logical_id, previous, "TableInput", "AWS::Glue::Table")?;
        let next_name = glue_input_name(logical_id, props, "TableInput", "AWS::Glue::Table")?;
        if previous.get("CatalogId") != props.get("CatalogId")
            || previous.get("DatabaseName") != props.get("DatabaseName")
            || previous_name != next_name
            || next_name != current.ref_value
        {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::Glue::Table catalog, database, and name require replacement for {logical_id}"
            )));
        }
        if previous.get("TableInput") != props.get("TableInput") {
            self.call_aws_json_11(
                "glue",
                "AWSGlue.UpdateTable",
                json!({
                    "CatalogId": props["CatalogId"],
                    "DatabaseName": props["DatabaseName"],
                    "TableInput": props["TableInput"],
                }),
                logical_id,
            )
            .await?;
        }
        Ok(current.clone())
    }

    async fn kms_key(&self, logical_id: &str, props: &Value) -> Result<ResolvedResource, CfnError> {
        validate_kms_key_properties(logical_id, props)?;
        let mut body = serde_json::Map::new();
        for property in [
            "Description",
            "KeySpec",
            "KeyUsage",
            "Origin",
            "MultiRegion",
        ] {
            if let Some(value) = props.get(property) {
                body.insert(property.to_string(), value.clone());
            }
        }
        if let Some(policy) = props.get("KeyPolicy") {
            body.insert("Policy".into(), Value::String(policy.to_string()));
        }
        let response = self
            .call_aws_json_11(
                "kms",
                "TrentService.CreateKey",
                Value::Object(body),
                logical_id,
            )
            .await?;
        let metadata = response.get("KeyMetadata").ok_or_else(|| {
            CfnError::ResourceFailed(format!(
                "KMS CreateKey for {logical_id} returned no KeyMetadata"
            ))
        })?;
        let key_id = required_response_string(metadata, "KeyId", logical_id)?;
        let arn = required_response_string(metadata, "Arn", logical_id)?;
        Ok(ResolvedResource {
            ref_value: key_id.clone(),
            attributes: std::collections::BTreeMap::from([
                ("Arn".into(), arn),
                ("KeyId".into(), key_id),
            ]),
        })
    }

    fn update_kms_key(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_kms_key_properties(logical_id, previous)?;
        validate_kms_key_properties(logical_id, props)?;
        ensure_only_supported_changes(
            logical_id,
            "AWS::KMS::Key",
            previous,
            props,
            &["PendingWindowInDays"],
        )?;
        Ok(current.clone())
    }

    async fn kms_alias(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_kms_alias_properties(logical_id, props)?;
        let alias_name = required_property(props, "AliasName", logical_id)?;
        self.call_aws_json_11(
            "kms",
            "TrentService.CreateAlias",
            json!({
                "AliasName": alias_name,
                "TargetKeyId": props["TargetKeyId"],
            }),
            logical_id,
        )
        .await?;
        Ok(ResolvedResource {
            ref_value: alias_name,
            attributes: Default::default(),
        })
    }

    async fn update_kms_alias(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_kms_alias_properties(logical_id, previous)?;
        validate_kms_alias_properties(logical_id, props)?;
        if previous.get("AliasName") != props.get("AliasName")
            || props.get("AliasName").and_then(Value::as_str) != Some(&current.ref_value)
        {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::KMS::Alias name requires replacement for {logical_id}"
            )));
        }
        if previous.get("TargetKeyId") != props.get("TargetKeyId") {
            self.call_aws_json_11(
                "kms",
                "TrentService.UpdateAlias",
                json!({
                    "AliasName": current.ref_value,
                    "TargetKeyId": props["TargetKeyId"],
                }),
                logical_id,
            )
            .await?;
        }
        Ok(current.clone())
    }

    async fn events_event_bus(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_event_bus_properties(logical_id, props)?;
        let name = event_bus_resource_name(props, logical_id)?;
        let mut body = mapped_properties(
            props,
            &[
                ("Name", "Name"),
                ("Description", "Description"),
                ("EventSourceName", "EventSourceName"),
                ("KmsKeyIdentifier", "KmsKeyIdentifier"),
                ("DeadLetterConfig", "DeadLetterConfig"),
                ("LogConfig", "LogConfig"),
                ("Tags", "Tags"),
            ],
        );
        body["Name"] = props["Name"].clone();
        self.call_aws_json("events", "AWSEvents.CreateEventBus", body, logical_id)
            .await?;

        let configure = async {
            if let Some(policy) = props.get("Policy") {
                self.set_event_bus_policy(&name, Some(policy), logical_id)
                    .await?;
            }
            self.describe_event_bus(&name, logical_id).await
        }
        .await;
        match configure {
            Ok(resource) => Ok(resource),
            Err(primary) => match self.delete_events_event_bus(&name).await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
            },
        }
    }

    async fn update_events_event_bus(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_event_bus_properties(logical_id, previous)?;
        validate_event_bus_properties(logical_id, props)?;
        if previous.get("Name") != props.get("Name")
            || previous.get("EventSourceName") != props.get("EventSourceName")
        {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::Events::EventBus name and event source require replacement for {logical_id}"
            )));
        }

        let name = &current.ref_value;
        let mut body = json!({ "Name": name });
        for property in [
            "Description",
            "KmsKeyIdentifier",
            "DeadLetterConfig",
            "LogConfig",
        ] {
            if previous.get(property) != props.get(property) {
                body[property] = props.get(property).cloned().unwrap_or_else(|| {
                    if matches!(property, "Description" | "KmsKeyIdentifier") {
                        Value::String(String::new())
                    } else {
                        Value::Null
                    }
                });
            }
        }
        if body.as_object().is_some_and(|value| value.len() > 1) {
            self.call_aws_json("events", "AWSEvents.UpdateEventBus", body, logical_id)
                .await?;
        }

        if previous.get("Policy") != props.get("Policy") {
            self.set_event_bus_policy(name, props.get("Policy"), logical_id)
                .await?;
        }
        let previous_tags = event_bus_tags(logical_id, previous)?;
        let next_tags = event_bus_tags(logical_id, props)?;
        let arn = current.attributes.get("Arn").ok_or_else(|| {
            CfnError::ResourceFailed(format!(
                "AWS::Events::EventBus resource {logical_id} has no Arn"
            ))
        })?;
        let additions: Vec<Value> = next_tags
            .iter()
            .filter(|(key, value)| previous_tags.get(*key) != Some(*value))
            .map(|(key, value)| json!({ "Key": key, "Value": value }))
            .collect();
        let removals: Vec<Value> = previous_tags
            .keys()
            .filter(|key| !next_tags.contains_key(*key))
            .map(|key| json!(key))
            .collect();
        if !additions.is_empty() {
            self.call_aws_json(
                "events",
                "AWSEvents.TagResource",
                json!({ "ResourceARN": arn, "Tags": additions }),
                logical_id,
            )
            .await?;
        }
        if !removals.is_empty() {
            self.call_aws_json(
                "events",
                "AWSEvents.UntagResource",
                json!({ "ResourceARN": arn, "TagKeys": removals }),
                logical_id,
            )
            .await?;
        }
        self.describe_event_bus(name, logical_id).await
    }

    async fn set_event_bus_policy(
        &self,
        name: &str,
        policy: Option<&Value>,
        logical_id: &str,
    ) -> Result<(), CfnError> {
        match policy {
            Some(policy) => self
                .call_aws_json(
                    "events",
                    "AWSEvents.PutPermission",
                    json!({ "EventBusName": name, "Policy": policy.to_string() }),
                    logical_id,
                )
                .await
                .map(|_| ()),
            None => self
                .call_aws_json(
                    "events",
                    "AWSEvents.RemovePermission",
                    json!({ "EventBusName": name, "RemoveAllPermissions": true }),
                    logical_id,
                )
                .await
                .map(|_| ()),
        }
    }

    async fn describe_event_bus(
        &self,
        name: &str,
        logical_id: &str,
    ) -> Result<ResolvedResource, CfnError> {
        let response = self
            .call_aws_json(
                "events",
                "AWSEvents.DescribeEventBus",
                json!({ "Name": name }),
                logical_id,
            )
            .await?;
        let resolved_name = required_response_string(&response, "Name", logical_id)?;
        let arn = required_response_string(&response, "Arn", logical_id)?;
        let mut attributes = std::collections::BTreeMap::new();
        attributes.insert("Arn".into(), arn);
        attributes.insert("Name".into(), resolved_name.clone());
        Ok(ResolvedResource {
            ref_value: resolved_name,
            attributes,
        })
    }

    async fn dynamodb_table(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_dynamodb_table_properties(logical_id, props)?;
        let table_name = match props.get("TableName") {
            Some(Value::String(name)) if !name.is_empty() => name.clone(),
            Some(_) => {
                return Err(CfnError::Validation(format!(
                    "AWS::DynamoDB::Table resource {logical_id} requires TableName to be a non-empty string when specified"
                )))
            }
            None => generate_name(stack_name, logical_id, 255),
        };

        let mut body = json!({
            "TableName": table_name,
            "AttributeDefinitions": props["AttributeDefinitions"],
            "KeySchema": props["KeySchema"],
            "BillingMode": dynamodb_billing_mode(props),
        });
        for name in ["LocalSecondaryIndexes", "GlobalSecondaryIndexes", "Tags"] {
            if let Some(value) = props.get(name) {
                body[name] = value.clone();
            }
        }
        if let Some(value) = props.get("ProvisionedThroughput") {
            body["ProvisionedThroughput"] = dynamodb_throughput(logical_id, value)?;
        }
        if let Some(value) = props.get("StreamSpecification") {
            body["StreamSpecification"] = dynamodb_stream_specification(logical_id, value)?;
        }

        self.call_aws_json(
            "dynamodb",
            "DynamoDB_20120810.CreateTable",
            body,
            logical_id,
        )
        .await?;

        let configure = async {
            if let Some(specification) = props.get("TimeToLiveSpecification") {
                self.call_aws_json(
                    "dynamodb",
                    "DynamoDB_20120810.UpdateTimeToLive",
                    json!({
                        "TableName": table_name,
                        "TimeToLiveSpecification": specification,
                    }),
                    logical_id,
                )
                .await?;
            }
            if let Some(specification) = props.get("PointInTimeRecoverySpecification") {
                self.call_aws_json(
                    "dynamodb",
                    "DynamoDB_20120810.UpdateContinuousBackups",
                    json!({
                        "TableName": table_name,
                        "PointInTimeRecoverySpecification": specification,
                    }),
                    logical_id,
                )
                .await?;
            }
            Ok::<(), CfnError>(())
        }
        .await;

        if let Err(primary) = configure {
            return match self.delete_dynamodb_table(&table_name).await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
            };
        }

        match self.describe_dynamodb_table(&table_name, logical_id).await {
            Ok(resolution) => Ok(resolution),
            Err(primary) => match self.delete_dynamodb_table(&table_name).await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
            },
        }
    }

    async fn dynamodb_global_table(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let (table_props, replicas) = self.global_table_properties(logical_id, props)?;
        let resolved = self
            .dynamodb_table(logical_id, stack_name, &table_props)
            .await?;
        let mut created: Vec<String> = Vec::new();
        for region in replicas.iter().filter(|region| *region != &self.region) {
            if let Err(primary) = self
                .dynamodb_replica_update(logical_id, &resolved.ref_value, region, true)
                .await
            {
                let mut failure = primary;
                for added in created.iter().rev() {
                    if let Err(cleanup) = self
                        .dynamodb_replica_update(logical_id, &resolved.ref_value, added, false)
                        .await
                    {
                        failure = with_cleanup_failure(failure, cleanup);
                    }
                }
                return match self.delete_dynamodb_table(&resolved.ref_value).await {
                    Ok(()) => Err(failure),
                    Err(cleanup) => Err(with_cleanup_failure(failure, cleanup)),
                };
            }
            created.push((*region).clone());
        }
        self.describe_dynamodb_table(&resolved.ref_value, logical_id)
            .await
    }

    async fn update_dynamodb_global_table(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let (old_table, old_replicas) = self.global_table_properties(logical_id, previous)?;
        let (new_table, new_replicas) = self.global_table_properties(logical_id, props)?;
        if old_table != new_table {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::DynamoDB::GlobalTable {logical_id} only supports changing Replicas"
            )));
        }
        let removed: Vec<_> = old_replicas.difference(&new_replicas).collect();
        let added: Vec<_> = new_replicas.difference(&old_replicas).collect();
        if removed.len() + added.len() > 1 {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::GlobalTable {logical_id} supports one replica change per update"
            )));
        }
        if let Some(region) = removed.first() {
            self.dynamodb_replica_update(logical_id, &current.ref_value, region, false)
                .await?;
        }
        if let Some(region) = added.first() {
            self.dynamodb_replica_update(logical_id, &current.ref_value, region, true)
                .await?;
        }
        self.describe_dynamodb_table(&current.ref_value, logical_id)
            .await
    }

    async fn delete_dynamodb_global_table(
        &self,
        table_name: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        let replicas = self.global_table_replicas("delete", props)?;
        for region in replicas.iter().filter(|region| *region != &self.region) {
            self.dynamodb_replica_update("delete", table_name, region, false)
                .await?;
        }
        self.delete_dynamodb_table(table_name).await
    }

    async fn dynamodb_replica_update(
        &self,
        logical_id: &str,
        table_name: &str,
        region: &str,
        create: bool,
    ) -> Result<(), CfnError> {
        let update = if create {
            json!({"Create": {"RegionName": region}})
        } else {
            json!({"Delete": {"RegionName": region}})
        };
        self.call_aws_json(
            "dynamodb",
            "DynamoDB_20120810.UpdateTable",
            json!({"TableName": table_name, "ReplicaUpdates": [update]}),
            logical_id,
        )
        .await?;
        Ok(())
    }

    fn global_table_properties(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<(Value, std::collections::BTreeSet<String>), CfnError> {
        ensure_known_properties(
            logical_id,
            "AWS::DynamoDB::GlobalTable",
            props,
            &[
                "TableName",
                "AttributeDefinitions",
                "KeySchema",
                "BillingMode",
                "Replicas",
                "StreamSpecification",
                "MultiRegionConsistency",
            ],
        )?;
        if props.get("BillingMode").and_then(Value::as_str) != Some("PAY_PER_REQUEST") {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::GlobalTable {logical_id} requires PAY_PER_REQUEST billing"
            )));
        }
        if props
            .get("MultiRegionConsistency")
            .is_some_and(|v| v.as_str() != Some("EVENTUAL"))
        {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::GlobalTable {logical_id} supports only EVENTUAL consistency"
            )));
        }
        let replicas = self.global_table_replicas(logical_id, props)?;
        if replicas.len() > 1
            && props
                .get("StreamSpecification")
                .and_then(|v| v.get("StreamViewType"))
                .and_then(Value::as_str)
                != Some("NEW_AND_OLD_IMAGES")
        {
            return Err(CfnError::Validation(format!("AWS::DynamoDB::GlobalTable {logical_id} requires NEW_AND_OLD_IMAGES StreamSpecification for multiple replicas")));
        }
        let mut table = props.clone();
        table
            .as_object_mut()
            .ok_or_else(|| {
                CfnError::Validation(format!(
                    "AWS::DynamoDB::GlobalTable {logical_id} Properties must be an object"
                ))
            })?
            .remove("Replicas");
        table
            .as_object_mut()
            .unwrap()
            .remove("MultiRegionConsistency");
        validate_dynamodb_table_properties(logical_id, &table)?;
        Ok((table, replicas))
    }

    fn global_table_replicas(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<std::collections::BTreeSet<String>, CfnError> {
        let entries = props
            .get("Replicas")
            .and_then(Value::as_array)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                CfnError::Validation(format!(
                    "AWS::DynamoDB::GlobalTable {logical_id} requires Replicas"
                ))
            })?;
        let mut regions = std::collections::BTreeSet::new();
        for entry in entries {
            let object = entry.as_object().ok_or_else(|| {
                CfnError::Validation(format!(
                    "AWS::DynamoDB::GlobalTable {logical_id} requires Replica objects"
                ))
            })?;
            if object.len() != 1 {
                return Err(CfnError::Validation(format!(
                    "AWS::DynamoDB::GlobalTable {logical_id} supports only Replica.Region"
                )));
            }
            let region = object
                .get("Region")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    CfnError::Validation(format!(
                        "AWS::DynamoDB::GlobalTable {logical_id} requires Replica.Region"
                    ))
                })?;
            if !regions.insert(region.to_string()) {
                return Err(CfnError::Validation(format!(
                    "AWS::DynamoDB::GlobalTable {logical_id} has duplicate replica region"
                )));
            }
        }
        if !regions.contains(&self.region) {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::GlobalTable {logical_id} must include stack region {}",
                self.region
            )));
        }
        Ok(regions)
    }

    async fn update_dynamodb_table(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_dynamodb_table_properties(logical_id, previous)?;
        validate_dynamodb_table_properties(logical_id, props)?;
        validate_dynamodb_ttl_update(logical_id, previous, props)?;
        ensure_only_supported_changes(
            logical_id,
            "AWS::DynamoDB::Table",
            previous,
            props,
            &[
                "BillingMode",
                "ProvisionedThroughput",
                "StreamSpecification",
                "TimeToLiveSpecification",
                "PointInTimeRecoverySpecification",
                "Tags",
            ],
        )?;

        let table_name = &current.ref_value;
        let previous_billing = dynamodb_billing_mode(previous);
        let next_billing = dynamodb_billing_mode(props);
        let mut update = json!({ "TableName": table_name });
        if previous_billing != next_billing {
            update["BillingMode"] = json!(next_billing);
            if next_billing == "PROVISIONED" {
                update["ProvisionedThroughput"] = dynamodb_throughput(
                    logical_id,
                    props.get("ProvisionedThroughput").expect("validated above"),
                )?;
            }
        } else if previous.get("ProvisionedThroughput") != props.get("ProvisionedThroughput") {
            update["ProvisionedThroughput"] = dynamodb_throughput(
                logical_id,
                props.get("ProvisionedThroughput").expect("validated above"),
            )?;
        }
        if previous.get("StreamSpecification") != props.get("StreamSpecification") {
            update["StreamSpecification"] = match props.get("StreamSpecification") {
                Some(value) => dynamodb_stream_specification(logical_id, value)?,
                None => json!({ "StreamEnabled": false }),
            };
        }
        if update.as_object().is_some_and(|body| body.len() > 1) {
            self.call_aws_json(
                "dynamodb",
                "DynamoDB_20120810.UpdateTable",
                update,
                logical_id,
            )
            .await?;
        }

        if previous.get("TimeToLiveSpecification") != props.get("TimeToLiveSpecification") {
            let specification = props
                .get("TimeToLiveSpecification")
                .cloned()
                .unwrap_or_else(|| {
                    json!({
                        "Enabled": false,
                        "AttributeName": previous
                            .get("TimeToLiveSpecification")
                            .and_then(|value| value.get("AttributeName"))
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    })
                });
            self.call_aws_json(
                "dynamodb",
                "DynamoDB_20120810.UpdateTimeToLive",
                json!({
                    "TableName": table_name,
                    "TimeToLiveSpecification": specification,
                }),
                logical_id,
            )
            .await?;
        }

        if previous.get("PointInTimeRecoverySpecification")
            != props.get("PointInTimeRecoverySpecification")
        {
            let specification = props
                .get("PointInTimeRecoverySpecification")
                .cloned()
                .unwrap_or_else(|| json!({ "PointInTimeRecoveryEnabled": false }));
            self.call_aws_json(
                "dynamodb",
                "DynamoDB_20120810.UpdateContinuousBackups",
                json!({
                    "TableName": table_name,
                    "PointInTimeRecoverySpecification": specification,
                }),
                logical_id,
            )
            .await?;
        }

        let previous_tags = dynamodb_tags(logical_id, previous)?;
        let next_tags = dynamodb_tags(logical_id, props)?;
        let additions: Vec<Value> = next_tags
            .iter()
            .filter(|(key, value)| previous_tags.get(*key) != Some(*value))
            .map(|(key, value)| json!({ "Key": key, "Value": value }))
            .collect();
        let removals: Vec<Value> = previous_tags
            .keys()
            .filter(|key| !next_tags.contains_key(*key))
            .map(|key| json!(key))
            .collect();
        let resource_arn = format!(
            "arn:aws:dynamodb:{}:{}:table/{table_name}",
            self.region, self.account
        );
        if !additions.is_empty() {
            self.call_aws_json(
                "dynamodb",
                "DynamoDB_20120810.TagResource",
                json!({ "ResourceArn": resource_arn, "Tags": additions }),
                logical_id,
            )
            .await?;
        }
        if !removals.is_empty() {
            self.call_aws_json(
                "dynamodb",
                "DynamoDB_20120810.UntagResource",
                json!({ "ResourceArn": resource_arn, "TagKeys": removals }),
                logical_id,
            )
            .await?;
        }

        self.describe_dynamodb_table(table_name, logical_id).await
    }

    async fn describe_dynamodb_table(
        &self,
        table_name: &str,
        logical_id: &str,
    ) -> Result<ResolvedResource, CfnError> {
        let response = self
            .call_aws_json(
                "dynamodb",
                "DynamoDB_20120810.DescribeTable",
                json!({ "TableName": table_name }),
                logical_id,
            )
            .await?;
        dynamodb_table_resolution(&response, table_name, logical_id)
    }

    async fn delete_dynamodb_table(&self, table_name: &str) -> Result<(), CfnError> {
        let mut headers = json_host();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_static("DynamoDB_20120810.DeleteTable"),
        );
        let (status, response) = self
            .call(
                "dynamodb",
                Method::POST,
                "/",
                headers,
                Bytes::from(json!({ "TableName": table_name }).to_string()),
            )
            .await?;
        if (200..300).contains(&status) || dynamodb_resource_not_found(status, &response) {
            return Ok(());
        }
        Err(CfnError::ResourceFailed(format!(
            "dynamodb deletion for {table_name} failed ({status}): {}",
            String::from_utf8_lossy(&response)
        )))
    }

    async fn sqs_queue_policy(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_sqs_queue_policy(logical_id, props)?;
        let queues = sqs_queue_policy_queues(logical_id, props)?;
        let policy = sqs_queue_policy_document(logical_id, props)?;
        let mut applied = Vec::new();
        for queue_url in queues {
            if let Err(primary) = self
                .set_sqs_queue_policy(queue_url, &policy, logical_id, false)
                .await
            {
                return match self.rollback_sqs_queue_policies(&applied, logical_id).await {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
                };
            }
            applied.push((queue_url.to_string(), None));
        }
        Ok(ResolvedResource {
            ref_value: generate_name(stack_name, logical_id, 80),
            attributes: Default::default(),
        })
    }

    async fn update_sqs_queue_policy(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_sqs_queue_policy(logical_id, previous)?;
        validate_sqs_queue_policy(logical_id, props)?;
        let previous_queues = sqs_queue_policy_queues(logical_id, previous)?;
        let next_queues = sqs_queue_policy_queues(logical_id, props)?;
        let previous_policy = sqs_queue_policy_document(logical_id, previous)?;
        let next_policy = sqs_queue_policy_document(logical_id, props)?;
        let previous_set: std::collections::BTreeSet<&str> =
            previous_queues.iter().copied().collect();
        let next_set: std::collections::BTreeSet<&str> = next_queues.iter().copied().collect();
        let mut changes: Vec<(&str, &str, Option<String>)> = previous_set
            .difference(&next_set)
            .map(|queue_url| (*queue_url, "", Some(previous_policy.clone())))
            .collect();
        changes.extend(next_queues.iter().map(|queue_url| {
            (
                *queue_url,
                next_policy.as_str(),
                previous_set
                    .contains(queue_url)
                    .then(|| previous_policy.clone()),
            )
        }));

        let mut applied = Vec::new();
        for (queue_url, policy, rollback) in changes {
            if let Err(primary) = self
                .set_sqs_queue_policy(queue_url, policy, logical_id, false)
                .await
            {
                return match self.rollback_sqs_queue_policies(&applied, logical_id).await {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
                };
            }
            applied.push((queue_url.to_string(), rollback));
        }
        Ok(current.clone())
    }

    async fn delete_sqs_queue_policy(&self, props: &Value) -> Result<(), CfnError> {
        let logical_id = "AWS::SQS::QueuePolicy";
        validate_sqs_queue_policy(logical_id, props)?;
        let mut failures = Vec::new();
        for queue_url in sqs_queue_policy_queues(logical_id, props)? {
            if let Err(error) = self
                .set_sqs_queue_policy(queue_url, "", logical_id, true)
                .await
            {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(CfnError::ResourceFailed(format!(
                "SQS QueuePolicy deletion failed: {}",
                failures.join("; ")
            )))
        }
    }

    async fn rollback_sqs_queue_policies(
        &self,
        applied: &[(String, Option<String>)],
        logical_id: &str,
    ) -> Result<(), CfnError> {
        let mut failures = Vec::new();
        for (queue_url, policy) in applied.iter().rev() {
            if let Err(error) = self
                .set_sqs_queue_policy(
                    queue_url,
                    policy.as_deref().unwrap_or_default(),
                    logical_id,
                    true,
                )
                .await
            {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(CfnError::ResourceFailed(failures.join("; ")))
        }
    }

    async fn set_sqs_queue_policy(
        &self,
        queue_url: &str,
        policy: &str,
        logical_id: &str,
        ignore_missing: bool,
    ) -> Result<(), CfnError> {
        let mut headers = json_host();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_static("AmazonSQS.SetQueueAttributes"),
        );
        let (status, response) = self
            .call(
                "sqs",
                Method::POST,
                "/",
                headers,
                Bytes::from(
                    json!({
                        "QueueUrl": queue_url,
                        "Attributes": { "Policy": policy },
                    })
                    .to_string(),
                ),
            )
            .await?;
        if (200..300).contains(&status)
            || (ignore_missing && sqs_queue_does_not_exist(status, &response))
        {
            return Ok(());
        }
        Err(CfnError::ResourceFailed(format!(
            "SQS QueuePolicy for {logical_id} failed on {queue_url} ({status}): {}",
            String::from_utf8_lossy(&response)
        )))
    }

    async fn sqs_queue(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let fifo = props
            .get("FifoQueue")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let name = props
            .get("QueueName")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
                let mut generated =
                    generate_name(stack_name, logical_id, if fifo { 75 } else { 80 });
                if fifo {
                    generated.push_str(".fifo");
                }
                generated
            });
        let mut body = json!({"QueueName": name});
        let attributes = sqs_attributes(props);
        if !attributes.is_empty() {
            body["Attributes"] = Value::Object(attributes);
        }
        let tags = cfn_tags_object(props);
        if !tags.is_empty() {
            body["Tags"] = Value::Object(tags);
        }
        let response = self
            .call_aws_json("sqs", "AmazonSQS.CreateQueue", body, logical_id)
            .await?;
        let queue_url = required_response_string(&response, "QueueUrl", logical_id)?;
        Ok(self.sqs_resolution(queue_url, &name))
    }

    async fn update_sqs_queue(
        &self,
        logical_id: &str,
        queue_url: &str,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_only_supported_changes(
            logical_id,
            "AWS::SQS::Queue",
            previous,
            props,
            &[
                "DelaySeconds",
                "MaximumMessageSize",
                "MessageRetentionPeriod",
                "ReceiveMessageWaitTimeSeconds",
                "VisibilityTimeout",
                "RedrivePolicy",
                "RedriveAllowPolicy",
                "ContentBasedDeduplication",
                "DeduplicationScope",
                "FifoThroughputLimit",
                "KmsDataKeyReusePeriodSeconds",
                "KmsMasterKeyId",
                "SqsManagedSseEnabled",
            ],
        )?;
        if previous.get("QueueName") != props.get("QueueName")
            || previous.get("FifoQueue") != props.get("FifoQueue")
        {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::SQS::Queue name and FIFO mode require replacement for {logical_id}"
            )));
        }
        let attributes = sqs_attributes(props);
        if !attributes.is_empty() {
            self.call_aws_json(
                "sqs",
                "AmazonSQS.SetQueueAttributes",
                json!({"QueueUrl": queue_url, "Attributes": attributes}),
                logical_id,
            )
            .await?;
        }
        let name = queue_url.rsplit('/').next().unwrap_or(logical_id);
        Ok(self.sqs_resolution(queue_url.to_string(), name))
    }

    fn sqs_resolution(&self, queue_url: String, name: &str) -> ResolvedResource {
        let mut attributes = std::collections::BTreeMap::new();
        attributes.insert(
            "Arn".into(),
            format!("arn:aws:sqs:{}:{}:{name}", self.region, self.account),
        );
        attributes.insert("QueueName".into(), name.to_string());
        ResolvedResource {
            ref_value: queue_url,
            attributes,
        }
    }

    async fn sns_topic(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(
            logical_id,
            "AWS::SNS::Topic",
            props,
            &[
                "TopicName",
                "DisplayName",
                "FifoTopic",
                "ContentBasedDeduplication",
                "KmsMasterKeyId",
                "SignatureVersion",
                "DeliveryPolicy",
                "Tags",
            ],
        )?;
        let fifo = props
            .get("FifoTopic")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let name = props
            .get("TopicName")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
                let mut generated =
                    generate_name(stack_name, logical_id, if fifo { 251 } else { 256 });
                if fifo {
                    generated.push_str(".fifo");
                }
                generated
            });
        let mut body = json!({"Name": name});
        let attributes = sns_topic_attributes(props);
        if !attributes.is_empty() {
            body["Attributes"] = Value::Object(attributes);
        }
        if let Some(tags) = props.get("Tags") {
            body["Tags"] = tags.clone();
        }
        let response = self
            .call_aws_json(
                "sns",
                "AmazonSimpleNotificationService.CreateTopic",
                body,
                logical_id,
            )
            .await?;
        let arn = required_response_string(&response, "TopicArn", logical_id)?;
        let mut attributes = std::collections::BTreeMap::new();
        attributes.insert("Arn".into(), arn.clone());
        attributes.insert("TopicName".into(), name);
        Ok(ResolvedResource {
            ref_value: arn,
            attributes,
        })
    }

    async fn update_sns_topic(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_only_supported_changes(
            logical_id,
            "AWS::SNS::Topic",
            previous,
            props,
            &[
                "TopicName",
                "DisplayName",
                "FifoTopic",
                "ContentBasedDeduplication",
                "KmsMasterKeyId",
                "SignatureVersion",
                "DeliveryPolicy",
                "Tags",
            ],
        )?;
        if previous.get("TopicName") != props.get("TopicName")
            || previous.get("FifoTopic") != props.get("FifoTopic")
        {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::SNS::Topic name and FIFO mode require replacement for {logical_id}"
            )));
        }
        let previous_attributes = sns_topic_attributes(previous);
        let next_attributes = sns_topic_attributes(props);
        for name in [
            "DisplayName",
            "ContentBasedDeduplication",
            "KmsMasterKeyId",
            "SignatureVersion",
            "DeliveryPolicy",
        ] {
            if previous_attributes.get(name) != next_attributes.get(name) {
                let value = next_attributes
                    .get(name)
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                self.call_aws_json(
                    "sns",
                    "AmazonSimpleNotificationService.SetTopicAttributes",
                    json!({
                        "TopicArn": current.ref_value,
                        "AttributeName": name,
                        "AttributeValue": value
                    }),
                    logical_id,
                )
                .await?;
            }
        }
        if previous.get("Tags") != props.get("Tags") {
            let previous_tags = cfn_tags_object(previous);
            let next_tags = cfn_tags_object(props);
            let removed: Vec<Value> = previous_tags
                .keys()
                .filter(|key| !next_tags.contains_key(*key))
                .cloned()
                .map(Value::String)
                .collect();
            if !removed.is_empty() {
                self.call_aws_json(
                    "sns",
                    "AmazonSimpleNotificationService.UntagResource",
                    json!({"ResourceArn": current.ref_value, "TagKeys": removed}),
                    logical_id,
                )
                .await?;
            }
            if let Some(tags) = props.get("Tags").filter(|value| value.is_array()) {
                self.call_aws_json(
                    "sns",
                    "AmazonSimpleNotificationService.TagResource",
                    json!({"ResourceArn": current.ref_value, "Tags": tags}),
                    logical_id,
                )
                .await?;
            }
        }
        Ok(current.clone())
    }

    async fn sns_subscription(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(
            logical_id,
            "AWS::SNS::Subscription",
            props,
            &[
                "TopicArn",
                "Protocol",
                "Endpoint",
                "RawMessageDelivery",
                "FilterPolicy",
                "FilterPolicyScope",
                "RedrivePolicy",
                "DeliveryPolicy",
                "Region",
            ],
        )?;
        if props
            .get("Region")
            .and_then(Value::as_str)
            .is_some_and(|region| region != self.region)
        {
            return Err(CfnError::ResourceFailed(format!(
                "cross-region AWS::SNS::Subscription is not supported for {logical_id}"
            )));
        }
        let topic_arn = required_property(props, "TopicArn", logical_id)?;
        let protocol = required_property(props, "Protocol", logical_id)?;
        let endpoint = required_property(props, "Endpoint", logical_id)?;
        let mut body = json!({
            "TopicArn": topic_arn,
            "Protocol": protocol,
            "Endpoint": endpoint,
            "ReturnSubscriptionArn": "true"
        });
        let attributes = sns_subscription_attributes(props);
        if !attributes.is_empty() {
            body["Attributes"] = Value::Object(attributes);
        }
        let response = self
            .call_aws_json(
                "sns",
                "AmazonSimpleNotificationService.Subscribe",
                body,
                logical_id,
            )
            .await?;
        let arn = required_response_string(&response, "SubscriptionArn", logical_id)?;
        Ok(ResolvedResource {
            ref_value: arn,
            attributes: Default::default(),
        })
    }

    async fn update_sns_subscription(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_only_supported_changes(
            logical_id,
            "AWS::SNS::Subscription",
            previous,
            props,
            &[
                "TopicArn",
                "Protocol",
                "Endpoint",
                "RawMessageDelivery",
                "FilterPolicy",
                "FilterPolicyScope",
                "RedrivePolicy",
                "DeliveryPolicy",
                "Region",
            ],
        )?;
        if ["TopicArn", "Protocol", "Endpoint", "Region"]
            .iter()
            .any(|name| previous.get(name) != props.get(name))
        {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::SNS::Subscription target changes require replacement for {logical_id}"
            )));
        }
        let previous_attributes = sns_subscription_attributes(previous);
        let next_attributes = sns_subscription_attributes(props);
        for name in [
            "RawMessageDelivery",
            "FilterPolicy",
            "FilterPolicyScope",
            "RedrivePolicy",
            "DeliveryPolicy",
        ] {
            if previous_attributes.get(name) != next_attributes.get(name) {
                let value = next_attributes
                    .get(name)
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                self.call_aws_json(
                    "sns",
                    "AmazonSimpleNotificationService.SetSubscriptionAttributes",
                    json!({
                        "SubscriptionArn": current.ref_value,
                        "AttributeName": name,
                        "AttributeValue": value
                    }),
                    logical_id,
                )
                .await?;
            }
        }
        Ok(current.clone())
    }

    async fn events_rule(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let name = props
            .get("Name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| generate_name(stack_name, logical_id, 64));
        match self.put_events_rule(logical_id, &name, props).await {
            Ok(resource) => Ok(resource),
            Err(error) => match self.delete_events_rule(&name, props).await {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(with_cleanup_failure(error, cleanup_error)),
            },
        }
    }

    async fn update_events_rule(
        &self,
        logical_id: &str,
        name: &str,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_only_supported_changes(
            logical_id,
            "AWS::Events::Rule",
            previous,
            props,
            &[
                "Description",
                "EventPattern",
                "RoleArn",
                "ScheduleExpression",
                "State",
                "Targets",
            ],
        )?;
        if previous.get("Name") != props.get("Name")
            || event_bus_name(previous) != event_bus_name(props)
        {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::Events::Rule name and event bus require replacement for {logical_id}"
            )));
        }
        let resource = self.put_events_rule(logical_id, name, props).await?;
        let next_ids = event_target_ids(props);
        let removed: Vec<_> = event_target_ids(previous)
            .into_iter()
            .filter(|id| !next_ids.contains(id))
            .map(Value::String)
            .collect();
        if !removed.is_empty() {
            self.call_aws_json(
                "events",
                "AWSEvents.RemoveTargets",
                json!({
                    "Rule": name,
                    "EventBusName": event_bus_name(props),
                    "Ids": removed,
                }),
                logical_id,
            )
            .await?;
        }
        Ok(resource)
    }

    async fn put_events_rule(
        &self,
        logical_id: &str,
        name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let mut body = serde_json::Map::new();
        body.insert("Name".into(), Value::String(name.to_string()));
        body.insert("EventBusName".into(), Value::String(event_bus_name(props)));
        for property in [
            "Description",
            "RoleArn",
            "ScheduleExpression",
            "State",
            "Tags",
        ] {
            if let Some(value) = props.get(property) {
                body.insert(property.to_string(), value.clone());
            }
        }
        if let Some(pattern) = props.get("EventPattern") {
            body.insert("EventPattern".into(), Value::String(pattern.to_string()));
        }
        let response = self
            .call_aws_json(
                "events",
                "AWSEvents.PutRule",
                Value::Object(body),
                logical_id,
            )
            .await?;
        let arn = required_response_string(&response, "RuleArn", logical_id)?;

        if let Some(targets) = props.get("Targets").and_then(Value::as_array) {
            if !targets.is_empty() {
                let result = self
                    .call_aws_json(
                        "events",
                        "AWSEvents.PutTargets",
                        json!({
                            "Rule": name,
                            "EventBusName": event_bus_name(props),
                            "Targets": targets,
                        }),
                        logical_id,
                    )
                    .await?;
                if result
                    .get("FailedEntryCount")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    != 0
                {
                    return Err(CfnError::ResourceFailed(format!(
                        "EventBridge PutTargets for {logical_id} failed: {result}"
                    )));
                }
            }
        }

        let mut attributes = std::collections::BTreeMap::new();
        attributes.insert("Arn".into(), arn);
        Ok(ResolvedResource {
            ref_value: name.to_string(),
            attributes,
        })
    }

    async fn pipes_pipe(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let name = props
            .get("Name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| generate_name(stack_name, logical_id, 64));
        let result = async {
            let response = self
                .call_json(
                    "pipes",
                    Method::POST,
                    &format!("/v1/pipes/{name}"),
                    pipe_body(props),
                    logical_id,
                )
                .await?;
            pipe_resolution(&response, &name, logical_id)
        }
        .await;
        match result {
            Ok(resource) => Ok(resource),
            Err(error) => match self.delete_pipes_pipe(&name).await {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(with_cleanup_failure(error, cleanup_error)),
            },
        }
    }

    async fn update_pipes_pipe(
        &self,
        logical_id: &str,
        name: &str,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        if previous.get("Name") != props.get("Name")
            || previous.get("Source") != props.get("Source")
        {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::Pipes::Pipe name and source require replacement for {logical_id}"
            )));
        }
        ensure_only_supported_changes(
            logical_id,
            "AWS::Pipes::Pipe",
            previous,
            props,
            &[
                "Description",
                "DesiredState",
                "Enrichment",
                "EnrichmentParameters",
                "RoleArn",
                "SourceParameters",
                "Target",
                "TargetParameters",
            ],
        )?;
        let response = self
            .call_json(
                "pipes",
                Method::PUT,
                &format!("/v1/pipes/{name}"),
                pipe_body(props),
                logical_id,
            )
            .await?;
        pipe_resolution(&response, name, logical_id)
    }

    async fn s3_bucket(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_s3_bucket_properties(logical_id, props)?;
        let name = self.s3_bucket_name(props, stack_name, logical_id);
        let (status, body) = self
            .call(
                "s3",
                Method::PUT,
                &format!("/{name}"),
                s3_bucket_headers(props),
                Bytes::new(),
            )
            .await?;
        // A taken name is a hard failure: CloudFormation never adopts a bucket it did not
        // create, so retried deployments of retained names surface `AlreadyExists`.
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "S3 CreateBucket for {logical_id} failed ({status}): {}",
                String::from_utf8_lossy(&body)
            )));
        }
        if let Err(primary) = self
            .reconcile_s3_bucket_configuration(logical_id, &name, None, props)
            .await
        {
            return match self.delete_bucket(&name).await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
            };
        }
        Ok(Self::s3_resolution(&name, &self.region))
    }

    fn s3_bucket_name(&self, props: &Value, stack_name: &str, logical_id: &str) -> String {
        if let Some(name) = props.get("BucketName").and_then(Value::as_str) {
            return name.to_string();
        }
        let regional =
            props.get("BucketNamespace").and_then(Value::as_str) == Some("account-regional");
        let suffix = format!("-{}-{}-an", self.account, self.region);
        let prefix = props
            .get("BucketNamePrefix")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
                generate_name(
                    stack_name,
                    logical_id,
                    if regional { 63 - suffix.len() } else { 63 },
                )
                .trim_end_matches('-')
                .to_string()
            });
        if regional {
            format!("{prefix}{suffix}")
        } else {
            prefix
        }
    }

    async fn update_s3_bucket(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
        replacement: Replacement,
    ) -> Result<ResolvedResource, CfnError> {
        validate_s3_bucket_properties(logical_id, previous)?;
        validate_s3_bucket_properties(logical_id, props)?;
        if previous.get("BucketName") != props.get("BucketName")
            || previous.get("BucketNamePrefix") != props.get("BucketNamePrefix")
            || previous.get("BucketNamespace") != props.get("BucketNamespace")
            || self.s3_bucket_name(props, "", logical_id) != current.ref_value
                && (props.get("BucketName").is_some() || props.get("BucketNamePrefix").is_some())
        {
            return self
                .replace_s3_bucket(logical_id, &current.ref_value, props, replacement)
                .await;
        }
        self.reconcile_s3_bucket_configuration(
            logical_id,
            &current.ref_value,
            Some(previous),
            props,
        )
        .await?;
        Ok(current.clone())
    }

    async fn replace_s3_bucket(
        &self,
        logical_id: &str,
        old_name: &str,
        props: &Value,
        replacement: Replacement,
    ) -> Result<ResolvedResource, CfnError> {
        let new_name =
            if props.get("BucketName").is_some() || props.get("BucketNamePrefix").is_some() {
                self.s3_bucket_name(props, "", logical_id)
            } else {
                return Err(CfnError::ResourceFailed(format!(
                    "AWS::S3::Bucket BucketName requires replacement for {logical_id}"
                )));
            };
        let (status, body) = self
            .call(
                "s3",
                Method::PUT,
                &format!("/{new_name}"),
                s3_bucket_headers(props),
                Bytes::new(),
            )
            .await?;
        let target_preexisting = if status == 409 {
            match replacement {
                // Rollback re-adopts the old physical resource when the forward replacement
                // retained it; a forward replacement must never take over a taken name.
                Replacement::Rollback => true,
                Replacement::Update(_) => {
                    return Err(CfnError::ResourceFailed(format!(
                        "S3 CreateBucket for {logical_id} failed (409): {}",
                        String::from_utf8_lossy(&body)
                    )))
                }
            }
        } else if (200..300).contains(&status) {
            false
        } else {
            return Err(CfnError::ResourceFailed(format!(
                "S3 CreateBucket for {logical_id} failed ({status}): {}",
                String::from_utf8_lossy(&body)
            )));
        };
        if let Err(primary) = self
            .reconcile_s3_bucket_configuration(logical_id, &new_name, None, props)
            .await
        {
            if !target_preexisting {
                if let Err(cleanup) = self.delete_bucket(&new_name).await {
                    return Err(with_cleanup_failure(primary, cleanup));
                }
            }
            return Err(primary);
        }
        // Only a forward replacement with `Retain` keeps the old physical bucket. On rollback
        // the source is the physical resource created by the failed update and must go.
        if !matches!(replacement, Replacement::Update(ResourcePolicy::Retain)) {
            if let Err(primary) = self.delete_bucket(old_name).await {
                let primary = CfnError::ResourceFailed(format!(
                    "S3 DeleteBucket for {logical_id} failed: {primary}"
                ));
                // The replacement created the target before the source delete failed: remove
                // it so the stack keeps its pre-update physical state. A preexisting target
                // was never created by this action and must never be deleted.
                if target_preexisting {
                    return Err(primary);
                }
                return match self.delete_bucket(&new_name).await {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
                };
            }
        }
        Ok(Self::s3_resolution(&new_name, &self.region))
    }

    fn s3_resolution(name: &str, region: &str) -> ResolvedResource {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("Arn".into(), format!("arn:aws:s3:::{name}"));
        attrs.insert("DomainName".into(), format!("{name}.s3.amazonaws.com"));
        attrs.insert(
            "RegionalDomainName".into(),
            format!("{name}.s3.{}.amazonaws.com", region),
        );
        ResolvedResource {
            ref_value: name.to_string(),
            attributes: attrs,
        }
    }

    async fn reconcile_s3_bucket_configuration(
        &self,
        logical_id: &str,
        bucket: &str,
        previous: Option<&Value>,
        props: &Value,
    ) -> Result<(), CfnError> {
        let encryption = props.get("BucketEncryption");
        if previous.map_or(encryption.is_some(), |value| {
            value.get("BucketEncryption") != encryption
        }) {
            match encryption {
                Some(value) => {
                    let xml = s3_bucket_encryption_xml(logical_id, value)?;
                    self.put_s3_bucket_configuration(
                        logical_id,
                        bucket,
                        "encryption",
                        "PutBucketEncryption",
                        xml,
                    )
                    .await?;
                }
                None => {
                    self.delete_s3_call(&format!("/{bucket}?encryption"), bucket)
                        .await?;
                }
            }
        }

        let versioning = props.get("VersioningConfiguration");
        if previous.map_or(versioning.is_some(), |value| {
            value.get("VersioningConfiguration") != versioning
        }) {
            let xml = match versioning {
                Some(value) => s3_bucket_versioning_xml(logical_id, value)?,
                None => {
                    "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>"
                        .to_string()
                }
            };
            self.put_s3_bucket_configuration(
                logical_id,
                bucket,
                "versioning",
                "PutBucketVersioning",
                xml,
            )
            .await?;
        }

        let notification = props.get("NotificationConfiguration");
        if previous.map_or(notification.is_some(), |value| {
            value.get("NotificationConfiguration") != notification
        }) {
            let xml = match notification {
                Some(value) => s3_bucket_notification_xml(logical_id, value)?,
                None => "<NotificationConfiguration/>".to_string(),
            };
            self.put_s3_bucket_configuration(
                logical_id,
                bucket,
                "notification",
                "PutBucketNotificationConfiguration",
                xml,
            )
            .await?;
        }
        Ok(())
    }

    async fn put_s3_bucket_configuration(
        &self,
        logical_id: &str,
        bucket: &str,
        query: &str,
        operation: &str,
        xml: String,
    ) -> Result<(), CfnError> {
        let (status, response) = self
            .call(
                "s3",
                Method::PUT,
                &format!("/{bucket}?{query}"),
                path_host(),
                Bytes::from(xml),
            )
            .await?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        Err(CfnError::ResourceFailed(format!(
            "S3 {operation} for {logical_id} failed ({status}): {}",
            String::from_utf8_lossy(&response)
        )))
    }

    async fn s3_bucket_policy(&self, props: &Value) -> Result<ResolvedResource, CfnError> {
        let bucket = props
            .get("Bucket")
            .and_then(Value::as_str)
            .filter(|bucket| !bucket.is_empty())
            .ok_or_else(|| {
                CfnError::Validation("AWS::S3::BucketPolicy requires non-empty Bucket".into())
            })?
            .to_string();
        if let Some(doc) = props.get("PolicyDocument") {
            let body = Bytes::from(doc.to_string());
            let (status, response) = self
                .call(
                    "s3",
                    Method::PUT,
                    &format!("/{bucket}?policy"),
                    path_host(),
                    body,
                )
                .await?;
            if !(200..300).contains(&status) {
                return Err(CfnError::ResourceFailed(format!(
                    "S3 PutBucketPolicy for {bucket} failed ({status}): {}",
                    String::from_utf8_lossy(&response)
                )));
            }
        }
        Ok(ResolvedResource {
            ref_value: bucket,
            attributes: Default::default(),
        })
    }

    async fn stepfunctions_state_machine(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_stepfunctions_properties(logical_id, props)?;
        let name = props
            .get("StateMachineName")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| generate_name(stack_name, logical_id, 80));
        let body = stepfunctions_create_body(logical_id, &name, props)?;
        let response = self
            .call_aws_json(
                "states",
                "AWSStepFunctions.CreateStateMachine",
                body,
                logical_id,
            )
            .await?;
        stepfunctions_resolution(&response, &name, logical_id)
    }

    async fn update_stepfunctions_state_machine(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_stepfunctions_properties(logical_id, props)?;
        ensure_only_supported_changes(
            logical_id,
            "AWS::StepFunctions::StateMachine",
            previous,
            props,
            &[
                "Definition",
                "DefinitionString",
                "RoleArn",
                "LoggingConfiguration",
                "TracingConfiguration",
                "EncryptionConfiguration",
            ],
        )?;
        let mut body = stepfunctions_mutable_body(logical_id, props)?;
        body["stateMachineArn"] = json!(current.ref_value);
        if previous.get("LoggingConfiguration").is_some()
            && props.get("LoggingConfiguration").is_none()
        {
            body["loggingConfiguration"] = json!({ "level": "OFF" });
        }
        let response = self
            .call_aws_json(
                "states",
                "AWSStepFunctions.UpdateStateMachine",
                body,
                logical_id,
            )
            .await?;
        let mut resolution = current.clone();
        if let Some(revision) = response.get("revisionId").and_then(Value::as_str) {
            resolution
                .attributes
                .insert("StateMachineRevisionId".into(), revision.to_string());
        }
        Ok(resolution)
    }

    async fn delete_stepfunctions_state_machine(&self, arn: &str) -> Result<(), CfnError> {
        self.call_aws_json(
            "states",
            "AWSStepFunctions.DeleteStateMachine",
            json!({ "stateMachineArn": arn }),
            arn,
        )
        .await?;
        for _ in 0..300 {
            match self
                .call_aws_json(
                    "states",
                    "AWSStepFunctions.DescribeStateMachine",
                    json!({ "stateMachineArn": arn }),
                    arn,
                )
                .await
            {
                Ok(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                Err(CfnError::ResourceFailed(message))
                    if message.contains("StateMachineDoesNotExist") =>
                {
                    return Ok(())
                }
                Err(error) => return Err(error),
            }
        }
        Err(CfnError::ResourceFailed(format!(
            "Step Functions state machine {arn} is still deleting; active executions or final log delivery have not finished; retry deletion"
        )))
    }

    async fn logs_group(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(
            logical_id,
            "AWS::Logs::LogGroup",
            props,
            &["LogGroupName", "RetentionInDays", "Tags", "LogGroupClass"],
        )?;
        let name = props
            .get("LogGroupName")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| generate_name(stack_name, logical_id, 512));
        let mut create = json!({"logGroupName": name});
        let tags = cfn_tags_object(props);
        if !tags.is_empty() {
            create["tags"] = Value::Object(tags);
        }
        if let Some(class) = props.get("LogGroupClass") {
            create["logGroupClass"] = class.clone();
        }
        self.call_logs("CreateLogGroup", create, logical_id).await?;

        if let Some(retention) = props.get("RetentionInDays") {
            if let Err(primary) = self
                .call_logs(
                    "PutRetentionPolicy",
                    json!({
                        "logGroupName": name,
                        "retentionInDays": coerce_number(retention),
                    }),
                    logical_id,
                )
                .await
            {
                return match self.delete_logs_group(&name).await {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
                };
            }
        }

        Ok(self.logs_group_resolution(name))
    }

    async fn update_logs_group(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        ensure_known_properties(
            logical_id,
            "AWS::Logs::LogGroup",
            props,
            &["LogGroupName", "RetentionInDays", "Tags", "LogGroupClass"],
        )?;
        ensure_only_supported_changes(
            logical_id,
            "AWS::Logs::LogGroup",
            previous,
            props,
            &["RetentionInDays"],
        )?;
        if previous.get("RetentionInDays") != props.get("RetentionInDays") {
            if let Some(retention) = props.get("RetentionInDays") {
                self.call_logs(
                    "PutRetentionPolicy",
                    json!({
                        "logGroupName": current.ref_value,
                        "retentionInDays": coerce_number(retention),
                    }),
                    logical_id,
                )
                .await?;
            } else {
                self.call_logs(
                    "DeleteRetentionPolicy",
                    json!({"logGroupName": current.ref_value}),
                    logical_id,
                )
                .await?;
            }
        }
        Ok(current.clone())
    }

    fn logs_group_resolution(&self, name: String) -> ResolvedResource {
        let mut attributes = std::collections::BTreeMap::new();
        attributes.insert(
            "Arn".into(),
            format!(
                "arn:aws:logs:{}:{}:log-group:{name}:*",
                self.region, self.account
            ),
        );
        ResolvedResource {
            ref_value: name,
            attributes,
        }
    }

    async fn logs_stream(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_logs_stream_properties(logical_id, props)?;
        let group_name = logs_stream_group(props)?;
        let stream_name = props
            .get("LogStreamName")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| generate_name(stack_name, logical_id, 512));
        self.create_logs_stream(logical_id, group_name, &stream_name)
            .await
    }

    async fn update_logs_stream(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_logs_stream_properties(logical_id, previous)?;
        validate_logs_stream_properties(logical_id, props)?;
        ensure_only_supported_changes(
            logical_id,
            "AWS::Logs::LogStream",
            previous,
            props,
            &["LogGroupName", "LogStreamName"],
        )?;
        let previous_group = logs_stream_group(previous)?;
        let next_group = logs_stream_group(props)?;
        let next_name = props
            .get("LogStreamName")
            .and_then(Value::as_str)
            .unwrap_or(&current.ref_value);
        if previous_group == next_group && current.ref_value == next_name {
            return Ok(current.clone());
        }

        let replacement = self
            .create_logs_stream(logical_id, next_group, next_name)
            .await?;
        if let Err(primary) = self
            .delete_logs_stream(previous_group, &current.ref_value)
            .await
        {
            return match self.delete_logs_stream(next_group, next_name).await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
            };
        }
        Ok(replacement)
    }

    async fn create_logs_stream(
        &self,
        logical_id: &str,
        group_name: &str,
        stream_name: &str,
    ) -> Result<ResolvedResource, CfnError> {
        self.call_logs(
            "CreateLogStream",
            json!({
                "logGroupName": group_name,
                "logStreamName": stream_name,
            }),
            logical_id,
        )
        .await?;

        match self
            .read_logs_stream(logical_id, group_name, stream_name)
            .await
        {
            Ok(resolution) => Ok(resolution),
            Err(primary) => match self.delete_logs_stream(group_name, stream_name).await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(with_cleanup_failure(primary, cleanup)),
            },
        }
    }

    async fn read_logs_stream(
        &self,
        logical_id: &str,
        group_name: &str,
        stream_name: &str,
    ) -> Result<ResolvedResource, CfnError> {
        let response = self
            .call_logs(
                "DescribeLogStreams",
                json!({
                    "logGroupName": group_name,
                    "logStreamNamePrefix": stream_name,
                    "limit": 50,
                }),
                logical_id,
            )
            .await?;
        let stream = response
            .get("logStreams")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|stream| {
                stream.get("logStreamName").and_then(Value::as_str) == Some(stream_name)
            })
            .ok_or_else(|| {
                CfnError::ResourceFailed(format!(
                    "CloudWatch Logs did not return created log stream {stream_name} for {logical_id}"
                ))
            })?;
        let name = stream
            .get("logStreamName")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CfnError::ResourceFailed(format!(
                    "CloudWatch Logs returned an invalid log stream for {logical_id}"
                ))
            })?;
        Ok(ResolvedResource {
            ref_value: name.to_string(),
            attributes: Default::default(),
        })
    }

    async fn iam_role(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let name = props
            .get("RoleName")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| generate_name(stack_name, logical_id, 64));
        let assume = props
            .get("AssumeRolePolicyDocument")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "{}".to_string());
        let mut form = format!(
            "Action=CreateRole&Version=2010-05-08&RoleName={}&AssumeRolePolicyDocument={}",
            enc(&name),
            enc(&assume)
        );
        if let Some(path) = props.get("Path").and_then(Value::as_str) {
            form.push_str(&format!("&Path={}", enc(path)));
        }
        let (status, body) = self
            .call("iam", Method::POST, "/", form_host(), Bytes::from(form))
            .await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "IAM CreateRole for {logical_id} failed ({status}): {}",
                String::from_utf8_lossy(&body)
            )));
        }

        let configuration_result = async {
            if let Some(policies) = props.get("Policies").and_then(Value::as_array) {
                for policy in policies {
                    let policy_name = policy
                        .get("PolicyName")
                        .and_then(Value::as_str)
                        .unwrap_or("inline");
                    let document = policy
                        .get("PolicyDocument")
                        .map(|document| document.to_string())
                        .unwrap_or_default();
                    let form = format!(
                        "Action=PutRolePolicy&Version=2010-05-08&RoleName={}&PolicyName={}&PolicyDocument={}",
                        enc(&name),
                        enc(policy_name),
                        enc(&document)
                    );
                    let (status, response) = self
                        .call("iam", Method::POST, "/", form_host(), Bytes::from(form))
                        .await?;
                    if !(200..300).contains(&status) {
                        return Err(CfnError::ResourceFailed(format!(
                            "IAM PutRolePolicy for {logical_id} failed ({status}): {}",
                            String::from_utf8_lossy(&response)
                        )));
                    }
                }
            }

            if let Some(arns) = props.get("ManagedPolicyArns").and_then(Value::as_array) {
                for arn in arns.iter().filter_map(Value::as_str) {
                    let form = format!(
                        "Action=AttachRolePolicy&Version=2010-05-08&RoleName={}&PolicyArn={}",
                        enc(&name),
                        enc(arn)
                    );
                    let (status, response) = self
                        .call("iam", Method::POST, "/", form_host(), Bytes::from(form))
                        .await?;
                    if !(200..300).contains(&status) {
                        return Err(CfnError::ResourceFailed(format!(
                            "IAM AttachRolePolicy for {logical_id} failed ({status}): {}",
                            String::from_utf8_lossy(&response)
                        )));
                    }
                }
            }
            Ok::<(), CfnError>(())
        }
        .await;

        if let Err(error) = configuration_result {
            return match self.delete_role(&name, props).await {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(with_cleanup_failure(error, cleanup_error)),
            };
        }

        let arn = format!("arn:aws:iam::{}:role/{name}", self.account);
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("Arn".into(), arn);
        attrs.insert("RoleId".into(), format!("AROA{}", short_id()));
        Ok(ResolvedResource {
            ref_value: name,
            attributes: attrs,
        })
    }

    async fn lambda_function(
        &self,
        logical_id: &str,
        stack_name: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let name = props
            .get("FunctionName")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| generate_name(stack_name, logical_id, 64));

        // Resolve the code package into an inline base64 zip the Lambda service accepts.
        let code = self.resolve_code(props.get("Code")).await?;

        let mut body = json!({
            "FunctionName": name,
            "Code": code,
        });
        let obj = body.as_object_mut().unwrap();
        for (cfn, api) in [
            ("Handler", "Handler"),
            ("Runtime", "Runtime"),
            ("Role", "Role"),
            ("Description", "Description"),
        ] {
            if let Some(v) = props.get(cfn) {
                obj.insert(api.to_string(), v.clone());
            }
        }
        if let Some(m) = props.get("MemorySize") {
            obj.insert("MemorySize".into(), coerce_number(m));
        }
        if let Some(t) = props.get("Timeout") {
            obj.insert("Timeout".into(), coerce_number(t));
        }
        if let Some(env) = props.get("Environment") {
            obj.insert("Environment".into(), env.clone());
        }
        if let Some(vpc) = props.get("VpcConfig") {
            obj.insert("VpcConfig".into(), vpc.clone());
        }

        let (status, resp) = self
            .call(
                "lambda",
                Method::POST,
                "/2015-03-31/functions",
                json_host(),
                Bytes::from(body.to_string()),
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "Lambda CreateFunction for {logical_id} failed ({status}): {}",
                String::from_utf8_lossy(&resp)
            )));
        }
        let parsed: Value = serde_json::from_slice(&resp).unwrap_or(Value::Null);
        let arn = parsed
            .get("FunctionArn")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "arn:aws:lambda:{}:{}:function:{name}",
                    self.region, self.account
                )
            });

        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("Arn".into(), arn);
        Ok(ResolvedResource {
            ref_value: name,
            attributes: attrs,
        })
    }

    async fn update_lambda_function(
        &self,
        logical_id: &str,
        function: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        let code = self.resolve_code(props.get("Code")).await?;
        self.call_json(
            "lambda",
            Method::PUT,
            &format!("/2015-03-31/functions/{function}/code"),
            code,
            logical_id,
        )
        .await?;

        let mut configuration = mapped_properties(
            props,
            &[
                ("Handler", "Handler"),
                ("Runtime", "Runtime"),
                ("Role", "Role"),
                ("Description", "Description"),
                ("Environment", "Environment"),
                ("VpcConfig", "VpcConfig"),
            ],
        );
        if let Some(memory) = props.get("MemorySize") {
            configuration["MemorySize"] = coerce_number(memory);
        }
        if let Some(timeout) = props.get("Timeout") {
            configuration["Timeout"] = coerce_number(timeout);
        }
        self.call_json(
            "lambda",
            Method::PUT,
            &format!("/2015-03-31/functions/{function}/configuration"),
            configuration,
            logical_id,
        )
        .await?;
        Ok(())
    }

    async fn lambda_version(&self, props: &Value) -> Result<ResolvedResource, CfnError> {
        let function = props
            .get("FunctionName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let (status, resp) = self
            .call(
                "lambda",
                Method::POST,
                &format!("/2015-03-31/functions/{function}/versions"),
                json_host(),
                Bytes::from("{}"),
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "Lambda PublishVersion for {function} failed ({status}): {}",
                String::from_utf8_lossy(&resp)
            )));
        }
        let parsed: Value = serde_json::from_slice(&resp).map_err(|error| {
            CfnError::ResourceFailed(format!(
                "Lambda PublishVersion for {function} returned invalid JSON: {error}"
            ))
        })?;
        let version = required_response_string(&parsed, "Version", &function)?;
        let arn = required_response_string(&parsed, "FunctionArn", &function)?;
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("Version".into(), version);
        Ok(ResolvedResource {
            ref_value: arn,
            attributes: attrs,
        })
    }

    async fn lambda_permission(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let function = required_property(props, "FunctionName", logical_id)?;
        let mut body = mapped_properties(
            props,
            &[
                ("Action", "Action"),
                ("Principal", "Principal"),
                ("SourceArn", "SourceArn"),
                ("SourceAccount", "SourceAccount"),
                ("EventSourceToken", "EventSourceToken"),
                ("FunctionUrlAuthType", "FunctionUrlAuthType"),
                ("PrincipalOrgID", "PrincipalOrgID"),
            ],
        );
        body["StatementId"] = json!(logical_id);
        self.call_json(
            "lambda",
            Method::POST,
            &format!("/2015-03-31/functions/{function}/policy"),
            body,
            logical_id,
        )
        .await?;
        Ok(ResolvedResource {
            ref_value: format!("{function}|{logical_id}"),
            attributes: Default::default(),
        })
    }

    async fn lambda_event_source_mapping(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_lambda_event_source_mapping(logical_id, props)?;
        let response = self
            .call_json(
                "lambda",
                Method::POST,
                "/2015-03-31/event-source-mappings",
                lambda_event_source_mapping_create_body(props),
                logical_id,
            )
            .await?;
        let uuid = required_response_string(&response, "UUID", logical_id)?;
        let mapping_arn = required_response_string(&response, "EventSourceMappingArn", logical_id)?;
        let mut attributes = std::collections::BTreeMap::new();
        attributes.insert("Id".into(), uuid.clone());
        attributes.insert("EventSourceMappingArn".into(), mapping_arn);
        Ok(ResolvedResource {
            ref_value: uuid,
            attributes,
        })
    }

    async fn update_lambda_event_source_mapping(
        &self,
        logical_id: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_lambda_event_source_mapping(logical_id, previous)?;
        validate_lambda_event_source_mapping(logical_id, props)?;
        if ["FunctionName", "EventSourceArn", "StartingPosition"]
            .iter()
            .any(|name| previous.get(*name) != props.get(*name))
        {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::Lambda::EventSourceMapping function, event source, and starting position require replacement for {logical_id}"
            )));
        }
        self.call_json(
            "lambda",
            Method::PUT,
            &format!("/2015-03-31/event-source-mappings/{}", current.ref_value),
            json!({
                "BatchSize": props.get("BatchSize").cloned().unwrap_or_else(|| {
                    json!(lambda_event_source_mapping_default_batch_size(props))
                }),
                "Enabled": props.get("Enabled").cloned().unwrap_or(json!(true)),
                "FunctionResponseTypes": props
                    .get("FunctionResponseTypes")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            }),
            logical_id,
        )
        .await?;
        Ok(current.clone())
    }

    async fn apigateway_rest_api(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let mut body = mapped_properties(
            props,
            &[
                ("Name", "name"),
                ("Description", "description"),
                ("EndpointConfiguration", "endpointConfiguration"),
                ("BinaryMediaTypes", "binaryMediaTypes"),
                ("MinimumCompressionSize", "minimumCompressionSize"),
                ("ApiKeySourceType", "apiKeySource"),
            ],
        );
        if body.get("name").is_none() {
            body["name"] = json!(logical_id);
        }
        let response = self
            .call_json("apigateway", Method::POST, "/restapis", body, logical_id)
            .await?;
        let id = required_response_string(&response, "id", logical_id)?;
        let mut attributes = std::collections::BTreeMap::new();
        if let Some(root) = response.get("rootResourceId").and_then(Value::as_str) {
            attributes.insert("RootResourceId".into(), root.to_string());
        }
        Ok(ResolvedResource {
            ref_value: id,
            attributes,
        })
    }

    async fn apigateway_resource(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let api = required_property(props, "RestApiId", logical_id)?;
        let parent = required_property(props, "ParentId", logical_id)?;
        let body = mapped_properties(props, &[("PathPart", "pathPart")]);
        let response = self
            .call_json(
                "apigateway",
                Method::POST,
                &format!("/restapis/{api}/resources/{parent}"),
                body,
                logical_id,
            )
            .await?;
        Ok(ResolvedResource {
            ref_value: required_response_string(&response, "id", logical_id)?,
            attributes: Default::default(),
        })
    }

    async fn apigateway_method(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let api = required_property(props, "RestApiId", logical_id)?;
        let resource = required_property(props, "ResourceId", logical_id)?;
        let method = required_property(props, "HttpMethod", logical_id)?;
        let body = mapped_properties(
            props,
            &[
                ("AuthorizationType", "authorizationType"),
                ("AuthorizerId", "authorizerId"),
                ("ApiKeyRequired", "apiKeyRequired"),
                ("RequestParameters", "requestParameters"),
                ("RequestModels", "requestModels"),
                ("RequestValidatorId", "requestValidatorId"),
            ],
        );
        self.call_json(
            "apigateway",
            Method::PUT,
            &format!("/restapis/{api}/resources/{resource}/methods/{method}"),
            body,
            logical_id,
        )
        .await?;
        if let Some(integration) = props.get("Integration") {
            let body = mapped_properties(
                integration,
                &[
                    ("Type", "type"),
                    ("IntegrationHttpMethod", "integrationHttpMethod"),
                    ("Uri", "uri"),
                    ("Credentials", "credentials"),
                    ("RequestParameters", "requestParameters"),
                    ("RequestTemplates", "requestTemplates"),
                    ("PassthroughBehavior", "passthroughBehavior"),
                    ("ContentHandling", "contentHandling"),
                    ("TimeoutInMillis", "timeoutInMillis"),
                ],
            );
            self.call_json(
                "apigateway",
                Method::PUT,
                &format!("/restapis/{api}/resources/{resource}/methods/{method}/integration"),
                body,
                logical_id,
            )
            .await?;
        }
        Ok(ResolvedResource {
            ref_value: format!("{api}:{resource}:{method}"),
            attributes: Default::default(),
        })
    }

    async fn apigateway_deployment(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let api = required_property(props, "RestApiId", logical_id)?;
        let mut body = mapped_properties(
            props,
            &[("StageName", "stageName"), ("Description", "description")],
        );
        if let Some(stage_description) =
            apigateway_stage_description(props.get("StageDescription"), logical_id)?
        {
            body["stageDescription"] = stage_description;
        }
        let response = self
            .call_json(
                "apigateway",
                Method::POST,
                &format!("/restapis/{api}/deployments"),
                body,
                logical_id,
            )
            .await?;
        Ok(ResolvedResource {
            ref_value: required_response_string(&response, "id", logical_id)?,
            attributes: Default::default(),
        })
    }

    async fn apigateway_v2_api(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        if props.get("Body").is_some()
            && props
                .get("ProtocolType")
                .is_some_and(|value| value != "HTTP")
        {
            return Err(CfnError::Validation(
                "HTTP API Body requires ProtocolType HTTP".into(),
            ));
        }
        let routes = props.get("Body").map(api_routes_from_body).transpose()?;
        let mut body = mapped_properties(
            props,
            &[
                ("Name", "name"),
                ("ProtocolType", "protocolType"),
                ("Description", "description"),
                ("RouteSelectionExpression", "routeSelectionExpression"),
            ],
        );
        if let Some(cors) = props.get("CorsConfiguration") {
            body["corsConfiguration"] = apigateway_v2_cors(cors, logical_id)?;
        }
        if let Some(definition) = props.get("Body") {
            body["name"] = definition
                .pointer("/info/title")
                .cloned()
                .unwrap_or_else(|| json!(logical_id));
            body["protocolType"] = json!("HTTP");
        }
        let response = self
            .call_json("apigatewayv2", Method::POST, "/v2/apis", body, logical_id)
            .await?;
        let api_id = required_response_string(&response, "apiId", logical_id)?;
        let endpoint = match required_response_string(&response, "apiEndpoint", logical_id) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                if let Err(cleanup) = self.delete_apigateway_v2_api(&api_id).await {
                    return Err(with_cleanup_failure(error, cleanup));
                }
                return Err(error);
            }
        };
        if let Some(routes) = routes {
            if let Err(error) = self
                .create_api_body_routes(logical_id, &api_id, &routes)
                .await
            {
                let _ = self.delete_apigateway_v2_api(&api_id).await;
                return Err(error);
            }
        }
        Ok(ResolvedResource {
            ref_value: api_id.clone(),
            attributes: std::collections::BTreeMap::from([
                ("ApiId".into(), api_id.clone()),
                ("ApiEndpoint".into(), endpoint),
                (
                    "ExecuteApiArn".into(),
                    format!(
                        "arn:aws:execute-api:{}:{}:{api_id}",
                        self.region, self.account
                    ),
                ),
            ]),
        })
    }

    async fn create_api_body_routes(
        &self,
        logical_id: &str,
        api_id: &str,
        routes: &[(String, String, String)],
    ) -> Result<(), CfnError> {
        for (route_key, uri, payload_version) in routes {
            let integration = self
                .call_json(
                    "apigatewayv2",
                    Method::POST,
                    &format!("/v2/apis/{api_id}/integrations"),
                    json!({
                        "integrationType":"AWS_PROXY",
                        "integrationUri":uri,
                        "integrationMethod":"POST",
                        "payloadFormatVersion":payload_version
                    }),
                    logical_id,
                )
                .await?;
            let integration_id =
                required_response_string(&integration, "integrationId", logical_id)?;
            self.call_json(
                "apigatewayv2",
                Method::POST,
                &format!("/v2/apis/{api_id}/routes"),
                json!({"routeKey":route_key,"target":format!("integrations/{integration_id}")}),
                logical_id,
            )
            .await?;
        }
        Ok(())
    }

    async fn clear_api_body_routes(&self, logical_id: &str, api_id: &str) -> Result<(), CfnError> {
        let routes = self
            .call_json(
                "apigatewayv2",
                Method::GET,
                &format!("/v2/apis/{api_id}/routes"),
                json!({}),
                logical_id,
            )
            .await?;
        for route in routes["items"].as_array().into_iter().flatten() {
            let route_id = required_response_string(route, "routeId", logical_id)?;
            self.call_json(
                "apigatewayv2",
                Method::DELETE,
                &format!("/v2/apis/{api_id}/routes/{route_id}"),
                json!({}),
                logical_id,
            )
            .await?;
        }
        let integrations = self
            .call_json(
                "apigatewayv2",
                Method::GET,
                &format!("/v2/apis/{api_id}/integrations"),
                json!({}),
                logical_id,
            )
            .await?;
        for integration in integrations["items"].as_array().into_iter().flatten() {
            let integration_id =
                required_response_string(integration, "integrationId", logical_id)?;
            self.call_json(
                "apigatewayv2",
                Method::DELETE,
                &format!("/v2/apis/{api_id}/integrations/{integration_id}"),
                json!({}),
                logical_id,
            )
            .await?;
        }
        Ok(())
    }

    async fn apigateway_v2_integration(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let api = required_property(props, "ApiId", logical_id)?;
        let body = mapped_properties(
            props,
            &[
                ("IntegrationType", "integrationType"),
                ("IntegrationUri", "integrationUri"),
                ("IntegrationMethod", "integrationMethod"),
                ("IntegrationSubtype", "integrationSubtype"),
                ("PayloadFormatVersion", "payloadFormatVersion"),
                ("TimeoutInMillis", "timeoutInMillis"),
                ("RequestParameters", "requestParameters"),
            ],
        );
        let response = self
            .call_json(
                "apigatewayv2",
                Method::POST,
                &format!("/v2/apis/{api}/integrations"),
                body,
                logical_id,
            )
            .await?;
        Ok(ResolvedResource {
            ref_value: required_response_string(&response, "integrationId", logical_id)?,
            attributes: Default::default(),
        })
    }

    async fn apigateway_v2_route(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let api = required_property(props, "ApiId", logical_id)?;
        let body = mapped_properties(
            props,
            &[
                ("RouteKey", "routeKey"),
                ("Target", "target"),
                ("AuthorizationType", "authorizationType"),
                ("AuthorizerId", "authorizerId"),
                ("AuthorizationScopes", "authorizationScopes"),
                ("ApiKeyRequired", "apiKeyRequired"),
            ],
        );
        let response = self
            .call_json(
                "apigatewayv2",
                Method::POST,
                &format!("/v2/apis/{api}/routes"),
                body,
                logical_id,
            )
            .await?;
        Ok(ResolvedResource {
            ref_value: required_response_string(&response, "routeId", logical_id)?,
            attributes: Default::default(),
        })
    }

    async fn apigateway_v2_stage(
        &self,
        logical_id: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let api = required_property(props, "ApiId", logical_id)?;
        let mut body = mapped_properties(
            props,
            &[
                ("StageName", "stageName"),
                ("AutoDeploy", "autoDeploy"),
                ("DeploymentId", "deploymentId"),
                ("Description", "description"),
                ("StageVariables", "stageVariables"),
                ("DefaultRouteSettings", "defaultRouteSettings"),
            ],
        );
        if let Some(settings) = props.get("AccessLogSettings") {
            body["accessLogSettings"] = apigateway_v2_access_log_settings(settings, logical_id)?;
        }
        self.call_json(
            "apigatewayv2",
            Method::POST,
            &format!("/v2/apis/{api}/stages"),
            body,
            logical_id,
        )
        .await?;
        Ok(ResolvedResource {
            ref_value: required_property(props, "StageName", logical_id)?,
            attributes: Default::default(),
        })
    }

    async fn update_apigateway_rest_api(
        &self,
        logical_id: &str,
        api_id: &str,
        previous: &Value,
        props: &Value,
    ) -> Result<(), CfnError> {
        ensure_only_supported_changes(
            logical_id,
            "AWS::ApiGateway::RestApi",
            previous,
            props,
            &[
                "Name",
                "Description",
                "EndpointConfiguration",
                "BinaryMediaTypes",
                "MinimumCompressionSize",
                "ApiKeySourceType",
            ],
        )?;
        let mut operations = Vec::new();
        for (property, path, default) in [
            ("Name", "/name", json!(logical_id)),
            ("Description", "/description", Value::Null),
            (
                "MinimumCompressionSize",
                "/minimumCompressionSize",
                Value::Null,
            ),
            ("ApiKeySourceType", "/apiKeySource", json!("HEADER")),
        ] {
            let old = effective_property(previous, property, default.clone());
            let new = effective_property(props, property, default);
            if old != new {
                operations.push(json!({ "op": "add", "path": path, "value": new }));
            }
        }

        let previous_endpoint = endpoint_types(previous);
        let next_endpoint = endpoint_types(props);
        if previous_endpoint != next_endpoint {
            operations.push(json!({
                "op": "add",
                "path": "/endpointConfiguration/types",
                "value": next_endpoint,
            }));
        }

        let previous_binary = binary_media_types(previous);
        let next_binary = binary_media_types(props);
        if previous_binary != next_binary {
            for index in (0..previous_binary.len()).rev() {
                operations.push(json!({
                    "op": "remove",
                    "path": format!("/binaryMediaTypes/{index}"),
                }));
            }
            for value in next_binary {
                operations.push(json!({
                    "op": "add",
                    "path": "/binaryMediaTypes/-",
                    "value": value,
                }));
            }
        }

        if operations.is_empty() {
            return Err(CfnError::ResourceFailed(format!(
                "no supported AWS::ApiGateway::RestApi properties changed for {logical_id}"
            )));
        }
        self.call_json(
            "apigateway",
            Method::PATCH,
            &format!("/restapis/{api_id}"),
            json!({ "patchOperations": operations }),
            logical_id,
        )
        .await?;
        Ok(())
    }

    async fn update_apigateway_v2_api(
        &self,
        logical_id: &str,
        api_id: &str,
        previous: &Value,
        props: &Value,
    ) -> Result<(), CfnError> {
        ensure_only_supported_changes(
            logical_id,
            "AWS::ApiGatewayV2::Api",
            previous,
            props,
            &[
                "Name",
                "ProtocolType",
                "Description",
                "RouteSelectionExpression",
                "CorsConfiguration",
                "Body",
            ],
        )?;
        if previous.get("ProtocolType") != props.get("ProtocolType") {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::ApiGatewayV2::Api ProtocolType cannot be updated for {logical_id}"
            )));
        }
        if props.get("Body").is_some()
            && props
                .get("ProtocolType")
                .is_some_and(|value| value != "HTTP")
        {
            return Err(CfnError::Validation(
                "HTTP API Body requires ProtocolType HTTP".into(),
            ));
        }
        let new_routes = props.get("Body").map(api_routes_from_body).transpose()?;
        let old_routes = previous.get("Body").map(api_routes_from_body).transpose()?;
        let mut body = mapped_properties(
            props,
            &[
                ("Name", "name"),
                ("Description", "description"),
                ("RouteSelectionExpression", "routeSelectionExpression"),
            ],
        );
        if let Some(cors) = props.get("CorsConfiguration") {
            body["corsConfiguration"] = apigateway_v2_cors(cors, logical_id)?;
        }
        if let Some(title) = props
            .get("Body")
            .and_then(|value| value.pointer("/info/title"))
        {
            body["name"] = title.clone();
        }
        reset_removed_property(&mut body, previous, props, "Name", "name", Value::Null);
        reset_removed_property(
            &mut body,
            previous,
            props,
            "Description",
            "description",
            Value::Null,
        );
        let default_route_selection =
            if previous.get("ProtocolType").and_then(Value::as_str) == Some("WEBSOCKET") {
                Value::Null
            } else {
                json!("$request.method $request.path")
            };
        reset_removed_property(
            &mut body,
            previous,
            props,
            "RouteSelectionExpression",
            "routeSelectionExpression",
            default_route_selection,
        );
        reset_removed_property(
            &mut body,
            previous,
            props,
            "CorsConfiguration",
            "corsConfiguration",
            Value::Null,
        );
        self.call_json(
            "apigatewayv2",
            Method::PATCH,
            &format!("/v2/apis/{api_id}"),
            body,
            logical_id,
        )
        .await?;
        if previous.get("Body") != props.get("Body") {
            self.clear_api_body_routes(logical_id, api_id).await?;
            if let Some(routes) = new_routes {
                if let Err(error) = self
                    .create_api_body_routes(logical_id, api_id, &routes)
                    .await
                {
                    let _ = self.clear_api_body_routes(logical_id, api_id).await;
                    if let Some(routes) = old_routes {
                        let _ = self
                            .create_api_body_routes(logical_id, api_id, &routes)
                            .await;
                    }
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    async fn update_apigateway_v2_integration(
        &self,
        logical_id: &str,
        integration_id: &str,
        previous: &Value,
        props: &Value,
    ) -> Result<(), CfnError> {
        ensure_only_supported_changes(
            logical_id,
            "AWS::ApiGatewayV2::Integration",
            previous,
            props,
            &[
                "ApiId",
                "IntegrationType",
                "IntegrationUri",
                "IntegrationMethod",
                "IntegrationSubtype",
                "PayloadFormatVersion",
                "TimeoutInMillis",
                "RequestParameters",
            ],
        )?;
        let api = required_property(props, "ApiId", logical_id)?;
        let mut body = mapped_properties(
            props,
            &[
                ("IntegrationType", "integrationType"),
                ("IntegrationUri", "integrationUri"),
                ("IntegrationMethod", "integrationMethod"),
                ("IntegrationSubtype", "integrationSubtype"),
                ("PayloadFormatVersion", "payloadFormatVersion"),
                ("TimeoutInMillis", "timeoutInMillis"),
                ("RequestParameters", "requestParameters"),
            ],
        );
        for (source, target, default) in [
            ("IntegrationType", "integrationType", Value::Null),
            ("IntegrationUri", "integrationUri", Value::Null),
            ("IntegrationMethod", "integrationMethod", Value::Null),
            ("IntegrationSubtype", "integrationSubtype", Value::Null),
            ("PayloadFormatVersion", "payloadFormatVersion", Value::Null),
            ("TimeoutInMillis", "timeoutInMillis", json!(30_000)),
            ("RequestParameters", "requestParameters", json!({})),
        ] {
            reset_removed_property(&mut body, previous, props, source, target, default);
        }
        self.call_json(
            "apigatewayv2",
            Method::PATCH,
            &format!("/v2/apis/{api}/integrations/{integration_id}"),
            body,
            logical_id,
        )
        .await?;
        Ok(())
    }

    async fn update_apigateway_v2_route(
        &self,
        logical_id: &str,
        route_id: &str,
        previous: &Value,
        props: &Value,
    ) -> Result<(), CfnError> {
        ensure_only_supported_changes(
            logical_id,
            "AWS::ApiGatewayV2::Route",
            previous,
            props,
            &[
                "ApiId",
                "RouteKey",
                "Target",
                "AuthorizationType",
                "AuthorizerId",
                "AuthorizationScopes",
                "ApiKeyRequired",
            ],
        )?;
        let api = required_property(props, "ApiId", logical_id)?;
        let mut body = mapped_properties(
            props,
            &[
                ("RouteKey", "routeKey"),
                ("Target", "target"),
                ("AuthorizationType", "authorizationType"),
                ("AuthorizerId", "authorizerId"),
                ("AuthorizationScopes", "authorizationScopes"),
                ("ApiKeyRequired", "apiKeyRequired"),
            ],
        );
        for (source, target, default) in [
            ("RouteKey", "routeKey", Value::Null),
            ("Target", "target", Value::Null),
            ("AuthorizationType", "authorizationType", json!("NONE")),
            ("AuthorizerId", "authorizerId", Value::Null),
            ("AuthorizationScopes", "authorizationScopes", json!([])),
            ("ApiKeyRequired", "apiKeyRequired", json!(false)),
        ] {
            reset_removed_property(&mut body, previous, props, source, target, default);
        }
        self.call_json(
            "apigatewayv2",
            Method::PATCH,
            &format!("/v2/apis/{api}/routes/{route_id}"),
            body,
            logical_id,
        )
        .await?;
        Ok(())
    }

    async fn update_apigateway_v2_stage(
        &self,
        logical_id: &str,
        stage_name: &str,
        previous: &Value,
        props: &Value,
    ) -> Result<(), CfnError> {
        ensure_only_supported_changes(
            logical_id,
            "AWS::ApiGatewayV2::Stage",
            previous,
            props,
            &[
                "ApiId",
                "StageName",
                "AutoDeploy",
                "DeploymentId",
                "Description",
                "StageVariables",
                "DefaultRouteSettings",
                "AccessLogSettings",
            ],
        )?;
        let api = required_property(props, "ApiId", logical_id)?;
        let mut body = mapped_properties(
            props,
            &[
                ("AutoDeploy", "autoDeploy"),
                ("DeploymentId", "deploymentId"),
                ("Description", "description"),
                ("StageVariables", "stageVariables"),
                ("DefaultRouteSettings", "defaultRouteSettings"),
            ],
        );
        if let Some(settings) = props.get("AccessLogSettings") {
            body["accessLogSettings"] = apigateway_v2_access_log_settings(settings, logical_id)?;
        }
        for (source, target, default) in [
            ("AutoDeploy", "autoDeploy", json!(false)),
            ("DeploymentId", "deploymentId", Value::Null),
            ("Description", "description", Value::Null),
            ("StageVariables", "stageVariables", json!({})),
            ("DefaultRouteSettings", "defaultRouteSettings", json!({})),
            ("AccessLogSettings", "accessLogSettings", Value::Null),
        ] {
            reset_removed_property(&mut body, previous, props, source, target, default);
        }
        self.call_json(
            "apigatewayv2",
            Method::PATCH,
            &format!("/v2/apis/{api}/stages/{stage_name}"),
            body,
            logical_id,
        )
        .await?;
        Ok(())
    }

    /// Resolve `Code` into `{ "ZipFile": <base64> }`. Supports inline `ZipFile` and an
    /// `S3Bucket`/`S3Key` reference (fetched from the S3 service and re-inlined, since the
    /// Lambda data plane consumes inline zips).
    async fn resolve_code(&self, code: Option<&Value>) -> Result<Value, CfnError> {
        let Some(code) = code else {
            return Err(CfnError::Validation(
                "Lambda function is missing Code".into(),
            ));
        };
        if let Some(zip) = code.get("ZipFile").and_then(Value::as_str) {
            return Ok(json!({ "ZipFile": zip }));
        }
        let bucket = code.get("S3Bucket").and_then(Value::as_str);
        let key = code.get("S3Key").and_then(Value::as_str);
        if let (Some(bucket), Some(key)) = (bucket, key) {
            let (status, bytes) = self
                .call(
                    "s3",
                    Method::GET,
                    &format!("/{bucket}/{key}"),
                    path_host(),
                    Bytes::new(),
                )
                .await?;
            if !(200..300).contains(&status) {
                return Err(CfnError::ResourceFailed(format!(
                    "fetching Lambda code s3://{bucket}/{key} failed ({status})"
                )));
            }
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            return Ok(json!({ "ZipFile": b64 }));
        }
        Err(CfnError::Validation(
            "Lambda Code must provide ZipFile or S3Bucket/S3Key".into(),
        ))
    }

    // --- teardown -------------------------------------------------------------------------

    async fn delete_glue_database(&self, name: &str, props: &Value) -> Result<(), CfnError> {
        let catalog_id = required_property(props, "CatalogId", name)?;
        self.delete_aws_json_11(
            "glue",
            "AWSGlue.DeleteDatabase",
            json!({ "CatalogId": catalog_id, "Name": name }),
            name,
            &["EntityNotFoundException"],
        )
        .await
    }

    async fn delete_glue_table(&self, name: &str, props: &Value) -> Result<(), CfnError> {
        let catalog_id = required_property(props, "CatalogId", name)?;
        let database_name = required_property(props, "DatabaseName", name)?;
        self.delete_aws_json_11(
            "glue",
            "AWSGlue.DeleteTable",
            json!({
                "CatalogId": catalog_id,
                "DatabaseName": database_name,
                "Name": name,
            }),
            name,
            &["EntityNotFoundException"],
        )
        .await
    }

    async fn delete_kms_key(&self, key_id: &str, props: &Value) -> Result<(), CfnError> {
        let pending_window = kms_pending_window_days(props)?;
        self.delete_aws_json_11(
            "kms",
            "TrentService.ScheduleKeyDeletion",
            json!({
                "KeyId": key_id,
                "PendingWindowInDays": pending_window,
            }),
            key_id,
            &["NotFoundException", "KMSInvalidStateException"],
        )
        .await
    }

    async fn delete_kms_alias(&self, alias_name: &str) -> Result<(), CfnError> {
        self.delete_aws_json_11(
            "kms",
            "TrentService.DeleteAlias",
            json!({ "AliasName": alias_name }),
            alias_name,
            &["NotFoundException"],
        )
        .await
    }

    async fn delete_sqs_queue(&self, queue_url: &str) -> Result<(), CfnError> {
        self.call_aws_json(
            "sqs",
            "AmazonSQS.DeleteQueue",
            json!({"QueueUrl": queue_url}),
            queue_url,
        )
        .await
        .map(|_| ())
    }

    async fn delete_sns_topic(&self, topic_arn: &str) -> Result<(), CfnError> {
        self.call_aws_json(
            "sns",
            "AmazonSimpleNotificationService.DeleteTopic",
            json!({"TopicArn": topic_arn}),
            topic_arn,
        )
        .await
        .map(|_| ())
    }

    async fn delete_sns_subscription(&self, subscription_arn: &str) -> Result<(), CfnError> {
        self.call_aws_json(
            "sns",
            "AmazonSimpleNotificationService.Unsubscribe",
            json!({"SubscriptionArn": subscription_arn}),
            subscription_arn,
        )
        .await
        .map(|_| ())
    }

    async fn delete_events_event_bus(&self, name: &str) -> Result<(), CfnError> {
        let mut headers = json_host();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_static("AWSEvents.DeleteEventBus"),
        );
        let (status, response) = self
            .call(
                "events",
                Method::POST,
                "/",
                headers,
                Bytes::from(json!({ "Name": name }).to_string()),
            )
            .await?;
        if (200..300).contains(&status)
            || aws_json_error_is(status, &response, "ResourceNotFoundException")
        {
            return Ok(());
        }
        Err(CfnError::ResourceFailed(format!(
            "EventBridge deletion for {name} failed ({status}): {}",
            String::from_utf8_lossy(&response)
        )))
    }

    async fn delete_events_rule(&self, name: &str, props: &Value) -> Result<(), CfnError> {
        self.call_aws_json(
            "events",
            "AWSEvents.DeleteRule",
            json!({
                "Name": name,
                "EventBusName": event_bus_name(props),
                "Force": true,
            }),
            name,
        )
        .await
        .map(|_| ())
    }

    async fn delete_pipes_pipe(&self, name: &str) -> Result<(), CfnError> {
        self.delete_call("pipes", &format!("/v1/pipes/{name}"), name)
            .await
    }

    async fn delete_logs_group(&self, name: &str) -> Result<(), CfnError> {
        self.call_logs("DeleteLogGroup", json!({"logGroupName": name}), name)
            .await
            .map(|_| ())
    }

    async fn delete_logs_stream(
        &self,
        group_name: &str,
        stream_name: &str,
    ) -> Result<(), CfnError> {
        self.call_logs(
            "DeleteLogStream",
            json!({
                "logGroupName": group_name,
                "logStreamName": stream_name,
            }),
            stream_name,
        )
        .await
        .map(|_| ())
    }

    async fn delete_bucket(&self, bucket: &str) -> Result<(), CfnError> {
        self.delete_s3_call(&format!("/{bucket}"), bucket).await
    }

    async fn delete_bucket_policy(&self, bucket: &str) -> Result<(), CfnError> {
        self.delete_s3_call(&format!("/{bucket}?policy"), bucket)
            .await
    }

    async fn delete_s3_call(&self, path: &str, physical_id: &str) -> Result<(), CfnError> {
        let (status, response) = self
            .call("s3", Method::DELETE, path, path_host(), Bytes::new())
            .await?;
        ensure_delete_succeeded("s3", physical_id, status, &response)
    }

    async fn delete_role(&self, role: &str, props: &Value) -> Result<(), CfnError> {
        if let Some(policies) = props.get("Policies").and_then(Value::as_array) {
            for policy in policies {
                let policy_name = policy
                    .get("PolicyName")
                    .and_then(Value::as_str)
                    .unwrap_or("inline");
                self.iam_role_teardown_action(
                    "DeleteRolePolicy",
                    role,
                    Some(("PolicyName", policy_name)),
                )
                .await?;
            }
        }

        if let Some(arns) = props.get("ManagedPolicyArns").and_then(Value::as_array) {
            for arn in arns.iter().filter_map(Value::as_str) {
                self.iam_role_teardown_action("DetachRolePolicy", role, Some(("PolicyArn", arn)))
                    .await?;
            }
        }

        self.iam_role_teardown_action("DeleteRole", role, None)
            .await
    }

    async fn iam_role_teardown_action(
        &self,
        action: &str,
        role: &str,
        policy: Option<(&str, &str)>,
    ) -> Result<(), CfnError> {
        let mut form = format!("Action={action}&Version=2010-05-08&RoleName={}", enc(role));
        if let Some((key, value)) = policy {
            form.push_str(&format!("&{key}={}", enc(value)));
        }
        let (status, response) = self
            .call("iam", Method::POST, "/", form_host(), Bytes::from(form))
            .await?;
        let target = match policy {
            Some((_, policy)) => format!("role {role}, policy {policy}"),
            None => format!("role {role}"),
        };
        ensure_delete_succeeded(&format!("IAM {action}"), &target, status, &response)
    }

    pub(crate) async fn associated_lambda_log_group(
        &self,
        function: &str,
    ) -> Result<Option<String>, CfnError> {
        // The native executor and guest environment use this exact configured default.
        // This is an association, never proof that CloudFormation owns the log group.
        let group = format!("/aws/lambda/{function}");
        let result = self
            .call_logs(
                "DescribeLogGroups",
                json!({"logGroupNamePrefix": group}),
                function,
            )
            .await?;
        let groups = result
            .get("logGroups")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CfnError::ResourceFailed(
                    "CloudWatch Logs DescribeLogGroups returned no logGroups list".into(),
                )
            })?;
        Ok(groups
            .iter()
            .any(|entry| entry.get("logGroupName").and_then(Value::as_str) == Some(group.as_str()))
            .then_some(group))
    }

    async fn delete_function(&self, function: &str) -> Result<(), CfnError> {
        let (status, response) = self
            .call(
                "lambda",
                Method::DELETE,
                &format!("/2015-03-31/functions/{function}"),
                json_host(),
                Bytes::new(),
            )
            .await?;
        ensure_delete_succeeded("lambda", function, status, &response)
    }

    async fn delete_lambda_permission(&self, physical_id: &str) -> Result<(), CfnError> {
        let Some((function, statement_id)) = physical_id.rsplit_once('|') else {
            return Err(CfnError::ResourceFailed(format!(
                "invalid Lambda permission physical id: {physical_id}"
            )));
        };
        self.delete_call(
            "lambda",
            &format!("/2015-03-31/functions/{function}/policy/{statement_id}"),
            physical_id,
        )
        .await
    }

    async fn delete_lambda_event_source_mapping(&self, uuid: &str) -> Result<(), CfnError> {
        self.delete_call(
            "lambda",
            &format!("/2015-03-31/event-source-mappings/{uuid}"),
            uuid,
        )
        .await
    }

    async fn delete_apigateway_resource(
        &self,
        resource_id: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        let api = required_property(props, "RestApiId", resource_id)?;
        self.delete_call(
            "apigateway",
            &format!("/restapis/{api}/resources/{resource_id}"),
            resource_id,
        )
        .await
    }

    async fn delete_apigateway_method(&self, physical_id: &str) -> Result<(), CfnError> {
        let Some((api, resource, method)) = parse_apigateway_method_id(physical_id) else {
            return Err(CfnError::ResourceFailed(format!(
                "invalid API Gateway method physical id: {physical_id}"
            )));
        };
        self.delete_call(
            "apigateway",
            &format!("/restapis/{api}/resources/{resource}/methods/{method}"),
            physical_id,
        )
        .await
    }

    async fn delete_apigateway_deployment(
        &self,
        deployment_id: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        let api = required_property(props, "RestApiId", deployment_id)?;
        self.delete_call(
            "apigateway",
            &format!("/restapis/{api}/deployments/{deployment_id}"),
            deployment_id,
        )
        .await
    }

    async fn delete_apigateway_v2_integration(
        &self,
        integration_id: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        let api = required_property(props, "ApiId", integration_id)?;
        self.delete_call(
            "apigatewayv2",
            &format!("/v2/apis/{api}/integrations/{integration_id}"),
            integration_id,
        )
        .await
    }

    async fn delete_apigateway_v2_route(
        &self,
        route_id: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        let api = required_property(props, "ApiId", route_id)?;
        self.delete_call(
            "apigatewayv2",
            &format!("/v2/apis/{api}/routes/{route_id}"),
            route_id,
        )
        .await
    }

    async fn delete_apigateway_v2_stage(
        &self,
        stage_name: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        let api = required_property(props, "ApiId", stage_name)?;
        self.delete_call(
            "apigatewayv2",
            &format!("/v2/apis/{api}/stages/{stage_name}"),
            stage_name,
        )
        .await
    }

    async fn delete_apigateway_rest_api(&self, api_id: &str) -> Result<(), CfnError> {
        self.delete_call("apigateway", &format!("/restapis/{api_id}"), api_id)
            .await
    }

    async fn delete_apigateway_v2_api(&self, api_id: &str) -> Result<(), CfnError> {
        self.delete_call("apigatewayv2", &format!("/v2/apis/{api_id}"), api_id)
            .await
    }

    // --- dispatch helper ------------------------------------------------------------------

    async fn delete_call(
        &self,
        service: &str,
        path: &str,
        physical_id: &str,
    ) -> Result<(), CfnError> {
        let (status, response) = self
            .call(service, Method::DELETE, path, json_host(), Bytes::new())
            .await?;
        ensure_delete_succeeded(service, physical_id, status, &response)
    }

    async fn call_aws_json(
        &self,
        service: &str,
        target: &str,
        body: Value,
        logical_id: &str,
    ) -> Result<Value, CfnError> {
        let mut headers = json_host();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(target).map_err(|_| CfnError::Internal)?,
        );
        let (status, response) = self
            .call(
                service,
                Method::POST,
                "/",
                headers,
                Bytes::from(body.to_string()),
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "{service} provisioning for {logical_id} failed ({status}): {}",
                String::from_utf8_lossy(&response)
            )));
        }
        if response.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_slice(&response).map_err(|error| {
                CfnError::ResourceFailed(format!(
                    "{service} returned invalid JSON for {logical_id}: {error}"
                ))
            })
        }
    }

    async fn call_aws_json_11(
        &self,
        service: &str,
        target: &str,
        body: Value,
        logical_id: &str,
    ) -> Result<Value, CfnError> {
        let mut headers = json_11_host();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(target).map_err(|_| CfnError::Internal)?,
        );
        let (status, response) = self
            .call(
                service,
                Method::POST,
                "/",
                headers,
                Bytes::from(body.to_string()),
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "{service} provisioning for {logical_id} failed ({status}): {}",
                String::from_utf8_lossy(&response)
            )));
        }
        if response.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_slice(&response).map_err(|error| {
                CfnError::ResourceFailed(format!(
                    "{service} returned invalid JSON for {logical_id}: {error}"
                ))
            })
        }
    }

    async fn delete_aws_json_11(
        &self,
        service: &str,
        target: &str,
        body: Value,
        physical_id: &str,
        accepted_errors: &[&str],
    ) -> Result<(), CfnError> {
        let mut headers = json_11_host();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(target).map_err(|_| CfnError::Internal)?,
        );
        let (status, response) = self
            .call(
                service,
                Method::POST,
                "/",
                headers,
                Bytes::from(body.to_string()),
            )
            .await?;
        if (200..300).contains(&status)
            || accepted_errors
                .iter()
                .any(|error| aws_json_error_is(status, &response, error))
        {
            return Ok(());
        }
        Err(CfnError::ResourceFailed(format!(
            "{service} deletion for {physical_id} failed ({status}): {}",
            String::from_utf8_lossy(&response)
        )))
    }

    async fn call_logs(
        &self,
        operation: &str,
        body: Value,
        logical_id: &str,
    ) -> Result<Value, CfnError> {
        let mut headers = json_11_host();
        headers.insert(
            "x-amz-target",
            HeaderValue::from_str(&format!("Logs_20140328.{operation}"))
                .map_err(|_| CfnError::Internal)?,
        );
        let (status, response) = self
            .call(
                "logs",
                Method::POST,
                "/",
                headers,
                Bytes::from(body.to_string()),
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "CloudWatch Logs {operation} for {logical_id} failed ({status}): {}",
                String::from_utf8_lossy(&response)
            )));
        }
        if response.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_slice(&response).map_err(|error| {
                CfnError::ResourceFailed(format!(
                    "CloudWatch Logs returned invalid JSON for {logical_id}: {error}"
                ))
            })
        }
    }

    async fn call_json(
        &self,
        service: &str,
        method: Method,
        path: &str,
        body: Value,
        logical_id: &str,
    ) -> Result<Value, CfnError> {
        let (status, response) = self
            .call(
                service,
                method,
                path,
                json_host(),
                Bytes::from(body.to_string()),
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "{service} provisioning for {logical_id} failed ({status}): {}",
                String::from_utf8_lossy(&response)
            )));
        }
        if response.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_slice(&response).map_err(|error| {
                CfnError::ResourceFailed(format!(
                    "{service} returned invalid JSON for {logical_id}: {error}"
                ))
            })
        }
    }

    pub(crate) async fn call(
        &self,
        service: &str,
        method: Method,
        path: &str,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<(u16, Bytes), CfnError> {
        let registry = self.registry.upgrade().ok_or(CfnError::Internal)?;
        let handler = registry
            .native_handler(&ServiceName::new(service))
            .ok_or_else(|| {
                CfnError::ResourceFailed(format!("service {service} is not available"))
            })?;
        let request = ServiceRequest {
            method,
            uri: path.parse().map_err(|_| CfnError::Internal)?,
            headers,
            body,
            region: self.region.clone(),
            account_id: self.account.clone(),
            request_id: uuid::Uuid::new_v4().to_string(),
        };
        let response = if let Some(dispatcher) = registry.internal_dispatcher() {
            let mut headers = request.headers;
            let caller = self.caller_access_key.as_deref().unwrap_or("locallycloud");
            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!(
                    "AWS4-HMAC-SHA256 Credential={caller}/19700101/{}/{service}/aws4_request",
                    self.region
                ))
                .map_err(|_| CfnError::Internal)?,
            );
            dispatcher
                .dispatch_scoped(
                    &request.method,
                    &request.uri,
                    &headers,
                    request.body,
                    &request.request_id,
                    &self.account,
                    &self.region,
                )
                .await
        } else {
            handler.handle(request).await
        };
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map_err(|_| CfnError::Internal)?;
        Ok((status, bytes))
    }
}

fn validate_glue_database_properties(logical_id: &str, props: &Value) -> Result<(), CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::Glue::Database",
        props,
        &["CatalogId", "DatabaseInput"],
    )?;
    required_property(props, "CatalogId", logical_id)?;
    glue_input_name(logical_id, props, "DatabaseInput", "AWS::Glue::Database")?;
    Ok(())
}

fn validate_glue_table_properties(logical_id: &str, props: &Value) -> Result<(), CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::Glue::Table",
        props,
        &["CatalogId", "DatabaseName", "TableInput"],
    )?;
    required_property(props, "CatalogId", logical_id)?;
    required_property(props, "DatabaseName", logical_id)?;
    glue_input_name(logical_id, props, "TableInput", "AWS::Glue::Table")?;
    Ok(())
}

fn glue_input_name<'a>(
    logical_id: &str,
    props: &'a Value,
    input_property: &str,
    resource_type: &str,
) -> Result<&'a str, CfnError> {
    props
        .get(input_property)
        .and_then(Value::as_object)
        .and_then(|input| input.get("Name"))
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "{resource_type} resource {logical_id} requires non-empty {input_property}.Name"
            ))
        })
}

fn validate_kms_key_properties(logical_id: &str, props: &Value) -> Result<(), CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::KMS::Key",
        props,
        &[
            "Description",
            "KeyPolicy",
            "KeySpec",
            "KeyUsage",
            "Origin",
            "MultiRegion",
            "PendingWindowInDays",
        ],
    )?;
    if props
        .get("KeyPolicy")
        .is_some_and(|value| !value.is_object())
    {
        return Err(CfnError::Validation(format!(
            "AWS::KMS::Key resource {logical_id} requires KeyPolicy to be an object"
        )));
    }
    if props.get("Description").is_some_and(|value| {
        value
            .as_str()
            .is_none_or(|description| description.len() > 8192)
    }) {
        return Err(CfnError::Validation(format!(
            "AWS::KMS::Key resource {logical_id} requires Description to be a string of at most 8192 bytes"
        )));
    }
    for (property, expected) in [
        ("KeySpec", "SYMMETRIC_DEFAULT"),
        ("KeyUsage", "ENCRYPT_DECRYPT"),
        ("Origin", "AWS_KMS"),
    ] {
        if props
            .get(property)
            .is_some_and(|value| value.as_str() != Some(expected))
        {
            return Err(CfnError::Validation(format!(
                "AWS::KMS::Key resource {logical_id} supports only {property}={expected}"
            )));
        }
    }
    if props
        .get("MultiRegion")
        .is_some_and(|value| value.as_bool() != Some(false))
    {
        return Err(CfnError::Validation(format!(
            "AWS::KMS::Key resource {logical_id} supports only MultiRegion=false"
        )));
    }
    kms_pending_window_days(props)?;
    Ok(())
}

fn kms_pending_window_days(props: &Value) -> Result<u64, CfnError> {
    match props.get("PendingWindowInDays") {
        None => Ok(30),
        Some(value) => value
            .as_u64()
            .filter(|days| (7..=30).contains(days))
            .ok_or_else(|| {
                CfnError::Validation(
                    "AWS::KMS::Key requires PendingWindowInDays between 7 and 30".into(),
                )
            }),
    }
}

fn validate_kms_alias_properties(logical_id: &str, props: &Value) -> Result<(), CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::KMS::Alias",
        props,
        &["AliasName", "TargetKeyId"],
    )?;
    let alias_name = required_property(props, "AliasName", logical_id)?;
    if !alias_name.starts_with("alias/") || alias_name.starts_with("alias/aws/") {
        return Err(CfnError::Validation(format!(
            "AWS::KMS::Alias resource {logical_id} requires a customer AliasName beginning with alias/"
        )));
    }
    required_property(props, "TargetKeyId", logical_id)?;
    Ok(())
}

fn validate_event_bus_properties(logical_id: &str, props: &Value) -> Result<(), CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::Events::EventBus",
        props,
        &[
            "Name",
            "Description",
            "EventSourceName",
            "KmsKeyIdentifier",
            "DeadLetterConfig",
            "LogConfig",
            "Policy",
            "Tags",
        ],
    )?;
    required_property(props, "Name", logical_id)?;
    if props.get("EventSourceName").is_some()
        && props
            .get("EventSourceName")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        return Err(CfnError::Validation(format!(
            "AWS::Events::EventBus resource {logical_id} requires EventSourceName to be a non-empty string when specified"
        )));
    }
    for property in ["Description", "KmsKeyIdentifier"] {
        if props.get(property).is_some() && !props[property].is_string() {
            return Err(CfnError::Validation(format!(
                "AWS::Events::EventBus resource {logical_id} requires {property} to be a string"
            )));
        }
    }
    for property in ["DeadLetterConfig", "LogConfig", "Policy"] {
        if props.get(property).is_some() && !props[property].is_object() {
            return Err(CfnError::Validation(format!(
                "AWS::Events::EventBus resource {logical_id} requires {property} to be an object"
            )));
        }
    }
    event_bus_tags(logical_id, props)?;
    Ok(())
}

fn event_bus_resource_name(props: &Value, logical_id: &str) -> Result<String, CfnError> {
    required_property(props, "Name", logical_id)
}

fn event_bus_tags(
    logical_id: &str,
    props: &Value,
) -> Result<std::collections::BTreeMap<String, String>, CfnError> {
    let Some(tags) = props.get("Tags") else {
        return Ok(Default::default());
    };
    let tags = tags.as_array().ok_or_else(|| {
        CfnError::Validation(format!(
            "AWS::Events::EventBus resource {logical_id} requires Tags to be an array"
        ))
    })?;
    let mut output = std::collections::BTreeMap::new();
    for tag in tags {
        let key = tag
            .get("Key")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CfnError::Validation(format!(
                    "AWS::Events::EventBus resource {logical_id} requires non-empty tag keys"
                ))
            })?;
        let value = tag.get("Value").and_then(Value::as_str).ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::Events::EventBus resource {logical_id} requires string tag values"
            ))
        })?;
        if tag.as_object().is_none_or(|tag| {
            tag.keys()
                .any(|field| !matches!(field.as_str(), "Key" | "Value"))
        }) {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::Events::EventBus resource {logical_id} contains unsupported tag fields"
            )));
        }
        if output.insert(key.to_string(), value.to_string()).is_some() {
            return Err(CfnError::Validation(format!(
                "AWS::Events::EventBus resource {logical_id} has duplicate tag key {key}"
            )));
        }
    }
    Ok(output)
}

fn validate_sqs_queue_policy(logical_id: &str, props: &Value) -> Result<(), CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::SQS::QueuePolicy",
        props,
        &["Queues", "PolicyDocument"],
    )?;
    sqs_queue_policy_queues(logical_id, props)?;
    sqs_queue_policy_document(logical_id, props)?;
    Ok(())
}

fn sqs_queue_policy_queues<'a>(
    logical_id: &str,
    props: &'a Value,
) -> Result<Vec<&'a str>, CfnError> {
    let queues = props
        .get("Queues")
        .and_then(Value::as_array)
        .filter(|queues| !queues.is_empty())
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::SQS::QueuePolicy resource {logical_id} requires a non-empty Queues array"
            ))
        })?;
    let mut seen = std::collections::BTreeSet::new();
    let mut output = Vec::with_capacity(queues.len());
    for queue in queues {
        let queue = queue
            .as_str()
            .filter(|queue| !queue.is_empty())
            .ok_or_else(|| {
                CfnError::Validation(format!(
                    "AWS::SQS::QueuePolicy resource {logical_id} requires non-empty queue URLs"
                ))
            })?;
        if !seen.insert(queue) {
            return Err(CfnError::Validation(format!(
                "AWS::SQS::QueuePolicy resource {logical_id} contains duplicate queue URL {queue}"
            )));
        }
        output.push(queue);
    }
    Ok(output)
}

fn sqs_queue_policy_document(logical_id: &str, props: &Value) -> Result<String, CfnError> {
    props
        .get("PolicyDocument")
        .filter(|policy| policy.is_object())
        .map(Value::to_string)
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::SQS::QueuePolicy resource {logical_id} requires object PolicyDocument"
            ))
        })
}

fn validate_lambda_event_source_mapping(logical_id: &str, props: &Value) -> Result<(), CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::Lambda::EventSourceMapping",
        props,
        &[
            "FunctionName",
            "EventSourceArn",
            "BatchSize",
            "Enabled",
            "FunctionResponseTypes",
            "StartingPosition",
        ],
    )?;
    required_property(props, "FunctionName", logical_id)?;
    let source = required_property(props, "EventSourceArn", logical_id)?;
    let source_type = if source.starts_with("arn:aws:sqs:") {
        "sqs"
    } else if (source.starts_with("arn:aws:dynamodb:")
        && source.contains(":table/")
        && source.contains("/stream/"))
        || (source.starts_with("arn:aws:kinesis:") && source.contains(":stream/"))
    {
        "stream"
    } else {
        return Err(CfnError::Validation(format!(
            "AWS::Lambda::EventSourceMapping resource {logical_id} has unsupported EventSourceArn"
        )));
    };
    if let Some(batch_size) = props.get("BatchSize") {
        let max = if source_type == "sqs" { 10 } else { 10_000 };
        if !batch_size
            .as_u64()
            .is_some_and(|batch_size| (1..=max).contains(&batch_size))
        {
            return Err(CfnError::Validation(format!(
                "AWS::Lambda::EventSourceMapping resource {logical_id} requires BatchSize between 1 and {max}"
            )));
        }
    }
    if props
        .get("Enabled")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(CfnError::Validation(format!(
            "AWS::Lambda::EventSourceMapping resource {logical_id} requires Enabled to be boolean"
        )));
    }
    if let Some(response_types) = props.get("FunctionResponseTypes") {
        let valid = response_types.as_array().is_some_and(|values| {
            values.len() <= 1
                && values
                    .iter()
                    .all(|value| value.as_str() == Some("ReportBatchItemFailures"))
        });
        if !valid {
            return Err(CfnError::Validation(format!(
                "AWS::Lambda::EventSourceMapping resource {logical_id} supports only ReportBatchItemFailures"
            )));
        }
    }
    let starting_position = props.get("StartingPosition").and_then(Value::as_str);
    if source_type == "stream" && !matches!(starting_position, Some("LATEST" | "TRIM_HORIZON")) {
        return Err(CfnError::Validation(format!(
            "AWS::Lambda::EventSourceMapping resource {logical_id} requires LATEST or TRIM_HORIZON StartingPosition for stream sources"
        )));
    }
    if source_type == "sqs" && props.get("StartingPosition").is_some() {
        return Err(CfnError::Validation(format!(
            "AWS::Lambda::EventSourceMapping resource {logical_id} cannot specify StartingPosition for SQS"
        )));
    }
    Ok(())
}

fn lambda_event_source_mapping_default_batch_size(props: &Value) -> u64 {
    if props
        .get("EventSourceArn")
        .and_then(Value::as_str)
        .is_some_and(|source| source.starts_with("arn:aws:sqs:"))
    {
        10
    } else {
        100
    }
}

fn lambda_event_source_mapping_create_body(props: &Value) -> Value {
    mapped_properties(
        props,
        &[
            ("FunctionName", "FunctionName"),
            ("EventSourceArn", "EventSourceArn"),
            ("BatchSize", "BatchSize"),
            ("Enabled", "Enabled"),
            ("FunctionResponseTypes", "FunctionResponseTypes"),
            ("StartingPosition", "StartingPosition"),
        ],
    )
}

fn aws_json_error_is(status: u16, response: &[u8], suffix: &str) -> bool {
    status >= 400
        && serde_json::from_slice::<Value>(response)
            .ok()
            .and_then(|body| {
                body.get("__type")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .is_some_and(|error_type| error_type.ends_with(suffix))
}

fn sqs_queue_does_not_exist(status: u16, response: &[u8]) -> bool {
    aws_json_error_is(status, response, "#QueueDoesNotExist")
        || aws_json_error_is(status, response, "#AWS.SimpleQueueService.NonExistentQueue")
}

fn dynamodb_table_resolution(
    response: &Value,
    table_name: &str,
    logical_id: &str,
) -> Result<ResolvedResource, CfnError> {
    let table = response.get("Table").ok_or_else(|| {
        CfnError::ResourceFailed(format!(
            "DynamoDB DescribeTable for {logical_id} returned no Table"
        ))
    })?;
    let arn = required_response_string(table, "TableArn", logical_id)?;
    let mut attributes = std::collections::BTreeMap::new();
    attributes.insert("Arn".into(), arn);
    if let Some(stream_arn) = table.get("LatestStreamArn").and_then(Value::as_str) {
        attributes.insert("StreamArn".into(), stream_arn.to_string());
    }
    Ok(ResolvedResource {
        ref_value: table_name.to_string(),
        attributes,
    })
}

fn dynamodb_resource_not_found(status: u16, response: &[u8]) -> bool {
    status == 400
        && serde_json::from_slice::<Value>(response)
            .ok()
            .and_then(|body| {
                body.get("__type")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .is_some_and(|error_type| error_type.ends_with("#ResourceNotFoundException"))
}

fn dynamodb_billing_mode(props: &Value) -> &str {
    props
        .get("BillingMode")
        .and_then(Value::as_str)
        .unwrap_or("PROVISIONED")
}

fn validate_dynamodb_table_properties(logical_id: &str, props: &Value) -> Result<(), CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::DynamoDB::Table",
        props,
        &[
            "TableName",
            "AttributeDefinitions",
            "KeySchema",
            "BillingMode",
            "ProvisionedThroughput",
            "LocalSecondaryIndexes",
            "GlobalSecondaryIndexes",
            "StreamSpecification",
            "Tags",
            "TimeToLiveSpecification",
            "PointInTimeRecoverySpecification",
        ],
    )?;

    if props.get("TableName").is_some()
        && props
            .get("TableName")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .is_none()
    {
        return Err(CfnError::Validation(format!(
            "AWS::DynamoDB::Table resource {logical_id} requires TableName to be a non-empty string when specified"
        )));
    }

    let attribute_definitions = dynamodb_required_array(logical_id, props, "AttributeDefinitions")?;
    for definition in attribute_definitions {
        dynamodb_known_object_fields(
            logical_id,
            "AttributeDefinitions entry",
            definition,
            &["AttributeName", "AttributeType"],
        )?;
        dynamodb_required_string(
            logical_id,
            definition,
            "AttributeName",
            "AttributeDefinitions entry",
        )?;
        let attribute_type = dynamodb_required_string(
            logical_id,
            definition,
            "AttributeType",
            "AttributeDefinitions entry",
        )?;
        if !matches!(attribute_type, "S" | "N" | "B") {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} has invalid AttributeType {attribute_type}"
            )));
        }
    }
    validate_dynamodb_key_schema(
        logical_id,
        dynamodb_required_array(logical_id, props, "KeySchema")?,
        "KeySchema",
    )?;

    let billing_mode = dynamodb_billing_mode(props);
    if props.get("BillingMode").is_some() && !props["BillingMode"].is_string() {
        return Err(CfnError::Validation(format!(
            "AWS::DynamoDB::Table resource {logical_id} requires BillingMode to be a string"
        )));
    }
    if !matches!(billing_mode, "PROVISIONED" | "PAY_PER_REQUEST") {
        return Err(CfnError::Validation(format!(
            "AWS::DynamoDB::Table resource {logical_id} has invalid BillingMode {billing_mode}"
        )));
    }
    match (billing_mode, props.get("ProvisionedThroughput")) {
        ("PROVISIONED", Some(throughput)) => {
            dynamodb_throughput(logical_id, throughput)?;
        }
        ("PROVISIONED", None) => {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} requires ProvisionedThroughput with PROVISIONED billing"
            )))
        }
        ("PAY_PER_REQUEST", Some(_)) => {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} cannot specify ProvisionedThroughput with PAY_PER_REQUEST billing"
            )))
        }
        _ => {}
    }

    if let Some(indexes) = props.get("GlobalSecondaryIndexes") {
        if billing_mode != "PAY_PER_REQUEST" {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::DynamoDB::Table resource {logical_id} supports GlobalSecondaryIndexes only with PAY_PER_REQUEST billing"
            )));
        }
        validate_dynamodb_indexes(logical_id, indexes, "GlobalSecondaryIndexes")?;
    }
    if let Some(indexes) = props.get("LocalSecondaryIndexes") {
        validate_dynamodb_indexes(logical_id, indexes, "LocalSecondaryIndexes")?;
    }
    if let Some(specification) = props.get("StreamSpecification") {
        dynamodb_stream_specification(logical_id, specification)?;
    }
    if let Some(specification) = props.get("TimeToLiveSpecification") {
        dynamodb_known_object_fields(
            logical_id,
            "TimeToLiveSpecification",
            specification,
            &["AttributeName", "Enabled"],
        )?;
        let enabled = specification
            .get("Enabled")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                CfnError::Validation(format!(
                    "AWS::DynamoDB::Table resource {logical_id} requires boolean TimeToLiveSpecification.Enabled"
                ))
            })?;
        if enabled {
            dynamodb_required_string(
                logical_id,
                specification,
                "AttributeName",
                "TimeToLiveSpecification",
            )?;
        } else if specification.get("AttributeName").is_some()
            && specification
                .get("AttributeName")
                .and_then(Value::as_str)
                .is_none()
        {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} requires TimeToLiveSpecification.AttributeName to be a string when specified"
            )));
        }
    }
    if let Some(specification) = props.get("PointInTimeRecoverySpecification") {
        dynamodb_known_object_fields(
            logical_id,
            "PointInTimeRecoverySpecification",
            specification,
            &["PointInTimeRecoveryEnabled"],
        )?;
        if !specification
            .get("PointInTimeRecoveryEnabled")
            .is_some_and(Value::is_boolean)
        {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} requires boolean PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled"
            )));
        }
    }
    dynamodb_tags(logical_id, props)?;
    Ok(())
}

fn validate_dynamodb_ttl_update(
    logical_id: &str,
    previous: &Value,
    next: &Value,
) -> Result<(), CfnError> {
    let previous_ttl = previous.get("TimeToLiveSpecification");
    let next_ttl = next.get("TimeToLiveSpecification");
    let previous_enabled = previous_ttl
        .and_then(|value| value.get("Enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let next_enabled = next_ttl
        .and_then(|value| value.get("Enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let previous_attribute = previous_ttl
        .and_then(|value| value.get("AttributeName"))
        .and_then(Value::as_str);
    let next_attribute = next_ttl
        .and_then(|value| value.get("AttributeName"))
        .and_then(Value::as_str);
    if previous_enabled && next_enabled && previous_attribute != next_attribute {
        return Err(CfnError::ResourceFailed(format!(
            "AWS::DynamoDB::Table resource {logical_id} cannot change the enabled TTL attribute without disabling TTL first"
        )));
    }
    Ok(())
}

fn dynamodb_required_array<'a>(
    logical_id: &str,
    props: &'a Value,
    name: &str,
) -> Result<&'a [Value], CfnError> {
    props
        .get(name)
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .map(Vec::as_slice)
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} requires non-empty array property {name}"
            ))
        })
}

fn dynamodb_known_object_fields(
    logical_id: &str,
    property: &str,
    value: &Value,
    supported: &[&str],
) -> Result<(), CfnError> {
    let object = value.as_object().ok_or_else(|| {
        CfnError::Validation(format!(
            "AWS::DynamoDB::Table resource {logical_id} property {property} must be an object"
        ))
    })?;
    if object
        .keys()
        .any(|name| !supported.contains(&name.as_str()))
    {
        return Err(CfnError::ResourceFailed(format!(
            "AWS::DynamoDB::Table resource {logical_id} property {property} contains unsupported fields"
        )));
    }
    Ok(())
}

fn dynamodb_required_string<'a>(
    logical_id: &str,
    value: &'a Value,
    name: &str,
    property: &str,
) -> Result<&'a str, CfnError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} requires non-empty string {property}.{name}"
            ))
        })
}

fn validate_dynamodb_key_schema(
    logical_id: &str,
    key_schema: &[Value],
    property: &str,
) -> Result<(), CfnError> {
    if key_schema.is_empty() {
        return Err(CfnError::Validation(format!(
            "AWS::DynamoDB::Table resource {logical_id} requires non-empty {property}"
        )));
    }
    for key in key_schema {
        dynamodb_known_object_fields(
            logical_id,
            &format!("{property} entry"),
            key,
            &["AttributeName", "KeyType"],
        )?;
        dynamodb_required_string(
            logical_id,
            key,
            "AttributeName",
            &format!("{property} entry"),
        )?;
        let key_type =
            dynamodb_required_string(logical_id, key, "KeyType", &format!("{property} entry"))?;
        if !matches!(key_type, "HASH" | "RANGE") {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} has invalid {property} KeyType {key_type}"
            )));
        }
    }
    Ok(())
}

fn validate_dynamodb_indexes(
    logical_id: &str,
    value: &Value,
    property: &str,
) -> Result<(), CfnError> {
    let indexes = value.as_array().filter(|values| !values.is_empty()).ok_or_else(|| {
        CfnError::Validation(format!(
            "AWS::DynamoDB::Table resource {logical_id} property {property} must be a non-empty array"
        ))
    })?;
    for index in indexes {
        dynamodb_known_object_fields(
            logical_id,
            &format!("{property} entry"),
            index,
            &["IndexName", "KeySchema", "Projection"],
        )?;
        dynamodb_required_string(logical_id, index, "IndexName", &format!("{property} entry"))?;
        let key_schema = index
            .get("KeySchema")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CfnError::Validation(format!(
                    "AWS::DynamoDB::Table resource {logical_id} requires array {property}.KeySchema"
                ))
            })?;
        validate_dynamodb_key_schema(logical_id, key_schema, &format!("{property}.KeySchema"))?;
        let projection = index.get("Projection").ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} requires {property}.Projection"
            ))
        })?;
        dynamodb_known_object_fields(
            logical_id,
            &format!("{property}.Projection"),
            projection,
            &["ProjectionType", "NonKeyAttributes"],
        )?;
        let projection_type = dynamodb_required_string(
            logical_id,
            projection,
            "ProjectionType",
            &format!("{property}.Projection"),
        )?;
        if !matches!(projection_type, "ALL" | "KEYS_ONLY" | "INCLUDE") {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} has invalid {property} ProjectionType {projection_type}"
            )));
        }
        if projection
            .get("NonKeyAttributes")
            .is_some_and(|attributes| {
                attributes
                    .as_array()
                    .is_none_or(|values| values.iter().any(|value| !value.is_string()))
            })
        {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} requires {property}.Projection.NonKeyAttributes to be a string array"
            )));
        }
    }
    Ok(())
}

fn dynamodb_throughput(logical_id: &str, value: &Value) -> Result<Value, CfnError> {
    dynamodb_known_object_fields(
        logical_id,
        "ProvisionedThroughput",
        value,
        &["ReadCapacityUnits", "WriteCapacityUnits"],
    )?;
    let read = value
        .get("ReadCapacityUnits")
        .map(coerce_number)
        .filter(|value| value.as_u64().is_some_and(|capacity| capacity > 0))
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} requires positive ProvisionedThroughput.ReadCapacityUnits"
            ))
        })?;
    let write = value
        .get("WriteCapacityUnits")
        .map(coerce_number)
        .filter(|value| value.as_u64().is_some_and(|capacity| capacity > 0))
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} requires positive ProvisionedThroughput.WriteCapacityUnits"
            ))
        })?;
    Ok(json!({
        "ReadCapacityUnits": read,
        "WriteCapacityUnits": write,
    }))
}

fn dynamodb_stream_specification(logical_id: &str, value: &Value) -> Result<Value, CfnError> {
    dynamodb_known_object_fields(
        logical_id,
        "StreamSpecification",
        value,
        &["StreamViewType"],
    )?;
    let view_type =
        dynamodb_required_string(logical_id, value, "StreamViewType", "StreamSpecification")?;
    if !matches!(
        view_type,
        "KEYS_ONLY" | "NEW_IMAGE" | "OLD_IMAGE" | "NEW_AND_OLD_IMAGES"
    ) {
        return Err(CfnError::Validation(format!(
            "AWS::DynamoDB::Table resource {logical_id} has invalid StreamViewType {view_type}"
        )));
    }
    Ok(json!({
        "StreamEnabled": true,
        "StreamViewType": view_type,
    }))
}

fn dynamodb_tags(
    logical_id: &str,
    props: &Value,
) -> Result<std::collections::BTreeMap<String, String>, CfnError> {
    let Some(tags) = props.get("Tags") else {
        return Ok(std::collections::BTreeMap::new());
    };
    let tags = tags.as_array().ok_or_else(|| {
        CfnError::Validation(format!(
            "AWS::DynamoDB::Table resource {logical_id} property Tags must be an array"
        ))
    })?;
    let mut output = std::collections::BTreeMap::new();
    for tag in tags {
        dynamodb_known_object_fields(logical_id, "Tags entry", tag, &["Key", "Value"])?;
        let key = dynamodb_required_string(logical_id, tag, "Key", "Tags entry")?;
        let value = tag.get("Value").and_then(Value::as_str).ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} requires string Tags entry.Value"
            ))
        })?;
        if output.insert(key.to_string(), value.to_string()).is_some() {
            return Err(CfnError::Validation(format!(
                "AWS::DynamoDB::Table resource {logical_id} has duplicate tag key {key}"
            )));
        }
    }
    Ok(output)
}

fn pipe_body(props: &Value) -> Value {
    mapped_properties(
        props,
        &[
            ("Source", "Source"),
            ("Target", "Target"),
            ("RoleArn", "RoleArn"),
            ("Description", "Description"),
            ("DesiredState", "DesiredState"),
            ("SourceParameters", "SourceParameters"),
            ("TargetParameters", "TargetParameters"),
            ("Enrichment", "Enrichment"),
            ("EnrichmentParameters", "EnrichmentParameters"),
            ("Tags", "Tags"),
        ],
    )
}

fn pipe_resolution(
    response: &Value,
    name: &str,
    logical_id: &str,
) -> Result<ResolvedResource, CfnError> {
    let arn = required_response_string(response, "Arn", logical_id)?;
    let mut attributes = std::collections::BTreeMap::new();
    attributes.insert("Arn".into(), arn);
    if let Some(state) = response.get("CurrentState").and_then(Value::as_str) {
        attributes.insert("CurrentState".into(), state.to_string());
    }
    Ok(ResolvedResource {
        ref_value: name.to_string(),
        attributes,
    })
}

fn sns_topic_attributes(props: &Value) -> serde_json::Map<String, Value> {
    let mut attributes = serde_json::Map::new();
    for (source, target) in [
        ("DisplayName", "DisplayName"),
        ("FifoTopic", "FifoTopic"),
        ("ContentBasedDeduplication", "ContentBasedDeduplication"),
        ("KmsMasterKeyId", "KmsMasterKeyId"),
        ("SignatureVersion", "SignatureVersion"),
        ("DeliveryPolicy", "DeliveryPolicy"),
    ] {
        if let Some(value) = props.get(source) {
            let value = match value {
                Value::String(value) => value.clone(),
                Value::Bool(value) => value.to_string(),
                Value::Object(_) => value.to_string(),
                _ => continue,
            };
            attributes.insert(target.into(), Value::String(value));
        }
    }
    attributes
}

fn sns_subscription_attributes(props: &Value) -> serde_json::Map<String, Value> {
    let mut attributes = serde_json::Map::new();
    for name in [
        "RawMessageDelivery",
        "FilterPolicy",
        "FilterPolicyScope",
        "RedrivePolicy",
        "DeliveryPolicy",
    ] {
        if let Some(value) = props.get(name) {
            let value = match value {
                Value::String(value) => value.clone(),
                Value::Bool(value) => value.to_string(),
                Value::Object(_) => value.to_string(),
                _ => continue,
            };
            attributes.insert(name.into(), Value::String(value));
        }
    }
    attributes
}

fn validate_route53_health_check<'a>(
    logical_id: &str,
    props: &'a Value,
) -> Result<&'a str, CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::Route53::HealthCheck",
        props,
        &["HealthCheckConfig"],
    )?;
    let config = props
        .get("HealthCheckConfig")
        .and_then(Value::as_object)
        .ok_or_else(|| CfnError::Validation(format!("{logical_id} requires HealthCheckConfig")))?;
    if config
        .keys()
        .any(|name| !["Type", "RoutingControlArn"].contains(&name.as_str()))
        || config.get("Type").and_then(Value::as_str) != Some("RECOVERY_CONTROL")
    {
        return Err(CfnError::Validation(format!(
            "{logical_id} supports only RECOVERY_CONTROL health checks"
        )));
    }
    config
        .get("RoutingControlArn")
        .and_then(Value::as_str)
        .filter(|arn| !arn.is_empty())
        .ok_or_else(|| CfnError::Validation(format!("{logical_id} requires RoutingControlArn")))
}

fn route53_xml_id(response: &[u8], logical_id: &str) -> Result<String, CfnError> {
    let xml = std::str::from_utf8(response).map_err(|_| CfnError::Internal)?;
    let id = xml
        .split_once("<Id>")
        .and_then(|(_, tail)| tail.split_once("</Id>"))
        .map(|(id, _)| id)
        .filter(|id| {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        })
        .ok_or_else(|| {
            CfnError::ResourceFailed(format!(
                "Route53 returned no health check ID for {logical_id}"
            ))
        })?;
    Ok(id.to_owned())
}

fn route53_record_xml(logical_id: &str, props: &Value) -> Result<String, CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::Route53::RecordSet",
        props,
        &[
            "HostedZoneId",
            "Name",
            "Type",
            "TTL",
            "ResourceRecords",
            "Failover",
            "SetIdentifier",
            "HealthCheckId",
            "AliasTarget",
        ],
    )?;
    let name = required_property(props, "Name", logical_id)?;
    required_property(props, "HostedZoneId", logical_id)?;
    let kind = required_property(props, "Type", logical_id)?;
    if !["A", "AAAA", "CNAME", "TXT"].contains(&kind.as_str()) {
        return Err(CfnError::Validation(format!(
            "{logical_id} has unsupported record Type"
        )));
    }
    let destination = if let Some(alias) = props.get("AliasTarget") {
        ensure_known_properties(
            logical_id,
            "AliasTarget",
            alias,
            &["DNSName", "HostedZoneId", "EvaluateTargetHealth"],
        )?;
        if !matches!(kind.as_str(), "A" | "AAAA")
            || props.get("TTL").is_some()
            || props.get("ResourceRecords").is_some()
        {
            return Err(CfnError::Validation(format!(
                "{logical_id} AliasTarget requires A/AAAA without TTL/ResourceRecords"
            )));
        }
        let dns = required_property(alias, "DNSName", logical_id)?;
        let zone = required_property(alias, "HostedZoneId", logical_id)?;
        let evaluate = alias
            .get("EvaluateTargetHealth")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                CfnError::Validation(format!(
                    "{logical_id} requires boolean EvaluateTargetHealth"
                ))
            })?;
        format!("<AliasTarget><HostedZoneId>{}</HostedZoneId><DNSName>{}</DNSName><EvaluateTargetHealth>{evaluate}</EvaluateTargetHealth></AliasTarget>", xml_escape(&zone), xml_escape(&dns))
    } else {
        let ttl = props
            .get("TTL")
            .and_then(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| value.as_u64().map(|n| n.to_string()))
            })
            .and_then(|value| value.parse::<u32>().ok().map(|_| value))
            .ok_or_else(|| CfnError::Validation(format!("{logical_id} requires numeric TTL")))?;
        let values = props
            .get("ResourceRecords")
            .and_then(Value::as_array)
            .filter(|values| !values.is_empty() && values.len() <= 1000)
            .ok_or_else(|| {
                CfnError::Validation(format!("{logical_id} requires ResourceRecords"))
            })?;
        let mut records = String::new();
        for value in values {
            let value = value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CfnError::Validation(format!("{logical_id} requires string ResourceRecords"))
                })?;
            records.push_str(&format!(
                "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                xml_escape(value)
            ));
        }
        format!("<TTL>{ttl}</TTL><ResourceRecords>{records}</ResourceRecords>")
    };
    let failover = props.get("Failover").and_then(Value::as_str);
    let identifier = props.get("SetIdentifier").and_then(Value::as_str);
    if (failover.is_some() != identifier.is_some())
        || failover.is_some_and(|role| !["PRIMARY", "SECONDARY"].contains(&role))
        || identifier.is_some_and(str::is_empty)
    {
        return Err(CfnError::Validation(format!(
            "{logical_id} requires matching Failover and SetIdentifier"
        )));
    }
    let check = props.get("HealthCheckId").and_then(Value::as_str);
    if props.get("HealthCheckId").is_some() && check.is_none_or(str::is_empty) {
        return Err(CfnError::Validation(format!(
            "{logical_id} has invalid HealthCheckId"
        )));
    }
    let identifier = identifier
        .map(|id| format!("<SetIdentifier>{}</SetIdentifier>", xml_escape(id)))
        .unwrap_or_default();
    let failover = failover
        .map(|role| format!("<Failover>{role}</Failover>"))
        .unwrap_or_default();
    let check = check
        .map(|id| format!("<HealthCheckId>{}</HealthCheckId>", xml_escape(id)))
        .unwrap_or_default();
    Ok(format!("<ResourceRecordSet><Name>{}</Name><Type>{kind}</Type>{identifier}{failover}{destination}{check}</ResourceRecordSet>", xml_escape(&name)))
}

fn ensure_known_properties(
    logical_id: &str,
    resource_type: &str,
    props: &Value,
    supported: &[&str],
) -> Result<(), CfnError> {
    if props
        .as_object()
        .into_iter()
        .flatten()
        .any(|(name, _)| !supported.contains(&name.as_str()))
    {
        return Err(CfnError::ResourceFailed(format!(
            "{resource_type} resource {logical_id} contains unsupported properties"
        )));
    }
    Ok(())
}

fn validate_logs_stream_properties(logical_id: &str, props: &Value) -> Result<(), CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::Logs::LogStream",
        props,
        &["LogGroupName", "LogStreamName"],
    )?;
    logs_stream_group(props)?;
    if props.get("LogStreamName").is_some()
        && props
            .get("LogStreamName")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .is_none()
    {
        return Err(CfnError::Validation(format!(
            "AWS::Logs::LogStream resource {logical_id} requires LogStreamName to be a non-empty string when specified"
        )));
    }
    Ok(())
}

fn logs_stream_group(props: &Value) -> Result<&str, CfnError> {
    props
        .get("LogGroupName")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            CfnError::Validation("AWS::Logs::LogStream requires non-empty LogGroupName".into())
        })
}

fn sqs_attributes(props: &Value) -> serde_json::Map<String, Value> {
    const FIELDS: &[&str] = &[
        "DelaySeconds",
        "MaximumMessageSize",
        "MessageRetentionPeriod",
        "ReceiveMessageWaitTimeSeconds",
        "VisibilityTimeout",
        "RedrivePolicy",
        "RedriveAllowPolicy",
        "FifoQueue",
        "ContentBasedDeduplication",
        "DeduplicationScope",
        "FifoThroughputLimit",
        "KmsDataKeyReusePeriodSeconds",
        "KmsMasterKeyId",
        "SqsManagedSseEnabled",
    ];
    FIELDS
        .iter()
        .filter_map(|name| {
            let value = props.get(*name)?;
            let value = match value {
                Value::String(value) => value.clone(),
                Value::Bool(value) => value.to_string(),
                Value::Number(value) => value.to_string(),
                value => value.to_string(),
            };
            Some(((*name).to_string(), Value::String(value)))
        })
        .collect()
}

fn cfn_tags_object(props: &Value) -> serde_json::Map<String, Value> {
    props
        .get("Tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tag| {
            Some((
                tag.get("Key")?.as_str()?.to_string(),
                Value::String(tag.get("Value")?.as_str()?.to_string()),
            ))
        })
        .collect()
}

fn event_bus_name(props: &Value) -> String {
    props
        .get("EventBusName")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .split_once(":event-bus/")
                .map(|(_, name)| name)
                .unwrap_or(value)
                .to_string()
        })
        .unwrap_or_else(|| "default".to_string())
}

fn event_target_ids(props: &Value) -> Vec<String> {
    props
        .get("Targets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|target| target.get("Id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

fn ensure_only_supported_changes(
    logical_id: &str,
    resource_type: &str,
    previous: &Value,
    next: &Value,
    supported: &[&str],
) -> Result<(), CfnError> {
    let changed_unsupported = previous
        .as_object()
        .into_iter()
        .flatten()
        .chain(next.as_object().into_iter().flatten())
        .any(|(name, _)| {
            !supported.contains(&name.as_str()) && previous.get(name) != next.get(name)
        });
    if changed_unsupported {
        return Err(CfnError::ResourceFailed(format!(
            "{resource_type} resource {logical_id} contains changed properties that are not supported"
        )));
    }
    Ok(())
}

fn effective_property(props: &Value, name: &str, default: Value) -> Value {
    props.get(name).cloned().unwrap_or(default)
}

fn reset_removed_property(
    body: &mut Value,
    previous: &Value,
    next: &Value,
    source: &str,
    target: &str,
    default: Value,
) {
    if previous.get(source).is_some() && next.get(source).is_none() {
        body[target] = default;
    }
}

fn endpoint_types(props: &Value) -> Value {
    props
        .get("EndpointConfiguration")
        .and_then(|configuration| configuration.get("Types"))
        .cloned()
        .unwrap_or_else(|| json!(["EDGE"]))
}

fn binary_media_types(props: &Value) -> Vec<Value> {
    props
        .get("BinaryMediaTypes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn api_id<'a>(props: &'a Value, name: &str) -> Option<&'a str> {
    props.get(name).and_then(Value::as_str)
}

fn apigateway_method_id(props: &Value) -> Option<String> {
    Some(format!(
        "{}:{}:{}",
        api_id(props, "RestApiId")?,
        api_id(props, "ResourceId")?,
        api_id(props, "HttpMethod")?
    ))
}

fn parse_apigateway_method_id(physical_id: &str) -> Option<(&str, &str, &str)> {
    let mut parts = physical_id.splitn(3, ':');
    Some((parts.next()?, parts.next()?, parts.next()?))
}

fn mapped_object_property(
    value: &Value,
    logical_id: &str,
    property: &str,
    fields: &[(&str, &str)],
) -> Result<Value, CfnError> {
    let object = value.as_object().ok_or_else(|| {
        CfnError::Validation(format!(
            "{logical_id} property {property} must be an object"
        ))
    })?;
    if let Some(name) = object
        .keys()
        .find(|name| !fields.iter().any(|(source, _)| source == &name.as_str()))
    {
        return Err(CfnError::Validation(format!(
            "{logical_id} property {property} contains unsupported field {name}"
        )));
    }
    Ok(mapped_properties(value, fields))
}

fn apigateway_v2_access_log_settings(value: &Value, logical_id: &str) -> Result<Value, CfnError> {
    mapped_object_property(
        value,
        logical_id,
        "AccessLogSettings",
        &[("DestinationArn", "destinationArn"), ("Format", "format")],
    )
}

fn api_routes_from_body(body: &Value) -> Result<Vec<(String, String, String)>, CfnError> {
    let root = body
        .as_object()
        .ok_or_else(|| CfnError::Validation("HTTP API Body must be an object".into()))?;
    if root
        .keys()
        .any(|key| !matches!(key.as_str(), "openapi" | "info" | "paths" | "tags"))
    {
        return Err(CfnError::Validation(
            "unsupported HTTP API Body field".into(),
        ));
    }
    if body.get("openapi").and_then(Value::as_str) != Some("3.0.1") {
        return Err(CfnError::Validation(
            "HTTP API Body requires OpenAPI 3.0.1".into(),
        ));
    }
    let paths = body
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| CfnError::Validation("HTTP API Body.paths must be an object".into()))?;
    let mut routes = Vec::new();
    for (path, methods) in paths {
        if !path.starts_with('/') && path != "$default" {
            return Err(CfnError::Validation(
                "HTTP API path must start with /".into(),
            ));
        }
        let methods = methods
            .as_object()
            .ok_or_else(|| CfnError::Validation("HTTP API methods must be an object".into()))?;
        for (method, operation) in methods {
            if !matches!(
                method.as_str(),
                "get"
                    | "post"
                    | "put"
                    | "patch"
                    | "delete"
                    | "head"
                    | "options"
                    | "x-amazon-apigateway-any-method"
            ) {
                return Err(CfnError::Validation(format!(
                    "unsupported HTTP API method {method}"
                )));
            }
            let fields = operation.as_object().ok_or_else(|| {
                CfnError::Validation("HTTP API operation must be an object".into())
            })?;
            if fields.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "responses" | "x-amazon-apigateway-integration" | "isDefaultRoute"
                )
            }) || operation.get("responses") != Some(&json!({}))
            {
                return Err(CfnError::Validation(
                    "unsupported HTTP API operation field".into(),
                ));
            }
            if operation.get("isDefaultRoute").is_some()
                && (path != "$default" || operation.get("isDefaultRoute") != Some(&json!(true)))
            {
                return Err(CfnError::Validation(
                    "invalid HTTP API default route".into(),
                ));
            }
            let integration = operation
                .get("x-amazon-apigateway-integration")
                .ok_or_else(|| {
                    CfnError::Validation("HTTP API route requires Lambda integration".into())
                })?;
            let integration_fields = integration.as_object().ok_or_else(|| {
                CfnError::Validation("HTTP API integration must be an object".into())
            })?;
            if integration_fields.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "type" | "httpMethod" | "uri" | "payloadFormatVersion"
                )
            }) {
                return Err(CfnError::Validation(
                    "unsupported HTTP API integration field".into(),
                ));
            }
            if integration.get("type").and_then(Value::as_str) != Some("aws_proxy")
                || integration.get("httpMethod").and_then(Value::as_str) != Some("POST")
            {
                return Err(CfnError::Validation(
                    "unsupported HTTP API integration".into(),
                ));
            }
            let uri = integration
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CfnError::Validation("HTTP API integration uri is required".into())
                })?;
            if !uri.contains(":apigateway:")
                || !uri.contains(":lambda:path/2015-03-31/functions/")
                || !uri.ends_with("/invocations")
            {
                return Err(CfnError::Validation(
                    "unsupported HTTP API Lambda integration uri".into(),
                ));
            }
            let payload = integration
                .get("payloadFormatVersion")
                .and_then(Value::as_str)
                .filter(|value| matches!(*value, "1.0" | "2.0"))
                .ok_or_else(|| {
                    CfnError::Validation("unsupported HTTP API payload format".into())
                })?;
            let route_key = if path == "$default" {
                "$default".to_string()
            } else if method == "x-amazon-apigateway-any-method" {
                format!("ANY {path}")
            } else {
                format!("{} {path}", method.to_ascii_uppercase())
            };
            routes.push((route_key, uri.into(), payload.into()));
        }
    }
    Ok(routes)
}

fn apigateway_v2_cors(value: &Value, logical_id: &str) -> Result<Value, CfnError> {
    mapped_object_property(
        value,
        logical_id,
        "CorsConfiguration",
        &[
            ("AllowCredentials", "allowCredentials"),
            ("AllowHeaders", "allowHeaders"),
            ("AllowMethods", "allowMethods"),
            ("AllowOrigins", "allowOrigins"),
            ("ExposeHeaders", "exposeHeaders"),
            ("MaxAge", "maxAge"),
        ],
    )
}

fn apigateway_stage_description(
    value: Option<&Value>,
    logical_id: &str,
) -> Result<Option<Value>, CfnError> {
    let Some(value) = value else { return Ok(None) };
    let description = value.as_object().ok_or_else(|| {
        CfnError::Validation(format!(
            "{logical_id} property StageDescription must be an object"
        ))
    })?;
    let allowed = [
        "AccessLogSetting",
        "Description",
        "MethodSettings",
        "Variables",
    ];
    if let Some(name) = description
        .keys()
        .find(|name| !allowed.contains(&name.as_str()))
    {
        return Err(CfnError::Validation(format!(
            "{logical_id} property StageDescription contains unsupported field {name}"
        )));
    }
    let mut mapped = serde_json::Map::new();
    for (source, target) in [("Description", "description"), ("Variables", "variables")] {
        if let Some(value) = description.get(source) {
            mapped.insert(target.to_string(), value.clone());
        }
    }
    if description
        .get("Variables")
        .is_some_and(|variables| !variables.is_object())
    {
        return Err(CfnError::Validation(format!(
            "{logical_id} property StageDescription.Variables must be an object"
        )));
    }
    if let Some(access) = description.get("AccessLogSetting") {
        mapped.insert(
            "accessLogSettings".into(),
            mapped_object_property(
                access,
                logical_id,
                "StageDescription.AccessLogSetting",
                &[("DestinationArn", "destinationArn"), ("Format", "format")],
            )?,
        );
    }
    if let Some(methods) = description.get("MethodSettings") {
        let methods = methods.as_array().ok_or_else(|| {
            CfnError::Validation(format!(
                "{logical_id} property StageDescription.MethodSettings must be a list"
            ))
        })?;
        let method_fields = [
            ("ResourcePath", "resourcePath"),
            ("HttpMethod", "httpMethod"),
            ("LoggingLevel", "loggingLevel"),
            ("DataTraceEnabled", "dataTraceEnabled"),
            ("MetricsEnabled", "metricsEnabled"),
            ("CachingEnabled", "cachingEnabled"),
            ("CacheTtlInSeconds", "cacheTtlInSeconds"),
            ("CacheDataEncrypted", "cacheDataEncrypted"),
            (
                "RequireAuthorizationForCacheControl",
                "requireAuthorizationForCacheControl",
            ),
            (
                "UnauthorizedCacheControlHeaderStrategy",
                "unauthorizedCacheControlHeaderStrategy",
            ),
            ("ThrottlingBurstLimit", "throttlingBurstLimit"),
            ("ThrottlingRateLimit", "throttlingRateLimit"),
        ];
        let mut settings = serde_json::Map::new();
        for method in methods {
            let method = mapped_object_property(
                method,
                logical_id,
                "StageDescription.MethodSettings[]",
                &method_fields,
            )?;
            let resource = method
                .get("resourcePath")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CfnError::Validation(format!(
                        "{logical_id} MethodSettings entry requires ResourcePath"
                    ))
                })?;
            let http_method = method
                .get("httpMethod")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    CfnError::Validation(format!(
                        "{logical_id} MethodSettings entry requires HttpMethod"
                    ))
                })?;
            let key = if resource == "/*" && http_method == "*" {
                "*/*".to_string()
            } else {
                format!("{http_method}/{resource}")
            };
            let mut setting = method
                .as_object()
                .cloned()
                .expect("mapped object is an object");
            setting.remove("resourcePath");
            setting.remove("httpMethod");
            settings.insert(key, Value::Object(setting));
        }
        mapped.insert("methodSettings".into(), Value::Object(settings));
    }
    Ok(Some(Value::Object(mapped)))
}

fn mapped_properties(props: &Value, fields: &[(&str, &str)]) -> Value {
    let mut body = serde_json::Map::new();
    for (source, target) in fields {
        if let Some(value) = props.get(*source) {
            body.insert((*target).to_string(), value.clone());
        }
    }
    Value::Object(body)
}

fn validate_s3_bucket_properties(logical_id: &str, props: &Value) -> Result<(), CfnError> {
    if !props.is_object() {
        return Err(CfnError::Validation(format!(
            "AWS::S3::Bucket resource {logical_id} requires Properties to be an object"
        )));
    }
    ensure_known_properties(
        logical_id,
        "AWS::S3::Bucket",
        props,
        &[
            "BucketName",
            "BucketNamePrefix",
            "BucketNamespace",
            "BucketEncryption",
            "VersioningConfiguration",
            "NotificationConfiguration",
        ],
    )?;
    if props.get("BucketName").is_some()
        && props
            .get("BucketName")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .is_none()
    {
        return Err(CfnError::Validation(format!(
            "AWS::S3::Bucket resource {logical_id} requires BucketName to be a non-empty string when specified"
        )));
    }
    let namespace = props.get("BucketNamespace").and_then(Value::as_str);
    if props.get("BucketNamespace").is_some()
        && !matches!(namespace, Some("global" | "account-regional"))
    {
        return Err(CfnError::Validation(format!(
            "AWS::S3::Bucket resource {logical_id} requires BucketNamespace global or account-regional"
        )));
    }
    if props.get("BucketNamePrefix").is_some() {
        let valid_prefix = props
            .get("BucketNamePrefix")
            .and_then(Value::as_str)
            .is_some_and(|prefix| !prefix.is_empty());
        if !valid_prefix
            || namespace != Some("account-regional")
            || props.get("BucketName").is_some()
        {
            return Err(CfnError::Validation(format!(
                "AWS::S3::Bucket resource {logical_id} requires BucketNamePrefix with account-regional namespace and without BucketName"
            )));
        }
    }
    if let Some(value) = props.get("BucketEncryption") {
        s3_bucket_encryption_xml(logical_id, value)?;
    }
    if let Some(value) = props.get("VersioningConfiguration") {
        s3_bucket_versioning_xml(logical_id, value)?;
    }
    if let Some(value) = props.get("NotificationConfiguration") {
        s3_bucket_notification_xml(logical_id, value)?;
    }
    Ok(())
}

fn s3_bucket_encryption_xml(logical_id: &str, value: &Value) -> Result<String, CfnError> {
    let configuration = value.as_object().ok_or_else(|| {
        CfnError::Validation(format!(
            "AWS::S3::Bucket resource {logical_id} requires BucketEncryption to be an object"
        ))
    })?;
    ensure_known_properties(
        logical_id,
        "AWS::S3::Bucket.BucketEncryption",
        value,
        &["ServerSideEncryptionConfiguration"],
    )?;
    let rules = configuration
        .get("ServerSideEncryptionConfiguration")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::S3::Bucket resource {logical_id} requires ServerSideEncryptionConfiguration to be an array"
            ))
        })?;
    if rules.len() != 1 {
        return Err(CfnError::Validation(format!(
            "AWS::S3::Bucket resource {logical_id} supports exactly one server-side encryption rule"
        )));
    }
    let rule = &rules[0];
    ensure_known_properties(
        logical_id,
        "AWS::S3::Bucket.ServerSideEncryptionRule",
        rule,
        &["ServerSideEncryptionByDefault", "BucketKeyEnabled"],
    )?;
    let rule = rule.as_object().ok_or_else(|| {
        CfnError::Validation(format!(
            "AWS::S3::Bucket resource {logical_id} requires the encryption rule to be an object"
        ))
    })?;
    let default = rule.get("ServerSideEncryptionByDefault").ok_or_else(|| {
        CfnError::Validation(format!(
            "AWS::S3::Bucket resource {logical_id} requires ServerSideEncryptionByDefault"
        ))
    })?;
    ensure_known_properties(
        logical_id,
        "AWS::S3::Bucket.ServerSideEncryptionByDefault",
        default,
        &["SSEAlgorithm", "KMSMasterKeyID"],
    )?;
    let default = default.as_object().ok_or_else(|| {
        CfnError::Validation(format!(
            "AWS::S3::Bucket resource {logical_id} requires ServerSideEncryptionByDefault to be an object"
        ))
    })?;
    let algorithm = default
        .get("SSEAlgorithm")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::S3::Bucket resource {logical_id} requires SSEAlgorithm"
            ))
        })?;
    let kms_key = match default.get("KMSMasterKeyID") {
        Some(value) => Some(
            value
                .as_str()
                .filter(|key| !key.is_empty())
                .ok_or_else(|| {
                    CfnError::Validation(format!(
                        "AWS::S3::Bucket resource {logical_id} requires KMSMasterKeyID to be a non-empty string"
                    ))
                })?,
        ),
        None => None,
    };
    match algorithm {
        "AES256" if kms_key.is_none() => {}
        "AES256" => {
            return Err(CfnError::Validation(format!(
                "AWS::S3::Bucket resource {logical_id} cannot use KMSMasterKeyID with AES256"
            )))
        }
        "aws:kms" if kms_key.is_some() => {}
        "aws:kms" => {
            return Err(CfnError::Validation(format!(
                "AWS::S3::Bucket resource {logical_id} requires KMSMasterKeyID with aws:kms"
            )))
        }
        _ => {
            return Err(CfnError::Validation(format!(
                "AWS::S3::Bucket resource {logical_id} supports only AES256 or aws:kms encryption"
            )))
        }
    }
    let bucket_key_enabled = match rule.get("BucketKeyEnabled") {
        Some(value) => Some(value.as_bool().ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::S3::Bucket resource {logical_id} requires BucketKeyEnabled to be a boolean"
            ))
        })?),
        None => None,
    };

    let mut xml = format!(
        "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>{algorithm}</SSEAlgorithm>"
    );
    if let Some(key) = kms_key {
        xml.push_str(&format!(
            "<KMSMasterKeyID>{}</KMSMasterKeyID>",
            xml_escape(key)
        ));
    }
    xml.push_str("</ApplyServerSideEncryptionByDefault>");
    if let Some(enabled) = bucket_key_enabled {
        xml.push_str(&format!("<BucketKeyEnabled>{enabled}</BucketKeyEnabled>"));
    }
    xml.push_str("</Rule></ServerSideEncryptionConfiguration>");
    Ok(xml)
}

fn s3_bucket_versioning_xml(logical_id: &str, value: &Value) -> Result<String, CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::S3::Bucket.VersioningConfiguration",
        value,
        &["Status"],
    )?;
    let status = value
        .as_object()
        .and_then(|value| value.get("Status"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::S3::Bucket resource {logical_id} requires VersioningConfiguration.Status"
            ))
        })?;
    if status != "Enabled" && status != "Suspended" {
        return Err(CfnError::Validation(format!(
            "AWS::S3::Bucket resource {logical_id} requires versioning Status Enabled or Suspended"
        )));
    }
    Ok(format!(
        "<VersioningConfiguration><Status>{status}</Status></VersioningConfiguration>"
    ))
}

fn s3_bucket_notification_xml(logical_id: &str, value: &Value) -> Result<String, CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::S3::Bucket.NotificationConfiguration",
        value,
        &["EventBridgeConfiguration"],
    )?;
    let event_bridge = value
        .as_object()
        .and_then(|value| value.get("EventBridgeConfiguration"))
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::S3::Bucket resource {logical_id} requires EventBridgeConfiguration"
            ))
        })?;
    ensure_known_properties(
        logical_id,
        "AWS::S3::Bucket.EventBridgeConfiguration",
        event_bridge,
        &["EventBridgeEnabled"],
    )?;
    let enabled = event_bridge
        .as_object()
        .and_then(|value| value.get("EventBridgeEnabled"))
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::S3::Bucket resource {logical_id} requires EventBridgeEnabled to be a boolean"
            ))
        })?;
    if enabled {
        Ok(
            "<NotificationConfiguration><EventBridgeConfiguration/></NotificationConfiguration>"
                .to_string(),
        )
    } else {
        Ok("<NotificationConfiguration/>".to_string())
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn stepfunctions_create_body(
    logical_id: &str,
    name: &str,
    props: &Value,
) -> Result<Value, CfnError> {
    let definition = stepfunctions_definition(logical_id, props)?;
    let role_arn = required_property(props, "RoleArn", logical_id)?;
    let mut body = stepfunctions_mutable_body(logical_id, props)?;
    body["name"] = json!(name);
    body["definition"] = json!(definition);
    body["roleArn"] = json!(role_arn);
    body["type"] = props
        .get("StateMachineType")
        .cloned()
        .unwrap_or_else(|| json!("STANDARD"));
    if let Some(tags) = stepfunctions_tags(logical_id, props)? {
        body["tags"] = tags;
    }
    Ok(body)
}

fn stepfunctions_definition(logical_id: &str, props: &Value) -> Result<String, CfnError> {
    match (props.get("Definition"), props.get("DefinitionString")) {
        (Some(_), Some(_)) => Err(CfnError::Validation(format!(
            "AWS::StepFunctions::StateMachine resource {logical_id} cannot specify both Definition and DefinitionString"
        ))),
        (Some(Value::Object(definition)), None) => {
            Ok(Value::Object(definition.clone()).to_string())
        }
        (Some(_), None) => Err(CfnError::Validation(format!(
            "AWS::StepFunctions::StateMachine resource {logical_id} requires Definition to be an object"
        ))),
        (None, Some(Value::String(definition))) if !definition.is_empty() => {
            Ok(definition.clone())
        }
        (None, Some(_)) => Err(CfnError::Validation(format!(
            "AWS::StepFunctions::StateMachine resource {logical_id} requires DefinitionString to be a non-empty string"
        ))),
        (None, None) => Err(CfnError::Validation(format!(
            "AWS::StepFunctions::StateMachine resource {logical_id} requires Definition or DefinitionString"
        ))),
    }
}

fn stepfunctions_mutable_body(logical_id: &str, props: &Value) -> Result<Value, CfnError> {
    let mut body = serde_json::Map::new();
    if props.get("Definition").is_some() || props.get("DefinitionString").is_some() {
        body.insert(
            "definition".into(),
            Value::String(stepfunctions_definition(logical_id, props)?),
        );
    }
    if let Some(value) = props.get("RoleArn") {
        let role_arn = value.as_str().filter(|value| !value.is_empty()).ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::StepFunctions::StateMachine resource {logical_id} requires RoleArn to be a non-empty string"
            ))
        })?;
        body.insert("roleArn".into(), json!(role_arn));
    }
    if let Some(value) = props.get("LoggingConfiguration") {
        body.insert(
            "loggingConfiguration".into(),
            stepfunctions_logging_configuration(logical_id, value)?,
        );
    }
    if let Some(value) = props.get("TracingConfiguration") {
        body.insert(
            "tracingConfiguration".into(),
            stepfunctions_tracing_configuration(logical_id, value)?,
        );
    }
    if let Some(value) = props.get("EncryptionConfiguration") {
        body.insert(
            "encryptionConfiguration".into(),
            stepfunctions_encryption_configuration(logical_id, value)?,
        );
    }
    Ok(Value::Object(body))
}

fn stepfunctions_logging_configuration(logical_id: &str, value: &Value) -> Result<Value, CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::StepFunctions::StateMachine.LoggingConfiguration",
        value,
        &["Level", "IncludeExecutionData", "Destinations"],
    )?;
    let object = value.as_object().ok_or_else(|| {
        CfnError::Validation(format!(
            "AWS::StepFunctions::StateMachine resource {logical_id} requires LoggingConfiguration to be an object"
        ))
    })?;
    let mut mapped = serde_json::Map::new();
    if let Some(level) = object.get("Level") {
        mapped.insert("level".into(), level.clone());
    }
    if let Some(include_data) = object.get("IncludeExecutionData") {
        mapped.insert("includeExecutionData".into(), include_data.clone());
    }
    if let Some(destinations) = object.get("Destinations") {
        let destinations = destinations.as_array().ok_or_else(|| {
            CfnError::Validation(format!(
                "AWS::StepFunctions::StateMachine resource {logical_id} requires Destinations to be an array"
            ))
        })?;
        let mapped_destinations = destinations
            .iter()
            .map(|destination| {
                ensure_known_properties(
                    logical_id,
                    "AWS::StepFunctions::StateMachine.Destination",
                    destination,
                    &["CloudWatchLogsLogGroup"],
                )?;
                let group = destination
                    .get("CloudWatchLogsLogGroup")
                    .ok_or_else(|| {
                        CfnError::Validation(format!(
                            "AWS::StepFunctions::StateMachine resource {logical_id} requires CloudWatchLogsLogGroup"
                        ))
                    })?;
                ensure_known_properties(
                    logical_id,
                    "AWS::StepFunctions::StateMachine.CloudWatchLogsLogGroup",
                    group,
                    &["LogGroupArn"],
                )?;
                let arn = group
                    .get("LogGroupArn")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        CfnError::Validation(format!(
                            "AWS::StepFunctions::StateMachine resource {logical_id} requires LogGroupArn"
                        ))
                    })?;
                Ok(json!({
                    "cloudWatchLogsLogGroup": { "logGroupArn": arn }
                }))
            })
            .collect::<Result<Vec<_>, CfnError>>()?;
        mapped.insert("destinations".into(), Value::Array(mapped_destinations));
    }
    Ok(Value::Object(mapped))
}

fn stepfunctions_tracing_configuration(logical_id: &str, value: &Value) -> Result<Value, CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::StepFunctions::StateMachine.TracingConfiguration",
        value,
        &["Enabled"],
    )?;
    Ok(json!({
        "enabled": value.get("Enabled").cloned().unwrap_or(Value::Bool(false))
    }))
}

fn stepfunctions_encryption_configuration(
    logical_id: &str,
    value: &Value,
) -> Result<Value, CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::StepFunctions::StateMachine.EncryptionConfiguration",
        value,
        &["Type", "KmsKeyId", "KmsDataKeyReusePeriodSeconds"],
    )?;
    let mut mapped = serde_json::Map::new();
    for (source, target) in [
        ("Type", "type"),
        ("KmsKeyId", "kmsKeyId"),
        (
            "KmsDataKeyReusePeriodSeconds",
            "kmsDataKeyReusePeriodSeconds",
        ),
    ] {
        if let Some(value) = value.get(source) {
            mapped.insert(target.into(), value.clone());
        }
    }
    Ok(Value::Object(mapped))
}

fn stepfunctions_tags(logical_id: &str, props: &Value) -> Result<Option<Value>, CfnError> {
    let Some(tags) = props.get("Tags") else {
        return Ok(None);
    };
    let tags = tags.as_array().ok_or_else(|| {
        CfnError::Validation(format!(
            "AWS::StepFunctions::StateMachine resource {logical_id} requires Tags to be an array"
        ))
    })?;
    let mapped = tags
        .iter()
        .map(|tag| {
            ensure_known_properties(
                logical_id,
                "AWS::StepFunctions::StateMachine.Tag",
                tag,
                &["Key", "Value"],
            )?;
            Ok(json!({
                "key": required_property(tag, "Key", logical_id)?,
                "value": required_property(tag, "Value", logical_id)?,
            }))
        })
        .collect::<Result<Vec<_>, CfnError>>()?;
    Ok(Some(Value::Array(mapped)))
}

fn validate_stepfunctions_properties(logical_id: &str, props: &Value) -> Result<(), CfnError> {
    ensure_known_properties(
        logical_id,
        "AWS::StepFunctions::StateMachine",
        props,
        &[
            "Definition",
            "DefinitionString",
            "RoleArn",
            "StateMachineName",
            "StateMachineType",
            "LoggingConfiguration",
            "TracingConfiguration",
            "EncryptionConfiguration",
            "Tags",
        ],
    )?;
    stepfunctions_definition(logical_id, props)?;
    if let Some(name) = props.get("StateMachineName") {
        if name.as_str().filter(|name| !name.is_empty()).is_none() {
            return Err(CfnError::Validation(format!(
                "AWS::StepFunctions::StateMachine resource {logical_id} requires StateMachineName to be a non-empty string"
            )));
        }
    }
    Ok(())
}

fn stepfunctions_resolution(
    response: &Value,
    name: &str,
    logical_id: &str,
) -> Result<ResolvedResource, CfnError> {
    let arn = required_response_string(response, "stateMachineArn", logical_id)?;
    let mut attributes = std::collections::BTreeMap::from([
        ("Arn".into(), arn.clone()),
        ("Name".into(), name.to_string()),
    ]);
    if let Some(revision) = response.get("revisionId").and_then(Value::as_str) {
        attributes.insert("StateMachineRevisionId".into(), revision.to_string());
    }
    Ok(ResolvedResource {
        ref_value: arn,
        attributes,
    })
}

fn required_property(props: &Value, name: &str, logical_id: &str) -> Result<String, CfnError> {
    props
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            CfnError::Validation(format!("{logical_id} requires string property {name}"))
        })
}

fn required_response_string(
    response: &Value,
    name: &str,
    logical_id: &str,
) -> Result<String, CfnError> {
    response
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            CfnError::ResourceFailed(format!("provisioning {logical_id} returned no {name}"))
        })
}

fn s3_bucket_headers(props: &Value) -> HeaderMap {
    let mut headers = path_host();
    if props.get("BucketNamespace").and_then(Value::as_str) == Some("account-regional") {
        headers.insert(
            "x-amz-bucket-namespace",
            HeaderValue::from_static("account-regional"),
        );
    }
    headers
}

fn path_host() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("host", HeaderValue::from_static("localhost:4566"));
    h
}

fn form_host() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        "content-type",
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    h
}

fn json_host() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("content-type", HeaderValue::from_static("application/json"));
    h
}

fn json_11_host() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        "content-type",
        HeaderValue::from_static("application/x-amz-json-1.1"),
    );
    h
}

fn with_cleanup_failure(primary: CfnError, cleanup: CfnError) -> CfnError {
    CfnError::ResourceFailed(format!(
        "{primary}; cleanup after provisioning failure also failed: {cleanup}"
    ))
}

fn ensure_delete_succeeded(
    service: &str,
    physical_id: &str,
    status: u16,
    response: &[u8],
) -> Result<(), CfnError> {
    if (200..300).contains(&status) || status == 404 {
        return Ok(());
    }
    Err(CfnError::ResourceFailed(format!(
        "{service} deletion for {physical_id} failed ({status}): {}",
        String::from_utf8_lossy(response)
    )))
}

/// Coerce a possibly-stringified number (CFN often stringifies) to a JSON number.
fn coerce_number(v: &Value) -> Value {
    match v {
        Value::Number(_) => v.clone(),
        Value::String(s) => s
            .parse::<i64>()
            .map(|n| json!(n))
            .unwrap_or_else(|_| v.clone()),
        _ => v.clone(),
    }
}

/// Generate an AWS-like physical name `{stack}-{logical}-{rand}` within `max` chars, lowercased.
fn generate_name(stack: &str, logical: &str, max: usize) -> String {
    let base = format!(
        "{}-{}-{}",
        stack.to_ascii_lowercase(),
        logical.to_ascii_lowercase(),
        short_id()
    );
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    cleaned.chars().take(max).collect()
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// Percent-encode a value for a form-urlencoded body.
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::body::Body;
    use locallycloud_core::handler::NativeHandler;
    use locallycloud_core::registry::{AwsProtocol, ServiceMetadata};

    use super::*;

    #[tokio::test]
    async fn api_v2_attributes_match_native_api_and_survive_update() {
        let registry = Arc::new(ServiceRegistry::new());
        locallycloud_apigateway::register(&registry);
        let provisioner = Provisioner::new(
            Arc::downgrade(&registry),
            "us-west-2".into(),
            "123456789012".into(),
        );
        for (protocol, scheme) in [("HTTP", "https"), ("WEBSOCKET", "wss")] {
            let props = json!({"Name": "attributes", "ProtocolType": protocol,
                "RouteSelectionExpression": if protocol == "HTTP" {
                    "$request.method $request.path"
                } else { "$request.body.action" }});
            let api = provisioner.apigateway_v2_api("Api", &props).await.unwrap();
            let actual = provisioner
                .call_json(
                    "apigatewayv2",
                    Method::GET,
                    &format!("/v2/apis/{}", api.ref_value),
                    Value::Null,
                    "Api",
                )
                .await
                .unwrap();
            assert_eq!(api.attributes["ApiEndpoint"], actual["apiEndpoint"]);
            assert_eq!(
                api.attributes["ApiEndpoint"],
                format!(
                    "{scheme}://{}.execute-api.us-west-2.amazonaws.com",
                    api.ref_value
                )
            );
            assert_eq!(api.attributes["ApiId"], api.ref_value);
            assert_eq!(
                api.attributes["ExecuteApiArn"],
                format!(
                    "arn:aws:execute-api:us-west-2:123456789012:{}",
                    api.ref_value
                )
            );
            let mut next = props.clone();
            next["Name"] = json!("renamed");
            let updated = provisioner
                .update(
                    "Api",
                    "AWS::ApiGatewayV2::Api",
                    &api,
                    &props,
                    &next,
                    Replacement::Update(ResourcePolicy::Delete),
                )
                .await
                .unwrap();
            assert_eq!(updated.attributes, api.attributes);
            provisioner
                .delete_apigateway_v2_api(&api.ref_value)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn scoped_provisioning_preserves_each_callers_access_key() {
        use locallycloud_core::integration::{InternalDispatcher, RequestIdentity};
        use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
        use std::time::Duration;
        struct KeyRecorder(Mutex<Vec<String>>);
        #[async_trait]
        impl NativeHandler for KeyRecorder {
            async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
                assert_eq!(request.account_id, "000000000000");
                assert_eq!(request.region, "us-east-1");
                assert_eq!(
                    request
                        .headers
                        .get("x-locallycloud-verified-internal-scope")
                        .unwrap(),
                    "1"
                );
                let identity = RequestIdentity::access_key_from_authorization(
                    request
                        .headers
                        .get(http::header::AUTHORIZATION)
                        .unwrap()
                        .to_str()
                        .unwrap(),
                )
                .unwrap();
                self.0.lock().unwrap().push(identity);
                http::Response::builder()
                    .status(200)
                    .body(Body::from("{}"))
                    .unwrap()
            }
        }
        let registry = Arc::new(ServiceRegistry::new());
        let recorder = Arc::new(KeyRecorder(Mutex::new(Vec::new())));
        registry.register_native(
            ServiceName::new("kms"),
            ServiceMetadata::new(AwsProtocol::Json11, Some("TrentService")),
            recorder.clone(),
        );
        registry.set_internal_dispatcher(Arc::new(InternalDispatcher::new_shared(
            &registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            "us-east-1".into(),
            "000000000000".into(),
        )));
        let first = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "000000000000".into(),
        )
        .with_caller_access_key(Some("AKIAFIRSTCALLER000001".into()));
        let second = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "000000000000".into(),
        )
        .with_caller_access_key(Some("AKIASECONDCALLER0001".into()));
        let (a, b) = tokio::join!(
            first.call_aws_json(
                "kms",
                "TrentService.ScheduleKeyDeletion",
                json!({"KeyId":"first"}),
                "first"
            ),
            second.call_aws_json(
                "kms",
                "TrentService.ScheduleKeyDeletion",
                json!({"KeyId":"second"}),
                "second"
            )
        );
        a.unwrap();
        b.unwrap();
        let mut callers = recorder.0.lock().unwrap().clone();
        callers.sort();
        assert_eq!(callers, ["AKIAFIRSTCALLER000001", "AKIASECONDCALLER0001"]);
    }

    struct IamRecorder {
        requests: Mutex<Vec<String>>,
        response_status: Option<(&'static str, u16)>,
    }

    #[async_trait]
    impl NativeHandler for IamRecorder {
        async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
            let body = String::from_utf8(request.body.to_vec()).unwrap();
            let action = query_action(&body).to_string();
            self.requests.lock().unwrap().push(body);
            let status = self
                .response_status
                .filter(|(failed_action, _)| *failed_action == action)
                .map(|(_, status)| status)
                .unwrap_or(200);
            http::Response::builder()
                .status(status)
                .body(Body::from(if status >= 400 { "failed" } else { "" }))
                .unwrap()
        }
    }

    fn query_action(body: &str) -> &str {
        body.split('&')
            .find_map(|field| field.strip_prefix("Action="))
            .unwrap()
    }

    fn recorder_provisioner(
        response_status: Option<(&'static str, u16)>,
    ) -> (Provisioner, Arc<IamRecorder>, Arc<ServiceRegistry>) {
        let registry = Arc::new(ServiceRegistry::new());
        let recorder = Arc::new(IamRecorder {
            requests: Mutex::new(Vec::new()),
            response_status,
        });
        registry.register_native(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            recorder.clone(),
        );
        let provisioner = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "123456789012".into(),
        );
        (provisioner, recorder, registry)
    }

    #[test]
    fn global_table_requires_stack_region_and_rejects_unsupported_properties() {
        let (provisioner, _, _registry) = recorder_provisioner(None);
        let base = json!({
            "TableName": "orders",
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "BillingMode": "PAY_PER_REQUEST",
            "StreamSpecification": {"StreamViewType": "NEW_AND_OLD_IMAGES"},
            "Replicas": [{"Region": "us-east-1"}, {"Region": "us-west-2"}]
        });
        assert!(provisioner.global_table_properties("Orders", &base).is_ok());
        let mut wrong_region = base.clone();
        wrong_region["Replicas"] = json!([{"Region": "us-west-2"}]);
        assert!(provisioner
            .global_table_properties("Orders", &wrong_region)
            .is_err());
        let mut unsupported = base;
        unsupported["GlobalTableWitnesses"] = json!([{"Region": "us-east-2"}]);
        assert!(provisioner
            .global_table_properties("Orders", &unsupported)
            .is_err());
    }

    #[test]
    fn enc_escapes_reserved() {
        assert_eq!(enc("a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(enc("plain-Value_1.0~"), "plain-Value_1.0~");
    }

    #[test]
    fn generated_name_is_bounded_and_clean() {
        let n = generate_name("lc-compat-dev", "ServerlessDeploymentBucket", 63);
        assert!(n.len() <= 63);
        assert!(n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        assert!(n.starts_with("lc-compat-dev-serverlessdeploymentbucket-"));
    }

    #[test]
    fn supported_resource_types_are_explicit() {
        assert!(is_supported_resource_type("AWS::S3::Bucket"));
        assert!(is_supported_resource_type("AWS::Logs::LogGroup"));
        assert!(!is_supported_resource_type("AWS::MadeUp::Resource"));
    }

    #[test]
    fn coerce_stringified_number() {
        assert_eq!(coerce_number(&json!("128")), json!(128));
        assert_eq!(coerce_number(&json!(256)), json!(256));
    }

    #[tokio::test]
    async fn bucket_policy_requires_non_empty_bucket() {
        let provisioner = Provisioner::new(Weak::new(), "us-east-1".into(), "123456789012".into());

        let error = provisioner
            .s3_bucket_policy(&json!({"Bucket": ""}))
            .await
            .unwrap_err();

        assert_eq!(
            error,
            CfnError::Validation("AWS::S3::BucketPolicy requires non-empty Bucket".into())
        );
    }

    #[tokio::test]
    async fn iam_role_teardown_removes_policies_before_role_and_accepts_not_found() {
        let (provisioner, recorder, _registry) =
            recorder_provisioner(Some(("DeleteRolePolicy", 404)));
        let properties = json!({
            "Policies": [
                {"PolicyName": "inline one"},
                {"PolicyName": "inline/two"}
            ],
            "ManagedPolicyArns": [
                "arn:aws:iam::aws:policy/ReadOnlyAccess",
                "arn:aws:iam::123456789012:policy/custom"
            ]
        });

        provisioner
            .deprovision("AWS::IAM::Role", "role/name", &properties)
            .await
            .unwrap();

        assert_eq!(
            *recorder.requests.lock().unwrap(),
            [
                "Action=DeleteRolePolicy&Version=2010-05-08&RoleName=role%2Fname&PolicyName=inline%20one",
                "Action=DeleteRolePolicy&Version=2010-05-08&RoleName=role%2Fname&PolicyName=inline%2Ftwo",
                "Action=DetachRolePolicy&Version=2010-05-08&RoleName=role%2Fname&PolicyArn=arn%3Aaws%3Aiam%3A%3Aaws%3Apolicy%2FReadOnlyAccess",
                "Action=DetachRolePolicy&Version=2010-05-08&RoleName=role%2Fname&PolicyArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Apolicy%2Fcustom",
                "Action=DeleteRole&Version=2010-05-08&RoleName=role%2Fname",
            ]
        );
    }

    #[tokio::test]
    async fn iam_role_teardown_propagates_each_phase_failure() {
        let properties = json!({
            "Policies": [{"PolicyName": "inline one"}],
            "ManagedPolicyArns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
        });
        let cases = [
            ("DeleteRolePolicy", 1, Some("inline one")),
            (
                "DetachRolePolicy",
                2,
                Some("arn:aws:iam::aws:policy/ReadOnlyAccess"),
            ),
            ("DeleteRole", 3, None),
        ];

        for (failed_action, expected_requests, policy) in cases {
            let (provisioner, recorder, _registry) =
                recorder_provisioner(Some((failed_action, 500)));

            let error = provisioner
                .deprovision("AWS::IAM::Role", "role/name", &properties)
                .await
                .unwrap_err()
                .to_string();

            let requests = recorder.requests.lock().unwrap();
            assert_eq!(requests.len(), expected_requests, "{failed_action}");
            assert_eq!(query_action(requests.last().unwrap()), failed_action);
            assert!(error.contains(failed_action), "{error}");
            assert!(error.contains("role role/name"), "{error}");
            if let Some(policy) = policy {
                assert!(error.contains(&format!("policy {policy}")), "{error}");
            }
        }
    }

    #[test]
    fn cleanup_failure_preserves_both_diagnostics() {
        let error = with_cleanup_failure(
            CfnError::ResourceFailed("provisioning failed".into()),
            CfnError::ResourceFailed("deletion failed".into()),
        );

        assert_eq!(
            error,
            CfnError::ResourceFailed(
                "provisioning failed; cleanup after provisioning failure also failed: deletion failed"
                    .into()
            )
        );
    }

    struct S3Recorder {
        existing: Vec<&'static str>,
        /// DELETE to these bucket paths answers 500.
        fail_delete: Vec<&'static str>,
        requests: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl NativeHandler for S3Recorder {
        async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
            let path = request.uri.path().to_string();
            let method = request.method.to_string();
            self.requests
                .lock()
                .unwrap()
                .push(format!("{method} {path}"));
            let bucket = path.trim_start_matches('/');
            let preexisting =
                method == "PUT" && !path.contains('?') && self.existing.contains(&bucket);
            let failed = method == "DELETE" && self.fail_delete.contains(&bucket);
            let status = if preexisting {
                409
            } else if failed {
                500
            } else {
                200
            };
            http::Response::builder()
                .status(status)
                .body(Body::empty())
                .unwrap()
        }
    }

    fn s3_provisioner(
        existing: Vec<&'static str>,
        fail_delete: Vec<&'static str>,
    ) -> (Provisioner, Arc<S3Recorder>, Arc<ServiceRegistry>) {
        let registry = Arc::new(ServiceRegistry::new());
        let recorder = Arc::new(S3Recorder {
            existing,
            fail_delete,
            requests: Mutex::new(Vec::new()),
        });
        registry.register_native(
            ServiceName::new("s3"),
            ServiceMetadata::new(AwsProtocol::RestXml, None),
            recorder.clone(),
        );
        let provisioner = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "123456789012".into(),
        );
        (provisioner, recorder, registry)
    }

    fn bucket_resolution(name: &str) -> ResolvedResource {
        ResolvedResource {
            ref_value: name.to_string(),
            attributes: std::collections::BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn s3_bucket_prefix_creates_account_regional_bucket() {
        let (provisioner, s3, _registry) = s3_provisioner(Vec::new(), Vec::new());
        let props = json!({"BucketNamePrefix": "etl-data", "BucketNamespace": "account-regional"});
        let result = provisioner
            .s3_bucket("Data", "stack", &props)
            .await
            .unwrap();
        assert_eq!(result.ref_value, "etl-data-123456789012-us-east-1-an");
        assert_eq!(
            s3.requests.lock().unwrap()[0],
            "PUT /etl-data-123456789012-us-east-1-an"
        );
        assert_eq!(
            s3_bucket_headers(&props)
                .get("x-amz-bucket-namespace")
                .unwrap(),
            "account-regional"
        );
        let invalid = json!({"BucketNamePrefix": "etl-data", "BucketNamespace": "global"});
        assert!(validate_s3_bucket_properties("Data", &invalid).is_err());
        let unnamed = json!({"BucketNamespace": "account-regional"});
        let name = provisioner.s3_bucket_name(&unnamed, "stack", "LongLogicalResourceName");
        assert!(name.len() <= 63);
        assert!(name.ends_with("-123456789012-us-east-1-an"));
    }

    #[tokio::test]
    async fn s3_bucket_replacement_follows_update_replace_policy() {
        let (provisioner, s3, _registry) = s3_provisioner(Vec::new(), Vec::new());
        let current = bucket_resolution("old");
        let updated = provisioner
            .update(
                "B",
                "AWS::S3::Bucket",
                &current,
                &json!({"BucketName": "old"}),
                &json!({"BucketName": "new"}),
                Replacement::Update(ResourcePolicy::Retain),
            )
            .await
            .expect("replacement with Retain succeeds");
        assert_eq!(updated.ref_value, "new");
        assert_eq!(*s3.requests.lock().unwrap(), ["PUT /new"]);

        let (provisioner, s3, _registry) = s3_provisioner(Vec::new(), Vec::new());
        let updated = provisioner
            .update(
                "B",
                "AWS::S3::Bucket",
                &current,
                &json!({"BucketName": "old"}),
                &json!({"BucketName": "new"}),
                Replacement::Update(ResourcePolicy::Delete),
            )
            .await
            .expect("replacement with Delete succeeds");
        assert_eq!(updated.ref_value, "new");
        assert_eq!(*s3.requests.lock().unwrap(), ["PUT /new", "DELETE /old"]);
    }

    #[tokio::test]
    async fn s3_bucket_replacement_conflict_and_rollback() {
        // A forward replacement to a taken name fails without deleting the source.
        let (provisioner, s3, _registry) = s3_provisioner(vec!["new"], Vec::new());
        let current = bucket_resolution("old");
        let error = provisioner
            .update(
                "B",
                "AWS::S3::Bucket",
                &current,
                &json!({"BucketName": "old"}),
                &json!({"BucketName": "new"}),
                Replacement::Update(ResourcePolicy::Delete),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("409"), "{error}");
        assert_eq!(*s3.requests.lock().unwrap(), ["PUT /new"]);

        // Rollback re-adopts the retained old bucket and deletes the one the update created.
        let (provisioner, s3, _registry) = s3_provisioner(vec!["old"], Vec::new());
        let updated = bucket_resolution("new");
        let restored = provisioner
            .update(
                "B",
                "AWS::S3::Bucket",
                &updated,
                &json!({"BucketName": "new"}),
                &json!({"BucketName": "old"}),
                Replacement::Rollback,
            )
            .await
            .expect("rollback replacement succeeds");
        assert_eq!(restored.ref_value, "old");
        assert_eq!(*s3.requests.lock().unwrap(), ["PUT /old", "DELETE /new"]);
    }

    #[tokio::test]
    async fn s3_bucket_replacement_source_delete_failure_deletes_new_bucket() {
        let (provisioner, s3, _registry) = s3_provisioner(Vec::new(), vec!["old"]);
        let current = bucket_resolution("old");
        let error = provisioner
            .update(
                "B",
                "AWS::S3::Bucket",
                &current,
                &json!({"BucketName": "old"}),
                &json!({"BucketName": "new"}),
                Replacement::Update(ResourcePolicy::Delete),
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("S3 DeleteBucket for B failed"),
            "{error}"
        );
        assert!(
            !error
                .to_string()
                .contains("cleanup after provisioning failure"),
            "cleanup succeeded, only the primary failure is reported: {error}"
        );
        assert_eq!(
            *s3.requests.lock().unwrap(),
            ["PUT /new", "DELETE /old", "DELETE /new"]
        );
    }

    #[tokio::test]
    async fn s3_bucket_replacement_source_delete_failure_keeps_both_diagnostics() {
        let (provisioner, s3, _registry) = s3_provisioner(Vec::new(), vec!["old", "new"]);
        let current = bucket_resolution("old");
        let error = provisioner
            .update(
                "B",
                "AWS::S3::Bucket",
                &current,
                &json!({"BucketName": "old"}),
                &json!({"BucketName": "new"}),
                Replacement::Update(ResourcePolicy::Delete),
            )
            .await
            .unwrap_err();
        let error = error.to_string();
        assert!(error.contains("S3 DeleteBucket for B failed"), "{error}");
        assert!(
            error.contains("cleanup after provisioning failure also failed"),
            "cleanup failure must be preserved: {error}"
        );
        assert_eq!(
            *s3.requests.lock().unwrap(),
            ["PUT /new", "DELETE /old", "DELETE /new"]
        );
    }

    #[tokio::test]
    async fn s3_bucket_rollback_delete_failure_never_deletes_adopted_target() {
        let (provisioner, s3, _registry) = s3_provisioner(vec!["old"], vec!["new"]);
        let updated = bucket_resolution("new");
        let error = provisioner
            .update(
                "B",
                "AWS::S3::Bucket",
                &updated,
                &json!({"BucketName": "new"}),
                &json!({"BucketName": "old"}),
                Replacement::Rollback,
            )
            .await
            .unwrap_err();
        let error = error.to_string();
        assert!(error.contains("S3 DeleteBucket for B failed"), "{error}");
        assert_eq!(
            *s3.requests.lock().unwrap(),
            ["PUT /old", "DELETE /new"],
            "the preexisting adopted target must not be deleted"
        );
    }
}
