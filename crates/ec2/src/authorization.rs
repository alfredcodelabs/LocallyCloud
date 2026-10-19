//! EC2 operator IAM boundary. Owned topology helpers do not impersonate API callers.
use super::*;
use axum::http;
use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::identity::trusted_role;
use locallycloud_core::integration::RequestIdentity;

fn denied() -> Ec2Error {
    Ec2Error::new(
        "UnauthorizedOperation",
        "You are not authorized to perform this operation",
    )
}

impl Ec2Handler {
    pub(super) fn authorize_input(
        &self,
        request: &ServiceRequest,
        input: &mut Input,
    ) -> Result<(), Ec2Error> {
        let action = input
            .one("Action")?
            .ok_or_else(|| Ec2Error::new("MissingAction", "Missing Action"))?
            .to_owned();
        let planned = match action.as_str() {
            "CreateVpc" => Some("vpc"),
            "CreateSubnet" => Some("subnet"),
            "CreateSecurityGroup" => Some("sg"),
            "CreateNetworkInterface" => Some("eni"),
            "CreateRouteTable" => Some("rtb"),
            "CreateInternetGateway" => Some("igw"),
            "AllocateAddress" => Some("eipalloc"),
            "CreateNatGateway" => Some("nat"),
            "CreateVpcEndpoint" => Some("vpce"),
            "RunInstances" => Some("i"),
            _ => None,
        };
        if let Some(kind) = planned {
            input.planned_ids.insert(kind.into(), resource_id(kind));
        }
        if action == "RunInstances" {
            input.planned_ids.insert("eni".into(), resource_id("eni"));
        }
        let Some(registry) = &self.registry else {
            return Ok(());
        };
        let registry = registry
            .upgrade()
            .ok_or_else(|| Ec2Error::new("InternalError", "EC2 authorization unavailable"))?;
        let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
            return Ok(());
        };
        let delegated = trusted_role(request);
        let caller = RequestIdentity {
            account_id: request.account_id.clone(),
            access_key_id: request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(RequestIdentity::access_key_from_authorization),
            arn: None,
        };
        if evaluator.strict_sigv4_required() {
            let attested = [
                "x-locallycloud-verified-external-sigv4",
                "x-locallycloud-verified-internal-scope",
            ]
            .iter()
            .any(|header| {
                request.headers.get(*header) == Some(&http::HeaderValue::from_static("1"))
            });
            if !attested || caller.access_key_id.is_none() && delegated.is_none() {
                return Err(denied());
            }
        }
        let action = input.required("Action")?;
        let arn = |kind: &str, id: &str| {
            format!(
                "arn:aws:ec2:{}:{}:{kind}/{id}",
                request.region, request.account_id
            )
        };
        let mut context = BTreeMap::from([("ec2:Region".into(), vec![request.region.clone()])]);
        let key = (request.account_id.clone(), request.region.clone());
        let state = self.scopes.lock().map_err(|_| {
            Ec2Error::new("InternalError", "EC2 authorization topology unavailable")
        })?;
        let scope = state.get(&key);
        let mut resources = Vec::new();
        let mut vpc = input.one("VpcId")?.map(str::to_owned);
        if let Some(subnet) = input.one("SubnetId")? {
            context.insert("ec2:Subnet".into(), vec![arn("subnet", subnet)]);
            vpc = vpc.or_else(|| scope?.subnets.get(subnet).map(|value| value.vpc_id.clone()));
        }
        if let Some(group) = input.one("GroupId")? {
            vpc = vpc.or_else(|| {
                scope?
                    .security_groups
                    .get(group)
                    .map(|value| value.vpc_id.clone())
            });
        }
        if let Some(table) = input.one("RouteTableId")? {
            vpc = vpc.or_else(|| {
                scope?
                    .route_tables
                    .get(table)
                    .map(|value| value.vpc_id.clone())
            });
        }
        if action.starts_with("Describe") || action.starts_with("List") {
            resources.push("*".into());
        } else {
            match action {
                "CreateVpc" => resources.push(arn("vpc", &input.resource_id("vpc"))),
                "CreateSubnet" => {
                    resources.push(arn("subnet", &input.resource_id("subnet")));
                    resources.push(arn("vpc", input.required("VpcId")?));
                }
                "CreateSecurityGroup" => {
                    resources.push(arn("security-group", &input.resource_id("sg")));
                    resources.push(arn("vpc", input.required("VpcId")?));
                }
                "CreateNetworkInterface" => {
                    resources.push(arn("network-interface", &input.resource_id("eni")));
                    resources.push(arn("subnet", input.required("SubnetId")?));
                    for id in input.indexed("SecurityGroupId")? {
                        resources.push(arn("security-group", &id));
                    }
                }
                "CreateRouteTable" => {
                    resources.push(arn("route-table", &input.resource_id("rtb")));
                    resources.push(arn("vpc", input.required("VpcId")?));
                }
                "CreateInternetGateway" => {
                    resources.push(arn("internet-gateway", &input.resource_id("igw")))
                }
                "AllocateAddress" => {
                    resources.push(arn("elastic-ip", &input.resource_id("eipalloc")))
                }
                "CreateNatGateway" => {
                    resources.push(arn("natgateway", &input.resource_id("nat")));
                    if let Some(id) = input.one("SubnetId")? {
                        resources.push(arn("subnet", id));
                    }
                    if let Some(id) = input.one("AllocationId")? {
                        resources.push(arn("elastic-ip", id));
                    }
                }
                "CreateVpcEndpoint" => {
                    resources.push(arn("vpc-endpoint", &input.resource_id("vpce")));
                    resources.push(arn("vpc", input.required("VpcId")?));
                }
                "DeleteVpc" | "ModifyVpcAttribute" => {
                    resources.push(arn("vpc", input.required("VpcId")?))
                }
                "DeleteSubnet" => resources.push(arn("subnet", input.required("SubnetId")?)),
                "DeleteSecurityGroup"
                | "AuthorizeSecurityGroupIngress"
                | "RevokeSecurityGroupIngress"
                | "AuthorizeSecurityGroupEgress"
                | "RevokeSecurityGroupEgress" => {
                    resources.push(arn("security-group", input.required("GroupId")?))
                }
                "DeleteNetworkInterface" => resources.push(arn(
                    "network-interface",
                    input.required("NetworkInterfaceId")?,
                )),
                "DeleteRouteTable" | "CreateRoute" | "DeleteRoute" | "AssociateRouteTable" => {
                    resources.push(arn("route-table", input.required("RouteTableId")?));
                    if action == "AssociateRouteTable" {
                        resources.push(arn("subnet", input.required("SubnetId")?));
                    }
                }
                "DisassociateRouteTable" => {
                    let association = input.required("AssociationId")?;
                    let table = scope
                        .and_then(|scope| {
                            scope
                                .route_tables
                                .values()
                                .find(|table| table.associations.contains_key(association))
                        })
                        .ok_or_else(|| {
                            Ec2Error::new(
                                "InvalidAssociationID.NotFound",
                                "The association does not exist",
                            )
                        })?;
                    vpc = Some(table.vpc_id.clone());
                    resources.push(arn("route-table", &table.id));
                }
                "DeleteInternetGateway" | "AttachInternetGateway" | "DetachInternetGateway" => {
                    resources.push(arn(
                        "internet-gateway",
                        input.required("InternetGatewayId")?,
                    ));
                    if action != "DeleteInternetGateway" {
                        resources.push(arn("vpc", input.required("VpcId")?));
                    }
                }
                "ReleaseAddress" => {
                    resources.push(arn("elastic-ip", input.required("AllocationId")?))
                }
                "DeleteNatGateway" => {
                    resources.push(arn("natgateway", input.required("NatGatewayId")?))
                }
                "DeleteVpcEndpoints" => {
                    for id in input.indexed("VpcEndpointId")? {
                        resources.push(arn("vpc-endpoint", &id));
                    }
                }
                "TerminateInstances" | "StartInstances" => {
                    for id in input.indexed("InstanceId")? {
                        resources.push(arn("instance", &id));
                        if action == "StartInstances" {
                            if let Some(instance) = scope.and_then(|scope| scope.instances.get(&id))
                            {
                                vpc = Some(instance.spec.vpc_id.clone());
                                context.insert(
                                    "ec2:Subnet".into(),
                                    vec![arn("subnet", &instance.spec.subnet_id)],
                                );
                            }
                        }
                    }
                }
                "RunInstances" => {
                    resources.push(arn("instance", &input.resource_id("i")));
                    resources.push(arn("network-interface", &input.resource_id("eni")));
                    resources.push(format!(
                        "arn:aws:ec2:{}::image/{}",
                        request.region,
                        input.required("ImageId")?
                    ));
                    let subnet = input.required("SubnetId")?;
                    resources.push(arn("subnet", subnet));
                    let mut groups = input.indexed("SecurityGroupId")?;
                    if groups.is_empty() {
                        if let Some(default) = scope.and_then(|scope| {
                            scope.security_groups.values().find(|group| {
                                group.is_default && Some(&group.vpc_id) == vpc.as_ref()
                            })
                        }) {
                            groups.push(default.id.clone());
                        }
                    }
                    if groups.is_empty() {
                        return Err(denied());
                    }
                    for id in groups {
                        resources.push(arn("security-group", &id));
                    }
                }
                _ => resources.push("*".into()),
            }
        }
        if let Some(vpc) = vpc {
            context.insert("ec2:Vpc".into(), vec![arn("vpc", &vpc)]);
        }
        drop(state);
        if resources.is_empty() {
            resources.push("*".into());
        }
        for resource in resources {
            evaluator
                .authorize(AuthorizationRequest {
                    request_identity: caller.clone(),
                    delegated_identity: delegated.clone(),
                    source_service: "ec2".into(),
                    action: format!("ec2:{action}"),
                    resource,
                    context: context.clone(),
                })
                .map_err(|_| denied())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::integration::authorization::{
        AuthorizationError, AuthorizationEvaluator,
    };
    use locallycloud_core::integration::identity::{CallerIdentity, PRINCIPAL_HEADER};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Policy {
        allowed: Mutex<Vec<(String, String)>>,
        require_role: AtomicBool,
        calls: Mutex<Vec<AuthorizationRequest>>,
    }
    impl AuthorizationEvaluator for Policy {
        fn strict_sigv4_required(&self) -> bool {
            true
        }
        fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError> {
            let role_ok = !self.require_role.load(Ordering::SeqCst)
                || matches!(&request.delegated_identity,Some(CallerIdentity::AssumedRole {role_arn,..}) if role_arn=="arn:aws:iam::111:role/operator");
            let allowed = role_ok
                && self
                    .allowed
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(action, resource)| {
                        action == &request.action
                            && (resource == &request.resource
                                || resource
                                    .strip_suffix('*')
                                    .is_some_and(|prefix| request.resource.starts_with(prefix)))
                    });
            self.calls.lock().unwrap().push(request);
            if allowed {
                Ok(())
            } else {
                Err(AuthorizationError::Denied)
            }
        }
    }
    fn request(form: &str) -> ServiceRequest {
        let mut request = crate::tests::request("111", "us-east-1", form);
        request.headers.insert(http::header::AUTHORIZATION,http::HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=AKIALOW/20261019/us-east-1/ec2/aws4_request, SignedHeaders=host, Signature=unchecked-unit-fixture"));
        request.headers.insert(
            "x-locallycloud-verified-external-sigv4",
            http::HeaderValue::from_static("1"),
        );
        request
    }
    async fn response(handler: &Ec2Handler, request: ServiceRequest) -> (u16, String) {
        let response = handler.handle(request).await;
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }
    fn policy(registry: &Arc<ServiceRegistry>, handler: Arc<Ec2Handler>) -> Arc<Policy> {
        let policy = Arc::new(Policy {
            allowed: Mutex::new(Vec::new()),
            require_role: AtomicBool::new(false),
            calls: Mutex::new(Vec::new()),
        });
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            handler,
            policy.clone(),
        );
        policy
    }

    #[tokio::test]
    async fn ec2_operator_denies_unsigned_and_requires_exact_group_permission() {
        let registry = Arc::new(ServiceRegistry::new());
        let handler = register(&registry);
        let (_, vpc) = crate::tests::call(
            &handler,
            "111",
            "us-east-1",
            "Action=CreateVpc&CidrBlock=10.88.0.0%2F16",
        )
        .await;
        let vpc = crate::tests::id(&vpc, "vpcId");
        let (_, group) = crate::tests::call(
            &handler,
            "111",
            "us-east-1",
            &format!("Action=CreateSecurityGroup&VpcId={vpc}&GroupName=app&GroupDescription=app"),
        )
        .await;
        let group = crate::tests::id(&group, "groupId");
        let policy = policy(&registry, handler.clone());
        let mutation=format!("Action=AuthorizeSecurityGroupIngress&GroupId={group}&IpProtocol=tcp&FromPort=8080&ToPort=8080&CidrIp=10.88.0.0%2F16");
        let (status, body) = response(&handler, request(&mutation)).await;
        assert_eq!(status, 403, "{body}");
        assert!(body.contains("UnauthorizedOperation"));
        {
            let state = handler.scopes.lock().unwrap();
            assert!(
                state[&("111".into(), "us-east-1".into())].security_groups[&group]
                    .ingress
                    .is_empty()
            );
        }
        let mut unsigned = request(&mutation);
        unsigned
            .headers
            .remove("x-locallycloud-verified-external-sigv4");
        assert_eq!(response(&handler, unsigned).await.0, 403);
        let arn = format!("arn:aws:ec2:us-east-1:111:security-group/{group}");
        policy
            .allowed
            .lock()
            .unwrap()
            .push(("ec2:AuthorizeSecurityGroupIngress".into(), arn.clone()));
        assert_eq!(response(&handler, request(&mutation)).await.0, 200);
        let call = policy.calls.lock().unwrap().last().cloned().unwrap();
        assert_eq!(call.resource, arn);
        assert_eq!(
            call.context["ec2:Vpc"],
            vec![format!("arn:aws:ec2:us-east-1:111:vpc/{vpc}")]
        );
        assert_eq!(
            call.request_identity.access_key_id.as_deref(),
            Some("AKIALOW")
        );
        assert!(call.delegated_identity.is_none());
        assert_eq!(
            response(&handler, request("Action=DescribeSubnets"))
                .await
                .0,
            403
        );
        policy
            .allowed
            .lock()
            .unwrap()
            .push(("ec2:DescribeSubnets".into(), "*".into()));
        assert_eq!(
            response(&handler, request("Action=DescribeSubnets"))
                .await
                .0,
            200
        );
        assert_eq!(policy.calls.lock().unwrap().last().unwrap().resource, "*");
    }

    #[tokio::test]
    async fn creations_authorize_actual_ids_and_delegation_requires_core_attestation() {
        let registry = Arc::new(ServiceRegistry::new());
        let handler = register(&registry);
        let policy = policy(&registry, handler.clone());
        policy.allowed.lock().unwrap().push((
            "ec2:CreateVpc".into(),
            "arn:aws:ec2:us-east-1:111:vpc/*".into(),
        ));
        let (status, body) = response(
            &handler,
            request("Action=CreateVpc&CidrBlock=10.89.0.0%2F16"),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let created = crate::tests::id(&body, "vpcId");
        assert_eq!(
            policy.calls.lock().unwrap().last().unwrap().resource,
            format!("arn:aws:ec2:us-east-1:111:vpc/{created}")
        );
        policy.require_role.store(true, Ordering::SeqCst);
        policy
            .allowed
            .lock()
            .unwrap()
            .push(("ec2:DescribeVpcs".into(), "*".into()));
        let mut delegated = request("Action=DescribeVpcs");
        delegated.headers.insert(
            PRINCIPAL_HEADER,
            http::HeaderValue::from_static("arn:aws:iam::111:role/operator/session"),
        );
        assert_eq!(response(&handler, delegated.clone()).await.0, 403);
        assert!(policy
            .calls
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .delegated_identity
            .is_none());
        delegated
            .headers
            .remove("x-locallycloud-verified-external-sigv4");
        delegated.headers.remove(http::header::AUTHORIZATION);
        delegated.headers.insert(
            "x-locallycloud-verified-internal-scope",
            http::HeaderValue::from_static("1"),
        );
        assert_eq!(response(&handler, delegated.clone()).await.0, 200);
        assert!(matches!(
            policy
                .calls
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .delegated_identity,
            Some(CallerIdentity::AssumedRole { .. })
        ));
        delegated.headers.insert(
            PRINCIPAL_HEADER,
            http::HeaderValue::from_static("arn:aws:iam::222:role/operator/session"),
        );
        assert_eq!(response(&handler, delegated).await.0, 403);
    }
    #[tokio::test]
    async fn start_instances_requires_exact_instance_authority_before_runtime_launch() {
        let registry = Arc::new(ServiceRegistry::new());
        let runtime = crate::tests::mock_runtime(false).await;
        let handler = register_with_instance_runtime(&registry, runtime.clone());
        let (vpc, subnet, group) = crate::tests::instance_network(&handler).await;
        let form=format!("Action=RunInstances&ImageId=ami-locallycloud-http&InstanceType=t3.micro&MinCount=1&MaxCount=1&SubnetId={subnet}&SecurityGroupId.1={group}");
        let req = crate::tests::request("111", "us-east-1", &form);
        let spec = match handler
            .prepare_instance(&req, &Input::parse(&req).unwrap())
            .unwrap()
        {
            PreparedInstance::Launch(spec) => spec,
            _ => panic!("new instance"),
        };
        handler
            .scopes
            .lock()
            .unwrap()
            .get_mut(&("111".into(), "us-east-1".into()))
            .unwrap()
            .instances
            .get_mut(&spec.instance_id)
            .unwrap()
            .state = InstanceState::Stopped;
        let policy = policy(&registry, handler.clone());
        let start = format!("Action=StartInstances&InstanceId.1={}", spec.instance_id);
        assert_eq!(response(&handler, request(&start)).await.0, 403);
        assert_eq!(runtime.starts.load(Ordering::SeqCst), 0);
        let resource = format!("arn:aws:ec2:us-east-1:111:instance/{}", spec.instance_id);
        policy
            .allowed
            .lock()
            .unwrap()
            .push(("ec2:StartInstances".into(), resource.clone()));
        assert_eq!(response(&handler, request(&start)).await.0, 200);
        let call = policy.calls.lock().unwrap().last().cloned().unwrap();
        assert_eq!(call.resource, resource);
        assert_eq!(
            call.context["ec2:Vpc"],
            vec![format!("arn:aws:ec2:us-east-1:111:vpc/{vpc}")]
        );
        policy
            .allowed
            .lock()
            .unwrap()
            .push(("ec2:TerminateInstances".into(), resource));
        assert_eq!(
            response(
                &handler,
                request(&format!(
                    "Action=TerminateInstances&InstanceId.1={}",
                    spec.instance_id
                ))
            )
            .await
            .0,
            200
        );
    }
}
