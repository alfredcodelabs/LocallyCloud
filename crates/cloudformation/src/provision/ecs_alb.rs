//! Bounded Fargate/internal HTTP ALB lifecycle through the owning AWS handlers.
use super::*;

const CLUSTER: &str = "AWS::ECS::Cluster";
const DEFINITION: &str = "AWS::ECS::TaskDefinition";
const SERVICE: &str = "AWS::ECS::Service";
const ALB: &str = "AWS::ElasticLoadBalancingV2::LoadBalancer";
const GROUP: &str = "AWS::ElasticLoadBalancingV2::TargetGroup";
const LISTENER: &str = "AWS::ElasticLoadBalancingV2::Listener";

pub(crate) fn validate_ecs_alb_property_names(
    id: &str,
    kind: &str,
    props: &Value,
) -> Result<(), CfnError> {
    super::ecs_sg::validate_sg_rule_names(id, kind, props)?;
    let allowed: &[&str] = match kind {
        CLUSTER => &["ClusterName"],
        DEFINITION => &[
            "Family",
            "ContainerDefinitions",
            "Cpu",
            "Memory",
            "NetworkMode",
            "RequiresCompatibilities",
            "TaskRoleArn",
            "ExecutionRoleArn",
        ],
        SERVICE => &[
            "ServiceName",
            "Cluster",
            "TaskDefinition",
            "LaunchType",
            "DesiredCount",
            "NetworkConfiguration",
            "LoadBalancers",
            "HealthCheckGracePeriodSeconds",
        ],
        ALB => &[
            "Name",
            "Type",
            "Scheme",
            "Subnets",
            "SecurityGroups",
            "IpAddressType",
        ],
        GROUP => &[
            "Name",
            "VpcId",
            "Port",
            "Protocol",
            "TargetType",
            "HealthCheckProtocol",
            "HealthCheckPort",
            "HealthCheckPath",
            "HealthCheckEnabled",
            "HealthCheckIntervalSeconds",
            "HealthCheckTimeoutSeconds",
            "HealthyThresholdCount",
            "UnhealthyThresholdCount",
            "Matcher",
            "TargetGroupAttributes",
        ],
        LISTENER => &["LoadBalancerArn", "Port", "Protocol", "DefaultActions"],
        _ => return Ok(()),
    };
    if props.is_null() {
        return Ok(());
    }
    ensure_known_properties(id, kind, props, allowed)?;
    let list = |value: &Value, keys: &[&str]| -> Result<(), CfnError> {
        for value in value.as_array().into_iter().flatten() {
            ensure_known_properties(id, kind, value, keys)?;
        }
        Ok(())
    };
    match kind {
        DEFINITION => {
            list(
                &props["ContainerDefinitions"],
                &[
                    "Name",
                    "Image",
                    "Essential",
                    "Command",
                    "EntryPoint",
                    "Environment",
                    "PortMappings",
                    "LogConfiguration",
                ],
            )?;
            for container in props["ContainerDefinitions"]
                .as_array()
                .into_iter()
                .flatten()
            {
                list(&container["Environment"], &["Name", "Value"])?;
                list(&container["PortMappings"], &["ContainerPort", "Protocol"])?;
                if let Some(log) = container.get("LogConfiguration") {
                    ensure_known_properties(id, kind, log, &["LogDriver", "Options"])?;
                    ensure_known_properties(
                        id,
                        kind,
                        &log["Options"],
                        &["awslogs-group", "awslogs-region", "awslogs-stream-prefix"],
                    )?;
                }
            }
        }
        SERVICE => {
            if let Some(network) = props.get("NetworkConfiguration") {
                ensure_known_properties(id, kind, network, &["AwsvpcConfiguration"])?;
                ensure_known_properties(
                    id,
                    kind,
                    &network["AwsvpcConfiguration"],
                    &["Subnets", "SecurityGroups", "AssignPublicIp"],
                )?;
            }
            list(
                &props["LoadBalancers"],
                &["TargetGroupArn", "ContainerName", "ContainerPort"],
            )?;
        }
        GROUP => {
            ensure_known_properties(id, kind, &props["Matcher"], &["HttpCode"])?;
            list(&props["TargetGroupAttributes"], &["Key", "Value"])?;
        }
        LISTENER => list(&props["DefaultActions"], &["Type", "TargetGroupArn"])?,
        _ => {}
    }
    Ok(())
}
fn resource_name(stack: &str, id: &str, maximum: usize) -> String {
    // Preserve the unique suffix even when long stack and logical names are truncated.
    format!(
        "{}-{}",
        generate_name(stack, id, maximum - 13).trim_matches('-'),
        short_id()
    )
}
fn object(id: &str, value: &Value, mapping: &[(&str, &str)]) -> Result<Value, CfnError> {
    let allowed: Vec<_> = mapping.iter().map(|(key, _)| *key).collect();
    ensure_known_properties(id, "ECS properties", value, &allowed)?;
    let source = value
        .as_object()
        .ok_or_else(|| CfnError::Validation(format!("{id} requires an object")))?;
    let mut target = serde_json::Map::new();
    for (from, to) in mapping {
        if let Some(value) = source.get(*from) {
            target.insert((*to).into(), value.clone());
        }
    }
    Ok(Value::Object(target))
}
fn array_map(
    id: &str,
    value: &Value,
    mapping: &[(&str, &str)],
    maximum: usize,
) -> Result<Value, CfnError> {
    let values = value
        .as_array()
        .filter(|values| !values.is_empty() && values.len() <= maximum)
        .ok_or_else(|| CfnError::Validation(format!("{id} requires 1..{maximum} entries")))?;
    values
        .iter()
        .map(|value| object(id, value, mapping))
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}
fn ecs_body(id: &str, kind: &str, props: &Value) -> Result<Value, CfnError> {
    validate_ecs_alb_property_names(id, kind, props)?;
    let mut body = match kind {
        DEFINITION => object(
            id,
            props,
            &[
                ("Family", "family"),
                ("ContainerDefinitions", "containerDefinitions"),
                ("Cpu", "cpu"),
                ("Memory", "memory"),
                ("NetworkMode", "networkMode"),
                ("RequiresCompatibilities", "requiresCompatibilities"),
                ("TaskRoleArn", "taskRoleArn"),
                ("ExecutionRoleArn", "executionRoleArn"),
            ],
        )?,
        SERVICE => object(
            id,
            props,
            &[
                ("ServiceName", "serviceName"),
                ("Cluster", "cluster"),
                ("TaskDefinition", "taskDefinition"),
                ("LaunchType", "launchType"),
                ("DesiredCount", "desiredCount"),
                ("NetworkConfiguration", "networkConfiguration"),
                ("LoadBalancers", "loadBalancers"),
                (
                    "HealthCheckGracePeriodSeconds",
                    "healthCheckGracePeriodSeconds",
                ),
            ],
        )?,
        _ => return Err(CfnError::Internal),
    };
    if kind == DEFINITION {
        required_property(props, "Cpu", id)?;
        required_property(props, "Memory", id)?;
        if props["NetworkMode"] != "awsvpc"
            || props["RequiresCompatibilities"] != json!(["FARGATE"])
        {
            return Err(CfnError::Validation(format!(
                "{id} requires awsvpc and FARGATE"
            )));
        }
        let mut containers = array_map(
            id,
            &props["ContainerDefinitions"],
            &[
                ("Name", "name"),
                ("Image", "image"),
                ("Essential", "essential"),
                ("Command", "command"),
                ("EntryPoint", "entryPoint"),
                ("Environment", "environment"),
                ("PortMappings", "portMappings"),
                ("LogConfiguration", "logConfiguration"),
            ],
            1,
        )?;
        for (index, container) in containers
            .as_array_mut()
            .ok_or(CfnError::Internal)?
            .iter_mut()
            .enumerate()
        {
            let original = &props["ContainerDefinitions"][index];
            required_property(original, "Name", id)?;
            required_property(original, "Image", id)?;
            if let Some(environment) = original.get("Environment") {
                container["environment"] = array_map(
                    id,
                    environment,
                    &[("Name", "name"), ("Value", "value")],
                    100,
                )?;
            }
            container["portMappings"] = array_map(
                id,
                &original["PortMappings"],
                &[("ContainerPort", "containerPort"), ("Protocol", "protocol")],
                1,
            )?;
            if let Some(log) = original.get("LogConfiguration") {
                container["logConfiguration"] = object(
                    id,
                    log,
                    &[("LogDriver", "logDriver"), ("Options", "options")],
                )?;
            }
        }
        body["containerDefinitions"] = containers;
    } else {
        required_property(props, "Cluster", id)?;
        required_property(props, "TaskDefinition", id)?;
        let desired = match props.get("DesiredCount") {
            None => 1,
            Some(value) => value
                .as_u64()
                .filter(|count| *count <= 2)
                .ok_or_else(|| CfnError::Validation(format!("{id} requires desired count 0..2")))?,
        };
        if props["LaunchType"] != "FARGATE" {
            return Err(CfnError::Validation(format!("{id} requires FARGATE")));
        }
        body["desiredCount"] = desired.into();
        let network = object(
            id,
            &props["NetworkConfiguration"],
            &[("AwsvpcConfiguration", "awsvpcConfiguration")],
        )?;
        let awsvpc = object(
            id,
            &network["awsvpcConfiguration"],
            &[
                ("Subnets", "subnets"),
                ("SecurityGroups", "securityGroups"),
                ("AssignPublicIp", "assignPublicIp"),
            ],
        )?;
        if awsvpc["subnets"]
            .as_array()
            .is_none_or(|values| values.len() != 1)
            || awsvpc
                .get("assignPublicIp")
                .is_some_and(|value| value != "DISABLED")
        {
            return Err(CfnError::Validation(format!(
                "{id} requires one private subnet"
            )));
        }
        body["networkConfiguration"] = json!({"awsvpcConfiguration":awsvpc});
        if let Some(groups) = props.get("LoadBalancers") {
            body["loadBalancers"] = array_map(
                id,
                groups,
                &[
                    ("TargetGroupArn", "targetGroupArn"),
                    ("ContainerName", "containerName"),
                    ("ContainerPort", "containerPort"),
                ],
                1,
            )?;
        }
    }
    Ok(body)
}
fn text<'a>(xml: &'a str, key: &str) -> Option<&'a str> {
    xml.split_once(&format!("<{key}>"))?
        .1
        .split_once(&format!("</{key}>"))
        .map(|(value, _)| value)
}
fn actual(xml: &str, key: &str, id: &str) -> Result<String, CfnError> {
    text(xml, key)
        .map(str::to_owned)
        .ok_or_else(|| CfnError::ResourceFailed(format!("{id} response lacks {key}")))
}
fn query_value(id: &str, props: &Value, key: &str) -> Result<String, CfnError> {
    match props.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        Some(Value::Number(value)) => Ok(value.to_string()),
        Some(Value::Bool(value)) => Ok(value.to_string()),
        _ => Err(CfnError::Validation(format!("{id} requires {key}"))),
    }
}
fn elb_fields(
    id: &str,
    kind: &str,
    props: &Value,
    name: &str,
) -> Result<Vec<(String, String)>, CfnError> {
    validate_ecs_alb_property_names(id, kind, props)?;
    let mut fields = Vec::new();
    match kind {
        ALB => {
            if props
                .get("Type")
                .is_some_and(|value| value != "application")
                || props["Scheme"] != "internal"
                || props
                    .get("IpAddressType")
                    .is_some_and(|value| value != "ipv4")
            {
                return Err(CfnError::Validation(format!(
                    "{id} supports internal IPv4 application load balancers"
                )));
            }
            fields.extend([
                ("Name".into(), name.into()),
                ("Type".into(), "application".into()),
                ("Scheme".into(), "internal".into()),
            ]);
            for (key, max) in [("Subnets", 2), ("SecurityGroups", 5)] {
                let values = props[key]
                    .as_array()
                    .filter(|values| !values.is_empty() && values.len() <= max)
                    .ok_or_else(|| CfnError::Validation(format!("{id} requires bounded {key}")))?;
                if key == "Subnets" && values.len() != 2 {
                    return Err(CfnError::Validation(format!(
                        "{id} requires two ALB subnets"
                    )));
                }
                for (index, value) in values.iter().enumerate() {
                    let value = value.as_str().ok_or_else(|| {
                        CfnError::Validation(format!("{id} requires string {key}"))
                    })?;
                    fields.push((format!("{key}.member.{}", index + 1), value.into()));
                }
            }
        }
        GROUP => {
            if props["Protocol"] != "HTTP" || props["TargetType"] != "ip" {
                return Err(CfnError::Validation(format!(
                    "{id} supports HTTP IP target groups"
                )));
            }
            fields.push(("Name".into(), name.into()));
            for key in ["VpcId", "Port", "Protocol", "TargetType"] {
                fields.push((key.into(), query_value(id, props, key)?));
            }
            for key in [
                "HealthCheckProtocol",
                "HealthCheckPort",
                "HealthCheckPath",
                "HealthCheckEnabled",
                "HealthCheckIntervalSeconds",
                "HealthCheckTimeoutSeconds",
                "HealthyThresholdCount",
                "UnhealthyThresholdCount",
            ] {
                if props.get(key).is_some() {
                    fields.push((key.into(), query_value(id, props, key)?));
                }
            }
            if let Some(matcher) = props.get("Matcher") {
                ensure_known_properties(id, "Matcher", matcher, &["HttpCode"])?;
                fields.push((
                    "Matcher.HttpCode".into(),
                    required_property(matcher, "HttpCode", id)?,
                ));
            }
            if let Some(attributes) = props.get("TargetGroupAttributes") {
                let values = attributes
                    .as_array()
                    .filter(|values| values.len() == 1)
                    .ok_or_else(|| {
                        CfnError::Validation(format!(
                            "{id} supports one deregistration delay attribute"
                        ))
                    })?;
                ensure_known_properties(
                    id,
                    "TargetGroupAttributes",
                    &values[0],
                    &["Key", "Value"],
                )?;
                if values[0]["Key"] != "deregistration_delay.timeout_seconds"
                    || values[0]["Value"]
                        .as_str()
                        .and_then(|value| value.parse::<u32>().ok())
                        .is_none_or(|delay| delay > 3600)
                {
                    return Err(CfnError::Validation(format!(
                        "{id} requires deregistration delay 0..3600"
                    )));
                }
            }
        }
        LISTENER => {
            if props["Protocol"] != "HTTP" {
                return Err(CfnError::Validation(format!(
                    "{id} supports HTTP listeners"
                )));
            }
            for key in ["LoadBalancerArn", "Protocol", "Port"] {
                fields.push((key.into(), query_value(id, props, key)?));
            }
            let actions = props["DefaultActions"]
                .as_array()
                .filter(|values| values.len() == 1)
                .ok_or_else(|| {
                    CfnError::Validation(format!("{id} requires one forwarding action"))
                })?;
            ensure_known_properties(
                id,
                "DefaultActions",
                &actions[0],
                &["Type", "TargetGroupArn"],
            )?;
            if actions[0]["Type"] != "forward" {
                return Err(CfnError::Validation(format!(
                    "{id} supports forwarding actions"
                )));
            }
            fields.push(("DefaultActions.member.1.Type".into(), "forward".into()));
            fields.push((
                "DefaultActions.member.1.TargetGroupArn".into(),
                required_property(&actions[0], "TargetGroupArn", id)?,
            ));
        }
        _ => return Err(CfnError::Internal),
    }
    Ok(fields)
}
impl Provisioner {
    async fn ecs_call(&self, operation: &str, body: Value, id: &str) -> Result<Value, CfnError> {
        self.call_aws_json_11(
            "ecs",
            &format!("AmazonEC2ContainerServiceV20141113.{operation}"),
            body,
            id,
        )
        .await
    }
    async fn elb_response(
        &self,
        operation: &str,
        fields: &[(String, String)],
    ) -> Result<(u16, String), CfnError> {
        let mut form = format!("Action={operation}&Version=2015-12-01");
        for (key, value) in fields {
            form.push_str(&format!("&{key}={}", enc(value)));
        }
        let (status, body) = self
            .call(
                "elasticloadbalancing",
                Method::POST,
                "/",
                form_host(),
                Bytes::from(form),
            )
            .await?;
        Ok((
            status,
            String::from_utf8(body.to_vec()).map_err(|_| CfnError::Internal)?,
        ))
    }
    async fn elb_call(
        &self,
        operation: &str,
        fields: &[(String, String)],
        id: &str,
    ) -> Result<String, CfnError> {
        let (status, body) = self.elb_response(operation, fields).await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "ELB {operation} for {id} failed ({status}): {body}"
            )));
        }
        Ok(body)
    }
    async fn wait_ecs_service(
        &self,
        id: &str,
        physical: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        let desired = props
            .get("DesiredCount")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let value = self
                .ecs_call(
                    "DescribeServices",
                    json!({"cluster":props["Cluster"],"services":[physical]}),
                    id,
                )
                .await?;
            let service = value["services"]
                .as_array()
                .and_then(|values| values.first());
            let mut ready = service.is_some_and(|service| {
                service["status"] == "ACTIVE"
                    && service["runningCount"] == desired
                    && service["pendingCount"] == 0
            });
            if ready
                && desired != 0
                && props["LoadBalancers"]
                    .as_array()
                    .is_some_and(|groups| !groups.is_empty())
            {
                let list = self
                    .ecs_call(
                        "ListTasks",
                        json!({"cluster":props["Cluster"],"serviceName":physical}),
                        id,
                    )
                    .await?;
                let arns = list["taskArns"]
                    .as_array()
                    .filter(|values| values.len() == desired as usize);
                if let Some(arns) = arns {
                    let tasks = self
                        .ecs_call(
                            "DescribeTasks",
                            json!({"cluster":props["Cluster"],"tasks":arns}),
                            id,
                        )
                        .await?;
                    let task_values = tasks["tasks"].as_array().ok_or(CfnError::Internal)?;
                    ready &= task_values.len() == desired as usize;
                    for task in task_values {
                        let ip = task["attachments"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .flat_map(|attachment| {
                                attachment["details"].as_array().into_iter().flatten()
                            })
                            .find(|detail| detail["name"] == "privateIPv4Address")
                            .and_then(|detail| detail["value"].as_str())
                            .ok_or(CfnError::Internal)?;
                        for group in props["LoadBalancers"].as_array().into_iter().flatten() {
                            let health = self
                                .elb_call(
                                    "DescribeTargetHealth",
                                    &[
                                        (
                                            "TargetGroupArn".into(),
                                            required_property(group, "TargetGroupArn", id)?,
                                        ),
                                        ("Targets.member.1.Id".into(), ip.into()),
                                        (
                                            "Targets.member.1.Port".into(),
                                            query_value(id, group, "ContainerPort")?,
                                        ),
                                    ],
                                    id,
                                )
                                .await?;
                            ready &= text(&health, "State") == Some("healthy");
                        }
                    }
                } else {
                    ready = false;
                }
            }
            if ready {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(CfnError::ResourceFailed(format!(
                    "ECS service {physical} did not stabilize within the local 60-second gate"
                )));
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
    pub(super) async fn ecs_alb_resource(
        &self,
        id: &str,
        stack: &str,
        kind: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_ecs_alb_property_names(id, kind, props)?;
        match kind {
            CLUSTER => {
                let name = props
                    .get("ClusterName")
                    .map(|_| required_property(props, "ClusterName", id))
                    .transpose()?
                    .unwrap_or_else(|| resource_name(stack, id, 128));
                let previous = self
                    .ecs_call("DescribeClusters", json!({"clusters":[name]}), id)
                    .await?;
                if previous["clusters"].as_array().is_some_and(|clusters| {
                    clusters.iter().any(|cluster| cluster["status"] == "ACTIVE")
                }) {
                    return Err(CfnError::ResourceFailed(format!(
                        "ECS cluster {name} already exists"
                    )));
                }
                let value = self
                    .ecs_call("CreateCluster", json!({"clusterName":name}), id)
                    .await?;
                let arn = required_response_string(&value["cluster"], "clusterArn", id)?;
                Ok(ResolvedResource {
                    ref_value: name,
                    attributes: [("Arn".into(), arn)].into(),
                })
            }
            DEFINITION => {
                let mut body = ecs_body(id, kind, props)?;
                if body.get("family").is_none() {
                    body["family"] = resource_name(stack, id, 128).into();
                }
                let value = self.ecs_call("RegisterTaskDefinition", body, id).await?;
                let arn =
                    required_response_string(&value["taskDefinition"], "taskDefinitionArn", id)?;
                Ok(ResolvedResource {
                    ref_value: arn.clone(),
                    attributes: [("TaskDefinitionArn".into(), arn)].into(),
                })
            }
            SERVICE => {
                let mut body = ecs_body(id, kind, props)?;
                if body.get("serviceName").is_none() {
                    body["serviceName"] = resource_name(stack, id, 128).into();
                }
                let value = self.ecs_call("CreateService", body, id).await?;
                let arn = required_response_string(&value["service"], "serviceArn", id)?;
                let name = required_response_string(&value["service"], "serviceName", id)?;
                if let Err(error) = self.wait_ecs_service(id, &arn, props).await {
                    return Err(match self.delete_ecs_alb(SERVICE, &arn, props).await {
                        Ok(()) => error,
                        Err(cleanup) => CfnError::ResourceFailed(format!(
                            "{error}; ECS service cleanup failed: {cleanup}"
                        )),
                    });
                }
                Ok(ResolvedResource {
                    ref_value: arn,
                    attributes: [("Name".into(), name)].into(),
                })
            }
            ALB | GROUP | LISTENER => {
                let name = props
                    .get("Name")
                    .map(|_| required_property(props, "Name", id))
                    .transpose()?
                    .unwrap_or_else(|| resource_name(stack, id, 32));
                let fields = elb_fields(id, kind, props, &name)?;
                if kind != LISTENER {
                    let (operation, code) = if kind == ALB {
                        ("DescribeLoadBalancers", "LoadBalancerNotFound")
                    } else {
                        ("DescribeTargetGroups", "TargetGroupNotFound")
                    };
                    let (status, body) = self
                        .elb_response(operation, &[("Names.member.1".into(), name.clone())])
                        .await?;
                    if (200..300).contains(&status) {
                        return Err(CfnError::ResourceFailed(format!(
                            "{kind} {name} already exists"
                        )));
                    }
                    if text(&body, "Code") != Some(code) {
                        return Err(CfnError::ResourceFailed(format!(
                            "{operation} ownership check failed ({status}): {body}"
                        )));
                    }
                }
                let (operation, key) = match kind {
                    ALB => ("CreateLoadBalancer", "LoadBalancerArn"),
                    GROUP => ("CreateTargetGroup", "TargetGroupArn"),
                    _ => ("CreateListener", "ListenerArn"),
                };
                let xml = self.elb_call(operation, &fields, id).await?;
                let arn = actual(&xml, key, id)?;
                let result = async {
                    let mut attributes = std::collections::BTreeMap::new();
                    if kind == ALB {
                        attributes.insert("DNSName".into(), actual(&xml, "DNSName", id)?);
                        attributes.insert(
                            "LoadBalancerName".into(),
                            actual(&xml, "LoadBalancerName", id)?,
                        );
                        attributes.insert(
                            "LoadBalancerFullName".into(),
                            arn.split_once("loadbalancer/")
                                .ok_or(CfnError::Internal)?
                                .1
                                .into(),
                        );
                    }
                    if kind == GROUP {
                        if let Some(values) =
                            props.get("TargetGroupAttributes").and_then(Value::as_array)
                        {
                            self.elb_call(
                                "ModifyTargetGroupAttributes",
                                &[
                                    ("TargetGroupArn".into(), arn.clone()),
                                    (
                                        "Attributes.member.1.Key".into(),
                                        required_property(&values[0], "Key", id)?,
                                    ),
                                    (
                                        "Attributes.member.1.Value".into(),
                                        required_property(&values[0], "Value", id)?,
                                    ),
                                ],
                                id,
                            )
                            .await?;
                        }
                        attributes.insert(
                            "TargetGroupFullName".into(),
                            arn.split_once("targetgroup/")
                                .ok_or(CfnError::Internal)?
                                .1
                                .into(),
                        );
                        attributes.insert(
                            "TargetGroupName".into(),
                            actual(&xml, "TargetGroupName", id)?,
                        );
                    }
                    Ok(ResolvedResource {
                        ref_value: arn.clone(),
                        attributes,
                    })
                }
                .await;
                if let Err(error) = result {
                    return Err(match self.delete_ecs_alb(kind, &arn, props).await {
                        Ok(()) => error,
                        Err(cleanup) => {
                            CfnError::ResourceFailed(format!("{error}; cleanup failed: {cleanup}"))
                        }
                    });
                }
                result
            }
            _ => Err(CfnError::Internal),
        }
    }
    pub(super) async fn update_ecs_alb(
        &self,
        id: &str,
        kind: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        validate_ecs_alb_property_names(id, kind, props)?;
        if kind != SERVICE {
            return Err(CfnError::ResourceFailed(format!(
                "{kind} {id} replacement is not supported"
            )));
        }
        let mut before = previous.clone();
        let mut after = props.clone();
        before
            .as_object_mut()
            .ok_or(CfnError::Internal)?
            .remove("DesiredCount");
        after
            .as_object_mut()
            .ok_or(CfnError::Internal)?
            .remove("DesiredCount");
        if before != after {
            return Err(CfnError::ResourceFailed(format!(
                "{id} supports desired-count updates only"
            )));
        }
        let body = ecs_body(id, kind, props)?;
        let actual = self
            .ecs_call(
                "DescribeServices",
                json!({"cluster":body["cluster"],"services":[current.ref_value]}),
                id,
            )
            .await?;
        let previous_count = actual["services"]
            .as_array()
            .and_then(|services| services.first())
            .and_then(|service| service["desiredCount"].as_u64())
            .filter(|count| *count <= 2)
            .ok_or(CfnError::Internal)?;
        let result = async {
            self.ecs_call("UpdateService",json!({"cluster":body["cluster"],"service":current.ref_value,"desiredCount":body["desiredCount"]}),id).await?;
            self.wait_ecs_service(id,&current.ref_value,props).await
        }.await;
        if let Err(error) = result {
            return Err(match self.ecs_call("UpdateService",json!({"cluster":body["cluster"],"service":current.ref_value,"desiredCount":previous_count}),id).await {
                Ok(_) => error, Err(cleanup) => CfnError::ResourceFailed(format!("{error}; ECS update rollback failed: {cleanup}")),
            });
        }
        Ok(current.clone())
    }
    pub(super) async fn delete_ecs_alb(
        &self,
        kind: &str,
        physical: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        match kind {
            CLUSTER => {
                let value = self
                    .ecs_call("DescribeClusters", json!({"clusters":[physical]}), physical)
                    .await?;
                if value["clusters"].as_array().is_some_and(|clusters| {
                    clusters.is_empty()
                        || clusters
                            .iter()
                            .all(|cluster| cluster["status"] == "INACTIVE")
                }) {
                    return Ok(());
                }
                self.ecs_call("DeleteCluster", json!({"cluster":physical}), physical)
                    .await?;
            }
            DEFINITION => {
                self.ecs_call(
                    "DeregisterTaskDefinition",
                    json!({"taskDefinition":physical}),
                    physical,
                )
                .await?;
            }
            SERVICE => {
                let cluster = required_property(props, "Cluster", physical)?;
                let before = self
                    .ecs_call(
                        "DescribeServices",
                        json!({"cluster":cluster,"services":[physical]}),
                        physical,
                    )
                    .await?;
                if before["services"]
                    .as_array()
                    .is_none_or(|services| services.is_empty())
                {
                    return Ok(());
                }
                self.ecs_call(
                    "DeleteService",
                    json!({"cluster":cluster,"service":physical,"force":true}),
                    physical,
                )
                .await?;
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3630);
                loop {
                    let value = self
                        .ecs_call(
                            "DescribeServices",
                            json!({"cluster":cluster,"services":[physical]}),
                            physical,
                        )
                        .await?;
                    if value["services"].as_array().is_some_and(|services| {
                        services.is_empty()
                            || services
                                .iter()
                                .all(|service| service["status"] == "INACTIVE")
                    }) {
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Err(CfnError::ResourceFailed(format!(
                            "ECS service {physical} cleanup timed out"
                        )));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
            ALB | GROUP | LISTENER => {
                let (action, key, missing) = match kind {
                    ALB => (
                        "DeleteLoadBalancer",
                        "LoadBalancerArn",
                        "LoadBalancerNotFound",
                    ),
                    GROUP => ("DeleteTargetGroup", "TargetGroupArn", "TargetGroupNotFound"),
                    _ => ("DeleteListener", "ListenerArn", "ListenerNotFound"),
                };
                let (status, body) = self
                    .elb_response(action, &[(key.into(), physical.into())])
                    .await?;
                if !(200..300).contains(&status) && text(&body, "Code") != Some(missing) {
                    return Err(CfnError::ResourceFailed(format!(
                        "{action} failed ({status}): {body}"
                    )));
                }
            }
            _ => return Err(CfnError::Internal),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;
    struct Runtime;
    #[async_trait]
    impl locallycloud_ecs::TaskRuntime for Runtime {
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
        async fn start(
            &self,
            _: &locallycloud_ecs::TaskLaunch,
        ) -> Result<locallycloud_ecs::TaskNetworkInfo, String> {
            Err("injected image start failure".into())
        }
        async fn stop(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        async fn running(&self, _: &str) -> bool {
            false
        }
    }
    fn definition() -> Value {
        json!({"Family":"web","Cpu":"256","Memory":"512","NetworkMode":"awsvpc","RequiresCompatibilities":["FARGATE"],"ContainerDefinitions":[{"Name":"app","Image":"example.com/web:1","PortMappings":[{"ContainerPort":8080,"Protocol":"tcp"}]}]})
    }
    #[tokio::test]
    async fn native_ecs_control_lifecycle_and_failed_scale_compensates_desired_state() {
        let registry = ServiceRegistry::with_known_services();
        locallycloud_ecs::register_with_runtime(&registry, Some(Arc::new(Runtime)));
        let provisioner = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "111111111111".into(),
        );
        let cluster = provisioner
            .ecs_alb_resource("Cluster", "stack", CLUSTER, &json!({"ClusterName":"web"}))
            .await
            .unwrap();
        assert_eq!(cluster.ref_value, "web");
        assert_eq!(
            cluster.attributes["Arn"],
            "arn:aws:ecs:us-east-1:111111111111:cluster/web"
        );
        assert!(provisioner
            .ecs_alb_resource("Other", "other", CLUSTER, &json!({"ClusterName":"web"}))
            .await
            .is_err());
        let definition = provisioner
            .ecs_alb_resource("Task", "stack", DEFINITION, &definition())
            .await
            .unwrap();
        let props = json!({"ServiceName":"web","Cluster":cluster.ref_value,"TaskDefinition":definition.ref_value,"LaunchType":"FARGATE","DesiredCount":0,"NetworkConfiguration":{"AwsvpcConfiguration":{"Subnets":["subnet-test"]}}});
        let service = provisioner
            .ecs_alb_resource("Service", "stack", SERVICE, &props)
            .await
            .unwrap();
        assert!(service.ref_value.ends_with("service/web/web"));
        let mut scaled = props.clone();
        scaled["DesiredCount"] = 1.into();
        let error = provisioner
            .update_ecs_alb("Service", SERVICE, &service, &props, &scaled)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("injected image start failure"));
        let actual = provisioner
            .ecs_call(
                "DescribeServices",
                json!({"cluster":"web","services":[service.ref_value]}),
                "service",
            )
            .await
            .unwrap();
        assert_eq!(actual["services"][0]["desiredCount"], 0);
        provisioner
            .delete_ecs_alb(SERVICE, &service.ref_value, &props)
            .await
            .unwrap();
        provisioner
            .delete_ecs_alb(DEFINITION, &definition.ref_value, &Value::Null)
            .await
            .unwrap();
        let inactive = provisioner
            .ecs_call(
                "DescribeTaskDefinition",
                json!({"taskDefinition":definition.ref_value}),
                "task",
            )
            .await
            .unwrap();
        assert_eq!(inactive["taskDefinition"]["status"], "INACTIVE");
        provisioner
            .delete_ecs_alb(CLUSTER, &cluster.ref_value, &Value::Null)
            .await
            .unwrap();
    }
    #[test]
    fn strict_translations_reject_unimplemented_contracts_and_keep_task_metadata() {
        let mut props = definition();
        props["ContainerDefinitions"][0]["Privileged"] = true.into();
        assert!(ecs_body("Task", DEFINITION, &props).is_err());
        let mut props = definition();
        props["ContainerDefinitions"][0]["LogConfiguration"] = json!({"LogDriver":"awslogs","Options":{"awslogs-group":"/ecs/web","awslogs-region":"us-east-1","awslogs-stream-prefix":"web"}});
        props["TaskRoleArn"] = "arn:aws:iam::111111111111:role/task".into();
        let translated = ecs_body("Task", DEFINITION, &props).unwrap();
        assert_eq!(
            translated["containerDefinitions"][0]["logConfiguration"]["logDriver"],
            "awslogs"
        );
        assert_eq!(translated["taskRoleArn"], props["TaskRoleArn"]);
        assert!(elb_fields("ALB",ALB,&json!({"Type":"network","Scheme":"internal","Subnets":["a","b"],"SecurityGroups":["sg"]}),"web").is_err());
        assert!(elb_fields("Listener",LISTENER,&json!({"LoadBalancerArn":"arn","Port":443,"Protocol":"HTTPS","DefaultActions":[{"Type":"forward","TargetGroupArn":"group"}]}),"").is_err());
        assert!(elb_fields("Target",GROUP,&json!({"Name":"web","VpcId":"vpc","Port":8080,"Protocol":"HTTP","TargetType":"ip","TargetGroupAttributes":[{"Key":"unknown","Value":"1"}]}),"web").is_err());
    }
    struct Vpc(Arc<locallycloud_ec2::Ec2Handler>);
    impl locallycloud_elbv2::VpcPreflight for Vpc {
        fn vpc_lease(&self, account: &str, region: &str, id: &str) -> Option<Arc<dyn Send + Sync>> {
            self.0
                .vpc_lease(account, region, id)
                .map(|lease| Arc::new(lease) as Arc<dyn Send + Sync>)
        }
    }
    #[tokio::test]
    async fn native_target_group_contract_preserves_existing_resources_and_releases_vpc_lease() {
        let registry = ServiceRegistry::with_known_services();
        let ec2 = locallycloud_ec2::register(&registry);
        locallycloud_elbv2::register_with_vpc_preflight(&registry, Arc::new(Vpc(ec2)));
        let provisioner = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "111111111111".into(),
        );
        let vpc = provisioner
            .ec2_vpc("Vpc", &json!({"CidrBlock":"10.72.0.0/16"}))
            .await
            .unwrap();
        let props = json!({"Name":"owned-target","VpcId":vpc.ref_value,"Port":8080,"Protocol":"HTTP","TargetType":"ip","HealthCheckPath":"/health","HealthCheckIntervalSeconds":5,"HealthCheckTimeoutSeconds":2,"HealthyThresholdCount":2,"UnhealthyThresholdCount":2,"TargetGroupAttributes":[{"Key":"deregistration_delay.timeout_seconds","Value":"1"}]});
        let group = provisioner
            .ecs_alb_resource("Group", "stack", GROUP, &props)
            .await
            .unwrap();
        assert!(group.ref_value.starts_with(
            "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/owned-target/"
        ));
        assert_eq!(group.attributes["TargetGroupName"], "owned-target");
        assert!(provisioner
            .ecs_alb_resource("Other", "other", GROUP, &props)
            .await
            .is_err());
        let actual = provisioner
            .elb_call(
                "DescribeTargetGroupAttributes",
                &[("TargetGroupArn".into(), group.ref_value.clone())],
                "group",
            )
            .await
            .unwrap();
        assert!(actual.contains("<Value>1</Value>"));
        assert!(provisioner
            .delete_ec2("DeleteVpc", "VpcId", &vpc.ref_value)
            .await
            .is_err());
        provisioner
            .delete_ecs_alb(GROUP, &group.ref_value, &props)
            .await
            .unwrap();
        provisioner
            .delete_ecs_alb(GROUP, &group.ref_value, &props)
            .await
            .unwrap();
        provisioner
            .delete_ec2("DeleteVpc", "VpcId", &vpc.ref_value)
            .await
            .unwrap();
    }
    #[test]
    fn template_preflight_rejects_nested_unsupported_properties_before_resource_work() {
        let mut task = definition();
        task["ContainerDefinitions"][0]["Privileged"] = true.into();
        let template = json!({"Resources":{"Vpc":{"Type":"AWS::EC2::VPC","Properties":{"CidrBlock":"10.0.0.0/16"}},"Task":{"Type":DEFINITION,"Properties":task}}});
        assert!(crate::template::Template::parse(&template.to_string()).is_err());
        let a = resource_name(
            "a-very-long-stack-name-that-exceeds-load-balancer-limits",
            "Resource",
            32,
        );
        let b = resource_name(
            "a-very-long-stack-name-that-exceeds-load-balancer-limits",
            "Resource",
            32,
        );
        assert!(a.len() <= 32 && b.len() <= 32);
        assert_ne!(a, b);
        assert!(!a.ends_with('-'));
    }
}
