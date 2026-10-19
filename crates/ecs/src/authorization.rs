//! Public ECS action authorization; autonomous reconciliation uses its own service identities.
use super::*;
use locallycloud_core::integration::authorization::AuthorizationRequest;
use locallycloud_core::integration::identity::trusted_role;

impl EcsHandler {
    pub(super) fn authorize_operator(
        &self,
        request: &ServiceRequest,
        resolved_definition: Option<&str>,
    ) -> Result<(), EcsError> {
        let Some(evaluator) = self.registry.upgrade().and_then(|registry| {
            registry.authorization_evaluator(&locallycloud_core::registry::ServiceName::new("iam"))
        }) else {
            return Ok(());
        };
        let operation = self.operation(request)?;
        let input: Value = decode(&request.body)?;
        let scope = Scope::new(request);
        let cluster = || cluster_name(&scope, input["cluster"].as_str().unwrap_or("default"));
        let service_arn = |value: &str| -> Result<String, EcsError> {
            let cluster = cluster()?;
            let name = service_name(&scope, &cluster, value)?;
            Ok(format!(
                "arn:aws:ecs:{}:{}:service/{cluster}/{name}",
                scope.region, scope.account
            ))
        };
        let task_arn = |value: &str| -> Result<String, EcsError> {
            let prefix = format!("arn:aws:ecs:{}:{}:task/", scope.region, scope.account);
            if value.starts_with("arn:") {
                return if value.starts_with(&prefix) {
                    Ok(value.into())
                } else {
                    Err(EcsError::Client("Task was not found".into()))
                };
            }
            Ok(format!("{prefix}{}/{value}", cluster()?))
        };
        // AWS's authorization table requires wildcard resources for registration and task-definition reads.
        // https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecs.html
        let mut resources = match operation {
            "CreateCluster" => {
                let name = input["clusterName"].as_str().unwrap_or("default");
                valid_name(name)?;
                vec![scope.cluster_arn(name)]
            }
            "DeleteCluster" => {
                vec![scope.cluster_arn(&cluster_name(&scope, required(&input, "cluster")?)?)]
            }
            "DescribeClusters" => match input.get("clusters") {
                Some(values) => strings(values, 100)?
                    .into_iter()
                    .map(|value| cluster_name(&scope, value).map(|name| scope.cluster_arn(&name)))
                    .collect::<Result<Vec<_>, _>>()?,
                None => vec![scope.cluster_arn("default")],
            },
            "RunTask" => vec![resolved_definition.ok_or(EcsError::Internal)?.into()],
            "DeregisterTaskDefinition" => {
                let identifier = required(&input, "taskDefinition")?;
                let (family, revision) = task_identifier(&scope, identifier)?;
                vec![scope.task_arn(
                    &family,
                    revision.ok_or_else(|| {
                        EcsError::Client("Deregistration requires a revision".into())
                    })?,
                )]
            }
            "CreateService" => vec![service_arn(required(&input, "serviceName")?)?],
            "UpdateService" | "DeleteService" => vec![service_arn(required(&input, "service")?)?],
            "DescribeServices" => strings(&input["services"], 10)?
                .into_iter()
                .map(service_arn)
                .collect::<Result<Vec<_>, _>>()?,
            "StopTask" => vec![task_arn(required(&input, "task")?)?],
            "DescribeTasks" => strings(&input["tasks"], 100)?
                .into_iter()
                .map(task_arn)
                .collect::<Result<Vec<_>, _>>()?,
            "RegisterTaskDefinition" | "DescribeTaskDefinition" | "ListClusters" | "ListTasks" => {
                vec!["*".into()]
            }
            _ => return Ok(()),
        };
        if resources.is_empty() {
            resources.push("*".into());
        }
        let mut context = BTreeMap::new();
        if matches!(
            operation,
            "RunTask"
                | "CreateService"
                | "UpdateService"
                | "DeleteService"
                | "DescribeServices"
                | "StopTask"
                | "DescribeTasks"
                | "ListTasks"
        ) {
            context.insert("ecs:cluster".into(), vec![scope.cluster_arn(&cluster()?)]);
        }
        if let Some(definition) = resolved_definition {
            context.insert("ecs:task-definition".into(), vec![definition.into()]);
            let actual = self.describe_task_definition(
                DescribeTaskDefinition {
                    task_definition: definition.into(),
                    include: None,
                },
                &scope,
            )?;
            for (property, key) in [("cpu", "ecs:task-cpu"), ("memory", "ecs:task-memory")] {
                if let Some(value) = actual["taskDefinition"][property].as_str() {
                    context.insert(key.into(), vec![value.into()]);
                }
            }
        }
        if operation == "RegisterTaskDefinition" {
            if let Some(cpu) = input["cpu"].as_str() {
                context.insert("ecs:task-cpu".into(), vec![parse_cpu(cpu)?.to_string()]);
            }
            if let Some(memory) = input["memory"].as_str() {
                context.insert(
                    "ecs:task-memory".into(),
                    vec![parse_memory(memory)?.to_string()],
                );
            }
        }
        if let Some(subnets) =
            input["networkConfiguration"]["awsvpcConfiguration"]["subnets"].as_array()
        {
            let values = subnets
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| EcsError::Serialization("Subnet must be a string".into()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            context.insert("ecs:subnet".into(), values);
        }
        let caller = RequestIdentity {
            account_id: scope.account.clone(),
            access_key_id: request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(RequestIdentity::access_key_from_authorization),
            arn: None,
        };
        for resource in resources {
            evaluator
                .authorize(AuthorizationRequest {
                    request_identity: caller.clone(),
                    delegated_identity: trusted_role(request),
                    source_service: "ecs".into(),
                    action: format!("ecs:{operation}"),
                    resource,
                    context: context.clone(),
                })
                .map_err(|_| EcsError::AccessDenied)?;
        }
        Ok(())
    }
}
fn required<'a>(value: &'a Value, key: &str) -> Result<&'a str, EcsError> {
    value[key]
        .as_str()
        .ok_or_else(|| EcsError::Serialization(format!("{key} must be a string")))
}
fn strings(value: &Value, maximum: usize) -> Result<Vec<&str>, EcsError> {
    let values = value
        .as_array()
        .filter(|values| values.len() <= maximum)
        .ok_or_else(|| EcsError::Client("Invalid resource list".into()))?;
    values
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                EcsError::Serialization("Resource identifier must be a string".into())
            })
        })
        .collect()
}
