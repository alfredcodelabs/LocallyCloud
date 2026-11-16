//! IAM and repository policies apply to each operation, including an already issued token.
use super::*;
use locallycloud_core::integration::authorization::{AuthorizationEvaluator, ResourcePolicyError};
use locallycloud_core::integration::identity::{trusted_role, CallerIdentity};
use locallycloud_core::integration::request_context::verified_request_context;

fn denied() -> AwsError {
    AwsError::new("AccessDeniedException", "Access denied", 400)
}

fn unavailable() -> AwsError {
    AwsError::new("ServerException", "ECR authorization is unavailable", 500)
}

pub(super) fn normalized_repository_policy(raw: &str) -> Result<Arc<str>, AwsError> {
    if raw.is_empty() || raw.len() > 10_240 {
        return Err(invalid("policyText must contain 1 to 10240 bytes"));
    }
    let mut policy: Value =
        serde_json::from_str(raw).map_err(|_| invalid("policyText must be a JSON policy"))?;
    let normalize = |statement: &mut Value| -> Result<(), AwsError> {
        statement
            .as_object_mut()
            .ok_or_else(|| invalid("policy statement must be an object"))?
            .entry("Resource")
            .or_insert_with(|| json!("*"));
        Ok(())
    };
    match policy.get_mut("Statement") {
        Some(Value::Array(statements)) if !statements.is_empty() => {
            for statement in statements {
                normalize(statement)?;
            }
        }
        Some(statement @ Value::Object(_)) => normalize(statement)?,
        _ => return Err(invalid("policyText requires statements")),
    }
    Ok(serde_json::to_string(&policy)
        .map_err(|_| invalid("invalid policyText"))?
        .into())
}

impl EcrHandler {
    /// Authorize the execution role before materializing a private image for ECS.
    /// The runtime supplies an attested identity, never a principal parsed from an image URI.
    pub async fn authorize_image_pull(
        self: &Arc<Self>,
        account: &str,
        region: &str,
        repository: &str,
        identity: CallerIdentity,
    ) -> Result<(), String> {
        let handler = self.clone();
        let (account, region, repository) =
            (account.to_owned(), region.to_owned(), repository.to_owned());
        tokio::task::spawn_blocking(move || {
            let denied = || "ECR image access denied".to_owned();
            validate_repository_name(&repository).map_err(|_| denied())?;
            let Some(evaluator) = handler.evaluator().map_err(|_| denied())? else { return Ok(()); };
            if !evaluator.strict_sigv4_required() { return Ok(()); }
            let CallerIdentity::AssumedRole { role_arn, .. } = &identity else { return Err(denied()); };
            let request = ServiceRequest {
                method:http::Method::GET, uri:http::Uri::from_static("/"), headers:http::HeaderMap::new(), body:bytes::Bytes::new(),
                account_id:account.clone(), region, request_id:"ecr-image-pull".into(),
            };
            let caller = RequestIdentity { account_id:account, access_key_id:None, arn:None };
            evaluator.authorize_service_role_trust(locallycloud_core::integration::authorization::ServiceRoleAuthorizationRequest {
                caller:caller.clone(), delegated_caller:None, caller_context:Default::default(), source_arn:None,
                role_arn:role_arn.clone(), service_principal:"ecs-tasks.amazonaws.com".into(), action:"sts:AssumeRole".into(), resource:role_arn.clone(),
            }).map_err(|_| denied())?;
            evaluator.authorize(Self::authorization_request(&request, caller.clone(), Some(identity.clone()), "GetAuthorizationToken", "*".into())).map_err(|_| denied())?;
            for action in ["BatchGetImage", "GetDownloadUrlForLayer"] {
                handler.authorize_repository(evaluator.as_ref(), &request, caller.clone(), Some(identity.clone()), action, &repository).map_err(|_| denied())?;
            }
            Ok(())
        }).await.map_err(|_| "ECR image authorization worker unavailable".to_owned())?
    }

    fn evaluator(&self) -> Result<Option<Arc<dyn AuthorizationEvaluator>>, AwsError> {
        let Some(registry) = &self.registry else {
            return Ok(None);
        };
        let registry = registry.upgrade().ok_or_else(unavailable)?;
        registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .map(Some)
            .ok_or_else(unavailable)
    }

    pub(super) fn request_identity(request: &ServiceRequest) -> RequestIdentity {
        RequestIdentity {
            account_id: request.account_id.clone(),
            access_key_id: request
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|header| header.to_str().ok())
                .and_then(RequestIdentity::access_key_from_authorization),
            arn: None,
        }
    }

    fn authorization_request(
        request: &ServiceRequest,
        identity: RequestIdentity,
        delegated_identity: Option<CallerIdentity>,
        action: &str,
        resource: String,
    ) -> AuthorizationRequest {
        let mut context = verified_request_context(request);
        context.insert(
            "aws:resourceaccount".into(),
            vec![request.account_id.clone()],
        );
        AuthorizationRequest {
            request_identity: identity,
            delegated_identity,
            source_service: "ecr".into(),
            action: format!("ecr:{action}"),
            resource,
            context,
        }
    }

    fn repository_arn(request: &ServiceRequest, name: &str) -> String {
        format!(
            "arn:aws:ecr:{}:{}:repository/{name}",
            request.region, request.account_id
        )
    }

    fn authorize_repository(
        &self,
        evaluator: &dyn AuthorizationEvaluator,
        request: &ServiceRequest,
        identity: RequestIdentity,
        delegated: Option<CallerIdentity>,
        action: &str,
        name: &str,
    ) -> Result<(), AwsError> {
        let policy = self
            .repos
            .get(&Self::key(&request.account_id, &request.region, name))
            .and_then(|repository| repository.effective_policy.clone());
        evaluator
            .authorize_resource_policy(
                Self::authorization_request(
                    request,
                    identity,
                    delegated,
                    action,
                    Self::repository_arn(request, name),
                ),
                policy.as_deref(),
                &request.account_id,
            )
            .map_err(|_| denied())
    }

    pub(super) fn authorize_control_plane(
        &self,
        request: &ServiceRequest,
        operation: &str,
        body: &Map<String, Value>,
    ) -> Result<(), AwsError> {
        if operation == "GetAuthorizationToken" {
            return Ok(());
        }
        let Some(registry) = &self.registry else {
            return Ok(());
        };
        let registry = registry.upgrade().ok_or_else(unavailable)?;
        let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
            return Ok(());
        };
        if !evaluator.strict_sigv4_required() {
            return Ok(());
        }
        let identity = Self::request_identity(request);
        let delegated = trusted_role(request);
        match operation {
            "DescribeRepositories" => {
                if let Some(names) = body.get("repositoryNames") {
                    let names = names
                        .as_array()
                        .filter(|names| !names.is_empty() && names.len() <= 100)
                        .ok_or_else(|| invalid("repositoryNames must contain 1 to 100 names"))?;
                    for name in names {
                        let name = name
                            .as_str()
                            .ok_or_else(|| invalid("repository name must be a string"))?;
                        validate_repository_name(name)?;
                        self.authorize_repository(
                            evaluator.as_ref(),
                            request,
                            identity.clone(),
                            delegated.clone(),
                            operation,
                            name,
                        )?;
                    }
                    return Ok(());
                }
                evaluator
                    .authorize(Self::authorization_request(
                        request,
                        identity,
                        delegated,
                        operation,
                        "*".into(),
                    ))
                    .map_err(|_| denied())
            }
            "CreateRepository" => {
                let name = required_repository_name(body)?;
                evaluator
                    .authorize(Self::authorization_request(
                        request,
                        identity,
                        delegated,
                        operation,
                        Self::repository_arn(request, name),
                    ))
                    .map_err(|_| denied())
            }
            "DeleteRepository"
            | "ListImages"
            | "BatchDeleteImage"
            | "GetRepositoryPolicy"
            | "SetRepositoryPolicy"
            | "DeleteRepositoryPolicy" => self.authorize_repository(
                evaluator.as_ref(),
                request,
                identity,
                delegated,
                operation,
                required_repository_name(body)?,
            ),
            _ => Ok(()),
        }
    }

    pub(super) fn authorize_token_issuance(
        &self,
        request: &ServiceRequest,
    ) -> Result<(), AwsError> {
        let Some(evaluator) = self.evaluator()? else {
            return Ok(());
        };
        if !evaluator.strict_sigv4_required() {
            return Ok(());
        }
        evaluator
            .authorize(Self::authorization_request(
                request,
                Self::request_identity(request),
                trusted_role(request),
                "GetAuthorizationToken",
                "*".into(),
            ))
            .map_err(|_| denied())
    }

    pub(super) fn authorize_registry(
        &self,
        token: &RegistryToken,
        request: &ServiceRequest,
    ) -> Result<(), registry_v2::RegistryError> {
        let denied_error = || registry_v2::RegistryError::Denied;
        let evaluator = self.evaluator().map_err(|_| denied_error())?;
        let Some(evaluator) = evaluator else {
            return Ok(());
        };
        if !evaluator.strict_sigv4_required() {
            return Ok(());
        }
        // A Registry token cannot revive expired STS credentials or a deleted principal.
        // Typed service delegation is retained only when Core attested it at issuance.
        if token.delegated_identity.is_none()
            && evaluator
                .resolve_caller_arn(&token.identity)
                .ok()
                .flatten()
                .is_none()
        {
            return Err(denied_error());
        }
        if let Some(permission) = registry_v2::authorization(request)? {
            for action in permission.actions {
                self.authorize_repository(
                    evaluator.as_ref(),
                    request,
                    token.identity.clone(),
                    token.delegated_identity.clone(),
                    action,
                    permission.repository,
                )
                .map_err(|_| denied_error())?;
            }
        }
        Ok(())
    }

    pub(super) fn repository_policy(
        &self,
        request: &ServiceRequest,
        body: &Map<String, Value>,
        operation: &str,
    ) -> Result<Value, AwsError> {
        let allowed = if operation == "SetRepositoryPolicy" {
            &["registryId", "repositoryName", "policyText", "force"][..]
        } else {
            &["registryId", "repositoryName"][..]
        };
        reject_unknown_fields(body, allowed, operation)?;
        validate_registry_id(body, &request.account_id)?;
        let name = required_repository_name(body)?;
        let proposed = if operation == "SetRepositoryPolicy" {
            let raw = body
                .get("policyText")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("policyText is required"))?;
            let normalized = normalized_repository_policy(raw)?;
            let evaluator = self.evaluator()?.ok_or_else(unavailable)?;
            evaluator
                .validate_resource_policy(&normalized)
                .map_err(|error| match error {
                    ResourcePolicyError::Malformed(_) => {
                        invalid("policyText is not a supported valid repository policy")
                    }
                    ResourcePolicyError::Unsupported(_) => AwsError::new(
                        "UnsupportedOperationException",
                        "repository policy construct is not implemented",
                        501,
                    ),
                })?;
            let force = match body.get("force") {
                None => false,
                Some(Value::Bool(force)) => *force,
                _ => return Err(invalid("force must be a boolean")),
            };
            if !force
                && evaluator
                    .authorize_resource_policy(
                        Self::authorization_request(
                            request,
                            Self::request_identity(request),
                            trusted_role(request),
                            "SetRepositoryPolicy",
                            Self::repository_arn(request, name),
                        ),
                        Some(&normalized),
                        &request.account_id,
                    )
                    .is_err()
            {
                return Err(invalid(
                    "the repository policy would prevent future policy updates; force is required",
                ));
            }
            Some((raw.to_owned(), normalized))
        } else {
            None
        };
        let mut repository = self
            .repos
            .get_mut(&Self::key(&request.account_id, &request.region, name))
            .ok_or_else(|| repository_not_found(name, &request.account_id))?;
        if operation == "GetRepositoryPolicy" {
            return repository.policy.as_ref().map(|policy| json!({"registryId":request.account_id,"repositoryName":name,"policyText":policy}))
                .ok_or_else(|| AwsError::new("RepositoryPolicyNotFoundException", "repository policy does not exist", 400));
        }
        let previous = repository.policy.clone();
        if operation == "DeleteRepositoryPolicy" && previous.is_none() {
            return Err(AwsError::new(
                "RepositoryPolicyNotFoundException",
                "repository policy does not exist",
                400,
            ));
        }
        let mut staged = repository.clone();
        match proposed {
            Some((raw, normalized)) => {
                staged.policy = Some(raw);
                staged.effective_policy = Some(normalized);
            }
            None => {
                staged.policy = None;
                staged.effective_policy = None;
            }
        }
        let metadata = serde_json::to_vec(&staged).map_err(|_| unavailable())?;
        self.registry_v2
            .save_repository_metadata(&request.account_id, &request.region, name, &metadata)
            .map_err(|_| unavailable())?;
        let returned = staged
            .policy
            .as_ref()
            .or(previous.as_ref())
            .cloned()
            .ok_or_else(unavailable)?;
        *repository = staged;
        Ok(json!({"registryId":request.account_id,"repositoryName":name,"policyText":returned}))
    }
}
