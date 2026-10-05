use super::*;

impl CognitoHandler {
    pub(super) fn authorize_management(
        &self,
        request: &ServiceRequest,
        operation: &str,
        input: &Map<String, Value>,
    ) -> Result<(), CognitoError> {
        use locallycloud_core::integration::{
            authorization::AuthorizationRequest, RequestIdentity,
        };
        use locallycloud_core::registry::ServiceName;
        let Some(registry) = self.registry.upgrade() else {
            return Ok(());
        };
        let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
            return Ok(());
        };
        if !evaluator.strict_sigv4_required() {
            return Ok(());
        }
        let delegated_identity = locallycloud_core::integration::identity::trusted_role(request);
        if delegated_identity.is_none()
            && !request
                .headers
                .get("x-locallycloud-verified-external-sigv4")
                .is_some_and(|v| v == "1")
        {
            return Err(CognitoError::AccessDenied);
        }
        let access_key_id = request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(RequestIdentity::access_key_from_authorization);
        if access_key_id.is_none() && delegated_identity.is_none() {
            return Err(CognitoError::AccessDenied);
        }
        let resource = input
            .get("UserPoolId")
            .and_then(Value::as_str)
            .map(|id| {
                format!(
                    "arn:aws:cognito-idp:{}:{}:userpool/{id}",
                    request.region, request.account_id
                )
            })
            .unwrap_or_else(|| "*".into());
        evaluator
            .authorize(AuthorizationRequest {
                request_identity: RequestIdentity {
                    account_id: request.account_id.clone(),
                    access_key_id,
                    arn: None,
                },
                delegated_identity,
                source_service: "cognito-idp".into(),
                action: format!("cognito-idp:{operation}"),
                resource,
                context: BTreeMap::new(),
            })
            .map_err(|_| CognitoError::AccessDenied)
    }

    fn client_pool(
        &self,
        request: &ServiceRequest,
        client_id: &str,
    ) -> Result<Arc<Mutex<Pool>>, CognitoError> {
        for (scope, pool) in self
            .pools
            .read()
            .map_err(|_| CognitoError::Internal)?
            .iter()
        {
            if scope.account == request.account_id
                && scope.region == request.region
                && pool
                    .lock()
                    .map_err(|_| CognitoError::Internal)?
                    .clients
                    .contains_key(client_id)
            {
                return Ok(pool.clone());
            }
        }
        Err(CognitoError::ResourceNotFound)
    }

    pub(super) fn sign_up(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(
            input,
            &["ClientId", "Username", "Password", "UserAttributes"],
        )?;
        let client_id = string(input, "ClientId")?;
        let username = string(input, "Username")?;
        let password = string(input, "Password")?;
        if username.len() > 128 || username.chars().any(char::is_whitespace) {
            return Err(CognitoError::InvalidParameter);
        }
        validate_password(password)?;
        let attributes = attributes(input.get("UserAttributes"))?;
        if attributes.contains_key("email_verified")
            || attributes.contains_key("phone_number_verified")
            || attributes.contains_key("sub")
        {
            return Err(CognitoError::InvalidParameter);
        }
        let cell = self.client_pool(request, client_id)?;
        let mut pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        if pool.users.contains_key(username) {
            return Err(CognitoError::UsernameExists);
        }
        let sub = Uuid::new_v4().to_string();
        pool.users.insert(
            username.to_owned(),
            User {
                username: username.to_owned(),
                sub: sub.clone(),
                status: "UNCONFIRMED",
                enabled: true,
                password: PasswordHash::new(password),
                attributes,
                created: now()?,
            },
        );
        // No auto-verification is configured: confirmation requires AdminConfirmSignUp.
        Ok(json!({"UserConfirmed":false,"UserSub":sub}))
    }

    pub(super) fn confirm_user(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["UserPoolId", "Username"])?;
        let cell = self.pool(request, string(input, "UserPoolId")?)?;
        let mut pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        let user = pool
            .users
            .get_mut(string(input, "Username")?)
            .ok_or(CognitoError::UserNotFound)?;
        if user.status != "UNCONFIRMED" {
            return Err(CognitoError::NotAuthorized);
        }
        user.status = "CONFIRMED";
        Ok(json!({}))
    }

    pub(super) fn initiate_auth(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["ClientId", "AuthFlow", "AuthParameters"])?;
        let cell = self.client_pool(request, string(input, "ClientId")?)?;
        let pool_id = cell.lock().map_err(|_| CognitoError::Internal)?.id.clone();
        let mut auth = input.clone();
        auth.insert("UserPoolId".into(), pool_id.into());
        self.password_auth(request, &auth, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

    #[tokio::test]
    async fn management_checks_delegated_role_and_rejects_forged_attestation_at_ingress() {
        use locallycloud_core::integration::{
            authorization::{AuthorizationError, AuthorizationEvaluator, AuthorizationRequest},
            identity::{CallerIdentity, IdentityPropagator},
            InternalDispatcher,
        };
        use locallycloud_core::proxy::{LegacyHealth, ProxyConfig};
        use locallycloud_core::registry::{ServiceMetadata, ServiceName, ServiceRegistry};
        struct Deny(Arc<Mutex<Vec<AuthorizationRequest>>>);
        impl AuthorizationEvaluator for Deny {
            fn strict_sigv4_required(&self) -> bool {
                true
            }
            fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError> {
                self.0.lock().unwrap().push(request);
                Err(AuthorizationError::Denied)
            }
        }
        let registry = ServiceRegistry::with_known_services();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(CognitoHandler::with_registry(Arc::downgrade(&registry)));
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            handler.clone(),
            Arc::new(Deny(calls.clone())),
        );
        registry.register_native(
            ServiceName::new("cognito-idp"),
            ServiceMetadata::new(AwsProtocol::Json11, Some(TARGET_PREFIX)),
            handler.clone(),
        );
        let mut request = ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: Default::default(),
            body: json!({"UserPoolId":"us-east-1_test","Username":"alice"})
                .to_string()
                .into(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "authz-test".into(),
        };
        request.headers.insert(
            "content-type",
            "application/x-amz-json-1.1".parse().unwrap(),
        );
        request.headers.insert(
            "x-amz-target",
            format!("{TARGET_PREFIX}.AdminConfirmSignUp")
                .parse()
                .unwrap(),
        );
        request.headers.insert(
            "x-locallycloud-verified-internal-scope",
            "1".parse().unwrap(),
        );
        let role = CallerIdentity::AssumedRole {
            role_arn: "arn:aws:iam::000000000000:role/worker".into(),
            session_name: "producer".into(),
        };
        IdentityPropagator::attach(&mut request.headers, &role);
        assert!(matches!(
            handler.process(&request).await,
            Err(CognitoError::AccessDenied)
        ));
        {
            let requests = calls.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].delegated_identity, Some(role));
            assert_eq!(requests[0].action, "cognito-idp:AdminConfirmSignUp");
            assert_eq!(
                requests[0].resource,
                "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_test"
            );
        }
        let dispatcher = InternalDispatcher::new(
            registry,
            ProxyConfig {
                backend_url: "http://127.0.0.1:1".into(),
                upstream_timeout: std::time::Duration::from_secs(1),
            },
            LegacyHealth::new(false),
            request.region.clone(),
            request.account_id.clone(),
        );
        request.headers.insert(
            "x-locallycloud-verified-external-sigv4",
            "1".parse().unwrap(),
        );
        request.headers.insert(http::header::AUTHORIZATION, "AWS4-HMAC-SHA256 Credential=AKIAFORGED/20261004/us-east-1/cognito-idp/aws4_request, SignedHeaders=host;x-amz-date;x-amz-target, Signature=0000000000000000000000000000000000000000000000000000000000000000".parse().unwrap());
        let response = dispatcher
            .dispatch(
                &request.method,
                &request.uri,
                &request.headers,
                request.body.clone(),
                &request.request_id,
            )
            .await;
        assert_eq!(response.status(), 403);
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn signup_requires_confirmation_then_issues_verifiable_scoped_tokens() {
        let handler = CognitoHandler::new();
        let request = ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: Default::default(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "auth-test".into(),
        };
        let pool = handler
            .create_pool(&request, json!({"PoolName":"test"}).as_object().unwrap())
            .await
            .unwrap();
        let id = pool["UserPool"]["Id"].as_str().unwrap();
        let client = handler.create_client(&request, json!({"UserPoolId":id,"ClientName":"app","ExplicitAuthFlows":["ALLOW_USER_PASSWORD_AUTH"]}).as_object().unwrap()).unwrap();
        let client_id = client["UserPoolClient"]["ClientId"].as_str().unwrap();
        let signup = json!({"ClientId":client_id,"Username":"alice","Password":"Correct123!"});
        let created = handler
            .sign_up(&request, signup.as_object().unwrap())
            .unwrap();
        assert_eq!(created["UserConfirmed"], false);
        assert!(matches!(
            handler.sign_up(&request, signup.as_object().unwrap()),
            Err(CognitoError::UsernameExists)
        ));
        let auth = json!({"ClientId":client_id,"AuthFlow":"USER_PASSWORD_AUTH","AuthParameters":{"USERNAME":"alice","PASSWORD":"Correct123!"}});
        assert!(matches!(
            handler.initiate_auth(&request, auth.as_object().unwrap()),
            Err(CognitoError::UserNotConfirmed)
        ));
        handler
            .confirm_user(
                &request,
                json!({"UserPoolId":id,"Username":"alice"})
                    .as_object()
                    .unwrap(),
            )
            .unwrap();
        let tokens = handler
            .initiate_auth(&request, auth.as_object().unwrap())
            .unwrap();
        let jwks = handler
            .jwks_for_pool(&request.account_id, &request.region, id)
            .unwrap();
        for (field, use_, index) in [("AccessToken", "access", 0), ("IdToken", "id", 1)] {
            let key = &jwks["keys"][index];
            let key = DecodingKey::from_rsa_components(
                key["n"].as_str().unwrap(),
                key["e"].as_str().unwrap(),
            )
            .unwrap();
            let mut validation = Validation::new(Algorithm::RS256);
            validation.validate_aud = false;
            let claims = decode::<Value>(
                tokens["AuthenticationResult"][field].as_str().unwrap(),
                &key,
                &validation,
            )
            .unwrap()
            .claims;
            assert_eq!(claims["token_use"], use_);
            assert_eq!(claims["sub"], created["UserSub"]);
        }
        let mut bad = auth.clone();
        bad["AuthParameters"]["PASSWORD"] = "Wrong123!".into();
        assert!(matches!(
            handler.initiate_auth(&request, bad.as_object().unwrap()),
            Err(CognitoError::NotAuthorized)
        ));
        let mut foreign = request.clone();
        foreign.region = "us-west-2".into();
        assert!(matches!(
            handler.initiate_auth(&foreign, auth.as_object().unwrap()),
            Err(CognitoError::ResourceNotFound)
        ));
    }
}
