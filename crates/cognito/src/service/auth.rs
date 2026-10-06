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

    pub(super) async fn sign_up_async(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        let cell = self.client_pool(request, string(input, "ClientId")?)?;
        let mailbox = self.mailbox.clone();
        let request = request.clone();
        let input = input.clone();
        tokio::task::spawn_blocking(move || Self::sign_up_in_pool(&request, &input, cell, mailbox))
            .await
            .map_err(|_| CognitoError::Internal)?
    }

    #[cfg(test)]
    fn sign_up(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        let cell = self.client_pool(request, string(input, "ClientId")?)?;
        Self::sign_up_in_pool(request, input, cell, self.mailbox.clone())
    }

    fn sign_up_in_pool(
        request: &ServiceRequest,
        input: &Map<String, Value>,
        cell: Arc<Mutex<Pool>>,
        mailbox: Option<Arc<crate::ConfirmationMailbox>>,
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
        let mut pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        if pool.deleted || !pool.clients.contains_key(client_id) {
            return Err(CognitoError::ResourceNotFound);
        }
        if pool.users.contains_key(username) {
            return Err(CognitoError::UsernameExists);
        }
        let confirmation = if pool.auto_verify_email {
            let mailbox = mailbox.as_ref().ok_or(CognitoError::CodeDeliveryFailure)?;
            let email = attributes
                .get("email")
                .filter(|v| v.contains('@') && !v.chars().any(char::is_whitespace))
                .ok_or(CognitoError::InvalidParameter)?;
            use rand::Rng;
            let code = format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000u32));
            let expires = now()? + 86400;
            mailbox.deliver(&json!({"AccountId":request.account_id,"Region":request.region,"UserPoolId":pool.id,"ClientId":client_id,"Username":username,"Destination":email,"DeliveryMedium":"EMAIL","ConfirmationCode":code,"ExpiresAt":expires}))?;
            Some(ConfirmationCode {
                client_id: client_id.into(),
                hash: PasswordHash::new(&code),
                expires,
                failures: 0,
            })
        } else {
            None
        };
        let details = confirmation.as_ref().map(|_| {
            let email = attributes.get("email").expect("verified delivery attribute");
            let (local, domain) = email.split_once('@').expect("validated email");
            json!({"AttributeName":"email","DeliveryMedium":"EMAIL","Destination":format!("{}***@{}",local.chars().next().unwrap_or('*'),domain)})
        });
        let sub = Uuid::new_v4().to_string();
        pool.users.insert(
            username.to_owned(),
            User {
                username: username.to_owned(),
                sub: sub.clone(),
                status: "UNCONFIRMED",
                enabled: true,
                password: PasswordHash::new(password),
                password_generation: opaque_token(),
                confirmation,
                attributes,
                created: now()?,
            },
        );
        let mut result = json!({"UserConfirmed":false,"UserSub":sub});
        if let Some(details) = details {
            result["CodeDeliveryDetails"] = details;
        }
        Ok(result)
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
        user.confirmation = None;
        Ok(json!({}))
    }

    pub(super) fn confirm_sign_up(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(
            input,
            &[
                "ClientId",
                "Username",
                "ConfirmationCode",
                "ForceAliasCreation",
            ],
        )?;
        if input.get("ForceAliasCreation").is_some_and(|v| v != false) {
            return Err(CognitoError::Unsupported);
        }
        let client_id = string(input, "ClientId")?;
        let username = string(input, "Username")?;
        let code = string(input, "ConfirmationCode")?;
        let cell = self.client_pool(request, client_id)?;
        let mut pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        let user = pool
            .users
            .get_mut(username)
            .ok_or(CognitoError::UserNotFound)?;
        if user.status != "UNCONFIRMED" {
            return Err(CognitoError::NotAuthorized);
        }
        let confirmation = user
            .confirmation
            .as_mut()
            .ok_or(CognitoError::CodeMismatch)?;
        if confirmation.client_id != client_id {
            return Err(CognitoError::CodeMismatch);
        }
        if confirmation.expires <= now()? {
            return Err(CognitoError::ExpiredCode);
        }
        if confirmation.failures >= 5 {
            return Err(CognitoError::TooManyFailedAttempts);
        }
        if code.len() != 6
            || !code.bytes().all(|v| v.is_ascii_digit())
            || !confirmation.hash.verify(code)
        {
            confirmation.failures += 1;
            return Err(CognitoError::CodeMismatch);
        }
        user.attributes
            .insert("email_verified".into(), "true".into());
        user.status = "CONFIRMED";
        user.confirmation = None;
        Ok(json!({}))
    }

    pub(super) fn respond_to_challenge(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
        admin: bool,
    ) -> Result<Value, CognitoError> {
        allowed(
            input,
            if admin {
                &[
                    "UserPoolId",
                    "ClientId",
                    "ChallengeName",
                    "ChallengeResponses",
                    "Session",
                ]
            } else {
                &["ClientId", "ChallengeName", "ChallengeResponses", "Session"]
            },
        )?;
        if string(input, "ChallengeName")? != "NEW_PASSWORD_REQUIRED" {
            return Err(CognitoError::Unsupported);
        }
        let client_id = string(input, "ClientId")?;
        let cell = if admin {
            self.pool(request, string(input, "UserPoolId")?)?
        } else {
            self.client_pool(request, client_id)?
        };
        let responses = input
            .get("ChallengeResponses")
            .and_then(Value::as_object)
            .ok_or(CognitoError::InvalidParameter)?;
        allowed(responses, &["USERNAME", "NEW_PASSWORD"])?;
        let username = string(responses, "USERNAME")?;
        let password = string(responses, "NEW_PASSWORD")?;
        validate_password(password)?;
        let session_id = string(input, "Session")?;
        let mut pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        let issued = now()?;
        pool.challenges
            .retain(|_, challenge| challenge.expires > issued);
        let session = pool
            .challenges
            .get(session_id)
            .ok_or(CognitoError::NotAuthorized)?;
        let client = pool
            .clients
            .get(client_id)
            .ok_or(CognitoError::ResourceNotFound)?;
        if session.client_id != client_id
            || session.username != username
            || session.admin != admin
            || (admin && !client.admin_password_auth)
            || (!admin && !client.user_password_auth)
        {
            return Err(CognitoError::NotAuthorized);
        }
        let user = pool
            .users
            .get(username)
            .ok_or(CognitoError::NotAuthorized)?;
        if !user.enabled
            || user.status != "FORCE_CHANGE_PASSWORD"
            || user.sub != session.sub
            || user.password_generation != session.generation
        {
            return Err(CognitoError::NotAuthorized);
        }
        let result = authentication_result(&pool, user, client_id)?;
        let user = pool
            .users
            .get_mut(username)
            .ok_or(CognitoError::NotAuthorized)?;
        user.password = PasswordHash::new(password);
        user.password_generation = opaque_token();
        user.status = "CONFIRMED";
        pool.challenges.remove(session_id);
        Ok(result)
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
    #[tokio::test]
    async fn temporary_password_challenge_scopes_expiry_and_single_use() {
        let handler = CognitoHandler::new();
        let request = ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: Default::default(),
            body: Default::default(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "challenge-test".into(),
        };
        let result = handler
            .create_pool(
                &request,
                json!({"PoolName":"challenge"}).as_object().unwrap(),
            )
            .await
            .unwrap();
        let id = result["UserPool"]["Id"].as_str().unwrap();
        let result=handler.create_client(&request,json!({"UserPoolId":id,"ClientName":"web","ExplicitAuthFlows":["ALLOW_USER_PASSWORD_AUTH","ALLOW_ADMIN_USER_PASSWORD_AUTH"]}).as_object().unwrap()).unwrap();
        let client = result["UserPoolClient"]["ClientId"].as_str().unwrap();
        handler.admin_create_user(&request,json!({"UserPoolId":id,"Username":"alice","TemporaryPassword":"Temporary1!","MessageAction":"SUPPRESS"}).as_object().unwrap()).unwrap();
        let login = json!({"ClientId":client,"AuthFlow":"USER_PASSWORD_AUTH","AuthParameters":{"USERNAME":"alice","PASSWORD":"Temporary1!"}});
        let challenge = handler
            .initiate_auth(&request, login.as_object().unwrap())
            .unwrap();
        assert_eq!(challenge["ChallengeName"], "NEW_PASSWORD_REQUIRED");
        assert!(challenge.get("AuthenticationResult").is_none());
        let mut response = json!({"ClientId":client,"ChallengeName":"NEW_PASSWORD_REQUIRED","Session":challenge["Session"],"ChallengeResponses":{"USERNAME":"alice","NEW_PASSWORD":"Permanent1!"}});
        response["ChallengeResponses"]["NEW_PASSWORD"] = "short".into();
        assert!(matches!(
            handler.respond_to_challenge(&request, response.as_object().unwrap(), false),
            Err(CognitoError::InvalidPassword)
        ));
        response["ChallengeResponses"]["NEW_PASSWORD"] = "Permanent1!".into();
        let mut foreign = request.clone();
        foreign.region = "us-west-2".into();
        assert!(handler
            .respond_to_challenge(&foreign, response.as_object().unwrap(), false)
            .is_err());
        foreign = request.clone();
        foreign.account_id = "111111111111".into();
        assert!(handler
            .respond_to_challenge(&foreign, response.as_object().unwrap(), false)
            .is_err());
        let mut admin = response.clone();
        admin["UserPoolId"] = id.into();
        assert!(handler
            .respond_to_challenge(&request, admin.as_object().unwrap(), true)
            .is_err());
        let result = handler
            .respond_to_challenge(&request, response.as_object().unwrap(), false)
            .unwrap();
        assert!(result["AuthenticationResult"]["AccessToken"].is_string());
        assert!(handler
            .respond_to_challenge(&request, response.as_object().unwrap(), false)
            .is_err());
        assert!(handler
            .initiate_auth(&request, login.as_object().unwrap())
            .is_err());
        handler.admin_set_password(&request,json!({"UserPoolId":id,"Username":"alice","Password":"Temporary2!","Permanent":false}).as_object().unwrap()).unwrap();
        let login = json!({"UserPoolId":id,"ClientId":client,"AuthFlow":"ADMIN_USER_PASSWORD_AUTH","AuthParameters":{"USERNAME":"alice","PASSWORD":"Temporary2!"}});
        let challenge = handler
            .admin_auth(&request, login.as_object().unwrap())
            .unwrap();
        let response = json!({"UserPoolId":id,"ClientId":client,"ChallengeName":"NEW_PASSWORD_REQUIRED","Session":challenge["Session"],"ChallengeResponses":{"USERNAME":"alice","NEW_PASSWORD":"Permanent2!"}});
        let cell = handler.pool(&request, id).unwrap();
        cell.lock()
            .unwrap()
            .challenges
            .get_mut(challenge["Session"].as_str().unwrap())
            .unwrap()
            .expires = now().unwrap() - 1;
        assert!(handler
            .respond_to_challenge(&request, response.as_object().unwrap(), true)
            .is_err());
        let challenge = handler
            .admin_auth(&request, login.as_object().unwrap())
            .unwrap();
        let mut response = response;
        response["Session"] = challenge["Session"].clone();
        assert!(handler
            .respond_to_challenge(&request, response.as_object().unwrap(), true)
            .is_ok());
    }
    #[tokio::test]
    async fn mailbox_confirmation_uses_real_scoped_expiring_code_and_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("lc-cognito-mailbox-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mailbox = Arc::new(crate::ConfirmationMailbox::new(root.clone()).unwrap());
        let handler = CognitoHandler::with_registry_and_mailbox(Default::default(), Some(mailbox));
        let request = ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: Default::default(),
            body: Default::default(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "confirmation-test".into(),
        };
        let pool = handler
            .create_pool(
                &request,
                json!({"PoolName":"confirmation","AutoVerifiedAttributes":["email"]})
                    .as_object()
                    .unwrap(),
            )
            .await
            .unwrap();
        let id = pool["UserPool"]["Id"].as_str().unwrap();
        let create_client = |name| json!({"UserPoolId":id,"ClientName":name,"ExplicitAuthFlows":["ALLOW_USER_PASSWORD_AUTH"]});
        let client = handler
            .create_client(&request, create_client("web").as_object().unwrap())
            .unwrap()["UserPoolClient"]["ClientId"]
            .as_str()
            .unwrap()
            .to_owned();
        let other = handler
            .create_client(&request, create_client("other").as_object().unwrap())
            .unwrap()["UserPoolClient"]["ClientId"]
            .as_str()
            .unwrap()
            .to_owned();
        let signup = json!({"ClientId":client,"Username":"alice","Password":"SecurePass1!","UserAttributes":[{"Name":"email","Value":"alice@example.test"}]});
        let result = handler
            .sign_up(&request, signup.as_object().unwrap())
            .unwrap();
        assert_eq!(result["UserConfirmed"], false);
        assert_eq!(result["CodeDeliveryDetails"]["DeliveryMedium"], "EMAIL");
        assert!(result.get("ConfirmationCode").is_none());
        assert!(matches!(
            handler.sign_up(&request, signup.as_object().unwrap()),
            Err(CognitoError::UsernameExists)
        ));
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        let entry = std::fs::read_dir(&root).unwrap().next().unwrap().unwrap();
        assert_eq!(
            entry.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        let delivery: Value =
            serde_json::from_slice(&std::fs::read(entry.path()).unwrap()).unwrap();
        let code = delivery["ConfirmationCode"].as_str().unwrap();
        assert_eq!(code.len(), 6);
        let login = json!({"ClientId":client,"AuthFlow":"USER_PASSWORD_AUTH","AuthParameters":{"USERNAME":"alice","PASSWORD":"SecurePass1!"}});
        assert!(matches!(
            handler.initiate_auth(&request, login.as_object().unwrap()),
            Err(CognitoError::UserNotConfirmed)
        ));
        let mut confirm = json!({"ClientId":client,"Username":"alice","ConfirmationCode":code});
        confirm["ClientId"] = other.into();
        assert!(handler
            .confirm_sign_up(&request, confirm.as_object().unwrap())
            .is_err());
        confirm["ClientId"] = client.clone().into();
        let mut foreign = request.clone();
        foreign.account_id = "111111111111".into();
        assert!(handler
            .confirm_sign_up(&foreign, confirm.as_object().unwrap())
            .is_err());
        confirm["ConfirmationCode"] = "0000000".into();
        assert!(matches!(
            handler.confirm_sign_up(&request, confirm.as_object().unwrap()),
            Err(CognitoError::CodeMismatch)
        ));
        confirm["ConfirmationCode"] = code.into();
        handler
            .confirm_sign_up(&request, confirm.as_object().unwrap())
            .unwrap();
        assert!(handler
            .confirm_sign_up(&request, confirm.as_object().unwrap())
            .is_err());
        let authenticated = handler
            .initiate_auth(&request, login.as_object().unwrap())
            .unwrap();
        use base64::Engine;
        let token = authenticated["AuthenticationResult"]["IdToken"]
            .as_str()
            .unwrap();
        let claims: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims["email_verified"], true);
        let mut signup = signup;
        signup["Username"] = "bob".into();
        handler
            .sign_up(&request, signup.as_object().unwrap())
            .unwrap();
        let cell = handler.pool(&request, id).unwrap();
        cell.lock()
            .unwrap()
            .users
            .get_mut("bob")
            .unwrap()
            .confirmation
            .as_mut()
            .unwrap()
            .expires = now().unwrap() - 1;
        confirm["Username"] = "bob".into();
        assert!(matches!(
            handler.confirm_sign_up(&request, confirm.as_object().unwrap()),
            Err(CognitoError::ExpiredCode)
        ));
        std::fs::remove_dir_all(&root).unwrap();
        signup["Username"] = "carol".into();
        assert!(matches!(
            handler.sign_up(&request, signup.as_object().unwrap()),
            Err(CognitoError::CodeDeliveryFailure)
        ));
        assert!(!cell.lock().unwrap().users.contains_key("carol"));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(crate::ConfirmationMailbox::new(root.clone()).is_err());
        std::fs::remove_dir(&root).unwrap();
        handler
            .delete_pool(&request, json!({"UserPoolId":id}).as_object().unwrap())
            .unwrap();
        assert!(matches!(
            CognitoHandler::sign_up_in_pool(&request, signup.as_object().unwrap(), cell, None),
            Err(CognitoError::ResourceNotFound)
        ));
    }
}
