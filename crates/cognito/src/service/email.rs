//! Confirmation delivery owns its reservation across asynchronous native SES dispatch.
use super::*;
use http::{HeaderMap, HeaderValue, Method};
use locallycloud_core::integration::{
    authorization::ServiceRoleAuthorizationRequest,
    identity::{CallerIdentity, IdentityPropagator},
    RequestIdentity,
};
use locallycloud_core::registry::ServiceRegistry;
use std::sync::Weak;

#[derive(Clone)]
pub(super) struct EmailSettings {
    from: String,
    source_arn: String,
    reply_to: Option<String>,
}
impl EmailSettings {
    pub fn parse(
        value: Option<&Value>,
        request: &ServiceRequest,
    ) -> Result<Option<Self>, CognitoError> {
        let Some(value) = value else { return Ok(None) };
        let value = value.as_object().ok_or(CognitoError::InvalidParameter)?;
        allowed(
            value,
            &[
                "EmailSendingAccount",
                "SourceArn",
                "From",
                "ReplyToEmailAddress",
            ],
        )?;
        if value.is_empty()
            || (value
                .get("EmailSendingAccount")
                .is_some_and(|v| v == "COGNITO_DEFAULT")
                && value.len() == 1)
        {
            return Ok(None);
        }
        if string(value, "EmailSendingAccount")? != "DEVELOPER" {
            return Err(CognitoError::Unsupported);
        }
        let source_arn = string(value, "SourceArn")?;
        let prefix = format!(
            "arn:aws:ses:{}:{}:identity/",
            request.region, request.account_id
        );
        let identity = source_arn
            .strip_prefix(&prefix)
            .filter(|s| !s.is_empty() && !s.contains(['/', ':']))
            .ok_or(CognitoError::InvalidParameter)?;
        let from = value
            .get("From")
            .map(|v| v.as_str().ok_or(CognitoError::InvalidParameter))
            .transpose()?
            .unwrap_or(identity);
        let address = from
            .rsplit_once('<')
            .map_or(from, |(_, tail)| tail.strip_suffix('>').unwrap_or(""));
        let (local, domain) = address
            .rsplit_once('@')
            .filter(|(a, b)| !a.is_empty() && !b.is_empty())
            .ok_or(CognitoError::InvalidParameter)?;
        if from.len() > 320
            || !from.is_ascii()
            || from.bytes().any(|b| b.is_ascii_control())
            || local.contains(['<', '>'])
            || (identity != address && !identity.eq_ignore_ascii_case(domain))
        {
            return Err(CognitoError::InvalidParameter);
        }
        let reply_to = value
            .get("ReplyToEmailAddress")
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or(CognitoError::InvalidParameter)
            })
            .transpose()?;
        if reply_to.as_ref().is_some_and(|s| {
            s.len() > 320
                || !s.is_ascii()
                || !s.contains('@')
                || s.bytes().any(|b| b.is_ascii_control())
        }) {
            return Err(CognitoError::InvalidParameter);
        }
        Ok(Some(Self {
            from: from.into(),
            source_arn: source_arn.into(),
            reply_to,
        }))
    }
    pub fn output(&self) -> Value {
        let mut value =
            json!({"EmailSendingAccount":"DEVELOPER","SourceArn":self.source_arn,"From":self.from});
        if let Some(reply) = &self.reply_to {
            value["ReplyToEmailAddress"] = json!(reply);
        }
        value
    }
    pub fn message(&self, recipient: &str, code: &str) -> Value {
        let mut value = json!({"FromEmailAddress":self.from,"Destination":{"ToAddresses":[recipient]},"Content":{"Simple":{"Subject":{"Data":"Your verification code"},"Body":{"Text":{"Data":format!("Your verification code is {code}. For your security, do not share this code.")}}}}});
        if let Some(reply) = &self.reply_to {
            value["ReplyToAddresses"] = json!([reply]);
        }
        value
    }
}

pub(super) enum Delivery {
    None,
    Mailbox {
        mailbox: Arc<crate::ConfirmationMailbox>,
        message: Value,
    },
    Ses {
        settings: EmailSettings,
        source: String,
        account: String,
        region: String,
        payload: Value,
    },
}
pub(super) struct PreparedSignup {
    pub cell: Arc<Mutex<Pool>>,
    pub username: String,
    pub client_id: String,
    pub user: Option<User>,
    pub result: Value,
    pub delivery: Delivery,
}
impl PreparedSignup {
    #[cfg(test)]
    pub fn deliver_local(&self) -> Result<(), CognitoError> {
        match &self.delivery {
            Delivery::None => Ok(()),
            Delivery::Mailbox { mailbox, message } => mailbox.deliver(message),
            Delivery::Ses { .. } => Err(CognitoError::CodeDeliveryFailure),
        }
    }
    pub async fn deliver(&self, registry: Weak<ServiceRegistry>) -> Result<(), CognitoError> {
        match &self.delivery {
            Delivery::None => Ok(()),
            Delivery::Mailbox { mailbox, message } => {
                let mailbox = mailbox.clone();
                let message = message.clone();
                tokio::task::spawn_blocking(move || mailbox.deliver(&message))
                    .await
                    .map_err(|_| CognitoError::Internal)?
            }
            Delivery::Ses {
                settings,
                source,
                account,
                region,
                payload,
            } => {
                let registry = registry
                    .upgrade()
                    .ok_or(CognitoError::CodeDeliveryFailure)?;
                let dispatcher = registry
                    .internal_dispatcher()
                    .ok_or(CognitoError::CodeDeliveryFailure)?;
                let role=format!("arn:aws:iam::{account}:role/aws-service-role/email.cognito-idp.amazonaws.com/AWSServiceRoleForAmazonCognitoIdpEmail");
                if dispatcher.strict_sigv4_required() {
                    let evaluator = registry
                        .authorization_evaluator(&locallycloud_core::registry::ServiceName::new(
                            "iam",
                        ))
                        .ok_or(CognitoError::CodeDeliveryFailure)?;
                    evaluator
                        .authorize_service_role_trust(ServiceRoleAuthorizationRequest {
                            delegated_caller: None,
                            caller_context: Default::default(),
                            source_arn: Some(source.clone()),
                            caller: RequestIdentity {
                                account_id: account.clone(),
                                access_key_id: None,
                                arn: None,
                            },
                            role_arn: role.clone(),
                            service_principal: "email.cognito-idp.amazonaws.com".into(),
                            action: "ses:SendEmail".into(),
                            resource: settings.source_arn.clone(),
                        })
                        .map_err(|_| CognitoError::CodeDeliveryFailure)?;
                }
                let mut headers = HeaderMap::new();
                headers.insert("content-type", HeaderValue::from_static("application/json"));
                headers.insert("authorization",HeaderValue::from_str(&format!("AWS4-HMAC-SHA256 Credential=locallycloud/19700101/{region}/ses/aws4_request")).map_err(|_|CognitoError::InvalidParameter)?);
                IdentityPropagator::attach(
                    &mut headers,
                    &CallerIdentity::AssumedRole {
                        role_arn: role,
                        session_name: "cognito-email".into(),
                    },
                );
                headers.insert(
                    "x-locallycloud-source-arn",
                    HeaderValue::from_str(source).map_err(|_| CognitoError::InvalidParameter)?,
                );
                headers.insert(
                    "x-locallycloud-source-account",
                    HeaderValue::from_str(account).map_err(|_| CognitoError::InvalidParameter)?,
                );
                let response = dispatcher
                    .dispatch_scoped(
                        &Method::POST,
                        &"/v2/email/outbound-emails"
                            .parse()
                            .map_err(|_| CognitoError::Internal)?,
                        &headers,
                        axum::body::Bytes::from(payload.to_string()),
                        &Uuid::new_v4().to_string(),
                        account,
                        region,
                    )
                    .await;
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(CognitoError::CodeDeliveryFailure)
                }
            }
        }
    }
    pub fn finish(mut self) -> Result<Value, CognitoError> {
        let mut pool = self.cell.lock().map_err(|_| CognitoError::Internal)?;
        if pool.deleted || !pool.clients.contains_key(&self.client_id) {
            return Err(CognitoError::ResourceNotFound);
        }
        if pool.users.contains_key(&self.username) {
            return Err(CognitoError::UsernameExists);
        }
        let user = self.user.take().ok_or(CognitoError::Internal)?;
        pool.users.insert(self.username.clone(), user);
        pool.pending_signups.remove(&self.username);
        Ok(self.result.clone())
    }
}
impl Drop for PreparedSignup {
    fn drop(&mut self) {
        if self.user.is_none() {
            return;
        }
        if let Ok(mut pool) = self.cell.lock() {
            pool.pending_signups.remove(&self.username);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn failed_ses_delivery_releases_username_and_never_publishes_user() {
        let handler = CognitoHandler::new();
        let request = ServiceRequest {
            method: Method::POST,
            uri: "/".parse().unwrap(),
            headers: Default::default(),
            body: Default::default(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "email-test".into(),
        };
        let configuration = json!({"EmailSendingAccount":"DEVELOPER","SourceArn":"arn:aws:ses:us-east-1:000000000000:identity/example.com","From":"sender@example.com"});
        let pool=handler.create_pool(&request,json!({"PoolName":"ses","AutoVerifiedAttributes":["email"],"EmailConfiguration":configuration}).as_object().unwrap()).await.unwrap();
        let id = pool["UserPool"]["Id"].as_str().unwrap();
        assert_eq!(pool["UserPool"]["EmailConfiguration"], configuration);
        let client = handler
            .create_client(
                &request,
                json!({"UserPoolId":id,"ClientName":"web"})
                    .as_object()
                    .unwrap(),
            )
            .unwrap();
        let input = json!({"ClientId":client["UserPoolClient"]["ClientId"],"Username":"alice","Password":"SecurePass1!","UserAttributes":[{"Name":"email","Value":"alice@example.net"}]});
        for _ in 0..2 {
            assert!(matches!(
                handler
                    .sign_up_async(&request, input.as_object().unwrap())
                    .await,
                Err(CognitoError::CodeDeliveryFailure)
            ));
            let cell = handler.pool(&request, id).unwrap();
            let pool = cell.lock().unwrap();
            assert!(pool.users.is_empty());
            assert!(pool.pending_signups.is_empty());
        }
        assert!(EmailSettings::parse(Some(&json!({"EmailSendingAccount":"DEVELOPER","SourceArn":"arn:aws:ses:us-east-1:111111111111:identity/example.com","From":"sender@example.com"})),&request).is_err());
    }
}
