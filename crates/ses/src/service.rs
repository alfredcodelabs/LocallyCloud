use crate::{
    config::{Provider, SesConfig, SesCredentials},
    error::Error,
    model::{Identity, MAX_BODY},
    protocol::{self, Operation},
    provider::{Delivery, Outcome},
    store::Store,
};
use async_trait::async_trait;
use axum::{body::Body, response::Response};
use locallycloud_core::{
    handler::{NativeHandler, ServiceRequest},
    registry::{ServiceName, ServiceRegistry},
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Weak,
};

pub(crate) struct Service(pub Arc<Handler>);

pub(crate) struct Handler {
    pub store: Arc<Store>,
    pub config: SesConfig,
    pub delivery: Delivery,
    registry: Weak<ServiceRegistry>,
    running: AtomicBool,
}
impl Handler {
    pub fn new(
        store: Arc<Store>,
        config: SesConfig,
        credentials: SesCredentials,
        registry: Weak<ServiceRegistry>,
        listeners: &[std::net::SocketAddr],
    ) -> Result<Arc<Self>, String> {
        config.validate()?;
        let delivery = Delivery::new(&config, credentials, listeners)?;
        Ok(Arc::new(Self {
            store,
            config,
            delivery,
            registry,
            running: AtomicBool::new(false),
        }))
    }
    pub fn start(self: &Arc<Self>) {
        if !Delivery::enabled(&self.config)
            || self
                .running
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        let handler = self.clone();
        tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..handler.config.max_concurrency {
                let handler = handler.clone();
                tasks.spawn(async move { handler.work().await });
            }
            while let Some(result) = tasks.join_next().await {
                if result.is_err() {
                    tracing::error!(
                        service = "ses",
                        cause_code = "delivery_worker_failed",
                        "SES delivery worker failed"
                    );
                }
            }
            handler.running.store(false, Ordering::Release);
            // Close the accept/idle race after releasing ownership of this worker group.
            if handler
                .store
                .run(|s| s.has_pending())
                .await
                .unwrap_or(false)
            {
                handler.start();
            }
        });
    }
    async fn work(self: Arc<Self>) {
        loop {
            let binding = self.delivery.binding.clone();
            let timeout = self.config.request_timeout_secs;
            let job = self.store.run(move |s| s.claim(&binding, timeout)).await;
            match job {
                Ok(Some(job)) => {
                    let outcome = self.delivery.send(&job).await;
                    if let Outcome::Failed(cause) = &outcome {
                        tracing::warn!(service="ses",operation="SendEmail",message_id=%job.id,cause_code=*cause,"SES provider delivery rejected");
                    }
                    let id = job.id.clone();
                    let result = self
                        .store
                        .run(move |s| match outcome {
                            Outcome::Accepted(remote) => {
                                s.outcome(&id, "provider_accepted", Some(&remote), "", 0)
                            }
                            Outcome::Retry(delay) => {
                                s.outcome(&id, "queued", None, "retryable_provider_failure", delay)
                            }
                            Outcome::Failed(cause) => s.outcome(&id, "failed", None, cause, 0),
                        })
                        .await;
                    if result.is_err() {
                        tracing::error!(
                            service = "ses",
                            cause_code = "delivery_state_failed",
                            "SES delivery result could not be persisted"
                        );
                    }
                }
                Ok(None) => match self.store.run(|s| s.has_pending()).await {
                    Ok(false) => return,
                    Ok(true) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
                    Err(_) => {
                        tracing::error!(
                            service = "ses",
                            cause_code = "state_unavailable",
                            "SES delivery state unavailable"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                },
                Err(_) => {
                    tracing::error!(
                        service = "ses",
                        cause_code = "state_unavailable",
                        "SES delivery state unavailable"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }
    fn authorize(
        &self,
        request: &ServiceRequest,
        action: &str,
        resource: &str,
        operation: &Operation,
    ) -> Result<(), Error> {
        use locallycloud_core::integration::authorization::{
            verified_caller, AuthorizationRequest,
        };
        let evaluator = self
            .registry
            .upgrade()
            .and_then(|r| r.authorization_evaluator(&ServiceName::new("iam")));
        let Some(evaluator) = evaluator else {
            return Ok(());
        };
        if !evaluator.strict_sigv4_required() {
            return Ok(());
        }
        let (request_identity, delegated_identity) =
            verified_caller(evaluator.as_ref(), request).map_err(|_| Error::AccessDenied)?;
        let mut context =
            locallycloud_core::integration::request_context::verified_request_context(request);
        context.insert(
            "aws:resourceaccount".into(),
            vec![request.account_id.clone()],
        );
        if let Operation::Send(mail) = operation {
            context.insert("ses:fromaddress".into(), vec![mail.sender.clone()]);
            context.insert(
                "ses:recipients".into(),
                mail.to
                    .iter()
                    .chain(&mail.cc)
                    .chain(&mail.bcc)
                    .cloned()
                    .collect(),
            );
        }
        if let Operation::Create { tags, .. } = operation {
            let keys = tags
                .iter()
                .filter_map(|tag| tag["Key"].as_str().map(str::to_owned))
                .collect();
            context.insert("aws:tagkeys".into(), keys);
            for tag in tags {
                if let (Some(key), Some(value)) = (tag["Key"].as_str(), tag["Value"].as_str()) {
                    context.insert(
                        format!("aws:requesttag/{}", key.to_ascii_lowercase()),
                        vec![value.into()],
                    );
                }
            }
        }
        evaluator
            .authorize(AuthorizationRequest {
                request_identity,
                delegated_identity,
                source_service: "ses".into(),
                action: format!("ses:{action}"),
                resource: resource.into(),
                context,
            })
            .map_err(|_| Error::AccessDenied)
    }
    async fn execute(
        self: &Arc<Self>,
        request: &ServiceRequest,
        mut call: protocol::Call,
    ) -> Result<Value, Error> {
        match &mut call.operation {
            Operation::Create { name, tags, .. } => *name = Identity::new(name, tags.clone())?.name,
            Operation::Get(name) | Operation::Delete(name) => {
                *name = Identity::new(name, Vec::new())?.name
            }
            Operation::List { .. } | Operation::Send(_) => {}
        }
        let verified_identity = if let Operation::Send(mail) = &call.operation {
            let account = request.account_id.clone();
            let region = request.region.clone();
            let sender = mail.sender.clone();
            self.store
                .run(move |s| s.sender_identity(&account, &region, &sender))
                .await?
        } else {
            None
        };
        let target = match &call.operation {
            Operation::Create { name, .. } | Operation::Get(name) | Operation::Delete(name) => {
                Some(name.as_str())
            }
            Operation::Send(mail) => Some(verified_identity.as_deref().unwrap_or(&mail.sender)),
            Operation::List { .. } => None,
        };
        let resource = target
            .map(|name| {
                format!(
                    "arn:aws:ses:{}:{}:identity/{name}",
                    request.region, request.account_id
                )
            })
            .unwrap_or_else(|| "*".into());
        self.authorize(request, &call.action, &resource, &call.operation)?;
        if matches!(&call.operation,Operation::Create {tags,..} if !tags.is_empty()) {
            self.authorize(request, "TagResource", &resource, &call.operation)?;
        }
        let account = request.account_id.clone();
        let region = request.region.clone();
        match call.operation {
            Operation::Create {name,tags,idempotent}=>{
                let mut identity=Identity::new(&name,tags)?;
                identity.verified=self.config.auto_verify_identities;
                if identity.kind=="DOMAIN" {identity.dkim_tokens=(0..3).map(|_|uuid::Uuid::new_v4().simple().to_string()).collect();}
                self.store.run(move|s|{s.create(&account,&region,&identity,idempotent)?;Ok(identity.created_output())}).await
            }
            Operation::Get(name)=>self.store.run(move|s|Ok(s.identity(&account,&region,&name)?.output())).await,
            Operation::Delete(name)=>self.store.run(move|s|{s.delete(&account,&region,&name,call.protocol == protocol::WireProtocol::Query)?;Ok(json!({}))}).await,
            Operation::List {after,limit,kind}=>{
                self.store.run(move|s| {
                    let after=s.decode_cursor(&account,&region,&call.action,kind.as_deref(),&after)?;
                    let mut rows=s.list(&account,&region,&after,limit+1,kind.as_deref())?;
                    let more=rows.len()>limit;rows.truncate(limit);
                    let token=if more {rows.last().map(|r|s.encode_cursor(&account,&region,&call.action,kind.as_deref(),&r.name)).transpose()?}else{None};
                    let identities:Vec<_>=rows.into_iter().map(|r| {
                        let status=if r.verified {"SUCCESS"}else{"PENDING"};
                        json!({"IdentityName":r.name,"IdentityType":r.kind,"SendingEnabled":r.verified,"VerificationStatus":status})
                    }).collect();
                    let mut value=json!({"EmailIdentities":identities});
                    if let Some(token)=token {value["NextToken"]=json!(token);}
                    Ok(value)
                }).await
            }
            Operation::Send(mail)=>{
                let identity_name=verified_identity.ok_or(Error::Rejected("Email address is not verified in this account and region"))?;
                let config=self.config.clone();let binding=self.delivery.binding.clone();
                let handler=self.clone();
                // Notification belongs to the owned commit: cancelling the HTTP future cannot strand a job.
                self.store.run(move|s| {
                    let id=s.accept(&account,&region,mail,&config,&binding,&identity_name)?;
                    if config.provider==Provider::Resend {
                        handler.start();
                    }
                    Ok(json!({"MessageId":id}))
                }).await
            }
        }
    }
}
#[async_trait]
impl NativeHandler for Service {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let wire = protocol::WireProtocol::for_request(&request);
        if request.body.len() > MAX_BODY {
            return Error::BadRequest("The local SES request body limit is 10 MiB")
                .response(&request.request_id, wire);
        }
        let call = match protocol::decode(&request) {
            Ok(call) => call,
            Err(error) => return error.response(&request.request_id, wire),
        };
        let action = call.action.clone();
        match self.0.execute(&request, call).await {
            Ok(value) => {
                if wire == protocol::WireProtocol::Query {
                    Response::builder()
                        .header("content-type", "text/xml")
                        .header("x-amzn-RequestId", &request.request_id)
                        .body(Body::from(protocol::query_result(
                            &action,
                            &value,
                            &request.request_id,
                        )))
                        .unwrap_or_else(|_| Response::new(Body::empty()))
                } else {
                    Response::builder()
                        .header("content-type", "application/json")
                        .header("x-amzn-RequestId", &request.request_id)
                        .body(Body::from(value.to_string()))
                        .unwrap_or_else(|_| Response::new(Body::empty()))
                }
            }
            Err(error) => error.response(&request.request_id, wire),
        }
    }
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        let account = account.to_owned();
        self.0
            .store
            .run(move |s| s.regions(&account))
            .await
            .map_err(|_| "SES state unavailable")
    }
}

#[cfg(test)]
impl Handler {
    pub(crate) fn with_delivery(
        store: Arc<Store>,
        config: SesConfig,
        delivery: Delivery,
        registry: Weak<ServiceRegistry>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            config,
            delivery,
            registry,
            running: AtomicBool::new(false),
        })
    }
}
