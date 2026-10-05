use super::*;

impl LambdaHandler {
    pub(super) async fn route_durable(
        &self,
        req: &ServiceRequest,
    ) -> Result<(u16, Option<Value>), LambdaError> {
        let persistence = self.persistence.lock().unwrap().clone();
        let Some(persistence) = persistence else {
            return self.route(req).await;
        };
        let Some(target) = metadata_target(req)? else {
            return self.route(req).await;
        };
        // ponytail: serialize control-plane changes; per-function gates if metadata throughput warrants it.
        let guard = self.metadata_gate.clone().lock_owned().await;
        let (account, region) = (&req.account_id, &req.region);
        let name = target.name().to_string();
        // Deletion commits under Executor's existing admission/cleanup guard.
        if target.is_function()
            && req.method == Method::DELETE
            && req.uri.path().trim_matches('/').split('/').count() == 3
        {
            let response = self.route(req).await?;
            self.concurrency
                .clear_reserved(&function_arn(region, account, &name));
            return Ok(response);
        }
        let mut staged = LambdaHandler::with_parts(self.registry.clone(), None);
        staged.executor = self.executor.clone();
        *staged.ec2.lock().unwrap() = self.ec2.lock().unwrap().clone();
        if target.is_function() {
            staged.store = Arc::new(self.store.stage_one(account, region, &name));
            staged.layers = self.layers.clone();
        } else {
            staged.store = self.store.clone();
            staged.layers = Arc::new(self.layers.stage_one(account, region, &name));
        }
        let response = staged.route(req).await?;
        let original_store = self.store.clone();
        let original_layers = self.layers.clone();
        let concurrency = self.concurrency.clone();
        let account = account.clone();
        let region = region.clone();
        let committed_name = name.clone();
        let is_function = target.is_function();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            if is_function {
                persistence.commit_function(
                    &original_store,
                    &staged.store,
                    &account,
                    &region,
                    &committed_name,
                )?;
                let arn = function_arn(&region, &account, &committed_name);
                match original_store.get_reserved_concurrency(&account, &region, &committed_name) {
                    Some(Some(value)) => concurrency.set_reserved(&arn, value),
                    _ => concurrency.clear_reserved(&arn),
                }
            } else {
                persistence.commit_layer(
                    &original_layers,
                    &staged.layers,
                    &account,
                    &region,
                    &committed_name,
                )?;
            }
            Ok::<_, LambdaError>(())
        })
        .await
        .map_err(|_| crate::persistence::state_error("Lambda commit worker failed"))??;
        if target.is_function() {
            let arn = function_arn(&req.region, &req.account_id, &name);
            for mapping in self.esm.list(Some(&arn), None) {
                self.reconcile_esm(&req.account_id, &req.region, &mapping);
            }
        }
        Ok(response)
    }
}

enum MetadataTarget {
    Function(String),
    Layer(String),
}
impl MetadataTarget {
    fn name(&self) -> &str {
        match self {
            Self::Function(name) | Self::Layer(name) => name,
        }
    }
    fn is_function(&self) -> bool {
        matches!(self, Self::Function(_))
    }
}
fn metadata_target(req: &ServiceRequest) -> Result<Option<MetadataTarget>, LambdaError> {
    if req.method == Method::GET || req.method == Method::HEAD {
        return Ok(None);
    }
    let segments = req
        .uri
        .path()
        .trim_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    match segments.as_slice() {
        ["2015-03-31", "functions"] if req.method == Method::POST => {
            let input = parse_json(&req.body)?;
            let name = require_nonempty_string(&input, "FunctionName")?;
            Ok(Some(MetadataTarget::Function(resolve_function_name(
                name,
                &req.region,
            )?)))
        }
        [_, "functions", name, ..] => Ok(Some(MetadataTarget::Function(resolve_function_name(
            name,
            &req.region,
        )?))),
        ["2017-03-31", "tags", arn] => Ok(Some(MetadataTarget::Function(resolve_function_name(
            arn,
            &req.region,
        )?))),
        ["2018-10-31", "layers", name, ..] => Ok(Some(MetadataTarget::Layer((*name).into()))),
        _ => Ok(None),
    }
}
