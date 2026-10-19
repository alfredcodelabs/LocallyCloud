//! Explicit recovery of configured stopped instances; never restore live runtime handles.
use super::*;

fn state_change(id: &str, previous: InstanceState, current: InstanceState) -> String {
    format!("<instancesSet><item><instanceId>{}</instanceId><currentState><code>{}</code><name>{}</name></currentState><previousState><code>{}</code><name>{}</name></previousState></item></instancesSet>", escape(id),instance_state_code(current),instance_state(current),instance_state_code(previous),instance_state(previous))
}

impl Ec2Handler {
    pub(super) async fn start_instances(
        &self,
        request: &ServiceRequest,
        input: &Input,
    ) -> Result<String, Ec2Error> {
        for field in input.fields.keys() {
            if !["Action", "Version", "DryRun"].contains(&field.as_str())
                && indexed_key(field, "InstanceId").is_none()
            {
                return Err(Ec2Error::unsupported(field));
            }
        }
        let ids = input.indexed("InstanceId")?;
        let id = match ids.as_slice() {
            [] => return Err(Ec2Error::new("MissingParameter", "InstanceId is required")),
            [id] => id.clone(),
            _ => {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Only one instance per StartInstances request is supported",
                ))
            }
        };
        input.dry_run()?;
        let handler = self.clone();
        let key = (request.account_id.clone(), request.region.clone());
        // The operation owns its completion even when the HTTP client disconnects.
        tokio::spawn(async move {
            let _permit = handler
                .instance_operations
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| {
                    Ec2Error::new("InternalError", "EC2 instance operations unavailable")
                })?;
            handler.resume_instance(key, id).await
        })
        .await
        .map_err(|_| Ec2Error::new("InternalError", "EC2 instance start worker unavailable"))?
    }

    async fn resume_instance(&self, key: (String, String), id: String) -> Result<String, Ec2Error> {
        let runtime = self.runtime.clone().ok_or_else(|| {
            Ec2Error::new("UnsupportedOperation", "Instance runtime is not configured")
        })?;
        let handler = self.clone();
        let operation_key = key.clone();
        let operation_id = id.clone();
        let previous = tokio::task::spawn_blocking(move || {
            let mut states = handler
                .scopes
                .lock()
                .map_err(|_| Ec2Error::new("InternalError", "EC2 instance state unavailable"))?;
            let scope = states.get_mut(&operation_key).ok_or_else(|| {
                Ec2Error::new("InvalidInstanceID.NotFound", "The instance does not exist")
            })?;
            let old = scope.instances.get(&operation_id).cloned().ok_or_else(|| {
                Ec2Error::new("InvalidInstanceID.NotFound", "The instance does not exist")
            })?;
            match old.state {
                InstanceState::Running => return Ok((old, false)),
                InstanceState::Stopped => {}
                _ => {
                    return Err(Ec2Error::new(
                        "IncorrectInstanceState",
                        "The instance is not in a state from which it can be started",
                    ))
                }
            }
            if !scope
                .network_interfaces
                .get(&old.eni_id)
                .is_some_and(|eni| {
                    eni.vpc_id == old.spec.vpc_id
                        && eni.subnet_id == old.spec.subnet_id
                        && eni.private_ip == old.spec.private_ip
                        && eni.group_ids == old.spec.security_group_ids
                })
            {
                return Err(Ec2Error::new(
                    "IncorrectInstanceState",
                    "The instance network configuration is unavailable",
                ));
            }
            let mut proposed = old.clone();
            proposed.state = InstanceState::Pending;
            proposed.endpoint = None;
            handler.persist(
                &operation_key,
                &[Change::put("instance", &operation_id, &proposed)?],
            )?;
            scope.instances.insert(operation_id, proposed);
            Ok::<_, Ec2Error>((old, true))
        })
        .await
        .map_err(|_| {
            Ec2Error::new(
                "InternalError",
                "EC2 instance preparation worker unavailable",
            )
        })??;
        let (old, launch) = previous;
        if !launch {
            return Ok(state_change(&id, old.state, old.state));
        }
        let result = async {
            runtime
                .start_instance(&old.spec)
                .await
                .map_err(|_| Ec2Error::new("InternalError", "Instance runtime failed to start"))?;
            if !probe_instance(runtime.as_ref(), &old.spec).await {
                return Err(Ec2Error::new(
                    "InternalError",
                    "Instance runtime failed to start a healthy HTTP service",
                ));
            }
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|_| Ec2Error::new("InternalError", "Could not bind instance proxy"))?;
            let endpoint = listener
                .local_addr()
                .map_err(|_| Ec2Error::new("InternalError", "Could not inspect instance proxy"))?;
            let handler = self.clone();
            let operation_key = key.clone();
            let mut proposed = old.clone();
            proposed.state = InstanceState::Running;
            proposed.endpoint = Some(endpoint);
            tokio::task::spawn_blocking(move || {
                let mut states = handler.scopes.lock().map_err(|_| {
                    Ec2Error::new("InternalError", "EC2 instance state unavailable")
                })?;
                let scope = states.get_mut(&operation_key).ok_or_else(|| {
                    Ec2Error::new("InternalError", "EC2 instance ownership changed")
                })?;
                if !scope
                    .instances
                    .get(&proposed.spec.instance_id)
                    .is_some_and(|instance| {
                        instance.state == InstanceState::Pending
                            && instance.eni_id == proposed.eni_id
                    })
                {
                    return Err(Ec2Error::new(
                        "IncorrectInstanceState",
                        "Instance ownership changed during start",
                    ));
                }
                handler.persist(
                    &operation_key,
                    &[Change::put(
                        "instance",
                        &proposed.spec.instance_id,
                        &proposed,
                    )?],
                )?;
                scope
                    .instances
                    .insert(proposed.spec.instance_id.clone(), proposed);
                Ok::<_, Ec2Error>(())
            })
            .await
            .map_err(|_| {
                Ec2Error::new(
                    "InternalError",
                    "EC2 instance persistence worker unavailable",
                )
            })??;
            let handler = self.clone();
            let proxy_key = key.clone();
            let spec = old.spec.clone();
            let runtime = runtime.clone();
            tokio::spawn(async move {
                serve_instance_proxy(listener, handler, proxy_key, spec, runtime).await;
            });
            Ok(state_change(
                &id,
                InstanceState::Stopped,
                InstanceState::Running,
            ))
        }
        .await;
        if result.is_err() {
            let stopped = runtime.stop_instance(&id).await.is_ok();
            let handler = self.clone();
            let operation_key = key.clone();
            let mut fallback = old;
            fallback.endpoint = None;
            fallback.state = if stopped {
                InstanceState::Stopped
            } else {
                InstanceState::ShuttingDown
            };
            let restored = tokio::task::spawn_blocking(move || {
                let mut states = handler
                    .scopes
                    .lock()
                    .map_err(|_| Ec2Error::new("InternalError", "EC2 rollback unavailable"))?;
                let scope = states.get_mut(&operation_key).ok_or_else(|| {
                    Ec2Error::new("InternalError", "EC2 rollback ownership changed")
                })?;
                let persisted = handler.persist(
                    &operation_key,
                    &[Change::put(
                        "instance",
                        &fallback.spec.instance_id,
                        &fallback,
                    )?],
                );
                // Failed pending/running commits restore as stopped on restart. Do not
                // expose a live endpoint or discard ownership when cleanup needs retry.
                scope
                    .instances
                    .insert(fallback.spec.instance_id.clone(), fallback);
                persisted
            })
            .await;
            if !stopped || !matches!(restored, Ok(Ok(()))) {
                return Err(Ec2Error::new(
                    "InternalError",
                    "Instance start failed; runtime or persistence cleanup remains pending",
                ));
            }
        }
        result
    }
}
