use super::*;

#[derive(Clone)]
pub(super) struct EsmController {
    pub(super) esm: Arc<EsmStore>,
    store: Arc<FunctionStore>,
    registry: Weak<ServiceRegistry>,
    executor_available: bool,
    sqs_esm_max_pollers: u32,
    esm_workers: Arc<Mutex<Option<HashMap<String, EsmWorker>>>>,
    gate: Arc<tokio::sync::Mutex<()>>,
}

impl LambdaHandler {
    pub(super) fn esm_controller(&self) -> EsmController {
        EsmController {
            esm: self.esm.clone(),
            store: self.store.clone(),
            registry: self.registry.clone(),
            executor_available: self.executor.is_some(),
            sqs_esm_max_pollers: self.sqs_esm_max_pollers,
            esm_workers: self.esm_workers.clone(),
            gate: self.esm_gate.clone(),
        }
    }

    pub(super) async fn write_esm<T: Send + 'static>(
        &self,
        write: impl FnOnce(EsmController) -> Result<T, LambdaError> + Send + 'static,
    ) -> Result<T, LambdaError> {
        let controller = self.esm_controller();
        let guard = self.esm_gate.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            write(controller)
        })
        .await
        .map_err(|_| LambdaError::InternalError("Event source state worker failed".into()))?
    }

    pub(super) async fn reconcile_esm(
        &self,
        account: &str,
        region: &str,
        mapping: &crate::esm::EventSourceMapping,
    ) -> Result<(), LambdaError> {
        let account = account.to_owned();
        let region = region.to_owned();
        let mapping = mapping.clone();
        self.write_esm(move |controller| controller.reconcile(&account, &region, &mapping))
            .await
    }
}

impl EsmController {
    pub(super) fn write<T>(
        self,
        write: impl FnOnce(Self) -> Result<T, LambdaError>,
    ) -> Result<T, LambdaError> {
        let gate = self.gate.clone();
        let _guard = gate.blocking_lock();
        write(self)
    }

    // Commit and reconciliation share the blocking lifecycle gate; worker locks never cover I/O.
    pub(super) fn reconcile(
        &self,
        account: &str,
        region: &str,
        mapping: &crate::esm::EventSourceMapping,
    ) -> Result<(), LambdaError> {
        let Some(mapping) = self.esm.get(&mapping.uuid) else {
            self.abort(&mapping.uuid);
            return Ok(());
        };
        {
            let Ok(mut slot) = self.esm_workers.lock() else {
                return Ok(());
            };
            let Some(workers) = slot.as_mut() else {
                return Ok(());
            };
            if let Some(cancel) = workers
                .get_mut(&mapping.uuid)
                .and_then(|worker| worker.cancel.take())
            {
                let _ = cancel.send(());
            }
        }
        if !mapping.enabled {
            return Ok(());
        }
        if !self.executor_available {
            self.esm.update(&mapping.uuid, |mapping| {
                mapping.state = "Disabled".into();
                mapping.last_processing_result = Some("ComputeUnavailable".into());
            })?;
            return Ok(());
        }
        let name = mapping
            .function_arn
            .split(":function:")
            .nth(1)
            .and_then(|name| name.split(':').next());
        if name.is_none_or(|name| self.store.get(account, region, name).is_none()) {
            self.esm.update(&mapping.uuid, |mapping| {
                mapping.state = "Disabled".into();
                mapping.last_processing_result = Some("FunctionUnavailable".into());
            })?;
            return Ok(());
        }
        let source: Arc<dyn BatchSource> = match SourceType::from_arn(&mapping.event_source_arn) {
            Some(SourceType::DynamoDbStreams) => match DynamoDbBatchSource::new(
                self.registry.clone(),
                self.esm.clone(),
                self.store.clone(),
                mapping.clone(),
                account,
                region,
            ) {
                Ok(source) => Arc::new(source),
                Err(_) => {
                    tracing::warn!(
                        service = "lambda",
                        cause_code = "event_source_mapping_start_failed",
                        "could not start event source mapping"
                    );
                    return Ok(());
                }
            },
            Some(SourceType::Sqs) => match SqsBatchSource::new(
                self.registry.clone(),
                self.store.clone(),
                &mapping.function_arn,
                &mapping.event_source_arn,
                account,
                region,
            ) {
                Ok(source) => Arc::new(source),
                Err(_) => {
                    tracing::warn!(
                        service = "lambda",
                        cause_code = "event_source_mapping_start_failed",
                        "could not start event source mapping"
                    );
                    return Ok(());
                }
            },
            Some(SourceType::Kinesis) => match KinesisBatchSource::new(
                self.registry.clone(),
                self.esm.clone(),
                self.store.clone(),
                mapping.clone(),
                account,
                region,
            ) {
                Ok(source) => Arc::new(source),
                Err(_) => {
                    tracing::warn!(
                        service = "lambda",
                        cause_code = "event_source_mapping_start_failed",
                        "could not start event source mapping"
                    );
                    return Ok(());
                }
            },
            _ => return Ok(()),
        };
        self.esm.update(&mapping.uuid, |mapping| {
            mapping.state = "Enabled".into();
            mapping.last_processing_result = None;
        })?;
        let store = self.esm.clone();
        let registry = self.registry.clone();
        let uuid = mapping.uuid.clone();
        let worker_uuid = uuid.clone();
        let account = account.to_string();
        let region = region.to_string();
        let functions = self.store.clone();
        let worker_count = match SourceType::from_arn(&mapping.event_source_arn) {
            Some(SourceType::Sqs) => mapping
                .maximum_concurrency
                .unwrap_or(self.sqs_esm_max_pollers)
                .min(self.sqs_esm_max_pollers),
            _ => 1,
        };
        let (cancel, cancelled) = tokio::sync::oneshot::channel();
        let Ok(mut slot) = self.esm_workers.lock() else {
            return Ok(());
        };
        let Some(workers) = slot.as_mut() else {
            return Ok(());
        };
        let mut previous = workers.remove(&uuid);
        if let Some(cancel) = previous.as_mut().and_then(|worker| worker.cancel.take()) {
            let _ = cancel.send(());
        }
        let polling = (SourceType::from_arn(&mapping.event_source_arn) == Some(SourceType::Sqs))
            .then(|| {
                crate::esm::PollingControl::new(worker_count, mapping.maximum_concurrency.is_some())
            });
        let worker = tokio::spawn(async move {
            if let Some(previous) = previous {
                let _ = previous.handle.await;
            }
            run_workers(worker_count, cancelled, || {
                let store = store.clone();
                let registry = registry.clone();
                let worker_uuid = worker_uuid.clone();
                let account = account.clone();
                let region = region.clone();
                let functions = functions.clone();
                let source = source.clone();
                let polling = polling.clone();
                async move {
            while let Some(current) = store.get(&worker_uuid).filter(|item| item.enabled) {
                let _permit = match &polling { Some(control) => Some(control.acquire().await), None => None };
                let function_name = current
                    .function_arn
                    .split(":function:")
                    .nth(1)
                    .unwrap_or("")
                    .split(':')
                    .next()
                    .unwrap_or("");
                if functions.get(&account, &region, function_name).is_none() {
                    let state = store.clone();
                    let id = worker_uuid.clone();
                    let persisted = tokio::task::spawn_blocking(move || state.update(&id, |mapping| {
                        mapping.state = "Disabled".into();
                        mapping.last_processing_result = Some("FunctionUnavailable".into());
                    })).await;
                    if !matches!(persisted, Ok(Ok(_))) {
                        tracing::warn!(service = "lambda", cause_code = "event_source_state_write_failed", "could not persist event source state");
                    }
                    break;
                }
                let result = crate::esm::poll_once_typed(&current, &source, |event| {
                    let registry = registry.clone();
                    let account = account.clone();
                    let region = region.clone();
                    let function_name = current.function_arn.clone();
                    async move {
                        let registry = registry.upgrade().ok_or(crate::esm::PollError::Invocation(LambdaInternalError::Unavailable))?;
                        let lambda = registry.lambda_api(&ServiceName::new("lambda")).ok_or(crate::esm::PollError::Invocation(LambdaInternalError::Unavailable))?;
                        let payload = serde_json::to_vec(&event).map_err(|error| crate::esm::PollError::InvalidResponse(error.to_string()))?;
                        let trace_header = esm_trace_header(&event);
                        let output = match lambda
                            .invoke(LambdaInvokeRequest {
                                call: LambdaCallContext {
                                    source_service: "lambda-esm".into(),
                                    account_id: account,
                                    region,
                                    request_id: uuid::Uuid::new_v4().to_string(),
                                    caller_arn: None,
                                },
                                function_name,
                                qualifier: None,
                                payload: SensitivePayload::new(payload),
                                trace_header,
                            })
                            .await
                        {
                            Ok(output) => output,
                            Err(error) => return Err(crate::esm::PollError::Invocation(error)),
                        };
                        if output.function_error.is_some() {
                            return Err(crate::esm::PollError::FunctionFailed);
                        }
                        Ok(output.payload.into_vec())
                    }
                })
                .await;
                let processing = match &result {
                    Ok(crate::esm::PollOutcome::Processed) => "OK".to_string(),
                    Ok(crate::esm::PollOutcome::PartialFailure) => "Partial batch failure".to_string(),
                    Ok(crate::esm::PollOutcome::Empty) => "No records processed".to_string(),
                    Err(error) => error.to_string(),
                };
                let state = store.clone();
                let id = worker_uuid.clone();
                let persisted = tokio::task::spawn_blocking(move || state.set_processing_result(&id, processing)).await;
                if !matches!(persisted, Ok(Ok(()))) {
                    tracing::warn!(service = "lambda", cause_code = "event_source_state_write_failed", "could not persist event source state");
                }
                if let Some(control) = &polling { control.report(&result, current.reports_batch_item_failures()); }
                if let Err(error) = result {
                    let cause_code = match error {
                        crate::esm::PollError::Source(_) => "event_source_read_failed",
                        crate::esm::PollError::Invocation(_) => "event_source_invocation_rejected",
                        crate::esm::PollError::FunctionFailed => "event_source_function_failed",
                        crate::esm::PollError::InvalidResponse(_) => "event_source_response_invalid",
                    };
                    tracing::warn!(service = "lambda", cause_code, mapping_id = %worker_uuid, "Event source mapping cycle failed");
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
                }
            }).await;
        });
        workers.retain(|_, worker| !worker.handle.is_finished());
        workers.insert(
            uuid,
            EsmWorker {
                handle: worker,
                cancel: Some(cancel),
            },
        );
        Ok(())
    }

    pub(super) fn abort(&self, uuid: &str) {
        if let Ok(mut slot) = self.esm_workers.lock() {
            let Some(workers) = slot.as_mut() else {
                return;
            };
            workers.retain(|_, worker| !worker.handle.is_finished());
            if let Some(cancel) = workers
                .get_mut(uuid)
                .and_then(|worker| worker.cancel.take())
            {
                let _ = cancel.send(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::tests::{create_fn, request};
    use locallycloud_state::StateDb;

    async fn fixture() -> (std::path::PathBuf, Arc<StateDb>, Arc<LambdaHandler>, String) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.locallycloud-tmp/batch-a4a6/lambda")
            .join(format!("test-{}", uuid::Uuid::new_v4()));
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let handler = Arc::new(LambdaHandler::new());
        handler.esm.attach_state(db.clone()).unwrap();
        create_fn(&handler).await;
        let mapping = create_mapping(
            "us-east-1",
            "arn:aws:lambda:us-east-1:000000000000:function:fn",
            &json!({
                "EventSourceArn":"arn:aws:sqs:us-east-1:000000000000:q", "Enabled":false
            }),
        )
        .unwrap();
        let uuid = mapping.uuid.clone();
        handler.esm.insert(mapping).unwrap();
        (root, db, handler, uuid)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn esm_routes_yield_while_sqlite_writer_is_busy() {
        let (root, db, handler, uuid) = fixture().await;
        let resource = format!("/2015-03-31/event-source-mappings/{uuid}");
        let tags = format!(
            "/2017-03-31/tags/arn:aws:lambda:us-east-1:000000000000:event-source-mapping:{uuid}"
        );
        for (method, path, body, status) in [
            (Method::PUT, resource.clone(), r#"{"BatchSize":2}"#, 202),
            (
                Method::POST,
                tags.clone(),
                r#"{"Tags":{"team":"events"}}"#,
                204,
            ),
            (Method::DELETE, format!("{tags}?tagKeys=team"), "", 204),
            (Method::DELETE, resource.clone(), "", 202),
        ] {
            let writer = db.connection().unwrap();
            writer.execute_batch("BEGIN IMMEDIATE").unwrap();
            let release = tokio::spawn(async move {
                tokio::task::yield_now().await;
                writer.execute_batch("ROLLBACK").unwrap();
            });
            let response = handler.handle(request(method, &path, body)).await;
            release.await.unwrap();
            assert_eq!(response.status().as_u16(), status);
        }
        assert!(handler.esm.get(&uuid).is_none());
        drop(handler);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn partial_update_uses_current_batch_defaults_after_waiting_for_lifecycle_gate() {
        use std::future::{poll_fn, Future};
        use std::task::Poll;

        let (root, db, handler, uuid) = fixture().await;
        let writer = db.connection().unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let (entered, entering) = tokio::sync::oneshot::channel();
        let first_handler = handler.clone();
        let first_uuid = uuid.clone();
        let first = tokio::spawn(async move {
            first_handler
                .write_esm(move |controller| {
                    let _ = entered.send(());
                    controller.esm.update(&first_uuid, |mapping| {
                        mapping.batch_size = 15;
                        mapping.maximum_batching_window_in_seconds = 1;
                    })?;
                    Ok(())
                })
                .await
        });
        entering.await.unwrap();
        let path = format!("/2015-03-31/event-source-mappings/{uuid}");
        let mut second =
            Box::pin(handler.handle(request(Method::PUT, &path, r#"{"Enabled":false}"#)));
        poll_fn(|context| {
            assert!(second.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        writer.execute_batch("ROLLBACK").unwrap();
        first.await.unwrap().unwrap();
        assert_eq!(second.await.status(), 202);
        let mapping = handler.esm.get(&uuid).unwrap();
        assert_eq!(mapping.batch_size, 15);
        assert_eq!(mapping.maximum_batching_window_in_seconds, 1);
        assert!(!mapping.enabled);
        let restored = EsmStore::new();
        restored.attach_state(db.clone()).unwrap();
        let mapping = restored.get(&uuid).unwrap();
        assert_eq!(mapping.batch_size, 15);
        assert_eq!(mapping.maximum_batching_window_in_seconds, 1);
        assert!(!mapping.enabled);
        drop((restored, writer, handler, db));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_esm_write_finishes_commit_and_worker_reconciliation() {
        let (root, db, handler, uuid) = fixture().await;
        let writer = db.connection().unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let (entered, entering) = tokio::sync::oneshot::channel();
        let (done, completed) = tokio::sync::oneshot::channel();
        let (read, reader) = std::sync::mpsc::channel();
        let worker_handler = handler.clone();
        let worker_uuid = uuid.clone();
        let client = tokio::spawn(async move {
            worker_handler
                .write_esm(move |mut controller| {
                    // A poller with no reachable registry exercises lifecycle without compute.
                    controller.executor_available = true;
                    let mut read_without_lock = false;
                    let mapping = controller
                        .esm
                        .update(&worker_uuid, |mapping| {
                            let _ = entered.send(());
                            read_without_lock = reader.recv_timeout(Duration::from_secs(2)).is_ok();
                            mapping.enabled = true;
                        })?
                        .unwrap();
                    assert!(read_without_lock);
                    controller.reconcile("000000000000", "us-east-1", &mapping)?;
                    let _ = done.send(());
                    Ok(())
                })
                .await
        });
        entering.await.unwrap();
        assert!(!handler.esm.get(&uuid).unwrap().enabled);
        read.send(()).unwrap();
        client.abort();
        let _ = client.await;
        writer.execute_batch("ROLLBACK").unwrap();
        completed.await.unwrap();
        assert!(handler.esm.get(&uuid).unwrap().enabled);
        assert!(handler
            .esm_workers
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .contains_key(&uuid));
        handler.shutdown().await;
        let restored = EsmStore::new();
        restored.attach_state(db.clone()).unwrap();
        assert!(restored.get(&uuid).unwrap().enabled);
        drop(restored);
        drop(writer);
        drop(handler);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_prevents_a_detached_commit_from_starting_a_worker() {
        let (root, db, handler, uuid) = fixture().await;
        let mut controller = handler.esm_controller();
        controller.executor_available = true;
        let workers = handler.esm_workers.clone();
        let mapping = handler
            .esm
            .update(&uuid, |mapping| mapping.enabled = true)
            .unwrap()
            .unwrap();
        handler.shutdown().await;
        controller
            .reconcile("000000000000", "us-east-1", &mapping)
            .unwrap();
        assert!(workers.lock().unwrap().is_none());
        drop(controller);
        drop(handler);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_reconciliations_use_current_state_and_drain_previous_workers() {
        let (root, db, handler, uuid) = fixture().await;
        let writer = db.connection().unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let (entered, entering) = tokio::sync::oneshot::channel();
        let mut clients = Vec::new();
        for (batch_size, entered) in [(2, Some(entered)), (3, None)] {
            let handler = handler.clone();
            let uuid = uuid.clone();
            clients.push(tokio::spawn(async move {
                handler
                    .write_esm(move |mut controller| {
                        controller.executor_available = true;
                        if let Some(entered) = entered {
                            let _ = entered.send(());
                        }
                        let mapping = controller
                            .esm
                            .update(&uuid, |mapping| {
                                mapping.enabled = true;
                                mapping.batch_size = batch_size;
                            })?
                            .unwrap();
                        controller.reconcile("000000000000", "us-east-1", &mapping)
                    })
                    .await
            }));
        }
        entering.await.unwrap();
        writer.execute_batch("ROLLBACK").unwrap();
        for client in clients {
            client.await.unwrap().unwrap();
        }
        let stale = handler.esm.get(&uuid).unwrap();
        handler
            .write_esm(move |mut controller| {
                controller.executor_available = true;
                controller.esm.update(&stale.uuid, |mapping| {
                    mapping.enabled = false;
                    mapping.state = "Disabled".into();
                })?;
                controller.reconcile("000000000000", "us-east-1", &stale)?;
                assert!(!controller.esm.get(&stale.uuid).unwrap().enabled);
                controller.esm.remove(&stale.uuid)?;
                controller.reconcile("000000000000", "us-east-1", &stale)?;
                Ok(())
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), handler.shutdown())
            .await
            .unwrap();
        assert!(handler.esm_workers.lock().unwrap().is_none());
        drop(writer);
        drop(handler);
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }
}
