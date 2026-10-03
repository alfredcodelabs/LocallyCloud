//! CloudFormation service handler: Query-protocol dispatch, stack lifecycle orchestration,
//! and XML responses. Registered `Native` in the Core registry.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use bytes::Bytes;
use http::Method;
use serde_json::Value;

use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};

use crate::error::CfnError;
use crate::model::{Output, Stack, StackEvent, StackResource, StackStatus};
use crate::proto::Query;
use crate::provision::{Provisioner, Replacement};
use crate::store::{CfnStore, ChangeSet, ChangeSetChange};
use crate::template::{resolve, ResolveCtx, ResolvedResource, Template};
use crate::xml::{query_envelope, text_el, xml_escape};

const STACK_TYPE: &str = "AWS::CloudFormation::Stack";

pub struct CfnHandler {
    store: Arc<CfnStore>,
    registry: Weak<ServiceRegistry>,
}

impl CfnHandler {
    fn new(registry: Weak<ServiceRegistry>) -> Self {
        CfnHandler {
            store: CfnStore::new(),
            registry,
        }
    }

    fn provisioner(&self, region: &str, account: &str) -> Provisioner {
        Provisioner::new(
            self.registry.clone(),
            region.to_string(),
            account.to_string(),
        )
    }

    async fn dispatch(
        &self,
        op: &str,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        match op {
            "CreateStack" => self.create_stack(q, region, account, None).await,
            "CreateChangeSet" => self.create_change_set(q, region, account).await,
            "DescribeChangeSet" => self.describe_change_set(q, region, account),
            "ExecuteChangeSet" => self.execute_change_set(q, region, account).await,
            "DeleteChangeSet" => self.delete_change_set(q, region, account),
            "UpdateStack" => self.update_stack(q, region, account).await,
            "DeleteStack" => self.delete_stack(q, region, account).await,
            "DescribeStacks" => self.describe_stacks(q, region, account),
            "DescribeStackEvents" => self.describe_stack_events(q, region, account),
            "DescribeStackResources" => self.describe_stack_resources(q, region, account),
            "DescribeStackResource" => self.describe_stack_resource(q, region, account),
            "ListStackResources" => self.list_stack_resources(q, region, account),
            "GetTemplate" => self.get_template(q, region, account),
            "ValidateTemplate" => self.validate_template(q, region, account).await,
            "GetTemplateSummary" => self.get_template_summary(q, region, account).await,
            "ListStacks" => Ok(self.list_stacks(region, account)),
            other => Err(CfnError::Unsupported(format!(
                "operation {other} is not supported"
            ))),
        }
    }

    async fn resolve_template_body(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        if let Some(body) = q.get("TemplateBody") {
            return Ok(body);
        }
        if let Some(url) = q.get("TemplateURL") {
            let (bucket, key) = parse_s3_url(&url)
                .ok_or_else(|| CfnError::Validation(format!("unsupported TemplateURL: {url}")))?;
            let registry = self.registry.upgrade().ok_or(CfnError::Internal)?;
            let handler = registry
                .native_handler(&ServiceName::new("s3"))
                .ok_or(CfnError::Internal)?;
            let mut headers = http::HeaderMap::new();
            headers.insert("host", http::HeaderValue::from_static("localhost:4566"));
            let req = ServiceRequest {
                method: Method::GET,
                uri: format!("/{bucket}/{key}")
                    .parse()
                    .map_err(|_| CfnError::Internal)?,
                headers,
                body: Bytes::new(),
                region: region.to_string(),
                account_id: account.to_string(),
                request_id: uuid::Uuid::new_v4().to_string(),
            };
            let resp = handler.handle(req).await;
            let status = resp.status().as_u16();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .map_err(|_| CfnError::Internal)?;
            if !(200..300).contains(&status) {
                return Err(CfnError::Validation(format!(
                    "could not fetch TemplateURL {url} ({status})"
                )));
            }
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        Err(CfnError::Validation(
            "Either TemplateBody or TemplateURL must be specified".into(),
        ))
    }

    async fn create_change_set(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let name = q
            .get("ChangeSetName")
            .ok_or_else(|| CfnError::Validation("ChangeSetName is required".into()))?;
        let stack = q
            .get("StackName")
            .ok_or_else(|| CfnError::Validation("StackName is required".into()))?;
        let change_type = q.get("ChangeSetType").unwrap_or_else(|| "UPDATE".into());
        if !matches!(change_type.as_str(), "CREATE" | "UPDATE") {
            return Err(CfnError::Validation(
                "ChangeSetType must be CREATE or UPDATE".into(),
            ));
        }
        if self
            .store
            .find_change_set(account, region, &stack, &name)
            .is_some()
        {
            return Err(CfnError::AlreadyExists(format!(
                "ChangeSet [{name}] already exists"
            )));
        }
        let existing = self.store.find(account, region, &stack);
        if (change_type == "CREATE") == existing.is_some() {
            return Err(CfnError::Validation(format!(
                "ChangeSetType {change_type} is invalid for stack {stack}"
            )));
        }
        let body = self.resolve_template_body(q, region, account).await?;
        let template = Template::parse(&body)?;
        check_capabilities(q, &template)?;
        let params = q.parameters();
        let conditions = template.evaluate_conditions(region, account, &params)?;
        let active = template.active_resources(&conditions)?;
        let changes = change_set_changes(existing.as_ref(), &active, region, account, &params)?;
        let unchanged = existing
            .as_ref()
            .is_some_and(|old| old.template_body == body && old.parameters == params);
        let id = format!(
            "arn:aws:cloudformation:{region}:{account}:changeSet/{name}/{}",
            uuid::Uuid::new_v4()
        );
        let stack_id = existing
            .as_ref()
            .map(|old| old.stack_id.clone())
            .unwrap_or_else(|| make_stack_id(region, account, &stack));
        let mut request = q.clone();
        request.params.insert("TemplateBody".into(), body);
        request.params.remove("TemplateURL");
        let inserted = self.store.insert_change_set(
            account,
            region,
            ChangeSet {
                id: id.clone(),
                name: name.clone(),
                stack_name: stack,
                stack_id: stack_id.clone(),
                change_type,
                status: if unchanged {
                    "FAILED"
                } else {
                    "CREATE_COMPLETE"
                }
                .into(),
                reason: unchanged
                    .then(|| "The submitted information didn't contain changes.".into()),
                executed: false,
                request,
                changes,
            },
        );
        if !inserted {
            return Err(CfnError::AlreadyExists(format!(
                "ChangeSet [{name}] already exists"
            )));
        }
        Ok(format!(
            "{}{}",
            text_el("Id", &id),
            text_el("StackId", &stack_id)
        ))
    }

    fn lookup_change_set(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<ChangeSet, CfnError> {
        let name = q
            .get("ChangeSetName")
            .ok_or_else(|| CfnError::Validation("ChangeSetName is required".into()))?;
        let stack = q.get("StackName").unwrap_or_default();
        self.store
            .find_change_set(account, region, &stack, &name)
            .ok_or_else(|| CfnError::Validation(format!("ChangeSet [{name}] does not exist")))
    }

    fn describe_change_set(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let cs = self.lookup_change_set(q, region, account)?;
        let reason = cs
            .reason
            .as_deref()
            .map(|s| text_el("StatusReason", s))
            .unwrap_or_default();
        let changes = cs.changes.iter().map(|change| {
            let physical = change.physical_id.as_deref()
                .map(|id| text_el("PhysicalResourceId", id)).unwrap_or_default();
            format!("<member><Type>Resource</Type><ResourceChange>{}{}{}<Action>{}</Action></ResourceChange></member>",
                text_el("LogicalResourceId", &change.logical_id),
                text_el("ResourceType", &change.resource_type), physical, change.action)
        }).collect::<String>();
        Ok(format!(
            "{}{}{}{}{}{}{}{}{}<Changes>{changes}</Changes>",
            text_el("ChangeSetId", &cs.id),
            text_el("ChangeSetName", &cs.name),
            text_el("StackId", &cs.stack_id),
            text_el("StackName", &cs.stack_name),
            text_el("Status", &cs.status),
            text_el(
                "ExecutionStatus",
                if cs.executed {
                    "EXECUTE_COMPLETE"
                } else if cs.status == "FAILED" {
                    "UNAVAILABLE"
                } else {
                    "AVAILABLE"
                }
            ),
            text_el("ChangeSetType", &cs.change_type),
            reason,
            text_el("CreationTime", &now_iso())
        ))
    }

    async fn execute_change_set(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let cs = self.lookup_change_set(q, region, account)?;
        if !self.store.claim_change_set(account, region, &cs) {
            return Err(CfnError::Validation(format!(
                "ChangeSet [{}] is not executable",
                cs.name
            )));
        }
        if cs.change_type == "CREATE" {
            self.create_stack(&cs.request, region, account, Some(&cs.stack_id))
                .await?;
        } else {
            self.update_stack(&cs.request, region, account).await?;
        }
        Ok(String::new())
    }

    fn delete_change_set(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let cs = self.lookup_change_set(q, region, account)?;
        self.store.remove_change_set(account, region, &cs);
        Ok(String::new())
    }

    async fn create_stack(
        &self,
        q: &Query,
        region: &str,
        account: &str,
        change_set_stack_id: Option<&str>,
    ) -> Result<String, CfnError> {
        let name = q
            .get("StackName")
            .ok_or_else(|| CfnError::Validation("StackName is required".into()))?;
        if self.store.get(account, region, &name).is_some() {
            return Err(CfnError::AlreadyExists(format!(
                "Stack [{name}] already exists"
            )));
        }
        let body = self.resolve_template_body(q, region, account).await?;
        let template = Template::parse(&body)?;
        check_capabilities(q, &template)?;
        let parameters = q.parameters();
        let conditions = template.evaluate_conditions(region, account, &parameters)?;
        let active = template.active_resources(&conditions)?;
        let outputs = template.active_outputs(&conditions, &active)?;
        let stack_id = change_set_stack_id
            .map(str::to_string)
            .unwrap_or_else(|| make_stack_id(region, account, &name));

        let (status, resources, outputs, events) = self
            .provision(
                &name,
                &stack_id,
                &template,
                &parameters,
                region,
                account,
                true,
                &[],
                None,
                &conditions,
                &active,
                &outputs,
            )
            .await;

        let now = now_iso();
        let stack = Stack {
            stack_id: stack_id.clone(),
            stack_name: name.clone(),
            status,
            template_body: body,
            parameters,
            resources,
            outputs,
            events,
            tags: q.tags(),
            creation_time: now,
            last_updated_time: None,
        };
        self.store.put(account, region, stack);
        Ok(format!("<StackId>{}</StackId>", xml_escape(&stack_id)))
    }

    async fn update_stack(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let name = q
            .get("StackName")
            .ok_or_else(|| CfnError::Validation("StackName is required".into()))?;
        let existing = self
            .store
            .find(account, region, &name)
            .ok_or_else(|| CfnError::Validation(format!("Stack [{name}] does not exist")))?;
        let body = self.resolve_template_body(q, region, account).await?;
        let template = Template::parse(&body)?;
        check_capabilities(q, &template)?;
        let previous_template = Template::parse(&existing.template_body)?;
        let parameters = q.parameters();
        let conditions = template.evaluate_conditions(region, account, &parameters)?;
        let active = template.active_resources(&conditions)?;
        let output_exprs = template.active_outputs(&conditions, &active)?;

        let (status, resources, outputs, mut events) = self
            .provision(
                &name,
                &existing.stack_id,
                &template,
                &parameters,
                region,
                account,
                false,
                &existing.resources,
                Some((&previous_template, &existing.parameters)),
                &conditions,
                &active,
                &output_exprs,
            )
            .await;

        // Preserve prior events, newest first is produced by describe.
        let mut all_events = existing.events.clone();
        all_events.append(&mut events);

        let update_failed = status == StackStatus::UpdateFailed;
        let stack = Stack {
            stack_id: existing.stack_id.clone(),
            stack_name: name.clone(),
            status,
            template_body: if update_failed {
                existing.template_body.clone()
            } else {
                body
            },
            parameters: if update_failed {
                existing.parameters.clone()
            } else {
                parameters
            },
            resources,
            outputs: if update_failed {
                existing.outputs.clone()
            } else {
                outputs
            },
            events: all_events,
            tags: if update_failed || q.tags().is_empty() {
                existing.tags.clone()
            } else {
                q.tags()
            },
            creation_time: existing.creation_time.clone(),
            last_updated_time: Some(now_iso()),
        };
        let stack_id = stack.stack_id.clone();
        self.store.put(account, region, stack);
        Ok(format!("<StackId>{}</StackId>", xml_escape(&stack_id)))
    }

    async fn delete_stack(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let name = q
            .get("StackName")
            .ok_or_else(|| CfnError::Validation("StackName is required".into()))?;
        if let Some(mut stack) = self.store.find(account, region, &name) {
            let provisioner = self.provisioner(region, account);
            let template = Template::parse(&stack.template_body)?;
            let declarations: BTreeMap<_, _> = template
                .resources()
                .into_iter()
                .map(|decl| (decl.logical_id.clone(), decl))
                .collect();
            let resolved: BTreeMap<_, _> = stack
                .resources
                .iter()
                .map(|resource| {
                    (
                        resource.logical_id.clone(),
                        ResolvedResource {
                            ref_value: resource.physical_id.clone(),
                            attributes: resource.attributes.clone(),
                        },
                    )
                })
                .collect();
            let conditions = template.evaluate_conditions(region, account, &stack.parameters)?;
            let ctx = ResolveCtx {
                region,
                account,
                stack_name: &stack.stack_name,
                partition: "aws",
                resources: &resolved,
                parameters: &stack.parameters,
                conditions: &conditions,
            };
            stack.events.push(event(
                &stack.stack_name,
                STACK_TYPE,
                "DELETE_IN_PROGRESS",
                None,
            ));
            let mut remaining = stack.resources.clone();
            let mut failures = Vec::new();

            // Tear down in reverse provisioning order. Continue after failures so independent
            // resources still get a cleanup attempt.
            for resource in stack.resources.iter().rev() {
                if declarations
                    .get(&resource.logical_id)
                    .is_some_and(|decl| decl.deletion_policy.retains_on_delete())
                {
                    remaining.retain(|candidate| candidate.logical_id != resource.logical_id);
                    stack.events.push(event(
                        &resource.logical_id,
                        &resource.resource_type,
                        "DELETE_SKIPPED",
                        Some("retained by DeletionPolicy".into()),
                    ));
                    continue;
                }
                let properties = declarations
                    .get(&resource.logical_id)
                    .map(|decl| resolve(&decl.properties, &ctx))
                    .unwrap_or(Value::Null);
                stack.events.push(event(
                    &resource.logical_id,
                    &resource.resource_type,
                    "DELETE_IN_PROGRESS",
                    None,
                ));
                match provisioner
                    .deprovision(&resource.resource_type, &resource.physical_id, &properties)
                    .await
                {
                    Ok(()) => {
                        remaining.retain(|candidate| candidate.logical_id != resource.logical_id);
                        stack.events.push(event(
                            &resource.logical_id,
                            &resource.resource_type,
                            "DELETE_COMPLETE",
                            None,
                        ));
                    }
                    Err(error) => {
                        let reason = error.to_string();
                        if let Some(candidate) = remaining
                            .iter_mut()
                            .find(|candidate| candidate.logical_id == resource.logical_id)
                        {
                            candidate.status = "DELETE_FAILED".into();
                        }
                        stack.events.push(event(
                            &resource.logical_id,
                            &resource.resource_type,
                            "DELETE_FAILED",
                            Some(reason.clone()),
                        ));
                        failures.push(format!("{}: {reason}", resource.logical_id));
                    }
                }
            }

            if failures.is_empty() {
                self.store.remove(account, region, &stack.stack_name);
            } else {
                let reason = failures.join("; ");
                stack.status = StackStatus::DeleteFailed;
                stack.resources = remaining;
                stack.events.push(event(
                    &stack.stack_name,
                    STACK_TYPE,
                    "DELETE_FAILED",
                    Some(reason),
                ));
                self.store.put(account, region, stack);
            }
        }
        // Deleting a non-existent stack is a no-op success in AWS.
        Ok(String::new())
    }

    #[allow(clippy::too_many_arguments)]
    async fn provision(
        &self,
        stack_name: &str,
        _stack_id: &str,
        _template: &Template,
        parameters: &BTreeMap<String, String>,
        region: &str,
        account: &str,
        creating: bool,
        existing: &[StackResource],
        previous: Option<(&Template, &BTreeMap<String, String>)>,
        conditions: &BTreeMap<String, bool>,
        active: &[crate::template::ResourceDecl],
        output_exprs: &[(String, Value, Option<Value>)],
    ) -> (
        StackStatus,
        Vec<StackResource>,
        Vec<Output>,
        Vec<StackEvent>,
    ) {
        enum ReconcileAction {
            Created {
                logical_id: String,
                resource_type: String,
                properties: Value,
            },
            Updated {
                logical_id: String,
                resource_type: String,
                applied_properties: Value,
                previous_properties: Value,
            },
        }

        let provisioner = self.provisioner(region, account);
        let previous_resolved: BTreeMap<String, ResolvedResource> = existing
            .iter()
            .map(|resource| {
                (
                    resource.logical_id.clone(),
                    ResolvedResource {
                        ref_value: resource.physical_id.clone(),
                        attributes: resource.attributes.clone(),
                    },
                )
            })
            .collect();
        let previous_declarations: BTreeMap<_, _> = previous
            .map(|(template, _)| template.resources())
            .unwrap_or_default()
            .into_iter()
            .map(|decl| (decl.logical_id.clone(), decl))
            .collect();
        let declarations: BTreeMap<_, _> = active
            .iter()
            .cloned()
            .map(|decl| (decl.logical_id.clone(), decl))
            .collect();
        let previous_conditions = previous
            .and_then(|(template, previous_parameters)| {
                template
                    .evaluate_conditions(region, account, previous_parameters)
                    .ok()
            })
            .unwrap_or_default();
        let previous_ctx = previous.map(|(_, previous_parameters)| ResolveCtx {
            region,
            account,
            stack_name,
            partition: "aws",
            resources: &previous_resolved,
            parameters: previous_parameters,
            conditions: &previous_conditions,
        });

        // Removed resources and logical ids whose type changed must not remain available to
        // intrinsic resolution. Tear them down in reverse creation order before reconciling.
        let mut removal_failures = BTreeMap::new();
        for resource in existing.iter().rev().filter(|resource| {
            declarations
                .get(&resource.logical_id)
                .is_none_or(|decl| decl.resource_type != resource.resource_type)
        }) {
            if previous_declarations
                .get(&resource.logical_id)
                .is_some_and(|decl| decl.deletion_policy.retains_on_delete())
            {
                continue;
            }
            let properties = previous_declarations
                .get(&resource.logical_id)
                .zip(previous_ctx.as_ref())
                .map(|(decl, ctx)| resolve(&decl.properties, ctx))
                .unwrap_or(Value::Null);
            if let Err(error) = provisioner
                .deprovision(&resource.resource_type, &resource.physical_id, &properties)
                .await
            {
                removal_failures.insert(resource.logical_id.clone(), error.to_string());
            }
        }

        let mut resources: Vec<StackResource> = existing
            .iter()
            .filter(|resource| {
                removal_failures.contains_key(&resource.logical_id)
                    || declarations
                        .get(&resource.logical_id)
                        .is_some_and(|decl| decl.resource_type == resource.resource_type)
            })
            .cloned()
            .collect();
        let mut resolved: BTreeMap<String, ResolvedResource> = resources
            .iter()
            .map(|resource| {
                (
                    resource.logical_id.clone(),
                    ResolvedResource {
                        ref_value: resource.physical_id.clone(),
                        attributes: resource.attributes.clone(),
                    },
                )
            })
            .collect();
        let mut events: Vec<StackEvent> = Vec::new();
        let mut failure_reason = None;
        let mut successful_actions = Vec::new();

        let (in_progress, complete, failed_status) = if creating {
            ("CREATE_IN_PROGRESS", "CREATE_COMPLETE", "CREATE_FAILED")
        } else {
            ("UPDATE_IN_PROGRESS", "UPDATE_COMPLETE", "UPDATE_FAILED")
        };

        // Stack-level start event (deployment tools monitor these to detect completion).
        events.push(event(stack_name, STACK_TYPE, in_progress, None));

        if !removal_failures.is_empty() {
            for resource in &mut resources {
                if let Some(reason) = removal_failures.get(&resource.logical_id) {
                    resource.status = failed_status.to_string();
                    events.push(event(
                        &resource.logical_id,
                        &resource.resource_type,
                        failed_status,
                        Some(reason.clone()),
                    ));
                }
            }
            events.push(event(
                stack_name,
                STACK_TYPE,
                failed_status,
                Some("resource teardown failed".into()),
            ));
            return (StackStatus::UpdateFailed, resources, Vec::new(), events);
        }

        for decl in active {
            let ctx = ResolveCtx {
                region,
                account,
                stack_name,
                partition: "aws",
                resources: &resolved,
                parameters,
                conditions,
            };
            let props = resolve(&decl.properties, &ctx);
            if let Some(current) = resolved.get(&decl.logical_id).cloned() {
                let previous_properties = previous_declarations
                    .get(&decl.logical_id)
                    .zip(previous_ctx.as_ref())
                    .map(|(previous_decl, ctx)| resolve(&previous_decl.properties, ctx))
                    .unwrap_or(Value::Null);
                if previous_properties == props {
                    continue;
                }
                events.push(event(
                    &decl.logical_id,
                    &decl.resource_type,
                    in_progress,
                    None,
                ));
                match provisioner
                    .update(
                        &decl.logical_id,
                        &decl.resource_type,
                        &current,
                        &previous_properties,
                        &props,
                        Replacement::Update(decl.update_replace_policy),
                    )
                    .await
                {
                    Ok(updated) => {
                        if let Some(resource) = resources
                            .iter_mut()
                            .find(|resource| resource.logical_id == decl.logical_id)
                        {
                            resource.physical_id = updated.ref_value.clone();
                            resource.attributes = updated.attributes.clone();
                            resource.status = complete.to_string();
                        }
                        successful_actions.push(ReconcileAction::Updated {
                            logical_id: decl.logical_id.clone(),
                            resource_type: decl.resource_type.clone(),
                            applied_properties: props.clone(),
                            previous_properties,
                        });
                        resolved.insert(decl.logical_id.clone(), updated);
                        events.push(event(&decl.logical_id, &decl.resource_type, complete, None));
                    }
                    Err(error) => {
                        let reason = error.to_string();
                        events.push(event(
                            &decl.logical_id,
                            &decl.resource_type,
                            failed_status,
                            Some(reason.clone()),
                        ));
                        failure_reason = Some(reason);
                        break;
                    }
                }
                continue;
            }
            events.push(event(
                &decl.logical_id,
                &decl.resource_type,
                in_progress,
                None,
            ));
            match provisioner
                .provision(&decl.logical_id, stack_name, &decl.resource_type, &props)
                .await
            {
                Ok(rr) => {
                    resources.push(StackResource {
                        logical_id: decl.logical_id.clone(),
                        physical_id: rr.ref_value.clone(),
                        resource_type: decl.resource_type.clone(),
                        status: complete.to_string(),
                        attributes: rr.attributes.clone(),
                    });
                    events.push(event(&decl.logical_id, &decl.resource_type, complete, None));
                    successful_actions.push(ReconcileAction::Created {
                        logical_id: decl.logical_id.clone(),
                        resource_type: decl.resource_type.clone(),
                        properties: props.clone(),
                    });
                    resolved.insert(decl.logical_id.clone(), rr);
                }
                Err(error) => {
                    let reason = error.to_string();
                    events.push(event(
                        &decl.logical_id,
                        &decl.resource_type,
                        failed_status,
                        Some(reason.clone()),
                    ));
                    failure_reason = Some(reason);
                    break;
                }
            }
        }

        if let Some(provisioning_failure) = failure_reason {
            let status = if creating {
                StackStatus::CreateFailed
            } else {
                StackStatus::UpdateFailed
            };
            let mut stack_reason = format!("resource provisioning failed: {provisioning_failure}");

            let mut cleanup_failures = Vec::new();
            for action in successful_actions.iter().rev() {
                match action {
                    ReconcileAction::Created {
                        logical_id,
                        resource_type,
                        properties,
                    } => {
                        let Some(resource) = resources
                            .iter()
                            .find(|resource| resource.logical_id == *logical_id)
                            .cloned()
                        else {
                            continue;
                        };
                        events.push(event(logical_id, resource_type, "DELETE_IN_PROGRESS", None));
                        match provisioner
                            .deprovision(resource_type, &resource.physical_id, properties)
                            .await
                        {
                            Ok(()) => {
                                resources.retain(|candidate| candidate.logical_id != *logical_id);
                                resolved.remove(logical_id);
                                events.push(event(
                                    logical_id,
                                    resource_type,
                                    "DELETE_COMPLETE",
                                    None,
                                ));
                            }
                            Err(error) => {
                                let reason = error.to_string();
                                if let Some(candidate) = resources
                                    .iter_mut()
                                    .find(|candidate| candidate.logical_id == *logical_id)
                                {
                                    candidate.status = "DELETE_FAILED".into();
                                }
                                events.push(event(
                                    logical_id,
                                    resource_type,
                                    "DELETE_FAILED",
                                    Some(reason.clone()),
                                ));
                                cleanup_failures.push(format!("{logical_id}: {reason}"));
                            }
                        }
                    }
                    ReconcileAction::Updated {
                        logical_id,
                        resource_type,
                        applied_properties,
                        previous_properties,
                    } => {
                        events.push(event(
                            logical_id,
                            resource_type,
                            "UPDATE_ROLLBACK_IN_PROGRESS",
                            None,
                        ));
                        let Some(current) = resolved.get(logical_id).cloned() else {
                            let reason = "updated resource resolution is unavailable".to_string();
                            events.push(event(
                                logical_id,
                                resource_type,
                                "UPDATE_ROLLBACK_FAILED",
                                Some(reason.clone()),
                            ));
                            cleanup_failures.push(format!("{logical_id}: {reason}"));
                            continue;
                        };
                        match provisioner
                            .update(
                                logical_id,
                                resource_type,
                                &current,
                                applied_properties,
                                previous_properties,
                                Replacement::Rollback,
                            )
                            .await
                        {
                            Ok(restored) => {
                                if let Some(resource) = resources
                                    .iter_mut()
                                    .find(|resource| resource.logical_id == *logical_id)
                                {
                                    resource.physical_id = restored.ref_value.clone();
                                    resource.attributes = restored.attributes.clone();
                                    resource.status = "UPDATE_ROLLBACK_COMPLETE".into();
                                }
                                resolved.insert(logical_id.clone(), restored);
                                events.push(event(
                                    logical_id,
                                    resource_type,
                                    "UPDATE_ROLLBACK_COMPLETE",
                                    None,
                                ));
                            }
                            Err(error) => {
                                let reason = error.to_string();
                                if let Some(resource) = resources
                                    .iter_mut()
                                    .find(|resource| resource.logical_id == *logical_id)
                                {
                                    resource.status = "UPDATE_ROLLBACK_FAILED".into();
                                }
                                events.push(event(
                                    logical_id,
                                    resource_type,
                                    "UPDATE_ROLLBACK_FAILED",
                                    Some(reason.clone()),
                                ));
                                cleanup_failures.push(format!("{logical_id}: {reason}"));
                            }
                        }
                    }
                }
            }
            if !cleanup_failures.is_empty() {
                stack_reason.push_str("; rollback failed: ");
                stack_reason.push_str(&cleanup_failures.join("; "));
            }

            events.push(event(
                stack_name,
                STACK_TYPE,
                failed_status,
                Some(stack_reason),
            ));
            return (status, resources, Vec::new(), events);
        }

        // Resolve outputs against the fully-provisioned resource set.
        let ctx = ResolveCtx {
            region,
            account,
            stack_name,
            partition: "aws",
            resources: &resolved,
            parameters,
            conditions,
        };
        let outputs = output_exprs
            .iter()
            .cloned()
            .map(|(key, value_expr, export_expr)| Output {
                key,
                value: crate::template::resolve_to_string(&value_expr, &ctx),
                export_name: export_expr.map(|e| crate::template::resolve_to_string(&e, &ctx)),
            })
            .collect();

        let status = if creating {
            StackStatus::CreateComplete
        } else {
            StackStatus::UpdateComplete
        };
        events.push(event(stack_name, STACK_TYPE, complete, None));
        (status, resources, outputs, events)
    }

    fn describe_stacks(&self, q: &Query, region: &str, account: &str) -> Result<String, CfnError> {
        let members = if let Some(name) = q.get("StackName") {
            let stack = self
                .store
                .find(account, region, &name)
                .or_else(|| {
                    self.store
                        .review_change_set(account, region, &name)
                        .map(|cs| review_stack(&cs))
                })
                .ok_or_else(|| {
                    CfnError::Validation(format!("Stack with id {name} does not exist"))
                })?;
            render_stack(&stack)
        } else {
            self.store
                .list(account, region)
                .iter()
                .map(render_stack)
                .collect::<String>()
        };
        Ok(format!("<Stacks>{members}</Stacks>"))
    }

    fn describe_stack_events(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let name = q
            .get("StackName")
            .ok_or_else(|| CfnError::Validation("StackName is required".into()))?;
        let stack = self
            .store
            .find(account, region, &name)
            .or_else(|| {
                self.store
                    .review_change_set(account, region, &name)
                    .map(|cs| review_stack(&cs))
            })
            .ok_or_else(|| CfnError::Validation(format!("Stack with id {name} does not exist")))?;
        // Newest first, as AWS returns.
        let members: String = stack
            .events
            .iter()
            .rev()
            .map(|e| render_event(&stack, e))
            .collect();
        Ok(format!("<StackEvents>{members}</StackEvents>"))
    }

    fn describe_stack_resources(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let name = q
            .get("StackName")
            .ok_or_else(|| CfnError::Validation("StackName is required".into()))?;
        let stack = self
            .store
            .find(account, region, &name)
            .ok_or_else(|| CfnError::Validation(format!("Stack with id {name} does not exist")))?;
        let members: String = stack
            .resources
            .iter()
            .map(|r| render_resource_detail(&stack, r))
            .collect();
        Ok(format!("<StackResources>{members}</StackResources>"))
    }

    fn describe_stack_resource(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let name = q
            .get("StackName")
            .ok_or_else(|| CfnError::Validation("StackName is required".into()))?;
        let logical = q
            .get("LogicalResourceId")
            .ok_or_else(|| CfnError::Validation("LogicalResourceId is required".into()))?;
        let stack = self
            .store
            .find(account, region, &name)
            .ok_or_else(|| CfnError::Validation(format!("Stack with id {name} does not exist")))?;
        let resource = stack.resource(&logical).ok_or_else(|| {
            CfnError::Validation(format!(
                "Resource {logical} does not exist for stack {name}"
            ))
        })?;
        Ok(format!(
            "<StackResourceDetail>{}</StackResourceDetail>",
            resource_detail_inner(&stack, resource)
        ))
    }

    fn list_stack_resources(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let name = q
            .get("StackName")
            .ok_or_else(|| CfnError::Validation("StackName is required".into()))?;
        let stack = self
            .store
            .find(account, region, &name)
            .ok_or_else(|| CfnError::Validation(format!("Stack with id {name} does not exist")))?;
        let members: String = stack
            .resources
            .iter()
            .map(|r| {
                format!(
                    "<member>{}{}{}{}<LastUpdatedTimestamp>{}</LastUpdatedTimestamp></member>",
                    text_el("LogicalResourceId", &r.logical_id),
                    text_el("PhysicalResourceId", &r.physical_id),
                    text_el("ResourceType", &r.resource_type),
                    text_el("ResourceStatus", &r.status),
                    xml_escape(&stack.creation_time),
                )
            })
            .collect();
        Ok(format!(
            "<StackResourceSummaries>{members}</StackResourceSummaries>"
        ))
    }

    fn get_template(&self, q: &Query, region: &str, account: &str) -> Result<String, CfnError> {
        let name = q
            .get("StackName")
            .ok_or_else(|| CfnError::Validation("StackName is required".into()))?;
        let stack = self
            .store
            .find(account, region, &name)
            .ok_or_else(|| CfnError::Validation(format!("Stack with id {name} does not exist")))?;
        match q.get("TemplateStage").as_deref() {
            None | Some("Original") => Ok(text_el("TemplateBody", &stack.template_body)),
            Some("Processed") => Ok(text_el(
                "TemplateBody",
                &Template::parse(&stack.template_body)?.processed_body()?,
            )),
            Some(other) => Err(CfnError::Validation(format!(
                "Invalid TemplateStage {other}"
            ))),
        }
    }

    async fn validate_template(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let body = self.resolve_template_body(q, region, account).await?;
        let template = Template::parse(&body)?;
        Ok(render_template_summary(&template, false))
    }

    async fn get_template_summary(
        &self,
        q: &Query,
        region: &str,
        account: &str,
    ) -> Result<String, CfnError> {
        let body = if let Some(name) = q.get("StackName") {
            self.store
                .find(account, region, &name)
                .ok_or_else(|| {
                    CfnError::Validation(format!("Stack with id {name} does not exist"))
                })?
                .template_body
        } else {
            self.resolve_template_body(q, region, account).await?
        };
        let template = Template::parse(&body)?;
        Ok(render_template_summary(&template, true))
    }

    fn list_stacks(&self, region: &str, account: &str) -> String {
        let members: String = self
            .store
            .list(account, region)
            .iter()
            .map(|s| {
                format!(
                    "<member>{}{}{}<CreationTime>{}</CreationTime></member>",
                    text_el("StackId", &s.stack_id),
                    text_el("StackName", &s.stack_name),
                    text_el("StackStatus", s.status.as_str()),
                    xml_escape(&s.creation_time),
                )
            })
            .collect();
        format!("<StackSummaries>{members}</StackSummaries>")
    }
}

#[async_trait]
impl NativeHandler for CfnHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let q = Query::parse(&request.body);
        let op = match q.action() {
            Some(op) => op,
            None => {
                return CfnError::Validation("missing Action".into())
                    .into_response(&request.request_id)
            }
        };
        match self
            .dispatch(&op, &q, &request.region, &request.account_id)
            .await
        {
            Ok(inner) => {
                let body = query_envelope(&op, &inner, &request.request_id);
                Response::builder()
                    .status(200)
                    .header("content-type", "text/xml")
                    .header("x-amzn-RequestId", &request.request_id)
                    .body(Body::from(body))
                    .expect("xml response is valid")
            }
            Err(err) => err.into_response(&request.request_id),
        }
    }
}

/// Register CloudFormation as a `Native` Query-protocol service.
pub fn register(registry: &Arc<ServiceRegistry>) {
    let handler: Arc<dyn NativeHandler> = Arc::new(CfnHandler::new(Arc::downgrade(registry)));
    registry.register_native(
        ServiceName::new("cloudformation"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        handler,
    );
}

fn check_capabilities(q: &Query, template: &Template) -> Result<(), CfnError> {
    let iam: Vec<_> = template
        .resources()
        .into_iter()
        .filter(|resource| resource.resource_type.starts_with("AWS::IAM::"))
        .collect();
    if iam.is_empty() {
        return Ok(());
    }
    let named = iam.iter().any(|resource| {
        [
            "RoleName",
            "PolicyName",
            "UserName",
            "GroupName",
            "InstanceProfileName",
        ]
        .iter()
        .any(|key| resource.properties.get(*key).is_some())
    });
    let capabilities: Vec<_> = (1..)
        .map(|index| q.get(&format!("Capabilities.member.{index}")))
        .take_while(Option::is_some)
        .flatten()
        .collect();
    let acknowledged = if named {
        capabilities
            .iter()
            .any(|value| value == "CAPABILITY_NAMED_IAM")
    } else {
        capabilities
            .iter()
            .any(|value| value == "CAPABILITY_IAM" || value == "CAPABILITY_NAMED_IAM")
    };
    if acknowledged {
        Ok(())
    } else {
        let required = if named {
            "CAPABILITY_NAMED_IAM"
        } else {
            "CAPABILITY_IAM"
        };
        Err(CfnError::InsufficientCapabilities(format!(
            "Requires capabilities : [{required}]"
        )))
    }
}

fn render_template_summary(template: &Template, include_types: bool) -> String {
    let resources = template.resources();
    let params = template
        .parameter_declarations()
        .iter()
        .map(|(name, definition)| {
            let default = definition
                .get("Default")
                .map(|value| text_el("DefaultValue", &value_to_text(value)))
                .unwrap_or_default();
            let description = definition
                .get("Description")
                .and_then(Value::as_str)
                .map(|value| text_el("Description", value))
                .unwrap_or_default();
            let parameter_type = if include_types {
                definition
                    .get("Type")
                    .and_then(Value::as_str)
                    .map(|value| text_el("ParameterType", value))
                    .unwrap_or_default()
            } else {
                String::new()
            };
            format!(
                "<member>{}{}{}{}<NoEcho>{}</NoEcho></member>",
                text_el("ParameterKey", name),
                parameter_type,
                description,
                default,
                definition
                    .get("NoEcho")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            )
        })
        .collect::<String>();
    let iam = resources
        .iter()
        .filter(|r| r.resource_type == "AWS::IAM::Role")
        .collect::<Vec<_>>();
    let capabilities = if iam.is_empty() {
        String::new()
    } else if iam.iter().any(|r| r.properties.get("RoleName").is_some()) {
        "<member>CAPABILITY_NAMED_IAM</member>".to_string()
    } else {
        "<member>CAPABILITY_IAM</member>".to_string()
    };
    let reason = if iam.is_empty() {
        String::new()
    } else {
        text_el(
            "CapabilitiesReason",
            &format!(
                "The following resource(s) require capabilities: [{}]",
                iam.iter()
                    .map(|r| r.logical_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    };
    let transforms = template
        .declared_transform()
        .map(|name| format!("<member>{}</member>", xml_escape(name)))
        .unwrap_or_default();
    let description = template
        .description()
        .map(|value| text_el("Description", value))
        .unwrap_or_default();
    let types = if include_types {
        format!(
            "<ResourceTypes>{}</ResourceTypes>",
            resources
                .iter()
                .map(|r| format!("<member>{}</member>", xml_escape(&r.resource_type)))
                .collect::<String>()
        )
    } else {
        String::new()
    };
    format!("{description}<Parameters>{params}</Parameters><Capabilities>{capabilities}</Capabilities>{reason}<DeclaredTransforms>{transforms}</DeclaredTransforms>{types}")
}

fn value_to_text(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn change_set_changes(
    existing: Option<&Stack>,
    next: &[crate::template::ResourceDecl],
    region: &str,
    account: &str,
    params: &BTreeMap<String, String>,
) -> Result<Vec<ChangeSetChange>, CfnError> {
    let previous = if let Some(stack) = existing {
        let template = Template::parse(&stack.template_body)?;
        let conditions = template.evaluate_conditions(region, account, &stack.parameters)?;
        template.active_resources(&conditions)?
    } else {
        Vec::new()
    };
    let old = previous
        .iter()
        .map(|r| (r.logical_id.as_str(), r))
        .collect::<BTreeMap<_, _>>();
    let new = next
        .iter()
        .map(|r| (r.logical_id.as_str(), r))
        .collect::<BTreeMap<_, _>>();
    let params_changed = existing.is_some_and(|stack| stack.parameters != *params);
    let mut changes = Vec::new();
    for resource in next {
        let action = match old.get(resource.logical_id.as_str()) {
            None => Some("Add"),
            Some(previous)
                if params_changed
                    || previous.resource_type != resource.resource_type
                    || previous.properties != resource.properties
                    || previous.depends_on != resource.depends_on
                    || previous.deletion_policy != resource.deletion_policy
                    || previous.update_replace_policy != resource.update_replace_policy =>
            {
                Some("Modify")
            }
            _ => None,
        };
        if let Some(action) = action {
            changes.push(ChangeSetChange {
                logical_id: resource.logical_id.clone(),
                resource_type: resource.resource_type.clone(),
                action,
                physical_id: existing
                    .and_then(|stack| stack.resource(&resource.logical_id))
                    .map(|resource| resource.physical_id.clone()),
            });
        }
    }
    for resource in previous {
        if !new.contains_key(resource.logical_id.as_str()) {
            changes.push(ChangeSetChange {
                logical_id: resource.logical_id.clone(),
                resource_type: resource.resource_type,
                action: "Remove",
                physical_id: existing
                    .and_then(|stack| stack.resource(&resource.logical_id))
                    .map(|resource| resource.physical_id.clone()),
            });
        }
    }
    Ok(changes)
}

fn review_stack(cs: &ChangeSet) -> Stack {
    Stack {
        stack_id: cs.stack_id.clone(),
        stack_name: cs.stack_name.clone(),
        status: StackStatus::ReviewInProgress,
        template_body: String::new(),
        parameters: Default::default(),
        resources: Vec::new(),
        outputs: Vec::new(),
        events: vec![event(
            &cs.stack_name,
            STACK_TYPE,
            "REVIEW_IN_PROGRESS",
            None,
        )],
        tags: Vec::new(),
        creation_time: now_iso(),
        last_updated_time: None,
    }
}

fn render_stack(stack: &Stack) -> String {
    let outputs: String = stack
        .outputs
        .iter()
        .map(|o| {
            let export = o
                .export_name
                .as_ref()
                .map(|e| text_el("ExportName", e))
                .unwrap_or_default();
            format!(
                "<member>{}{}{}</member>",
                text_el("OutputKey", &o.key),
                text_el("OutputValue", &o.value),
                export
            )
        })
        .collect();
    let params: String = stack
        .parameters
        .iter()
        .map(|(k, v)| {
            format!(
                "<member>{}{}</member>",
                text_el("ParameterKey", k),
                text_el("ParameterValue", v)
            )
        })
        .collect();
    let tags: String = stack
        .tags
        .iter()
        .map(|(k, v)| {
            format!(
                "<member>{}{}</member>",
                text_el("Key", k),
                text_el("Value", v)
            )
        })
        .collect();
    let last_updated = stack
        .last_updated_time
        .as_ref()
        .map(|t| text_el("LastUpdatedTime", t))
        .unwrap_or_default();
    format!(
        "<member>{}{}{}<CreationTime>{}</CreationTime>{}<Outputs>{}</Outputs><Parameters>{}</Parameters><Tags>{}</Tags><DisableRollback>false</DisableRollback><EnableTerminationProtection>false</EnableTerminationProtection></member>",
        text_el("StackId", &stack.stack_id),
        text_el("StackName", &stack.stack_name),
        text_el("StackStatus", stack.status.as_str()),
        xml_escape(&stack.creation_time),
        last_updated,
        outputs,
        params,
        tags,
    )
}

fn render_event(stack: &Stack, e: &StackEvent) -> String {
    let reason = e
        .reason
        .as_ref()
        .map(|r| text_el("ResourceStatusReason", r))
        .unwrap_or_default();
    let physical_id = if e.resource_type == STACK_TYPE {
        stack.stack_id.as_str()
    } else {
        stack
            .resource(&e.logical_id)
            .map(|r| r.physical_id.as_str())
            .unwrap_or(e.logical_id.as_str())
    };
    format!(
        "<member>{}{}{}{}{}{}{}<Timestamp>{}</Timestamp>{}</member>",
        text_el("StackId", &stack.stack_id),
        text_el("StackName", &stack.stack_name),
        text_el("EventId", &e.event_id),
        text_el("LogicalResourceId", &e.logical_id),
        text_el("PhysicalResourceId", physical_id),
        text_el("ResourceType", &e.resource_type),
        text_el("ResourceStatus", &e.status),
        xml_escape(&e.timestamp),
        reason,
    )
}

fn render_resource_detail(stack: &Stack, r: &StackResource) -> String {
    format!("<member>{}</member>", resource_detail_inner(stack, r))
}

fn resource_detail_inner(stack: &Stack, r: &StackResource) -> String {
    format!(
        "{}{}{}{}{}{}<Timestamp>{}</Timestamp><LastUpdatedTimestamp>{}</LastUpdatedTimestamp>",
        text_el("StackId", &stack.stack_id),
        text_el("StackName", &stack.stack_name),
        text_el("LogicalResourceId", &r.logical_id),
        text_el("PhysicalResourceId", &r.physical_id),
        text_el("ResourceType", &r.resource_type),
        text_el("ResourceStatus", &r.status),
        xml_escape(&stack.creation_time),
        xml_escape(&stack.creation_time),
    )
}

fn event(
    logical_id: &str,
    resource_type: &str,
    status: &str,
    reason: Option<String>,
) -> StackEvent {
    StackEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        logical_id: logical_id.to_string(),
        resource_type: resource_type.to_string(),
        status: status.to_string(),
        reason,
        timestamp: now_iso(),
    }
}

fn make_stack_id(region: &str, account: &str, name: &str) -> String {
    format!(
        "arn:aws:cloudformation:{region}:{account}:stack/{name}/{}",
        uuid::Uuid::new_v4()
    )
}

fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Parse `(bucket, key)` from an S3 object URL in path-style or virtual-hosted form.
fn parse_s3_url(url: &str) -> Option<(String, String)> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let (authority, path) = rest.split_once('/')?;
    let host = authority.split(':').next().unwrap_or(authority);
    // Virtual-hosted: <bucket>.s3... → bucket in host, key is the whole path.
    if let Some(idx) = host.find(".s3.").or_else(|| host.find(".s3-")) {
        let bucket = &host[..idx];
        if !bucket.is_empty() {
            return Some((bucket.to_string(), path.to_string()));
        }
    }
    // Path-style: /<bucket>/<key...>
    let (bucket, key) = path.split_once('/')?;
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    Some((bucket.to_string(), key.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct TestS3 {
        failed_put: Option<&'static str>,
        /// A PUT to this path answers 409 (bucket name already taken).
        existing: Option<&'static str>,
        fail_delete: bool,
        requests: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl NativeHandler for TestS3 {
        async fn handle(&self, request: ServiceRequest) -> Response {
            let path = request.uri.path().to_string();
            self.requests
                .lock()
                .expect("test S3 request lock")
                .push(format!("{} {path}", request.method));
            let taken = request.method == Method::PUT && self.existing == Some(path.as_str());
            let should_fail = (request.method == Method::PUT
                && self.failed_put == Some(path.as_str()))
                || (request.method == Method::DELETE && self.fail_delete);
            let status = if taken {
                409
            } else if should_fail {
                500
            } else {
                200
            };
            Response::builder()
                .status(status)
                .body(Body::empty())
                .expect("test S3 response")
        }
    }

    fn handler_with_s3(s3: Arc<TestS3>) -> (Arc<ServiceRegistry>, CfnHandler) {
        let registry = Arc::new(ServiceRegistry::new());
        registry.register_native(
            ServiceName::new("s3"),
            ServiceMetadata::new(AwsProtocol::RestXml, None),
            s3,
        );
        let handler = CfnHandler::new(Arc::downgrade(&registry));
        (registry, handler)
    }

    fn failing_create_template() -> Template {
        Template::parse(
            &serde_json::json!({
                "Resources": {
                    "First": {
                        "Type": "AWS::S3::Bucket",
                        "Properties": { "BucketName": "first" }
                    },
                    "Second": {
                        "Type": "AWS::S3::Bucket",
                        "DependsOn": "First",
                        "Properties": { "BucketName": "second" }
                    }
                }
            })
            .to_string(),
        )
        .expect("valid test template")
    }

    #[test]
    fn parse_path_style_and_virtual_hosted_urls() {
        assert_eq!(
            parse_s3_url("http://localhost:4599/my-bucket/templates/a.json"),
            Some(("my-bucket".to_string(), "templates/a.json".to_string()))
        );
        assert_eq!(
            parse_s3_url("https://my-bucket.s3.us-east-1.amazonaws.com/templates/a.json"),
            Some(("my-bucket".to_string(), "templates/a.json".to_string()))
        );
    }

    #[tokio::test]
    async fn failed_create_removes_resources_cleaned_up_successfully() {
        let s3 = Arc::new(TestS3 {
            failed_put: Some("/second"),
            existing: None,
            fail_delete: false,
            requests: Mutex::new(Vec::new()),
        });
        let (_registry, handler) = handler_with_s3(s3.clone());
        let template = failing_create_template();
        let conditions = template
            .evaluate_conditions("us-east-1", "000000000000", &BTreeMap::new())
            .unwrap();
        let active = template.active_resources(&conditions).unwrap();
        let output_exprs = template.active_outputs(&conditions, &active).unwrap();
        let (status, resources, _, events) = handler
            .provision(
                "stack",
                "stack-id",
                &template,
                &BTreeMap::new(),
                "us-east-1",
                "000000000000",
                true,
                &[],
                None,
                &conditions,
                &active,
                &output_exprs,
            )
            .await;

        assert_eq!(status, StackStatus::CreateFailed);
        assert!(resources.is_empty());
        assert!(events
            .iter()
            .any(|event| { event.logical_id == "First" && event.status == "DELETE_COMPLETE" }));
        assert_eq!(
            *s3.requests.lock().expect("test S3 request lock"),
            ["PUT /first", "PUT /second", "DELETE /first"]
        );
    }

    #[tokio::test]
    async fn failed_create_retains_cleanup_failure_diagnostic() {
        let s3 = Arc::new(TestS3 {
            failed_put: Some("/second"),
            existing: None,
            fail_delete: true,
            requests: Mutex::new(Vec::new()),
        });
        let (_registry, handler) = handler_with_s3(s3);
        let template = failing_create_template();
        let conditions = template
            .evaluate_conditions("us-east-1", "000000000000", &BTreeMap::new())
            .unwrap();
        let active = template.active_resources(&conditions).unwrap();
        let output_exprs = template.active_outputs(&conditions, &active).unwrap();
        let (status, resources, _, events) = handler
            .provision(
                "stack",
                "stack-id",
                &template,
                &BTreeMap::new(),
                "us-east-1",
                "000000000000",
                true,
                &[],
                None,
                &conditions,
                &active,
                &output_exprs,
            )
            .await;

        assert_eq!(status, StackStatus::CreateFailed);
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].status, "DELETE_FAILED");
        assert!(events.iter().any(|event| {
            event.logical_id == "stack"
                && event
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("rollback failed: First"))
        }));
    }

    #[tokio::test]
    async fn failed_delete_retains_stack_resource_and_events() {
        let s3 = Arc::new(TestS3 {
            failed_put: None,
            existing: None,
            fail_delete: true,
            requests: Mutex::new(Vec::new()),
        });
        let (_registry, handler) = handler_with_s3(s3);
        let template_body = serde_json::json!({
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": { "BucketName": "bucket" }
                }
            }
        })
        .to_string();
        handler.store.put(
            "000000000000",
            "us-east-1",
            Stack {
                stack_id: "stack-id".into(),
                stack_name: "stack".into(),
                status: StackStatus::CreateComplete,
                template_body,
                parameters: BTreeMap::new(),
                resources: vec![StackResource {
                    logical_id: "Bucket".into(),
                    physical_id: "bucket".into(),
                    resource_type: "AWS::S3::Bucket".into(),
                    status: "CREATE_COMPLETE".into(),
                    attributes: BTreeMap::new(),
                }],
                outputs: Vec::new(),
                events: Vec::new(),
                tags: Vec::new(),
                creation_time: now_iso(),
                last_updated_time: None,
            },
        );

        handler
            .delete_stack(
                &Query::parse(b"StackName=stack"),
                "us-east-1",
                "000000000000",
            )
            .await
            .expect("DeleteStack response");

        let stack = handler
            .store
            .get("000000000000", "us-east-1", "stack")
            .expect("failed stack remains stored");
        assert_eq!(stack.status, StackStatus::DeleteFailed);
        assert_eq!(stack.resources[0].status, "DELETE_FAILED");
        assert!(stack
            .events
            .iter()
            .any(|event| { event.logical_id == "Bucket" && event.status == "DELETE_FAILED" }));
        assert!(stack
            .events
            .iter()
            .any(|event| { event.logical_id == "stack" && event.status == "DELETE_FAILED" }));
    }

    fn policy_template(bucket_name: &str, retain_on_replace: bool) -> Template {
        let mut bucket = serde_json::json!({
            "Type": "AWS::S3::Bucket",
            "Properties": { "BucketName": bucket_name }
        });
        if retain_on_replace {
            bucket["UpdateReplacePolicy"] = serde_json::json!("Retain");
        }
        Template::parse(&serde_json::json!({ "Resources": { "Bucket": bucket } }).to_string())
            .expect("valid policy template")
    }

    async fn run_provision(
        handler: &CfnHandler,
        template: &Template,
        creating: bool,
        existing: &[StackResource],
        previous: Option<&Template>,
    ) -> (
        StackStatus,
        Vec<StackResource>,
        Vec<Output>,
        Vec<StackEvent>,
    ) {
        let conditions = template
            .evaluate_conditions("us-east-1", "000000000000", &BTreeMap::new())
            .expect("conditions");
        let active = template
            .active_resources(&conditions)
            .expect("active resources");
        let output_exprs = template
            .active_outputs(&conditions, &active)
            .expect("outputs");
        let previous_parameters = BTreeMap::new();
        handler
            .provision(
                "stack",
                "stack-id",
                template,
                &BTreeMap::new(),
                "us-east-1",
                "000000000000",
                creating,
                existing,
                previous.map(|t| (t, &previous_parameters)),
                &conditions,
                &active,
                &output_exprs,
            )
            .await
    }

    #[tokio::test]
    async fn update_replacement_applies_update_replace_policy() {
        let s3 = Arc::new(TestS3 {
            failed_put: None,
            existing: None,
            fail_delete: false,
            requests: Mutex::new(Vec::new()),
        });
        let (_registry, handler) = handler_with_s3(s3.clone());
        let initial = policy_template("old", true);
        let (status, resources, _, _) = run_provision(&handler, &initial, true, &[], None).await;
        assert_eq!(status, StackStatus::CreateComplete);

        let renamed = policy_template("new", true);
        let (status, resources, _, _) =
            run_provision(&handler, &renamed, false, &resources, Some(&initial)).await;
        assert_eq!(status, StackStatus::UpdateComplete);
        assert_eq!(resources[0].physical_id, "new");
        // `UpdateReplacePolicy: Retain` keeps the old physical bucket.
        assert_eq!(
            *s3.requests.lock().expect("test S3 request lock"),
            ["PUT /old", "PUT /new"]
        );

        let renamed_again = policy_template("third", false);
        let (status, resources, _, _) =
            run_provision(&handler, &renamed_again, false, &resources, Some(&renamed)).await;
        assert_eq!(status, StackStatus::UpdateComplete);
        assert_eq!(resources[0].physical_id, "third");
        // Without the policy the replaced bucket is deleted.
        assert_eq!(
            s3.requests
                .lock()
                .expect("test S3 request lock")
                .last()
                .map(String::as_str),
            Some("DELETE /new")
        );
    }

    #[tokio::test]
    async fn update_rollback_deletes_newly_created_retain_except_on_create() {
        let s3 = Arc::new(TestS3 {
            failed_put: Some("/c"),
            existing: None,
            fail_delete: false,
            requests: Mutex::new(Vec::new()),
        });
        let (_registry, handler) = handler_with_s3(s3.clone());
        let initial = Template::parse(
            &serde_json::json!({
                "Resources": {
                    "A": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "a"}},
                    "E": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "e"}}
                }
            })
            .to_string(),
        )
        .expect("valid template");
        let (_, resources, _, _) = run_provision(&handler, &initial, true, &[], None).await;

        let update = Template::parse(
            &serde_json::json!({
                "Resources": {
                    "A": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "a", "VersioningConfiguration": {"Status": "Enabled"}}},
                    "E": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "e"}},
                    "Mid": {"Type": "AWS::S3::Bucket", "DeletionPolicy": "RetainExceptOnCreate", "Properties": {"BucketName": "b"}},
                    "ZFail": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "c"}}
                }
            })
            .to_string(),
        )
        .expect("valid template");
        let (status, resources, _, events) =
            run_provision(&handler, &update, false, &resources, Some(&initial)).await;

        assert_eq!(status, StackStatus::UpdateFailed);
        // The rolled-back resource is out of stack scope again; A and E survive the rollback.
        assert_eq!(
            resources
                .iter()
                .map(|resource| resource.logical_id.as_str())
                .collect::<Vec<_>>(),
            ["A", "E"]
        );
        let requests = s3.requests.lock().expect("test S3 request lock").clone();
        // Rollback tears down the update's own creation even under RetainExceptOnCreate.
        assert!(requests.contains(&"DELETE /b".to_string()), "{requests:?}");
        assert!(!requests.contains(&"DELETE /a".to_string()), "{requests:?}");
        assert!(events
            .iter()
            .any(|event| { event.logical_id == "stack" && event.status == "UPDATE_FAILED" }));
    }

    #[tokio::test]
    async fn create_stack_fails_when_bucket_name_is_taken() {
        let s3 = Arc::new(TestS3 {
            failed_put: None,
            existing: Some("/taken"),
            fail_delete: false,
            requests: Mutex::new(Vec::new()),
        });
        let (_registry, handler) = handler_with_s3(s3.clone());
        let template = Template::parse(
            &serde_json::json!({
                "Resources": {
                    "B": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "taken"}}
                }
            })
            .to_string(),
        )
        .expect("valid template");
        let (status, resources, _, events) =
            run_provision(&handler, &template, true, &[], None).await;

        assert_eq!(status, StackStatus::CreateFailed);
        assert!(resources.is_empty());
        assert!(events.iter().any(|event| {
            event.logical_id == "B"
                && event.status == "CREATE_FAILED"
                && event
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("409"))
        }));
    }

    #[tokio::test]
    async fn delete_stack_retains_retain_except_on_create_bucket() {
        let s3 = Arc::new(TestS3 {
            failed_put: None,
            existing: None,
            fail_delete: false,
            requests: Mutex::new(Vec::new()),
        });
        let (_registry, handler) = handler_with_s3(s3.clone());
        let template_body = serde_json::json!({
            "Resources": {
                "Kept": {"Type": "AWS::S3::Bucket", "DeletionPolicy": "RetainExceptOnCreate", "Properties": {"BucketName": "kept"}},
                "Eph": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "eph"}}
            }
        })
        .to_string();
        handler.store.put(
            "000000000000",
            "us-east-1",
            Stack {
                stack_id: "stack-id".into(),
                stack_name: "stack".into(),
                status: StackStatus::CreateComplete,
                template_body,
                parameters: BTreeMap::new(),
                resources: vec![
                    StackResource {
                        logical_id: "Kept".into(),
                        physical_id: "kept".into(),
                        resource_type: "AWS::S3::Bucket".into(),
                        status: "CREATE_COMPLETE".into(),
                        attributes: BTreeMap::new(),
                    },
                    StackResource {
                        logical_id: "Eph".into(),
                        physical_id: "eph".into(),
                        resource_type: "AWS::S3::Bucket".into(),
                        status: "CREATE_COMPLETE".into(),
                        attributes: BTreeMap::new(),
                    },
                ],
                outputs: Vec::new(),
                events: Vec::new(),
                tags: Vec::new(),
                creation_time: now_iso(),
                last_updated_time: None,
            },
        );

        handler
            .delete_stack(
                &Query::parse(b"StackName=stack"),
                "us-east-1",
                "000000000000",
            )
            .await
            .expect("DeleteStack response");

        assert!(
            handler
                .store
                .get("000000000000", "us-east-1", "stack")
                .is_none(),
            "stack deletes fully while retained resources stay behind"
        );
        assert_eq!(
            *s3.requests.lock().expect("test S3 request lock"),
            ["DELETE /eph"]
        );
    }
}
