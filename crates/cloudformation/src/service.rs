//! CloudFormation service handler: Query-protocol dispatch, stack lifecycle orchestration,
//! and XML responses. Registered `Native` in the Core registry.

use std::collections::{BTreeMap, BTreeSet};
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
use crate::template::{resolve, ResolveCtx, ResolvedResource, ResourcePolicy, Template};
use crate::xml::{query_envelope, text_el, xml_escape};

const STACK_TYPE: &str = "AWS::CloudFormation::Stack";

pub struct CfnHandler {
    store: Arc<CfnStore>,
    registry: Weak<ServiceRegistry>,
    caller_access_key: Option<String>,
}

impl CfnHandler {
    fn new(registry: Weak<ServiceRegistry>) -> Self {
        CfnHandler {
            store: CfnStore::new(),
            registry,
            caller_access_key: None,
        }
    }

    fn provisioner(&self, region: &str, account: &str) -> Provisioner {
        Provisioner::new(
            self.registry.clone(),
            region.to_string(),
            account.to_string(),
        )
        .with_caller_access_key(self.caller_access_key.clone())
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
            "ListStacks" => Ok(self.list_stacks(q, region, account)),
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
            let mut headers = http::HeaderMap::new();
            headers.insert("host", http::HeaderValue::from_static("localhost:4566"));
            let (status, bytes) = self
                .provisioner(region, account)
                .call(
                    "s3",
                    Method::GET,
                    &format!("/{bucket}/{key}"),
                    headers,
                    Bytes::new(),
                )
                .await?;
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
        let params = effective_parameters(q, &template, existing.as_ref())?;
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
        request
            .params
            .retain(|key, _| !key.starts_with("Parameters.member."));
        for (index, (name, value)) in params.iter().enumerate() {
            request.params.insert(
                format!("Parameters.member.{}.ParameterKey", index + 1),
                name.clone(),
            );
            request.params.insert(
                format!("Parameters.member.{}.ParameterValue", index + 1),
                value.clone(),
            );
        }
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
        let parameters = effective_parameters(q, &template, None)?;
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
        let mut existing = self
            .store
            .find(account, region, &name)
            .ok_or_else(|| CfnError::Validation(format!("Stack [{name}] does not exist")))?;
        let body = self.resolve_template_body(q, region, account).await?;
        let template = Template::parse(&body)?;
        check_capabilities(q, &template)?;
        let previous_template = Template::parse(&existing.template_body)?;
        let parameters = effective_parameters(q, &template, Some(&existing))?;
        let conditions = template.evaluate_conditions(region, account, &parameters)?;
        let active = template.active_resources(&conditions)?;
        let output_exprs = template.active_outputs(&conditions, &active)?;

        if existing
            .resources
            .iter()
            .any(|resource| !resource.pending_cleanup.is_empty())
        {
            let failed = cleanup_network_replacements(
                &self.provisioner(region, account),
                &mut existing.resources,
                &mut existing.events,
            )
            .await;
            self.store.put(account, region, existing.clone());
            if failed {
                return Err(CfnError::Validation(
                    "Previous network replacement cleanup is still pending; inspect stack events"
                        .into(),
                ));
            }
        }

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
            if stack.status == StackStatus::DeleteComplete {
                return Ok(String::new());
            }
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
            // Retired targets are kept in the stack until cleanup really succeeds.
            let mut replacement_events = Vec::new();
            cleanup_network_replacements(
                &provisioner,
                &mut stack.resources,
                &mut replacement_events,
            )
            .await;
            stack.events.extend(replacement_events);
            let mut remaining = stack.resources.clone();
            let mut failures = Vec::new();

            // Updates can add a new dependency after its existing dependent in storage order.
            // Use the current template graph for teardown, then include any retained old entries.
            let mut deletion_order: Vec<_> = template
                .active_resources(&conditions)?
                .into_iter()
                .rev()
                .filter_map(|declaration| {
                    stack
                        .resources
                        .iter()
                        .find(|resource| resource.logical_id == declaration.logical_id)
                })
                .collect();
            let ordered_ids: BTreeSet<_> = deletion_order
                .iter()
                .map(|resource| resource.logical_id.as_str())
                .collect();
            deletion_order.extend(
                stack
                    .resources
                    .iter()
                    .rev()
                    .filter(|resource| !ordered_ids.contains(resource.logical_id.as_str())),
            );
            // Producers can recreate a managed group while an invocation is draining.
            // Stable sorting preserves the graph order of every other resource.
            deletion_order.sort_by_key(|resource| resource.resource_type == "AWS::Logs::LogGroup");
            // Continue after failures so independent resources still get a cleanup attempt.
            for resource in deletion_order {
                if matches!(
                    resource.status.as_str(),
                    "DELETE_COMPLETE" | "DELETE_SKIPPED"
                ) {
                    continue;
                }
                if !resource.pending_cleanup.is_empty() {
                    failures.push(format!(
                        "{}: retired replacement cleanup is pending",
                        resource.logical_id
                    ));
                    continue;
                }
                if declarations
                    .get(&resource.logical_id)
                    .is_some_and(|decl| decl.deletion_policy.retains_on_delete())
                {
                    if let Some(candidate) = remaining
                        .iter_mut()
                        .find(|candidate| candidate.logical_id == resource.logical_id)
                    {
                        candidate.status = "DELETE_SKIPPED".into();
                    }
                    stack.events.push(event(
                        &resource.logical_id,
                        &resource.resource_type,
                        "DELETE_SKIPPED",
                        Some("retained by DeletionPolicy".into()),
                    ));
                    continue;
                }
                if resource.resource_type == "AWS::Logs::LogGroup"
                    && remaining.iter().any(|candidate| {
                        matches!(
                            candidate.resource_type.as_str(),
                            "AWS::Lambda::Function" | "AWS::StepFunctions::StateMachine"
                        ) && candidate.status == "DELETE_FAILED"
                    })
                {
                    let reason =
                        "Log group cleanup deferred because a stack log producer failed deletion"
                            .to_owned();
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
                    continue;
                }
                let properties = declarations
                    .get(&resource.logical_id)
                    .map(|decl| resolve(&decl.properties, &ctx))
                    .transpose()
                    .map(|properties| properties.unwrap_or(Value::Null));
                stack.events.push(event(
                    &resource.logical_id,
                    &resource.resource_type,
                    "DELETE_IN_PROGRESS",
                    None,
                ));
                let log_notice = if resource.resource_type == "AWS::Lambda::Function" {
                    let group = format!("/aws/lambda/{}", resource.physical_id);
                    if stack.resources.iter().any(|candidate| {
                        candidate.resource_type == "AWS::Logs::LogGroup"
                            && candidate.physical_id == group
                    }) {
                        None
                    } else {
                        match provisioner.associated_lambda_log_group(&resource.physical_id).await {
                            Ok(Some(group)) => Some(format!("Associated log group {group} is not managed by this stack and remains after Lambda deletion")),
                            Ok(None) => None,
                            Err(error) => Some(format!("Could not verify associated log group {group}: {error}")),
                        }
                    }
                } else {
                    None
                };
                let deletion = match properties {
                    Ok(properties) => {
                        provisioner
                            .deprovision(
                                &resource.resource_type,
                                &resource.physical_id,
                                &properties,
                            )
                            .await
                    }
                    Err(error) => Err(error),
                };
                match deletion {
                    Ok(()) => {
                        if let Some(candidate) = remaining
                            .iter_mut()
                            .find(|candidate| candidate.logical_id == resource.logical_id)
                        {
                            candidate.status = "DELETE_COMPLETE".into();
                        }
                        stack.events.push(event(
                            &resource.logical_id,
                            &resource.resource_type,
                            "DELETE_COMPLETE",
                            log_notice,
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
                stack.status = StackStatus::DeleteComplete;
                stack.resources = remaining;
                stack.last_updated_time = Some(now_iso());
                stack.events.push(event(
                    &stack.stack_name,
                    STACK_TYPE,
                    "DELETE_COMPLETE",
                    None,
                ));
                self.store.archive(account, region, stack);
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
                deferred_previous: Option<ResolvedResource>,
                replacement_policy: ResourcePolicy,
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

        // Resolve prior resource properties before any destructive reconciliation. A missing
        // attribute must preserve the old graph, not become an empty lifecycle argument.
        let prior_properties = existing
            .iter()
            .map(|resource| {
                let properties = previous_declarations
                    .get(&resource.logical_id)
                    .zip(previous_ctx.as_ref())
                    .ok_or_else(|| {
                        CfnError::Validation(format!(
                            "previous declaration for {} is unavailable",
                            resource.logical_id
                        ))
                    })?;
                Ok((
                    resource.logical_id.clone(),
                    resolve(&properties.0.properties, properties.1)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, CfnError>>();
        let prior_properties = match prior_properties {
            Ok(properties) => properties,
            Err(error) => {
                return (
                    StackStatus::UpdateFailed,
                    existing.to_vec(),
                    Vec::new(),
                    vec![event(
                        stack_name,
                        STACK_TYPE,
                        "UPDATE_FAILED",
                        Some(error.to_string()),
                    )],
                )
            }
        };

        // A type change reuses a logical ID, so its old resource is removed first.
        // Pure removals stay in physical inventory until dependents have been updated.
        let mut removal_failures = BTreeMap::new();
        for resource in existing.iter().rev().filter(|resource| {
            declarations
                .get(&resource.logical_id)
                .is_some_and(|decl| decl.resource_type != resource.resource_type)
        }) {
            if previous_declarations
                .get(&resource.logical_id)
                .is_some_and(|decl| decl.deletion_policy.retains_on_delete())
            {
                continue;
            }
            let properties = prior_properties
                .get(&resource.logical_id)
                .cloned()
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
                        .is_none_or(|decl| decl.resource_type == resource.resource_type)
            })
            .cloned()
            .collect();
        // Previous dependency order also covers dependencies introduced by prior updates.
        let previous_order: BTreeMap<_, _> = previous
            .and_then(|(template, _)| template.active_resources(&previous_conditions).ok())
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(index, declaration)| (declaration.logical_id, index))
            .collect();
        resources.sort_by_key(|resource| {
            previous_order
                .get(&resource.logical_id)
                .copied()
                .unwrap_or(usize::MAX)
        });
        let mut resolved: BTreeMap<String, ResolvedResource> = resources
            .iter()
            .filter(|resource| {
                declarations
                    .get(&resource.logical_id)
                    .is_some_and(|decl| decl.resource_type == resource.resource_type)
            })
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
            let props = match resolve(&decl.properties, &ctx) {
                Ok(properties) => properties,
                Err(error) => {
                    events.push(event(
                        &decl.logical_id,
                        &decl.resource_type,
                        failed_status,
                        Some(error.to_string()),
                    ));
                    failure_reason = Some(error.to_string());
                    break;
                }
            };
            if let Some(current) = resolved.get(&decl.logical_id).cloned() {
                let previous_properties = prior_properties
                    .get(&decl.logical_id)
                    .cloned()
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
                            deferred_previous: (matches!(
                                decl.resource_type.as_str(),
                                "AWS::EC2::NatGateway"
                                    | "AWS::EC2::Route"
                                    | "AWS::EC2::VPCGatewayAttachment"
                            ) && current.ref_value != updated.ref_value)
                                .then_some(current),
                            replacement_policy: decl.update_replace_policy,
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
                        pending_cleanup: Vec::new(),
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

        // Resolve outputs before retiring old dependencies, so failures use the same rollback.
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
            .map(|(key, value, export)| {
                Ok(Output {
                    key: key.clone(),
                    value: crate::template::resolve_to_string(value, &ctx)?,
                    export_name: export
                        .as_ref()
                        .map(|value| crate::template::resolve_to_string(value, &ctx))
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, CfnError>>();
        let outputs = match outputs {
            Ok(outputs) => outputs,
            Err(error) => {
                failure_reason.get_or_insert_with(|| error.to_string());
                Vec::new()
            }
        };

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
                        deferred_previous,
                        replacement_policy: _,
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
                        let restore = if let Some(previous) = deferred_previous {
                            provisioner
                                .deprovision(resource_type, &current.ref_value, applied_properties)
                                .await
                                .map(|()| previous.clone())
                        } else {
                            provisioner
                                .update(
                                    logical_id,
                                    resource_type,
                                    &current,
                                    applied_properties,
                                    previous_properties,
                                    Replacement::Rollback,
                                )
                                .await
                        };
                        match restore {
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

        for action in &successful_actions {
            if let ReconcileAction::Updated {
                logical_id,
                previous_properties,
                deferred_previous: Some(previous),
                replacement_policy,
                ..
            } = action
            {
                if *replacement_policy != ResourcePolicy::Retain {
                    if let Some(resource) = resources
                        .iter_mut()
                        .find(|resource| resource.logical_id == *logical_id)
                    {
                        resource
                            .pending_cleanup
                            .push(crate::model::ReplacementCleanup {
                                physical_id: previous.ref_value.clone(),
                                properties: previous_properties.clone(),
                            });
                    }
                }
            }
        }
        // Cleanup is last: failed reconciliation can restore the still-live old dependencies.
        for resource in &mut resources {
            if !declarations.contains_key(&resource.logical_id) {
                if previous_declarations
                    .get(&resource.logical_id)
                    .is_some_and(|decl| decl.deletion_policy.retains_on_delete())
                {
                    continue;
                }
                let properties = prior_properties
                    .get(&resource.logical_id)
                    .cloned()
                    .unwrap_or(Value::Null);
                resource
                    .pending_cleanup
                    .push(crate::model::ReplacementCleanup {
                        physical_id: resource.physical_id.clone(),
                        properties,
                    });
            }
        }
        resources.retain(|resource| {
            declarations.contains_key(&resource.logical_id) || !resource.pending_cleanup.is_empty()
        });
        let cleanup_failed =
            cleanup_network_replacements(&provisioner, &mut resources, &mut events).await;

        let status = if creating {
            StackStatus::CreateComplete
        } else if cleanup_failed {
            StackStatus::UpdateCompleteCleanupInProgress
        } else {
            StackStatus::UpdateComplete
        };
        events.push(event(stack_name, STACK_TYPE, status.as_str(), None));
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
                    "<member>{}{}{}{}{}<LastUpdatedTimestamp>{}</LastUpdatedTimestamp></member>",
                    text_el("LogicalResourceId", &r.logical_id),
                    text_el("PhysicalResourceId", &r.physical_id),
                    text_el("ResourceType", &r.resource_type),
                    text_el("ResourceStatus", &r.status),
                    resource_status_reason(&stack, r),
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

    fn list_stacks(&self, q: &Query, region: &str, account: &str) -> String {
        let filters: Vec<_> = q
            .params
            .iter()
            .filter(|(key, _)| key.starts_with("StackStatusFilter.member."))
            .map(|(_, value)| value.as_str())
            .collect();
        let members: String = self
            .store
            .list_with_deleted(account, region)
            .iter()
            .filter(|s| filters.is_empty() || filters.contains(&s.status.as_str()))
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
    async fn resource_regions(&self, account: &str) -> Result<Vec<String>, &'static str> {
        self.store.resource_regions(account)
    }

    async fn handle(&self, request: ServiceRequest) -> Response {
        let q = Query::parse(&request.body);
        let op = match q.action() {
            Some(op) => op,
            None => {
                return CfnError::Validation("missing Action".into())
                    .into_response(&request.request_id)
            }
        };
        if matches!(
            op.as_str(),
            "ListStacks"
                | "DescribeStacks"
                | "DescribeStackEvents"
                | "DescribeStackResources"
                | "DescribeStackResource"
                | "ListStackResources"
                | "GetTemplate"
                | "GetTemplateSummary"
                | "DescribeChangeSet"
        ) {
            let stack_name = q.get("StackName");
            let resource = if op == "DescribeChangeSet" {
                self.lookup_change_set(&q, &request.region, &request.account_id)
                    .ok()
                    .map(|change| change.stack_id)
            } else {
                stack_name
                    .as_deref()
                    .and_then(|name| self.store.find(&request.account_id, &request.region, name))
                    .map(|stack| stack.stack_id)
            }
            .unwrap_or_else(|| "*".into());
            let allowed = locallycloud_core::integration::authorization::authorize_native_read(
                &self.registry,
                &request,
                "cloudformation",
                &format!("cloudformation:{op}"),
                &resource,
            )
            .is_ok();
            let list_allowed = op != "DescribeStacks"
                || stack_name.is_some()
                || locallycloud_core::integration::authorization::authorize_native_read(
                    &self.registry,
                    &request,
                    "cloudformation",
                    "cloudformation:ListStacks",
                    "*",
                )
                .is_ok();
            if !allowed || !list_allowed {
                return locallycloud_core::error_mapping::AwsError::new(
                    "AccessDenied",
                    "Not authorized to read CloudFormation resources",
                    403,
                )
                .with_request_id(request.request_id.clone())
                .with_xml_namespace(crate::error::CFN_XMLNS)
                .render(AwsProtocol::Query)
                .into_response();
            }
        }
        let execution = Self {
            store: self.store.clone(),
            registry: self.registry.clone(),
            caller_access_key: request
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(
                    locallycloud_core::integration::RequestIdentity::access_key_from_authorization,
                ),
        };
        match execution
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

fn parameter_no_echo(definition: &Value) -> bool {
    definition
        .get("NoEcho")
        .is_some_and(|value| value == true || value.as_str() == Some("true"))
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
                parameter_no_echo(definition)
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

fn effective_parameters(
    q: &Query,
    template: &Template,
    previous: Option<&Stack>,
) -> Result<BTreeMap<String, String>, CfnError> {
    let declarations: BTreeMap<_, _> = template.parameter_declarations().into_iter().collect();
    let previous = previous
        .map(|stack| {
            Template::parse(&stack.template_body)
                .map(|template| template.effective_parameters(&stack.parameters))
        })
        .transpose()?;
    let mut supplied = BTreeMap::new();
    let mut index = 1;
    while let Some(name) = q
        .params
        .get(&format!("Parameters.member.{index}.ParameterKey"))
    {
        if !declarations.contains_key(name) || supplied.contains_key(name) {
            return Err(CfnError::Validation(format!(
                "Unknown or duplicate parameter {name}"
            )));
        }
        let value = q
            .params
            .get(&format!("Parameters.member.{index}.ParameterValue"));
        let use_previous = match q
            .params
            .get(&format!("Parameters.member.{index}.UsePreviousValue"))
            .map(String::as_str)
        {
            None | Some("false") => false,
            Some("true") => true,
            _ => {
                return Err(CfnError::Validation(
                    "UsePreviousValue must be true or false".into(),
                ))
            }
        };
        let resolved = if use_previous {
            if value.is_some() {
                return Err(CfnError::Validation(format!(
                    "Parameter {name} cannot specify both ParameterValue and UsePreviousValue"
                )));
            }
            previous
                .as_ref()
                .and_then(|values| values.get(name))
                .cloned()
                .ok_or_else(|| {
                    CfnError::Validation(format!("Parameter {name} has no previous value"))
                })?
        } else if let Some(value) = value {
            value.clone()
        } else if let Some(value) = declarations[name].get("Default") {
            value_to_text(value)
        } else {
            return Err(CfnError::Validation(format!(
                "Parameter {name} requires a value"
            )));
        };
        supplied.insert(name.clone(), resolved);
        index += 1;
    }
    let parameters = template.effective_parameters(&supplied);
    for name in declarations.keys() {
        if !parameters.contains_key(name) {
            return Err(CfnError::Validation(format!(
                "Parameter {name} requires a value"
            )));
        }
    }
    Ok(parameters)
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
    // Report effective defaults without mutating the stored values used by Ref/provisioning.
    let declarations = Template::parse(&stack.template_body)
        .ok()
        .map(|template| template.parameter_declarations());
    let parameters = Template::parse(&stack.template_body)
        .map(|template| template.effective_parameters(&stack.parameters))
        .unwrap_or_else(|_| stack.parameters.clone());
    let params: String = parameters
        .iter()
        .map(|(key, value)| {
            // Corrupt stored templates must not reveal values when masking metadata is unavailable.
            let hidden = declarations.as_ref().is_none_or(|declarations| {
                declarations
                    .iter()
                    .any(|(name, definition)| name == key && parameter_no_echo(definition))
            });
            format!(
                "<member>{}{}</member>",
                text_el("ParameterKey", key),
                text_el("ParameterValue", if hidden { "*****" } else { value })
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
    let status_reason = stack
        .events
        .iter()
        .rev()
        .find(|event| event.resource_type == STACK_TYPE && event.status == stack.status.as_str())
        .and_then(|event| event.reason.as_deref())
        .map(|reason| text_el("StackStatusReason", reason))
        .unwrap_or_default();
    let last_updated = stack
        .last_updated_time
        .as_ref()
        .map(|t| text_el("LastUpdatedTime", t))
        .unwrap_or_default();
    format!(
        "<member>{}{}{}<CreationTime>{}</CreationTime>{}{}<Outputs>{}</Outputs><Parameters>{}</Parameters><Tags>{}</Tags><DisableRollback>false</DisableRollback><EnableTerminationProtection>false</EnableTerminationProtection></member>",
        text_el("StackId", &stack.stack_id),
        text_el("StackName", &stack.stack_name),
        text_el("StackStatus", stack.status.as_str()),
        xml_escape(&stack.creation_time),
        last_updated,
        status_reason,
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

fn resource_status_reason(stack: &Stack, r: &StackResource) -> String {
    stack
        .events
        .iter()
        .rev()
        .find(|event| event.logical_id == r.logical_id && event.status == r.status)
        .and_then(|event| event.reason.as_deref())
        .map(|reason| text_el("ResourceStatusReason", reason))
        .unwrap_or_default()
}

fn resource_detail_inner(stack: &Stack, r: &StackResource) -> String {
    let reason = resource_status_reason(stack, r);
    format!(
        "{}{}{}{}{}{}{}<Timestamp>{}</Timestamp><LastUpdatedTimestamp>{}</LastUpdatedTimestamp>",
        text_el("StackId", &stack.stack_id),
        text_el("StackName", &stack.stack_name),
        text_el("LogicalResourceId", &r.logical_id),
        text_el("PhysicalResourceId", &r.physical_id),
        text_el("ResourceType", &r.resource_type),
        text_el("ResourceStatus", &r.status),
        reason,
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

/// Cleanup is deferred until new dependents have switched, and failed physical IDs remain
/// attached to their stack resource for the next update/delete attempt.
async fn cleanup_network_replacements(
    provisioner: &Provisioner,
    resources: &mut Vec<StackResource>,
    events: &mut Vec<StackEvent>,
) -> bool {
    let mut failed = false;
    let mut removed = BTreeSet::new();
    for resource in resources.iter_mut().rev() {
        let mut remaining = Vec::new();
        for retired in resource.pending_cleanup.drain(..).rev() {
            match provisioner
                .deprovision(
                    &resource.resource_type,
                    &retired.physical_id,
                    &retired.properties,
                )
                .await
            {
                Ok(()) => {
                    if retired.physical_id == resource.physical_id {
                        removed.insert(resource.logical_id.clone());
                    }
                    events.push(event(
                        &resource.logical_id,
                        &resource.resource_type,
                        "DELETE_COMPLETE",
                        Some(format!("Retired resource {}", retired.physical_id)),
                    ));
                }
                Err(error) => {
                    if retired.physical_id == resource.physical_id {
                        resource.status = "DELETE_FAILED".into();
                    }
                    events.push(event(
                        &resource.logical_id,
                        &resource.resource_type,
                        "DELETE_FAILED",
                        Some(format!(
                            "Replacement cleanup failed for {}: {error}",
                            retired.physical_id
                        )),
                    ));
                    remaining.push(retired);
                    failed = true;
                }
            }
        }
        remaining.reverse();
        resource.pending_cleanup = remaining;
    }
    resources.retain(|resource| {
        !removed.contains(&resource.logical_id) || !resource.pending_cleanup.is_empty()
    });
    failed
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

    #[tokio::test]
    async fn describe_stack_masks_noecho_effective_parameters_but_preserves_outputs() {
        let (_registry, handler) = handler_with_s3(Arc::new(TestS3 {
            failed_put: None,
            existing: None,
            fail_delete: false,
            requests: Mutex::new(Vec::new()),
        }));
        let raw = serde_json::json!({
            "Parameters": {
                "Secret":{"Type":"String","NoEcho":true,"Default":"default-marker"},
                "LegacySecret":{"Type":"String","NoEcho":"true","Default":"legacy-marker"},
                "Visible":{"Type":"String","Default":"visible-default"},
                "Count":{"Type":"Number","Default":7}
            },
            "Resources":{"Bucket":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"noecho-gate"}}},
            "Outputs":{"DeliberateExposure":{"Value":{"Ref":"Secret"}},
                "DefaultExposure":{"Value":{"Ref":"LegacySecret"}},
                "NumberDefault":{"Value":{"Ref":"Count"}}}
        });
        let query = Query {
            params: BTreeMap::from([
                ("StackName".into(), "noecho-stack".into()),
                ("TemplateBody".into(), raw.to_string()),
                ("Parameters.member.1.ParameterKey".into(), "Secret".into()),
                (
                    "Parameters.member.1.ParameterValue".into(),
                    "effective-marker".into(),
                ),
            ]),
        };
        handler
            .create_stack(&query, "us-east-1", "000000000000", None)
            .await
            .unwrap();
        let stack = handler
            .store
            .find("000000000000", "us-east-1", "noecho-stack")
            .unwrap();
        assert_eq!(stack.status, StackStatus::CreateComplete);
        assert_eq!(stack.parameters["Secret"], "effective-marker");
        let xml = handler
            .describe_stacks(&query, "us-east-1", "000000000000")
            .unwrap();
        let parameters = xml
            .split("<Parameters>")
            .nth(1)
            .unwrap()
            .split("</Parameters>")
            .next()
            .unwrap();
        assert!(parameters
            .contains("<ParameterKey>Secret</ParameterKey><ParameterValue>*****</ParameterValue>"));
        assert!(parameters.contains(
            "<ParameterKey>LegacySecret</ParameterKey><ParameterValue>*****</ParameterValue>"
        ));
        assert!(parameters.contains(
            "<ParameterKey>Visible</ParameterKey><ParameterValue>visible-default</ParameterValue>"
        ));
        assert!(!parameters.contains("effective-marker") && !parameters.contains("legacy-marker"));
        assert!(xml.contains("<OutputValue>effective-marker</OutputValue>"));
        assert!(xml.contains("<OutputValue>legacy-marker</OutputValue>"));
        assert!(xml.contains("<OutputValue>7</OutputValue>"));
        let mut update = query.clone();
        update.params.remove("Parameters.member.1.ParameterValue");
        update
            .params
            .insert("Parameters.member.1.UsePreviousValue".into(), "true".into());
        let mut updated_template = raw.clone();
        updated_template["Parameters"]["Secret"]["Default"] = serde_json::json!("changed-default");
        updated_template["Parameters"]["Count"]["Default"] = serde_json::json!(8);
        update
            .params
            .insert("TemplateBody".into(), updated_template.to_string());
        handler
            .update_stack(&update, "us-east-1", "000000000000")
            .await
            .unwrap();
        let updated = handler
            .store
            .find("000000000000", "us-east-1", "noecho-stack")
            .unwrap();
        assert_eq!(updated.status, StackStatus::UpdateComplete);
        assert_eq!(updated.parameters["Secret"], "effective-marker");
        assert_eq!(updated.parameters["Count"], "8");
        let updated_xml = handler
            .describe_stacks(&query, "us-east-1", "000000000000")
            .unwrap();
        assert!(updated_xml.contains("<OutputValue>effective-marker</OutputValue>"));
        assert!(updated_xml.contains("<OutputValue>8</OutputValue>"));
        // Invalid previous-value requests fail before provisioning or changing state.
        update.params.insert(
            "Parameters.member.1.ParameterValue".into(),
            "conflict".into(),
        );
        assert!(handler
            .update_stack(&update, "us-east-1", "000000000000")
            .await
            .is_err());
        assert_eq!(
            handler
                .store
                .find("000000000000", "us-east-1", "noecho-stack")
                .unwrap()
                .parameters,
            updated.parameters
        );
        let summary = render_template_summary(&Template::parse(&raw.to_string()).unwrap(), true);
        assert!(
            summary.contains("<DefaultValue>default-marker</DefaultValue><NoEcho>true</NoEcho>")
        );
        // The documented AWS string Boolean form is metadata too, not a masking bypass.
        assert!(summary.contains("<DefaultValue>legacy-marker</DefaultValue><NoEcho>true</NoEcho>"));
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
        let (registry, handler) = handler_with_s3(s3);
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
                    pending_cleanup: Vec::new(),
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
        let query = Query::parse(b"StackName=stack");
        assert!(handler
            .describe_stacks(&query, "us-east-1", "000000000000")
            .unwrap()
            .contains("<StackStatusReason>"));
        assert!(handler
            .describe_stack_resources(&query, "us-east-1", "000000000000")
            .unwrap()
            .contains("<ResourceStatusReason>"));
        let healthy = Arc::new(TestS3 {
            failed_put: None,
            existing: None,
            fail_delete: false,
            requests: Mutex::new(Vec::new()),
        });
        registry.register_native(
            ServiceName::new("s3"),
            ServiceMetadata::new(AwsProtocol::RestXml, None),
            healthy.clone(),
        );
        handler
            .delete_stack(&query, "us-east-1", "000000000000")
            .await
            .unwrap();
        let archived = handler
            .store
            .find("000000000000", "us-east-1", "stack-id")
            .unwrap();
        assert_eq!(archived.status, StackStatus::DeleteComplete);
        assert_eq!(archived.resources[0].status, "DELETE_COMPLETE");
        assert_eq!(*healthy.requests.lock().unwrap(), ["DELETE /bucket"]);
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
    async fn unresolved_outputs_roll_back_created_resources_before_retiring_dependencies() {
        let s3 = Arc::new(TestS3 {
            failed_put: None,
            existing: None,
            fail_delete: false,
            requests: Mutex::new(Vec::new()),
        });
        let (_registry, handler) = handler_with_s3(s3.clone());
        let initial = Template::parse(
            &serde_json::json!({"Resources":{
                "Bucket":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"old"}},
                "Retired":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"retired"}}
            }})
            .to_string(),
        )
        .unwrap();
        let (_, existing, _, _) = run_provision(&handler, &initial, true, &[], None).await;
        s3.requests.lock().unwrap().clear();
        let next = Template::parse(
            &serde_json::json!({"Resources":{
            "Bucket":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"old"}},
            "Added":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"new"}}
        },"Outputs":{"Unavailable":{"Value":{"Fn::Sub":"${Bucket.Missing}"}}}})
            .to_string(),
        )
        .unwrap();
        let (status, resources, outputs, events) =
            run_provision(&handler, &next, false, &existing, Some(&initial)).await;
        assert_eq!(status, StackStatus::UpdateFailed);
        assert!(outputs.is_empty());
        assert_eq!(
            resources
                .iter()
                .map(|resource| resource.logical_id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["Bucket", "Retired"])
        );
        assert_eq!(*s3.requests.lock().unwrap(), ["PUT /new", "DELETE /new"]);
        assert!(events.iter().any(|event| event
            .reason
            .as_ref()
            .is_some_and(|reason| reason.contains("Bucket.Missing"))));
        s3.requests.lock().unwrap().clear();
        let (status, resources, outputs, _) = run_provision(&handler, &next, true, &[], None).await;
        assert_eq!(status, StackStatus::CreateFailed);
        assert!(resources.is_empty() && outputs.is_empty());
        assert_eq!(
            *s3.requests.lock().unwrap(),
            ["PUT /new", "PUT /old", "DELETE /old", "DELETE /new"]
        );
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

    struct DrainingLambdaLogs {
        fail_lambda: std::sync::atomic::AtomicBool,
        groups: Mutex<BTreeSet<String>>,
        calls: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl NativeHandler for DrainingLambdaLogs {
        async fn handle(&self, request: ServiceRequest) -> Response {
            if request.uri.path().starts_with("/2015-03-31/functions/") {
                self.calls.lock().unwrap().push("delete-lambda".into());
                if self.fail_lambda.load(std::sync::atomic::Ordering::SeqCst) {
                    return Response::builder().status(500).body(Body::empty()).unwrap();
                }
                // Model the final log publication of a draining in-flight invocation.
                self.groups
                    .lock()
                    .unwrap()
                    .insert("/aws/lambda/function".into());
            } else {
                assert_eq!(
                    request.headers["x-amz-target"],
                    "Logs_20140328.DeleteLogGroup"
                );
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                self.calls.lock().unwrap().push("delete-log-group".into());
                self.groups
                    .lock()
                    .unwrap()
                    .remove(body["logGroupName"].as_str().unwrap());
            }
            Response::builder()
                .status(200)
                .body(Body::from("{}"))
                .unwrap()
        }
    }
    #[tokio::test]
    async fn managed_log_cleanup_follows_producer_drain_and_retries_failed_producer() {
        let probe = Arc::new(DrainingLambdaLogs {
            fail_lambda: std::sync::atomic::AtomicBool::new(true),
            groups: Mutex::new(BTreeSet::from([
                "/aws/lambda/function".into(),
                "kept".into(),
            ])),
            calls: Mutex::new(Vec::new()),
        });
        let registry = Arc::new(ServiceRegistry::new());
        registry.register_native(
            ServiceName::new("lambda"),
            ServiceMetadata::new(AwsProtocol::RestJson, None),
            probe.clone(),
        );
        registry.register_native(
            ServiceName::new("logs"),
            ServiceMetadata::new(AwsProtocol::Json11, None),
            probe.clone(),
        );
        let handler = CfnHandler::new(Arc::downgrade(&registry));
        let body = serde_json::json!({"Resources": {
            "Function":{"Type":"AWS::Lambda::Function","Properties":{"FunctionName":"function"}},
            "Logs":{"Type":"AWS::Logs::LogGroup","Properties":{"LogGroupName":{"Fn::Sub":"/aws/lambda/${Function}"}}},
            "Kept":{"Type":"AWS::Logs::LogGroup","DeletionPolicy":"Retain","Properties":{"LogGroupName":"kept"}}
        }}).to_string();
        let resources = [
            ("Function", "function", "AWS::Lambda::Function"),
            ("Logs", "/aws/lambda/function", "AWS::Logs::LogGroup"),
            ("Kept", "kept", "AWS::Logs::LogGroup"),
        ]
        .into_iter()
        .map(|(logical_id, physical_id, resource_type)| StackResource {
            logical_id: logical_id.into(),
            physical_id: physical_id.into(),
            resource_type: resource_type.into(),
            status: "CREATE_COMPLETE".into(),
            attributes: BTreeMap::new(),
            pending_cleanup: Vec::new(),
        })
        .collect();
        handler.store.put(
            "000000000000",
            "us-east-1",
            Stack {
                stack_id: "drain-stack-id".into(),
                stack_name: "drain-stack".into(),
                status: StackStatus::CreateComplete,
                template_body: body,
                parameters: BTreeMap::new(),
                resources,
                outputs: Vec::new(),
                events: Vec::new(),
                tags: Vec::new(),
                creation_time: now_iso(),
                last_updated_time: None,
            },
        );
        let query = Query::parse(b"StackName=drain-stack");
        handler
            .delete_stack(&query, "us-east-1", "000000000000")
            .await
            .unwrap();
        let failed = handler
            .store
            .find("000000000000", "us-east-1", "drain-stack")
            .unwrap();
        assert_eq!(failed.status, StackStatus::DeleteFailed);
        assert_eq!(failed.resource("Logs").unwrap().status, "DELETE_FAILED");
        assert_eq!(
            failed.resource("Logs").unwrap().physical_id,
            "/aws/lambda/function"
        );
        assert_eq!(failed.resource("Kept").unwrap().status, "DELETE_SKIPPED");
        assert_eq!(*probe.calls.lock().unwrap(), ["delete-lambda"]);
        assert!(probe
            .groups
            .lock()
            .unwrap()
            .contains("/aws/lambda/function"));
        probe
            .fail_lambda
            .store(false, std::sync::atomic::Ordering::SeqCst);
        handler
            .delete_stack(&query, "us-east-1", "000000000000")
            .await
            .unwrap();
        assert_eq!(
            *probe.calls.lock().unwrap(),
            ["delete-lambda", "delete-lambda", "delete-log-group"]
        );
        assert_eq!(
            *probe.groups.lock().unwrap(),
            BTreeSet::from(["kept".into()])
        );
        let deleted = handler
            .store
            .find("000000000000", "us-east-1", "drain-stack-id")
            .unwrap();
        assert_eq!(deleted.status, StackStatus::DeleteComplete);
        assert_eq!(deleted.resource("Logs").unwrap().status, "DELETE_COMPLETE");
        assert_eq!(deleted.resource("Kept").unwrap().status, "DELETE_SKIPPED");
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
                        pending_cleanup: Vec::new(),
                    },
                    StackResource {
                        logical_id: "Eph".into(),
                        physical_id: "eph".into(),
                        resource_type: "AWS::S3::Bucket".into(),
                        status: "CREATE_COMPLETE".into(),
                        attributes: BTreeMap::new(),
                        pending_cleanup: Vec::new(),
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
        let archived = handler
            .store
            .find("000000000000", "us-east-1", "stack-id")
            .unwrap();
        assert_eq!(archived.status, StackStatus::DeleteComplete);
        assert_eq!(archived.resource("Kept").unwrap().status, "DELETE_SKIPPED");
        assert_eq!(archived.resource("Eph").unwrap().status, "DELETE_COMPLETE");
        let query = Query::parse(b"StackName=stack-id");
        let resources = handler
            .describe_stack_resources(&query, "us-east-1", "000000000000")
            .unwrap();
        assert!(resources.contains("<PhysicalResourceId>kept</PhysicalResourceId>"));
        assert!(resources
            .contains("<ResourceStatusReason>retained by DeletionPolicy</ResourceStatusReason>"));
        assert!(handler
            .describe_stack_events(&query, "us-east-1", "000000000000")
            .unwrap()
            .contains("<PhysicalResourceId>eph</PhysicalResourceId>"));
        assert!(handler
            .describe_stacks(
                &Query::parse(b"StackName=stack"),
                "us-east-1",
                "000000000000"
            )
            .is_err());
        assert!(!handler
            .describe_stacks(&Query::parse(b""), "us-east-1", "000000000000")
            .unwrap()
            .contains("stack-id"));
        assert!(handler
            .list_stacks(
                &Query::parse(b"StackStatusFilter.member.1=DELETE_COMPLETE"),
                "us-east-1",
                "000000000000"
            )
            .contains("stack-id"));
        assert!(!handler
            .list_stacks(
                &Query::parse(b"StackStatusFilter.member.1=CREATE_COMPLETE"),
                "us-east-1",
                "000000000000"
            )
            .contains("stack-id"));
        // Repeated deletion by archived ID cannot delete retained physical resources.
        handler
            .delete_stack(&query, "us-east-1", "000000000000")
            .await
            .unwrap();
        assert_eq!(s3.requests.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn removed_resource_cleanup_failure_keeps_inventory_until_retry() {
        let failing = Arc::new(TestS3 {
            failed_put: None,
            existing: None,
            fail_delete: true,
            requests: Mutex::new(Vec::new()),
        });
        let (registry, handler) = handler_with_s3(failing);
        let initial = policy_template("old", false);
        let (_, original, _, _) = run_provision(&handler, &initial, true, &[], None).await;
        let empty = Template::parse("{\"Resources\":{}}").unwrap();
        let (status, mut pending, _, _) =
            run_provision(&handler, &empty, false, &original, Some(&initial)).await;
        assert_eq!(status, StackStatus::UpdateCompleteCleanupInProgress);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].physical_id, "old");
        assert_eq!(pending[0].status, "DELETE_FAILED");
        assert_eq!(pending[0].pending_cleanup[0].physical_id, "old");
        registry.register_native(
            ServiceName::new("s3"),
            ServiceMetadata::new(AwsProtocol::RestXml, None),
            Arc::new(TestS3 {
                failed_put: None,
                existing: None,
                fail_delete: false,
                requests: Mutex::new(Vec::new()),
            }),
        );
        assert!(
            !cleanup_network_replacements(
                &handler.provisioner("us-east-1", "000000000000"),
                &mut pending,
                &mut Vec::new()
            )
            .await
        );
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn removed_security_group_survives_rollback_until_lambda_switches() {
        let registry = Arc::new(ServiceRegistry::new());
        let ec2 = locallycloud_ec2::register(&registry);
        locallycloud_lambda::register(&registry).attach_ec2(ec2.clone());
        let handler = CfnHandler::new(Arc::downgrade(&registry));
        let topology = serde_json::json!({"Resources": {
            "Vpc":{"Type":"AWS::EC2::VPC","Properties":{"CidrBlock":"10.55.0.0/16"}},
            "Subnet":{"Type":"AWS::EC2::Subnet","Properties":{"VpcId":{"Ref":"Vpc"},"CidrBlock":"10.55.1.0/24"}},
            "Preferred":{"Type":"AWS::EC2::SecurityGroup","Properties":{"VpcId":{"Ref":"Vpc"},"GroupDescription":"preferred"}},
            "Retired":{"Type":"AWS::EC2::SecurityGroup","Properties":{"VpcId":{"Ref":"Vpc"},"GroupDescription":"retired"}},
            "Function":{"Type":"AWS::Lambda::Function","Properties":{"FunctionName":"cfn-sg-switch","Runtime":"nodejs22.x","Handler":"index.handler","Role":"arn:aws:iam::000000000000:role/test","Code":{"ZipFile":"UEsDBBQAAAAAAMeaQ100F2L+HQAAAB0AAAAIAAAAaW5kZXguanNleHBvcnRzLmhhbmRsZXI9YXN5bmMoKT0+KHt9KVBLAQIUAxQAAAAAAMeaQ100F2L+HQAAAB0AAAAIAAAAAAAAAAAAAACAAQAAAABpbmRleC5qc1BLBQYAAAAAAQABADYAAABDAAAAAAA="},"VpcConfig":{"SubnetIds":[{"Ref":"Subnet"}],"SecurityGroupIds":[{"Ref":"Retired"}]}}}
        }});
        let initial = Template::parse(&topology.to_string()).unwrap();
        let (status, original, _, events) =
            run_provision(&handler, &initial, true, &[], None).await;
        assert_eq!(status, StackStatus::CreateComplete, "{events:?}");
        let retired = original
            .iter()
            .find(|resource| resource.logical_id == "Retired")
            .unwrap()
            .physical_id
            .clone();
        let mut changed = topology.clone();
        changed["Resources"]
            .as_object_mut()
            .unwrap()
            .remove("Retired");
        changed["Resources"]["Function"]["Properties"]["VpcConfig"]["SecurityGroupIds"] =
            serde_json::json!([{"Ref":"Preferred"}]);
        let mut failed = changed.clone();
        failed["Resources"]["Failure"] = serde_json::json!({"Type":"AWS::EC2::Subnet","DependsOn":"Function","Properties":{"VpcId":"vpc-missing","CidrBlock":"10.56.1.0/24"}});
        let failed = Template::parse(&failed.to_string()).unwrap();
        let (status, restored, _, events) =
            run_provision(&handler, &failed, false, &original, Some(&initial)).await;
        assert_eq!(status, StackStatus::UpdateFailed);
        assert!(restored
            .iter()
            .any(|resource| resource.physical_id == retired));
        assert!(!events
            .iter()
            .any(|event| event.status == "UPDATE_ROLLBACK_FAILED"));
        async fn groups(ec2: &locallycloud_ec2::Ec2Handler) -> String {
            let response = ec2
                .handle(ServiceRequest {
                    method: Method::POST,
                    uri: "/".parse().unwrap(),
                    headers: http::HeaderMap::new(),
                    body: Bytes::from_static(b"Action=DescribeSecurityGroups&Version=2016-11-15"),
                    region: "us-east-1".into(),
                    account_id: "000000000000".into(),
                    request_id: "gate".into(),
                })
                .await;
            assert!(response.status().is_success());
            String::from_utf8(
                axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap()
        }
        assert!(groups(&ec2).await.contains(&retired));
        let changed = Template::parse(&changed.to_string()).unwrap();
        let (status, updated, _, _) =
            run_provision(&handler, &changed, false, &restored, Some(&initial)).await;
        assert_eq!(status, StackStatus::UpdateComplete);
        assert!(!updated
            .iter()
            .any(|resource| resource.physical_id == retired));
        assert!(!groups(&ec2).await.contains(&retired));
        let empty = Template::parse("{\"Resources\":{}}").unwrap();
        let (status, remaining, _, _) =
            run_provision(&handler, &empty, false, &updated, Some(&changed)).await;
        assert_eq!(status, StackStatus::UpdateComplete);
        assert!(remaining.is_empty());
    }

    #[tokio::test]
    async fn nat_replacement_defers_cleanup_and_rollback_preserves_original_target() {
        let registry = Arc::new(ServiceRegistry::new());
        let ec2 = locallycloud_ec2::register(&registry);
        struct FaultEc2 {
            native: Arc<locallycloud_ec2::Ec2Handler>,
            fail_cleanup: std::sync::atomic::AtomicBool,
        }
        #[async_trait]
        impl NativeHandler for FaultEc2 {
            async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
                if request.body.starts_with(b"Action=DeleteNatGateway&")
                    && self
                        .fail_cleanup
                        .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    return http::Response::builder()
                        .status(503)
                        .body(Body::from("injected cleanup failure"))
                        .unwrap();
                }
                self.native.handle(request).await
            }
        }
        let fault = Arc::new(FaultEc2 {
            native: ec2.clone(),
            fail_cleanup: std::sync::atomic::AtomicBool::new(false),
        });
        registry.register_native(
            ServiceName::new("ec2"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            fault.clone(),
        );
        let handler = CfnHandler::new(Arc::downgrade(&registry));
        let topology = serde_json::json!({"Resources": {
            "Vpc": {"Type":"AWS::EC2::VPC","Properties":{"CidrBlock":"10.54.0.0/16"}},
            "Subnet": {"Type":"AWS::EC2::Subnet","Properties":{"VpcId":{"Ref":"Vpc"},"CidrBlock":"10.54.1.0/24"}},
            "Gateway": {"Type":"AWS::EC2::InternetGateway"},
            "Attachment": {"Type":"AWS::EC2::VPCGatewayAttachment","Properties":{"VpcId":{"Ref":"Vpc"},"InternetGatewayId":{"Ref":"Gateway"}}},
            "Address": {"Type":"AWS::EC2::EIP","DependsOn":"Attachment","Properties":{"Domain":"vpc"}},
            "Nat": {"Type":"AWS::EC2::NatGateway","Properties":{"SubnetId":{"Ref":"Subnet"},"AllocationId":{"Fn::GetAtt":["Address","AllocationId"]}}},
            "Table": {"Type":"AWS::EC2::RouteTable","Properties":{"VpcId":{"Ref":"Vpc"}}},
            "Route": {"Type":"AWS::EC2::Route","Properties":{"RouteTableId":{"Ref":"Table"},"DestinationCidrBlock":"0.0.0.0/0","NatGatewayId":{"Ref":"Nat"}}}
        }});
        let initial = Template::parse(&topology.to_string()).unwrap();
        let (status, original, _, _) = run_provision(&handler, &initial, true, &[], None).await;
        assert_eq!(status, StackStatus::CreateComplete);
        let original_nat = original
            .iter()
            .find(|resource| resource.logical_id == "Nat")
            .unwrap()
            .physical_id
            .clone();
        let mut changed = topology.clone();
        changed["Resources"]["NewAddress"] =
            serde_json::json!({"Type":"AWS::EC2::EIP","Properties":{"Domain":"vpc"}});
        changed["Resources"]["Nat"]["Properties"]["AllocationId"] =
            serde_json::json!({"Fn::GetAtt":["NewAddress","AllocationId"]});
        let mut failed = changed.clone();
        failed["Resources"]["Failure"] = serde_json::json!({"Type":"AWS::EC2::NatGateway","DependsOn":"Route","Properties":{"SubnetId":"subnet-missing","AllocationId":{"Fn::GetAtt":["NewAddress","AllocationId"]}}});
        let failed = Template::parse(&failed.to_string()).unwrap();
        let (status, restored, _, events) =
            run_provision(&handler, &failed, false, &original, Some(&initial)).await;
        assert_eq!(status, StackStatus::UpdateFailed);
        assert!(!events
            .iter()
            .any(|event| event.status == "UPDATE_ROLLBACK_FAILED"));
        assert_eq!(
            restored
                .iter()
                .find(|resource| resource.logical_id == "Nat")
                .unwrap()
                .physical_id,
            original_nat
        );
        async fn describe(handler: &locallycloud_ec2::Ec2Handler, action: &str) -> String {
            let response = handler
                .handle(ServiceRequest {
                    method: Method::POST,
                    uri: "/".parse().unwrap(),
                    headers: http::HeaderMap::new(),
                    body: Bytes::from(format!("Action={action}&Version=2016-11-15")),
                    region: "us-east-1".into(),
                    account_id: "000000000000".into(),
                    request_id: "gate".into(),
                })
                .await;
            assert!(response.status().is_success());
            String::from_utf8(
                axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap()
        }
        assert_eq!(
            describe(&ec2, "DescribeNatGateways")
                .await
                .matches("<natGatewayId>")
                .count(),
            1
        );
        assert_eq!(
            describe(&ec2, "DescribeAddresses")
                .await
                .matches("<allocationId>")
                .count(),
            1
        );
        assert!(describe(&ec2, "DescribeRouteTables")
            .await
            .contains(&format!("<natGatewayId>{original_nat}</natGatewayId>")));
        let changed_body = changed.to_string();
        let changed = Template::parse(&changed_body).unwrap();
        fault
            .fail_cleanup
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (status, mut updated, _, mut events) =
            run_provision(&handler, &changed, false, &restored, Some(&initial)).await;
        assert_eq!(status, StackStatus::UpdateCompleteCleanupInProgress);
        let cleanup = &updated
            .iter()
            .find(|resource| resource.logical_id == "Nat")
            .unwrap()
            .pending_cleanup;
        assert_eq!(cleanup.len(), 1);
        assert_eq!(cleanup[0].physical_id, original_nat);
        assert!(
            !cleanup_network_replacements(
                &handler.provisioner("us-east-1", "000000000000"),
                &mut updated,
                &mut events
            )
            .await
        );
        let updated_nat = &updated
            .iter()
            .find(|resource| resource.logical_id == "Nat")
            .unwrap()
            .physical_id;
        assert_ne!(updated_nat, &original_nat);
        assert_eq!(
            describe(&ec2, "DescribeNatGateways")
                .await
                .matches("<natGatewayId>")
                .count(),
            1
        );
        assert!(describe(&ec2, "DescribeRouteTables")
            .await
            .contains(&format!("<natGatewayId>{updated_nat}</natGatewayId>")));
        assert!(updated
            .iter()
            .all(|resource| resource.pending_cleanup.is_empty()));
        handler.store.put(
            "000000000000",
            "us-east-1",
            Stack {
                stack_id:
                    "arn:aws:cloudformation:us-east-1:000000000000:stack/replacement-stack/id"
                        .into(),
                stack_name: "replacement-stack".into(),
                status: StackStatus::UpdateComplete,
                template_body: changed_body,
                parameters: BTreeMap::new(),
                resources: updated,
                outputs: Vec::new(),
                events,
                tags: Vec::new(),
                creation_time: now_iso(),
                last_updated_time: None,
            },
        );
        handler
            .delete_stack(
                &Query::parse(b"StackName=replacement-stack"),
                "us-east-1",
                "000000000000",
            )
            .await
            .unwrap();
        assert!(handler
            .store
            .find("000000000000", "us-east-1", "replacement-stack")
            .is_none());
        assert_eq!(
            describe(&ec2, "DescribeNatGateways")
                .await
                .matches("<natGatewayId>")
                .count(),
            0
        );
        assert_eq!(
            describe(&ec2, "DescribeAddresses")
                .await
                .matches("<allocationId>")
                .count(),
            0
        );
    }
}
