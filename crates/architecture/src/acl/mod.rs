//! Anti-corruption layer between deployed AWS state and the review model.
//!
//! Reads go only through the injected [`AwsReader`], so they re-enter the front door with
//! the dashboard profile's identity and read-only admission. This layer is also the
//! security boundary: identities, statuses, relationships and reasons leave it; templates,
//! policies, environment values, state machine definitions and code do not.

mod extract;
mod identity;
mod reads;
mod stack;
mod template;
mod xml;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{stream, StreamExt, TryStreamExt};
use locallycloud_core::views::architecture::{ArchitectureSource, AwsReader, Scope, TopologyError};
use serde_json::Value;

use crate::domain::{
    Finding, Resource, Snapshot, SnapshotMeta, Topology, CONDITIONAL_NOT_RECORDED, MAX_NODES,
    NOT_RECORDED,
};
use extract::Context;
use identity::Identities;
use stack::StackResource;
use template::{Resolver, TemplateView};

/// Bounds on the work one topology may cause.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub reads: usize,
    pub in_flight: usize,
    pub deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            reads: 2048,
            in_flight: 8,
            deadline: Duration::from_secs(30),
        }
    }
}

/// Builds the review snapshot of one CloudFormation stack from its deployed state.
/// Stateless: it holds no background work and nothing at idle.
#[derive(Debug, Default)]
pub struct CloudFormationTopology {
    limits: Limits,
}

impl CloudFormationTopology {
    pub fn new(limits: Limits) -> Self {
        Self { limits }
    }

    async fn build(
        &self,
        reader: &dyn AwsReader,
        scope: &Scope,
        stack_name: &str,
    ) -> Result<Snapshot, TopologyError> {
        let reads = reads::Reads::new(reader, self.limits.reads);
        let stack = stack::describe(&reads, scope, stack_name).await?;
        let (resources, template) = tokio::try_join!(
            stack::resources(&reads, &stack.id),
            stack::processed_template(&reads, &stack.id),
        )?;
        if resources.len() > MAX_NODES {
            return Err(limit(crate::domain::LimitExceeded::Nodes));
        }
        let view = template.as_ref().and_then(TemplateView::new);
        let mut topology = Topology::new(SnapshotMeta {
            stack_id: stack.id.clone(),
            stack_name: stack.name.clone(),
            account: scope.account.clone(),
            region: scope.region.clone(),
            captured_at: captured_at(),
        });
        add_nodes(&mut topology, &resources, view.as_ref(), &stack.name)?;
        if let Some(view) = &view {
            for finding in view.dependency_findings() {
                topology.record(finding).map_err(limit)?;
            }
        }

        let identities = Identities::new(scope, &resources);
        let resolver = Resolver {
            pseudo: HashMap::from([
                ("AWS::Region", scope.region.clone()),
                ("AWS::AccountId", scope.account.clone()),
                ("AWS::Partition", "aws".to_owned()),
                ("AWS::URLSuffix", "amazonaws.com".to_owned()),
                ("AWS::StackName", stack.name.clone()),
                ("AWS::StackId", stack.id.clone()),
            ]),
            parameters: &stack.parameters,
            physical: resources
                .iter()
                .map(|r| (r.logical_id.as_str(), r.physical_id.as_str()))
                .collect(),
        };
        let ctx = Context {
            reads: &reads,
            identities: &identities,
            resources: &resources,
            template: view.as_ref(),
            resolver: &resolver,
        };
        // Ordered buffering keeps the document deterministic for the same deployed state.
        // Futures are inert until polled, so at most `in_flight` reads run at once.
        let pending: Vec<_> = resources
            .iter()
            .map(|resource| extract::extract(&ctx, resource))
            .collect();
        let findings: Vec<Vec<Finding>> = stream::iter(pending)
            .buffered(self.limits.in_flight.max(1))
            .try_collect()
            .await?;
        for finding in findings.into_iter().flatten() {
            topology.record(finding).map_err(limit)?;
        }
        topology.finish().map_err(limit)
    }
}

#[async_trait]
impl ArchitectureSource for CloudFormationTopology {
    async fn topology(
        &self,
        reader: &dyn AwsReader,
        scope: &Scope,
        stack: &str,
    ) -> Result<Value, TopologyError> {
        let snapshot = tokio::time::timeout(self.limits.deadline, self.build(reader, scope, stack))
            .await
            .map_err(|_| {
                TopologyError::Unprocessable("Topology exceeded its time limit".into())
            })??;
        serde_json::to_value(snapshot)
            .map_err(|_| TopologyError::Unprocessable("Topology could not be serialized".into()))
    }
}

/// Template order first (as the browser model lays it out), then deployed resources the
/// processed template does not declare.
fn add_nodes(
    topology: &mut Topology,
    resources: &[StackResource],
    view: Option<&TemplateView<'_>>,
    stack_name: &str,
) -> Result<(), TopologyError> {
    let deployed: HashMap<&str, &StackResource> = resources
        .iter()
        .map(|r| (r.logical_id.as_str(), r))
        .collect();
    match view {
        Some(view) => {
            for declaration in view.declarations() {
                let recorded = deployed.get(declaration.logical_id);
                let resource_type = recorded
                    .map(|r| r.resource_type.as_str())
                    .or(declaration.resource_type)
                    .ok_or_else(|| {
                        TopologyError::Unprocessable("Template resource without a Type".into())
                    })?;
                let status = match (recorded, declaration.conditional) {
                    (Some(r), _) if !r.status.is_empty() => r.status.as_str(),
                    (_, true) => CONDITIONAL_NOT_RECORDED,
                    (_, false) => NOT_RECORDED,
                };
                topology
                    .add_resource(Resource {
                        logical_id: declaration.logical_id,
                        resource_type,
                        physical_id: recorded.map_or("", |r| r.physical_id.as_str()),
                        status,
                    })
                    .map_err(limit)?;
            }
        }
        None => {
            topology
                .record(Finding::gap(
                    stack_name,
                    "TemplateBody",
                    "Processed template unavailable or not JSON; dependencies and \
                     undeployed conditional resources are omitted",
                ))
                .map_err(limit)?;
        }
    }
    for resource in resources {
        topology
            .add_resource(Resource {
                logical_id: &resource.logical_id,
                resource_type: &resource.resource_type,
                physical_id: &resource.physical_id,
                status: &resource.status,
            })
            .map_err(limit)?;
    }
    Ok(())
}

fn limit(error: crate::domain::LimitExceeded) -> TopologyError {
    TopologyError::Unprocessable(error.to_string())
}

fn captured_at() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}
