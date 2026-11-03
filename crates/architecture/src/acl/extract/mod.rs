//! Per-resource-type readers of deployed configuration.
//!
//! Each extractor reads one deployed resource and translates what its service reports into
//! domain findings. A destination becomes an edge only when it matches exactly one resource
//! of the stack; everything else is recorded as a gap with its reason.

mod api_method;
mod bucket;
mod event_rule;
mod event_source;
mod state_machine;

use locallycloud_core::views::architecture::TopologyError;

use super::identity::{types, Identities};
use super::reads::Reads;
use super::stack::StackResource;
use super::template::{Resolver, TemplateView};
use crate::domain::Finding;

/// Reasons shared by extractors (the browser model shows them verbatim).
pub(crate) mod reason {
    pub const UNRESOLVED_DESTINATION: &str = "External, ambiguous or unresolved destination";
    pub const DYNAMIC_VALUE: &str =
        "Dynamic JSONPath or JSONata value; destination is chosen at run time";
    pub const DRIFTED: &str = "Deployed configuration not found; it may have drifted";
    pub const READ_FAILED: &str = "Deployed configuration could not be read";
}

/// Everything an extractor may consult. Reads go through `reads` only.
pub(crate) struct Context<'a> {
    pub reads: &'a Reads<'a>,
    pub identities: &'a Identities,
    pub resources: &'a [StackResource],
    pub template: Option<&'a TemplateView<'a>>,
    pub resolver: &'a Resolver<'a>,
}

impl Context<'_> {
    /// A template property of `logical_id` resolved to a string, when it can be.
    pub(crate) fn declared(&self, logical_id: &str, property: &str) -> Declared {
        let Some(value) = self
            .template
            .and_then(|template| template.property(logical_id, property))
        else {
            return Declared::Absent;
        };
        match self.resolver.literal(value) {
            Some(text) => Declared::Value(text),
            None => Declared::Unresolved,
        }
    }
}

pub(crate) enum Declared {
    Absent,
    Unresolved,
    Value(String),
}

#[derive(Clone, Copy)]
enum Extractor {
    EventSourceMapping,
    EventRule,
    StateMachine,
    RestMethod,
    Bucket,
}

impl Extractor {
    fn for_type(resource_type: &str) -> Option<Self> {
        match resource_type {
            types::EVENT_SOURCE_MAPPING => Some(Extractor::EventSourceMapping),
            types::EVENT_RULE => Some(Extractor::EventRule),
            types::STATE_MACHINE => Some(Extractor::StateMachine),
            types::REST_METHOD => Some(Extractor::RestMethod),
            types::S3_BUCKET => Some(Extractor::Bucket),
            _ => None,
        }
    }
}

/// Configured flows of one deployed resource; resources without a reader yield nothing.
pub(crate) async fn extract(
    ctx: &Context<'_>,
    resource: &StackResource,
) -> Result<Vec<Finding>, TopologyError> {
    if resource.physical_id.is_empty() {
        return Ok(Vec::new());
    }
    let Some(extractor) = Extractor::for_type(&resource.resource_type) else {
        return Ok(Vec::new());
    };
    match extractor {
        Extractor::EventSourceMapping => event_source::extract(ctx, resource).await,
        Extractor::EventRule => event_rule::extract(ctx, resource).await,
        Extractor::StateMachine => state_machine::extract(ctx, resource).await,
        Extractor::RestMethod => api_method::extract(ctx, resource).await,
        Extractor::Bucket => bucket::extract(ctx, resource).await,
    }
}

/// Evidence for an edge read from deployed configuration.
fn deployed(logical_id: &str, operation: &str, field: &str) -> String {
    format!("{logical_id} {operation} {field} (configuration only; delivery not observed)")
}
