//! Stack domain model.

use std::collections::BTreeMap;

/// Lifecycle status of a stack (subset of the AWS status set that this engine drives).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackStatus {
    CreateComplete,
    UpdateComplete,
    DeleteComplete,
    CreateFailed,
    UpdateFailed,
    DeleteFailed,
}

impl StackStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            StackStatus::CreateComplete => "CREATE_COMPLETE",
            StackStatus::UpdateComplete => "UPDATE_COMPLETE",
            StackStatus::DeleteComplete => "DELETE_COMPLETE",
            StackStatus::CreateFailed => "CREATE_FAILED",
            StackStatus::UpdateFailed => "UPDATE_FAILED",
            StackStatus::DeleteFailed => "DELETE_FAILED",
        }
    }
}

/// A provisioned stack resource.
#[derive(Debug, Clone)]
pub struct StackResource {
    pub logical_id: String,
    pub physical_id: String,
    pub resource_type: String,
    pub status: String,
    /// `Fn::GetAtt`-resolvable attributes (e.g. `Arn`).
    pub attributes: BTreeMap<String, String>,
}

/// A recorded stack event (surfaced by `DescribeStackEvents`).
#[derive(Debug, Clone)]
pub struct StackEvent {
    pub event_id: String,
    pub logical_id: String,
    pub resource_type: String,
    pub status: String,
    pub reason: Option<String>,
    pub timestamp: String,
}

/// A resolved stack output.
#[derive(Debug, Clone)]
pub struct Output {
    pub key: String,
    pub value: String,
    pub export_name: Option<String>,
}

/// A CloudFormation stack.
#[derive(Debug, Clone)]
pub struct Stack {
    pub stack_id: String,
    pub stack_name: String,
    pub status: StackStatus,
    pub template_body: String,
    pub parameters: BTreeMap<String, String>,
    pub resources: Vec<StackResource>,
    pub outputs: Vec<Output>,
    pub events: Vec<StackEvent>,
    pub tags: Vec<(String, String)>,
    pub creation_time: String,
    pub last_updated_time: Option<String>,
}

impl Stack {
    pub fn resource(&self, logical_id: &str) -> Option<&StackResource> {
        self.resources.iter().find(|r| r.logical_id == logical_id)
    }
}
