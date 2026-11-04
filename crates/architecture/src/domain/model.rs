//! The review model as the browser consumes it (`version: 1` snapshot documents).

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

/// Status of a declared resource that CloudFormation never recorded.
pub const NOT_RECORDED: &str = "NOT_RECORDED";
/// Status of a conditional resource that was declared but not created.
pub const CONDITIONAL_NOT_RECORDED: &str = "CONDITIONAL_NOT_RECORDED";
/// Status of a review assumption that no AWS read confirms.
pub const INFERRED: &str = "INFERRED";

/// What an edge claims about two resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EdgeKind {
    /// Template references or `DependsOn`: provisioning order, not data flow.
    Dependency,
    /// A deployed service configuration names the destination.
    Configured,
    /// A review assumption that requires human validation.
    Proposed,
}

impl EdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Dependency => "dependency",
            EdgeKind::Configured => "configured",
            EdgeKind::Proposed => "proposed",
        }
    }
}

/// Who asserted a node, when it is not a captured resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Declared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FactId {
    EncryptionAtRest,
    PublicAccessBlock,
    Versioning,
    PointInTimeRecovery,
    TlsOnly,
    ResourcePolicy,
    DeadLetter,
    ReservedConcurrency,
    SecretsInEnvironment,
    RolePrivilege,
    LogRetention,
    ExecutionLogging,
    ApiAuthorization,
    Throttling,
    AccessLogs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FactValue {
    Kms,
    ServiceManaged,
    Enabled,
    Disabled,
    Suspended,
    Partial,
    Enforced,
    Configured,
    Limited,
    Public,
    Restricted,
    ResolvedSecret,
    Suspected,
    NoneDetected,
    WildcardAction,
    WildcardResource,
    Scoped,
    Retained,
    NeverExpires,
    AllMethods,
    SomeOpen,
    Open,
    NotDeclared,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Fact {
    pub id: FactId,
    pub value: FactValue,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub physical_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    pub zone: String,
    pub x: u32,
    pub y: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub facts: Vec<Fact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Edge {
    pub id: String,
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    pub label: String,
    pub evidence: String,
}

/// A relationship that could not be established, with the reason and never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unresolved {
    pub target: String,
    pub property: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotScope {
    pub account: String,
    pub region: String,
    pub stack: String,
    pub captured_at: String,
}

/// Identity of the captured stack.
#[derive(Debug, Clone)]
pub struct SnapshotMeta {
    /// Stack ARN; also the document identity used to merge later captures.
    pub stack_id: String,
    pub stack_name: String,
    pub account: String,
    pub region: String,
    pub captured_at: String,
}

/// A captured topology. Zones and threats belong to the reviewer and start empty.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub version: u8,
    pub document_type: &'static str,
    pub id: String,
    pub title: String,
    pub source: &'static str,
    pub scope: SnapshotScope,
    pub zones: EmptyList,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub threats: EmptyList,
    pub unresolved: Vec<Unresolved>,
}

/// A list the capture never fills (reviewer-owned data).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmptyList;

impl Serialize for EmptyList {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_seq(Some(0))?.end()
    }
}

/// Bounded text, as the browser model truncates it (counted in characters).
pub(crate) fn bounded_text(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}
