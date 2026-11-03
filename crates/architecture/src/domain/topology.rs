//! Builds a bounded [`Snapshot`] from resources and findings.

use std::collections::HashSet;
use std::fmt;

use super::model::{
    bounded_text, Edge, EdgeKind, EmptyList, Node, Origin, Snapshot, SnapshotMeta, SnapshotScope,
    Unresolved, INFERRED,
};

/// Same bounds the browser model enforces.
pub const MAX_NODES: usize = 512;
pub const MAX_EDGES: usize = 2048;
pub const MAX_UNRESOLVED: usize = 2048;

const TEXT: usize = 256;
const PHYSICAL_ID: usize = 1024;
const EVIDENCE: usize = 1000;

/// Node of the inferred external caller of REST APIs.
pub const HTTP_CLIENT_ID: &str = "inferred:http-client";
const HTTP_CLIENT_NAME: &str = "HTTP client — exposure unverified";
const HTTP_CLIENT_TYPE: &str = "External actor";
const HTTP_CLIENT_LABEL: &str = "HTTP interface (unverified)";
const HTTP_CLIENT_EVIDENCE: &str = "Inferred review assumption from REST methods. Authentication, \
reachability and public exposure require human validation. No traffic was observed.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitExceeded {
    Nodes,
    Edges,
    Unresolved,
}

impl fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitExceeded::Nodes => write!(f, "Topology limit: {MAX_NODES} resources"),
            LimitExceeded::Edges => write!(f, "Topology limit: {MAX_EDGES} relationships"),
            LimitExceeded::Unresolved => {
                write!(f, "Topology limit: {MAX_UNRESOLVED} unresolved references")
            }
        }
    }
}

impl std::error::Error for LimitExceeded {}

/// What an extractor learned about one resource.
#[derive(Debug, Clone, PartialEq)]
pub enum Finding {
    Relation {
        from: String,
        to: String,
        kind: EdgeKind,
        label: String,
        evidence: String,
    },
    Gap(Unresolved),
    /// A REST API exposes methods; the reviewer must validate who can call it.
    HttpInterface(String),
}

impl Finding {
    pub fn relation(
        from: &str,
        to: &str,
        kind: EdgeKind,
        label: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        Finding::Relation {
            from: from.to_owned(),
            to: to.to_owned(),
            kind,
            label: label.into(),
            evidence: evidence.into(),
        }
    }

    pub fn configured(
        from: &str,
        to: &str,
        label: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        Self::relation(from, to, EdgeKind::Configured, label, evidence)
    }

    pub fn gap(target: &str, property: impl Into<String>, reason: impl Into<String>) -> Self {
        Finding::Gap(Unresolved {
            target: target.to_owned(),
            property: property.into(),
            reason: reason.into(),
        })
    }
}

/// One resource as the capture saw it.
pub struct Resource<'a> {
    pub logical_id: &'a str,
    pub resource_type: &'a str,
    pub physical_id: &'a str,
    pub status: &'a str,
}

pub struct Topology {
    meta: SnapshotMeta,
    nodes: Vec<Node>,
    node_ids: HashSet<String>,
    edges: Vec<Edge>,
    edge_ids: HashSet<String>,
    unresolved: Vec<Unresolved>,
    gap_keys: HashSet<(String, String, String)>,
    http_apis: Vec<String>,
}

impl Topology {
    pub fn new(meta: SnapshotMeta) -> Self {
        Self {
            meta,
            nodes: Vec::new(),
            node_ids: HashSet::new(),
            edges: Vec::new(),
            edge_ids: HashSet::new(),
            unresolved: Vec::new(),
            gap_keys: HashSet::new(),
            http_apis: Vec::new(),
        }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.node_ids.contains(id)
    }

    /// Adds a resource in grid order; a repeated logical ID is ignored.
    pub fn add_resource(&mut self, resource: Resource<'_>) -> Result<(), LimitExceeded> {
        if self.node_ids.contains(resource.logical_id) {
            return Ok(());
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(LimitExceeded::Nodes);
        }
        let (x, y) = grid(self.nodes.len());
        self.node_ids.insert(resource.logical_id.to_owned());
        self.nodes.push(Node {
            id: resource.logical_id.to_owned(),
            name: bounded_text(resource.logical_id, TEXT),
            resource_type: bounded_text(resource.resource_type, TEXT),
            physical_id: bounded_text(resource.physical_id, PHYSICAL_ID),
            status: bounded_text(resource.status, TEXT),
            origin: None,
            zone: String::new(),
            x,
            y,
        });
        Ok(())
    }

    pub fn record(&mut self, finding: Finding) -> Result<(), LimitExceeded> {
        match finding {
            Finding::Relation {
                from,
                to,
                kind,
                label,
                evidence,
            } => self.relate(&from, &to, kind, &label, &evidence),
            Finding::Gap(gap) => self.gap(gap),
            Finding::HttpInterface(api) => {
                if self.contains(&api) && !self.http_apis.contains(&api) {
                    self.http_apis.push(api);
                }
                Ok(())
            }
        }
    }

    /// Edges between unknown nodes, or from a node to itself, are dropped; the first edge
    /// with a given identity wins.
    fn relate(
        &mut self,
        from: &str,
        to: &str,
        kind: EdgeKind,
        label: &str,
        evidence: &str,
    ) -> Result<(), LimitExceeded> {
        if from == to || !self.contains(from) || !self.contains(to) {
            return Ok(());
        }
        let label = bounded_text(label, TEXT);
        let id = bounded_text(&edge_id(kind, from, to, &label), TEXT);
        if self.edge_ids.contains(&id) {
            return Ok(());
        }
        if self.edges.len() >= MAX_EDGES {
            return Err(LimitExceeded::Edges);
        }
        self.edge_ids.insert(id.clone());
        self.edges.push(Edge {
            id,
            from: from.to_owned(),
            to: to.to_owned(),
            kind,
            label,
            evidence: bounded_text(evidence, EVIDENCE),
        });
        Ok(())
    }

    fn gap(&mut self, gap: Unresolved) -> Result<(), LimitExceeded> {
        let gap = Unresolved {
            target: bounded_text(&gap.target, TEXT),
            property: bounded_text(&gap.property, TEXT),
            reason: bounded_text(&gap.reason, TEXT),
        };
        let key = (gap.target.clone(), gap.property.clone(), gap.reason.clone());
        if self.gap_keys.contains(&key) {
            return Ok(());
        }
        if self.unresolved.len() >= MAX_UNRESOLVED {
            return Err(LimitExceeded::Unresolved);
        }
        self.gap_keys.insert(key);
        self.unresolved.push(gap);
        Ok(())
    }

    /// Adds the inferred HTTP client for REST APIs, then seals the document.
    pub fn finish(mut self) -> Result<Snapshot, LimitExceeded> {
        self.infer_http_client()?;
        let meta = self.meta;
        Ok(Snapshot {
            version: 1,
            document_type: "snapshot",
            id: meta.stack_id.clone(),
            title: bounded_text(&meta.stack_name, TEXT),
            source: "snapshot",
            scope: SnapshotScope {
                account: meta.account,
                region: meta.region,
                stack: meta.stack_id,
                captured_at: meta.captured_at,
            },
            zones: EmptyList,
            nodes: self.nodes,
            edges: self.edges,
            threats: EmptyList,
            unresolved: self.unresolved,
        })
    }

    fn infer_http_client(&mut self) -> Result<(), LimitExceeded> {
        if self.http_apis.is_empty() {
            return Ok(());
        }
        let apis = std::mem::take(&mut self.http_apis);
        if self.nodes.len() >= MAX_NODES || self.contains(HTTP_CLIENT_ID) {
            for api in &apis {
                self.gap(Unresolved {
                    target: api.clone(),
                    property: "HTTP client".into(),
                    reason: "Inferred actor omitted at model limit or identity collision".into(),
                })?;
            }
            return Ok(());
        }
        let rows = u32::try_from(self.nodes.len().div_ceil(4)).unwrap_or(u32::MAX);
        self.node_ids.insert(HTTP_CLIENT_ID.to_owned());
        self.nodes.push(Node {
            id: HTTP_CLIENT_ID.into(),
            name: HTTP_CLIENT_NAME.into(),
            resource_type: HTTP_CLIENT_TYPE.into(),
            physical_id: String::new(),
            status: INFERRED.into(),
            origin: Some(Origin::Declared),
            zone: String::new(),
            x: 60,
            y: rows.saturating_mul(160).saturating_add(100),
        });
        for api in &apis {
            self.relate(
                HTTP_CLIENT_ID,
                api,
                EdgeKind::Proposed,
                HTTP_CLIENT_LABEL,
                HTTP_CLIENT_EVIDENCE,
            )?;
        }
        Ok(())
    }
}

/// Stable edge identity shared with the browser model: `${kind}:${from}:${to}:${label}`.
pub fn edge_id(kind: EdgeKind, from: &str, to: &str, label: &str) -> String {
    format!("{}:{from}:{to}:{label}", kind.as_str())
}

/// Initial grid layout of the browser model: four columns, 260 by 160 pixels.
pub fn grid(index: usize) -> (u32, u32) {
    let column = u32::try_from(index % 4).unwrap_or(0);
    let row = u32::try_from(index / 4).unwrap_or(u32::MAX);
    (
        60 + column * 260,
        row.saturating_mul(160).saturating_add(100),
    )
}
