//! The architecture-review model: resources, relationships, gaps and their bounds.
//!
//! Pure data and rules; nothing here knows how AWS state is read.

mod model;
mod topology;

pub use model::{
    Edge, EdgeKind, EmptyList, Fact, FactId, FactValue, Node, Origin, Snapshot, SnapshotMeta,
    SnapshotScope, Unresolved, CONDITIONAL_NOT_RECORDED, INFERRED, NOT_RECORDED,
};
pub use topology::{
    edge_id, grid, Finding, LimitExceeded, Resource, Topology, HTTP_CLIENT_ID, MAX_EDGES,
    MAX_FACTS, MAX_NODES, MAX_UNRESOLVED,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> SnapshotMeta {
        SnapshotMeta {
            stack_id: "arn:aws:cloudformation:us-east-1:000000000000:stack/demo/1".into(),
            stack_name: "demo".into(),
            account: "000000000000".into(),
            region: "us-east-1".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn resource<'a>(id: &'a str, resource_type: &'a str) -> Resource<'a> {
        Resource {
            logical_id: id,
            resource_type,
            physical_id: "physical",
            status: "CREATE_COMPLETE",
            config_hash: None,
        }
    }

    #[test]
    fn serializes_the_snapshot_document_shape() {
        let mut topology = Topology::new(meta());
        topology
            .add_resource(resource("Queue", "AWS::SQS::Queue"))
            .unwrap();
        topology
            .add_resource(resource("Rule", "AWS::Events::Rule"))
            .unwrap();
        topology
            .record(Finding::configured("Rule", "Queue", "target", "evidence"))
            .unwrap();
        topology
            .record(Finding::gap("Rule", "EventBusName", "reason"))
            .unwrap();
        let json = serde_json::to_value(topology.finish().unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "version": 1,
                "documentType": "snapshot",
                "id": "arn:aws:cloudformation:us-east-1:000000000000:stack/demo/1",
                "title": "demo",
                "source": "snapshot",
                "scope": {
                    "account": "000000000000",
                    "region": "us-east-1",
                    "stack": "arn:aws:cloudformation:us-east-1:000000000000:stack/demo/1",
                    "capturedAt": "2026-01-01T00:00:00Z"
                },
                "zones": [],
                "nodes": [
                    {"id": "Queue", "name": "Queue", "type": "AWS::SQS::Queue",
                     "physicalId": "physical", "status": "CREATE_COMPLETE", "zone": "",
                     "x": 60, "y": 100},
                    {"id": "Rule", "name": "Rule", "type": "AWS::Events::Rule",
                     "physicalId": "physical", "status": "CREATE_COMPLETE", "zone": "",
                     "x": 320, "y": 100}
                ],
                "edges": [{
                    "id": "configured:Rule:Queue:target", "from": "Rule", "to": "Queue",
                    "kind": "configured", "label": "target", "evidence": "evidence"
                }],
                "threats": [],
                "unresolved": [{"target": "Rule", "property": "EventBusName", "reason": "reason"}]
            })
        );
    }

    #[test]
    fn lays_resources_out_on_the_browser_grid() {
        assert_eq!(grid(0), (60, 100));
        assert_eq!(grid(3), (840, 100));
        assert_eq!(grid(4), (60, 260));
        assert_eq!(grid(9), (320, 420));
    }

    #[test]
    fn edge_ids_follow_kind_from_to_label() {
        assert_eq!(
            edge_id(EdgeKind::Dependency, "A", "B", "DependsOn"),
            "dependency:A:B:DependsOn"
        );
        assert_eq!(
            edge_id(EdgeKind::Proposed, HTTP_CLIENT_ID, "Api", "x"),
            "proposed:inferred:http-client:Api:x"
        );
    }

    #[test]
    fn drops_self_unknown_and_duplicate_edges() {
        let mut topology = Topology::new(meta());
        topology.add_resource(resource("A", "T")).unwrap();
        topology.add_resource(resource("B", "T")).unwrap();
        for finding in [
            Finding::configured("A", "A", "l", "e"),
            Finding::configured("A", "Missing", "l", "e"),
            Finding::configured("A", "B", "l", "first"),
            Finding::configured("A", "B", "l", "second"),
            Finding::gap("A", "p", "r"),
            Finding::gap("A", "p", "r"),
        ] {
            topology.record(finding).unwrap();
        }
        let snapshot = topology.finish().unwrap();
        assert_eq!(snapshot.edges.len(), 1);
        assert_eq!(snapshot.edges[0].evidence, "first");
        assert_eq!(snapshot.unresolved.len(), 1);
    }

    #[test]
    fn enforces_node_edge_and_gap_limits() {
        let mut topology = Topology::new(meta());
        let ids: Vec<String> = (0..=MAX_NODES).map(|i| format!("R{i}")).collect();
        for id in &ids[..MAX_NODES] {
            topology.add_resource(resource(id, "T")).unwrap();
        }
        assert_eq!(
            topology.add_resource(resource(&ids[MAX_NODES], "T")),
            Err(LimitExceeded::Nodes)
        );
        let mut added = 0;
        'outer: for from in &ids[..MAX_NODES] {
            for to in &ids[..MAX_NODES] {
                if from == to {
                    continue;
                }
                if added == MAX_EDGES {
                    break 'outer;
                }
                topology
                    .record(Finding::configured(from, to, "l", "e"))
                    .unwrap();
                added += 1;
            }
        }
        assert_eq!(
            topology.record(Finding::configured("R0", "R511", "other", "e")),
            Err(LimitExceeded::Edges)
        );
        for i in 0..MAX_UNRESOLVED {
            topology
                .record(Finding::gap("R0", format!("p{i}"), "r"))
                .unwrap();
        }
        assert_eq!(
            topology.record(Finding::gap("R0", "overflow", "r")),
            Err(LimitExceeded::Unresolved)
        );
        assert_eq!(
            LimitExceeded::Nodes.to_string(),
            "Topology limit: 512 resources"
        );
    }

    #[test]
    fn infers_one_http_client_with_proposed_edges() {
        let mut topology = Topology::new(meta());
        for id in ["Api", "Method", "Worker", "Other", "Fifth"] {
            topology.add_resource(resource(id, "T")).unwrap();
        }
        topology
            .record(Finding::HttpInterface("Api".into()))
            .unwrap();
        topology
            .record(Finding::HttpInterface("Api".into()))
            .unwrap();
        topology
            .record(Finding::HttpInterface("Unknown".into()))
            .unwrap();
        let snapshot = topology.finish().unwrap();
        let client = snapshot.nodes.last().unwrap();
        assert_eq!(client.id, HTTP_CLIENT_ID);
        assert_eq!(client.status, INFERRED);
        assert_eq!(client.origin, Some(Origin::Declared));
        assert_eq!((client.x, client.y), (60, 420));
        assert_eq!(snapshot.edges.len(), 1);
        let edge = &snapshot.edges[0];
        assert_eq!(edge.kind, EdgeKind::Proposed);
        assert_eq!(edge.to, "Api");
        assert!(edge.evidence.contains("public exposure"));
        let json = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(json["nodes"][5]["origin"], "declared");
        assert!(json["nodes"][0].get("origin").is_none());
    }

    #[test]
    fn records_a_gap_when_the_inferred_client_cannot_be_added() {
        let mut topology = Topology::new(meta());
        topology.add_resource(resource("Api", "T")).unwrap();
        topology
            .add_resource(resource(HTTP_CLIENT_ID, "T"))
            .unwrap();
        topology
            .record(Finding::HttpInterface("Api".into()))
            .unwrap();
        let snapshot = topology.finish().unwrap();
        assert_eq!(snapshot.nodes.len(), 2);
        assert!(snapshot.edges.is_empty());
        assert_eq!(snapshot.unresolved[0].property, "HTTP client");
    }

    #[test]
    fn truncates_text_like_the_browser_model() {
        let mut topology = Topology::new(meta());
        let long = "x".repeat(300);
        topology
            .add_resource(Resource {
                logical_id: &long,
                resource_type: "T",
                physical_id: &"p".repeat(2000),
                status: "S",
                config_hash: None,
            })
            .unwrap();
        let node = &topology.finish().unwrap().nodes[0];
        assert_eq!(node.name.len(), 256);
        assert_eq!(node.physical_id.len(), 1024);
    }
}
