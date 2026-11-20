use super::*;
use serde_json::json;

#[test]
fn deployment_selection_shares_payloads_independent_of_configuration_size() {
    for entries in [1, 10_000] {
        let values: BTreeMap<_, _> = (0..entries)
            .map(|index| {
                (
                    format!("resource-{index:05}"),
                    json!({"path":format!("/items/{index}"),"payload":"x".repeat(64)}),
                )
            })
            .collect();
        let mut rest = RestApiRecord {
            resources: values.clone(),
            ..Default::default()
        };
        rest.deployment_snapshots
            .insert("deployed".into(), rest.snapshot());
        let mut v2 = ApiV2Record {
            routes: values,
            ..Default::default()
        };
        v2.deployment_snapshots
            .insert("deployed".into(), v2.snapshot());
        for _ in 0..8 {
            let selected = rest.deployment_snapshots.get("deployed").cloned().unwrap();
            assert!(std::ptr::eq(
                &rest.deployment_snapshots["deployed"].resources["resource-00000"],
                &selected.resources["resource-00000"],
            ));
            let selected = v2.deployment_snapshots.get("deployed").cloned().unwrap();
            assert!(std::ptr::eq(
                &v2.deployment_snapshots["deployed"].routes["resource-00000"],
                &selected.routes["resource-00000"],
            ));
        }
    }
}

#[tokio::test]
async fn deployments_preserve_edits_stage_selection_and_schema_across_restart() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.locallycloud-tmp/batch-apigw-firehose-ddb/apigateway")
        .join(format!("deployment-restart-{}", Uuid::new_v4()));
    let db_path = root.join("state.sqlite3");
    let persistence = tokio::task::spawn_blocking(move || {
        Persistence::new(
            Arc::new(locallycloud_state::StateDb::open(db_path).unwrap()),
            locallycloud_state::StateCipher::with_key(&[7; 32]),
        )
        .unwrap()
    })
    .await
    .unwrap();
    let store = ApiGwStore::new();
    let rest = store.insert_rest(
        "account",
        "region",
        "rest",
        RestApiRecord {
            api: json!({"policy":"deployed-policy","endpointConfiguration":{"types":["REGIONAL"]}}),
            resources: BTreeMap::from([("resource".into(), json!({"version":0}))]),
            ..Default::default()
        },
    );
    let v2 = store.insert_v2(
        "account",
        "region",
        "v2",
        ApiV2Record {
            api: json!({"protocolType":"WEBSOCKET","routeSelectionExpression":"$request.body.action"}),
            routes: BTreeMap::from([("route".into(), json!({"routeKey":"$connect","version":0}))]),
            integrations: BTreeMap::from([("integration".into(), json!({"version":0}))]),
            ..Default::default()
        },
    );
    let registry = std::sync::Weak::new();
    let domains = crate::domains::DomainBindings::default();
    let ctx = crate::v1::Ctx {
        store: &store,
        registry: &registry,
        region: "region",
        account: "account",
        request_id: "deployment-test",
        waf: None,
        domains: &domains,
    };
    let (_, first_rest) = crate::v1::create_deployment(&ctx, "rest", &json!({"stageName":"prod"}))
        .await
        .unwrap();
    let (_, first_v2) = crate::v2::create_deployment(&ctx, "v2", &json!({}))
        .await
        .unwrap();
    crate::v2::create_stage(
        &ctx,
        "v2",
        &json!({"stageName":"prod","deploymentId":first_v2["deploymentId"]}),
    )
    .await
    .unwrap();
    {
        let mut record = rest.write().await;
        record.api["policy"] = json!("pending-policy");
        record.api["disableExecuteApiEndpoint"] = json!(true);
        record.resources.get_mut("resource").unwrap()["version"] = json!(1);
    }
    {
        let mut record = v2.write().await;
        record.api["routeSelectionExpression"] = json!("$request.body.changed");
        record.routes.get_mut("route").unwrap()["version"] = json!(1);
        record.integrations.get_mut("integration").unwrap()["version"] = json!(1);
    }
    let (_, second_rest) = crate::v1::create_deployment(&ctx, "rest", &json!({}))
        .await
        .unwrap();
    let (_, second_v2) = crate::v2::create_deployment(&ctx, "v2", &json!({}))
        .await
        .unwrap();
    let snapshot = store.snapshot_scope("account", "region").await;
    let serialized = serde_json::to_value(rest.read().await.clone()).unwrap();
    let first_rest_id = first_rest["id"].as_str().unwrap();
    let second_rest_id = second_rest["id"].as_str().unwrap();
    let first_v2_id = first_v2["deploymentId"].as_str().unwrap();
    let second_v2_id = second_v2["deploymentId"].as_str().unwrap();
    let legacy: RestDeploymentSnapshot =
        serde_json::from_value(serialized["deployment_snapshots"][first_rest_id].clone()).unwrap();
    assert_eq!(legacy.policy, "deployed-policy");
    assert_eq!(legacy.resources["resource"]["version"], 0);
    let serialized = serde_json::to_value(v2.read().await.clone()).unwrap();
    let legacy: ApiV2DeploymentSnapshot =
        serde_json::from_value(serialized["deployment_snapshots"][first_v2_id].clone()).unwrap();
    assert_eq!(legacy.routes["route"]["version"], 0);
    let persistence = tokio::task::spawn_blocking(move || {
        persistence.save("account", "region", &snapshot).unwrap();
        persistence
    })
    .await
    .unwrap();
    drop(rest);
    drop(v2);
    drop(store);
    let restored = tokio::task::spawn_blocking(move || {
        let restored = ApiGwStore::new();
        persistence.restore(&restored).unwrap();
        restored
    })
    .await
    .unwrap();
    {
        let record = restored.rest("account", "region", "rest").unwrap();
        let record = record.read().await;
        assert_eq!(record.stages["prod"]["deploymentId"], first_rest_id);
        assert_eq!(record.api["policy"], "pending-policy");
        assert_eq!(record.api["disableExecuteApiEndpoint"], true);
        let old = record
            .deployment_snapshots
            .get(first_rest_id)
            .cloned()
            .unwrap();
        assert!(Arc::ptr_eq(
            &old,
            &record.deployment_snapshots[first_rest_id]
        ));
        assert_eq!(old.policy, "deployed-policy");
        assert_eq!(old.resources["resource"]["version"], 0);
        let new = &record.deployment_snapshots[second_rest_id];
        assert!(!Arc::ptr_eq(&old, new));
        assert_eq!(new.policy, "pending-policy");
        assert_eq!(new.resources["resource"]["version"], 1);
    }
    {
        let record = restored.v2("account", "region", "v2").unwrap();
        let record = record.read().await;
        assert_eq!(record.stages["prod"]["deploymentId"], first_v2_id);
        assert_eq!(record.routes["route"]["version"], 1);
        let old = record
            .deployment_snapshots
            .get(first_v2_id)
            .cloned()
            .unwrap();
        assert!(Arc::ptr_eq(&old, &record.deployment_snapshots[first_v2_id]));
        assert_eq!(old.routes["route"]["version"], 0);
        assert_eq!(old.integrations["integration"]["version"], 0);
        assert_eq!(old.api["routeSelectionExpression"], "$request.body.action");
        let new = &record.deployment_snapshots[second_v2_id];
        assert!(!Arc::ptr_eq(&old, new));
        assert_eq!(new.routes["route"]["version"], 1);
        assert_eq!(new.integrations["integration"]["version"], 1);
    }
    drop(restored);
    tokio::fs::remove_dir_all(root).await.unwrap();
}
