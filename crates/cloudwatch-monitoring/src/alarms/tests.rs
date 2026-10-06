use super::*;

#[test]
fn evaluator_durable_transitions_outbox_restart_and_commit_failure() {
    let path = std::env::temp_dir().join(format!(
        "locallycloud-alarm-gate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let db = Arc::new(locallycloud_state::StateDb::open(path.join("state.sqlite3")).unwrap());
    let persistence = Arc::new(
        persistence::Persistence::with_cipher(
            db.clone(),
            locallycloud_state::StateCipher::with_key(&[9; 32]),
        )
        .unwrap(),
    );
    let domain = MonitoringDomain {
        series: Default::default(),
        persistence: Some(persistence.clone()),
    };
    let scope = ScopeKey {
        account_id: "000000000000".into(),
        region: "us-east-1".into(),
    };
    let alarms = Alarms::new(Some(persistence.clone())).unwrap();
    let config = json!({"AlarmName":"orders","Namespace":"Orders","MetricName":"Errors","Statistic":"Sum","Period":10,"EvaluationPeriods":3,"DatapointsToAlarm":2,"Threshold":2,"ComparisonOperator":"GreaterThanThreshold","TreatMissingData":"notBreaching","AlarmActions":["arn:aws:sns:us-east-1:000000000000:alerts"]});
    let mut tagged_config = config.clone();
    tagged_config["Tags"] = json!([{"Key":"team","Value":"durable"}]);
    alarms
        .process("PutMetricAlarm", &tagged_config, &scope)
        .unwrap();
    let end = now_ms() / 10000 * 10000;
    let observations: Vec<_> = [(end - 1000, 4.0), (end - 11000, 5.0)]
        .into_iter()
        .map(|(timestamp_ms, value)| MetricObservation {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            namespace: "Orders".into(),
            metric_name: "Errors".into(),
            dimensions: BTreeMap::new(),
            timestamp_ms,
            value,
            unit: None,
            storage_resolution: 1,
            origin: MetricOrigin::PublicPutMetricData,
            correlation_id: format!("sample-{timestamp_ms}"),
        })
        .collect();
    domain.commit(observations.clone()).unwrap();
    domain.commit(observations).unwrap(); // Retrying a durable batch cannot double its samples.
    assert_eq!(
        domain
            .points(
                &scope,
                &MetricKey {
                    namespace: "Orders".into(),
                    metric_name: "Errors".into(),
                    dimensions: BTreeMap::new()
                },
                end - 30000,
                end,
                None
            )
            .unwrap()
            .len(),
        2
    );
    alarms.evaluate(&domain, end).unwrap();
    let describe = alarms
        .process("DescribeAlarms", &json!({"AlarmNames":["orders"]}), &scope)
        .unwrap();
    assert_eq!(describe["MetricAlarms"][0]["StateValue"], "ALARM");
    let pending = alarms.pending().unwrap();
    assert_eq!(pending.len(), 1);
    let restored = Alarms::new(Some(persistence.clone())).unwrap();
    let tag_selector = json!({"ResourceARN":arn(&scope,"orders")});
    assert_eq!(
        restored
            .process("ListTagsForResource", &tag_selector, &scope)
            .unwrap()["Tags"],
        json!([{"Key":"team","Value":"durable"}])
    );
    assert_eq!(restored.pending().unwrap().len(), 1);
    assert_eq!(persistence.load().unwrap().len(), 2);
    let mut log_one = persistence.load().unwrap()[0].clone();
    log_one.origin = MetricOrigin::CloudWatchLogs;
    log_one.correlation_id = "logs-effect:one".into();
    let mut log_two = log_one.clone();
    log_two.correlation_id = "logs-effect:two".into();
    assert_eq!(
        persistence
            .commit(&[log_one.clone(), log_two.clone()])
            .unwrap()
            .len(),
        2
    );
    assert!(persistence.commit(&[log_two, log_one]).unwrap().is_empty());
    let mut changed = config.clone();
    changed["Threshold"] = json!(100);
    db.connection().unwrap().execute_batch("CREATE TRIGGER fail_alarm BEFORE UPDATE ON monitoring_alarms BEGIN SELECT RAISE(ABORT,'injected');END;").unwrap();
    assert!(restored.process("TagResource", &json!({"ResourceARN":arn(&scope,"orders"),"Tags":[{"Key":"team","Value":"uncommitted"}]}), &scope).is_err());
    assert_eq!(
        restored
            .process("ListTagsForResource", &tag_selector, &scope)
            .unwrap()["Tags"],
        json!([{"Key":"team","Value":"durable"}])
    );
    assert!(restored
        .process("PutMetricAlarm", &changed, &scope)
        .is_err());
    assert_eq!(
        restored
            .process("DescribeAlarms", &json!({"AlarmNames":["orders"]}), &scope)
            .unwrap()["MetricAlarms"][0]["Threshold"],
        2.0
    );
    db.connection()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_alarm;")
        .unwrap();
    restored.finish_action(pending[0].id, None).unwrap();
    assert!(Alarms::new(Some(persistence.clone()))
        .unwrap()
        .pending()
        .unwrap()
        .is_empty());
    let foreign = ScopeKey {
        region: "us-west-2".into(),
        ..scope.clone()
    };
    assert!(restored
        .process("DescribeAlarms", &json!({}), &foreign)
        .unwrap()["MetricAlarms"]
        .as_array()
        .unwrap()
        .is_empty());
    for (policy, expected) in [
        ("missing", "INSUFFICIENT_DATA"),
        ("ignore", "INSUFFICIENT_DATA"),
        ("breaching", "ALARM"),
        ("notBreaching", "OK"),
    ] {
        let mut c = config.clone();
        c["AlarmName"] = format!("missing-{policy}").into();
        c["MetricName"] = "NoData".into();
        c["TreatMissingData"] = policy.into();
        c["AlarmActions"] = json!([]);
        restored.process("PutMetricAlarm", &c, &scope).unwrap();
        restored.evaluate(&domain, end).unwrap();
        let value = restored
            .process(
                "DescribeAlarms",
                &json!({"AlarmNames":[format!("missing-{policy}")]}),
                &scope,
            )
            .unwrap();
        assert_eq!(value["MetricAlarms"][0]["StateValue"], expected);
    }
    // A failed second mutation must leave the complete public batch unchanged.
    let mut second = config.clone();
    second["AlarmName"] = "second".into();
    restored.process("PutMetricAlarm", &second, &scope).unwrap();
    db.connection().unwrap().execute_batch("CREATE TRIGGER fail_second BEFORE UPDATE ON monitoring_alarms WHEN OLD.name='second' BEGIN SELECT RAISE(ABORT,'injected');END;").unwrap();
    assert!(restored
        .process(
            "DisableAlarmActions",
            &json!({"AlarmNames":["orders","second"]}),
            &scope
        )
        .is_err());
    assert!(restored
        .process("DescribeAlarms", &json!({"AlarmNames":["orders"]}), &scope)
        .unwrap()["MetricAlarms"][0]["ActionsEnabled"]
        .as_bool()
        .unwrap());
    db.connection()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_second;")
        .unwrap();
    let page = restored
        .process("DescribeAlarms", &json!({"MaxRecords":1}), &scope)
        .unwrap();
    let token = page["NextToken"].as_str().unwrap();
    let reloaded = Alarms::new(Some(persistence.clone())).unwrap();
    let next = reloaded
        .process(
            "DescribeAlarms",
            &json!({"MaxRecords":1,"NextToken":token}),
            &scope,
        )
        .unwrap();
    assert_ne!(
        page["MetricAlarms"][0]["AlarmName"],
        next["MetricAlarms"][0]["AlarmName"]
    );
    assert!(reloaded
        .process(
            "DescribeAlarms",
            &json!({"MaxRecords":2,"NextToken":token}),
            &scope
        )
        .is_err());
    assert!(reloaded
        .process(
            "DescribeAlarms",
            &json!({"MaxRecords":1,"NextToken":token}),
            &foreign
        )
        .is_err());
    assert!(reloaded
        .process(
            "DescribeAlarms",
            &json!({"MaxRecords":1,"NextToken":format!("00{token}")}),
            &scope
        )
        .is_err());
    restored
        .process("DeleteAlarms", &json!({"AlarmNames":["orders"]}), &scope)
        .unwrap();
    assert!(Alarms::new(Some(persistence.clone()))
        .unwrap()
        .process("DescribeAlarms", &json!({"AlarmNames":["orders"]}), &scope)
        .unwrap()["MetricAlarms"]
        .as_array()
        .unwrap()
        .is_empty());
    let reloaded = Alarms::new(Some(persistence.clone())).unwrap();
    let history = reloaded
        .process(
            "DescribeAlarmHistory",
            &json!({"AlarmName":"orders"}),
            &scope,
        )
        .unwrap();
    assert!(history["AlarmHistoryItems"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["HistoryItemType"] == "Action"));
    assert!(history["AlarmHistoryItems"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["HistoryItemType"] == "StateUpdate"));
    let page = reloaded
        .process(
            "DescribeAlarmHistory",
            &json!({"AlarmName":"orders","MaxRecords":1}),
            &scope,
        )
        .unwrap();
    let token = page["NextToken"].as_str().unwrap();
    let next = Alarms::new(Some(persistence.clone()))
        .unwrap()
        .process(
            "DescribeAlarmHistory",
            &json!({"AlarmName":"orders","MaxRecords":1,"NextToken":token}),
            &scope,
        )
        .unwrap();
    assert_ne!(page["AlarmHistoryItems"][0], next["AlarmHistoryItems"][0]);
    assert!(reloaded
        .process(
            "DescribeAlarmHistory",
            &json!({"AlarmName":"second","MaxRecords":1,"NextToken":token}),
            &scope
        )
        .is_err());
    drop(domain);
    drop(db);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn missing_data_positions_and_delivery_backlog_are_not_silently_lost() {
    let alarms = Alarms::new(None).unwrap();
    let scope = ScopeKey {
        account_id: "000000000000".into(),
        region: "us-east-1".into(),
    };
    let domain = MonitoringDomain::default();
    let end = now_ms() / 10000 * 10000;
    for (name, needed, samples, expected) in [
        ("aged-breach", 3, vec![(2, 4.0)], "ALARM"),
        ("young-breach", 3, vec![(0, 4.0)], "INSUFFICIENT_DATA"),
        ("mixed-old", 2, vec![(4, 0.0), (2, 4.0)], "OK"),
    ] {
        alarms.process("PutMetricAlarm", &json!({"AlarmName":name,"Namespace":"Positions","MetricName":name,"Statistic":"Sum","Period":10,"EvaluationPeriods":3,"DatapointsToAlarm":needed,"Threshold":2,"ComparisonOperator":"GreaterThanThreshold","TreatMissingData":"missing"}), &scope).unwrap();
        domain
            .commit(
                samples
                    .into_iter()
                    .map(|(age, value)| MetricObservation {
                        account_id: scope.account_id.clone(),
                        region: scope.region.clone(),
                        namespace: "Positions".into(),
                        metric_name: name.into(),
                        dimensions: Default::default(),
                        timestamp_ms: end - age * 10000 - 1000,
                        value,
                        unit: None,
                        storage_resolution: 1,
                        origin: MetricOrigin::PublicPutMetricData,
                        correlation_id: format!("{name}-{age}"),
                    })
                    .collect(),
            )
            .unwrap();
        alarms.evaluate(&domain, end).unwrap();
        assert_eq!(
            alarms
                .process("DescribeAlarms", &json!({"AlarmNames":[name]}), &scope)
                .unwrap()["MetricAlarms"][0]["StateValue"],
            expected
        );
    }
    // Fair selection reaches an action behind a full unsuccessful delivery page.
    {
        let mut state = alarms.state.lock().unwrap();
        for id in 1..=65 {
            state.pending.insert(
                id,
                Pending {
                    id,
                    scope: scope.clone(),
                    target: "unused".into(),
                    message: "{}".into(),
                    alarm_name: "aged-breach".into(),
                },
            );
        }
    }
    assert_eq!(alarms.pending().unwrap().last().unwrap().id, 64);
    assert_eq!(alarms.pending().unwrap().first().unwrap().id, 65);
    alarms
        .finish_action(65, Some("SNS target missing"))
        .unwrap();
    assert_eq!(alarms.state.lock().unwrap().pending.len(), 64);
    assert!(alarms
        .process(
            "DescribeAlarmHistory",
            &json!({"HistoryItemType":"Action"}),
            &scope
        )
        .unwrap()["AlarmHistoryItems"][0]["HistoryData"]
        .as_str()
        .unwrap()
        .contains("Failed"));
    let mut state = alarms.state.lock().unwrap();
    let pending = state.pending[&1].clone();
    for id in 66..=10001 {
        let mut item = pending.clone();
        item.id = id;
        state.pending.insert(id, item);
    }
    let before = state.history.len();
    assert!(alarms
        .commit_batch(&mut state, &scope, &[], vec![pending], None, vec![])
        .is_err());
    assert_eq!(state.history.len(), before);
}

#[test]
fn alarm_tags_creation_update_validation_and_legacy_record() {
    let scope = ScopeKey {
        account_id: "000000000000".into(),
        region: "us-east-1".into(),
    };
    let alarms = Alarms::new(None).unwrap();
    let resource = arn(&scope, "tagged");
    let selector = json!({"ResourceARN":resource});
    let query =
        QueryRequest::parse(b"Action=TagResource&Tags.member.1.Key=empty&Tags.member.1.Value=");
    assert_eq!(
        query_json(&query).unwrap()["Tags"],
        json!([{"Key":"empty","Value":""}])
    );
    let query = QueryRequest::parse(b"Action=UntagResource&TagKeys.member.1=empty");
    assert_eq!(query_json(&query).unwrap()["TagKeys"], json!(["empty"]));
    let mut config = json!({"AlarmName":"tagged","Namespace":"Orders","MetricName":"Errors","Statistic":"Sum","Period":60,"EvaluationPeriods":1,"Threshold":2,"ComparisonOperator":"GreaterThanThreshold","Tags":[{"Key":"team","Value":"orders"}]});
    alarms.process("PutMetricAlarm", &config, &scope).unwrap();
    assert_eq!(
        alarms
            .process("ListTagsForResource", &selector, &scope)
            .unwrap()["Tags"],
        json!([{"Key":"team","Value":"orders"}])
    );
    config["Tags"] = json!([{"Key":"ignored","Value":"update"}]);
    alarms.process("PutMetricAlarm", &config, &scope).unwrap();
    assert_eq!(
        alarms
            .process("ListTagsForResource", &selector, &scope)
            .unwrap()["Tags"],
        json!([{"Key":"team","Value":"orders"}])
    );
    assert!(alarms
        .process("DescribeAlarms", &json!({}), &scope)
        .unwrap()["MetricAlarms"][0]
        .get("Tags")
        .is_none());
    alarms.process("TagResource",&json!({"ResourceARN":resource,"Tags":[{"Key":"team","Value":"etl"},{"Key":"empty","Value":""}]}),&scope).unwrap();
    alarms
        .process(
            "UntagResource",
            &json!({"ResourceARN":resource,"TagKeys":["empty","absent"]}),
            &scope,
        )
        .unwrap();
    assert_eq!(
        alarms
            .process("ListTagsForResource", &selector, &scope)
            .unwrap()["Tags"],
        json!([{"Key":"team","Value":"etl"}])
    );
    for tags in [
        json!([{"Key":"aws:reserved","Value":"x"}]),
        json!([{"Key":"k","Value":"x".repeat(257)}]),
        json!([{"Key":"k","Value":"a"},{"Key":"k","Value":"b"}]),
        json!((0..51)
            .map(|n| json!({"Key":format!("k{n}"),"Value":"x"}))
            .collect::<Vec<_>>()),
    ] {
        assert!(alarms
            .process(
                "TagResource",
                &json!({"ResourceARN":resource,"Tags":tags}),
                &scope
            )
            .is_err());
    }
    let tags = json!((0..50)
        .map(|n| json!({"Key":format!("k{n}"),"Value":"x"}))
        .collect::<Vec<_>>());
    assert!(alarms
        .process(
            "TagResource",
            &json!({"ResourceARN":resource,"Tags":tags}),
            &scope
        )
        .is_err()); // Existing team plus fifty new tags is invalid atomically.
    assert_eq!(
        alarms
            .process("ListTagsForResource", &selector, &scope)
            .unwrap()["Tags"],
        json!([{"Key":"team","Value":"etl"}])
    );
    assert!(matches!(
        alarms.process(
            "ListTagsForResource",
            &json!({"ResourceARN":"not-an-arn"}),
            &scope
        ),
        Err(MonitoringError::InvalidParameter(_))
    ));
    for resource in [
        "arn:aws:cloudwatch:us-west-2:000000000000:alarm:tagged",
        "arn:aws:cloudwatch:us-east-1:111111111111:alarm:tagged",
    ] {
        assert!(matches!(
            alarms.process(
                "ListTagsForResource",
                &json!({"ResourceARN":resource}),
                &scope
            ),
            Err(MonitoringError::ResourceNotFoundException(_))
        ));
    }
    let mut legacy = serde_json::to_value(
        alarms
            .state
            .lock()
            .unwrap()
            .records
            .get(&(scope.clone(), "tagged".into()))
            .unwrap(),
    )
    .unwrap();
    legacy.as_object_mut().unwrap().remove("tags");
    assert!(serde_json::from_value::<Record>(legacy)
        .unwrap()
        .tags
        .is_empty());
}
