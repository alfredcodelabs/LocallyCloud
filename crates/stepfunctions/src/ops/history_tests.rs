use super::*;

fn history_ids(history: &[u64], offset: usize, maximum: usize, reverse: bool) -> Vec<u64> {
    let mut page = history_page(history, offset, maximum, reverse).to_vec();
    if reverse {
        page.reverse();
    }
    page
}

#[test]
fn history_windows_match_the_previous_algorithm_at_boundaries() {
    for count in [0, 1, 17, 1000, 25_000] {
        let history: Vec<_> = (0..count).collect();
        for reverse in [false, true] {
            let mut reference = history.clone();
            if reverse {
                reference.reverse();
            }
            for offset in [0, 1, 16, count as usize, usize::MAX] {
                for maximum in [0, 1, 7, 1000, usize::MAX] {
                    let expected: Vec<_> = reference
                        .iter()
                        .skip(offset)
                        .take(maximum)
                        .copied()
                        .collect();
                    assert_eq!(history_ids(&history, offset, maximum, reverse), expected);
                }
            }
        }
    }
}

#[tokio::test]
async fn history_pages_preserve_order_tokens_details_and_scope() {
    let store = SfnStore::new();
    let mut execution: Execution = serde_json::from_value(json!({
        "arn":"arn:aws:states:us-east-1:000000000000:execution:page:owned",
        "name":"owned","state_machine_arn":"arn:aws:states:us-east-1:000000000000:stateMachine:page",
        "state_machine_type":"STANDARD","definition":"{}","role_arn":"role",
        "status":"Succeeded","input":{},"start_date":1.0,"start_time":"time",
        "variables":{},"redrive_count":0
    })).unwrap();
    for id in 1..=17 {
        execution.record(
            "PassStateExited",
            json!({"name":"state","output":{"id":id}}),
        );
    }
    let arn = execution.arn.clone();
    store.insert_execution(execution);
    let ctx = Ctx {
        store: &store,
        registry: Weak::new(),
        account: "000000000000",
        region: "us-east-1",
        request_id: "owned",
    };
    for reverse in [false, true] {
        for include in [false, true] {
            let mut ids = Vec::new();
            let mut token = None;
            loop {
                let mut request = json!({"executionArn":arn,"maxResults":3,"reverseOrder":reverse,"includeExecutionData":include});
                if let Some(token) = token {
                    request["nextToken"] = token;
                }
                let response = get_execution_history(&ctx, &request).await.unwrap();
                for event in response["events"].as_array().unwrap() {
                    let id = event["id"].as_u64().unwrap();
                    ids.push(id);
                    let details = &event["passStateExitedEventDetails"];
                    assert_eq!(details["name"], "state");
                    if include {
                        assert_eq!(details["output"], json!({"id":id}).to_string());
                    } else {
                        assert!(details.get("output").is_none());
                    }
                    assert_eq!(
                        event.get("previousEventId"),
                        (id > 1).then(|| json!(id - 1)).as_ref()
                    );
                }
                token = response.get("nextToken").cloned();
                if token.is_none() {
                    break;
                }
                assert_eq!(token, Some(json!(ids.len().to_string())));
            }
            let expected: Vec<_> = if reverse {
                (1..=17).rev().collect()
            } else {
                (1..=17).collect()
            };
            assert_eq!(ids, expected);
        }
    }
    let response = get_execution_history(
        &ctx,
        &json!({"executionArn":arn,"nextToken":usize::MAX.to_string()}),
    )
    .await
    .unwrap();
    assert_eq!(response, json!({"events":[]}));
    assert!(
        get_execution_history(&ctx, &json!({"executionArn":arn,"nextToken":"invalid"}))
            .await
            .is_err()
    );
    let foreign = Ctx {
        account: "111111111111",
        ..ctx
    };
    assert!(matches!(
        get_execution_history(&foreign, &json!({"executionArn":arn})).await,
        Err(SfnError::ExecutionDoesNotExist(_))
    ));
}

#[test]
#[ignore = "manual fixed-fixture history selection scaling measurement"]
fn history_page_scaling_benchmark() {
    use std::hint::black_box;
    use std::time::Instant;
    for count in [1000, 10_000, 25_000] {
        let history: Vec<u64> = (0..count).collect();
        let maximum = 100;
        let mut old = Vec::new();
        let mut new = Vec::new();
        for _ in 0..5 {
            let start = Instant::now();
            for _ in 0..2000 {
                let mut events: Vec<_> = black_box(&history).iter().collect();
                events.reverse();
                black_box(
                    events
                        .into_iter()
                        .take(maximum)
                        .copied()
                        .collect::<Vec<_>>(),
                );
            }
            old.push(start.elapsed().as_nanos() / 2000);
            let start = Instant::now();
            for _ in 0..2000 {
                black_box(history_ids(black_box(&history), 0, maximum, true));
            }
            new.push(start.elapsed().as_nanos() / 2000);
        }
        old.sort_unstable();
        new.sort_unstable();
        eprintln!("history_selection profile={} n={count} page={maximum} old_ns={} new_ns={} old_temporary_refs={count} new_temporary_refs=0", if cfg!(debug_assertions) { "debug" } else { "release" }, old[2], new[2]);
    }
}
