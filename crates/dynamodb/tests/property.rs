//! Property-based tests for DynamoDB design Properties 1–18.
//!
//! These drive the real in-process handlers (no mocks) and the pure value engine.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use proptest::prelude::*;
use serde_json::{json, Value};

use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use locallycloud_dynamodb::expression::{ConditionExpression, UpdateExpression};
use locallycloud_dynamodb::service::DynamoHandler;
use locallycloud_dynamodb::value::{
    item_from_json, item_size, item_to_json, normalize_number, AttributeValue, Item,
};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}

fn req_with_prefix(prefix: &str, op: &str, body: Value) -> ServiceRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("{prefix}.{op}")).unwrap(),
    );
    ServiceRequest {
        method: Method::POST,
        uri: "/".parse().unwrap(),
        headers,
        body: Bytes::from(body.to_string()),
        region: "us-east-1".into(),
        account_id: "000000000000".into(),
        request_id: "rid".into(),
    }
}

fn req(op: &str, body: Value) -> ServiceRequest {
    req_with_prefix("DynamoDB_20120810", op, body)
}

async fn call(h: &DynamoHandler, op: &str, body: Value) -> (u16, Value) {
    let resp = if matches!(
        op,
        "ListStreams" | "DescribeStream" | "GetShardIterator" | "GetRecords"
    ) {
        h.streams_handler()
            .handle(req_with_prefix("DynamoDBStreams_20120810", op, body))
            .await
    } else {
        h.handle(req(op, body)).await
    };
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn create_pk_sk(h: &DynamoHandler, name: &str, stream: bool) {
    let mut body = json!({
        "TableName": name,
        "KeySchema": [
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"}
        ],
        "AttributeDefinitions": [
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "N"}
        ],
        "BillingMode": "PAY_PER_REQUEST"
    });
    if stream {
        body["StreamSpecification"] =
            json!({ "StreamEnabled": true, "StreamViewType": "NEW_IMAGE" });
    }
    let (s, _) = call(h, "CreateTable", body).await;
    assert_eq!(s, 200);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, .. ProptestConfig::default() })]

    /// Property 2: number normalization is idempotent and canonical.
    #[test]
    fn number_normalization_is_idempotent(n in -1_000_000i64..1_000_000) {
        let s = n.to_string();
        let once = normalize_number(&s).unwrap();
        let twice = normalize_number(&once).unwrap();
        prop_assert_eq!(once, twice);
    }

    /// Property 1: item marshalling round-trips (JSON → item → JSON → item).
    #[test]
    fn marshalling_round_trip(
        keys in proptest::collection::vec("[a-z]{1,6}", 1..5),
        vals in proptest::collection::vec("[a-zA-Z0-9 ]{0,10}", 1..5),
    ) {
        let mut obj = serde_json::Map::new();
        for (k, v) in keys.iter().zip(vals.iter()) {
            obj.insert(k.clone(), json!({ "S": v }));
        }
        let json_item = Value::Object(obj);
        let item = item_from_json(&json_item).unwrap();
        let again = item_from_json(&item_to_json(&item)).unwrap();
        prop_assert_eq!(item, again);
    }

    /// Property 3: equivalent decimal encodings normalize to one canonical representation.
    #[test]
    fn number_normalization_is_canonical(n in -1_000_000i64..1_000_000, zeros in 1usize..6) {
        let plain = normalize_number(&n.to_string()).unwrap();
        let padded = normalize_number(&format!("{n}.{}", "0".repeat(zeros))).unwrap();
        prop_assert_eq!(plain, padded);
    }

    /// Property 4: every generated item below the size limit is accepted on size grounds.
    #[test]
    fn item_size_boundary_accepts_valid_items(payload in "[a-zA-Z0-9]{0,2048}") {
        let item = item_from_json(&json!({"pk":{"S":"p"},"sk":{"N":"1"},"data":{"S":payload}})).unwrap();
        prop_assert!(item_size(&item) <= locallycloud_dynamodb::value::MAX_ITEM_SIZE);
        let h = DynamoHandler::new();
        rt().block_on(async {
            create_pk_sk(&h, "size", false).await;
            let (status, _) = call(&h, "PutItem", json!({"TableName":"size","Item":item_to_json(&item)})).await;
            prop_assert_eq!(status, 200);
            Ok(())
        }).unwrap();
    }

    /// Property 5: set membership is independent of wire order.
    #[test]
    fn set_order_is_independent(values in proptest::collection::vec("[a-z]{1,6}", 1..8)) {
        let unique: BTreeSet<String> = values.into_iter().collect();
        let forward: Vec<String> = unique.iter().cloned().collect();
        let reverse: Vec<String> = forward.iter().rev().cloned().collect();
        let a = item_from_json(&json!({"set":{"SS":forward}})).unwrap();
        let b = item_from_json(&json!({"set":{"SS":reverse}})).unwrap();
        prop_assert_eq!(a, b);
    }

    /// Property 6: a present scalar comparison and its logical negation are complementary.
    #[test]
    fn condition_negation_is_complementary(n in -100_000i64..100_000) {
        let mut item = Item::new();
        item.insert("n".into(), AttributeValue::N(n.to_string()));
        let values = HashMap::from([(":n".to_string(), AttributeValue::N(n.to_string()))]);
        let condition = ConditionExpression::parse("n = :n", &HashMap::new(), &values).unwrap();
        let negated = ConditionExpression::parse("NOT (n = :n)", &HashMap::new(), &values).unwrap();
        prop_assert_ne!(condition.matches(&item), negated.matches(&item));
    }

    /// Property 7: assigning a constant with SET is idempotent.
    #[test]
    fn set_assignment_is_idempotent(initial in "[a-z]{0,8}", assigned in "[a-z]{0,8}") {
        let mut item = Item::from([("value".into(), AttributeValue::S(initial))]);
        let values = HashMap::from([(":v".to_string(), AttributeValue::S(assigned))]);
        let update = UpdateExpression::parse("SET #v = :v", &HashMap::from([("#v".into(), "value".into())]), &values).unwrap();
        update.apply(&mut item).unwrap();
        let once = item.clone();
        update.apply(&mut item).unwrap();
        prop_assert_eq!(item, once);
    }

    /// Property 8: Query pagination completeness — paging by Limit covers every item once.
    #[test]
    fn query_pagination_is_complete(count in 1usize..15, page in 1usize..5) {
        let h = DynamoHandler::new();
        rt().block_on(async {
            create_pk_sk(&h, "pg", false).await;
            for i in 0..count {
                call(&h, "PutItem", json!({ "TableName": "pg", "Item": { "pk": {"S": "p"}, "sk": {"N": i.to_string()} } })).await;
            }
            let mut seen = std::collections::BTreeSet::new();
            let mut start: Option<Value> = None;
            loop {
                let mut q = json!({
                    "TableName": "pg",
                    "KeyConditionExpression": "pk = :p",
                    "ExpressionAttributeValues": { ":p": {"S": "p"} },
                    "Limit": page
                });
                if let Some(s) = &start { q["ExclusiveStartKey"] = s.clone(); }
                let (st, v) = call(&h, "Query", q).await;
                prop_assert_eq!(st, 200);
                for item in v["Items"].as_array().unwrap() {
                    seen.insert(item["sk"]["N"].as_str().unwrap().to_string());
                }
                match v.get("LastEvaluatedKey") {
                    Some(lek) => start = Some(lek.clone()),
                    None => break,
                }
            }
            prop_assert_eq!(seen.len(), count);
            Ok(())
        }).unwrap();
    }

    /// Property 9: parallel-scan coverage — segments partition the items disjointly and fully.
    #[test]
    fn parallel_scan_covers_all_once(count in 1usize..20, segments in 1usize..4) {
        let h = DynamoHandler::new();
        rt().block_on(async {
            create_pk_sk(&h, "ps", false).await;
            for i in 0..count {
                call(&h, "PutItem", json!({ "TableName": "ps", "Item": { "pk": {"S": format!("p{i}")}, "sk": {"N": "0"} } })).await;
            }
            let mut seen = std::collections::BTreeSet::new();
            for seg in 0..segments {
                let (st, v) = call(&h, "Scan", json!({ "TableName": "ps", "TotalSegments": segments, "Segment": seg })).await;
                prop_assert_eq!(st, 200);
                for item in v["Items"].as_array().unwrap() {
                    let pk = item["pk"]["S"].as_str().unwrap().to_string();
                    prop_assert!(seen.insert(pk), "each item appears in exactly one segment");
                }
            }
            prop_assert_eq!(seen.len(), count);
            Ok(())
        }).unwrap();
    }

    /// Property 10: every item containing its GSI key is retrievable through that GSI.
    #[test]
    fn gsi_covers_keyed_items(id in "[a-z]{1,8}", gsi_key in "[a-z]{1,8}") {
        let h = DynamoHandler::new();
        rt().block_on(async {
            let create = json!({
                "TableName":"gsi",
                "KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],
                "AttributeDefinitions":[
                    {"AttributeName":"id","AttributeType":"S"},
                    {"AttributeName":"g","AttributeType":"S"}
                ],
                "BillingMode":"PAY_PER_REQUEST",
                "GlobalSecondaryIndexes":[{
                    "IndexName":"by-g",
                    "KeySchema":[{"AttributeName":"g","KeyType":"HASH"}],
                    "Projection":{"ProjectionType":"ALL"}
                }]
            });
            prop_assert_eq!(call(&h, "CreateTable", create).await.0, 200);
            call(&h, "PutItem", json!({"TableName":"gsi","Item":{"id":{"S":id.clone()},"g":{"S":gsi_key.clone()}}})).await;
            let (status, result) = call(&h, "Query", json!({
                "TableName":"gsi","IndexName":"by-g",
                "KeyConditionExpression":"g = :g",
                "ExpressionAttributeValues":{":g":{"S":gsi_key}}
            })).await;
            prop_assert_eq!(status, 200);
            prop_assert_eq!(result["Items"][0]["id"]["S"].as_str(), Some(id.as_str()));
            Ok(())
        }).unwrap();
    }

    /// Property 11: a late transaction failure leaves every staged write unapplied.
    #[test]
    fn transaction_atomicity_holds(first in "[a-z]{1,8}", existing in "[i-z]{1,8}") {
        prop_assume!(first != existing);
        let h = DynamoHandler::new();
        rt().block_on(async {
            create_pk_sk(&h, "atomic", false).await;
            call(&h, "PutItem", json!({"TableName":"atomic","Item":{"pk":{"S":existing.clone()},"sk":{"N":"0"}}})).await;
            let transaction = json!({"TransactItems":[
                {"Put":{"TableName":"atomic","Item":{"pk":{"S":first.clone()},"sk":{"N":"0"}}}},
                {"Put":{"TableName":"atomic","Item":{"pk":{"S":existing},"sk":{"N":"0"}},"ConditionExpression":"attribute_not_exists(pk)"}}
            ]});
            prop_assert_eq!(call(&h, "TransactWriteItems", transaction).await.0, 400);
            let (_, item) = call(&h, "GetItem", json!({"TableName":"atomic","Key":{"pk":{"S":first},"sk":{"N":"0"}}})).await;
            prop_assert!(item.get("Item").is_none());
            Ok(())
        }).unwrap();
    }

    /// Property 12: replaying one ClientRequestToken does not re-apply an ADD update.
    #[test]
    fn transaction_token_is_idempotent(token_suffix in "[a-z0-9]{1,12}") {
        let h = DynamoHandler::new();
        rt().block_on(async {
            create_pk_sk(&h, "idem", false).await;
            call(&h, "PutItem", json!({"TableName":"idem","Item":{"pk":{"S":"p"},"sk":{"N":"0"},"count":{"N":"0"}}})).await;
            let transaction = json!({
                "ClientRequestToken":format!("token-{token_suffix}"),
                "TransactItems":[{"Update":{
                    "TableName":"idem","Key":{"pk":{"S":"p"},"sk":{"N":"0"}},
                    "UpdateExpression":"ADD #count :one",
                    "ExpressionAttributeNames":{"#count":"count"},
                    "ExpressionAttributeValues":{":one":{"N":"1"}}
                }}]
            });
            prop_assert_eq!(call(&h, "TransactWriteItems", transaction.clone()).await.0, 200);
            prop_assert_eq!(call(&h, "TransactWriteItems", transaction).await.0, 200);
            let (_, item) = call(&h, "GetItem", json!({"TableName":"idem","Key":{"pk":{"S":"p"},"sk":{"N":"0"}}})).await;
            prop_assert_eq!(item["Item"]["count"]["N"].as_str(), Some("1"));
            Ok(())
        }).unwrap();
    }

    /// Property 13: stream sequence numbers are strictly increasing.
    #[test]
    fn stream_records_are_ordered_and_complete(count in 1usize..12) {
        let h = DynamoHandler::new();
        rt().block_on(async {
            create_pk_sk(&h, "st", true).await;
            for i in 0..count {
                call(&h, "PutItem", json!({ "TableName": "st", "Item": { "pk": {"S": "p"}, "sk": {"N": i.to_string()} } })).await;
            }
            let (_, ls) = call(&h, "ListStreams", json!({ "TableName": "st" })).await;
            let arn = ls["Streams"][0]["StreamArn"].as_str().unwrap().to_string();
            let (_, d) = call(&h, "DescribeStream", json!({ "StreamArn": arn })).await;
            let shard = d["StreamDescription"]["Shards"][0]["ShardId"].as_str().unwrap().to_string();
            let (_, it) = call(&h, "GetShardIterator", json!({ "StreamArn": arn, "ShardId": shard, "ShardIteratorType": "TRIM_HORIZON" })).await;
            let iter = it["ShardIterator"].as_str().unwrap().to_string();
            let (_, rec) = call(&h, "GetRecords", json!({ "ShardIterator": iter })).await;
            let records = rec["Records"].as_array().unwrap();
            prop_assert_eq!(records.len(), count);
            let mut prev = String::new();
            for r in records {
                let seq = r["dynamodb"]["SequenceNumber"].as_str().unwrap().to_string();
                prop_assert!(seq > prev, "sequence numbers strictly increase");
                prev = seq;
            }
            Ok(())
        }).unwrap();
    }

    /// Property 14: following shard iterators returns every record exactly once.
    #[test]
    fn stream_reads_are_complete(count in 1usize..12, page in 1usize..5) {
        let h = DynamoHandler::new();
        rt().block_on(async {
            create_pk_sk(&h, "complete", true).await;
            for i in 0..count {
                call(&h, "PutItem", json!({"TableName":"complete","Item":{"pk":{"S":"p"},"sk":{"N":i.to_string()}}})).await;
            }
            let (_, listed) = call(&h, "ListStreams", json!({"TableName":"complete"})).await;
            let arn = listed["Streams"][0]["StreamArn"].as_str().unwrap().to_string();
            let (_, described) = call(&h, "DescribeStream", json!({"StreamArn":arn.clone()})).await;
            let shard = described["StreamDescription"]["Shards"][0]["ShardId"].as_str().unwrap().to_string();
            let (_, iterator) = call(&h, "GetShardIterator", json!({"StreamArn":arn,"ShardId":shard,"ShardIteratorType":"TRIM_HORIZON"})).await;
            let mut iterator = iterator["ShardIterator"].as_str().unwrap().to_string();
            let mut ids = BTreeSet::new();
            loop {
                let (_, response) = call(&h, "GetRecords", json!({"ShardIterator":iterator,"Limit":page})).await;
                let records = response["Records"].as_array().unwrap();
                if records.is_empty() { break; }
                for record in records {
                    prop_assert!(ids.insert(record["eventID"].as_str().unwrap().to_string()));
                }
                iterator = response["NextShardIterator"].as_str().unwrap().to_string();
            }
            prop_assert_eq!(ids.len(), count);
            Ok(())
        }).unwrap();
    }

    /// Property 15: PartiQL SELECT returns the same item a classic PutItem stored.
    #[test]
    fn partiql_matches_classic(val in "[a-zA-Z0-9]{1,12}") {
        let h = DynamoHandler::new();
        rt().block_on(async {
            create_pk_sk(&h, "pq", false).await;
            call(&h, "PutItem", json!({ "TableName": "pq", "Item": { "pk": {"S": "p"}, "sk": {"N": "1"}, "data": {"S": val.clone()} } })).await;
            let (st, v) = call(&h, "ExecuteStatement", json!({
                "Statement": "SELECT * FROM pq WHERE pk = ? AND sk = ?",
                "Parameters": [ {"S": "p"}, {"N": "1"} ]
            })).await;
            prop_assert_eq!(st, 200);
            prop_assert_eq!(v["Items"].as_array().unwrap().len(), 1);
            prop_assert_eq!(v["Items"][0]["data"]["S"].as_str().unwrap(), val.as_str());
            Ok(())
        }).unwrap();
    }

    /// Property 16: every generated missing-resource error has an SDK-deserializable type.
    #[test]
    fn errors_have_qualified_type(table in "[a-z]{1,12}") {
        let h = DynamoHandler::new();
        rt().block_on(async {
            let (status, body) = call(&h, "DescribeTable", json!({"TableName":table})).await;
            prop_assert_eq!(status, 400);
            prop_assert!(body["__type"].as_str().unwrap().ends_with("#ResourceNotFoundException"));
            Ok(())
        }).unwrap();
    }

    /// Property 17: region/account scoping — a name in one scope is invisible from another.
    #[test]
    fn scoping_isolates_names(name in "[a-z]{1,10}") {
        let h = DynamoHandler::new();
        rt().block_on(async {
            create_pk_sk(&h, &name, false).await;
            // A different region request for the same name does not resolve.
            let mut other = req("DescribeTable", json!({ "TableName": name }));
            other.region = "eu-west-1".into();
            let resp = h.handle(other).await;
            prop_assert_eq!(resp.status().as_u16(), 400);
            Ok(())
        }).unwrap();
    }

    /// Property 18: concurrent writes to distinct keys converge to their union.
    #[test]
    fn distinct_writes_are_confluent(count in 1usize..12) {
        let h = Arc::new(DynamoHandler::new());
        rt().block_on(async {
            create_pk_sk(&h, "confluent", false).await;
            let mut writes = tokio::task::JoinSet::new();
            for i in 0..count {
                let handler = h.clone();
                writes.spawn(async move {
                    call(&handler, "PutItem", json!({
                        "TableName":"confluent",
                        "Item":{"pk":{"S":format!("p{i}")},"sk":{"N":"0"}}
                    })).await.0
                });
            }
            while let Some(result) = writes.join_next().await {
                prop_assert_eq!(result.unwrap(), 200);
            }
            let (status, result) = call(&h, "Scan", json!({"TableName":"confluent"})).await;
            prop_assert_eq!(status, 200);
            prop_assert_eq!(result["Count"].as_u64(), Some(count as u64));
            Ok(())
        }).unwrap();
    }
}

/// Property 11 smoke: transaction atomicity — a failing condition rolls back all actions.
#[tokio::test]
async fn transaction_is_atomic_on_failure() {
    let h = DynamoHandler::new();
    create_pk_sk(&h, "tx", false).await;
    // Pre-existing item so the conditional Put fails.
    call(
        &h,
        "PutItem",
        json!({ "TableName": "tx", "Item": { "pk": {"S": "a"}, "sk": {"N": "0"} } }),
    )
    .await;
    let txn = json!({ "TransactItems": [
        { "Put": { "TableName": "tx", "Item": { "pk": {"S": "b"}, "sk": {"N": "0"} } } },
        { "Put": { "TableName": "tx", "Item": { "pk": {"S": "a"}, "sk": {"N": "0"} },
                   "ConditionExpression": "attribute_not_exists(pk)" } }
    ] });
    let (s, _) = call(&h, "TransactWriteItems", txn).await;
    assert_eq!(s, 400);
    // The first Put must have been rolled back (b not present).
    let (_, g) = call(
        &h,
        "GetItem",
        json!({ "TableName": "tx", "Key": { "pk": {"S": "b"}, "sk": {"N": "0"} } }),
    )
    .await;
    assert!(g.get("Item").is_none(), "atomicity: no partial writes");
}

/// Property 16 smoke: errors deserialize as the JSON 1.0 `__type` shape.
#[tokio::test]
async fn errors_render_type_shape() {
    let h = DynamoHandler::new();
    let (s, v) = call(
        &h,
        "GetItem",
        json!({ "TableName": "missing", "Key": { "id": {"S": "a"} } }),
    )
    .await;
    assert_eq!(s, 400);
    assert!(v["__type"]
        .as_str()
        .unwrap()
        .contains("ResourceNotFoundException"));
}
