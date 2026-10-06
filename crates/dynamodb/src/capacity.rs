//! Optional controlled capacity for local retry tests; no adaptive or partition model.
use std::time::{Duration, Instant};

use crate::error::DdbError;
use crate::store::{TableData, TableDefinition, WarmThroughput};
use crate::value::{item_size, Item};

pub(crate) struct CapacityModel {
    pub enabled: bool,
    pub clock: fn() -> Instant,
}

impl Default for CapacityModel {
    fn default() -> Self {
        Self {
            enabled: std::env::var("LOCALLYCLOUD_DYNAMODB_SIMULATE_WRITE_LIMITS").as_deref()
                == Ok("1"),
            clock: Instant::now,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct WriteWindow {
    started: Option<Instant>,
    spent: u64,
}

impl CapacityModel {
    pub(crate) fn plan(
        &self,
        table: &TableData,
        units: u64,
        now: Instant,
    ) -> Result<WriteWindow, DdbError> {
        let mut window = table.write_window.clone();
        if !self.enabled || units == 0 {
            return Ok(window);
        }
        if window
            .started
            .is_none_or(|started| now.saturating_duration_since(started) >= Duration::from_secs(1))
        {
            window.started = Some(now);
            window.spent = 0;
        }
        let limit = write_limit(&table.def);
        if units > limit.saturating_sub(window.spent) {
            let message = "The controlled table write capacity was exceeded".into();
            return Err(match table.def.billing_mode.as_str() {
                "PROVISIONED" => DdbError::ProvisionedThroughputExceeded(message),
                _ => DdbError::Throttling(message),
            });
        }
        window.spent += units;
        Ok(window)
    }

    pub(crate) fn admit(
        &self,
        table: &mut TableData,
        old: Option<&Item>,
        new: Option<&Item>,
    ) -> Result<(), DdbError> {
        let plan = self.plan(table, write_units(old, new), (self.clock)())?;
        table.write_window = plan;
        Ok(())
    }
}

pub(crate) fn write_limit(def: &TableDefinition) -> u64 {
    match def.billing_mode.as_str() {
        "PROVISIONED" => def.write_capacity,
        _ => {
            def.warm_throughput
                .unwrap_or_else(|| WarmThroughput::baseline(0, 0))
                .write
        }
    }
}

pub(crate) fn write_units(old: Option<&Item>, new: Option<&Item>) -> u64 {
    let bytes = old
        .map(item_size)
        .unwrap_or(0)
        .max(new.map(item_size).unwrap_or(0));
    bytes.div_ceil(1024).max(1) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{self, Ctx};
    use crate::store::TableStore;
    use crate::value::item_from_json;
    use serde_json::json;
    use std::sync::LazyLock;

    fn fixed_time() -> Instant {
        static START: LazyLock<Instant> = LazyLock::new(Instant::now);
        *START
    }
    fn next_second() -> Instant {
        fixed_time() + Duration::from_secs(1)
    }
    fn context(store: &TableStore) -> Ctx<'_> {
        Ctx {
            store,
            account: "000000000000",
            region: "us-east-1",
        }
    }

    #[tokio::test]
    async fn ledger_write_limits_preserve_atomicity_retry_configuration_and_scopes() {
        let mut store = TableStore::new();
        store.capacity.enabled = true;
        store.capacity.clock = fixed_time;
        for (name, capacity) in [("ledger", 6), ("payments", 1)] {
            ops::create_table(&context(&store), &json!({"TableName":name,"KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PROVISIONED","ProvisionedThroughput":{"ReadCapacityUnits":1,"WriteCapacityUnits":capacity}})).await.unwrap();
        }
        let transaction = json!({"ClientRequestToken":"retry-throttle","TransactItems":[{"Put":{"TableName":"ledger","Item":{"id":{"S":"a"}}}},{"Put":{"TableName":"payments","Item":{"id":{"S":"a"}}}}]});
        let Err(DdbError::TransactionCanceled(reasons)) =
            ops::transact_write_items(&context(&store), &transaction).await
        else {
            panic!("expected throttle")
        };
        assert_eq!(reasons[0].code, "None");
        assert_eq!(reasons[1].code, "ProvisionedThroughputExceeded");
        for name in ["ledger", "payments"] {
            assert_eq!(
                ops::get_item(
                    &context(&store),
                    &json!({"TableName":name,"Key":{"id":{"S":"a"}}})
                )
                .await
                .unwrap(),
                json!({})
            );
            assert_eq!(
                store
                    .get("000000000000", "us-east-1", name)
                    .unwrap()
                    .read()
                    .await
                    .write_window
                    .spent,
                if name == "ledger" { 2 } else { 0 }
            );
        }
        let abandoned = store.txn_slot("000000000000", "us-east-1", "retry-throttle");
        store.purge_expired_txn_tokens();
        let active = store.txn_slot("000000000000", "us-east-1", "retry-throttle");
        assert!(std::sync::Arc::ptr_eq(&abandoned, &active));
        let old_pointer = std::sync::Arc::downgrade(&abandoned);
        drop(active);
        drop(abandoned);
        store.purge_expired_txn_tokens();
        assert!(
            old_pointer.upgrade().is_none(),
            "abandoned throttled token must not retain a permanent slot"
        );
        ops::update_table(&context(&store),&json!({"TableName":"payments","ProvisionedThroughput":{"ReadCapacityUnits":1,"WriteCapacityUnits":2}})).await.unwrap();
        ops::transact_write_items(&context(&store), &transaction)
            .await
            .unwrap();
        // A successful token replay must not spend capacity twice.
        ops::transact_write_items(&context(&store), &transaction)
            .await
            .unwrap();
        let item =
            item_from_json(&json!({"id":{"S":"a"},"payload":{"S":"x".repeat(1024)}})).unwrap();
        assert_eq!(write_units(None, Some(&item)), 2);
        ops::update_item(&context(&store),&json!({"TableName":"ledger","Key":{"id":{"S":"a"}},"UpdateExpression":"SET payload = :p","ExpressionAttributeValues":{":p":{"S":"x".repeat(1024)}}})).await.unwrap();
        assert!(matches!(
            ops::delete_item(
                &context(&store),
                &json!({"TableName":"ledger","Key":{"id":{"S":"a"}}})
            )
            .await,
            Err(DdbError::ProvisionedThroughputExceeded(_))
        ));
        assert!(matches!(
            ops::put_item(
                &context(&store),
                &json!({"TableName":"ledger","Item":{"id":{"S":"b"}}})
            )
            .await,
            Err(DdbError::ProvisionedThroughputExceeded(_))
        ));
        assert!(ops::get_item(
            &context(&store),
            &json!({"TableName":"ledger","Key":{"id":{"S":"a"}}})
        )
        .await
        .unwrap()
        .get("Item")
        .is_some());
        let foreign = Ctx {
            store: &store,
            account: "000000000000",
            region: "us-west-2",
        };
        assert!(matches!(
            ops::put_item(
                &foreign,
                &json!({"TableName":"ledger","Item":{"id":{"S":"b"}}})
            )
            .await,
            Err(DdbError::ResourceNotFound(_))
        ));
        store.capacity.clock = next_second;
        ops::delete_item(
            &context(&store),
            &json!({"TableName":"ledger","Key":{"id":{"S":"a"}}}),
        )
        .await
        .unwrap();
        let batch = json!({"RequestItems":{"payments":[{"PutRequest":{"Item":{"id":{"S":"b"}}}},{"PutRequest":{"Item":{"id":{"S":"c"}}}},{"PutRequest":{"Item":{"id":{"S":"d"}}}}]}});
        let response = ops::batch_write_item(&context(&store), &batch)
            .await
            .unwrap();
        assert_eq!(
            response["UnprocessedItems"]["payments"],
            json!([{"PutRequest":{"Item":{"id":{"S":"d"}}}}])
        );
        assert_eq!(
            ops::get_item(
                &context(&store),
                &json!({"TableName":"payments","Key":{"id":{"S":"d"}}})
            )
            .await
            .unwrap(),
            json!({})
        );
        // Failed conditions charge the old item, not a larger proposed replacement.
        ops::create_table(&context(&store), &json!({"TableName":"conditions","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PROVISIONED","ProvisionedThroughput":{"ReadCapacityUnits":1,"WriteCapacityUnits":8}})).await.unwrap();
        let old = json!({"id":{"S":"old"},"payload":{"S":"x".repeat(1024)}});
        ops::put_item(
            &context(&store),
            &json!({"TableName":"conditions","Item":old}),
        )
        .await
        .unwrap();
        let condition_table = store
            .get("000000000000", "us-east-1", "conditions")
            .unwrap();
        assert_eq!(condition_table.read().await.write_window.spent, 2);
        assert!(matches!(ops::put_item(&context(&store), &json!({"TableName":"conditions","Item":{"id":{"S":"old"}},"ConditionExpression":"??"})).await, Err(DdbError::Validation(_))));
        assert_eq!(
            condition_table.read().await.write_window.spent,
            2,
            "invalid expressions do not charge"
        );
        for (verb, request) in [
            (
                "Put",
                json!({"TableName":"conditions","Item":{"id":{"S":"old"},"payload":{"S":"x".repeat(3000)}},"ConditionExpression":"attribute_not_exists(id)"}),
            ),
            (
                "Update",
                json!({"TableName":"conditions","Key":{"id":{"S":"old"}},"UpdateExpression":"SET payload = :p","ExpressionAttributeValues":{":p":{"S":"x".repeat(3000)}},"ConditionExpression":"attribute_not_exists(id)"}),
            ),
            (
                "Delete",
                json!({"TableName":"conditions","Key":{"id":{"S":"old"}},"ConditionExpression":"attribute_not_exists(id)"}),
            ),
        ] {
            let result = match verb {
                "Put" => ops::put_item(&context(&store), &request).await,
                "Update" => ops::update_item(&context(&store), &request).await,
                _ => ops::delete_item(&context(&store), &request).await,
            };
            assert!(
                matches!(result, Err(DdbError::ConditionalCheckFailed(_))),
                "{verb}: {result:?}"
            );
        }
        assert_eq!(condition_table.read().await.write_window.spent, 8);
        assert_eq!(
            ops::get_item(
                &context(&store),
                &json!({"TableName":"conditions","Key":{"id":{"S":"old"}}})
            )
            .await
            .unwrap()["Item"],
            old
        );
        assert!(matches!(ops::delete_item(&context(&store), &json!({"TableName":"conditions","Key":{"id":{"S":"old"}},"ConditionExpression":"attribute_not_exists(id)"})).await, Err(DdbError::ProvisionedThroughputExceeded(_))));
        ops::create_table(&context(&store), &json!({"TableName":"missing","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"BillingMode":"PROVISIONED","ProvisionedThroughput":{"ReadCapacityUnits":1,"WriteCapacityUnits":1}})).await.unwrap();
        assert!(matches!(ops::put_item(&context(&store), &json!({"TableName":"missing","Item":{"id":{"S":"absent"},"payload":{"S":"x".repeat(3000)}},"ConditionExpression":"attribute_exists(id)"})).await, Err(DdbError::ConditionalCheckFailed(_))));
        assert_eq!(
            store
                .get("000000000000", "us-east-1", "missing")
                .unwrap()
                .read()
                .await
                .write_window
                .spent,
            1
        );
        assert!(matches!(
            ops::put_item(
                &context(&store),
                &json!({"TableName":"missing","Item":{"id":{"S":"absent"}}})
            )
            .await,
            Err(DdbError::ProvisionedThroughputExceeded(_))
        ));
        assert_eq!(
            ops::get_item(
                &context(&store),
                &json!({"TableName":"missing","Key":{"id":{"S":"absent"}}})
            )
            .await
            .unwrap(),
            json!({})
        );

        ops::update_table(&context(&store),&json!({"TableName":"payments","BillingMode":"PAY_PER_REQUEST","WarmThroughput":{"WriteUnitsPerSecond":8000}})).await.unwrap();
        let table = store.get("000000000000", "us-east-1", "payments").unwrap();
        let guard = table.read().await;
        assert_eq!(write_limit(&guard.def), 8000);
        assert!(store
            .capacity
            .plan(&guard, 8000, next_second() + Duration::from_secs(1))
            .is_ok());
        assert!(matches!(
            store
                .capacity
                .plan(&guard, 8001, next_second() + Duration::from_secs(1)),
            Err(DdbError::Throttling(_))
        ));
        drop(guard);
        fn third_second() -> Instant {
            fixed_time() + Duration::from_secs(2)
        }
        store.capacity.clock = third_second;
        let failed = json!({"TransactItems":[
            {"Put":{"TableName":"ledger","Item":{"id":{"S":"cancelled-ledger"}},"ConditionExpression":"attribute_exists(id)"}},
            {"Put":{"TableName":"payments","Item":{"id":{"S":"cancelled-payment"}}}}
        ]});
        let Err(DdbError::TransactionCanceled(reasons)) =
            ops::transact_write_items(&context(&store), &failed).await
        else {
            panic!("expected conditional cancellation");
        };
        assert_eq!(reasons[0].code, "ConditionalCheckFailed");
        assert_eq!(reasons[1].code, "None");
        for (name, key) in [
            ("ledger", "cancelled-ledger"),
            ("payments", "cancelled-payment"),
        ] {
            let table = store.get("000000000000", "us-east-1", name).unwrap();
            assert_eq!(
                table.read().await.write_window.spent,
                2,
                "canceled attempted write still charges {name}"
            );
            assert_eq!(
                ops::get_item(
                    &context(&store),
                    &json!({"TableName":name,"Key":{"id":{"S":key}}})
                )
                .await
                .unwrap(),
                json!({})
            );
        }
    }
}
