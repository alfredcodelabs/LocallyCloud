use super::*;
use locallycloud_state::{StateCipher, StateDb};
use std::path::PathBuf;
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    database: Arc<StateDb>,
}

impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/analytics-tests")
            .join(Uuid::new_v4().to_string());
        let database = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        Self { root, database }
    }

    fn handler(&self) -> GlueHandler {
        let state =
            AnalyticsState::with_state(self.database.clone(), StateCipher::with_key(&[7; 32]))
                .unwrap();
        GlueHandler::new(Arc::new(state))
    }

    fn restore(&self, key: u8) -> Result<AnalyticsState, crate::persistence::PersistError> {
        // Reopen the actual database rather than retaining an in-memory state object.
        AnalyticsState::with_state(
            Arc::new(StateDb::open(self.database.path().to_owned())?),
            StateCipher::with_key(&[key; 32]),
        )
    }

    fn rows(&self) -> Vec<(String, Vec<u8>)> {
        self.database.connection().unwrap().prepare(
            "SELECT account||region||name,payload FROM glue_databases
             UNION ALL SELECT account||region||database_name||name,payload FROM glue_tables ORDER BY 1",
        ).unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap()
            .collect::<Result<_, _>>().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn call(
    handler: &GlueHandler,
    account: &str,
    region: &str,
    operation: &str,
    body: Value,
) -> Result<Value, AnalyticsError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE),
    );
    headers.insert(
        "x-amz-target",
        HeaderValue::from_str(&format!("AWSGlue.{operation}")).unwrap(),
    );
    handler.process(&ServiceRequest {
        method: http::Method::POST,
        uri: "/".parse().unwrap(),
        headers,
        body: body.to_string().into(),
        account_id: account.into(),
        region: region.into(),
        request_id: "durable-glue".into(),
    })
}

fn table_input(pointer: &str) -> Value {
    json!({"Name":"events","TableType":"EXTERNAL_TABLE",
        "Parameters":{"table_type":"ICEBERG","metadata_location":pointer},
        "StorageDescriptor":{"Location":"s3://lake/events/","Columns":[{"Name":"id","Type":"bigint"}]}})
}

fn seed(handler: &GlueHandler, account: &str, region: &str) {
    call(
        handler,
        account,
        region,
        "CreateDatabase",
        json!({"DatabaseInput":{"Name":"lake","Description":"private-catalog-description"}}),
    )
    .unwrap();
    call(handler, account, region, "CreateTable", json!({"DatabaseName":"lake","TableInput":table_input("s3://lake/events/metadata/one.json")})).unwrap();
}

#[test]
fn scoped_catalog_metadata_versions_and_deletions_survive_restart() {
    let fixture = Fixture::new();
    let handler = fixture.handler();
    let scopes = [
        ("111111111111", "us-east-1"),
        ("222222222222", "us-east-1"),
        ("111111111111", "eu-west-1"),
    ];
    for (account, region) in scopes {
        seed(&handler, account, region);
    }
    call(
        &handler,
        scopes[0].0,
        scopes[0].1,
        "UpdateDatabase",
        json!({"Name":"lake","DatabaseInput":{"Name":"lake","Description":"updated-description"}}),
    )
    .unwrap();
    let unchanged_database_rows: Vec<_> = fixture
        .rows()
        .into_iter()
        .filter(|(name, _)| !name.ends_with("events"))
        .collect();
    call(&handler, scopes[0].0, scopes[0].1, "UpdateTable", json!({"DatabaseName":"lake","VersionId":"1","TableInput":table_input("s3://lake/events/metadata/two.json")})).unwrap();
    assert_eq!(
        unchanged_database_rows,
        fixture
            .rows()
            .into_iter()
            .filter(|(name, _)| !name.ends_with("events"))
            .collect::<Vec<_>>()
    );
    let before: Vec<_> = scopes
        .iter()
        .map(|(account, region)| {
            (
                call(
                    &handler,
                    account,
                    region,
                    "GetDatabase",
                    json!({"Name":"lake"}),
                )
                .unwrap(),
                call(
                    &handler,
                    account,
                    region,
                    "GetTable",
                    json!({"DatabaseName":"lake","Name":"events"}),
                )
                .unwrap(),
            )
        })
        .collect();
    assert_eq!(before[0].1["Table"]["VersionId"], "2");
    assert_eq!(before[1].1["Table"]["VersionId"], "1");
    drop(handler);
    let handler = GlueHandler::new(Arc::new(fixture.restore(7).unwrap()));
    for ((account, region), expected) in scopes.into_iter().zip(before) {
        assert_eq!(
            call(
                &handler,
                account,
                region,
                "GetDatabase",
                json!({"Name":"lake"})
            )
            .unwrap(),
            expected.0
        );
        assert_eq!(
            call(
                &handler,
                account,
                region,
                "GetTable",
                json!({"DatabaseName":"lake","Name":"events"})
            )
            .unwrap(),
            expected.1
        );
    }
    let before = fixture.rows();
    assert!(matches!(
        call(
            &handler,
            scopes[0].0,
            scopes[0].1,
            "UpdateTable",
            json!({"DatabaseName":"lake","VersionId":"1","TableInput":table_input("s3://lake/events/metadata/stale.json")})
        ),
        Err(AnalyticsError::ConcurrentModification)
    ));
    assert_eq!(fixture.rows(), before);
    call(
        &handler,
        scopes[0].0,
        scopes[0].1,
        "DeleteTable",
        json!({"DatabaseName":"lake","Name":"events"}),
    )
    .unwrap();
    call(
        &handler,
        scopes[0].0,
        scopes[0].1,
        "DeleteDatabase",
        json!({"Name":"lake"}),
    )
    .unwrap();
    drop(handler);
    let handler = GlueHandler::new(Arc::new(fixture.restore(7).unwrap()));
    assert!(matches!(
        call(
            &handler,
            scopes[0].0,
            scopes[0].1,
            "GetDatabase",
            json!({"Name":"lake"})
        ),
        Err(AnalyticsError::EntityNotFound)
    ));
    assert!(matches!(
        call(
            &handler,
            scopes[0].0,
            scopes[0].1,
            "GetTable",
            json!({"DatabaseName":"lake","Name":"events"})
        ),
        Err(AnalyticsError::EntityNotFound)
    ));
    assert!(call(
        &handler,
        scopes[1].0,
        scopes[1].1,
        "GetTable",
        json!({"DatabaseName":"lake","Name":"events"})
    )
    .is_ok());
}

#[test]
fn failed_storage_mutations_leave_memory_and_durable_rows_unchanged() {
    let fixture = Fixture::new();
    let handler = fixture.handler();
    seed(&handler, "111111111111", "us-east-1");
    call(
        &handler,
        "111111111111",
        "us-east-1",
        "CreateDatabase",
        json!({"DatabaseInput":{"Name":"empty"}}),
    )
    .unwrap();
    for table in ["glue_databases", "glue_tables"] {
        for operation in ["INSERT", "UPDATE", "DELETE"] {
            fixture
                .database
                .connection()
                .unwrap()
                .execute_batch(&format!(
                    "CREATE TRIGGER fail_{table}_{operation} AFTER {operation} ON {table}
                 BEGIN SELECT RAISE(ABORT,'injected storage failure'); END;"
                ))
                .unwrap();
        }
    }
    let before = fixture.rows();
    let visible = |handler: &GlueHandler| {
        (
            call(
                handler,
                "111111111111",
                "us-east-1",
                "GetDatabases",
                json!({}),
            )
            .unwrap(),
            call(
                handler,
                "111111111111",
                "us-east-1",
                "GetTables",
                json!({"DatabaseName":"lake"}),
            )
            .unwrap(),
        )
    };
    let expected = visible(&handler);
    for (operation, body) in [
        ("CreateDatabase", json!({"DatabaseInput":{"Name":"other"}})),
        (
            "UpdateDatabase",
            json!({"Name":"lake","DatabaseInput":{"Name":"lake","Description":"changed"}}),
        ),
        ("DeleteDatabase", json!({"Name":"empty"})),
        (
            "CreateTable",
            json!({"DatabaseName":"lake","TableInput":{"Name":"other"}}),
        ),
        (
            "UpdateTable",
            json!({"DatabaseName":"lake","VersionId":"1","TableInput":table_input("s3://lake/events/metadata/two.json")}),
        ),
        (
            "DeleteTable",
            json!({"DatabaseName":"lake","Name":"events"}),
        ),
    ] {
        assert!(
            matches!(
                call(&handler, "111111111111", "us-east-1", operation, body),
                Err(AnalyticsError::Internal)
            ),
            "{operation}"
        );
        assert_eq!(visible(&handler), expected, "{operation}");
        assert_eq!(fixture.rows(), before, "{operation}");
    }
    drop(handler);
    assert_eq!(
        visible(&GlueHandler::new(Arc::new(fixture.restore(7).unwrap()))),
        expected
    );
}

#[test]
fn restoration_rejects_wrong_key_corruption_unsupported_schema_and_orphans() {
    for corruption in [
        "UPDATE glue_databases SET payload=x'00'",
        "UPDATE glue_tables SET version=2",
        "UPDATE glue_tables SET payload=x'00'",
        "PRAGMA foreign_keys=OFF; DELETE FROM glue_databases",
        "ALTER TABLE glue_tables RENAME COLUMN payload TO incompatible_payload",
    ] {
        let fixture = Fixture::new();
        let handler = fixture.handler();
        seed(&handler, "111111111111", "us-east-1");
        assert!(fixture.restore(8).is_err());
        let marker = b"private-catalog-description";
        assert!(fixture
            .rows()
            .iter()
            .all(|(_, payload)| !payload.windows(marker.len()).any(|p| p == marker)));
        drop(handler);
        fixture
            .database
            .connection()
            .unwrap()
            .execute_batch(corruption)
            .unwrap();
        assert!(fixture.restore(7).is_err(), "{corruption}");
    }
}
