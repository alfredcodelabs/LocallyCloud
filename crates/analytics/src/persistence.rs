//! Incremental encrypted Glue catalog records. Callers hold the scope lock.
use std::sync::Arc;

use locallycloud_state::{StateCipher, StateDb};
use rusqlite::params;

use crate::state::{AnalyticsState, DatabaseRecord, Scope, TableRecord};

pub(crate) type PersistError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) struct Persistence {
    database: Arc<StateDb>,
    cipher: StateCipher,
}

impl Persistence {
    pub(crate) fn new(database: Arc<StateDb>, cipher: StateCipher) -> Result<Self, PersistError> {
        database.connection()?.execute_batch(
            "CREATE TABLE IF NOT EXISTS glue_databases (
                account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
                version INTEGER NOT NULL, payload BLOB NOT NULL,
                PRIMARY KEY(account,region,name)
            );
            CREATE TABLE IF NOT EXISTS glue_tables (
                account TEXT NOT NULL, region TEXT NOT NULL, database_name TEXT NOT NULL,
                name TEXT NOT NULL, version INTEGER NOT NULL, payload BLOB NOT NULL,
                PRIMARY KEY(account,region,database_name,name),
                FOREIGN KEY(account,region,database_name)
                    REFERENCES glue_databases(account,region,name)
            );",
        )?;
        Ok(Self { database, cipher })
    }

    pub(crate) fn restore(&self, state: &AnalyticsState) -> Result<(), PersistError> {
        let connection = self.database.connection()?;
        let mut databases =
            connection.prepare("SELECT account,region,name,version,payload FROM glue_databases")?;
        let mut rows = databases.query([])?;
        while let Some(row) = rows.next()? {
            let account: String = row.get(0)?;
            let region: String = row.get(1)?;
            let name: String = row.get(2)?;
            check_version(row.get(3)?)?;
            let payload: Vec<u8> = row.get(4)?;
            let clear = self
                .cipher
                .open(&["glue", &account, &region, "database", &name], &payload)?;
            let record: DatabaseRecord = serde_json::from_slice(&clear)?;
            if record.input.name != name || !valid_times(record.create_time, record.update_time) {
                return Err(invalid_state());
            }
            state
                .catalog(&Scope::new(&account, &region))
                .lock()
                .map_err(|_| invalid_state())?
                .databases
                .insert(name, record);
        }
        let mut tables = connection
            .prepare("SELECT account,region,database_name,name,version,payload FROM glue_tables")?;
        let mut rows = tables.query([])?;
        while let Some(row) = rows.next()? {
            let account: String = row.get(0)?;
            let region: String = row.get(1)?;
            let database: String = row.get(2)?;
            let name: String = row.get(3)?;
            check_version(row.get(4)?)?;
            let payload: Vec<u8> = row.get(5)?;
            let clear = self.cipher.open(
                &["glue", &account, &region, "table", &database, &name],
                &payload,
            )?;
            let record: TableRecord = serde_json::from_slice(&clear)?;
            if record.input.name != name
                || record.version_id == 0
                || !valid_times(record.create_time, record.update_time)
            {
                return Err(invalid_state());
            }
            let slot = state.catalog(&Scope::new(&account, &region));
            let mut catalog = slot.lock().map_err(|_| invalid_state())?;
            catalog
                .databases
                .get_mut(&database)
                .ok_or_else(invalid_state)?
                .tables
                .insert(name, record);
        }
        Ok(())
    }

    pub(crate) fn save_database(
        &self,
        scope: &Scope,
        record: &DatabaseRecord,
    ) -> Result<(), PersistError> {
        let name = &record.input.name;
        let payload = self.cipher.seal(
            &["glue", scope.account_id(), scope.region(), "database", name],
            &serde_json::to_vec(record)?,
        )?;
        self.database.connection()?.execute(
            "INSERT INTO glue_databases(account,region,name,version,payload) VALUES (?1,?2,?3,1,?4)
             ON CONFLICT(account,region,name) DO UPDATE SET payload=excluded.payload",
            params![scope.account_id(), scope.region(), name, payload],
        )?;
        Ok(())
    }

    pub(crate) fn save_table(
        &self,
        scope: &Scope,
        database: &str,
        record: &TableRecord,
    ) -> Result<(), PersistError> {
        let name = &record.input.name;
        let payload = self.cipher.seal(
            &[
                "glue",
                scope.account_id(),
                scope.region(),
                "table",
                database,
                name,
            ],
            &serde_json::to_vec(record)?,
        )?;
        self.database.connection()?.execute(
            "INSERT INTO glue_tables(account,region,database_name,name,version,payload)
             VALUES (?1,?2,?3,?4,1,?5)
             ON CONFLICT(account,region,database_name,name) DO UPDATE SET payload=excluded.payload",
            params![scope.account_id(), scope.region(), database, name, payload],
        )?;
        Ok(())
    }

    pub(crate) fn delete_database(&self, scope: &Scope, name: &str) -> Result<(), PersistError> {
        let changed = self.database.connection()?.execute(
            "DELETE FROM glue_databases WHERE account=?1 AND region=?2 AND name=?3",
            params![scope.account_id(), scope.region(), name],
        )?;
        check_deleted(changed)
    }

    pub(crate) fn delete_table(
        &self,
        scope: &Scope,
        database: &str,
        name: &str,
    ) -> Result<(), PersistError> {
        let changed = self.database.connection()?.execute(
            "DELETE FROM glue_tables WHERE account=?1 AND region=?2 AND database_name=?3 AND name=?4",
            params![scope.account_id(), scope.region(), database, name],
        )?;
        check_deleted(changed)
    }
}

fn check_deleted(changed: usize) -> Result<(), PersistError> {
    if changed != 1 {
        return Err(invalid_state());
    }
    Ok(())
}

fn check_version(version: i64) -> Result<(), PersistError> {
    if version != 1 {
        return Err(std::io::Error::other(
            "unsupported Glue state version; use a compatible locallycloud binary",
        )
        .into());
    }
    Ok(())
}

fn valid_times(created: f64, updated: f64) -> bool {
    created.is_finite() && updated.is_finite() && created >= 0.0 && updated >= 0.0
}

fn invalid_state() -> PersistError {
    std::io::Error::other("invalid Glue catalog state; restore a consistent state database backup")
        .into()
}
