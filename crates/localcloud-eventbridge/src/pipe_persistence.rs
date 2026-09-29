use std::sync::Arc;

use localcloud_state::StateDb;
use rusqlite::params;

use crate::model::Pipe;

pub(super) fn load(db: &StateDb) -> Result<Vec<(String, String, Pipe)>, String> {
    let connection = db.connection().map_err(|error| error.to_string())?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS events_pipes (
        account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, payload BLOB NOT NULL,
        PRIMARY KEY(account, region, name)
    )",
        )
        .map_err(|error| error.to_string())?;
    let mut statement = connection
        .prepare("SELECT account, region, payload FROM events_pipes")
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    rows.map(|row| {
        let (account, region, payload) = row.map_err(|error| error.to_string())?;
        let pipe = serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
        Ok((account, region, pipe))
    })
    .collect()
}

pub(super) fn save(
    db: Option<Arc<StateDb>>,
    account: &str,
    region: &str,
    pipe: &Pipe,
) -> Result<(), String> {
    let Some(db) = db else {
        return Ok(());
    };
    let payload = serde_json::to_vec(pipe).map_err(|error| error.to_string())?;
    db.connection()
        .map_err(|error| error.to_string())?
        .execute(
            "INSERT INTO events_pipes(account,region,name,payload) VALUES(?1,?2,?3,?4)
            ON CONFLICT(account,region,name) DO UPDATE SET payload=excluded.payload",
            params![account, region, pipe.name, payload],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub(super) fn delete(
    db: Option<Arc<StateDb>>,
    account: &str,
    region: &str,
    name: &str,
) -> Result<(), String> {
    let Some(db) = db else {
        return Ok(());
    };
    db.connection()
        .map_err(|error| error.to_string())?
        .execute(
            "DELETE FROM events_pipes WHERE account=?1 AND region=?2 AND name=?3",
            params![account, region, name],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}
