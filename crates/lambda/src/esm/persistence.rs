use super::{state_error, EventSourceMapping};
use crate::error::LambdaError;
use locallycloud_state::StateDb;
use rusqlite::params;
use std::sync::Arc;

type CheckpointRow = ((String, String), (f64, Option<String>));

pub(super) struct Persistence {
    state: Arc<StateDb>,
}
impl Persistence {
    pub(super) fn open(state: Arc<StateDb>) -> Result<Self, LambdaError> {
        state.connection().map_err(|_| state_error())?.execute_batch(
            "CREATE TABLE IF NOT EXISTS lambda_event_source_mappings (uuid TEXT PRIMARY KEY, config TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS lambda_stream_checkpoints (uuid TEXT NOT NULL, shard TEXT NOT NULL, generation REAL NOT NULL, sequence TEXT,
            PRIMARY KEY(uuid,shard), FOREIGN KEY(uuid) REFERENCES lambda_event_source_mappings(uuid) ON DELETE CASCADE);"
        ).map_err(|_| state_error())?;
        Ok(Self { state })
    }
    pub(super) fn load(&self) -> Result<Vec<EventSourceMapping>, LambdaError> {
        let connection = self.state.connection().map_err(|_| state_error())?;
        let mut statement = connection
            .prepare("SELECT config FROM lambda_event_source_mappings")
            .map_err(|_| state_error())?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| state_error())?;
        rows.map(|row| {
            serde_json::from_str(&row.map_err(|_| state_error())?).map_err(|_| state_error())
        })
        .collect()
    }
    pub(super) fn save(&self, mapping: &EventSourceMapping) -> Result<(), LambdaError> {
        let config = serde_json::to_string(mapping).map_err(|_| state_error())?;
        self.state.connection().map_err(|_| state_error())?.execute(
            "INSERT INTO lambda_event_source_mappings VALUES (?1,?2) ON CONFLICT(uuid) DO UPDATE SET config=excluded.config", params![mapping.uuid,config]
        ).map_err(|_| state_error())?;
        Ok(())
    }
    pub(super) fn remove(&self, uuid: &str) -> Result<(), LambdaError> {
        self.state
            .connection()
            .map_err(|_| state_error())?
            .execute(
                "DELETE FROM lambda_event_source_mappings WHERE uuid=?1",
                [uuid],
            )
            .map_err(|_| state_error())?;
        Ok(())
    }
    pub(super) fn checkpoints(&self) -> Result<Vec<CheckpointRow>, LambdaError> {
        let connection = self.state.connection().map_err(|_| state_error())?;
        let mut statement = connection
            .prepare("SELECT uuid,shard,generation,sequence FROM lambda_stream_checkpoints")
            .map_err(|_| state_error())?;
        let rows = statement
            .query_map([], |row| {
                Ok(((row.get(0)?, row.get(1)?), (row.get(2)?, row.get(3)?)))
            })
            .map_err(|_| state_error())?;
        rows.collect::<Result<_, _>>().map_err(|_| state_error())
    }
    pub(super) fn save_checkpoint(
        &self,
        uuid: &str,
        shard: &str,
        generation: f64,
        sequence: Option<&str>,
    ) -> Result<(), LambdaError> {
        self.state.connection().map_err(|_| state_error())?.execute(
            "INSERT INTO lambda_stream_checkpoints VALUES (?1,?2,?3,?4) ON CONFLICT(uuid,shard) DO UPDATE SET generation=excluded.generation, sequence=excluded.sequence", params![uuid,shard,generation,sequence]
        ).map_err(|_| state_error())?;
        Ok(())
    }
}
