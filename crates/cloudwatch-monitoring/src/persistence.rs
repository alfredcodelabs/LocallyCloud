use super::*;
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::params;

pub(super) struct Persistence {
    pub(super) db: Arc<StateDb>,
    pub(super) cipher: StateCipher,
}

pub(super) fn internal(error: impl std::fmt::Display) -> MonitoringError {
    MonitoringError::Internal(format!("monitoring persistence failed: {error}"))
}

impl Persistence {
    pub(super) fn new(db: Arc<StateDb>) -> Result<Self, MonitoringError> {
        let cipher = StateCipher::from_env().map_err(internal)?;
        Self::with_cipher(db, cipher)
    }

    pub(super) fn with_cipher(
        db: Arc<StateDb>,
        cipher: StateCipher,
    ) -> Result<Self, MonitoringError> {
        db.connection().map_err(internal)?.execute_batch("CREATE TABLE IF NOT EXISTS monitoring_points(account TEXT NOT NULL,region TEXT NOT NULL,correlation TEXT NOT NULL,ordinal INTEGER NOT NULL,ts INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,region,correlation,ordinal));CREATE INDEX IF NOT EXISTS monitoring_point_time ON monitoring_points(ts);").map_err(internal)?;
        Ok(Self { db, cipher })
    }

    pub(super) fn commit(
        &self,
        observations: &[MetricObservation],
    ) -> Result<Vec<MetricObservation>, MonitoringError> {
        let mut connection = self.db.connection().map_err(internal)?;
        let tx = connection.transaction().map_err(internal)?;
        let mut accepted = Vec::new();
        for (index, observation) in observations.iter().enumerate() {
            let index = if observation.origin == MetricOrigin::CloudWatchLogs
                && observation.correlation_id.starts_with("logs-effect:")
            {
                0
            } else {
                index
            };
            let ordinal = index.to_string();
            let context = [
                "monitoring-point",
                &observation.account_id,
                &observation.region,
                &observation.correlation_id,
                &ordinal,
            ];
            let payload = self
                .cipher
                .seal(
                    &context,
                    &serde_json::to_vec(observation).map_err(internal)?,
                )
                .map_err(internal)?;
            if tx.execute("INSERT OR IGNORE INTO monitoring_points(account,region,correlation,ordinal,ts,payload)VALUES(?1,?2,?3,?4,?5,?6)",params![observation.account_id,observation.region,observation.correlation_id,index as i64,observation.timestamp_ms,payload]).map_err(internal)? > 0 {
                accepted.push(observation.clone());
            }
        }
        tx.commit().map_err(internal)?;
        Ok(accepted)
    }

    pub(super) fn load(&self) -> Result<Vec<MetricObservation>, MonitoringError> {
        let connection = self.db.connection().map_err(internal)?;
        let mut statement = connection.prepare("SELECT account,region,correlation,ordinal,payload FROM monitoring_points ORDER BY ts").map_err(internal)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })
            .map_err(internal)?;
        let mut observations = Vec::new();
        for row in rows {
            let (account, region, correlation, index, payload) = row.map_err(internal)?;
            let ordinal = index.to_string();
            let data = self
                .cipher
                .open(
                    &[
                        "monitoring-point",
                        &account,
                        &region,
                        &correlation,
                        &ordinal,
                    ],
                    &payload,
                )
                .map_err(internal)?;
            let observation: MetricObservation = serde_json::from_slice(&data).map_err(internal)?;
            if observation.account_id != account
                || observation.region != region
                || observation.correlation_id != correlation
            {
                return Err(internal("metric identity mismatch"));
            }
            observations.push(observation);
        }
        Ok(observations)
    }
}
