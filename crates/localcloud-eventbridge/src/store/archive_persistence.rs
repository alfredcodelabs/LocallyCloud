use super::*;
use crate::model::ArchivedEvent;
use rusqlite::{params, OptionalExtension};
use std::sync::atomic::Ordering;

fn archive_cutoff(retention_days: i64) -> Option<i64> {
    if retention_days <= 0 {
        return None;
    }
    OffsetDateTime::now_utc()
        .checked_sub(time::Duration::seconds(
            retention_days.saturating_mul(86_400),
        ))
        .and_then(|time| i64::try_from(time.unix_timestamp_nanos()).ok())
}

impl EbStore {
    pub async fn persist_archive(
        &self,
        account: &str,
        region: &str,
        name: &str,
    ) -> Result<(), String> {
        let Some(db) = &self.persistence else {
            return Ok(());
        };
        let _gate = self.persist_lock.lock().await;
        let scope = self.scope(account, region).await;
        let mut archive = scope
            .read()
            .await
            .archives
            .get(name)
            .cloned()
            .ok_or_else(|| format!("Archive {name} does not exist"))?;
        archive.events.clear();
        let payload = serde_json::to_vec(&archive).map_err(|error| error.to_string())?;
        let cutoff = archive_cutoff(archive.retention_days);
        let (account, region, name) = (account.to_owned(), region.to_owned(), name.to_owned());
        let db = db.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = db.connection().map_err(|error| error.to_string())?;
            let tx = conn.transaction().map_err(|error| error.to_string())?;
            tx.execute("INSERT INTO events_archives(account,region,name,payload) VALUES(?1,?2,?3,?4)
                ON CONFLICT(account,region,name) DO UPDATE SET payload=excluded.payload",
                params![account,region,name,payload]).map_err(|error| error.to_string())?;
            if let Some(cutoff) = cutoff {
                tx.execute("DELETE FROM events_archived_events WHERE account=?1 AND region=?2 AND archive_name=?3 AND time_ns<?4",
                    params![account,region,name,cutoff]).map_err(|error| error.to_string())?;
            }
            tx.commit().map_err(|error| error.to_string())
        }).await.map_err(|error| error.to_string()).and_then(|result| result);
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    pub async fn delete_persisted_archive(
        &self,
        account: &str,
        region: &str,
        name: &str,
    ) -> Result<(), String> {
        let Some(db) = &self.persistence else {
            return Ok(());
        };
        let _gate = self.persist_lock.lock().await;
        let (account, region, name) = (account.to_owned(), region.to_owned(), name.to_owned());
        let db = db.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = db.connection().map_err(|error| error.to_string())?;
            let tx = conn.transaction().map_err(|error| error.to_string())?;
            tx.execute("DELETE FROM events_archived_events WHERE account=?1 AND region=?2 AND archive_name=?3",
                params![account,region,name]).map_err(|error| error.to_string())?;
            tx.execute("DELETE FROM events_archives WHERE account=?1 AND region=?2 AND name=?3",
                params![account,region,name]).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())
        }).await.map_err(|error| error.to_string()).and_then(|result| result);
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    pub async fn accept_event(
        &self,
        fanout: PendingFanout,
        archived: Vec<(String, ArchivedEvent)>,
    ) -> Result<(), String> {
        let Some(db) = &self.persistence else {
            return Ok(());
        };
        let _gate = self.persist_lock.lock().await;
        let id = fanout.id.clone();
        let account = fanout.account.clone();
        let region = fanout.region.clone();
        let payload = serde_json::to_vec(&fanout).map_err(|error| error.to_string())?;
        let archived: Vec<_> = archived
            .into_iter()
            .map(|(name, event)| {
                Ok::<_, String>((
                    name,
                    i64::try_from(event.time.unix_timestamp_nanos())
                        .map_err(|_| "archived event timestamp is out of range".to_string())?,
                    serde_json::to_vec(&event).map_err(|error| error.to_string())?,
                ))
            })
            .collect::<Result<_, _>>()?;
        let db = db.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = db.connection().map_err(|error| error.to_string())?;
            let tx = conn.transaction().map_err(|error| error.to_string())?;
            tx.execute("INSERT INTO events_pending_fanout(id,payload) VALUES(?1,?2)",
                params![id,payload]).map_err(|error| error.to_string())?;
            for (name,time_ns,payload) in archived {
                let metadata: Vec<u8> = tx.query_row(
                    "SELECT payload FROM events_archives WHERE account=?1 AND region=?2 AND name=?3",
                    params![account,region,name], |row| row.get(0)
                ).optional().map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("Archive {name} is missing from durable store"))?;
                let archive: Archive = serde_json::from_slice(&metadata).map_err(|error| error.to_string())?;
                if let Some(cutoff) = archive_cutoff(archive.retention_days) {
                    tx.execute("DELETE FROM events_archived_events
                        WHERE account=?1 AND region=?2 AND archive_name=?3 AND time_ns<?4",
                        params![account,region,name,cutoff]).map_err(|error| error.to_string())?;
                }
                tx.execute("INSERT INTO events_archived_events(account,region,archive_name,time_ns,payload)
                    VALUES(?1,?2,?3,?4,?5)",params![account,region,name,time_ns,payload])
                    .map_err(|error| error.to_string())?;
            }
            tx.commit().map_err(|error| error.to_string())
        }).await.map_err(|error| error.to_string()).and_then(|result| result);
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    pub async fn persist_replay(
        &self,
        account: &str,
        region: &str,
        replay: &Replay,
        events: &[Value],
    ) -> Result<(), String> {
        let Some(db) = &self.persistence else {
            return Ok(());
        };
        let _gate = self.persist_lock.lock().await;
        let (account, region, name) = (account.to_owned(), region.to_owned(), replay.name.clone());
        let payload = serde_json::to_vec(replay).map_err(|error| error.to_string())?;
        let events = events
            .iter()
            .map(|event| serde_json::to_vec(event).map_err(|error| error.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let db = db.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = db.connection().map_err(|error| error.to_string())?;
            let tx = conn.transaction().map_err(|error| error.to_string())?;
            tx.execute("INSERT INTO events_replays(account,region,name,payload,cursor) VALUES(?1,?2,?3,?4,0)",
                params![account,region,name,payload]).map_err(|error| error.to_string())?;
            for (ordinal,payload) in events.into_iter().enumerate() {
                tx.execute("INSERT INTO events_replay_items(account,region,replay_name,ordinal,payload)
                    VALUES(?1,?2,?3,?4,?5)",params![account,region,name,ordinal as i64,payload])
                    .map_err(|error| error.to_string())?;
            }
            tx.commit().map_err(|error| error.to_string())
        }).await.map_err(|error| error.to_string()).and_then(|result| result);
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    pub async fn advance_replay(
        &self,
        account: &str,
        region: &str,
        name: &str,
        state: &str,
        cursor: usize,
    ) -> Result<bool, String> {
        self.update_replay_state(account, region, name, state, Some(cursor), true)
            .await
    }

    pub async fn set_replay_state(
        &self,
        account: &str,
        region: &str,
        name: &str,
        state: &str,
    ) -> Result<bool, String> {
        self.update_replay_state(account, region, name, state, None, true)
            .await
    }

    async fn update_replay_state(
        &self,
        account: &str,
        region: &str,
        name: &str,
        state: &str,
        cursor: Option<usize>,
        require_running: bool,
    ) -> Result<bool, String> {
        let Some(db) = &self.persistence else {
            return Ok(true);
        };
        let _gate = self.persist_lock.lock().await;
        let (account, region, name, state) = (
            account.to_owned(),
            region.to_owned(),
            name.to_owned(),
            state.to_owned(),
        );
        let db = db.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = db.connection().map_err(|error| error.to_string())?;
            let tx = conn.transaction().map_err(|error| error.to_string())?;
            let (payload,prior_cursor): (Vec<u8>,i64) = tx.query_row(
                "SELECT payload,cursor FROM events_replays WHERE account=?1 AND region=?2 AND name=?3",
                params![account,region,name], |row| Ok((row.get(0)?,row.get(1)?))
            ).optional().map_err(|error| error.to_string())?
                .ok_or_else(|| format!("Replay {name} does not exist"))?;
            let mut replay: Replay = serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
            if require_running && replay.state != "RUNNING" {
                return Ok(false);
            }
            replay.state = state.clone();
            let payload = serde_json::to_vec(&replay).map_err(|error| error.to_string())?;
            let cursor = cursor.map(|value| value as i64).unwrap_or(prior_cursor);
            tx.execute("UPDATE events_replays SET payload=?4,cursor=?5
                WHERE account=?1 AND region=?2 AND name=?3",
                params![account,region,name,payload,cursor]).map_err(|error| error.to_string())?;
            if state != "RUNNING" {
                tx.execute("DELETE FROM events_replay_items WHERE account=?1 AND region=?2 AND replay_name=?3",
                    params![account,region,name]).map_err(|error| error.to_string())?;
            }
            tx.commit().map_err(|error| error.to_string())?;
            Ok::<bool, String>(true)
        }).await.map_err(|error| error.to_string()).and_then(|result| result);
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    pub async fn snapshot_replay(
        &self,
        account: &str,
        region: &str,
        replay: &Replay,
    ) -> Result<usize, String> {
        let Some(db) = &self.persistence else {
            return Ok(0);
        };
        let _gate = self.persist_lock.lock().await;
        let archive_name = replay
            .source_arn
            .rsplit('/')
            .next()
            .ok_or_else(|| "invalid replay source ARN".to_string())?
            .to_owned();
        let start = i64::try_from(replay.start.unix_timestamp_nanos())
            .map_err(|_| "replay start timestamp is out of range".to_string())?;
        let end = i64::try_from(replay.end.unix_timestamp_nanos())
            .map_err(|_| "replay end timestamp is out of range".to_string())?;
        let (account, region, name, source_arn) = (
            account.to_owned(),
            region.to_owned(),
            replay.name.clone(),
            replay.source_arn.clone(),
        );
        let payload = serde_json::to_vec(replay).map_err(|error| error.to_string())?;
        let db = db.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = db.connection().map_err(|error| error.to_string())?;
            let tx = conn.transaction().map_err(|error| error.to_string())?;
            let metadata: Vec<u8> = tx.query_row(
                "SELECT payload FROM events_archives WHERE account=?1 AND region=?2 AND name=?3",
                params![account,region,archive_name], |row| row.get(0)
            ).optional().map_err(|error| error.to_string())?
                .ok_or_else(|| "Archive does not exist".to_string())?;
            let archive: Archive = serde_json::from_slice(&metadata).map_err(|error| error.to_string())?;
            if archive.arn != source_arn { return Err("Replay source archive mismatch".into()); }
            if let Some(cutoff) = archive_cutoff(archive.retention_days) {
                tx.execute("DELETE FROM events_archived_events
                    WHERE account=?1 AND region=?2 AND archive_name=?3 AND time_ns<?4",
                    params![account,region,archive_name,cutoff]).map_err(|error| error.to_string())?;
            }
            tx.execute("INSERT INTO events_replays(account,region,name,payload,cursor) VALUES(?1,?2,?3,?4,0)",
                params![account,region,name,payload]).map_err(|error| error.to_string())?;
            tx.execute("INSERT INTO events_replay_items(account,region,replay_name,ordinal,payload)
                SELECT ?1,?2,?3,row_number() OVER (ORDER BY seq)-1,payload
                FROM events_archived_events
                WHERE account=?1 AND region=?2 AND archive_name=?4 AND time_ns>=?5 AND time_ns<=?6
                ORDER BY seq",
                params![account,region,name,archive_name,start,end]).map_err(|error| error.to_string())?;
            let count: i64 = tx.query_row("SELECT count(*) FROM events_replay_items
                WHERE account=?1 AND region=?2 AND replay_name=?3",
                params![account,region,name], |row| row.get(0)).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            usize::try_from(count).map_err(|_| "replay snapshot too large".to_string())
        }).await.map_err(|error| error.to_string()).and_then(|result| result);
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    pub async fn load_replay_item(
        &self,
        account: &str,
        region: &str,
        name: &str,
        ordinal: usize,
    ) -> Result<Option<Value>, String> {
        let Some(db) = &self.persistence else {
            return Ok(None);
        };
        let db = db.clone();
        let (account, region, name) = (account.to_owned(), region.to_owned(), name.to_owned());
        tokio::task::spawn_blocking(move || {
            let conn = db.connection().map_err(|error| error.to_string())?;
            let payload: Option<Vec<u8>> = conn.query_row(
                "SELECT payload FROM events_replay_items WHERE account=?1 AND region=?2 AND replay_name=?3 AND ordinal=?4",
                params![account,region,name,ordinal as i64], |row| row.get(0)
            ).optional().map_err(|error| error.to_string())?;
            payload.map(|payload| {
                let mut event = match serde_json::from_slice::<ArchivedEvent>(&payload) {
                    Ok(archived) => archived.event,
                    Err(_) => serde_json::from_slice::<Value>(&payload).map_err(|error| error.to_string())?,
                };
                event["replay-name"] = Value::String(name);
                Ok(event)
            }).transpose()
        }).await.map_err(|error| error.to_string())?
    }

    pub async fn archive_count(
        &self,
        account: &str,
        region: &str,
        name: &str,
        now: OffsetDateTime,
    ) -> Result<usize, String> {
        let Some(db) = &self.persistence else {
            let scope = self.scope(account, region).await;
            return Ok(scope
                .read()
                .await
                .archives
                .get(name)
                .map_or(0, |archive| archive.events.len()));
        };
        let _gate = self.persist_lock.lock().await;
        let scope = self.scope(account, region).await;
        let retention = scope
            .read()
            .await
            .archives
            .get(name)
            .ok_or_else(|| format!("Archive {name} does not exist"))?
            .retention_days;
        let cutoff = if retention > 0 {
            now.checked_sub(time::Duration::seconds(retention.saturating_mul(86_400)))
                .and_then(|time| i64::try_from(time.unix_timestamp_nanos()).ok())
        } else {
            None
        };
        let (account, region, name) = (account.to_owned(), region.to_owned(), name.to_owned());
        let db = db.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = db.connection().map_err(|error| error.to_string())?;
            let tx = conn.transaction().map_err(|error| error.to_string())?;
            if let Some(cutoff) = cutoff {
                tx.execute("DELETE FROM events_archived_events WHERE account=?1 AND region=?2 AND archive_name=?3 AND time_ns<?4",
                    params![account,region,name,cutoff]).map_err(|error| error.to_string())?;
            }
            let count: i64 = tx.query_row("SELECT count(*) FROM events_archived_events
                WHERE account=?1 AND region=?2 AND archive_name=?3",
                params![account,region,name], |row| row.get(0)).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            usize::try_from(count).map_err(|_| "archive count too large".to_string())
        }).await.map_err(|error| error.to_string()).and_then(|result| result);
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    pub async fn pending_replays(
        &self,
    ) -> Result<Vec<(String, String, Replay, usize, usize)>, String> {
        let Some(db) = &self.persistence else {
            return Ok(Vec::new());
        };
        let db = db.clone();
        tokio::task::spawn_blocking(move || {
            let conn = db.connection().map_err(|error| error.to_string())?;
            let mut stmt = conn
                .prepare("SELECT account,region,name,payload,cursor FROM events_replays")
                .map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })
                .map_err(|error| error.to_string())?;
            let mut pending = Vec::new();
            for row in rows {
                let (account, region, name, payload, cursor) =
                    row.map_err(|error| error.to_string())?;
                let replay: Replay =
                    serde_json::from_slice(&payload).map_err(|error| error.to_string())?;
                if replay.name != name || cursor < 0 {
                    return Err("invalid EventBridge replay cursor".into());
                }
                if replay.state != "RUNNING" {
                    continue;
                }
                let (count, min, max): (i64, Option<i64>, Option<i64>) = conn
                    .query_row(
                        "SELECT count(*),min(ordinal),max(ordinal) FROM events_replay_items
                     WHERE account=?1 AND region=?2 AND replay_name=?3",
                        params![account, region, name],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .map_err(|error| error.to_string())?;
                if count < 0
                    || (count > 0 && (min != Some(0) || max != Some(count - 1)))
                    || cursor > count
                {
                    return Err("invalid EventBridge replay snapshot".into());
                }
                pending.push((account, region, replay, cursor as usize, count as usize));
            }
            Ok::<_, String>(pending)
        })
        .await
        .map_err(|error| error.to_string())?
    }
}

#[cfg(test)]
mod tests {
    use super::archive_cutoff;

    #[test]
    fn huge_retention_does_not_overflow() {
        assert_eq!(archive_cutoff(i64::MAX), None);
    }
}
