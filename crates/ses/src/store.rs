//! Incremental encrypted state; every call executes on a blocking worker.
use crate::{
    config::{Provider, SesConfig},
    error::Error,
    model::{Identity, Mail},
};
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Envelope {
    pub mail: Mail,
    pub provider: String,
    pub binding: String,
    pub created: i64,
}
pub(crate) struct Job {
    pub id: String,
    pub envelope: Envelope,
    pub attempts: i64,
}
pub(crate) struct Store {
    db: Arc<StateDb>,
    cipher: StateCipher,
}
impl Store {
    pub fn open(db: Arc<StateDb>, cipher: StateCipher) -> Result<Arc<Self>, Error> {
        let store = Arc::new(Self { db, cipher });
        let connection = store.db.connection().map_err(|_| Error::Storage)?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS ses_identities(account TEXT NOT NULL,region TEXT NOT NULL,name TEXT NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,region,name));
            CREATE TABLE IF NOT EXISTS ses_messages(id TEXT PRIMARY KEY,account TEXT NOT NULL,region TEXT NOT NULL,status TEXT NOT NULL,provider TEXT NOT NULL,binding TEXT NOT NULL,payload BLOB NOT NULL,bytes INTEGER NOT NULL,created INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_at INTEGER NOT NULL DEFAULT 0,provider_id TEXT,cause TEXT);
            CREATE INDEX IF NOT EXISTS ses_due ON ses_messages(status,next_at);
            CREATE INDEX IF NOT EXISTS ses_messages_scope ON ses_messages(account,region);")?;
        for (table, kind, key) in [
            ("ses_identities", "identity", "name"),
            ("ses_messages", "message", "id"),
        ] {
            let sql = format!("SELECT account,region,{key},payload FROM {table}");
            let mut query = connection.prepare(&sql)?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                let account: String = row.get(0)?;
                let region: String = row.get(1)?;
                let id: String = row.get(2)?;
                let data: Vec<u8> = row.get(3)?;
                let _clear = store
                    .cipher
                    .open(&["ses", &account, &region, kind, &id], &data)
                    .map_err(|_| Error::Storage)?;
            }
        }
        Ok(store)
    }
    pub async fn run<T: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce(&Self) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || f(&store))
            .await
            .map_err(|_| Error::Storage)?
    }
    fn seal<T: Serialize>(
        &self,
        account: &str,
        region: &str,
        kind: &str,
        id: &str,
        v: &T,
    ) -> Result<Vec<u8>, Error> {
        let plain = Zeroizing::new(serde_json::to_vec(v).map_err(|_| Error::Storage)?);
        self.cipher
            .seal(&["ses", account, region, kind, id], &plain)
            .map_err(|_| Error::Storage)
    }
    fn decode<T: serde::de::DeserializeOwned>(
        &self,
        account: &str,
        region: &str,
        kind: &str,
        id: &str,
        data: &[u8],
    ) -> Result<T, Error> {
        let plain = self
            .cipher
            .open(&["ses", account, region, kind, id], data)
            .map_err(|_| Error::Storage)?;
        serde_json::from_slice(&plain).map_err(|_| Error::Storage)
    }
    pub fn create(
        &self,
        account: &str,
        region: &str,
        identity: &Identity,
        idempotent: bool,
    ) -> Result<(), Error> {
        let mut connection = self.db.connection().map_err(|_| Error::Storage)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<Vec<u8>> = tx
            .query_row(
                "SELECT payload FROM ses_identities WHERE account=?1 AND region=?2 AND name=?3",
                params![account, region, identity.name],
                |r| r.get(0),
            )
            .optional()?;
        let updated = if let Some(data) = prior {
            if !idempotent {
                return Err(Error::Exists);
            }
            let mut prior: Identity =
                self.decode(account, region, "identity", &identity.name, &data)?;
            prior.verified |= identity.verified;
            prior
        } else {
            identity.clone()
        };
        let data = self.seal(account, region, "identity", &updated.name, &updated)?;
        tx.execute("INSERT INTO ses_identities(account,region,name,payload) VALUES(?1,?2,?3,?4) ON CONFLICT(account,region,name) DO UPDATE SET payload=excluded.payload",params![account,region,updated.name,data])?;
        tx.commit()?;
        Ok(())
    }

    pub fn identity(&self, account: &str, region: &str, name: &str) -> Result<Identity, Error> {
        let data: Option<Vec<u8>> = self
            .db
            .connection()
            .map_err(|_| Error::Storage)?
            .query_row(
                "SELECT payload FROM ses_identities WHERE account=?1 AND region=?2 AND name=?3",
                params![account, region, name],
                |row| row.get(0),
            )
            .optional()?;
        self.decode(
            account,
            region,
            "identity",
            name,
            &data.ok_or(Error::Missing)?,
        )
    }
    pub fn list(
        &self,
        account: &str,
        region: &str,
        after: &str,
        limit: usize,
        kind: Option<&str>,
    ) -> Result<Vec<Identity>, Error> {
        let connection = self.db.connection().map_err(|_| Error::Storage)?;
        let mut query=connection.prepare("SELECT name,payload FROM ses_identities WHERE account=?1 AND region=?2 AND name>?3 AND (?5='' OR (?5='EMAIL_ADDRESS' AND instr(name,'@')>0) OR (?5='DOMAIN' AND instr(name,'@')=0)) ORDER BY name LIMIT ?4")?;
        let rows = query.query_map(
            params![account, region, after, limit as i64, kind.unwrap_or("")],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        rows.map(|row| {
            let (name, data) = row?;
            self.decode(account, region, "identity", &name, &data)
        })
        .collect()
    }
    pub fn delete(
        &self,
        account: &str,
        region: &str,
        name: &str,
        missing_ok: bool,
    ) -> Result<(), Error> {
        let count = self.db.connection().map_err(|_| Error::Storage)?.execute(
            "DELETE FROM ses_identities WHERE account=?1 AND region=?2 AND name=?3",
            params![account, region, name],
        )?;
        if count == 0 && !missing_ok {
            return Err(Error::Missing);
        }
        Ok(())
    }
    pub fn sender_identity(
        &self,
        account: &str,
        region: &str,
        sender: &str,
    ) -> Result<Option<String>, Error> {
        let domain = sender
            .rsplit_once('@')
            .map(|(_, d)| d.to_ascii_lowercase())
            .ok_or(Error::BadRequest("Invalid sender"))?;
        for name in [sender, domain.as_str()] {
            match self.identity(account, region, name) {
                Ok(identity) if identity.name != name => return Err(Error::Storage),
                Ok(identity) if identity.verified => return Ok(Some(name.into())),
                Ok(_) | Err(Error::Missing) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }
    pub fn accept(
        &self,
        account: &str,
        region: &str,
        mail: Mail,
        config: &SesConfig,
        binding: &str,
        identity_name: &str,
    ) -> Result<String, Error> {
        let mut connection = self.db.connection().map_err(|_| Error::Storage)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let domain = mail
            .sender
            .rsplit_once('@')
            .map(|(_, d)| d.to_ascii_lowercase())
            .ok_or(Error::BadRequest("Invalid sender"))?;
        if identity_name != mail.sender && identity_name != domain {
            return Err(Error::Rejected(
                "Sender identity does not match the message",
            ));
        }
        let data: Option<Vec<u8>> = tx
            .query_row(
                "SELECT payload FROM ses_identities WHERE account=?1 AND region=?2 AND name=?3",
                params![account, region, identity_name],
                |r| r.get(0),
            )
            .optional()?;
        let identity: Identity = self.decode(
            account,
            region,
            "identity",
            identity_name,
            &data.ok_or(Error::Rejected(
                "Email address is not verified in this account and region",
            ))?,
        )?;
        if !identity.verified {
            return Err(Error::Rejected(
                "Email address is not verified in this account and region",
            ));
        }
        if identity.name != identity_name {
            return Err(Error::Storage);
        }
        let id = uuid::Uuid::new_v4().to_string();
        let created = now();
        let envelope = Envelope {
            mail,
            provider: config.provider.name().into(),
            binding: binding.into(),
            created,
        };
        let payload = self.seal(account, region, "message", &id, &envelope)?;
        if config.provider != Provider::Capture {
            let (count,bytes):(i64,i64)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(bytes),0) FROM ses_messages WHERE status IN ('queued','sending','blocked','uncertain')",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
            if count >= config.max_pending_messages as i64
                || bytes.saturating_add(payload.len() as i64) > config.max_pending_bytes as i64
            {
                return Err(Error::Capacity);
            }
        }
        let status = if config.provider == Provider::Capture {
            "captured"
        } else {
            "queued"
        };
        tx.execute("INSERT INTO ses_messages(id,account,region,status,provider,binding,payload,bytes,created) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![id,account,region,status,envelope.provider,binding,payload,payload.len() as i64,created])?;
        tx.commit()?;
        Ok(id)
    }
    pub fn has_pending(&self) -> Result<bool, Error> {
        Ok(self
            .db
            .connection()
            .map_err(|_| Error::Storage)?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ses_messages WHERE status IN ('queued','sending'))",
                [],
                |r| r.get(0),
            )?)
    }
    pub fn claim(&self, binding: &str, timeout: u64) -> Result<Option<Job>, Error> {
        let mut connection = self.db.connection().map_err(|_| Error::Storage)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("UPDATE ses_messages SET status='blocked',cause='configuration_changed' WHERE status IN ('queued','sending') AND binding<>?1",[binding])?;
        let row=tx.query_row("SELECT id,account,region,payload,attempts FROM ses_messages WHERE status IN ('queued','sending') AND next_at<=?1 ORDER BY created,id LIMIT 1",[now()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,i64>(4)?))).optional()?;
        let Some((id, account, region, payload, attempts)) = row else {
            tx.commit()?;
            return Ok(None);
        };
        let envelope: Envelope = self.decode(&account, &region, "message", &id, &payload)?;
        if envelope.provider != "resend" || envelope.binding != binding {
            return Err(Error::Storage);
        }
        if now().saturating_sub(envelope.created) >= 23 * 3600 || attempts >= 8 {
            tx.execute("UPDATE ses_messages SET status='uncertain',cause='retry_window_exhausted' WHERE id=?1",[&id])?;
            tx.commit()?;
            tracing::warn!(service="ses",operation="SendEmail",message_id=%id,cause_code="retry_window_exhausted","SES delivery requires resolution after its retry window");
            return Ok(None);
        }
        tx.execute(
            "UPDATE ses_messages SET status='sending',attempts=attempts+1,next_at=?2 WHERE id=?1",
            params![id, now() + timeout as i64 + 30],
        )?;
        tx.commit()?;
        Ok(Some(Job {
            id,
            envelope,
            attempts: attempts + 1,
        }))
    }
    pub fn outcome(
        &self,
        id: &str,
        status: &str,
        provider_id: Option<&str>,
        cause: &str,
        delay: u64,
    ) -> Result<(), Error> {
        self.db.connection().map_err(|_| Error::Storage)?.execute(
            "UPDATE ses_messages SET status=?2,provider_id=?3,cause=?4,next_at=?5 WHERE id=?1",
            params![
                id,
                status,
                provider_id,
                cause,
                now().saturating_add(delay as i64)
            ],
        )?;
        Ok(())
    }
    pub fn encode_cursor(
        &self,
        account: &str,
        region: &str,
        action: &str,
        kind: Option<&str>,
        name: &str,
    ) -> Result<String, Error> {
        use base64::Engine;
        let data = self
            .cipher
            .seal(
                &["ses", "cursor", account, region, action, kind.unwrap_or("")],
                name.as_bytes(),
            )
            .map_err(|_| Error::Storage)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data))
    }
    pub fn decode_cursor(
        &self,
        account: &str,
        region: &str,
        action: &str,
        kind: Option<&str>,
        token: &str,
    ) -> Result<String, Error> {
        use base64::Engine;
        if token.is_empty() {
            return Ok(String::new());
        }
        if token.len() > 4096 {
            return Err(Error::BadRequest("Invalid continuation token"));
        }
        let bad = || Error::BadRequest("Invalid continuation token");
        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| bad())?;
        let name = self
            .cipher
            .open(
                &["ses", "cursor", account, region, action, kind.unwrap_or("")],
                &data,
            )
            .map_err(|_| bad())?;
        String::from_utf8(name.to_vec()).map_err(|_| bad())
    }
    pub fn regions(&self, account: &str) -> Result<Vec<String>, Error> {
        let connection = self.db.connection().map_err(|_| Error::Storage)?;
        let mut query=connection.prepare("SELECT region FROM ses_identities WHERE account=?1 UNION SELECT region FROM ses_messages WHERE account=?1 ORDER BY region")?;
        let regions = query
            .query_map([account], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(regions)
    }
}
