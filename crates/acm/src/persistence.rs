//! Encrypted certificate entities; runtime associations are rebuilt by their consumers.
use super::{internal, material::MaterialMetadata, AcmTlsIdentity, Certificate, Scope, State};
use locallycloud_core::error_mapping::AwsError;
use locallycloud_state::{StateCipher, StateDb};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::Zeroizing;

pub(super) struct AcmPersistence {
    db: Arc<StateDb>,
    cipher: StateCipher,
}

#[derive(Serialize, Deserialize)]
struct StoredCertificate {
    arn: String,
    metadata: MaterialMetadata,
    tags: BTreeMap<String, String>,
    imported_at: i64,
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}
impl Drop for StoredCertificate {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.private_key_der);
    }
}
impl AcmPersistence {
    pub fn new(db: Arc<StateDb>) -> Result<Self, AwsError> {
        Self::with_cipher(db, StateCipher::from_env().map_err(|_| internal())?)
    }
    fn with_cipher(db: Arc<StateDb>, cipher: StateCipher) -> Result<Self, AwsError> {
        db.connection().map_err(|_| internal())?.execute_batch(
            "CREATE TABLE IF NOT EXISTS acm_certificates(account TEXT NOT NULL,region TEXT NOT NULL,arn TEXT NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(account,region,arn));"
        ).map_err(|_| internal())?;
        Ok(Self { db, cipher })
    }
    pub fn restore(&self) -> Result<State, AwsError> {
        let connection = self.db.connection().map_err(|_| internal())?;
        let mut query = connection
            .prepare("SELECT account,region,arn,payload FROM acm_certificates")
            .map_err(|_| internal())?;
        let rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|_| internal())?;
        let mut state = State::default();
        for row in rows {
            let (account, region, arn, payload) = row.map_err(|_| internal())?;
            let bytes = self
                .cipher
                .open(&["acm", &account, &region, "certificate", &arn], &payload)
                .map_err(|_| internal())?;
            let mut stored: StoredCertificate =
                serde_json::from_slice(&bytes).map_err(|_| internal())?;
            if stored.arn != arn
                || stored.private_key_der.is_empty()
                || stored.certificate_der.is_empty()
            {
                return Err(internal());
            }
            let certificate = Certificate {
                arn,
                metadata: stored.metadata.clone(),
                tags: std::mem::take(&mut stored.tags),
                imported_at: stored.imported_at,
                tls: Some(Arc::new(AcmTlsIdentity {
                    certificate_der: std::mem::take(&mut stored.certificate_der),
                    private_key_der: Zeroizing::new(std::mem::take(&mut stored.private_key_der)),
                })),
                associations: BTreeMap::new(),
            };
            state
                .certs
                .entry(Scope { account, region })
                .or_default()
                .insert(certificate.arn.clone(), certificate);
        }
        Ok(state)
    }
    pub fn save(&self, scope: &Scope, certificate: &Certificate) -> Result<(), AwsError> {
        let tls = certificate.tls.as_ref().ok_or_else(internal)?;
        let stored = StoredCertificate {
            arn: certificate.arn.clone(),
            metadata: certificate.metadata.clone(),
            tags: certificate.tags.clone(),
            imported_at: certificate.imported_at,
            certificate_der: tls.certificate_der.clone(),
            private_key_der: tls.private_key_der.to_vec(),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&stored).map_err(|_| internal())?);
        let payload = self
            .cipher
            .seal(
                &[
                    "acm",
                    &scope.account,
                    &scope.region,
                    "certificate",
                    &certificate.arn,
                ],
                &bytes,
            )
            .map_err(|_| internal())?;
        self.db.connection().map_err(|_| internal())?.execute("INSERT INTO acm_certificates(account,region,arn,payload) VALUES(?1,?2,?3,?4) ON CONFLICT(account,region,arn) DO UPDATE SET payload=excluded.payload", params![scope.account,scope.region,certificate.arn,payload]).map_err(|_| internal())?;
        Ok(())
    }
    pub fn delete(&self, scope: &Scope, arn: &str) -> Result<(), AwsError> {
        self.db
            .connection()
            .map_err(|_| internal())?
            .execute(
                "DELETE FROM acm_certificates WHERE account=?1 AND region=?2 AND arn=?3",
                params![scope.account, scope.region, arn],
            )
            .map_err(|_| internal())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{tests::fixture, AcmAssociationApi, AcmHandler, AssociationDecision};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use locallycloud_core::handler::ServiceRequest;
    use serde_json::json;
    use std::sync::Mutex;

    fn request() -> ServiceRequest {
        ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: Default::default(),
            body: Default::default(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            request_id: "durability".into(),
        }
    }
    fn database() -> (std::path::PathBuf, Arc<StateDb>) {
        let directory =
            std::env::temp_dir().join(format!("locallycloud-acm-durable-{}", uuid::Uuid::new_v4()));
        let db = Arc::new(StateDb::open(directory.join("state.sqlite3")).unwrap());
        (directory, db)
    }
    fn handler(db: Arc<StateDb>) -> AcmHandler {
        let persistence = AcmPersistence::with_cipher(db, StateCipher::with_key(&[8; 32])).unwrap();
        AcmHandler {
            state: Arc::new(Mutex::new(persistence.restore().unwrap())),
            persistence: Some(Arc::new(persistence)),
        }
    }
    fn import(handler: &AcmHandler, req: &ServiceRequest) -> String {
        let (cert, key) = fixture("api.example.test", "2048");
        handler.import(req,json!({"Certificate":STANDARD.encode(cert),"PrivateKey":STANDARD.encode(&key),"Tags":[{"Key":"environment","Value":"local"}]}).as_object().unwrap()).unwrap()["CertificateArn"].as_str().unwrap().to_owned()
    }
    #[test]
    fn encrypted_restart_preserves_material_tags_scope_and_reacquires_associations() {
        let (directory, db) = database();
        let req = request();
        let first = handler(db.clone());
        let arn = import(&first, &req);
        first
            .acquire(
                &req.account_id,
                &req.region,
                &arn,
                "api.example.test",
                "consumer",
            )
            .unwrap();
        let identity = first
            .tls_identity(&req.account_id, &req.region, &arn, "api.example.test")
            .unwrap();
        let payload: Vec<u8> = db
            .connection()
            .unwrap()
            .query_row("SELECT payload FROM acm_certificates", [], |row| row.get(0))
            .unwrap();
        assert!(!payload
            .windows(b"private_key_der".len())
            .any(|bytes| bytes == b"private_key_der"));
        assert!(!payload
            .windows(b"environment".len())
            .any(|bytes| bytes == b"environment"));
        assert!(!payload
            .windows(identity.private_key_der.len())
            .any(|bytes| bytes == identity.private_key_der.as_slice()));
        drop(first);
        let restored = handler(db.clone());
        let lookup = json!({"CertificateArn":arn});
        let lookup = lookup.as_object().unwrap();
        let description = restored.describe(&req, lookup).unwrap();
        assert_eq!(description["Certificate"]["InUseBy"], json!([]));
        assert_eq!(
            restored.list_tags(&req, lookup).unwrap()["Tags"],
            json!([{"Key":"environment","Value":"local"}])
        );
        let actual = restored
            .tls_identity(&req.account_id, &req.region, &arn, "api.example.test")
            .unwrap();
        assert!(actual.private_key_der.as_slice() == identity.private_key_der.as_slice());
        assert_eq!(actual.certificate_der, identity.certificate_der);
        assert_eq!(
            restored.preflight(&req.account_id, "eu-west-1", &arn, "api.example.test"),
            AssociationDecision::NotFound
        );
        restored
            .acquire(
                &req.account_id,
                &req.region,
                &arn,
                "api.example.test",
                "consumer",
            )
            .unwrap();
        assert!(restored.delete(&req, lookup).is_err());
        assert!(
            AcmPersistence::with_cipher(db.clone(), StateCipher::with_key(&[9; 32]))
                .unwrap()
                .restore()
                .is_err()
        );
        restored
            .release(&req.account_id, &req.region, &arn, "consumer")
            .unwrap();
        restored.delete(&req, lookup).unwrap();
        drop(restored);
        assert!(handler(db.clone()).describe(&req, lookup).is_err());
        drop(db);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn failed_sql_commit_preserves_import_tags_and_delete_visibility() {
        let (directory, db) = database();
        let req = request();
        let handler = handler(db.clone());
        let arn = import(&handler, &req);
        let connection = db.connection().unwrap();
        connection.execute_batch("CREATE TRIGGER reject_acm_insert BEFORE INSERT ON acm_certificates BEGIN SELECT RAISE(FAIL,'fault'); END; CREATE TRIGGER reject_acm_delete BEFORE DELETE ON acm_certificates BEGIN SELECT RAISE(FAIL,'fault'); END;").unwrap();
        let (cert, key) = fixture("api.example.test", "2048");
        assert!(handler
            .import(
                &req,
                json!({"Certificate":STANDARD.encode(&cert),"PrivateKey":STANDARD.encode(&key)})
                    .as_object()
                    .unwrap()
            )
            .is_err());
        assert_eq!(
            handler
                .state
                .lock()
                .unwrap()
                .certs
                .values()
                .map(|scope| scope.len())
                .sum::<usize>(),
            1
        );
        let previous = handler
            .describe(&req, json!({"CertificateArn":arn}).as_object().unwrap())
            .unwrap();
        assert!(handler.import(&req,json!({"CertificateArn":arn,"Certificate":STANDARD.encode(&cert),"PrivateKey":STANDARD.encode(&key)}).as_object().unwrap()).is_err());
        assert_eq!(
            handler
                .describe(&req, json!({"CertificateArn":arn}).as_object().unwrap())
                .unwrap(),
            previous
        );
        assert!(handler
            .add_tags(
                &req,
                json!({"CertificateArn":arn,"Tags":[{"Key":"environment","Value":"changed"}]})
                    .as_object()
                    .unwrap()
            )
            .is_err());
        assert_eq!(
            handler
                .list_tags(&req, json!({"CertificateArn":arn}).as_object().unwrap())
                .unwrap()["Tags"][0]["Value"],
            "local"
        );
        assert!(handler
            .delete(&req, json!({"CertificateArn":arn}).as_object().unwrap())
            .is_err());
        assert_eq!(
            handler.preflight(&req.account_id, &req.region, &arn, "api.example.test"),
            AssociationDecision::Eligible
        );
        connection
            .execute_batch("DROP TRIGGER reject_acm_insert; DROP TRIGGER reject_acm_delete;")
            .unwrap();
        handler
            .delete(&req, json!({"CertificateArn":arn}).as_object().unwrap())
            .unwrap();
        drop(connection);
        drop(handler);
        drop(db);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
