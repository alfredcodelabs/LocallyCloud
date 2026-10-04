//! Versioned authenticated body chunks; plaintext keys never enter durable state.
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;

use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM};
use aws_lc_rs::rand;
use bytes::Bytes;
use locallycloud_core::integration::kms::SensitiveBytes;
use locallycloud_state::StateDb;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::S3Error;
use crate::store::StoredBody;

pub(crate) const CHUNK: usize = 64 * 1024;
const OVERHEAD: usize = 12 + 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBody {
    pub version: u8,
    pub logical_len: usize,
    pub id: [u8; 16],
    pub wrapped_key: Vec<u8>,
    pub kms_key: Option<String>,
    pub context: BTreeMap<String, String>,
    pub ciphertext: Box<StoredBody>,
}

fn cipher(key: &[u8]) -> Result<RandomizedNonceKey, S3Error> {
    RandomizedNonceKey::new(&AES_256_GCM, key).map_err(|_| S3Error::InternalError)
}
fn seal(key: &[u8], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, S3Error> {
    let mut data = Zeroizing::new(plain.to_vec());
    let nonce = cipher(key)?
        .seal_in_place_append_tag(Aad::from(aad), &mut *data)
        .map_err(|_| S3Error::InternalError)?;
    let mut sealed = nonce.as_ref().to_vec();
    sealed.extend_from_slice(&data);
    Ok(sealed)
}
fn open(key: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, S3Error> {
    let nonce: [u8; 12] = sealed
        .get(..12)
        .ok_or(S3Error::InternalError)?
        .try_into()
        .map_err(|_| S3Error::InternalError)?;
    let mut data = Zeroizing::new(sealed[12..].to_vec());
    let plain_len = cipher(key)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut data,
        )
        .map_err(|_| S3Error::InternalError)?
        .len();
    data.truncate(plain_len);
    Ok(data)
}
fn random<const N: usize>() -> Result<[u8; N], S3Error> {
    let mut bytes = [0; N];
    rand::fill(&mut bytes).map_err(|_| S3Error::InternalError)?;
    Ok(bytes)
}
impl EncryptedBody {
    fn aad(&self, index: usize) -> Result<Vec<u8>, S3Error> {
        serde_json::to_vec(&(
            "locallycloud-s3-body",
            self.version,
            self.logical_len,
            self.id,
            &self.kms_key,
            &self.context,
            index,
        ))
        .map_err(|_| S3Error::InternalError)
    }
    pub fn encrypt(
        body: &StoredBody,
        key: &SensitiveBytes,
        wrapped_key: Vec<u8>,
        kms_key: Option<String>,
        context: BTreeMap<String, String>,
    ) -> Result<Self, S3Error> {
        let mut encrypted = Self {
            version: 1,
            logical_len: body.len(),
            id: random()?,
            wrapped_key,
            kms_key,
            context,
            ciphertext: Box::new(StoredBody::Inline(Bytes::new())),
        };
        let mut file = if body.len() > CHUNK - OVERHEAD {
            Some(tempfile::tempfile().map_err(|_| S3Error::InternalError)?)
        } else {
            None
        };
        let mut inline = Vec::new();
        // Include an authenticated zero-length chunk for empty objects.
        for index in 0..body.len().div_ceil(CHUNK).max(1) {
            let start = index * CHUNK;
            let plain = body.read_range(start, (start + CHUNK).min(body.len()))?;
            let sealed = seal(key.as_slice(), &encrypted.aad(index)?, &plain)?;
            if let Some(file) = &mut file {
                file.write_all(&sealed)
                    .map_err(|_| S3Error::InternalError)?;
            } else {
                inline.extend_from_slice(&sealed);
            }
        }
        encrypted.ciphertext = Box::new(if let Some(file) = file {
            let len = usize::try_from(file.metadata().map_err(|_| S3Error::InternalError)?.len())
                .map_err(|_| S3Error::InternalError)?;
            StoredBody::File {
                file: Arc::new(file),
                len,
                path: None,
            }
        } else {
            StoredBody::Inline(Bytes::from(inline))
        });
        Ok(encrypted)
    }
    pub fn read_range(
        &self,
        key: &SensitiveBytes,
        start: usize,
        end: usize,
    ) -> Result<Bytes, S3Error> {
        if self.version != 1 || start > end || end > self.logical_len {
            return Err(S3Error::InternalError);
        }
        let expected = self
            .logical_len
            .checked_add(
                self.logical_len
                    .div_ceil(CHUNK)
                    .max(1)
                    .checked_mul(OVERHEAD)
                    .ok_or(S3Error::InternalError)?,
            )
            .ok_or(S3Error::InternalError)?;
        if self.ciphertext.len() != expected {
            return Err(S3Error::InternalError);
        }
        if start == end && self.logical_len != 0 {
            return Ok(Bytes::new());
        }
        let first = start / CHUNK;
        let last = if start == end {
            first
        } else {
            (end - 1) / CHUNK
        };
        let mut result = Vec::with_capacity(end - start);
        for index in first..=last {
            let chunk_start = index * CHUNK;
            let logical_end = (chunk_start + CHUNK).min(self.logical_len);
            let encoded_start = index * (CHUNK + OVERHEAD);
            let encoded_end = encoded_start + logical_end - chunk_start + OVERHEAD;
            let sealed = self.ciphertext.read_range(encoded_start, encoded_end)?;
            let plain = open(key.as_slice(), &self.aad(index)?, &sealed)?;
            result.extend_from_slice(
                &plain[start.saturating_sub(chunk_start)..(end - chunk_start).min(plain.len())],
            );
        }
        Ok(Bytes::from(result))
    }
}

/// S3-owned wrapping material is separate from public/customer KMS keys.
#[derive(Debug)]
pub struct StorageKeys {
    wrapping: SensitiveBytes,
}
impl StorageKeys {
    pub fn ephemeral() -> Result<Self, S3Error> {
        Ok(Self {
            wrapping: SensitiveBytes::new(random::<32>()?.to_vec()),
        })
    }
    pub fn persistent(db: &StateDb) -> Result<Self, S3Error> {
        let master =
            locallycloud_state::external_master_key().map_err(|_| S3Error::InternalError)?;
        Self::with_master(db, &master)
    }
    pub fn with_master(db: &StateDb, master: &[u8]) -> Result<Self, S3Error> {
        let mut connection = db.connection().map_err(|_| S3Error::InternalError)?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS s3_storage_key (id INTEGER PRIMARY KEY CHECK(id=1), sealed BLOB NOT NULL)").map_err(|_| S3Error::InternalError)?;
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| S3Error::InternalError)?;
        let saved = tx.query_row("SELECT sealed FROM s3_storage_key WHERE id=1", [], |row| {
            row.get::<_, Vec<u8>>(0)
        });
        let aad = b"locallycloud-s3-wrapping-key-v1";
        let wrapping = match saved {
            Ok(saved) => open(master, aad, &saved)?,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let key = Zeroizing::new(random::<32>()?.to_vec());
                tx.execute(
                    "INSERT INTO s3_storage_key VALUES(1, ?1)",
                    [seal(master, aad, &key)?],
                )
                .map_err(|_| S3Error::InternalError)?;
                key
            }
            Err(_) => return Err(S3Error::InternalError),
        };
        if wrapping.len() != 32 {
            return Err(S3Error::InternalError);
        }
        tx.commit().map_err(|_| S3Error::InternalError)?;
        Ok(Self {
            wrapping: SensitiveBytes::new(wrapping.to_vec()),
        })
    }
    pub fn generate(
        &self,
        context: &BTreeMap<String, String>,
    ) -> Result<(SensitiveBytes, Vec<u8>), S3Error> {
        let key = SensitiveBytes::new(random::<32>()?.to_vec());
        let aad = serde_json::to_vec(&("locallycloud-s3-data-key-v1", context))
            .map_err(|_| S3Error::InternalError)?;
        let wrapped = seal(self.wrapping.as_slice(), &aad, key.as_slice())?;
        Ok((key, wrapped))
    }
    pub fn decrypt(
        &self,
        context: &BTreeMap<String, String>,
        wrapped: &[u8],
    ) -> Result<SensitiveBytes, S3Error> {
        let aad = serde_json::to_vec(&("locallycloud-s3-data-key-v1", context))
            .map_err(|_| S3Error::InternalError)?;
        let key = open(self.wrapping.as_slice(), &aad, wrapped)?;
        if key.len() != 32 {
            return Err(S3Error::InternalError);
        }
        Ok(SensitiveBytes::new(key.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StoredBody;

    #[tokio::test]
    async fn encrypted_chunks_survive_restart_ranges_and_reject_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let db = StateDb::open(dir.path().join("private/state.sqlite3")).unwrap();
        let keys = StorageKeys::with_master(&db, &[0x42; 32]).unwrap();
        let context = BTreeMap::from([("aws:s3:arn".into(), "arn:aws:s3:::orders/invoice".into())]);
        let input = Bytes::from("private invoice/order-2042;".repeat(7000));
        let (plain, wrapped) = keys.generate(&context).unwrap();
        let encrypted = EncryptedBody::encrypt(
            &StoredBody::Inline(input.clone()),
            &plain,
            wrapped,
            None,
            context.clone(),
        )
        .unwrap();
        assert!(!encrypted
            .ciphertext
            .read_all()
            .unwrap()
            .windows(25)
            .any(|value| value == &input[..25]));
        let restored = StorageKeys::with_master(&db, &[0x42; 32]).unwrap();
        assert!(StorageKeys::with_master(&db, &[0x43; 32]).is_err());
        let key = restored.decrypt(&context, &encrypted.wrapped_key).unwrap();
        assert_eq!(
            encrypted.read_range(&key, CHUNK - 11, CHUNK + 15).unwrap(),
            input.slice(CHUNK - 11..CHUNK + 15)
        );
        let opened = StoredBody::Opened(Arc::new(encrypted.clone()), Arc::new(key));
        let output = axum::body::to_bytes(
            opened.response_body(0, input.len()).await.unwrap(),
            input.len(),
        )
        .await
        .unwrap();
        assert_eq!(output, input);
        assert_eq!(
            opened.single_part_etag().unwrap(),
            crate::integrity::etag(&input)
        );
        let mut corrupt = encrypted.clone();
        let mut ciphertext = encrypted.ciphertext.read_all().unwrap().to_vec();
        ciphertext[12] ^= 1;
        *corrupt.ciphertext = StoredBody::Inline(Bytes::from(ciphertext));
        assert!(corrupt.read_range(&plain, 0, 20).is_err());
        assert!(encrypted
            .read_range(&SensitiveBytes::new(vec![0x11; 32]), 0, 20)
            .is_err());
        let mut swapped = encrypted.clone();
        swapped.logical_len -= 1;
        assert!(swapped.read_range(&plain, 0, 20).is_err());
        swapped = encrypted;
        swapped
            .context
            .insert("aws:s3:arn".into(), "arn:aws:s3:::orders/different".into());
        assert!(swapped.read_range(&plain, 0, 20).is_err());
    }

    #[test]
    fn empty_objects_are_authenticated_and_legacy_parts_decode() {
        let keys = StorageKeys::ephemeral().unwrap();
        let context = BTreeMap::from([("aws:s3:arn".into(), "arn:aws:s3:::orders/empty".into())]);
        let (key, wrapped) = keys.generate(&context).unwrap();
        let body = EncryptedBody::encrypt(
            &StoredBody::Inline(Bytes::new()),
            &key,
            wrapped,
            None,
            context,
        )
        .unwrap();
        assert_eq!(body.ciphertext.len(), OVERHEAD);
        assert_eq!(body.read_range(&key, 0, 0).unwrap(), Bytes::new());
        let mut truncated = body;
        *truncated.ciphertext = StoredBody::Inline(Bytes::new());
        assert!(truncated.read_range(&key, 0, 0).is_err());
        let old_part: StoredBody = serde_json::from_str("[1,2,3]").unwrap();
        assert_eq!(old_part.read_all().unwrap(), Bytes::from_static(&[1, 2, 3]));
    }
}
