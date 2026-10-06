//! S3 store: bucket names are global; access to each bucket remains account-scoped.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use bytes::Bytes;
use dashmap::DashMap;
use md5::{Digest, Md5};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::RwLock;
use tokio_util::io::ReaderStream;

use crate::dirty::DirtyMap;
use crate::encryption::{EncryptedBody, StorageKeys, CHUNK};
use crate::error::S3Error;
use crate::integrity::ChecksumAlgorithm;
use crate::notifications::NotificationConfiguration;
use crate::persistence::StateRow;
use locallycloud_core::integration::kms::SensitiveBytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionMode {
    Governance,
    Compliance,
}

impl RetentionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Governance => "GOVERNANCE",
            Self::Compliance => "COMPLIANCE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRetention {
    pub mode: RetentionMode,
    pub retain_until: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultRetention {
    pub mode: RetentionMode,
    pub days: Option<i64>,
    pub years: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectLockConfiguration {
    pub default_retention: Option<DefaultRetention>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAccessBlock {
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorsRule {
    pub id: Option<String>,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age_seconds: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObjectPart {
    pub number: u16,
    pub size: usize,
    pub checksums: BTreeMap<ChecksumAlgorithm, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SseAlgorithm {
    Aes256,
    AwsKms,
}

impl SseAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes256 => "AES256",
            Self::AwsKms => "aws:kms",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSideEncryption {
    pub algorithm: SseAlgorithm,
    pub kms_key_arn: Option<String>,
    pub bucket_key_enabled: bool,
}

impl Default for ServerSideEncryption {
    fn default() -> Self {
        Self {
            algorithm: SseAlgorithm::Aes256,
            kms_key_arn: None,
            bucket_key_enabled: false,
        }
    }
}

// Small objects stay inline; larger bodies use an anonymous temporary file.
// Cloned versions and in-flight responses share one owner of the same bytes.
const INLINE_BODY_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub enum StoredBody {
    Inline(Bytes),
    Encrypted(Arc<EncryptedBody>),
    Opened(Arc<EncryptedBody>, Arc<SensitiveBytes>),
    Parts(Vec<StoredBody>),
    Range(Box<StoredBody>, usize, usize),
    DurableFile {
        path: PathBuf,
        len: usize,
    },
    File {
        file: Arc<std::fs::File>,
        len: usize,
        path: Option<PathBuf>,
    },
}

fn reopen(file: &std::fs::File) -> std::io::Result<std::fs::File> {
    std::fs::File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

impl StoredBody {
    pub fn new(body: Bytes) -> Result<Self, S3Error> {
        if body.len() <= INLINE_BODY_LIMIT {
            return Ok(Self::Inline(body));
        }
        let mut file = tempfile::tempfile().map_err(|_| S3Error::InternalError)?;
        file.write_all(&body).map_err(|_| S3Error::InternalError)?;
        Ok(Self::File {
            file: Arc::new(file),
            len: body.len(),
            path: None,
        })
    }

    pub fn from_parts(parts: &[Bytes]) -> Result<Self, S3Error> {
        let total = parts.iter().try_fold(0usize, |size, part| {
            size.checked_add(part.len()).ok_or(S3Error::InternalError)
        })?;
        if total <= INLINE_BODY_LIMIT {
            let mut body = Vec::with_capacity(total);
            for part in parts {
                body.extend_from_slice(part);
            }
            return Ok(Self::Inline(Bytes::from(body)));
        }
        let mut file = tempfile::tempfile().map_err(|_| S3Error::InternalError)?;
        for part in parts {
            file.write_all(part).map_err(|_| S3Error::InternalError)?;
        }
        Ok(Self::File {
            file: Arc::new(file),
            len: total,
            path: None,
        })
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Inline(body) => body.len(),
            Self::Encrypted(body) | Self::Opened(body, _) => body.logical_len,
            Self::Parts(parts) => parts.iter().map(Self::len).sum(),
            Self::Range(_, _, len) => *len,
            Self::File { len, .. } | Self::DurableFile { len, .. } => *len,
        }
    }

    pub fn single_part_etag(&self) -> Result<String, S3Error> {
        let mut hasher = Md5::new();
        let mut offset = 0;
        while offset < self.len() {
            let end = (offset + CHUNK).min(self.len());
            hasher.update(self.read_range(offset, end)?);
            offset = end;
        }
        let hex = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(format!("\"{hex}\""))
    }

    pub(crate) fn opaque_etag(&self) -> Result<String, S3Error> {
        let Self::Encrypted(body) = self else {
            return Err(S3Error::InternalError);
        };
        let hex = body
            .id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(format!("\"{hex}\""))
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn read_all(&self) -> Result<Bytes, S3Error> {
        match self {
            Self::Inline(body) => Ok(body.clone()),
            Self::Encrypted(_) => Err(S3Error::InternalError),
            Self::Opened(_, _) | Self::Parts(_) | Self::Range(_, _, _) => {
                self.read_range(0, self.len())
            }
            Self::DurableFile { .. } => self.read_range(0, self.len()),
            Self::File { file, .. } => {
                let mut reader = reopen(file).map_err(|_| S3Error::InternalError)?;
                let mut body = Vec::new();
                reader
                    .read_to_end(&mut body)
                    .map_err(|_| S3Error::InternalError)?;
                Ok(Bytes::from(body))
            }
        }
    }

    pub fn read_range(&self, start: usize, end: usize) -> Result<Bytes, S3Error> {
        if start > end || end > self.len() {
            return Err(S3Error::InternalError);
        }
        match self {
            Self::Inline(body) => Ok(body.slice(start..end)),
            Self::Encrypted(_) => Err(S3Error::InternalError),
            Self::Opened(body, key) => body.read_range(key, start, end),
            Self::Range(body, offset, len) => {
                if start > end || end > *len {
                    return Err(S3Error::InternalError);
                }
                body.read_range(offset + start, offset + end)
            }
            Self::Parts(parts) => {
                let mut output = Vec::with_capacity(end - start);
                let mut offset = 0;
                for part in parts {
                    let part_end = offset + part.len();
                    if start < part_end && end > offset {
                        output.extend_from_slice(&part.read_range(
                            start.saturating_sub(offset),
                            (end - offset).min(part.len()),
                        )?);
                    }
                    offset = part_end;
                }
                Ok(Bytes::from(output))
            }
            Self::DurableFile { path, .. } => {
                let mut reader = std::fs::File::open(path).map_err(|_| S3Error::InternalError)?;
                reader
                    .seek(SeekFrom::Start(start as u64))
                    .map_err(|_| S3Error::InternalError)?;
                let mut bytes = vec![0; end - start];
                reader
                    .read_exact(&mut bytes)
                    .map_err(|_| S3Error::InternalError)?;
                Ok(Bytes::from(bytes))
            }
            Self::File { file, .. } => {
                let mut reader = reopen(file).map_err(|_| S3Error::InternalError)?;
                reader
                    .seek(SeekFrom::Start(start as u64))
                    .map_err(|_| S3Error::InternalError)?;
                let mut bytes = vec![0; end - start];
                reader
                    .read_exact(&mut bytes)
                    .map_err(|_| S3Error::InternalError)?;
                Ok(Bytes::from(bytes))
            }
        }
    }

    /// Acquire readers before response headers while the service holds its bucket gate.
    /// The returned transient body retains open files through unlink/overwrite and streaming.
    fn pin_readers(&self) -> Result<Self, S3Error> {
        Ok(match self {
            Self::DurableFile { path, len } => Self::File {
                file: Arc::new(std::fs::File::open(path).map_err(|_| S3Error::InternalError)?),
                len: *len,
                path: Some(path.clone()),
            },
            Self::Encrypted(body) => {
                let mut pinned = (**body).clone();
                pinned.ciphertext = Box::new(body.ciphertext.pin_readers()?);
                Self::Encrypted(Arc::new(pinned))
            }
            Self::Opened(body, key) => {
                let mut pinned = (**body).clone();
                pinned.ciphertext = Box::new(body.ciphertext.pin_readers()?);
                Self::Opened(Arc::new(pinned), key.clone())
            }
            Self::Parts(parts) => Self::Parts(
                parts
                    .iter()
                    .map(Self::pin_readers)
                    .collect::<Result<_, _>>()?,
            ),
            Self::Range(body, offset, len) => {
                Self::Range(Box::new(body.pin_readers()?), *offset, *len)
            }
            _ => self.clone(),
        })
    }

    pub async fn response_body(&self, start: usize, len: usize) -> Result<Body, S3Error> {
        if start.checked_add(len).is_none_or(|end| end > self.len()) {
            return Err(S3Error::InternalError);
        }
        let pinned = self.pin_readers()?;
        match &pinned {
            Self::Inline(body) => Ok(Body::from(body.slice(start..start + len))),
            Self::Encrypted(_) => Err(S3Error::InternalError),
            Self::Opened(_, _) | Self::Parts(_) | Self::Range(_, _, _) => {
                let body = pinned.clone();
                let end = start + len;
                // Verify the first chunk before sending success headers, including empty objects.
                let first_body = body.clone();
                let first = tokio::task::spawn_blocking(move || {
                    first_body.read_range(start, (start + CHUNK).min(end))
                })
                .await
                .map_err(|_| S3Error::InternalError)??;
                let stream = futures_util::stream::try_unfold(
                    (body, start, end, Some(first)),
                    |(body, cursor, end, first)| async move {
                        if let Some(first) = first {
                            let next = cursor + first.len();
                            return Ok::<_, S3Error>(Some((first, (body, next, end, None))));
                        }
                        if cursor == end {
                            return Ok(None);
                        }
                        let next = (cursor + CHUNK).min(end);
                        let chunk_body = body.clone();
                        let bytes = tokio::task::spawn_blocking(move || {
                            chunk_body.read_range(cursor, next)
                        })
                        .await
                        .map_err(|_| S3Error::InternalError)??;
                        Ok(Some((bytes, (body, next, end, None))))
                    },
                );
                Ok(Body::from_stream(stream))
            }
            Self::DurableFile { .. } => Err(S3Error::InternalError),
            Self::File { file, .. } => {
                let reader = reopen(file).map_err(|_| S3Error::InternalError)?;
                let mut reader = tokio::fs::File::from_std(reader);
                reader
                    .seek(SeekFrom::Start(start as u64))
                    .await
                    .map_err(|_| S3Error::InternalError)?;
                Ok(Body::from_stream(ReaderStream::new(
                    reader.take(len as u64),
                )))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObject {
    /// Versioned encrypted body or explicitly recognized legacy plaintext body.
    pub body: StoredBody,
    pub etag: String,
    pub checksums: BTreeMap<ChecksumAlgorithm, String>,
    pub content_type: String,
    pub last_modified: OffsetDateTime,
    pub metadata: BTreeMap<String, String>,
    pub storage_class: String,
    pub tags: BTreeMap<String, String>,
    pub retention: Option<ObjectRetention>,
    pub legal_hold: bool,
    pub encryption: ServerSideEncryption,
    pub parts: Vec<StoredObjectPart>,
}

impl StoredObject {
    pub fn size(&self) -> usize {
        self.body.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersioningState {
    NeverEnabled,
    Enabled,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VersionValue {
    Object(Box<StoredObject>),
    DeleteMarker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredVersion {
    pub id: String,
    pub last_modified: OffsetDateTime,
    pub value: VersionValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPart {
    pub body: StoredBody,
    pub etag: String,
    pub checksums: BTreeMap<ChecksumAlgorithm, String>,
    pub last_modified: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartUpload {
    pub id: String,
    pub key: String,
    pub initiated: OffsetDateTime,
    pub content_type: String,
    pub metadata: BTreeMap<String, String>,
    pub storage_class: String,
    pub tags: BTreeMap<String, String>,
    pub retention: Option<ObjectRetention>,
    pub legal_hold: bool,
    pub encryption: ServerSideEncryption,
    #[serde(default)]
    pub key_envelope: Option<StoredBody>,
    #[serde(default)]
    pub parts: DirtyMap<u16, StoredPart>,
    pub parts_revision: u64,
}

/// Live bucket state behind a per-bucket lock.
#[derive(Clone, Serialize, Deserialize)]
pub struct BucketState {
    #[serde(skip)]
    pub(crate) transaction_gate: Arc<RwLock<()>>,
    pub name: String,
    pub region: String,
    pub creation_date: OffsetDateTime,
    pub notification_configuration: NotificationConfiguration,
    pub bucket_tags: Option<BTreeMap<String, String>>,
    pub cors: Option<Vec<CorsRule>>,
    pub policy: Option<String>,
    pub website: Option<String>,
    pub object_lock: Option<ObjectLockConfiguration>,
    pub public_access_block: Option<PublicAccessBlock>,
    pub encryption: ServerSideEncryption,
    /// Current readable objects. A latest delete marker removes the key from this index.
    #[serde(default)]
    pub objects: DirtyMap<String, StoredObject>,
    /// Version chains, newest first. Unversioned objects use the `null` sentinel.
    #[serde(default)]
    pub versions: DirtyMap<String, Vec<StoredVersion>>,
    pub versioning: VersioningState,
    #[serde(default)]
    pub uploads: DirtyMap<String, MultipartUpload>,
}

// Gate identity is immutable and can be looked up without taking bucket metadata locks.
struct StoredBucket {
    state: Arc<RwLock<BucketState>>,
    transaction_gate: Arc<RwLock<()>>,
}

impl StoredBucket {
    fn new(bucket: BucketState) -> Self {
        Self {
            transaction_gate: bucket.transaction_gate.clone(),
            state: Arc::new(RwLock::new(bucket)),
        }
    }
}

/// Globally named buckets with account-scoped access.
pub struct AccountStore {
    buckets: DashMap<String, (String, StoredBucket)>,
    account_public_access_blocks: DashMap<String, PublicAccessBlock>,
    next_id: AtomicU64,
    pub(crate) storage_keys: Arc<StorageKeys>,
}

impl Default for AccountStore {
    fn default() -> Self {
        Self {
            buckets: DashMap::new(),
            account_public_access_blocks: DashMap::new(),
            next_id: AtomicU64::new(1),
            storage_keys: Arc::new(StorageKeys::ephemeral().expect("S3 storage key generation")),
        }
    }
}

impl AccountStore {
    pub(crate) async fn resource_regions(
        &self,
        account: &str,
    ) -> Result<Vec<String>, &'static str> {
        let buckets: Vec<_> = self
            .buckets
            .iter()
            .filter(|e| e.value().0 == account)
            .map(|e| e.value().1.state.clone())
            .collect();
        let mut regions = Vec::new();
        for bucket in buckets {
            regions.push(bucket.read().await.region.clone());
        }
        Ok(regions)
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_upload_id(&self) -> String {
        format!(
            "lc-upload-{:016x}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        )
    }

    pub fn next_version_id(&self) -> String {
        format!(
            "lc-version-{:016x}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Reserve a bucket name across accounts and regions atomically.
    pub fn create(
        &self,
        account: &str,
        name: &str,
        region: &str,
        object_lock_enabled: bool,
    ) -> Result<(), S3Error> {
        use dashmap::mapref::entry::Entry;
        match self.buckets.entry(name.to_string()) {
            Entry::Occupied(slot) if slot.get().0 == account => {
                Err(S3Error::BucketAlreadyOwnedByYou)
            }
            Entry::Occupied(_) => Err(S3Error::BucketAlreadyExists),
            Entry::Vacant(slot) => {
                slot.insert((
                    account.to_string(),
                    StoredBucket::new(BucketState {
                        transaction_gate: Arc::new(RwLock::new(())),
                        name: name.to_string(),
                        region: region.to_string(),
                        creation_date: OffsetDateTime::now_utc(),
                        notification_configuration: NotificationConfiguration::default(),
                        bucket_tags: None,
                        cors: None,
                        policy: None,
                        website: None,
                        object_lock: object_lock_enabled.then_some(ObjectLockConfiguration {
                            default_retention: None,
                        }),
                        public_access_block: None,
                        encryption: ServerSideEncryption::default(),
                        objects: DirtyMap::default(),
                        versions: DirtyMap::default(),
                        versioning: if object_lock_enabled {
                            VersioningState::Enabled
                        } else {
                            VersioningState::NeverEnabled
                        },
                        uploads: DirtyMap::default(),
                    }),
                ));
                Ok(())
            }
        }
    }

    pub fn get(&self, account: &str, name: &str) -> Option<Arc<RwLock<BucketState>>> {
        self.buckets
            .get(name)
            .and_then(|entry| (entry.value().0 == account).then(|| entry.value().1.state.clone()))
    }

    pub(crate) fn transaction_gate(&self, account: &str, name: &str) -> Option<Arc<RwLock<()>>> {
        self.buckets.get(name).and_then(|entry| {
            (entry.value().0 == account).then(|| entry.value().1.transaction_gate.clone())
        })
    }

    pub fn exists(&self, account: &str, name: &str) -> bool {
        self.get(account, name).is_some()
    }

    pub fn remove(&self, account: &str, name: &str) -> Option<Arc<RwLock<BucketState>>> {
        use dashmap::mapref::entry::Entry;
        match self.buckets.entry(name.to_string()) {
            Entry::Occupied(slot) if slot.get().0 == account => Some(slot.remove().1.state),
            _ => None,
        }
    }

    pub fn account_public_access_block(&self, account: &str) -> Option<PublicAccessBlock> {
        self.account_public_access_blocks
            .get(account)
            .map(|entry| entry.clone())
    }

    pub fn put_account_public_access_block(&self, account: &str, block: PublicAccessBlock) {
        self.account_public_access_blocks
            .insert(account.to_string(), block);
    }

    pub fn delete_account_public_access_block(&self, account: &str) {
        self.account_public_access_blocks.remove(account);
    }

    /// All bucket names in an account, ascending.
    pub fn list_names(&self, account: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .buckets
            .iter()
            .filter(|entry| entry.value().0 == account)
            .map(|entry| entry.key().clone())
            .collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_is_exclusive_per_account() {
        let store = AccountStore::new();
        assert!(store.create("acc", "b", "us-east-1", false).is_ok());
        assert!(matches!(
            store.create("acc", "b", "us-east-1", false),
            Err(S3Error::BucketAlreadyOwnedByYou)
        ));
    }

    #[test]
    fn bucket_names_are_global_but_access_is_account_scoped() {
        let store = AccountStore::new();
        store.create("acc1", "shared", "us-east-1", false).unwrap();
        assert!(store.exists("acc1", "shared"));
        assert!(!store.exists("acc2", "shared"));
        assert!(matches!(
            store.create("acc2", "shared", "us-west-2", false),
            Err(S3Error::BucketAlreadyExists)
        ));
        assert!(store.remove("acc2", "shared").is_none());
        assert!(store.remove("acc1", "shared").is_some());
        assert!(store.create("acc2", "shared", "us-west-2", false).is_ok());
    }

    #[test]
    fn local_ids_are_atomic_and_deterministic() {
        let store = AccountStore::new();
        assert_eq!(store.next_upload_id(), "lc-upload-0000000000000001");
        assert_eq!(store.next_version_id(), "lc-version-0000000000000002");
    }
}

#[cfg(test)]
mod body_tests {
    use super::*;

    #[tokio::test]
    async fn durable_bodies_retain_no_idle_readers_and_pin_encrypted_composite_streams() {
        let dir = tempfile::tempdir().unwrap();
        let keys = StorageKeys::ephemeral().unwrap();
        let context = BTreeMap::new();
        let (key, wrapped) = keys.generate(&context).unwrap();
        let key = Arc::new(key);
        let mut small = Vec::new();
        for _ in 0..1000 {
            let encrypted = EncryptedBody::encrypt(
                &StoredBody::Inline(Bytes::from_static(b"small private object")),
                &key,
                wrapped.clone(),
                None,
                context.clone(),
            )
            .unwrap();
            let mut stored = StoredBody::Encrypted(Arc::new(encrypted));
            stored.make_durable(dir.path()).unwrap();
            let restored: StoredBody =
                serde_json::from_slice(&serde_json::to_vec(&stored).unwrap()).unwrap();
            let StoredBody::Encrypted(encrypted) = &restored else {
                panic!("encrypted storage envelope required");
            };
            assert!(
                matches!(&*encrypted.ciphertext, StoredBody::Inline(_)),
                "small durable ciphertext must not keep a file descriptor"
            );
            small.push(restored);
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let mut opened = Vec::new();
        let mut paths = Vec::new();
        let inputs = [
            Bytes::from(vec![b'a'; CHUNK * 2 + 17]),
            Bytes::from(vec![b'b'; CHUNK + 29]),
        ];
        for input in &inputs {
            let encrypted = EncryptedBody::encrypt(
                &StoredBody::Inline(input.clone()),
                &key,
                wrapped.clone(),
                None,
                context.clone(),
            )
            .unwrap();
            let mut stored = StoredBody::Encrypted(Arc::new(encrypted));
            stored.make_durable(dir.path()).unwrap();
            let restored: StoredBody =
                serde_json::from_slice(&serde_json::to_vec(&stored).unwrap()).unwrap();
            let StoredBody::Encrypted(encrypted) = restored else {
                panic!("encrypted storage envelope required");
            };
            let StoredBody::DurableFile { path, .. } = &*encrypted.ciphertext else {
                panic!("durable large ciphertext must use a path without retaining an open file");
            };
            paths.push(path.clone());
            opened.push(StoredBody::Opened(encrypted, key.clone()));
        }
        assert!(opened[0].read_range(2, 1).is_err());
        assert!(opened[0].read_range(0, inputs[0].len() + 1).is_err());
        let composite = StoredBody::Parts(vec![
            opened[0].clone(),
            StoredBody::Range(Box::new(opened[1].clone()), 3, inputs[1].len() - 3),
        ]);
        let response = composite.response_body(0, composite.len()).await.unwrap();
        // GC may unlink both blobs as soon as the response headers are returned.
        for path in paths {
            std::fs::remove_file(path).unwrap();
        }
        assert!(opened[0].read_range(CHUNK, CHUNK + 1).is_err());
        let received = axum::body::to_bytes(response, composite.len())
            .await
            .unwrap();
        let mut expected = inputs[0].to_vec();
        expected.extend_from_slice(&inputs[1][3..]);
        assert_eq!(received, Bytes::from(expected));
        assert_eq!(small.len(), 1000);
    }

    #[test]
    fn multipart_body_spills_without_assembling_in_memory() {
        let parts = [
            Bytes::from(vec![b'a'; INLINE_BODY_LIMIT]),
            Bytes::from_static(b"tail"),
        ];
        let body = StoredBody::from_parts(&parts).unwrap();
        assert!(matches!(body, StoredBody::File { .. }));
        assert_eq!(body.len(), INLINE_BODY_LIMIT + 4);
        assert_eq!(
            body.read_range(INLINE_BODY_LIMIT - 2, INLINE_BODY_LIMIT + 4)
                .unwrap(),
            Bytes::from_static(b"aatail")
        );
    }

    #[test]
    fn spilled_body_is_anonymous_and_shared_reads_survive_drop() {
        let bytes = Bytes::from(vec![b'x'; INLINE_BODY_LIMIT + 1]);
        let body = StoredBody::new(bytes.clone()).unwrap();
        let StoredBody::File { file, .. } = &body else {
            panic!("large body must spill to a temporary file");
        };
        use std::os::unix::fs::MetadataExt;
        assert_eq!(file.metadata().unwrap().nlink(), 0);
        assert_eq!(body.len(), bytes.len());
        assert_eq!(body.read_range(100, 110).unwrap(), bytes.slice(100..110));
        assert_eq!(body.read_all().unwrap(), bytes);
        assert_eq!(
            body.single_part_etag().unwrap(),
            crate::integrity::etag(&bytes)
        );
        let version = body.clone();
        drop(body);
        assert_eq!(version.read_all().unwrap(), bytes);
        drop(version);
    }
}

#[derive(Serialize, Deserialize)]
struct DurableStore {
    buckets: Vec<(String, String, serde_json::Value)>,
    account_public_access_blocks: Vec<(String, PublicAccessBlock)>,
    next_id: u64,
}

#[derive(Serialize, Deserialize)]
enum DurableBody {
    Inline(#[serde(with = "compact_bytes")] Vec<u8>),
    File(PathBuf),
    Encrypted(EncryptedBody),
}

// New rows use base64; existing JSON byte arrays remain readable.
mod compact_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Encoded {
            Base64(String),
            Legacy(Vec<u8>),
        }
        match Encoded::deserialize(deserializer)? {
            Encoded::Base64(value) => STANDARD.decode(value).map_err(serde::de::Error::custom),
            Encoded::Legacy(bytes) => Ok(bytes),
        }
    }
}

impl Serialize for StoredBody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let durable = match self {
            Self::Inline(bytes) => DurableBody::Inline(bytes.to_vec()),
            Self::Encrypted(body) | Self::Opened(body, _) => {
                DurableBody::Encrypted((**body).clone())
            }
            Self::Parts(_) | Self::Range(_, _, _) => {
                return Err(serde::ser::Error::custom("transient S3 composite body"))
            }
            Self::DurableFile { path, .. }
            | Self::File {
                path: Some(path), ..
            } => DurableBody::File(path.clone()),
            Self::File { path: None, .. } => {
                return Err(serde::ser::Error::custom(
                    "S3 body has not been made durable",
                ));
            }
        };
        durable.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StoredBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum CompatibleBody {
            Durable(DurableBody),
            LegacyPart(Vec<u8>),
        }
        let durable = match CompatibleBody::deserialize(deserializer)? {
            CompatibleBody::Durable(body) => body,
            CompatibleBody::LegacyPart(bytes) => DurableBody::Inline(bytes),
        };
        match durable {
            DurableBody::Encrypted(body) => Ok(Self::Encrypted(Arc::new(body))),
            DurableBody::Inline(bytes) => Ok(Self::Inline(Bytes::from(bytes))),
            DurableBody::File(path) => {
                let metadata = std::fs::metadata(&path).map_err(serde::de::Error::custom)?;
                let len = usize::try_from(metadata.len()).map_err(serde::de::Error::custom)?;
                Ok(Self::DurableFile { path, len })
            }
        }
    }
}

impl StoredBody {
    fn make_durable(&mut self, dir: &Path) -> Result<(), S3Error> {
        match self {
            Self::Encrypted(body) | Self::Opened(body, _) => {
                Arc::make_mut(body).ciphertext.make_durable(dir)?;
                return Ok(());
            }
            Self::Parts(_) | Self::Range(_, _, _) => return Err(S3Error::InternalError),
            _ => {}
        }
        match self {
            Self::Inline(_) | Self::DurableFile { .. } => return Ok(()),
            Self::File {
                path: Some(path),
                len,
                ..
            } => {
                *self = Self::DurableFile {
                    path: path.clone(),
                    len: *len,
                };
                return Ok(());
            }
            _ => {}
        }
        let mut temp = tempfile::NamedTempFile::new_in(dir).map_err(|_| S3Error::InternalError)?;
        match self {
            Self::Encrypted(_) | Self::Opened(_, _) | Self::Parts(_) | Self::Range(_, _, _) => {
                unreachable!("handled above")
            }
            Self::Inline(_) | Self::DurableFile { .. } => unreachable!("already durable"),
            Self::File { file, .. } => {
                let mut reader = reopen(file).map_err(|_| S3Error::InternalError)?;
                std::io::copy(&mut reader, &mut temp).map_err(|_| S3Error::InternalError)?;
            }
        }
        temp.as_file()
            .sync_all()
            .map_err(|_| S3Error::InternalError)?;
        let (_, path) = temp.keep().map_err(|_| S3Error::InternalError)?;
        std::fs::File::open(dir)
            .and_then(|file| file.sync_all())
            .map_err(|_| S3Error::InternalError)?;
        *self = Self::DurableFile {
            len: self.len(),
            path,
        };
        Ok(())
    }
}

impl AccountStore {
    pub fn durable_snapshot(&self, blobs: &Path) -> Result<Vec<u8>, S3Error> {
        let mut buckets = Vec::new();
        for entry in &self.buckets {
            let (account, bucket) = entry.value();
            let mut guard = bucket
                .state
                .try_write()
                .map_err(|_| S3Error::InternalError)?;
            for object in guard.objects.values_mut() {
                object.body.make_durable(blobs)?;
            }
            for chain in guard.versions.values_mut() {
                for version in chain {
                    if let VersionValue::Object(object) = &mut version.value {
                        object.body.make_durable(blobs)?;
                    }
                }
            }
            for upload in guard.uploads.values_mut() {
                if let Some(envelope) = &mut upload.key_envelope {
                    envelope.make_durable(blobs)?;
                }
                for part in upload.parts.values_mut() {
                    part.body.make_durable(blobs)?;
                }
            }
            buckets.push((
                account.clone(),
                entry.key().clone(),
                serde_json::to_value(&*guard).map_err(|_| S3Error::InternalError)?,
            ));
        }
        let account_public_access_blocks = self
            .account_public_access_blocks
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        serde_json::to_vec(&DurableStore {
            buckets,
            account_public_access_blocks,
            next_id: self.next_id.load(Ordering::Relaxed),
        })
        .map_err(|_| S3Error::InternalError)
    }

    pub(crate) fn restore_entries(
        &self,
        buckets: BTreeMap<(String, String), BucketState>,
        blocks: Vec<(String, PublicAccessBlock)>,
        next_id: u64,
    ) {
        // Restore is a complete committed snapshot, including absent namespaces.
        // The live recovery caller holds the namespace write gate.
        self.buckets.clear();
        self.account_public_access_blocks.clear();
        for ((account, name), mut bucket) in buckets {
            for (key, object) in &bucket.objects {
                if !bucket.versions.contains_key(key) {
                    bucket.versions.insert(
                        key.clone(),
                        vec![StoredVersion {
                            id: "null".into(),
                            last_modified: object.last_modified,
                            value: VersionValue::Object(Box::new(object.clone())),
                        }],
                    );
                }
            }
            bucket.objects.take_dirty();
            bucket.versions.take_dirty();
            for upload in bucket.uploads.values_mut() {
                upload.parts.take_dirty();
            }
            bucket.uploads.take_dirty();
            self.buckets
                .insert(name, (account, StoredBucket::new(bucket)));
        }
        for (account, block) in blocks {
            self.account_public_access_blocks.insert(account, block);
        }
        self.next_id.store(next_id, Ordering::Relaxed);
    }

    pub fn restore_snapshot(&self, payload: &[u8]) -> Result<(), S3Error> {
        let snapshot: DurableStore =
            serde_json::from_slice(payload).map_err(|_| S3Error::InternalError)?;
        for (account, name, value) in snapshot.buckets {
            let bucket = serde_json::from_value(value).map_err(|_| S3Error::InternalError)?;
            self.buckets
                .insert(name, (account, StoredBucket::new(bucket)));
        }
        for (account, block) in snapshot.account_public_access_blocks {
            self.account_public_access_blocks.insert(account, block);
        }
        self.next_id.store(snapshot.next_id, Ordering::Relaxed);
        Ok(())
    }
}

impl BucketState {
    fn metadata(&self) -> Result<Vec<u8>, S3Error> {
        #[derive(Serialize)]
        struct Metadata<'a> {
            name: &'a String,
            region: &'a String,
            creation_date: &'a OffsetDateTime,
            notification_configuration: &'a NotificationConfiguration,
            bucket_tags: &'a Option<BTreeMap<String, String>>,
            cors: &'a Option<Vec<CorsRule>>,
            policy: &'a Option<String>,
            website: &'a Option<String>,
            object_lock: &'a Option<ObjectLockConfiguration>,
            public_access_block: &'a Option<PublicAccessBlock>,
            encryption: &'a ServerSideEncryption,
            versioning: &'a VersioningState,
        }
        serde_json::to_vec(&Metadata {
            name: &self.name,
            region: &self.region,
            creation_date: &self.creation_date,
            notification_configuration: &self.notification_configuration,
            bucket_tags: &self.bucket_tags,
            cors: &self.cors,
            policy: &self.policy,
            website: &self.website,
            object_lock: &self.object_lock,
            public_access_block: &self.public_access_block,
            encryption: &self.encryption,
            versioning: &self.versioning,
        })
        .map_err(|_| S3Error::InternalError)
    }
}

impl MultipartUpload {
    fn metadata(&self) -> Result<Vec<u8>, S3Error> {
        #[derive(Serialize)]
        struct Metadata<'a> {
            id: &'a String,
            key: &'a String,
            initiated: &'a OffsetDateTime,
            content_type: &'a String,
            metadata: &'a BTreeMap<String, String>,
            storage_class: &'a String,
            tags: &'a BTreeMap<String, String>,
            retention: &'a Option<ObjectRetention>,
            legal_hold: &'a bool,
            encryption: &'a ServerSideEncryption,
            key_envelope: &'a Option<StoredBody>,
            parts_revision: &'a u64,
        }
        serde_json::to_vec(&Metadata {
            id: &self.id,
            key: &self.key,
            initiated: &self.initiated,
            content_type: &self.content_type,
            metadata: &self.metadata,
            storage_class: &self.storage_class,
            tags: &self.tags,
            retention: &self.retention,
            legal_hold: &self.legal_hold,
            encryption: &self.encryption,
            key_envelope: &self.key_envelope,
            parts_revision: &self.parts_revision,
        })
        .map_err(|_| S3Error::InternalError)
    }
}

impl AccountStore {
    pub(crate) fn durable_delta(
        &self,
        account: &str,
        name: Option<&str>,
        blobs: &Path,
    ) -> Result<Vec<StateRow>, S3Error> {
        let mut rows = Vec::new();
        let row = |kind: &str, key: String, subkey: String, payload: Option<Vec<u8>>| StateRow {
            account: account.into(),
            bucket: name.unwrap_or_default().into(),
            kind: kind.into(),
            key,
            subkey,
            payload,
        };
        let Some(name) = name else {
            let payload = self
                .account_public_access_blocks
                .get(account)
                .map(|v| serde_json::to_vec(v.value()).map_err(|_| S3Error::InternalError))
                .transpose()?;
            rows.push(row("account", account.into(), String::new(), payload));
            return Ok(rows);
        };
        let Some(bucket) = self.get(account, name) else {
            rows.push(row("bucket", String::new(), String::new(), None));
            return Ok(rows);
        };
        let mut guard = bucket.try_write().map_err(|_| {
            tracing::error!(
                stage = "bucket_lock",
                "S3 metadata guard was held during durable commit"
            );
            S3Error::InternalError
        })?;
        rows.push(row(
            "bucket",
            String::new(),
            String::new(),
            Some(guard.metadata()?),
        ));
        for key in guard.objects.take_dirty() {
            let payload = if let Some(object) = guard.objects.untracked_mut(&key) {
                object.body.make_durable(blobs)?;
                Some(serde_json::to_vec(object).map_err(|_| S3Error::InternalError)?)
            } else {
                None
            };
            rows.push(row("object", key, String::new(), payload));
        }
        let never_enabled = guard.versioning == VersioningState::NeverEnabled;
        for key in guard.versions.take_dirty() {
            let payload = if let Some(chain) = guard.versions.untracked_mut(&key) {
                if never_enabled
                    && chain.len() == 1
                    && chain[0].id == "null"
                    && matches!(chain[0].value, VersionValue::Object(_))
                {
                    rows.push(row("versions", key, String::new(), None));
                    continue;
                }
                for version in chain.iter_mut() {
                    if let VersionValue::Object(object) = &mut version.value {
                        object.body.make_durable(blobs)?;
                    }
                }
                Some(serde_json::to_vec(chain).map_err(|_| S3Error::InternalError)?)
            } else {
                None
            };
            rows.push(row("versions", key, String::new(), payload));
        }
        for key in guard.uploads.take_dirty() {
            if let Some(upload) = guard.uploads.untracked_mut(&key) {
                if let Some(body) = &mut upload.key_envelope {
                    body.make_durable(blobs)?;
                }
                rows.push(row(
                    "upload",
                    key.clone(),
                    String::new(),
                    Some(upload.metadata()?),
                ));
                for number in upload.parts.take_dirty() {
                    let payload = if let Some(part) = upload.parts.untracked_mut(&number) {
                        part.body.make_durable(blobs)?;
                        Some(serde_json::to_vec(part).map_err(|_| S3Error::InternalError)?)
                    } else {
                        None
                    };
                    rows.push(row("part", key.clone(), number.to_string(), payload));
                }
            } else {
                rows.push(row("upload", key, String::new(), None));
            }
        }
        Ok(rows)
    }
    pub(crate) fn durable_next_id(&self) -> u64 {
        self.next_id.load(Ordering::Relaxed)
    }
}
