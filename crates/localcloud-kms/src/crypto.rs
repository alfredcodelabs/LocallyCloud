use std::collections::BTreeMap;

use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::rand;
use zeroize::Zeroize;

use crate::error::KmsError;
use crate::model::{Scope, SecretMaterial};

const MAGIC: &[u8; 8] = b"LCKMSCT\0";
const VERSION: u8 = 1;
const TAG_LEN: usize = 16;
const MAX_SCOPE_PART: usize = 128;
const MAX_KEY_ID: usize = 128;
const MAX_CONTEXT: usize = 8 * 1024;
const MAX_CIPHERTEXT: usize = 4096 + TAG_LEN;
pub(crate) const MAX_ENVELOPE: usize = 16 * 1024;

pub(crate) struct Envelope {
    pub(crate) scope: Scope,
    pub(crate) key_id: String,
    pub(crate) material_version: u32,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

pub(crate) fn generate_data_key(length: usize) -> Result<Vec<u8>, KmsError> {
    if !(1..=1024).contains(&length) {
        return Err(KmsError::Validation);
    }
    let mut data = vec![0_u8; length];
    rand::fill(&mut data).map_err(|_| KmsError::Internal)?;
    Ok(data)
}

pub(crate) fn generate_material() -> Result<SecretMaterial, KmsError> {
    let mut material = [0_u8; 32];
    rand::fill(&mut material).map_err(|_| KmsError::Internal)?;
    Ok(SecretMaterial::new(material))
}

pub(crate) fn canonical_context(context: &BTreeMap<String, String>) -> Result<Vec<u8>, KmsError> {
    let encoded = serde_json::to_vec(context).map_err(|_| KmsError::Internal)?;
    if encoded.len() > MAX_CONTEXT {
        return Err(KmsError::Validation);
    }
    Ok(encoded)
}

pub(crate) fn seal(
    material: &SecretMaterial,
    scope: &Scope,
    key_id: &str,
    material_version: u32,
    context: &[u8],
    mut plaintext: Vec<u8>,
) -> Result<Vec<u8>, KmsError> {
    if plaintext.len() > 4096 {
        plaintext.zeroize();
        return Err(KmsError::Validation);
    }
    let aad = aad(scope, key_id, material_version, context)?;
    let key =
        RandomizedNonceKey::new(&AES_256_GCM, material.expose()).map_err(|_| KmsError::Internal)?;
    let nonce = match key.seal_in_place_append_tag(Aad::from(aad), &mut plaintext) {
        Ok(nonce) => nonce,
        Err(_) => {
            plaintext.zeroize();
            return Err(KmsError::Internal);
        }
    };

    let mut envelope = Vec::with_capacity(
        MAGIC.len()
            + 1
            + 2
            + scope.account_id.len()
            + 2
            + scope.region.len()
            + 2
            + key_id.len()
            + 4
            + NONCE_LEN
            + 4
            + plaintext.len(),
    );
    envelope.extend_from_slice(MAGIC);
    envelope.push(VERSION);
    put_string(&mut envelope, &scope.account_id)?;
    put_string(&mut envelope, &scope.region)?;
    put_string(&mut envelope, key_id)?;
    envelope.extend_from_slice(&material_version.to_be_bytes());
    envelope.extend_from_slice(&nonce.as_ref()[..]);
    let ciphertext_len = u32::try_from(plaintext.len()).map_err(|_| KmsError::Internal)?;
    envelope.extend_from_slice(&ciphertext_len.to_be_bytes());
    envelope.extend_from_slice(&plaintext);
    if envelope.len() > MAX_ENVELOPE {
        envelope.zeroize();
        return Err(KmsError::Internal);
    }
    Ok(envelope)
}

pub(crate) fn parse_envelope(bytes: &[u8]) -> Result<Envelope, KmsError> {
    if bytes.len() > MAX_ENVELOPE {
        return Err(KmsError::InvalidCiphertext);
    }
    let mut reader = Reader::new(bytes);
    if reader.take(MAGIC.len())? != MAGIC || reader.byte()? != VERSION {
        return Err(KmsError::InvalidCiphertext);
    }
    let account_id = reader.string(MAX_SCOPE_PART)?;
    let region = reader.string(MAX_SCOPE_PART)?;
    let key_id = reader.string(MAX_KEY_ID)?;
    let material_version = reader.u32()?;
    if material_version == 0 {
        return Err(KmsError::InvalidCiphertext);
    }
    let mut nonce = [0_u8; NONCE_LEN];
    nonce.copy_from_slice(reader.take(NONCE_LEN)?);
    let ciphertext_len = usize::try_from(reader.u32()?).map_err(|_| KmsError::InvalidCiphertext)?;
    if !(TAG_LEN..=MAX_CIPHERTEXT).contains(&ciphertext_len) {
        return Err(KmsError::InvalidCiphertext);
    }
    let ciphertext = reader.take(ciphertext_len)?.to_vec();
    if !reader.is_empty() {
        return Err(KmsError::InvalidCiphertext);
    }
    Ok(Envelope {
        scope: Scope { account_id, region },
        key_id,
        material_version,
        nonce,
        ciphertext,
    })
}

pub(crate) fn open(
    material: &SecretMaterial,
    envelope: Envelope,
    context: &[u8],
) -> Result<Vec<u8>, KmsError> {
    let aad = aad(
        &envelope.scope,
        &envelope.key_id,
        envelope.material_version,
        context,
    )?;
    let key =
        RandomizedNonceKey::new(&AES_256_GCM, material.expose()).map_err(|_| KmsError::Internal)?;
    let nonce = Nonce::assume_unique_for_key(envelope.nonce);
    let mut in_out = envelope.ciphertext;
    let plaintext_len = match key.open_in_place(nonce, Aad::from(aad), &mut in_out) {
        Ok(plaintext) => plaintext.len(),
        Err(_) => {
            in_out.zeroize();
            return Err(KmsError::InvalidCiphertext);
        }
    };
    in_out.truncate(plaintext_len);
    Ok(in_out)
}

fn aad(
    scope: &Scope,
    key_id: &str,
    material_version: u32,
    context: &[u8],
) -> Result<Vec<u8>, KmsError> {
    let mut aad = b"localcloud-kms-aad-v1".to_vec();
    put_string(&mut aad, &scope.account_id)?;
    put_string(&mut aad, &scope.region)?;
    put_string(&mut aad, key_id)?;
    aad.extend_from_slice(&material_version.to_be_bytes());
    let context_len = u32::try_from(context.len()).map_err(|_| KmsError::Validation)?;
    aad.extend_from_slice(&context_len.to_be_bytes());
    aad.extend_from_slice(context);
    Ok(aad)
}

fn put_string(output: &mut Vec<u8>, value: &str) -> Result<(), KmsError> {
    let length = u16::try_from(value.len()).map_err(|_| KmsError::Validation)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], KmsError> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(KmsError::InvalidCiphertext)?;
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, KmsError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, KmsError> {
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(bytes))
    }

    fn string(&mut self, maximum: usize) -> Result<String, KmsError> {
        let mut length = [0_u8; 2];
        length.copy_from_slice(self.take(2)?);
        let length = usize::from(u16::from_be_bytes(length));
        if length == 0 || length > maximum {
            return Err(KmsError::InvalidCiphertext);
        }
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| KmsError::InvalidCiphertext)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}
