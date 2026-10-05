//! Authenticated envelopes for sensitive service records in the shared database.
use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM, NONCE_LEN};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum StateCipherError {
    #[error(transparent)]
    MasterKey(#[from] crate::MasterKeyError),
    #[error("encrypted state record failed authentication")]
    InvalidCiphertext,
    #[error("state record encryption failed")]
    Encryption,
}

pub struct StateCipher {
    key: Zeroizing<[u8; 32]>,
}

impl StateCipher {
    pub fn ephemeral() -> Result<Self, StateCipherError> {
        let mut key = Zeroizing::new([0; 32]);
        aws_lc_rs::rand::fill(&mut *key).map_err(|_| StateCipherError::Encryption)?;
        Ok(Self::with_key(&key))
    }

    pub fn from_env() -> Result<Self, StateCipherError> {
        let key = crate::external_master_key()?;
        let bytes = key
            .as_slice()
            .try_into()
            .map_err(|_| crate::MasterKeyError::Invalid)?;
        Ok(Self::with_key(bytes))
    }

    pub fn with_key(key: &[u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(*key),
        }
    }

    pub fn seal(&self, context: &[&str], plaintext: &[u8]) -> Result<Vec<u8>, StateCipherError> {
        let key = RandomizedNonceKey::new(&AES_256_GCM, &*self.key)
            .map_err(|_| StateCipherError::Encryption)?;
        let mut data = Zeroizing::new(plaintext.to_vec());
        let nonce = key
            .seal_in_place_append_tag(Aad::from(aad(context)), &mut *data)
            .map_err(|_| StateCipherError::Encryption)?;
        let mut result = Vec::with_capacity(1 + NONCE_LEN + data.len());
        result.push(1);
        result.extend_from_slice(nonce.as_ref());
        result.extend_from_slice(&data);
        Ok(result)
    }

    pub fn open(
        &self,
        context: &[&str],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StateCipherError> {
        if ciphertext.len() < 1 + NONCE_LEN + 16 || ciphertext[0] != 1 {
            return Err(StateCipherError::InvalidCiphertext);
        }
        let nonce = ciphertext[1..1 + NONCE_LEN]
            .try_into()
            .map_err(|_| StateCipherError::InvalidCiphertext)?;
        let key = RandomizedNonceKey::new(&AES_256_GCM, &*self.key)
            .map_err(|_| StateCipherError::InvalidCiphertext)?;
        let mut data = Zeroizing::new(ciphertext[1 + NONCE_LEN..].to_vec());
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(context)),
                &mut data,
            )
            .map_err(|_| StateCipherError::InvalidCiphertext)?;
        let size = plaintext.len();
        data.truncate(size);
        Ok(data)
    }
}

fn aad(context: &[&str]) -> Vec<u8> {
    let mut result = b"locallycloud-state-record-v1".to_vec();
    for part in context {
        result.extend_from_slice(&(part.len() as u64).to_be_bytes());
        result.extend_from_slice(part.as_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_bind_identity_and_reject_corruption_and_wrong_master() {
        let cipher = StateCipher::with_key(&[7; 32]);
        let context = ["iam", "account", "role", "id"];
        let sealed = cipher.seal(&context, b"sensitive material").unwrap();
        assert_eq!(
            &*cipher.open(&context, &sealed).unwrap(),
            b"sensitive material"
        );
        assert_ne!(
            sealed,
            cipher.seal(&context, b"sensitive material").unwrap()
        );
        assert!(cipher
            .open(&["iam", "account", "role", "other"], &sealed)
            .is_err());
        assert!(cipher
            .open(&["ia", "maccount", "role", "id"], &sealed)
            .is_err());
        assert!(StateCipher::with_key(&[8; 32])
            .open(&context, &sealed)
            .is_err());
        let mut corrupted = sealed;
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(cipher.open(&context, &corrupted).is_err());
        assert!(cipher.open(&context, &[1]).is_err());
    }
}
