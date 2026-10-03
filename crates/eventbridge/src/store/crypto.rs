use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::hkdf::{Salt, HKDF_SHA256};
use base64::{engine::general_purpose::STANDARD, Engine};
use zeroize::Zeroizing;

use crate::model::Connection;

const CONNECTION_DOMAIN: &[u8] = b"locallycloud-eventbridge-connections-v1";

pub(super) struct ConnectionCrypto {
    key: Zeroizing<[u8; 32]>,
}

impl ConnectionCrypto {
    pub(super) fn from_env() -> Result<Option<Self>, String> {
        let encoded = match std::env::var("LOCALLYCLOUD_KMS_MASTER_KEY") {
            Ok(value) => Zeroizing::new(value),
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(_) => return Err("invalid LOCALLYCLOUD_KMS_MASTER_KEY".into()),
        };
        let decoded = Zeroizing::new(
            STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| "invalid LOCALLYCLOUD_KMS_MASTER_KEY".to_string())?,
        );
        let master: &[u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| "LOCALLYCLOUD_KMS_MASTER_KEY must decode to 32 bytes".to_string())?;
        Ok(Some(Self::from_master(master)?))
    }

    pub(super) fn from_master(master: &[u8; 32]) -> Result<Self, String> {
        let salt = Salt::new(HKDF_SHA256, b"locallycloud-eventbridge-v1");
        let prk = salt.extract(master);
        let mut key = Zeroizing::new([0u8; 32]);
        prk.expand(&[CONNECTION_DOMAIN], HKDF_SHA256)
            .map_err(|_| "connection key derivation failed".to_string())?
            .fill(&mut *key)
            .map_err(|_| "connection key derivation failed".to_string())?;
        Ok(Self { key })
    }

    pub(super) fn seal(
        &self,
        account: &str,
        region: &str,
        connection: &Connection,
    ) -> Result<Vec<u8>, String> {
        let key = RandomizedNonceKey::new(&AES_256_GCM, self.key.as_ref())
            .map_err(|_| "connection encryption unavailable".to_string())?;
        let mut data =
            Zeroizing::new(serde_json::to_vec(connection).map_err(|error| error.to_string())?);
        let nonce = key
            .seal_in_place_append_tag(
                Aad::from(connection_aad(account, region, &connection.name)),
                &mut *data,
            )
            .map_err(|_| "connection encryption failed".to_string())?;
        let mut sealed = nonce.as_ref().to_vec();
        sealed.extend_from_slice(&data);
        Ok(sealed)
    }

    pub(super) fn open(
        &self,
        account: &str,
        region: &str,
        name: &str,
        sealed: &[u8],
    ) -> Result<Connection, String> {
        if sealed.len() < NONCE_LEN + 16 {
            return Err("invalid sealed connection".into());
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&sealed[..NONCE_LEN]);
        let key = RandomizedNonceKey::new(&AES_256_GCM, self.key.as_ref())
            .map_err(|_| "connection decryption unavailable".to_string())?;
        let mut data = Zeroizing::new(sealed[NONCE_LEN..].to_vec());
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(connection_aad(account, region, name)),
                &mut data,
            )
            .map_err(|_| "wrong master key or corrupt connection".to_string())?;
        let connection: Connection =
            serde_json::from_slice(plain).map_err(|error| error.to_string())?;
        if connection.name != name {
            return Err("connection name mismatch".into());
        }
        Ok(connection)
    }
}

fn connection_aad(account: &str, region: &str, name: &str) -> Vec<u8> {
    let mut aad = CONNECTION_DOMAIN.to_vec();
    for part in [account, region, name] {
        aad.extend_from_slice(&(part.len() as u32).to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    aad
}
