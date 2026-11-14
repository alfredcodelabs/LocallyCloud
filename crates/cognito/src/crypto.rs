use std::num::NonZeroU32;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair, KeySize, PublicKeyComponents};
use aws_lc_rs::signature::KeyPair as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::{rngs::OsRng, RngCore};
use ring::pbkdf2;
use serde_json::Value;
use uuid::Uuid;

use crate::CognitoError;

const PASSWORD_ITERATIONS: u32 = 120_000;

pub(crate) struct PasswordHash {
    salt: [u8; 16],
    hash: [u8; 32],
}

impl PasswordHash {
    pub(crate) fn new(password: &str) -> Self {
        let mut salt = [0; 16];
        OsRng.fill_bytes(&mut salt);
        let mut hash = [0; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PASSWORD_ITERATIONS).expect("nonzero iterations"),
            &salt,
            password.as_bytes(),
            &mut hash,
        );
        Self { salt, hash }
    }

    pub(crate) fn verify(&self, password: &str) -> bool {
        pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PASSWORD_ITERATIONS).expect("nonzero iterations"),
            &self.salt,
            password.as_bytes(),
            &self.hash,
        )
        .is_ok()
    }
}

pub(crate) struct SigningKey {
    kid: String,
    encoding: EncodingKey,
    public_n: String,
    public_e: String,
}

impl SigningKey {
    pub(crate) fn generate() -> Result<Self, CognitoError> {
        let private = KeyPair::generate(KeySize::Rsa2048).map_err(|_| CognitoError::Internal)?;
        let public = PublicKeyComponents::<Vec<u8>>::from(private.public_key());
        let der: Pkcs8V1Der<'_> = private.as_der().map_err(|_| CognitoError::Internal)?;
        let info =
            pkcs8::PrivateKeyInfo::try_from(der.as_ref()).map_err(|_| CognitoError::Internal)?;
        let encoding = EncodingKey::from_rsa_der(info.private_key);
        Ok(Self {
            kid: Uuid::new_v4().simple().to_string(),
            encoding,
            public_n: URL_SAFE_NO_PAD.encode(public.n),
            public_e: URL_SAFE_NO_PAD.encode(public.e),
        })
    }

    pub(crate) fn sign(&self, claims: &Value) -> Result<String, CognitoError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        encode(&header, claims, &self.encoding).map_err(|_| CognitoError::Internal)
    }

    pub(crate) fn jwk(&self) -> Value {
        serde_json::json!({
            "alg": "RS256", "e": self.public_e, "kid": self.kid,
            "kty": "RSA", "n": self.public_n, "use": "sig"
        })
    }
}

pub(crate) fn opaque_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
