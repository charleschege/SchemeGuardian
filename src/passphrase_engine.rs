use crate::random64alpha;
use anyhow::Result;
use argon2::{self, ThreadMode, Variant, Version};
use secrecy::{DebugSecret, ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Passphrase Engine handles generation and authentication of passphrases
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Passphrase(SecretString);

impl DebugSecret for Passphrase {
    fn debug_secret() -> &'static str {
        "[SG_R3DACT3D::<PASSPHRAS3>]"
    }
}

impl Default for Passphrase {
    fn default() -> Self {
        Self(SecretString::new(
            "[SG_R3DACT3D::<PASSPHRAS3>]".to_owned(),
        ))
    }
}

impl<'a> Passphrase {
    /// Initialize an empty `Passphrase` struct
    pub fn new() -> Self {
        Self::default()
    }
    /// Add the passphrase to the `Passphrase` struct
    pub fn secret(mut self, value: SecretString) -> Self {
        self.0 = SecretString::new(value.expose_secret().trim().to_owned());

        self
    }
    /// Check the length of a passphrase to prevent DOS attack
    pub async fn issue(&self, key: SecretString) -> Result<SecretString> {
        if self.0.expose_secret().len() == 0 {
            return Err(anyhow::Error::new(argon2::Error::PwdTooShort));
        } else if self.0.expose_secret().len() / 1024 > 1 {
            Err(anyhow::Error::new(argon2::Error::PwdTooLong))
        } else {
            Ok(SecretString::new(argon2::hash_encoded(
                self.0.expose_secret().as_bytes(),
                random64alpha().await.expose_secret().as_bytes(),
                &self.argon2_config(key.expose_secret()),
            )?))
        }
    }
    /// Authenticate a passphrase
    pub async fn authenticate(&self, key: SecretString, hashed: SecretString) -> Result<custom_codes::AccessStatus> {
        if self.0.expose_secret().len() == 0 {
            return Err(anyhow::Error::new(argon2::Error::PwdTooShort));
        } else if self.0.expose_secret().len() / 1024 <= 1 {
            match argon2::verify_encoded_ext(
                hashed.expose_secret(),
                self.0.expose_secret().as_bytes(),
                key.expose_secret().as_bytes(),
                &[],
            )? {
                true => Ok(custom_codes::AccessStatus::Granted),
                false => Ok(custom_codes::AccessStatus::Denied),
            }
        } else {
            Err(anyhow::Error::new(argon2::Error::PwdTooLong))
        }
    }

    fn argon2_config(&self, key: &'a str) -> argon2::Config<'a> {

        let byt: &'a [u8] = key.as_bytes();
        drop(key); //TODO FInd a way to efficiently drop this from memory using Zeroize

        argon2::Config {
            variant: Variant::Argon2i,
            version: Version::Version13,
            mem_cost: 65536,
            time_cost: 3,
            lanes: 4,
            thread_mode: ThreadMode::Parallel,
            secret: &byt,
            ad: &[],
            hash_length: 32,
        }
    }
}