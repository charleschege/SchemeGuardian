use serde_derive::{Serialize, Deserialize};
use zeroize::Zeroize;
use secrecy::{DebugSecret, CloneableSecret};
use argon2::{self, ThreadMode, Variant, Version};
use crate::SG_SECRET_KEYS;
use crate::secrets::random64alpha;
use crate::{SGSecret, SGError};

    /// Passphrase Engine handles generation and authentication of passphrases
#[derive(Debug, Serialize, Deserialize, Zeroize, Clone)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
pub struct Passphrase(String);

impl CloneableSecret for Passphrase {}

impl DebugSecret for Passphrase {
    fn debug_secret() -> &'static str {
        "S3CR3T::REDACTED"
    }
}

impl Default for Passphrase {
    fn default() -> Self{ Self(String::default()) }
}

impl Passphrase {
        /// Initialize an empty `Passphrase` struct
    pub fn new() -> Self {
        Self(Default::default())
    }
        /// Add the passphrase to the `Passphrase` struct
    pub fn secret(mut self, value: SGSecret) -> Self {
        self.0 = value.0.trim().to_owned();

        self
    }
        /// Generate a new passphrase
    pub fn issue(&self) -> Result<SGSecret, SGError> {

        if self.0.len() == 0 {
            return Err(SGError::PassphraseEmpty);
        }else if self.0.len() / 1024 <= 1 {
            Ok(SGSecret(argon2::hash_encoded(&bincode::serialize(&self.0)?, &bincode::serialize(&random64alpha().0)?, &argon2_config())?))
        }else {
            Err(SGError::PassphraseTooLarge)
        }
    }
        /// Authenticate a passphrase
    pub fn authenticate(&self, hashed: SGSecret) -> Result<custom_codes::AccessStatus, SGError> {
        
        if self.0.len() == 0 {
            return Err(SGError::PassphraseEmpty);
        }else if self.0.len() / 1024 <= 1 {
            match argon2::verify_encoded_ext(&hashed.0, &bincode::serialize(&self.0)?, &SG_SECRET_KEYS.default.0.as_bytes(), &[])? {
                true => Ok(custom_codes::AccessStatus::Granted),
                false => Ok(custom_codes::AccessStatus::Denied),
            }
        }else {
            Err(SGError::PassphraseTooLarge)
        }


    }

}

fn argon2_config() -> argon2::Config<'static> {
    argon2::Config {
        variant: Variant::Argon2i,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: 3,
        lanes: 4,
        thread_mode: ThreadMode::Parallel,
        secret: &SG_SECRET_KEYS.default.0.as_bytes(),
        ad: &[],
        hash_length: 32,
    }
}