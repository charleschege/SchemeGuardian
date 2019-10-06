use serde_derive::{Serialize, Deserialize};
use secrecy::{SecretString, DebugSecret, ExposeSecret};
use argon2::{self, ThreadMode, Variant, Version};
use crate::SG_SECRET_KEYS;
use crate::secrets::random64alpha;
use crate::SGError;

    /// Passphrase Engine handles generation and authentication of passphrases
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Passphrase(SecretString);

impl DebugSecret for Passphrase {
    fn debug_secret() -> &'static str {
        "S3CR3T::REDACTED"
    }
}

impl Default for Passphrase {
    fn default() -> Self{ Self(SecretString::new("R3DACT3D::<Default>::S3CR3T".to_owned())) }
}

impl Passphrase {
        /// Initialize an empty `Passphrase` struct
    pub fn new() -> Self {
        Self::default()
    }
        /// Add the passphrase to the `Passphrase` struct
    pub fn secret(mut self, value: SecretString) -> Self {
        self.0 = SecretString::new(value.expose_secret().trim().to_owned());

        self
    }
        /// Generate a new passphrase
    pub fn issue(&self) -> Result<SecretString, SGError> {

        if self.0.expose_secret().len() == 0 {
            return Err(SGError::PassphraseEmpty);
        }else if self.0.expose_secret().len() / 1024 <= 1 {
            Ok(SecretString::new(argon2::hash_encoded(&bincode::serialize(self.0.expose_secret())?, &bincode::serialize(&random64alpha().expose_secret())?, &argon2_config())?))
        }else {
            Err(SGError::PassphraseTooLarge)
        }
    }
        /// Authenticate a passphrase
    pub fn authenticate(&self, hashed: SecretString) -> Result<custom_codes::AccessStatus, SGError> {
        
        if self.0.expose_secret().len() == 0 {
            return Err(SGError::PassphraseEmpty);
        }else if self.0.expose_secret().len() / 1024 <= 1 {
            match argon2::verify_encoded_ext(&hashed.expose_secret(), &bincode::serialize(&self.0)?, &SG_SECRET_KEYS.default.expose_secret().as_bytes(), &[])? {
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
        secret: &SG_SECRET_KEYS.default.expose_secret().as_bytes(),
        ad: &[],
        hash_length: 32,
    }
}