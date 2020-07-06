use serde::Deserialize;
use custom_codes::{SecOps, KeyLength};
use secrecy::{SecretString, ExposeSecret};
use anyhow::Result;
use std::fs::OpenOptions;
use futures::AsyncReadExt;
use smol::{blocking, reader};

use crate::CONFIG_FILE;

#[derive(Debug, Deserialize)]
pub (crate) struct SecretsConfig {
    pub (crate) default: SecretString,
    pub (crate) argon2: Option<SecretString>,
    pub (crate) aead: Option<SecretString>,
}

#[derive(Debug, Deserialize)]
pub (crate) struct SchemeGuardianConfig {
    pub (crate) secrets: SecretsConfig,
}

impl SchemeGuardianConfig {
    pub fn new() -> Self {
        Self {
            secrets: {
                SecretsConfig {
                    default: SecretString::new(String::default()),
                    argon2: Option::default(),
                    aead: Option::default(),
                }
            }
        }
    }

    pub (crate) async fn init(&mut self) -> Result<&SchemeGuardianConfig> {
        let mut contents = String::new();

        let file = blocking!(OpenOptions::new()
            .create(false)
            .write(false)
            .read(true)
            .open(CONFIG_FILE))?;
        
        let mut file = reader(file);

        file.read_to_string(&mut contents).await?;
        
        let sg_config: SchemeGuardianConfig = toml::from_str(&contents)?;
        sg_config.check_32_byte_length()?;

        self.secrets = sg_config.secrets;

        Ok(self)
    }

    fn check_default_key(&self) -> SecOps {
        let key_length = 32_usize;
        let user_default_length = self.secrets.default.expose_secret().len();
        
        if user_default_length < key_length {
            SecOps::KeyTooShort(KeyLength::Bytes32)
        }else if user_default_length > key_length {
            SecOps::KeyTooLong(KeyLength::Bytes32)
        }else {
            SecOps::KeyLengthSane
        }
    }

    fn check_argon2_key(&self) -> SecOps {
        let key_length = 32_usize;

        if let Some(argon2_key) = &self.secrets.argon2 {
            let argon2_len = argon2_key.expose_secret().len();

            if argon2_len < key_length {
                SecOps::KeyTooShort(KeyLength::Bytes32)
            }else if argon2_len > key_length {
                SecOps::KeyTooLong(KeyLength::Bytes32)
            }else {
                SecOps::KeyLengthSane
            }
        }else {
            SecOps::KeyLengthSane
        }
    }

    fn check_aead_key(&self) -> SecOps {
        let key_length = 32_usize;

        if let Some(aead_key) = &self.secrets.aead {
            let aead_len = aead_key.expose_secret().len();

            if aead_len < key_length {
                SecOps::KeyTooShort(KeyLength::Bytes32)
            }else if aead_len > key_length {
                SecOps::KeyTooLong(KeyLength::Bytes32)
            }else {
                SecOps::KeyLengthSane
            }
        }else {
            SecOps::KeyLengthSane
        }
    }

    fn check_32_byte_length(&self) -> Result<()> {
        let user_default_check = self.check_default_key();
        let user_argon2_check = self.check_argon2_key();
        let user_aead_check = self.check_aead_key();
        
        if user_default_check == SecOps::KeyLengthSane && user_argon2_check == SecOps::KeyLengthSane && user_aead_check == SecOps::KeyLengthSane {
            Ok(())
        }else if user_default_check != SecOps::KeyLengthSane {
            Err(anyhow::Error::new(user_default_check))
        }else if user_argon2_check != SecOps::KeyLengthSane {
            Err(anyhow::Error::new(user_argon2_check))
        }else {
            Err(anyhow::Error::new(user_aead_check))
        }
    }
}