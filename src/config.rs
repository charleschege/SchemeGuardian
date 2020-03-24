
use serde::{Deserialize};
use custom_codes::{SecOps, KeyLength};
use secrecy::{SecretString, ExposeSecret};
use anyhow::Result;
use async_std::{
    fs::OpenOptions,
    io::ErrorKind,
    io::stderr,
    io::prelude::*,
};
use crate::{
    SCHEMEGUARDIAN_TOML_FILE,
    ErrorLogger,
};

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
    pub async fn new() -> Self {
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

    pub async fn init(&mut self) -> Result<&SchemeGuardianConfig> {
        let mut contents = String::new();

        let file = OpenOptions::new()
            .create(false)
            .write(false)
            .read(true)
            .open(SCHEMEGUARDIAN_TOML_FILE)
            .await;

        match file {
            Ok(mut file_ok) => {
                file_ok.read_to_string(&mut contents).await?;
                let sg_config: SchemeGuardianConfig = toml::from_str(&contents)?;
                sg_config.check_32byte_length().await?;

                self.secrets = sg_config.secrets;

                Ok(self)
            },
            Err(error) => {
                if error.kind() == ErrorKind::NotFound {
                    ErrorLogger::init(anyhow::Error::new(error)).await
                        .cause(&format!("opening {}", SCHEMEGUARDIAN_TOML_FILE)).await
                        .build().await
                        .log().await?;

                    std::process::exit(1)
                }else if error.kind() == ErrorKind::PermissionDenied {
                    ErrorLogger::init(anyhow::Error::new(error)).await
                        .cause(&format!("opening {}", SCHEMEGUARDIAN_TOML_FILE)).await
                        .build().await
                        .log().await?;

                    std::process::exit(1)
                }else {
                    Err(anyhow::Error::new(error))
                }
            }
        }
    }

    async fn check_default_key(&self) -> SecOps {
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

    async fn check_argon2_key(&self) -> SecOps {
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

    async fn check_aead_key(&self) -> SecOps {
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

    async fn check_32byte_length(&self) -> Result<()> {
        let user_default_check = self.check_default_key().await;
        let user_argon2_check = self.check_argon2_key().await;
        let user_aead_check = self.check_aead_key().await;
        
        if user_default_check == SecOps::KeyLengthSane && user_argon2_check == SecOps::KeyLengthSane && user_aead_check == SecOps::KeyLengthSane {
            Ok(())
        }else if user_default_check != SecOps::KeyLengthSane {
            ErrorLogger::init(anyhow::Error::new(user_default_check)).await
                .cause("Check whether default key is of 32bytes in size").await
                .build().await
                .log().await?;
            
                std::process::exit(1)
        }else if user_argon2_check != SecOps::KeyLengthSane {
            ErrorLogger::init(anyhow::Error::new(user_argon2_check)).await
                .cause("Check whether argon2 key is of 32bytes in size").await
                .build().await
                .log().await?;
            
                std::process::exit(1)
        }else {
            ErrorLogger::init(anyhow::Error::new(user_aead_check)).await
                .cause("Check whether aead key is of 32bytes in size").await
                .build().await
                .log().await?;
            
                std::process::exit(1)
        }
    }
}
/*
toml::from_str(contents)?;
impl fmt::Debug for SchemeGuardianConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[R3DACT3D::<ARG0N2S3CR3T>]")
    }
}


impl fmt::Display for SchemeGuardianConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[R3DACT3D::<ARG0N2S3CR3T>]")
    }
}*/