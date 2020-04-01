use secrecy::{SecretString};
use std::collections::HashMap;
use crate::SchemeGuardianConfig;

/// Struct holds the whole structure in memory
pub (crate) struct SchemeGuardian<'a> {
    secrets: HashMap<&'a str, SecretString>
}

impl<'a> SchemeGuardian<'a> {  
    pub async fn new() -> SchemeGuardian<'a> {
        Self {
            secrets: HashMap::new(),
        }
    }

    pub async fn init(&mut self) -> &SchemeGuardian<'a> {
        let mut config = SchemeGuardianConfig::new().await;
        match config.init().await {
            Ok(_) => (),
            Err(error) => {
                eprintln!("{:?}", error);
                std::process::exit(1)
            }
        }

        self.secrets.insert("default_key", config.secrets.default);

        if let Some(argon2) = config.secrets.argon2 {
            self.secrets.insert("argon2_key", argon2);
        }

        if let Some(aead) = config.secrets.aead {
            self.secrets.insert("aead_key", aead);
        }

        self
    }
}

#[derive(Debug)]
pub struct LoadConfiguration;

impl<'a> LoadConfiguration {
    pub async fn load() -> HashMap<&'a str, SecretString> {
        let mut loader = SchemeGuardian::new().await;
        loader.init().await;

        loader.secrets
    }
}
