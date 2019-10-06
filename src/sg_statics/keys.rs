use secrecy::SecretString;
use serde_derive::Deserialize;
use std::fs;

    /// BrancaSecret used to store the `key` for generating branca secrets stored in `SchemeGuardian.toml` file
#[derive(Debug, Deserialize)]
pub struct SgTomlSecrets {
        ///Default secret key used on all positions
    pub default: SecretString,
        /// Expose the branca field to public API to make it easier to use
    pub branca: SecretString,
}

    /// SGConfig struct fetches configuration stored in `SchemeGuardian.toml` file
#[derive(Debug, Deserialize)]
pub struct SGConfig {
    secrets: SgTomlSecrets,
}

impl SGConfig {
        /// Create a new empty SGConfig struct that returns self 
    pub fn new() -> Self {
        Self{ secrets: SgTomlSecrets { default: SecretString::default(), branca: SecretString::default() } }
    }
        /// Extract branca encryption key from `SchemeGuardian.toml` file
    pub fn secrets(mut self) -> SgTomlSecrets {
        let fs = fs::read_to_string("SchemeGuardian.toml").unwrap();
        let data: SGConfig = toml::from_str(&fs).unwrap();
        self = data;

        self.secrets
    }
}