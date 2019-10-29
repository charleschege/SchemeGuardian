use redactedsecret::SecretString;
use serde::Deserialize;
use std::fs;

// This module should be modified to automatically generate and store a branca token in its own store.
// Try an algorithm like Forward Secrecy

/// BrancaSecret used to store the `key` for generating branca secrets stored in `SchemeGuardian.toml` file
#[derive(Debug, Deserialize)]
struct SgTomlSecrets {
    ///Default secret key used on all positions
    default: SecretString,
    /// Expose the branca field to public API to make it easier to use
    branca: SecretString,
}

/// SGConfig struct fetches configuration stored in `SchemeGuardian.toml` file
#[derive(Debug, Deserialize)]
pub struct SGConfig {
    secrets: SgTomlSecrets,
}

impl SGConfig {
    /// Create a new empty SGConfig struct that returns self
    pub fn new() -> Self {
        Self {
            secrets: SgTomlSecrets {
                default: SecretString::default(),
                branca: SecretString::default(),
            },
        }
    }
    /// Extract default encryption key from `SchemeGuardian.toml` file
    pub fn default(mut self) -> SecretString {
        let fs = fs::read_to_string("SchemeGuardian.toml").unwrap();
        let data: SGConfig = toml::from_str(&fs).unwrap();
        self = data;

        self.secrets.default
    }
    /// Extract branca encryption key from `SchemeGuardian.toml` file
    pub fn branca_key(mut self) -> SecretString {
        let fs = fs::read_to_string("SchemeGuardian.toml").unwrap();
        let data: SGConfig = toml::from_str(&fs).unwrap();
        self = data;

        self.secrets.branca
    }
}
