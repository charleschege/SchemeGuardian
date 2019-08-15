use serde_derive::{Serialize, Deserialize};
use zeroize::Zeroize;
use secrecy::{DebugSecret, CloneableSecret};

    /// Passphrase Engine handles generation and authentication of passphrases
#[derive(Debug, Serialize, Deserialize, Zeroize, Clone)]
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