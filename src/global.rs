use serde_derive::{Serialize, Deserialize};
use secrecy::{DebugSecret, CloneableSecret};
use zeroize::Zeroize;

    /// `SGSecret` is a struct with public fields that impl Zeroize and `#[zeroize(drop)]` for security.
    ///
    /// `Deref`, `ClonableSecret`, `DebugSecret`, `fmt::Debug`, `fmt::Display` and `Default` traits have been implemented for this
    /// ## Example
    /// ```
    /// use crate::SGSecret;
    /// let data = SGSecret(String::from("WHO AM I"));
    /// dbg!(data);
    /// ```
#[derive(Clone, Zeroize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
pub struct SGSecret(pub String);

impl CloneableSecret for SGSecret {}

impl DebugSecret for SGSecret {
    fn debug_secret() -> &'static str {
        "S3CR3T::R3DACT3D"
    }
}

impl std::fmt::Debug for SGSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "S3CR3T::R3DACT3D")
    }
}

impl std::fmt::Display for SGSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "S3CR3T::R3DACT3D")
    }
}

impl Default for SGSecret {
    fn default() -> Self{ Self(String::default()) }
}

impl std::ops::Deref for SGSecret {
    type Target = String;

    fn deref(&self) -> &String {
        &self.0
    }
}