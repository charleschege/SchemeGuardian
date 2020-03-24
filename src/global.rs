use serde::{Serialize, Deserialize};
use zeroize::Zeroize;
use tai64::TAI64N;

pub (crate) static SCHEMEGUARDIAN_TOML_FILE: &'static str = "./SchemeGuardian/SchemeGuardian.toml";
pub (crate) static SCHEMEGUARDIAN_LOG_FILE: &'static str = "./SchemeGuardian/SchemeGuardian.log";
pub (crate) static DEFAULT_KV_STORE_PATH: &'static str = "./SchemeGuardian/SchemeGuardianSecrets/secrets_kv_db";

/// ### A an expiry date to lease a secret
/// #### Example
/// ```
/// use schemeguardian::global::Lease;
/// let foo = Lease::Lifetime;
/// assert_eq!(foo, Lease::Lifetime);
/// ```
#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Clone, Eq, Zeroize, Debug)]
pub enum Lease {
    /// Has an expiry TAI time TAI64N type which doesnt care about leap seconds
    DateExpiryTAI(TAI64N),
    /// This is a lease to a secret that will never expire. This is field not recommended
    Lifetime,
    /// First time the scheme is accessed
    FirstAccess,
    /// This is a lease to a secret that will expire after the download is completed
    OnDownload,
    /// This is a lease to a secret that will expire after the specified number of downloads is completed
    OnDownloads(u64),
    /// This is a lease to a secret that will expire after the upload is completed
    OnUpload,
    /// This is a lease to a secret that will expire after the specified number of uploads are completed
    OnUploads(u64),
    /// This is a lease to a secret that will expire after the network is disconnected
    OnDisconnection,
    /// The lease time has not been specified by the user
    Unspecified,
}

impl Default for Lease {
    fn default() -> Self {
        Lease::DateExpiryTAI(TAI64N::now() + std::time::Duration::from_secs(timelite::LiteDuration::hours(24)))
    }
}

#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Clone, Eq, Zeroize, Debug)]
pub enum Role {
    SuperUser,
    Admin,
    SubAdmin,
    User,
    Specifed(String),
    Unspecified,
}

#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Clone, Eq, Zeroize)]
pub struct DatabaseAccess {
    name: String,
    document: Option<String>,
    field: Option<String>,
}

type Blake3Hash = String;

/// Scheme Control List //TODO
#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Clone, Eq, Zeroize)]
pub enum SchemeControlList {
    Network(String),
    File(String),
    Database(DatabaseAccess),
    Custom(Vec<u8>),
    TlsCertificate(String),
    Hash(Blake3Hash),
}

#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Clone, Eq, Zeroize, Debug)]
pub enum AccessControlList {
    Create,
    Read,
    Write,
    Execute,
    NoAccess,
}

#[derive(Serialize, Deserialize, Zeroize, Clone)]
pub (crate) struct TaiTimeStamp(TAI64N); // TODO see how to make the TAI64 Standalone

impl TaiTimeStamp {
    pub fn now() -> Self {
        Self(TAI64N::now())
    }
}

impl secrecy::DebugSecret for Lease {}
impl secrecy::DebugSecret for Role {}
impl secrecy::DebugSecret for AccessControlList {}
impl secrecy::DebugSecret for SchemeControlList {}
impl secrecy::DebugSecret for TaiTimeStamp {}

impl secrecy::CloneableSecret for Lease {}
impl secrecy::CloneableSecret for Role {}
impl secrecy::CloneableSecret for AccessControlList {}
impl secrecy::CloneableSecret for SchemeControlList {}
impl secrecy::CloneableSecret for TaiTimeStamp {}