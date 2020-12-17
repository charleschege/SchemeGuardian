use std::convert::TryInto;
use zeroize::Zeroize;
use tai64::TAI64N;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use secrecy::{SecretString, ExposeSecret};

pub (crate) const CONFIG_FILE: &str = "./SchemeGuardian/SchemeGuardianConf.toml";
pub const TOKEN_DB_PATH: &str = "../TuringDB_Repo/TokenStorage";
pub const TOKEN_SESSION_DOCUMENT: &str = "../TuringDB_Repo/TokenStorage/SessionStorage";
pub (crate) const GC_REGISTRY: &str = "GcRegistry";
pub (crate) const GC_STORAGE: &str = "GcStorage";
pub (crate) type TimeStamp = TAI64N;

/// ### A an expiry date to lease a secret
/// #### Example
/// ```
/// use schemeguardian::global::Lease;
/// let foo = Lease::Lifetime;
/// assert_eq!(foo, Lease::Lifetime);
/// ```
#[derive(PartialEq, PartialOrd, Clone, Eq, Zeroize, Debug, Serialize, Deserialize)]
pub (crate) enum Lease {
    /// This is a lease to a secret that will never expire. This is field not recommended
    Lifetime,
    /// Has an expiry TAI time TAI64N type which doesnt care about leap seconds
    DateExpiryTAI(TAI64N),
    /// First time the scheme is accessed
    FirstAccess,
    /// This is a lease to a secret that will expire after the download is completed
    OnDownload,
    /// This is a lease to a secret that will expire after the specified number of downloads is completed
    OnDownloads(usize),
    /// This is a lease to a secret that will expire after the upload is completed
    OnUpload,
    /// This is a lease to a secret that will expire after the specified number of uploads are completed
    OnUploads(usize),
    /// This is a lease to a secret that will expire after the network is disconnected
    OnDisconnection,
    /// A Lease that is not valid
    Corrupted,
}

impl Default for Lease {
    fn default() -> Self {
        Lease::DateExpiryTAI(TAI64N::now() + std::time::Duration::from_secs(timelite::LiteDuration::hours(24)))
    }
}

impl<'l> Lease {
    pub fn to_header(value: &Lease) -> Vec<u8> {
        match value {
            &Lease::Lifetime => vec![0x00],
            &Lease::DateExpiryTAI(timestamp) => {
                let mut container = vec![0x01];
                container.extend_from_slice(&timestamp.to_bytes());
                
                container
            },
            &Lease::FirstAccess => vec![0x03],
            &Lease::OnDownload => vec![0x04],
            &Lease::OnDownloads(number) => {
                let mut container = vec![0x05];
                container.extend_from_slice(&number.to_le_bytes());
                
                container
            },
            &Lease::OnUpload => vec![0x06],
            &Lease::OnUploads(number) => {
                let mut container = vec![0x07];
                container.extend_from_slice(&number.to_le_bytes());
                
                container
            },
            &Lease::OnDisconnection =>vec![0x08],
            &Lease::Corrupted => vec![0xff],
        }
    }
    pub fn from_header(value: &[u8]) -> Lease {
        let header = &[value[0]];
        match header {
            &[0x00] => Lease::Lifetime,
            &[0x01] => {
                if let Ok(timestamp) = TAI64N::from_slice(&value[1..]) {
                    Lease::DateExpiryTAI(timestamp)
                }else {
                    Lease::Corrupted
                }
            },
            &[0x03] => Lease::FirstAccess,
            &[0x04] => Lease::OnDownload,
            &[0x05] => {
                let data: Result<[u8; 8], _> = value[1..].try_into();

                match data {
                    Ok(value) => Lease::OnDownloads(usize::from_le_bytes(value)),
                    Err(_) => Lease::Corrupted
                }                
            },
            &[0x06] => Lease::OnUpload,
            &[0x07] => {
                let data: Result<[u8; 8], _> = value[1..].try_into();

                match data {
                    Ok(value) => Lease::OnUploads(usize::from_le_bytes(value)),
                    Err(_) => Lease::Corrupted
                }                
            },
            &[0x08] => Lease::OnDisconnection,
            _ => Lease::Corrupted,
        }
    }
}

#[derive(PartialEq, PartialOrd, Clone, Eq, Zeroize, Debug, Serialize, Deserialize)]
pub enum Role {
    SuperUser,
    Admin,
    SubAdmin,
    User,
    Specifed(String),
}


impl Role {
    pub fn to_header(value: &Role) -> Vec<u8> {
        match value {
            &Role::SuperUser => vec![0x00],
            &Role::Admin => vec![0x01],
            &Role::SubAdmin => vec![0x02],
            &Role::User => vec![0x03],
            Role::Specifed(custom) => {
                let mut data = Vec::new();
                data.extend_from_slice(&[0x04]);
                data.extend_from_slice(custom.as_bytes());

                data
            },
        }
    }

    pub fn from_header(value: &[u8]) -> Role {
        match value {
            &[0x00] => Role::SuperUser,
            &[0x01] => Role::Admin,
            &[0x02] => Role::SubAdmin,
            &[0x03] => Role::User,
            &[0x04] => {
                match String::from_utf8(value[1..].to_vec()) {
                    Ok(value) => Role::Specifed(value),
                    Err(_) => Role::User,
                }
            },
            _ => Role::User,
        }
    }
}


/// Transform `hex` value into `blake3::Hash`
pub fn to_blake3(hex: &SecretString) -> Result<blake3::Hash> {
    let hash_bytes = hex::decode(hex.expose_secret())?;
    let hash_array: [u8; blake3::OUT_LEN] = hash_bytes[..].try_into()?;
    let hash: blake3::Hash = hash_array.into();

    Ok(hash)
}

#[derive(Zeroize, Clone, Serialize, Deserialize)]
pub (crate) struct TaiTimestamp(TAI64N); // TODO see how to make the TAI64 Standalone

impl TaiTimestamp {
    pub fn now() -> Self {
        Self(TAI64N::now())
    }
    pub fn get_bytes(&self) -> secrecy::SecretVec<u8> {
        secrecy::SecretVec::new(self.0.to_bytes().to_vec())
    }
}

#[derive(Zeroize, Clone, Serialize, Deserialize)]
pub struct Identifier(pub (crate) String);

impl secrecy::DebugSecret for Lease {}
impl secrecy::DebugSecret for Role {}
impl secrecy::DebugSecret for TaiTimestamp {}
impl secrecy::DebugSecret for Identifier {}

impl secrecy::SerializableSecret for TaiTimestamp {}
impl secrecy::SerializableSecret for Role {}
impl secrecy::SerializableSecret for Lease {}
impl secrecy::SerializableSecret for Identifier {}

impl secrecy::CloneableSecret for Lease {}
impl secrecy::CloneableSecret for Role {}
impl secrecy::CloneableSecret for TaiTimestamp {}
impl secrecy::CloneableSecret for Identifier {}

pub enum GcExec {
    Hit,
    Miss,
    MalformedOperation,
}

#[derive(Debug)]
pub enum SgStatusCode {
    AuthenticToken,
    AuthorizedToken,
    Revoked,
    Rejected,
    AccessGranted,
    AccessDenied,
    BadDeserialize,
    BadSerialize,
    TuringDbOp(anyhow::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Ping {
    Unreachable,
    Online,
    Offline,
    //Varied, //TODO add ping ms
}

use turingdb::TuringEngine;
use async_trait::async_trait;
#[async_trait]
pub trait SecurityCheck {
    async fn issue(self, db_engine: &TuringEngine) -> Result<secrecy::SecretString>;

    async fn authorize(key: &str, db_engine: &TuringEngine) -> Result<SgStatusCode>;

    async fn authenticate(key: &str, db_engine: &TuringEngine) -> Result<SgStatusCode>;

    async fn revoke(key: &str, db_engine: &TuringEngine) -> Result<SgStatusCode>;
}

