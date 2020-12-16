use std::convert::TryInto;
use zeroize::Zeroize;
use tai64::TAI64N;
use serde::{Serialize, Deserialize};
use anyhow::Result;

pub (crate) const CONFIG_FILE: &str = "./SchemeGuardian/SchemeGuardianConf.toml";
pub (crate) const TOKEN_DB_PATH: &str = "./SchemeGuardian/TuringDB_Repo/TokenStorage";
pub (crate) const TOKEN_SESSION_DOCUMENT: &str = "./SchemeGuardian/TuringDB_Repo/TokenStorage/SessionStorage";
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

#[derive(Zeroize, Clone, Serialize, Deserialize)]
pub (crate) struct TaiTimestamp(TAI64N); // TODO see how to make the TAI64 Standalone

impl TaiTimestamp {
    pub fn now() -> Self {
        Self(TAI64N::now())
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
    fn generate_token() -> Self;

    async fn issue(self, db_engine: &TuringEngine) -> Result<crate::tokens::PrngToken>;

    async fn authorize(key: &str, db_engine: &TuringEngine) -> Result<SgStatusCode>;

    async fn authenticate(key: &str, db_engine: &TuringEngine) -> Result<SgStatusCode>;

    async fn revoke(key: &str, db_engine: &TuringEngine) -> Result<SgStatusCode>;
}

