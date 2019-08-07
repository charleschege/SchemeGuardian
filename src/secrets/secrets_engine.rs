use serde_derive::{Serialize, Deserialize};
use chrono::prelude::*;
use sled::{Db, IVec};
use secrecy::{Secret, ExposeSecret, CloneableSecret, DebugSecret};
use zeroize::Zeroize;

use crate::SGError;
use crate::secrets;

#[derive(Debug, Clone, Zeroize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
struct SGSecret(String);

impl CloneableSecret for SGSecret {}

impl DebugSecret for SGSecret {
    fn debug_secret() -> &'static str {
        "S3CR3T::REDACTED"
    }
}

impl Default for SGSecret {
    fn default() -> Self{ Self(String::default()) }
}

#[derive(Debug, Serialize, Deserialize)]
struct BrancaPayload<Attr> {
    bearer: SGSecret,
    attr: Option<Attr>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecondaryIndex {
    bearer: SGSecret,
    lease: Lease,
}

    /// `BrancaEngine` creates and authenticates branca secrets
#[derive(Debug, Serialize, Deserialize)]
pub struct BrancaEngine<Attr> {
    secret: BrancaPayload<Attr>,
    index: SecondaryIndex,
}

impl<'a, Attr> BrancaEngine<Attr> {
        /// Initialize a BrancaEngine for creating and authenticating branca secrets
    pub fn new() -> Self {
        Self {
            secret: BrancaPayload {
                bearer: Default::default(),
                attr: Default::default(),
            },
            index: SecondaryIndex { bearer: Default::default(), lease: Default::default(), }
        }
    }
        /// The username or client name  
    pub fn bearer(mut self, bearer: Secret<String>) -> Self {
        self.secret.bearer = SGSecret(bearer.expose_secret().clone().to_owned());
        self.index.bearer = SGSecret(bearer.expose_secret().to_owned());
        
        self
    }
        /// The expiry date or time for the secret
    pub fn expiry(mut self, expiry: chrono::Duration) -> Self  {
        self.index.lease = Lease::DateExpiry(Utc::now() + expiry);
        
        self
    }
        /// The properties of the secret like `Roles` 
    pub fn attributes(mut self, attr: Option<Attr>) -> Self where Attr: zeroize::Zeroize {
        self.secret.attr = if let Some(inner) = attr{ Some(inner)} else { None };
        
        self
    }

        /// Insert new token
    pub fn insert(self, path: &str) -> Result<(Secret<String>, Option<IVec>), SGError> where Attr: serde::Serialize {
        let db = Db::start_default(path)?;
        let raw_secret = serde_json::to_string(&self.secret)?;
        let encrypted = secrets::branca_encode(Secret::new(raw_secret))?;
            // Serialize from `ron` string
        let key = bincode::serialize(&encrypted.expose_secret())?; 
        let value = bincode::serialize::<SecondaryIndex>(&self.index)?; //TODO: Should I encrypt bearer with branca in index

        let dbop = db.insert(key, value)?;

        let mut sled_vec = vec![];

        db.iter().keys().for_each(|inner| sled_vec.push(inner));
        /*
        for inner in sled_vec {
            dbg!(bincode::deserialize::<String>(&inner?)?);
        }*/
        Ok((encrypted, dbop))
        
    }
        /// Authenticate an existing token
    pub fn authenticate(self, path: &str, raw_key: Secret<String>) -> Result<(custom_codes::DbOps, Option<IVec>), SGError> {
        let key = raw_key.expose_secret().as_bytes();
        let db = Db::start_default(path)?;
        let check_key = db.get(key)?;

        if let Some(binary) = check_key {
            Ok((custom_codes::DbOps::KeyFound, Some(binary)))
        }else {
            Ok((custom_codes::DbOps::KeyNotFound, None))
        } 
    }
}


    /// A an expiry date to lease a secret
#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd, Clone, Eq)]
pub enum Lease {
        /// Has an expiry date of DateTime<Utc>
    DateExpiry(DateTime<Utc>),
        /// This is a lease to a secret that will never expire
    Lifetime,
        /// This is a lease to a secret that will expire after the download is completed
    OnDownload,
        /// This is a lease to a secret that will expire after the upload is completed
    OnUpload,
        /// This is a lease to a secret that will expire after the network is disconnected
    OnDisconnection,
        /// The lease time has not been specified by the user
    UnSpecified,
}

impl Default for Lease {
    fn default() -> Self{ Lease::DateExpiry(Utc::now() + chrono::Duration::hours(24)) }
}

    /// Type of `secret`
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Zeroize)]
#[zeroize(drop)]
pub enum SecretType {
        /// A normal cookie
    Cookie,
        /// A branca token
    Branca,
        /// Time based auth
    TOTP,
        /// USB hardware auth
    USBkey,
        /// Near Field Communication
    NFC,
        /// Fingerprint Auth
    Fingerprint,
        /// Eye Iris scan
    Iris,
        /// Infrared scan
    IRscan,
        /// Noise Protocol Secret
    Noise,
        /// TLS Certificate
    TlsCert,
        /// DMARC for Email
    DMARC,
        /// DANE for Email
    DANE,
        /// A passphrase/ Password or PIN
    Passphrase,
        /// Bluetooth
    BluetoothPairKey,
        /// Username authenticator
    Bearer,
        /// A custom token authentication mechanism 
    CustomToken,
        /// An API key
    ApiKey,
        /// An email address
    EmailAddr,
        /// A DNS Security(DNSSEC, RPKI, ESNI, DoT, DoH, DoN<DNS over Noise>) -- `TO be confirmed`
    /* DNS... */
        /// A blockchain transaction
    BlockchainTx,
        /// A QR code
    QrCode,
        /// A barcode
    Barcode,
        /// Access to a hardware address, usable in a firewall router
    HardwareMacAddr,
        /// Access to an IP Address, usable in a firewall router
    IpAddress,
        /// Access to a Subnet, usable in a firewall router
    Subnet,
        /// Access to a port, usable in a firewall router
    Port,
        /// The type of secret is yet to be specified, usefull especially when you want to initialize something
    UnSpecified,
}
