use serde_derive::{Serialize, Deserialize};
use chrono::prelude::*;
use sled::{Db, IVec};
use secrecy::{Secret, ExposeSecret, CloneableSecret, DebugSecret};
use zeroize::Zeroize;
use branca::Branca;
use std::iter;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use either::{Either, Left, Right};
use std::collections::HashMap;

use crate::{SG_BRANCA_KEY, SG_DATETIME};
use crate::datetime::SGDateTime;
use crate::SGError;

    /// Type of Scheme to execute
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Scheme {
        /// A db scheme. `Db("Name of the database")`
    Db(String),
        /// TCP address
    Tcp(std::net::SocketAddr),
        /// UDP address
    Udp(std::net::SocketAddr),
        /// FTP address
    Ftp(std::net::SocketAddr),
        /// The type of scheme is yet to be specified, usefull especially when you want to initialize a scheme
    UnSpecified,
}

    /// Type of execution
#[derive(Debug, Clone)]
pub enum SGExec {
        /// Issue a Secret
    Issue,
        /// Check the integrity of a secret and whether its genuine
    Authenticate,
        /// Check for delegated power or authority
    Authorize,
        /// Reissue a secret to a particular user or client. 
        /// Can be useful in instead of deleting and then issuing a secret for a particular user from the database, 
        /// swap out the previous secret for a new secret
    ReIssue,
        /// Destroy a particular secret
    Revoke,
}


#[derive(Serialize, Deserialize, Zeroize, Debug, Clone)]
#[zeroize(drop)]
struct BearerKey {
    key: String,
}

impl BearerKey {
    fn new(key: String) -> Self {
        Self { key }
    }
}

    /// Simple builder for a `User` with username
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemeOptions<Attr> {
    scheme: Scheme,
    secret_type: SecretType,
    key: BearerKey,
    expiry: Lease,
    #[serde(skip)]
    rotating: Option<chrono::Duration>,
    attributes: Option<Attr>,
}

impl<'de, Attr> SchemeOptions<Attr> where Attr: std::clone::Clone + std::fmt::Debug + serde::Serialize + serde::Deserialize<'de>{
        /// Create new user with defaults
    pub fn new() -> Self {

        Self {
            scheme: Scheme::UnSpecified,
            secret_type: SecretType::UnSpecified,
            key: BearerKey::new(Default::default()),
            expiry: Lease::UnSpecified,
            rotating: None,
            attributes: Default::default(),
        }
    }
        /// Choose a scheme
    pub fn scheme(mut self, scheme: Scheme) -> Self {
        self.scheme = scheme;

        self
    }
        /// Choose a scheme
    pub fn token(mut self, token_type: SecretType) -> Self {
        self.secret_type = token_type;

        self
    }
        /// The primary key in the Key-Value Store
    pub fn key(mut self, token_type: Secret<String>) -> Self {
        self.key = {
            let data = token_type.expose_secret().trim();

            BearerKey::new(data.to_owned())
        };

        self
    }

        /// Add expiry date
    pub fn expiry(mut self, lease: Lease) -> Self {
        self.expiry = lease;

        self
    }

        /// Add expiry date
    pub fn rotate(mut self, time: chrono::Duration) -> Self {
        self.rotating = Some(time);

        self
    }

        /// Add some characteristics to the user
    pub fn attributes<T>(mut self, attr: Option<Attr>) -> Self {
        self.attributes = attr;

        self
    }

        /// kind of operation to operation
    pub fn execute(self, exec: SGExec) -> Result<(custom_codes::DbOps, Option<Secret<String>>, Option<IVec>), SGError> {

        match exec {
            SGExec::Issue => {
                match self.clone().scheme {
                    Scheme::Db(db_path) => {
                        match SecretsEngine::new(self.clone()).insert(&db_path) {
                            Ok(val) => {
                                if let Some(inner) = val.1 {
                                    Ok((custom_codes::DbOps::Modified, Some(val.0), Some(inner)))
                                }else {
                                    Ok((custom_codes::DbOps::Inserted, Some(val.0), None))
                                }
                            }
                            Err(e) => Err(e),
                        }
                    },
                    _ => Ok((custom_codes::DbOps::NotExecuted, None, None))
                }
                
            },
            SGExec::Authenticate => {
                let key = &self.key.key;

                match self.clone().scheme {
                    Scheme::Db(db_path) => {
                        match SecretsEngine::new(self.clone()).authenticate(&db_path, Secret::new(key.to_owned()))? {
                            (custom_codes::DbOps::KeyFound, Some(val)) => Ok((custom_codes::DbOps::KeyFound, Some(Secret::new(key.to_owned())), Some(val))),
                            (custom_codes::DbOps::KeyNotFound, None) => Ok((custom_codes::DbOps::KeyNotFound, None, None)),
                            (_,_) => Ok((custom_codes::DbOps::KeyNotFound, None, None)),
                        }
                    },
                    _ => Ok((custom_codes::DbOps::NotExecuted, None, None)),
                }
                
            },
            /*SGExec::Authorize =>
            SGExec::ReIssue =>
            SGExec::Revoke => */
            _ => Ok((custom_codes::DbOps::NotExecuted, None, None))
    }
        /*println!("[SCHEME]: {:?}", self.scheme);
        println!("[SECRET_TYPE]: {:?}", self.secret_type);
        println!("[KEY]: {:?}", self.key);
        println!("[EXPIRY]: {:?}", self.expiry);
        //println!("[ATTRIBUTES]: {:?}", self.attributes);
        println!("[EXEC]: {:?}", exec);


        Ok((custom_codes::AccessStatus::Granted, None))*/
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

    /// Access Level of a secret
#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd, Clone, Eq, Zeroize)]
#[zeroize(drop)]
pub enum AccessLevel {
    Create,
    Read,
    Write,
    Append,
    Delete,
}

#[derive(Debug, Clone, Zeroize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
pub struct SGSecret(String);

impl CloneableSecret for SGSecret {}

impl DebugSecret for SGSecret {
    fn debug_secret() -> &'static str {
        "SECRET::REDACTED"
    }
}

impl Default for SGSecret {
    fn default() -> Self{ Self(String::default()) }
}

#[derive(Debug, Serialize, Deserialize)]
struct Payload<Attr> {
    bearer: String,
    secret_kind: SecretType,
    attr: Option<Attr>,
    lease: Lease,
    rotating: Option<DateTime<Utc>>, // Enable to compare whether a rotation happened or not based on previous time
    //access: AccessLevel,
}

    /// Secrets engine handles Authenticate/Authorize, Create, Read, Update and Delete (ACRUD) for all secrets
#[derive(Serialize, Deserialize, Debug)]
pub struct SecretsEngine<Attr> {
    #[serde(skip)]
    secret: SGSecret,
    payload: Payload<Attr>,
}

impl<'de, Attr> SecretsEngine<Attr> where Attr: std::fmt::Debug + std::clone::Clone + serde::Serialize + serde::Deserialize<'de>{
        /// Intialize
    pub fn new(data: SchemeOptions<Attr>) -> Self {  
        
        Self { 
            secret: SGSecret(Default::default()),
            payload : Payload {
                bearer: Default::default(),
                secret_kind: SecretType::UnSpecified,
                attr: data.attributes,
                lease: data.expiry,
                rotating: match data.rotating { Some(rotator_interval) => Some(Utc::now() + rotator_interval), None => None, },
            },
        }
    }
        /// Insert new token
    pub fn insert(self, path: &str) -> Result<(Secret<String>, Option<IVec>), SGError> {
        let db = Db::start_default(path)?;

        let key = branca_random()?;
        let value = bincode::serialize(&self.payload)?;

        Ok((Secret::new(key.expose_secret().clone()), db.insert(key.expose_secret(), value)?))
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

        /// Rotate key after successful operation
    #[allow(dead_code)]
    fn rotating_key() {

    }

        /// Rotate key every `S` seconds after successful operation
    #[allow(dead_code)]
    fn rotating_key_secs() {

    }
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



    /// Struct to open a scheme
#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct Access {
    create: bool,
    read: bool,
    write: bool,
    append: bool,
}


impl Access {
        /// Create an new empty access level struct
        /// Initializes `Self` values as ` Access {
        ///     create: false,
        ///     open: "defaults:fallback/new",
        ///     read: false,
        ///     write: false,
        /// }
    pub fn new() -> Self {

        Self { create: false, read: false, write: false, append: false}
    }
        /// Replace default `create` field with user defined `Boolean` value
    pub fn create(mut self, access: bool) -> Self {
        self.create = access;

        self
    }
        /// Replace default `read` field with user defined `Boolean` value
    pub fn read(mut self, access: bool) -> Self {
        self.read = access;

        self
    }
        /// Replace default `write` field with user defined `Boolean` value
    pub fn write(mut self, access: bool) -> Self {
        self.write = access;

        self
    }
        /// Replace default `append` field with user defined `Boolean` value
    pub fn append(mut self, access: bool) -> Self {
        self.append = access;

        self
    }
        /// Replace default `open` field with user defined `Url` value
    pub fn open(self) -> Self {
        self
    }
}