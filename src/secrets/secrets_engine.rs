use serde_derive::{Serialize, Deserialize};
use chrono::prelude::*;
use sled::Db;
use secrecy::{Secret, ExposeSecret, CloneableSecret, DebugSecret};
use zeroize::Zeroize;

use crate::SGError;
use crate::secrets;

fn sg_auth() -> &'static str {
    "./SchemeGuardianDB/SG_AUTH"
}

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

    /// `Role` of the user
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Role {
        /// The user with all access rights
    SuperUser,
        /// A user with administrative rights
    Admin,
        /// A user with some administrative rights
    SubAdmin,
        /// A normal user
    User,
        /// A custom role for the user
    CustomRole(String),
}

impl Default for Role {
    fn default() -> Self{ Role::User }
}

    /// `Target` is the resource being requested or route being accessed
#[derive(Debug, Serialize, Deserialize)]
pub enum Target {
        /// `Guardian` Target for accounts that have a cloud manager and a user
    Guardian,
        /// `Global` Target has access to administration and user routes or permissions
    Global,
        /// A custom role for the user
    CustomTarget(String),
}

impl Default for Target {
    fn default() -> Self{ Target::CustomTarget(Default::default()) }
}

    /// `AuthPayload` creates and authenticates auth values
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthPayload {
    role: Role,
    target: Target,
    lease: Lease,
    random_key: String,
}

    /// `AuthEngine` creates and authenticates authorization/authentication secrets
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthEngine {
    bearer: SGSecret,
    payload: AuthPayload,
}

impl AuthEngine where {
        /// Initialize a AuthEngine for creating and authenticating branca secrets
    pub fn new() -> Self {
        Self { 
            bearer: Default::default(), 
            payload: AuthPayload {
                role: Default::default(), 
                target: Default::default(), 
                lease: Default::default(),
                random_key: secrets::random64alpha().expose_secret().to_owned(),
            }
        }
    }
        /// The username or client name  
    pub fn bearer(mut self, bearer: Secret<String>) -> Self {
        self.bearer = SGSecret(bearer.expose_secret().clone().to_owned());
        
        self
    }
        /// The role of the client  
    pub fn role(mut self, role: Role) -> Self {
        self.payload.role = role;
        
        self
    }
        /// The expiry date or time for the secret
    pub fn expiry(mut self, expiry: chrono::Duration) -> Self  {
        self.payload.lease = Lease::DateExpiry(Utc::now() + expiry);
        
        self
    }
        /// Target for the operation
    pub fn target(mut self, attr: Target) -> Self {
        self.payload.random_key = secrets::random64alpha().expose_secret().to_owned();
        self.payload.target = attr;
        
        self
    }

        /// Insert new token
    pub fn insert(self) -> Result<(custom_codes::DbOps, Secret<String>, Option<AuthPayload>), SGError> {
        let auth_db = sg_auth();
        let db = Db::start_default(auth_db)?;

        let key = bincode::serialize(&self.bearer.0)?; 

        let value = bincode::serialize::<AuthPayload>(&self.payload)?; //TODO: Should I encrypt bearer with branca in index

        let dbop = db.insert(key, value)?;

        let bearer_key = self.bearer.0.clone() + ":::" + &self.payload.random_key;

        if let Some(updated) = dbop {
            let data = bincode::deserialize::<AuthPayload>(&updated)?;
            Ok((custom_codes::DbOps::Modified, Secret::new(bearer_key), Some(data)))
        }else {
            Ok((custom_codes::DbOps::Inserted, Secret::new(bearer_key), None))
        }        
    }
        /// Create a new branca encoded token
    pub fn issue(self) -> Result<(custom_codes::DbOps, Secret<String>, Option<AuthPayload>), SGError> {
        let auth_db = sg_auth();
        let db = Db::start_default(auth_db)?;

        let key = bincode::serialize(&self.bearer.0)?; 

        let value = bincode::serialize::<AuthPayload>(&self.payload)?; //TODO: Should I encrypt bearer with branca in index

        let dbop = db.insert(key, value)?;

        let raw_key = self.bearer.0.clone() + ":::" + &self.payload.random_key;
        let bearer_key = crate::secrets::branca_encode(Secret::new(raw_key))?;

        if let Some(updated) = dbop {
            let data = bincode::deserialize::<AuthPayload>(&updated)?;
            Ok((custom_codes::DbOps::Modified, bearer_key, Some(data)))
        }else {
            Ok((custom_codes::DbOps::Inserted, bearer_key, None))
        }        
    }
        
        /// Authenticate an existing token
    pub fn get(self, raw_key: Secret<String>) -> Result<(custom_codes::DbOps, Option<Payload>), SGError> {
        let auth_db = sg_auth();
        let db = Db::start_default(auth_db)?;

        let raw_key = raw_key.expose_secret();
        let dual = raw_key.split(":::").collect::<Vec<&str>>();
        let key = bincode::serialize(dual[0])?;

        let check_key = db.get(key)?;

        if let Some(binary) = check_key {
            let data = bincode::deserialize::<AuthPayload>(&binary)?;
            Ok((custom_codes::DbOps::KeyFound, Some((data.role, data.target))))
        }else {
            Ok((custom_codes::DbOps::KeyNotFound, None))
        } 
    }
        
        /// Authenticate an existing token
        /// Currently returns:
        ///     `custom_codes::AccessStatus::Expired` for an secret that has reached end of life
        ///     `custom_codes::AccessStatus::Granted` for a secret that is live and RAC is authenticated
        ///     `custom_codes::AccessStatus::RejectedRAC` for a secret that is live but the RAC is not authentic
        ///     `custom_codes::AccessStatus::Rejected` for a secret that cannot be authenticated
    pub fn authenticate(self, raw_key: Secret<String>) -> Result<(custom_codes::AccessStatus, Option<Payload>), SGError> {
        let auth_db = sg_auth();
        let db = Db::start_default(auth_db)?;

        let raw_key = raw_key.expose_secret();
        let dual = raw_key.split(":::").collect::<Vec<&str>>();

        let key = bincode::serialize(dual[0])?;
        let user_random_key = dual[1];

        let check_key = db.get(key)?;

        if let Some(binary) = check_key {
            let payload = bincode::deserialize::<AuthPayload>(&binary)?;
            match payload.lease {
                Lease::DateExpiry(datetime) => {
                    if Utc::now() > datetime {
                        Ok((custom_codes::AccessStatus::Expired, None))
                    }else {
                        if payload.random_key == user_random_key {
                            Ok((custom_codes::AccessStatus::Granted, Some((payload.role, payload.target))))
                        }else {
                            Ok((custom_codes::AccessStatus::RejectedRAC, None))
                        }
                    }
                },
                Lease::Lifetime => Ok((custom_codes::AccessStatus::Granted, Some((payload.role, payload.target)))),
                _ => Ok((custom_codes::AccessStatus::Rejected, None))
            }            
        }else {
            Ok((custom_codes::AccessStatus::Rejected, None))
        } 
    }

        /// Remove a secret from the database
    pub fn rm(self, raw_key: Secret<String>) -> Result<(custom_codes::DbOps, Option<FullPayload>), SGError> {
        let auth_db = sg_auth();
        let db = Db::start_default(auth_db)?;

        let raw_key = raw_key.expose_secret();
        let dual = raw_key.split(":::").collect::<Vec<&str>>();
        let key = bincode::serialize(dual[0])?;

        let check_key = db.remove(key)?;

        if let Some(binary) = check_key {
            let data = bincode::deserialize::<AuthPayload>(&binary)?;
            Ok((custom_codes::DbOps::Deleted, Some((data.role, data.lease, data.target, data.random_key))))
        }else {
            Ok((custom_codes::DbOps::KeyNotFound, None))
        } 
    }

       /// Show all database entries
    pub fn list_keys(self) -> Result<Vec<u8>, SGError> {
        let auth_db = sg_auth();
        let db = Db::start_default(auth_db)?;
        
        let mut sled_vec = vec![];

        db.iter().keys().for_each(|data| {
            if let Ok(inner) = data {
                sled_vec.push(inner);
            }else {
                sled_vec.clear();
            }
        });

        Ok(vec![])
    }
    
       /// Show all database entries
    pub fn list_values(self) -> Result<Vec<u8>, SGError> {
        let auth_db = sg_auth();
        let db = Db::start_default(auth_db)?;
        
        let mut sled_vec = vec![];

        db.iter().values().for_each(|data| {
            if let Ok(inner) = data {
                sled_vec.push(inner);
            }else {
                sled_vec.clear();
            }
        });

        Ok(vec![])
    }
}

    /// A return value to an of the operation. It `contains the payload of the AuthPayload` from `AuthEngine`
pub type FullPayload = (Role, Lease, Target, String);

    /// A return value to an of the operation. It contains the payload of the AuthPayload values `Role` & `Target`
pub type Payload = (Role, Target);

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
