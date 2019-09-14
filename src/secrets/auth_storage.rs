use serde_derive::{Serialize, Deserialize};
use secrecy::ExposeSecret;
use chrono::{DateTime, Utc};
use crate::SGSecret;

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
    /// A return value to an of the operation. It `contains the payload of the AuthPayload (user, target, lease, random_key)`
    /// ## Example
    /// ```no_run
    /// use crate::secrets::auth_storage::Payload;
    /// fn fetch_from_db() -> Payload<MyUserEnum> {
    ///     // some code here
    /// }
    /// ```
pub type Payload<R> = (R, String, Lease, String);
    /// Get default path to database file
    /// ## Example
    /// ```no_run
    /// use crate::secrets::auth_storage::sg_simple_auth;
    /// let db = sg_simple_auth();
    /// ```
fn sg_simple_auth() -> &'static str {
    "./SchemeGuardianDB/SG_SIMPLE_AUTH"
}
    /// ## Struct for simple storage
    /// ### Struct structure
    /// ```no_run
    /// struct SimpleAuthStorage<AS> {
    ///     user: AS,
    ///     target: String,
    ///     lease: Lease,
    ///     random_key: String,
    /// }
    /// ```
#[derive(Debug)]
pub struct SimpleAuthStorage<AS> {
    user: Option<AS>,
    target: String,
    lease: Lease,
    random_key: SGSecret,
}

impl<AS> SimpleAuthStorage<AS> {
        /// Create a new SimpleAuthStorage
    pub fn new() -> Self {
        Self {
            user: None,
            target: Default::default(),
            lease: Default::default(),
            random_key: SGSecret(crate::secrets::random64alpha().expose_secret().to_owned()),
        }
    }
        /// Get key
    pub fn key(self) -> SGSecret {
        self.random_key
    }
}