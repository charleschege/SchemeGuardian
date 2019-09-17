use serde_derive::{Serialize, Deserialize};
use secrecy::{DebugSecret, CloneableSecret};
use zeroize::Zeroize;
use chrono::{DateTime, Utc};

    /// ### A an expiry date to lease a secret
    /// #### Example
    /// ```
    /// use schemeguardian::global::Lease;
    /// let foo = Lease::Lifetime;
    /// assert_eq!(foo, Lease::Lifetime);
    /// ```
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
    /// `SGSecret` is a struct with public fields that impl Zeroize and `#[zeroize(drop)]` for security.
    ///
    /// `Deref`, `ClonableSecret`, `DebugSecret`, `fmt::Debug`, `fmt::Display` and `Default` traits have been implemented for this
    /// ## Example
    /// ```
    /// use schemeguardian::SGSecret;
    /// let data = SGSecret(String::from("WHO AM I"));
    /// dbg!(data);
    /// ```
#[derive(Clone, Zeroize, Serialize, Deserialize, PartialEq, PartialOrd, Eq)]
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
    /// `Role` of the user
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Role<R> {
        /// The user with all access rights
    SuperUser,
        /// A user with administrative rights
    Admin,
        /// A user with some administrative rights
    SubAdmin,
        /// A normal user
    User,
        /// A custom role for the user
    CustomRole(R),
		/// Role is not specified hence the user has no rights
	Unspecified,
}

impl<R> Default for Role<R> {
    fn default() -> Self{ Role::Unspecified }
}

    /// A fixed set of unchangable roles
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum ImmutableRole {
        /// The user with all access rights
    SuperUser,
        /// A user with administrative rights
    Admin,
        /// A user with some administrative rights
    SubAdmin,
        /// A normal user
    User,
		/// Role is not specified hence the user has no rights
	Unspecified,
}

impl Default for ImmutableRole {
    fn default() -> Self { ImmutableRole::Unspecified }
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