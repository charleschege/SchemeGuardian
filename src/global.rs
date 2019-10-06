use serde_derive::{Serialize, Deserialize};
use redactedsecret::SecretString;
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
    CustomTarget(SecretString),
        /// An unspefified target
    Unspecified,
}

impl Default for Target {
    fn default() -> Self{ Self::Unspecified }
}