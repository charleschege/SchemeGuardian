use redactedsecret::SecretString;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use tai64::TAI64N;

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
    DateExpiryTAI(TAI64N),
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
    fn default() -> Self {
        Lease::DateExpiryTAI(TAI64N::from_system_time(
            &(SystemTime::now() + Duration::from_secs(timelite::LiteDuration::hours(24))),
        ))
    }
}
/// `Role` of the user
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum GenericRole<R> {
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

impl<R> Default for GenericRole<R> {
    fn default() -> Self {
        GenericRole::Unspecified
    }
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
    fn default() -> Self {
        ImmutableRole::Unspecified
    }
}

/// `Target` is the resource being requested or route being accessed
#[derive(Debug, Serialize, Deserialize, PartialEq)]
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
    fn default() -> Self {
        Self::Unspecified
    }
}
/// A return value to an of the operation. It contains the payload of the AuthPayload
///
/// `(user, role)`
/// ## Example
/// ```no_run
/// use schemeguardian::Payload;
/// use schemeguardian::ImmutableRole;
/// enum MyUserEnum {Foo, Bar}
/// fn fetch_from_db() -> Payload {
///     // some code here
///     (Default::default(), ImmutableRole::Unspecified)
/// }
/// ```
pub type Payload = (SecretString, ImmutableRole);

/// A return value to an of the operation. It contains the payload of the AuthPayload
///
/// `(user, role, target)`
/// ## Example
/// ```no_run
/// use schemeguardian::GenericPayload;
/// use schemeguardian::GenericRole;
/// enum MyUserEnum {Foo, Bar}
/// fn fetch_from_db<R>() -> GenericPayload<R> {
///     // some code here
///     (Default::default(), GenericRole::Unspecified, Default::default())
/// }
/// ```
pub type GenericPayload<R> = (SecretString, GenericRole<R>, Option<SecretString>);
