use redactedsecret::SecretString;
use serde::{Deserialize, Serialize};

/// Shows the current state of an authentication mechanism used by a user or node
/// The authentication mechanism can be of any kind including a Passphrase, PIN, Hardware etc.
/// ### Examples
/// ```
/// # use schemeguardian::AuthState;
/// let foo = AuthState::Unspecified;
/// assert_eq!(foo, AuthState::Unspecified);
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum AuthState {
    /// Shows that the current state of an authentication mechanism is yet to be set by the user.
    /// This is used for accounts that have to be pre-registered then the user has to set the authentication mechanism there after
    Unspecified,
    /// shows that an account auth state is in normal state and visible to the user
    Transparent(SecretString),
    /// shows that an accounts authentication is currently in a default state with a randomly generated authentication mechanism
    RandomDefault(SecretString),
    /// shows an account is temporary locked using a `TempLock`
    Locked(TempLock),
    /// shows that a user triggered an authentication for reset
    ResetTriggered(SecretString),
    /// shows the authentication code via email/chat for authentication reset has been triggered.
    ResetInProgress(SecretString),
}

/// Creates a temporary lock if triggered
/// ### Examples
/// ```
/// # use schemeguardian::TempLock;
/// let foo = TempLock::RandomToMail;
/// assert_eq!(foo, TempLock::RandomToMail);
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum TempLock {
    /// set after a specified timeframe in TAI64N
    Duration(tai64::TAI64N),
    /// set only after a user/node confirms a random key from email address
    RandomToMail,
    /// set only after a user/node confirms a random key from a logged in device
    RandomToNode,
    /// set after another `associated` user authenticates the random key from an authorized device
    RandomToUser,
    /// set after multiple `associated` users authenticate the random key from their devices
    RandomToMultiUser,
    /// set only after an `SuperUser` authenticates the random key
    RandomToSuperUser,
    /// set only after an `Admin` authenticates the random key
    RandomToAdmin,
    /// set only after a `SubAdmin` authenticates the random key
    RandomToSubAdmin,
    /// set after multiple `associated` nodes authenticate the random key
    RandomToMultiNode,
}
