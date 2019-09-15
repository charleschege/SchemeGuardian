use serde_derive::{Serialize, Deserialize};
use secrecy::ExposeSecret;
use crate::SGSecret;
use crate::Lease;

    /// ## Struct for simple storage
    /// ### Struct structure
    /// ```no_run
    /// use schemeguardian::global::Lease;
    /// struct SimpleAuthStorage<AS> {
    ///     user: Option<AS>, // `AS` implements `std::fmt::Debug + std::clone::Clone`
    ///     target: Option<AS>,
    ///     lease: Lease,
    ///     random_key: String,
    /// }
    /// ```
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SimpleAuthStorage<AS> {
    user: Option<AS>,
    target: Option<AS>,
    lease: Lease,
    random_key: SGSecret,
}

impl<AS> SimpleAuthStorage<AS> where AS: std::fmt::Debug + std::clone::Clone{
        /// ### Initialize a new SimpleAuthStorage
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::{SGSecret, Lease};
        /// use chrono::Utc;
        /// let foo = SimpleAuthStorage::<String>::new();
        /// ```
    pub fn new() -> Self {
        Self {
            user: Default::default(),
            target: Default::default(),
            lease: Default::default(),
            random_key: Default::default(),
        }
    }
        /// Add User
    pub fn user(mut self, user: AS) -> Self {
        self.user = Some(user);

        self
    }
        /// Add a target
    pub fn target(mut self, target: AS) -> Self {
        self.target = Some(target);

        self
    }
        /// Add a lease
    pub fn lease(mut self, lease: Lease) -> Self {
        self.lease = lease;

        self
    }
        /// Add a random_key
    pub fn build(mut self) -> Self {
        self.random_key = SGSecret(crate::secrets::random64alpha().expose_secret().to_owned());

        self
    }
}
    /// Get default path to database file
    /// ### Structure
    /// fn sg_simple_auth() -> &'static str {
    ///     "./SchemeGuardianDB/SG_SIMPLE_AUTH"
    /// }
fn sg_simple_auth() -> &'static str {
    "./SchemeGuardianDB/SG_SIMPLE_AUTH"
}

    /// A return value to an of the operation. It `contains the payload of the AuthPayload (user, target, lease, random_key)`
    /// ## Example
    /// ```no_run
    /// use schemeguardian::secrets::auth_storage::Payload;
    /// enum MyUserEnum {Foo, Bar}
    /// fn fetch_from_db() -> Payload<MyUserEnum> {
    ///     // some code here
    ///     (MyUserEnum::Bar, Default::default(), Default::default(), Default::default())
    /// }
    /// ```
pub type Payload<R> = (R, String, Lease, String);

