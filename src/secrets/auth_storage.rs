use serde_derive::{Serialize, Deserialize};
use secrecy::{ExposeSecret, Secret};
use crate::{SGSecret, Lease, SGError};

    /// ## Struct for simple storage
    /// ### Struct structure
    /// ```no_run
    /// use schemeguardian::global::Lease;
    /// struct SimpleAuthStorage<SAS> {
    ///     user: Option<SAS>, // `SAS` implements `std::fmt::Debug + std::clone::Clone`
    ///     target: Option<SAS>,
    ///     lease: Lease,
    ///     random_key: String,
    /// }
    /// ```
    /// #### Example
    /// ```
    /// use schemeguardian::secrets::SimpleAuthStorage;
    /// use schemeguardian::{SGSecret, Lease};
    /// use chrono::Utc;
    /// SimpleAuthStorage::new()
    ///     .user("Foo")
    ///     .target("Bar")
    ///     .lease(Lease::DateExpiry(Utc::now() + chrono::Duration::Days(7)))
    ///     .build();
        /// ```
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SimpleAuthStorage {
    user: String,
    target: String,
    lease: Lease,
    random_key: SGSecret,
}

impl SimpleAuthStorage {
        /// ### Initialize a new SimpleAuthStorage
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::{SGSecret, Lease};
        /// use chrono::Utc;
        /// let foo = SimpleAuthStorage::new();
        /// ```
    pub fn new() -> Self {
        Self {
            user: Default::default(),
            target: Default::default(),
            lease: Default::default(),
            random_key: Default::default(),
        }
    }
        /// ### Add a User
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// SimpleAuthStorage::new()
        ///     .user("Foo");
        /// ```
    pub fn user(mut self, user: &str) -> Self {
        self.user = user.to_owned();

        self
    }
        /// ### Add a Target
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// SimpleAuthStorage::new()
        ///     .target("Bar");
        /// ```
    pub fn target(mut self, target: &str) -> Self {
        self.target = target.to_owned();

        self
    }
        /// ### Add a Lease
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::Lease;
        /// use chrono::Utc;
        /// SimpleAuthStorage::new()
        ///     .lease(Lease::DateExpiry(Utc::now() + chrono::Duration::Days(7)));
        /// ```
    pub fn lease(mut self, lease: Lease) -> Self {
        self.lease = lease;

        self
    }
        /// ### Build the struct
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// SimpleAuthStorage::new()
        ///     .build();
        /// ```
    pub fn build(mut self) -> Self {
        self.random_key = SGSecret(crate::secrets::random64alpha().expose_secret().to_owned());

        self
    }
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::{SGSecret, Lease};
        /// use chrono::Utc;
        /// SimpleAuthStorage::new()
        ///     .user("Foo")
        ///     .target("Bar")
        ///     .lease(Lease::DateExpiry(Utc::now() + chrono::Duration::Days(7)))
        ///     .build()
        ///     .insert();
        /// ```
    pub fn insert(self) -> Result<(custom_codes::DbOps, Secret<String>), SGError> {
        let auth_db = sg_simple_auth();
        let db = sled::Db::open(auth_db)?;

        let key = bincode::serialize(&self.user)?; 

        let value = bincode::serialize::<SimpleAuthStorage>(&self)?; //TODO: Should I encrypt bearer with branca in index

        let dbop = db.insert(key, value)?;

        let bearer_key = Secret::new(self.user.clone() + ":::" + &self.random_key + ":::" + &self.target);

        if let Some(updated) = dbop {
            Ok((custom_codes::DbOps::Modified, bearer_key))
        }else {
            Ok((custom_codes::DbOps::Inserted, bearer_key))
        }        
    }
}
    /// Get default path to database file
    /// ### Structure
    /// fn sg_simple_auth() -> &'static str {
    ///
    ///     "./SchemeGuardianDB/SG_SIMPLE_AUTH"
    ///
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
pub type Payload = (String, String, Lease, String);
