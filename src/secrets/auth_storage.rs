use serde_derive::{Serialize, Deserialize};
use secrecy::{ExposeSecret, Secret};
use crate::{SGSecret, Lease, SGError, Role};

    /// ## Struct for simple storage
    /// ### Struct structure
    /// ```
    /// use schemeguardian::global::Lease;
    /// use schemeguardian::{Role, SGSecret};
    /// struct SimpleAuthStorage<R> {
    ///     user: SGSecret,
    ///     role: Role<R>,
    ///     target: SGSecret,
    ///     lease: Lease,
    ///     random_key: SGSecret,
    /// }
    /// ```
    /// #### Example
    /// ```
    /// use schemeguardian::secrets::SimpleAuthStorage;
    /// use schemeguardian::{SGSecret, Lease, Role};
    /// use chrono::Utc;
    /// use serde_derive::{Serialize, Deserialize};
    /// #[derive(Debug, Serialize, Deserialize)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    /// SimpleAuthStorage::<Custom>::new()
    ///     .user(SGSecret("Foo".to_owned()))
    ///     .role(Role::Admin)
    ///     .target(SGSecret("Bar".to_owned()))
    ///     .lease(Lease::DateExpiry(Utc::now() + chrono::Duration::days(7)))
    ///     .build();
    /// ```
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SimpleAuthStorage<R> {
    user: SGSecret,
    role: Role<R>,
    target: SGSecret,
    lease: Lease,
    random_key: SGSecret,
}

impl<R> SimpleAuthStorage<R> where R: serde::Serialize + serde::de::DeserializeOwned {
        /// ### Initialize a new SimpleAuthStorage
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use chrono::Utc;
        /// use serde_derive::{Serialize, Deserialize};
        /// #[derive(Debug, Serialize, Deserialize)]
        /// enum Custom {
        ///     ExecutiveBoard,
        /// }
        /// SimpleAuthStorage::<Custom>::new();
        /// ```
    pub fn new() -> Self {
        Self {
            user: Default::default(),
            role: Role::Unspecified,
            target: Default::default(),
            lease: Default::default(),
            random_key: Default::default(),
        }
    }
        /// ### Add a User
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::SGSecret;
        /// use serde_derive::{Serialize, Deserialize};
        /// #[derive(Debug, Serialize, Deserialize)]
        /// enum Custom {
        ///     ExecutiveBoard,
        /// }
        /// SimpleAuthStorage::<Custom>::new()
        ///     .user(SGSecret("Foo".to_owned()));
        /// ```
    pub fn user(mut self, user: SGSecret) -> Self {
        self.user = user;

        self
    }
        /// ### Add a Role
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::Role;
        /// use serde_derive::{Serialize, Deserialize};
        /// #[derive(Debug, Serialize, Deserialize)]
        /// enum Custom {
        ///     ExecutiveBoard,
        /// }
        /// SimpleAuthStorage::<Custom>::new()
        ///     .role(Role::Admin);
        /// ```
    pub fn role(mut self, value: Role<R>) -> Self {
        self.role = value;

        self
    }

      
        /// ### Add a Target
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::SGSecret;
        /// use serde_derive::{Serialize, Deserialize};
        /// #[derive(Debug, Serialize, Deserialize)]
        /// enum Custom {
        ///     ExecutiveBoard,
        /// }
        /// SimpleAuthStorage::<Custom>::new()
        ///     .target(SGSecret("Bar".to_owned()));
        /// ```
    pub fn target(mut self, target: SGSecret) -> Self {
        self.target = target;

        self
    }
        /// ### Add a Lease
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::Lease;
        /// use chrono::Utc;
        /// use serde_derive::{Serialize, Deserialize};
        /// #[derive(Debug, Serialize, Deserialize)]
        /// enum Custom {
        ///     ExecutiveBoard,
        /// }
        /// SimpleAuthStorage::<Custom>::new()
        ///     .lease(Lease::DateExpiry(Utc::now() + chrono::Duration::days(7)));
        /// ```
    pub fn lease(mut self, lease: Lease) -> Self {
        self.lease = lease;

        self
    }
        /// ### Build the struct
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use serde_derive::{Serialize, Deserialize};
        /// #[derive(Debug, Serialize, Deserialize)]
        /// enum Custom {
        ///     ExecutiveBoard,
        /// }
        /// SimpleAuthStorage::<Custom>::new()
        ///     .build();
        /// ```
    pub fn build(mut self) -> Self {
        self.random_key = SGSecret(crate::secrets::random64alpha().expose_secret().to_owned());

        self
    }
        /// ## Insert a new key to the Sled KV Store
        /// The outcome String is formatted as `user::random_key::target`
        /// #### Example
        /// ```no_run
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::{SGSecret, Lease};
        /// use chrono::Utc;
        /// use serde_derive::{Serialize, Deserialize};
        /// #[derive(Debug, Serialize, Deserialize)]
        /// enum Custom {
        ///     ExecutiveBoard,
        /// }
        /// SimpleAuthStorage::<Custom>::new()
        ///     .user(SGSecret("Foo".to_owned()))
        ///     .target(SGSecret("Bar".to_owned()))
        ///     .lease(Lease::DateExpiry(Utc::now() + chrono::Duration::days(7)))
        ///     .build()
        ///     .insert();
        /// ```
    pub fn insert(self) -> Result<(custom_codes::DbOps, Secret<String>), SGError> {
        let auth_db = sg_simple_auth();
        let db = sled::Db::open(auth_db)?;

        let key = bincode::serialize(&self.user)?; 

        let value = bincode::serialize::<Self>(&self)?; //TODO: Should I encrypt bearer with branca in index

        let dbop = db.insert(key, value)?;

        let bearer_key = Secret::new(self.user.0.clone() + ":::" + &self.random_key + ":::" + &self.target);

        if let Some(_) = dbop {
            Ok((custom_codes::DbOps::Modified, bearer_key))
        }else {
            Ok((custom_codes::DbOps::Inserted, bearer_key))
        }        
    }
        /// ## Get a value from a key
        /// #### Example
        /// ```no_run
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::SGSecret;
        /// use serde_derive::{Serialize, Deserialize};
        /// #[derive(Debug, Serialize, Deserialize)]
        /// enum Custom {
        ///     ExecutiveBoard,
        /// }
        /// SimpleAuthStorage::<Custom>::new()
        ///     .get(SGSecret("foo".to_owned()));
        /// ```
    pub fn get(self, redactable_key: SGSecret) -> Result<(custom_codes::DbOps, Option<Payload<R>>), SGError> {
        let auth_db = sg_simple_auth();
        let db = sled::Db::open(auth_db)?;

        let raw_key = &redactable_key.0;
        let key_collection = raw_key.split(":::").collect::<Vec<&str>>();
        let key = bincode::serialize(key_collection[0])?;

        let dbop = db.get(key)?;

        if let Some(dbvalues) = dbop {
            let data = bincode::deserialize::<Self>(&dbvalues)?;
            Ok((custom_codes::DbOps::KeyFound, Some((data.user, data.role, data.target, data.lease, data.random_key))))
        }else {
            Ok((custom_codes::DbOps::KeyNotFound, None))
        }      
    }

        /// ## Remove a secret from the database
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::SGSecret;  
        /// use serde_derive::{Serialize, Deserialize};      
        /// #[derive(Debug, Serialize, Deserialize)]
        /// enum Custom {
        ///     ExecutiveBoard,
        /// }
        /// SimpleAuthStorage::<Custom>::new()
        ///     .remove(SGSecret("foo".to_owned()));
        /// ```
    pub fn remove(self, redactable_key: SGSecret) -> Result<(custom_codes::DbOps, Option<Payload<R>>), SGError> {
        let auth_db = sg_simple_auth();
        let db = sled::Db::open(auth_db)?;

        let raw_key = &redactable_key.0;
        let key_collection = raw_key.split(":::").collect::<Vec<&str>>();
        let key = bincode::serialize(key_collection[0])?;

        let dbop = db.remove(key)?;

        if let Some(dbvalues) = dbop {
            let data = bincode::deserialize::<Self>(&dbvalues)?;
            Ok((custom_codes::DbOps::Deleted, Some((data.user, data.role, data.target, data.lease, data.random_key))))
        }else {
            Ok((custom_codes::DbOps::KeyNotFound, None))
        } 
    }
        /// ## Show all value entries in KV
        /// #### Example
        /// ```
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::SGSecret;
        /// use serde_derive::{Serialize, Deserialize};
        /// #[derive(Debug, Serialize, Deserialize)]
        /// enum Custom {
        ///     ExecutiveBoard,
        /// }
        /// SimpleAuthStorage::<Custom>::new()
        ///     .remove(SGSecret("foo".to_owned()));
        /// ```
    pub fn list(self) -> Result<Vec<Payload<R>>, SGError> {
        let auth_db = sg_simple_auth();
        let db = sled::Db::open(auth_db)?;
        let mut dbvalues: Vec<Payload<R>> = Vec::new();

        db.iter().values().for_each(|data| {
            if let Ok(inner) = data {
                match bincode::deserialize::<Self>(&inner) {
                    Ok(value) => {
                        dbvalues.push((value.user, value.role, value.target, value.lease, value.random_key))
                    },
                    Err(e) => { SGError::BincodeError(e); },
                }
            }else {
                dbvalues.clear();
            }
        });

        Ok(dbvalues)
    }
        /// ## Authenticate an existing token
        /// Currently returns:
        ///     `custom_codes::AccessStatus::Expired` for an secret that has reached end of life
        ///     `custom_codes::AccessStatus::Granted` for a secret that is live and RAC is authenticated
        ///     `custom_codes::AccessStatus::RejectedRAC` for a secret that is live but the RAC is not authentic
        ///     `custom_codes::AccessStatus::Rejected` for a secret that cannot be authenticated
        /// #### Example
        /// ```should_panic
        /// use schemeguardian::secrets::SimpleAuthStorage;
        /// use schemeguardian::SGSecret;
        /// use serde_derive::{Serialize, Deserialize};
        /// #[derive(Debug, Serialize, Deserialize)]
        /// enum Custom {
        ///     ExecutiveBoard,
        /// }
        /// SimpleAuthStorage::<Custom>::new()
        ///     .authenticate(SGSecret("foo".to_owned()));
        /// ```
    pub fn authenticate(self, redactable_key: SGSecret) -> Result<(custom_codes::AccessStatus, Option<Payload<R>>), SGError> {
        let auth_db = sg_simple_auth();
        let db = sled::Db::open(auth_db)?;

        let raw_key = &redactable_key.0;
        let key_collection = raw_key.split(":::").collect::<Vec<&str>>();
        let key = bincode::serialize(key_collection[0])?;
        let user_random_key = key_collection[1];

        let check_key = db.get(key)?;

        if let Some(dbvalues) = check_key {
            let payload = bincode::deserialize::<Self>(&dbvalues)?;
            match payload.lease {
                Lease::DateExpiry(datetime) => {
                    if chrono::Utc::now() > datetime {
                        Ok((custom_codes::AccessStatus::Expired, None))
                    }else {
                        if &payload.random_key.0 == user_random_key {
                            Ok((custom_codes::AccessStatus::Granted, Some((payload.user, payload.role, payload.target, payload.lease, payload.random_key))))
                        }else {
                            Ok((custom_codes::AccessStatus::RejectedRAC, None))
                        }
                    }
                },
                Lease::Lifetime => Ok((custom_codes::AccessStatus::Granted, Some((payload.user, payload.role, payload.target, payload.lease, payload.random_key)))),
                _ => Ok((custom_codes::AccessStatus::Rejected, None))
            }            
        }else {
            Ok((custom_codes::AccessStatus::Rejected, None))
        } 
    }
}
    /// Get default path to database file
    /// ### Structure
    /// ```no_run
    /// # fn main() {}
    /// fn sg_simple_auth() -> &'static str {
    ///     "./SchemeGuardianDB/SG_SIMPLE_AUTH"
    /// }
    /// ```
fn sg_simple_auth() -> &'static str {
    "./SchemeGuardianDB/SG_SIMPLE_AUTH"
}
    /// A return value to an of the operation. It contains the payload of the AuthPayload 
    ///
    /// `(user, role, target, lease, random_key)`
    /// ## Example
    /// ```no_run
    /// use schemeguardian::secrets::auth_storage::Payload;
    /// use schemeguardian::Role;
    /// enum MyUserEnum {Foo, Bar}
    /// fn fetch_from_db<R>() -> Payload<R> {
    ///     // some code here
    ///     (Default::default(), Role::Unspecified, Default::default(), Default::default(), Default::default())
    /// }
    /// ```
pub type Payload<R> = (SGSecret, Role<R>, SGSecret, Lease, SGSecret);
