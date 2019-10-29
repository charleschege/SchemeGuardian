use crate::SGError;
use redactedsecret::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// ## Struct for simple storage
/// ### Struct structure
/// ```
/// use redactedsecret::SecretString;
///
/// pub struct SecretStorage {
///     identifier: SecretString,
///     data: Vec<u8>,
/// }
/// ```
/// #### Example
/// ```
/// use schemeguardian::SecretStorage;
/// use redactedsecret::SecretString;
///
///
/// SecretStorage::new()
///     .identifier(SecretString::new("Foo".to_owned()))
///     .data(b"RANDOM::DATA".to_vec());
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SecretStorage {
    identifier: SecretString,
    data: Vec<u8>,
}

impl SecretStorage {
    /// ### Initialize a new SecretStorage
    /// #### Example
    /// ```
    /// use schemeguardian::SecretStorage;
    ///
    /// SecretStorage::new();
    /// ```
    pub fn new() -> Self {
        Self {
            identifier: SecretString::default(),
            data: b"PHANTOM::DEFAULT".to_vec(),
        }
    }
    /// ### Add a User
    /// #### Example
    /// ```
    /// use schemeguardian::SecretStorage;
    /// use redactedsecret::SecretString;
    ///
    /// SecretStorage::new()
    ///     .identifier(SecretString::new("Foo".to_owned()));
    /// ```
    pub fn identifier(mut self, value: SecretString) -> Self {
        self.identifier = value;

        self
    }
    /// ### Add a ImmutableRole
    /// #### Example
    /// ```
    /// use schemeguardian::SecretStorage;
    /// use redactedsecret::SecretString;
    ///
    /// SecretStorage::new()
    ///     .identifier(SecretString::new("Foo".to_owned()))
    ///     .data(b"RANDOM::DATA".to_vec());
    /// ```
    pub fn data(mut self, value: Vec<u8>) -> Self {
        self.data = value;

        self
    }
    /// ## Insert a new key to the Sled KV Store
    /// The outcome String is formatted as `user::random_key::target`
    /// #### Example
    /// ```no_run
    /// use schemeguardian::{SecretStorage, Lease};
    /// use redactedsecret::SecretString;
    ///
    /// SecretStorage::new()
    ///     .identifier(SecretString::new("Foo".to_owned()))
    ///     .data(b"RANDOM::DATA".to_vec())
    ///     .insert();
    /// ```
    pub fn insert(self) -> Result<custom_codes::DbOps, SGError> {
        let auth_db = secrets_storage();
        let db = sled::Db::open(auth_db)?;

        let key = bincode::serialize(&self.identifier)?;

        let dbop = db.insert(key, self.data)?;

        if let Some(_) = dbop {
            Ok(custom_codes::DbOps::Modified)
        } else {
            Ok(custom_codes::DbOps::Inserted)
        }
    }
    /// ## Get a value from a key
    /// #### Example
    /// ```no_run
    /// use schemeguardian::SecretStorage;
    /// use redactedsecret::SecretString;
    /// SecretStorage::new()
    ///     .get(&SecretString::new("Foo".to_owned()));
    /// ```
    pub fn get(self, key: &SecretString) -> Result<(custom_codes::DbOps, Vec<u8>), SGError> {
        let auth_db = secrets_storage();
        let db = sled::Db::open(auth_db)?;
        let key = bincode::serialize(key.expose_secret())?;

        if let Some(dbvalue) = db.get(key)? {
            Ok((custom_codes::DbOps::KeyFound, dbvalue.to_vec()))
        } else {
            Ok((custom_codes::DbOps::KeyNotFound, Vec::new()))
        }
    }
    /// ## Remove a secret from the database
    /// #### Example
    /// ```
    /// use schemeguardian::SecretStorage;
    /// use redactedsecret::SecretString;
    /// SecretStorage::new()
    ///     .remove(SecretString::new("Foo".to_owned()));
    /// ```
    pub fn remove(self, key: SecretString) -> Result<(custom_codes::DbOps, Vec<u8>), SGError> {
        let auth_db = secrets_storage();
        let db = sled::Db::open(auth_db)?;
        let key = bincode::serialize(&key.expose_secret())?;

        if let Some(dbvalues) = db.remove(key)? {
            Ok((custom_codes::DbOps::Deleted, dbvalues.to_vec()))
        } else {
            Ok((custom_codes::DbOps::KeyNotFound, Vec::new()))
        }
    }
    /// ## Show all value entries in KV
    /// #### Example
    /// ```
    /// use schemeguardian::SecretStorage;
    /// SecretStorage::new()
    ///     .list();
    /// ```
    pub fn list(self) -> Result<Vec<sled::IVec>, SGError> {
        let auth_db = secrets_storage();
        let db = sled::Db::open(auth_db)?;
        let mut dbvalues: Vec<sled::IVec> = Vec::new();

        db.iter().values().for_each(|data| {
            if let Ok(inner) = data {
                dbvalues.push(inner);
            } else {
                dbvalues.clear();
            }
        });

        Ok(dbvalues)
    }
}
/// Get default path to database file
/// ### Structure
/// ```no_run
/// # fn main() {}
/// fn secrets_storage() -> &'static str {
///     "./SchemeGuardianDB/SECRETS_STORAGE"
/// }
/// ```
fn secrets_storage() -> &'static str {
    "./SchemeGuardianDB/SECRETS_STORAGE"
}
