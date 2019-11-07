use crate::{GenericPayload, GenericRole, ImmutableRole, Lease, Payload, SGError};
use custom_codes::{AccessStatus, DbOps};
use redactedsecret::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use tai64::TAI64N;

/// Struct that splits a token at the pattern `:::`
/// ### Struct structure
/// ```
/// use redactedsecret::SecretString;
///
/// pub struct DestructureToken(SecretString);
/// ```
/// #### Example
/// ```
/// use schemeguardian::DestructureToken;
/// use redactedsecret::SecretString;
///
/// DestructureToken::new()
///     .token(SecretString::new("Foo".to_owned()))
///     .build();
/// ```
pub struct DestructureToken(SecretString);
/// Usage
/// ```
/// use schemeguardian::DestructureToken;
/// ```
impl DestructureToken {
    /// Initialize a new `DestructureToken` struct returning a `Self` value
    /// #### Example
    /// ```
    /// use schemeguardian::DestructureToken;
    /// use redactedsecret::SecretString;
    ///
    /// DestructureToken::new()
    ///     .token(SecretString::new("Foo".to_owned()))
    ///     .build();
    /// ```
    pub fn new() -> Self {
        Self(Default::default())
    }
    /// Replace the default field with user specified field
    /// #### Example
    /// ```
    /// use schemeguardian::DestructureToken;
    /// use redactedsecret::SecretString;
    ///
    /// DestructureToken::new()
    ///     .token(SecretString::new("Foo".to_owned()));
    /// ```
    pub fn token(mut self, value: SecretString) -> Self {
        self.0 = value;

        self
    }
    /// Takes the branca decoded key from the client and splits it into a `Identifier` keys
    /// #### Example
    /// ```
    /// use schemeguardian::DestructureToken;
    /// use redactedsecret::SecretString;
    ///
    /// DestructureToken::new()
    ///     .token(SecretString::new("Foo".to_owned()))
    ///     .identifier();
    /// ```
    pub fn identifier(&self) -> Option<SecretString> {
        if let Some(_) = self.0.expose_secret().find(":::") {
            let keys: Vec<&str> = self.0.expose_secret().split(":::").collect();

            Some(SecretString::new(keys[0].to_owned()))
        } else {
            None
        }
    }
    /// Takes the branca decoded key from the client and splits it into a `RandomAccessCode` keys
    /// #### Example
    /// ```
    /// use schemeguardian::DestructureToken;
    /// use redactedsecret::SecretString;
    ///
    /// DestructureToken::new()
    ///     .token(SecretString::new("Foo".to_owned()))
    ///     .rac();
    /// ```
    pub fn rac(&self) -> Option<SecretString> {
        if let Some(_) = self.0.expose_secret().find(":::") {
            let keys: Vec<&str> = self.0.expose_secret().split(":::").collect();

            Some(SecretString::new(keys[1].to_owned()))
        } else {
            None
        }
    }
    /// Takes the branca decoded key from the client and splits it into a `identifier` and `RandomAccessCode` keys
    /// Returns `(Identifier, RandomAccessCode)` as `(SecretString, SecretString)`
    /// #### Example
    /// ```
    /// use schemeguardian::DestructureToken;
    /// use redactedsecret::SecretString;
    ///
    /// DestructureToken::new()
    ///     .token(SecretString::new("Foo".to_owned()))
    ///     .build();
    /// ```
    pub fn build(&self) -> Option<(SecretString, SecretString)> {
        if let Some(_) = self.0.expose_secret().find(":::") {
            let keys: Vec<&str> = self.0.expose_secret().split(":::").collect();

            Some((
                SecretString::new(keys[0].to_owned()),
                SecretString::new(keys[1].to_owned()),
            ))
        } else {
            None
        }
    }
}

/// ### Struct structure
/// ```
/// use redactedsecret::SecretString;
/// use serde::{Serialize, Deserialize};
/// use schemeguardian::{ImmutableRole, Lease};
///
/// #[derive(Debug, Serialize, Deserialize, Clone)]
/// pub struct AuthEngine {
///    identifier: SecretString,
///    role: ImmutableRole,
///    lease: Lease,
///    random_key: SecretString,
/// }
/// ```
/// #### Example
/// ```
/// use schemeguardian::{AuthEngine, ImmutableRole, Lease};
/// use redactedsecret::SecretString;
/// use std::time::{SystemTime, Duration};
/// use tai64::{TAI64N};
///
/// AuthEngine::new()
///     .identifier(SecretString::new("Foo".to_owned()))
///     .role(ImmutableRole::Admin)
///     .lease(Lease::DateExpiryTAI(TAI64N::from_system_time(&(SystemTime::now() + Duration::from_secs(2)))))
///     .build();
/// ```
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthEngine {
    identifier: SecretString,
    role: ImmutableRole,
    lease: Lease,
    random_key: SecretString,
}
/// ### Usage
/// ```
/// use schemeguardian::AuthEngine;
///
/// AuthEngine::new();
/// ```
impl AuthEngine {
    /// ### Initialize a new AuthEngine
    /// #### Example
    /// ```
    /// use schemeguardian::AuthEngine;
    ///
    /// AuthEngine::new();
    ///     
    /// ```
    pub fn new() -> Self {
        Self {
            identifier: SecretString::default(),
            role: ImmutableRole::Unspecified,
            lease: Default::default(),
            random_key: SecretString::default(),
        }
    }
    /// ### Add an identifier
    /// #### Example
    /// ```
    /// use schemeguardian::AuthEngine;
    /// use redactedsecret::SecretString;
    ///
    /// AuthEngine::new()
    ///     .identifier(SecretString::new("Foo".to_owned()));
    /// ```
    pub fn identifier(mut self, user: SecretString) -> Self {
        self.identifier = user;

        self
    }
    /// ### Add a Role
    /// #### Example
    /// ```
    /// use schemeguardian::{AuthEngine, ImmutableRole};
    ///
    /// AuthEngine::new()
    ///     .role(ImmutableRole::Admin);
    /// ```
    pub fn role(mut self, value: ImmutableRole) -> Self {
        self.role = value;

        self
    }
    /// ### Add a Lease
    /// #### Example
    /// ```
    /// use schemeguardian::{AuthEngine, Lease};
    /// use std::time::{SystemTime, Duration};
    /// use tai64::{TAI64N};
    /// AuthEngine::new()
    ///     .lease(Lease::DateExpiryTAI(TAI64N::from_system_time(&(SystemTime::now() + Duration::from_secs(2)))));
    /// ```
    pub fn lease(mut self, lease: Lease) -> Self {
        self.lease = lease;

        self
    }
    /// ### Adds a random 64bit CSRNG phrase and builds the struct
    /// #### Example
    /// ```
    /// use schemeguardian::AuthEngine;
    /// AuthEngine::new()
    ///     .build();
    /// ```
    pub fn build(mut self) -> Self {
        self.random_key = SecretString::new(crate::random64alpha().expose_secret().to_owned());

        self
    }
    /// ### Inserts the secrets into the Key-Value Store
    /// #### Example
    /// ```
    /// use schemeguardian::AuthEngine;
    /// AuthEngine::new()
    ///     .build()
    ///     .insert();
    /// ```
    pub fn insert(self) -> Result<DbOps, SGError> {
        let not_encoded =
            self.identifier.expose_secret().to_owned() + ":::" + self.random_key.expose_secret();
        dbg!(not_encoded);

        crate::SecretStorage::new()
            .identifier(self.identifier.clone())
            .data(bincode::serialize(&self)?)
            .insert()
    }
    /// ### Shows the random 64bit CSRNG key
    /// #### Example
    /// ```
    /// use schemeguardian::AuthEngine;
    /// AuthEngine::new()
    ///     .show_random();
    /// ```
    pub fn show_random(self) -> Result<SecretString, SGError> {
        Ok(bincode::deserialize::<AuthEngine>(
            &crate::SecretStorage::new()
                .get(&SecretString::new("REDACTED".to_owned()))?
                .1,
        )?
        .random_key)
    }
    /// ### Shows value for ImmutableRole
    /// #### Example
    /// ```
    /// use schemeguardian::AuthEngine;
    /// AuthEngine::new()
    ///     .show_role();
    /// ```
    pub fn show_role(self) -> Result<ImmutableRole, SGError> {
        Ok(bincode::deserialize::<AuthEngine>(
            &crate::SecretStorage::new()
                .get(&SecretString::new("REDACTED".to_owned()))?
                .1,
        )?
        .role)
    }
    /// ## Authenticate an existing token
    /// Currently returns:
    ///     `custom_codes::AccessStatus::Expired` for an secret that has reached end of life
    ///     `custom_codes::AccessStatus::Granted` for a secret that is live and RAC is authenticated
    ///     `custom_codes::AccessStatus::RejectedRAC` for a secret that is live but the RAC is not authentic
    ///     `custom_codes::AccessStatus::Rejected` for a secret that cannot be authenticated
    /// #### Example
    /// ```no_run
    /// use schemeguardian::AuthEngine;
    /// use redactedsecret::SecretString;
    /// use serde::{Serialize, Deserialize};
    /// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    /// AuthEngine::new()
    ///     .authenticate(SecretString::new("Foo".to_owned()));
    /// ```
    pub fn authenticate(
        &self,
        user_random: SecretString,
    ) -> Result<(AccessStatus, Payload), SGError> {
        match crate::SecretStorage::new().get(&self.identifier)? {
            (DbOps::KeyNotFound, _) => Ok((AccessStatus::Denied, Default::default())),
            (DbOps::KeyFound, values) => {
                let data = bincode::deserialize::<AuthEngine>(&values)?;

                if self.identifier != data.identifier {
                    Ok((AccessStatus::Denied, Default::default()))
                } else if data.lease
                    <= Lease::DateExpiryTAI(TAI64N::from_system_time(&SystemTime::now()))
                {
                    Ok((AccessStatus::Expired, Default::default()))
                } else if data.random_key != user_random {
                    Ok((AccessStatus::RejectedRAC, Default::default()))
                } else if self.role != data.role {
                    Ok((AccessStatus::Denied, Default::default()))
                } else {
                    Ok((AccessStatus::Granted, (data.identifier, data.role)))
                }
            }
            _ => Ok((AccessStatus::Denied, Default::default())),
        }
    }
}

/// ### Struct structure
/// ```
/// use redactedsecret::SecretString;
/// use serde::{Serialize, Deserialize};
/// use schemeguardian::{GenericRole, Lease};
///
/// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
/// enum Custom {
///     ExecutiveBoard,
/// }
///
/// #[derive(Debug, Serialize, Deserialize)]
/// pub struct GenericAuthEngine<R> {
///     identifier: SecretString,
///     role: GenericRole<R>,
///     target: Option<SecretString>,
///     lease: Lease,
///     random_key: SecretString,
/// }
/// ```
/// #### Example
/// ```
/// use schemeguardian::{GenericAuthEngine, GenericRole, Lease};
/// use redactedsecret::SecretString;
/// use std::time::{SystemTime, Duration};
/// use tai64::{TAI64N};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
/// enum Custom {
///     ExecutiveBoard,
/// }
///
/// GenericAuthEngine::<Custom>::new()
///     .identifier(SecretString::new("Foo".to_owned()))
///     .role(GenericRole::CustomRole(Custom::ExecutiveBoard))
///     .target(SecretString::new("IT-Diploma".to_owned()))
///     .lease(Lease::DateExpiryTAI(TAI64N::from_system_time(&(SystemTime::now() + Duration::from_secs(2)))))
///     .build();
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct GenericAuthEngine<R> {
    identifier: SecretString,
    role: GenericRole<R>,
    target: Option<SecretString>,
    lease: Lease,
    random_key: SecretString,
}
/// #### Usage
/// ```
/// use schemeguardian::GenericAuthEngine;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
/// enum Custom {
///     ExecutiveBoard,
/// }
///
/// GenericAuthEngine::<Custom>::new();
/// ```
impl<R> GenericAuthEngine<R>
where
    R: serde::Serialize + serde::de::DeserializeOwned + std::cmp::PartialEq + std::fmt::Debug,
{
    /// ### Initialize a new GenericAuthEngine
    /// #### Example
    /// ```
    /// use schemeguardian::GenericAuthEngine;
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    /// GenericAuthEngine::<Custom>::new();
    /// ```
    pub fn new() -> Self {
        Self {
            identifier: SecretString::default(),
            role: GenericRole::Unspecified,
            target: Default::default(),
            lease: Default::default(),
            random_key: SecretString::default(),
        }
    }
    /// ### Add an identifier
    /// #### Example
    /// ```
    /// use schemeguardian::GenericAuthEngine;
    /// use serde::{Serialize, Deserialize};
    /// use redactedsecret::SecretString;
    ///
    /// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    /// GenericAuthEngine::<Custom>::new()
    ///     .identifier(SecretString::new("Foo".to_owned()));
    /// ```
    pub fn identifier(mut self, user: SecretString) -> Self {
        self.identifier = user;

        self
    }
    /// ### Add a Role
    /// #### Example
    /// ```
    /// use schemeguardian::{GenericAuthEngine, GenericRole};
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    ///
    /// GenericAuthEngine::<Custom>::new()
    ///     .role(GenericRole::CustomRole(Custom::ExecutiveBoard));
    /// ```
    pub fn role(mut self, value: GenericRole<R>) -> Self {
        self.role = value;

        self
    }
    /// ### Add a Target
    /// #### Example
    /// ```
    /// use schemeguardian::{GenericAuthEngine, GenericRole};
    /// use serde::{Serialize, Deserialize};
    /// use redactedsecret::SecretString;
    ///
    /// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    /// GenericAuthEngine::<Custom>::new()
    ///     .target(Some(SecretString::new("Foo".to_owned())));
    /// ```
    pub fn target(mut self, value: Option<SecretString>) -> Self {
        self.target = value;

        self
    }
    /// ### Add a Lease
    /// #### Example
    /// ```
    /// use schemeguardian::{GenericAuthEngine, Lease};
    /// use serde::{Serialize, Deserialize};
    /// use std::time::{SystemTime, Duration};
    /// use tai64::{TAI64N};
    ///
    /// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    /// GenericAuthEngine::<Custom>::new()
    ///     .lease(Lease::DateExpiryTAI(TAI64N::from_system_time(&(SystemTime::now() + Duration::from_secs(2)))));
    /// ```
    pub fn lease(mut self, lease: Lease) -> Self {
        self.lease = lease;

        self
    }
    /// ### Adds a random 64bit CSRNG phrase and builds the struct
    /// #### Example
    /// ```
    /// use schemeguardian::GenericAuthEngine;
    /// use serde::{Serialize, Deserialize};
    /// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    /// GenericAuthEngine::<Custom>::new()
    ///     .build();
    /// ```
    pub fn build(mut self) -> Self {
        self.random_key = SecretString::new(crate::random64alpha().expose_secret().to_owned());

        self
    }
    /// ### Inserts the secrets into the Key-Value Store
    /// #### Example
    /// ```
    /// use schemeguardian::AuthEngine;
    /// AuthEngine::new()
    ///     .build()
    ///     .insert();
    /// ```
    pub fn insert(self) -> Result<DbOps, SGError> {
        let not_encoded =
            self.identifier.expose_secret().to_owned() + ":::" + self.random_key.expose_secret();
        dbg!(not_encoded);

        crate::SecretStorage::new()
            .identifier(self.identifier.clone())
            .data(bincode::serialize(&self)?)
            .insert()
    }
    /// ### Shows the random 64bit CSRNG key
    /// #### Example
    /// ```
    /// use schemeguardian::GenericAuthEngine;
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    /// GenericAuthEngine::<Custom>::new()
    ///     .rac();
    /// ```
    pub fn rac(self) -> Result<SecretString, SGError> {

        Ok(self.random_key)
    }
    /// ### Shows value for GenericRole<R>
    /// #### Example
    /// ```
    /// use schemeguardian::GenericAuthEngine;
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    /// GenericAuthEngine::<Custom>::new()
    ///     .show_role();
    /// ```
    pub fn show_role(self) -> Result<GenericRole<R>, SGError> {
        Ok(bincode::deserialize::<GenericAuthEngine<R>>(
            &crate::SecretStorage::new()
                .get(&SecretString::new("REDACTED".to_owned()))?
                .1,
        )?
        .role)
    }
    /// ### Shows value for Target for GenericRole<R> struct
    /// #### Example
    /// ```
    /// use schemeguardian::GenericAuthEngine;
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    /// GenericAuthEngine::<Custom>::new()
    ///     .show_target();
    /// ```
    pub fn show_target(self) -> Result<Option<SecretString>, SGError> {
        Ok(bincode::deserialize::<GenericAuthEngine<R>>(
            &crate::SecretStorage::new()
                .get(&SecretString::new("REDACTED".to_owned()))?
                .1,
        )?
        .target)
    }
    /// ## Authenticate an existing token
    /// Currently returns:
    ///     `custom_codes::AccessStatus::Expired` for an secret that has reached end of life
    ///     `custom_codes::AccessStatus::Granted` for a secret that is live and RAC is authenticated
    ///     `custom_codes::AccessStatus::RejectedRAC` for a secret that is live but the RAC is not authentic
    ///     `custom_codes::AccessStatus::Rejected` for a secret that cannot be authenticated
    /// #### Example
    /// ```no_run
    /// use schemeguardian::GenericAuthEngine;
    /// use serde::{Serialize, Deserialize};
    /// use redactedsecret::SecretString;
    ///
    /// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    /// enum Custom {
    ///     ExecutiveBoard,
    /// }
    /// GenericAuthEngine::<Custom>::new()
    ///     .authenticate(SecretString::new("Foo".to_owned()));
    /// ```
    pub fn authenticate(
        &self,
        user_random: SecretString,
    ) -> Result<(AccessStatus, GenericPayload<R>), SGError> {
        match crate::SecretStorage::new().get(&self.identifier)? {
            (DbOps::KeyNotFound, _) => Ok((AccessStatus::Denied, Default::default())),
            (DbOps::KeyFound, values) => {
                let data = bincode::deserialize::<GenericAuthEngine<R>>(&values)?;

                if self.identifier != data.identifier {
                    Ok((AccessStatus::Denied, Default::default()))
                } else if data.lease
                    <= Lease::DateExpiryTAI(TAI64N::from_system_time(&SystemTime::now()))
                {
                    Ok((AccessStatus::Expired, Default::default()))
                } else if data.random_key != user_random {
                    Ok((AccessStatus::RejectedRAC, Default::default()))
                } else if self.role != data.role {
                    Ok((AccessStatus::Denied, Default::default()))
                } else {
                    Ok((
                        AccessStatus::Granted,
                        (data.identifier, data.role, data.target),
                    ))
                }
            }
            _ => Ok((AccessStatus::Denied, Default::default())),
        }
    }
}
