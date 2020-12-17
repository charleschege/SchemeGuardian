use crate::{global::{
    TaiTimestamp,
    Lease,
    Role,
    SgStatusCode,
    Ping,
    TOKEN_SESSION_DOCUMENT,
    TOKEN_DB_PATH,
    Identifier,
}, to_blake3};

use secrecy::{Secret, ExposeSecret, SecretString};
use turingdb::TuringEngine;
use custom_codes::DbOps;
use anyhow::Result;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PrngToken {
    identifier: Secret<Identifier>,
    timestamp: Secret<TaiTimestamp>,
    role: Secret<Role>,
    lease: Secret<Lease>,
    last_active: Secret<TaiTimestamp>,
    ping: Ping,
}

impl Default for PrngToken {
    fn default() -> Self {
        let lease = tai64::TAI64N::now() + std::time::Duration::from_secs(timelite::LiteDuration::hours(24));
        
        Self {
            identifier: Secret::new(Identifier(String::default())),
            timestamp: Secret::new(TaiTimestamp::now()),
            role: Secret::new(Role::User),
            lease: Secret::new(Lease::DateExpiryTAI(lease)),
            last_active: Secret::new(TaiTimestamp::now()),
            ping: Ping::Unreachable,
        }
    }
}

use async_trait::async_trait;
#[async_trait]
impl crate::global::SecurityCheck for PrngToken {
    /// Create a token
    async fn issue(self, db_engine: &TuringEngine) -> Result<SecretString> {
        let data = bincode::serialize::<Self>(&self)?;

        // Take only the `identifier`, `timestamp`, `role` and `lease`
        let mut token_hash = blake3::Hasher::new();
        token_hash.update(self.identifier.expose_secret().0.as_bytes());
        token_hash.update(self.timestamp.expose_secret().get_bytes().expose_secret());
        token_hash.update(&Role::to_header(self.role.expose_secret()));
        token_hash.update(&Lease::to_header(self.lease.expose_secret()));

        let hashed_token = token_hash.finalize();

        TuringEngine::field_insert(db_engine, 
            TOKEN_DB_PATH.as_ref(),
            TOKEN_SESSION_DOCUMENT.as_ref(),
            hashed_token.as_bytes(),
            &data,
        ).await?;


        Ok(SecretString::new(hex::encode(hashed_token.as_bytes())))
    }

    async fn authenticate(key: &str, db_engine: &TuringEngine) -> Result<SgStatusCode> {
        let hashed_token = to_blake3(&SecretString::new(key.into()))?;
        dbg!(&hashed_token);

        match TuringEngine::field_get(db_engine, 
            TOKEN_DB_PATH.as_ref(), 
        TOKEN_SESSION_DOCUMENT.as_ref(), 
        hashed_token.as_bytes(),
        ).await?{
            DbOps::FieldContents(_) => Ok(SgStatusCode::AuthenticToken),
            _ => Ok(SgStatusCode::Rejected)
        }
    }

    async fn authorize(key: &str, db_engine: &TuringEngine) -> Result<SgStatusCode> {
        match TuringEngine::field_get(db_engine, 
            TOKEN_DB_PATH.as_ref(), 
        TOKEN_SESSION_DOCUMENT.as_ref(), 
        blake3::hash(key.as_bytes()).as_bytes()
        ).await?{
            DbOps::FieldContents(_) => Ok(SgStatusCode::AccessGranted),
            _ => Ok(SgStatusCode::AccessDenied)
        }
    }

    async fn revoke(key: &str, db_engine: &TuringEngine) -> Result<SgStatusCode> {
        match TuringEngine::field_remove(db_engine, 
            TOKEN_DB_PATH.as_ref(), 
        TOKEN_SESSION_DOCUMENT.as_ref(), 
        blake3::hash(key.as_bytes()).as_bytes()
        ).await?{
            DbOps::FieldContents(_) => Ok(SgStatusCode::Revoked),
            _ => Ok(SgStatusCode::Rejected)
        }
    }

}