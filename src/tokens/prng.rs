use crate::global::{
    TaiTimestamp,
    Lease,
    Role,
    SgStatusCode,
    Ping,
    TOKEN_SESSION_DOCUMENT,
    TOKEN_DB_PATH,
    Identifier,
};

use secrecy::{Secret, ExposeSecret};
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
    fn generate_token() -> Self {
        
        Self::default()
    }
    /// Create a token
    async fn issue(self, db_engine: &TuringEngine) -> Result<Self> {
        let data = bincode::serialize::<Self>(&self)?;

        TuringEngine::field_insert(db_engine, 
            TOKEN_DB_PATH.as_ref(),
            TOKEN_SESSION_DOCUMENT.as_ref(),
            blake3::hash(self.identifier.expose_secret().0.as_bytes()).as_bytes(),
            &data,
        ).await?;

        Ok(self)
    }

    async fn authenticate(key: &str, db_engine: &TuringEngine) -> Result<SgStatusCode> {
        match TuringEngine::field_get(db_engine, 
            TOKEN_DB_PATH.as_ref(), 
        TOKEN_SESSION_DOCUMENT.as_ref(), 
        blake3::hash(key.as_bytes()).as_bytes()
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