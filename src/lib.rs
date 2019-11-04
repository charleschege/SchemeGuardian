#![deny(unsafe_code)]
#![deny(missing_docs)]
//#![deny(missing_doc_code_examples)]

//! # SchemeGuardian
//! Secrets Authrorization, Authentication, Verification and Encryption Manager with Key-Value Storage
//!

use lazy_static::*;
use redactedsecret::SecretString;

/// Re-export as public accessible APIs from crate
pub use auth_state::{AuthState, TempLock};
pub use global::{GenericPayload, GenericRole, ImmutableRole, Lease, Payload, Target};
mod auth_state;
/// Contains global types and methods
pub mod global;
/// secrets module
pub use secrets::{AuthEngine, DestructureToken, GenericAuthEngine};
mod secrets;
/// Storage types and methods for secrets
pub use storage::SecretStorage;
/// Module that generates a random alphanumeric lowercase 64bit phrase
mod csprng;
/// Module containing constants that live for the entirety of the program
pub mod sg_statics;
mod storage;
pub use csprng::random64alpha;
mod branca_engine;
pub use branca_engine::{branca_decode, branca_encode, branca_random};
mod passphrase;
/// Passphrase, PIN or password authentication module re-export
pub use passphrase::Passphrase;

pub use errors::SGError;
/// Module containing error handling using failure for the Rust `?` type
pub mod errors;

#[macro_export]
lazy_static! {
        /// Create a static for branca token generation secret key for branca tokens
   static ref SG_SECRET_KEYS: SecretString = {
       sg_statics::SGConfig::new().branca_key()
   };
}

// Secrets engine handles Deny, Authenticate, Authorize, Reject, Revoke (DAARR) for all secrets
