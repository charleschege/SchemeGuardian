#![deny(unsafe_code)]
//#![deny(missing_docs)]
//#![deny(missing_doc_code_examples)]

//! # SchemeGuardian
//! Secrets Authrorization, Authentication, Verification and Encryption Manager with Key-Value Storage
//!

/// Path errors are handled by the database so no errors are defined in this crate
///
///

/// Re-export as public accessible APIs from crate
mod passphrase_engine;
/// Passhrase, PIN, Password authentication module
pub use passphrase_engine::Passphrase;
/// Module that generates a random alphanumeric lowercase 64bit phrase
mod csprng;
/// Contains global types and methods
pub mod global;
pub use global::*;
pub use csprng::*;
//mod passphrase;
/// Passphrase, PIN or password authentication module re-export
//pub use passphrase::Passphrase;
mod tokens;
pub use tokens::*;
mod engine;

mod config;
pub (crate) use config::*;

mod storage;
pub use storage::*;

mod garbage_collector;
pub use garbage_collector::*;

// Secrets engine handles Deny, Authenticate, Authorize, Reject, Revoke (DAARR) for all secrets
// TODO Add jemalloc as the allocator

fn main() {
    
}