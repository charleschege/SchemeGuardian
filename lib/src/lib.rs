#![deny(unsafe_code)]
//#![deny(missing_docs)]
//#![deny(missing_doc_code_examples)]

//! # SchemeGuardian
//! Secrets Authrorization, Authentication, Verification and Encryption Manager with Key-Value Storage
//!

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
pub use engine::{LoadConfiguration};
mod config;
pub (crate) use config::*;
mod errors;
pub (crate) use errors::*;
mod storage;
pub use storage::TokenStorage;

// Secrets engine handles Deny, Authenticate, Authorize, Reject, Revoke (DAARR) for all secrets
// TODO Add jemalloc as the allocator
