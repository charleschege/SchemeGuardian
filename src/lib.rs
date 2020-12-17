#![deny(unsafe_code)]
//#![deny(missing_docs)]
//#![deny(missing_doc_code_examples)]

//! # SchemeGuardian
//! Secrets Authrorization, Authentication, Verification and Encryption Manager with Key-Value Storage
//!

mod tokens;
mod global;
mod storage;

pub use tokens::*;
pub use global::*;
pub use storage::*;

// Secrets engine handles Deny, Authenticate, Authorize, Reject, Revoke (DAARR) for all secrets
// TODO Add jemalloc as the allocator