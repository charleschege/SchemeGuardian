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

mod config;
pub (crate) use config::*;

// Secrets engine handles Deny, Authenticate, Authorize, Reject, Revoke (DAARR) for all secrets
// TODO Add jemalloc as the allocator

fn main() {
    use secrecy::{SecretString, Secret, ExposeSecret};
    {
        smol::run(async {
            let mut foo = Blake3Token::new();
            foo.username(SecretString::new("x43".to_owned()));
            foo.role(Secret::new(Role::SuperUser));
            foo.lease(Secret::new(Lease::default()));
    
            dbg!(foo.get_hash().await);

            dbg!(Blake3Token::to_blake3(&SecretString::new("d2c31d5a7cc9dbb254a5a5e2c295845d1e113c640f8783116e4640cb3162c368".into())));
        })
    }
}