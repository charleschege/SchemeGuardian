#![deny(unsafe_code)]
#![deny(missing_docs)]

//! # SchemeGuardian
//! Secrets Authrorization, Authentication, Verification and Encryption Manager with Key-Value Storage
//! 

use lazy_static::*;
use secrecy::Secret;

pub use secrets::secrets_engine;
    /// secrets module
pub mod secrets;

    /// Module containing constants that live for the entirety of the program
pub mod sg_statics;

pub use errors::SGError;
    /// Module containing error handling using failure for the Rust `?` type
pub mod errors;
    

#[macro_export]
lazy_static! {
        /// Create a static for branca token generation secret key for branca tokens
   pub static ref SG_BRANCA_KEY: Secret<sg_statics::SgTomlSecrets> = {
       sg_statics::SGConfig::new().secrets()
   };
}

    // Secrets engine handles Authenticate/Authorize, Create, Read, Update and Delete (ACRUD) for all secrets
    