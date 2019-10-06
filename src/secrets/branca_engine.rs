use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use branca::Branca;
use std::iter;
use std::convert::TryInto;
use redactedsecret::{ExposeSecret, SecretString};

use crate::SG_SECRET_KEYS;
use crate::SGError;

    /// Generate a random branca token of size u64 Alphanumeric
pub fn branca_random() -> Result<SecretString, SGError>{
    let key = &SG_SECRET_KEYS;
    let token = Branca::new(key.branca.expose_secret().as_bytes())?;
    let mut rng = thread_rng();
    let my_secret = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(64)
        .collect::<String>()
        .to_lowercase();
    
    Ok(SecretString::new(token.encode(&my_secret)?))
}

    /// Generate a branca token from a SecretString
pub fn branca_encode(value: SecretString) -> Result<SecretString, SGError> {
    let key = &SG_SECRET_KEYS;
    let token = Branca::new(key.branca.expose_secret().as_bytes())?;
        
    Ok(SecretString::new(token.encode(&value)?))
}

    /// !DONE [TODO: use chrono duration to give a custom ttl]
    /// !DONE use `chrono::Duration::hours(custom_time).num_milliseconds().try_into()?`
    /// Decode a branca token from an encoded token
pub fn branca_decode(value: SecretString) -> Result<SecretString, SGError> {
    let key = &SG_SECRET_KEYS;
    let token = Branca::new(key.branca.expose_secret().as_bytes())?;
        
    Ok(SecretString::new(token.decode(&value, chrono::Duration::milliseconds(0).num_milliseconds().try_into()?)?))
}