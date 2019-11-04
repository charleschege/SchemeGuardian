use branca::Branca;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use redactedsecret::{ExposeSecret, SecretString};
use std::iter;

use crate::SGError;
use crate::SG_SECRET_KEYS;

/// Generate a random branca token of size u64 Alphanumeric
pub fn branca_random() -> Result<SecretString, SGError> {
    let key = &SG_SECRET_KEYS;
    let token = Branca::new(key.expose_secret().as_bytes())?;
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
    let token = Branca::new(key.expose_secret().as_bytes())?;

    Ok(SecretString::new(token.encode(&value.expose_secret())?))
}

/// !DONE [TODO: use chrono duration to give a custom ttl]
/// !DONE use `chrono::Duration::hours(custom_time).num_milliseconds().try_into()?`
/// Decode a branca token from an encoded token
pub fn branca_decode(value: SecretString) -> Result<SecretString, SGError> {
    let key = &SG_SECRET_KEYS;
    let token = Branca::new(key.expose_secret().as_bytes())?;

    Ok(SecretString::new(token.decode(&value.expose_secret(), 0)?))
}