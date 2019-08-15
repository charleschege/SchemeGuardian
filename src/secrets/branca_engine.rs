use secrecy::{Secret, ExposeSecret};
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use crate::SG_BRANCA_KEY;
use crate::SGError;
use branca::Branca;
use std::iter;
use std::convert::TryInto;

    /// Generate a random branca token of size u64 Alphanumeric
pub fn branca_random() -> Result<Secret<String>, SGError>{
    let key = &SG_BRANCA_KEY;
    let token = Branca::new(key.expose_secret().branca.as_bytes())?;
    let mut rng = thread_rng();
    let my_secret = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(64)
        .collect::<String>()
        .to_lowercase();
    
    Ok(Secret::new(token.encode(&my_secret)?))
}

    /// Generate a branca token from a Secret<string>
pub fn branca_encode(value: Secret<String>) -> Result<Secret<String>, SGError> {
    let key = &SG_BRANCA_KEY;
    let token = Branca::new(key.expose_secret().branca.as_bytes())?;
        
    Ok(Secret::new(token.encode(&value.expose_secret())?))
}

    /// !DONE [TODO: use chrono duration to give a custom ttl]
    /// !DONE use `chrono::Duration::hours(custom_time).num_milliseconds().try_into()?`
    /// Decode a branca token from an encoded token
pub fn branca_decode(value: Secret<String>) -> Result<Secret<String>, SGError> {
    let key = &SG_BRANCA_KEY;
    let token = Branca::new(key.expose_secret().branca.as_bytes())?;
        
    Ok(Secret::new(token.decode(&value.expose_secret(), chrono::Duration::milliseconds(0).num_milliseconds().try_into()?)?))
}