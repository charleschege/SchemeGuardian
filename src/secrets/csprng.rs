use std::iter;
use secrecy::Secret;
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};

    /// Generate a random u64 Alphanumeric key to be stored in a Secret<String>
pub fn random64alpha() -> Secret<String>{
    let mut rng = thread_rng();
    
    Secret::new(
        iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(64)
        .collect::<String>()
        .to_lowercase()
    )
}