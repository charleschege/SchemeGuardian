use std::iter;
use crate::SGSecret;
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};

    /// Generate a random u64 Alphanumeric key to be stored in a Secret<String>
pub fn random64alpha() -> SGSecret{
    let mut rng = thread_rng();
    
    SGSecret(
        iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(64)
        .collect::<String>()
        .to_lowercase()
    )
}