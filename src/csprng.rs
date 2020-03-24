use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use secrecy::SecretString;
use std::iter;

/// Generate a random u64 Alphanumeric key to be stored in a Secret<String>
pub async fn random64alpha() -> SecretString {
    let mut rng = thread_rng();

    SecretString::new(
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(64)
            .collect::<String>()
            .to_lowercase(),
    )
}

/// Generate a random u24 Alphanumeric key to be stored in a Secret<String>
pub async fn random24alpha() -> SecretString {
    let mut rng = thread_rng();

    SecretString::new(
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(24)
            .collect::<String>()
            .to_lowercase(),
    )
}