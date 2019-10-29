use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use redactedsecret::SecretString;
use std::iter;

/// Generate a random u64 Alphanumeric key to be stored in a Secret<String>
pub fn random64alpha() -> SecretString {
    let mut rng = thread_rng();

    SecretString::new(
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(64)
            .collect::<String>()
            .to_lowercase(),
    )
}
