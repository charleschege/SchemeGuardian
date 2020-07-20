use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use secrecy::SecretString;
use std::iter;

/// Generate a random 512 byte(4096bit) Alphanumeric key to be stored in a Secret<String>
pub async fn random512alpha() -> SecretString {
    let mut rng = thread_rng();

    SecretString::new(
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(512)
            .collect::<String>()
            .to_lowercase(),
    )
}

/// Generate a random 256 byte(2048bit) Alphanumeric key to be stored in a Secret<String>
pub async fn random256alpha() -> SecretString {
    let mut rng = thread_rng();

    SecretString::new(
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(256)
            .collect::<String>()
            .to_lowercase(),
    )
}

/// Generate a random 128 byte(1024bit) Alphanumeric key to be stored in a Secret<String>
pub async fn random128alpha() -> SecretString {
    let mut rng = thread_rng();

    SecretString::new(
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(128)
            .collect::<String>()
            .to_lowercase(),
    )
}

/// Generate a random 64 byte(512bit) Alphanumeric key to be stored in a Secret<String>
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

/// Generate a random 32 byte(256bit) Alphanumeric key to be stored in a Secret<String>
pub async fn random32alpha() -> SecretString {
    let mut rng = thread_rng();

    SecretString::new(
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(32)
            .collect::<String>()
            .to_lowercase(),
    )
}

/// Generate a random 24 byte(192bit) Alphanumeric key to be stored in a Secret<String>
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