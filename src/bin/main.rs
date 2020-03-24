use anyhow::Result;
use secrecy::{SecretString, Secret, ExposeSecret};
use tai64::TAI64N;
use timelite::LiteDuration;

use schemeguardian::{Role, TokenContents, TokenStorage, Lease};

#[async_std::main]
async fn main() -> Result<()> {
    let config = schemeguardian::LoadConfiguration::load().await;
    let storage = TokenStorage::init().await?;

    let default_key = match config.get("default_key") {
        Some(key) => key,
        None => {
            eprintln!("THERE IS NO DEFAULT KEY GIVEN");
            std::process::exit(1)
        },
    };

    let aead_key_get = match config.get("aead_key") {
        Some(key) => key,
        None => default_key,
    };

    let now = TAI64N::now();
    let future =  now + std::time::Duration::from_secs(LiteDuration::minutes(10));

    let mut contents = TokenContents::new().await;
    contents
        .username(SecretString::new("x43".into())).await
        .lease(Secret::new(Lease::DateExpiryTAI(future))).await
        .role(Secret::new(Role::SuperUser)).await;

    dbg!(&contents);

    /*match schemeguardian::Token::new().await
        .key(aead_key_get.to_owned()).await
        .contents(contents).await
        .encrypt().await {
            Ok(inner) => {
                dbg!(&inner.0.expose_secret());
                storage.set(inner.0, inner.1).await?;
            },
            Err(e) => { dbg!(e); }
        }*/

    let cipher = "0Myor27f714sczWC1KF5JyGs5WBh_EXzhHN2AlCn1EDrBNhEGn6RbpqQPlBQY0yJp1gOeEW2Y6yV31ZHLjKLW4tcOMgE8i6GrFP4Q2T4hdOrPerKSoeh6WwIc2YXFofa1S7q";

    dbg!(&storage);

    if let Some(token_contents) = storage.get(SecretString::new(cipher.into())).await {
        dbg!(token_contents.authenticate(Secret::new(Role::SuperUser)).await);
    }else {
        dbg!("NO KEY FOUND");
    }

    /*match schemeguardian::Token::new().await
        .key(aead_key_get.to_owned()).await
        .decrypt(SecretString::new(cipher.into()), SecretString::new("gvw22b2hsaxxecfqzdtexthi".into())).await {
            Ok(inner) => {
                dbg!(inner.authenticate(
                    Secret::new(Role::SuperUser),
                ).await);
            },
            Err(e) => { dbg!(e); }
        }*/

    Ok(())
}