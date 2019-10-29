/*use redactedsecret::{SecretString, ExposeSecret};
use schemeguardian::{AuthEngine, ImmutableRole, Lease, SGError, SecretStorage, DestructureToken};
use std::time::{Duration, SystemTime};
use tai64::TAI64N;*/

use redactedsecret::{ExposeSecret, SecretString};
use schemeguardian::{DestructureToken, SGError};

fn main() -> Result<(), SGError> {
    /*dbg!(AuthEngine::new()
            .identifier(SecretString::new("REDACTED".to_owned()))
            .role(ImmutableRole::Admin)
            .lease(Lease::DateExpiryTAI(TAI64N::from_system_time(&(SystemTime::now() + Duration::from_secs(90)))))
            .build()
            .insert()
    )?;*/

    /*dbg!(AuthEngine::new()
            .identifier(SecretString::new("REDACTED".to_owned()))
            .role(ImmutableRole::Admin)
            .authenticate(SecretString::new("c9qt2gy4ul3hgho0k1uvo7hv3sxh3wrzz5xszbpak7sfnuoapg5dghq2glvmyfld".to_owned()))
    )?;*/

    /*dbg!(AuthEngine::new()
            .identifier(SecretString::new("REDACTED".to_owned()))
            .show_random()?.expose_secret()
    );*/

    dbg!(DestructureToken::new()
        .token(SecretString::new(
            "REDACTED:::c9qt2gy4ul3hgho0k1uvo7hv3sxh3wrzz5xszbpak7sfnuoapg5dghq2glvmyfld"
                .to_owned()
        ))
        .build());

    dbg!(schemeguardian::branca_encode(SecretString::new("1234".to_owned()))?.expose_secret());
    dbg!(schemeguardian::branca_decode(SecretString::new(
        "MvfUt0V4v0YYEOCnNBlahqPq699z6D5cPYYLgfqqVPJT1urdrGr4WmvwCoEXOYjvsM".to_owned()
    ))?
    .expose_secret());


use schemeguardian::{GenericAuthEngine, GenericRole, Lease};
use std::time::{SystemTime, Duration};
use tai64::{TAI64N};
use serde::{Serialize, Deserialize};
///
#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum Custom {
    ExecutiveBoard,
}

    GenericAuthEngine::<Custom>::new()
        .identifier(SecretString::new("Foo".to_owned()))
        .role(GenericRole::CustomRole(Custom::ExecutiveBoard))
        .target(SecretString::new("IT-Diploma".to_owned()))
        .lease(Lease::DateExpiryTAI(TAI64N::from_system_time(&(SystemTime::now() + Duration::from_secs(2)))))
        .build();

    Ok(())
}
