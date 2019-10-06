use serde_derive::{Serialize, Deserialize};
use schemeguardian::{SGError, Lease, Role};
use redactedsecret::SecretString;
use schemeguardian::secrets::SimpleAuthStorage;

#[derive(Debug, Serialize, Deserialize)]
enum CustomUser {
    InstitutionAdmin,
    InstitutionSubAdmin,
    Lecturer,
    Accounts,
}

#[test]
fn insertion() -> Result<(), SGError>{   

    println!("{:?}", {
        SimpleAuthStorage::<CustomUser>::new()
            .user(SecretString::new("x43".to_owned()))
            .role(Role::CustomRole(CustomUser::InstitutionAdmin))
            .target(Some(SecretString::new("ICT".to_owned())))
            .lease(Lease::DateExpiry(chrono::Utc::now() + chrono::Duration::days(7)))
            .build()
            .insert()?.1;
    });

    Ok(())
}