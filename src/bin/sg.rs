use serde_derive::{Serialize, Deserialize};
use schemeguardian::{SGError, Lease, Role};
use secrecy::{SecretString, ExposeSecret};
use schemeguardian::secrets::SimpleAuthStorage;

fn main() -> Result<(), SGError>{   

    /*if let Some(data) = SimpleAuthStorage::<CustomUser>::new()
        .get(SecretString::new("x43".to_owned()))?.1{
            println!("{:?}", data);
    };*/

    /*println!("{:?}", {
        let data = SimpleAuthStorage::<CustomUser>::new()
            .user(SecretString::new("x43".to_owned()))
            .role(Role::CustomRole(CustomUser::InstitutionAdmin))
            .target(Some(SecretString::new("ICT".to_owned())))
            .lease(Lease::DateExpiry(chrono::Utc::now() + chrono::Duration::days(7)))
            .build()
            .insert()?.1;
        let f = data.expose_secret().clone(); f
    });*/

    #[derive(Debug, Serialize, Deserialize)]
    enum CustomUser {
        InstitutionAdmin,
        InstitutionSubAdmin,
        Lecturer,
        Accounts,
    }

    
    let data = SimpleAuthStorage::<CustomUser>::new()
        .authenticate(SecretString::new("x43:::vs9mdrzyf037jzjwxlhyfoekobgfioydahw65vvhfcmzktqwbxsafl1d22n0frlb".to_owned()))?;

    match data.1 {
        Some(val) => {
            println!("[{:?}] - [USER]: {:?}", data.0, val.0.expose_secret());
            println!("[{:?}] - [ROLE]: {:?}", data.0, val.1);
            if let Some(inner) = val.2 { println!("[{:?}] - [TARGET]: {:?}", data.0, inner.expose_secret().as_str()) } else { println!("[{:?}] - [TARGET]:", Role::<CustomUser>::Unspecified) };
            println!("[{:?}] - [LEASE]: {:?}", data.0, val.3);
            println!("[{:?}] - [KEY]: {:?}", data.0, val.4.expose_secret());
        },
        None => println!("[{:?}] - THIS IS A DESERT!!!", data.0),
    }
    
    Ok(())
}