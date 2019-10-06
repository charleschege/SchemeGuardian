use serde_derive::{Serialize, Deserialize};
use schemeguardian::{SGError, Role};
use redactedsecret::{SecretString, ExposeSecret};
use schemeguardian::secrets::SimpleAuthStorage;

#[derive(Debug, Serialize, Deserialize)]
enum CustomUser {
    InstitutionAdmin,
    InstitutionSubAdmin,
    Lecturer,
    Accounts,
}

#[test]
fn fetch() -> Result<(), SGError> {
    
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