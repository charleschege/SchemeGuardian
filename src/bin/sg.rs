use schemeguardian::secrets::BrancaEngine;
use schemeguardian::SGError;
use secrecy::{Secret, ExposeSecret};
use serde_derive::{Serialize, Deserialize};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize)]
#[zeroize(no_drop)]
struct UserAttributes {
    role: Role,
}

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize)]
#[zeroize(no_drop)]
#[allow(unused_variables)]
enum Role {
    Student(String),
    Admin,
    Accounts,
    Lecturer,
    SubAdmin,
}

    // Secondary index in a sled database

fn main() -> Result<(), SGError>{    

    let cookie_db = "./SchemeGuardianDB/SG_branca";
    
    let user_attributes = UserAttributes { role: Role::Student("ICT".to_owned()) };

    let op = BrancaEngine::new()
        .bearer(Secret::new("x43".to_owned()))
        .expiry(chrono::Duration::weeks(1))
        .attributes(Some(user_attributes))
        .insert(cookie_db)?;
    
    println!("{:?}-{:?}", op.0.expose_secret(), op.1);

    //dbg!(op);

    Ok(())
}

/*
BrancaEngine {
    secret: BrancaPayload {
        attr: Some(
            UserAttributes {
                username: "x43",
                role: Student(
                    "ICT",
                ),
            },
        ),
    },
    lease: DateExpiry(
        2019-08-14T11:32:03.574414306Z,
    ),
}

*/