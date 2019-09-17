use serde_derive::{Serialize, Deserialize};
use schemeguardian::{SGSecret, SGError};
use schemeguardian::secrets::SimpleAuthStorage;

fn main() -> Result<(), SGError>{    
    /*println!("{:?}", SimpleAuthStorage::new()
        .user(SGSecret("x43".to_owned()))
        .target(SGSecret("ICT".to_owned()))
        .lease(Lease::DateExpiry(chrono::Utc::now() + chrono::Duration::days(7)))
        .build()
        .insert()?);*/

    /*if let Some(data) = SimpleAuthStorage::new()
        .get(SGSecret("x43".to_owned()))?.1{
            let d2  = data.3;
            println!("{:?}", d2.0);
        };*/

    /*println!("{:?}", {
        let data = SimpleAuthStorage::<CustomUser>::new()
            .user(SGSecret("x43".to_owned()))
            .target(SGSecret("ICT".to_owned()))
            .lease(Lease::DateExpiry(chrono::Utc::now() + chrono::Duration::days(7)))
            .build()
            .insert()?.1;
        let f = data.expose_secret().clone(); f
    });*/

    #[derive(Debug, Serialize, Deserialize)]
    enum CustomUser {
        Lecturer,
        Accounts,
    }
    println!("{:?}", SimpleAuthStorage::<CustomUser>::new()
        .authenticate(SGSecret("x43:::cgz569mu0mz0etyoffdyckta7mexlgssrct3m0054wgcleiiekuo2xgyvsjhvy6y:::ICT".to_owned()))?);
    
    Ok(())
}