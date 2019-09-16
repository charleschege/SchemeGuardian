use secrecy::ExposeSecret;
use schemeguardian::{SGSecret, Lease, SGError};
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

    println!("{:?}", {
        let data = SimpleAuthStorage::new()
            .user(SGSecret("x43".to_owned()))
            .target(SGSecret("ICT".to_owned()))
            .lease(Lease::DateExpiry(chrono::Utc::now() + chrono::Duration::days(7)))
            .build()
            .insert()?.1;
        let f = data.expose_secret().clone(); f
    });

    // x43:::xqktmxali4ajqfgw6zbv4zwem7amlnxqchgdzj8jyfelmsvizmssmveqrktal5fq:::ICT
    println!("{:?}", SimpleAuthStorage::new()
        .authenticate(SGSecret("x43:::xqktmxali4ajqfgw6zbv4zwem7amlnxqchgdzj8jyfelmsvizmssmveqrktal5fq:::ICT".to_owned()))?);
    
    Ok(())
}