use schemeguardian::SGError;
use schemeguardian::secrets::auth_storage::SimpleAuthStorage;




    // Secondary index in a sled database

fn main() -> Result<(), SGError>{    
    /*
    let op = AuthEngine::new()
        .bearer(Secret::new("x43".to_owned()))
        .role(Role::CustomRole("Student".to_owned()))
        .expiry(chrono::Duration::weeks(1))
        .target(Target::CustomTarget("ICT".to_owned()))
        .insert()?;
    
    println!("[{:?}]\n{:?}----{:?}", op.0, &op.1.expose_secret(), op.2);
    println!("[BRANCA ENCODED]\n{:?}", branca_encode(op.1)?.expose_secret());*/

    //let op = AuthEngine::new()
    //.authenticate(Secret::new("x43:::hgu9ys5if3gcy30uk9mwmbckzq6tk9pauh8she6ov75ju5q0pdkuozzatomwyrsx".to_owned()))?;
    //.rm(Secret::new("x43:::hgu9ys5if3gcy30uk9mwmbckzq6tk9pauh8she6ov75ju5q0pdkuozzatomwyrsx".to_owned()))?;
    //.list_keys()?;
/*
    if let Some(inner) = op.1 {
        println!("[ACCESS]:<{:?}>\n  - Role: {:?}\n  - Target: {:?}", op.0, inner.0, inner.1);
    }else {
        println!("[ACCESS]:<{:?}> ", op.0)
    }
    */

    println!("{}", SimpleAuthStorage::<String>::new().key());
    
    Ok(())
}