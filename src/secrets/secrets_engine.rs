use serde_derive::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct SecretsEngine {
    field: String,
}