use serde_derive::Deserialize;
use std::fs;
use chrono::prelude::*;
use either::{Either, Left, Right};

#[derive(Debug, Deserialize)]
struct SGdatetime {
    timezone: String,
}

#[derive(Debug, Deserialize)]
struct SGConfig {
    datetime: SGdatetime,
}

    /// Extract timezone from `SchemeGuardian.toml` file
pub fn timezone() -> String {
    let fs = fs::read_to_string("SchemeGuardian.toml").unwrap();

    let data: SGConfig = toml::from_str(&fs).unwrap();

    data.datetime.timezone
}


    /// Easy date builder
#[derive(Debug)]
pub struct SGDateTime {
    date_time: DateTime<Utc>,
}

impl SGDateTime {
        /// New date/time with fixed offset of zero seconds east
    pub fn utc(duration: chrono::Duration) -> String {
        (Utc::now() + duration).to_rfc3339()
    }
        /// Local date/time builder with timezone
    pub fn local(timezone: &str) -> Either<DateTime<FixedOffset>, DateTime<Utc>> {
        match timezone {
            "Africa/Nairobi" => Left(Utc::now().with_timezone(&FixedOffset::east(3 * 3600))),
            _ => Right(Utc::now()),
        }
    }
}