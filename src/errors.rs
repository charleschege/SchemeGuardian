use tai64::TAI64N;
use anyhow::Result;
use async_std::{
    fs::OpenOptions,
    prelude::*,
};
use crate::SCHEMEGUARDIAN_LOG_FILE;

#[derive(Debug)]
pub (crate) struct ErrorLogger<'el> {
    timestamp: TAI64N,
    error: anyhow::Error,
    cause: Option<&'el str>,
}

impl<'el> ErrorLogger<'el> {
    pub async fn init(client_error: anyhow::Error) -> ErrorLogger<'el> {
        ErrorLogger {
            timestamp: TAI64N::now(),
            error: client_error,
            cause: Option::default(),
        }
    }

    pub async fn cause(&mut self, cause: &'el str) -> &ErrorLogger<'el> {
        self.cause = Some(cause);

        self
    }

    pub async fn build(&self) -> &ErrorLogger<'el> {
        self
    }

    pub async fn log(&self) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(false)
            .append(true)
            .open(SCHEMEGUARDIAN_LOG_FILE)
            .await?;

        writeln!(&mut file, "{:?}", self).await?;
        
        Ok(())
    }
}