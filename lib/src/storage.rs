use anyhow::Result;
use custom_codes::DbOps;
use secrecy::{SecretString, ExposeSecret};
use crate::{DEFAULT_KV_STORE_PATH, TokenContents};
use std::collections::HashMap;
use async_std::{
    sync::{Mutex, Arc},
};

#[derive(Debug)]
pub struct TokenStorage {
    db: Arc<Mutex<HashMap<String, TokenContents>>>,
}

impl TokenStorage {
    pub async fn init() -> Result<TokenStorage> {
        let db = sled::Config::default()
            .create_new(false)
            .path(DEFAULT_KV_STORE_PATH)
            .open()?;

        let mut memdb: HashMap<String, TokenContents> = HashMap::new();

        for data in db.into_iter() {
            let (key, value) = data?; // TODO Make this more efficient

            let key_to_str = String::from_utf8(key.to_vec())?;

            memdb.insert(key_to_str, bincode::deserialize::<TokenContents>(&value.to_vec())?);
        }

        Ok(Self { db: Arc::new(Mutex::new(memdb)) })
    }

    pub async fn set(&self, key: SecretString, value: TokenContents) -> Result<DbOps> {
        let db = sled::Config::default()
            .create_new(false)
            .path(DEFAULT_KV_STORE_PATH)
            .open()?;

        let data_to_bytes = bincode::serialize::<TokenContents>(&value)?;
        
        db.transaction::<_,_, sled::Error>( |db| {
            db.insert(key.expose_secret().as_bytes(), data_to_bytes.to_vec())?;
            Ok(())
        })?;

        self.db.lock().await.insert(key.expose_secret().into(), value);

        Ok(DbOps::FieldInserted)
    }

    pub async fn get(&self, key: SecretString) -> Option<TokenContents> {
        
        match self.db.lock().await.get(key.expose_secret())  {
            Some(value) => {
                let mut data = TokenContents::new().await;
                data.swap(value).await;
                
                Some(data)
            },
            None => None,
        }
    }

    pub async fn remove(&mut self, key: SecretString) -> Result<DbOps> {
        if let Some(_) = self.db.lock().await.get(key.expose_secret()) {
            let db = sled::Config::default()
            .create_new(false)
            .path(DEFAULT_KV_STORE_PATH)
            .open()?;

            db.remove(key.expose_secret().as_bytes())?;

            self.db.lock().await.remove(key.expose_secret());

            Ok(DbOps::FieldDropped)
        }else {
            Ok(DbOps::FieldNotFound)
        }
    }

    pub async fn check(&self, key: SecretString) -> DbOps {

        match self.db.lock().await.get(key.expose_secret()) {
            Some(_) => DbOps::FieldFound,
            None => DbOps::FieldNotFound,
        }
    }

    pub async fn clear(&self) -> Result<DbOps> {
        let db = sled::Config::default()
            .create_new(false)
            .path(DEFAULT_KV_STORE_PATH)
            .open()?;

        db.clear()?;

        self.db.lock().await.clear();

        Ok(DbOps::Empty)
    }
}