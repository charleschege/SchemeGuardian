use std::{
    collections::BTreeMap,
    path::Path,
};
use async_lock::Lock;
use turingdb::TuringEngine;
use async_dup::Arc;
use custom_codes::DbOps;
use anyhow::Result;
use serde::Serialize;

use crate::{TimeStamp, GC_REGISTRY, GC_STORAGE, GcExec};

#[derive(Debug)]
pub struct GcRegistry<'gc>(BTreeMap<TimeStamp, Lock<GcData<'gc>>>);

impl<'gc> Default for GcRegistry<'gc> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<'gc> GcRegistry<'gc> {
    // TODO This double remove should run as a `sled::tree::Transaction`
    pub async fn run(&mut self, storage: Arc<&TuringEngine>, value: (TimeStamp, Lock<GcData<'gc>>)) -> Result<DbOps> {
        let gc_registry = Path::new(GC_REGISTRY);
        let gc_storage = Path::new(GC_STORAGE);

        let token_db = value.1.lock().await.db;
        let token_storage = value.1.lock().await.document;
        let token_key = value.1.lock().await.key;
        let gc_storage_key = value.1.lock().await.key;
        
        storage.field_remove(token_db, token_storage, token_key).await?;
        storage.field_remove(gc_registry, gc_storage, gc_storage_key).await?;
        self.0.remove(&value.0);

        Ok(DbOps::FieldDropped)
    }

    pub async fn clock(&mut self, storage: Arc<&TuringEngine>) -> Result<GcExec> {
        let value = self.0.iter().take(1).fold(
            (TimeStamp::now(), Lock::new(GcData::default())), 
            |_, val|
            (val.0.to_owned(), val.1.to_owned())
        );

        if value.0 <= TimeStamp::now() {
            let gcop = self.run(storage, value).await?;

            if gcop == DbOps::FieldDropped {
                Ok(GcExec::Hit)
            }else {
                Ok(GcExec::MalformedOperation)
            }
        }else {
            Ok(GcExec::Miss)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GcData<'gc> {
    db: &'gc Path,
    document: &'gc Path,
    key: &'gc [u8]
}

impl<'gc> Default for GcData<'gc> {
    fn default() -> Self {
        Self {
            db: Path::new(""),
            document: Path::new(""),
            key: Default::default(),
        }
    }
}

impl<'gc> GcData<'gc> {
    pub fn new() -> GcData<'gc> {
        GcData::default()
    }

    pub fn db(&mut self, value: &'gc str) -> &mut GcData<'gc> {
        self.db = Path::new(value);

        self
    }

    pub fn document(&mut self, value: &'gc str) -> &mut GcData<'gc> {
        self.document = Path::new(value);

        self
    }

    pub fn key(&mut self, value: &'gc [u8]) -> &mut GcData<'gc> {
        self.key = value;

        self
    }

    pub fn build(&mut self) -> &GcData<'gc> {

        self
    }
}
