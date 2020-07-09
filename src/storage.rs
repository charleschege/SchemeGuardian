use std::{
    path::Path,
    collections::HashMap,
};
use async_dup::Arc;
use anyhow::Result;
use custom_codes::DbOps;
use turingdb::TuringEngine;
use async_trait::async_trait;
use async_lock::Lock;

use crate::{TOKEN_DB, BLAKE3_DOCUMENT, TimeStamp, GC_REGISTRY, GC_STORAGE};

#[async_trait]
pub (crate) trait StorageOps {
    async fn get(&self, storage: Arc<&TuringEngine>, key: &[u8]) -> Result<DbOps>;
    async fn set(&self, storage: Arc<&TuringEngine>, key: &[u8], value: &[u8]) -> Result<DbOps>;
    async fn list(&self, storage: Arc<&TuringEngine>) -> DbOps;
    async fn modify(&self, storage: Arc<&TuringEngine>, key: &[u8], value: &[u8]) -> Result<DbOps>;
    async fn remove(&self, storage: Arc<&TuringEngine>, key: &[u8]) -> Result<DbOps>;
    async fn gc_set(&self, storage: Arc<&TuringEngine>, key: &[u8], value: &[u8]) -> Result<DbOps>;
}

#[async_trait]
trait GarbageCollector {
    async fn gc(storage: Arc<&TuringEngine>, field_name: &[u8]) -> Result<DbOps>;
}
pub (crate) struct SGStorage<'b3s> {
    blake3_token: Blake3Storage<'b3s>,
}

impl<'b3s> SGStorage<'b3s> {
    pub (crate) async fn init(storage: Arc<TuringEngine>) -> Result<DbOps> {
        storage.repo_init().await?;

        Ok(DbOps::RepoInitialized)
    }
}

#[derive(Debug)]
struct Blake3Storage<'b3s> {
    db: &'b3s Path,
    document: &'b3s Path,
}

impl<'b3s> Default for Blake3Storage<'b3s> {
    fn default() -> Self {
        Self {
            db: Path::new(TOKEN_DB),
            document: Path::new(BLAKE3_DOCUMENT),
        }
    }
}

#[async_trait]
impl<'b3s> StorageOps  for Blake3Storage<'b3s> {
    async fn get(&self, storage: Arc<&TuringEngine>, key: &[u8]) -> Result<DbOps> {
        storage.field_get(&self.db, &self.document, &key).await
    }
    async fn set(&self, storage: Arc<&TuringEngine>, key: &[u8], value: &[u8]) -> Result<DbOps> {
        storage.field_insert(&self.db, &self.document, &key, &value).await
    }
    async fn list(&self, storage: Arc<&TuringEngine>) -> DbOps {
        storage.field_list(&self.db, &self.document).await
    }
    async fn modify(&self, storage: Arc<&TuringEngine>, key: &[u8], value: &[u8]) -> Result<DbOps> {
        storage.field_modify(&self.db, &self.document, &key, &value).await
    }
    async fn remove(&self, storage: Arc<&TuringEngine>, key: &[u8]) -> Result<DbOps> {
        storage.field_remove(&self.db, &self.document, &key).await
    }
    async fn gc_set(&self, storage: Arc<&TuringEngine>, key: &[u8], value: &[u8]) -> Result<DbOps> {
        let gc_registry = Path::new(GC_REGISTRY);
        let gc_storage = Path::new(GC_STORAGE);

        storage.field_insert(gc_registry, gc_storage, key, value).await
    }
}

#[derive(Debug)]
struct GcRegistry<'gc>(HashMap<TimeStamp, Lock<GcData<'gc>>>);
#[derive(Debug)]
struct GcData<'gc> {
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
    fn new() -> GcData<'gc> {
        GcData::default()
    }

    fn db(&mut self, value: &'gc str) -> &mut GcData<'gc> {
        self.db = Path::new(value);

        self
    }

    fn document(&mut self, value: &'gc str) -> &mut GcData<'gc> {
        self.document = Path::new(value);

        self
    }

    fn key(&mut self, value: &'gc [u8]) -> &mut GcData<'gc> {
        self.key = value;

        self
    }

    fn build(&mut self) -> &GcData<'gc> {

        self
    }
}


#[async_trait]
impl<'gc> GarbageCollector for Blake3Storage<'gc> {
    async fn gc(storage: Arc<&TuringEngine>, key: &[u8]) -> Result<DbOps> {
        let gc_registry = Path::new(GC_REGISTRY);
        let gc_storage = Path::new(GC_STORAGE);

        storage.field_remove(gc_registry, gc_registry, key).await
    }
}