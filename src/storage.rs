use std::path::Path;
use async_dup::Arc;
use anyhow::Result;
use custom_codes::DbOps;
use turingdb::TuringEngine;
use async_trait::async_trait;

use crate::{TOKEN_DB, BLAKE3_DOCUMENT, TimeStamp, GC_REGISTRY, GC_STORAGE, GcData};

#[async_trait]
pub (crate) trait StorageOps {
    async fn get(&self, storage: Arc<&TuringEngine>, key: &[u8]) -> Result<DbOps>;
    async fn set(&self, storage: Arc<&TuringEngine>, key: &[u8], value: &[u8]) -> Result<DbOps>;
    async fn list(&self, storage: Arc<&TuringEngine>) -> DbOps;
    async fn modify(&self, storage: Arc<&TuringEngine>, key: &[u8], value: &[u8]) -> Result<DbOps>;
    async fn remove(&self, storage: Arc<&TuringEngine>, key: &[u8]) -> Result<DbOps>;
    async fn gc<'so>(&self, storage: Arc<&TuringEngine>, key: TimeStamp, value: &GcData<'so>) -> Result<DbOps>;
}

#[async_trait]
trait GarbageCollector {
    async fn gc(storage: Arc<&TuringEngine>, field_name: TimeStamp) -> Result<DbOps>;
}

#[derive(Debug)]
pub struct Blake3Storage<'b3s> {
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
    async fn gc<'so>(&self, storage: Arc<&TuringEngine>, key: TimeStamp, value: &GcData<'so>) -> Result<DbOps> {
        let gc_registry = Path::new(GC_REGISTRY);
        let gc_storage = Path::new(GC_STORAGE);
        let key = key.to_bytes();
        let value = bincode::serialize::<GcData<'so>>(&value)?;

        storage.field_insert(gc_registry, gc_storage, &key, &value).await
    }
}
