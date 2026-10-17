//! Composite storage provider for multi-backend RAID operations.
//!
//! Wraps N `StorageProvider` backends behind the `StorageProvider` trait,
//! delegating operations according to the configured RAID mode.

pub(crate) mod auth;
mod config;
mod erasure;
mod fanout;
mod health;

pub use auth::CompositeKey;
pub use config::{CompositeConfig, RaidMode};

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{OnceCell, RwLock};
use tracing::warn;

use crate::health::ProviderHealth;
use crate::provider::{ByteStream, Metadata, StorageProvider};
use crate::shard_map::{ChunkEntry, ShardMap};
use auth::{DOMAIN_MIRROR, TAG_LEN};
use axiomvault_common::{Error, Result, VaultPath};

/// A storage provider that distributes operations across multiple backends.
///
/// In mirror mode, writes fan out to all backends and reads return the first
/// successful result. In erasure mode, chunks are sharded via Reed-Solomon
/// coding across backends.
///
/// The backends are not trusted with integrity: the shard map and every
/// shard or mirror copy are authenticated under a [`CompositeKey`] they do
/// not hold, and anything that fails its tag is treated as missing.
pub struct CompositeStorageProvider {
    pub(crate) backends: Vec<Arc<dyn StorageProvider>>,
    pub(crate) config: CompositeConfig,
    /// Key for the shard map and shard tags; never given to a backend.
    pub(crate) key: CompositeKey,
    /// Cached Reed-Solomon encoder, created once for erasure mode.
    pub(crate) reed_solomon: Option<ReedSolomon>,
    /// Persistent shard map tracking chunk-to-backend mappings.
    pub(crate) shard_map: Arc<RwLock<ShardMap>>,
    /// One-shot cell that ensures shard map hydration runs exactly once.
    shard_map_init: OnceCell<()>,
    /// Per-backend health state for tracking availability and latency.
    pub(crate) health_states: Vec<Arc<RwLock<ProviderHealth>>>,
}

impl CompositeStorageProvider {
    /// Create a new composite provider authenticated under `key`.
    ///
    /// `key` must come from the vault layer (derived from the master key) so
    /// that no backend can compute it; see [`CompositeKey`].
    ///
    /// # Errors
    /// Returns `InvalidInput` if fewer than 2 backends are provided, or if
    /// erasure mode parameters don't match the backend count.
    pub fn new(
        backends: Vec<Arc<dyn StorageProvider>>,
        config: CompositeConfig,
        key: CompositeKey,
    ) -> Result<Self> {
        if backends.len() < 2 {
            return Err(Error::InvalidInput(
                "CompositeStorageProvider requires at least 2 backends".to_string(),
            ));
        }

        config.health.validate().map_err(Error::InvalidInput)?;

        if let RaidMode::Erasure {
            data_shards,
            parity_shards,
        } = config.mode
        {
            if data_shards == 0 {
                return Err(Error::InvalidInput(
                    "Erasure mode requires at least 1 data shard".to_string(),
                ));
            }
            if parity_shards == 0 {
                return Err(Error::InvalidInput(
                    "Erasure mode requires at least 1 parity shard".to_string(),
                ));
            }
            if data_shards + parity_shards != backends.len() {
                return Err(Error::InvalidInput(format!(
                    "Erasure mode requires data_shards({}) + parity_shards({}) == backend count({})",
                    data_shards,
                    parity_shards,
                    backends.len()
                )));
            }
        }

        let reed_solomon = if let RaidMode::Erasure {
            data_shards,
            parity_shards,
        } = config.mode
        {
            Some(
                ReedSolomon::new(data_shards, parity_shards)
                    .map_err(|e| Error::Storage(format!("Reed-Solomon init failed: {}", e)))?,
            )
        } else {
            None
        };

        let health_states = (0..backends.len())
            .map(|i| Arc::new(RwLock::new(ProviderHealth::new(i))))
            .collect();

        Ok(Self {
            backends,
            config,
            key,
            reed_solomon,
            shard_map: Arc::new(RwLock::new(ShardMap::new())),
            shard_map_init: OnceCell::const_new(),
            health_states,
        })
    }

    /// Load the shard map from all backends, merging any diverged copies.
    ///
    /// Call this after construction to hydrate the shard map from persistent
    /// storage. If no backends have a shard map yet, this is a no-op.
    pub async fn load_shard_map(&self) -> Result<()> {
        let loaded = ShardMap::load_from_all(&self.backends, &self.key).await?;
        *self.shard_map.write().await = loaded;
        let _ = self.shard_map_init.set(());
        Ok(())
    }

    /// Ensure the shard map has been hydrated from persistent storage.
    /// Called lazily before the first save to prevent overwriting existing data.
    ///
    /// Uses a `OnceCell` so at most one load ever runs, even under concurrency.
    /// If the load fails, the error is propagated and the `OnceCell` remains
    /// unset, allowing retry on the next call.
    async fn ensure_shard_map_loaded(&self) -> Result<()> {
        self.shard_map_init
            .get_or_try_init(|| async {
                let loaded = ShardMap::load_from_all(&self.backends, &self.key).await?;
                *self.shard_map.write().await = loaded;
                Ok::<(), Error>(())
            })
            .await?;
        Ok(())
    }

    /// Persist the current shard map to all backends.
    pub async fn save_shard_map(&self) -> Result<()> {
        let map = self.shard_map.read().await;
        map.save_to_all(&self.backends, &self.key).await
    }

    /// The authenticated shard map entry for `path`, loading the map first.
    ///
    /// Reads go through this: the entry names the write (`object_id`) and
    /// size every shard or copy must verify against.
    pub(crate) async fn entry_for(&self, path: &VaultPath) -> Result<ChunkEntry> {
        self.ensure_shard_map_loaded().await?;
        let path_str = path.to_string_path();
        self.shard_map
            .read()
            .await
            .get(&path_str)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("{path_str} is not in the shard map")))
    }

    /// Tag over one mirror copy: binds the write and the exact content.
    pub(crate) fn mirror_tag(&self, object_id: &[u8; 16], data: &[u8]) -> [u8; TAG_LEN] {
        let size = (data.len() as u64).to_le_bytes();
        self.key.tag(DOMAIN_MIRROR, &[object_id, &size, data])
    }

    /// Whether `data` is the copy `entry` describes.
    pub(crate) fn verify_mirror_copy(&self, entry: &ChunkEntry, data: &[u8]) -> bool {
        let Some(tag) = entry.mirror_tag else {
            return false;
        };
        let size = (data.len() as u64).to_le_bytes();
        data.len() as u64 == entry.original_size
            && self
                .key
                .verify(DOMAIN_MIRROR, &[&entry.object_id, &size, data], &tag)
    }

    /// Get a clone of the current shard map (for inspection/testing).
    pub async fn get_shard_map(&self) -> ShardMap {
        self.shard_map.read().await.clone()
    }

    /// Get the current RAID mode.
    pub fn mode(&self) -> RaidMode {
        self.config.mode
    }

    /// Get a reference to the backend list.
    pub fn backends(&self) -> &[Arc<dyn StorageProvider>] {
        &self.backends
    }

    /// Get a reference to the composite configuration.
    pub fn composite_config(&self) -> &CompositeConfig {
        &self.config
    }

    /// Get a reference to the shard map (behind `Arc<RwLock<_>>`).
    pub fn shard_map_ref(&self) -> &Arc<RwLock<ShardMap>> {
        &self.shard_map
    }

    /// Get the number of backends.
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Get the names of all backends.
    pub fn backend_names(&self) -> Vec<&str> {
        self.backends.iter().map(|b| b.name()).collect()
    }
}

/// Check whether a name matches the internal `.shardN` pattern.
fn is_shard_file(name: &str) -> bool {
    if let Some(pos) = name.rfind(".shard") {
        let suffix = &name[pos + 6..];
        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}

#[async_trait]
impl StorageProvider for CompositeStorageProvider {
    fn name(&self) -> &str {
        "composite"
    }

    async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        self.ensure_shard_map_loaded().await?;
        match self.config.mode {
            RaidMode::Mirror => {
                let original_size = data.len() as u64;
                let object_id = uuid::Uuid::new_v4().into_bytes();
                let mirror_tag = self.mirror_tag(&object_id, &data);
                let path = path.clone();
                let data: Bytes = data.into();
                let (meta, succeeded) = self
                    .fan_out("upload", |backend| {
                        let path = path.clone();
                        let data = data.clone();
                        async move { backend.upload(&path, data.to_vec()).await }
                    })
                    .await?;

                // Record mirror entry with only the backends that succeeded
                let path_str = path.to_string_path();
                let entry = ShardMap::mirror_entry(
                    &path_str,
                    original_size,
                    object_id,
                    mirror_tag,
                    &self.backends,
                    Some(&succeeded),
                );
                {
                    let mut map = self.shard_map.write().await;
                    map.insert(&path_str, entry);
                }
                self.save_shard_map().await?;

                Ok(meta)
            }
            RaidMode::Erasure { .. } => self.erasure_upload(path, data).await,
        }
    }

    async fn upload_stream(&self, path: &VaultPath, stream: ByteStream) -> Result<Metadata> {
        use futures::StreamExt;
        let mut data = Vec::new();
        let mut stream = stream;
        while let Some(chunk) = stream.next().await {
            data.extend_from_slice(&chunk?);
        }
        self.upload(path, data).await
    }

    async fn download(&self, path: &VaultPath) -> Result<Vec<u8>> {
        match self.config.mode {
            RaidMode::Mirror => {
                let entry = self.entry_for(path).await?;
                let path = path.clone();
                self.try_first("download", |backend| {
                    let path = path.clone();
                    let entry = &entry;
                    async move {
                        let data = backend.download(&path).await?;
                        if self.verify_mirror_copy(entry, &data) {
                            Ok(data)
                        } else {
                            Err(Error::Crypto(format!(
                                "mirror copy of {} failed authentication; treating it as missing",
                                path
                            )))
                        }
                    }
                })
                .await
            }
            RaidMode::Erasure { .. } => self.erasure_download(path).await,
        }
    }

    async fn download_stream(&self, path: &VaultPath) -> Result<ByteStream> {
        let data = self.download(path).await?;
        Ok(Box::pin(stream::once(async move { Ok(data) })))
    }

    async fn exists(&self, path: &VaultPath) -> Result<bool> {
        match self.config.mode {
            RaidMode::Mirror => {
                let path = path.clone();
                self.try_first("exists", |backend| {
                    let path = path.clone();
                    async move { backend.exists(&path).await }
                })
                .await
            }
            // Shard paths carry the write's object_id, so the authenticated
            // map is what says whether the object exists.
            RaidMode::Erasure { .. } => match self.entry_for(path).await {
                Ok(_) => Ok(true),
                Err(Error::NotFound(_)) => Ok(false),
                Err(e) => Err(e),
            },
        }
    }

    async fn delete(&self, path: &VaultPath) -> Result<()> {
        self.ensure_shard_map_loaded().await?;
        match self.config.mode {
            RaidMode::Mirror => {
                let path = path.clone();
                self.fan_out_void("delete", |backend| {
                    let path = path.clone();
                    async move { backend.delete(&path).await }
                })
                .await?;

                // Remove from shard map
                {
                    self.shard_map.write().await.remove(&path.to_string_path());
                }
                self.save_shard_map().await?;

                Ok(())
            }
            RaidMode::Erasure { .. } => self.erasure_delete(path).await,
        }
    }

    async fn list(&self, path: &VaultPath) -> Result<Vec<Metadata>> {
        let path = path.clone();

        // Query all backends concurrently and merge results.
        let futures: Vec<_> = self
            .backends
            .iter()
            .map(|b| {
                let p = path.clone();
                let backend = Arc::clone(b);
                async move { backend.list(&p).await }
            })
            .collect();
        let results = futures::future::join_all(futures).await;

        let mut merged: HashMap<String, Metadata> = HashMap::new();
        let mut any_success = false;
        let mut last_error: Option<Error> = None;

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(entries) => {
                    any_success = true;
                    for entry in entries {
                        merged
                            .entry(entry.name.clone())
                            .and_modify(|existing| {
                                if entry.modified > existing.modified {
                                    *existing = entry.clone();
                                }
                            })
                            .or_insert(entry);
                    }
                }
                Err(e) => {
                    warn!(
                        backend = self.backends[i].name(),
                        operation = "list",
                        error = %e,
                        "Backend list failed, continuing with other backends"
                    );
                    last_error = Some(e);
                }
            }
        }

        if any_success {
            let mut entries: Vec<Metadata> = merged.into_values().collect();
            // In erasure mode, filter out internal shard files
            if matches!(self.config.mode, RaidMode::Erasure { .. }) {
                entries.retain(|e| !is_shard_file(&e.name));
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(entries)
        } else {
            Err(last_error
                .unwrap_or_else(|| Error::Storage("All backends failed for list".to_string())))
        }
    }

    async fn metadata(&self, path: &VaultPath) -> Result<Metadata> {
        match self.config.mode {
            RaidMode::Mirror => {
                let path = path.clone();
                self.try_first("metadata", |backend| {
                    let path = path.clone();
                    async move { backend.metadata(&path).await }
                })
                .await
            }
            RaidMode::Erasure { .. } => {
                let entry = self.entry_for(path).await?;
                let shard_path = Self::shard_path(path, &entry.object_id, 0)?;
                let file_name = path.name().unwrap_or("/").to_string();
                // The size comes from the authenticated shard map, not a shard header.
                let original_size = entry.original_size;
                // Get filesystem metadata (timestamps etc) from the backend
                let shard_meta = self
                    .try_first("metadata", |backend| {
                        let sp = shard_path.clone();
                        async move { backend.metadata(&sp).await }
                    })
                    .await?;
                Ok(Metadata {
                    name: file_name,
                    size: Some(original_size),
                    is_directory: false,
                    ..shard_meta
                })
            }
        }
    }

    async fn create_dir(&self, path: &VaultPath) -> Result<Metadata> {
        let path = path.clone();
        let (meta, _) = self
            .fan_out("create_dir", |backend| {
                let path = path.clone();
                async move { backend.create_dir(&path).await }
            })
            .await?;
        Ok(meta)
    }

    async fn delete_dir(&self, path: &VaultPath) -> Result<()> {
        let path = path.clone();
        self.fan_out_void("delete_dir", |backend| {
            let path = path.clone();
            async move { backend.delete_dir(&path).await }
        })
        .await
    }

    async fn rename(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
        self.ensure_shard_map_loaded().await?;
        match self.config.mode {
            RaidMode::Mirror => {
                let from = from.clone();
                let to = to.clone();
                let (meta, succeeded) = self
                    .fan_out("rename", |backend| {
                        let from = from.clone();
                        let to = to.clone();
                        async move { backend.rename(&from, &to).await }
                    })
                    .await?;

                // Update shard map: rename entry, then remove shards for failed backends
                let from_str = from.to_string_path();
                let to_str = to.to_string_path();
                {
                    let mut map = self.shard_map.write().await;
                    map.rename(&from_str, &to_str);
                    if let Some(entry) = map.entries.get_mut(&to_str) {
                        entry.shards.retain(|idx, _| succeeded.contains(idx));
                    }
                }
                self.save_shard_map().await?;

                Ok(meta)
            }
            RaidMode::Erasure { .. } => {
                let object_id = self.entry_for(from).await?.object_id;
                let total = self.backends.len();
                let mut futures = Vec::with_capacity(total);
                for i in 0..total {
                    let backend = Arc::clone(&self.backends[i]);
                    let from_shard = Self::shard_path(from, &object_id, i)?;
                    let to_shard = Self::shard_path(to, &object_id, i)?;
                    futures.push(async move { backend.rename(&from_shard, &to_shard).await });
                }
                let meta = self
                    .erasure_per_shard("rename", to.name().unwrap_or("/").to_string(), futures)
                    .await?;

                // Update shard map
                let from_str = from.to_string_path();
                let to_str = to.to_string_path();
                let superseded = {
                    let mut map = self.shard_map.write().await;
                    let old = map.get(&to_str).cloned();
                    map.rename(&from_str, &to_str);
                    old
                };
                self.save_shard_map().await?;
                self.delete_superseded(&to_str, superseded, &object_id)
                    .await;

                Ok(meta)
            }
        }
    }

    async fn copy(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
        self.ensure_shard_map_loaded().await?;
        match self.config.mode {
            RaidMode::Mirror => {
                let from = from.clone();
                let to = to.clone();
                let (meta, succeeded) = self
                    .fan_out("copy", |backend| {
                        let from = from.clone();
                        let to = to.clone();
                        async move { backend.copy(&from, &to).await }
                    })
                    .await?;

                // Copy shard map entry for the new path, retaining only succeeded backends
                let from_str = from.to_string_path();
                let to_str = to.to_string_path();
                {
                    let mut map = self.shard_map.write().await;
                    if let Some(entry) = map.get(&from_str).cloned() {
                        let mut new_entry = entry;
                        for shard in new_entry.shards.values_mut() {
                            shard.backend_path = to_str.clone();
                        }
                        new_entry.shards.retain(|idx, _| succeeded.contains(idx));
                        new_entry.updated_at = chrono::Utc::now();
                        map.insert(&to_str, new_entry);
                    }
                }
                self.save_shard_map().await?;

                Ok(meta)
            }
            RaidMode::Erasure { .. } => {
                let object_id = self.entry_for(from).await?.object_id;
                let total = self.backends.len();
                let mut futures = Vec::with_capacity(total);
                for i in 0..total {
                    let backend = Arc::clone(&self.backends[i]);
                    let from_shard = Self::shard_path(from, &object_id, i)?;
                    let to_shard = Self::shard_path(to, &object_id, i)?;
                    futures.push(async move { backend.copy(&from_shard, &to_shard).await });
                }
                let meta = self
                    .erasure_per_shard("copy", to.name().unwrap_or("/").to_string(), futures)
                    .await?;

                // Copy shard map entry for the new path
                let from_str = from.to_string_path();
                let to_str = to.to_string_path();
                let superseded = {
                    let mut map = self.shard_map.write().await;
                    let old = map.get(&to_str).cloned();
                    if let Some(entry) = map.get(&from_str).cloned() {
                        let mut new_entry = entry;
                        for shard in new_entry.shards.values_mut() {
                            if let Some(suffix) = shard.backend_path.strip_prefix(&from_str) {
                                shard.backend_path = format!("{}{}", to_str, suffix);
                            }
                        }
                        new_entry.updated_at = chrono::Utc::now();
                        map.insert(&to_str, new_entry);
                    }
                    old
                };
                self.save_shard_map().await?;
                self.delete_superseded(&to_str, superseded, &object_id)
                    .await;

                Ok(meta)
            }
        }
    }
}
