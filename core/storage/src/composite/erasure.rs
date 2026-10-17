//! Reed-Solomon erasure coding logic for the composite storage provider.
//!
//! Handles encoding, decoding, and per-shard I/O operations for erasure (RAID 5/6) mode.
//!
//! Shard file layout: `SHARD_MAGIC || tag || shard_data`. The tag is a keyed
//! BLAKE2b-256 MAC (see [`super::auth`]) over the write's `object_id`, the
//! shard index, the coding parameters, the original size and the shard data.
//! The `object_id` and size are taken from the authenticated shard map entry,
//! never from the shard, so a backend cannot substitute another object's
//! shard, an older version of this one, or bytes with a recomputed checksum.

use std::future::Future;
use std::sync::Arc;
use tracing::warn;

use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::provider::Metadata;
use crate::shard_map::{ChunkEntry, ShardMap};
use axiomvault_common::{Error, Result, VaultPath};

use super::auth::{DOMAIN_SHARD, TAG_LEN};
use super::config::RaidMode;
use super::CompositeStorageProvider;

/// Leading bytes of an authenticated erasure shard.
const SHARD_MAGIC: &[u8; 4] = b"AXS2";
/// Bytes before the shard data: magic and tag.
const SHARD_HEADER_LEN: usize = SHARD_MAGIC.len() + TAG_LEN;

impl CompositeStorageProvider {
    /// Get erasure mode parameters, or error if in mirror mode.
    pub(crate) fn erasure_params(&self) -> Result<(usize, usize)> {
        match self.config.mode {
            RaidMode::Erasure {
                data_shards,
                parity_shards,
            } => Ok((data_shards, parity_shards)),
            RaidMode::Mirror => Err(Error::Storage("Not in erasure mode".to_string())),
        }
    }

    /// Get the cached Reed-Solomon encoder (only valid in erasure mode).
    pub(crate) fn reed_solomon(&self) -> Result<&ReedSolomon> {
        self.reed_solomon
            .as_ref()
            .ok_or_else(|| Error::Storage("Reed-Solomon not available in mirror mode".to_string()))
    }

    /// Encode data into N shards (k data + m parity) using Reed-Solomon.
    pub(crate) fn erasure_encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let (data_shards, parity_shards) = self.erasure_params()?;
        let total_shards = data_shards + parity_shards;

        // Reed-Solomon requires equal-length shards; use ceil division for shard size.
        // Empty data gets minimum 1-byte shards since RS cannot operate on zero-length shards.
        let shard_size = if data.is_empty() {
            1
        } else {
            data.len().div_ceil(data_shards)
        };

        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total_shards);
        for i in 0..data_shards {
            let start = i * shard_size;
            let end = std::cmp::min(start + shard_size, data.len());
            let mut shard = if start < data.len() {
                data[start..end].to_vec()
            } else {
                Vec::new()
            };
            shard.resize(shard_size, 0);
            shards.push(shard);
        }
        for _ in 0..parity_shards {
            shards.push(vec![0u8; shard_size]);
        }

        self.reed_solomon()?
            .encode(&mut shards)
            .map_err(|e| Error::Storage(format!("Reed-Solomon encode failed: {}", e)))?;

        Ok(shards)
    }

    /// Decode data from shards using Reed-Solomon.
    /// `shard_opts` has N entries; missing shards are `None`.
    pub(crate) fn erasure_decode(
        &self,
        mut shard_opts: Vec<Option<Vec<u8>>>,
        original_size: usize,
    ) -> Result<Vec<u8>> {
        let (data_shards, _) = self.erasure_params()?;

        self.reed_solomon()?
            .reconstruct(&mut shard_opts)
            .map_err(|e| Error::Storage(format!("Reed-Solomon reconstruct failed: {}", e)))?;

        let mut data = Vec::with_capacity(original_size);
        for s in shard_opts.iter().take(data_shards).flatten() {
            data.extend_from_slice(s);
        }
        data.truncate(original_size);
        Ok(data)
    }

    /// Run a `Metadata`-returning operation per shard (one future per backend),
    /// collect results, and return the first success with the given `name`.
    pub(crate) async fn erasure_per_shard(
        &self,
        op: &str,
        name: String,
        futures: Vec<impl Future<Output = Result<Metadata>>>,
    ) -> Result<Metadata> {
        let results = futures::future::join_all(futures).await;
        let mut first_meta: Option<Metadata> = None;
        let mut last_error: Option<Error> = None;
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(meta) => {
                    if first_meta.is_none() {
                        first_meta = Some(Metadata {
                            name: name.clone(),
                            ..meta
                        });
                    }
                }
                Err(e) => {
                    warn!(backend = self.backends[i].name(), shard = i, error = %e, operation = op, "Erasure shard operation failed");
                    last_error = Some(e);
                }
            }
        }
        first_meta.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                Error::Storage(format!("All backends failed for erasure {}", op))
            })
        })
    }

    /// Length every shard of an object of `original_size` bytes has.
    pub(crate) fn expected_shard_len(&self, original_size: u64) -> Result<usize> {
        let (data_shards, _) = self.erasure_params()?;
        let size = usize::try_from(original_size)
            .map_err(|_| Error::Storage("Erasure: original_size does not fit".to_string()))?;
        Ok(if size == 0 {
            1
        } else {
            size.div_ceil(data_shards)
        })
    }

    /// Pass the fields a shard tag covers to `f`: the write, the shard's
    /// index (its position in the set and its backend), the coding
    /// parameters, the object's size and the shard data.
    fn with_shard_fields<R>(
        &self,
        object_id: &[u8; 16],
        index: usize,
        original_size: u64,
        data: &[u8],
        f: impl FnOnce(&[&[u8]]) -> R,
    ) -> Result<R> {
        let (data_shards, parity_shards) = self.erasure_params()?;
        Ok(f(&[
            object_id,
            &(index as u64).to_le_bytes(),
            &(data_shards as u64).to_le_bytes(),
            &(parity_shards as u64).to_le_bytes(),
            &original_size.to_le_bytes(),
            data,
        ]))
    }

    /// Build the stored payload for shard `index` of the write `object_id`.
    pub(crate) fn seal_shard(
        &self,
        object_id: &[u8; 16],
        index: usize,
        original_size: u64,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let tag = self.with_shard_fields(object_id, index, original_size, data, |fields| {
            self.key.tag(DOMAIN_SHARD, fields)
        })?;
        let mut payload = Vec::with_capacity(SHARD_HEADER_LEN + data.len());
        payload.extend_from_slice(SHARD_MAGIC);
        payload.extend_from_slice(&tag);
        payload.extend_from_slice(data);
        Ok(payload)
    }

    /// The shard data of `payload` if it is shard `index` of `entry`, else
    /// `None`. A shard that fails here must be treated as missing.
    pub(crate) fn open_shard<'p>(
        &self,
        entry: &ChunkEntry,
        index: usize,
        payload: &'p [u8],
    ) -> Option<&'p [u8]> {
        if payload.len() < SHARD_HEADER_LEN || &payload[..SHARD_MAGIC.len()] != SHARD_MAGIC {
            return None;
        }
        let (stored_tag, data) = payload[SHARD_MAGIC.len()..].split_at(TAG_LEN);
        if data.len() != self.expected_shard_len(entry.original_size).ok()? {
            return None;
        }
        let valid = self
            .with_shard_fields(
                &entry.object_id,
                index,
                entry.original_size,
                data,
                |fields| self.key.verify(DOMAIN_SHARD, fields, stored_tag),
            )
            .ok()?;
        valid.then_some(data)
    }

    /// Build the shard path for a given file path and shard index.
    pub(crate) fn shard_path(path: &VaultPath, shard_index: usize) -> Result<VaultPath> {
        let path_str = path.to_string_path();
        VaultPath::parse(&format!("{}.shard{}", path_str, shard_index))
    }

    /// Upload data in erasure mode: encode into shards, write each to its backend.
    pub(crate) async fn erasure_upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        let original_size = data.len();
        let shards = self.erasure_encode(&data)?;
        // Fresh per write: shards of an earlier write of this path stop verifying.
        let object_id = uuid::Uuid::new_v4().into_bytes();

        let mut futures = Vec::with_capacity(shards.len());
        for (i, shard) in shards.into_iter().enumerate() {
            let backend = Arc::clone(&self.backends[i]);
            let shard_path = Self::shard_path(path, i)?;
            let payload = self.seal_shard(&object_id, i, original_size as u64, &shard)?;
            futures.push(async move {
                let start = tokio::time::Instant::now();
                let result = backend.upload(&shard_path, payload).await;
                (result, start.elapsed())
            });
        }

        let results = futures::future::join_all(futures).await;

        let mut first_meta: Option<Metadata> = None;
        let mut succeeded: Vec<usize> = Vec::new();
        let mut failure_count = 0usize;
        let mut last_error: Option<Error> = None;

        for (i, (result, latency)) in results.into_iter().enumerate() {
            match result {
                Ok(meta) => {
                    self.record_health_success(i, latency).await;
                    succeeded.push(i);
                    if first_meta.is_none() {
                        // Return metadata reflecting the original file, not the shard
                        first_meta = Some(Metadata {
                            name: path.name().unwrap_or("/").to_string(),
                            size: Some(original_size as u64),
                            ..meta
                        });
                    }
                }
                Err(e) => {
                    self.record_health_failure(i).await;
                    failure_count += 1;
                    warn!(
                        backend = self.backends[i].name(),
                        shard = i,
                        error = %e,
                        "Erasure upload: shard write failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        let (_, parity_shards) = self.erasure_params()?;
        if failure_count > parity_shards {
            return Err(last_error
                .unwrap_or_else(|| Error::Storage("Too many shard write failures".to_string())));
        }

        if failure_count > 0 {
            warn!(
                operation = "erasure_upload",
                failed = failure_count,
                total = self.backends.len(),
                "Partial erasure write: {}/{} shards failed",
                failure_count,
                self.backends.len()
            );
            self.check_redundancy_warning().await;
        }

        let meta = first_meta.ok_or_else(|| {
            last_error
                .unwrap_or_else(|| Error::Storage("All backends failed for erasure upload".into()))
        })?;

        // Record the shard mapping with only successful backends
        let (ds, ps) = self.erasure_params()?;
        let path_str = path.to_string_path();
        let entry = ShardMap::erasure_entry(
            &path_str,
            original_size as u64,
            object_id,
            ds,
            ps,
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

    /// Download data in erasure mode: fetch shards, reconstruct original data.
    ///
    /// Only shards that verify against the authenticated shard map entry are
    /// used; the rest count as missing, so the result is either the data that
    /// was written or an error.
    pub(crate) async fn erasure_download(&self, path: &VaultPath) -> Result<Vec<u8>> {
        self.probe_if_due().await;
        let entry = self.entry_for(path).await?;

        let RaidMode::Erasure {
            data_shards,
            parity_shards,
        } = self.config.mode
        else {
            return Err(Error::Storage("Not in erasure mode".to_string()));
        };

        let total = data_shards + parity_shards;
        let mut futures = Vec::with_capacity(total);
        for i in 0..total {
            let backend = Arc::clone(&self.backends[i]);
            let shard_path = Self::shard_path(path, i)?;
            futures.push(async move {
                let start = tokio::time::Instant::now();
                let result = backend.download(&shard_path).await;
                (i, result, start.elapsed())
            });
        }

        let results = futures::future::join_all(futures).await;

        let mut shard_opts: Vec<Option<Vec<u8>>> = vec![None; total];
        let mut available = 0usize;

        for (i, result, latency) in results {
            if let Ok(payload) = result {
                let Some(shard_data) = self.open_shard(&entry, i, &payload) else {
                    warn!(
                        shard = i,
                        "Erasure download: shard failed authentication, treating it as missing"
                    );
                    self.record_health_failure(i).await;
                    continue;
                };

                // Only record success after payload validation passes
                self.record_health_success(i, latency).await;
                shard_opts[i] = Some(shard_data.to_vec());
                available += 1;
            } else {
                self.record_health_failure(i).await;
            }
        }

        if available < data_shards {
            return Err(Error::Storage(format!(
                "Erasure download: only {}/{} shards available, need {}",
                available, total, data_shards
            )));
        }

        // `open_shard` fixed every shard's length from this authenticated size.
        self.erasure_decode(shard_opts, entry.original_size as usize)
    }

    /// Delete shards across all backends in erasure mode.
    pub(crate) async fn erasure_delete(&self, path: &VaultPath) -> Result<()> {
        let total = self.backends.len();
        let mut futures = Vec::with_capacity(total);
        for i in 0..total {
            let backend = Arc::clone(&self.backends[i]);
            let shard_path = Self::shard_path(path, i)?;
            futures.push(async move { backend.delete(&shard_path).await });
        }

        let results = futures::future::join_all(futures).await;
        let mut any_success = false;
        let mut last_error: Option<Error> = None;

        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok(()) => any_success = true,
                Err(e) => {
                    warn!(
                        backend = self.backends[i].name(),
                        shard = i,
                        error = %e,
                        "Erasure delete: shard delete failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        if any_success {
            // Remove from shard map
            let path_str = path.to_string_path();
            {
                self.shard_map.write().await.remove(&path_str);
            }
            self.save_shard_map().await?;
            Ok(())
        } else {
            Err(last_error
                .unwrap_or_else(|| Error::Storage("All backends failed for erasure delete".into())))
        }
    }
}
