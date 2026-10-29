//! Storage provider trait definition.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::pin::Pin;

use axiomvault_common::{Result, VaultPath};

/// Metadata for a stored object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// Unique identifier for the object (provider-specific).
    pub id: String,
    /// Name of the object.
    pub name: String,
    /// Size in bytes (None for directories).
    pub size: Option<u64>,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// Last modification time.
    pub modified: DateTime<Utc>,
    /// ETag or revision ID for conflict detection.
    pub etag: Option<String>,
    /// Provider-specific metadata.
    pub provider_data: Option<serde_json::Value>,
}

/// Conflict resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Keep both versions (rename local).
    KeepBoth,
    /// Prefer local version.
    PreferLocal,
    /// Prefer remote version.
    PreferRemote,
}

/// Byte stream type for upload/download operations.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>>> + Send>>;

/// Bytes and version metadata observed as one stable remote object revision.
#[derive(Debug, Clone)]
pub struct VersionedDownload {
    /// Complete object bytes.
    pub data: Vec<u8>,
    /// Metadata for the exact revision represented by `data`.
    pub metadata: Metadata,
}

/// Check a conditional-write precondition against the current object.
///
/// `current` is the object now at the path (`None` when absent). `expected`
/// is the revision the caller last observed (`None` when it observed none).
/// Fails with `Error::Conflict` unless both are absent, or the object exists
/// and its etag equals `expected`. An existing object without an etag never
/// satisfies a precondition, because its revision cannot be proven unchanged.
pub(crate) fn check_precondition(current: Option<&Metadata>, expected: Option<&str>) -> Result<()> {
    use axiomvault_common::Error;
    match (current, expected) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(Error::Conflict(
            "remote object was removed since it was read".to_string(),
        )),
        (Some(_), None) => Err(Error::Conflict("remote object already exists".to_string())),
        (Some(metadata), Some(expected)) if metadata.etag.as_deref() == Some(expected) => Ok(()),
        (Some(_), Some(_)) => Err(Error::Conflict(
            "remote object changed since it was read".to_string(),
        )),
    }
}

/// The error [`StorageProvider::download_bounded`] returns for an object
/// longer than `max_len`.
pub(crate) fn too_long(path: &VaultPath, max_len: u64) -> axiomvault_common::Error {
    std::io::Error::new(
        std::io::ErrorKind::FileTooLarge,
        format!("{path} is longer than {max_len} bytes"),
    )
    .into()
}

/// The most the default [`StorageProvider::download_bounded`] reserves up
/// front. Exact lengths up to this read without regrowing the buffer, and a
/// generous cap (vault metadata, the shard map) is not reserved in full for
/// an object far shorter than it.
const BOUNDED_PREALLOC_MAX: u64 = 1024 * 1024;

/// Storage provider trait for different backends.
///
/// All operations are async and use streams for large data transfers.
/// Implementations must handle their own authentication and rate limiting.
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Get the provider name (e.g., "gdrive", "local", "icloud").
    fn name(&self) -> &str;

    /// Upload data to the storage.
    ///
    /// # Preconditions
    /// - Parent directory must exist
    /// - `data` is the complete content to upload
    ///
    /// # Postconditions
    /// - File is created or updated at the specified path
    /// - Returns metadata of the uploaded file
    ///
    /// # Errors
    /// - Parent directory not found
    /// - Network/I/O errors
    /// - Authentication errors
    async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata>;

    /// Upload only if the object is still the revision the caller observed.
    ///
    /// `expected_etag` is `Some(etag)` when the object must exist with that
    /// etag, and `None` when the object must not exist (create-if-absent).
    /// On a mismatch nothing is written and `Error::Conflict` is returned.
    ///
    /// The default checks `metadata` and then calls `upload`. It refuses every
    /// mismatch it observes but leaves a time-of-check to time-of-use window
    /// between the two calls. Providers that can make the check and the write
    /// one step must override it.
    async fn upload_if_match(
        &self,
        path: &VaultPath,
        data: Vec<u8>,
        expected_etag: Option<&str>,
    ) -> Result<Metadata> {
        let current = match self.metadata(path).await {
            Ok(metadata) => Some(metadata),
            Err(axiomvault_common::Error::NotFound(_)) => None,
            Err(error) => return Err(error),
        };
        check_precondition(current.as_ref(), expected_etag)?;
        self.upload(path, data).await
    }

    /// Delete only if the object is still the revision the caller observed.
    ///
    /// `expected_etag` is the etag the caller last observed; `None` means it
    /// observed none, so any existing object is a conflict. Returns
    /// `Error::NotFound` when the object is absent and `Error::Conflict`, with
    /// nothing deleted, when its revision differs.
    ///
    /// The default checks `metadata` and then calls `delete`, with the same
    /// time-of-check to time-of-use window as [`Self::upload_if_match`].
    async fn delete_if_match(&self, path: &VaultPath, expected_etag: Option<&str>) -> Result<()> {
        let current = self.metadata(path).await?;
        check_precondition(Some(&current), expected_etag)?;
        self.delete(path).await
    }

    /// Atomically replace a complete local object.
    ///
    /// Sync engines use this operation for downloaded objects and only advance
    /// ETags after it succeeds. Providers with stronger transactional primitives
    /// should override it. The default delegates to `upload`, whose contract is
    /// already all-or-error for a complete byte vector; `LocalProvider`'s upload
    /// uses same-directory write, fsync, and rename.
    async fn replace_atomic(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        self.upload(path, data).await
    }

    /// Upload data as a stream.
    ///
    /// For large files, this allows streaming without loading entire file into memory.
    async fn upload_stream(&self, path: &VaultPath, stream: ByteStream) -> Result<Metadata>;

    /// Upload a stream whose complete byte length is known in advance.
    ///
    /// Providers with resumable/chunked APIs should override this method so the
    /// transport can remain bounded-memory. The compatibility default delegates
    /// to `upload_stream`.
    async fn upload_sized_stream(
        &self,
        path: &VaultPath,
        stream: ByteStream,
        _total_size: u64,
    ) -> Result<Metadata> {
        self.upload_stream(path, stream).await
    }

    /// Download data from storage.
    ///
    /// # Preconditions
    /// - File must exist at path
    ///
    /// # Postconditions
    /// - Returns complete file content
    ///
    /// # Errors
    /// - File not found
    /// - Network/I/O errors
    async fn download(&self, path: &VaultPath) -> Result<Vec<u8>>;

    /// Download bytes together with metadata for the same stable revision.
    ///
    /// Providers with an atomic revision API should override this method. The
    /// compatibility implementation validates that metadata is unchanged
    /// across the download and fails with a retryable conflict otherwise.
    async fn download_with_metadata(&self, path: &VaultPath) -> Result<VersionedDownload> {
        let before = self.metadata(path).await?;
        let data = self.download(path).await?;
        let after = self.metadata(path).await?;
        if before.etag != after.etag {
            return Err(axiomvault_common::Error::Conflict(
                "remote object changed during download".to_string(),
            ));
        }
        Ok(VersionedDownload {
            data,
            metadata: after,
        })
    }

    /// Download data as a stream.
    ///
    /// For large files, this allows streaming without loading entire file into memory.
    async fn download_stream(&self, path: &VaultPath) -> Result<ByteStream>;

    /// Download an object that must be at most `max_len` bytes long.
    ///
    /// Returns the complete object, or an `Error::Io` of kind
    /// [`FileTooLarge`](std::io::ErrorKind::FileTooLarge) as soon as the
    /// object is known to be longer, so a backend can't make the caller hold
    /// more than `max_len` bytes plus one read-ahead chunk. A shorter object
    /// is returned as is; callers that expect an exact length check it.
    ///
    /// The default reads [`download_stream`](Self::download_stream) into a
    /// buffer preallocated to `max_len` (at most 1 MiB) and stops at the first
    /// chunk that runs past it. Providers that can read a small object in one
    /// step should override it.
    async fn download_bounded(&self, path: &VaultPath, max_len: u64) -> Result<Vec<u8>> {
        use futures::StreamExt;
        let mut download = self.download_stream(path).await?;
        let mut data =
            Vec::with_capacity(usize::try_from(max_len.min(BOUNDED_PREALLOC_MAX)).unwrap_or(0));
        while let Some(chunk) = download.next().await {
            let chunk = chunk?;
            if chunk.len() as u64 > max_len - data.len() as u64 {
                return Err(too_long(path, max_len));
            }
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }

    /// Check if a path exists.
    async fn exists(&self, path: &VaultPath) -> Result<bool>;

    /// Delete a file.
    ///
    /// # Errors
    /// - File not found
    /// - Not permitted (e.g., directory)
    async fn delete(&self, path: &VaultPath) -> Result<()>;

    /// Like [`upload`](Self::upload), but the new directory entry may not be
    /// durable until [`sync_parent_dir`](Self::sync_parent_dir) of the path,
    /// or any later durable change in the same directory. The content itself
    /// is durable. The default is a durable upload.
    async fn upload_unsynced(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        self.upload(path, data).await
    }

    /// Like [`delete`](Self::delete), with the removal durable only as
    /// [`upload_unsynced`](Self::upload_unsynced) describes. The default is a
    /// durable delete.
    async fn delete_unsynced(&self, path: &VaultPath) -> Result<()> {
        self.delete(path).await
    }

    /// Make every directory entry change in the parent directory of `path`
    /// durable. Providers whose mutations are durable when they return need
    /// nothing here.
    async fn sync_parent_dir(&self, _path: &VaultPath) -> Result<()> {
        Ok(())
    }

    /// List contents of a directory.
    ///
    /// # Preconditions
    /// - Path must be a directory
    ///
    /// # Returns
    /// Vector of metadata for each item in the directory.
    async fn list(&self, path: &VaultPath) -> Result<Vec<Metadata>>;

    /// Get metadata for a path.
    ///
    /// # Errors
    /// - Path not found
    async fn metadata(&self, path: &VaultPath) -> Result<Metadata>;

    /// Create a directory.
    ///
    /// # Postconditions
    /// - Directory is created (including parents if needed)
    ///
    /// # Errors
    /// - Already exists as file
    /// - Permission denied
    async fn create_dir(&self, path: &VaultPath) -> Result<Metadata>;

    /// Delete a directory.
    ///
    /// # Preconditions
    /// - Directory must be empty (or recursive=true)
    async fn delete_dir(&self, path: &VaultPath) -> Result<()>;

    /// Move/rename a path.
    async fn rename(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata>;

    /// Copy a path.
    async fn copy(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata>;
}

/// Extension trait for conflict detection.
#[async_trait]
pub trait ConflictAware: StorageProvider {
    /// Check if there's a conflict with the remote version.
    ///
    /// Uses etag/revision comparison to detect conflicts.
    async fn has_conflict(&self, path: &VaultPath, local_etag: &str) -> Result<bool>;

    /// Resolve a conflict using the specified strategy.
    async fn resolve_conflict(
        &self,
        path: &VaultPath,
        local_data: Vec<u8>,
        strategy: ConflictResolution,
    ) -> Result<Metadata>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_serialization() {
        let metadata = Metadata {
            id: "test-id".to_string(),
            name: "test-file.txt".to_string(),
            size: Some(1024),
            is_directory: false,
            modified: Utc::now(),
            etag: Some("abc123".to_string()),
            provider_data: None,
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: Metadata = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, metadata.id);
        assert_eq!(deserialized.name, metadata.name);
        assert_eq!(deserialized.size, metadata.size);
    }
}
