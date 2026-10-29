//! Local filesystem storage provider.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;

use crate::provider::{check_precondition, too_long, ByteStream, Metadata, StorageProvider};
use axiomvault_common::{Error, Result, VaultPath};

/// Serialises every commit that replaces or removes a file in this process,
/// so a revision check and the rename or unlink it guards are one step.
static COMMIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn commit_lock() -> std::sync::MutexGuard<'static, ()> {
    COMMIT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// How a synced temporary file is committed to its target path.
enum Commit<'a> {
    /// Replace whatever is at the target.
    Replace,
    /// Commit only if the target is at this revision; `None` means absent.
    IfMatch(Option<&'a str>),
}

/// File mode for vault files (owner read/write only).
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;
/// Directory mode for vault directories (owner read/write/execute only).
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// Local filesystem storage provider.
///
/// Stores vault data in a local directory structure.
pub struct LocalProvider {
    root: PathBuf,
}

impl LocalProvider {
    /// Create a new local provider with the given root directory.
    ///
    /// # Preconditions
    /// - Root path must be a valid directory path
    ///
    /// # Postconditions
    /// - Provider is ready to use
    /// - Root directory is created if it doesn't exist
    /// - On Unix, a newly created root directory is restricted to mode `0o700`
    ///
    /// # Errors
    /// - Invalid path
    /// - Permission denied
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();

        // Never follow or chmod a symlink supplied as the provider root.
        if let Ok(meta) = std::fs::symlink_metadata(&root) {
            if meta.file_type().is_symlink() {
                return Err(Error::NotPermitted(
                    "local provider root must not be a symlink".to_string(),
                ));
            }
            if !meta.is_dir() {
                return Err(Error::InvalidInput(
                    "local provider root must be a directory".to_string(),
                ));
            }
        }

        // Create root if it doesn't exist (sync for constructor).
        // On Unix, restrict mode to 0o700 so other local users cannot read
        // wrapped keys, KDF parameters, or ciphertext sitting at rest.
        if !root.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(DIR_MODE)
                    .create(&root)?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(&root)?;
            }
        }

        // Defense in depth: if the root already existed (or an adversary
        // pre-created it in the gap between `exists()` and `create`), we
        // never applied DIR_MODE. With `recursive(true)`, `create` succeeds
        // silently against a pre-existing weak-mode directory. Read the
        // actual mode now and repair it if it differs. This does NOT close
        // the creation race, but it ensures any adversary's pre-emptive
        // weak-mode directory gets re-permissioned before we trust it for
        // wrapped keys / KDF parameters / ciphertext.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::symlink_metadata(&root)?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(Error::NotPermitted(
                    "local provider root changed or is a symlink".to_string(),
                ));
            }
            let current_mode = meta.permissions().mode() & 0o777;
            if current_mode != DIR_MODE {
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(DIR_MODE))?;
            }
        }

        Ok(Self { root })
    }

    /// Resolve a vault path while rejecting symlink roots and components at
    /// each operation boundary.
    fn checked_fs_path(&self, path: &VaultPath) -> Result<PathBuf> {
        let root_meta = std::fs::symlink_metadata(&self.root)?;
        if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
            return Err(Error::NotPermitted(
                "local provider root changed or is a symlink".to_string(),
            ));
        }

        let mut fs_path = self.root.clone();
        for component in path.components() {
            fs_path.push(component);
            match std::fs::symlink_metadata(&fs_path) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(Error::NotPermitted(format!(
                        "local provider path contains a symlink: {path}"
                    )));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(fs_path)
    }

    /// Persist directory-entry changes before reporting a durable mutation.
    async fn sync_parent(path: &Path) -> Result<()> {
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            fs::File::open(parent).await?.sync_all().await?;
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }

    /// Create metadata from filesystem metadata.
    fn create_metadata(&self, path: &VaultPath, fs_meta: std::fs::Metadata) -> Metadata {
        let modified: DateTime<Utc> = fs_meta
            .modified()
            .map(|t| t.into())
            .unwrap_or_else(|_| Utc::now());

        // Every write commits a fresh inode by rename or link, so the inode
        // plus nanosecond mtime and length identifies a revision. The former
        // whole-second mtime and length matched two same-length writes in
        // the same second, which defeats conditional writes.
        let mtime_nanos = fs_meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_nanos());
        #[cfg(unix)]
        let etag = {
            use std::os::unix::fs::MetadataExt;
            format!("{}-{}-{}", mtime_nanos, fs_meta.len(), fs_meta.ino())
        };
        #[cfg(not(unix))]
        let etag = format!("{}-{}", mtime_nanos, fs_meta.len());

        Metadata {
            id: Uuid::new_v4().to_string(),
            name: path.name().unwrap_or("/").to_string(),
            size: if fs_meta.is_file() {
                Some(fs_meta.len())
            } else {
                None
            },
            is_directory: fs_meta.is_dir(),
            modified,
            etag: Some(etag),
            provider_data: None,
        }
    }

    /// Metadata of the object now at `fs_path`, or `None` when absent.
    fn current_metadata(&self, path: &VaultPath, fs_path: &Path) -> Result<Option<Metadata>> {
        match std::fs::symlink_metadata(fs_path) {
            Ok(fs_meta) => Ok(Some(self.create_metadata(path, fs_meta))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Move a synced temporary file onto its target, removing the temporary
    /// file on any failure.
    ///
    /// Create-if-absent uses `hard_link`, which refuses an existing target
    /// atomically, so it is exact even against other processes. A revision
    /// precondition is checked and committed under `COMMIT_LOCK`, which every
    /// replacing write and delete in this process also takes, so it is exact
    /// against writers in this process. Writers in other processes do not take
    /// the lock and can still replace the file between check and rename.
    fn commit_temp(
        &self,
        path: &VaultPath,
        fs_path: &Path,
        tmp_path: &Path,
        commit: Commit<'_>,
    ) -> Result<()> {
        let result = match commit {
            Commit::IfMatch(None) => match std::fs::hard_link(tmp_path, fs_path) {
                Ok(()) => std::fs::remove_file(tmp_path).map_err(Error::from),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    Err(Error::Conflict(format!("object already exists: {path}")))
                }
                Err(error) => Err(error.into()),
            },
            Commit::IfMatch(Some(expected)) => {
                let _guard = commit_lock();
                self.current_metadata(path, fs_path)
                    .and_then(|current| check_precondition(current.as_ref(), Some(expected)))
                    .and_then(|()| std::fs::rename(tmp_path, fs_path).map_err(Error::from))
            }
            Commit::Replace => {
                let _guard = commit_lock();
                std::fs::rename(tmp_path, fs_path).map_err(Error::from)
            }
        };
        if result.is_err() {
            let _ = std::fs::remove_file(tmp_path);
        }
        result
    }

    /// Delete a file, optionally only if it is still at `expected` revision,
    /// and sync the directory when `sync` is set.
    async fn delete_file(
        &self,
        path: &VaultPath,
        expected: Option<Option<&str>>,
        sync: bool,
    ) -> Result<()> {
        let fs_path = self.checked_fs_path(path)?;
        {
            let _guard = commit_lock();
            let current = self
                .current_metadata(path, &fs_path)?
                .ok_or_else(|| Error::NotFound(format!("File not found: {}", path)))?;
            if current.is_directory {
                return Err(Error::InvalidInput(
                    "Use delete_dir for directories".to_string(),
                ));
            }
            if let Some(expected) = expected {
                check_precondition(Some(&current), expected)?;
            }
            std::fs::remove_file(&fs_path)?;
        }
        if sync {
            Self::sync_parent(&fs_path).await?;
        }
        Ok(())
    }

    /// Write `data` to a synced temporary file in the target directory, then
    /// commit it to `path` as `commit` allows, and sync the directory when
    /// `sync` is set.
    async fn write_file(
        &self,
        path: &VaultPath,
        data: Vec<u8>,
        commit: Commit<'_>,
        sync: bool,
    ) -> Result<Metadata> {
        let fs_path = self.checked_fs_path(path)?;

        // Check parent exists
        if let Some(parent) = fs_path.parent() {
            if !parent.exists() {
                return Err(Error::NotFound("Parent directory not found".to_string()));
            }
        }

        // Write atomically: write to a temp file in the same directory, then rename.
        // This prevents partial/corrupt files if the process is interrupted mid-write.
        let parent_dir = fs_path
            .parent()
            .ok_or_else(|| Error::InvalidInput("Cannot write to root path".to_string()))?;
        let tmp_path = parent_dir.join(format!(
            ".{}.tmp.{}",
            fs_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file"),
            uuid::Uuid::new_v4()
        ));

        // Create the temp file with restrictive permissions on Unix so
        // other local users cannot read ciphertext or vault config that
        // contains wrapped keys / KDF parameters. On non-Unix targets we
        // fall back to the default permissions (the file will inherit
        // platform defaults).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            use tokio::io::AsyncWriteExt;

            // tokio::fs::OpenOptions exposes `mode()` directly on Unix
            // (cfg-gated to the unix targets), so no extension trait
            // import is required.
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(FILE_MODE)
                .open(&tmp_path)
                .await?;
            tokio::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(FILE_MODE))
                .await?;
            if let Err(e) = file.write_all(&data).await {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e.into());
            }
            if let Err(e) = file.sync_all().await {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e.into());
            }
        }
        #[cfg(not(unix))]
        {
            // Match the Unix branch's durability semantics: explicit
            // create -> write_all -> sync_all. `fs::write` skips the
            // fsync, so on power loss the rename target could resolve to
            // a zero-length file. Keep both platforms aligned.
            use tokio::io::AsyncWriteExt;
            let mut file = fs::File::create(&tmp_path).await?;
            if let Err(e) = file.write_all(&data).await {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e.into());
            }
            if let Err(e) = file.sync_all().await {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e.into());
            }
        }

        // Take the revision from the synced temp file: rename and link keep
        // its inode, size and mtime, so the etag returned is the one written
        // even if another writer replaces the target right after the commit.
        let metadata = match std::fs::metadata(&tmp_path) {
            Ok(fs_meta) => self.create_metadata(path, fs_meta),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e.into());
            }
        };
        self.commit_temp(path, &fs_path, &tmp_path, commit)?;

        if sync {
            Self::sync_parent(&fs_path).await?;
        }
        Ok(metadata)
    }
}

#[async_trait]
impl StorageProvider for LocalProvider {
    fn name(&self) -> &str {
        "local"
    }

    async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        self.write_file(path, data, Commit::Replace, true).await
    }

    async fn upload_unsynced(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        self.write_file(path, data, Commit::Replace, false).await
    }

    async fn delete_unsynced(&self, path: &VaultPath) -> Result<()> {
        self.delete_file(path, None, false).await
    }

    async fn sync_parent_dir(&self, path: &VaultPath) -> Result<()> {
        Self::sync_parent(&self.checked_fs_path(path)?).await
    }

    async fn upload_if_match(
        &self,
        path: &VaultPath,
        data: Vec<u8>,
        expected_etag: Option<&str>,
    ) -> Result<Metadata> {
        self.write_file(path, data, Commit::IfMatch(expected_etag), true)
            .await
    }

    async fn delete_if_match(&self, path: &VaultPath, expected_etag: Option<&str>) -> Result<()> {
        self.delete_file(path, Some(expected_etag), true).await
    }

    async fn upload_stream(&self, path: &VaultPath, mut stream: ByteStream) -> Result<Metadata> {
        use futures::StreamExt;
        use tokio::io::AsyncWriteExt;

        let fs_path = self.checked_fs_path(path)?;
        let parent_dir = fs_path
            .parent()
            .ok_or_else(|| Error::InvalidInput("Cannot write to root path".to_string()))?;
        if !parent_dir.exists() {
            return Err(Error::NotFound("Parent directory not found".to_string()));
        }
        let tmp_path = parent_dir.join(format!(
            ".{}.tmp.{}",
            fs_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("file"),
            Uuid::new_v4()
        ));

        #[cfg(unix)]
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&tmp_path)
            .await?;
        #[cfg(not(unix))]
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;

        let write_result: Result<()> = async {
            while let Some(chunk) = stream.next().await {
                file.write_all(&chunk?).await?;
                file.flush().await?;
            }
            file.sync_all().await?;
            Ok(())
        }
        .await;
        if let Err(error) = write_result {
            let _ = fs::remove_file(&tmp_path).await;
            return Err(error);
        }
        let metadata = match std::fs::metadata(&tmp_path) {
            Ok(fs_meta) => self.create_metadata(path, fs_meta),
            Err(error) => {
                let _ = fs::remove_file(&tmp_path).await;
                return Err(error.into());
            }
        };
        self.commit_temp(path, &fs_path, &tmp_path, Commit::Replace)?;
        Self::sync_parent(&fs_path).await?;
        Ok(metadata)
    }

    async fn download(&self, path: &VaultPath) -> Result<Vec<u8>> {
        let fs_path = self.checked_fs_path(path)?;

        if !fs_path.exists() {
            return Err(Error::NotFound(format!("File not found: {}", path)));
        }

        if fs_path.is_dir() {
            return Err(Error::InvalidInput("Cannot download directory".to_string()));
        }

        Ok(fs::read(&fs_path).await?)
    }

    async fn download_stream(&self, path: &VaultPath) -> Result<ByteStream> {
        use futures::StreamExt;

        let fs_path = self.checked_fs_path(path)?;
        if !fs_path.exists() {
            return Err(Error::NotFound(format!("File not found: {}", path)));
        }
        if fs_path.is_dir() {
            return Err(Error::InvalidInput("Cannot download directory".to_string()));
        }
        let file = fs::File::open(fs_path).await?;
        let stream = tokio_util::io::ReaderStream::with_capacity(file, 64 * 1024)
            .map(|result| result.map(|bytes| bytes.to_vec()).map_err(Error::from));
        Ok(Box::pin(stream))
    }

    async fn download_bounded(&self, path: &VaultPath, max_len: u64) -> Result<Vec<u8>> {
        use std::io::Read;

        let fs_path = self.checked_fs_path(path)?;
        if !fs_path.exists() {
            return Err(Error::NotFound(format!("File not found: {}", path)));
        }
        if fs_path.is_dir() {
            return Err(Error::InvalidInput("Cannot download directory".to_string()));
        }
        // One blocking-pool hop for the whole object: a stream takes one per
        // chunk plus the open, which dominates the cost of small reads.
        let path = path.clone();
        tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(&fs_path)?;
            let len = file.metadata()?.len();
            if len > max_len {
                return Err(too_long(&path, max_len));
            }
            let mut data = Vec::with_capacity(len as usize);
            // The file may have grown since the stat.
            file.take(max_len.saturating_add(1))
                .read_to_end(&mut data)?;
            if data.len() as u64 > max_len {
                return Err(too_long(&path, max_len));
            }
            Ok(data)
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking join error: {}", e)))?
    }

    async fn exists(&self, path: &VaultPath) -> Result<bool> {
        let fs_path = self.checked_fs_path(path)?;
        Ok(fs_path.exists())
    }

    async fn delete(&self, path: &VaultPath) -> Result<()> {
        self.delete_file(path, None, true).await
    }

    async fn list(&self, path: &VaultPath) -> Result<Vec<Metadata>> {
        let fs_path = self.checked_fs_path(path)?;

        if !fs_path.exists() {
            return Err(Error::NotFound(format!("Directory not found: {}", path)));
        }

        if !fs_path.is_dir() {
            return Err(Error::InvalidInput("Not a directory".to_string()));
        }

        let mut results = Vec::new();
        let mut entries = fs::read_dir(&fs_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let entry_path = entry.path();
            let name = entry_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();

            let child_vault_path = path.join(&name)?;
            let fs_meta = entry.metadata().await?;
            results.push(self.create_metadata(&child_vault_path, fs_meta));
        }

        Ok(results)
    }

    async fn metadata(&self, path: &VaultPath) -> Result<Metadata> {
        let fs_path = self.checked_fs_path(path)?;

        if !fs_path.exists() {
            return Err(Error::NotFound(format!("Path not found: {}", path)));
        }

        let fs_meta = fs::metadata(&fs_path).await?;
        Ok(self.create_metadata(path, fs_meta))
    }

    async fn create_dir(&self, path: &VaultPath) -> Result<Metadata> {
        let fs_path = self.checked_fs_path(path)?;

        if fs_path.exists() {
            return Err(Error::AlreadyExists(format!(
                "Path already exists: {}",
                path
            )));
        }

        // On Unix, set the mode atomically at directory creation via
        // `DirBuilder::mode` instead of `create_dir` followed by
        // `set_permissions`. The latter leaves a brief window where the
        // directory exists with umask-affected permissions and another
        // local user could enter or list it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            let fs_path_blocking = fs_path.clone();
            tokio::task::spawn_blocking(move || {
                std::fs::DirBuilder::new()
                    .mode(DIR_MODE)
                    .create(&fs_path_blocking)?;
                std::fs::set_permissions(
                    &fs_path_blocking,
                    std::fs::Permissions::from_mode(DIR_MODE),
                )
            })
            .await
            .map_err(|e| Error::Storage(format!("spawn_blocking join error: {}", e)))??;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir(&fs_path).await?;
        }

        Self::sync_parent(&fs_path).await?;
        let fs_meta = fs::metadata(&fs_path).await?;
        Ok(self.create_metadata(path, fs_meta))
    }

    async fn delete_dir(&self, path: &VaultPath) -> Result<()> {
        let fs_path = self.checked_fs_path(path)?;

        if !fs_path.exists() {
            return Err(Error::NotFound(format!("Directory not found: {}", path)));
        }

        if !fs_path.is_dir() {
            return Err(Error::InvalidInput("Not a directory".to_string()));
        }

        // Check if empty
        let mut entries = fs::read_dir(&fs_path).await?;
        if entries.next_entry().await?.is_some() {
            return Err(Error::InvalidInput("Directory not empty".to_string()));
        }

        fs::remove_dir(&fs_path).await?;
        Self::sync_parent(&fs_path).await?;
        Ok(())
    }

    async fn rename(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
        let from_path = self.checked_fs_path(from)?;
        let to_path = self.checked_fs_path(to)?;

        if !from_path.exists() {
            return Err(Error::NotFound(format!("Source not found: {}", from)));
        }

        if to_path.exists() {
            return Err(Error::AlreadyExists(format!(
                "Destination already exists: {}",
                to
            )));
        }

        fs::rename(&from_path, &to_path).await?;
        Self::sync_parent(&from_path).await?;

        Self::sync_parent(&to_path).await?;
        let fs_meta = fs::metadata(&to_path).await?;
        Ok(self.create_metadata(to, fs_meta))
    }

    async fn copy(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
        let from_path = self.checked_fs_path(from)?;
        let to_path = self.checked_fs_path(to)?;

        if !from_path.exists() {
            return Err(Error::NotFound(format!("Source not found: {}", from)));
        }

        if to_path.exists() {
            return Err(Error::AlreadyExists(format!(
                "Destination already exists: {}",
                to
            )));
        }

        if from_path.is_dir() {
            // Create the destination directory with restrictive mode set
            // atomically at creation (Unix). Avoids the TOCTOU window where
            // `create_dir` followed by `set_permissions` would briefly
            // expose the new directory at the umask-affected mode.
            #[cfg(unix)]
            {
                use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
                let to_blocking = to_path.clone();
                tokio::task::spawn_blocking(move || {
                    std::fs::DirBuilder::new()
                        .mode(DIR_MODE)
                        .create(&to_blocking)?;
                    std::fs::set_permissions(
                        &to_blocking,
                        std::fs::Permissions::from_mode(DIR_MODE),
                    )
                })
                .await
                .map_err(|e| Error::Storage(format!("spawn_blocking join error: {}", e)))??;
            }
            #[cfg(not(unix))]
            {
                fs::create_dir(&to_path).await?;
            }
        } else {
            // Stream the source into a freshly-created destination instead of
            // loading the whole vault object into memory. The Unix path keeps
            // restrictive creation mode and then repairs exact bits in case a
            // restrictive umask removed owner permissions.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut source = fs::File::open(&from_path).await?;
                let mut destination = tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(FILE_MODE)
                    .open(&to_path)
                    .await?;
                tokio::fs::set_permissions(&to_path, std::fs::Permissions::from_mode(FILE_MODE))
                    .await?;
                if let Err(e) = tokio::io::copy(&mut source, &mut destination).await {
                    let _ = std::fs::remove_file(&to_path);
                    return Err(e.into());
                }
                if let Err(e) = destination.sync_all().await {
                    let _ = std::fs::remove_file(&to_path);
                    return Err(e.into());
                }
            }
            #[cfg(not(unix))]
            {
                let mut source = fs::File::open(&from_path).await?;
                let mut destination = fs::File::create_new(&to_path).await?;
                if let Err(e) = tokio::io::copy(&mut source, &mut destination).await {
                    let _ = std::fs::remove_file(&to_path);
                    return Err(e.into());
                }
                if let Err(e) = destination.sync_all().await {
                    let _ = std::fs::remove_file(&to_path);
                    return Err(e.into());
                }
            }
        }

        Self::sync_parent(&to_path).await?;
        let fs_meta = fs::metadata(&to_path).await?;
        Ok(self.create_metadata(to, fs_meta))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn unsynced_writes_and_deletes_commit_like_synced_ones() {
        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let dir = VaultPath::parse("/m").unwrap();
        provider.create_dir(&dir).await.unwrap();
        let path = dir.join("object").unwrap();

        provider
            .upload_unsynced(&path, b"first".to_vec())
            .await
            .unwrap();
        provider
            .upload_unsynced(&path, b"second".to_vec())
            .await
            .unwrap();
        provider.sync_parent_dir(&path).await.unwrap();
        assert_eq!(provider.download(&path).await.unwrap(), b"second");
        assert_eq!(provider.list(&dir).await.unwrap().len(), 1);

        provider.delete_unsynced(&path).await.unwrap();
        assert!(!provider.exists(&path).await.unwrap());
        assert!(provider.delete_unsynced(&path).await.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_root_is_rejected_without_chmodding_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = temp.path().join("root-link");
        symlink(&target, &root).unwrap();

        assert!(LocalProvider::new(&root).is_err());
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "symlink target permissions must not change");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn operation_rejects_symlink_component_inserted_after_construction() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let provider = LocalProvider::new(&root).unwrap();
        symlink(&outside, root.join("swapped")).unwrap();

        let path = VaultPath::parse("/swapped/escape.bin").unwrap();
        assert!(provider.upload(&path, b"secret".to_vec()).await.is_err());
        assert!(!outside.join("escape.bin").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn operation_rejects_root_replaced_by_symlink_after_construction() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        let moved = temp.path().join("moved-root");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let provider = LocalProvider::new(&root).unwrap();
        std::fs::rename(&root, &moved).unwrap();
        symlink(&outside, &root).unwrap();

        assert!(provider
            .upload(
                &VaultPath::parse("/escape.bin").unwrap(),
                b"secret".to_vec()
            )
            .await
            .is_err());
        assert!(!outside.join("escape.bin").exists());
    }

    #[tokio::test]
    async fn test_local_upload_download() {
        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let path = VaultPath::parse("/test.txt").unwrap();
        let data = b"Hello, Local!".to_vec();

        provider.upload(&path, data.clone()).await.unwrap();
        let downloaded = provider.download(&path).await.unwrap();

        assert_eq!(downloaded, data);
    }

    fn is_too_long(error: &Error) -> bool {
        matches!(error, Error::Io(e) if e.kind() == std::io::ErrorKind::FileTooLarge)
    }

    #[tokio::test]
    async fn download_bounded_reads_only_objects_within_the_bound() {
        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let path = VaultPath::parse("/blob").unwrap();
        provider.upload(&path, vec![7; 4096]).await.unwrap();

        for max_len in [4096, 4097, 1 << 30] {
            let data = provider.download_bounded(&path, max_len).await.unwrap();
            assert_eq!(data, vec![7; 4096]);
            // Sized from the file, not from the bound.
            assert_eq!(data.capacity(), 4096);
        }
        for max_len in [0, 4095] {
            let error = provider.download_bounded(&path, max_len).await.unwrap_err();
            assert!(is_too_long(&error), "{error}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn download_bounded_stops_at_the_bound_when_the_file_outgrows_its_stat() {
        use std::io::Write;

        // A FIFO stats as empty and then yields whatever is written to it.
        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let fifo = temp.path().join("growing");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let writer = std::thread::spawn(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(fifo)
                .unwrap()
                .write_all(&vec![0; 16 * 1024 * 1024])
        });

        let error = provider
            .download_bounded(&VaultPath::parse("/growing").unwrap(), 4096)
            .await
            .unwrap_err();
        assert!(is_too_long(&error), "{error}");
        // The reader hung up long before the writer was done.
        let write = writer.join().unwrap();
        assert_eq!(write.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn test_local_create_dir() {
        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let path = VaultPath::parse("/mydir").unwrap();

        let metadata = provider.create_dir(&path).await.unwrap();
        assert!(metadata.is_directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_local_upload_sets_restrictive_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let path = VaultPath::parse("/secret.bin").unwrap();
        provider
            .upload(&path, b"ciphertext".to_vec())
            .await
            .unwrap();

        let fs_path = temp.path().join("secret.bin");
        let mode = std::fs::metadata(&fs_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "uploaded file must be owner-only readable");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_local_create_dir_sets_restrictive_dir_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let path = VaultPath::parse("/private").unwrap();
        provider.create_dir(&path).await.unwrap();

        let fs_path = temp.path().join("private");
        let mode = std::fs::metadata(&fs_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "created directory must be owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn test_local_new_creates_root_with_restrictive_dir_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("vault-root");
        assert!(!root.exists());
        LocalProvider::new(&root).unwrap();

        let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "newly created vault root must be owner-only");
    }

    /// Defense-in-depth: when the root directory already exists (e.g. an
    /// adversary pre-created it with a permissive mode in the gap between
    /// our `exists()` check and our `DirBuilder::create`, or it was just
    /// left over from a prior run with the wrong mode), `LocalProvider::new`
    /// must repair the mode to `DIR_MODE` (0o700) before returning.
    #[cfg(unix)]
    #[test]
    fn test_local_new_repairs_pre_existing_root_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("vault-root");

        // Pre-create the root with a world-readable mode, simulating either
        // a leftover directory or an adversary winning the TOCTOU race.
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pre_mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(pre_mode, 0o755, "test setup must produce 0o755");

        LocalProvider::new(&root).unwrap();

        let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "pre-existing root with weak mode must be repaired to 0o700"
        );
    }

    /// Audit hardening: `copy` of a regular file must produce a destination
    /// with mode `0o600` from the moment of creation. The pre-fix
    /// implementation used `fs::copy` then `set_permissions`, leaving a
    /// TOCTOU window where another local user could open the destination at
    /// the umask-affected mode.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_local_copy_file_sets_restrictive_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let src = VaultPath::parse("/src.bin").unwrap();
        let dst = VaultPath::parse("/dst.bin").unwrap();
        provider.upload(&src, b"ciphertext".to_vec()).await.unwrap();
        provider.copy(&src, &dst).await.unwrap();

        let fs_path = temp.path().join("dst.bin");
        let mode = std::fs::metadata(&fs_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "copied file must be owner-only readable");

        // Content must still match.
        let copied = provider.download(&dst).await.unwrap();
        assert_eq!(copied, b"ciphertext");
    }

    /// Audit hardening: `copy` of a directory must produce a destination
    /// with mode `0o700` set atomically at creation (no TOCTOU window).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_local_copy_dir_sets_restrictive_dir_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let src = VaultPath::parse("/srcdir").unwrap();
        let dst = VaultPath::parse("/dstdir").unwrap();
        provider.create_dir(&src).await.unwrap();
        provider.copy(&src, &dst).await.unwrap();

        let fs_path = temp.path().join("dstdir");
        let mode = std::fs::metadata(&fs_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "copied directory must be owner-only");
    }

    #[tokio::test]
    async fn test_local_list() {
        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();

        provider
            .create_dir(&VaultPath::parse("/dir").unwrap())
            .await
            .unwrap();
        provider
            .upload(&VaultPath::parse("/dir/file1.txt").unwrap(), vec![1])
            .await
            .unwrap();
        provider
            .upload(&VaultPath::parse("/dir/file2.txt").unwrap(), vec![2])
            .await
            .unwrap();

        let contents = provider
            .list(&VaultPath::parse("/dir").unwrap())
            .await
            .unwrap();
        assert_eq!(contents.len(), 2);
    }

    /// Audit M-17: conditional writes and deletes refuse a stale revision
    /// and leave the newer one in place; create-if-absent never replaces.
    #[tokio::test]
    async fn test_local_conditional_write_and_delete_refuse_stale_revision() {
        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let path = VaultPath::parse("/test.txt").unwrap();

        let created = provider
            .upload_if_match(&path, b"a".to_vec(), None)
            .await
            .unwrap();
        assert_eq!(provider.metadata(&path).await.unwrap().etag, created.etag);
        assert!(matches!(
            provider.upload_if_match(&path, b"x".to_vec(), None).await,
            Err(Error::Conflict(_))
        ));
        // Same length, written straight away: must still be a new revision.
        let stale = created.etag.unwrap();
        let newer = provider
            .upload_if_match(&path, b"b".to_vec(), Some(&stale))
            .await
            .unwrap();
        assert_ne!(newer.etag.as_deref(), Some(stale.as_str()));
        assert!(matches!(
            provider
                .upload_if_match(&path, b"x".to_vec(), Some(&stale))
                .await,
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            provider.delete_if_match(&path, Some(&stale)).await,
            Err(Error::Conflict(_))
        ));
        assert_eq!(provider.download(&path).await.unwrap(), b"b");

        provider
            .delete_if_match(&path, newer.etag.as_deref())
            .await
            .unwrap();
        assert!(matches!(
            provider.delete_if_match(&path, newer.etag.as_deref()).await,
            Err(Error::NotFound(_))
        ));
        // Refused and committed writes leave no temporary files behind.
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    /// Same-length plain uploads in quick succession get distinct etags.
    #[tokio::test]
    async fn test_local_same_length_rewrites_get_distinct_etags() {
        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let path = VaultPath::parse("/test.txt").unwrap();
        let first = provider.upload(&path, b"one".to_vec()).await.unwrap();
        let second = provider.upload(&path, b"two".to_vec()).await.unwrap();
        assert_ne!(first.etag, second.etag);
        assert_eq!(provider.metadata(&path).await.unwrap().etag, second.etag);
    }

    struct BackpressureProbe {
        root: PathBuf,
        state: u8,
    }

    impl futures::Stream for BackpressureProbe {
        type Item = Result<Vec<u8>>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            match self.state {
                0 => {
                    self.state = 1;
                    std::task::Poll::Ready(Some(Ok(vec![0x5a; 64 * 1024])))
                }
                1 => {
                    self.state = 2;
                    let written = std::fs::read_dir(&self.root)
                        .ok()
                        .into_iter()
                        .flatten()
                        .filter_map(std::result::Result::ok)
                        .any(|entry| entry.metadata().map(|m| m.len() > 0).unwrap_or(false));
                    if written {
                        std::task::Poll::Ready(Some(Ok(vec![0x6b; 64 * 1024])))
                    } else {
                        std::task::Poll::Ready(Some(Err(Error::Storage(
                            "producer polled before prior chunk was written".to_string(),
                        ))))
                    }
                }
                _ => std::task::Poll::Ready(None),
            }
        }
    }

    #[tokio::test]
    async fn upload_stream_preserves_backpressure() {
        let temp = TempDir::new().unwrap();
        let provider = LocalProvider::new(temp.path()).unwrap();
        let path = VaultPath::parse("/large.bin").unwrap();
        let stream: ByteStream = Box::pin(BackpressureProbe {
            root: temp.path().to_path_buf(),
            state: 0,
        });

        provider.upload_stream(&path, stream).await.unwrap();
        assert_eq!(
            provider.metadata(&path).await.unwrap().size,
            Some(128 * 1024)
        );
    }
}
