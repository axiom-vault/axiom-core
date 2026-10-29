//! Audit M-17: sync uploads, deletes and keep-both copies must not overwrite
//! or delete a remote revision this side has not seen.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axiomvault_common::{Result, VaultPath};
use axiomvault_storage::{ByteStream, LocalProvider, MemoryProvider, Metadata, StorageProvider};
use axiomvault_sync::{ChangeType, ConflictStrategy, SyncConfig, SyncEngine, SyncStatus};
use tempfile::TempDir;

fn path(value: &str) -> VaultPath {
    VaultPath::parse(value).unwrap()
}

/// Wraps a provider to interleave a second writer at chosen points.
struct Racer {
    inner: Arc<dyn StorageProvider>,
    /// Writer B: after the next `metadata` of this path, write these bytes.
    write_after_metadata: Mutex<Option<(VaultPath, Vec<u8>)>>,
    /// A concurrent creator: on the first touch of a conflict-copy name,
    /// create these bytes there before the call proceeds.
    plant_conflict_name: Mutex<Option<Vec<u8>>>,
    planted_at: Mutex<Option<VaultPath>>,
    strip_etags: bool,
}

impl Racer {
    fn new(inner: Arc<dyn StorageProvider>) -> Self {
        Self {
            inner,
            write_after_metadata: Mutex::new(None),
            plant_conflict_name: Mutex::new(None),
            planted_at: Mutex::new(None),
            strip_etags: false,
        }
    }

    fn without_etags(inner: Arc<dyn StorageProvider>) -> Self {
        Self {
            strip_etags: true,
            ..Self::new(inner)
        }
    }

    fn strip(&self, mut metadata: Metadata) -> Metadata {
        if self.strip_etags {
            metadata.etag = None;
        }
        metadata
    }

    async fn maybe_plant(&self, path: &VaultPath) {
        if !path.to_string().contains("_conflict_") {
            return;
        }
        let planted = self.plant_conflict_name.lock().unwrap().take();
        if let Some(bytes) = planted {
            self.inner.upload(path, bytes).await.unwrap();
            *self.planted_at.lock().unwrap() = Some(path.clone());
        }
    }

    fn planted_at(&self) -> VaultPath {
        self.planted_at
            .lock()
            .unwrap()
            .clone()
            .expect("a conflict name was planted")
    }
}

#[async_trait]
impl StorageProvider for Racer {
    fn name(&self) -> &str {
        "racer"
    }

    async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        self.maybe_plant(path).await;
        self.inner.upload(path, data).await.map(|m| self.strip(m))
    }

    // M17-NEW-API-BEGIN
    async fn upload_if_match(
        &self,
        path: &VaultPath,
        data: Vec<u8>,
        expected_etag: Option<&str>,
    ) -> Result<Metadata> {
        self.maybe_plant(path).await;
        self.inner
            .upload_if_match(path, data, expected_etag)
            .await
            .map(|m| self.strip(m))
    }

    async fn delete_if_match(&self, path: &VaultPath, expected_etag: Option<&str>) -> Result<()> {
        self.inner.delete_if_match(path, expected_etag).await
    }
    // M17-NEW-API-END

    async fn upload_stream(&self, path: &VaultPath, stream: ByteStream) -> Result<Metadata> {
        self.inner.upload_stream(path, stream).await
    }

    async fn download(&self, path: &VaultPath) -> Result<Vec<u8>> {
        self.inner.download(path).await
    }

    async fn download_stream(&self, path: &VaultPath) -> Result<ByteStream> {
        self.inner.download_stream(path).await
    }

    async fn exists(&self, path: &VaultPath) -> Result<bool> {
        self.maybe_plant(path).await;
        self.inner.exists(path).await
    }

    async fn delete(&self, path: &VaultPath) -> Result<()> {
        self.inner.delete(path).await
    }

    async fn list(&self, path: &VaultPath) -> Result<Vec<Metadata>> {
        let listed = self.inner.list(path).await?;
        Ok(listed.into_iter().map(|m| self.strip(m)).collect())
    }

    async fn metadata(&self, path: &VaultPath) -> Result<Metadata> {
        let metadata = self.inner.metadata(path).await?;
        let pending = {
            let mut armed = self.write_after_metadata.lock().unwrap();
            match armed.as_ref() {
                Some((target, _)) if target == path => armed.take(),
                _ => None,
            }
        };
        if let Some((target, bytes)) = pending {
            self.inner.upload(&target, bytes).await?;
        }
        Ok(self.strip(metadata))
    }

    async fn create_dir(&self, path: &VaultPath) -> Result<Metadata> {
        self.inner.create_dir(path).await
    }

    async fn delete_dir(&self, path: &VaultPath) -> Result<()> {
        self.inner.delete_dir(path).await
    }

    async fn rename(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
        self.inner.rename(from, to).await
    }

    async fn copy(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
        self.inner.copy(from, to).await
    }
}

async fn engine(
    remote: Arc<dyn StorageProvider>,
    local: Arc<dyn StorageProvider>,
    state_dir: &TempDir,
) -> SyncEngine<dyn StorageProvider, dyn StorageProvider> {
    SyncEngine::from_arcs(remote, local, state_dir.path(), SyncConfig::default())
        .await
        .unwrap()
}

/// (a) Writer A checks the remote revision, writer B replaces it before A's
/// upload lands. A's upload must be refused and B's bytes must survive.
async fn upload_refused_when_remote_changes_after_check(remote_inner: Arc<dyn StorageProvider>) {
    let racer = Arc::new(Racer::new(remote_inner));
    let remote: Arc<dyn StorageProvider> = racer.clone();
    let local: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let state_dir = TempDir::new().unwrap();
    let engine_a = engine(remote.clone(), local, &state_dir).await;
    let file = path("/shared.bin");

    engine_a
        .stage_change(&file, b"base".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    engine_a
        .stage_change(&file, b"from-writer-a".to_vec(), ChangeType::Update)
        .await
        .unwrap();

    *racer.write_after_metadata.lock().unwrap() = Some((file.clone(), b"from-writer-b".to_vec()));
    let result = engine_a.sync_full().await.unwrap();

    assert_eq!(
        remote.download(&file).await.unwrap(),
        b"from-writer-b",
        "writer A's upload overwrote writer B's revision"
    );
    assert_eq!(result.conflicts_found, 1);
    assert_eq!(engine_a.staging().read().await.count(), 1);
    assert_eq!(
        engine_a.state().read().await.get(&file).unwrap().status,
        SyncStatus::Conflicted
    );
}

#[tokio::test]
async fn upload_refused_when_remote_changes_after_check_memory() {
    upload_refused_when_remote_changes_after_check(Arc::new(MemoryProvider::new())).await;
}

#[tokio::test]
async fn upload_refused_when_remote_changes_after_check_local() {
    let dir = TempDir::new().unwrap();
    upload_refused_when_remote_changes_after_check(Arc::new(
        LocalProvider::new(dir.path()).unwrap(),
    ))
    .await;
}

/// (b) Writer A synced a revision and stages a delete; writer B replaces the
/// revision first. A's delete must be refused and B's bytes must survive.
async fn delete_refused_when_remote_changed(remote: Arc<dyn StorageProvider>) {
    let local: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let state_dir = TempDir::new().unwrap();
    let engine_a = engine(remote.clone(), local, &state_dir).await;
    let file = path("/shared.bin");

    engine_a
        .stage_change(&file, b"base".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    engine_a.stage_delete(&file).await.unwrap();
    remote
        .upload(&file, b"from-writer-b".to_vec())
        .await
        .unwrap();

    let result = engine_a.sync_full().await.unwrap();

    assert!(
        remote.exists(&file).await.unwrap(),
        "writer A's delete removed writer B's revision"
    );
    assert_eq!(remote.download(&file).await.unwrap(), b"from-writer-b");
    assert_eq!(result.conflicts_found, 1);
    assert_eq!(engine_a.staging().read().await.count(), 1);
    assert_eq!(
        engine_a.state().read().await.get(&file).unwrap().status,
        SyncStatus::Conflicted
    );

    // A repeated sync must not delete against the recorded conflicting
    // revision either.
    engine_a.sync_full().await.unwrap();
    assert_eq!(remote.download(&file).await.unwrap(), b"from-writer-b");
}

#[tokio::test]
async fn delete_refused_when_remote_changed_memory() {
    delete_refused_when_remote_changed(Arc::new(MemoryProvider::new())).await;
}

#[tokio::test]
async fn delete_refused_when_remote_changed_local() {
    let dir = TempDir::new().unwrap();
    delete_refused_when_remote_changed(Arc::new(LocalProvider::new(dir.path()).unwrap())).await;
}

/// Build engines A and B on one remote and leave B with a pending conflict on
/// `/shared.bin` whose remote side is "remote-wins" and local side "kept".
async fn conflicted_pair(
    remote: Arc<dyn StorageProvider>,
    local_b: Arc<dyn StorageProvider>,
    dir_a: &TempDir,
    dir_b: &TempDir,
) -> SyncEngine<dyn StorageProvider, dyn StorageProvider> {
    let local_a: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let engine_a = engine(remote.clone(), local_a, dir_a).await;
    let engine_b = engine(remote, local_b, dir_b).await;
    let file = path("/shared.bin");
    engine_a
        .stage_change(&file, b"base".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    engine_b.sync_full().await.unwrap();
    engine_a
        .stage_change(&file, b"remote-wins".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_b
        .stage_change(&file, b"kept".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    assert_eq!(engine_b.sync_full().await.unwrap().conflicts_found, 1);
    engine_b
}

async fn conflict_copies(provider: &Arc<dyn StorageProvider>) -> Vec<(String, Vec<u8>)> {
    let mut copies = Vec::new();
    for metadata in provider.list(&VaultPath::root()).await.unwrap() {
        if metadata.name.contains("_conflict_") {
            let bytes = provider
                .download(&path(&format!("/{}", metadata.name)))
                .await
                .unwrap();
            copies.push((metadata.name, bytes));
        }
    }
    copies
}

/// (c) Keep-both must not overwrite an existing file at the conflict-copy
/// name on the local side; it must pick another name.
#[tokio::test]
async fn keep_both_does_not_overwrite_existing_local_conflict_name() {
    let remote: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let racer = Arc::new(Racer::new(Arc::new(MemoryProvider::new())));
    let local_b: Arc<dyn StorageProvider> = racer.clone();
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let engine_b = conflicted_pair(remote.clone(), local_b.clone(), &dir_a, &dir_b).await;

    *racer.plant_conflict_name.lock().unwrap() = Some(b"someone-else".to_vec());
    engine_b
        .resolve_conflict(
            &path("/shared.bin"),
            b"kept".to_vec(),
            ConflictStrategy::KeepBoth,
        )
        .await
        .unwrap();

    let planted = racer.planted_at();
    assert_eq!(
        local_b.download(&planted).await.unwrap(),
        b"someone-else",
        "keep-both overwrote an existing local file at the conflict name"
    );
    let kept: Vec<_> = conflict_copies(&local_b)
        .await
        .into_iter()
        .filter(|(_, bytes)| bytes == b"kept")
        .collect();
    assert_eq!(kept.len(), 1, "the kept copy must exist under a new name");
    assert_eq!(
        remote
            .download(&path(&format!("/{}", kept[0].0)))
            .await
            .unwrap(),
        b"kept"
    );
}

/// (c) Keep-both must not overwrite an existing remote object at the
/// conflict-copy name; it must pick another name.
#[tokio::test]
async fn keep_both_does_not_overwrite_existing_remote_conflict_name() {
    let racer = Arc::new(Racer::new(Arc::new(MemoryProvider::new())));
    let remote: Arc<dyn StorageProvider> = racer.clone();
    let local_b: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let engine_b = conflicted_pair(remote.clone(), local_b.clone(), &dir_a, &dir_b).await;

    *racer.plant_conflict_name.lock().unwrap() = Some(b"someone-else".to_vec());
    engine_b
        .resolve_conflict(
            &path("/shared.bin"),
            b"kept".to_vec(),
            ConflictStrategy::KeepBoth,
        )
        .await
        .unwrap();

    let planted = racer.planted_at();
    assert_eq!(
        remote.download(&planted).await.unwrap(),
        b"someone-else",
        "keep-both overwrote an existing remote object at the conflict name"
    );
    let kept: Vec<_> = conflict_copies(&remote)
        .await
        .into_iter()
        .filter(|(_, bytes)| bytes == b"kept")
        .collect();
    assert_eq!(kept.len(), 1, "the kept copy must exist under a new name");
    assert_eq!(
        remote.download(&path("/shared.bin")).await.unwrap(),
        b"remote-wins"
    );
}

/// (d) A provider that reports no etag gives no way to prove the remote is
/// unchanged, so an existing remote object is a conflict, not "no conflict".
#[tokio::test]
async fn missing_etag_with_existing_remote_is_conflict() {
    let inner: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let remote: Arc<dyn StorageProvider> = Arc::new(Racer::without_etags(inner.clone()));
    let local: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let state_dir = TempDir::new().unwrap();
    let file = path("/shared.bin");
    inner
        .upload(&file, b"existing-remote".to_vec())
        .await
        .unwrap();
    let engine = SyncEngine::from_arcs(
        remote.clone(),
        local,
        state_dir.path(),
        SyncConfig::default(),
    )
    .await
    .unwrap();

    engine
        .stage_change(&file, b"local-create".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    let result = engine.sync_full().await.unwrap();

    assert_eq!(
        remote.download(&file).await.unwrap(),
        b"existing-remote",
        "an upload over a remote object without an etag was not treated as a conflict"
    );
    assert_eq!(result.conflicts_found, 1);
    assert_eq!(
        engine.state().read().await.get(&file).unwrap().status,
        SyncStatus::Conflicted
    );
}

/// (e) Uploads and deletes with no concurrent writer still go through.
async fn non_conflicting_upload_update_and_delete(remote: Arc<dyn StorageProvider>) {
    let local: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let state_dir = TempDir::new().unwrap();
    let engine = engine(remote.clone(), local, &state_dir).await;
    let file = path("/plain.bin");

    engine
        .stage_change(&file, b"one".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    let created = engine.sync_full().await.unwrap();
    assert_eq!((created.files_synced, created.conflicts_found), (1, 0));
    assert_eq!(remote.download(&file).await.unwrap(), b"one");

    // Same length as the first revision, written immediately after it.
    engine
        .stage_change(&file, b"two".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    let updated = engine.sync_full().await.unwrap();
    assert_eq!((updated.files_synced, updated.conflicts_found), (1, 0));
    assert_eq!(remote.download(&file).await.unwrap(), b"two");

    engine.stage_delete(&file).await.unwrap();
    let deleted = engine.sync_full().await.unwrap();
    assert_eq!((deleted.files_synced, deleted.conflicts_found), (1, 0));
    assert!(!remote.exists(&file).await.unwrap());
    assert_eq!(engine.staging().read().await.count(), 0);
    assert!(engine.state().read().await.get(&file).is_none());
}

#[tokio::test]
async fn non_conflicting_upload_update_and_delete_memory() {
    non_conflicting_upload_update_and_delete(Arc::new(MemoryProvider::new())).await;
}

#[tokio::test]
async fn non_conflicting_upload_update_and_delete_local() {
    let dir = TempDir::new().unwrap();
    non_conflicting_upload_update_and_delete(Arc::new(LocalProvider::new(dir.path()).unwrap()))
        .await;
}
