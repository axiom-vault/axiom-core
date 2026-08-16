use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axiomvault_common::{Result, VaultPath};
use axiomvault_storage::{ByteStream, LocalProvider, MemoryProvider, Metadata, StorageProvider};
use axiomvault_sync::{
    ChangeType, ConflictStrategy, PrefixPathMapper, SyncConfig, SyncEngine, SyncStatus,
};
use tempfile::TempDir;

fn path(value: &str) -> VaultPath {
    VaultPath::parse(value).unwrap()
}

struct RacingDownloadProvider {
    inner: MemoryProvider,
    race_once: AtomicBool,
}

impl RacingDownloadProvider {
    fn new() -> Self {
        Self {
            inner: MemoryProvider::new(),
            race_once: AtomicBool::new(true),
        }
    }
}

#[async_trait]
impl StorageProvider for RacingDownloadProvider {
    fn name(&self) -> &str {
        "racing"
    }
    async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        self.inner.upload(path, data).await
    }
    async fn upload_stream(&self, path: &VaultPath, stream: ByteStream) -> Result<Metadata> {
        self.inner.upload_stream(path, stream).await
    }
    async fn download(&self, path: &VaultPath) -> Result<Vec<u8>> {
        let old = self.inner.download(path).await?;
        if self.race_once.swap(false, Ordering::SeqCst) {
            self.inner
                .upload(path, b"version-B-longer".to_vec())
                .await?;
        }
        Ok(old)
    }
    async fn download_stream(&self, path: &VaultPath) -> Result<ByteStream> {
        self.inner.download_stream(path).await
    }
    async fn exists(&self, path: &VaultPath) -> Result<bool> {
        self.inner.exists(path).await
    }
    async fn delete(&self, path: &VaultPath) -> Result<()> {
        self.inner.delete(path).await
    }
    async fn list(&self, path: &VaultPath) -> Result<Vec<Metadata>> {
        self.inner.list(path).await
    }
    async fn metadata(&self, path: &VaultPath) -> Result<Metadata> {
        self.inner.metadata(path).await
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

#[tokio::test]
async fn owned_provider_constructor_remains_source_compatible() {
    let state_dir = TempDir::new().unwrap();
    let engine = SyncEngine::new(
        MemoryProvider::new(),
        state_dir.path(),
        SyncConfig::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        engine.config().max_retries,
        SyncConfig::default().max_retries
    );
}

#[tokio::test]
async fn full_sync_never_pairs_version_a_bytes_with_version_b_etag() {
    let remote = Arc::new(RacingDownloadProvider::new());
    remote
        .upload(&path("/race.bin"), b"A".to_vec())
        .await
        .unwrap();
    let local: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let state_dir = TempDir::new().unwrap();
    let config = SyncConfig {
        max_retries: 1,
        ..SyncConfig::default()
    };
    let engine = SyncEngine::from_arcs(remote, local.clone(), state_dir.path(), config)
        .await
        .unwrap();

    let result = engine.sync_full().await.unwrap();
    assert_eq!(result.files_synced, 1);
    assert_eq!(
        local.download(&path("/race.bin")).await.unwrap(),
        b"version-B-longer"
    );
}

#[tokio::test]
async fn single_path_sync_never_pairs_version_a_bytes_with_version_b_etag() {
    let remote = Arc::new(RacingDownloadProvider::new());
    remote
        .upload(&path("/race.bin"), b"A".to_vec())
        .await
        .unwrap();
    let local: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let state_dir = TempDir::new().unwrap();
    let config = SyncConfig {
        max_retries: 1,
        ..SyncConfig::default()
    };
    let engine = SyncEngine::from_arcs(remote, local.clone(), state_dir.path(), config)
        .await
        .unwrap();

    let result = engine
        .sync_paths(vec!["/race.bin".to_string()])
        .await
        .unwrap();
    assert_eq!(result.files_synced, 1);
    assert_eq!(
        local.download(&path("/race.bin")).await.unwrap(),
        b"version-B-longer"
    );
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

#[tokio::test]
async fn remote_created_file_is_atomically_persisted_before_state_advances() {
    let remote: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    remote
        .upload(&path("/remote.bin"), b"ciphertext".to_vec())
        .await
        .unwrap();
    let remote_metadata = remote.metadata(&path("/remote.bin")).await.unwrap();
    let state_dir = TempDir::new().unwrap();
    let engine = engine(remote, local.clone(), &state_dir).await;

    let result = engine.sync_full().await.unwrap();

    assert_eq!(result.files_synced, 1);
    assert_eq!(result.pending_persistence, 0);
    assert_eq!(
        local.download(&path("/remote.bin")).await.unwrap(),
        b"ciphertext"
    );
    let state_handle = engine.state();
    let state = state_handle.read().await;
    let entry = state.get(&path("/remote.bin")).unwrap();
    assert_eq!(entry.status, SyncStatus::Synced);
    assert_eq!(entry.remote_etag, remote_metadata.etag);
}

#[tokio::test]
async fn prefix_mapping_uses_local_paths_for_state_and_remote_paths_for_transport() {
    let remote: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    remote.create_dir(&path("/vault")).await.unwrap();
    remote
        .upload(&path("/vault/item.bin"), b"mapped".to_vec())
        .await
        .unwrap();
    local.create_dir(&path("/cache")).await.unwrap();
    let state_dir = TempDir::new().unwrap();
    let mapper = PrefixPathMapper::new(path("/cache"), path("/vault"));
    let engine = SyncEngine::from_arcs_with_mapper(
        remote,
        local.clone(),
        state_dir.path(),
        SyncConfig::default(),
        Arc::new(mapper),
    )
    .await
    .unwrap();

    engine.sync_full().await.unwrap();

    assert_eq!(
        local.download(&path("/cache/item.bin")).await.unwrap(),
        b"mapped"
    );
    let state_handle = engine.state();
    let state = state_handle.read().await;
    assert!(state.get(&path("/cache/item.bin")).is_some());
    assert!(state.get(&path("/vault/item.bin")).is_none());
}

#[tokio::test]
async fn manual_conflict_resolution_uses_nonidentity_prefix_mapping() {
    let remote: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    remote.create_dir(&path("/vault")).await.unwrap();
    let local_a: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local_b: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    local_a.create_dir(&path("/cache")).await.unwrap();
    local_b.create_dir(&path("/cache")).await.unwrap();
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let mapper_a = Arc::new(PrefixPathMapper::new(path("/cache"), path("/vault")));
    let mapper_b = Arc::new(PrefixPathMapper::new(path("/cache"), path("/vault")));
    let engine_a = SyncEngine::from_arcs_with_mapper(
        remote.clone(),
        local_a,
        dir_a.path(),
        SyncConfig::default(),
        mapper_a,
    )
    .await
    .unwrap();
    let engine_b = SyncEngine::from_arcs_with_mapper(
        remote.clone(),
        local_b,
        dir_b.path(),
        SyncConfig::default(),
        mapper_b,
    )
    .await
    .unwrap();
    let local_path = path("/cache/item.bin");

    engine_a
        .stage_change(&local_path, b"base".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    engine_b.sync_full().await.unwrap();
    engine_a
        .stage_change(&local_path, b"device-a".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_b
        .stage_change(&local_path, b"device-b".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    assert_eq!(engine_b.sync_full().await.unwrap().conflicts_found, 1);

    engine_b
        .resolve_conflict(
            &local_path,
            b"device-b".to_vec(),
            ConflictStrategy::PreferLocal,
        )
        .await
        .unwrap();
    assert_eq!(
        remote.download(&path("/vault/item.bin")).await.unwrap(),
        b"device-b"
    );
    assert!(!remote.exists(&local_path).await.unwrap());
}

#[tokio::test]
async fn failed_local_persistence_keeps_remote_change_pending_for_retry() {
    let remote: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    remote.create_dir(&path("/nested")).await.unwrap();
    remote
        .upload(&path("/nested/retry.bin"), b"retry-me".to_vec())
        .await
        .unwrap();
    let local_dir = TempDir::new().unwrap();
    let local: Arc<dyn StorageProvider> = Arc::new(LocalProvider::new(local_dir.path()).unwrap());
    let state_dir = TempDir::new().unwrap();
    let engine = engine(remote, local.clone(), &state_dir).await;

    let failed = engine.sync_full().await.unwrap();
    assert_eq!(failed.files_failed, 1);
    assert_eq!(
        engine
            .state()
            .read()
            .await
            .get(&path("/nested/retry.bin"))
            .unwrap()
            .status,
        SyncStatus::RemoteModified
    );

    local.create_dir(&path("/nested")).await.unwrap();
    let retried = engine.sync_full().await.unwrap();
    assert_eq!(retried.files_synced, 1);
    assert_eq!(
        local.download(&path("/nested/retry.bin")).await.unwrap(),
        b"retry-me"
    );
}

#[tokio::test]
async fn two_devices_converge_for_updates_deletes_and_conflicts() {
    let remote: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local_a: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local_b: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let engine_a = engine(remote.clone(), local_a.clone(), &dir_a).await;
    let engine_b = engine(remote.clone(), local_b.clone(), &dir_b).await;
    let file = path("/shared.bin");

    local_a.upload(&file, b"v1".to_vec()).await.unwrap();
    engine_a
        .stage_change(&file, b"v1".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    engine_b.sync_full().await.unwrap();
    assert_eq!(local_b.download(&file).await.unwrap(), b"v1");

    local_b.upload(&file, b"v2".to_vec()).await.unwrap();
    engine_b
        .stage_change(&file, b"v2".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_b.sync_full().await.unwrap();
    engine_a.sync_full().await.unwrap();
    assert_eq!(local_a.download(&file).await.unwrap(), b"v2");

    local_a.upload(&file, b"device-a".to_vec()).await.unwrap();
    engine_a
        .stage_change(&file, b"device-a".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    local_b.upload(&file, b"device-b".to_vec()).await.unwrap();
    engine_b
        .stage_change(&file, b"device-b".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    let conflict = engine_b.sync_full().await.unwrap();
    assert_eq!(conflict.conflicts_found, 1);
    assert_eq!(engine_b.staging().read().await.count(), 1);

    engine_b
        .resolve_conflict(&file, b"device-b".to_vec(), ConflictStrategy::PreferLocal)
        .await
        .unwrap();
    engine_b.sync_full().await.unwrap();
    engine_a.sync_full().await.unwrap();
    assert_eq!(local_a.download(&file).await.unwrap(), b"device-b");

    local_b.delete(&file).await.unwrap();
    engine_b.stage_delete(&file).await.unwrap();
    engine_b.sync_full().await.unwrap();
    engine_a.sync_full().await.unwrap();
    assert!(!local_a.exists(&file).await.unwrap());
}

#[tokio::test]
async fn sync_state_and_config_survive_restart_atomically() {
    let remote: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let state_dir = TempDir::new().unwrap();
    let file = path("/pending.bin");
    local.upload(&file, b"pending".to_vec()).await.unwrap();
    let config = SyncConfig {
        max_retries: 7,
        ..SyncConfig::default()
    };
    let first = SyncEngine::from_arcs(remote.clone(), local.clone(), state_dir.path(), config)
        .await
        .unwrap();
    first
        .stage_change(&file, b"pending".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    drop(first);

    let restarted = SyncEngine::from_arcs(remote, local, state_dir.path(), SyncConfig::default())
        .await
        .unwrap();

    assert_eq!(restarted.config().max_retries, 7);
    assert_eq!(restarted.staging().read().await.count(), 1);
    assert_eq!(
        restarted.state().read().await.get(&file).unwrap().status,
        SyncStatus::LocalModified
    );
    restarted.sync_full().await.unwrap();
}
