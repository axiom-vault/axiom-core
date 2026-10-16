use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axiomvault_common::{Error, Result, VaultPath};
use axiomvault_storage::{ByteStream, MemoryProvider, Metadata, StorageProvider};
use axiomvault_sync::{
    ChangeType, ConflictStrategy, PrefixPathMapper, SyncConfig, SyncEngine, SyncStatus,
};
use tempfile::TempDir;
use tokio::sync::Notify;

fn path(value: &str) -> VaultPath {
    VaultPath::parse(value).unwrap()
}

struct FailConflictUploadOnce {
    inner: MemoryProvider,
    armed: AtomicBool,
    fail_list: AtomicBool,
    fail_delete_ack: AtomicBool,
    block_upload: AtomicBool,
    upload_entered: Notify,
    release_upload: Notify,
}

impl FailConflictUploadOnce {
    fn new() -> Self {
        Self {
            inner: MemoryProvider::new(),
            armed: AtomicBool::new(false),
            fail_list: AtomicBool::new(false),
            fail_delete_ack: AtomicBool::new(false),
            block_upload: AtomicBool::new(false),
            upload_entered: Notify::new(),
            release_upload: Notify::new(),
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn arm_list(&self) {
        self.fail_list.store(true, Ordering::SeqCst);
    }

    fn arm_delete_ack(&self) {
        self.fail_delete_ack.store(true, Ordering::SeqCst);
    }

    fn arm_block_upload(&self) {
        self.block_upload.store(true, Ordering::SeqCst);
    }

    async fn wait_for_blocked_upload(&self) {
        self.upload_entered.notified().await;
    }

    fn release_blocked_upload(&self) {
        self.release_upload.notify_one();
    }
}

#[async_trait]
impl StorageProvider for FailConflictUploadOnce {
    fn name(&self) -> &str {
        "fail-conflict-upload-once"
    }

    async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        if self.block_upload.swap(false, Ordering::SeqCst) {
            self.upload_entered.notify_one();
            self.release_upload.notified().await;
        }
        if path.to_string().contains("_conflict_") && self.armed.swap(false, Ordering::SeqCst) {
            self.inner.upload(path, data).await?;
            return Err(Error::Network("injected upload failure".to_string()));
        }
        self.inner.upload(path, data).await
    }

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
        self.inner.exists(path).await
    }

    async fn delete(&self, path: &VaultPath) -> Result<()> {
        self.inner.delete(path).await?;
        if self.fail_delete_ack.swap(false, Ordering::SeqCst) {
            return Err(Error::Network(
                "injected lost delete acknowledgement".to_string(),
            ));
        }
        Ok(())
    }

    async fn list(&self, path: &VaultPath) -> Result<Vec<Metadata>> {
        if self.fail_list.swap(false, Ordering::SeqCst) {
            return Err(Error::Network("injected scan failure".to_string()));
        }
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
async fn prefer_remote_persists_remote_and_does_not_reupload_rejected_local_change() {
    let remote: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local_a: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local_b: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let engine_a = engine(remote.clone(), local_a.clone(), &dir_a).await;
    let engine_b = engine(remote.clone(), local_b.clone(), &dir_b).await;
    let file = path("/shared.bin");

    local_a.upload(&file, b"base".to_vec()).await.unwrap();
    engine_a
        .stage_change(&file, b"base".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    engine_b.sync_full().await.unwrap();

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
    assert_eq!(engine_b.sync_full().await.unwrap().conflicts_found, 1);
    engine_b
        .resolve_conflict(&file, b"device-b".to_vec(), ConflictStrategy::PreferRemote)
        .await
        .unwrap();

    let local_after_resolution = local_b.download(&file).await.unwrap();
    let staged_after_resolution = engine_b.staging().read().await.count();
    engine_b.sync_full().await.unwrap();
    let remote_after_next_sync = remote.download(&file).await.unwrap();

    assert_eq!(
        (
            local_after_resolution,
            staged_after_resolution,
            remote_after_next_sync,
        ),
        (b"device-a".to_vec(), 0, b"device-a".to_vec()),
        "PreferRemote must persist the selected remote revision locally and discard the rejected staged local revision"
    );
}

#[tokio::test]
async fn prefer_local_discards_the_uploaded_staged_revision_immediately() {
    let remote: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local_a: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local_b: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let engine_a = engine(remote.clone(), local_a.clone(), &dir_a).await;
    let engine_b = engine(remote.clone(), local_b.clone(), &dir_b).await;
    let file = path("/shared.bin");

    local_a.upload(&file, b"base".to_vec()).await.unwrap();
    engine_a
        .stage_change(&file, b"base".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    engine_b.sync_full().await.unwrap();
    engine_a
        .stage_change(&file, b"device-a".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_b
        .stage_change(&file, b"device-b".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    assert_eq!(engine_b.sync_full().await.unwrap().conflicts_found, 1);

    engine_b
        .resolve_conflict(&file, b"device-b".to_vec(), ConflictStrategy::PreferLocal)
        .await
        .unwrap();

    assert_eq!(engine_b.staging().read().await.count(), 0);
    assert_eq!(local_b.download(&file).await.unwrap(), b"device-b");
    assert_eq!(remote.download(&file).await.unwrap(), b"device-b");
}

#[tokio::test]
async fn keep_both_uses_local_paths_for_local_persistence_and_state() {
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
        local_b.clone(),
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
        .stage_change(
            &local_path,
            b"remote-wins-original".to_vec(),
            ChangeType::Update,
        )
        .await
        .unwrap();
    engine_b
        .stage_change(&local_path, b"local-kept-copy".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    assert_eq!(engine_b.sync_full().await.unwrap().conflicts_found, 1);

    engine_b
        .resolve_conflict(
            &local_path,
            b"local-kept-copy".to_vec(),
            ConflictStrategy::KeepBoth,
        )
        .await
        .unwrap();

    assert_eq!(
        local_b.download(&local_path).await.unwrap(),
        b"remote-wins-original"
    );
    let local_entries = local_b.list(&path("/cache")).await.unwrap();
    let renamed = local_entries
        .iter()
        .find(|metadata| metadata.name.contains("_conflict_"))
        .expect("local conflict copy must exist");
    let renamed_local_path = path(&format!("/cache/{}", renamed.name));
    let renamed_remote_path = path(&format!("/vault/{}", renamed.name));
    assert_eq!(
        local_b.download(&renamed_local_path).await.unwrap(),
        b"local-kept-copy"
    );
    assert_eq!(
        remote.download(&renamed_remote_path).await.unwrap(),
        b"local-kept-copy"
    );
    assert_eq!(engine_b.staging().read().await.count(), 0);
    let state = engine_b.state();
    let state = state.read().await;
    assert_eq!(state.get(&local_path).unwrap().status, SyncStatus::Synced);
    assert_eq!(
        state.get(&renamed_local_path).unwrap().status,
        SyncStatus::Synced
    );
    assert!(state.get(&renamed_remote_path).is_none());
}

#[tokio::test]
async fn failed_keep_both_upload_retries_the_renamed_copy() {
    let remote_impl = Arc::new(FailConflictUploadOnce::new());
    let remote: Arc<dyn StorageProvider> = remote_impl.clone();
    let local_a: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local_b: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let engine_a = engine(remote.clone(), local_a, &dir_a).await;
    let engine_b = engine(remote.clone(), local_b.clone(), &dir_b).await;
    let file = path("/shared.bin");

    engine_a
        .stage_change(&file, b"base".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    engine_b.sync_full().await.unwrap();
    engine_a
        .stage_change(&file, b"remote-selected".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_b
        .stage_change(&file, b"local-copy".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    assert_eq!(engine_b.sync_full().await.unwrap().conflicts_found, 1);

    remote_impl.arm();
    assert!(engine_b
        .resolve_conflict(&file, b"local-copy".to_vec(), ConflictStrategy::KeepBoth)
        .await
        .is_err());

    let staged_path = engine_b
        .staging()
        .read()
        .await
        .all_changes()
        .next()
        .unwrap()
        .vault_path
        .clone();
    assert!(staged_path.to_string().contains("_conflict_"));
    assert_ne!(staged_path, file);

    drop(engine_b);
    let restarted = engine(remote.clone(), local_b.clone(), &dir_b).await;
    let retry = restarted.sync_full().await.unwrap();
    assert_eq!(retry.files_failed, 0);
    assert_eq!(restarted.staging().read().await.count(), 0);
    assert_eq!(remote.download(&file).await.unwrap(), b"remote-selected");
    assert_eq!(remote.download(&staged_path).await.unwrap(), b"local-copy");
    assert_eq!(local_b.download(&file).await.unwrap(), b"remote-selected");
    assert_eq!(local_b.download(&staged_path).await.unwrap(), b"local-copy");
}

#[tokio::test]
async fn remote_scan_failure_is_returned_to_the_caller() {
    let remote_impl = Arc::new(FailConflictUploadOnce::new());
    let remote: Arc<dyn StorageProvider> = remote_impl.clone();
    let local: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let state_dir = TempDir::new().unwrap();
    let engine = engine(remote, local, &state_dir).await;

    remote_impl.arm_list();
    let error = engine.sync_full().await.unwrap_err();

    assert!(matches!(error, Error::Network(message) if message == "injected scan failure"));
}

#[tokio::test]
async fn repeated_sync_keeps_an_unresolved_conflict_pending() {
    let remote: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local_a: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local_b: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let engine_a = engine(remote.clone(), local_a, &dir_a).await;
    let engine_b = engine(remote.clone(), local_b.clone(), &dir_b).await;
    let file = path("/shared.bin");

    engine_a
        .stage_change(&file, b"base".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    engine_b.sync_full().await.unwrap();
    engine_a
        .stage_change(&file, b"remote-version".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_b
        .stage_change(&file, b"local-version".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    assert_eq!(engine_b.sync_full().await.unwrap().conflicts_found, 1);

    let repeated = engine_b.sync_full().await.unwrap();

    assert_eq!(repeated.conflicts_found, 1);
    assert_eq!(engine_b.staging().read().await.count(), 1);
    assert_eq!(remote.download(&file).await.unwrap(), b"remote-version");
    assert_eq!(local_b.download(&file).await.unwrap(), b"base");
    assert_eq!(
        engine_b.state().read().await.get(&file).unwrap().status,
        SyncStatus::Conflicted
    );
}

#[tokio::test]
async fn lost_delete_acknowledgement_converges_on_missing_remote() {
    let remote_impl = Arc::new(FailConflictUploadOnce::new());
    let remote: Arc<dyn StorageProvider> = remote_impl.clone();
    let local: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let state_dir = TempDir::new().unwrap();
    let engine = engine(remote.clone(), local, &state_dir).await;
    let file = path("/delete-me.bin");

    engine
        .stage_change(&file, b"data".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    engine.sync_full().await.unwrap();
    engine.stage_delete(&file).await.unwrap();
    remote_impl.arm_delete_ack();

    let result = engine.sync_full().await.unwrap();

    assert_eq!(result.files_failed, 0);
    assert_eq!(result.files_synced, 1);
    assert_eq!(engine.staging().read().await.count(), 0);
    assert!(!remote.exists(&file).await.unwrap());
    assert!(engine.state().read().await.get(&file).is_none());
}

#[tokio::test]
async fn conflict_resolution_serializes_a_new_staged_revision() {
    let remote_impl = Arc::new(FailConflictUploadOnce::new());
    let remote: Arc<dyn StorageProvider> = remote_impl.clone();
    let local_a: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let local_b: Arc<dyn StorageProvider> = Arc::new(MemoryProvider::new());
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let engine_a = engine(remote.clone(), local_a, &dir_a).await;
    let engine_b = Arc::new(engine(remote.clone(), local_b, &dir_b).await);
    let file = path("/shared.bin");

    engine_a
        .stage_change(&file, b"base".to_vec(), ChangeType::Create)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    engine_b.sync_full().await.unwrap();
    engine_a
        .stage_change(&file, b"remote-version".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_b
        .stage_change(&file, b"conflicted-local".to_vec(), ChangeType::Update)
        .await
        .unwrap();
    engine_a.sync_full().await.unwrap();
    assert_eq!(engine_b.sync_full().await.unwrap().conflicts_found, 1);

    remote_impl.arm_block_upload();
    let resolving_engine = engine_b.clone();
    let resolving_path = file.clone();
    let resolve_task = tokio::spawn(async move {
        resolving_engine
            .resolve_conflict(
                &resolving_path,
                b"conflicted-local".to_vec(),
                ConflictStrategy::PreferLocal,
            )
            .await
    });
    remote_impl.wait_for_blocked_upload().await;

    let staging_engine = engine_b.clone();
    let staging_path = file.clone();
    let mut stage_task = tokio::spawn(async move {
        staging_engine
            .stage_change(&staging_path, b"newer-local".to_vec(), ChangeType::Update)
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut stage_task)
            .await
            .is_err(),
        "staging must wait while conflict resolution owns the mutation lock"
    );

    remote_impl.release_blocked_upload();
    resolve_task.await.unwrap().unwrap();
    stage_task.await.unwrap().unwrap();

    let staging = engine_b.staging();
    let staging = staging.read().await;
    assert_eq!(staging.count(), 1);
    let pending = staging.all_changes().next().unwrap();
    assert_eq!(
        staging.get_staged_data(&pending.id).await.unwrap(),
        b"newer-local"
    );
}
