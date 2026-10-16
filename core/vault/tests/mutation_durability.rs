use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axiomvault_common::{Error, Result, VaultId, VaultPath};
use axiomvault_crypto::KdfParams;
use axiomvault_storage::{ByteStream, MemoryProvider, Metadata, StorageProvider};
use axiomvault_vault::{VaultConfig, VaultOperations, VaultSession, VaultTree};

struct CommitThenErrorProvider {
    inner: MemoryProvider,
    lose_next_data_ack: AtomicBool,
}

impl CommitThenErrorProvider {
    fn new() -> Self {
        Self {
            inner: MemoryProvider::new(),
            lose_next_data_ack: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl StorageProvider for CommitThenErrorProvider {
    fn name(&self) -> &str {
        "commit-then-error"
    }

    async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        let metadata = self.inner.upload(path, data).await?;
        if path.to_string_path().starts_with("/d/")
            && self.lose_next_data_ack.swap(false, Ordering::SeqCst)
        {
            return Err(Error::Storage(
                "simulated lost upload acknowledgement".into(),
            ));
        }
        Ok(metadata)
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
async fn lost_update_ack_preserves_previous_readable_revision() {
    let provider = Arc::new(CommitThenErrorProvider::new());
    provider
        .create_dir(&VaultPath::parse("/d").unwrap())
        .await
        .unwrap();
    provider
        .create_dir(&VaultPath::parse("/m").unwrap())
        .await
        .unwrap();
    let creation = VaultConfig::new(
        VaultId::new("review").unwrap(),
        b"password",
        "memory",
        serde_json::Value::Null,
        KdfParams::moderate(),
    )
    .unwrap();
    let session = VaultSession::unlock(
        creation.config,
        b"password",
        provider.clone(),
        VaultTree::new(),
    )
    .unwrap();
    let ops = VaultOperations::new(&session).unwrap();
    let path = VaultPath::parse("/file.bin").unwrap();
    ops.create_file(&path, b"old readable content")
        .await
        .unwrap();

    provider.lose_next_data_ack.store(true, Ordering::SeqCst);
    assert!(ops
        .update_file(&path, b"new committed content")
        .await
        .is_err());

    assert_eq!(ops.read_file(&path).await.unwrap(), b"old readable content");
}
