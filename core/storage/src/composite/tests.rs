use super::*;
use crate::health::{HealthConfig, HealthStatus};
use crate::memory::MemoryProvider;
use crate::provider::ByteStream;
use crate::shard_map::ShardMap;
use async_trait::async_trait;
use axiomvault_common::{Error, Result, VaultPath};
use std::sync::Arc;

fn make_backends(n: usize) -> Vec<Arc<dyn StorageProvider>> {
    (0..n)
        .map(|_| Arc::new(MemoryProvider::new()) as Arc<dyn StorageProvider>)
        .collect()
}

/// The key every composite in these tests shares, as the vault would pass it.
fn test_key() -> CompositeKey {
    CompositeKey::from_bytes([0x42; 32])
}

fn new_composite(
    backends: Vec<Arc<dyn StorageProvider>>,
    config: CompositeConfig,
) -> Result<CompositeStorageProvider> {
    CompositeStorageProvider::new(backends, config, test_key())
}

/// Where shard `index` of the committed write of `path` lives.
async fn shard_of(provider: &CompositeStorageProvider, path: &str, index: usize) -> VaultPath {
    let entry = provider.get_shard_map().await.get(path).unwrap().clone();
    CompositeStorageProvider::shard_path(&VaultPath::parse(path).unwrap(), &entry.object_id, index)
        .unwrap()
}

fn mirror_config() -> CompositeConfig {
    CompositeConfig {
        mode: RaidMode::Mirror,
        health: HealthConfig::default(),
    }
}

// -- A provider that always fails, for partial-failure tests -----------

struct FailingProvider;

#[async_trait]
impl StorageProvider for FailingProvider {
    fn name(&self) -> &str {
        "failing"
    }
    async fn upload(&self, _: &VaultPath, _: Vec<u8>) -> Result<Metadata> {
        Err(Error::Storage("backend down".into()))
    }
    async fn upload_stream(&self, _: &VaultPath, _: ByteStream) -> Result<Metadata> {
        Err(Error::Storage("backend down".into()))
    }
    async fn download(&self, _: &VaultPath) -> Result<Vec<u8>> {
        Err(Error::Storage("backend down".into()))
    }
    async fn download_stream(&self, _: &VaultPath) -> Result<ByteStream> {
        Err(Error::Storage("backend down".into()))
    }
    async fn exists(&self, _: &VaultPath) -> Result<bool> {
        Err(Error::Storage("backend down".into()))
    }
    async fn delete(&self, _: &VaultPath) -> Result<()> {
        Err(Error::Storage("backend down".into()))
    }
    async fn list(&self, _: &VaultPath) -> Result<Vec<Metadata>> {
        Err(Error::Storage("backend down".into()))
    }
    async fn metadata(&self, _: &VaultPath) -> Result<Metadata> {
        Err(Error::Storage("backend down".into()))
    }
    async fn create_dir(&self, _: &VaultPath) -> Result<Metadata> {
        Err(Error::Storage("backend down".into()))
    }
    async fn delete_dir(&self, _: &VaultPath) -> Result<()> {
        Err(Error::Storage("backend down".into()))
    }
    async fn rename(&self, _: &VaultPath, _: &VaultPath) -> Result<Metadata> {
        Err(Error::Storage("backend down".into()))
    }
    async fn copy(&self, _: &VaultPath, _: &VaultPath) -> Result<Metadata> {
        Err(Error::Storage("backend down".into()))
    }
}

// -- Construction tests ------------------------------------------------

#[test]
fn test_requires_minimum_two_backends() {
    let result = new_composite(make_backends(1), mirror_config());
    assert!(result.is_err());
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("at least 2 backends"));
}

#[test]
fn test_construction_with_two_backends() {
    let provider = new_composite(make_backends(2), mirror_config()).unwrap();
    assert_eq!(provider.backend_count(), 2);
    assert_eq!(provider.name(), "composite");
    assert_eq!(provider.mode(), RaidMode::Mirror);
}

#[test]
fn test_erasure_validation() {
    // Mismatched shard count
    assert!(new_composite(
        make_backends(3),
        CompositeConfig {
            mode: RaidMode::Erasure {
                data_shards: 2,
                parity_shards: 2,
            },
            health: HealthConfig::default(),
        },
    )
    .is_err());

    // Valid erasure config
    assert!(new_composite(
        make_backends(5),
        CompositeConfig {
            mode: RaidMode::Erasure {
                data_shards: 3,
                parity_shards: 2,
            },
            health: HealthConfig::default(),
        },
    )
    .is_ok());

    // Zero data shards
    assert!(new_composite(
        make_backends(2),
        CompositeConfig {
            mode: RaidMode::Erasure {
                data_shards: 0,
                parity_shards: 2,
            },
            health: HealthConfig::default(),
        },
    )
    .is_err());
}

#[test]
fn test_backend_names() {
    let provider = new_composite(make_backends(3), mirror_config()).unwrap();
    let names = provider.backend_names();
    assert_eq!(names.len(), 3);
    assert!(names.iter().all(|n| *n == "memory"));
}

#[test]
fn test_config_serde_roundtrip() {
    let config = CompositeConfig {
        mode: RaidMode::Erasure {
            data_shards: 3,
            parity_shards: 2,
        },
        health: HealthConfig::default(),
    };
    let json = serde_json::to_string(&config).unwrap();
    let decoded: CompositeConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.mode, config.mode);
}

// -- Mirror happy-path tests -------------------------------------------

#[tokio::test]
async fn test_mirror_upload_download() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), mirror_config()).unwrap();

    let path = VaultPath::parse("/test.txt").unwrap();
    let data = b"hello world".to_vec();

    provider.upload(&path, data.clone()).await.unwrap();

    // All backends should have the data
    for backend in &backends {
        assert_eq!(backend.download(&path).await.unwrap(), data);
    }

    // Download via composite should work
    assert_eq!(provider.download(&path).await.unwrap(), data);
}

#[tokio::test]
async fn test_mirror_exists() {
    let provider = new_composite(make_backends(2), mirror_config()).unwrap();

    let path = VaultPath::parse("/test.txt").unwrap();
    assert!(!provider.exists(&path).await.unwrap());

    provider.upload(&path, vec![1, 2, 3]).await.unwrap();
    assert!(provider.exists(&path).await.unwrap());
}

#[tokio::test]
async fn test_mirror_delete() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), mirror_config()).unwrap();

    let path = VaultPath::parse("/test.txt").unwrap();
    provider.upload(&path, vec![1, 2, 3]).await.unwrap();
    provider.delete(&path).await.unwrap();

    for backend in &backends {
        assert!(!backend.exists(&path).await.unwrap());
    }
}

#[tokio::test]
async fn test_mirror_create_dir_and_list() {
    let provider = new_composite(make_backends(2), mirror_config()).unwrap();

    let dir = VaultPath::parse("/mydir").unwrap();
    let meta = provider.create_dir(&dir).await.unwrap();
    assert!(meta.is_directory);

    provider
        .upload(&VaultPath::parse("/mydir/file.txt").unwrap(), vec![42])
        .await
        .unwrap();

    let listing = provider.list(&dir).await.unwrap();
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].name, "file.txt");
}

#[tokio::test]
async fn test_mirror_rename() {
    let provider = new_composite(make_backends(2), mirror_config()).unwrap();

    let from = VaultPath::parse("/old.txt").unwrap();
    let to = VaultPath::parse("/new.txt").unwrap();

    provider.upload(&from, vec![1, 2, 3]).await.unwrap();
    provider.rename(&from, &to).await.unwrap();

    assert!(!provider.exists(&from).await.unwrap());
    assert!(provider.exists(&to).await.unwrap());
}

#[tokio::test]
async fn test_mirror_copy() {
    let provider = new_composite(make_backends(2), mirror_config()).unwrap();

    let from = VaultPath::parse("/original.txt").unwrap();
    let to = VaultPath::parse("/copy.txt").unwrap();
    let data = vec![1, 2, 3];

    provider.upload(&from, data.clone()).await.unwrap();
    provider.copy(&from, &to).await.unwrap();

    assert!(provider.exists(&from).await.unwrap());
    assert_eq!(provider.download(&to).await.unwrap(), data);
}

#[tokio::test]
async fn test_mirror_metadata() {
    let provider = new_composite(make_backends(2), mirror_config()).unwrap();

    let path = VaultPath::parse("/test.txt").unwrap();
    provider.upload(&path, vec![1, 2, 3]).await.unwrap();

    let meta = provider.metadata(&path).await.unwrap();
    assert_eq!(meta.name, "test.txt");
    assert_eq!(meta.size, Some(3));
    assert!(!meta.is_directory);
}

#[tokio::test]
async fn test_mirror_delete_dir() {
    let provider = new_composite(make_backends(2), mirror_config()).unwrap();

    let dir = VaultPath::parse("/mydir").unwrap();
    provider.create_dir(&dir).await.unwrap();
    provider.delete_dir(&dir).await.unwrap();

    assert!(!provider.exists(&dir).await.unwrap());
}

#[tokio::test]
async fn test_mirror_upload_stream() {
    let provider = new_composite(make_backends(2), mirror_config()).unwrap();

    let path = VaultPath::parse("/stream.txt").unwrap();
    let data = vec![10, 20, 30];
    let data_clone = data.clone();
    let stream: ByteStream = Box::pin(futures::stream::once(async move { Ok(data_clone) }));

    provider.upload_stream(&path, stream).await.unwrap();
    assert_eq!(provider.download(&path).await.unwrap(), data);
}

#[tokio::test]
async fn test_mirror_download_stream() {
    let provider = new_composite(make_backends(2), mirror_config()).unwrap();

    let path = VaultPath::parse("/stream.txt").unwrap();
    let data = vec![10, 20, 30];
    provider.upload(&path, data.clone()).await.unwrap();

    use futures::StreamExt;
    let mut stream = provider.download_stream(&path).await.unwrap();
    let mut result = Vec::new();
    while let Some(chunk) = stream.next().await {
        result.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(result, data);
}

// -- Partial-failure tests ---------------------------------------------

/// Seed an empty shard map on a backend so `load_from_all` finds `Ok(Some(_))`
/// even when other backends in the composite are failing.
async fn seed_empty_shard_map(backend: &dyn StorageProvider) {
    ShardMap::new()
        .save_to_backend(backend, &test_key())
        .await
        .unwrap();
}

#[tokio::test]
async fn test_mirror_upload_succeeds_with_one_failing_backend() {
    let healthy = Arc::new(MemoryProvider::new());
    seed_empty_shard_map(healthy.as_ref()).await;
    let backends: Vec<Arc<dyn StorageProvider>> = vec![Arc::new(FailingProvider), healthy];
    let provider = new_composite(backends, mirror_config()).unwrap();

    let path = VaultPath::parse("/test.txt").unwrap();
    // Should succeed — the MemoryProvider backend is healthy
    provider.upload(&path, vec![1, 2, 3]).await.unwrap();
    assert_eq!(provider.download(&path).await.unwrap(), vec![1, 2, 3]);
}

#[tokio::test]
async fn test_mirror_upload_fails_when_all_backends_fail() {
    let backends: Vec<Arc<dyn StorageProvider>> =
        vec![Arc::new(FailingProvider), Arc::new(FailingProvider)];
    let provider = new_composite(backends, mirror_config()).unwrap();

    let path = VaultPath::parse("/test.txt").unwrap();
    assert!(provider.upload(&path, vec![1, 2, 3]).await.is_err());
}

#[tokio::test]
async fn test_mirror_download_falls_back_to_healthy_backend() {
    let healthy = Arc::new(MemoryProvider::new());
    seed_empty_shard_map(healthy.as_ref()).await;
    let path = VaultPath::parse("/test.txt").unwrap();

    let backends: Vec<Arc<dyn StorageProvider>> = vec![Arc::new(FailingProvider), healthy];
    let provider = new_composite(backends, mirror_config()).unwrap();
    // Reads need the authenticated entry, so the copy is written through the composite.
    provider.upload(&path, vec![42]).await.unwrap();

    // First backend fails, second succeeds
    assert_eq!(provider.download(&path).await.unwrap(), vec![42]);
}

#[tokio::test]
async fn test_mirror_delete_succeeds_with_partial_failure() {
    let healthy = Arc::new(MemoryProvider::new());
    let path = VaultPath::parse("/test.txt").unwrap();
    healthy.upload(&path, vec![1]).await.unwrap();
    seed_empty_shard_map(healthy.as_ref()).await;

    let backends: Vec<Arc<dyn StorageProvider>> = vec![Arc::new(FailingProvider), healthy.clone()];
    let provider = new_composite(backends, mirror_config()).unwrap();

    provider.delete(&path).await.unwrap();
    assert!(!healthy.exists(&path).await.unwrap());
}

// -- Mirror list merge tests ----------------------------------------------

#[tokio::test]
async fn test_mirror_list_returns_union_of_diverged_backends() {
    let backend_a = Arc::new(MemoryProvider::new());
    let backend_b = Arc::new(MemoryProvider::new());

    let dir = VaultPath::parse("/data").unwrap();
    backend_a.create_dir(&dir).await.unwrap();
    backend_b.create_dir(&dir).await.unwrap();

    // backend_a has file1 only
    let file1 = VaultPath::parse("/data/file1.txt").unwrap();
    backend_a.upload(&file1, vec![1]).await.unwrap();

    // backend_b has file1 and file2
    backend_b.upload(&file1, vec![1]).await.unwrap();
    let file2 = VaultPath::parse("/data/file2.txt").unwrap();
    backend_b.upload(&file2, vec![2]).await.unwrap();

    let backends: Vec<Arc<dyn StorageProvider>> = vec![backend_a, backend_b];
    let provider = new_composite(backends, mirror_config()).unwrap();

    let listing = provider.list(&dir).await.unwrap();
    let names: Vec<&str> = listing.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, vec!["file1.txt", "file2.txt"]);
}

#[tokio::test]
async fn test_mirror_list_deduplicates_by_name_keeping_newest() {
    let backend_a = Arc::new(MemoryProvider::new());
    let backend_b = Arc::new(MemoryProvider::new());

    let dir = VaultPath::parse("/data").unwrap();
    backend_a.create_dir(&dir).await.unwrap();
    backend_b.create_dir(&dir).await.unwrap();

    // Upload to backend_a first (older timestamp)
    let file = VaultPath::parse("/data/file.txt").unwrap();
    backend_a.upload(&file, vec![1]).await.unwrap();
    let meta_a = backend_a.metadata(&file).await.unwrap();

    // Small delay to ensure different timestamps
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // Upload to backend_b second (newer timestamp)
    backend_b.upload(&file, vec![1, 2]).await.unwrap();
    let meta_b = backend_b.metadata(&file).await.unwrap();

    // Verify backend_b's timestamp is newer
    assert!(meta_b.modified >= meta_a.modified);

    let backends: Vec<Arc<dyn StorageProvider>> = vec![backend_a, backend_b];
    let provider = new_composite(backends, mirror_config()).unwrap();

    let listing = provider.list(&dir).await.unwrap();
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].name, "file.txt");
    // Should keep backend_b's entry (newer), which has size 2
    assert_eq!(listing[0].size, Some(2));
}

#[tokio::test]
async fn test_mirror_list_succeeds_with_one_failing_backend() {
    let healthy = Arc::new(MemoryProvider::new());
    let dir = VaultPath::parse("/data").unwrap();
    healthy.create_dir(&dir).await.unwrap();
    let file = VaultPath::parse("/data/file.txt").unwrap();
    healthy.upload(&file, vec![1]).await.unwrap();

    let backends: Vec<Arc<dyn StorageProvider>> = vec![Arc::new(FailingProvider), healthy];
    let provider = new_composite(backends, mirror_config()).unwrap();

    let listing = provider.list(&dir).await.unwrap();
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].name, "file.txt");
}

// -- Erasure coding tests -------------------------------------------------

fn erasure_config(data_shards: usize, parity_shards: usize) -> CompositeConfig {
    CompositeConfig {
        mode: RaidMode::Erasure {
            data_shards,
            parity_shards,
        },
        health: HealthConfig::default(),
    }
}

#[tokio::test]
async fn test_erasure_upload_download_basic() {
    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();

    let path = VaultPath::parse("/test.txt").unwrap();
    let data = b"hello world erasure coding test data".to_vec();

    let meta = provider.upload(&path, data.clone()).await.unwrap();
    assert_eq!(meta.name, "test.txt");
    assert_eq!(meta.size, Some(data.len() as u64));

    let downloaded = provider.download(&path).await.unwrap();
    assert_eq!(downloaded, data);
}

#[tokio::test]
async fn test_erasure_upload_download_empty_data() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), erasure_config(2, 1)).unwrap();

    let path = VaultPath::parse("/empty.bin").unwrap();
    let data = vec![];

    provider.upload(&path, data.clone()).await.unwrap();
    let downloaded = provider.download(&path).await.unwrap();
    assert_eq!(downloaded, data);
}

#[tokio::test]
async fn test_erasure_upload_download_single_byte() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), erasure_config(2, 1)).unwrap();

    let path = VaultPath::parse("/one.bin").unwrap();
    let data = vec![42];

    provider.upload(&path, data.clone()).await.unwrap();
    let downloaded = provider.download(&path).await.unwrap();
    assert_eq!(downloaded, data);
}

#[tokio::test]
async fn test_erasure_upload_download_large_data() {
    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();

    let path = VaultPath::parse("/large.bin").unwrap();
    let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

    provider.upload(&path, data.clone()).await.unwrap();
    let downloaded = provider.download(&path).await.unwrap();
    assert_eq!(downloaded, data);
}

#[tokio::test]
async fn test_erasure_reconstruct_with_exactly_k_shards() {
    // 3 data + 2 parity = 5 backends. Remove 2 (parity count) shards.
    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();

    let path = VaultPath::parse("/recover.txt").unwrap();
    let data = b"data that must survive two backend failures".to_vec();

    provider.upload(&path, data.clone()).await.unwrap();

    // Delete shards from backends 0 and 1 (simulating 2 backend failures)
    let shard0 = shard_of(&provider, "/recover.txt", 0).await;
    let shard1 = shard_of(&provider, "/recover.txt", 1).await;
    backends[0].delete(&shard0).await.unwrap();
    backends[1].delete(&shard1).await.unwrap();

    // Should still reconstruct from remaining 3 shards
    let downloaded = provider.download(&path).await.unwrap();
    assert_eq!(downloaded, data);
}

#[tokio::test]
async fn test_erasure_fails_with_too_few_shards() {
    // 3 data + 2 parity = 5 backends. Remove 3 shards (more than parity).
    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();

    let path = VaultPath::parse("/fail.txt").unwrap();
    let data = b"this will be unrecoverable".to_vec();

    provider.upload(&path, data).await.unwrap();

    // Delete 3 shards — only 2 remain, need 3
    backends[0]
        .delete(&shard_of(&provider, "/fail.txt", 0).await)
        .await
        .unwrap();
    backends[1]
        .delete(&shard_of(&provider, "/fail.txt", 1).await)
        .await
        .unwrap();
    backends[2]
        .delete(&shard_of(&provider, "/fail.txt", 2).await)
        .await
        .unwrap();

    let result = provider.download(&path).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("shards available"));
}

#[tokio::test]
async fn test_erasure_exists() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), erasure_config(2, 1)).unwrap();

    let path = VaultPath::parse("/check.bin").unwrap();
    assert!(!provider.exists(&path).await.unwrap());

    provider.upload(&path, vec![1, 2, 3]).await.unwrap();
    assert!(provider.exists(&path).await.unwrap());
}

#[tokio::test]
async fn test_erasure_delete() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), erasure_config(2, 1)).unwrap();

    let path = VaultPath::parse("/del.bin").unwrap();
    provider.upload(&path, vec![1, 2, 3]).await.unwrap();
    let shard_paths = [
        shard_of(&provider, "/del.bin", 0).await,
        shard_of(&provider, "/del.bin", 1).await,
        shard_of(&provider, "/del.bin", 2).await,
    ];

    provider.delete(&path).await.unwrap();

    // All shard files should be gone
    for (backend, shard_path) in backends.iter().zip(&shard_paths) {
        assert!(!backend.exists(shard_path).await.unwrap());
    }
}

#[tokio::test]
async fn test_erasure_rename() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), erasure_config(2, 1)).unwrap();

    let from = VaultPath::parse("/old.bin").unwrap();
    let to = VaultPath::parse("/new.bin").unwrap();
    let data = vec![10, 20, 30];

    provider.upload(&from, data.clone()).await.unwrap();
    provider.rename(&from, &to).await.unwrap();

    assert!(!provider.exists(&from).await.unwrap());
    assert!(provider.exists(&to).await.unwrap());
    assert_eq!(provider.download(&to).await.unwrap(), data);
}

#[tokio::test]
async fn test_erasure_copy() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), erasure_config(2, 1)).unwrap();

    let from = VaultPath::parse("/src.bin").unwrap();
    let to = VaultPath::parse("/dst.bin").unwrap();
    let data = vec![5, 10, 15, 20];

    provider.upload(&from, data.clone()).await.unwrap();
    provider.copy(&from, &to).await.unwrap();

    assert!(provider.exists(&from).await.unwrap());
    assert_eq!(provider.download(&from).await.unwrap(), data);
    assert_eq!(provider.download(&to).await.unwrap(), data);
}

#[tokio::test]
async fn test_erasure_metadata() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), erasure_config(2, 1)).unwrap();

    let path = VaultPath::parse("/meta.bin").unwrap();
    provider.upload(&path, vec![1, 2, 3]).await.unwrap();

    let meta = provider.metadata(&path).await.unwrap();
    assert_eq!(meta.name, "meta.bin");
    assert!(!meta.is_directory);
}

#[tokio::test]
async fn test_erasure_stream_upload_download() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), erasure_config(2, 1)).unwrap();

    let path = VaultPath::parse("/stream.bin").unwrap();
    let data = vec![100, 200, 255, 0, 1];
    let data_clone = data.clone();
    let stream: ByteStream = Box::pin(futures::stream::once(async move { Ok(data_clone) }));

    provider.upload_stream(&path, stream).await.unwrap();

    use futures::StreamExt;
    let mut download_stream = provider.download_stream(&path).await.unwrap();
    let mut result = Vec::new();
    while let Some(chunk) = download_stream.next().await {
        result.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(result, data);
}

#[tokio::test]
async fn test_erasure_5_backends_3_of_5_knock_out_2() {
    // Integration test per issue #145: 5 MemoryProvider backends, 3-of-5, knock out 2
    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();

    // Upload multiple files
    let files: Vec<(VaultPath, Vec<u8>)> = (0..5)
        .map(|i| {
            let path = VaultPath::parse(&format!("/file{}.dat", i)).unwrap();
            let data: Vec<u8> = (0..=255).cycle().take(100 + i * 50).collect();
            (path, data)
        })
        .collect();

    for (path, data) in &files {
        provider.upload(path, data.clone()).await.unwrap();
    }

    // Knock out backends 3 and 4 by deleting their shards
    for (path, _) in &files {
        let path_str = path.to_string_path();
        for shard_idx in [3, 4] {
            let shard_path = shard_of(&provider, &path_str, shard_idx).await;
            backends[shard_idx].delete(&shard_path).await.unwrap();
        }
    }

    // All files should still be readable (3 of 5 shards available)
    for (path, expected_data) in &files {
        let downloaded = provider.download(path).await.unwrap();
        assert_eq!(&downloaded, expected_data, "Data mismatch for {}", path);
    }
}

#[tokio::test]
async fn test_erasure_data_not_divisible_by_k() {
    // Data length not evenly divisible by data_shards — tests padding
    let backends = make_backends(4);
    let provider = new_composite(backends.clone(), erasure_config(3, 1)).unwrap();

    let path = VaultPath::parse("/odd.bin").unwrap();
    // 7 bytes / 3 shards = 2 remainder 1 → tests padding correctness
    let data = vec![1, 2, 3, 4, 5, 6, 7];

    provider.upload(&path, data.clone()).await.unwrap();
    let downloaded = provider.download(&path).await.unwrap();
    assert_eq!(downloaded, data);
}

#[tokio::test]
async fn test_erasure_corrupted_shard_detected() {
    // 3 data + 2 parity = 5 backends. Corrupt one shard payload.
    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();

    let path = VaultPath::parse("/corrupt.bin").unwrap();
    let data = b"data that must survive a corrupted shard".to_vec();

    provider.upload(&path, data.clone()).await.unwrap();

    // Corrupt shard 0 by overwriting with garbage
    let shard0_path = shard_of(&provider, "/corrupt.bin", 0).await;
    backends[0]
        .upload(
            &shard0_path,
            vec![
                0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
            ],
        )
        .await
        .unwrap();

    // Download should still succeed — corrupt shard fails its tag, RS reconstructs
    let downloaded = provider.download(&path).await.unwrap();
    assert_eq!(downloaded, data);
}

#[tokio::test]
async fn test_erasure_list_filters_shard_files() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), erasure_config(2, 1)).unwrap();

    let dir = VaultPath::parse("/data").unwrap();
    // Create dir on all backends so list works
    for backend in &backends {
        backend.create_dir(&dir).await.unwrap();
    }

    let path = VaultPath::parse("/data/file.txt").unwrap();
    provider.upload(&path, vec![1, 2, 3]).await.unwrap();

    let listing = provider.list(&dir).await.unwrap();
    // No .shardN entries should be visible
    for entry in &listing {
        assert!(
            !is_shard_file(&entry.name),
            "Shard file leaked into list: {}",
            entry.name
        );
    }
    // The listing should be empty since the logical file name "file.txt" is
    // not stored — only shard files exist on disk in erasure mode.
    assert!(listing.is_empty());
}

#[tokio::test]
async fn test_erasure_metadata_returns_original_size() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), erasure_config(2, 1)).unwrap();

    let path = VaultPath::parse("/sized.bin").unwrap();
    let data = vec![10, 20, 30, 40, 50];

    provider.upload(&path, data.clone()).await.unwrap();

    let meta = provider.metadata(&path).await.unwrap();
    assert_eq!(meta.name, "sized.bin");
    assert_eq!(meta.size, Some(data.len() as u64));
    assert!(!meta.is_directory);
}

#[test]
fn test_is_shard_file() {
    assert!(is_shard_file("file.txt.shard0"));
    assert!(is_shard_file("file.txt.shard12"));
    assert!(!is_shard_file("file.txt"));
    assert!(!is_shard_file("file.shard"));
    assert!(!is_shard_file("file.shardX"));
    assert!(!is_shard_file("noshard"));
    assert!(is_shard_file(
        "file.txt.0123456789abcdef0123456789abcdef.shard3"
    ));
}

// -- Toggleable provider for health tests ---------------------------------

use std::sync::atomic::{AtomicBool, Ordering};

/// A provider that delegates to an inner `MemoryProvider` but can be toggled
/// to fail all operations on demand.
struct ToggleableProvider {
    inner: MemoryProvider,
    should_fail: AtomicBool,
    provider_name: String,
}

impl ToggleableProvider {
    fn new(name: &str) -> Self {
        Self {
            inner: MemoryProvider::new(),
            should_fail: AtomicBool::new(false),
            provider_name: name.to_string(),
        }
    }

    fn set_failing(&self, fail: bool) {
        self.should_fail.store(fail, Ordering::SeqCst);
    }

    fn check(&self) -> Result<()> {
        if self.should_fail.load(Ordering::SeqCst) {
            Err(Error::Storage("backend down".into()))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl StorageProvider for ToggleableProvider {
    fn name(&self) -> &str {
        &self.provider_name
    }
    async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        self.check()?;
        self.inner.upload(path, data).await
    }
    async fn upload_stream(&self, path: &VaultPath, stream: ByteStream) -> Result<Metadata> {
        self.check()?;
        self.inner.upload_stream(path, stream).await
    }
    async fn download(&self, path: &VaultPath) -> Result<Vec<u8>> {
        self.check()?;
        self.inner.download(path).await
    }
    async fn download_stream(&self, path: &VaultPath) -> Result<ByteStream> {
        self.check()?;
        self.inner.download_stream(path).await
    }
    async fn exists(&self, path: &VaultPath) -> Result<bool> {
        self.check()?;
        self.inner.exists(path).await
    }
    async fn delete(&self, path: &VaultPath) -> Result<()> {
        self.check()?;
        self.inner.delete(path).await
    }
    async fn list(&self, path: &VaultPath) -> Result<Vec<Metadata>> {
        self.check()?;
        self.inner.list(path).await
    }
    async fn metadata(&self, path: &VaultPath) -> Result<Metadata> {
        self.check()?;
        self.inner.metadata(path).await
    }
    async fn create_dir(&self, path: &VaultPath) -> Result<Metadata> {
        self.check()?;
        self.inner.create_dir(path).await
    }
    async fn delete_dir(&self, path: &VaultPath) -> Result<()> {
        self.check()?;
        self.inner.delete_dir(path).await
    }
    async fn rename(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
        self.check()?;
        self.inner.rename(from, to).await
    }
    async fn copy(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
        self.check()?;
        self.inner.copy(from, to).await
    }
}

// -- Health tracking tests ------------------------------------------------

#[tokio::test]
async fn test_health_backends_start_healthy() {
    let provider = new_composite(make_backends(3), mirror_config()).unwrap();
    assert_eq!(provider.healthy_backend_count().await, 3);
    for i in 0..3 {
        let h = provider.backend_health(i).await.unwrap();
        assert_eq!(h.status, HealthStatus::Healthy);
    }
}

#[tokio::test]
async fn test_health_degraded_after_consecutive_failures() {
    let b0 = Arc::new(ToggleableProvider::new("t0"));
    let b1 = Arc::new(ToggleableProvider::new("t1"));
    let b2 = Arc::new(ToggleableProvider::new("t2"));

    // Upload some data while all backends are healthy
    let backends: Vec<Arc<dyn StorageProvider>> = vec![b0.clone(), b1.clone(), b2.clone()];
    let config = CompositeConfig {
        mode: RaidMode::Mirror,
        health: HealthConfig {
            failure_threshold: 3,
            unhealthy_threshold: 10,
            recovery_interval_secs: 3600,
        },
    };
    let provider = new_composite(backends, config).unwrap();

    let path = VaultPath::parse("/test.txt").unwrap();
    provider.upload(&path, b"hello".to_vec()).await.unwrap();

    // Now make b0 fail
    b0.set_failing(true);

    // Trigger 3 write failures on b0 (fan_out writes to all, so b0 fails each time)
    for _ in 0..3 {
        provider.upload(&path, b"hello".to_vec()).await.unwrap();
    }

    let h0 = provider.backend_health(0).await.unwrap();
    assert_eq!(h0.status, HealthStatus::Degraded);
    assert_eq!(h0.consecutive_failures, 3);

    // Backends 1 and 2 should still be healthy
    let h1 = provider.backend_health(1).await.unwrap();
    assert_eq!(h1.status, HealthStatus::Healthy);
    let h2 = provider.backend_health(2).await.unwrap();
    assert_eq!(h2.status, HealthStatus::Healthy);

    assert_eq!(provider.healthy_backend_count().await, 2);
}

#[tokio::test]
async fn test_health_degraded_skipped_for_reads() {
    let b0 = Arc::new(ToggleableProvider::new("t0"));
    let b1 = Arc::new(ToggleableProvider::new("t1"));

    let backends: Vec<Arc<dyn StorageProvider>> = vec![b0.clone(), b1.clone()];
    let config = CompositeConfig {
        mode: RaidMode::Mirror,
        health: HealthConfig {
            failure_threshold: 2,
            unhealthy_threshold: 10,
            recovery_interval_secs: 3600,
        },
    };
    let provider = new_composite(backends, config).unwrap();

    let path = VaultPath::parse("/data.bin").unwrap();
    provider.upload(&path, b"data".to_vec()).await.unwrap();

    // Make b0 fail and trigger enough failures to degrade it
    b0.set_failing(true);
    for _ in 0..2 {
        // These writes succeed overall (b1 is healthy) but record failures for b0
        provider.upload(&path, b"data".to_vec()).await.unwrap();
    }

    let h0 = provider.backend_health(0).await.unwrap();
    assert_eq!(h0.status, HealthStatus::Degraded);

    // Download should still succeed via b1 (b0 is skipped)
    let data = provider.download(&path).await.unwrap();
    assert_eq!(data, b"data");
}

#[tokio::test]
async fn test_health_recovery_on_success() {
    let b0 = Arc::new(ToggleableProvider::new("t0"));
    let b1 = Arc::new(ToggleableProvider::new("t1"));

    let backends: Vec<Arc<dyn StorageProvider>> = vec![b0.clone(), b1.clone()];
    let config = CompositeConfig {
        mode: RaidMode::Mirror,
        health: HealthConfig {
            failure_threshold: 2,
            unhealthy_threshold: 10,
            recovery_interval_secs: 3600,
        },
    };
    let provider = new_composite(backends, config).unwrap();

    let path = VaultPath::parse("/recover.txt").unwrap();
    provider.upload(&path, b"v1".to_vec()).await.unwrap();

    // Degrade b0
    b0.set_failing(true);
    for _ in 0..2 {
        provider.upload(&path, b"v1".to_vec()).await.unwrap();
    }
    assert_eq!(
        provider.backend_health(0).await.unwrap().status,
        HealthStatus::Degraded
    );

    // Restore b0
    b0.set_failing(false);

    // A successful write should recover it
    provider.upload(&path, b"v2".to_vec()).await.unwrap();
    assert_eq!(
        provider.backend_health(0).await.unwrap().status,
        HealthStatus::Healthy
    );
    assert_eq!(provider.healthy_backend_count().await, 2);
}

#[tokio::test]
async fn test_health_transition_to_offline() {
    let b0 = Arc::new(ToggleableProvider::new("t0"));
    let b1 = Arc::new(ToggleableProvider::new("t1"));

    let backends: Vec<Arc<dyn StorageProvider>> = vec![b0.clone(), b1.clone()];
    let config = CompositeConfig {
        mode: RaidMode::Mirror,
        health: HealthConfig {
            failure_threshold: 2,
            unhealthy_threshold: 5,
            recovery_interval_secs: 3600,
        },
    };
    let provider = new_composite(backends, config).unwrap();

    let path = VaultPath::parse("/offline.txt").unwrap();
    provider.upload(&path, b"data".to_vec()).await.unwrap();

    b0.set_failing(true);

    // 5 consecutive failures should transition through Degraded -> Offline
    for _ in 0..5 {
        provider.upload(&path, b"data".to_vec()).await.unwrap();
    }

    let h0 = provider.backend_health(0).await.unwrap();
    assert_eq!(h0.status, HealthStatus::Unhealthy);
    assert_eq!(h0.consecutive_failures, 5);
}

#[tokio::test]
async fn test_health_all_degraded_fallback_reads() {
    // When all backends are degraded, reads should still try all (prevent lockout)
    let b0 = Arc::new(ToggleableProvider::new("t0"));
    let b1 = Arc::new(ToggleableProvider::new("t1"));

    let backends: Vec<Arc<dyn StorageProvider>> = vec![b0.clone(), b1.clone()];
    let config = CompositeConfig {
        mode: RaidMode::Mirror,
        health: HealthConfig {
            failure_threshold: 1,
            unhealthy_threshold: 10,
            recovery_interval_secs: 3600,
        },
    };
    let provider = new_composite(backends, config).unwrap();

    let path = VaultPath::parse("/fallback.txt").unwrap();
    provider.upload(&path, b"data".to_vec()).await.unwrap();

    // Make both backends fail once each to degrade them
    b0.set_failing(true);
    b1.set_failing(true);
    let _ = provider.upload(&path, b"data".to_vec()).await; // Both fail

    // Now restore both
    b0.set_failing(false);
    b1.set_failing(false);

    // Both are degraded, but healthy_backend_indices falls back to all
    assert_eq!(provider.healthy_backend_count().await, 0);

    // Download should succeed because fallback tries all backends
    let data = provider.download(&path).await.unwrap();
    assert_eq!(data, b"data");
}

#[tokio::test]
async fn test_health_intermittent_failures_dont_degrade() {
    let b0 = Arc::new(ToggleableProvider::new("t0"));
    let b1 = Arc::new(ToggleableProvider::new("t1"));

    let backends: Vec<Arc<dyn StorageProvider>> = vec![b0.clone(), b1.clone()];
    let config = CompositeConfig {
        mode: RaidMode::Mirror,
        health: HealthConfig {
            failure_threshold: 3,
            unhealthy_threshold: 10,
            recovery_interval_secs: 3600,
        },
    };
    let provider = new_composite(backends, config).unwrap();

    let path = VaultPath::parse("/intermittent.txt").unwrap();
    provider.upload(&path, b"v1".to_vec()).await.unwrap();

    // 2 failures on b0
    b0.set_failing(true);
    provider.upload(&path, b"v1".to_vec()).await.unwrap();
    provider.upload(&path, b"v1".to_vec()).await.unwrap();

    // Success resets counter
    b0.set_failing(false);
    provider.upload(&path, b"v1".to_vec()).await.unwrap();

    assert_eq!(
        provider.backend_health(0).await.unwrap().status,
        HealthStatus::Healthy
    );
    assert_eq!(
        provider
            .backend_health(0)
            .await
            .unwrap()
            .consecutive_failures,
        0
    );
}

#[tokio::test]
async fn test_health_latency_tracking() {
    let provider = new_composite(make_backends(2), mirror_config()).unwrap();
    let path = VaultPath::parse("/latency.txt").unwrap();
    provider.upload(&path, b"data".to_vec()).await.unwrap();

    let h = provider.backend_health(0).await.unwrap();
    // After at least one successful op, avg_latency_ms should be > 0
    assert!(h.avg_latency_ms > 0.0);
}

#[tokio::test]
async fn test_health_probe_recovers_degraded_backend() {
    let b0 = Arc::new(ToggleableProvider::new("t0"));
    let b1 = Arc::new(ToggleableProvider::new("t1"));

    let backends: Vec<Arc<dyn StorageProvider>> = vec![b0.clone(), b1.clone()];
    let config = CompositeConfig {
        mode: RaidMode::Mirror,
        health: HealthConfig {
            failure_threshold: 1,
            unhealthy_threshold: 10,
            // Very short recovery interval so the probe fires immediately
            recovery_interval_secs: 0,
        },
    };
    let provider = new_composite(backends, config).unwrap();

    let path = VaultPath::parse("/probe.txt").unwrap();
    provider.upload(&path, b"data".to_vec()).await.unwrap();

    // Degrade b0
    b0.set_failing(true);
    provider.upload(&path, b"data".to_vec()).await.unwrap();
    assert_eq!(
        provider.backend_health(0).await.unwrap().status,
        HealthStatus::Degraded
    );

    // Restore b0
    b0.set_failing(false);

    // The next read triggers probe_if_due(), which should recover b0
    let data = provider.download(&path).await.unwrap();
    assert_eq!(data, b"data");

    assert_eq!(
        provider.backend_health(0).await.unwrap().status,
        HealthStatus::Healthy
    );
}

#[tokio::test]
async fn test_config_serde_backward_compat() {
    // Old-format JSON without health field should deserialize with defaults
    let json = r#"{"mode":"Mirror"}"#;
    let config: CompositeConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.mode, RaidMode::Mirror);
    assert_eq!(config.health.failure_threshold, 3);
    assert_eq!(config.health.unhealthy_threshold, 10);
    assert_eq!(config.health.recovery_interval_secs, 60);
}

// -- M-16: authenticated shard map and shards ----------------------------

/// What a hostile backend can build: it reads the plaintext shard map, so it
/// knows every entry's `object_id` and size, but it does not hold the key.
fn attacker_composite(config: CompositeConfig, n: usize) -> CompositeStorageProvider {
    CompositeStorageProvider::new(
        make_backends(n),
        config,
        CompositeKey::from_bytes([0x66; 32]),
    )
    .unwrap()
}

/// Backend `index` replaces its shard of `path` with different bytes of the
/// same length and re-seals it as well as it can: the integrity field is
/// recomputed over the new bytes, under a key that is not the vault's.
async fn rewrite_shard(
    provider: &CompositeStorageProvider,
    backends: &[Arc<dyn StorageProvider>],
    path: &str,
    index: usize,
) {
    let entry = provider.get_shard_map().await.get(path).unwrap().clone();
    let attacker = attacker_composite(erasure_config(3, 2), 5);
    let len = provider
        .expected_shard_len(entry.original_size)
        .expect("erasure mode");
    let garbage = vec![0xA5u8; len];
    let payload = attacker
        .seal_shard(&entry.object_id, index, entry.original_size, &garbage)
        .unwrap();
    backends[index]
        .upload(&shard_of(provider, path, index).await, payload)
        .await
        .unwrap();
}

/// (a) A shard rewritten with a recomputed check is detected; the read
/// reconstructs from the other shards, also from a freshly loaded composite.
#[tokio::test]
async fn test_m16_rewritten_shard_with_recomputed_check_is_rejected() {
    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    let path = VaultPath::parse("/victim.bin").unwrap();
    let data: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
    provider.upload(&path, data.clone()).await.unwrap();

    rewrite_shard(&provider, &backends, "/victim.bin", 0).await;

    assert_eq!(provider.download(&path).await.unwrap(), data);
    let fresh = new_composite(backends, erasure_config(3, 2)).unwrap();
    assert_eq!(fresh.download(&path).await.unwrap(), data);
}

/// (a) A backend that serves its genuine shard from an earlier write of the
/// same path (a valid tag, the wrong version) is not mixed into the decode.
#[tokio::test]
async fn test_m16_stale_shard_version_is_rejected() {
    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    let path = VaultPath::parse("/doc.bin").unwrap();
    let v1 = vec![1u8; 120];
    let v2 = vec![2u8; 120];

    provider.upload(&path, v1).await.unwrap();
    let old0 = backends[0]
        .download(&shard_of(&provider, "/doc.bin", 0).await)
        .await
        .unwrap();
    let old1 = backends[1]
        .download(&shard_of(&provider, "/doc.bin", 1).await)
        .await
        .unwrap();
    provider.upload(&path, v2.clone()).await.unwrap();

    backends[0]
        .upload(&shard_of(&provider, "/doc.bin", 0).await, old0)
        .await
        .unwrap();
    backends[1]
        .upload(&shard_of(&provider, "/doc.bin", 1).await, old1)
        .await
        .unwrap();

    assert_eq!(provider.download(&path).await.unwrap(), v2);
}

/// (b) A backend publishes a shard map with newer timestamps and a different
/// layout. It is refused, the genuine entry stays, and reads are not redirected.
#[tokio::test]
async fn test_m16_forged_shard_map_is_refused() {
    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    let path = VaultPath::parse("/doc.bin").unwrap();
    let data = b"the genuine contents of doc.bin".to_vec();
    provider.upload(&path, data.clone()).await.unwrap();
    let genuine = provider
        .get_shard_map()
        .await
        .get("/doc.bin")
        .unwrap()
        .clone();

    let mut forged = provider.get_shard_map().await;
    forged.version += 1000;
    let entry = forged.entries.get_mut("/doc.bin").unwrap();
    entry.original_size = 3;
    entry.object_id = [0x99; 16];
    entry.updated_at = chrono::Utc::now() + chrono::Duration::hours(1);
    for shard in entry.shards.values_mut() {
        shard.backend_path = "/evil.bin.shard0".to_string();
    }

    // Tagged under a key that is not the vault's, and as bare JSON.
    let attacker_key = CompositeKey::from_bytes([0x66; 32]);
    forged
        .save_to_backend(backends[0].as_ref(), &attacker_key)
        .await
        .unwrap();
    backends[1]
        .upload(
            &VaultPath::parse(".axiomvault/shard_map.json").unwrap(),
            forged.to_json().unwrap(),
        )
        .await
        .unwrap();

    let fresh = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    fresh.load_shard_map().await.unwrap();
    assert_eq!(fresh.get_shard_map().await.get("/doc.bin"), Some(&genuine));
    assert_eq!(fresh.download(&path).await.unwrap(), data);
}

/// (b) Replaying an older, genuinely tagged map does not roll an entry back.
#[tokio::test]
async fn test_m16_replayed_old_shard_map_does_not_roll_back() {
    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    let path = VaultPath::parse("/doc.bin").unwrap();
    let map_file = VaultPath::parse(".axiomvault/shard_map.json").unwrap();

    provider.upload(&path, vec![1u8; 64]).await.unwrap();
    let old_map = backends[0].download(&map_file).await.unwrap();
    provider.upload(&path, vec![2u8; 64]).await.unwrap();
    let current = provider
        .get_shard_map()
        .await
        .get("/doc.bin")
        .unwrap()
        .clone();

    backends[0]
        .upload(&map_file, old_map.clone())
        .await
        .unwrap();
    backends[1].upload(&map_file, old_map).await.unwrap();

    let fresh = new_composite(backends, erasure_config(3, 2)).unwrap();
    fresh.load_shard_map().await.unwrap();
    assert_eq!(fresh.get_shard_map().await.get("/doc.bin"), Some(&current));
    assert_eq!(fresh.download(&path).await.unwrap(), vec![2u8; 64]);
}

/// (e) Up to `parity_shards` forged shards are reconstructed around; one
/// more fails closed with an error, never with wrong data.
#[tokio::test]
async fn test_m16_forged_shards_up_to_parity_then_fail_closed() {
    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    let path = VaultPath::parse("/limit.bin").unwrap();
    let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    provider.upload(&path, data.clone()).await.unwrap();

    rewrite_shard(&provider, &backends, "/limit.bin", 1).await;
    rewrite_shard(&provider, &backends, "/limit.bin", 3).await;
    assert_eq!(provider.download(&path).await.unwrap(), data);

    rewrite_shard(&provider, &backends, "/limit.bin", 4).await;
    let err = provider.download(&path).await.unwrap_err();
    assert!(err.to_string().contains("shards available"), "{err}");
}

/// Mirror mode: a backend that rewrites its copy is skipped on read.
#[tokio::test]
async fn test_m16_rewritten_mirror_copy_is_skipped() {
    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), mirror_config()).unwrap();
    let path = VaultPath::parse("/m.bin").unwrap();
    provider.upload(&path, b"genuine".to_vec()).await.unwrap();

    backends[0]
        .upload(&path, b"forged!".to_vec())
        .await
        .unwrap();
    assert_eq!(provider.download(&path).await.unwrap(), b"genuine");

    backends[1]
        .upload(&path, b"forged!".to_vec())
        .await
        .unwrap();
    backends[2]
        .upload(&path, b"forged!".to_vec())
        .await
        .unwrap();
    assert!(provider.download(&path).await.is_err());
}

/// (d) A genuine erasure set with one backend down writes and reads, then
/// rebuilds the replaced backend, and the rebuilt shard is genuine.
#[tokio::test]
async fn test_m16_genuine_erasure_set_with_backend_missing_reads_and_rebuilds() {
    use crate::rebuild::{RaidRebuilder, RebuildConfig};

    let mut backends = make_backends(5);
    backends[4] = Arc::new(FailingProvider);
    // With a backend down, the first load needs a map somewhere (as in the
    // partial-failure tests above).
    seed_empty_shard_map(backends[0].as_ref()).await;
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    let path = VaultPath::parse("/d.bin").unwrap();
    let data: Vec<u8> = (0..777u32).map(|i| (i * 13) as u8).collect();
    provider.upload(&path, data.clone()).await.unwrap();
    assert_eq!(provider.download(&path).await.unwrap(), data);

    backends[4] = Arc::new(MemoryProvider::new());
    let replaced = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    let result = RaidRebuilder::new(&replaced, 4, RebuildConfig::default())
        .unwrap()
        .rebuild()
        .await
        .unwrap();
    assert_eq!((result.rebuilt, result.failed), (1, 0));

    // Only shards 2, 3 and the rebuilt 4 are left: the read needs shard 4.
    backends[0]
        .delete(&shard_of(&provider, "/d.bin", 0).await)
        .await
        .unwrap();
    backends[1]
        .delete(&shard_of(&provider, "/d.bin", 1).await)
        .await
        .unwrap();
    assert_eq!(replaced.download(&path).await.unwrap(), data);
}

/// (d) The same for a mirror set.
#[tokio::test]
async fn test_m16_genuine_mirror_set_with_backend_missing_reads_and_rebuilds() {
    use crate::rebuild::{RaidRebuilder, RebuildConfig};

    let mut backends = make_backends(3);
    backends[2] = Arc::new(FailingProvider);
    // With a backend down, the first load needs a map somewhere (as in the
    // partial-failure tests above).
    seed_empty_shard_map(backends[0].as_ref()).await;
    let provider = new_composite(backends.clone(), mirror_config()).unwrap();
    let path = VaultPath::parse("/m.bin").unwrap();
    provider
        .upload(&path, b"mirror data".to_vec())
        .await
        .unwrap();
    assert_eq!(provider.download(&path).await.unwrap(), b"mirror data");

    backends[2] = Arc::new(MemoryProvider::new());
    let replaced = new_composite(backends.clone(), mirror_config()).unwrap();
    let result = RaidRebuilder::new(&replaced, 2, RebuildConfig::default())
        .unwrap()
        .rebuild()
        .await
        .unwrap();
    assert_eq!((result.rebuilt, result.failed), (1, 0));
    assert_eq!(backends[2].download(&path).await.unwrap(), b"mirror data");
}

/// (c) Mirror rebuild never copies a source copy that fails its tag.
#[tokio::test]
async fn test_m16_mirror_rebuild_skips_forged_source() {
    use crate::rebuild::{RaidRebuilder, RebuildConfig};

    let backends = make_backends(3);
    let provider = new_composite(backends.clone(), mirror_config()).unwrap();
    let path = VaultPath::parse("/r.bin").unwrap();
    provider.upload(&path, b"genuine".to_vec()).await.unwrap();

    // Every source forged: nothing is copied.
    backends[0]
        .upload(&path, b"forged!".to_vec())
        .await
        .unwrap();
    backends[1]
        .upload(&path, b"forged!".to_vec())
        .await
        .unwrap();
    backends[2].delete(&path).await.unwrap();
    let result = RaidRebuilder::new(&provider, 2, RebuildConfig::default())
        .unwrap()
        .rebuild()
        .await
        .unwrap();
    assert_eq!((result.rebuilt, result.failed), (0, 1));
    assert!(!backends[2].exists(&path).await.unwrap());

    // One source genuine: that one is copied, whichever is tried first.
    backends[1]
        .upload(&path, b"genuine".to_vec())
        .await
        .unwrap();
    let result = RaidRebuilder::new(&provider, 2, RebuildConfig::default())
        .unwrap()
        .rebuild()
        .await
        .unwrap();
    assert_eq!((result.rebuilt, result.failed), (1, 0));
    assert_eq!(backends[2].download(&path).await.unwrap(), b"genuine");
}

/// (c) Erasure rebuild drops forged source shards: it rebuilds the genuine
/// shard when enough genuine ones remain, and writes nothing when not.
#[tokio::test]
async fn test_m16_erasure_rebuild_skips_forged_shards() {
    use crate::rebuild::{RaidRebuilder, RebuildConfig};

    let backends = make_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    let path = VaultPath::parse("/e.bin").unwrap();
    provider
        .upload(&path, (0..500u32).map(|i| i as u8).collect())
        .await
        .unwrap();
    let genuine4 = backends[4]
        .download(&shard_of(&provider, "/e.bin", 4).await)
        .await
        .unwrap();

    rewrite_shard(&provider, &backends, "/e.bin", 0).await;
    backends[4]
        .delete(&shard_of(&provider, "/e.bin", 4).await)
        .await
        .unwrap();
    let result = RaidRebuilder::new(&provider, 4, RebuildConfig::default())
        .unwrap()
        .rebuild()
        .await
        .unwrap();
    assert_eq!((result.rebuilt, result.failed), (1, 0));
    assert_eq!(
        backends[4]
            .download(&shard_of(&provider, "/e.bin", 4).await)
            .await
            .unwrap(),
        genuine4
    );

    rewrite_shard(&provider, &backends, "/e.bin", 1).await;
    backends[4]
        .delete(&shard_of(&provider, "/e.bin", 4).await)
        .await
        .unwrap();
    let result = RaidRebuilder::new(&provider, 4, RebuildConfig::default())
        .unwrap()
        .rebuild()
        .await
        .unwrap();
    assert_eq!((result.rebuilt, result.failed), (0, 1));
    assert!(!backends[4]
        .exists(&shard_of(&provider, "/e.bin", 4).await)
        .await
        .unwrap());
}

// -- M-16 follow-up: an interrupted overwrite keeps the old generation -----

/// A backend that can refuse shard-map writes (a crash before the map
/// commit) and deletes (a failed cleanup); everything else is in memory.
struct CrashableProvider {
    inner: MemoryProvider,
    fail_map_writes: std::sync::atomic::AtomicBool,
    fail_deletes: std::sync::atomic::AtomicBool,
}

impl CrashableProvider {
    fn new() -> Self {
        Self {
            inner: MemoryProvider::new(),
            fail_map_writes: Default::default(),
            fail_deletes: Default::default(),
        }
    }
}

#[async_trait]
impl StorageProvider for CrashableProvider {
    fn name(&self) -> &str {
        "crashable"
    }
    async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        let is_map = path.to_string_path().contains(".axiomvault/shard_map");
        if is_map
            && self
                .fail_map_writes
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Error::Storage("crashed before the map commit".into()));
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
        if self.fail_deletes.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::Storage("delete refused".into()));
        }
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

fn crashable_backends(n: usize) -> (Vec<Arc<CrashableProvider>>, Vec<Arc<dyn StorageProvider>>) {
    let raw: Vec<Arc<CrashableProvider>> =
        (0..n).map(|_| Arc::new(CrashableProvider::new())).collect();
    let dyns = raw
        .iter()
        .map(|b| Arc::clone(b) as Arc<dyn StorageProvider>)
        .collect();
    (raw, dyns)
}

/// An overwrite whose shards are all written but whose map commit never
/// happens (the process dies in between) must leave the old content readable.
#[tokio::test]
async fn test_m16_crash_before_map_commit_keeps_old_content() {
    let (raw, backends) = crashable_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    let path = VaultPath::parse("/doc.bin").unwrap();
    let v1: Vec<u8> = (0..400u32).map(|i| i as u8).collect();
    provider.upload(&path, v1.clone()).await.unwrap();

    for b in &raw {
        b.fail_map_writes
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    assert!(provider.upload(&path, vec![0xEE; 400]).await.is_err());
    drop(provider);

    // Restart: a fresh composite sees only what reached the backends.
    for b in &raw {
        b.fail_map_writes
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
    let restarted = new_composite(backends, erasure_config(3, 2)).unwrap();
    assert_eq!(restarted.download(&path).await.unwrap(), v1);
}

/// After a committed overwrite the previous generation's shards are
/// deleted, and a backend that refuses the delete does not fail the write.
#[tokio::test]
async fn test_m16_superseded_shards_deleted_after_commit_and_failed_delete_is_harmless() {
    let (raw, backends) = crashable_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    let path = VaultPath::parse("/doc.bin").unwrap();

    provider.upload(&path, vec![1u8; 90]).await.unwrap();
    let v1_shards: Vec<VaultPath> =
        futures::future::join_all((0..5).map(|i| shard_of(&provider, "/doc.bin", i))).await;
    provider.upload(&path, vec![2u8; 90]).await.unwrap();
    for (b, p) in backends.iter().zip(&v1_shards) {
        assert!(
            !b.exists(p).await.unwrap(),
            "superseded shard {p} left behind"
        );
    }

    raw[0]
        .fail_deletes
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let v2_shard0 = shard_of(&provider, "/doc.bin", 0).await;
    provider.upload(&path, vec![3u8; 90]).await.unwrap();
    assert!(backends[0].exists(&v2_shard0).await.unwrap());
    assert_eq!(provider.download(&path).await.unwrap(), vec![3u8; 90]);
    let restarted = new_composite(backends, erasure_config(3, 2)).unwrap();
    assert_eq!(restarted.download(&path).await.unwrap(), vec![3u8; 90]);
}

fn set_map_writes_fail(backends: &[Arc<CrashableProvider>], fail: bool) {
    for b in backends {
        b.fail_map_writes
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Mirror mode: an overwrite whose copies are written but whose map commit
/// never happens must leave the committed copy readable after a restart.
#[tokio::test]
async fn test_m16_mirror_crash_before_map_commit_keeps_old_content() {
    let (raw, backends) = crashable_backends(3);
    let provider = new_composite(backends.clone(), mirror_config()).unwrap();
    let path = VaultPath::parse("/m.bin").unwrap();
    provider
        .upload(&path, b"version one".to_vec())
        .await
        .unwrap();

    set_map_writes_fail(&raw, true);
    assert!(provider
        .upload(&path, b"version two".to_vec())
        .await
        .is_err());
    drop(provider);

    set_map_writes_fail(&raw, false);
    let restarted = new_composite(backends, mirror_config()).unwrap();
    assert_eq!(restarted.download(&path).await.unwrap(), b"version one");
}

/// Only one of five backends accepts the new map: nothing of the committed
/// generation is deleted, and with that backend gone the old content reads.
#[tokio::test]
async fn test_m16_minority_map_commit_deletes_nothing() {
    let (raw, backends) = crashable_backends(5);
    let provider = new_composite(backends.clone(), erasure_config(3, 2)).unwrap();
    let path = VaultPath::parse("/doc.bin").unwrap();
    let v1: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    provider.upload(&path, v1.clone()).await.unwrap();
    let v1_shards: Vec<VaultPath> =
        futures::future::join_all((0..5).map(|i| shard_of(&provider, "/doc.bin", i))).await;

    set_map_writes_fail(&raw[1..], true);
    let _ = provider.upload(&path, vec![0xEE; 300]).await;
    for (b, p) in backends.iter().zip(&v1_shards) {
        assert!(
            b.exists(p).await.unwrap(),
            "committed shard {p} was deleted"
        );
    }

    // The one backend that took the new map is lost.
    set_map_writes_fail(&raw[1..], false);
    let mut survivors = backends.clone();
    survivors[0] = Arc::new(FailingProvider);
    let restarted = new_composite(survivors, erasure_config(3, 2)).unwrap();
    assert_eq!(restarted.download(&path).await.unwrap(), v1);
}

/// The same for a mirror set: the committed copy is not overwritten.
#[tokio::test]
async fn test_m16_mirror_minority_map_commit_keeps_committed_copy() {
    let (raw, backends) = crashable_backends(3);
    let provider = new_composite(backends.clone(), mirror_config()).unwrap();
    let path = VaultPath::parse("/m.bin").unwrap();
    provider
        .upload(&path, b"version one".to_vec())
        .await
        .unwrap();

    set_map_writes_fail(&raw[1..], true);
    let _ = provider.upload(&path, b"version two".to_vec()).await;
    for b in &backends {
        assert_eq!(b.download(&path).await.unwrap(), b"version one");
    }

    set_map_writes_fail(&raw[1..], false);
    let mut survivors = backends.clone();
    survivors[0] = Arc::new(FailingProvider);
    let restarted = new_composite(survivors, mirror_config()).unwrap();
    assert_eq!(restarted.download(&path).await.unwrap(), b"version one");
}

/// Two mirrors with one down never reach a map majority, so the copy stays
/// staged. It still reads, exists, lists under its own name and has the
/// right size.
#[tokio::test]
async fn test_m16_unpromoted_mirror_copy_stays_usable() {
    let healthy = Arc::new(MemoryProvider::new());
    seed_empty_shard_map(healthy.as_ref()).await;
    let dir = VaultPath::parse("/data").unwrap();
    healthy.create_dir(&dir).await.unwrap();
    let backends: Vec<Arc<dyn StorageProvider>> = vec![Arc::new(FailingProvider), healthy.clone()];
    let provider = new_composite(backends, mirror_config()).unwrap();
    let path = VaultPath::parse("/data/file.bin").unwrap();

    provider.upload(&path, b"staged".to_vec()).await.unwrap();
    assert!(
        !healthy.exists(&path).await.unwrap(),
        "promoted without a majority"
    );

    assert_eq!(provider.download(&path).await.unwrap(), b"staged");
    assert!(provider.exists(&path).await.unwrap());
    assert_eq!(provider.metadata(&path).await.unwrap().size, Some(6));
    let names: Vec<String> = provider
        .list(&dir)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert_eq!(names, vec!["file.bin"]);

    // Rename and copy carry the staged copy along.
    let renamed = VaultPath::parse("/data/renamed.bin").unwrap();
    let copied = VaultPath::parse("/data/copied.bin").unwrap();
    provider.rename(&path, &renamed).await.unwrap();
    provider.copy(&renamed, &copied).await.unwrap();
    assert!(!provider.exists(&path).await.unwrap());
    assert_eq!(provider.download(&renamed).await.unwrap(), b"staged");
    assert_eq!(provider.download(&copied).await.unwrap(), b"staged");
}
