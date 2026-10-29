//! iCloud Drive storage provider implementation.
//!
//! Wraps `LocalProvider` around the iCloud Drive mount point on macOS.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

use axiomvault_common::{Error, Result, VaultPath};

use crate::local::LocalProvider;
use crate::provider::{ByteStream, Metadata, StorageProvider};

/// iCloud Drive provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ICloudConfig {
    /// Override the auto-detected iCloud Drive path.
    /// If not set, the provider auto-detects on macOS.
    #[serde(default)]
    pub root_path: Option<String>,
    /// Relative subfolder within iCloud Drive (for example `AxiomVault/work`).
    /// Absolute paths, prefixes, traversal, and empty/whitespace components are rejected.
    #[serde(default)]
    pub subfolder: Option<String>,
}

/// iCloud Drive storage provider.
///
/// Delegates all operations to an inner `LocalProvider` pointed at the
/// iCloud Drive folder on macOS. Syncing is handled transparently by the OS.
pub struct ICloudProvider {
    local: LocalProvider,
}

impl ICloudProvider {
    /// Create a new iCloud Drive provider.
    ///
    /// Auto-detects the iCloud Drive folder on macOS, or uses the
    /// configured `root_path` override.
    pub fn new(config: ICloudConfig) -> Result<Self> {
        let base_path = match config.root_path {
            Some(ref path) => PathBuf::from(path),
            None => super::detect_icloud_path().ok_or_else(|| {
                Error::NotFound(
                    "iCloud Drive not found. \
                     iCloud Drive is only available on macOS with iCloud enabled. \
                     You can set a custom path via the 'root_path' config option."
                        .to_string(),
                )
            })?,
        };

        let root = match config.subfolder.as_deref() {
            Some(subfolder) => confined_root(base_path, subfolder)?,
            None => base_path,
        };

        let local = LocalProvider::new(&root)?;
        Ok(Self { local })
    }
}

/// Join a configured subfolder onto `base` as plain named components,
/// rejecting anything that could move the root: absolute paths, drive
/// prefixes, `.`/`..`, empty or whitespace-only components, and existing
/// symlinks (`LocalProvider` only rejects a symlink as the final root).
fn confined_root(base: PathBuf, subfolder: &str) -> Result<PathBuf> {
    let mut root = base;
    for component in subfolder.split(['/', '\\']) {
        if component.trim().is_empty()
            || component == "."
            || component == ".."
            || component.contains(':')
        {
            return Err(Error::InvalidInput(format!(
                "iCloud subfolder must be a relative path of named folders \
                 (no root, drive prefix, '.', '..' or empty components): {subfolder:?}"
            )));
        }
        root.push(component);
        if std::fs::symlink_metadata(&root).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(Error::NotPermitted(format!(
                "iCloud subfolder must not pass through a symlink: {subfolder:?}"
            )));
        }
    }
    Ok(root)
}

#[async_trait]
impl StorageProvider for ICloudProvider {
    fn name(&self) -> &str {
        "icloud"
    }

    async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
        self.local.upload(path, data).await
    }

    async fn upload_stream(&self, path: &VaultPath, stream: ByteStream) -> Result<Metadata> {
        self.local.upload_stream(path, stream).await
    }

    async fn download(&self, path: &VaultPath) -> Result<Vec<u8>> {
        self.local.download(path).await
    }

    async fn download_stream(&self, path: &VaultPath) -> Result<ByteStream> {
        self.local.download_stream(path).await
    }

    async fn download_bounded(&self, path: &VaultPath, max_len: u64) -> Result<Vec<u8>> {
        self.local.download_bounded(path, max_len).await
    }

    async fn exists(&self, path: &VaultPath) -> Result<bool> {
        self.local.exists(path).await
    }

    async fn delete(&self, path: &VaultPath) -> Result<()> {
        self.local.delete(path).await
    }

    async fn list(&self, path: &VaultPath) -> Result<Vec<Metadata>> {
        self.local.list(path).await
    }

    async fn metadata(&self, path: &VaultPath) -> Result<Metadata> {
        self.local.metadata(path).await
    }

    async fn create_dir(&self, path: &VaultPath) -> Result<Metadata> {
        self.local.create_dir(path).await
    }

    async fn delete_dir(&self, path: &VaultPath) -> Result<()> {
        self.local.delete_dir(path).await
    }

    async fn rename(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
        self.local.rename(from, to).await
    }

    async fn copy(&self, from: &VaultPath, to: &VaultPath) -> Result<Metadata> {
        self.local.copy(from, to).await
    }
}

/// Create an iCloud Drive provider from configuration.
pub fn create_icloud_provider(config: serde_json::Value) -> Result<Arc<dyn StorageProvider>> {
    let icloud_config: ICloudConfig = serde_json::from_value(config)
        .map_err(|e| Error::InvalidInput(format!("Invalid iCloud config: {}", e)))?;

    Ok(Arc::new(ICloudProvider::new(icloud_config)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_root(dir: &tempfile::TempDir) -> ICloudConfig {
        ICloudConfig {
            root_path: Some(dir.path().to_string_lossy().to_string()),
            subfolder: None,
        }
    }

    fn config_with_subfolder(dir: &tempfile::TempDir, subfolder: &str) -> ICloudConfig {
        ICloudConfig {
            root_path: Some(dir.path().to_string_lossy().to_string()),
            subfolder: Some(subfolder.to_string()),
        }
    }

    fn assert_rejected(subfolder: &str) {
        let dir = tempfile::TempDir::new().unwrap();
        match ICloudProvider::new(config_with_subfolder(&dir, subfolder)) {
            Err(Error::InvalidInput(_)) => {}
            Err(err) => panic!("unexpected error for subfolder {subfolder:?}: {err}"),
            Ok(_) => panic!("invalid subfolder should be rejected: {subfolder:?}"),
        }
    }

    #[test]
    fn test_icloud_config_serialization() {
        let config = ICloudConfig {
            root_path: Some("/tmp/test-icloud".to_string()),
            subfolder: Some("AxiomVault".to_string()),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ICloudConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.root_path, config.root_path);
        assert_eq!(deserialized.subfolder, config.subfolder);
    }

    #[test]
    fn test_create_provider_with_custom_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider = ICloudProvider::new(config_with_root(&dir)).unwrap();

        assert_eq!(provider.name(), "icloud");
    }

    #[test]
    fn test_create_provider_with_nested_subfolder() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider = ICloudProvider::new(config_with_subfolder(&dir, "AxiomVault/work")).unwrap();

        assert_eq!(provider.name(), "icloud");
        assert!(dir.path().join("AxiomVault").join("work").exists());
    }

    #[test]
    fn test_rejects_absolute_subfolder() {
        assert_rejected("/escape");
        assert_rejected("\\\\server\\share");
    }

    #[test]
    fn test_rejects_parent_traversal_subfolder() {
        assert_rejected("..");
        assert_rejected("safe/../escape");
        assert_rejected("safe/./escape");
    }

    #[test]
    fn test_rejects_empty_or_whitespace_subfolder_components() {
        assert_rejected("");
        assert_rejected("   ");
        assert_rejected("safe//escape");
        assert_rejected("safe/ /escape");
        assert_rejected("safe/");
    }

    #[test]
    fn test_rejects_windows_prefix_subfolder() {
        assert_rejected("C:\\escape");
        assert_rejected("C:escape");
        assert_rejected("safe/C:/escape");
    }

    #[cfg(unix)]
    #[test]
    fn test_rejects_symlinked_subfolder_component() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();

        let result = ICloudProvider::new(config_with_subfolder(&dir, "link/vault"));

        assert!(matches!(result, Err(Error::NotPermitted(_))));
        assert!(!outside.path().join("vault").exists());
    }

    #[test]
    fn test_create_provider_factory() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = serde_json::json!({
            "root_path": dir.path().to_string_lossy().to_string(),
        });
        let provider = create_icloud_provider(config).unwrap();

        assert_eq!(provider.name(), "icloud");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_create_provider_without_root_path_fails_off_macos() {
        let err = match ICloudProvider::new(ICloudConfig {
            root_path: None,
            subfolder: None,
        }) {
            Ok(_) => panic!("provider creation without a root path should fail off macOS"),
            Err(err) => err,
        };

        assert!(
            matches!(err, Error::NotFound(message) if message.contains("iCloud Drive not found"))
        );
    }

    #[tokio::test]
    async fn test_icloud_basic_operations() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider = ICloudProvider::new(config_with_root(&dir)).unwrap();

        // Create a directory
        let dir_path = VaultPath::parse("test-dir").unwrap();
        provider.create_dir(&dir_path).await.unwrap();
        assert!(provider.exists(&dir_path).await.unwrap());

        // Upload a file
        let file_path = VaultPath::parse("test-dir/hello.txt").unwrap();
        provider
            .upload(&file_path, b"hello world".to_vec())
            .await
            .unwrap();

        // Download and verify
        let data = provider.download(&file_path).await.unwrap();
        assert_eq!(data, b"hello world");

        // List directory
        let entries = provider.list(&dir_path).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");

        // Delete
        provider.delete(&file_path).await.unwrap();
        assert!(!provider.exists(&file_path).await.unwrap());
    }
}
