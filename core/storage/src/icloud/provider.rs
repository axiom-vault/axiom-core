//! iCloud Drive storage provider implementation.
//!
//! Wraps `LocalProvider` around the iCloud Drive mount point on macOS.

use crate::local::LocalProvider;
use crate::provider::{ByteStream, Metadata, StorageProvider};
use async_trait::async_trait;
use axiomvault_common::{Error, Result, VaultPath};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
                    "iCloud Drive not found. iCloud Drive is only available on macOS with iCloud enabled. You can set a custom path via the 'root_path' config option.".to_string(),
                )
            })?,
        };

        let root = match config.subfolder.as_deref() {
            Some(subfolder) => base_path.join(validate_subfolder(subfolder)?),
            None => base_path,
        };

        let local = LocalProvider::new(&root)?;
        Ok(Self { local })
    }
}

fn validate_subfolder(subfolder: &str) -> Result<PathBuf> {
    if subfolder.trim().is_empty() {
        return Err(Error::InvalidInput(
            "iCloud subfolder cannot be empty or whitespace".to_string(),
        ));
    }

    if has_windows_drive_prefix(subfolder) {
        return Err(Error::InvalidInput(
            "iCloud subfolder must be a relative path without filesystem prefixes".to_string(),
        ));
    }

    let path = Path::new(subfolder);
    if path.is_absolute() || path.has_root() {
        return Err(Error::InvalidInput(
            "iCloud subfolder must be a relative path".to_string(),
        ));
    }

    let mut sanitized = PathBuf::new();
    for component in subfolder.split(['/', '\\']) {
        if component.trim().is_empty() {
            return Err(Error::InvalidInput(
                "iCloud subfolder components cannot be empty or whitespace".to_string(),
            ));
        }
        if component == "." || component == ".." {
            return Err(Error::InvalidInput(
                "iCloud subfolder cannot contain '.' or '..' path components".to_string(),
            ));
        }
        sanitized.push(component);
    }

    if sanitized.as_os_str().is_empty() {
        return Err(Error::InvalidInput(
            "iCloud subfolder cannot be empty or whitespace".to_string(),
        ));
    }

    Ok(sanitized)
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
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
        let config = ICloudConfig {
            root_path: Some(dir.path().to_string_lossy().to_string()),
            subfolder: None,
        };

        let provider = ICloudProvider::new(config).unwrap();
        assert_eq!(provider.name(), "icloud");
    }

    #[test]
    fn test_create_provider_with_nested_subfolder() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = ICloudConfig {
            root_path: Some(dir.path().to_string_lossy().to_string()),
            subfolder: Some("AxiomVault/work".to_string()),
        };

        let provider = ICloudProvider::new(config).unwrap();

        assert_eq!(provider.name(), "icloud");
        assert!(dir.path().join("AxiomVault").join("work").exists());
    }

    #[test]
    fn test_rejects_absolute_subfolder() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = match ICloudProvider::new(ICloudConfig {
            root_path: Some(dir.path().to_string_lossy().to_string()),
            subfolder: Some("/escape".to_string()),
        }) {
            Ok(_) => panic!("absolute subfolder should be rejected"),
            Err(err) => err,
        };

        assert!(matches!(err, Error::InvalidInput(message) if message.contains("relative path")));
    }

    #[test]
    fn test_rejects_parent_traversal_subfolder() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = match ICloudProvider::new(ICloudConfig {
            root_path: Some(dir.path().to_string_lossy().to_string()),
            subfolder: Some("safe/../escape".to_string()),
        }) {
            Ok(_) => panic!("parent traversal should be rejected"),
            Err(err) => err,
        };

        assert!(matches!(err, Error::InvalidInput(message) if message.contains("'.' or '..'")));
    }

    #[test]
    fn test_rejects_empty_or_whitespace_subfolder_components() {
        let dir = tempfile::TempDir::new().unwrap();

        let repeated_separator_err = match ICloudProvider::new(ICloudConfig {
            root_path: Some(dir.path().to_string_lossy().to_string()),
            subfolder: Some("safe//escape".to_string()),
        }) {
            Ok(_) => panic!("empty path components should be rejected"),
            Err(err) => err,
        };
        assert!(
            matches!(repeated_separator_err, Error::InvalidInput(message) if message.contains("empty or whitespace"))
        );

        let whitespace_component_err = match ICloudProvider::new(ICloudConfig {
            root_path: Some(dir.path().to_string_lossy().to_string()),
            subfolder: Some("safe/ /escape".to_string()),
        }) {
            Ok(_) => panic!("whitespace-only path components should be rejected"),
            Err(err) => err,
        };
        assert!(
            matches!(whitespace_component_err, Error::InvalidInput(message) if message.contains("empty or whitespace"))
        );
    }

    #[test]
    fn test_rejects_windows_prefix_subfolder() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = match ICloudProvider::new(ICloudConfig {
            root_path: Some(dir.path().to_string_lossy().to_string()),
            subfolder: Some("C:\\escape".to_string()),
        }) {
            Ok(_) => panic!("windows-style prefixes should be rejected"),
            Err(err) => err,
        };

        assert!(matches!(err, Error::InvalidInput(message) if message.contains("prefixes")));
    }

    #[test]
    fn test_create_provider_factory() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = serde_json::json!({
            "root_path": dir.path().to_string_lossy().to_string()
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
        let config = ICloudConfig {
            root_path: Some(dir.path().to_string_lossy().to_string()),
            subfolder: None,
        };
        let provider = ICloudProvider::new(config).unwrap();

        let dir_path = VaultPath::parse("test-dir").unwrap();
        provider.create_dir(&dir_path).await.unwrap();
        assert!(provider.exists(&dir_path).await.unwrap());

        let file_path = VaultPath::parse("test-dir/hello.txt").unwrap();
        provider
            .upload(&file_path, b"hello world".to_vec())
            .await
            .unwrap();

        let data = provider.download(&file_path).await.unwrap();
        assert_eq!(data, b"hello world");

        let entries = provider.list(&dir_path).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");

        provider.delete(&file_path).await.unwrap();
        assert!(!provider.exists(&file_path).await.unwrap());
    }
}
