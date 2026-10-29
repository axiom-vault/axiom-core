//! Vault format migration framework.
//!
//! Provides versioned migrations for upgrading vault formats between versions.
//! Migrations are executed in sequence with automatic backup and rollback support.

use std::fmt;

use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::config::{
    download_metadata, VaultConfig, VaultVersion, CONFIG_FILENAME, CONFIG_MAX_LEN, META_DIRNAME,
    TREE_FILENAME, TREE_MAX_LEN,
};
use crate::manifest::{GenerationManifest, MANIFEST_FILENAME, MANIFEST_MAX_LEN};
use crate::session::VaultSession;
use axiomvault_common::{Error, Result, VaultPath};
use axiomvault_crypto::{recovery::RecoveryKey, MasterKey};
use axiomvault_storage::StorageProvider;

/// Backup filename for vault config during migration.
pub const CONFIG_BACKUP_FILENAME: &str = "vault.config.backup";
const CONFIG_MIGRATION_FILENAME: &str = "vault.config.migration";

/// Fully verified result of a committed migration.
pub struct MigrationOutcome {
    pub config: VaultConfig,
    pub recovery_words: Option<Zeroizing<String>>,
}

/// Status of migration check for a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Vault is at the current version; no migration needed.
    UpToDate,
    /// Vault needs migration from one version to another.
    NeedsMigration {
        from: VaultVersion,
        to: VaultVersion,
    },
    /// Vault version is incompatible (different major version, no migration path).
    Incompatible { version: VaultVersion },
}

impl fmt::Display for MigrationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrationStatus::UpToDate => write!(f, "Up to date"),
            MigrationStatus::NeedsMigration { from, to } => {
                write!(f, "Needs migration from {} to {}", from, to)
            }
            MigrationStatus::Incompatible { version } => {
                write!(f, "Incompatible version: {}", version)
            }
        }
    }
}

/// A single migration step from one version to the next.
pub trait Migration: Send + Sync {
    /// The version this migration upgrades from.
    fn source_version(&self) -> VaultVersion;
    /// The version this migration upgrades to.
    fn target_version(&self) -> VaultVersion;
    /// Human-readable description of what this migration does.
    fn description(&self) -> &str;
    /// Transform a config using authenticated secret material.
    fn migrate(
        &self,
        config: &mut VaultConfig,
        password: &[u8],
    ) -> Result<Option<Zeroizing<String>>>;
}

/// Registry of all available migrations.
pub struct MigrationRegistry {
    migrations: Vec<Box<dyn Migration>>,
}

struct AuthenticatedConfig {
    config: VaultConfig,
    master_key: MasterKey,
}

impl MigrationRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            migrations: Vec::new(),
        }
    }

    /// Create a registry pre-populated with all known migrations.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(MigrationV1_0ToV1_1));
        registry
    }

    /// Register a migration step.
    pub fn register(&mut self, migration: Box<dyn Migration>) {
        self.migrations.push(migration);
    }

    /// Find the ordered migration path from one version to another.
    ///
    /// Returns `None` if no path exists (e.g., incompatible major versions).
    pub fn find_path(&self, from: &VaultVersion, to: &VaultVersion) -> Option<Vec<&dyn Migration>> {
        if from == to {
            return Some(Vec::new());
        }

        // Only support forward migration within the same major version.
        if from.major != to.major {
            return None;
        }

        // Forward migration: from.minor < to.minor
        if from.minor >= to.minor {
            return None;
        }

        let mut path = Vec::new();
        let mut current = *from;

        while current != *to {
            let next = self
                .migrations
                .iter()
                .find(|m| m.source_version() == current);
            let migration = next?;
            let target = migration.target_version();
            // Ensure we're moving forward and not past our target.
            if target.minor > to.minor || target.major != to.major {
                return None;
            }
            path.push(migration.as_ref());
            current = target;
        }

        Some(path)
    }

    /// Authenticate, transform, verify, and atomically commit all migrations.
    ///
    /// The config is loaded and persisted exclusively through `StorageProvider`,
    /// so local and cloud-backed vaults share identical rollback semantics.
    pub async fn migrate(
        &self,
        provider: &dyn StorageProvider,
        password: &[u8],
        target: &VaultVersion,
    ) -> Result<MigrationOutcome> {
        let config_path = VaultPath::parse(CONFIG_FILENAME)?;
        let backup_path = VaultPath::parse(CONFIG_BACKUP_FILENAME)?;
        let temp_path = VaultPath::parse(CONFIG_MIGRATION_FILENAME)?;

        self.recover_interrupted(provider, password, &config_path, &backup_path, &temp_path)
            .await?;

        let original_bytes = download_metadata(provider, &config_path, CONFIG_MAX_LEN).await?;
        let mut config = VaultConfig::from_bytes(&original_bytes)?;
        let from = config.version;
        let path = self.find_path(&from, target).ok_or_else(|| {
            Error::Vault(format!("No migration path from {} to {}", from, target))
        })?;
        if path.is_empty() {
            validate_v1_1_invariants(&config)?;
            return Ok(MigrationOutcome {
                config,
                recovery_words: None,
            });
        }

        let original_master_key = config
            .verify_password(password)?
            .ok_or_else(|| Error::NotPermitted("Invalid password".to_string()))?;
        if config.is_legacy_format() {
            prove_legacy_master_key(provider, &original_master_key).await?;
        }
        let mut recovery_words = None;
        for migration in path {
            recovery_words = migration.migrate(&mut config, password)?;
        }
        if config.version != *target {
            return Err(Error::Vault(format!(
                "Migration completed in memory at {} instead of {}",
                config.version, target
            )));
        }
        validate_v1_1_invariants(&config)?;
        let password_master_key = config
            .verify_password(password)?
            .ok_or_else(|| Error::Vault("Migrated config rejected its password".to_string()))?;
        if password_master_key.as_bytes() != original_master_key.as_bytes() {
            return Err(Error::Vault(
                "Migration changed the vault master key".to_string(),
            ));
        }
        let words = recovery_words.as_ref().ok_or_else(|| {
            Error::Vault("Migration did not produce required recovery words".to_string())
        })?;
        let recovery_key = RecoveryKey::from_mnemonic(words)?;
        let recovered_master_key = config
            .verify_recovery_key(&recovery_key)?
            .ok_or_else(|| Error::Vault("Migrated recovery key failed verification".to_string()))?;
        if recovered_master_key.as_bytes() != original_master_key.as_bytes() {
            return Err(Error::Vault(
                "Recovery key unwraps a different master key".to_string(),
            ));
        }

        // Tagged under the proven master key: every open, upgrade and recovery
        // path refuses an untagged 1.1 config that no manifest binds.
        provider
            .upload(
                &temp_path,
                config.to_authenticated_bytes(&original_master_key)?,
            )
            .await?;
        if let Err(error) = provider.rename(&config_path, &backup_path).await {
            let _ = provider.delete(&temp_path).await;
            return Err(error);
        }
        if let Err(error) = provider.rename(&temp_path, &config_path).await {
            let restore = provider.rename(&backup_path, &config_path).await;
            return match restore {
                Ok(_) => Err(error),
                Err(restore_error) => Err(Error::Storage(format!(
                    "migration commit failed ({error}); rollback failed ({restore_error})"
                ))),
            };
        }

        let committed = match download_metadata(provider, &config_path, CONFIG_MAX_LEN).await {
            Ok(bytes) => VaultConfig::from_bytes(&bytes),
            Err(error) => Err(error),
        };
        if let Err(verify_error) = committed.and_then(|saved| {
            validate_v1_1_invariants(&saved)?;
            saved.verify_password(password)?.ok_or_else(|| {
                Error::Vault("Committed config failed authentication".to_string())
            })?;
            Ok(())
        }) {
            let _ = provider.delete(&config_path).await;
            if let Err(restore_error) = provider.rename(&backup_path, &config_path).await {
                return Err(Error::Storage(format!(
                    "committed config verification failed ({verify_error}); rollback failed ({restore_error})"
                )));
            }
            return Err(verify_error);
        }

        if let Err(error) = provider.delete(&backup_path).await {
            warn!("Migration committed but backup cleanup failed: {}", error);
        }
        info!("Migration completed successfully to version {}", target);
        Ok(MigrationOutcome {
            config,
            recovery_words,
        })
    }

    async fn recover_interrupted(
        &self,
        provider: &dyn StorageProvider,
        password: &[u8],
        config_path: &VaultPath,
        backup_path: &VaultPath,
        temp_path: &VaultPath,
    ) -> Result<()> {
        let backup_exists = provider.exists(backup_path).await?;
        let config_exists = provider.exists(config_path).await?;
        let temp_exists = provider.exists(temp_path).await?;

        if !backup_exists && !temp_exists {
            return Ok(());
        }

        // Read, parse, and authenticate every surviving candidate before changing
        // any storage state. Besides keeping wrong-password attempts side-effect
        // free, this prevents a malformed artifact from being silently discarded.
        let config = if config_exists {
            Some(
                self.load_authenticated_config(provider, config_path, password)
                    .await?,
            )
        } else {
            None
        };
        let backup = if backup_exists {
            Some(
                self.load_authenticated_config(provider, backup_path, password)
                    .await?,
            )
        } else {
            None
        };
        let temporary = if temp_exists {
            Some(
                self.load_authenticated_config(provider, temp_path, password)
                    .await?,
            )
        } else {
            None
        };
        // Valid pairs share one master key, so one legacy candidate's proof covers
        // the restore below, which would otherwise discard a committed 1.1 config.
        if let Some(legacy) = [&config, &backup, &temporary]
            .into_iter()
            .flatten()
            .find(|candidate| candidate.config.is_legacy_format())
        {
            prove_legacy_master_key(provider, &legacy.master_key).await?;
        }

        match (&config, &backup, &temporary) {
            (Some(previous), None, Some(next)) => {
                self.validate_interrupted_pair(previous, next)?;
                provider.delete(temp_path).await?;
            }
            (None, Some(previous), Some(next)) => {
                self.validate_interrupted_pair(previous, next)?;
                provider.rename(backup_path, config_path).await?;
                provider.delete(temp_path).await?;
            }
            (None, Some(_), None) => {
                provider.rename(backup_path, config_path).await?;
            }
            (Some(next), Some(previous), None) => {
                self.validate_interrupted_pair(previous, next)?;

                // A crash after publishing the migrated config but before backup
                // cleanup may have prevented its recovery words from reaching the
                // caller. Move the committed candidate back to the temporary slot,
                // restore the legacy config, and rerun the migration so fresh words
                // are returned. Every intermediate state is handled by this same
                // recovery state machine on retry.
                provider.rename(config_path, temp_path).await?;
                provider.rename(backup_path, config_path).await?;
                provider.delete(temp_path).await?;
            }
            (Some(_), Some(_), Some(_)) => {
                return Err(Error::Vault(
                    "Invalid interrupted migration state: config, backup, and temporary config all exist"
                        .to_string(),
                ));
            }
            (None, None, Some(_)) => {
                return Err(Error::Vault(
                    "Invalid interrupted migration state: temporary config has no source config"
                        .to_string(),
                ));
            }
            (Some(_), None, None) | (None, None, None) => {}
        }
        Ok(())
    }

    async fn load_authenticated_config(
        &self,
        provider: &dyn StorageProvider,
        path: &VaultPath,
        password: &[u8],
    ) -> Result<AuthenticatedConfig> {
        let bytes = download_metadata(provider, path, CONFIG_MAX_LEN).await?;
        let config = VaultConfig::from_bytes(&bytes)?;
        let master_key = config
            .verify_password(password)?
            .ok_or_else(|| Error::NotPermitted("Invalid password".to_string()))?;
        if config.version >= VaultVersion::V1_1 {
            validate_v1_1_invariants(&config)?;
        }
        Ok(AuthenticatedConfig { config, master_key })
    }

    fn validate_interrupted_pair(
        &self,
        previous: &AuthenticatedConfig,
        next: &AuthenticatedConfig,
    ) -> Result<()> {
        let has_forward_path = self
            .find_path(&previous.config.version, &next.config.version)
            .is_some_and(|path| !path.is_empty());
        if previous.config.id != next.config.id
            || previous.master_key.as_bytes() != next.master_key.as_bytes()
            || !has_forward_path
        {
            return Err(Error::Vault(
                "Interrupted migration candidates do not represent the same vault migration"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for MigrationRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Check whether a vault config requires migration.
///
/// 1.0 needs the password-authenticated registry migration to 1.1 first;
/// 1.1 is upgraded to `CURRENT` by `VaultManager::upgrade_to_current`.
pub fn check_migration_needed(config: &VaultConfig) -> MigrationStatus {
    let current = VaultVersion::CURRENT;
    let incompatible = MigrationStatus::Incompatible {
        version: config.version,
    };

    if config.version == current || config.version == VaultVersion::V1_1 {
        if validate_v1_1_invariants(config).is_err() {
            return incompatible;
        }
        if config.version == current {
            return MigrationStatus::UpToDate;
        }
    } else if config.version != (VaultVersion { major: 1, minor: 0 }) {
        // Unknown 1.x, other majors, and vaults newer than this software.
        return incompatible;
    }

    MigrationStatus::NeedsMigration {
        from: config.version,
        to: current,
    }
}

/// Prove that the key a legacy config yields is the vault master key.
///
/// A legacy config has no `wrapped_master_key`, so `verify_password` returns the
/// password-derived key itself. `key_verification` is encrypted under that same
/// key, so it proves only the password. A newer config stripped of its wrapped
/// key looks identical, and there the derived key is just the password KEK:
/// wrapping it would issue recovery words for the wrong key and drop the only
/// wrap of the real one. So the key must authenticate an object written under
/// the master key: the snapshot manifest or the tree index, whichever exist.
async fn prove_legacy_master_key(
    provider: &dyn StorageProvider,
    master_key: &MasterKey,
) -> Result<()> {
    let refused = |reason: &str| {
        Error::Crypto(format!(
            "legacy migration refused: {reason}; the password-derived key is not proven to be the vault master key"
        ))
    };
    let meta = VaultPath::parse(META_DIRNAME)?;
    let manifest_path = meta.join(MANIFEST_FILENAME)?;
    let tree_path = meta.join(TREE_FILENAME)?;
    let mut proven = false;
    if provider.exists(&manifest_path).await? {
        let bytes = download_metadata(provider, &manifest_path, MANIFEST_MAX_LEN).await?;
        GenerationManifest::open(master_key, &bytes)
            .map_err(|_| refused("the snapshot manifest does not authenticate"))?;
        proven = true;
    }
    if provider.exists(&tree_path).await? {
        let bytes = download_metadata(provider, &tree_path, TREE_MAX_LEN).await?;
        VaultSession::decrypt_tree_bytes(master_key, &bytes)
            .map_err(|_| refused("the tree index does not authenticate"))?;
        proven = true;
    }
    if !proven {
        return Err(refused("no tree index or snapshot manifest exists"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Built-in migrations
// ---------------------------------------------------------------------------

fn validate_v1_1_invariants(config: &VaultConfig) -> Result<()> {
    if config.version < VaultVersion::V1_1
        || config.wrapped_master_key.is_none()
        || config.recovery_wrapped_master_key.is_none()
        || config.recovery_key_verification.is_none()
        || config.encrypted_recovery_key.is_none()
    {
        return Err(Error::Vault(
            "vault config does not satisfy v1.1 key-wrapping and recovery invariants".to_string(),
        ));
    }
    Ok(())
}

/// Authenticated migration from the legacy password-derived-key format to
/// independently wrapped password and recovery keys.
#[allow(non_camel_case_types)]
struct MigrationV1_0ToV1_1;

impl Migration for MigrationV1_0ToV1_1 {
    fn source_version(&self) -> VaultVersion {
        VaultVersion { major: 1, minor: 0 }
    }

    fn target_version(&self) -> VaultVersion {
        VaultVersion { major: 1, minor: 1 }
    }

    fn description(&self) -> &str {
        "Wrap the legacy master key and configure authenticated recovery"
    }

    fn migrate(
        &self,
        config: &mut VaultConfig,
        password: &[u8],
    ) -> Result<Option<Zeroizing<String>>> {
        if config.version != self.source_version() || !config.is_legacy_format() {
            return Err(Error::Vault(
                "v1.0 migration requires an authenticated legacy config".to_string(),
            ));
        }
        config.migrate_to_v1_1(password).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiomvault_common::VaultId;
    use axiomvault_crypto::KdfParams;

    fn make_test_config(version: VaultVersion) -> VaultConfig {
        let id = VaultId::new("test-vault").unwrap();
        let password = b"test";
        let params = KdfParams::moderate();
        let creation =
            VaultConfig::new(id, password, "local", serde_json::Value::Null, params).unwrap();
        let mut config = creation.config;
        config.version = version;
        config
    }

    fn make_legacy_config() -> VaultConfig {
        let mut config = make_test_config(VaultVersion { major: 1, minor: 0 });
        config.wrapped_master_key = None;
        config.recovery_wrapped_master_key = None;
        config.recovery_key_verification = None;
        config.encrypted_recovery_key = None;
        config
    }

    async fn upload_config(provider: &dyn StorageProvider, filename: &str, bytes: Vec<u8>) {
        provider
            .upload(&VaultPath::parse(filename).unwrap(), bytes)
            .await
            .unwrap();
    }

    /// Write `m/tree.json` encrypted under `key`, as every real vault has.
    async fn upload_tree(provider: &dyn StorageProvider, key: &MasterKey) {
        let meta = VaultPath::parse(META_DIRNAME).unwrap();
        if !provider.exists(&meta).await.unwrap() {
            provider.create_dir(&meta).await.unwrap();
        }
        let tree_key = key.derive_file_key(crate::session::TREE_KEY_CONTEXT);
        let tree_json = crate::tree::VaultTree::new().to_json().unwrap();
        let encrypted =
            axiomvault_crypto::encrypt(tree_key.as_bytes(), tree_json.as_bytes()).unwrap();
        provider
            .upload(&meta.join(TREE_FILENAME).unwrap(), encrypted)
            .await
            .unwrap();
    }

    /// A genuine 1.0 vault: its tree is encrypted under the password-derived key.
    async fn upload_legacy_tree(
        provider: &dyn StorageProvider,
        legacy: &VaultConfig,
        password: &[u8],
    ) {
        let key = legacy.verify_password(password).unwrap().unwrap();
        upload_tree(provider, &key).await;
    }

    /// Every stored path with its bytes (directories map to `None`).
    async fn storage_snapshot(
        provider: &dyn StorageProvider,
    ) -> std::collections::BTreeMap<String, Option<Vec<u8>>> {
        let mut objects = std::collections::BTreeMap::new();
        let mut pending = vec![VaultPath::root()];
        while let Some(directory) = pending.pop() {
            for entry in provider.list(&directory).await.unwrap() {
                let path = directory.join(&entry.name).unwrap();
                if entry.is_directory {
                    objects.insert(path.to_string(), None);
                    pending.push(path);
                } else {
                    objects.insert(
                        path.to_string(),
                        Some(provider.download(&path).await.unwrap()),
                    );
                }
            }
        }
        objects
    }

    /// A 2.0 config with its wrapped key and recovery material stripped and
    /// relabelled 1.0: what a provider can serve in place of a real config.
    fn stripped_config() -> (VaultConfig, MasterKey) {
        let creation = VaultConfig::new(
            VaultId::new("stripped").unwrap(),
            b"test",
            "local",
            serde_json::Value::Null,
            KdfParams::moderate(),
        )
        .unwrap();
        let mut config = creation.config;
        config.version = VaultVersion { major: 1, minor: 0 };
        config.wrapped_master_key = None;
        config.recovery_wrapped_master_key = None;
        config.recovery_key_verification = None;
        config.encrypted_recovery_key = None;
        (config, creation.master_key)
    }

    #[tokio::test]
    async fn stripped_wrapped_key_without_tree_is_refused_without_writes() {
        let (stripped, _) = stripped_config();
        let provider = axiomvault_storage::MemoryProvider::new();
        provider
            .create_dir(&VaultPath::parse("d").unwrap())
            .await
            .unwrap();
        provider
            .create_dir(&VaultPath::parse(META_DIRNAME).unwrap())
            .await
            .unwrap();
        upload_config(&provider, CONFIG_FILENAME, stripped.to_bytes().unwrap()).await;
        let before = storage_snapshot(&provider).await;

        let result = MigrationRegistry::with_defaults()
            .migrate(&provider, b"test", &VaultVersion::V1_1)
            .await;

        match result {
            Err(Error::Crypto(message)) => assert!(
                message.contains("no tree index or snapshot manifest exists"),
                "unexpected refusal: {message}"
            ),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("a stripped config must not be migrated"),
        }
        assert_eq!(storage_snapshot(&provider).await, before);
    }

    #[tokio::test]
    async fn stripped_wrapped_key_with_real_tree_is_refused_without_writes() {
        let (stripped, master_key) = stripped_config();
        let provider = axiomvault_storage::MemoryProvider::new();
        upload_tree(&provider, &master_key).await;
        upload_config(&provider, CONFIG_FILENAME, stripped.to_bytes().unwrap()).await;
        let before = storage_snapshot(&provider).await;

        let result = MigrationRegistry::with_defaults()
            .migrate(&provider, b"test", &VaultVersion::V1_1)
            .await;

        match result {
            Err(Error::Crypto(message)) => assert!(
                message.contains("the tree index does not authenticate"),
                "unexpected refusal: {message}"
            ),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("a stripped config must not be migrated"),
        }
        assert_eq!(storage_snapshot(&provider).await, before);
    }

    #[tokio::test]
    async fn interrupted_restore_of_a_stripped_backup_is_refused_without_writes() {
        let (stripped, _) = stripped_config();
        let provider = axiomvault_storage::MemoryProvider::new();
        upload_config(
            &provider,
            CONFIG_BACKUP_FILENAME,
            stripped.to_bytes().unwrap(),
        )
        .await;
        let before = storage_snapshot(&provider).await;

        let result = MigrationRegistry::with_defaults()
            .migrate(&provider, b"test", &VaultVersion::V1_1)
            .await;

        assert!(matches!(result, Err(Error::Crypto(_))));
        assert_eq!(storage_snapshot(&provider).await, before);
    }

    #[test]
    fn partially_stripped_config_is_refused_by_migrate_to_v1_1() {
        let mut config = make_test_config(VaultVersion { major: 1, minor: 0 });
        config.wrapped_master_key = None;
        let before = config.to_bytes().unwrap();
        assert!(config.migrate_to_v1_1(b"test").is_err());
        assert_eq!(config.to_bytes().unwrap(), before);
    }

    #[test]
    fn test_check_migration_up_to_date() {
        let config = make_test_config(VaultVersion::CURRENT);
        assert_eq!(check_migration_needed(&config), MigrationStatus::UpToDate);
    }

    #[test]
    fn test_check_migration_incompatible_major() {
        let config = make_test_config(VaultVersion { major: 3, minor: 0 });
        let status = check_migration_needed(&config);
        assert_eq!(
            status,
            MigrationStatus::Incompatible {
                version: VaultVersion { major: 3, minor: 0 }
            }
        );
    }

    #[test]
    fn v1_vaults_are_upgradable_and_newer_formats_are_refused() {
        assert_eq!(
            check_migration_needed(&make_test_config(VaultVersion::V1_1)),
            MigrationStatus::NeedsMigration {
                from: VaultVersion::V1_1,
                to: VaultVersion::CURRENT
            }
        );
        let legacy = make_legacy_config();
        assert_eq!(
            check_migration_needed(&legacy),
            MigrationStatus::NeedsMigration {
                from: VaultVersion { major: 1, minor: 0 },
                to: VaultVersion::CURRENT
            }
        );
        // A 1.1 label without the key-wrapping fields cannot be upgraded.
        let mut broken = legacy.clone();
        broken.version = VaultVersion::V1_1;
        assert!(matches!(
            check_migration_needed(&broken),
            MigrationStatus::Incompatible { .. }
        ));
        for version in [
            VaultVersion { major: 1, minor: 2 },
            VaultVersion { major: 2, minor: 1 },
            VaultVersion { major: 3, minor: 0 },
        ] {
            assert_eq!(
                check_migration_needed(&make_test_config(version)),
                MigrationStatus::Incompatible { version }
            );
        }
    }

    #[test]
    fn test_registry_find_path_same_version() {
        let registry = MigrationRegistry::with_defaults();
        let v1_0 = VaultVersion { major: 1, minor: 0 };
        let path = registry.find_path(&v1_0, &v1_0);
        assert!(path.is_some());
        assert!(path.unwrap().is_empty());
    }

    #[test]
    fn test_registry_find_path_v1_0_to_v1_1() {
        let registry = MigrationRegistry::with_defaults();
        let v1_0 = VaultVersion { major: 1, minor: 0 };
        let v1_1 = VaultVersion { major: 1, minor: 1 };
        let path = registry.find_path(&v1_0, &v1_1);
        assert!(path.is_some());
        let steps = path.unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].source_version(), v1_0);
        assert_eq!(steps[0].target_version(), v1_1);
    }

    #[test]
    fn test_registry_find_path_cross_major_fails() {
        let registry = MigrationRegistry::with_defaults();
        let v1_0 = VaultVersion { major: 1, minor: 0 };
        let v2_0 = VaultVersion { major: 2, minor: 0 };
        assert!(registry.find_path(&v1_0, &v2_0).is_none());
    }

    #[tokio::test]
    async fn test_migration_v1_0_to_v1_1() {
        let password = b"test";
        let mut legacy = make_test_config(VaultVersion { major: 1, minor: 0 });
        legacy.wrapped_master_key = None;
        legacy.recovery_wrapped_master_key = None;
        legacy.recovery_key_verification = None;
        legacy.encrypted_recovery_key = None;
        let original_master_key = legacy.verify_password(password).unwrap().unwrap();
        let provider = axiomvault_storage::MemoryProvider::new();
        upload_tree(&provider, &original_master_key).await;
        provider
            .upload(
                &axiomvault_common::VaultPath::parse(CONFIG_FILENAME).unwrap(),
                legacy.to_bytes().unwrap(),
            )
            .await
            .unwrap();
        let registry = MigrationRegistry::with_defaults();
        let target = VaultVersion { major: 1, minor: 1 };

        let outcome = registry
            .migrate(&provider, password, &target)
            .await
            .unwrap();

        assert_eq!(outcome.config.version, target);
        assert!(outcome.config.wrapped_master_key.is_some());
        assert!(outcome.config.recovery_wrapped_master_key.is_some());
        let recovery_words = outcome
            .recovery_words
            .expect("migration must return recovery words");
        let reopened_master_key = outcome
            .config
            .verify_password(password)
            .unwrap()
            .expect("password must reopen migrated vault");
        assert_eq!(
            reopened_master_key.as_bytes(),
            original_master_key.as_bytes()
        );
        let recovery_key =
            axiomvault_crypto::recovery::RecoveryKey::from_mnemonic(&recovery_words).unwrap();
        let recovered_master_key = outcome
            .config
            .verify_recovery_key(&recovery_key)
            .unwrap()
            .expect("recovery words must reopen migrated vault");
        assert_eq!(
            recovered_master_key.as_bytes(),
            original_master_key.as_bytes()
        );
    }

    #[tokio::test]
    async fn test_migration_already_at_target() {
        let config = make_test_config(VaultVersion { major: 1, minor: 1 });
        let provider = axiomvault_storage::MemoryProvider::new();
        provider
            .upload(
                &VaultPath::parse(CONFIG_FILENAME).unwrap(),
                config.to_bytes().unwrap(),
            )
            .await
            .unwrap();
        let registry = MigrationRegistry::with_defaults();
        let target = VaultVersion { major: 1, minor: 1 };

        let outcome = registry.migrate(&provider, b"test", &target).await.unwrap();
        assert_eq!(outcome.config.version, target);
        assert!(outcome.recovery_words.is_none());
    }

    #[tokio::test]
    async fn test_migration_no_path_fails() {
        let config = make_test_config(VaultVersion { major: 1, minor: 0 });
        let provider = axiomvault_storage::MemoryProvider::new();
        provider
            .upload(
                &VaultPath::parse(CONFIG_FILENAME).unwrap(),
                config.to_bytes().unwrap(),
            )
            .await
            .unwrap();
        let registry = MigrationRegistry::with_defaults();
        let target = VaultVersion { major: 1, minor: 5 };

        let result = registry.migrate(&provider, b"test", &target).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn interrupted_commit_restores_backup_before_migrating() {
        let mut config = make_test_config(VaultVersion { major: 1, minor: 0 });
        config.wrapped_master_key = None;
        config.recovery_wrapped_master_key = None;
        config.recovery_key_verification = None;
        config.encrypted_recovery_key = None;
        let provider = axiomvault_storage::MemoryProvider::new();
        upload_legacy_tree(&provider, &config, b"test").await;
        provider
            .upload(
                &VaultPath::parse(CONFIG_BACKUP_FILENAME).unwrap(),
                config.to_bytes().unwrap(),
            )
            .await
            .unwrap();
        let registry = MigrationRegistry::with_defaults();

        let outcome = registry
            .migrate(&provider, b"test", &VaultVersion::V1_1)
            .await
            .unwrap();
        assert_eq!(outcome.config.version, VaultVersion::V1_1);
        assert!(provider
            .exists(&VaultPath::parse(CONFIG_FILENAME).unwrap())
            .await
            .unwrap());
        assert!(!provider
            .exists(&VaultPath::parse(CONFIG_BACKUP_FILENAME).unwrap())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn wrong_password_does_not_modify_legacy_config() {
        let legacy = make_legacy_config();
        let original = legacy.to_bytes().unwrap();
        let provider = axiomvault_storage::MemoryProvider::new();
        provider
            .upload(
                &VaultPath::parse(CONFIG_FILENAME).unwrap(),
                original.clone(),
            )
            .await
            .unwrap();

        let result = MigrationRegistry::with_defaults()
            .migrate(&provider, b"wrong password", &VaultVersion::V1_1)
            .await;

        assert!(matches!(result, Err(Error::NotPermitted(_))));
        assert_eq!(
            provider
                .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
                .await
                .unwrap(),
            original
        );
        assert!(!provider
            .exists(&VaultPath::parse(CONFIG_BACKUP_FILENAME).unwrap())
            .await
            .unwrap());
        assert!(!provider
            .exists(&VaultPath::parse(CONFIG_MIGRATION_FILENAME).unwrap())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn wrong_password_does_not_restore_interrupted_backup() {
        let backup = make_legacy_config().to_bytes().unwrap();
        let provider = axiomvault_storage::MemoryProvider::new();
        upload_config(&provider, CONFIG_BACKUP_FILENAME, backup.clone()).await;

        let result = MigrationRegistry::with_defaults()
            .migrate(&provider, b"wrong password", &VaultVersion::V1_1)
            .await;

        assert!(matches!(result, Err(Error::NotPermitted(_))));
        assert!(!provider
            .exists(&VaultPath::parse(CONFIG_FILENAME).unwrap())
            .await
            .unwrap());
        assert_eq!(
            provider
                .download(&VaultPath::parse(CONFIG_BACKUP_FILENAME).unwrap())
                .await
                .unwrap(),
            backup
        );
    }

    #[tokio::test]
    async fn wrong_password_does_not_delete_interrupted_temporary_config() {
        let legacy = make_legacy_config();
        let config_bytes = legacy.to_bytes().unwrap();
        let mut staged = legacy.clone();
        staged.migrate_to_v1_1(b"test").unwrap();
        let staged_bytes = staged.to_bytes().unwrap();
        let provider = axiomvault_storage::MemoryProvider::new();
        upload_config(&provider, CONFIG_FILENAME, config_bytes.clone()).await;
        upload_config(&provider, CONFIG_MIGRATION_FILENAME, staged_bytes.clone()).await;

        let result = MigrationRegistry::with_defaults()
            .migrate(&provider, b"wrong password", &VaultVersion::V1_1)
            .await;

        assert!(matches!(result, Err(Error::NotPermitted(_))));
        assert_eq!(
            provider
                .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
                .await
                .unwrap(),
            config_bytes
        );
        assert_eq!(
            provider
                .download(&VaultPath::parse(CONFIG_MIGRATION_FILENAME).unwrap())
                .await
                .unwrap(),
            staged_bytes
        );
    }

    #[tokio::test]
    async fn postcommit_interruption_rolls_back_and_returns_new_recovery_words() {
        let password = b"test";
        let legacy = make_legacy_config();
        let original_master_key = legacy.verify_password(password).unwrap().unwrap();
        let backup_bytes = legacy.to_bytes().unwrap();
        let mut committed = legacy.clone();
        committed.migrate_to_v1_1(password).unwrap();
        let provider = axiomvault_storage::MemoryProvider::new();
        upload_tree(&provider, &original_master_key).await;
        upload_config(&provider, CONFIG_FILENAME, committed.to_bytes().unwrap()).await;
        upload_config(&provider, CONFIG_BACKUP_FILENAME, backup_bytes).await;

        let outcome = MigrationRegistry::with_defaults()
            .migrate(&provider, password, &VaultVersion::V1_1)
            .await
            .unwrap();

        let recovery_words = outcome
            .recovery_words
            .expect("retry must return replacement recovery words");
        let recovery_key = RecoveryKey::from_mnemonic(&recovery_words).unwrap();
        let recovered_master_key = outcome
            .config
            .verify_recovery_key(&recovery_key)
            .unwrap()
            .unwrap();
        assert_eq!(
            recovered_master_key.as_bytes(),
            original_master_key.as_bytes()
        );
        let persisted = VaultConfig::from_bytes(
            &provider
                .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            persisted
                .verify_password(password)
                .unwrap()
                .unwrap()
                .as_bytes(),
            original_master_key.as_bytes()
        );
        assert_eq!(
            persisted
                .verify_recovery_key(&recovery_key)
                .unwrap()
                .unwrap()
                .as_bytes(),
            original_master_key.as_bytes()
        );
        assert!(!provider
            .exists(&VaultPath::parse(CONFIG_BACKUP_FILENAME).unwrap())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn malformed_interrupted_candidate_is_preserved_until_removed_then_retry_succeeds() {
        let legacy = make_legacy_config();
        let config_bytes = legacy.to_bytes().unwrap();
        let malformed = b"not a vault config".to_vec();
        let provider = axiomvault_storage::MemoryProvider::new();
        upload_legacy_tree(&provider, &legacy, b"test").await;
        upload_config(&provider, CONFIG_FILENAME, config_bytes.clone()).await;
        upload_config(&provider, CONFIG_MIGRATION_FILENAME, malformed.clone()).await;

        let result = MigrationRegistry::with_defaults()
            .migrate(&provider, b"test", &VaultVersion::V1_1)
            .await;

        assert!(result.is_err());
        assert_eq!(
            provider
                .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
                .await
                .unwrap(),
            config_bytes
        );
        assert_eq!(
            provider
                .download(&VaultPath::parse(CONFIG_MIGRATION_FILENAME).unwrap())
                .await
                .unwrap(),
            malformed
        );

        provider
            .delete(&VaultPath::parse(CONFIG_MIGRATION_FILENAME).unwrap())
            .await
            .unwrap();
        let outcome = MigrationRegistry::with_defaults()
            .migrate(&provider, b"test", &VaultVersion::V1_1)
            .await
            .unwrap();
        assert_eq!(outcome.config.version, VaultVersion::V1_1);
        assert!(outcome.recovery_words.is_some());
    }

    #[test]
    fn test_migration_status_display() {
        assert_eq!(MigrationStatus::UpToDate.to_string(), "Up to date");

        let status = MigrationStatus::NeedsMigration {
            from: VaultVersion { major: 1, minor: 0 },
            to: VaultVersion { major: 1, minor: 1 },
        };
        assert_eq!(status.to_string(), "Needs migration from 1.0 to 1.1");

        let status = MigrationStatus::Incompatible {
            version: VaultVersion { major: 2, minor: 0 },
        };
        assert_eq!(status.to_string(), "Incompatible version: 2.0");
    }
}
