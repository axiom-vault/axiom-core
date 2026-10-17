//! Vault manager for creating and managing vaults.

use std::sync::Arc;

use crate::config::{VaultConfig, VaultVersion, CONFIG_FILENAME, DATA_DIRNAME, META_DIRNAME};
use crate::freshness::{
    FreshnessAnchor, FreshnessState, LocalFileFreshnessAnchor, UnavailableFreshnessAnchor,
};
use crate::manifest::{digest, GenerationManifest, MANIFEST_FILENAME};
use crate::migration::{check_migration_needed, MigrationStatus};
use crate::session::VaultSession;
use crate::tree::VaultTree;
use axiomvault_common::{Error, Result, VaultId, VaultPath};
use axiomvault_crypto::recovery::RecoveryKey;
use axiomvault_crypto::{KdfParams, MasterKey};
use axiomvault_storage::{create_default_registry, ProviderRegistry, StorageProvider};
use zeroize::Zeroizing;

fn persisted_provider_config(
    provider_type: &str,
    runtime_config: &serde_json::Value,
) -> Result<serde_json::Value> {
    let (identity_key, provider_label) = match provider_type {
        "gdrive" => ("folder_id", "Google Drive"),
        "dropbox" => ("root_path", "Dropbox"),
        "onedrive" => ("root_path", "OneDrive"),
        _ => return Ok(runtime_config.clone()),
    };
    let identity = runtime_config
        .get(identity_key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::InvalidInput(format!("{provider_label} config requires '{identity_key}'"))
        })?;
    let credential_ref = runtime_config
        .get("credential_ref")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::InvalidInput(format!(
                "{provider_label} config requires local 'credential_ref'"
            ))
        })?;
    Ok(serde_json::json!({
        identity_key: identity,
        "credential_ref": credential_ref,
        "credential_schema": 1,
    }))
}

/// Whether an authenticated 1.1 config must be upgraded to `CURRENT` on open.
///
/// Callers relabel only their in-memory copy and publish it as a new manifest
/// generation; `vault.config` is a cache written after the manifest commit, so
/// it never reads 2.0 while the authoritative snapshot is still 1.1.
fn needs_format_upgrade(config: &VaultConfig) -> Result<bool> {
    match check_migration_needed(config) {
        MigrationStatus::UpToDate => Ok(false),
        MigrationStatus::NeedsMigration { from, .. } if from == VaultVersion::V1_1 => Ok(true),
        MigrationStatus::NeedsMigration { from, .. } => Err(Error::Vault(format!(
            "vault version {from} must be migrated to {} before it can be opened",
            VaultVersion::V1_1
        ))),
        MigrationStatus::Incompatible { version } => Err(Error::Vault(format!(
            "Incompatible vault version: {version}"
        ))),
    }
}

fn is_oauth_cloud_provider(provider_type: &str) -> bool {
    matches!(provider_type, "gdrive" | "dropbox" | "onedrive")
}

/// Resolves an opaque credential reference using local-only storage.
///
/// Implementations may use an OS keychain, keystore, Secret Service, or a
/// private local file. Returned credentials are passed only to the provider
/// factory and are never included in `vault.config`.
pub trait LocalCredentialResolver: Send + Sync {
    /// Resolve provider credentials for a non-secret persisted reference.
    fn resolve(&self, provider_type: &str, credential_ref: &str) -> Result<serde_json::Value>;
}

/// Result of vault creation, containing the session and recovery words.
pub struct VaultCreation {
    /// Active session for the newly created vault.
    pub session: VaultSession,
    /// Recovery key encoded as 24 BIP39 words. Must be shown to user once.
    pub recovery_words: Zeroizing<String>,
}

/// Vault manager for creating and opening vaults.
pub struct VaultManager {
    registry: ProviderRegistry,
    credential_resolver: Option<Arc<dyn LocalCredentialResolver>>,
    freshness_anchor: Arc<dyn FreshnessAnchor>,
    ephemeral_namespace: String,
}

impl VaultManager {
    /// Create a new vault manager with default providers.
    pub fn new() -> Self {
        Self::with_registry(create_default_registry())
    }

    /// Create with custom registry.
    pub fn with_registry(registry: ProviderRegistry) -> Self {
        let freshness_anchor: Arc<dyn FreshnessAnchor> =
            match LocalFileFreshnessAnchor::platform_default() {
                Ok(anchor) => Arc::new(anchor),
                Err(error) => Arc::new(UnavailableFreshnessAnchor::new(error.to_string())),
            };
        Self::with_registry_and_security(registry, None, freshness_anchor)
    }

    /// Create with a custom provider registry and local credential resolver.
    pub fn with_registry_and_credential_resolver(
        registry: ProviderRegistry,
        credential_resolver: Arc<dyn LocalCredentialResolver>,
    ) -> Self {
        let freshness_anchor: Arc<dyn FreshnessAnchor> =
            match LocalFileFreshnessAnchor::platform_default() {
                Ok(anchor) => Arc::new(anchor),
                Err(error) => Arc::new(UnavailableFreshnessAnchor::new(error.to_string())),
            };
        Self::with_registry_and_security(registry, Some(credential_resolver), freshness_anchor)
    }

    /// Create with a custom provider registry and trusted freshness anchor.
    pub fn with_registry_and_anchor(
        registry: ProviderRegistry,
        freshness_anchor: Arc<dyn FreshnessAnchor>,
    ) -> Self {
        Self::with_registry_and_security(registry, None, freshness_anchor)
    }

    /// Create with a custom provider registry, credential resolver, and freshness anchor.
    pub fn with_registry_credential_resolver_and_anchor(
        registry: ProviderRegistry,
        credential_resolver: Arc<dyn LocalCredentialResolver>,
        freshness_anchor: Arc<dyn FreshnessAnchor>,
    ) -> Self {
        Self::with_registry_and_security(registry, Some(credential_resolver), freshness_anchor)
    }

    fn with_registry_and_security(
        registry: ProviderRegistry,
        credential_resolver: Option<Arc<dyn LocalCredentialResolver>>,
        freshness_anchor: Arc<dyn FreshnessAnchor>,
    ) -> Self {
        Self {
            registry,
            credential_resolver,
            freshness_anchor,
            ephemeral_namespace: uuid::Uuid::new_v4().to_string(),
        }
    }

    fn freshness_id_from(
        provider_type: &str,
        provider_config: &serde_json::Value,
        vault_id: &VaultId,
        ephemeral_namespace: Option<&str>,
    ) -> Result<VaultId> {
        let stable_identity = match provider_type {
            "memory" => serde_json::json!({ "instance": ephemeral_namespace }),
            "local" => serde_json::json!({ "root": provider_config.get("root") }),
            "gdrive" => serde_json::json!({ "folder_id": provider_config.get("folder_id") }),
            "dropbox" => serde_json::json!({ "root_path": provider_config.get("root_path") }),
            "onedrive" => serde_json::json!({
                "drive_id": provider_config.get("drive_id"),
                "folder_id": provider_config.get("folder_id"),
                "root_path": provider_config.get("root_path")
            }),
            _ => provider_config.clone(),
        };
        let material = serde_json::to_vec(&serde_json::json!({
            "provider": provider_type,
            "vault_id": vault_id.as_str(),
            "identity": stable_identity,
        }))
        .map_err(|error| Error::Serialization(error.to_string()))?;
        VaultId::new(format!("anchor-{}", digest(&material)))
    }

    fn freshness_id(
        &self,
        provider_type: &str,
        provider_config: &serde_json::Value,
        vault_id: &VaultId,
    ) -> Result<VaultId> {
        Self::freshness_id_from(
            provider_type,
            provider_config,
            vault_id,
            Some(&self.ephemeral_namespace),
        )
    }

    /// Get the provider registry.
    pub fn registry(&self) -> &ProviderRegistry {
        &self.registry
    }

    /// Get mutable provider registry.
    pub fn registry_mut(&mut self) -> &mut ProviderRegistry {
        &mut self.registry
    }

    fn runtime_provider_config(
        &self,
        provider_type: &str,
        provider_config: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        if !is_oauth_cloud_provider(provider_type) || provider_config.get("tokens").is_some() {
            return Ok(provider_config.clone());
        }

        let safe_config = persisted_provider_config(provider_type, provider_config)?;
        let credential_ref = safe_config["credential_ref"]
            .as_str()
            .expect("persisted_provider_config validates credential_ref");
        let resolver = self.credential_resolver.as_ref().ok_or_else(|| {
            Error::InvalidInput(format!(
                "Cloud credential reference '{credential_ref}' must be resolved by a local credential resolver"
            ))
        })?;
        let credentials = resolver.resolve(provider_type, credential_ref)?;
        let tokens = credentials.get("tokens").cloned().ok_or_else(|| {
            Error::InvalidInput(format!(
                "Local credential reference '{credential_ref}' did not resolve OAuth tokens"
            ))
        })?;
        let mut runtime_config = safe_config;
        runtime_config["tokens"] = tokens;
        if let Some(auth_config) = credentials.get("auth_config") {
            runtime_config["auth_config"] = auth_config.clone();
        }
        Ok(runtime_config)
    }

    async fn load_bound_snapshot(
        provider: &Arc<dyn StorageProvider>,
        master_key: &MasterKey,
        manifest_bytes: &[u8],
    ) -> Result<(VaultConfig, Vec<u8>, VaultTree, GenerationManifest)> {
        let manifest = GenerationManifest::open(master_key, manifest_bytes)?;
        let (tree_path, config_path) = manifest.object_paths()?;
        if !provider.exists(&tree_path).await? || !provider.exists(&config_path).await? {
            return Err(Error::Crypto(
                "snapshot manifest references a missing generation object".to_string(),
            ));
        }
        let encrypted_tree = provider.download(&tree_path).await?;
        let config_bytes = provider.download(&config_path).await?;
        let config = VaultConfig::from_bytes(&config_bytes)?;
        manifest.verify_bindings(&config.id, &encrypted_tree, &config_bytes)?;
        let tree = VaultSession::decrypt_tree_bytes(master_key, &encrypted_tree)?;
        Ok((config, config_bytes, tree, manifest))
    }

    /// Create a new vault.
    ///
    /// # Returns
    /// A `VaultCreation` with the active session and recovery words.
    pub async fn create_vault(
        &self,
        vault_id: VaultId,
        password: &[u8],
        provider_type: &str,
        provider_config: serde_json::Value,
        kdf_params: KdfParams,
    ) -> Result<VaultCreation> {
        let anchor_id = self.freshness_id(provider_type, &provider_config, &vault_id)?;
        if self.freshness_anchor.load(&anchor_id)?.is_some() {
            return Err(Error::AlreadyExists(
                "freshness anchor already exists for vault ID".to_string(),
            ));
        }
        let runtime_config = self.runtime_provider_config(provider_type, &provider_config)?;
        let provider = self.registry.resolve(provider_type, runtime_config)?;
        let persisted_config = persisted_provider_config(provider_type, &provider_config)?;

        let creation = VaultConfig::new(
            vault_id,
            password,
            provider_type,
            persisted_config,
            kdf_params,
        )?;

        self.initialize_vault_structure(&provider, &creation.config)
            .await?;

        // Use from_master_key to avoid a second Argon2id KDF round.
        let session = VaultSession::from_master_key_with_freshness(
            creation.config,
            creation.master_key,
            provider,
            VaultTree::new(),
            self.freshness_anchor.clone(),
            anchor_id,
            0,
        )?;
        session.save_tree().await?;

        Ok(VaultCreation {
            session,
            recovery_words: creation.recovery_words,
        })
    }

    /// Initialize vault directory structure.
    async fn initialize_vault_structure(
        &self,
        provider: &Arc<dyn StorageProvider>,
        config: &VaultConfig,
    ) -> Result<()> {
        let data_path = VaultPath::parse(DATA_DIRNAME)?;
        if !provider.exists(&data_path).await? {
            provider.create_dir(&data_path).await?;
        }

        let meta_path = VaultPath::parse(META_DIRNAME)?;
        if !provider.exists(&meta_path).await? {
            provider.create_dir(&meta_path).await?;
        }

        let config_path = VaultPath::parse(CONFIG_FILENAME)?;
        let config_bytes = config.to_bytes()?;
        provider.upload(&config_path, config_bytes).await?;

        Ok(())
    }

    /// Open an existing vault.
    pub async fn open_vault(
        &self,
        provider_type: &str,
        provider_config: serde_json::Value,
        password: &[u8],
    ) -> Result<VaultSession> {
        let runtime_config = self.runtime_provider_config(provider_type, &provider_config)?;
        let provider = self.registry.resolve(provider_type, runtime_config)?;

        let config_path = VaultPath::parse(CONFIG_FILENAME)?;
        let manifest_path = VaultPath::parse(META_DIRNAME)?.join(MANIFEST_FILENAME)?;

        if provider.exists(&manifest_path).await? {
            let manifest_bytes = provider.download(&manifest_path).await?;
            let credential_config_bytes =
                match GenerationManifest::config_path_hint(&manifest_bytes)? {
                    Some(path) => provider.download(&path).await?,
                    None => {
                        if !provider.exists(&config_path).await? {
                            return Err(Error::NotFound(
                                "Vault configuration not found".to_string(),
                            ));
                        }
                        provider.download(&config_path).await?
                    }
                };
            let credential_config = VaultConfig::from_bytes(&credential_config_bytes)?;
            let master_key = credential_config
                .verify_password(password)?
                .ok_or_else(|| Error::NotPermitted("Invalid password".to_string()))?;
            let (snapshot_config, snapshot_config_bytes, tree, manifest) =
                Self::load_bound_snapshot(&provider, &master_key, &manifest_bytes).await?;
            let current_master_key =
                snapshot_config.verify_password(password)?.ok_or_else(|| {
                    Error::Conflict(
                        "vault config does not match the current authenticated snapshot"
                            .to_string(),
                    )
                })?;
            if current_master_key.as_bytes() != master_key.as_bytes() {
                return Err(Error::Crypto(
                    "snapshot config unwraps a different master key".to_string(),
                ));
            }
            let mut config = snapshot_config;
            let upgrade = needs_format_upgrade(&config)?;
            let anchor_id = self.freshness_id(provider_type, &provider_config, &config.id)?;
            let anchored_state = self.freshness_anchor.load_state(&anchor_id)?;
            if let Some(accepted) = &anchored_state {
                if manifest.generation < accepted.generation {
                    return Err(Error::Conflict(format!(
                        "vault snapshot rollback detected: generation {} is older than trusted generation {}",
                        manifest.generation, accepted.generation
                    )));
                }
                if manifest.generation == accepted.generation
                    && accepted
                        .manifest_digest
                        .as_ref()
                        .is_some_and(|identity| identity != &digest(&manifest_bytes))
                {
                    return Err(Error::Conflict(
                        "same-generation snapshot fork detected".to_string(),
                    ));
                }
            }
            self.freshness_anchor.store_state(
                &anchor_id,
                FreshnessState {
                    generation: manifest.generation,
                    manifest_digest: Some(digest(&manifest_bytes)),
                },
            )?;
            let _ = provider.upload(&config_path, snapshot_config_bytes).await;
            if upgrade {
                config.version = VaultVersion::CURRENT;
            }
            let session = VaultSession::from_master_key_with_freshness(
                config,
                master_key,
                provider,
                tree,
                self.freshness_anchor.clone(),
                anchor_id,
                manifest.generation,
            )?;
            if upgrade {
                // Commits a 2.0 generation; on failure the 1.1 snapshot stays current.
                session.save_tree().await?;
            }
            return Ok(session);
        }

        if !provider.exists(&config_path).await? {
            return Err(Error::NotFound("Vault configuration not found".to_string()));
        }
        let config_bytes = provider.download(&config_path).await?;
        let mut config = VaultConfig::from_bytes(&config_bytes)?;

        let anchor_id = self.freshness_id(provider_type, &provider_config, &config.id)?;
        let anchored_state = self.freshness_anchor.load_state(&anchor_id)?;
        let master_key = config
            .verify_password(password)?
            .ok_or_else(|| Error::NotPermitted("Invalid password".to_string()))?;

        if anchored_state.is_some() {
            return Err(Error::Conflict(
                "snapshot manifest missing for a vault with trusted freshness state".to_string(),
            ));
        }
        let upgrade = needs_format_upgrade(&config)?;

        // Legacy bootstrap is allowed only when neither storage nor this device has
        // freshness state. Authenticate and decrypt before sanitizing a legacy config.
        let tree = VaultSession::load_and_decrypt_tree(&provider, &master_key).await?;
        if is_oauth_cloud_provider(provider_type) {
            let safe_config = persisted_provider_config(provider_type, &provider_config)?;
            if config.provider_config != safe_config {
                config.provider_config = safe_config;
                provider.upload(&config_path, config.to_bytes()?).await?;
            }
        }
        // Relabel only after the sanitizing upload above, so the first manifest
        // (written by `save_tree` below) precedes any 2.0 `vault.config`.
        if upgrade {
            config.version = VaultVersion::CURRENT;
        }

        let session = VaultSession::from_master_key_with_freshness(
            config,
            master_key,
            provider,
            tree,
            self.freshness_anchor.clone(),
            anchor_id,
            0,
        )?;
        session.save_tree().await?;
        Ok(session)
    }

    /// Reset vault password using recovery key words.
    ///
    /// # Postconditions
    /// - Vault password is changed to new_password
    /// - Recovery key is unchanged
    /// - Returns an active session
    pub async fn recover_vault(
        &self,
        provider_type: &str,
        provider_config: serde_json::Value,
        recovery_words: &str,
        new_password: &[u8],
    ) -> Result<VaultSession> {
        let runtime_config = self.runtime_provider_config(provider_type, &provider_config)?;
        let provider = self.registry.resolve(provider_type, runtime_config)?;

        let config_path = VaultPath::parse(CONFIG_FILENAME)?;
        let recovery_key = RecoveryKey::from_mnemonic(recovery_words)?;

        // Verify the currently stored authenticated snapshot before mutating config.
        let manifest_path = VaultPath::parse(META_DIRNAME)?.join(MANIFEST_FILENAME)?;
        let stored_manifest = if provider.exists(&manifest_path).await? {
            Some(provider.download(&manifest_path).await?)
        } else {
            None
        };
        let credential_config_bytes = match stored_manifest.as_deref() {
            Some(bytes) => match GenerationManifest::config_path_hint(bytes)? {
                Some(path) => provider.download(&path).await?,
                None => {
                    if !provider.exists(&config_path).await? {
                        return Err(Error::NotFound("Vault configuration not found".to_string()));
                    }
                    provider.download(&config_path).await?
                }
            },
            None => {
                if !provider.exists(&config_path).await? {
                    return Err(Error::NotFound("Vault configuration not found".to_string()));
                }
                provider.download(&config_path).await?
            }
        };
        let credential_config = VaultConfig::from_bytes(&credential_config_bytes)?;
        let mut config = credential_config.clone();
        let master_key = credential_config
            .verify_recovery_key(&recovery_key)?
            .ok_or_else(|| Error::NotPermitted("Invalid recovery key".to_string()))?;

        let (tree, generation) = if let Some(manifest_bytes) = stored_manifest {
            let (snapshot_config, snapshot_config_bytes, tree, manifest) =
                Self::load_bound_snapshot(&provider, &master_key, &manifest_bytes).await?;
            let current_master_key = snapshot_config
                .verify_recovery_key(&recovery_key)?
                .ok_or_else(|| Error::NotPermitted("Invalid recovery key".to_string()))?;
            if current_master_key.as_bytes() != master_key.as_bytes() {
                return Err(Error::Crypto(
                    "snapshot recovery config unwraps a different master key".to_string(),
                ));
            }
            config = snapshot_config;
            let anchor_id = self.freshness_id(provider_type, &provider_config, &config.id)?;
            let anchored_state = self.freshness_anchor.load_state(&anchor_id)?;
            if let Some(accepted) = &anchored_state {
                if manifest.generation < accepted.generation {
                    return Err(Error::Conflict(
                        "vault snapshot rollback detected during recovery".to_string(),
                    ));
                }
                if manifest.generation == accepted.generation
                    && accepted
                        .manifest_digest
                        .as_ref()
                        .is_some_and(|identity| identity != &digest(&manifest_bytes))
                {
                    return Err(Error::Conflict(
                        "same-generation snapshot fork detected during recovery".to_string(),
                    ));
                }
            }
            self.freshness_anchor.store_state(
                &anchor_id,
                FreshnessState {
                    generation: manifest.generation,
                    manifest_digest: Some(digest(&manifest_bytes)),
                },
            )?;
            let _ = provider.upload(&config_path, snapshot_config_bytes).await;
            (tree, manifest.generation)
        } else {
            let anchor_id = self.freshness_id(provider_type, &provider_config, &config.id)?;
            let anchored_state = self.freshness_anchor.load_state(&anchor_id)?;
            if anchored_state.is_some() {
                return Err(Error::Conflict(
                    "snapshot manifest missing for a vault with trusted freshness state"
                        .to_string(),
                ));
            }
            (
                VaultSession::load_and_decrypt_tree(&provider, &master_key).await?,
                0,
            )
        };

        // A 1.1 vault is published as 2.0 by the `save_tree` below.
        if needs_format_upgrade(&config)? {
            config.version = VaultVersion::CURRENT;
        }

        // Reset password in config. The master key itself doesn't change.
        config.reset_password(&recovery_key, new_password)?;
        if is_oauth_cloud_provider(provider_type) {
            config.provider_config = persisted_provider_config(provider_type, &provider_config)?;
        }

        let anchor_id = self.freshness_id(provider_type, &provider_config, &config.id)?;
        let session = VaultSession::from_master_key_with_freshness(
            config,
            master_key,
            provider.clone(),
            tree,
            self.freshness_anchor.clone(),
            anchor_id,
            generation,
        )?;
        session.save_tree().await?;
        Ok(session)
    }

    /// Check if a vault exists at the given location.
    pub async fn vault_exists(
        &self,
        provider_type: &str,
        provider_config: serde_json::Value,
    ) -> Result<bool> {
        let runtime_config = self.runtime_provider_config(provider_type, &provider_config)?;
        let provider = self.registry.resolve(provider_type, runtime_config)?;
        let config_path = VaultPath::parse(CONFIG_FILENAME)?;
        if provider.exists(&config_path).await? {
            return Ok(true);
        }
        let manifest_path = VaultPath::parse(META_DIRNAME)?.join(MANIFEST_FILENAME)?;
        provider.exists(&manifest_path).await
    }

    /// Save vault configuration to storage.
    pub async fn save_config(&self, session: &mut VaultSession) -> Result<()> {
        if let Err(error) = session.save_tree_with_config().await {
            session.restore_committed_config()?;
            return Err(error);
        }
        Ok(())
    }

    /// Save vault tree to storage (encrypted).
    pub async fn save_tree(&self, session: &VaultSession) -> Result<()> {
        session.save_tree().await
    }
}

impl Default for VaultManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::freshness::{FreshnessAnchor, InMemoryFreshnessAnchor};
    use crate::manifest::MANIFEST_FILENAME;
    use async_trait::async_trait;
    use axiomvault_storage::{ByteStream, MemoryProvider, Metadata};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct ManifestFailProvider {
        inner: MemoryProvider,
        fail_next_manifest: AtomicBool,
        pause_next_tree_after_commit: AtomicBool,
        pause_next_canonical_tree_after_commit: AtomicBool,
    }

    impl ManifestFailProvider {
        fn new() -> Self {
            Self {
                inner: MemoryProvider::new(),
                fail_next_manifest: AtomicBool::new(false),
                pause_next_tree_after_commit: AtomicBool::new(false),
                pause_next_canonical_tree_after_commit: AtomicBool::new(false),
            }
        }

        fn fail_next_manifest(&self) {
            self.fail_next_manifest.store(true, Ordering::SeqCst);
        }

        fn pause_next_tree_after_commit(&self) {
            self.pause_next_tree_after_commit
                .store(true, Ordering::SeqCst);
        }

        fn pause_next_canonical_tree_after_commit(&self) {
            self.pause_next_canonical_tree_after_commit
                .store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl StorageProvider for ManifestFailProvider {
        fn name(&self) -> &str {
            "manifest-fail"
        }

        async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
            if path == &manifest_path() && self.fail_next_manifest.swap(false, Ordering::SeqCst) {
                return Err(Error::Storage("injected manifest failure".to_string()));
            }
            let metadata = self.inner.upload(path, data).await?;
            let name = path.name().unwrap_or_default();
            if (path == &tree_path() || name.starts_with("tree."))
                && self
                    .pause_next_tree_after_commit
                    .swap(false, Ordering::SeqCst)
            {
                std::future::pending::<()>().await;
            }
            if path == &tree_path()
                && self
                    .pause_next_canonical_tree_after_commit
                    .swap(false, Ordering::SeqCst)
            {
                std::future::pending::<()>().await;
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

    struct ToggleStoreFailureAnchor {
        inner: InMemoryFreshnessAnchor,
        fail_next_store: AtomicBool,
    }

    impl ToggleStoreFailureAnchor {
        fn new() -> Self {
            Self {
                inner: InMemoryFreshnessAnchor::new(),
                fail_next_store: AtomicBool::new(false),
            }
        }

        fn fail_next_store(&self) {
            self.fail_next_store.store(true, Ordering::SeqCst);
        }
    }

    impl FreshnessAnchor for ToggleStoreFailureAnchor {
        fn load(&self, vault_id: &VaultId) -> Result<Option<u64>> {
            self.inner.load(vault_id)
        }

        fn store(&self, vault_id: &VaultId, generation: u64) -> Result<()> {
            self.inner.store(vault_id, generation)
        }

        fn load_state(&self, vault_id: &VaultId) -> Result<Option<FreshnessState>> {
            self.inner.load_state(vault_id)
        }

        fn store_state(&self, vault_id: &VaultId, state: FreshnessState) -> Result<()> {
            if self.fail_next_store.swap(false, Ordering::SeqCst) {
                return Err(Error::Vault("injected anchor failure".to_string()));
            }
            self.inner.store_state(vault_id, state)
        }
    }

    fn test_anchor_id(vault_id: &VaultId) -> VaultId {
        VaultManager::freshness_id_from("test", &serde_json::Value::Null, vault_id, None).unwrap()
    }

    #[test]
    fn freshness_identity_distinguishes_providers_and_ignores_rotating_cloud_tokens() {
        let id = VaultId::new("same-user-id").unwrap();
        let local_a = VaultManager::freshness_id_from(
            "local",
            &serde_json::json!({"root": "/tmp/a"}),
            &id,
            None,
        )
        .unwrap();
        let local_b = VaultManager::freshness_id_from(
            "local",
            &serde_json::json!({"root": "/tmp/b"}),
            &id,
            None,
        )
        .unwrap();
        assert_ne!(local_a, local_b);

        let cloud_a = VaultManager::freshness_id_from(
            "gdrive",
            &serde_json::json!({"folder_id": "stable", "tokens": {"access_token": "a"}}),
            &id,
            None,
        )
        .unwrap();
        let cloud_b = VaultManager::freshness_id_from(
            "gdrive",
            &serde_json::json!({"folder_id": "stable", "tokens": {"access_token": "b"}}),
            &id,
            None,
        )
        .unwrap();
        assert_eq!(cloud_a, cloud_b);

        let memory_a = VaultManager::freshness_id_from(
            "memory",
            &serde_json::Value::Null,
            &id,
            Some("instance-a"),
        )
        .unwrap();
        let memory_b = VaultManager::freshness_id_from(
            "memory",
            &serde_json::Value::Null,
            &id,
            Some("instance-b"),
        )
        .unwrap();
        assert_ne!(memory_a, memory_b);
    }

    fn manager_with_storage(
        provider: Arc<MemoryProvider>,
        anchor: Arc<dyn FreshnessAnchor>,
    ) -> VaultManager {
        let mut registry = ProviderRegistry::new();
        registry
            .register("test", Box::new(move |_| Ok(provider.clone())))
            .unwrap();
        VaultManager::with_registry_and_anchor(registry, anchor)
    }

    fn manager_with_manifest_failure_storage(
        provider: Arc<ManifestFailProvider>,
        anchor: Arc<dyn FreshnessAnchor>,
    ) -> VaultManager {
        let mut registry = ProviderRegistry::new();
        registry
            .register("test", Box::new(move |_| Ok(provider.clone())))
            .unwrap();
        VaultManager::with_registry_and_anchor(registry, anchor)
    }

    fn tree_path() -> VaultPath {
        VaultPath::parse(META_DIRNAME)
            .unwrap()
            .join(crate::config::TREE_FILENAME)
            .unwrap()
    }

    fn manifest_path() -> VaultPath {
        VaultPath::parse(META_DIRNAME)
            .unwrap()
            .join(MANIFEST_FILENAME)
            .unwrap()
    }

    async fn stored_snapshot<P: StorageProvider + ?Sized>(
        provider: &P,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            provider
                .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
                .await
                .unwrap(),
            provider.download(&tree_path()).await.unwrap(),
            provider.download(&manifest_path()).await.unwrap(),
        )
    }

    struct FailingAnchor;

    impl FreshnessAnchor for FailingAnchor {
        fn load(&self, _vault_id: &VaultId) -> Result<Option<u64>> {
            Err(Error::Vault("anchor I/O failed".to_string()))
        }

        fn store(&self, _vault_id: &VaultId, _generation: u64) -> Result<()> {
            Err(Error::Vault("anchor I/O failed".to_string()))
        }
    }

    #[tokio::test]
    async fn anchor_read_errors_fail_closed_before_create() {
        let provider = Arc::new(MemoryProvider::new());
        let manager = manager_with_storage(provider.clone(), Arc::new(FailingAnchor));
        let result = manager
            .create_vault(
                VaultId::new("anchor-error").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await;

        assert!(result.is_err());
        assert!(!provider
            .exists(&VaultPath::parse(CONFIG_FILENAME).unwrap())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn removing_manifest_after_anchor_exists_is_rejected() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        manager
            .create_vault(
                VaultId::new("missing-manifest").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        provider.delete(&manifest_path()).await.unwrap();

        let error = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("missing manifest must fail closed");
        assert!(error.to_string().contains("manifest missing"));
    }

    #[tokio::test]
    async fn create_persists_authenticated_generation_and_anchor() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("fresh-vault").unwrap();

        manager
            .create_vault(
                vault_id.clone(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();

        let manifest_path = VaultPath::parse(META_DIRNAME)
            .unwrap()
            .join(MANIFEST_FILENAME)
            .unwrap();
        assert!(provider.exists(&manifest_path).await.unwrap());
        assert_eq!(anchor.load(&test_anchor_id(&vault_id)).unwrap(), Some(1));
    }

    #[tokio::test]
    async fn open_restores_generation_for_the_next_update() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider, anchor.clone());
        let vault_id = VaultId::new("reopen-update").unwrap();
        let creation = manager
            .create_vault(
                vault_id.clone(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        drop(creation);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        reopened.save_tree().await.unwrap();

        assert_eq!(anchor.load(&test_anchor_id(&vault_id)).unwrap(), Some(2));
    }

    #[tokio::test]
    async fn replaying_an_older_file_ciphertext_is_rejected() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor);
        let creation = manager
            .create_vault(
                VaultId::new("file-rollback").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let ops = VaultOperations::new(&creation.session).unwrap();
        let path = VaultPath::parse("/note.txt").unwrap();
        ops.create_file(&path, b"generation one").await.unwrap();
        let encrypted_name = creation
            .session
            .tree()
            .read()
            .await
            .get_node(&path)
            .unwrap()
            .metadata
            .encrypted_name
            .clone();
        let object_path = VaultPath::parse(DATA_DIRNAME)
            .unwrap()
            .join(&encrypted_name)
            .unwrap();
        let old_ciphertext = provider.download(&object_path).await.unwrap();

        ops.update_file(&path, b"generation two").await.unwrap();
        let current_encrypted_name = creation
            .session
            .tree()
            .read()
            .await
            .get_node(&path)
            .unwrap()
            .metadata
            .encrypted_name
            .clone();
        let current_object_path = VaultPath::parse(DATA_DIRNAME)
            .unwrap()
            .join(&current_encrypted_name)
            .unwrap();
        provider
            .upload(&current_object_path, old_ciphertext)
            .await
            .unwrap();

        assert!(ops.read_file(&path).await.is_err());
    }

    #[tokio::test]
    async fn password_change_commits_a_new_authenticated_generation() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider, anchor.clone());
        let vault_id = VaultId::new("password-generation").unwrap();
        let mut creation = manager
            .create_vault(
                vault_id.clone(),
                b"old-password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();

        creation
            .session
            .change_password(b"old-password", b"new-password")
            .unwrap();
        manager.save_config(&mut creation.session).await.unwrap();
        drop(creation);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .unwrap();
        assert!(reopened.is_active());
        assert_eq!(anchor.load(&test_anchor_id(&vault_id)).unwrap(), Some(2));
    }

    #[tokio::test]
    async fn recovery_password_reset_commits_a_fresh_generation() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider, anchor.clone());
        let vault_id = VaultId::new("recovery-generation").unwrap();
        let creation = manager
            .create_vault(
                vault_id.clone(),
                b"old-password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let words = creation.recovery_words.clone();
        drop(creation);

        manager
            .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
            .await
            .unwrap();
        manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .unwrap();
        assert_eq!(anchor.load(&test_anchor_id(&vault_id)).unwrap(), Some(2));
    }

    #[tokio::test]
    async fn directory_manifest_failure_restores_previous_snapshot_and_reopens() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(ManifestFailProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_manifest_failure_storage(provider.clone(), anchor);
        let creation = manager
            .create_vault(
                VaultId::new("manifest-publication-rollback").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let previous = stored_snapshot(provider.as_ref()).await;
        provider.fail_next_manifest();
        assert!(VaultOperations::new(&creation.session)
            .unwrap()
            .create_directory(&VaultPath::parse("/uncommitted").unwrap())
            .await
            .is_err());
        assert_eq!(stored_snapshot(provider.as_ref()).await, previous);
        drop(creation);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert!(
            !VaultOperations::new(&reopened)
                .unwrap()
                .exists(&VaultPath::parse("/uncommitted").unwrap())
                .await
        );
    }

    #[tokio::test]
    async fn transient_anchor_failure_is_retried_before_publication_returns() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(ToggleStoreFailureAnchor::new());
        let manager = manager_with_storage(provider, anchor.clone());
        let creation = manager
            .create_vault(
                VaultId::new("directory-publication-rollback").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let ops = VaultOperations::new(&creation.session).unwrap();
        anchor.fail_next_store();
        assert!(ops
            .create_directory(&VaultPath::parse("/committed").unwrap())
            .await
            .is_ok());
        drop(creation);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert!(
            VaultOperations::new(&reopened)
                .unwrap()
                .exists(&VaultPath::parse("/committed").unwrap())
                .await
        );
    }

    #[tokio::test]
    async fn config_publication_failure_rolls_back_and_old_password_reopens() {
        let provider = Arc::new(ManifestFailProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_manifest_failure_storage(provider.clone(), anchor);
        let mut creation = manager
            .create_vault(
                VaultId::new("config-publication-rollback").unwrap(),
                b"old-password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        creation
            .session
            .change_password(b"old-password", b"new-password")
            .unwrap();
        provider.fail_next_manifest();
        assert!(manager.save_config(&mut creation.session).await.is_err());
        assert!(creation
            .session
            .config()
            .verify_password(b"old-password")
            .unwrap()
            .is_some());
        assert!(creation
            .session
            .config()
            .verify_password(b"new-password")
            .unwrap()
            .is_none());
        drop(creation);

        assert!(manager
            .open_vault("test", serde_json::Value::Null, b"old-password")
            .await
            .is_ok());
        assert!(manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cancellation_after_tree_upload_keeps_previous_snapshot_openable() {
        use crate::operations::VaultOperations;
        use std::time::Duration;

        let provider = Arc::new(ManifestFailProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_manifest_failure_storage(provider.clone(), anchor);
        let creation = manager
            .create_vault(
                VaultId::new("cancelled-tree-publication").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();

        provider.pause_next_tree_after_commit();
        let path = VaultPath::parse("/uncommitted").unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            VaultOperations::new(&creation.session)
                .unwrap()
                .create_directory(&path),
        )
        .await;
        assert!(result.is_err(), "publication future must be cancelled");
        drop(creation);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .expect("the previous committed snapshot must remain openable");
        assert!(!VaultOperations::new(&reopened).unwrap().exists(&path).await);
    }

    #[tokio::test]
    async fn cancellation_after_manifest_commit_makes_live_session_stale() {
        use crate::operations::VaultOperations;
        use std::time::Duration;

        let provider = Arc::new(ManifestFailProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_manifest_failure_storage(provider.clone(), anchor);
        let creation = manager
            .create_vault(
                VaultId::new("cancelled-postcommit-publication").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let ops = VaultOperations::new(&creation.session).unwrap();
        let committed = VaultPath::parse("/committed").unwrap();

        provider.pause_next_canonical_tree_after_commit();
        let result =
            tokio::time::timeout(Duration::from_millis(50), ops.create_directory(&committed)).await;
        assert!(result.is_err(), "publication future must be cancelled");
        assert!(!ops.exists(&committed).await);
        let stale_error = ops
            .create_directory(&VaultPath::parse("/must-reopen").unwrap())
            .await
            .expect_err("a post-commit cancelled session must not publish again");
        assert!(stale_error.to_string().contains("advanced"));
        drop(creation);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert!(
            VaultOperations::new(&reopened)
                .unwrap()
                .exists(&committed)
                .await
        );
    }

    #[tokio::test]
    async fn cancelled_v1_password_upgrade_keeps_old_snapshot_openable() {
        use std::time::Duration;

        let provider = Arc::new(ManifestFailProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_manifest_failure_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("cancelled-v1-password-upgrade").unwrap();
        let creation = VaultConfig::new(
            vault_id.clone(),
            b"old-password",
            "test",
            serde_json::Value::Null,
            KdfParams::moderate(),
        )
        .unwrap();
        let config_bytes = creation.config.to_bytes().unwrap();
        let storage: Arc<dyn StorageProvider> = provider.clone();
        manager
            .initialize_vault_structure(&storage, &creation.config)
            .await
            .unwrap();
        let legacy = VaultSession::from_master_key(
            creation.config,
            creation.master_key,
            provider.clone(),
            VaultTree::new(),
        )
        .unwrap();
        legacy.save_tree().await.unwrap();
        let encrypted_tree = provider.download(&tree_path()).await.unwrap();
        let legacy_manifest = GenerationManifest::legacy_for_test(
            vault_id.clone(),
            1,
            &encrypted_tree,
            &config_bytes,
            Default::default(),
        );
        let legacy_manifest_bytes = legacy_manifest.seal(legacy.master_key().unwrap()).unwrap();
        provider
            .upload(&manifest_path(), legacy_manifest_bytes.clone())
            .await
            .unwrap();
        anchor
            .store_state(
                &test_anchor_id(&vault_id),
                FreshnessState {
                    generation: 1,
                    manifest_digest: Some(digest(&legacy_manifest_bytes)),
                },
            )
            .unwrap();
        drop(legacy);

        let mut session = manager
            .open_vault("test", serde_json::Value::Null, b"old-password")
            .await
            .unwrap();
        session
            .change_password(b"old-password", b"new-password")
            .unwrap();
        provider.pause_next_tree_after_commit();
        let result =
            tokio::time::timeout(Duration::from_millis(50), manager.save_config(&mut session))
                .await;
        assert!(result.is_err(), "v1 upgrade must be cancelled pre-commit");
        let pending_error = crate::operations::VaultOperations::new(&session)
            .unwrap()
            .create_directory(&VaultPath::parse("/must-save-config-first").unwrap())
            .await
            .expect_err("pending config must not leak into a later tree mutation");
        assert!(pending_error.to_string().contains("uncommitted changes"));
        drop(session);

        assert!(manager
            .open_vault("test", serde_json::Value::Null, b"old-password")
            .await
            .is_ok());
        assert!(manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn stale_concurrent_session_cannot_publish_same_generation_fork() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider, anchor);
        let creation = manager
            .create_vault(
                VaultId::new("same-generation-fork").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        drop(creation);
        let session_a = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        let session_b = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();

        let ops_a = VaultOperations::new(&session_a).unwrap();
        let ops_b = VaultOperations::new(&session_b).unwrap();
        let accepted_path = VaultPath::parse("/accepted-a").unwrap();
        let fork_path = VaultPath::parse("/accepted-b").unwrap();
        let (result_a, result_b) = tokio::join!(
            ops_a.create_directory(&accepted_path),
            ops_b.create_directory(&fork_path)
        );
        assert_ne!(result_a.is_ok(), result_b.is_ok());
        let rejected = result_a.err().or_else(|| result_b.err()).unwrap();
        assert!(rejected.to_string().contains("advanced"));
        drop(session_a);
        drop(session_b);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        let ops = VaultOperations::new(&reopened).unwrap();
        assert_ne!(
            ops.exists(&accepted_path).await,
            ops.exists(&fork_path).await
        );
    }

    #[tokio::test]
    async fn full_snapshot_rollback_is_rejected() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor);
        let creation = manager
            .create_vault(
                VaultId::new("full-rollback").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let old = stored_snapshot(provider.as_ref()).await;
        creation.session.save_tree().await.unwrap();
        provider
            .upload(&VaultPath::parse(CONFIG_FILENAME).unwrap(), old.0)
            .await
            .unwrap();
        provider.upload(&tree_path(), old.1).await.unwrap();
        provider.upload(&manifest_path(), old.2).await.unwrap();

        let error = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("rollback must be rejected");
        assert!(matches!(error, Error::NotFound(_) | Error::Conflict(_)));
    }

    #[tokio::test]
    async fn mixed_tree_and_manifest_generations_are_rejected() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let creation = manager
            .create_vault(
                VaultId::new("mixed-generation").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let first_manifest_bytes = provider.download(&manifest_path()).await.unwrap();
        let first_manifest = GenerationManifest::open(
            creation.session.master_key().unwrap(),
            &first_manifest_bytes,
        )
        .unwrap();
        let (first_tree_path, _) = first_manifest.object_paths().unwrap();
        let old_tree = provider.download(&first_tree_path).await.unwrap();
        creation.session.save_tree().await.unwrap();
        let current_manifest_bytes = provider.download(&manifest_path()).await.unwrap();
        let current_manifest = GenerationManifest::open(
            creation.session.master_key().unwrap(),
            &current_manifest_bytes,
        )
        .unwrap();
        let (current_tree_path, _) = current_manifest.object_paths().unwrap();
        provider.upload(&current_tree_path, old_tree).await.unwrap();

        let error = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("rollback must be rejected");
        assert!(error.to_string().contains("tree and manifest"));
    }

    #[tokio::test]
    async fn tampered_manifest_is_rejected() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        manager
            .create_vault(
                VaultId::new("manifest-tamper").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let mut bytes = provider.download(&manifest_path()).await.unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        provider.upload(&manifest_path(), bytes).await.unwrap();

        let error = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("rollback must be rejected");
        assert!(error.to_string().contains("authentication failed"));
    }

    #[tokio::test]
    async fn unauthenticated_manifest_config_hint_cannot_escape_generation_namespace() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        manager
            .create_vault(
                VaultId::new("manifest-hint-tamper").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&provider.download(&manifest_path()).await.unwrap()).unwrap();
        envelope["config_object"] = serde_json::Value::String("/vault.config".to_string());
        provider
            .upload(&manifest_path(), serde_json::to_vec(&envelope).unwrap())
            .await
            .unwrap();

        let error = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("an out-of-namespace hint must fail closed");
        assert!(error.to_string().contains("invalid config object hint"));
    }

    #[tokio::test]
    async fn unauthenticated_config_cannot_request_excessive_kdf_resources() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        manager
            .create_vault(
                VaultId::new("kdf-resource-limit").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let manifest_bytes = provider.download(&manifest_path()).await.unwrap();
        let config_path = GenerationManifest::config_path_hint(&manifest_bytes)
            .unwrap()
            .unwrap();
        let mut config =
            VaultConfig::from_bytes(&provider.download(&config_path).await.unwrap()).unwrap();
        config.kdf_params.memory_cost = 1_048_577;
        provider
            .upload(&config_path, config.to_bytes().unwrap())
            .await
            .unwrap();

        let error = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("excessive KDF parameters must be rejected before derivation");
        assert!(error.to_string().contains("unsafe KDF resource limits"));
    }

    #[tokio::test]
    async fn v2_manifest_opens_without_canonical_config_cache() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        manager
            .create_vault(
                VaultId::new("missing-config-cache").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        provider
            .delete(&VaultPath::parse(CONFIG_FILENAME).unwrap())
            .await
            .unwrap();

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .expect("the authenticated v2 config object is authoritative");
        assert!(reopened.is_active());
    }

    #[tokio::test]
    async fn pre_password_change_config_replay_is_rejected() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let mut creation = manager
            .create_vault(
                VaultId::new("config-rollback").unwrap(),
                b"old-password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let old_config = provider
            .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
            .await
            .unwrap();
        creation
            .session
            .change_password(b"old-password", b"new-password")
            .unwrap();
        manager.save_config(&mut creation.session).await.unwrap();
        provider
            .upload(&VaultPath::parse(CONFIG_FILENAME).unwrap(), old_config)
            .await
            .unwrap();

        let error = manager
            .open_vault("test", serde_json::Value::Null, b"old-password")
            .await
            .err()
            .expect("rollback must be rejected");
        assert!(matches!(error, Error::NotPermitted(_)));
        assert!(manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn authenticated_first_open_bootstraps_a_new_local_anchor() {
        let provider = Arc::new(MemoryProvider::new());
        let creator =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        creator
            .create_vault(
                VaultId::new("first-open").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();

        let new_anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let opener = manager_with_storage(provider, new_anchor.clone());
        opener
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(
            new_anchor
                .load(&test_anchor_id(&VaultId::new("first-open").unwrap()))
                .unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn legacy_vault_without_any_anchor_is_bootstrapped() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let creation = VaultConfig::new(
            VaultId::new("legacy-bootstrap").unwrap(),
            b"password",
            "test",
            serde_json::Value::Null,
            KdfParams::moderate(),
        )
        .unwrap();
        let storage: Arc<dyn StorageProvider> = provider.clone();
        manager
            .initialize_vault_structure(&storage, &creation.config)
            .await
            .unwrap();
        let legacy_session = VaultSession::from_master_key(
            creation.config,
            creation.master_key,
            provider.clone(),
            VaultTree::new(),
        )
        .unwrap();
        legacy_session.save_tree().await.unwrap();
        assert!(!provider.exists(&manifest_path()).await.unwrap());

        manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert!(provider.exists(&manifest_path()).await.unwrap());
        assert_eq!(
            anchor
                .load(&test_anchor_id(&VaultId::new("legacy-bootstrap").unwrap()))
                .unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn test_create_vault() {
        let manager = VaultManager::with_registry_and_anchor(
            create_default_registry(),
            Arc::new(InMemoryFreshnessAnchor::new()),
        );
        let vault_id = VaultId::new("test-vault").unwrap();
        let password = b"secure-password";

        let creation = manager
            .create_vault(
                vault_id.clone(),
                password,
                "memory",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();

        assert!(creation.session.is_active());
        assert_eq!(creation.session.vault_id().as_str(), vault_id.as_str());
        assert_eq!(creation.recovery_words.split_whitespace().count(), 24);
    }

    #[tokio::test]
    async fn test_open_vault() {
        let manager = VaultManager::with_registry_and_anchor(
            create_default_registry(),
            Arc::new(InMemoryFreshnessAnchor::new()),
        );
        let vault_id = VaultId::new("test-vault").unwrap();
        let password = b"secure-password";

        let creation = manager
            .create_vault(
                vault_id.clone(),
                password,
                "memory",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();

        let provider = creation.session.provider();
        drop(creation.session);

        let config_path = VaultPath::parse(CONFIG_FILENAME).unwrap();
        let config_bytes = provider.download(&config_path).await.unwrap();
        let config = VaultConfig::from_bytes(&config_bytes).unwrap();

        let master_key = config
            .verify_password(password)
            .unwrap()
            .expect("password should be correct");

        let tree = VaultSession::load_and_decrypt_tree(&provider, &master_key)
            .await
            .unwrap();

        let reopened = VaultSession::from_master_key(config, master_key, provider, tree).unwrap();
        assert!(reopened.is_active());
        assert_eq!(reopened.vault_id().as_str(), vault_id.as_str());
    }

    #[tokio::test]
    async fn test_vault_exists() {
        let manager = VaultManager::with_registry_and_anchor(
            create_default_registry(),
            Arc::new(InMemoryFreshnessAnchor::new()),
        );

        let exists = manager
            .vault_exists("memory", serde_json::Value::Null)
            .await;
        assert!(exists.is_ok());
    }

    struct TestCredentialResolver;

    impl LocalCredentialResolver for TestCredentialResolver {
        fn resolve(&self, provider_type: &str, credential_ref: &str) -> Result<serde_json::Value> {
            assert_eq!(provider_type, "gdrive");
            assert_eq!(credential_ref, "local:gdrive:resolved");
            Ok(serde_json::json!({
                "tokens": {
                    "access_token": "resolver-access-secret",
                    "refresh_token": "resolver-refresh-secret",
                    "expires_at": "2099-01-01T00:00:00Z"
                },
                "auth_config": {
                    "client_id": "client-id",
                    "client_secret": "resolver-client-secret",
                    "redirect_url": "http://localhost/callback"
                }
            }))
        }
    }

    #[tokio::test]
    async fn opening_legacy_cloud_config_migrates_and_strips_embedded_credentials() {
        let storage = Arc::new(axiomvault_storage::MemoryProvider::new());
        let runtime_config = serde_json::json!({
            "folder_id": "legacy-folder",
            "credential_ref": "local:gdrive:resolved",
            "tokens": {
                "access_token": "initial-local-access",
                "refresh_token": "initial-local-refresh",
                "expires_at": "2099-01-01T00:00:00Z"
            }
        });
        let mut create_registry = ProviderRegistry::new();
        let create_storage = storage.clone();
        create_registry
            .register("gdrive", Box::new(move |_| Ok(create_storage.clone())))
            .unwrap();
        let create_manager = VaultManager::with_registry_and_anchor(
            create_registry,
            Arc::new(InMemoryFreshnessAnchor::new()),
        );
        let creation = create_manager
            .create_vault(
                VaultId::new("legacy-cloud").unwrap(),
                b"password",
                "gdrive",
                runtime_config,
                KdfParams::moderate(),
            )
            .await
            .unwrap();

        let mut legacy: serde_json::Value =
            serde_json::from_slice(&creation.session.config().to_bytes().unwrap()).unwrap();
        legacy["provider_config"] = serde_json::json!({
            "folder_id": "legacy-folder",
            "tokens": {
                "access_token": "legacy-uploaded-access-secret",
                "refresh_token": "legacy-uploaded-refresh-secret",
                "expires_at": "2099-01-01T00:00:00Z"
            },
            "auth_config": {
                "client_id": "legacy-client-id",
                "client_secret": "legacy-uploaded-client-secret",
                "redirect_url": "http://localhost/callback"
            }
        });
        storage
            .upload(
                &VaultPath::parse(CONFIG_FILENAME).unwrap(),
                serde_json::to_vec(&legacy).unwrap(),
            )
            .await
            .unwrap();
        storage
            .delete(
                &VaultPath::parse(META_DIRNAME)
                    .unwrap()
                    .join(MANIFEST_FILENAME)
                    .unwrap(),
            )
            .await
            .unwrap();
        drop(creation);

        let mut open_registry = ProviderRegistry::new();
        let open_storage = storage.clone();
        open_registry
            .register("gdrive", Box::new(move |_| Ok(open_storage.clone())))
            .unwrap();
        let open_manager = VaultManager::with_registry_credential_resolver_and_anchor(
            open_registry,
            Arc::new(TestCredentialResolver),
            Arc::new(InMemoryFreshnessAnchor::new()),
        );
        let safe_config = serde_json::json!({
            "credential_schema": 1,
            "credential_ref": "local:gdrive:resolved",
            "folder_id": "legacy-folder"
        });

        let session = open_manager
            .open_vault("gdrive", safe_config.clone(), b"password")
            .await
            .unwrap();
        assert_eq!(session.config().provider_config, safe_config);
        let migrated = storage
            .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
            .await
            .unwrap();
        let migrated = String::from_utf8(migrated).unwrap();
        assert!(!migrated.contains("legacy-uploaded-access-secret"));
        assert!(!migrated.contains("legacy-uploaded-refresh-secret"));
        assert!(!migrated.contains("legacy-uploaded-client-secret"));
        assert!(migrated.contains("local:gdrive:resolved"));
    }

    #[tokio::test]
    async fn injected_local_credential_resolver_supplies_runtime_secrets_only() {
        let storage = Arc::new(axiomvault_storage::MemoryProvider::new());
        let observed_runtime = Arc::new(std::sync::Mutex::new(None));
        let observed = observed_runtime.clone();
        let resolved = storage.clone();
        let mut registry = ProviderRegistry::new();
        registry
            .register(
                "gdrive",
                Box::new(move |config| {
                    *observed.lock().unwrap() = Some(config);
                    Ok(resolved.clone())
                }),
            )
            .unwrap();
        let manager = VaultManager::with_registry_credential_resolver_and_anchor(
            registry,
            Arc::new(TestCredentialResolver),
            Arc::new(InMemoryFreshnessAnchor::new()),
        );
        let safe_config = serde_json::json!({
            "credential_schema": 1,
            "credential_ref": "local:gdrive:resolved",
            "folder_id": "remote-folder"
        });

        manager
            .create_vault(
                VaultId::new("resolved-local-credential").unwrap(),
                b"password",
                "gdrive",
                safe_config,
                KdfParams::moderate(),
            )
            .await
            .unwrap();

        let runtime = observed_runtime.lock().unwrap().clone().unwrap();
        assert_eq!(runtime["tokens"]["access_token"], "resolver-access-secret");
        let uploaded = storage
            .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
            .await
            .unwrap();
        let uploaded = String::from_utf8(uploaded).unwrap();
        assert!(!uploaded.contains("resolver-access-secret"));
        assert!(!uploaded.contains("resolver-refresh-secret"));
        assert!(!uploaded.contains("resolver-client-secret"));
    }

    #[tokio::test]
    async fn unresolved_cloud_credential_reference_is_rejected_explicitly() {
        let manager = VaultManager::new();
        let error = manager
            .create_vault(
                VaultId::new("missing-local-credential").unwrap(),
                b"password",
                "gdrive",
                serde_json::json!({
                    "credential_schema": 1,
                    "credential_ref": "local:gdrive:missing",
                    "folder_id": "remote-folder"
                }),
                KdfParams::moderate(),
            )
            .await
            .err()
            .expect("an unresolved local credential reference must fail");

        assert!(
            error.to_string().contains("credential reference"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn sibling_cloud_vault_uploads_exclude_oauth_credentials() {
        for (provider_type, identity_key, identity_value) in [
            ("dropbox", "root_path", "/AxiomVault"),
            ("onedrive", "root_path", "/AxiomVault"),
        ] {
            let storage = Arc::new(axiomvault_storage::MemoryProvider::new());
            let mut registry = ProviderRegistry::new();
            let resolved = storage.clone();
            registry
                .register(provider_type, Box::new(move |_| Ok(resolved.clone())))
                .unwrap();
            let manager = VaultManager::with_registry_and_anchor(
                registry,
                Arc::new(InMemoryFreshnessAnchor::new()),
            );
            let mut provider_config = serde_json::json!({
                "credential_ref": format!("local:{provider_type}:test"),
                "tokens": {
                    "access_token": format!("{provider_type}-access-secret"),
                    "refresh_token": format!("{provider_type}-refresh-secret"),
                    "expires_at": "2099-01-01T00:00:00Z"
                },
                "auth_config": {
                    "client_id": "client-id",
                    "client_secret": format!("{provider_type}-client-secret"),
                    "redirect_url": "http://localhost/callback"
                }
            });
            provider_config[identity_key] = serde_json::json!(identity_value);

            manager
                .create_vault(
                    VaultId::new(format!("{provider_type}-test")).unwrap(),
                    b"password",
                    provider_type,
                    provider_config,
                    KdfParams::moderate(),
                )
                .await
                .unwrap();

            let bytes = storage
                .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
                .await
                .unwrap();
            let uploaded = String::from_utf8(bytes).unwrap();
            assert!(!uploaded.contains(&format!("{provider_type}-access-secret")));
            assert!(!uploaded.contains(&format!("{provider_type}-refresh-secret")));
            assert!(!uploaded.contains(&format!("{provider_type}-client-secret")));
            let config = VaultConfig::from_bytes(uploaded.as_bytes()).unwrap();
            assert_eq!(config.provider_config[identity_key], identity_value);
            assert_eq!(config.provider_config["credential_schema"], 1);
            assert_eq!(
                config.provider_config["credential_ref"],
                format!("local:{provider_type}:test")
            );
        }
    }

    #[tokio::test]
    async fn cloud_vault_upload_excludes_google_oauth_credentials() {
        let storage = Arc::new(axiomvault_storage::MemoryProvider::new());
        let mut registry = ProviderRegistry::new();
        let resolved = storage.clone();
        registry
            .register("gdrive", Box::new(move |_| Ok(resolved.clone())))
            .unwrap();
        let manager = VaultManager::with_registry_and_anchor(
            registry,
            Arc::new(InMemoryFreshnessAnchor::new()),
        );
        let provider_config = serde_json::json!({
            "folder_id": "remote-folder",
            "credential_ref": "local:gdrive:test",
            "tokens": {
                "access_token": "uploaded-access-secret",
                "refresh_token": "uploaded-refresh-secret",
                "expires_at": "2099-01-01T00:00:00Z"
            },
            "auth_config": {
                "client_id": "client-id",
                "client_secret": "uploaded-client-secret",
                "redirect_url": "http://localhost/callback"
            }
        });

        manager
            .create_vault(
                VaultId::new("cloud-test").unwrap(),
                b"password",
                "gdrive",
                provider_config,
                KdfParams::moderate(),
            )
            .await
            .unwrap();

        let bytes = storage
            .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
            .await
            .unwrap();
        let uploaded = String::from_utf8(bytes).unwrap();
        assert!(!uploaded.contains("uploaded-access-secret"));
        assert!(!uploaded.contains("uploaded-refresh-secret"));
        assert!(!uploaded.contains("uploaded-client-secret"));
        let config = VaultConfig::from_bytes(uploaded.as_bytes()).unwrap();
        assert_eq!(
            config.provider_config,
            serde_json::json!({
                "credential_schema": 1,
                "credential_ref": "local:gdrive:test",
                "folder_id": "remote-folder"
            })
        );
    }

    const V1_1_CONTENT: &[u8] = b"one-shot content written by a 1.1 client";

    fn config_path() -> VaultPath {
        VaultPath::parse(CONFIG_FILENAME).unwrap()
    }

    async fn stored_config<P: StorageProvider + ?Sized>(provider: &P) -> VaultConfig {
        VaultConfig::from_bytes(&provider.download(&config_path()).await.unwrap()).unwrap()
    }

    async fn committed_config<P: StorageProvider + ?Sized>(
        provider: &P,
        master_key: &MasterKey,
    ) -> (u64, VaultConfig) {
        let manifest = GenerationManifest::open(
            master_key,
            &provider.download(&manifest_path()).await.unwrap(),
        )
        .unwrap();
        let (_, config_object) = manifest.object_paths().unwrap();
        let config =
            VaultConfig::from_bytes(&provider.download(&config_object).await.unwrap()).unwrap();
        (manifest.generation, config)
    }

    /// A b6520ff-style vault: 1.1 `vault.config`, `m/tree.json`, no manifest,
    /// and one file in the one-shot AEAD encoding (`content_version` 0).
    async fn write_v1_1_vault_without_manifest(
        provider: Arc<dyn StorageProvider>,
        vault_id: &str,
    ) -> (VaultPath, Zeroizing<String>) {
        use crate::operations::VaultOperations;

        let creation = VaultConfig::new(
            VaultId::new(vault_id).unwrap(),
            b"password",
            "test",
            serde_json::Value::Null,
            KdfParams::moderate(),
        )
        .unwrap();
        let mut v1_1 = creation.config.clone();
        v1_1.version = VaultVersion::V1_1;
        provider
            .create_dir(&VaultPath::parse(DATA_DIRNAME).unwrap())
            .await
            .unwrap();
        provider
            .create_dir(&VaultPath::parse(META_DIRNAME).unwrap())
            .await
            .unwrap();
        let session = VaultSession::from_master_key(
            creation.config,
            creation.master_key,
            provider.clone(),
            VaultTree::new(),
        )
        .unwrap();
        let file = VaultPath::parse("/notes.txt").unwrap();
        VaultOperations::new(&session)
            .unwrap()
            .create_file(&file, V1_1_CONTENT)
            .await
            .unwrap();
        assert_eq!(
            session
                .tree()
                .read()
                .await
                .get_node(&file)
                .unwrap()
                .metadata
                .content_version,
            0
        );
        drop(session);
        provider
            .upload(&config_path(), v1_1.to_bytes().unwrap())
            .await
            .unwrap();
        assert!(!provider.exists(&manifest_path()).await.unwrap());
        (file, creation.recovery_words)
    }

    #[tokio::test]
    async fn fresh_vault_opens_at_current_version() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        manager
            .create_vault(
                VaultId::new("fresh-version").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let session = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(
            session.config().version,
            VaultVersion { major: 2, minor: 0 }
        );
        assert_eq!(
            stored_config(provider.as_ref()).await.version,
            VaultVersion::CURRENT
        );
    }

    #[tokio::test]
    async fn v1_1_vault_without_manifest_upgrades_on_open_and_survives_interruption() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(ManifestFailProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_manifest_failure_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("v1-1-bootstrap").unwrap();
        let (file, _) =
            write_v1_1_vault_without_manifest(provider.clone(), vault_id.as_str()).await;
        let v1_1_bytes = provider.download(&config_path()).await.unwrap();

        // Interrupted before the first manifest commit: storage is still 1.1.
        provider.fail_next_manifest();
        assert!(manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .is_err());
        assert!(!provider.exists(&manifest_path()).await.unwrap());
        assert_eq!(provider.download(&config_path()).await.unwrap(), v1_1_bytes);

        let session = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(session.config().version, VaultVersion::CURRENT);
        let (generation, committed) =
            committed_config(provider.as_ref(), session.master_key().unwrap()).await;
        assert_eq!(generation, 1);
        assert_eq!(committed.version, VaultVersion::CURRENT);
        assert_eq!(
            stored_config(provider.as_ref()).await.version,
            VaultVersion::CURRENT
        );
        assert_eq!(
            VaultOperations::new(&session)
                .unwrap()
                .read_file(&file)
                .await
                .unwrap(),
            V1_1_CONTENT
        );
        drop(session);

        // A 2.0 vault reopens without another upgrade generation.
        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(anchor.load(&test_anchor_id(&vault_id)).unwrap(), Some(1));
        assert_eq!(
            VaultOperations::new(&reopened)
                .unwrap()
                .read_file(&file)
                .await
                .unwrap(),
            V1_1_CONTENT
        );
    }

    #[tokio::test]
    async fn v1_1_vault_with_manifest_upgrades_on_open_and_survives_interruption() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(ManifestFailProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_manifest_failure_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("v1-1-manifest").unwrap();
        let creation = manager
            .create_vault(
                vault_id.clone(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let file = VaultPath::parse("/notes.txt").unwrap();
        VaultOperations::new(&creation.session)
            .unwrap()
            .create_file(&file, V1_1_CONTENT)
            .await
            .unwrap();

        // Republish the committed snapshot labelled 1.1, as a pre-bump client did.
        let master_key = creation.session.master_key().unwrap();
        let current = GenerationManifest::open(
            master_key,
            &provider.download(&manifest_path()).await.unwrap(),
        )
        .unwrap();
        let (tree_object, _) = current.object_paths().unwrap();
        let encrypted_tree = provider.download(&tree_object).await.unwrap();
        let mut v1_1 = creation.session.config().clone();
        v1_1.version = VaultVersion::V1_1;
        let v1_1_bytes = v1_1.to_bytes().unwrap();
        let labelled = GenerationManifest::new(
            vault_id.clone(),
            current.generation + 1,
            &encrypted_tree,
            &v1_1_bytes,
            current.object_digests.clone(),
        );
        let (labelled_tree, labelled_config) = labelled.object_paths().unwrap();
        provider
            .upload(&labelled_tree, encrypted_tree)
            .await
            .unwrap();
        provider
            .upload(&labelled_config, v1_1_bytes.clone())
            .await
            .unwrap();
        let labelled_bytes = labelled.seal(master_key).unwrap();
        provider
            .upload(&manifest_path(), labelled_bytes.clone())
            .await
            .unwrap();
        provider
            .upload(&config_path(), v1_1_bytes.clone())
            .await
            .unwrap();
        anchor
            .store_state(
                &test_anchor_id(&vault_id),
                FreshnessState {
                    generation: labelled.generation,
                    manifest_digest: Some(digest(&labelled_bytes)),
                },
            )
            .unwrap();
        let v1_1_generation = labelled.generation;
        drop(creation);

        // Interrupted before the 2.0 manifest commit: still a 1.1 vault.
        provider.fail_next_manifest();
        assert!(manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .is_err());
        assert_eq!(
            provider.download(&manifest_path()).await.unwrap(),
            labelled_bytes
        );
        assert_eq!(
            stored_config(provider.as_ref()).await.version,
            VaultVersion::V1_1
        );

        let session = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(session.config().version, VaultVersion::CURRENT);
        let (generation, committed) =
            committed_config(provider.as_ref(), session.master_key().unwrap()).await;
        assert_eq!(generation, v1_1_generation + 1);
        assert_eq!(committed.version, VaultVersion::CURRENT);
        assert_eq!(
            stored_config(provider.as_ref()).await.version,
            VaultVersion::CURRENT
        );
        assert_eq!(
            VaultOperations::new(&session)
                .unwrap()
                .read_file(&file)
                .await
                .unwrap(),
            V1_1_CONTENT
        );
        drop(session);

        // Committed, but the `vault.config` cache write was lost: the manifest is
        // authoritative, so the vault opens at 2.0 and the cache is rewritten.
        provider.upload(&config_path(), v1_1_bytes).await.unwrap();
        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(reopened.config().version, VaultVersion::CURRENT);
        assert_eq!(
            stored_config(provider.as_ref()).await.version,
            VaultVersion::CURRENT
        );
        assert_eq!(
            anchor.load(&test_anchor_id(&vault_id)).unwrap(),
            Some(v1_1_generation + 1)
        );
        assert_eq!(
            VaultOperations::new(&reopened)
                .unwrap()
                .read_file(&file)
                .await
                .unwrap(),
            V1_1_CONTENT
        );
    }

    #[tokio::test]
    async fn recovering_a_v1_1_vault_publishes_it_as_current() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let (file, words) =
            write_v1_1_vault_without_manifest(provider.clone(), "v1-1-recover").await;

        let session = manager
            .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
            .await
            .unwrap();
        assert_eq!(session.config().version, VaultVersion::CURRENT);
        let (_, committed) =
            committed_config(provider.as_ref(), session.master_key().unwrap()).await;
        assert_eq!(committed.version, VaultVersion::CURRENT);
        assert_eq!(
            stored_config(provider.as_ref()).await.version,
            VaultVersion::CURRENT
        );
        assert_eq!(
            VaultOperations::new(&session)
                .unwrap()
                .read_file(&file)
                .await
                .unwrap(),
            V1_1_CONTENT
        );
    }

    #[tokio::test]
    async fn v1_0_vault_is_refused_on_open_until_migrated_then_upgrades() {
        use crate::migration::MigrationRegistry;

        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let mut legacy = VaultConfig::new(
            VaultId::new("v1-0-open").unwrap(),
            b"password",
            "test",
            serde_json::Value::Null,
            KdfParams::moderate(),
        )
        .unwrap()
        .config;
        legacy.version = VaultVersion { major: 1, minor: 0 };
        legacy.wrapped_master_key = None;
        legacy.recovery_wrapped_master_key = None;
        legacy.recovery_key_verification = None;
        legacy.encrypted_recovery_key = None;
        let legacy_bytes = legacy.to_bytes().unwrap();
        provider
            .create_dir(&VaultPath::parse(DATA_DIRNAME).unwrap())
            .await
            .unwrap();
        provider
            .create_dir(&VaultPath::parse(META_DIRNAME).unwrap())
            .await
            .unwrap();
        provider
            .upload(&config_path(), legacy_bytes.clone())
            .await
            .unwrap();

        let error = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("a 1.0 vault must be migrated before it is opened");
        assert!(error.to_string().contains("must be migrated"));
        assert!(!provider.exists(&manifest_path()).await.unwrap());
        assert_eq!(
            provider.download(&config_path()).await.unwrap(),
            legacy_bytes
        );

        let outcome = MigrationRegistry::with_defaults()
            .migrate(provider.as_ref(), b"password", &VaultVersion::V1_1)
            .await
            .unwrap();
        assert_eq!(outcome.config.version, VaultVersion::V1_1);
        assert!(outcome.recovery_words.is_some());

        let session = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(session.config().version, VaultVersion::CURRENT);
        assert_eq!(
            stored_config(provider.as_ref()).await.version,
            VaultVersion::CURRENT
        );
    }

    #[tokio::test]
    async fn v1_1_client_cannot_read_chunked_content_of_a_current_vault() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let creation = manager
            .create_vault(
                VaultId::new("chunked-content").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        let source = source_dir.path().join("large.bin");
        let content: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        std::fs::write(&source, &content).unwrap();
        let file = VaultPath::parse("/large.bin").unwrap();
        let ops = VaultOperations::new(&creation.session).unwrap();
        ops.create_file_from_path(&file, &source).await.unwrap();
        let metadata = creation
            .session
            .tree()
            .read()
            .await
            .get_node(&file)
            .unwrap()
            .metadata
            .clone();
        // Chunked stream framing v2 (operations::STREAM_CONTENT_VERSION).
        assert_eq!(metadata.content_version, 2);

        // Version gate: the 1.1 client (b6520ff) accepts only major == 1.
        let stored = stored_config(provider.as_ref()).await;
        assert_eq!(stored.version, VaultVersion::CURRENT);
        assert_ne!(stored.version.major, VaultVersion::V1_1.major);

        // Content: past the gate, the 1.1 client's read_file uses one-shot AEAD
        // `decrypt`, which rejects the chunked object.
        let ciphertext = provider
            .download(
                &VaultPath::parse(DATA_DIRNAME)
                    .unwrap()
                    .join(&metadata.encrypted_name)
                    .unwrap(),
            )
            .await
            .unwrap();
        let file_key = creation
            .session
            .master_key()
            .unwrap()
            .derive_file_key(metadata.encrypted_name.as_bytes());
        assert!(axiomvault_crypto::decrypt(file_key.as_bytes(), &ciphertext).is_err());
        assert_eq!(ops.read_file(&file).await.unwrap(), content);
    }
}
