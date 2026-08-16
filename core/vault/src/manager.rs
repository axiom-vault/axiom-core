//! Vault manager for creating and managing vaults.

use std::sync::Arc;

use crate::config::{VaultConfig, CONFIG_FILENAME, DATA_DIRNAME, META_DIRNAME};
use crate::freshness::{FreshnessAnchor, LocalFileFreshnessAnchor, UnavailableFreshnessAnchor};
use crate::manifest::{digest, GenerationManifest, MANIFEST_FILENAME};
use crate::session::VaultSession;
use crate::tree::VaultTree;
use axiomvault_common::{Error, Result, VaultId, VaultPath};
use axiomvault_crypto::recovery::RecoveryKey;
use axiomvault_crypto::KdfParams;
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
        if !provider.exists(&config_path).await? {
            return Err(Error::NotFound("Vault configuration not found".to_string()));
        }

        let config_bytes = provider.download(&config_path).await?;
        let mut config = VaultConfig::from_bytes(&config_bytes)?;
        let anchor_id = self.freshness_id(provider_type, &provider_config, &config.id)?;

        let master_key = config
            .verify_password(password)?
            .ok_or_else(|| Error::NotPermitted("Invalid password".to_string()))?;

        let manifest_path = VaultPath::parse(META_DIRNAME)?.join(MANIFEST_FILENAME)?;
        let anchored_generation = self.freshness_anchor.load(&anchor_id)?;

        if provider.exists(&manifest_path).await? {
            let tree_path = VaultPath::parse(META_DIRNAME)?.join(crate::config::TREE_FILENAME)?;
            if !provider.exists(&tree_path).await? {
                return Err(Error::Crypto(
                    "snapshot manifest exists but encrypted tree is missing".to_string(),
                ));
            }
            let encrypted_tree = provider.download(&tree_path).await?;
            let manifest_bytes = provider.download(&manifest_path).await?;
            let manifest = GenerationManifest::open(&master_key, &manifest_bytes)?;
            manifest.verify_bindings(&config.id, &encrypted_tree, &config_bytes)?;
            if anchored_generation.is_some_and(|accepted| manifest.generation < accepted) {
                return Err(Error::Conflict(format!(
                    "vault snapshot rollback detected: generation {} is older than trusted generation {}",
                    manifest.generation,
                    anchored_generation.unwrap_or_default()
                )));
            }
            let tree = VaultSession::decrypt_tree_bytes(&master_key, &encrypted_tree)?;
            self.freshness_anchor
                .store(&anchor_id, manifest.generation)?;
            return VaultSession::from_master_key_with_freshness(
                config,
                master_key,
                provider,
                tree,
                self.freshness_anchor.clone(),
                anchor_id,
                manifest.generation,
            );
        }

        if anchored_generation.is_some() {
            return Err(Error::Conflict(
                "snapshot manifest missing for a vault with trusted freshness state".to_string(),
            ));
        }

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
        if !provider.exists(&config_path).await? {
            return Err(Error::NotFound("Vault configuration not found".to_string()));
        }

        let config_bytes = provider.download(&config_path).await?;
        let mut config = VaultConfig::from_bytes(&config_bytes)?;
        let anchor_id = self.freshness_id(provider_type, &provider_config, &config.id)?;

        let recovery_key = RecoveryKey::from_mnemonic(recovery_words)?;

        // Verify recovery key and get master key for tree decryption.
        let master_key = config
            .verify_recovery_key(&recovery_key)?
            .ok_or_else(|| Error::NotPermitted("Invalid recovery key".to_string()))?;

        // Verify the currently stored authenticated snapshot before mutating config.
        let manifest_path = VaultPath::parse(META_DIRNAME)?.join(MANIFEST_FILENAME)?;
        let anchored_generation = self.freshness_anchor.load(&anchor_id)?;
        let (tree, generation) = if provider.exists(&manifest_path).await? {
            let tree_path = VaultPath::parse(META_DIRNAME)?.join(crate::config::TREE_FILENAME)?;
            if !provider.exists(&tree_path).await? {
                return Err(Error::Crypto(
                    "snapshot manifest exists but encrypted tree is missing".to_string(),
                ));
            }
            let encrypted_tree = provider.download(&tree_path).await?;
            let manifest_bytes = provider.download(&manifest_path).await?;
            let manifest = GenerationManifest::open(&master_key, &manifest_bytes)?;
            manifest.verify_bindings(&config.id, &encrypted_tree, &config_bytes)?;
            if anchored_generation.is_some_and(|accepted| manifest.generation < accepted) {
                return Err(Error::Conflict(
                    "vault snapshot rollback detected during recovery".to_string(),
                ));
            }
            let tree = VaultSession::decrypt_tree_bytes(&master_key, &encrypted_tree)?;
            self.freshness_anchor
                .store(&anchor_id, manifest.generation)?;
            (tree, manifest.generation)
        } else {
            if anchored_generation.is_some() {
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

        // Reset password in config. The master key itself doesn't change.
        config.reset_password(&recovery_key, new_password)?;
        if is_oauth_cloud_provider(provider_type) {
            config.provider_config = persisted_provider_config(provider_type, &provider_config)?;
        }

        // Persist config first; the following snapshot commit binds it to the tree.
        let config_bytes = config.to_bytes()?;
        provider.upload(&config_path, config_bytes).await?;

        let session = VaultSession::from_master_key_with_freshness(
            config,
            master_key,
            provider,
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
        provider.exists(&config_path).await
    }

    /// Save vault configuration to storage.
    pub async fn save_config(&self, session: &VaultSession) -> Result<()> {
        let config_path = VaultPath::parse(CONFIG_FILENAME)?;
        let config_bytes = session.config().to_bytes()?;
        session
            .provider()
            .upload(&config_path, config_bytes)
            .await?;
        // Config and tree are one authenticated snapshot generation. Re-sealing
        // the tree binds this exact config and advances the trusted anchor.
        session.save_tree().await?;
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
    use axiomvault_storage::MemoryProvider;

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

    async fn stored_snapshot(provider: &MemoryProvider) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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
        provider.upload(&object_path, old_ciphertext).await.unwrap();

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
        manager.save_config(&creation.session).await.unwrap();
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
        let old = stored_snapshot(&provider).await;
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
        assert!(error.to_string().contains("rollback detected"));
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
        let old_tree = provider.download(&tree_path()).await.unwrap();
        creation.session.save_tree().await.unwrap();
        provider.upload(&tree_path(), old_tree).await.unwrap();

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
        manager.save_config(&creation.session).await.unwrap();
        provider
            .upload(&VaultPath::parse(CONFIG_FILENAME).unwrap(), old_config)
            .await
            .unwrap();

        let error = manager
            .open_vault("test", serde_json::Value::Null, b"old-password")
            .await
            .err()
            .expect("rollback must be rejected");
        assert!(error.to_string().contains("config and snapshot manifest"));
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
}
