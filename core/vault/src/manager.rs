//! Vault manager for creating and managing vaults.

use std::path::{Component, Path};
use std::sync::Arc;

use crate::config::{
    download_metadata, VaultConfig, VaultVersion, CONFIG_FILENAME, CONFIG_MAX_LEN, DATA_DIRNAME,
    META_DIRNAME, TREE_MAX_LEN,
};
use crate::freshness::{
    AnchorKeys, FreshnessAnchor, FreshnessState, LocalFileFreshnessAnchor,
    UnavailableFreshnessAnchor,
};
use crate::manifest::{digest, GenerationManifest, MANIFEST_FILENAME, MANIFEST_MAX_LEN};
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

/// Whether an authenticated 1.1 config must be upgraded to `CURRENT`.
///
/// Only the explicit paths `upgrade_to_current` and `recover_vault` pass
/// `allow_upgrade`; every open path refuses a 1.1 vault, and callers check
/// this before any write.
///
/// Callers relabel only their in-memory copy and publish it as a new manifest
/// generation; `vault.config` is a cache written after the manifest commit, so
/// it never reads 2.0 while the authoritative snapshot is still 1.1.
fn needs_format_upgrade(config: &VaultConfig, allow_upgrade: bool) -> Result<bool> {
    match check_migration_needed(config) {
        MigrationStatus::UpToDate => Ok(false),
        MigrationStatus::NeedsMigration { from, .. } if from == VaultVersion::V1_1 => {
            if allow_upgrade {
                Ok(true)
            } else {
                Err(Error::Vault(format!(
                    "vault version {from} must be upgraded with `axiom vault migrate` before it can be opened"
                )))
            }
        }
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

/// A local provider's `root` as the filesystem resolves it: absolute, with
/// symlinks, `.`, `..` and trailing slashes resolved. A root that does not
/// exist yet, as for a vault being created, resolves through its nearest
/// existing ancestor. A root that cannot be resolved is refused, never keyed
/// as typed, since the anchor key must not depend on how the path is spelt.
fn canonical_local_root(provider_config: &serde_json::Value) -> Result<String> {
    let root = provider_config
        .get("root")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::InvalidInput("local provider config requires 'root'".to_string()))?;
    let unresolvable = |detail: &dyn std::fmt::Display| {
        Error::InvalidInput(format!("cannot resolve local vault root {root}: {detail}"))
    };
    let mut existing = Path::new(root).components();
    let mut missing = Vec::new();
    let resolved = loop {
        let candidate = match existing.as_path() {
            path if path.as_os_str().is_empty() => Path::new("."),
            path => path,
        };
        match std::fs::canonicalize(candidate) {
            Ok(resolved) => break resolved,
            // A dangling symlink is not a directory still to be created.
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && std::fs::symlink_metadata(candidate).is_err() =>
            {
                match existing.next_back() {
                    Some(Component::Normal(name)) => missing.push(name),
                    _ => return Err(unresolvable(&error)),
                }
            }
            Err(error) => return Err(unresolvable(&error)),
        }
    };
    missing
        .into_iter()
        .rev()
        .fold(resolved, |path, name| path.join(name))
        .into_os_string()
        .into_string()
        .map_err(|_| unresolvable(&"not valid UTF-8"))
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

/// A provider location as given by the caller and, for a local root, as
/// the filesystem resolves it; see [`AnchorKeys`].
struct AnchorLocation<'a> {
    provider_type: &'a str,
    typed: &'a serde_json::Value,
    resolved: Option<serde_json::Value>,
    namespace: &'a str,
}

impl AnchorLocation<'_> {
    /// Keys for the location alone, or for `vault_id` at it. `config.id`
    /// comes from the unauthenticated `vault.config`, so a location marker is
    /// what lets the no-manifest path detect a vault this device has already
    /// anchored.
    fn keys(&self, vault_id: Option<&VaultId>) -> Result<AnchorKeys> {
        let id = |config| {
            VaultManager::freshness_id_from(
                self.provider_type,
                config,
                vault_id,
                Some(self.namespace),
            )
        };
        Ok(AnchorKeys::new(
            id(self.typed)?,
            self.resolved.as_ref().map(id).transpose()?,
        ))
    }
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
        vault_id: Option<&VaultId>,
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
            "vault_id": vault_id.map(VaultId::as_str),
            "identity": stable_identity,
        }))
        .map_err(|error| Error::Serialization(error.to_string()))?;
        VaultId::new(format!("anchor-{}", digest(&material)))
    }

    /// The anchor identity of a provider location, worked out once per
    /// operation so that every key it uses comes from one resolution of the
    /// local root.
    fn anchor_location<'a>(
        &'a self,
        provider_type: &'a str,
        provider_config: &'a serde_json::Value,
    ) -> Result<AnchorLocation<'a>> {
        let resolved = match provider_type {
            "local" => Some(serde_json::json!({ "root": canonical_local_root(provider_config)? })),
            _ => None,
        };
        Ok(AnchorLocation {
            provider_type,
            typed: provider_config,
            resolved,
            namespace: &self.ephemeral_namespace,
        })
    }

    fn mark_location_anchored(&self, location: &AnchorLocation<'_>) -> Result<()> {
        location.keys(None)?.mark(self.freshness_anchor.as_ref())
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
        let encrypted_tree = download_metadata(provider.as_ref(), &tree_path, TREE_MAX_LEN).await?;
        let config_bytes =
            download_metadata(provider.as_ref(), &config_path, CONFIG_MAX_LEN).await?;
        let mut config = VaultConfig::from_bytes(&config_bytes)?;
        manifest.verify_bindings(&config.id, &encrypted_tree, &config_bytes)?;
        // The manifest binds these bytes; the tag binds them to the master key
        // even where no manifest does (see the no-manifest paths).
        config.verify_integrity(master_key, true)?;
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
        let location = self.anchor_location(provider_type, &provider_config)?;
        let anchor_keys = location.keys(Some(&vault_id))?;
        if anchor_keys
            .load_state(self.freshness_anchor.as_ref())?
            .is_some()
        {
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

        self.initialize_vault_structure(&provider, &creation.config, &creation.master_key)
            .await?;

        // Use from_master_key to avoid a second Argon2id KDF round.
        let session = VaultSession::from_master_key_with_freshness(
            creation.config,
            creation.master_key,
            provider,
            VaultTree::new(),
            self.freshness_anchor.clone(),
            anchor_keys,
            0,
        )?;
        session.save_tree().await?;
        self.mark_location_anchored(&location)?;

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
        master_key: &MasterKey,
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
        let config_bytes = config.to_authenticated_bytes(master_key)?;
        provider.upload(&config_path, config_bytes).await?;

        Ok(())
    }

    /// Open an existing vault.
    ///
    /// A 1.1 vault is refused before anything is written; upgrade it with
    /// [`VaultManager::upgrade_to_current`].
    pub async fn open_vault(
        &self,
        provider_type: &str,
        provider_config: serde_json::Value,
        password: &[u8],
    ) -> Result<VaultSession> {
        self.open_with_upgrade_policy(provider_type, provider_config, password, false)
            .await
    }

    /// Upgrade a 1.1 vault to `CURRENT` and return the open session.
    ///
    /// The upgrade is published as a new manifest generation; `vault.config`
    /// reads `CURRENT` only after that commit, so an interrupted upgrade leaves
    /// a 1.1 vault that can be upgraded again. A vault already at `CURRENT` is
    /// opened exactly as by [`VaultManager::open_vault`], without a new
    /// generation. A 1.0 vault is refused until the registry migrates it to 1.1,
    /// and an untagged 1.1 config that no manifest binds is refused.
    pub async fn upgrade_to_current(
        &self,
        provider_type: &str,
        provider_config: serde_json::Value,
        password: &[u8],
    ) -> Result<VaultSession> {
        self.open_with_upgrade_policy(provider_type, provider_config, password, true)
            .await
    }

    async fn open_with_upgrade_policy(
        &self,
        provider_type: &str,
        provider_config: serde_json::Value,
        password: &[u8],
        allow_upgrade: bool,
    ) -> Result<VaultSession> {
        let runtime_config = self.runtime_provider_config(provider_type, &provider_config)?;
        let provider = self.registry.resolve(provider_type, runtime_config)?;
        let location = self.anchor_location(provider_type, &provider_config)?;

        let config_path = VaultPath::parse(CONFIG_FILENAME)?;
        let manifest_path = VaultPath::parse(META_DIRNAME)?.join(MANIFEST_FILENAME)?;

        if provider.exists(&manifest_path).await? {
            let manifest_bytes =
                download_metadata(provider.as_ref(), &manifest_path, MANIFEST_MAX_LEN).await?;
            let credential_config_bytes =
                match GenerationManifest::config_path_hint(&manifest_bytes)? {
                    Some(path) => {
                        download_metadata(provider.as_ref(), &path, CONFIG_MAX_LEN).await?
                    }
                    None => {
                        if !provider.exists(&config_path).await? {
                            return Err(Error::NotFound(
                                "Vault configuration not found".to_string(),
                            ));
                        }
                        download_metadata(provider.as_ref(), &config_path, CONFIG_MAX_LEN).await?
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
            let upgrade = needs_format_upgrade(&config, allow_upgrade)?;
            let anchor_keys = location.keys(Some(&config.id))?;
            let anchored_state = anchor_keys.load_state(self.freshness_anchor.as_ref())?;
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
            anchor_keys.store_state(
                self.freshness_anchor.as_ref(),
                &FreshnessState {
                    generation: manifest.generation,
                    manifest_digest: Some(digest(&manifest_bytes)),
                },
            )?;
            self.mark_location_anchored(&location)?;
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
                anchor_keys,
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
        let config_bytes =
            download_metadata(provider.as_ref(), &config_path, CONFIG_MAX_LEN).await?;
        let mut config = VaultConfig::from_bytes(&config_bytes)?;

        let anchor_keys = location.keys(Some(&config.id))?;
        let anchored_state = anchor_keys.load_state(self.freshness_anchor.as_ref())?;
        let location_anchored = location
            .keys(None)?
            .is_anchored(self.freshness_anchor.as_ref())?;
        let master_key = config
            .verify_password(password)?
            .ok_or_else(|| Error::NotPermitted("Invalid password".to_string()))?;

        if anchored_state.is_some() || location_anchored {
            return Err(Error::Conflict(
                "snapshot manifest missing for a vault with trusted freshness state".to_string(),
            ));
        }
        // No manifest binds this config, so its tag is the only check of the
        // fields the password does not cover; refuse before any write. It runs
        // before the version gate, so an untagged 1.1 config is refused as
        // unauthenticated on every path, not sent to an upgrade that refuses it.
        config.verify_integrity(&master_key, false)?;
        let upgrade = needs_format_upgrade(&config, allow_upgrade)?;

        // Legacy bootstrap is allowed only when neither storage nor this device has
        // freshness state. Authenticate and decrypt before sanitizing a legacy config.
        let tree = VaultSession::load_and_decrypt_tree(&provider, &master_key).await?;
        if is_oauth_cloud_provider(provider_type) {
            let safe_config = persisted_provider_config(provider_type, &provider_config)?;
            if config.provider_config != safe_config {
                config.provider_config = safe_config;
                provider
                    .upload(&config_path, config.to_authenticated_bytes(&master_key)?)
                    .await?;
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
            anchor_keys,
            0,
        )?;
        session.save_tree().await?;
        // Marked only after the first manifest commit, so a failed bootstrap can retry.
        self.mark_location_anchored(&location)?;
        Ok(session)
    }

    /// Reset vault password using recovery key words.
    ///
    /// Recovery is an explicit user action, so a 1.1 vault is upgraded to
    /// `CURRENT` here, as by [`VaultManager::upgrade_to_current`]: its 1.1
    /// snapshot is verified with the recovery words, then the reset is
    /// committed as its first `CURRENT` generation. An interrupted recovery
    /// leaves the 1.1 vault as it was. A 1.0 vault is refused until migrated.
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
        let location = self.anchor_location(provider_type, &provider_config)?;

        let config_path = VaultPath::parse(CONFIG_FILENAME)?;
        let recovery_key = RecoveryKey::from_mnemonic(recovery_words)?;

        // Verify the currently stored authenticated snapshot before mutating config.
        let manifest_path = VaultPath::parse(META_DIRNAME)?.join(MANIFEST_FILENAME)?;
        let stored_manifest = if provider.exists(&manifest_path).await? {
            Some(download_metadata(provider.as_ref(), &manifest_path, MANIFEST_MAX_LEN).await?)
        } else {
            None
        };
        let credential_config_bytes = match stored_manifest.as_deref() {
            Some(bytes) => match GenerationManifest::config_path_hint(bytes)? {
                Some(path) => download_metadata(provider.as_ref(), &path, CONFIG_MAX_LEN).await?,
                None => {
                    if !provider.exists(&config_path).await? {
                        return Err(Error::NotFound("Vault configuration not found".to_string()));
                    }
                    download_metadata(provider.as_ref(), &config_path, CONFIG_MAX_LEN).await?
                }
            },
            None => {
                if !provider.exists(&config_path).await? {
                    return Err(Error::NotFound("Vault configuration not found".to_string()));
                }
                download_metadata(provider.as_ref(), &config_path, CONFIG_MAX_LEN).await?
            }
        };
        let credential_config = VaultConfig::from_bytes(&credential_config_bytes)?;
        // Refuse 1.0 before key work; it has no recovery key until migrated.
        needs_format_upgrade(&credential_config, true)?;
        // The reset rewraps under these parameters; refuse weak ones before
        // either branch writes. The snapshot config is checked again below.
        credential_config.kdf_params.validate_minimum()?;
        let mut config = credential_config.clone();
        let master_key = credential_config
            .verify_recovery_key(&recovery_key)?
            .ok_or_else(|| Error::NotPermitted("Invalid recovery key".to_string()))?;

        let (tree, generation, upgrade) = if let Some(manifest_bytes) = stored_manifest {
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
            // Refuse 1.0 and weak KDF parameters before the anchor and cache
            // writes below; a 1.1 snapshot is upgraded by the recovery commit.
            config.kdf_params.validate_minimum()?;
            let upgrade = needs_format_upgrade(&config, true)?;
            if upgrade {
                config.verify_recovery_key_binding(&recovery_key, &master_key)?;
            }
            let anchor_keys = location.keys(Some(&config.id))?;
            let anchored_state = anchor_keys.load_state(self.freshness_anchor.as_ref())?;
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
            anchor_keys.store_state(
                self.freshness_anchor.as_ref(),
                &FreshnessState {
                    generation: manifest.generation,
                    manifest_digest: Some(digest(&manifest_bytes)),
                },
            )?;
            self.mark_location_anchored(&location)?;
            let _ = provider.upload(&config_path, snapshot_config_bytes).await;
            (tree, manifest.generation, upgrade)
        } else {
            let anchored_state = location
                .keys(Some(&config.id))?
                .load_state(self.freshness_anchor.as_ref())?;
            if anchored_state.is_some()
                || location
                    .keys(None)?
                    .is_anchored(self.freshness_anchor.as_ref())?
            {
                return Err(Error::Conflict(
                    "snapshot manifest missing for a vault with trusted freshness state"
                        .to_string(),
                ));
            }
            // Recovery does not use the password, so nothing else checks the KDF
            // parameters `reset_password` rewraps under: verify the tag first.
            // An untagged 1.1 config is refused here (see `verify_integrity`).
            config.verify_integrity(&master_key, false)?;
            // No manifest binds a 1.1 config, so check every recovery field and
            // authenticate the tree under the recovered key before any write.
            let upgrade = needs_format_upgrade(&config, true)?;
            if upgrade {
                config.verify_recovery_key_binding(&recovery_key, &master_key)?;
            }
            (
                VaultSession::load_and_decrypt_tree(&provider, &master_key).await?,
                0,
                upgrade,
            )
        };

        // Reset password in config under a new master key; the vault is
        // re-encrypted under it and committed as a new generation below.
        let new_master_key = config.reset_password(&recovery_key, new_password)?;
        if is_oauth_cloud_provider(provider_type) {
            config.provider_config = persisted_provider_config(provider_type, &provider_config)?;
        }
        // In memory only: the rotation commit publishes it as a new generation
        // before the `vault.config` cache, as in `open_with_upgrade_policy`.
        if upgrade {
            config.version = VaultVersion::CURRENT;
        }

        let anchor_keys = location.keys(Some(&config.id))?;
        let mut session = VaultSession::from_master_key_with_freshness(
            config,
            master_key,
            provider.clone(),
            tree,
            self.freshness_anchor.clone(),
            anchor_keys,
            generation,
        )?;
        session.stage_master_key_rotation(new_master_key);
        session.commit_master_key_rotation().await?;
        self.mark_location_anchored(&location)?;
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct ManifestFailProvider {
        inner: MemoryProvider,
        fail_next_manifest: AtomicBool,
        fail_next_config_object: AtomicBool,
        fail_next_tree_object: AtomicBool,
        fail_next_data_object: AtomicBool,
        fail_deletes: AtomicBool,
        pause_next_tree_after_commit: AtomicBool,
        pause_next_canonical_tree_after_commit: AtomicBool,
    }

    impl ManifestFailProvider {
        fn new() -> Self {
            Self {
                inner: MemoryProvider::new(),
                fail_next_manifest: AtomicBool::new(false),
                fail_next_config_object: AtomicBool::new(false),
                fail_next_tree_object: AtomicBool::new(false),
                fail_next_data_object: AtomicBool::new(false),
                fail_deletes: AtomicBool::new(false),
                pause_next_tree_after_commit: AtomicBool::new(false),
                pause_next_canonical_tree_after_commit: AtomicBool::new(false),
            }
        }

        fn fail_next_manifest(&self) {
            self.fail_next_manifest.store(true, Ordering::SeqCst);
        }

        /// Fail the next upload of a generation config object (`m/config.*`).
        fn fail_next_config_object(&self) {
            self.fail_next_config_object.store(true, Ordering::SeqCst);
        }

        /// Fail the next upload of a generation tree object (`m/tree.<g>.*`).
        fn fail_next_tree_object(&self) {
            self.fail_next_tree_object.store(true, Ordering::SeqCst);
        }

        /// Fail the next upload of a data object (`d/*`).
        fn fail_next_data_object(&self) {
            self.fail_next_data_object.store(true, Ordering::SeqCst);
        }

        /// Fail every delete until reset.
        fn fail_deletes(&self, fail: bool) {
            self.fail_deletes.store(fail, Ordering::SeqCst);
        }

        fn injected_upload_failure(&self, path: &VaultPath) -> Result<()> {
            let name = path.name().unwrap_or_default();
            let components = path.components();
            let in_meta = components.len() == 2 && components[0] == META_DIRNAME;
            let in_data = components.len() == 2 && components[0] == DATA_DIRNAME;
            let failed = (in_meta
                && name.starts_with("config.")
                && self.fail_next_config_object.swap(false, Ordering::SeqCst))
                || (in_meta
                    && name.starts_with("tree.")
                    && name.ends_with(".enc")
                    && self.fail_next_tree_object.swap(false, Ordering::SeqCst))
                || (in_data && self.fail_next_data_object.swap(false, Ordering::SeqCst));
            if failed {
                return Err(Error::Storage(format!(
                    "injected upload failure for {name}"
                )));
            }
            Ok(())
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
            self.injected_upload_failure(path)?;
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
            self.injected_upload_failure(path)?;
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
            if self.fail_deletes.load(Ordering::SeqCst) {
                return Err(Error::Storage("injected delete failure".to_string()));
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

    struct ToggleStoreFailureAnchor {
        inner: InMemoryFreshnessAnchor,
        failing_stores: AtomicUsize,
    }

    impl ToggleStoreFailureAnchor {
        fn new() -> Self {
            Self {
                inner: InMemoryFreshnessAnchor::new(),
                failing_stores: AtomicUsize::new(0),
            }
        }

        fn fail_next_store(&self) {
            self.fail_next_stores(1);
        }

        fn fail_next_stores(&self, count: usize) {
            self.failing_stores.store(count, Ordering::SeqCst);
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
            let left = self.failing_stores.load(Ordering::SeqCst);
            if left > 0 {
                self.failing_stores.store(left - 1, Ordering::SeqCst);
                return Err(Error::Vault("injected anchor failure".to_string()));
            }
            self.inner.store_state(vault_id, state)
        }
    }

    fn test_anchor_id(vault_id: &VaultId) -> VaultId {
        VaultManager::freshness_id_from("test", &serde_json::Value::Null, Some(vault_id), None)
            .unwrap()
    }

    fn test_location_id() -> VaultId {
        VaultManager::freshness_id_from("test", &serde_json::Value::Null, None, None).unwrap()
    }

    #[test]
    fn freshness_identity_distinguishes_providers_and_ignores_rotating_cloud_tokens() {
        let id = VaultId::new("same-user-id").unwrap();
        let local_a = VaultManager::freshness_id_from(
            "local",
            &serde_json::json!({"root": "/tmp/a"}),
            Some(&id),
            None,
        )
        .unwrap();
        let local_b = VaultManager::freshness_id_from(
            "local",
            &serde_json::json!({"root": "/tmp/b"}),
            Some(&id),
            None,
        )
        .unwrap();
        assert_ne!(local_a, local_b);

        let cloud_a = VaultManager::freshness_id_from(
            "gdrive",
            &serde_json::json!({"folder_id": "stable", "tokens": {"access_token": "a"}}),
            Some(&id),
            None,
        )
        .unwrap();
        let cloud_b = VaultManager::freshness_id_from(
            "gdrive",
            &serde_json::json!({"folder_id": "stable", "tokens": {"access_token": "b"}}),
            Some(&id),
            None,
        )
        .unwrap();
        assert_eq!(cloud_a, cloud_b);

        let memory_a = VaultManager::freshness_id_from(
            "memory",
            &serde_json::Value::Null,
            Some(&id),
            Some("instance-a"),
        )
        .unwrap();
        let memory_b = VaultManager::freshness_id_from(
            "memory",
            &serde_json::Value::Null,
            Some(&id),
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
    async fn publishing_deletes_the_superseded_generation_objects() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let creation = manager
            .create_vault(
                VaultId::new("superseded-objects").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let ops = crate::VaultOperations::new(&creation.session).unwrap();
        for name in ["/a", "/b", "/c"] {
            ops.create_file(&VaultPath::parse(name).unwrap(), b"content")
                .await
                .unwrap();
        }

        let mut generation_objects: Vec<String> = provider
            .list(&VaultPath::parse(META_DIRNAME).unwrap())
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .filter(|name| {
                (name.starts_with("tree.") && name.ends_with(".enc"))
                    || (name.starts_with("config.") && name.ends_with(".json"))
            })
            .collect();
        generation_objects.sort();
        assert_eq!(generation_objects.len(), 2, "{generation_objects:?}");
        assert!(generation_objects[0].starts_with("config.4."));
        assert!(generation_objects[1].starts_with("tree.4."));
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
        let config_bytes = creation
            .config
            .to_authenticated_bytes(&creation.master_key)
            .unwrap();
        let storage: Arc<dyn StorageProvider> = provider.clone();
        manager
            .initialize_vault_structure(&storage, &creation.config, &creation.master_key)
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

    /// M-3: an old `vault.config` copy plus the old password must not decrypt
    /// anything written after a password change.
    #[tokio::test]
    async fn old_config_and_old_password_cannot_decrypt_data_written_after_password_change() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let mut creation = manager
            .create_vault(
                VaultId::new("m3-old-config").unwrap(),
                b"old-password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let before = VaultPath::parse("/before.txt").unwrap();
        let before_content = b"written before the change";
        VaultOperations::new(&creation.session)
            .unwrap()
            .create_file(&before, before_content)
            .await
            .unwrap();
        let old_config = VaultConfig::from_bytes(
            &provider
                .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();

        creation
            .session
            .change_password(b"old-password", b"new-password")
            .unwrap();
        manager.save_config(&mut creation.session).await.unwrap();
        let after = VaultPath::parse("/after.txt").unwrap();
        let after_content = b"written after the change";
        VaultOperations::new(&creation.session)
            .unwrap()
            .create_file(&after, after_content)
            .await
            .unwrap();
        drop(creation);

        // The attacker holds the old config and the old password, and can read
        // every object in storage.
        let old_key = old_config
            .verify_password(b"old-password")
            .unwrap()
            .expect("the old config still accepts the old password");
        let data_dir = VaultPath::parse(DATA_DIRNAME).unwrap();
        let mut recovered = Vec::new();
        for entry in provider.list(&data_dir).await.unwrap() {
            let bytes = provider
                .download(&data_dir.join(&entry.name).unwrap())
                .await
                .unwrap();
            let file_key = old_key.derive_file_key(entry.name.as_bytes());
            if let Ok(plaintext) = axiomvault_crypto::decrypt(file_key.as_bytes(), &bytes) {
                recovered.push(plaintext);
            }
        }
        assert!(
            !recovered.iter().any(|p| p == after_content),
            "old config + old password decrypted a file written after the password change"
        );
        // Pre-change files were re-encrypted under the new key and their old
        // ciphertext deleted, so the old key opens nothing in current storage.
        assert!(recovered.is_empty(), "old key still opens a stored object");
        assert!(VaultSession::decrypt_tree_bytes(
            &old_key,
            &provider.download(&tree_path()).await.unwrap()
        )
        .is_err());
        assert!(GenerationManifest::open(
            &old_key,
            &provider.download(&manifest_path()).await.unwrap()
        )
        .is_err());

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .unwrap();
        let ops = VaultOperations::new(&reopened).unwrap();
        assert_eq!(ops.read_file(&after).await.unwrap(), after_content);
        assert_eq!(ops.read_file(&before).await.unwrap(), before_content);
    }

    /// Two root-level and nested one-shot files, a streamed file two
    /// directories deep, and an empty directory.
    async fn write_rotation_fixture(session: &VaultSession) -> Vec<(VaultPath, Vec<u8>)> {
        use crate::operations::VaultOperations;

        let ops = VaultOperations::new(session).unwrap();
        for dir in ["/dir", "/dir/sub", "/empty"] {
            ops.create_directory(&VaultPath::parse(dir).unwrap())
                .await
                .unwrap();
        }
        let mut files = vec![
            (VaultPath::parse("/a.txt").unwrap(), b"root file".to_vec()),
            (VaultPath::parse("/dir/c.txt").unwrap(), b"nested".to_vec()),
        ];
        for (path, content) in &files {
            ops.create_file(path, content).await.unwrap();
        }
        let streamed = VaultPath::parse("/dir/sub/b.bin").unwrap();
        let content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let temp = tempfile::TempDir::new().unwrap();
        let source = temp.path().join("b.bin");
        std::fs::write(&source, &content).unwrap();
        ops.create_file_from_path(&streamed, &source).await.unwrap();
        files.push((streamed, content));
        files
    }

    async fn assert_fixture(session: &VaultSession, files: &[(VaultPath, Vec<u8>)]) {
        use crate::operations::VaultOperations;

        let ops = VaultOperations::new(session).unwrap();
        for (path, content) in files {
            assert_eq!(&ops.read_file(path).await.unwrap(), content, "{path}");
        }
        assert!(ops.exists(&VaultPath::parse("/empty").unwrap()).await);
    }

    async fn object_names<P: StorageProvider + ?Sized>(
        provider: &P,
        dir: &str,
    ) -> std::collections::BTreeSet<String> {
        provider
            .list(&VaultPath::parse(dir).unwrap())
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect()
    }

    async fn all_objects<P: StorageProvider + ?Sized>(
        provider: &P,
    ) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut objects = std::collections::BTreeMap::new();
        for dir in [DATA_DIRNAME, META_DIRNAME] {
            for name in object_names(provider, dir).await {
                let path = VaultPath::parse(dir).unwrap().join(&name).unwrap();
                objects.insert(path.to_string(), provider.download(&path).await.unwrap());
            }
        }
        let config = VaultPath::parse(CONFIG_FILENAME).unwrap();
        objects.insert(
            config.to_string(),
            provider.download(&config).await.unwrap(),
        );
        objects
    }

    /// Whether `key` decrypts any one-shot data object in storage.
    async fn key_opens_any_data_object<P: StorageProvider + ?Sized>(
        provider: &P,
        key: &MasterKey,
    ) -> bool {
        let data_dir = VaultPath::parse(DATA_DIRNAME).unwrap();
        for name in object_names(provider, DATA_DIRNAME).await {
            let bytes = provider
                .download(&data_dir.join(&name).unwrap())
                .await
                .unwrap();
            let file_key = key.derive_file_key(name.as_bytes());
            if axiomvault_crypto::decrypt(file_key.as_bytes(), &bytes).is_ok()
                || axiomvault_crypto::DecryptingStream::new(file_key.as_bytes())
                    .unwrap()
                    .decrypt_stream(bytes.as_slice(), std::io::sink())
                    .is_ok()
            {
                return true;
            }
        }
        false
    }

    #[tokio::test]
    async fn recovery_words_from_before_rotation_open_the_rotated_vault() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let mut creation = manager
            .create_vault(
                VaultId::new("rotation-recovery").unwrap(),
                b"old-password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let words = creation.recovery_words.clone();
        let mut files = write_rotation_fixture(&creation.session).await;
        let old_config = VaultConfig::from_bytes(
            &provider
                .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();

        creation
            .session
            .change_password(b"old-password", b"new-password")
            .unwrap();
        manager.save_config(&mut creation.session).await.unwrap();
        let after = (VaultPath::parse("/after.txt").unwrap(), b"after".to_vec());
        VaultOperations::new(&creation.session)
            .unwrap()
            .create_file(&after.0, &after.1)
            .await
            .unwrap();
        files.push(after);
        drop(creation);

        // The old config's recovery wrap yields the old key, which opens
        // nothing written after the rotation.
        let rk = RecoveryKey::from_mnemonic(&words).unwrap();
        let old_recovered = old_config.verify_recovery_key(&rk).unwrap().unwrap();
        assert!(GenerationManifest::open(
            &old_recovered,
            &provider.download(&manifest_path()).await.unwrap()
        )
        .is_err());
        assert!(!key_opens_any_data_object(provider.as_ref(), &old_recovered).await);

        // The same words recover the vault and read the current data.
        let recovered = manager
            .recover_vault("test", serde_json::Value::Null, &words, b"third-password")
            .await
            .unwrap();
        assert_fixture(&recovered, &files).await;
        drop(recovered);
        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"third-password")
            .await
            .unwrap();
        assert_fixture(&reopened, &files).await;
    }

    #[derive(Debug, Clone, Copy)]
    enum RotationFailure {
        DataObject,
        ConfigObject,
        TreeObject,
        Manifest,
    }

    #[tokio::test]
    async fn interrupted_rotation_before_commit_keeps_old_password_and_data() {
        for failure in [
            RotationFailure::DataObject,
            RotationFailure::ConfigObject,
            RotationFailure::TreeObject,
            RotationFailure::Manifest,
        ] {
            let provider = Arc::new(ManifestFailProvider::new());
            let manager = manager_with_manifest_failure_storage(
                provider.clone(),
                Arc::new(InMemoryFreshnessAnchor::new()),
            );
            let mut creation = manager
                .create_vault(
                    VaultId::new("interrupted-rotation").unwrap(),
                    b"old-password",
                    "test",
                    serde_json::Value::Null,
                    KdfParams::moderate(),
                )
                .await
                .unwrap();
            let files = write_rotation_fixture(&creation.session).await;
            let data_before = object_names(provider.as_ref(), DATA_DIRNAME).await;
            let manifest_before = provider.download(&manifest_path()).await.unwrap();

            creation
                .session
                .change_password(b"old-password", b"new-password")
                .unwrap();
            match failure {
                RotationFailure::DataObject => provider.fail_next_data_object(),
                RotationFailure::ConfigObject => provider.fail_next_config_object(),
                RotationFailure::TreeObject => provider.fail_next_tree_object(),
                RotationFailure::Manifest => provider.fail_next_manifest(),
            }
            assert!(
                manager.save_config(&mut creation.session).await.is_err(),
                "{failure:?}"
            );
            assert!(creation
                .session
                .config()
                .verify_password(b"old-password")
                .unwrap()
                .is_some());
            // The live session still reads its data under the old key.
            assert_fixture(&creation.session, &files).await;
            drop(creation);

            assert_eq!(
                provider.download(&manifest_path()).await.unwrap(),
                manifest_before,
                "{failure:?}"
            );
            assert_eq!(
                object_names(provider.as_ref(), DATA_DIRNAME).await,
                data_before,
                "{failure:?}: uncommitted re-encrypted objects must be removed"
            );
            let reopened = manager
                .open_vault("test", serde_json::Value::Null, b"old-password")
                .await
                .unwrap_or_else(|error| panic!("{failure:?}: {error}"));
            assert_fixture(&reopened, &files).await;
            drop(reopened);
            assert!(manager
                .open_vault("test", serde_json::Value::Null, b"new-password")
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn anchor_failure_after_rotation_commit_keeps_new_password_and_data() {
        // One failure is retried within the commit; two fail the call after
        // the manifest has already committed.
        for failures in [1, 2] {
            let provider = Arc::new(MemoryProvider::new());
            let anchor = Arc::new(ToggleStoreFailureAnchor::new());
            let manager = manager_with_storage(provider.clone(), anchor.clone());
            let mut creation = manager
                .create_vault(
                    VaultId::new("anchor-rotation").unwrap(),
                    b"old-password",
                    "test",
                    serde_json::Value::Null,
                    KdfParams::moderate(),
                )
                .await
                .unwrap();
            let files = write_rotation_fixture(&creation.session).await;
            creation
                .session
                .change_password(b"old-password", b"new-password")
                .unwrap();
            anchor.fail_next_stores(failures);
            let result = manager.save_config(&mut creation.session).await;
            assert_eq!(result.is_ok(), failures == 1, "{failures}: {result:?}");
            drop(creation);

            let reopened = manager
                .open_vault("test", serde_json::Value::Null, b"new-password")
                .await
                .unwrap_or_else(|error| panic!("{failures}: {error}"));
            assert_fixture(&reopened, &files).await;
            drop(reopened);
            assert!(manager
                .open_vault("test", serde_json::Value::Null, b"old-password")
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn recovery_reset_rotates_master_key_and_refuses_bad_words_without_writing() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("reset-rotation").unwrap();
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
        let mut files = write_rotation_fixture(&creation.session).await;
        drop(creation);
        let old_config = VaultConfig::from_bytes(
            &provider
                .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        let old_key = old_config
            .verify_password(b"old-password")
            .unwrap()
            .unwrap();

        // Valid words of another vault are refused before any write.
        let objects_before = all_objects(provider.as_ref()).await;
        let anchor_before = anchor.load_state(&test_anchor_id(&vault_id)).unwrap();
        let wrong_words = RecoveryKey::generate().to_mnemonic().unwrap();
        let error = manager
            .recover_vault("test", serde_json::Value::Null, &wrong_words, b"reset")
            .await
            .err()
            .expect("a wrong recovery key must be refused");
        assert!(matches!(error, Error::NotPermitted(_)), "{error}");
        assert_eq!(all_objects(provider.as_ref()).await, objects_before);
        assert_eq!(
            anchor.load_state(&test_anchor_id(&vault_id)).unwrap(),
            anchor_before
        );

        let reset = manager
            .recover_vault("test", serde_json::Value::Null, &words, b"reset-password")
            .await
            .unwrap();
        assert_ne!(reset.master_key().unwrap().as_bytes(), old_key.as_bytes());
        let after = (VaultPath::parse("/after.txt").unwrap(), b"after".to_vec());
        VaultOperations::new(&reset)
            .unwrap()
            .create_file(&after.0, &after.1)
            .await
            .unwrap();
        files.push(after);
        drop(reset);

        assert!(!key_opens_any_data_object(provider.as_ref(), &old_key).await);
        assert!(GenerationManifest::open(
            &old_key,
            &provider.download(&manifest_path()).await.unwrap()
        )
        .is_err());
        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"reset-password")
            .await
            .unwrap();
        assert_fixture(&reopened, &files).await;
        drop(reopened);
        assert!(manager
            .open_vault("test", serde_json::Value::Null, b"old-password")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rotation_handles_an_empty_vault() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let mut creation = manager
            .create_vault(
                VaultId::new("empty-rotation").unwrap(),
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
        assert_eq!(
            creation.session.commit_master_key_rotation().await.unwrap(),
            0
        );
        drop(creation);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .unwrap();
        assert_eq!(reopened.tree().read().await.count_files(), 0);
        assert!(object_names(provider.as_ref(), DATA_DIRNAME)
            .await
            .is_empty());
        drop(reopened);
        assert!(manager
            .open_vault("test", serde_json::Value::Null, b"old-password")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rotation_rewrites_nested_files_and_deletes_old_master_objects() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let mut creation = manager
            .create_vault(
                VaultId::new("nested-rotation").unwrap(),
                b"old-password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let files = write_rotation_fixture(&creation.session).await;
        let old_data = object_names(provider.as_ref(), DATA_DIRNAME).await;
        let old_meta = object_names(provider.as_ref(), META_DIRNAME).await;
        let old_key = creation.session.master_key().unwrap().clone();

        creation
            .session
            .change_password(b"old-password", b"new-password")
            .unwrap();
        assert_eq!(
            creation.session.commit_master_key_rotation().await.unwrap(),
            0
        );
        assert_fixture(&creation.session, &files).await;

        let new_data = object_names(provider.as_ref(), DATA_DIRNAME).await;
        assert_eq!(new_data.len(), files.len());
        assert!(new_data.is_disjoint(&old_data));
        assert_eq!(
            new_data,
            crate::operations::file_object_names(&*creation.session.tree().read().await)
                .into_iter()
                .collect()
        );
        let new_meta = object_names(provider.as_ref(), META_DIRNAME).await;
        let generation_objects: Vec<_> = new_meta
            .iter()
            .filter(|name| {
                (name.starts_with("tree.") && name.ends_with(".enc")) || name.starts_with("config.")
            })
            .collect();
        assert_eq!(generation_objects.len(), 2, "{new_meta:?}");
        assert!(generation_objects
            .iter()
            .all(|name| !old_meta.contains(*name)));
        assert!(!key_opens_any_data_object(provider.as_ref(), &old_key).await);
        drop(creation);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .unwrap();
        assert_fixture(&reopened, &files).await;
    }

    #[tokio::test]
    async fn failed_old_object_delete_does_not_fail_the_rotation() {
        let provider = Arc::new(ManifestFailProvider::new());
        let manager = manager_with_manifest_failure_storage(
            provider.clone(),
            Arc::new(InMemoryFreshnessAnchor::new()),
        );
        let mut creation = manager
            .create_vault(
                VaultId::new("delete-failure-rotation").unwrap(),
                b"old-password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let files = write_rotation_fixture(&creation.session).await;
        let old_data = object_names(provider.as_ref(), DATA_DIRNAME).await;

        creation
            .session
            .change_password(b"old-password", b"new-password")
            .unwrap();
        provider.fail_deletes(true);
        let remaining = creation.session.commit_master_key_rotation().await.unwrap();
        provider.fail_deletes(false);
        assert!(remaining >= old_data.len(), "{remaining}");
        assert!(old_data.is_subset(&object_names(provider.as_ref(), DATA_DIRNAME).await));
        assert_fixture(&creation.session, &files).await;
        drop(creation);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .unwrap();
        assert_fixture(&reopened, &files).await;
        drop(reopened);
        assert!(manager
            .open_vault("test", serde_json::Value::Null, b"old-password")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn writers_opened_before_a_rotation_are_not_published() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let mut creation = manager
            .create_vault(
                VaultId::new("writer-rotation").unwrap(),
                b"old-password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        let files = write_rotation_fixture(&creation.session).await;
        let replaced = files[0].0.clone();
        let created = VaultPath::parse("/new.txt").unwrap();
        let (mut replacing, mut creating) = {
            let ops = VaultOperations::new(&creation.session).unwrap();
            (
                ops.open_file_writer(&replaced).await.unwrap(),
                ops.create_file_writer(&created).await.unwrap(),
            )
        };
        replacing.write(b"replacement").await.unwrap();
        creating.write(b"created").await.unwrap();

        creation
            .session
            .change_password(b"old-password", b"new-password")
            .unwrap();
        manager.save_config(&mut creation.session).await.unwrap();
        let tree_before = serde_json::to_vec(&*creation.session.tree().read().await).unwrap();

        let ops = VaultOperations::new(&creation.session).unwrap();
        assert!(matches!(
            ops.finish_file_writer(&replaced, replacing).await,
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            ops.finish_file_writer(&created, creating).await,
            Err(Error::Conflict(_))
        ));
        let tree = creation.session.tree().read().await;
        assert_eq!(serde_json::to_vec(&*tree).unwrap(), tree_before);
        assert_eq!(
            object_names(provider.as_ref(), DATA_DIRNAME).await,
            crate::operations::file_object_names(&tree)
                .into_iter()
                .collect()
        );
        drop(tree);
        assert_fixture(&creation.session, &files).await;
        drop(creation);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .unwrap();
        assert_fixture(&reopened, &files).await;
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
            .initialize_vault_structure(&storage, &creation.config, &creation.master_key)
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

    /// N-1: the provider deletes the manifest and rewrites the unauthenticated
    /// `id` in `vault.config` so the id-derived anchor lookup misses.
    async fn strip_manifest_and_rename_vault(provider: &MemoryProvider) {
        let config_path = VaultPath::parse(CONFIG_FILENAME).unwrap();
        let mut config =
            VaultConfig::from_bytes(&provider.download(&config_path).await.unwrap()).unwrap();
        config.id = VaultId::new("attacker-renamed").unwrap();
        provider
            .upload(&config_path, config.to_bytes().unwrap())
            .await
            .unwrap();
        provider.delete(&manifest_path()).await.unwrap();
    }

    #[tokio::test]
    async fn renamed_vault_without_manifest_cannot_bypass_device_anchor() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let creation = manager
            .create_vault(
                VaultId::new("anchored").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        creation.session.save_tree().await.unwrap();
        let words = creation.recovery_words.clone();
        drop(creation);

        strip_manifest_and_rename_vault(&provider).await;

        let error = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("open must refuse a manifest-less vault at an anchored location");
        assert!(matches!(error, Error::Conflict(_)));
        let error = manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("upgrade must refuse a manifest-less vault at an anchored location");
        assert!(matches!(error, Error::Conflict(_)));
        let error = manager
            .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
            .await
            .err()
            .expect("recovery must refuse a manifest-less vault at an anchored location");
        assert!(matches!(error, Error::Conflict(_)));
        assert!(!provider.exists(&manifest_path()).await.unwrap());
        assert_eq!(
            anchor
                .load(&test_anchor_id(&VaultId::new("attacker-renamed").unwrap()))
                .unwrap(),
            None
        );
        assert_eq!(
            anchor
                .load(&test_anchor_id(&VaultId::new("anchored").unwrap()))
                .unwrap(),
            Some(2)
        );
    }

    #[tokio::test]
    async fn legacy_vault_bootstraps_beside_an_anchor_for_another_location() {
        let anchored_storage = Arc::new(MemoryProvider::new());
        let legacy_storage = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let mut registry = ProviderRegistry::new();
        let anchored = anchored_storage.clone();
        registry
            .register("test", Box::new(move |_| Ok(anchored.clone())))
            .unwrap();
        let legacy = legacy_storage.clone();
        registry
            .register("legacy", Box::new(move |_| Ok(legacy.clone())))
            .unwrap();
        let manager = VaultManager::with_registry_and_anchor(registry, anchor.clone());
        manager
            .create_vault(
                VaultId::new("anchored").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();

        let creation = VaultConfig::new(
            VaultId::new("legacy-elsewhere").unwrap(),
            b"password",
            "legacy",
            serde_json::Value::Null,
            KdfParams::moderate(),
        )
        .unwrap();
        let storage: Arc<dyn StorageProvider> = legacy_storage.clone();
        manager
            .initialize_vault_structure(&storage, &creation.config, &creation.master_key)
            .await
            .unwrap();
        VaultSession::from_master_key(
            creation.config,
            creation.master_key,
            legacy_storage.clone(),
            VaultTree::new(),
        )
        .unwrap()
        .save_tree()
        .await
        .unwrap();
        assert!(!legacy_storage.exists(&manifest_path()).await.unwrap());

        manager
            .open_vault("legacy", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert!(legacy_storage.exists(&manifest_path()).await.unwrap());
        // The bootstrapped location is now marked, so the bypass is closed for it too.
        strip_manifest_and_rename_vault(&legacy_storage).await;
        assert!(matches!(
            manager
                .open_vault("legacy", serde_json::Value::Null, b"password")
                .await,
            Err(Error::Conflict(_))
        ));
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
    async fn legacy_cloud_config_holding_credentials_is_refused_before_any_write() {
        for version in [VaultVersion::CURRENT, VaultVersion::V1_1] {
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

            let mut labelled = creation.session.config().clone();
            labelled.version = version;
            let mut legacy: serde_json::Value =
                serde_json::from_slice(&labelled.to_bytes().unwrap()).unwrap();
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

            // A tagged config cannot hold credentials (serialization refuses
            // them), so a config holding them was written outside the vault:
            // at 2.0 its tag fails, at 1.1 it is untagged. Every path refuses
            // it before the sanitizing upload (M-1).
            let expected = if version == VaultVersion::V1_1 {
                crate::config::UNAUTHENTICATED_V1_1
            } else {
                "config_mac"
            };
            for result in [
                open_manager
                    .open_vault("gdrive", safe_config.clone(), b"password")
                    .await,
                open_manager
                    .upgrade_to_current("gdrive", safe_config.clone(), b"password")
                    .await,
            ] {
                match result {
                    Err(error) => assert!(error.to_string().contains(expected), "{error}"),
                    Ok(_) => panic!("a {version} cloud config holding credentials was opened"),
                }
            }
            let untouched = storage
                .download(&VaultPath::parse(CONFIG_FILENAME).unwrap())
                .await
                .unwrap();
            assert_eq!(untouched, serde_json::to_vec(&legacy).unwrap());
        }
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

    /// A b6520ff-style vault: untagged 1.1 `vault.config`, `m/tree.json`, no
    /// manifest, and one file in the one-shot AEAD encoding (`content_version`
    /// 0). Every path refuses it; see `write_tagged_v1_1_vault_without_manifest`.
    async fn write_untagged_v1_1_vault_without_manifest(
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

    /// `write_untagged_v1_1_vault_without_manifest` with a tagged
    /// `vault.config`, as the registry's 1.0 -> 1.1 migration writes it.
    async fn write_tagged_v1_1_vault_without_manifest(
        provider: Arc<dyn StorageProvider>,
        vault_id: &str,
    ) -> (VaultPath, Zeroizing<String>) {
        let written = write_untagged_v1_1_vault_without_manifest(provider.clone(), vault_id).await;
        let config = stored_config(provider.as_ref()).await;
        let master_key = config.verify_password(b"password").unwrap().unwrap();
        provider
            .upload(
                &config_path(),
                config.to_authenticated_bytes(&master_key).unwrap(),
            )
            .await
            .unwrap();
        written
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

    const V1_1_REFUSAL: &str =
        "vault version 1.1 must be upgraded with `axiom vault migrate` before it can be opened";

    fn assert_v1_1_refusal(result: Result<VaultSession>) {
        match result {
            Err(Error::Vault(message)) => assert_eq!(message, V1_1_REFUSAL),
            Err(other) => panic!("unexpected error for a 1.1 vault: {other}"),
            Ok(_) => panic!("a 1.1 vault must not open without an explicit upgrade"),
        }
    }

    /// Every stored object keyed by path, with its content digest and etag.
    /// `MemoryProvider` issues a fresh etag on every upload, so equal maps mean
    /// no object was written at all.
    async fn storage_objects<P: StorageProvider + ?Sized>(
        provider: &P,
    ) -> std::collections::BTreeMap<String, (String, Option<String>)> {
        let mut objects = std::collections::BTreeMap::new();
        let mut pending = vec![VaultPath::root()];
        while let Some(directory) = pending.pop() {
            for entry in provider.list(&directory).await.unwrap() {
                let path = directory.join(&entry.name).unwrap();
                if entry.is_directory {
                    objects.insert(path.to_string(), ("directory".to_string(), entry.etag));
                    pending.push(path);
                } else {
                    let bytes = provider.download(&path).await.unwrap();
                    objects.insert(path.to_string(), (digest(&bytes), entry.etag));
                }
            }
        }
        objects
    }

    async fn storage_digests<P: StorageProvider + ?Sized>(
        provider: &P,
    ) -> std::collections::BTreeMap<String, String> {
        storage_objects(provider)
            .await
            .into_iter()
            .map(|(path, (content, _))| (path, content))
            .collect()
    }

    struct V1_1ManifestVault {
        file: VaultPath,
        generation: u64,
        manifest_bytes: Vec<u8>,
        config_bytes: Vec<u8>,
        recovery_words: Zeroizing<String>,
    }

    /// A vault whose current manifest generation is labelled 1.1, as a pre-bump
    /// client on this device published it, with a 1.1 `vault.config` cache.
    async fn write_v1_1_vault_with_manifest<P: StorageProvider + ?Sized>(
        manager: &VaultManager,
        provider: &P,
        anchor: &dyn FreshnessAnchor,
        vault_id: &VaultId,
    ) -> V1_1ManifestVault {
        use crate::operations::VaultOperations;

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
                &test_anchor_id(vault_id),
                FreshnessState {
                    generation: labelled.generation,
                    manifest_digest: Some(digest(&labelled_bytes)),
                },
            )
            .unwrap();
        V1_1ManifestVault {
            file,
            generation: labelled.generation,
            manifest_bytes: labelled_bytes,
            config_bytes: v1_1_bytes,
            recovery_words: creation.recovery_words.clone(),
        }
    }

    #[tokio::test]
    async fn opening_a_v1_1_vault_is_refused_before_any_write() {
        // Without a manifest: no cache, sanitize, manifest or anchor write.
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("v1-1-refused").unwrap();
        write_tagged_v1_1_vault_without_manifest(provider.clone(), vault_id.as_str()).await;
        let before = storage_objects(provider.as_ref()).await;

        assert_v1_1_refusal(
            manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
        );
        assert_eq!(storage_objects(provider.as_ref()).await, before);
        assert_eq!(anchor.load_state(&test_anchor_id(&vault_id)).unwrap(), None);
        let location_id = test_location_id();
        assert_eq!(anchor.load(&location_id).unwrap(), None);

        // With a 1.1 manifest generation: the anchor state is left as it was.
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("v1-1-manifest-refused").unwrap();
        write_v1_1_vault_with_manifest(&manager, provider.as_ref(), anchor.as_ref(), &vault_id)
            .await;
        let before = storage_objects(provider.as_ref()).await;
        let anchored = anchor.load_state(&test_anchor_id(&vault_id)).unwrap();

        assert_v1_1_refusal(
            manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
        );
        assert_eq!(storage_objects(provider.as_ref()).await, before);
        assert_eq!(
            anchor.load_state(&test_anchor_id(&vault_id)).unwrap(),
            anchored
        );
    }

    #[tokio::test]
    async fn upgrade_to_current_makes_a_v1_1_vault_readable_at_current() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let (file, _) =
            write_tagged_v1_1_vault_without_manifest(provider.clone(), "v1-1-upgrade").await;

        let session = manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
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

        // The upgraded vault now opens through the ordinary path.
        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
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
    async fn upgrade_to_current_on_a_current_vault_writes_nothing() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("already-current").unwrap();
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
        drop(creation);
        let before = storage_digests(provider.as_ref()).await;
        let generation = anchor.load(&test_anchor_id(&vault_id)).unwrap();

        let session = manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(session.config().version, VaultVersion::CURRENT);
        // Same bytes everywhere and no new generation: at most the open path's
        // identical `vault.config` cache refresh.
        assert_eq!(storage_digests(provider.as_ref()).await, before);
        assert_eq!(anchor.load(&test_anchor_id(&vault_id)).unwrap(), generation);
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
    async fn v1_1_vault_without_manifest_upgrades_explicitly_and_survives_interruption() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(ManifestFailProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_manifest_failure_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("v1-1-bootstrap").unwrap();
        let (file, _) =
            write_tagged_v1_1_vault_without_manifest(provider.clone(), vault_id.as_str()).await;
        let v1_1_bytes = provider.download(&config_path()).await.unwrap();

        // Interrupted before the first manifest commit: storage is still 1.1.
        provider.fail_next_manifest();
        assert!(manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await
            .is_err());
        assert!(!provider.exists(&manifest_path()).await.unwrap());
        assert_eq!(provider.download(&config_path()).await.unwrap(), v1_1_bytes);
        assert_v1_1_refusal(
            manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
        );

        let session = manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
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
    async fn cancelled_upgrade_leaves_a_v1_1_vault_refused_and_upgradable() {
        use crate::operations::VaultOperations;
        use std::time::Duration;

        let provider = Arc::new(ManifestFailProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_manifest_failure_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("v1-1-cancelled-upgrade").unwrap();
        let (file, _) =
            write_tagged_v1_1_vault_without_manifest(provider.clone(), vault_id.as_str()).await;
        let v1_1_bytes = provider.download(&config_path()).await.unwrap();

        // Cancelled after the generation tree upload, before the manifest commit.
        provider.pause_next_tree_after_commit();
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            manager.upgrade_to_current("test", serde_json::Value::Null, b"password"),
        )
        .await;
        assert!(result.is_err(), "upgrade future must be cancelled");
        assert!(!provider.exists(&manifest_path()).await.unwrap());
        assert_eq!(provider.download(&config_path()).await.unwrap(), v1_1_bytes);
        assert_eq!(anchor.load_state(&test_anchor_id(&vault_id)).unwrap(), None);
        assert_v1_1_refusal(
            manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
        );

        let session = manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(session.config().version, VaultVersion::CURRENT);
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
    async fn v1_1_vault_with_manifest_upgrades_explicitly_and_survives_interruption() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(ManifestFailProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_manifest_failure_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("v1-1-manifest").unwrap();
        let vault =
            write_v1_1_vault_with_manifest(&manager, provider.as_ref(), anchor.as_ref(), &vault_id)
                .await;
        let file = vault.file;
        let v1_1_generation = vault.generation;
        // Untagged: only the sealed manifest authenticates these bytes.
        assert!(VaultConfig::from_bytes(&vault.config_bytes)
            .unwrap()
            .config_mac
            .is_none());

        // Interrupted before the 2.0 manifest commit: still a 1.1 vault.
        provider.fail_next_manifest();
        assert!(manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await
            .is_err());
        assert_eq!(
            provider.download(&manifest_path()).await.unwrap(),
            vault.manifest_bytes
        );
        assert_eq!(
            stored_config(provider.as_ref()).await.version,
            VaultVersion::V1_1
        );
        assert_v1_1_refusal(
            manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
        );

        let session = manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
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
        provider
            .upload(&config_path(), vault.config_bytes)
            .await
            .unwrap();
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
    async fn upgrade_cannot_bypass_the_location_marker() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        write_tagged_v1_1_vault_without_manifest(provider.clone(), "v1-1-marked").await;
        manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        let location_id = test_location_id();
        assert!(anchor.load(&location_id).unwrap().is_some());

        // N-1 after the upgrade, relabelled 1.1 so only the upgrade path would
        // accept it: the location marker still refuses the no-manifest path.
        strip_manifest_and_rename_vault(&provider).await;
        let mut relabelled = stored_config(provider.as_ref()).await;
        relabelled.version = VaultVersion::V1_1;
        provider
            .upload(&config_path(), relabelled.to_bytes().unwrap())
            .await
            .unwrap();
        let before = storage_objects(provider.as_ref()).await;

        assert!(matches!(
            manager
                .upgrade_to_current("test", serde_json::Value::Null, b"password")
                .await,
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
            Err(Error::Conflict(_))
        ));
        assert_eq!(storage_objects(provider.as_ref()).await, before);
        assert_eq!(
            anchor
                .load(&test_anchor_id(&VaultId::new("attacker-renamed").unwrap()))
                .unwrap(),
            None
        );
    }

    async fn read_v1_1_file(session: &VaultSession, file: &VaultPath) -> Vec<u8> {
        crate::operations::VaultOperations::new(session)
            .unwrap()
            .read_file(file)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn recovering_a_v1_1_vault_resets_the_password_and_upgrades_to_current() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("v1-1-recover").unwrap();
        let (file, words) =
            write_tagged_v1_1_vault_without_manifest(provider.clone(), vault_id.as_str()).await;
        let old_key = stored_config(provider.as_ref())
            .await
            .verify_password(b"password")
            .unwrap()
            .unwrap();

        // The password is forgotten; only the recovery words are used.
        let session = manager
            .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
            .await
            .unwrap();
        assert_eq!(session.config().version, VaultVersion::CURRENT);
        assert_ne!(session.master_key().unwrap().as_bytes(), old_key.as_bytes());
        assert!(provider.exists(&manifest_path()).await.unwrap());
        let (generation, committed) =
            committed_config(provider.as_ref(), session.master_key().unwrap()).await;
        assert_eq!(generation, 1);
        assert_eq!(committed.version, VaultVersion::CURRENT);
        assert_eq!(
            stored_config(provider.as_ref()).await.version,
            VaultVersion::CURRENT
        );
        assert_eq!(read_v1_1_file(&session, &file).await, V1_1_CONTENT);
        drop(session);
        assert_eq!(anchor.load(&test_anchor_id(&vault_id)).unwrap(), Some(1));
        assert!(!key_opens_any_data_object(provider.as_ref(), &old_key).await);

        // The new password opens the 2.0 vault through the ordinary path.
        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .unwrap();
        assert_eq!(reopened.config().version, VaultVersion::CURRENT);
        assert_eq!(read_v1_1_file(&reopened, &file).await, V1_1_CONTENT);
        drop(reopened);

        // The old password no longer opens it, by either path.
        assert!(matches!(
            manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
            Err(Error::NotPermitted(_))
        ));
        assert!(matches!(
            manager
                .upgrade_to_current("test", serde_json::Value::Null, b"password")
                .await,
            Err(Error::NotPermitted(_))
        ));

        // The recovery words keep working on the recovered vault.
        drop(
            manager
                .recover_vault("test", serde_json::Value::Null, &words, b"third-password")
                .await
                .unwrap(),
        );
        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"third-password")
            .await
            .unwrap();
        assert_eq!(read_v1_1_file(&reopened, &file).await, V1_1_CONTENT);
    }

    #[tokio::test]
    async fn recovering_a_v1_1_manifest_vault_upgrades_it_in_the_next_generation() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("v1-1-manifest-recover").unwrap();
        let vault =
            write_v1_1_vault_with_manifest(&manager, provider.as_ref(), anchor.as_ref(), &vault_id)
                .await;

        let session = manager
            .recover_vault(
                "test",
                serde_json::Value::Null,
                &vault.recovery_words,
                b"new-password",
            )
            .await
            .unwrap();
        let (generation, committed) =
            committed_config(provider.as_ref(), session.master_key().unwrap()).await;
        assert_eq!(generation, vault.generation + 1);
        assert_eq!(committed.version, VaultVersion::CURRENT);
        assert_eq!(read_v1_1_file(&session, &vault.file).await, V1_1_CONTENT);
        drop(session);

        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"new-password")
            .await
            .unwrap();
        assert_eq!(read_v1_1_file(&reopened, &vault.file).await, V1_1_CONTENT);
        drop(reopened);
        assert!(manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn wrong_or_empty_recovery_words_on_a_v1_1_vault_write_nothing() {
        // Without a manifest.
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("v1-1-wrong-words").unwrap();
        let (file, words) =
            write_tagged_v1_1_vault_without_manifest(provider.clone(), vault_id.as_str()).await;
        let before = storage_objects(provider.as_ref()).await;
        let location_id = test_location_id();
        let wrong_words = RecoveryKey::generate().to_mnemonic().unwrap();

        let error = manager
            .recover_vault("test", serde_json::Value::Null, &wrong_words, b"reset")
            .await
            .err()
            .expect("wrong recovery words must be refused");
        assert!(matches!(error, Error::NotPermitted(_)), "{error}");
        for empty in ["", "   "] {
            assert!(manager
                .recover_vault("test", serde_json::Value::Null, empty, b"reset")
                .await
                .is_err());
        }
        assert_eq!(storage_objects(provider.as_ref()).await, before);
        assert_eq!(anchor.load_state(&test_anchor_id(&vault_id)).unwrap(), None);
        assert_eq!(anchor.load(&location_id).unwrap(), None);

        // The refused attempts leave a 1.1 vault: still refused on open, and
        // still recoverable with the right words.
        assert_v1_1_refusal(
            manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
        );
        let session = manager
            .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
            .await
            .unwrap();
        assert_eq!(read_v1_1_file(&session, &file).await, V1_1_CONTENT);

        // With a 1.1 manifest generation: storage and anchor are left as they were.
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let vault_id = VaultId::new("v1-1-manifest-wrong-words").unwrap();
        write_v1_1_vault_with_manifest(&manager, provider.as_ref(), anchor.as_ref(), &vault_id)
            .await;
        let before = storage_objects(provider.as_ref()).await;
        let anchored = anchor.load_state(&test_anchor_id(&vault_id)).unwrap();
        for attempt in [wrong_words.as_str(), "", "   "] {
            assert!(manager
                .recover_vault("test", serde_json::Value::Null, attempt, b"reset")
                .await
                .is_err());
        }
        assert_eq!(storage_objects(provider.as_ref()).await, before);
        assert_eq!(
            anchor.load_state(&test_anchor_id(&vault_id)).unwrap(),
            anchored
        );
        assert_v1_1_refusal(
            manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
        );
    }

    #[tokio::test]
    async fn v1_1_recovery_refuses_a_mismatched_encrypted_recovery_key_without_writes() {
        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let (_, words) =
            write_tagged_v1_1_vault_without_manifest(provider.clone(), "v1-1-mismatched-recovery")
                .await;
        let mut config = stored_config(provider.as_ref()).await;
        let master_key = config.verify_password(b"password").unwrap().unwrap();
        config.config_mac = None;
        config.encrypted_recovery_key = Some(
            axiomvault_crypto::encrypt(master_key.as_bytes(), RecoveryKey::generate().as_bytes())
                .unwrap(),
        );
        // Tagged, so recovery reaches the binding check rather than refusing
        // an untagged config.
        provider
            .upload(
                &config_path(),
                config.to_authenticated_bytes(&master_key).unwrap(),
            )
            .await
            .unwrap();
        let before = storage_objects(provider.as_ref()).await;

        let error = manager
            .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
            .await
            .err()
            .expect("a recovery key that disagrees with its stored copy must be refused");
        assert_eq!(
            error.to_string(),
            "Cryptographic error: stored recovery key does not match the recovery words"
        );
        assert_eq!(storage_objects(provider.as_ref()).await, before);

        // Untagged, the password upgrade refuses it as unauthenticated.
        provider
            .upload(&config_path(), config.to_bytes().unwrap())
            .await
            .unwrap();
        let before = storage_objects(provider.as_ref()).await;
        let error = manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("an untagged config with unbound recovery fields must not be upgraded");
        assert_eq!(error.to_string(), crate::config::UNAUTHENTICATED_V1_1);
        assert_eq!(storage_objects(provider.as_ref()).await, before);
    }

    #[tokio::test]
    async fn recovering_a_v1_0_vault_is_refused_until_migrated() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let mut legacy = VaultConfig::new(
            VaultId::new("v1-0-recover").unwrap(),
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
        for dirname in [DATA_DIRNAME, META_DIRNAME] {
            provider
                .create_dir(&VaultPath::parse(dirname).unwrap())
                .await
                .unwrap();
        }
        provider
            .upload(&config_path(), legacy.to_bytes().unwrap())
            .await
            .unwrap();
        let before = storage_objects(provider.as_ref()).await;
        let words = RecoveryKey::generate().to_mnemonic().unwrap();

        let error = manager
            .recover_vault("test", serde_json::Value::Null, &words, b"reset")
            .await
            .err()
            .expect("a 1.0 vault must be migrated before it is recovered");
        assert!(
            matches!(
                &error,
                Error::Vault(message)
                    if message == "vault version 1.0 must be migrated to 1.1 before it can be opened"
            ),
            "{error}"
        );
        assert_eq!(storage_objects(provider.as_ref()).await, before);
        let location_id = test_location_id();
        assert_eq!(anchor.load(&location_id).unwrap(), None);
    }

    #[tokio::test]
    async fn interrupted_v1_1_recovery_keeps_the_old_snapshot_or_commits_the_new_one() {
        // Failures before the manifest commit leave the 1.1 vault as it was.
        for failure in [
            RotationFailure::DataObject,
            RotationFailure::ConfigObject,
            RotationFailure::TreeObject,
            RotationFailure::Manifest,
        ] {
            let provider = Arc::new(ManifestFailProvider::new());
            let anchor = Arc::new(InMemoryFreshnessAnchor::new());
            let manager = manager_with_manifest_failure_storage(provider.clone(), anchor.clone());
            let vault_id = VaultId::new("v1-1-interrupted-recovery").unwrap();
            let (file, words) =
                write_tagged_v1_1_vault_without_manifest(provider.clone(), vault_id.as_str()).await;
            let v1_1_bytes = provider.download(&config_path()).await.unwrap();
            let tree_before = provider.download(&tree_path()).await.unwrap();
            let data_before = object_names(provider.as_ref(), DATA_DIRNAME).await;

            match failure {
                RotationFailure::DataObject => provider.fail_next_data_object(),
                RotationFailure::ConfigObject => provider.fail_next_config_object(),
                RotationFailure::TreeObject => provider.fail_next_tree_object(),
                RotationFailure::Manifest => provider.fail_next_manifest(),
            }
            assert!(
                manager
                    .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
                    .await
                    .is_err(),
                "{failure:?}"
            );
            assert!(
                !provider.exists(&manifest_path()).await.unwrap(),
                "{failure:?}"
            );
            assert_eq!(
                provider.download(&config_path()).await.unwrap(),
                v1_1_bytes,
                "{failure:?}"
            );
            assert_eq!(
                provider.download(&tree_path()).await.unwrap(),
                tree_before,
                "{failure:?}"
            );
            assert_eq!(
                object_names(provider.as_ref(), DATA_DIRNAME).await,
                data_before,
                "{failure:?}: uncommitted re-encrypted objects must be removed"
            );
            assert_eq!(
                anchor.load_state(&test_anchor_id(&vault_id)).unwrap(),
                None,
                "{failure:?}"
            );
            assert!(manager
                .open_vault("test", serde_json::Value::Null, b"new-password")
                .await
                .is_err());
            assert_v1_1_refusal(
                manager
                    .open_vault("test", serde_json::Value::Null, b"password")
                    .await,
            );

            // The untouched 1.1 snapshot is recovered on retry.
            let session = manager
                .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
                .await
                .unwrap_or_else(|error| panic!("{failure:?}: {error}"));
            assert_eq!(read_v1_1_file(&session, &file).await, V1_1_CONTENT);
            drop(session);
            let reopened = manager
                .open_vault("test", serde_json::Value::Null, b"new-password")
                .await
                .unwrap_or_else(|error| panic!("{failure:?}: {error}"));
            assert_eq!(read_v1_1_file(&reopened, &file).await, V1_1_CONTENT);
        }

        // An anchor failure after the manifest commit leaves the new 2.0 vault.
        // One failure is retried within the commit; two fail the call.
        for failures in [1, 2] {
            let provider = Arc::new(MemoryProvider::new());
            let anchor = Arc::new(ToggleStoreFailureAnchor::new());
            let manager = manager_with_storage(provider.clone(), anchor.clone());
            let (file, words) =
                write_tagged_v1_1_vault_without_manifest(provider.clone(), "v1-1-anchor-recovery")
                    .await;

            anchor.fail_next_stores(failures);
            let result = manager
                .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
                .await;
            assert_eq!(result.is_ok(), failures == 1, "{failures}");
            drop(result);

            let reopened = manager
                .open_vault("test", serde_json::Value::Null, b"new-password")
                .await
                .unwrap_or_else(|error| panic!("{failures}: {error}"));
            assert_eq!(reopened.config().version, VaultVersion::CURRENT);
            assert_eq!(read_v1_1_file(&reopened, &file).await, V1_1_CONTENT);
            drop(reopened);
            assert!(manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn v1_0_vault_is_refused_until_migrated_then_upgraded_explicitly() {
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
        // A real 1.0 vault's tree is encrypted under the password-derived key.
        let legacy_key = legacy.verify_password(b"password").unwrap().unwrap();
        let tree_key = legacy_key.derive_file_key(crate::session::TREE_KEY_CONTEXT);
        provider
            .upload(
                &tree_path(),
                axiomvault_crypto::encrypt(
                    tree_key.as_bytes(),
                    VaultTree::new().to_json().unwrap().as_bytes(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let before = storage_objects(provider.as_ref()).await;

        let v1_0_refusal = "vault version 1.0 must be migrated to 1.1 before it can be opened";
        let error = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("a 1.0 vault must be migrated before it is opened");
        assert!(matches!(&error, Error::Vault(message) if message == v1_0_refusal));
        let error = manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await
            .err()
            .expect("a 1.0 vault must be migrated before it is upgraded");
        assert!(matches!(&error, Error::Vault(message) if message == v1_0_refusal));
        assert_eq!(storage_objects(provider.as_ref()).await, before);
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
        assert!(stored_config(provider.as_ref()).await.config_mac.is_some());
        assert_v1_1_refusal(
            manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
        );

        let session = manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(session.config().version, VaultVersion::CURRENT);
        assert_eq!(
            stored_config(provider.as_ref()).await.version,
            VaultVersion::CURRENT
        );
        drop(session);
        let reopened = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(reopened.config().version, VaultVersion::CURRENT);
    }

    /// A current vault holding one file, created through `create_vault`.
    async fn write_current_vault_with_file(
        manager: &VaultManager,
        vault_id: &str,
    ) -> (VaultPath, Zeroizing<String>) {
        use crate::operations::VaultOperations;

        let creation = manager
            .create_vault(
                VaultId::new(vault_id).unwrap(),
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
        (file, creation.recovery_words.clone())
    }

    #[tokio::test]
    async fn manifest_referencing_a_missing_tree_object_is_refused_without_writes() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let (_, words) = write_current_vault_with_file(&manager, "missing-tree-object").await;
        let master_key = stored_config(provider.as_ref())
            .await
            .verify_password(b"password")
            .unwrap()
            .unwrap();
        let manifest = GenerationManifest::open(
            &master_key,
            &provider.download(&manifest_path()).await.unwrap(),
        )
        .unwrap();
        let (tree_object, _) = manifest.object_paths().unwrap();
        provider.delete(&tree_object).await.unwrap();
        provider.delete(&tree_path()).await.unwrap();
        let before = storage_objects(provider.as_ref()).await;
        let anchored = anchor
            .load_state(&test_anchor_id(
                &VaultId::new("missing-tree-object").unwrap(),
            ))
            .unwrap();
        let other_device = Arc::new(InMemoryFreshnessAnchor::new());
        let opener = manager_with_storage(provider.clone(), other_device.clone());

        for manager in [&manager, &opener] {
            for result in [
                manager
                    .open_vault("test", serde_json::Value::Null, b"password")
                    .await,
                manager
                    .upgrade_to_current("test", serde_json::Value::Null, b"password")
                    .await,
                manager
                    .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
                    .await,
            ] {
                match result {
                    Err(Error::Crypto(message)) => assert_eq!(
                        message,
                        "snapshot manifest references a missing generation object"
                    ),
                    Err(other) => panic!("unexpected error: {other}"),
                    Ok(_) => panic!("a manifest whose tree is missing must not open"),
                }
            }
        }
        assert_eq!(storage_objects(provider.as_ref()).await, before);
        assert_eq!(
            anchor
                .load_state(&test_anchor_id(
                    &VaultId::new("missing-tree-object").unwrap()
                ))
                .unwrap(),
            anchored
        );
        assert_eq!(
            other_device
                .load_state(&test_anchor_id(
                    &VaultId::new("missing-tree-object").unwrap()
                ))
                .unwrap(),
            None
        );
    }

    fn assert_missing_tree_refusal(result: Result<VaultSession>) {
        match result {
            Err(Error::Vault(message)) => assert!(
                message.starts_with("tree index m/tree.json is missing but"),
                "unexpected refusal: {message}"
            ),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("a vault with data but no tree index must not open as empty"),
        }
    }

    #[tokio::test]
    async fn missing_tree_index_with_data_is_refused_without_writes() {
        // No manifest, no tree, one object in `d/`: a 1.1 vault being upgraded.
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        write_tagged_v1_1_vault_without_manifest(provider.clone(), "tree-less-v1-1").await;
        provider.delete(&tree_path()).await.unwrap();
        let before = storage_objects(provider.as_ref()).await;

        assert_missing_tree_refusal(
            manager
                .upgrade_to_current("test", serde_json::Value::Null, b"password")
                .await,
        );
        assert_eq!(storage_objects(provider.as_ref()).await, before);
        assert_eq!(
            anchor
                .load_state(&test_anchor_id(&VaultId::new("tree-less-v1-1").unwrap()))
                .unwrap(),
            None
        );

        // A current vault whose manifest and tree index are withheld, opened on a
        // device with no freshness state for it.
        let provider = Arc::new(MemoryProvider::new());
        let creator =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let (_, words) = write_current_vault_with_file(&creator, "tree-less-current").await;
        provider.delete(&manifest_path()).await.unwrap();
        provider.delete(&tree_path()).await.unwrap();
        let before = storage_objects(provider.as_ref()).await;
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let opener = manager_with_storage(provider.clone(), anchor.clone());

        assert_missing_tree_refusal(
            opener
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
        );
        assert_missing_tree_refusal(
            opener
                .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
                .await,
        );
        assert_eq!(storage_objects(provider.as_ref()).await, before);
        assert_eq!(
            anchor
                .load_state(&test_anchor_id(&VaultId::new("tree-less-current").unwrap()))
                .unwrap(),
            None
        );
        let location_id = test_location_id();
        assert_eq!(anchor.load(&location_id).unwrap(), None);
    }

    #[tokio::test]
    async fn freshly_created_vault_reopens_and_keeps_its_files() {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let creation = manager
            .create_vault(
                VaultId::new("fresh-reopen").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        assert!(creation
            .session
            .tree()
            .read()
            .await
            .list(&VaultPath::root())
            .unwrap()
            .is_empty());
        drop(creation);

        let file = VaultPath::parse("/fresh.txt").unwrap();
        let session = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        VaultOperations::new(&session)
            .unwrap()
            .create_file(&file, b"fresh content")
            .await
            .unwrap();
        drop(session);

        for manager in [
            &manager,
            &manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new())),
        ] {
            let session = manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await
                .unwrap();
            assert_eq!(
                VaultOperations::new(&session)
                    .unwrap()
                    .read_file(&file)
                    .await
                    .unwrap(),
                b"fresh content"
            );
        }
    }

    #[tokio::test]
    async fn stripped_wrapped_key_and_tree_cannot_be_migrated_or_opened() {
        use crate::migration::MigrationRegistry;

        let provider = Arc::new(MemoryProvider::new());
        let manager =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        write_current_vault_with_file(&manager, "stripped-key").await;
        let real_master_key = stored_config(provider.as_ref())
            .await
            .verify_password(b"password")
            .unwrap()
            .unwrap();
        // The provider strips the wrapped key and recovery material, labels the
        // config 1.0, and withholds every object that would expose the swap.
        let mut stripped = stored_config(provider.as_ref()).await;
        stripped.version = VaultVersion { major: 1, minor: 0 };
        stripped.wrapped_master_key = None;
        stripped.recovery_wrapped_master_key = None;
        stripped.recovery_key_verification = None;
        stripped.encrypted_recovery_key = None;
        provider
            .upload(&config_path(), stripped.to_bytes().unwrap())
            .await
            .unwrap();
        provider.delete(&tree_path()).await.unwrap();
        provider.delete(&manifest_path()).await.unwrap();
        let before = storage_objects(provider.as_ref()).await;

        let error = MigrationRegistry::with_defaults()
            .migrate(provider.as_ref(), b"password", &VaultVersion::V1_1)
            .await
            .err()
            .expect("a stripped config must not be migrated");
        assert!(matches!(&error, Error::Crypto(message)
            if message.contains("not proven to be the vault master key")));
        for result in [
            manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await,
            manager
                .upgrade_to_current("test", serde_json::Value::Null, b"password")
                .await,
        ] {
            assert!(result.is_err());
        }
        assert_eq!(storage_objects(provider.as_ref()).await, before);
        // The real master key is still the one the data is under.
        assert_ne!(
            stripped
                .verify_password(b"password")
                .unwrap()
                .unwrap()
                .as_bytes(),
            real_master_key.as_bytes()
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

    // -- M-1: integrity of `vault.config` -----------------------------------

    async fn rewrite_config_object(
        provider: &MemoryProvider,
        path: &VaultPath,
        edit: &dyn Fn(&mut serde_json::Value),
    ) {
        let mut json: serde_json::Value =
            serde_json::from_slice(&provider.download(path).await.unwrap()).unwrap();
        edit(&mut json);
        provider
            .upload(path, serde_json::to_vec(&json).unwrap())
            .await
            .unwrap();
    }

    fn weaken_kdf(json: &mut serde_json::Value) {
        json["kdf_params"] =
            serde_json::json!({ "memory_cost": 8, "time_cost": 1, "parallelism": 1 });
    }

    fn redirect_provider(json: &mut serde_json::Value) {
        json["provider_config"] = serde_json::json!({ "root": "/attacker" });
    }

    fn strip_config_mac(json: &mut serde_json::Value) {
        json.as_object_mut().unwrap().remove("config_mac");
    }

    fn alter_config_mac(json: &mut serde_json::Value) {
        let tag = json["config_mac"]
            .as_array_mut()
            .expect("stored config carries a config_mac");
        tag[0] = (tag[0].as_u64().unwrap() ^ 1).into();
    }

    const OPEN_PATHS: [&str; 3] = ["open_vault", "upgrade_to_current", "recover_vault"];

    /// Run the open path named `path` (one of `OPEN_PATHS`) on `manager`.
    async fn open_attempt(
        manager: &VaultManager,
        path: &str,
        password: &[u8],
        words: &str,
    ) -> Result<VaultSession> {
        let null = serde_json::Value::Null;
        match path {
            "open_vault" => manager.open_vault("test", null, password).await,
            "upgrade_to_current" => manager.upgrade_to_current("test", null, password).await,
            "recover_vault" => {
                manager
                    .recover_vault("test", null, words, b"reset-password")
                    .await
            }
            _ => unreachable!("unknown open path {path}"),
        }
    }

    /// A refusal: which open path, on which device, with or without the
    /// manifest, and the error it returned.
    struct Refusal {
        path: &'static str,
        new_device: bool,
        manifest_stripped: bool,
        message: String,
    }

    /// Apply `edit` as the provider and assert that every open path refuses
    /// it, on this device (`anchor`) and on a device that has never seen the
    /// vault, without writing to storage or to either device's anchor. Runs
    /// twice: with the manifest in place (the provider rewrites `vault.config`
    /// and the generation config object the manifest hint names) and with the
    /// manifest deleted (N-1). The genuine snapshot is put back after each run.
    async fn assert_rewrite_refused(
        provider: &Arc<MemoryProvider>,
        anchor: &Arc<InMemoryFreshnessAnchor>,
        vault_id: &str,
        password: &[u8],
        words: &str,
        edit: &dyn Fn(&mut serde_json::Value),
    ) -> Vec<Refusal> {
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let manifest = provider.download(&manifest_path()).await.unwrap();
        let object = GenerationManifest::config_path_hint(&manifest)
            .unwrap()
            .unwrap();
        let mut originals = Vec::new();
        for path in [config_path(), object.clone()] {
            let bytes = provider.download(&path).await.unwrap();
            originals.push((path, bytes));
        }
        let anchor_id = test_anchor_id(&VaultId::new(vault_id).unwrap());
        let mut refusals = Vec::new();
        for manifest_stripped in [false, true] {
            rewrite_config_object(provider, &config_path(), edit).await;
            if manifest_stripped {
                provider.delete(&manifest_path()).await.unwrap();
            } else {
                rewrite_config_object(provider, &object, edit).await;
            }
            let before = storage_objects(provider.as_ref()).await;
            let anchored = anchor.load_state(&anchor_id).unwrap();
            let other_anchor = Arc::new(InMemoryFreshnessAnchor::new());
            let other_device = manager_with_storage(provider.clone(), other_anchor.clone());

            for (new_device, manager) in [(false, &manager), (true, &other_device)] {
                for path in OPEN_PATHS {
                    let context = format!(
                        "{path} (new device: {new_device}, manifest stripped: {manifest_stripped})"
                    );
                    match open_attempt(manager, path, password, words).await {
                        Ok(_) => panic!("{context} accepted a rewritten vault.config"),
                        Err(error) => refusals.push(Refusal {
                            path,
                            new_device,
                            manifest_stripped,
                            message: error.to_string(),
                        }),
                    }
                    assert_eq!(
                        storage_objects(provider.as_ref()).await,
                        before,
                        "{context} wrote to storage"
                    );
                }
            }
            assert_eq!(anchor.load_state(&anchor_id).unwrap(), anchored);
            assert_eq!(other_anchor.load_state(&anchor_id).unwrap(), None);
            let location_id = test_location_id();
            assert_eq!(other_anchor.load(&location_id).unwrap(), None);

            for (path, bytes) in &originals {
                provider.upload(path, bytes.clone()).await.unwrap();
            }
            provider
                .upload(&manifest_path(), manifest.clone())
                .await
                .unwrap();
        }
        refusals
    }

    /// `assert_rewrite_refused` on a fresh vault holding one file.
    async fn assert_config_rewrite_refused(
        vault_id: &str,
        edit: &dyn Fn(&mut serde_json::Value),
    ) -> Vec<Refusal> {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let (_, words) = write_current_vault_with_file(&manager, vault_id).await;
        assert_rewrite_refused(&provider, &anchor, vault_id, b"password", &words, edit).await
    }

    async fn read_back(session: &VaultSession, file: &VaultPath) -> Vec<u8> {
        crate::operations::VaultOperations::new(session)
            .unwrap()
            .read_file(file)
            .await
            .unwrap()
    }

    /// The genuine snapshot opens and reads `file` on this device and on a
    /// device that has never seen the vault.
    async fn assert_genuine_snapshot_opens(
        provider: &Arc<MemoryProvider>,
        anchor: &Arc<InMemoryFreshnessAnchor>,
        password: &[u8],
        file: &VaultPath,
    ) {
        let other_device: Arc<InMemoryFreshnessAnchor> = Arc::new(InMemoryFreshnessAnchor::new());
        for device in [anchor.clone(), other_device] {
            let session = manager_with_storage(provider.clone(), device)
                .open_vault("test", serde_json::Value::Null, password)
                .await
                .unwrap();
            assert_eq!(read_back(&session, file).await, V1_1_CONTENT);
        }
    }

    /// M-1 (a): weaker KDF parameters written into `vault.config` are refused
    /// before any write. A password open already fails on them (the password
    /// check is keyed by those parameters); recovery does not use the
    /// password, so without config integrity it rewraps under them.
    #[tokio::test]
    async fn rewritten_kdf_parameters_are_refused_before_any_write() {
        assert_config_rewrite_refused("weak-kdf", &weaken_kdf).await;
    }

    /// M-1 (b): a changed hardware-key enrollment or provider setting is
    /// refused before any write.
    #[tokio::test]
    async fn rewritten_hardware_key_or_provider_settings_are_refused_before_any_write() {
        let fake_enrollment = |json: &mut serde_json::Value| {
            json["hardware_key"] = serde_json::json!({
                "metadata": { "kind": "RawSecret", "enrolled_at": "2026-01-01T00:00:00Z" },
                "wrapped_master_key": vec![7u8; 72],
                "key_verification": vec![7u8; 58],
            });
        };
        assert_config_rewrite_refused("hardware-key-added", &fake_enrollment).await;
        assert_config_rewrite_refused("provider-config", &redirect_provider).await;
        assert_config_rewrite_refused("provider-type", &|json: &mut serde_json::Value| {
            json["provider_type"] = serde_json::json!("attacker");
        })
        .await;

        // An enrolled hardware key removed by the provider.
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let (file, words) = write_current_vault_with_file(&manager, "hardware-key-removed").await;
        let mut session = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        let master_key = session.master_key().unwrap().clone();
        session
            .config_mut()
            .enroll_hardware_key(
                &master_key,
                b"simulated-yubikey-hmac-response",
                crate::config::HardwareKeyMetadata::new(
                    crate::config::HardwareKeyKind::YubiKeyHmacSha1,
                    None,
                    None,
                ),
            )
            .unwrap();
        manager.save_config(&mut session).await.unwrap();
        drop(session);
        assert_genuine_snapshot_opens(&provider, &anchor, b"password", &file).await;
        assert_rewrite_refused(
            &provider,
            &anchor,
            "hardware-key-removed",
            b"password",
            &words,
            &|json: &mut serde_json::Value| {
                json.as_object_mut().unwrap().remove("hardware_key");
            },
        )
        .await;
    }

    /// M-1 (c) and (e): the genuine config reopens and reads data after a
    /// password change and after a recovery, and a tampered copy of each new
    /// config is refused.
    #[tokio::test]
    async fn rotated_configs_reopen_and_their_tampered_copies_are_refused() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let vault_id = "m1-rotation";
        let (file, words) = write_current_vault_with_file(&manager, vault_id).await;

        let mut session = manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        session
            .change_password(b"password", b"changed-password")
            .unwrap();
        manager.save_config(&mut session).await.unwrap();
        assert_eq!(read_back(&session, &file).await, V1_1_CONTENT);
        drop(session);
        assert_genuine_snapshot_opens(&provider, &anchor, b"changed-password", &file).await;
        for edit in [
            weaken_kdf as fn(&mut serde_json::Value),
            redirect_provider,
            alter_config_mac,
        ] {
            assert_rewrite_refused(
                &provider,
                &anchor,
                vault_id,
                b"changed-password",
                &words,
                &edit,
            )
            .await;
        }

        let recovered = manager
            .recover_vault(
                "test",
                serde_json::Value::Null,
                &words,
                b"recovered-password",
            )
            .await
            .unwrap();
        assert_eq!(read_back(&recovered, &file).await, V1_1_CONTENT);
        drop(recovered);
        assert_genuine_snapshot_opens(&provider, &anchor, b"recovered-password", &file).await;
        for edit in [
            weaken_kdf as fn(&mut serde_json::Value),
            redirect_provider,
            alter_config_mac,
        ] {
            assert_rewrite_refused(
                &provider,
                &anchor,
                vault_id,
                b"recovered-password",
                &words,
                &edit,
            )
            .await;
        }
    }

    /// M-1 (d): a config whose tag was removed or altered is refused, and where
    /// no manifest binds the config the refusal names the tag.
    #[tokio::test]
    async fn removed_or_altered_config_mac_is_refused_with_a_clear_message() {
        for (edit, expected) in [
            (
                strip_config_mac as fn(&mut serde_json::Value),
                "vault.config has no integrity tag (config_mac); a 2.0 vault config without one is refused",
            ),
            (
                alter_config_mac,
                "vault.config integrity check failed (config_mac mismatch): the stored config was changed outside this vault",
            ),
        ] {
            let refusals = assert_config_rewrite_refused("mac-edit", &edit).await;
            let unbound: Vec<_> = refusals
                .iter()
                .filter(|refusal| refusal.new_device && refusal.manifest_stripped)
                .collect();
            assert_eq!(unbound.len(), OPEN_PATHS.len());
            for refusal in unbound {
                assert_eq!(
                    refusal.message,
                    format!("Cryptographic error: {expected}"),
                    "{}",
                    refusal.path
                );
            }
        }
    }

    /// M-1 (f): a vault made by `create_vault` stores a tagged config, opens
    /// and reads back on this device and a new one, and its genuine config
    /// also bootstraps where the manifest is missing.
    #[tokio::test]
    async fn created_vault_stores_a_tagged_config_and_reads_back() {
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let (file, _) = write_current_vault_with_file(&manager, "m1-fresh").await;

        let stored = provider.download(&config_path()).await.unwrap();
        let manifest = provider.download(&manifest_path()).await.unwrap();
        let object = GenerationManifest::config_path_hint(&manifest)
            .unwrap()
            .unwrap();
        assert_eq!(provider.download(&object).await.unwrap(), stored);
        let json: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(json["config_mac"].as_array().map(Vec::len), Some(32));

        assert_genuine_snapshot_opens(&provider, &anchor, b"password", &file).await;

        provider.delete(&manifest_path()).await.unwrap();
        let session =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()))
                .open_vault("test", serde_json::Value::Null, b"password")
                .await
                .unwrap();
        assert_eq!(read_back(&session, &file).await, V1_1_CONTENT);
    }

    // -- KDF floor and untagged 1.1 configs ---------------------------------

    /// Strip the manifest (N-1) and rewrite `vault.config` as 1.1 without its
    /// tag, applying `edit` too: what a provider serves a new device.
    async fn relabel_as_untagged_v1_1(
        provider: &MemoryProvider,
        edit: &dyn Fn(&mut serde_json::Value),
    ) {
        provider.delete(&manifest_path()).await.unwrap();
        rewrite_config_object(provider, &config_path(), &|json| {
            json["version"] = serde_json::json!({ "major": 1, "minor": 1 });
            strip_config_mac(json);
            edit(json);
        })
        .await;
    }

    /// Assert `result` is refused with `expected` and nothing was written: not
    /// to storage, not to `device`'s anchor for `vault_id` or the location.
    async fn assert_refused_without_writes(
        result: Result<VaultSession>,
        expected: &str,
        provider: &MemoryProvider,
        before: &std::collections::BTreeMap<String, (String, Option<String>)>,
        device: &InMemoryFreshnessAnchor,
        vault_id: &str,
    ) {
        match result {
            Ok(session) => panic!(
                "accepted; the master key was rewrapped under {:?}",
                session.config().kdf_params
            ),
            Err(error) => assert!(error.to_string().contains(expected), "{error}"),
        }
        assert_eq!(&storage_objects(provider).await, before);
        assert_eq!(
            device
                .load_state(&test_anchor_id(&VaultId::new(vault_id).unwrap()))
                .unwrap(),
            None
        );
        let location_id = test_location_id();
        assert_eq!(device.load(&location_id).unwrap(), None);
    }

    /// (a) On a device that has never seen the vault, a provider relabels the
    /// config 1.1, strips its tag and weakens its KDF parameters. Before the
    /// floor, recovery accepted it and rewrapped the new master key under the
    /// weak parameters, so the new password was cheap to brute-force from the
    /// next `vault.config`.
    #[tokio::test]
    async fn new_device_recovery_refuses_a_relabelled_untagged_weak_kdf_config() {
        let provider = Arc::new(MemoryProvider::new());
        let creator =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let (_, words) = write_current_vault_with_file(&creator, "kdf-floor-relabel").await;
        relabel_as_untagged_v1_1(&provider, &weaken_kdf).await;
        let before = storage_objects(provider.as_ref()).await;

        let new_device = Arc::new(InMemoryFreshnessAnchor::new());
        let result = manager_with_storage(provider.clone(), new_device.clone())
            .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
            .await;
        assert_refused_without_writes(
            result,
            "KDF parameters below the minimum",
            &provider,
            &before,
            &new_device,
            "kdf-floor-relabel",
        )
        .await;
    }

    /// (b) The same relabelled, untagged config with the vault's own KDF
    /// parameters is refused by recovery: nothing authenticates it.
    #[tokio::test]
    async fn new_device_recovery_refuses_a_relabelled_untagged_config() {
        let provider = Arc::new(MemoryProvider::new());
        let creator =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        let (_, words) = write_current_vault_with_file(&creator, "untagged-relabel").await;
        relabel_as_untagged_v1_1(&provider, &|_| {}).await;
        let before = storage_objects(provider.as_ref()).await;

        let new_device = Arc::new(InMemoryFreshnessAnchor::new());
        let result = manager_with_storage(provider.clone(), new_device.clone())
            .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
            .await;
        assert_refused_without_writes(
            result,
            crate::config::UNAUTHENTICATED_V1_1,
            &provider,
            &before,
            &new_device,
            "untagged-relabel",
        )
        .await;
    }

    /// (c) and (e) A genuine tagged config at the floor (`moderate()`, the
    /// CLI's weakest strength) and above it (`interactive()`) changes its
    /// password and recovers on a new device, with and without the manifest;
    /// a tagged 1.1 config at the floor upgrades and changes its password.
    #[tokio::test]
    async fn genuine_configs_at_or_above_the_floor_upgrade_change_password_and_recover() {
        use crate::operations::VaultOperations;

        let floor = KdfParams::moderate();
        assert_eq!(
            (floor.memory_cost, floor.time_cost),
            (KdfParams::MIN_MEMORY_COST, KdfParams::MIN_TIME_COST)
        );
        for params in [KdfParams::moderate(), KdfParams::interactive()] {
            let provider = Arc::new(MemoryProvider::new());
            let anchor = Arc::new(InMemoryFreshnessAnchor::new());
            let manager = manager_with_storage(provider.clone(), anchor.clone());
            let creation = manager
                .create_vault(
                    VaultId::new("floor-genuine").unwrap(),
                    b"password",
                    "test",
                    serde_json::Value::Null,
                    params.clone(),
                )
                .await
                .unwrap();
            let file = VaultPath::parse("/notes.txt").unwrap();
            VaultOperations::new(&creation.session)
                .unwrap()
                .create_file(&file, V1_1_CONTENT)
                .await
                .unwrap();
            let words = creation.recovery_words.clone();
            drop(creation);

            let mut session = manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await
                .unwrap();
            session
                .change_password(b"password", b"changed-password")
                .unwrap();
            manager.save_config(&mut session).await.unwrap();
            drop(session);
            assert_genuine_snapshot_opens(&provider, &anchor, b"changed-password", &file).await;

            for strip_manifest in [false, true] {
                if strip_manifest {
                    provider.delete(&manifest_path()).await.unwrap();
                }
                let recovered = manager_with_storage(
                    provider.clone(),
                    Arc::new(InMemoryFreshnessAnchor::new()),
                )
                .recover_vault(
                    "test",
                    serde_json::Value::Null,
                    &words,
                    b"recovered-password",
                )
                .await
                .unwrap_or_else(|error| panic!("{params:?}, {strip_manifest}: {error}"));
                assert_eq!(read_back(&recovered, &file).await, V1_1_CONTENT);
                assert_eq!(
                    recovered.config().kdf_params.memory_cost,
                    params.memory_cost
                );
            }
        }

        // A tagged 1.1 vault at the floor, upgraded with the password.
        let provider = Arc::new(MemoryProvider::new());
        let anchor = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), anchor.clone());
        let (file, _) =
            write_tagged_v1_1_vault_without_manifest(provider.clone(), "floor-v1-1").await;
        let mut session = manager
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        assert_eq!(session.config().version, VaultVersion::CURRENT);
        session
            .change_password(b"password", b"changed-password")
            .unwrap();
        manager.save_config(&mut session).await.unwrap();
        drop(session);
        assert_genuine_snapshot_opens(&provider, &anchor, b"changed-password", &file).await;
    }

    /// (d) A genuine config just below the floor is refused on every path that
    /// rewraps the master key, before any write.
    #[tokio::test]
    async fn configs_just_below_the_floor_are_refused_on_every_rewrap_path() {
        let below = [
            KdfParams {
                memory_cost: KdfParams::MIN_MEMORY_COST - 1,
                ..KdfParams::moderate()
            },
            KdfParams {
                time_cost: KdfParams::MIN_TIME_COST - 1,
                ..KdfParams::moderate()
            },
        ];
        for params in below {
            let context = format!("{params:?}");
            let provider = Arc::new(MemoryProvider::new());
            let anchor = Arc::new(InMemoryFreshnessAnchor::new());
            let manager = manager_with_storage(provider.clone(), anchor.clone());
            let creation = manager
                .create_vault(
                    VaultId::new("below-floor").unwrap(),
                    b"password",
                    "test",
                    serde_json::Value::Null,
                    params.clone(),
                )
                .await
                .unwrap();
            let words = creation.recovery_words.clone();
            drop(creation);
            let refused = |error: Error| {
                assert!(
                    error
                        .to_string()
                        .contains("KDF parameters below the minimum"),
                    "{context}: {error}"
                )
            };

            // change_password and the in-session recovery reset.
            // Opening refreshes the `vault.config` cache; it rewraps nothing.
            let mut session = manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await
                .unwrap();
            let before = storage_objects(provider.as_ref()).await;
            let anchored = anchor
                .load_state(&test_anchor_id(&VaultId::new("below-floor").unwrap()))
                .unwrap();
            refused(
                session
                    .change_password(b"password", b"new-password")
                    .unwrap_err(),
            );
            let recovery_key = RecoveryKey::from_mnemonic(&words).unwrap();
            refused(
                session
                    .reset_password_with_recovery(&recovery_key, b"new-password")
                    .unwrap_err(),
            );
            assert_eq!(session.config().kdf_params.memory_cost, params.memory_cost);
            drop(session);
            assert_eq!(
                storage_objects(provider.as_ref()).await,
                before,
                "{context}"
            );

            // reset_password / rotate_master_key on the config itself.
            let mut config = stored_config(provider.as_ref()).await;
            let unchanged = config.to_bytes().unwrap();
            refused(
                config
                    .reset_password(&recovery_key, b"new-password")
                    .unwrap_err(),
            );
            refused(
                config
                    .rotate_master_key(&recovery_key, b"new-password")
                    .unwrap_err(),
            );
            assert_eq!(config.to_bytes().unwrap(), unchanged);

            // recover_vault: manifest branch on this device, then both branches
            // on a new device.
            for (strip_manifest, device) in [
                (false, anchor.clone()),
                (false, Arc::new(InMemoryFreshnessAnchor::new())),
                (true, Arc::new(InMemoryFreshnessAnchor::new())),
            ] {
                if strip_manifest {
                    provider.delete(&manifest_path()).await.unwrap();
                }
                let before = storage_objects(provider.as_ref()).await;
                let device_state = device
                    .load_state(&test_anchor_id(&VaultId::new("below-floor").unwrap()))
                    .unwrap();
                refused(
                    manager_with_storage(provider.clone(), device.clone())
                        .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
                        .await
                        .err()
                        .expect("recovery under parameters below the floor"),
                );
                assert_eq!(
                    storage_objects(provider.as_ref()).await,
                    before,
                    "{context}"
                );
                assert_eq!(
                    device
                        .load_state(&test_anchor_id(&VaultId::new("below-floor").unwrap()))
                        .unwrap(),
                    device_state,
                    "{context}"
                );
            }
            // Only the manifest deletion above changed storage.
            let mut expected = before.clone();
            expected.retain(|path, _| !path.ends_with(MANIFEST_FILENAME));
            assert_eq!(storage_objects(provider.as_ref()).await, expected);
            assert_eq!(
                anchor
                    .load_state(&test_anchor_id(&VaultId::new("below-floor").unwrap()))
                    .unwrap(),
                anchored
            );
        }
    }

    /// (f) A 1.1 config from the registry's `migrate_to_v1_1` is tagged and
    /// recovers without the password.
    #[tokio::test]
    async fn v1_1_configs_from_migration_are_tagged_and_recover() {
        use crate::migration::MigrationRegistry;

        // 1.0 -> 1.1 through the registry.
        let provider = Arc::new(MemoryProvider::new());
        let mut legacy = VaultConfig::new(
            VaultId::new("migrated-v1-1").unwrap(),
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
        for dirname in [DATA_DIRNAME, META_DIRNAME] {
            provider
                .create_dir(&VaultPath::parse(dirname).unwrap())
                .await
                .unwrap();
        }
        provider
            .upload(&config_path(), legacy.to_bytes().unwrap())
            .await
            .unwrap();
        let legacy_key = legacy.verify_password(b"password").unwrap().unwrap();
        let tree_key = legacy_key.derive_file_key(crate::session::TREE_KEY_CONTEXT);
        provider
            .upload(
                &tree_path(),
                axiomvault_crypto::encrypt(
                    tree_key.as_bytes(),
                    VaultTree::new().to_json().unwrap().as_bytes(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let outcome = MigrationRegistry::with_defaults()
            .migrate(provider.as_ref(), b"password", &VaultVersion::V1_1)
            .await
            .unwrap();
        let words = outcome.recovery_words.unwrap();
        let stored: serde_json::Value =
            serde_json::from_slice(&provider.download(&config_path()).await.unwrap()).unwrap();
        assert_eq!(
            stored["version"],
            serde_json::json!({ "major": 1, "minor": 1 })
        );
        assert_eq!(stored["config_mac"].as_array().map(Vec::len), Some(32));
        let recovered =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()))
                .recover_vault("test", serde_json::Value::Null, &words, b"new-password")
                .await
                .unwrap();
        assert_eq!(recovered.config().version, VaultVersion::CURRENT);
    }

    /// No 1.0 or 1.1 vault predates the tag, so an untagged 1.1 config that no
    /// manifest binds is refused by the password upgrade too: it would
    /// otherwise publish the config's provider settings, vault id and
    /// hardware-key flag in a tagged 2.0 generation. Both a 1.1-shaped
    /// config and a 2.0 config relabelled 1.1 with a redirected provider.
    #[tokio::test]
    async fn upgrade_to_current_refuses_an_untagged_v1_1_config_without_a_manifest() {
        let provider = Arc::new(MemoryProvider::new());
        write_untagged_v1_1_vault_without_manifest(provider.clone(), "untagged-upgrade").await;
        let before = storage_objects(provider.as_ref()).await;
        let device = Arc::new(InMemoryFreshnessAnchor::new());
        let result = manager_with_storage(provider.clone(), device.clone())
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await;
        assert_refused_without_writes(
            result,
            crate::config::UNAUTHENTICATED_V1_1,
            &provider,
            &before,
            &device,
            "untagged-upgrade",
        )
        .await;

        let provider = Arc::new(MemoryProvider::new());
        let creator =
            manager_with_storage(provider.clone(), Arc::new(InMemoryFreshnessAnchor::new()));
        write_current_vault_with_file(&creator, "relabel-upgrade").await;
        relabel_as_untagged_v1_1(&provider, &redirect_provider).await;
        let before = storage_objects(provider.as_ref()).await;
        let device = Arc::new(InMemoryFreshnessAnchor::new());
        let result = manager_with_storage(provider.clone(), device.clone())
            .upgrade_to_current("test", serde_json::Value::Null, b"password")
            .await;
        assert_refused_without_writes(
            result,
            crate::config::UNAUTHENTICATED_V1_1,
            &provider,
            &before,
            &device,
            "relabel-upgrade",
        )
        .await;
    }

    /// An untagged 1.1 config without a manifest is refused as unauthenticated
    /// by every path that yields a session (open, upgrade, recovery, which is
    /// `reset_password`), and storage stays byte-identical (`storage_objects`
    /// compares every object's digest and etag). `change_password` and the
    /// session's recovery reset need a session, which none of these returns.
    #[tokio::test]
    async fn untagged_v1_1_config_without_a_manifest_is_refused_by_every_path() {
        let provider = Arc::new(MemoryProvider::new());
        let (_, words) =
            write_untagged_v1_1_vault_without_manifest(provider.clone(), "untagged-v1-1").await;
        let before = storage_objects(provider.as_ref()).await;
        let device = Arc::new(InMemoryFreshnessAnchor::new());
        let manager = manager_with_storage(provider.clone(), device.clone());
        for path in OPEN_PATHS {
            let result = open_attempt(&manager, path, b"password", &words).await;
            assert!(
                result
                    .as_ref()
                    .err()
                    .is_some_and(|error| error.to_string() == crate::config::UNAUTHENTICATED_V1_1),
                "{path}"
            );
            assert_refused_without_writes(
                result,
                crate::config::UNAUTHENTICATED_V1_1,
                &provider,
                &before,
                &device,
                "untagged-v1-1",
            )
            .await;
        }
    }

    /// Freshness anchors of real local vaults, opened through different
    /// spellings of their path.
    #[cfg(unix)]
    mod local_anchor {
        use super::*;

        /// A local vault created at `<tmp>/real/vault`, with spellings of its
        /// root that all name the same directory.
        struct LocalVault {
            temp: tempfile::TempDir,
            canonical: std::path::PathBuf,
            id: VaultId,
        }

        impl LocalVault {
            fn new(name: &str) -> Self {
                let temp = tempfile::tempdir().unwrap();
                let real = std::fs::canonicalize(temp.path()).unwrap().join("real");
                std::fs::create_dir(&real).unwrap();
                std::os::unix::fs::symlink(&real, temp.path().join("alias")).unwrap();
                Self {
                    canonical: real.join("vault"),
                    temp,
                    id: VaultId::new(name).unwrap(),
                }
            }

            fn config(root: impl AsRef<Path>) -> serde_json::Value {
                serde_json::json!({ "root": root.as_ref().to_str().unwrap() })
            }

            /// Through a symlinked parent directory.
            fn alias(&self) -> serde_json::Value {
                Self::config(self.temp.path().join("alias/vault"))
            }

            /// Relative to the working directory.
            fn relative(&self) -> serde_json::Value {
                let up = std::env::current_dir().unwrap().components().count() - 1;
                let absolute = self.canonical.strip_prefix("/").unwrap();
                Self::config(Path::new(&"../".repeat(up)).join(absolute))
            }

            fn trailing_slash(&self) -> serde_json::Value {
                Self::config(format!("{}/", self.canonical.display()))
            }

            fn copy(&self, to: &str) -> std::path::PathBuf {
                let target = self.temp.path().join(to);
                copy_dir(&self.canonical, &target);
                target
            }

            fn restore(&self, from: &Path) {
                std::fs::remove_dir_all(&self.canonical).unwrap();
                copy_dir(from, &self.canonical);
            }
        }

        fn copy_dir(from: &Path, to: &Path) {
            std::fs::create_dir(to).unwrap();
            for entry in std::fs::read_dir(from).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    copy_dir(&entry.path(), &to.join(entry.file_name()));
                } else {
                    std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
                }
            }
        }

        fn local_manager(anchor: Arc<dyn FreshnessAnchor>) -> VaultManager {
            VaultManager::with_registry_and_anchor(create_default_registry(), anchor)
        }

        async fn add_file(session: &VaultSession, name: &str) {
            crate::operations::VaultOperations::new(session)
                .unwrap()
                .create_file(&VaultPath::parse(name).unwrap(), b"content")
                .await
                .unwrap();
        }

        /// The anchor key of `id` at a local root spelt as in `config`.
        fn key(config: &serde_json::Value, id: &VaultId) -> VaultId {
            VaultManager::freshness_id_from("local", config, Some(id), None).unwrap()
        }

        fn is_rollback(result: Result<VaultSession>) -> bool {
            result
                .err()
                .is_some_and(|error| error.to_string().contains("rollback detected"))
        }

        #[tokio::test]
        async fn local_anchor_follows_the_directory_not_the_spelling_of_its_path() {
            let vault = LocalVault::new("local-spellings");
            let anchor = Arc::new(InMemoryFreshnessAnchor::new());
            let manager = local_manager(anchor.clone());
            let canonical = LocalVault::config(&vault.canonical);
            let creation = manager
                .create_vault(
                    vault.id.clone(),
                    b"password",
                    "local",
                    canonical.clone(),
                    KdfParams::moderate(),
                )
                .await
                .unwrap();
            add_file(&creation.session, "/one").await;
            drop(creation);
            let generation_two = vault.copy("generation-two");

            let anchor_id = key(&canonical, &vault.id);
            for spelling in [vault.alias(), vault.relative(), vault.trailing_slash()] {
                let keys = manager
                    .anchor_location("local", &spelling)
                    .unwrap()
                    .keys(Some(&vault.id))
                    .unwrap();
                assert_eq!(keys.lock_id(), &anchor_id, "{spelling}");
            }

            let session = manager
                .open_vault("local", vault.alias(), b"password")
                .await
                .unwrap();
            add_file(&session, "/two").await;
            drop(session);
            assert_eq!(anchor.load(&anchor_id).unwrap(), Some(3));
            assert_eq!(
                anchor.load(&key(&vault.alias(), &vault.id)).unwrap(),
                Some(3)
            );

            vault.restore(&generation_two);
            for spelling in [vault.alias(), vault.relative(), canonical] {
                assert!(
                    is_rollback(
                        manager
                            .open_vault("local", spelling.clone(), b"password")
                            .await
                    ),
                    "{spelling}"
                );
            }
        }

        #[tokio::test]
        async fn legacy_anchor_under_the_typed_root_is_honoured_and_migrated() {
            let vault = LocalVault::new("local-legacy");
            let creator = Arc::new(InMemoryFreshnessAnchor::new());
            let manager = local_manager(creator.clone());
            let canonical = LocalVault::config(&vault.canonical);
            let creation = manager
                .create_vault(
                    vault.id.clone(),
                    b"password",
                    "local",
                    canonical.clone(),
                    KdfParams::moderate(),
                )
                .await
                .unwrap();
            add_file(&creation.session, "/one").await;
            let generation_two = vault.copy("generation-two");
            add_file(&creation.session, "/two").await;
            drop(creation);
            let generation_three = vault.copy("generation-three");

            let anchor_id = key(&canonical, &vault.id);
            let current = creator.load_state(&anchor_id).unwrap().unwrap();
            // What an older build stored after opening through the alias.
            let legacy_id =
                VaultManager::freshness_id_from("local", &vault.alias(), Some(&vault.id), None)
                    .unwrap();
            assert_ne!(legacy_id, anchor_id);

            // Only the legacy key: honoured, and copied to the canonical key.
            let device = Arc::new(InMemoryFreshnessAnchor::new());
            device.store_state(&legacy_id, current.clone()).unwrap();
            let manager = local_manager(device.clone());
            vault.restore(&generation_two);
            assert!(is_rollback(
                manager
                    .open_vault("local", vault.alias(), b"password")
                    .await
            ));
            assert_eq!(
                device.load_state(&anchor_id).unwrap(),
                Some(current.clone())
            );
            assert!(is_rollback(
                manager
                    .open_vault("local", canonical.clone(), b"password")
                    .await
            ));

            // Both keys: the higher generation wins.
            let device = Arc::new(InMemoryFreshnessAnchor::new());
            device.store(&anchor_id, current.generation - 1).unwrap();
            device.store_state(&legacy_id, current.clone()).unwrap();
            let manager = local_manager(device.clone());
            assert!(is_rollback(
                manager
                    .open_vault("local", vault.alias(), b"password")
                    .await
            ));
            vault.restore(&generation_three);
            manager
                .open_vault("local", vault.alias(), b"password")
                .await
                .unwrap();
            assert_eq!(device.load_state(&anchor_id).unwrap(), Some(current));

            // A legacy location marker still refuses a vault whose manifest is gone.
            let device = Arc::new(InMemoryFreshnessAnchor::new());
            let legacy_location =
                VaultManager::freshness_id_from("local", &vault.alias(), None, None).unwrap();
            device.store(&legacy_location, 0).unwrap();
            std::fs::remove_file(vault.canonical.join(META_DIRNAME).join(MANIFEST_FILENAME))
                .unwrap();
            let error = local_manager(device)
                .open_vault("local", vault.alias(), b"password")
                .await
                .err()
                .unwrap();
            assert!(
                error.to_string().contains("snapshot manifest missing"),
                "{error}"
            );
        }

        /// The vault is advanced through `alias/vault` while `alias` points
        /// at `real`; an attacker then repoints `alias` at an older copy.
        #[tokio::test]
        async fn repointing_a_parent_symlink_does_not_dodge_the_anchor() {
            let vault = LocalVault::new("local-repointed");
            let anchor = Arc::new(InMemoryFreshnessAnchor::new());
            let manager = local_manager(anchor);
            let creation = manager
                .create_vault(
                    vault.id.clone(),
                    b"password",
                    "local",
                    vault.alias(),
                    KdfParams::moderate(),
                )
                .await
                .unwrap();
            add_file(&creation.session, "/one").await;
            let other = vault.temp.path().join("other");
            std::fs::create_dir(&other).unwrap();
            copy_dir(&vault.canonical, &other.join("vault"));
            let generation_two = vault.copy("generation-two");
            add_file(&creation.session, "/two").await;
            drop(creation);

            let alias = vault.temp.path().join("alias");
            std::fs::remove_file(&alias).unwrap();
            std::os::unix::fs::symlink(&other, &alias).unwrap();
            assert!(is_rollback(
                manager
                    .open_vault("local", vault.alias(), b"password")
                    .await
            ));

            // The resolved key was kept too, so the real path sees it.
            vault.restore(&generation_two);
            assert!(is_rollback(
                manager
                    .open_vault("local", LocalVault::config(&vault.canonical), b"password")
                    .await
            ));
        }

        #[test]
        fn unresolvable_local_roots_are_refused() {
            let temp = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(temp.path().join("nowhere"), temp.path().join("dangling"))
                .unwrap();
            for root in [
                temp.path().join("dangling/vault"),
                temp.path().join("missing/.."),
            ] {
                assert!(
                    canonical_local_root(&LocalVault::config(&root)).is_err(),
                    "{}",
                    root.display()
                );
            }
            assert!(canonical_local_root(&serde_json::json!({})).is_err());
            let nested = temp.path().join("a/b/vault");
            assert_eq!(
                canonical_local_root(&LocalVault::config(&nested)).unwrap(),
                std::fs::canonicalize(temp.path())
                    .unwrap()
                    .join("a/b/vault")
                    .to_str()
                    .unwrap()
            );
        }

        #[tokio::test]
        async fn recreating_a_deleted_vault_needs_a_new_id() {
            let vault = LocalVault::new("recreated");
            let manager = local_manager(Arc::new(InMemoryFreshnessAnchor::new()));
            let config = LocalVault::config(&vault.canonical);
            let create = |id| {
                manager.create_vault(
                    id,
                    b"password",
                    "local",
                    config.clone(),
                    KdfParams::moderate(),
                )
            };
            drop(create(vault.id.clone()).await.unwrap());
            std::fs::remove_dir_all(&vault.canonical).unwrap();

            // The anchor outlives the deleted storage, so the old ID is refused.
            assert!(matches!(
                create(vault.id.clone()).await.err(),
                Some(Error::AlreadyExists(_))
            ));
            let fresh = VaultId::unique("recreated").unwrap();
            drop(create(fresh.clone()).await.unwrap());
            let session = manager
                .open_vault("local", config.clone(), b"password")
                .await
                .unwrap();
            assert_eq!(session.vault_id(), &fresh);
        }

        #[tokio::test]
        async fn same_id_at_two_locations_keeps_separate_anchors() {
            let first = LocalVault::new("same-name");
            let second = LocalVault::new("same-name");
            let anchor = Arc::new(InMemoryFreshnessAnchor::new());
            let manager = local_manager(anchor.clone());
            let mut sessions = Vec::new();
            for vault in [&first, &second] {
                let creation = manager
                    .create_vault(
                        vault.id.clone(),
                        b"password",
                        "local",
                        LocalVault::config(&vault.canonical),
                        KdfParams::moderate(),
                    )
                    .await
                    .unwrap();
                sessions.push(creation.session);
            }
            add_file(&sessions[0], "/one").await;

            let first_key = key(&LocalVault::config(&first.canonical), &first.id);
            let second_key = key(&LocalVault::config(&second.canonical), &second.id);
            assert_ne!(first_key, second_key);
            assert_eq!(anchor.load(&first_key).unwrap(), Some(2));
            assert_eq!(anchor.load(&second_key).unwrap(), Some(1));
        }
    }

    /// A backend that panics on an unbounded read of vault metadata (any
    /// config and everything under `m/`), records the bound of each bounded
    /// one, and serves objects whose name starts with `oversized` as longer
    /// than any bound.
    struct MetadataBoundProvider {
        inner: MemoryProvider,
        oversized: std::sync::Mutex<Option<&'static str>>,
        bounds: std::sync::Mutex<Vec<(String, u64)>>,
    }

    impl MetadataBoundProvider {
        fn assert_bounded(path: &VaultPath) {
            let metadata = path.to_string_path().starts_with("/m/")
                || path
                    .name()
                    .is_some_and(|name| name.starts_with(CONFIG_FILENAME));
            assert!(!metadata, "unbounded read of {path}");
        }
    }

    #[async_trait]
    impl StorageProvider for MetadataBoundProvider {
        fn name(&self) -> &str {
            "metadata-bound"
        }
        async fn upload(&self, path: &VaultPath, data: Vec<u8>) -> Result<Metadata> {
            self.inner.upload(path, data).await
        }
        async fn upload_stream(&self, path: &VaultPath, stream: ByteStream) -> Result<Metadata> {
            self.inner.upload_stream(path, stream).await
        }
        async fn download(&self, path: &VaultPath) -> Result<Vec<u8>> {
            Self::assert_bounded(path);
            self.inner.download(path).await
        }
        async fn download_stream(&self, path: &VaultPath) -> Result<ByteStream> {
            Self::assert_bounded(path);
            self.inner.download_stream(path).await
        }
        async fn download_bounded(&self, path: &VaultPath, max_len: u64) -> Result<Vec<u8>> {
            let name = path.name().unwrap_or_default().to_string();
            let oversized = *self.oversized.lock().unwrap();
            self.bounds.lock().unwrap().push((name.clone(), max_len));
            if oversized.is_some_and(|prefix| name.starts_with(prefix)) {
                return Err(
                    std::io::Error::new(std::io::ErrorKind::FileTooLarge, "oversized").into(),
                );
            }
            self.inner.download_bounded(path, max_len).await
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

    async fn metadata_bound_vault() -> (Arc<MetadataBoundProvider>, VaultManager) {
        use crate::operations::VaultOperations;

        let provider = Arc::new(MetadataBoundProvider {
            inner: MemoryProvider::new(),
            oversized: Default::default(),
            bounds: Default::default(),
        });
        let mut registry = ProviderRegistry::new();
        let registered = provider.clone();
        registry
            .register("test", Box::new(move |_| Ok(registered.clone())))
            .unwrap();
        let manager = VaultManager::with_registry_and_anchor(
            registry,
            Arc::new(InMemoryFreshnessAnchor::new()),
        );
        let creation = manager
            .create_vault(
                VaultId::new("metadata-bounds").unwrap(),
                b"password",
                "test",
                serde_json::Value::Null,
                KdfParams::moderate(),
            )
            .await
            .unwrap();
        VaultOperations::new(&creation.session)
            .unwrap()
            .create_file(&VaultPath::parse("/file").unwrap(), b"content")
            .await
            .unwrap();
        (provider, manager)
    }

    #[tokio::test]
    async fn vault_metadata_is_read_within_the_bound_for_its_format() {
        let (provider, manager) = metadata_bound_vault().await;
        manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
        crate::health::check_vault_structure(provider.as_ref(), "test")
            .await
            .unwrap();

        let bounds = provider.bounds.lock().unwrap().clone();
        for format in ["config.", "tree.", "generation.manifest", CONFIG_FILENAME] {
            assert!(
                bounds.iter().any(|(name, _)| name.starts_with(format)),
                "no {format} read in {bounds:?}"
            );
        }
        for (name, bound) in bounds {
            let expected = if name.starts_with("config.") || name.starts_with(CONFIG_FILENAME) {
                CONFIG_MAX_LEN
            } else if name.starts_with("tree.") {
                TREE_MAX_LEN
            } else if name == MANIFEST_FILENAME {
                MANIFEST_MAX_LEN
            } else {
                continue;
            };
            assert_eq!(bound, expected, "{name}");
        }
    }

    #[tokio::test]
    async fn oversized_vault_metadata_is_refused() {
        let (provider, manager) = metadata_bound_vault().await;
        for format in ["generation.manifest", "config.", "tree."] {
            *provider.oversized.lock().unwrap() = Some(format);
            match manager
                .open_vault("test", serde_json::Value::Null, b"password")
                .await
            {
                Err(Error::Crypto(message)) => {
                    assert!(message.contains("limit for vault metadata"), "{message}")
                }
                Err(error) => panic!("{format}: {error}"),
                Ok(_) => panic!("a vault with an oversized {format} was opened"),
            }
        }
        *provider.oversized.lock().unwrap() = None;
        manager
            .open_vault("test", serde_json::Value::Null, b"password")
            .await
            .unwrap();
    }
}
