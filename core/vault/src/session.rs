//! Vault session management.
//!
//! Sessions hold decrypted keys in memory and provide access to vault operations.
//! Keys are automatically zeroized when the session is dropped.

use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::config::{VaultConfig, CONFIG_FILENAME, DATA_DIRNAME, META_DIRNAME, TREE_FILENAME};
use crate::freshness::{
    publication_lock, AnchorKeys, FreshnessAnchor, FreshnessState as AnchorFreshnessState,
};
use crate::manifest::{digest, GenerationManifest, MANIFEST_FILENAME};
use crate::tree::VaultTree;
use axiomvault_common::{Error, Result, VaultId, VaultPath};
use axiomvault_crypto::recovery::RecoveryKey;
use axiomvault_crypto::{decrypt, encrypt, MasterKey};
use axiomvault_storage::StorageProvider;

/// Context tag for tree index key derivation. Changing this invalidates all existing vaults.
pub(crate) const TREE_KEY_CONTEXT: &[u8] = b"vault_tree_index_v1";

/// Session handle for tracking active sessions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionHandle(String);

impl SessionHandle {
    /// Generate a new unique session handle.
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Get the handle string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SessionHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// State of the vault session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is active and keys are available.
    Active,
    /// Session is locked, keys have been cleared.
    Locked,
}

/// Active vault session.
///
/// Holds the master key and provides access to vault operations.
/// The master key is zeroized when the session is dropped or locked.
pub struct VaultSession {
    /// Unique session identifier.
    handle: SessionHandle,
    /// Vault configuration.
    config: VaultConfig,
    committed_config: StdMutex<VaultConfig>,
    /// Master key (zeroized on drop).
    master_key: Option<MasterKey>,
    /// Replacement master key staged by a password change or reset. It
    /// becomes `master_key` only once the re-encrypted vault is committed.
    pending_master_key: Option<MasterKey>,
    /// Storage provider.
    provider: Arc<dyn StorageProvider>,
    /// Cached vault tree.
    tree: Arc<RwLock<VaultTree>>,
    /// Session state.
    state: SessionState,
    /// Monotonic snapshot state for manager-created sessions.
    freshness: Option<FreshnessState>,
}

struct FreshnessState {
    anchor: Arc<dyn FreshnessAnchor>,
    anchor_keys: AnchorKeys,
    generation: Mutex<u64>,
    /// `vault.config` bytes this session last wrote, so publishing an
    /// unchanged config does not rewrite and resync the cache every time.
    written_config: StdMutex<Option<Vec<u8>>>,
}

impl VaultSession {
    /// Create a new vault session from an already-derived master key.
    ///
    /// This is the preferred constructor for `open_vault` paths where the key has
    /// already been derived (verified against `key_verification`) so we avoid
    /// running the expensive Argon2id KDF a second time.
    ///
    /// # Errors
    /// - Incompatible vault version
    pub fn from_master_key(
        config: VaultConfig,
        master_key: MasterKey,
        provider: Arc<dyn StorageProvider>,
        tree: VaultTree,
    ) -> Result<Self> {
        Self::from_master_key_internal(config, master_key, provider, tree, None)
    }

    pub(crate) fn from_master_key_with_freshness(
        config: VaultConfig,
        master_key: MasterKey,
        provider: Arc<dyn StorageProvider>,
        tree: VaultTree,
        anchor: Arc<dyn FreshnessAnchor>,
        anchor_keys: AnchorKeys,
        generation: u64,
    ) -> Result<Self> {
        Self::from_master_key_internal(
            config,
            master_key,
            provider,
            tree,
            Some(FreshnessState {
                anchor,
                anchor_keys,
                generation: Mutex::new(generation),
                written_config: StdMutex::new(None),
            }),
        )
    }

    fn from_master_key_internal(
        config: VaultConfig,
        master_key: MasterKey,
        provider: Arc<dyn StorageProvider>,
        tree: VaultTree,
        freshness: Option<FreshnessState>,
    ) -> Result<Self> {
        if !config.version.is_compatible() {
            return Err(Error::Vault(format!(
                "Incompatible vault version: {:?}",
                config.version
            )));
        }

        Ok(Self {
            handle: SessionHandle::new(),
            committed_config: StdMutex::new(config.clone()),
            config,
            master_key: Some(master_key),
            pending_master_key: None,
            provider,
            tree: Arc::new(RwLock::new(tree)),
            state: SessionState::Active,
            freshness,
        })
    }

    /// Create a new vault session by unlocking with password.
    ///
    /// Derives the master key via Argon2id. Prefer `from_master_key` when the
    /// key has already been derived (e.g. in `open_vault`), to avoid a double KDF.
    pub fn unlock(
        config: VaultConfig,
        password: &[u8],
        provider: Arc<dyn StorageProvider>,
        tree: VaultTree,
    ) -> Result<Self> {
        let master_key = config
            .verify_password(password)?
            .ok_or_else(|| Error::NotPermitted("Invalid password".to_string()))?;

        Self::from_master_key(config, master_key, provider, tree)
    }

    /// Load and decrypt the vault tree index from storage.
    ///
    /// A missing tree index yields an empty tree only when the vault holds
    /// nothing else: no object under `d/` and none under `m/` (which includes
    /// the snapshot manifest and generation objects). Otherwise the index was
    /// lost or withheld, and opening it as empty would let the next save
    /// publish an empty tree over the real one, orphaning every object.
    pub async fn load_and_decrypt_tree(
        provider: &Arc<dyn StorageProvider>,
        master_key: &MasterKey,
    ) -> Result<VaultTree> {
        let tree_path = VaultPath::parse(META_DIRNAME)?.join(TREE_FILENAME)?;

        if !provider.exists(&tree_path).await? {
            for dirname in [DATA_DIRNAME, META_DIRNAME] {
                let dir = VaultPath::parse(dirname)?;
                if provider.exists(&dir).await? && !provider.list(&dir).await?.is_empty() {
                    return Err(Error::Vault(format!(
                        "tree index {META_DIRNAME}/{TREE_FILENAME} is missing but {dirname}/ is not empty; \
                         refusing to open the vault as empty"
                    )));
                }
            }
            return Ok(VaultTree::new());
        }

        let encrypted_bytes = provider.download(&tree_path).await?;

        Self::decrypt_tree_bytes(master_key, &encrypted_bytes)
    }

    pub(crate) fn decrypt_tree_bytes(
        master_key: &MasterKey,
        encrypted_bytes: &[u8],
    ) -> Result<VaultTree> {
        let tree_key = master_key.derive_file_key(TREE_KEY_CONTEXT);
        let tree_bytes = decrypt(tree_key.as_bytes(), encrypted_bytes).map_err(|e| {
            Error::Crypto(format!(
                "Failed to decrypt tree index (wrong password or corrupted vault): {}",
                e
            ))
        })?;

        let mut tree_json = String::from_utf8(tree_bytes).map_err(|e| {
            // Zeroize the bytes recovered from the conversion error.
            use zeroize::Zeroize;
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            Error::Serialization("Invalid UTF-8 in tree data".to_string())
        })?;

        let tree = VaultTree::from_json(&tree_json);

        // Zeroize the JSON string containing decrypted filenames/metadata.
        use zeroize::Zeroize;
        tree_json.zeroize();

        tree
    }

    /// Get the session handle.
    pub fn handle(&self) -> &SessionHandle {
        &self.handle
    }

    /// Get the vault ID.
    pub fn vault_id(&self) -> &VaultId {
        &self.config.id
    }

    /// Get the vault configuration.
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// Get mutable reference to the vault configuration.
    pub fn config_mut(&mut self) -> &mut VaultConfig {
        &mut self.config
    }

    pub(crate) fn restore_committed_config(&mut self) -> Result<()> {
        self.pending_master_key = None;
        self.config = self
            .committed_config
            .lock()
            .map_err(|_| Error::Vault("committed config lock poisoned".to_string()))?
            .clone();
        Ok(())
    }

    /// Get the storage provider.
    pub fn provider(&self) -> Arc<dyn StorageProvider> {
        self.provider.clone()
    }

    /// Get reference to the vault tree.
    pub fn tree(&self) -> &Arc<RwLock<VaultTree>> {
        &self.tree
    }

    /// Get the master key, if session is active.
    pub fn master_key(&self) -> Result<&MasterKey> {
        match self.state {
            SessionState::Active => self
                .master_key
                .as_ref()
                .ok_or_else(|| Error::Vault("Master key not available".to_string())),
            SessionState::Locked => Err(Error::NotPermitted("Session is locked".to_string())),
        }
    }

    /// Get the current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Check if session is active.
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }

    /// Lock the session, clearing all keys from memory.
    pub fn lock(&mut self) {
        if let Some(key) = self.master_key.take() {
            drop(key);
        }
        self.pending_master_key = None;
        self.state = SessionState::Locked;
    }

    /// Change the vault password.
    ///
    /// Stages a new master key wrapped under the new password and under the
    /// vault's existing recovery key, so the recovery words keep working. The
    /// change takes effect when it is saved (`VaultManager::save_config`),
    /// which re-encrypts every object under the new key and publishes it as
    /// a new generation; an old `vault.config` and the old password then
    /// decrypt nothing written after the change. Until then the session keeps
    /// the current key and refuses other mutations.
    ///
    /// # Errors
    /// - Session is locked
    /// - Old password is incorrect
    /// - New password is empty
    /// - A password change is already staged
    /// - The stored recovery key is missing or does not verify
    /// - Cryptographic operation fails
    /// - Self-verification of the new wrapping fails (should never happen;
    ///   indicates a serious bug)
    pub fn change_password(&mut self, old_password: &[u8], new_password: &[u8]) -> Result<()> {
        if self.state != SessionState::Active {
            return Err(Error::NotPermitted("Session is locked".to_string()));
        }

        if new_password.is_empty() {
            return Err(Error::InvalidInput(
                "New password cannot be empty".to_string(),
            ));
        }
        if self.pending_master_key.is_some() {
            return Err(Error::Conflict(
                "a password change is already staged; save or reopen first".to_string(),
            ));
        }

        let master_key = self.master_key()?.clone();

        // Verify the old password is correct before proceeding.
        self.config
            .verify_password(old_password)?
            .ok_or_else(|| Error::NotPermitted("Invalid old password".to_string()))?;

        // Keep the recovery words: wrap the new key under the same recovery key.
        let recovery_key = self.config.decrypt_recovery_key(&master_key)?;
        if self.config.verify_recovery_key(&recovery_key)?.is_none() {
            return Err(Error::Crypto(
                "stored recovery key does not match its verification data".to_string(),
            ));
        }

        let mut config = self.config.clone();
        let new_master_key = config.rotate_master_key(&recovery_key, new_password)?;
        self.config = config;
        self.pending_master_key = Some(new_master_key);
        Ok(())
    }

    /// Reset password using a recovery key.
    ///
    /// Stages a new master key exactly as [`VaultSession::change_password`]
    /// does; the reset takes effect when it is saved.
    pub fn reset_password_with_recovery(
        &mut self,
        recovery_key: &RecoveryKey,
        new_password: &[u8],
    ) -> Result<()> {
        if self.pending_master_key.is_some() {
            return Err(Error::Conflict(
                "a password change is already staged; save or reopen first".to_string(),
            ));
        }
        // Get the master key from recovery before resetting password.
        // This avoids a second Argon2id round after reset_password.
        let master_key = self
            .config
            .verify_recovery_key(recovery_key)?
            .ok_or_else(|| Error::NotPermitted("Invalid recovery key".to_string()))?;

        let mut config = self.config.clone();
        let new_master_key = config.reset_password(recovery_key, new_password)?;
        self.config = config;
        self.master_key = Some(master_key);
        self.pending_master_key = Some(new_master_key);
        self.state = SessionState::Active;

        Ok(())
    }

    /// Stage `new_master_key`, already wrapped by `config`, for the next save.
    pub(crate) fn stage_master_key_rotation(&mut self, new_master_key: MasterKey) {
        self.pending_master_key = Some(new_master_key);
    }

    /// Re-encrypt the vault under the staged master key and commit it.
    ///
    /// Every object is written under a new name, so the current generation
    /// stays intact until the manifest commit. After the commit the session
    /// switches to the new key, the old key is zeroized, and the objects of
    /// the old key are deleted on a best-effort basis. Returns how many old
    /// objects could not be deleted (a failed listing counts as one).
    pub(crate) async fn commit_master_key_rotation(&mut self) -> Result<usize> {
        let new_key = self
            .pending_master_key
            .clone()
            .ok_or_else(|| Error::Vault("no master key rotation is staged".to_string()))?;
        if self.freshness.is_none() {
            // Without a manifest there is no atomic commit point, and this path
            // never persists the config.
            return Err(Error::NotPermitted(
                "a password change must be published through a manager-opened session".to_string(),
            ));
        }
        let old_key = self.master_key()?.clone();
        let old_tree = self.tree.read().await.clone();

        let mut written = Vec::new();
        let rotated = match crate::operations::reencrypt_tree(
            &self.provider,
            &old_key,
            &new_key,
            &old_tree,
            &mut written,
        )
        .await
        {
            Ok(tree) => tree,
            Err(error) => {
                self.delete_best_effort(&written).await;
                return Err(error);
            }
        };

        if let Err(error) = self
            .save_tree_snapshot_internal(&rotated, true, Some(&new_key))
            .await
        {
            // The new objects are garbage only while the old generation is
            // still current; if the new manifest may have landed, keep them.
            if self.old_generation_is_current(&old_key).await {
                self.delete_best_effort(&written).await;
            }
            return Err(error);
        }

        // Committed: switch the session over and zeroize the old key.
        self.master_key = Some(new_key);
        self.pending_master_key = None;
        drop(old_key);
        *self.tree.write().await = rotated.clone();

        Ok(self.delete_superseded_objects(&rotated).await)
    }

    /// Whether storage still holds the generation sealed under `key` (or no
    /// manifest at all), so nothing published under a new key is current.
    async fn old_generation_is_current(&self, key: &MasterKey) -> bool {
        let Ok(path) = VaultPath::parse(META_DIRNAME).and_then(|m| m.join(MANIFEST_FILENAME))
        else {
            return false;
        };
        match self.provider.download(&path).await {
            Ok(bytes) => GenerationManifest::open(key, &bytes).is_ok(),
            Err(_) => !self.provider.exists(&path).await.unwrap_or(true),
        }
    }

    async fn delete_best_effort(&self, paths: &[VaultPath]) {
        for path in paths {
            if let Err(error) = self.provider.delete(path).await {
                tracing::warn!(%error, "could not delete an uncommitted re-encrypted object");
            }
        }
    }

    /// Delete every data object `tree` does not reference and every
    /// generation object except the current one. Returns the number left.
    async fn delete_superseded_objects(&self, tree: &VaultTree) -> usize {
        let mut remaining = 0;
        let keep_meta = match self.current_generation_objects().await {
            Ok(names) => Some(names),
            Err(error) => {
                tracing::warn!(%error, "could not read the committed manifest; old generation objects kept");
                remaining += 1;
                None
            }
        };
        let keep_data = crate::operations::file_object_names(tree);
        for dirname in [DATA_DIRNAME, META_DIRNAME] {
            let Ok(dir) = VaultPath::parse(dirname) else {
                remaining += 1;
                continue;
            };
            let entries = match self.provider.list(&dir).await {
                Ok(entries) => entries,
                Err(error) => {
                    tracing::warn!(%error, dirname, "could not list objects of the old master key");
                    remaining += 1;
                    continue;
                }
            };
            for entry in entries {
                let superseded = if dirname == DATA_DIRNAME {
                    !keep_data.contains(&entry.name)
                } else {
                    let generation_object = (entry.name.starts_with("tree.")
                        && entry.name.ends_with(".enc"))
                        || (entry.name.starts_with("config.") && entry.name.ends_with(".json"));
                    match &keep_meta {
                        Some(keep) => generation_object && !keep.contains(&entry.name),
                        None => false,
                    }
                };
                if !superseded {
                    continue;
                }
                let deleted = match dir.join(&entry.name) {
                    Ok(path) => self.provider.delete(&path).await.is_ok(),
                    Err(_) => false,
                };
                if !deleted {
                    remaining += 1;
                }
            }
        }
        if remaining > 0 {
            tracing::warn!(
                remaining,
                "password change committed, but objects of the old master key remain in storage"
            );
        }
        remaining
    }

    async fn current_generation_objects(&self) -> Result<Vec<String>> {
        let path = VaultPath::parse(META_DIRNAME)?.join(MANIFEST_FILENAME)?;
        let manifest =
            GenerationManifest::open(self.master_key()?, &self.provider.download(&path).await?)?;
        let (tree_object, config_object) = manifest.object_paths()?;
        Ok([tree_object, config_object]
            .iter()
            .filter_map(|path| path.name().map(str::to_string))
            .collect())
    }

    /// Persist a supplied tree snapshot to storage (encrypted).
    ///
    /// Callers can build and validate a candidate tree without exposing it
    /// in-memory, then publish it only after this write succeeds.
    pub(crate) async fn save_tree_snapshot(&self, tree: &VaultTree) -> Result<()> {
        self.save_tree_snapshot_internal(tree, false, None).await
    }

    /// Publish `tree` and the session config as the next generation.
    ///
    /// The stored generation is opened with the session's current key; the
    /// new one is encrypted and sealed under `rotate_to` when given.
    async fn save_tree_snapshot_internal(
        &self,
        tree: &VaultTree,
        allow_config_change: bool,
        rotate_to: Option<&MasterKey>,
    ) -> Result<()> {
        if !allow_config_change {
            let committed = self
                .committed_config
                .lock()
                .map_err(|_| Error::Vault("committed config lock poisoned".to_string()))?;
            if committed.to_bytes()? != self.config.to_bytes()? {
                return Err(Error::Conflict(
                    "vault config has uncommitted changes; save or reopen before mutating"
                        .to_string(),
                ));
            }
        }
        let publication = self
            .freshness
            .as_ref()
            .map(|freshness| publication_lock(freshness.anchor_keys.lock_id()))
            .transpose()?;
        let _publication_guard = match &publication {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let tree_json = tree.to_json()?;
        let sealing_key = match rotate_to {
            Some(key) => key,
            None => self.master_key()?,
        };

        let tree_key = sealing_key.derive_file_key(TREE_KEY_CONTEXT);
        let encrypted = encrypt(tree_key.as_bytes(), tree_json.as_bytes())
            .map_err(|e| Error::Crypto(format!("Failed to encrypt tree index: {}", e)))?;

        let tree_path = VaultPath::parse(META_DIRNAME)?.join(TREE_FILENAME)?;
        if self.freshness.is_none() {
            self.provider.upload(&tree_path, encrypted).await?;
            return Ok(());
        }

        let freshness = self.freshness.as_ref().expect("freshness checked above");
        let mut generation = freshness.generation.lock().await;
        let manifest_path = VaultPath::parse(META_DIRNAME)?.join(MANIFEST_FILENAME)?;
        let previous_manifest = if self.provider.exists(&manifest_path).await? {
            Some(self.provider.download(&manifest_path).await?)
        } else {
            None
        };

        let anchored = freshness
            .anchor_keys
            .load_state(freshness.anchor.as_ref())?;
        let previous = match (&anchored, &previous_manifest) {
            (None, None) if *generation == 0 => None,
            (Some(state), Some(bytes))
                if state.generation == *generation
                    && state
                        .manifest_digest
                        .as_ref()
                        .is_none_or(|expected| expected == &digest(bytes)) =>
            {
                let stored = GenerationManifest::open(self.master_key()?, bytes)?;
                if stored.generation != *generation {
                    return Err(Error::Conflict(
                        "stored snapshot advanced; reopen the vault before mutating it".to_string(),
                    ));
                }
                Some(stored)
            }
            _ => {
                return Err(Error::Conflict(
                    "trusted snapshot advanced; reopen the vault before mutating it".to_string(),
                ));
            }
        };

        let next_generation = generation
            .checked_add(1)
            .ok_or_else(|| Error::Vault("snapshot generation counter exhausted".to_string()))?;
        // Tagged under the key that seals this generation, so a rotation
        // re-tags the config under the new master key.
        let config_bytes = self.config.to_authenticated_bytes(sealing_key)?;
        let manifest = GenerationManifest::new(
            self.config.id.clone(),
            next_generation,
            &encrypted,
            &config_bytes,
            tree.object_digests(),
        );
        let (generation_tree_path, generation_config_path) = manifest.object_paths()?;
        let manifest_bytes = manifest.seal(sealing_key)?;
        let manifest_digest = digest(&manifest_bytes);
        let config_path = VaultPath::parse(CONFIG_FILENAME)?;

        // Both objects live in the manifest's directory: sync it once, after
        // both are in place and before the manifest that references them.
        self.provider
            .upload_unsynced(&generation_config_path, config_bytes.clone())
            .await?;
        self.provider
            .upload_unsynced(&generation_tree_path, encrypted.clone())
            .await?;
        self.provider.sync_parent_dir(&generation_tree_path).await?;

        if let Err(error) = self
            .provider
            .upload(&manifest_path, manifest_bytes.clone())
            .await
        {
            let visible = self
                .provider
                .download(&manifest_path)
                .await
                .is_ok_and(|bytes| bytes == manifest_bytes);
            if !visible {
                return Err(error);
            }
            self.provider
                .upload(&manifest_path, manifest_bytes.clone())
                .await
                .map_err(|retry| {
                    Error::Storage(format!(
                        "manifest upload failed ({error}); durability retry failed ({retry})"
                    ))
                })?;
        }

        let next_state = AnchorFreshnessState {
            generation: next_generation,
            manifest_digest: Some(manifest_digest),
        };
        if let Err(error) = freshness
            .anchor_keys
            .store_state(freshness.anchor.as_ref(), &next_state)
        {
            freshness
                .anchor_keys
                .store_state(freshness.anchor.as_ref(), &next_state)
                .map_err(|retry| {
                    Error::Storage(format!(
                        "freshness anchor update failed ({error}); durability retry failed ({retry})"
                    ))
                })?;
        }
        // Compatibility caches for health tooling and pre-manifest readers. They
        // are deliberately written after the manifest commit and never authoritative.
        // A crash can leave the tree cache stale and superseded generation
        // objects in place, as a crash right after the commit can, so their
        // directory is synced by the next publication instead of here.
        let config_written = freshness
            .written_config
            .lock()
            .is_ok_and(|written| written.as_deref() == Some(config_bytes.as_slice()));
        if !config_written
            && self
                .provider
                .upload(&config_path, config_bytes.clone())
                .await
                .is_ok()
        {
            if let Ok(mut written) = freshness.written_config.lock() {
                *written = Some(config_bytes);
            }
        }
        let _ = self.provider.upload_unsynced(&tree_path, encrypted).await;
        if let Some(previous) = previous {
            if previous.version == 2 {
                if let Ok((previous_tree_path, previous_config_path)) = previous.object_paths() {
                    if previous_tree_path != generation_tree_path {
                        let _ = self.provider.delete_unsynced(&previous_tree_path).await;
                    }
                    if previous_config_path != generation_config_path {
                        let _ = self.provider.delete_unsynced(&previous_config_path).await;
                    }
                }
            }
        }
        *self
            .committed_config
            .lock()
            .map_err(|_| Error::Vault("committed config lock poisoned".to_string()))? =
            self.config.clone();
        *generation = next_generation;
        Ok(())
    }

    /// Save the current tree state to storage (encrypted).
    pub async fn save_tree(&self) -> Result<()> {
        let tree = self.tree.read().await;
        self.save_tree_snapshot(&tree).await
    }

    /// Publish the session config. A staged password change or reset is
    /// committed as a master key rotation.
    pub(crate) async fn save_tree_with_config(&mut self) -> Result<()> {
        if self.pending_master_key.is_some() {
            self.commit_master_key_rotation().await?;
            return Ok(());
        }
        let tree = self.tree.read().await;
        self.save_tree_snapshot_internal(&tree, true, None).await
    }
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VaultConfigCreation;
    use axiomvault_storage::MemoryProvider;

    fn create_test_config() -> (VaultConfigCreation, Arc<MemoryProvider>) {
        let id = VaultId::new("test").unwrap();
        let password = b"test-password";
        let params = axiomvault_crypto::KdfParams::moderate();
        let creation =
            VaultConfig::new(id, password, "memory", serde_json::Value::Null, params).unwrap();
        let provider = Arc::new(MemoryProvider::new());
        (creation, provider)
    }

    fn create_test_session() -> (VaultSession, VaultConfig) {
        let (creation, provider) = create_test_config();
        let config = creation.config;
        let password = b"test-password";

        let session =
            VaultSession::unlock(config.clone(), password, provider, VaultTree::new()).unwrap();

        (session, config)
    }

    #[test]
    fn test_session_creation() {
        let (session, _) = create_test_session();
        assert!(session.is_active());
        assert!(session.master_key().is_ok());
    }

    #[test]
    fn test_session_lock() {
        let (mut session, _) = create_test_session();
        session.lock();

        assert!(!session.is_active());
        assert_eq!(session.state(), SessionState::Locked);
        assert!(session.master_key().is_err());
    }

    #[test]
    fn test_wrong_password_fails() {
        let id = VaultId::new("test").unwrap();
        let password = b"correct";
        let params = axiomvault_crypto::KdfParams::moderate();
        let creation =
            VaultConfig::new(id, password, "memory", serde_json::Value::Null, params).unwrap();

        let provider = Arc::new(MemoryProvider::new());
        let result = VaultSession::unlock(creation.config, b"wrong", provider, VaultTree::new());

        assert!(result.is_err());
    }

    #[test]
    fn test_change_password() {
        let (mut session, _) = create_test_session();
        let old_password = b"test-password";
        let new_password = b"new-password";

        session.change_password(old_password, new_password).unwrap();

        assert!(session
            .config()
            .verify_password(new_password)
            .unwrap()
            .is_some());
        assert!(session
            .config()
            .verify_password(old_password)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_change_password_empty_rejected() {
        let (mut session, _) = create_test_session();
        let result = session.change_password(b"test-password", b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_change_password_stages_a_new_master_key() {
        let (mut session, _) = create_test_session();
        let old_password = b"test-password";
        let new_password = b"new-password";

        // Capture master key bytes before password change.
        let mk_before = session.master_key().unwrap().as_bytes().to_owned();

        session.change_password(old_password, new_password).unwrap();

        // The session keeps the current key until the rotation is committed.
        let mk_after = session.master_key().unwrap().as_bytes().to_owned();
        assert_eq!(mk_before, mk_after, "master key changes only on commit");

        // The new password unwraps the staged key, not the current one.
        let mk_from_new = session
            .config()
            .verify_password(new_password)
            .unwrap()
            .expect("new password should verify");
        assert_ne!(mk_before, mk_from_new.as_bytes().to_owned());
        assert_eq!(
            session.pending_master_key.as_ref().unwrap().as_bytes(),
            mk_from_new.as_bytes()
        );
        assert!(session.change_password(new_password, b"third").is_err());
    }

    #[test]
    fn test_change_password_config_round_trip() {
        let (mut session, _) = create_test_session();
        let old_password = b"test-password";
        let new_password = b"new-password";

        session.change_password(old_password, new_password).unwrap();
        let staged = session
            .pending_master_key
            .as_ref()
            .unwrap()
            .as_bytes()
            .to_owned();

        // Serialize and deserialize the config (simulates save_config + reopen).
        let json = session.config().to_json().unwrap();
        let restored = VaultConfig::from_json(&json).unwrap();

        // The restored config must accept the new password and yield
        // the staged master key.
        let mk_restored = restored
            .verify_password(new_password)
            .unwrap()
            .expect("new password should work after config round-trip");
        assert_eq!(staged, mk_restored.as_bytes().to_owned());

        // The old password must be rejected.
        assert!(restored.verify_password(old_password).unwrap().is_none());
    }

    #[test]
    fn test_change_password_recovery_key_still_works() {
        let (creation, provider) = create_test_config();
        let config = creation.config;
        let recovery_words = creation.recovery_words;

        let mut session =
            VaultSession::unlock(config, b"test-password", provider, VaultTree::new()).unwrap();

        let mk_before = session.master_key().unwrap().as_bytes().to_owned();

        session
            .change_password(b"test-password", b"rotated")
            .unwrap();

        // The same recovery words unwrap the new master key, and the stored
        // recovery key is re-encrypted under it.
        let rk = axiomvault_crypto::recovery::RecoveryKey::from_mnemonic(&recovery_words).unwrap();
        let mk_from_recovery = session
            .config()
            .verify_recovery_key(&rk)
            .unwrap()
            .expect("recovery key should still work after password change");
        assert_ne!(mk_before, mk_from_recovery.as_bytes().to_owned());
        assert_eq!(
            session.pending_master_key.as_ref().unwrap().as_bytes(),
            mk_from_recovery.as_bytes()
        );
        assert_eq!(
            *session
                .config()
                .decrypt_recovery_key(&mk_from_recovery)
                .unwrap()
                .to_mnemonic()
                .unwrap(),
            *recovery_words
        );
    }

    #[tokio::test]
    async fn missing_tree_is_empty_only_when_the_vault_holds_nothing() {
        let (creation, provider) = create_test_config();
        let storage: Arc<dyn StorageProvider> = provider.clone();
        let key = creation.master_key;

        // No `d/` or `m/` at all, then both present but empty.
        assert_eq!(
            VaultSession::load_and_decrypt_tree(&storage, &key)
                .await
                .unwrap()
                .count_files(),
            0
        );
        for dir in [DATA_DIRNAME, META_DIRNAME] {
            provider
                .create_dir(&VaultPath::parse(dir).unwrap())
                .await
                .unwrap();
        }
        assert_eq!(
            VaultSession::load_and_decrypt_tree(&storage, &key)
                .await
                .unwrap()
                .count_files(),
            0
        );

        for (dir, object) in [
            (DATA_DIRNAME, "object"),
            (META_DIRNAME, "generation.manifest"),
        ] {
            let path = VaultPath::parse(dir).unwrap().join(object).unwrap();
            provider.upload(&path, b"x".to_vec()).await.unwrap();
            let error = VaultSession::load_and_decrypt_tree(&storage, &key)
                .await
                .expect_err("a missing tree beside stored objects must be refused");
            assert!(
                error
                    .to_string()
                    .contains(&format!("but {dir}/ is not empty")),
                "unexpected error: {error}"
            );
            provider.delete(&path).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_change_password_data_remains_decryptable_until_commit() {
        use crate::operations::VaultOperations;

        let (creation, provider) = create_test_config();
        let config = creation.config;

        // Initialize storage directories.
        provider
            .create_dir(&VaultPath::parse("/d").unwrap())
            .await
            .unwrap();
        provider
            .create_dir(&VaultPath::parse("/m").unwrap())
            .await
            .unwrap();

        let mut session =
            VaultSession::unlock(config, b"test-password", provider.clone(), VaultTree::new())
                .unwrap();

        let file_a = VaultPath::parse("/secret.txt").unwrap();
        let file_b = VaultPath::parse("/photo.bin").unwrap();
        let content_a = b"top-secret document content";
        let content_b: Vec<u8> = (0..=255).collect();

        // Write files before password change.
        {
            let ops = VaultOperations::new(&session).unwrap();
            ops.create_file(&file_a, content_a).await.unwrap();
            ops.create_file(&file_b, &content_b).await.unwrap();
        }

        // Rotate the password.
        session
            .change_password(b"test-password", b"rotated-pw")
            .unwrap();

        // All previously encrypted files must still be readable in the
        // same session (master key unchanged in memory).
        {
            let ops = VaultOperations::new(&session).unwrap();
            assert_eq!(ops.read_file(&file_a).await.unwrap(), content_a);
            assert_eq!(ops.read_file(&file_b).await.unwrap(), content_b);
        }

        // A session without a manifest has no atomic commit point, so it
        // refuses to publish the rotation and leaves storage untouched.
        let tree_path = VaultPath::parse("/m/tree.json").unwrap();
        let stored_tree = provider.download(&tree_path).await.unwrap();
        assert!(session.save_tree_with_config().await.is_err());
        assert_eq!(provider.download(&tree_path).await.unwrap(), stored_tree);
        let ops = VaultOperations::new(&session).unwrap();
        assert_eq!(ops.read_file(&file_a).await.unwrap(), content_a);
        assert_eq!(ops.read_file(&file_b).await.unwrap(), content_b);
    }
}
