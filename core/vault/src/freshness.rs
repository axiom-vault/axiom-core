//! Trusted local monotonic freshness anchors.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

use axiomvault_common::{Error, Result, VaultId};
use serde::{Deserialize, Serialize};

/// Trusted identity of the latest accepted authenticated manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessState {
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_digest: Option<String>,
}

/// Serialize snapshot publication for the same trusted anchor in this process.
pub(crate) fn publication_lock(vault_id: &VaultId) -> Result<Arc<tokio::sync::Mutex<()>>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| Error::Vault("snapshot publication lock poisoned".to_string()))?;
    if let Some(lock) = locks.get(vault_id.as_str()).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(vault_id.as_str().to_string(), Arc::downgrade(&lock));
    Ok(lock)
}

/// Trusted state kept outside the storage provider controlled by an attacker.
pub trait FreshnessAnchor: Send + Sync {
    /// Return the latest locally accepted generation, if this device has one.
    fn load(&self, vault_id: &VaultId) -> Result<Option<u64>>;

    /// Advance the anchor. Implementations must reject decreasing generations.
    fn store(&self, vault_id: &VaultId, generation: u64) -> Result<()>;

    /// Load generation plus accepted manifest identity. The default reads a
    /// legacy generation-only anchor so old implementations remain source
    /// compatible; authenticated snapshots then fail closed on storing an
    /// identity unless the implementation overrides `store_state`.
    fn load_state(&self, vault_id: &VaultId) -> Result<Option<FreshnessState>> {
        Ok(self.load(vault_id)?.map(|generation| FreshnessState {
            generation,
            manifest_digest: None,
        }))
    }

    /// Atomically advance the accepted generation and manifest identity.
    fn store_state(&self, vault_id: &VaultId, state: FreshnessState) -> Result<()> {
        if state.manifest_digest.is_some() {
            return Err(Error::Vault(
                "freshness anchor does not support manifest identity".to_string(),
            ));
        }
        self.store(vault_id, state.generation)
    }
}

/// Anchor used when the platform cannot provide trusted local storage.
/// Every operation fails closed rather than silently disabling protection.
pub struct UnavailableFreshnessAnchor {
    reason: String,
}

impl UnavailableFreshnessAnchor {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl FreshnessAnchor for UnavailableFreshnessAnchor {
    fn load(&self, _vault_id: &VaultId) -> Result<Option<u64>> {
        Err(Error::Vault(format!(
            "freshness anchor unavailable: {}",
            self.reason
        )))
    }

    fn store(&self, _vault_id: &VaultId, _generation: u64) -> Result<()> {
        Err(Error::Vault(format!(
            "freshness anchor unavailable: {}",
            self.reason
        )))
    }
}

/// Process-local anchor useful for tests and explicitly ephemeral clients.
#[derive(Default)]
pub struct InMemoryFreshnessAnchor {
    generations: RwLock<HashMap<String, FreshnessState>>,
}

impl InMemoryFreshnessAnchor {
    pub fn new() -> Self {
        Self::default()
    }
}

impl FreshnessAnchor for InMemoryFreshnessAnchor {
    fn load(&self, vault_id: &VaultId) -> Result<Option<u64>> {
        let generations = self
            .generations
            .read()
            .map_err(|_| Error::Vault("freshness anchor lock poisoned".to_string()))?;
        Ok(generations
            .get(vault_id.as_str())
            .map(|state| state.generation))
    }

    fn store(&self, vault_id: &VaultId, generation: u64) -> Result<()> {
        let mut generations = self
            .generations
            .write()
            .map_err(|_| Error::Vault("freshness anchor lock poisoned".to_string()))?;
        Self::store_locked(
            &mut generations,
            vault_id,
            FreshnessState {
                generation,
                manifest_digest: None,
            },
        )
    }

    fn load_state(&self, vault_id: &VaultId) -> Result<Option<FreshnessState>> {
        let generations = self
            .generations
            .read()
            .map_err(|_| Error::Vault("freshness anchor lock poisoned".to_string()))?;
        Ok(generations.get(vault_id.as_str()).cloned())
    }

    fn store_state(&self, vault_id: &VaultId, state: FreshnessState) -> Result<()> {
        let mut generations = self
            .generations
            .write()
            .map_err(|_| Error::Vault("freshness anchor lock poisoned".to_string()))?;
        Self::store_locked(&mut generations, vault_id, state)
    }
}

impl InMemoryFreshnessAnchor {
    fn store_locked(
        generations: &mut HashMap<String, FreshnessState>,
        vault_id: &VaultId,
        state: FreshnessState,
    ) -> Result<()> {
        if let Some(current) = generations.get(vault_id.as_str()) {
            if state.generation < current.generation {
                return Err(Error::Conflict(
                    "refusing to decrease freshness anchor".to_string(),
                ));
            }
            if state.generation == current.generation {
                if let (Some(current), Some(incoming)) =
                    (&current.manifest_digest, &state.manifest_digest)
                {
                    if current != incoming {
                        return Err(Error::Conflict(
                            "same-generation manifest fork detected".to_string(),
                        ));
                    }
                }
                if current.manifest_digest.is_some() && state.manifest_digest.is_none() {
                    return Ok(());
                }
            }
        }
        generations.insert(vault_id.as_str().to_string(), state);
        Ok(())
    }
}

/// File-backed anchor stored outside the vault's storage provider.
pub struct LocalFileFreshnessAnchor {
    directory: PathBuf,
    lock: RwLock<()>,
}

impl LocalFileFreshnessAnchor {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            lock: RwLock::new(()),
        }
    }

    pub fn platform_default() -> Result<Self> {
        let base = dirs::data_local_dir().ok_or_else(|| {
            Error::Vault("local data directory unavailable for freshness anchor".to_string())
        })?;
        Ok(Self::new(base.join("axiomvault").join("freshness")))
    }

    fn path(&self, vault_id: &VaultId) -> PathBuf {
        self.directory
            .join(format!("{}.generation", vault_id.as_str()))
    }

    fn read_state(path: &Path) -> Result<Option<FreshnessState>> {
        match fs::read_to_string(path) {
            Ok(value) => {
                let value = value.trim();
                if let Ok(generation) = value.parse::<u64>() {
                    return Ok(Some(FreshnessState {
                        generation,
                        manifest_digest: None,
                    }));
                }
                serde_json::from_str(value).map(Some).map_err(|_| {
                    Error::Vault("freshness anchor is corrupt; refusing to open vault".to_string())
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(Error::Vault(format!(
                "failed to read freshness anchor: {error}"
            ))),
        }
    }
    fn write_state(&self, vault_id: &VaultId, state: FreshnessState) -> Result<()> {
        fs::create_dir_all(&self.directory).map_err(|error| {
            Error::Vault(format!(
                "failed to create freshness anchor directory: {error}"
            ))
        })?;
        let path = self.path(vault_id);
        if let Some(current) = Self::read_state(&path)? {
            if state.generation < current.generation {
                return Err(Error::Conflict(
                    "refusing to decrease freshness anchor".to_string(),
                ));
            }
            if state.generation == current.generation
                && current.manifest_digest.is_some()
                && state.manifest_digest.is_some()
                && current.manifest_digest != state.manifest_digest
            {
                return Err(Error::Conflict(
                    "same-generation manifest fork detected".to_string(),
                ));
            }
            if state.generation == current.generation
                && current.manifest_digest.is_some()
                && state.manifest_digest.is_none()
            {
                return Ok(());
            }
        }

        let temporary = path.with_extension("generation.tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| Error::Vault(format!("failed to write freshness anchor: {error}")))?;
        serde_json::to_writer(&mut file, &state)
            .map_err(|error| Error::Vault(format!("failed to write freshness anchor: {error}")))?;
        writeln!(file)
            .map_err(|error| Error::Vault(format!("failed to write freshness anchor: {error}")))?;
        file.sync_all()
            .map_err(|error| Error::Vault(format!("failed to sync freshness anchor: {error}")))?;
        fs::rename(&temporary, &path).map_err(|error| {
            Error::Vault(format!("failed to replace freshness anchor: {error}"))
        })?;
        Ok(())
    }
}

impl FreshnessAnchor for LocalFileFreshnessAnchor {
    fn load(&self, vault_id: &VaultId) -> Result<Option<u64>> {
        Ok(self.load_state(vault_id)?.map(|state| state.generation))
    }

    fn store(&self, vault_id: &VaultId, generation: u64) -> Result<()> {
        self.store_state(
            vault_id,
            FreshnessState {
                generation,
                manifest_digest: None,
            },
        )
    }

    fn load_state(&self, vault_id: &VaultId) -> Result<Option<FreshnessState>> {
        let _guard = self
            .lock
            .read()
            .map_err(|_| Error::Vault("freshness anchor lock poisoned".to_string()))?;
        Self::read_state(&self.path(vault_id))
    }

    fn store_state(&self, vault_id: &VaultId, state: FreshnessState) -> Result<()> {
        let _guard = self
            .lock
            .write()
            .map_err(|_| Error::Vault("freshness anchor lock poisoned".to_string()))?;
        self.write_state(vault_id, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_anchor_persists_and_never_decreases() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = VaultId::new("anchor-test").unwrap();
        let anchor = LocalFileFreshnessAnchor::new(directory.path());

        assert_eq!(anchor.load(&vault_id).unwrap(), None);
        anchor.store(&vault_id, 4).unwrap();
        assert_eq!(anchor.load(&vault_id).unwrap(), Some(4));
        assert!(anchor.store(&vault_id, 3).is_err());
        assert_eq!(anchor.load(&vault_id).unwrap(), Some(4));
    }

    #[test]
    fn corrupt_local_anchor_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = VaultId::new("corrupt-anchor").unwrap();
        let anchor = LocalFileFreshnessAnchor::new(directory.path());
        fs::create_dir_all(directory.path()).unwrap();
        fs::write(anchor.path(&vault_id), b"not-a-generation").unwrap();

        assert!(anchor.load(&vault_id).is_err());
    }
}
