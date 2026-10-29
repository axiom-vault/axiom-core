//! Vault configuration and metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use subtle::ConstantTimeEq;

use axiomvault_common::{Error, Result, VaultId};
use axiomvault_crypto::recovery::{
    self, create_recovery_verification, generate_master_key, unwrap_key, wrap_key, RecoveryKey,
};
use axiomvault_crypto::recovery::{create_hardware_key_verification, derive_hardware_key_kek};
use axiomvault_crypto::{KdfParams, MasterKey, Salt};
use zeroize::Zeroizing;

fn contains_oauth_credentials(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(entries) => entries.iter().any(|(key, value)| {
            let normalized = key.to_ascii_lowercase().replace('-', "_");
            matches!(
                normalized.as_str(),
                "tokens"
                    | "auth_config"
                    | "access_token"
                    | "refresh_token"
                    | "client_secret"
                    | "authorization_code"
                    | "code_verifier"
            ) || contains_oauth_credentials(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(contains_oauth_credentials),
        _ => false,
    }
}

fn serialize_provider_config<S>(
    value: &serde_json::Value,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if contains_oauth_credentials(value) {
        return Err(serde::ser::Error::custom(
            "OAuth credentials are forbidden in serialized vault configuration",
        ));
    }
    value.serialize(serializer)
}

/// Vault format version for migration support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VaultVersion {
    pub major: u32,
    pub minor: u32,
}

impl VaultVersion {
    /// Current vault format version.
    /// Bumped to 1.1 to indicate recovery key / key-wrapping support.
    /// Bumped to 2.0 for manifest-based generations: `vault.config` and
    /// `m/tree.json` became non-authoritative caches, so 1.x clients (whose
    /// only gate is the major version) must refuse these vaults.
    pub const CURRENT: Self = Self { major: 2, minor: 0 };

    /// Key-wrapping and recovery format; the last version that registry
    /// migrations write. A 1.1 vault is upgraded to `CURRENT` on open.
    pub const V1_1: Self = Self { major: 1, minor: 1 };

    /// Check if this version is compatible with the current version.
    pub fn is_compatible(&self) -> bool {
        self.major == Self::CURRENT.major
    }
}

impl std::fmt::Display for VaultVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl Default for VaultVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareKeyKind {
    YubiKeyHmacSha1,
    FidoDerivedSecret,
    RawSecret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareKeyMetadata {
    pub kind: HardwareKeyKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub enrolled_at: DateTime<Utc>,
}

impl HardwareKeyMetadata {
    pub fn new(kind: HardwareKeyKind, label: Option<String>, key_id: Option<String>) -> Self {
        Self {
            kind,
            label,
            key_id,
            enrolled_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareKeyConfig {
    pub metadata: HardwareKeyMetadata,
    pub wrapped_master_key: Vec<u8>,
    pub key_verification: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareKeyStatus {
    pub enrolled: bool,
    pub metadata: Option<HardwareKeyMetadata>,
}

impl HardwareKeyStatus {
    pub fn is_enrolled(&self) -> bool {
        self.enrolled
    }
}

/// Encrypted vault configuration.
///
/// This structure is stored at the vault root and contains all
/// necessary metadata for vault operations.
///
/// ## Key hierarchy (v1.1+)
///
/// A random **master key** is generated at vault creation. It is encrypted
/// ("wrapped") under two independent key-encryption keys (KEKs):
///
/// 1. `wrapped_master_key` -- wrapped with a KEK derived from the user
///    password via Argon2id.
/// 2. `recovery_wrapped_master_key` -- wrapped with a KEK derived from a
///    256-bit recovery key via Blake2b.
///
/// The `key_verification` field lets us cheaply verify the password
/// without unwrapping the master key (AEAD decryption of a known
/// constant).
///
/// ## Legacy format (v1.0)
///
/// In the original format the Argon2id output *was* the master key
/// directly -- there was no wrapping step. Old vaults are detected by
/// the absence of `wrapped_master_key` and can be migrated in-place.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Unique vault identifier.
    pub id: VaultId,
    /// Vault format version.
    pub version: VaultVersion,
    /// Salt for password-based key derivation (Argon2id).
    pub salt: Salt,
    /// KDF parameters.
    pub kdf_params: KdfParams,
    /// Storage provider type (e.g., "local", "gdrive").
    pub provider_type: String,
    /// Provider-specific configuration.
    #[serde(serialize_with = "serialize_provider_config")]
    pub provider_config: serde_json::Value,
    /// Vault creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp.
    pub modified_at: DateTime<Utc>,
    /// Encrypted master key verification data.
    /// This is used to verify the password without storing the key.
    pub key_verification: Vec<u8>,

    // -- v1.1 fields (key wrapping + recovery) ---------------------------
    /// Master key encrypted (wrapped) with the password-derived KEK.
    /// `None` for legacy v1.0 vaults that have not been migrated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_master_key: Option<Vec<u8>>,

    /// Master key encrypted (wrapped) with the recovery-key-derived KEK.
    /// `None` if no recovery key has been set up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_master_key: Option<Vec<u8>>,

    /// Verification data for the recovery key (encrypted known constant).
    /// Allows checking whether user-supplied recovery words are correct
    /// without unwrapping the master key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key_verification: Option<Vec<u8>>,

    /// Recovery key encrypted with the master key so the user can
    /// re-display it later (requires unlocking with password first).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_recovery_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_key: Option<HardwareKeyConfig>,

    // -- 2.0 field (config integrity, M-1) ------------------------------
    /// Keyed BLAKE2b tag over every other field, under a key derived from
    /// the master key. Set only on the bytes written to storage
    /// ([`VaultConfig::to_authenticated_bytes`]) and removed on load by
    /// [`VaultConfig::verify_integrity`], so an in-memory config never
    /// carries a tag that its edits would make stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_mac: Option<Vec<u8>>,
}

/// Domain separation for the `config_mac` key.
const CONFIG_MAC_CONTEXT: &[u8] = b"vault_config_mac_v1";

/// Result of creating a new vault configuration.
pub struct VaultConfigCreation {
    /// The vault configuration to persist.
    pub config: VaultConfig,
    /// The master key, passed through to avoid a second Argon2id round on vault creation.
    pub master_key: MasterKey,
    /// The recovery key mnemonic (24 BIP39 words). Show to user once.
    pub recovery_words: Zeroizing<String>,
}

impl VaultConfig {
    /// Create a new vault configuration with key wrapping and recovery key.
    ///
    /// # Preconditions
    /// - `password` must not be empty
    ///
    /// # Returns
    /// A `VaultConfigCreation` containing the config and the recovery words
    /// that must be shown to the user exactly once.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        id: VaultId,
        password: &[u8],
        provider_type: impl Into<String>,
        provider_config: serde_json::Value,
        kdf_params: KdfParams,
    ) -> Result<VaultConfigCreation> {
        use axiomvault_crypto::{derive_key, encrypt};

        let salt = Salt::generate();

        // 1. Generate a random master key.
        let master_key = generate_master_key();

        // 2. Derive password KEK and wrap the master key.
        let password_kek = derive_key(password, &salt, &kdf_params)?;
        let wrapped_master_key = wrap_key(&master_key, password_kek.as_bytes())?;

        // 3. Create password verification data.
        let verification_plaintext = b"AXIOMVAULT_KEY_VERIFICATION_V1";
        let key_verification = encrypt(password_kek.as_bytes(), verification_plaintext)?;

        // 4. Generate recovery key and wrap the master key with it.
        let recovery_key = RecoveryKey::generate();
        let recovery_kek = recovery_key.derive_kek();
        let recovery_wrapped_master_key = wrap_key(&master_key, &recovery_kek)?;
        let recovery_key_verification = create_recovery_verification(&recovery_key)?;

        // 5. Encrypt the recovery key with the master key so it can be
        //    re-displayed later when the vault is unlocked.
        let encrypted_recovery_key = encrypt(master_key.as_bytes(), recovery_key.as_bytes())?;

        let recovery_words = recovery_key.to_mnemonic()?;

        let now = Utc::now();

        let config = VaultConfig {
            id,
            version: VaultVersion::CURRENT,
            salt,
            kdf_params,
            provider_type: provider_type.into(),
            provider_config,
            created_at: now,
            modified_at: now,
            key_verification,
            wrapped_master_key: Some(wrapped_master_key),
            recovery_wrapped_master_key: Some(recovery_wrapped_master_key),
            recovery_key_verification: Some(recovery_key_verification),
            encrypted_recovery_key: Some(encrypted_recovery_key),
            hardware_key: None,
            config_mac: None,
        };

        Ok(VaultConfigCreation {
            config,
            master_key,
            recovery_words,
        })
    }

    /// Check whether this config uses the legacy (v1.0) key model where the
    /// Argon2id output *is* the master key, rather than the wrapped model.
    pub fn is_legacy_format(&self) -> bool {
        self.wrapped_master_key.is_none()
    }

    /// Verify a password against this configuration.
    ///
    /// Returns the **master key** on success so the caller does not need
    /// to derive it a second time (avoids double-KDF cost on unlock).
    ///
    /// For v1.1+ vaults the password-derived KEK unwraps the stored
    /// `wrapped_master_key`. For legacy v1.0 vaults the Argon2id output
    /// is used directly as the master key.
    ///
    /// # Returns
    /// - `Ok(Some(key))` if password is correct
    /// - `Ok(None)` if password is incorrect
    /// - `Err(_)` if verification failed for other reasons
    pub fn verify_password(&self, password: &[u8]) -> Result<Option<MasterKey>> {
        use axiomvault_crypto::{decrypt, derive_key};
        use zeroize::Zeroize;

        let password_kek = derive_key(password, &self.salt, &self.kdf_params)?;

        // First, verify the password by decrypting the verification constant.
        match decrypt(password_kek.as_bytes(), &self.key_verification) {
            Ok(mut plaintext) => {
                let expected = b"AXIOMVAULT_KEY_VERIFICATION_V1";
                let valid = plaintext.len() == expected.len()
                    && bool::from(plaintext.as_slice().ct_eq(expected));
                plaintext.zeroize();
                if !valid {
                    return Ok(None);
                }
            }
            Err(_) => return Ok(None),
        }

        // Password is correct. Now obtain the master key.
        if let Some(ref wrapped) = self.wrapped_master_key {
            // v1.1+: unwrap the master key.
            let master_key = unwrap_key(wrapped, password_kek.as_bytes())?;
            Ok(Some(master_key))
        } else {
            // Legacy v1.0: the KEK *is* the master key.
            Ok(Some(password_kek))
        }
    }

    /// Verify a recovery key and return the master key on success.
    ///
    /// # Returns
    /// - `Ok(Some(key))` if recovery key is correct
    /// - `Ok(None)` if recovery key is incorrect
    /// - `Err(_)` on internal error
    pub fn verify_recovery_key(&self, recovery_key: &RecoveryKey) -> Result<Option<MasterKey>> {
        let verification = self
            .recovery_key_verification
            .as_ref()
            .ok_or_else(|| Error::Vault("No recovery key configured for this vault".to_string()))?;

        if !recovery::verify_recovery_key(recovery_key, verification)? {
            return Ok(None);
        }

        let wrapped = self.recovery_wrapped_master_key.as_ref().ok_or_else(|| {
            Error::Vault("Recovery-wrapped master key missing from config".to_string())
        })?;

        let recovery_kek = recovery_key.derive_kek();
        let master_key = unwrap_key(wrapped, &recovery_kek)?;
        Ok(Some(master_key))
    }

    pub fn verify_hardware_key(&self, secret: &[u8]) -> Result<Option<MasterKey>> {
        let hardware_key = self
            .hardware_key
            .as_ref()
            .ok_or_else(|| Error::Vault("No hardware key configured for this vault".to_string()))?;

        if !recovery::verify_hardware_key(secret, &hardware_key.key_verification)? {
            return Ok(None);
        }

        let hardware_kek = derive_hardware_key_kek(secret)?;
        let master_key = unwrap_key(&hardware_key.wrapped_master_key, &hardware_kek)?;
        Ok(Some(master_key))
    }

    pub fn enroll_hardware_key(
        &mut self,
        master_key: &MasterKey,
        secret: &[u8],
        metadata: HardwareKeyMetadata,
    ) -> Result<()> {
        let hardware_kek = derive_hardware_key_kek(secret)?;
        let wrapped_master_key = wrap_key(master_key, &hardware_kek)?;
        let key_verification = create_hardware_key_verification(secret)?;

        self.hardware_key = Some(HardwareKeyConfig {
            metadata,
            wrapped_master_key,
            key_verification,
        });
        self.modified_at = Utc::now();
        Ok(())
    }

    pub fn remove_hardware_key(&mut self) {
        self.hardware_key = None;
        self.modified_at = Utc::now();
    }

    pub fn hardware_key_status(&self) -> HardwareKeyStatus {
        HardwareKeyStatus {
            enrolled: self.hardware_key.is_some(),
            metadata: self
                .hardware_key
                .as_ref()
                .map(|config| config.metadata.clone()),
        }
    }

    /// Reset the password using a recovery key.
    ///
    /// Generates a new master key, wraps it under the new password and under
    /// the same recovery key (so the existing recovery words keep working),
    /// and returns it. Nothing in storage is encrypted under the returned key
    /// yet: persisting this config alone strands the vault, so the vault must
    /// be re-encrypted and published under it first (`recover_vault` does).
    pub fn reset_password(
        &mut self,
        recovery_key: &RecoveryKey,
        new_password: &[u8],
    ) -> Result<MasterKey> {
        if new_password.is_empty() {
            return Err(Error::InvalidInput(
                "New password cannot be empty".to_string(),
            ));
        }

        // Verify the recovery key before touching any field.
        self.verify_recovery_key(recovery_key)?
            .ok_or_else(|| Error::NotPermitted("Invalid recovery key".to_string()))?;

        self.rotate_master_key(recovery_key, new_password)
    }

    /// Replace the master key with a fresh one wrapped under `new_password`
    /// and under `recovery_key`, the vault's existing recovery key.
    ///
    /// The stored recovery key is re-encrypted under the new master key. A
    /// hardware-key wrap holds the old master key and cannot be re-wrapped
    /// without the hardware secret, so the enrollment is removed.
    pub(crate) fn rotate_master_key(
        &mut self,
        recovery_key: &RecoveryKey,
        new_password: &[u8],
    ) -> Result<MasterKey> {
        use axiomvault_crypto::{derive_key, encrypt};

        if new_password.is_empty() {
            return Err(Error::InvalidInput(
                "New password cannot be empty".to_string(),
            ));
        }
        // Every rewrap (password change and both recovery paths) comes through
        // here, under parameters read from storage.
        self.kdf_params.validate_minimum()?;

        let master_key = generate_master_key();
        let new_salt = Salt::generate();
        let new_kek = derive_key(new_password, &new_salt, &self.kdf_params)?;
        let new_wrapped = wrap_key(&master_key, new_kek.as_bytes())?;
        let recovery_kek = recovery_key.derive_kek();
        let recovery_wrapped = wrap_key(&master_key, &recovery_kek)?;

        // Self-verify both wraps before anything can be persisted.
        if unwrap_key(&new_wrapped, new_kek.as_bytes())?.as_bytes() != master_key.as_bytes()
            || unwrap_key(&recovery_wrapped, &recovery_kek)?.as_bytes() != master_key.as_bytes()
        {
            return Err(Error::Crypto(
                "master key verification failed after wrapping; aborting rotation".to_string(),
            ));
        }

        let verification_plaintext = b"AXIOMVAULT_KEY_VERIFICATION_V1";
        self.key_verification = encrypt(new_kek.as_bytes(), verification_plaintext)?;
        self.salt = new_salt;
        self.wrapped_master_key = Some(new_wrapped);
        self.recovery_wrapped_master_key = Some(recovery_wrapped);
        self.encrypted_recovery_key =
            Some(encrypt(master_key.as_bytes(), recovery_key.as_bytes())?);
        self.hardware_key = None;
        self.modified_at = Utc::now();

        Ok(master_key)
    }

    /// Retrieve the stored recovery key by decrypting with the master key.
    ///
    /// Requires the vault to be unlocked (master key available).
    pub fn decrypt_recovery_key(&self, master_key: &MasterKey) -> Result<RecoveryKey> {
        use axiomvault_crypto::decrypt;

        let encrypted = self.encrypted_recovery_key.as_ref().ok_or_else(|| {
            Error::Vault("No encrypted recovery key stored in this vault".to_string())
        })?;

        use zeroize::{Zeroize, Zeroizing};

        let mut plaintext = decrypt(master_key.as_bytes(), encrypted)?;
        if plaintext.len() != 32 {
            return Err(Error::Crypto(format!(
                "Decrypted recovery key has wrong length: expected 32, got {}",
                plaintext.len()
            )));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&plaintext);

        // Best-effort: wipe plaintext buffer containing key material.
        plaintext.zeroize();

        Ok(RecoveryKey::from_bytes(*bytes))
    }

    /// Check that `encrypted_recovery_key` holds `recovery_key` under `master_key`.
    ///
    /// The 1.1 layout keeps the recovery key in three fields:
    /// `recovery_key_verification` and `recovery_wrapped_master_key`, which
    /// [`VaultConfig::verify_recovery_key`] checks, and `encrypted_recovery_key`,
    /// which this checks against the master key that wrap yields.
    pub(crate) fn verify_recovery_key_binding(
        &self,
        recovery_key: &RecoveryKey,
        master_key: &MasterKey,
    ) -> Result<()> {
        let stored = self.decrypt_recovery_key(master_key)?;
        if !bool::from(stored.as_bytes().ct_eq(recovery_key.as_bytes())) {
            return Err(Error::Crypto(
                "stored recovery key does not match the recovery words".to_string(),
            ));
        }
        Ok(())
    }

    /// Migrate a legacy v1.0 vault to the v1.1 key-wrapping format.
    ///
    /// For legacy vaults, the Argon2id output was the master key. We keep
    /// that as the master key and simply wrap it under both the password
    /// KEK and a new recovery KEK.
    ///
    /// The password proves only the derived key, not that it is the master
    /// key: a newer config stripped of `wrapped_master_key` looks legacy too.
    /// This touches no storage, so callers must first prove the key against an
    /// object encrypted under the master key, as `MigrationRegistry::migrate`
    /// does, before persisting the result.
    ///
    /// # Returns
    /// The recovery words to show to the user.
    pub fn migrate_to_v1_1(&mut self, password: &[u8]) -> Result<Zeroizing<String>> {
        use axiomvault_crypto::encrypt;

        if !self.is_legacy_format() {
            return Err(Error::Vault("Vault is already in v1.1 format".to_string()));
        }
        // A real 1.0 config has no recovery material; its presence means the
        // wrapped key was stripped from a newer config.
        if self.recovery_wrapped_master_key.is_some()
            || self.recovery_key_verification.is_some()
            || self.encrypted_recovery_key.is_some()
        {
            return Err(Error::Vault(
                "legacy migration refused: config has recovery fields of a newer format but no wrapped master key"
                    .to_string(),
            ));
        }

        // In legacy mode, verify_password returns the Argon2id output which
        // serves as BOTH the master key and the password KEK. Reuse it to
        // avoid a second KDF round.
        let master_key = self
            .verify_password(password)?
            .ok_or_else(|| Error::NotPermitted("Invalid password".to_string()))?;

        // In legacy format, KEK == master key, so wrap with itself.
        let wrapped_master_key = wrap_key(&master_key, master_key.as_bytes())?;

        let recovery_key = RecoveryKey::generate();
        let recovery_kek = recovery_key.derive_kek();
        let recovery_wrapped = wrap_key(&master_key, &recovery_kek)?;
        let recovery_verification = create_recovery_verification(&recovery_key)?;
        let encrypted_recovery_key = encrypt(master_key.as_bytes(), recovery_key.as_bytes())?;
        let recovery_words = recovery_key.to_mnemonic()?;

        self.version = VaultVersion::V1_1;
        self.wrapped_master_key = Some(wrapped_master_key);
        self.recovery_wrapped_master_key = Some(recovery_wrapped);
        self.recovery_key_verification = Some(recovery_verification);
        self.encrypted_recovery_key = Some(encrypted_recovery_key);
        self.hardware_key = None;
        self.modified_at = Utc::now();

        Ok(recovery_words)
    }

    /// Serialize configuration to JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Deserialize configuration from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        let config: Self =
            serde_json::from_str(json).map_err(|e| Error::Serialization(e.to_string()))?;
        config.kdf_params.validate()?;
        Ok(config)
    }

    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| Error::Serialization(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let config: Self =
            serde_json::from_slice(bytes).map_err(|e| Error::Serialization(e.to_string()))?;
        config.kdf_params.validate()?;
        Ok(config)
    }

    /// `config_mac` over this config with the tag itself left out.
    fn compute_mac(&self, master_key: &MasterKey) -> Result<Vec<u8>> {
        use blake2::digest::consts::U32;
        use blake2::digest::Mac;

        let mut untagged = self.clone();
        untagged.config_mac = None;
        let key = master_key.derive_file_key(CONFIG_MAC_CONTEXT);
        let mut mac = <blake2::Blake2bMac<U32> as Mac>::new_from_slice(key.as_bytes())
            .map_err(|e| Error::Crypto(format!("config MAC key rejected: {e}")))?;
        mac.update(&untagged.to_bytes()?);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Serialize for storage with a `config_mac` under `master_key`, the key
    /// the generation that publishes these bytes is sealed with.
    pub(crate) fn to_authenticated_bytes(&self, master_key: &MasterKey) -> Result<Vec<u8>> {
        let mut tagged = self.clone();
        tagged.config_mac = Some(self.compute_mac(master_key)?);
        tagged.to_bytes()
    }

    /// Check `config_mac` against `master_key` and remove it.
    ///
    /// The tag is keyed by the master key, so this runs after unlock and before
    /// anything is written or rewrapped. A `CURRENT` config must carry a tag.
    /// Nothing tells an untagged 1.1 config from a 2.0 config stripped and
    /// relabelled, so it is accepted only where `bound_by_manifest`: a sealed
    /// manifest binds these bytes. Every 1.1 config this code writes (the
    /// registry's 1.0 -> 1.1 step) is tagged. Any tag present must verify.
    pub(crate) fn verify_integrity(
        &mut self,
        master_key: &MasterKey,
        bound_by_manifest: bool,
    ) -> Result<()> {
        let Some(tag) = self.config_mac.take() else {
            if self.version.major >= VaultVersion::CURRENT.major {
                return Err(Error::Crypto(format!(
                    "{CONFIG_FILENAME} has no integrity tag (config_mac); a {} vault config \
                     without one is refused",
                    self.version
                )));
            }
            if !bound_by_manifest && self.version >= VaultVersion::V1_1 {
                return Err(Error::Crypto(format!(
                    "{CONFIG_FILENAME} is not authenticated: a {} config with no integrity tag \
                     (config_mac) and no snapshot manifest is refused; restore a tagged copy of \
                     {CONFIG_FILENAME}, or a copy bound by a snapshot manifest",
                    self.version
                )));
            }
            return Ok(());
        };
        let expected = self.compute_mac(master_key)?;
        if tag.len() != expected.len() || !bool::from(tag.as_slice().ct_eq(&expected)) {
            return Err(Error::Crypto(format!(
                "{CONFIG_FILENAME} integrity check failed (config_mac mismatch): \
                 the stored config was changed outside this vault"
            )));
        }
        Ok(())
    }
}

/// The refusal of an untagged 1.1 config that no manifest binds.
#[cfg(test)]
pub(crate) const UNAUTHENTICATED_V1_1: &str = "Cryptographic error: vault.config is not \
    authenticated: a 1.1 config with no integrity tag (config_mac) and no snapshot manifest is \
    refused; restore a tagged copy of vault.config, or a copy bound by a snapshot manifest";

/// Configuration file name in vault root.
pub const CONFIG_FILENAME: &str = "vault.config";

/// Data directory name in vault root.
pub const DATA_DIRNAME: &str = "d";

/// Metadata directory name in vault root.
pub const META_DIRNAME: &str = "m";

/// Tree state filename in metadata directory.
pub const TREE_FILENAME: &str = "tree.json";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_config_rejects_unbounded_kdf_work_before_authentication() {
        let config = VaultConfig::new(
            VaultId::new("kdf-budget").unwrap(),
            b"password",
            "memory",
            serde_json::Value::Null,
            KdfParams::moderate(),
        )
        .unwrap()
        .config;
        for field in ["memory_cost", "time_cost", "parallelism"] {
            let mut json = serde_json::to_value(&config).unwrap();
            json["kdf_params"][field] = serde_json::json!(u32::MAX);
            let bytes = serde_json::to_vec(&json).unwrap();
            assert!(
                VaultConfig::from_bytes(&bytes).is_err(),
                "unbounded {field} accepted"
            );
            assert!(VaultConfig::from_json(std::str::from_utf8(&bytes).unwrap()).is_err());
        }
    }

    fn tagged_config() -> (VaultConfig, MasterKey) {
        let creation = VaultConfig::new(
            VaultId::new("config-mac").unwrap(),
            b"password",
            "local",
            serde_json::json!({ "root": "/vault" }),
            KdfParams::moderate(),
        )
        .unwrap();
        (creation.config, creation.master_key)
    }

    #[test]
    fn config_mac_round_trips_and_is_removed_on_verify() {
        let (config, master_key) = tagged_config();
        let bytes = config.to_authenticated_bytes(&master_key).unwrap();
        let mut restored = VaultConfig::from_bytes(&bytes).unwrap();
        assert!(restored.config_mac.is_some());
        restored.verify_integrity(&master_key, false).unwrap();
        assert!(restored.config_mac.is_none());
        assert_eq!(restored.to_bytes().unwrap(), config.to_bytes().unwrap());
        // Re-tagging the verified config reproduces the stored bytes.
        assert_eq!(restored.to_authenticated_bytes(&master_key).unwrap(), bytes);
    }

    #[test]
    fn config_mac_covers_every_field_and_the_key() {
        let (config, master_key) = tagged_config();
        let bytes = config.to_authenticated_bytes(&master_key).unwrap();
        type Edit = fn(&mut serde_json::Value);
        let edits: [(&str, Edit); 6] = [
            ("kdf_params", |json| {
                json["kdf_params"]["memory_cost"] = 16.into()
            }),
            ("hardware_key", |json| {
                json["hardware_key"] = serde_json::json!({
                    "metadata": { "kind": "RawSecret", "enrolled_at": "2026-01-01T00:00:00Z" },
                    "wrapped_master_key": [1, 2, 3],
                    "key_verification": [4, 5, 6],
                })
            }),
            ("provider_config", |json| {
                json["provider_config"]["root"] = "/attacker".into()
            }),
            ("provider_type", |json| {
                json["provider_type"] = "gdrive".into()
            }),
            ("version", |json| json["version"]["minor"] = 1.into()),
            ("salt", |json| {
                let byte = json["salt"][0].as_u64().unwrap();
                json["salt"][0] = (byte ^ 1).into()
            }),
        ];
        for (field, edit) in edits {
            let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            edit(&mut json);
            let mut tampered =
                VaultConfig::from_bytes(&serde_json::to_vec(&json).unwrap()).unwrap();
            let error = tampered.verify_integrity(&master_key, true).unwrap_err();
            assert!(
                error.to_string().contains("config_mac mismatch"),
                "{field}: {error}"
            );
        }
        let mut genuine = VaultConfig::from_bytes(&bytes).unwrap();
        let other_key = generate_master_key();
        assert!(genuine.verify_integrity(&other_key, true).is_err());
    }

    #[test]
    fn untagged_config_is_refused_unless_a_manifest_binds_a_1_1_config() {
        let (mut config, master_key) = tagged_config();
        for bound_by_manifest in [false, true] {
            let error = config
                .clone()
                .verify_integrity(&master_key, bound_by_manifest)
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "Cryptographic error: vault.config has no integrity tag (config_mac); a 2.0 vault config without one is refused"
            );
        }
        // An untagged 1.1 config is accepted only where a manifest binds it.
        config.version = VaultVersion::V1_1;
        config.clone().verify_integrity(&master_key, true).unwrap();
        assert_eq!(
            config
                .verify_integrity(&master_key, false)
                .unwrap_err()
                .to_string(),
            UNAUTHENTICATED_V1_1
        );
    }

    #[test]
    fn test_vault_version_compatibility() {
        let current = VaultVersion::CURRENT;
        assert!(current.is_compatible());

        let incompatible = VaultVersion { major: 3, minor: 0 };
        assert!(!incompatible.is_compatible());

        // 1.x vaults are not directly usable; they upgrade through migration
        // (1.0) or on open (1.1) before a session is created.
        assert!(!VaultVersion { major: 1, minor: 0 }.is_compatible());
        assert!(!VaultVersion::V1_1.is_compatible());
    }

    #[test]
    fn v1_1_client_gate_refuses_current_format() {
        // Copy of the 1.1 client's only open-path gate (b6520ff
        // `VaultVersion::is_compatible`, called by `VaultSession::from_master_key`).
        fn v1_1_client_is_compatible(version: &VaultVersion) -> bool {
            version.major == VaultVersion::V1_1.major
        }
        assert!(!v1_1_client_is_compatible(&VaultVersion::CURRENT));
        assert!(v1_1_client_is_compatible(&VaultVersion::V1_1));
    }

    #[test]
    fn new_config_reports_current_version() {
        let config = VaultConfig::new(
            VaultId::new("fresh").unwrap(),
            b"password",
            "memory",
            serde_json::Value::Null,
            KdfParams::moderate(),
        )
        .unwrap()
        .config;
        assert_eq!(config.version, VaultVersion { major: 2, minor: 0 });
    }

    #[test]
    fn test_config_creation_and_verification() {
        let id = VaultId::new("test-vault").unwrap();
        let password = b"secure-password";
        let params = KdfParams::moderate();

        let creation =
            VaultConfig::new(id, password, "memory", serde_json::Value::Null, params).unwrap();
        let config = creation.config;

        assert_eq!(creation.recovery_words.split_whitespace().count(), 24);
        assert!(config.wrapped_master_key.is_some());
        assert!(config.recovery_wrapped_master_key.is_some());
        assert!(!config.is_legacy_format());

        assert!(config.verify_password(password).unwrap().is_some());
        assert!(config.verify_password(b"wrong-password").unwrap().is_none());
    }

    #[test]
    fn test_recovery_key_verify_and_reset_password() {
        let id = VaultId::new("test-vault").unwrap();
        let password = b"old-password";
        let params = KdfParams::moderate();

        let creation =
            VaultConfig::new(id, password, "memory", serde_json::Value::Null, params).unwrap();
        let mut config = creation.config;
        let recovery_words = creation.recovery_words;

        let rk = RecoveryKey::from_mnemonic(&recovery_words).unwrap();
        assert!(config.verify_recovery_key(&rk).unwrap().is_some());

        let old_key = config.verify_password(password).unwrap().unwrap();
        let new_password = b"new-password";
        let new_key = config.reset_password(&rk, new_password).unwrap();
        assert_ne!(old_key.as_bytes(), new_key.as_bytes());

        assert!(config.verify_password(password).unwrap().is_none());
        assert_eq!(
            config
                .verify_password(new_password)
                .unwrap()
                .unwrap()
                .as_bytes(),
            new_key.as_bytes()
        );
        assert_eq!(
            config.verify_recovery_key(&rk).unwrap().unwrap().as_bytes(),
            new_key.as_bytes()
        );

        // A wrong recovery key is refused without changing the config.
        let before = config.to_bytes().unwrap();
        assert!(matches!(
            config.reset_password(&RecoveryKey::generate(), b"other"),
            Err(Error::NotPermitted(_))
        ));
        assert_eq!(config.to_bytes().unwrap(), before);
    }

    #[test]
    fn test_decrypt_recovery_key() {
        let id = VaultId::new("test-vault").unwrap();
        let password = b"password";
        let params = KdfParams::moderate();

        let creation =
            VaultConfig::new(id, password, "memory", serde_json::Value::Null, params).unwrap();
        let config = creation.config;
        let recovery_words = creation.recovery_words;

        let master_key = config.verify_password(password).unwrap().unwrap();
        let decrypted_rk = config.decrypt_recovery_key(&master_key).unwrap();
        let decrypted_words = decrypted_rk.to_mnemonic().unwrap();

        assert_eq!(*decrypted_words, *recovery_words);
    }

    #[test]
    fn test_master_key_consistency() {
        let id = VaultId::new("test-vault").unwrap();
        let password = b"password";
        let params = KdfParams::moderate();

        let creation =
            VaultConfig::new(id, password, "memory", serde_json::Value::Null, params).unwrap();
        let config = creation.config;
        let recovery_words = creation.recovery_words;

        let mk_from_password = config.verify_password(password).unwrap().unwrap();
        let rk = RecoveryKey::from_mnemonic(&recovery_words).unwrap();
        let mk_from_recovery = config.verify_recovery_key(&rk).unwrap().unwrap();

        assert_eq!(mk_from_password.as_bytes(), mk_from_recovery.as_bytes());
    }

    #[test]
    fn oauth_credentials_cannot_be_serialized_in_vault_config() {
        let mut config = VaultConfig::new(
            VaultId::new("cloud-secrets").unwrap(),
            b"password",
            "gdrive",
            serde_json::json!({
                "credential_schema": 1,
                "credential_ref": "local:gdrive:test",
                "folder_id": "folder"
            }),
            KdfParams::moderate(),
        )
        .unwrap()
        .config;
        config.provider_config["tokens"] = serde_json::json!({
            "access_token": "must-never-serialize",
            "refresh_token": "must-never-serialize",
            "expires_at": "2099-01-01T00:00:00Z"
        });

        let error = serde_json::to_string(&config).unwrap_err();
        assert!(error.to_string().contains("OAuth credentials"));
    }

    #[test]
    fn test_config_serialization() {
        let id = VaultId::new("test-vault").unwrap();
        let password = b"test";
        let params = KdfParams::moderate();

        let creation = VaultConfig::new(
            id,
            password,
            "local",
            serde_json::json!({"root": "/tmp/vault"}),
            params,
        )
        .unwrap();
        let config = creation.config;

        let json = config.to_json().unwrap();
        let restored = VaultConfig::from_json(&json).unwrap();

        assert_eq!(restored.id.as_str(), config.id.as_str());
        assert_eq!(restored.provider_type, config.provider_type);
        assert!(restored.wrapped_master_key.is_some());
        assert!(restored.verify_password(password).unwrap().is_some());
        assert!(!restored.hardware_key_status().is_enrolled());
    }

    #[test]
    fn test_hardware_key_enroll_verify_remove_status_and_serialization() {
        let id = VaultId::new("test-vault").unwrap();
        let password = b"password";
        let params = KdfParams::moderate();
        let creation =
            VaultConfig::new(id, password, "memory", serde_json::Value::Null, params).unwrap();
        let mut config = creation.config;
        let master_key = config.verify_password(password).unwrap().unwrap();
        let metadata = HardwareKeyMetadata::new(
            HardwareKeyKind::YubiKeyHmacSha1,
            Some("YubiKey slot 2".to_string()),
            Some("yk-slot-2".to_string()),
        );
        let secret = b"simulated-yubikey-hmac-response";

        assert!(!config.hardware_key_status().is_enrolled());
        config
            .enroll_hardware_key(&master_key, secret, metadata.clone())
            .unwrap();
        let status = config.hardware_key_status();
        assert!(status.is_enrolled());
        assert_eq!(status.metadata, Some(metadata.clone()));
        assert!(config.verify_hardware_key(secret).unwrap().is_some());
        assert!(config
            .verify_hardware_key(b"totally-wrong-hardware-secret")
            .unwrap()
            .is_none());

        let json = config.to_json().unwrap();
        let restored = VaultConfig::from_json(&json).unwrap();
        assert!(restored.hardware_key_status().is_enrolled());
        assert_eq!(restored.hardware_key_status().metadata, Some(metadata));
        assert!(restored.verify_hardware_key(secret).unwrap().is_some());

        config.remove_hardware_key();
        assert!(!config.hardware_key_status().is_enrolled());
        assert!(config.verify_hardware_key(secret).is_err());
    }

    #[test]
    fn test_old_vault_json_without_hardware_key_deserializes() {
        let id = VaultId::new("legacy-json").unwrap();
        let password = b"password";
        let params = KdfParams::moderate();
        let creation =
            VaultConfig::new(id, password, "memory", serde_json::Value::Null, params).unwrap();
        let config = creation.config;
        let json = config.to_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("hardware_key").is_none());
        let restored = VaultConfig::from_json(&json).unwrap();
        assert!(!restored.hardware_key_status().is_enrolled());
        assert!(restored.verify_password(password).unwrap().is_some());
    }

    #[test]
    fn test_legacy_format_detection() {
        let id = VaultId::new("legacy").unwrap();
        let password = b"password";
        let params = KdfParams::moderate();
        let salt = Salt::generate();

        let master_key = axiomvault_crypto::derive_key(password, &salt, &params).unwrap();
        let verification_plaintext = b"AXIOMVAULT_KEY_VERIFICATION_V1";
        let key_verification =
            axiomvault_crypto::encrypt(master_key.as_bytes(), verification_plaintext).unwrap();

        let config = VaultConfig {
            id,
            version: VaultVersion { major: 1, minor: 0 },
            salt,
            kdf_params: params,
            provider_type: "memory".to_string(),
            provider_config: serde_json::Value::Null,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            key_verification,
            wrapped_master_key: None,
            recovery_wrapped_master_key: None,
            recovery_key_verification: None,
            encrypted_recovery_key: None,
            hardware_key: None,
            config_mac: None,
        };

        assert!(config.is_legacy_format());
        assert!(config.verify_password(password).unwrap().is_some());
        assert!(config.verify_password(b"wrong").unwrap().is_none());
    }

    #[test]
    fn test_migrate_legacy_to_v1_1() {
        let id = VaultId::new("legacy").unwrap();
        let password = b"password";
        let params = KdfParams::moderate();
        let salt = Salt::generate();

        let master_key = axiomvault_crypto::derive_key(password, &salt, &params).unwrap();
        let verification_plaintext = b"AXIOMVAULT_KEY_VERIFICATION_V1";
        let key_verification =
            axiomvault_crypto::encrypt(master_key.as_bytes(), verification_plaintext).unwrap();

        let mut config = VaultConfig {
            id,
            version: VaultVersion { major: 1, minor: 0 },
            salt,
            kdf_params: params,
            provider_type: "memory".to_string(),
            provider_config: serde_json::Value::Null,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            key_verification,
            wrapped_master_key: None,
            recovery_wrapped_master_key: None,
            recovery_key_verification: None,
            encrypted_recovery_key: None,
            hardware_key: None,
            config_mac: None,
        };

        let recovery_words = config.migrate_to_v1_1(password).unwrap();
        assert_eq!(recovery_words.split_whitespace().count(), 24);
        assert!(!config.is_legacy_format());

        let mk_after = config.verify_password(password).unwrap().unwrap();
        assert_eq!(master_key.as_bytes(), mk_after.as_bytes());

        let rk = RecoveryKey::from_mnemonic(&recovery_words).unwrap();
        let mk_from_recovery = config.verify_recovery_key(&rk).unwrap().unwrap();
        assert_eq!(master_key.as_bytes(), mk_from_recovery.as_bytes());
    }
}
