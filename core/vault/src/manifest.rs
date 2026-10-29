//! Authenticated snapshot generation manifest.

use std::collections::BTreeMap;

use axiomvault_common::{Error, Result, VaultId, VaultPath};
use axiomvault_crypto::{decrypt, encrypt, MasterKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const MANIFEST_FILENAME: &str = "generation.manifest";
const MANIFEST_KEY_CONTEXT: &[u8] = b"vault_generation_manifest_v1";

#[derive(Serialize, Deserialize)]
struct ManifestEnvelope {
    envelope_version: u32,
    config_object: String,
    sealed_manifest: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct GenerationManifest {
    pub version: u32,
    pub vault_id: VaultId,
    pub generation: u64,
    pub tree_digest: String,
    pub config_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tree_object: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config_object: Option<String>,
    #[serde(default)]
    pub object_digests: BTreeMap<String, String>,
}

impl GenerationManifest {
    #[cfg(test)]
    pub fn legacy_for_test(
        vault_id: VaultId,
        generation: u64,
        encrypted_tree: &[u8],
        config_bytes: &[u8],
        object_digests: BTreeMap<String, String>,
    ) -> Self {
        Self {
            version: 1,
            vault_id,
            generation,
            tree_digest: digest(encrypted_tree),
            config_digest: digest(config_bytes),
            tree_object: None,
            config_object: None,
            object_digests,
        }
    }

    pub fn new(
        vault_id: VaultId,
        generation: u64,
        encrypted_tree: &[u8],
        config_bytes: &[u8],
        object_digests: BTreeMap<String, String>,
    ) -> Self {
        let tree_digest = digest(encrypted_tree);
        let config_digest = digest(config_bytes);
        Self {
            version: 2,
            vault_id,
            generation,
            tree_object: Some(format!("/m/tree.{generation}.{tree_digest}.enc")),
            config_object: Some(format!("/m/config.{generation}.{config_digest}.json")),
            tree_digest,
            config_digest,
            object_digests,
        }
    }

    pub fn object_paths(&self) -> Result<(VaultPath, VaultPath)> {
        match self.version {
            1 => Ok((
                VaultPath::parse(crate::config::META_DIRNAME)?
                    .join(crate::config::TREE_FILENAME)?,
                VaultPath::parse(crate::config::CONFIG_FILENAME)?,
            )),
            2 => {
                let expected_tree = format!("/m/tree.{}.{}.enc", self.generation, self.tree_digest);
                let expected_config =
                    format!("/m/config.{}.{}.json", self.generation, self.config_digest);
                if self.tree_object.as_deref() != Some(expected_tree.as_str())
                    || self.config_object.as_deref() != Some(expected_config.as_str())
                {
                    return Err(Error::Crypto(
                        "snapshot manifest contains an invalid generation object path".to_string(),
                    ));
                }
                Ok((
                    VaultPath::parse(&expected_tree)?,
                    VaultPath::parse(&expected_config)?,
                ))
            }
            _ => Err(Error::Crypto(
                "unsupported snapshot manifest version".to_string(),
            )),
        }
    }

    pub fn verify_bindings(
        &self,
        vault_id: &VaultId,
        encrypted_tree: &[u8],
        config_bytes: &[u8],
    ) -> Result<()> {
        if !matches!(self.version, 1 | 2) || &self.vault_id != vault_id {
            return Err(Error::Crypto(
                "snapshot manifest vault identity mismatch".to_string(),
            ));
        }
        self.object_paths()?;
        if self.tree_digest != digest(encrypted_tree) {
            return Err(Error::Crypto(
                "snapshot tree and manifest generations do not match".to_string(),
            ));
        }
        if self.config_digest != digest(config_bytes) {
            return Err(Error::Crypto(
                "vault config and snapshot manifest generations do not match".to_string(),
            ));
        }
        Ok(())
    }

    pub fn seal(&self, master_key: &MasterKey) -> Result<Vec<u8>> {
        let mut plaintext =
            serde_json::to_vec(self).map_err(|error| Error::Serialization(error.to_string()))?;
        let key = master_key.derive_file_key(MANIFEST_KEY_CONTEXT);
        let sealed = encrypt(key.as_bytes(), &plaintext)?;
        plaintext.zeroize();
        if self.version == 1 {
            return Ok(sealed);
        }
        let config_object = self.config_object.clone().ok_or_else(|| {
            Error::Serialization("snapshot manifest is missing its config object".to_string())
        })?;
        serde_json::to_vec(&ManifestEnvelope {
            envelope_version: 1,
            config_object,
            sealed_manifest: URL_SAFE_NO_PAD.encode(sealed),
        })
        .map_err(|error| Error::Serialization(error.to_string()))
    }

    pub fn open(master_key: &MasterKey, bytes: &[u8]) -> Result<Self> {
        let (sealed, envelope_config) = match serde_json::from_slice::<ManifestEnvelope>(bytes) {
            Ok(envelope) => {
                if envelope.envelope_version != 1 {
                    return Err(Error::Crypto(
                        "unsupported snapshot manifest envelope".to_string(),
                    ));
                }
                Self::validate_config_hint(&envelope.config_object)?;
                let sealed = URL_SAFE_NO_PAD
                    .decode(&envelope.sealed_manifest)
                    .map_err(|_| {
                        Error::Crypto("snapshot manifest envelope is malformed".to_string())
                    })?;
                (sealed, Some(envelope.config_object))
            }
            Err(_) => (bytes.to_vec(), None),
        };
        let key = master_key.derive_file_key(MANIFEST_KEY_CONTEXT);
        let mut plaintext = decrypt(key.as_bytes(), &sealed)
            .map_err(|_| Error::Crypto("snapshot manifest authentication failed".to_string()))?;
        let result = serde_json::from_slice::<Self>(&plaintext)
            .map_err(|error| Error::Serialization(error.to_string()))
            .and_then(|manifest| {
                if let Some(config_object) = envelope_config {
                    if manifest.config_object.as_deref() != Some(&config_object) {
                        return Err(Error::Crypto(
                            "snapshot manifest envelope binding mismatch".to_string(),
                        ));
                    }
                } else if manifest.version != 1 {
                    return Err(Error::Crypto(
                        "snapshot manifest envelope is missing".to_string(),
                    ));
                }
                Ok(manifest)
            });
        plaintext.zeroize();
        result
    }

    pub fn config_path_hint(bytes: &[u8]) -> Result<Option<VaultPath>> {
        let Ok(envelope) = serde_json::from_slice::<ManifestEnvelope>(bytes) else {
            return Ok(None);
        };
        if envelope.envelope_version != 1 {
            return Err(Error::Crypto(
                "unsupported snapshot manifest envelope".to_string(),
            ));
        }
        Self::validate_config_hint(&envelope.config_object)
    }

    fn validate_config_hint(path: &str) -> Result<Option<VaultPath>> {
        let parsed = VaultPath::parse(path)?;
        let components = parsed.components();
        let valid = components.len() == 2
            && components[0] == crate::config::META_DIRNAME
            && components[1].starts_with("config.")
            && components[1].ends_with(".json");
        if !valid {
            return Err(Error::Crypto(
                "snapshot manifest contains an invalid config object hint".to_string(),
            ));
        }
        Ok(Some(parsed))
    }
}

/// Incremental hasher producing the same digests as [`digest`].
pub(crate) type DigestHasher = Blake2b<U32>;

pub(crate) fn digest(bytes: &[u8]) -> String {
    let mut hasher = DigestHasher::new();
    hasher.update(bytes);
    finish_digest(hasher)
}

pub(crate) fn finish_digest(hasher: DigestHasher) -> String {
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}
