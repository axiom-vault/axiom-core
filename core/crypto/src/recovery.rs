//! Recovery key generation and key wrapping.
//!
//! Provides:
//! - Random master key generation
//! - Key wrapping (encrypting a master key with a KEK)
//! - Recovery key generation as BIP39 mnemonic words
//! - Deriving a KEK from a recovery key via Blake2b (high-entropy input,
//!   no need for slow Argon2id)

use crate::aead;
use crate::keys::{MasterKey, KEY_LENGTH};
use axiomvault_common::{Error, Result};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Context string for deriving a recovery KEK via Blake2b.
const RECOVERY_KEK_CONTEXT: &[u8] = b"axiomvault_recovery_kek_v1";
/// Context string for deriving a hardware-key KEK via Blake2b.
const HARDWARE_KEY_KEK_CONTEXT: &[u8] = b"axiomvault_hardware_key_kek_v1";
/// Minimum acceptable hardware-key secret length in bytes.
const MIN_HARDWARE_KEY_SECRET_LENGTH: usize = 16;

/// A 256-bit recovery key that can be encoded as BIP39 mnemonic words.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey {
    entropy: [u8; KEY_LENGTH],
}

impl RecoveryKey {
    /// Generate a new random recovery key.
    pub fn generate() -> Self {
        use rand::RngExt;

        let mut entropy = [0u8; KEY_LENGTH];
        rand::rng().fill(&mut entropy[..]);
        Self { entropy }
    }

    /// Create from raw entropy bytes.
    pub fn from_bytes(entropy: [u8; KEY_LENGTH]) -> Self {
        Self { entropy }
    }

    /// Get raw entropy bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.entropy
    }

    /// Encode recovery key as BIP39 mnemonic words (24 words for 256 bits).
    pub fn to_mnemonic(&self) -> Result<Zeroizing<String>> {
        let mnemonic = bip39::Mnemonic::from_entropy(&self.entropy)
            .map_err(|e| Error::Crypto(format!("Failed to encode recovery key: {}", e)))?;
        Ok(Zeroizing::new(mnemonic.to_string()))
    }

    /// Decode recovery key from BIP39 mnemonic words.
    pub fn from_mnemonic(words: &str) -> Result<Self> {
        let mnemonic: bip39::Mnemonic = words
            .parse()
            .map_err(|e| Error::Crypto(format!("Invalid recovery key words: {}", e)))?;
        let mut entropy = mnemonic.to_entropy();
        if entropy.len() != KEY_LENGTH {
            let actual_len = entropy.len();
            entropy.zeroize();
            return Err(Error::Crypto(format!(
                "Invalid recovery key length: expected {} bytes, got {}",
                KEY_LENGTH, actual_len
            )));
        }

        let mut bytes = [0u8; KEY_LENGTH];
        bytes.copy_from_slice(&entropy);
        entropy.zeroize();
        Ok(Self { entropy: bytes })
    }

    /// Derive a key-encryption key (KEK) from this recovery key using Blake2b.
    pub fn derive_kek(&self) -> Zeroizing<[u8; KEY_LENGTH]> {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(self.entropy);
        hasher.update(RECOVERY_KEK_CONTEXT);
        let mut result = hasher.finalize();

        let mut kek = Zeroizing::new([0u8; KEY_LENGTH]);
        kek.copy_from_slice(&result);
        result.as_mut_slice().zeroize();
        kek
    }
}

/// Derive a key-encryption key (KEK) from caller-provided hardware-key bytes.
pub fn derive_hardware_key_kek(secret: &[u8]) -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
    if secret.is_empty() {
        return Err(Error::InvalidInput(
            "Hardware-key secret cannot be empty".to_string(),
        ));
    }
    if secret.len() < MIN_HARDWARE_KEY_SECRET_LENGTH {
        return Err(Error::InvalidInput(format!(
            "Hardware-key secret must be at least {} bytes",
            MIN_HARDWARE_KEY_SECRET_LENGTH
        )));
    }

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(secret);
    hasher.update(HARDWARE_KEY_KEK_CONTEXT);
    let mut result = hasher.finalize();

    let mut kek = Zeroizing::new([0u8; KEY_LENGTH]);
    kek.copy_from_slice(&result);
    result.as_mut_slice().zeroize();
    Ok(kek)
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecoveryKey([REDACTED])")
    }
}

/// Generate a new random master key.
pub fn generate_master_key() -> MasterKey {
    use rand::RngExt;

    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    rand::rng().fill(&mut key[..]);
    MasterKey::from_bytes(*key)
}

/// Wrap (encrypt) a master key with a key-encryption key.
pub fn wrap_key(master_key: &MasterKey, kek: &[u8; KEY_LENGTH]) -> Result<Vec<u8>> {
    aead::encrypt(kek, master_key.as_bytes())
}

/// Unwrap (decrypt) a master key with a key-encryption key.
pub fn unwrap_key(wrapped: &[u8], kek: &[u8; KEY_LENGTH]) -> Result<MasterKey> {
    let mut plaintext = aead::decrypt(kek, wrapped)?;
    if plaintext.len() != KEY_LENGTH {
        return Err(Error::Crypto(format!(
            "Unwrapped key has wrong length: expected {}, got {}",
            KEY_LENGTH,
            plaintext.len()
        )));
    }

    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(MasterKey::from_bytes(*key))
}

/// Verification constant used to validate recovery keys.
pub const RECOVERY_VERIFICATION_PLAINTEXT: &[u8] = b"AXIOMVAULT_RECOVERY_VERIFICATION_V1";
/// Verification constant used to validate caller-provided hardware-key bytes.
pub const HARDWARE_KEY_VERIFICATION_PLAINTEXT: &[u8] = b"AXIOMVAULT_HARDWARE_KEY_VERIFICATION_V1";

/// Create verification data for a recovery key.
pub fn create_recovery_verification(recovery_key: &RecoveryKey) -> Result<Vec<u8>> {
    let kek = recovery_key.derive_kek();
    aead::encrypt(&*kek, RECOVERY_VERIFICATION_PLAINTEXT)
}

/// Verify recovery key against stored verification data.
pub fn verify_recovery_key(recovery_key: &RecoveryKey, verification: &[u8]) -> Result<bool> {
    use subtle::ConstantTimeEq;

    let kek = recovery_key.derive_kek();
    match aead::decrypt(&*kek, verification) {
        Ok(mut plaintext) => {
            let valid = plaintext.len() == RECOVERY_VERIFICATION_PLAINTEXT.len()
                && bool::from(plaintext.as_slice().ct_eq(RECOVERY_VERIFICATION_PLAINTEXT));
            plaintext.zeroize();
            Ok(valid)
        }
        Err(_) => Ok(false),
    }
}

/// Create verification data for caller-provided hardware-key bytes.
pub fn create_hardware_key_verification(secret: &[u8]) -> Result<Vec<u8>> {
    let kek = derive_hardware_key_kek(secret)?;
    aead::encrypt(&*kek, HARDWARE_KEY_VERIFICATION_PLAINTEXT)
}

/// Verify caller-provided hardware-key bytes against stored verification data.
pub fn verify_hardware_key(secret: &[u8], verification: &[u8]) -> Result<bool> {
    use subtle::ConstantTimeEq;

    let kek = derive_hardware_key_kek(secret)?;
    match aead::decrypt(&*kek, verification) {
        Ok(mut plaintext) => {
            let valid = plaintext.len() == HARDWARE_KEY_VERIFICATION_PLAINTEXT.len()
                && bool::from(
                    plaintext
                        .as_slice()
                        .ct_eq(HARDWARE_KEY_VERIFICATION_PLAINTEXT),
                );
            plaintext.zeroize();
            Ok(valid)
        }
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_key_mnemonic_roundtrip() {
        let key = RecoveryKey::generate();
        let words = key.to_mnemonic().unwrap();
        assert_eq!(words.split_whitespace().count(), 24);

        let restored = RecoveryKey::from_mnemonic(&words).unwrap();
        assert_eq!(key.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn test_recovery_key_invalid_mnemonic() {
        let result = RecoveryKey::from_mnemonic("not valid words at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_master_key_is_random() {
        let k1 = generate_master_key();
        let k2 = generate_master_key();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let master = generate_master_key();
        let kek = [42u8; KEY_LENGTH];
        let wrapped = wrap_key(&master, &kek).unwrap();
        let unwrapped = unwrap_key(&wrapped, &kek).unwrap();
        assert_eq!(master.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn test_unwrap_wrong_kek_fails() {
        let master = generate_master_key();
        let kek1 = [1u8; KEY_LENGTH];
        let kek2 = [2u8; KEY_LENGTH];
        let wrapped = wrap_key(&master, &kek1).unwrap();
        assert!(unwrap_key(&wrapped, &kek2).is_err());
    }

    #[test]
    fn test_recovery_verification() {
        let rk = RecoveryKey::generate();
        let verification = create_recovery_verification(&rk).unwrap();
        assert!(verify_recovery_key(&rk, &verification).unwrap());

        let rk2 = RecoveryKey::generate();
        assert!(!verify_recovery_key(&rk2, &verification).unwrap());
    }

    #[test]
    fn test_recovery_kek_deterministic() {
        let key = RecoveryKey::from_bytes([99u8; KEY_LENGTH]);
        let kek1 = key.derive_kek();
        let kek2 = key.derive_kek();
        assert_eq!(*kek1, *kek2);
    }

    #[test]
    fn test_recovery_kek_different_keys() {
        let k1 = RecoveryKey::from_bytes([1u8; KEY_LENGTH]);
        let k2 = RecoveryKey::from_bytes([2u8; KEY_LENGTH]);
        assert_ne!(*k1.derive_kek(), *k2.derive_kek());
    }

    #[test]
    fn test_hardware_key_verification_roundtrip() {
        let secret = b"simulated-yubikey-response";
        let verification = create_hardware_key_verification(secret).unwrap();
        assert!(verify_hardware_key(secret, &verification).unwrap());
        assert!(!verify_hardware_key(b"totally-wrong-hardware-secret", &verification).unwrap());
    }

    #[test]
    fn test_hardware_key_secret_must_not_be_empty() {
        assert!(derive_hardware_key_kek(b"").is_err());
    }

    #[test]
    fn test_hardware_key_secret_must_meet_minimum_length() {
        assert!(derive_hardware_key_kek(b"short-hw-secret").is_err());
    }
}
