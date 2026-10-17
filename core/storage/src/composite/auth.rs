//! Keyed authentication for the composite layer (M-16).
//!
//! Every backend in a composite set is untrusted: it can rewrite any file it
//! holds, including the shard map and its own shards. The composite layer
//! therefore authenticates both with BLAKE2b-256 in keyed mode under a
//! [`CompositeKey`] that the backends never see. A CRC or an unkeyed hash
//! would not do: a backend can recompute either over bytes of its choosing.

use std::fmt;

use blake2::digest::consts::U32;
use blake2::digest::Mac;
use zeroize::Zeroizing;

/// Length of an authentication tag in bytes.
pub(crate) const TAG_LEN: usize = 32;

/// Domain for the tag over a serialized shard map.
pub(crate) const DOMAIN_SHARD_MAP: &[u8] = b"axiomvault/composite/shard-map/v1";
/// Domain for the tag over one erasure shard.
pub(crate) const DOMAIN_SHARD: &[u8] = b"axiomvault/composite/erasure-shard/v1";
/// Domain for the tag over one mirror copy.
pub(crate) const DOMAIN_MIRROR: &[u8] = b"axiomvault/composite/mirror-copy/v1";

type Blake2bMac256 = blake2::Blake2bMac<U32>;

/// Secret key that authenticates the shard map and every shard of a
/// composite set.
///
/// The storage backends must not be able to compute it. The vault layer
/// derives it from the master key with its own domain, for example
/// `master_key.derive_file_key(b"composite_auth_v1")`, the same way it keys
/// the `vault.config` MAC; the backends hold only ciphertext and the wrapped
/// master key, so they cannot.
pub struct CompositeKey(Zeroizing<[u8; 32]>);

impl CompositeKey {
    /// Wrap 32 bytes of key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn mac(&self, domain: &[u8], parts: &[&[u8]]) -> Blake2bMac256 {
        let mut mac = <Blake2bMac256 as Mac>::new_from_slice(self.0.as_slice())
            .expect("BLAKE2b accepts a 32-byte key");
        // Length-prefix every field so no two field lists hash alike.
        for part in std::iter::once(&domain).chain(parts.iter()) {
            mac.update(&(part.len() as u64).to_le_bytes());
            mac.update(part);
        }
        mac
    }

    /// Tag over `parts` under `domain`.
    pub(crate) fn tag(&self, domain: &[u8], parts: &[&[u8]]) -> [u8; TAG_LEN] {
        self.mac(domain, parts).finalize().into_bytes().into()
    }

    /// Check `tag` over `parts` under `domain` in constant time.
    pub(crate) fn verify(&self, domain: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
        self.mac(domain, parts).verify_slice(tag).is_ok()
    }
}

impl fmt::Debug for CompositeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CompositeKey([REDACTED])")
    }
}
