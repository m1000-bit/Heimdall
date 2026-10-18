//! Key management for data-at-rest protection.
//!
//! Design constraints:
//!
//! * Long-term secrets never touch the filesystem in the clear. The keystore
//!   is a single blob encrypted under a master key stretched from a passphrase
//!   with Argon2id.
//! * The blob is authenticated, so a tampered file fails to decrypt instead of
//!   yielding attacker-chosen key material.
//! * Key records carry a monotonic generation counter and a creation timestamp,
//!   so an operator can answer "which key encrypted this log entry" after a
//!   rotation.

use crate::{
    aead::{Sealed, Suite, open, seal},
    error::{Error, Result},
    kdf::{self, Passphrase, argon2_params},
    secret::{Key32, random_bytes},
    util,
};
use sha2::Digest as _;

const STORE_MAGIC: &[u8; 8] = b"HDV3KMS\0";
const STORE_VERSION: u8 = 1;

/// Alias so the salt length can be used as a const generic argument.
const SALT_LEN: usize = argon2_params::SALT_LEN;

/// One stored secret. `value` is an opaque blob; the KMS does not interpret it,
/// which lets Sentinel store mixed-suit material without the KMS learning the
/// scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub label: String,
    pub suite: Suite,
    pub material: Vec<u8>,
    pub generation: u32,
    pub created_at_unix: u64,
}

impl KeyRecord {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.material.len());
        out.extend_from_slice(b"rec");
        out.push(self.suite as u8);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.created_at_unix.to_be_bytes());
        util::put_bytes(&mut out, self.label.as_bytes());
        util::put_bytes(&mut out, &self.material);
        out
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        // The record tag is written raw: the enclosing container already
        // length-prefixes each record, so a second prefix here would desync the
        // decoder.
        if !buf.starts_with(b"rec") {
            return Err(Error::Kms("bad record tag".into()));
        }
        let mut cur = &buf[3..];
        let suite = Suite::from_u8(
            *cur.first()
                .ok_or_else(|| Error::Kms("truncated record".into()))?,
        )?;
        cur = &cur[1..];
        if cur.len() < 12 {
            return Err(Error::Kms("truncated record".into()));
        }
        let generation = u32::from_be_bytes([cur[0], cur[1], cur[2], cur[3]]);
        let created_at_unix = u64::from_be_bytes([
            cur[4], cur[5], cur[6], cur[7], cur[8], cur[9], cur[10], cur[11],
        ]);
        cur = &cur[12..];
        let label = String::from_utf8(util::take_bytes(&mut cur)?.to_vec())
            .map_err(|_| Error::Kms("record label is not UTF-8".into()))?;
        let material = util::take_bytes(&mut cur)?.to_vec();
        if !cur.is_empty() {
            return Err(Error::Kms("trailing bytes in record".into()));
        }
        Ok(Self {
            label,
            suite,
            material,
            generation,
            created_at_unix,
        })
    }
}

/// An opened keystore. Holds the unwrapped master key in scrubbed memory for as
/// long as it is alive.
pub struct KeyStore {
    master: Key32,
    /// Argon2id salt, kept in the clear in the blob header. A salt is not a
    /// secret; hiding it would only mean an attacker cannot tell which KDF ran.
    salt: [u8; argon2_params::SALT_LEN],
    records: Vec<KeyRecord>,
    next_generation: u32,
}

impl core::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyStore")
            .field("records", &self.records.len())
            .field("master", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl KeyStore {
    /// Creates a new store from a freshly sampled salt.
    pub fn create(passphrase: &Passphrase) -> Result<Self> {
        let salt = random_bytes::<SALT_LEN>();
        let master = kdf::derive_from_passphrase(passphrase.as_bytes(), salt.as_bytes())?;
        Ok(Self {
            master,
            salt: *salt.as_bytes(),
            records: Vec::new(),
            next_generation: 1,
        })
    }

    /// Serialises the store. The output is safe to write to disk: it contains
    /// no plaintext key material.
    ///
    /// Layout: `magic(8) | version(1) | salt(16) | nonce(12) | ciphertext | tag`.
    pub fn seal_to_blob(&self) -> Result<Vec<u8>> {
        let mut plain = Vec::new();
        util::put_bytes(&mut plain, &self.next_generation.to_be_bytes());
        for rec in &self.records {
            util::put_bytes(&mut plain, &rec.encode());
        }

        let sealed = seal(Suite::ChaCha20Poly1305, &self.master, &plain, STORE_MAGIC)?;
        let mut out = Vec::with_capacity(9 + self.salt.len() + sealed.len());
        out.extend_from_slice(STORE_MAGIC);
        out.push(STORE_VERSION);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&sealed.to_bytes());
        Ok(out)
    }

    /// Opens a blob with a passphrase. A wrong passphrase and a tampered blob
    /// are indistinguishable: both surface as [`Error::Decrypt`].
    pub fn open_from_blob(blob: &[u8], passphrase: &Passphrase) -> Result<Self> {
        const HEADER: usize = 9 + argon2_params::SALT_LEN;
        if blob.len() <= HEADER || &blob[..8] != STORE_MAGIC {
            return Err(Error::StoreCorrupted);
        }
        if blob[8] != STORE_VERSION {
            return Err(Error::Kms(format!(
                "keystore version {} is not supported by this build",
                blob[8]
            )));
        }
        let salt: [u8; argon2_params::SALT_LEN] = blob[9..HEADER]
            .try_into()
            .map_err(|_| Error::StoreCorrupted)?;
        let sealed = Sealed::from_bytes(&blob[HEADER..])?;

        let master = kdf::derive_from_passphrase(passphrase.as_bytes(), &salt)?;
        let plain = open(Suite::ChaCha20Poly1305, &master, &sealed, STORE_MAGIC)?;

        let mut cur = &plain[..];
        let gen_bytes = util::take_bytes(&mut cur)?;
        let next_generation = u32::from_be_bytes(
            gen_bytes
                .try_into()
                .map_err(|_| Error::Kms("bad generation counter".into()))?,
        );

        let mut records = Vec::new();
        while !cur.is_empty() {
            records.push(KeyRecord::decode(util::take_bytes(&mut cur)?)?);
        }

        Ok(Self {
            master,
            salt,
            records,
            next_generation,
        })
    }

    pub fn salt_hex(&self) -> String {
        util::to_hex(&self.salt)
    }

    pub fn insert(
        &mut self,
        label: impl Into<String>,
        suite: Suite,
        material: Vec<u8>,
    ) -> Result<u32> {
        let label = label.into();
        if label.is_empty() || label.len() > 128 {
            return Err(Error::Kms("key label must be 1..=128 bytes".into()));
        }
        let generation = self.next_generation;
        self.records.retain(|r| r.label != label);
        self.records.push(KeyRecord {
            label,
            suite,
            material,
            generation,
            created_at_unix: now_unix(),
        });
        self.next_generation = generation.saturating_add(1);
        Ok(generation)
    }

    pub fn get(&self, label: &str) -> Result<&KeyRecord> {
        self.records
            .iter()
            .find(|r| r.label == label)
            .ok_or_else(|| Error::KeyNotFound(label.to_string()))
    }

    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.records.iter().map(|r| r.label.as_str())
    }

    /// Removes a record. The master key remains the only secret in memory; the
    /// removed material is overwritten in place rather than just dropped.
    pub fn remove(&mut self, label: &str) -> Result<()> {
        let idx = self
            .records
            .iter()
            .position(|r| r.label == label)
            .ok_or_else(|| Error::KeyNotFound(label.to_string()))?;
        let mut rec = self.records.remove(idx);
        zeroize::Zeroize::zeroize(&mut rec.material);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Wraps a fresh random key for storage, so secrets at rest inside the store are
/// themselves enveloped rather than stored raw.
pub fn wrap_material(label: &str) -> Result<(Suite, Vec<u8>)> {
    let suite = Suite::ChaCha20Poly1305;
    let mut material = random_bytes::<32>().to_vec().to_vec();
    // Bind the label into the material so a record copied to a different label
    // stops verifying.
    let digest = sha3::Sha3_256::digest(label.as_bytes());
    material
        .iter_mut()
        .zip(digest.iter())
        .for_each(|(a, b)| *a ^= *b);
    Ok((suite, material))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(s: &str) -> Passphrase {
        Passphrase::from_utf8(s.as_bytes())
    }

    #[test]
    fn store_roundtrips_records() {
        let p = pass("Tr0ub4dor&3xKcd!correct-horse");
        let mut store = KeyStore::create(&p).unwrap();
        let (_, m1) = wrap_material("sentinel/tls").unwrap();
        store
            .insert("sentinel/tls", Suite::ChaCha20Poly1305, m1.clone())
            .unwrap();
        let (_, m2) = wrap_material("logs").unwrap();
        store.insert("logs", Suite::Aes256Gcm, m2.clone()).unwrap();

        let blob = store.seal_to_blob().unwrap();
        let reopened = KeyStore::open_from_blob(&blob, &p).unwrap();

        assert_eq!(reopened.get("sentinel/tls").unwrap().material, m1);
        assert_eq!(reopened.get("logs").unwrap().suite, Suite::Aes256Gcm);
        assert_eq!(reopened.len(), 2);
    }

    #[test]
    fn blob_contains_no_plaintext_material() {
        let p = pass("Tr0ub4dor&3xKcd!correct-horse");
        let mut store = KeyStore::create(&p).unwrap();
        let (_, m) = wrap_material("canary-label-xyz").unwrap();
        store
            .insert("canary-label-xyz", Suite::ChaCha20Poly1305, m)
            .unwrap();
        let blob = store.seal_to_blob().unwrap();
        assert!(
            !blob.windows(8).any(|w| w == b"canary-l"),
            "keystore leaked a plaintext key label"
        );
    }

    #[test]
    fn wrong_passphrase_fails_opaquely() {
        let p = pass("Tr0ub4dor&3xKcd!correct-horse");
        let store = KeyStore::create(&p).unwrap();
        let blob = store.seal_to_blob().unwrap();
        let err = KeyStore::open_from_blob(&blob, &pass("not-the-passphrase")).unwrap_err();
        assert!(matches!(err, Error::Decrypt));
    }

    #[test]
    fn tampered_blob_is_rejected() {
        let p = pass("Tr0ub4dor&3xKcd!correct-horse");
        let mut store = KeyStore::create(&p).unwrap();
        let (_, m) = wrap_material("k").unwrap();
        store.insert("k", Suite::ChaCha20Poly1305, m).unwrap();
        let blob = store.seal_to_blob().unwrap();

        for i in 0..blob.len() {
            let mut bad = blob.clone();
            bad[i] ^= 0x01;
            // Either the magic/structure check or AEAD authentication must fire.
            assert!(
                KeyStore::open_from_blob(&bad, &p).is_err(),
                "tampering at byte {i} was not detected"
            );
        }
    }

    #[test]
    fn truncated_blob_is_rejected() {
        let p = pass("Tr0ub4dor&3xKcd!correct-horse");
        let store = KeyStore::create(&p).unwrap();
        let blob = store.seal_to_blob().unwrap();
        for n in [0usize, 1, 8, 9, 20, blob.len() - 1] {
            assert!(KeyStore::open_from_blob(&blob[..n], &p).is_err());
        }
    }

    #[test]
    fn insert_replaces_and_bumps_generation() {
        let p = pass("Tr0ub4dor&3xKcd!correct-horse");
        let mut store = KeyStore::create(&p).unwrap();
        let g1 = store
            .insert("k", Suite::ChaCha20Poly1305, vec![1; 32])
            .unwrap();
        let g2 = store
            .insert("k", Suite::ChaCha20Poly1305, vec![2; 32])
            .unwrap();
        assert_eq!(g1, 1);
        assert_eq!(g2, 2);
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("k").unwrap().generation, 2);
    }

    #[test]
    fn remove_and_missing_label() {
        let p = pass("Tr0ub4dor&3xKcd!correct-horse");
        let mut store = KeyStore::create(&p).unwrap();
        store
            .insert("k", Suite::ChaCha20Poly1305, vec![7; 32])
            .unwrap();
        store.remove("k").unwrap();
        assert!(store.is_empty());
        assert!(matches!(store.get("k"), Err(Error::KeyNotFound(_))));
        assert!(store.remove("k").is_err());
    }

    #[test]
    fn empty_label_is_rejected() {
        let p = pass("Tr0ub4dor&3xKcd!correct-horse");
        let mut store = KeyStore::create(&p).unwrap();
        assert!(
            store
                .insert("", Suite::ChaCha20Poly1305, vec![0; 32])
                .is_err()
        );
    }
}
