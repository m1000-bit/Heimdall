//! Durable baselines for the anomaly engine.
//!
//! # Why they are sealed
//!
//! A baseline is what "normal" looks like on this host. Anyone who can write
//! the file can teach the detector that a siege looks like a quiet afternoon,
//! and the defence then goes quiet without ever raising an alert -- the
//! failure is invisible precisely because the thing that failed is the thing
//! that reports.
//!
//! So the baselines are sealed with ChaCha20-Poly1305 under a key derived from
//! the daemon's passphrase, and a file that does not open is refused rather
//! than half-believed. The daemon reports the refusal loudly and starts from
//! cold: a defence that keeps running on a baseline it could not verify is
//! worse than one that relearns and says so.
//!
//! # Format
//!
//! ```text
//! "HDBL" | version | salt (16) | nonce (12) | ciphertext || tag
//! ```
//!
//! The salt lives in a sidecar next to the file, as the audit log's does, and
//! the copy in the header is checked against it. That way a file that has
//! been moved or replaced is refused rather than decrypted with the wrong
//! key, and the salt never has to be guessed from the file alone.
//!
//! The salt is not a secret: its job is to make the key derivation unique per
//! file. The passphrase is the secret, and it never leaves the daemon.
//!
//! # The plaintext
//!
//! JSON, because it is inspectable: an operator can read what the daemon
//! considers normal without running it. It holds the detector configuration,
//! the sample counter, and every stream's baseline.

use std::fs;
use std::path::{Path, PathBuf};

use heimdall_crypto::aead::{CipherKey, Suite, derive_key, open_with, seal_with};
use heimdall_crypto::kdf::derive_from_passphrase;
use heimdall_crypto::secret::{Secret, random_bytes};
use serde::{Deserialize, Serialize};

use crate::anomaly::{AnomalyEngine, BaselineSnapshot, DetectorConfig};

/// The HKDF label that separates the baseline key from every other key.
pub const BASELINE_KEY_LABEL: &[u8] = b"heimdall/baseline/v1";

const MAGIC: &[u8; 4] = b"HDBL";
const VERSION: u8 = 0x01;
const SALT_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN;

/// What the plaintext holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineFile {
    /// The format version, so an old file is rejected rather than misread.
    version: u8,
    /// The detector configuration the baselines were learned under.
    config: DetectorConfig,
    /// How many samples the engine had seen in total.
    scanned: u64,
    /// Every stream's baseline.
    streams: Vec<BaselineSnapshot>,
}

/// Everything that can go wrong with the baseline file.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The file could not be read or written.
    #[error("i/o error: {0}")]
    Io(String),
    /// The key could not be derived, or the file did not authenticate.
    #[error("the baseline file is not trustworthy: {0}")]
    Untrusted(String),
    /// The file is not a baseline file at all.
    #[error("malformed baseline file: {0}")]
    Malformed(String),
}

/// A sealed file holding the engine's baselines.
#[derive(Debug)]
pub struct BaselineStore {
    path: PathBuf,
    salt: [u8; SALT_LEN],
    key: CipherKey,
}

impl BaselineStore {
    /// Prepares a store for the file at `path`.
    ///
    /// The key is derived from the passphrase and the file's salt, so the
    /// store opens the same file across restarts. The salt is created on the
    /// first call and kept in a sidecar next to it.
    ///
    /// # Errors
    ///
    /// Fails when the key cannot be derived from the passphrase, or when the
    /// sidecar cannot be read or written.
    pub fn open(
        path: impl Into<PathBuf>,
        passphrase: &heimdall_crypto::Passphrase,
    ) -> Result<Self, StoreError> {
        let path = path.into();
        let salt = load_or_create_salt(&salt_sidecar_path(&path))?;
        let master = derive_from_passphrase(passphrase.as_bytes(), &salt)
            .map_err(|e| StoreError::Untrusted(e.to_string()))?;
        let key = derive_key(Suite::ChaCha20Poly1305, &master, BASELINE_KEY_LABEL)
            .map_err(|e| StoreError::Untrusted(e.to_string()))?;
        Ok(Self { path, salt, key })
    }

    /// Where the file lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes the engine's baselines.
    ///
    /// The file is written whole, through a temporary file and a rename, so a
    /// crash halfway through leaves the previous baselines intact rather than a
    /// half-written file that would fail to authenticate on the next start.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be written.
    pub fn save(&self, engine: &AnomalyEngine) -> Result<(), StoreError> {
        let body = BaselineFile {
            version: VERSION,
            config: engine.config(),
            scanned: engine.scanned(),
            streams: engine.snapshots(),
        };
        let plaintext =
            serde_json::to_vec(&body).map_err(|e| StoreError::Malformed(e.to_string()))?;

        // The salt is the additional data, so the ciphertext is bound to the
        // file it belongs to: a file moved to another path with another salt
        // does not authenticate.
        let sealed = seal_with(&self.key, &plaintext, &self.salt)
            .map_err(|e| StoreError::Untrusted(e.to_string()))?;

        // The nonce travels with the ciphertext: `to_bytes` prefixes it, so
        // the reader never has to be told it out of band.
        let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&sealed.to_bytes());

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| StoreError::Io(e.to_string()))?;
        }
        let temporary = self.path.with_extension("tmp");
        fs::write(&temporary, &out).map_err(|e| StoreError::Io(e.to_string()))?;
        fs::rename(&temporary, &self.path).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    /// Reads the baselines back into the engine.
    ///
    /// Returns `false` when there is no file yet, which is the normal state on
    /// a first run rather than a failure.
    ///
    /// # Errors
    ///
    /// Fails when the file exists but does not authenticate, or when it is not
    /// a baseline file. A file that fails is never loaded: the engine keeps
    /// whatever it had, which is empty on a fresh start.
    pub fn load(&self, engine: &mut AnomalyEngine) -> Result<bool, StoreError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(StoreError::Io(e.to_string())),
        };

        if bytes.len() < HEADER_LEN {
            return Err(StoreError::Malformed("the file is too short".into()));
        }
        if &bytes[..4] != MAGIC {
            return Err(StoreError::Malformed("this is not a baseline file".into()));
        }
        let version = bytes[4];
        if version != VERSION {
            return Err(StoreError::Malformed(format!(
                "unsupported baseline version {version}"
            )));
        }
        let salt = &bytes[5..5 + SALT_LEN];
        if salt != self.salt.as_slice() {
            return Err(StoreError::Untrusted(
                "the file was sealed with a different salt".into(),
            ));
        }
        let sealed = heimdall_crypto::aead::Sealed::from_bytes(&bytes[HEADER_LEN..])
            .map_err(|e| StoreError::Malformed(e.to_string()))?;

        let plaintext = open_with(&self.key, &sealed, salt)
            .map_err(|e| StoreError::Untrusted(e.to_string()))?;

        let body: BaselineFile =
            serde_json::from_slice(&plaintext).map_err(|e| StoreError::Malformed(e.to_string()))?;
        if body.version != VERSION {
            return Err(StoreError::Malformed(format!(
                "unsupported baseline version {}",
                body.version
            )));
        }

        engine.restore(body.streams, body.scanned);
        Ok(true)
    }
}

/// The sidecar that holds the salt.
fn salt_sidecar_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".salt");
    PathBuf::from(name)
}

/// Reads the salt, or creates it the first time.
///
/// The salt is written before the file it belongs to, so a store that is
/// opened but never saved still has a stable key: the same passphrase derives
/// the same key next time.
fn load_or_create_salt(path: &Path) -> Result<[u8; SALT_LEN], StoreError> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() != SALT_LEN {
                return Err(StoreError::Malformed(format!(
                    "the salt sidecar must be {SALT_LEN} bytes, found {}",
                    bytes.len()
                )));
            }
            let mut salt = [0_u8; SALT_LEN];
            salt.copy_from_slice(&bytes);
            Ok(salt)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let salt: Secret<SALT_LEN> = random_bytes();
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| StoreError::Io(e.to_string()))?;
            }
            fs::write(path, salt.as_bytes()).map_err(|e| StoreError::Io(e.to_string()))?;
            Ok(*salt.as_bytes())
        }
        Err(e) => Err(StoreError::Io(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passphrase() -> heimdall_crypto::Passphrase {
        heimdall_crypto::Passphrase::from_utf8(b"a test passphrase")
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "heimdall-baseline-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        path
    }

    fn train(engine: &mut AnomalyEngine) {
        for i in 0..200 {
            engine.observe("cpu", 100.0 + f64::from(i % 7));
        }
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(salt_sidecar_path(path));
    }

    #[test]
    fn baselines_survive_a_restart() {
        let path = temp_path("roundtrip");
        cleanup(&path);

        let mut engine = AnomalyEngine::default();
        train(&mut engine);
        let before = engine.snapshots();

        let store = BaselineStore::open(&path, &passphrase()).expect("store");
        store.save(&engine).expect("save");

        // A second store, as a second process would build: the salt comes from
        // the sidecar, so the key is the same.
        let reopened = BaselineStore::open(&path, &passphrase()).expect("store");
        let mut restored = AnomalyEngine::default();
        let loaded = reopened.load(&mut restored).expect("load");
        assert!(loaded, "the file was written, so it must load");
        assert_eq!(restored.snapshots(), before);
        assert_eq!(restored.scanned(), engine.scanned());

        cleanup(&path);
    }

    #[test]
    fn a_missing_file_is_not_a_failure() {
        let path = temp_path("missing");
        cleanup(&path);
        let store = BaselineStore::open(&path, &passphrase()).expect("store");
        let mut engine = AnomalyEngine::default();
        assert!(!store.load(&mut engine).expect("load"));
        cleanup(&path);
    }

    #[test]
    fn a_tampered_file_is_refused() {
        let path = temp_path("tampered");
        cleanup(&path);

        let mut engine = AnomalyEngine::default();
        train(&mut engine);
        let store = BaselineStore::open(&path, &passphrase()).expect("store");
        store.save(&engine).expect("save");

        // Flip a byte in the ciphertext.
        let mut bytes = fs::read(&path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(&path, &bytes).expect("write");

        let mut restored = AnomalyEngine::default();
        let refused = store.load(&mut restored);
        assert!(refused.is_err(), "a tampered file must not load");
        assert!(
            restored.snapshots().is_empty(),
            "a refused file must leave the engine empty"
        );

        cleanup(&path);
    }

    #[test]
    fn a_file_from_another_passphrase_is_refused() {
        let path = temp_path("wrong-key");
        cleanup(&path);

        let mut engine = AnomalyEngine::default();
        train(&mut engine);
        let store = BaselineStore::open(&path, &passphrase()).expect("store");
        store.save(&engine).expect("save");

        // Same salt, different passphrase: the salt is on disk, so the key is
        // the only thing standing between the file and the reader.
        let other = BaselineStore::open(
            &path,
            &heimdall_crypto::Passphrase::from_utf8(b"a different passphrase"),
        )
        .expect("store");
        let mut restored = AnomalyEngine::default();
        assert!(
            other.load(&mut restored).is_err(),
            "a file sealed under another passphrase must not open"
        );

        cleanup(&path);
    }
}
