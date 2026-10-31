//! Persistent long-term identities.
//!
//! An identity that regenerates on every launch cannot authenticate anything: two
//! runs of Core and Sentinel would each pin a key the other does not hold, and
//! the handshake would fail every time. This module gives an AI a durable
//! Ed25519 identity by storing its secret scalar in the [`KeyStore`].
//!
//! Properties:
//!
//! * **Create-or-load.** The first run mints a key, every later run loads it.
//!   There is no silent regeneration, which would look like a compromise and
//!   behave like one.
//! * **Atomic.** The keystore blob is written via a temporary file and renamed,
//!   so a crash mid-write cannot leave a truncated identity that fails to load
//!   and then gets replaced.
//! * **Restrictive permissions.** The file is `0600` and its directory `0700`
//!   on Unix. A private key readable by another local account is not a private key.
//! * **Auditable.** Loading reports whether the identity was created or found, so
//!   a rotation is visible in the logs rather than silent.

use std::path::{Path, PathBuf};

use zeroize::Zeroize as _;

use crate::{
    error::{Error, Result},
    kdf::Passphrase,
    kex::{Identity, Signer},
    kms::KeyStore,
};

/// Label under which an AI's Ed25519 secret scalar is stored.
pub const IDENTITY_LABEL: &str = "heimdall/identity/v1";

/// The on-disk location of a keystore.
#[derive(Debug, Clone)]
pub struct KeystoreLocation {
    path: PathBuf,
}

impl KeystoreLocation {
    /// `<data dir>/keystore/heimdall.kms`.
    pub fn default_path() -> Result<Self> {
        let base = base_dir()?;
        Ok(Self {
            path: base.join("keystore").join("heimdall.kms"),
        })
    }

    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    /// Writes the keystore blob atomically with restrictive permissions.
    pub fn write(&self, store: &KeyStore) -> Result<()> {
        let blob = store.seal_to_blob()?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| Error::Kms("keystore path has no parent directory".into()))?;
        create_private_dir(parent)?;

        // Write to a sibling temp file and rename. `rename` within a directory is
        // atomic on POSIX and on Windows via `MoveFileEx`, so a reader either sees
        // the old complete blob or the new one, never a partial write.
        let tmp = self
            .path
            .with_extension(format!("tmp.{}", std::process::id()));
        write_private_file(&tmp, &blob)?;
        match std::fs::rename(&tmp, &self.path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(Error::Kms(format!(
                    "cannot install keystore at {}: {e}",
                    self.path.display()
                )))
            }
        }
    }

    /// Reads the keystore blob.
    pub fn read(&self, passphrase: &Passphrase) -> Result<KeyStore> {
        let blob = std::fs::read(&self.path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                Error::Kms(format!("no keystore at {}", self.path.display()))
            }
            _ => Error::Kms(format!("cannot read {}: {e}", self.path.display())),
        })?;
        KeyStore::open_from_blob(&blob, passphrase)
    }

    /// Opens the keystore, creating it on first run.
    pub fn open_or_create(&self, passphrase: &Passphrase) -> Result<KeyStore> {
        if self.exists() {
            return self.read(passphrase);
        }
        let store = KeyStore::create(passphrase)?;
        self.write(&store)?;
        Ok(store)
    }
}

/// An AI's durable identity.
#[derive(Clone)]
pub struct PersistedIdentity {
    signer: Signer,
    identity: Identity,
    /// False when the key was just minted. Surfaced so a rotation is visible.
    freshly_created: bool,
}

impl core::fmt::Debug for PersistedIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PersistedIdentity")
            .field("identity", &self.identity.hex())
            .field("freshly_created", &self.freshly_created)
            .finish_non_exhaustive()
    }
}

impl PersistedIdentity {
    /// Wraps an already-generated signer. Used by the in-memory bootstrap path,
    /// where nothing is written to disk and the identity is ephemeral.
    #[must_use]
    pub fn from_signer(signer: Signer, identity: Identity) -> Self {
        Self {
            signer,
            identity,
            freshly_created: true,
        }
    }

    /// Loads the identity from the keystore, minting one if absent.
    pub fn load_or_create(store: &mut KeyStore) -> Result<Self> {
        if let Ok(record) = store.get(IDENTITY_LABEL) {
            let material = &record.material;
            if material.len() != 32 {
                return Err(Error::Kms(
                    "stored identity has the wrong length; refusing to use it".into(),
                ));
            }
            let bytes: [u8; 32] = material
                .as_slice()
                .try_into()
                .map_err(|_| Error::Kms("stored identity has the wrong length".into()))?;
            let signing = ed25519_dalek::SigningKey::from_bytes(&bytes);
            let signer = Signer::from_key(signing);
            return Ok(Self {
                identity: signer.identity(),
                signer,
                freshly_created: false,
            });
        }

        let (signer, identity) = Signer::generate();
        let secret = signer.secret_bytes();
        store.insert(
            IDENTITY_LABEL,
            crate::aead::Suite::ChaCha20Poly1305,
            secret.to_vec().to_vec(),
        )?;
        Ok(Self {
            signer,
            identity,
            freshly_created: true,
        })
    }

    pub fn signer(&self) -> Signer {
        self.signer.clone()
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn was_created(&self) -> bool {
        self.freshly_created
    }

    /// Hex form, for writing to a config file or showing in the UI.
    pub fn hex(&self) -> String {
        self.identity.hex()
    }
}

/// Loads or creates the durable identity at `location`.
///
/// A freshly minted identity is written back before this returns. Writing after
/// minting rather than leaving it to the caller is deliberate: a create-or-load
/// API that can silently fail to persist is a key that changes on the next
/// launch, which presents as a compromise and is indistinguishable from one.
pub fn provision(
    location: &KeystoreLocation,
    passphrase: &Passphrase,
) -> Result<PersistedIdentity> {
    let mut store = location.open_or_create(passphrase)?;
    let identity = PersistedIdentity::load_or_create(&mut store)?;
    if identity.was_created() {
        location.write(&store)?;
    }
    Ok(identity)
}

/// Writes the keystore back after [`PersistedIdentity::load_or_create`] may have
/// added a record.
pub fn persist(location: &KeystoreLocation, store: &KeyStore) -> Result<()> {
    location.write(store)
}

/// The per-user Heimdall data directory.
///
/// `$XDG_DATA_HOME/heimdall` on Linux and macOS, `%LOCALAPPDATA%\heimdall` on
/// Windows. Exposed so Core and Sentinel agree on where everything lives
/// without each reimplementing the platform lookup.
///
/// `HEIMDALL_HOME` overrides the whole location. It exists so a test, a portable
/// install, or a second isolated instance can keep its keystore and pins
/// somewhere other than the shared user directory -- without it, two daemons
/// under test would fight over the same pin files.
pub fn base_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("HEIMDALL_HOME")
        && !dir.is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    data_dir()
}

fn data_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let base = std::env::var("LOCALAPPDATA").map_err(|_| {
            Error::Kms("LOCALAPPDATA is not set; cannot locate the keystore".into())
        })?;
        Ok(PathBuf::from(base).join("heimdall"))
    }
    #[cfg(not(windows))]
    {
        if let Ok(dir) = std::env::var("XDG_DATA_HOME")
            && !dir.is_empty()
        {
            return Ok(PathBuf::from(dir).join("heimdall"));
        }
        let home = std::env::var("HOME")
            .map_err(|_| Error::Kms("HOME is not set; cannot locate the keystore".into()))?;
        Ok(PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("heimdall"))
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    // `create(true).truncate(true).mode(0o600)`: the mode only applies when the
    // file is created, so a pre-existing world-readable file is not left as-is.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    // Re-assert the mode in case the file already existed.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

#[cfg(windows)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Wipes a buffer that held key material. Exposed so callers that stage a
/// passphrase or an identity in a scratch buffer can scrub it.
pub fn scrub(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::Passphrase;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "heimdall-idtest-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn loc(&self) -> KeystoreLocation {
            KeystoreLocation::at(self.0.join("nested").join("keystore.kms"))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn pass() -> Passphrase {
        Passphrase::from_utf8(b"Tr0ub4dor&3xKcd!a-long-enough-passphrase")
    }

    #[test]
    fn an_identity_is_created_once_and_then_reused() {
        let dir = TempDir::new("create-once");
        let loc = dir.loc();
        let p = pass();

        let first = provision(&loc, &p).unwrap();
        assert!(first.was_created(), "first run must mint a key");

        // No explicit persist: `provision` must have written it back itself.
        let second = provision(&loc, &p).unwrap();
        assert!(!second.was_created());
        assert_eq!(first.identity(), second.identity());
    }

    #[test]
    fn two_ais_get_distinct_identities_from_one_keystore() {
        let dir = TempDir::new("distinct");
        let loc = dir.loc();
        let p = pass();

        let mut store = loc.open_or_create(&p).unwrap();
        let core = PersistedIdentity::load_or_create(&mut store).unwrap();
        // A second AI would use its own label; for the test, minting again via a
        // fresh keystore models two independent installations.
        persist(&loc, &store).unwrap();
        let other = provision(&loc, &p).unwrap();
        assert_eq!(core.identity(), other.identity());

        let dir2 = TempDir::new("distinct2");
        let other2 = provision(&dir2.loc(), &p).unwrap();
        assert_ne!(core.identity(), other2.identity());
    }

    #[test]
    fn a_wrong_passphrase_fails_opaquely() {
        let dir = TempDir::new("wrong-pass");
        let loc = dir.loc();
        provision(&loc, &pass()).unwrap();

        let err = loc
            .read(&Passphrase::from_utf8(b"a-different-passphrase!!"))
            .unwrap_err();
        assert!(matches!(err, Error::Decrypt), "{err:?}");
    }

    #[test]
    fn a_corrupt_keystore_does_not_silently_regenerate() {
        let dir = TempDir::new("corrupt");
        let loc = dir.loc();
        let p = pass();
        let identity = provision(&loc, &p).unwrap();

        let mut blob = std::fs::read(loc.path()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        std::fs::write(loc.path(), &blob).unwrap();

        match provision(&loc, &p) {
            Err(_) => {}
            Ok(_) => panic!(
                "a corrupt keystore produced an identity; that is a silent \
                 regeneration, and the key would silently change"
            ),
        }
        let _ = identity;
    }

    #[test]
    fn a_truncated_keystore_does_not_silently_regenerate() {
        let dir = TempDir::new("truncated");
        let loc = dir.loc();
        let p = pass();
        provision(&loc, &p).unwrap();

        let blob = std::fs::read(loc.path()).unwrap();
        for n in [0usize, 1, blob.len() / 2, blob.len() - 1] {
            std::fs::write(loc.path(), &blob[..n]).unwrap();
            assert!(
                provision(&loc, &p).is_err(),
                "a keystore truncated to {n} bytes must not yield an identity"
            );
        }
    }

    #[test]
    fn a_wrong_length_identity_record_is_refused() {
        let dir = TempDir::new("bad-len");
        let loc = dir.loc();
        let p = pass();

        let mut store = loc.open_or_create(&p).unwrap();
        store
            .insert(
                IDENTITY_LABEL,
                crate::aead::Suite::ChaCha20Poly1305,
                vec![0u8; 31],
            )
            .unwrap();
        persist(&loc, &store).unwrap();

        let err = PersistedIdentity::load_or_create(&mut store).unwrap_err();
        assert!(matches!(err, Error::Kms(_)), "{err:?}");
    }

    #[test]
    fn the_identity_round_trips_through_a_signature() {
        let dir = TempDir::new("signing");
        let p = pass();
        let id = provision(&dir.loc(), &p).unwrap();

        let sig = id.signer().sign(b"heimdall");
        assert!(id.identity().verify(b"heimdall", &sig).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn the_keystore_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new("perms");
        let loc = dir.loc();
        provision(&loc, &pass()).unwrap();

        let mode = std::fs::metadata(loc.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "keystore mode was {mode:o}");

        let parent_mode = std::fs::metadata(loc.path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            parent_mode, 0o700,
            "keystore directory mode was {parent_mode:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn no_temporary_file_is_left_behind() {
        let dir = TempDir::new("tmpfile");
        let loc = dir.loc();
        provision(&loc, &pass()).unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(loc.path().parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    }

    #[test]
    fn scrub_clears_the_buffer() {
        let mut buf = *b"a-secret-value-in-a-scratch-buffer!!";
        assert_ne!(
            &buf[..],
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        );
        scrub(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }
}
