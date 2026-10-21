//! Who Core is willing to talk to, and how that decision is recorded.
//!
//! # Trust on first use, and what it costs
//!
//! Sentinel publishes its identity to a file in the data directory. Core pins the
//! first value it reads there and refuses to change it silently. That is trust
//! on first use, and it has exactly one meaningful weakness: **if the data
//! directory is writable by an attacker before the first run, they choose
//! Sentinel's identity.** Everything after that first run is protected, because
//! the pin is compared and a mismatch is fatal.
//!
//! The alternative — shipping a certificate authority, a hardware attestation
//! path or an out-of-band exchange — is not something to improvise. So this is
//! implemented as an explicit, auditable TOFU pin with:
//!
//! * the pin file written atomically at `0600`;
//! * the first-seen timestamp recorded, so a re-pin is visible;
//! * an expected value the caller *can* supply, which turns the first run into a
//!   real check when the deployment can supply one;
//! * a mismatch on later runs being a hard error, never a silent re-pin.
//!
//! [`PeerPin::describe`] states the trust basis in words so the UI can show it.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use heimdall_crypto::Identity;
use heimdall_crypto::identity::base_dir;

use crate::error::{Error, Result};

/// Why Core believes this peer is who it claims to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustBasis {
    /// Supplied by configuration or deployment, and verified against the pin.
    Configured,
    /// First run: accepted whatever was on disk. This is the weak case.
    TrustOnFirstUse,
}

impl TrustBasis {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::TrustOnFirstUse => "trust on first use",
        }
    }

    pub const fn is_weak(self) -> bool {
        matches!(self, Self::TrustOnFirstUse)
    }
}

/// A pinned peer identity, as persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPin {
    pub identity: Identity,
    pub role: &'static str,
    pub pinned_at_unix: u64,
    pub basis: TrustBasis,
}

impl PeerPin {
    pub fn describe(&self) -> String {
        format!(
            "{} pinned as {} on {} ({})",
            self.role,
            &self.identity.hex()[..16],
            self.pinned_at_unix,
            self.basis.label()
        )
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(b"HDV3PIN");
        out.push(1); // record version
        out.push(u8::from(self.basis == TrustBasis::Configured));
        out.extend_from_slice(&self.pinned_at_unix.to_be_bytes());
        out.extend_from_slice(&self.identity.verifying_key);
        // Length-prefixed so a malformed file cannot desync the reader.
        out.extend_from_slice(&(self.role.len() as u16).to_be_bytes());
        out.extend_from_slice(self.role.as_bytes());
        out
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        // magic(7) | version(1) | basis(1) | timestamp(8) | key(32) | role_len(2)
        const HEADER: usize = 7 + 1 + 1 + 8 + 32 + 2;
        if buf.len() < HEADER || &buf[..7] != b"HDV3PIN" {
            return Err(Error::Link("not a peer pin file".into()));
        }
        if buf[7] != 1 {
            return Err(Error::Link(format!(
                "unsupported peer pin version {}",
                buf[7]
            )));
        }
        let configured = buf[8] != 0;
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&buf[9..17]);
        let pinned_at_unix = u64::from_be_bytes(ts);
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&buf[17..49]);
        let role_len = u16::from_be_bytes([buf[49], buf[50]]) as usize;
        if buf.len() < HEADER + role_len {
            return Err(Error::Link("truncated peer pin file".into()));
        }
        let role = String::from_utf8_lossy(&buf[HEADER..HEADER + role_len]).to_string();
        let _ = role;
        Ok(Self {
            identity: Identity { verifying_key: vk },
            role: "peer",
            pinned_at_unix,
            basis: if configured {
                TrustBasis::Configured
            } else {
                TrustBasis::TrustOnFirstUse
            },
        })
    }
}

/// Where a pin lives.
#[derive(Debug, Clone)]
pub struct PinLocation {
    path: PathBuf,
}

impl PinLocation {
    /// `<data dir>/peers/<role>.pin`.
    pub fn for_role(role: &str) -> Result<Self> {
        let path = base_dir()?.join("peers").join(format!("{role}.pin"));
        Ok(Self { path })
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

    fn write(&self, pin: &PeerPin) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| Error::Link("pin path has no parent".into()))?;
        std::fs::create_dir_all(parent)?;
        restrict_dir(parent)?;

        let tmp = self
            .path
            .with_extension(format!("tmp.{}", std::process::id()));
        write_restricted(&tmp, &pin.encode())?;
        match std::fs::rename(&tmp, &self.path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(Error::Link(format!(
                    "cannot install peer pin at {}: {e}",
                    self.path.display()
                )))
            }
        }
    }

    /// Loads the pin, creating it on first run.
    ///
    /// `expected` is what the caller believes the peer should be. Supplying it on
    /// the first run converts the pin from trust-on-first-use into a real check.
    /// On later runs, if `expected` is supplied it must match the stored pin.
    pub fn load_or_pin(&self, role: &'static str, expected: Option<&str>) -> Result<PeerPin> {
        let supplied = expected
            .map(|e| {
                Identity::parse_hex(e).map_err(|err| {
                    Error::Link(format!("configured {role} identity is malformed: {err}"))
                })
            })
            .transpose()?;

        let stored = if self.exists() {
            let buf = std::fs::read(&self.path)?;
            let mut pin = PeerPin::decode(&buf)?;
            pin.role = role;
            Some(pin)
        } else {
            None
        };

        match (stored, supplied) {
            (Some(stored_pin), Some(expected_id)) => {
                if !heimdall_crypto::util::ct_eq(
                    stored_pin.identity.verifying_key.as_slice(),
                    expected_id.verifying_key.as_slice(),
                ) {
                    // A changed identity is a hard stop, never a re-pin. This is
                    // the difference between TOFU-with-persistence and TOFU that
                    // silently re-trusts whatever turned up most recently.
                    return Err(Error::Link(format!(
                        "{role} identity does not match the pin recorded on {}: \
                         expected {}, found {}. Refusing to re-pin; if the peer was \
                         deliberately rotated, delete {}.",
                        stored_pin.pinned_at_unix,
                        &expected_id.hex()[..16],
                        &stored_pin.identity.hex()[..16],
                        self.path.display()
                    )));
                }
                Ok(stored_pin)
            }
            (Some(stored_pin), None) => Ok(stored_pin),
            (None, Some(expected_id)) => {
                let pin = PeerPin {
                    identity: expected_id,
                    role,
                    pinned_at_unix: now_unix(),
                    basis: TrustBasis::Configured,
                };
                self.write(&pin)?;
                Ok(pin)
            }
            (None, None) => Err(Error::Link(format!(
                "no peer pin for {role} and no configured identity to create one; \
                 pass the expected identity to bootstrap trust explicitly"
            ))),
        }
    }

    /// Reads the pinned identity without creating anything.
    pub fn read(&self) -> Result<Identity> {
        let buf = std::fs::read(&self.path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                Error::Link(format!("no pin at {}", self.path.display()))
            }
            _ => Error::Link(format!("cannot read {}: {e}", self.path.display())),
        })?;
        Ok(PeerPin::decode(&buf)?.identity)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// A no-op on Windows, where the pin directory inherits the user's ACL.
///
/// Still returns a `Result` so the caller does not need a platform branch; the
/// Windows implementation has nothing to check and nothing to fail at.
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)]
fn restrict_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_restricted(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn write_restricted(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "heimdall-pin-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn loc(&self) -> PinLocation {
            PinLocation::at(self.0.join("peers").join("sentinel.pin"))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_configured_pin_is_recorded_and_reused() {
        let dir = TempDir::new("configured");
        let loc = dir.loc();
        let (signer, id) = heimdall_crypto::Signer::generate();

        let first = loc.load_or_pin("sentinel", Some(&id.hex())).unwrap();
        assert_eq!(first.basis, TrustBasis::Configured);
        assert!(!first.basis.is_weak());

        let second = loc.load_or_pin("sentinel", Some(&id.hex())).unwrap();
        assert_eq!(second.identity, first.identity);
        assert_eq!(second.pinned_at_unix, first.pinned_at_unix);
        let _ = signer;
    }

    #[test]
    fn a_changed_identity_is_a_hard_error_not_a_re_pin() {
        let dir = TempDir::new("changed");
        let loc = dir.loc();
        let (_, first) = heimdall_crypto::Signer::generate();
        loc.load_or_pin("sentinel", Some(&first.hex())).unwrap();

        let (_, rotated) = heimdall_crypto::Signer::generate();
        let err = loc
            .load_or_pin("sentinel", Some(&rotated.hex()))
            .unwrap_err();
        assert!(
            matches!(err, Error::Link(ref m) if m.contains("Refusing to re-pin")),
            "{err:?}"
        );
        // The original pin must survive the failed attempt.
        assert_eq!(loc.read().unwrap(), first);
    }

    #[test]
    fn the_first_run_without_a_configured_identity_is_marked_weak() {
        let dir = TempDir::new("tofu");
        let loc = dir.loc();
        let (signer, id) = heimdall_crypto::Signer::generate();

        // Seed a pin directly to model "someone else ran first".
        let pin = PeerPin {
            identity: id.clone(),
            role: "sentinel",
            pinned_at_unix: 1,
            basis: TrustBasis::TrustOnFirstUse,
        };
        loc.write(&pin).unwrap();

        let loaded = loc.load_or_pin("sentinel", None).unwrap();
        assert_eq!(loaded.identity, id);
        assert_eq!(loaded.basis, TrustBasis::TrustOnFirstUse);
        assert!(loaded.basis.is_weak());
        assert!(loaded.describe().contains("trust on first use"));
        let _ = signer;
    }

    #[test]
    fn first_run_with_nothing_configured_is_refused() {
        let dir = TempDir::new("nothing");
        let loc = dir.loc();
        let err = loc.load_or_pin("sentinel", None).unwrap_err();
        assert!(
            matches!(err, Error::Link(ref m) if m.contains("no peer pin")),
            "{err:?}"
        );
        assert!(!loc.exists(), "nothing should have been written");
    }

    #[test]
    fn a_malformed_configured_identity_is_refused() {
        let dir = TempDir::new("malformed");
        let loc = dir.loc();
        let err = loc.load_or_pin("sentinel", Some("not-hex")).unwrap_err();
        assert!(matches!(err, Error::Link(_)), "{err:?}");
    }

    #[test]
    fn a_corrupt_pin_file_is_refused() {
        let dir = TempDir::new("corrupt");
        let loc = dir.loc();
        let (_, id) = heimdall_crypto::Signer::generate();
        loc.load_or_pin("sentinel", Some(&id.hex())).unwrap();

        let good = std::fs::read(loc.path()).unwrap();
        for n in [0usize, 3, 7, 20, good.len() - 1] {
            std::fs::write(loc.path(), &good[..n]).unwrap();
            assert!(
                loc.read().is_err(),
                "a pin truncated to {n} bytes must not be accepted"
            );
        }
    }

    #[test]
    fn a_pin_with_a_flipped_identity_byte_is_detected() {
        let dir = TempDir::new("flip");
        let loc = dir.loc();
        let (_, id) = heimdall_crypto::Signer::generate();
        loc.load_or_pin("sentinel", Some(&id.hex())).unwrap();

        let mut bytes = std::fs::read(loc.path()).unwrap();
        bytes[20] ^= 0x01;
        std::fs::write(loc.path(), &bytes).unwrap();

        // The pin now names a different identity; supplying the real one must fail.
        let err = loc.load_or_pin("sentinel", Some(&id.hex())).unwrap_err();
        assert!(
            matches!(err, Error::Link(ref m) if m.contains("Refusing to re-pin")),
            "{err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_pin_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("perms");
        let loc = dir.loc();
        let (_, id) = heimdall_crypto::Signer::generate();
        loc.load_or_pin("sentinel", Some(&id.hex())).unwrap();

        let mode = std::fs::metadata(loc.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "pin mode was {mode:o}");
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let (_, id) = heimdall_crypto::Signer::generate();
        let pin = PeerPin {
            identity: id,
            role: "sentinel",
            pinned_at_unix: 0xDEAD_BEEF_CAFE,
            basis: TrustBasis::Configured,
        };
        let decoded = PeerPin::decode(&pin.encode()).unwrap();
        assert_eq!(decoded.identity, pin.identity);
        assert_eq!(decoded.pinned_at_unix, pin.pinned_at_unix);
        assert_eq!(decoded.basis, pin.basis);
    }
}
