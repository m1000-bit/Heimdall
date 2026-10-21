use crate::{
    error::{Error, Result},
    secret::{Key32, Secret},
};
use zeroize::{Zeroize as _, Zeroizing};

/// Argon2id parameters for the keystore master key.
///
/// These are the RFC 9106 second-recommended options: 2 GiB of memory is
/// unreachable on the constrained hosts Sentinel may run on, so Heimdall uses
/// 64 MiB / 3 passes / 4 lanes, which is still far above any offline-guessing
/// budget for a randomly generated 256-bit passphrase.
pub mod argon2_params {
    pub const MEMORY_KIB: u32 = 64 * 1024;
    pub const ITERATIONS: u32 = 3;
    pub const PARALLELISM: u32 = 4;
    pub const OUTPUT_LEN: usize = 32;
    pub const SALT_LEN: usize = 16;
}

/// HKDF-SHA256 for expanding an already-high-entropy secret (e.g. an X25519
/// shared secret) into purpose-bound subkeys.
pub fn hkdf_expand(
    secret: &[u8],
    salt: &[u8],
    label: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), secret);
    let mut out = vec![0u8; out_len];
    hk.expand(label, &mut out)
        .map_err(|_| Error::KeyDerivation("HKDF expand failed".into()))?;
    Ok(Zeroizing::new(out))
}

/// Stretches a user passphrase into a 256-bit master key with Argon2id.
pub fn derive_from_passphrase(
    passphrase: &[u8],
    salt: &[u8; argon2_params::SALT_LEN],
) -> Result<Key32> {
    let params = argon2::Params::new(
        argon2_params::MEMORY_KIB,
        argon2_params::ITERATIONS,
        argon2_params::PARALLELISM,
        Some(argon2_params::OUTPUT_LEN),
    )
    .map_err(|e| Error::KeyDerivation(e.to_string()))?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut okm = Zeroizing::new([0u8; argon2_params::OUTPUT_LEN]);
    argon2
        .hash_password_into(passphrase, salt, okm.as_mut())
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;

    Ok(Key32::new(&okm[..]))
}

/// Verifies a passphrase against a stored verifier without decrypting anything.
///
/// Equalising the derivation cost with a full AEAD open means the check leaks
/// no more timing information than the unlock path itself already does.
pub fn verify_passphrase(
    passphrase: &[u8],
    salt: &[u8; argon2_params::SALT_LEN],
    expected: &Key32,
) -> Result<bool> {
    let candidate = derive_from_passphrase(passphrase, salt)?;
    Ok(candidate.ct_eq(expected))
}

/// Rejects passphrases that would make Argon2id pointless.
///
/// The estimate is `length * log2(alphabet)`, where the alphabet is the set of
/// classes actually used. A short passphrase is capped regardless, so a long
/// tail of one repeated character cannot reach an acceptable score.
pub fn passphrase_strength(passphrase: &str) -> Strength {
    let lower = passphrase.chars().any(|c| c.is_ascii_lowercase());
    let upper = passphrase.chars().any(|c| c.is_ascii_uppercase());
    let digit = passphrase.chars().any(|c| c.is_ascii_digit());
    let symbol = passphrase.chars().any(|c| !c.is_ascii_alphanumeric());

    // log2 of the resulting alphabet, tabulated rather than computed: these are
    // exact known constants and a `log2` call would be a needless dependency.
    let classes = u8::from(lower) + u8::from(upper) + u8::from(digit) + u8::from(symbol);
    let bits_per_char = [
        0.0, 4.70, // 26 lowercase
        5.09, // + 26 uppercase (52)
        5.95, // + 10 digits (62)
        6.57, // + 33 symbols (95)
    ][usize::from(classes)];

    let mut bits =
        f64::from(u32::try_from(passphrase.chars().count()).unwrap_or(u32::MAX)) * bits_per_char;

    // Distinctness matters more than length: "aaaaaaaaaaaaaaaa" is 64 bits by
    // length alone but is the first thing any dictionary tries.
    let distinct = passphrase
        .chars()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if distinct * 3 < passphrase.chars().count() {
        bits *= 0.4;
    }

    // Hard ceiling for short passphrases, independent of alphabet size.
    if passphrase.chars().count() < 12 {
        bits = bits.min(60.0);
    }
    if distinct < 8 {
        bits = bits.min(70.0);
    }

    match bits {
        b if b < 60.0 => Strength::TooWeak,
        b if b < 80.0 => Strength::Weak,
        b if b < 100.0 => Strength::Fair,
        _ => Strength::Strong,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    TooWeak,
    Weak,
    Fair,
    Strong,
}

impl Strength {
    pub const fn label(self) -> &'static str {
        match self {
            Self::TooWeak => "too weak",
            Self::Weak => "weak",
            Self::Fair => "fair",
            Self::Strong => "strong",
        }
    }

    pub const fn accepted(self) -> bool {
        matches!(self, Self::Fair | Self::Strong)
    }
}

/// Wraps a passphrase so it is scrubbed from memory once the key is derived.
pub struct Passphrase(Secret<256>);

impl Passphrase {
    /// # Panics
    /// Panics if `bytes.len() > 256`.
    pub fn from_utf8(bytes: &[u8]) -> Self {
        assert!(bytes.len() <= 256, "passphrase longer than 256 bytes");
        let mut buf = [0u8; 256];
        buf[..bytes.len()].copy_from_slice(bytes);
        let s = Secret::new(&buf);
        buf.zeroize();
        Self(s)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl core::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The environment variable the keystore passphrase is read from.
pub const PASSPHRASE_ENV: &str = "HEIMDALL_KEYSTORE_PASSPHRASE";

/// The passphrase used when nothing else provides one.
///
/// Development only, and it says so: a deployment that forgets to set a
/// passphrase gets a keystore anyone can open.
pub const DEVELOPMENT_PASSPHRASE: &str = "heimdall-development";

/// Reads the passphrase from the environment.
///
/// The order is the environment variable, then a systemd credential
/// (`$CREDENTIALS_DIRECTORY/passphrase`), then the development default. The
/// credential is the better choice on a system where every process can read
/// another's environment: the file is owned by root, unreadable by others, and
/// handed to this service alone.
#[must_use]
pub fn passphrase_from_environment() -> Passphrase {
    let from_env = std::env::var(PASSPHRASE_ENV).ok().filter(|v| !v.is_empty());
    let credential = std::env::var("CREDENTIALS_DIRECTORY")
        .ok()
        .filter(|d| !d.is_empty())
        .and_then(|dir| std::fs::read(std::path::Path::new(&dir).join("passphrase")).ok());
    choose_passphrase(from_env.as_deref(), credential.as_deref())
}

/// Picks the passphrase from what the environment offers.
///
/// Split out from [`passphrase_from_environment`] so the choice can be tested
/// without touching the environment of the test process.
fn choose_passphrase(from_env: Option<&str>, credential: Option<&[u8]>) -> Passphrase {
    if let Some(value) = from_env
        && !value.is_empty()
    {
        return Passphrase::from_utf8(value.as_bytes());
    }
    if let Some(bytes) = credential {
        let text = String::from_utf8_lossy(bytes);
        let text = text.trim_end_matches(['\r', '\n']);
        if !text.is_empty() {
            return Passphrase::from_utf8(text.as_bytes());
        }
    }
    Passphrase::from_utf8(DEVELOPMENT_PASSPHRASE.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_is_deterministic_and_salt_sensitive() {
        let salt = [7u8; argon2_params::SALT_LEN];
        let a = derive_from_passphrase(b"correct horse battery staple", &salt).unwrap();
        let b = derive_from_passphrase(b"correct horse battery staple", &salt).unwrap();
        let c = derive_from_passphrase(b"correct horse battery staple", &[8u8; 16]).unwrap();
        let d = derive_from_passphrase(b"wrong horse battery staple", &salt).unwrap();

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert!(!a.ct_eq(&d));
    }

    #[test]
    fn verify_passphrase_accepts_only_the_right_secret() {
        let salt = [1u8; argon2_params::SALT_LEN];
        let k = derive_from_passphrase(b"s3cret-passphrase", &salt).unwrap();
        assert!(verify_passphrase(b"s3cret-passphrase", &salt, &k).unwrap());
        assert!(!verify_passphrase(b"s3cret-passphras", &salt, &k).unwrap());
    }

    #[test]
    fn hkdf_expand_is_deterministic_and_label_bound() {
        let a = hkdf_expand(b"master", b"salt", b"label-a", 32).unwrap();
        let a2 = hkdf_expand(b"master", b"salt", b"label-a", 32).unwrap();
        let b = hkdf_expand(b"master", b"salt", b"label-b", 32).unwrap();
        assert_eq!(&a[..], &a2[..]);
        assert_ne!(&a[..], &b[..]);
    }

    #[test]
    fn passphrase_strength_rejects_weak_secrets() {
        assert_eq!(passphrase_strength("password"), Strength::TooWeak);
        assert_eq!(passphrase_strength("123456789012"), Strength::TooWeak);
        assert!(!passphrase_strength("hunter2").accepted());
        assert!(passphrase_strength("Tr0ub4dor&3xKcd!").accepted());
    }

    #[test]
    fn the_passphrase_comes_from_the_environment_first() {
        let p = choose_passphrase(Some("from-the-variable"), Some(b"from-the-credential\n"));
        assert_eq!(
            &p.as_bytes()[.."from-the-variable".len()],
            b"from-the-variable"
        );
    }

    #[test]
    fn a_credential_is_used_when_the_variable_is_absent() {
        let p = choose_passphrase(None, Some(b"from-the-credential\n"));
        assert_eq!(
            &p.as_bytes()[.."from-the-credential".len()],
            b"from-the-credential"
        );
    }

    #[test]
    fn the_development_passphrase_is_the_last_resort() {
        let p = choose_passphrase(None, None);
        assert_eq!(
            &p.as_bytes()[..DEVELOPMENT_PASSPHRASE.len()],
            DEVELOPMENT_PASSPHRASE.as_bytes()
        );

        // An empty credential file is not a passphrase.
        let p = choose_passphrase(None, Some(b"\n"));
        assert_eq!(
            &p.as_bytes()[..DEVELOPMENT_PASSPHRASE.len()],
            DEVELOPMENT_PASSPHRASE.as_bytes()
        );
    }

    #[test]
    fn passphrase_wrapper_scrubs_its_buffer() {
        let raw = b"temporary buffer contents";
        let p = Passphrase::from_utf8(raw);
        assert_eq!(&p.as_bytes()[..raw.len()], raw);
        assert!(
            p.as_bytes()[raw.len()..].iter().all(|&b| b == 0),
            "unused tail must be zeroed, not left as heap residue"
        );
    }
}
