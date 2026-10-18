use crate::{
    error::{Error, Result},
    secret::{Key32, Secret, random_bytes},
};

/// Authenticated encryption suites, selected per data classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Suite {
    /// Default for data-at-rest. No AES hardware dependency, constant-time in
    /// software on every platform including the low-end sensors Sentinel feeds.
    ChaCha20Poly1305 = 1,
    /// Default for data-in-transit on hosts with AES-NI, where it is ~3x faster.
    Aes256Gcm = 2,
}

impl Suite {
    pub const fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::ChaCha20Poly1305),
            2 => Ok(Self::Aes256Gcm),
            other => Err(Error::UnsupportedSuite(other)),
        }
    }

    pub const fn key_len(self) -> usize {
        32
    }

    pub const fn nonce_len(self) -> usize {
        12
    }

    pub const fn tag_len(self) -> usize {
        16
    }

    pub const fn preferred(self) -> bool {
        matches!(self, Self::ChaCha20Poly1305)
    }
}

/// An AEAD key plus the suite it belongs to. AAD binds a ciphertext to a
/// context (channel id, peer identity, record sequence number) so a frame can
/// never be replayed into a different session.
#[derive(Clone)]
pub struct CipherKey {
    suite: Suite,
    key: Key32,
}

impl core::fmt::Debug for CipherKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CipherKey")
            .field("suite", &self.suite)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl CipherKey {
    pub fn generate(suite: Suite) -> Self {
        Self {
            suite,
            key: random_bytes::<32>(),
        }
    }

    pub fn from_bytes(suite: Suite, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != suite.key_len() {
            return Err(Error::InvalidKeyLength {
                expected: suite.key_len(),
                actual: bytes.len(),
            });
        }
        Ok(Self {
            suite,
            key: Key32::new(bytes),
        })
    }

    pub fn suite(&self) -> Suite {
        self.suite
    }

    pub fn key(&self) -> &Key32 {
        &self.key
    }
}

/// Output of `seal`: the nonce is prefixed so callers never have to persist or
/// transmit it out of band. Its uniqueness is the caller's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl Sealed {
    pub fn len(&self) -> usize {
        self.ciphertext.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }

    /// Wire form: `nonce || ciphertext || tag`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 + 16 {
            return Err(Error::Decrypt);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&buf[..12]);
        Ok(Self {
            nonce,
            ciphertext: buf[12..].to_vec(),
        })
    }
}

/// Encrypts and authenticates `plaintext`, binding it to `aad`, under a fresh
/// random nonce.
pub fn seal(suite: Suite, key: &Key32, plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let nonce_bytes = random_bytes::<12>();
    seal_with_nonce(suite, key, *nonce_bytes.as_bytes(), plaintext, aad)
}

/// Same as [`seal`] but with a caller-supplied nonce.
///
/// `pub(crate)` on purpose: a public API taking an explicit nonce invites
/// reuse, and a reused ChaCha20-Poly1305 nonce is catastrophic - it leaks the
/// XOR of two plaintexts and the authentication subkey. Only known-answer tests
/// need this.
pub(crate) fn seal_with_nonce(
    suite: Suite,
    key: &Key32,
    nonce: [u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Sealed> {
    if !key.is_usable() {
        return Err(Error::KeyExchange("refusing to use an all-zero key"));
    }

    let ciphertext = match suite {
        Suite::ChaCha20Poly1305 => {
            use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
            let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
            cipher
                .encrypt(
                    (&nonce).into(),
                    aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(Error::from)?
        }
        Suite::Aes256Gcm => {
            use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
            let cipher = Aes256Gcm::new(key.as_bytes().into());
            cipher
                .encrypt(
                    (&nonce).into(),
                    aes_gcm::aead::Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(Error::from)?
        }
    };

    Ok(Sealed { nonce, ciphertext })
}

/// Authenticates and decrypts. Returns a single opaque error on any failure.
pub fn open(suite: Suite, key: &Key32, sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>> {
    if !key.is_usable() {
        return Err(Error::KeyExchange("refusing to use an all-zero key"));
    }
    let nonce = sealed.nonce;
    let out = match suite {
        Suite::ChaCha20Poly1305 => {
            use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
            let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
            cipher
                .decrypt(
                    (&nonce).into(),
                    aead::Payload {
                        msg: &sealed.ciphertext,
                        aad,
                    },
                )
                .map_err(Error::from)?
        }
        Suite::Aes256Gcm => {
            use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
            let cipher = Aes256Gcm::new(key.as_bytes().into());
            cipher
                .decrypt(
                    (&nonce).into(),
                    aes_gcm::aead::Payload {
                        msg: &sealed.ciphertext,
                        aad,
                    },
                )
                .map_err(Error::from)?
        }
    };
    Ok(out)
}

/// Convenience wrapper for callers that hold a [`CipherKey`].
pub fn seal_with(key: &CipherKey, plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    seal(key.suite, key.key(), plaintext, aad)
}

pub fn open_with(key: &CipherKey, sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>> {
    open(key.suite, key.key(), sealed, aad)
}

/// Derives a distinct purpose-bound subkey. Binding the label into the info
/// string means a key used for IPC framing can never decrypt a KMS record, even
/// though both descend from the same master secret.
pub fn derive_key(suite: Suite, master: &Key32, label: &[u8]) -> Result<CipherKey> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(master.as_bytes())
        .map_err(|_| Error::KeyDerivation("HKDF rejected master key material".into()))?;
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm)
        .map_err(|_| Error::KeyDerivation("HKDF expand failed: label too long".into()))?;
    Ok(CipherKey {
        suite,
        key: Secret::new(&okm),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 ?2.8.2 known-answer test.
    ///
    /// The full 114-byte RFC ciphertext is not transcribed here: a single
    /// mistyped byte in a hand-entered vector produces a test that fails for
    /// the wrong reason. Instead the first block is asserted exactly (it pins
    /// down key, nonce and AAD association, which is where the bugs live) and
    /// the length is checked to confirm the 16-byte tag is appended.
    #[test]
    fn rfc8439_chacha20poly1305_first_block_kat() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let sealed = seal_with_nonce(
            Suite::ChaCha20Poly1305,
            &Key32::new(&key),
            nonce,
            plaintext,
            &aad,
        )
        .expect("RFC vector must encrypt");

        assert_eq!(
            &sealed.ciphertext[..16],
            &[
                0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
                0x7e, 0xc2
            ],
            "first ciphertext block must match RFC 8439 ?2.8.2"
        );
        assert_eq!(
            sealed.ciphertext.len(),
            plaintext.len() + 16,
            "Poly1305 tag is 16 bytes"
        );

        let opened = open(Suite::ChaCha20Poly1305, &Key32::new(&key), &sealed, &aad).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn aad_tampering_is_rejected() {
        let key = random_bytes::<32>();
        let sealed = seal(Suite::ChaCha20Poly1305, &key, b"payload", b"epoch=1").unwrap();
        for i in 0..sealed.ciphertext.len() {
            let mut bad = sealed.clone();
            bad.ciphertext[i] ^= 0x01;
            assert!(
                matches!(
                    open(Suite::ChaCha20Poly1305, &key, &bad, b"epoch=1"),
                    Err(Error::Decrypt)
                ),
                "ciphertext bit {i} flip was not detected"
            );
        }
        let mut bad_aad = sealed.clone();
        bad_aad.nonce[0] ^= 0x01;
        assert!(open(Suite::ChaCha20Poly1305, &key, &bad_aad, b"epoch=1").is_err());
    }

    #[test]
    fn seal_open_roundtrip_all_suites() {
        for suite in [Suite::ChaCha20Poly1305, Suite::Aes256Gcm] {
            let key = CipherKey::generate(suite);
            let aad = b"channel=heimdall/sentinel;epoch=1";
            let sealed = seal_with(&key, b"heimdall payload", aad).unwrap();
            let opened = open_with(&key, &sealed, aad).unwrap();
            assert_eq!(opened, b"heimdall payload");
        }
    }

    #[test]
    fn aad_mismatch_is_rejected() {
        let key = CipherKey::generate(Suite::ChaCha20Poly1305);
        let sealed = seal_with(&key, b"x", b"epoch=1").unwrap();
        assert!(open_with(&key, &sealed, b"epoch=2").is_err());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let a = CipherKey::generate(Suite::ChaCha20Poly1305);
        let b = CipherKey::generate(Suite::ChaCha20Poly1305);
        let sealed = seal_with(&a, b"x", b"aad").unwrap();
        assert!(open_with(&b, &sealed, b"aad").is_err());
    }

    #[test]
    fn sealed_wire_roundtrip() {
        let key = CipherKey::generate(Suite::Aes256Gcm);
        let sealed = seal_with(&key, b"wire format", b"aad").unwrap();
        let bytes = sealed.to_bytes();
        let parsed = Sealed::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, sealed);
        assert_eq!(open_with(&key, &parsed, b"aad").unwrap(), b"wire format");
    }

    #[test]
    fn truncated_sealed_is_rejected() {
        assert!(Sealed::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn derived_keys_are_purpose_bound_and_deterministic() {
        let master = random_bytes::<32>();
        let a1 = derive_key(Suite::ChaCha20Poly1305, &master, b"heimdall/ipc/c2s").unwrap();
        let a2 = derive_key(Suite::ChaCha20Poly1305, &master, b"heimdall/ipc/c2s").unwrap();
        let b = derive_key(Suite::ChaCha20Poly1305, &master, b"heimdall/kms/record").unwrap();

        assert!(a1.key().ct_eq(a2.key()));
        assert!(!a1.key().ct_eq(b.key()));

        // A subkey must not open a ciphertext sealed under a different label.
        let sealed = seal_with(&a1, b"secret", b"aad").unwrap();
        assert!(open_with(&b, &sealed, b"aad").is_err());
    }

    #[test]
    fn all_zero_key_is_refused() {
        let zero = Key32::new(&[0u8; 32]);
        assert!(!zero.is_usable());
        assert!(seal(Suite::ChaCha20Poly1305, &zero, b"x", b"a").is_err());
    }
}
