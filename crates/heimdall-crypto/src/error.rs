pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("encryption failed")]
    Encrypt,

    #[error("authentication failed")]
    Decrypt,

    #[error("unsupported cipher suite: {0}")]
    UnsupportedSuite(u8),

    #[error("key exchange failed: {0}")]
    KeyExchange(&'static str),

    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("signature verification failed")]
    BadSignature,

    #[error("KMS error: {0}")]
    Kms(String),

    #[error("key not found in store: {0}")]
    KeyNotFound(String),

    #[error("keystore integrity check failed: store may have been tampered with")]
    StoreCorrupted,

    #[error("protocol violation: {0}")]
    Protocol(String),

    #[error("passphrase is required to unlock the keystore")]
    PassphraseRequired,
}

/// Any authentication failure is collapsed into a single indistinguishable
/// variant. Differentiating "bad tag" from "malformed nonce" from "wrong key"
/// hands an attacker a decryption oracle.
impl From<aead::Error> for Error {
    fn from(_: aead::Error) -> Self {
        Self::Decrypt
    }
}
