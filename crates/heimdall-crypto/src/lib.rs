//! # heimdall-crypto
//!
//! Cryptographic core shared by Heimdall Core and Heimdall Sentinel.
//!
//! Everything here is implemented on the `rustCrypto` primitives rather than on
//! a bespoke construction: this crate's job is to compose reviewed algorithms
//! correctly and to refuse unsafe combinations, not to invent new ciphers.
//!
//! What it provides, mapped to section 5 of the design document:
//!
//! | Requirement           | Implementation                          |
//! |-----------------------|-----------------------------------------|
//! | Data-in-transit (PFS) | [`session::Handshake`], X25519 + HKDF   |
//! | Mutual authentication | Ed25519 identities, pinned per session  |
//! | Data-at-rest          | [`kms::KeyStore`], ChaCha20-Poly1305    |
//! | Key management        | Argon2id KDF, [`kdf::Passphrase`]       |
//! | Memory protection     | [`secret::Secret`], zeroize-on-drop      |
//!
//! Invariants enforced by this crate:
//!
//! 1. No key material is ever returned as a plain `Vec<u8>` from a long-lived
//!    type; `Secret` scrubs on drop and redacts in `Debug`.
//! 2. All authentication failures collapse into one error variant.
//! 3. Peer identity is checked *before* any signature verification, so an
//!    unpinned key can never be probed as an oracle.
//! 4. Every session derives fresh traffic keys; none is ever reused.

pub mod aead;
pub mod error;
pub mod kdf;
pub mod kex;
pub mod kms;
pub mod secret;
pub mod session;
pub mod util;

pub use aead::{CipherKey, Sealed, Suite};
pub use error::{Error, Result};
pub use kdf::{Passphrase, Strength, passphrase_strength};
pub use kex::{Identity, Role, Signer};
pub use kms::{KeyRecord, KeyStore};
pub use secret::{Key32, Secret, random_bytes};
pub use session::{Handshake, Hello, SessionKeys};

/// Crate-wide protocol version. Bumped when the wire format changes.
pub const PROTOCOL_VERSION: u16 = 3;
