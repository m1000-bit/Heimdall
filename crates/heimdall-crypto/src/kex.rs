use crate::{
    error::{Error, Result},
    secret::{Key32, Secret},
};
use sha2::Digest as _;

/// Length of an X25519 public key, an Ed25519 public key, and a signature.
pub const PUBKEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;

/// An X25519 keypair. The secret half never leaves this type: it is boxed and
/// zeroized on drop, and it is not exposed by any accessor.
pub struct KeyPair {
    secret: Secret<32>,
    public: [u8; PUBKEY_LEN],
}

impl core::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public_hex())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl KeyPair {
    pub fn generate() -> Self {
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pk = x25519_dalek::PublicKey::from(&sk);
        Self {
            secret: Secret::new(sk.as_bytes()),
            public: pk.to_bytes(),
        }
    }

    pub fn public(&self) -> &[u8; PUBKEY_LEN] {
        &self.public
    }

    pub fn public_hex(&self) -> String {
        crate::util::to_hex(&self.public)
    }

    /// ECDH. The shared secret is rejected when it lands on a low-order point,
    /// which would otherwise yield an attacker-chosen "shared" value.
    pub fn diffie_hellman(&self, peer_public: &[u8; PUBKEY_LEN]) -> Result<Key32> {
        let peer = x25519_dalek::PublicKey::from(*peer_public);
        let sk = x25519_dalek::StaticSecret::from(*self.secret.as_bytes());
        let shared = sk.diffie_hellman(&peer);
        let shared_bytes = shared.to_bytes();
        if !shared.was_contributory() || shared_bytes.ct_eq_zero() {
            return Err(Error::KeyExchange(
                "rejected a non-contributory shared secret",
            ));
        }
        Ok(Key32::new(&shared_bytes))
    }
}

trait CtEqZero {
    fn ct_eq_zero(&self) -> bool;
}

impl CtEqZero for [u8; 32] {
    fn ct_eq_zero(&self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.ct_eq(&[0u8; 32]))
    }
}

/// Which AI is driving the exchange. Fixed per session and bound into the
/// transcript, so a flight cannot be reflected back at its sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Heimdall Core, the initiator and long-term authority.
    Initiator,
    /// Heimdall Sentinel, the responder.
    Responder,
}

/// Incremental transcript hash over the key exchange.
///
/// Every field is length-prefixed before being appended. Without that, a peer
/// could present two different byte strings that hash identically (e.g. moving
/// bytes across a field boundary) and get two valid handshakes for one
/// exchange.
#[derive(Clone)]
pub struct Transcript {
    buffer: Vec<u8>,
}

impl core::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Transcript({} bytes)", self.buffer.len())
    }
}

impl Transcript {
    pub fn new(magic: &[u8]) -> Self {
        Self {
            buffer: magic.to_vec(),
        }
    }

    pub fn push(&mut self, label: &[u8], bytes: &[u8]) {
        self.buffer
            .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.buffer
            .extend_from_slice(&(label.len() as u32).to_be_bytes());
        self.buffer.extend_from_slice(label);
        self.buffer.extend_from_slice(bytes);
    }

    pub fn push_u8(&mut self, label: &[u8], value: u8) {
        self.push(label, &[value]);
    }

    /// Snapshot of the transcript so far. Cloned into the hello so the peer can
    /// verify it without having to replay every prior step.
    pub fn finish(&self) -> Key32 {
        let digest = sha3::Sha3_256::digest(&self.buffer);
        Key32::new(&digest)
    }
}

impl Role {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
        }
    }

    #[must_use]
pub const fn flip(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

/// A long-term Ed25519 identity: the anchor of mutual authentication.
///
/// Even with a valid PFS tunnel, a peer that cannot prove possession of a
/// pinned identity is not trusted - the tunnel only proves the session is
/// private, not who is on the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub verifying_key: [u8; PUBKEY_LEN],
}

impl Identity {
    pub fn generate() -> (ed25519_dalek::SigningKey, Self) {
        let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let id = Self::from_verifying_key(signing.verifying_key());
        (signing, id)
    }

    pub fn from_verifying_key(vk: ed25519_dalek::VerifyingKey) -> Self {
        Self {
            verifying_key: vk.to_bytes(),
        }
    }

    pub fn hex(&self) -> String {
        crate::util::to_hex(&self.verifying_key)
    }

    pub fn parse_hex(s: &str) -> Result<Self> {
        let bytes = crate::util::from_hex(s).map_err(Error::KeyExchange)?;
        let arr: [u8; PUBKEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::KeyExchange("identity must be 32 hex-encoded bytes"))?;
        Ok(Self { verifying_key: arr })
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; SIG_LEN]) -> Result<()> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&self.verifying_key)
            .map_err(|_| Error::KeyExchange("invalid Ed25519 verifying key"))?;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        vk.verify_strict(message, &sig)
            .map_err(|_| Error::BadSignature)
    }
}

/// Signs with the private identity.
///
/// The `zeroize` feature of `ed25519-dalek` gives `SigningKey` a
/// `ZeroizeOnDrop` impl, which scrubs the scalar on release. `Debug` is
/// implemented manually so the key never reaches a log sink.
#[derive(Clone)]
pub struct Signer {
    key: ed25519_dalek::SigningKey,
}

impl core::fmt::Debug for Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Signer(<redacted>)")
    }
}

impl Signer {
    pub fn generate() -> (Self, Identity) {
        let (key, id) = Identity::generate();
        (Self::from_key(key), id)
    }

    pub fn from_key(key: ed25519_dalek::SigningKey) -> Self {
        Self { key }
    }

    pub fn identity(&self) -> Identity {
        Identity::from_verifying_key(self.key.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIG_LEN] {
        use ed25519_dalek::Signer as _;
        self.key.sign(message).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7748_x25519_vector() {
        // RFC 7748 section 6.1.
        let alice_sk = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_sk = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let expected_shared = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];

        let sk = x25519_dalek::StaticSecret::from(alice_sk);
        let alice_pub = x25519_dalek::PublicKey::from(&sk).to_bytes();
        let kp = KeyPair {
            secret: Secret::new(&alice_sk),
            public: alice_pub,
        };
        let bob_pub =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_sk)).to_bytes();
        let shared = kp.diffie_hellman(&bob_pub).unwrap();
        assert_eq!(shared.as_bytes(), &expected_shared);
    }

    #[test]
    fn dh_is_symmetric() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let sa = a.diffie_hellman(b.public()).unwrap();
        let sb = b.diffie_hellman(a.public()).unwrap();
        assert!(sa.ct_eq(&sb));
    }

    #[test]
    fn low_order_public_key_is_rejected() {
        // All-zero is a low-order point: the resulting shared secret would be
        // a constant chosen by the attacker.
        let kp = KeyPair::generate();
        assert!(kp.diffie_hellman(&[0u8; 32]).is_err());
    }

    #[test]
    fn signature_roundtrip_and_tamper_detection() {
        let (signer, id) = Signer::generate();
        let msg = b"heimdall core approves patch 0xdeadbeef";
        let sig = signer.sign(msg);
        assert!(id.verify(msg, &sig).is_ok());
        assert!(matches!(
            id.verify(b"other message", &sig),
            Err(Error::BadSignature)
        ));

        let mut tampered = sig;
        tampered[0] ^= 0x01;
        assert!(matches!(
            id.verify(msg, &tampered),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn identity_hex_roundtrip() {
        let (_, id) = Signer::generate();
        let parsed = Identity::parse_hex(&id.hex()).unwrap();
        assert_eq!(parsed, id);
        assert!(Identity::parse_hex("nothex").is_err());
        assert!(Identity::parse_hex("aabb").is_err());
    }

    #[test]
    fn transcript_is_domain_separated_by_label() {
        let mut t = Transcript::new(b"heimdall/v3/kex");
        t.push(b"a", b"value");
        let first = t.finish();
        let mut t2 = Transcript::new(b"heimdall/v3/kex");
        t2.push(b"b", b"value");
        assert!(!first.ct_eq(&t2.finish()));
    }
}
