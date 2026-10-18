//! Session establishment between the two AIs.
//!
//! Every session runs a fresh X25519 exchange, giving perfect forward secrecy:
//! compromising a long-term Ed25519 identity today does not decrypt a session
//! recorded last week. Both sides pin the other's long-term identity and sign
//! their own flight, which makes the channel mutually authenticated even
//! though the transport itself is an unauthenticated local socket.
//!
//! Wire sequence:
//!
//! ```text
//! Core     -> Sentinel : Hello { role=initiator, eph_i, sig_i }
//! Sentinel -> Core     : Hello { role=responder, eph_r, sig_r }
//! ```
//!
//! Transcript layout is fixed at `magic || suite || init_id || resp_id ||`,
//! then the initiator flight, then the responder flight. Both sides compute the
//! same final hash without exchanging it, which is what binds the derived
//! session keys to this specific exchange and not to a replayed one.
//! [`ReplayGuard`] covers the remaining case: a whole recorded flight replayed
//! at a fresh session.

use std::collections::VecDeque;

use crate::{
    aead::{CipherKey, Suite, derive_key},
    error::{Error, Result},
    kdf::hkdf_expand,
    kex::{Identity, KeyPair, Role, SIG_LEN, Signer, Transcript},
    secret::Key32,
};
use zeroize::Zeroize as _;

pub const KEX_VERSION: u8 = 1;
pub const KEX_MAGIC: &[u8] = b"heimdall/v3/kex";
const HELLO_LEN: usize = 1 + 1 + 32 + 32 + 32 + SIG_LEN;

/// One handshake flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub version: u8,
    pub suite: Suite,
    pub identity: Identity,
    pub ephemeral_pub: [u8; 32],
    /// Hash of the transcript up to and including this flight.
    pub transcript_hash: [u8; 32],
    pub signature: [u8; SIG_LEN],
}

impl Hello {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HELLO_LEN);
        out.push(self.version);
        out.push(self.suite as u8);
        out.extend_from_slice(&self.identity.verifying_key);
        out.extend_from_slice(&self.ephemeral_pub);
        out.extend_from_slice(&self.transcript_hash);
        out.extend_from_slice(&self.signature);
        debug_assert_eq!(out.len(), HELLO_LEN);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() != HELLO_LEN {
            return Err(Error::Protocol("malformed hello frame".into()));
        }
        if buf[0] != KEX_VERSION {
            return Err(Error::Protocol(format!(
                "unsupported key exchange version {}",
                buf[0]
            )));
        }
        let suite = Suite::from_u8(buf[1])?;
        let mut identity = [0u8; 32];
        identity.copy_from_slice(&buf[2..34]);
        let mut ephemeral_pub = [0u8; 32];
        ephemeral_pub.copy_from_slice(&buf[34..66]);
        let mut transcript_hash = [0u8; 32];
        transcript_hash.copy_from_slice(&buf[66..98]);
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&buf[98..]);
        Ok(Self {
            version: KEX_VERSION,
            suite,
            identity: Identity {
                verifying_key: identity,
            },
            ephemeral_pub,
            transcript_hash,
            signature,
        })
    }
}

/// Directional record keys for one established session.
#[derive(Clone)]
pub struct SessionKeys {
    pub core_to_sentinel: CipherKey,
    pub sentinel_to_core: CipherKey,
    pub transcript: Key32,
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("suite", &self.core_to_sentinel.suite())
            .field("transcript", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Remembers recently accepted handshake transcripts so a captured flight
/// cannot be presented twice.
///
/// The transcript binding alone is not sufficient. A recorded Core hello is a
/// perfectly valid, self-consistent flight, so a fresh Sentinel would accept it
/// and derive keys for a session Core never asked for. No attacker gains the
/// traffic keys (Core's ephemeral scalar is secret), but the Sentinel would
/// still allocate and encrypt toward a peer that does not exist, which is a
/// usable resource-exhaustion and confusion primitive.
pub struct ReplayGuard {
    seen: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl core::fmt::Debug for ReplayGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReplayGuard")
            .field("entries", &self.seen.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl ReplayGuard {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: VecDeque::with_capacity(capacity),
            capacity: capacity.max(1),
        }
    }

    /// Rejects a transcript that has been accepted before, and records it.
    pub fn check_and_record(&mut self, transcript: &[u8; 32]) -> Result<()> {
        if self.seen.iter().any(|e| e == transcript) {
            return Err(Error::Protocol("replayed handshake transcript".into()));
        }
        if self.seen.len() == self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(*transcript);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(64)
    }
}

/// Drives one side of the exchange.
///
/// The initiator calls [`Handshake::begin`] then [`Handshake::finish`]. The
/// responder calls [`Handshake::finish`] on the received initiator flight, then
/// [`Handshake::begin`] and returns the resulting hello to the initiator.
///
/// The responder's flight is committed to *both* ephemerals, so it cannot be
/// precomputed and replayed at a Core that never sent the matching initiator
/// flight. Without that binding the handshake would accept a reflection
/// attack: a recorded Sentinel reply replayed at a fresh Core session would
/// verify, because the reply is self-consistent on its own.
pub struct Handshake {
    role: Role,
    signer: Signer,
    own: Identity,
    peer: Identity,
    suite: Suite,
    ephemeral: KeyPair,
    /// `magic || suite || init-id || resp-id`. Immutable after construction.
    prefix: Transcript,
    /// Set by `finish` once the peer's ephemeral has been verified. The
    /// responder needs it to build its own flight.
    peer_ephemeral: Option<[u8; 32]>,
}

impl core::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Handshake")
            .field("role", &self.role)
            .field("own", &self.own.hex())
            .field("peer", &self.peer.hex())
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

impl Handshake {
    pub fn initiator(signer: Signer, pinned_peer: Identity, suite: Suite) -> Self {
        Self::new(Role::Initiator, signer, pinned_peer, suite)
    }

    pub fn responder(signer: Signer, pinned_peer: Identity, suite: Suite) -> Self {
        Self::new(Role::Responder, signer, pinned_peer, suite)
    }

    fn new(role: Role, signer: Signer, peer: Identity, suite: Suite) -> Self {
        let own = signer.identity();
        let (init_id, resp_id) = match role {
            Role::Initiator => (own.verifying_key, peer.verifying_key),
            Role::Responder => (peer.verifying_key, own.verifying_key),
        };
        let mut prefix = Transcript::new(KEX_MAGIC);
        prefix.push_u8(b"suit", suite as u8);
        prefix.push(b"init-id", &init_id);
        prefix.push(b"resp-id", &resp_id);

        Self {
            role,
            signer,
            own,
            peer,
            suite,
            ephemeral: KeyPair::generate(),
            prefix,
            peer_ephemeral: None,
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.own
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Transcript hash for this side's own flight, from its own point of view.
    /// The responder commits to the initiator's ephemeral because it has already
    /// verified it in `finish`.
    fn own_flight_transcript(&self) -> Result<Key32> {
        let mut t = self.prefix.clone();
        match self.role {
            Role::Initiator => {
                t.push(b"init-flight", self.ephemeral.public());
            }
            Role::Responder => {
                let peer_eph = self.peer_ephemeral.as_ref().ok_or_else(|| {
                    Error::Protocol("responder must verify the initiator flight first".into())
                })?;
                t.push(b"init-flight", peer_eph);
                t.push(b"resp-flight", self.ephemeral.public());
            }
        }
        Ok(t.finish())
    }

    /// Transcript hash this side expects in the peer's flight. Includes this
    /// side's own ephemeral, which is what stops a flight from being replayed
    /// into a different session.
    fn expected_peer_transcript(&self, peer_eph: &[u8; 32]) -> Key32 {
        let mut t = self.prefix.clone();
        match self.role {
            Role::Initiator => {
                t.push(b"init-flight", self.ephemeral.public());
                t.push(b"resp-flight", peer_eph);
            }
            Role::Responder => {
                t.push(b"init-flight", peer_eph);
            }
        }
        t.finish()
    }

    /// Transcript hash over the completed exchange, always in canonical
    /// initiator-then-responder order. This is the salt for the traffic keys, so
    /// both sides must compute it identically.
    fn session_transcript(&self, peer_eph: &[u8; 32]) -> Key32 {
        let (init_eph, resp_eph) = match self.role {
            Role::Initiator => (self.ephemeral.public(), peer_eph),
            Role::Responder => (peer_eph, self.ephemeral.public()),
        };
        let mut t = self.prefix.clone();
        t.push(b"init-flight", init_eph);
        t.push(b"resp-flight", resp_eph);
        t.finish()
    }

    /// Builds this side's flight.
    pub fn begin(&mut self) -> Result<Hello> {
        let th = self.own_flight_transcript()?;

        let mut hello = Hello {
            version: KEX_VERSION,
            suite: self.suite,
            identity: self.own.clone(),
            ephemeral_pub: *self.ephemeral.public(),
            transcript_hash: *th.as_bytes(),
            signature: [0u8; SIG_LEN],
        };
        let msg = self.signing_message(&hello, &th);
        hello.signature = self.signer.sign(&msg);
        Ok(hello)
    }

    /// Fixed-length signing input. Signing the transcript digest instead of the
    /// raw hello keeps the message constant-size and prevents signature reuse
    /// across differently-encoded-but-equivalent flights.
    fn signing_message(&self, hello: &Hello, th: &Key32) -> Vec<u8> {
        let mut msg = Vec::with_capacity(160);
        msg.extend_from_slice(b"heimdall/v3/hello-sig");
        msg.push(self.role.tag());
        msg.push(hello.version);
        msg.push(hello.suite as u8);
        msg.extend_from_slice(&hello.identity.verifying_key);
        msg.extend_from_slice(&hello.ephemeral_pub);
        msg.extend_from_slice(th.as_bytes());
        msg
    }

    /// Validates the peer's flight against the pinned identity and completes the
    /// exchange. Returns the session keys.
    ///
    /// Ordering matters: identity pinning, then transcript consistency, then
    /// replay rejection, then signature, and only at the very end is any
    /// attacker-supplied curve material fed to `diffie_hellman`. Doing it in any
    /// other order would expose unpinned keys to the verifier and turn this into
    /// a signature oracle.
    pub fn finish(
        &mut self,
        peer_hello: &Hello,
        replay_guard: &mut ReplayGuard,
    ) -> Result<SessionKeys> {
        if peer_hello.version != KEX_VERSION {
            return Err(Error::Protocol(
                "peer speaks an unsupported kex version".into(),
            ));
        }
        if peer_hello.suite != self.suite {
            return Err(Error::Protocol(format!(
                "peer selected suite {:?}, we offered {:?}",
                peer_hello.suite, self.suite
            )));
        }
        // Identity pinning: a valid signature from an unpinned key proves
        // nothing, so this check comes before any signature work.
        if !crate::util::ct_eq(&peer_hello.identity.verifying_key, &self.peer.verifying_key) {
            return Err(Error::KeyExchange(
                "peer identity is not the pinned identity",
            ));
        }

        // Recompute the expected transcript digest. This binds the flight to
        // our own ephemeral, so a recorded flight replayed into a different
        // session is rejected before any signature is checked.
        let peer_th = self.expected_peer_transcript(&peer_hello.ephemeral_pub);
        if !crate::util::ct_eq(peer_th.as_bytes(), &peer_hello.transcript_hash) {
            return Err(Error::Protocol(
                "transcript hash mismatch: flight does not belong to this session".into(),
            ));
        }

        replay_guard.check_and_record(&peer_hello.transcript_hash)?;

        let mut msg = Vec::with_capacity(160);
        msg.extend_from_slice(b"heimdall/v3/hello-sig");
        msg.push(self.role.flip().tag());
        msg.push(peer_hello.version);
        msg.push(peer_hello.suite as u8);
        msg.extend_from_slice(&peer_hello.identity.verifying_key);
        msg.extend_from_slice(&peer_hello.ephemeral_pub);
        msg.extend_from_slice(peer_th.as_bytes());
        peer_hello.identity.verify(&msg, &peer_hello.signature)?;

        // Only now do we touch attacker-supplied curve material.
        let shared = self.ephemeral.diffie_hellman(&peer_hello.ephemeral_pub)?;
        let session_th = self.session_transcript(&peer_hello.ephemeral_pub);

        // The label picks the direction, so both sides derive the same value for
        // the same direction. Binding it to the role here rather than to the
        // tuple position is what keeps the two directions from being swapped.
        let keys = SessionKeys {
            core_to_sentinel: derive_kdf(
                &shared,
                &session_th,
                b"heimdall/v3/kdf/core-to-sentinel",
            )?,
            sentinel_to_core: derive_kdf(
                &shared,
                &session_th,
                b"heimdall/v3/kdf/sentinel-to-core",
            )?,
            transcript: session_th,
        };
        // Only a fully verified exchange may arm the responder for its flight.
        self.peer_ephemeral = Some(peer_hello.ephemeral_pub);
        Ok(keys)
    }
}

/// HKDF the X25519 output into two independent AEAD keys. The salt is the
/// transcript hash, so the keys are unique per session even in the pathological
/// case of a shared static secret.
fn derive_kdf(shared: &Key32, salt: &Key32, label: &[u8]) -> Result<CipherKey> {
    let okm = hkdf_expand(shared.as_bytes(), salt.as_bytes(), label, 32)?;
    let mut master = Key32::new(&okm);
    let key = derive_key(Suite::ChaCha20Poly1305, &master, b"heimdall/v3/session")?;
    master.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUITE: Suite = Suite::ChaCha20Poly1305;

    struct Pair {
        core: Signer,
        core_id: Identity,
        sentinel: Signer,
        sentinel_id: Identity,
    }

    impl Pair {
        fn new() -> Self {
            let (core, core_id) = Signer::generate();
            let (sentinel, sentinel_id) = Signer::generate();
            Self {
                core,
                core_id,
                sentinel,
                sentinel_id,
            }
        }

        fn core_handshake(&self) -> Handshake {
            Handshake::initiator(self.core.clone(), self.sentinel_id.clone(), SUITE)
        }

        fn sentinel_handshake(&self) -> Handshake {
            Handshake::responder(self.sentinel.clone(), self.core_id.clone(), SUITE)
        }
    }

    /// Runs the full exchange, returning both sides' keys plus the flights that
    /// crossed the wire. The caller supplies the guard because it must be the
    /// *same* guard across sessions: it is what makes a replay detectable.
    fn exchange_with(
        p: &Pair,
        guard: &mut ReplayGuard,
    ) -> (SessionKeys, SessionKeys, Hello, Hello) {
        let mut core = p.core_handshake();
        let mut sentinel = p.sentinel_handshake();

        let core_hello = core.begin().expect("initiator may always begin");
        let sentinel_keys = sentinel
            .finish(&core_hello, guard)
            .expect("responder must accept");
        let sentinel_hello = sentinel.begin().expect("responder has verified a flight");
        let core_keys = core
            .finish(&sentinel_hello, guard)
            .expect("initiator must accept");

        (core_keys, sentinel_keys, core_hello, sentinel_hello)
    }

    fn exchange(p: &Pair) -> (SessionKeys, SessionKeys, Hello, Hello) {
        let mut guard = ReplayGuard::default();
        exchange_with(p, &mut guard)
    }

    #[test]
    fn handshake_agrees_on_identical_keys() {
        let p = Pair::new();
        let (core, sentinel, _, _) = exchange(&p);
        assert!(
            core.core_to_sentinel
                .key()
                .ct_eq(sentinel.core_to_sentinel.key())
        );
        assert!(
            core.sentinel_to_core
                .key()
                .ct_eq(sentinel.sentinel_to_core.key())
        );
        assert!(core.transcript.ct_eq(&sentinel.transcript));
    }

    #[test]
    fn forward_secrecy_each_session_uses_fresh_keys() {
        let p = Pair::new();
        let (first, _, _, _) = exchange(&p);
        let (second, _, _, _) = exchange(&p);
        assert!(
            !first
                .core_to_sentinel
                .key()
                .ct_eq(second.core_to_sentinel.key()),
            "a second session must not reuse the first session's traffic keys"
        );
    }

    #[test]
    fn directional_keys_are_distinct() {
        let p = Pair::new();
        let (core, _, _, _) = exchange(&p);
        assert!(
            !core
                .core_to_sentinel
                .key()
                .ct_eq(core.sentinel_to_core.key())
        );
    }

    #[test]
    fn established_session_actually_encrypts() {
        use crate::aead::{open_with, seal_with};
        let p = Pair::new();
        let (core, sentinel, _, _) = exchange(&p);

        let aad = b"seq=1;dir=c2s";
        let sealed = seal_with(&core.core_to_sentinel, b"sentinel, status?", aad).unwrap();
        assert_eq!(
            open_with(&sentinel.core_to_sentinel, &sealed, aad).unwrap(),
            b"sentinel, status?"
        );

        // The reverse direction key must not open it.
        assert!(open_with(&sentinel.sentinel_to_core, &sealed, aad).is_err());
    }

    #[test]
    fn pinned_identity_mismatch_is_refused() {
        // An impostor holding a valid keypair tries to talk to Sentinel, which
        // has pinned Core's identity. A cryptographically valid signature from
        // the wrong key must still be refused.
        let p = Pair::new();
        let (attacker, _) = Signer::generate();
        let hello = {
            let mut a = Handshake::initiator(attacker, p.sentinel_id.clone(), SUITE);
            a.begin().unwrap()
        };
        assert!(
            hello.identity != p.core_id,
            "test premise: the impostor identity is distinct from Core"
        );

        let mut sentinel = p.sentinel_handshake();
        let mut guard = ReplayGuard::default();
        assert!(matches!(
            sentinel.finish(&hello, &mut guard),
            Err(Error::KeyExchange(_))
        ));
    }

    #[test]
    fn responder_cannot_speak_before_verifying() {
        // Without this guard the responder's flight would not be bound to any
        // initiator ephemeral, and the reply could be replayed.
        let p = Pair::new();
        let mut sentinel = p.sentinel_handshake();
        assert!(matches!(sentinel.begin(), Err(Error::Protocol(_))));
    }

    #[test]
    fn forged_signature_is_refused() {
        let p = Pair::new();
        let mut hello = p.core_handshake().begin().unwrap();
        hello.signature[0] ^= 0x01;

        let mut sentinel = p.sentinel_handshake();
        let mut guard = ReplayGuard::default();
        assert!(matches!(
            sentinel.finish(&hello, &mut guard),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn hello_substitution_is_detected_by_transcript_hash() {
        let p = Pair::new();
        let mut guard = ReplayGuard::default();
        let mut core = p.core_handshake();
        let mut sentinel = p.sentinel_handshake();

        let hello = core.begin().unwrap();
        sentinel.finish(&hello, &mut guard).unwrap();
        let response = sentinel.begin().unwrap();

        let mut tampered = response.clone();
        tampered.ephemeral_pub[0] ^= 0xff;

        assert!(core.finish(&tampered, &mut guard).is_err());
    }

    #[test]
    fn reflection_of_responder_flight_is_refused() {
        // Record a complete, valid exchange, then replay Sentinel's reply at a
        // brand new Core session. The reply is internally consistent, so only
        // the binding to Core's *fresh* ephemeral can reject it.
        let p = Pair::new();
        let (_, _, _, recorded_response) = exchange(&p);

        let mut guard = ReplayGuard::default();
        let mut fresh_core = p.core_handshake();
        fresh_core.begin().unwrap();
        assert!(
            fresh_core.finish(&recorded_response, &mut guard).is_err(),
            "a recorded Sentinel reply must not authenticate a new session"
        );
    }

    #[test]
    fn replay_of_whole_session_is_refused_at_the_next_session() {
        let p = Pair::new();
        let mut guard = ReplayGuard::default();
        let (_, _, recorded_init, _) = exchange_with(&p, &mut guard);

        // Same long-lived guard, fresh Sentinel: this is exactly the state a
        // listening Sentinel is in after a legitimate session ends.
        let mut fresh_sentinel = p.sentinel_handshake();
        assert!(
            fresh_sentinel.finish(&recorded_init, &mut guard).is_err(),
            "a recorded Core hello must not authenticate a new session"
        );
    }

    #[test]
    fn replay_guard_is_bounded_and_order_independent() {
        let mut guard = ReplayGuard::new(2);
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];

        guard.check_and_record(&a).unwrap();
        guard.check_and_record(&b).unwrap();
        assert_eq!(guard.len(), 2);
        assert!(
            guard.check_and_record(&a).is_err(),
            "replay must be rejected"
        );

        // Pushing past capacity evicts the oldest entry.
        guard.check_and_record(&c).unwrap();
        assert_eq!(guard.len(), 2);
        assert!(
            guard.check_and_record(&a).is_ok(),
            "evicted entry is forgotten"
        );
    }

    #[test]
    fn swapped_peer_identity_is_refused() {
        let p = Pair::new();
        let (_, third) = Signer::generate();
        let mut core = Handshake::initiator(p.core.clone(), third, SUITE);
        let hello = core.begin().unwrap();
        let mut sentinel = p.sentinel_handshake();
        let mut guard = ReplayGuard::default();
        assert!(sentinel.finish(&hello, &mut guard).is_err());
    }

    #[test]
    fn suite_downgrade_is_refused() {
        let p = Pair::new();
        let mut hello = p.core_handshake().begin().unwrap();
        hello.suite = Suite::Aes256Gcm;
        let mut sentinel = p.sentinel_handshake();
        let mut guard = ReplayGuard::default();
        assert!(matches!(
            sentinel.finish(&hello, &mut guard),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn unknown_kex_version_is_refused_on_the_wire() {
        let p = Pair::new();
        let mut hello = p.core_handshake().begin().unwrap();
        hello.version = 2;
        let mut bytes = hello.encode();
        bytes[0] = 2;
        assert!(Hello::decode(&bytes).is_err());
    }

    #[test]
    fn hello_wire_roundtrip() {
        let p = Pair::new();
        let mut core =
            Handshake::initiator(p.core.clone(), p.sentinel_id.clone(), Suite::Aes256Gcm);
        let hello = core.begin().unwrap();
        let bytes = hello.encode();
        assert_eq!(Hello::decode(&bytes).unwrap(), hello);
        assert!(Hello::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(Hello::decode(&[]).is_err());
        assert!(Hello::decode(&[bytes.as_slice(), &[0u8; 4]].concat()).is_err());
    }

    #[test]
    fn debug_output_leaks_no_key_material() {
        let p = Pair::new();
        let (keys, _, _, _) = exchange(&p);
        let rendered = format!("{keys:?}");
        assert!(rendered.contains("redacted"), "{rendered}");
        let h = format!("{:?}", p.core_handshake());
        assert!(!h.contains("secret"));
    }
}
