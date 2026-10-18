//! The encrypted session: handshake plus ordered, authenticated records.
//!
//! Once a [`Session`] exists, every byte in either direction is encrypted and
//! authenticated, and records are strictly ordered. Three properties are
//! enforced here rather than left to callers:
//!
//! 1. **Direction.** Core and Sentinel hold different keys, so a frame sealed
//!    for one direction can never be opened by the other.
//! 2. **Ordering.** Each direction has its own monotonic sequence counter. A gap
//!    closes the session instead of being skipped, because a skipped record is
//!    exactly how a replay-based desynchronisation attack proceeds.
//! 3. **Direction validity.** A Core session will not accept a frame typed as
//!    Sentinel -> Core, so a bug in one AI cannot make the other impersonate it.

use heimdall_crypto::{
    Identity, ReplayGuard, SessionKeys, Signer,
    aead::Suite,
    session::{Handshake, Hello},
};

use crate::{
    error::{Error, Result},
    frame::{self, FrameKind},
    message::{CloseReason, Message},
    transport::Stream,
};

/// Which side of the channel a session belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Core,
    Sentinel,
}

impl Side {
    const fn frame_kind(self, outbound: bool) -> FrameKind {
        match (self, outbound) {
            (Self::Core, true) | (Self::Sentinel, false) => FrameKind::CoreToSentinel,
            (Self::Core, false) | (Self::Sentinel, true) => FrameKind::SentinelToCore,
        }
    }

    const fn key(self, keys: &SessionKeys) -> &CipherKeyRef {
        match self {
            Self::Core => &keys.core_to_sentinel,
            Self::Sentinel => &keys.sentinel_to_core,
        }
    }

    const fn peer_key(self, keys: &SessionKeys) -> &CipherKeyRef {
        match self {
            Self::Core => &keys.sentinel_to_core,
            Self::Sentinel => &keys.core_to_sentinel,
        }
    }
}

type CipherKeyRef = heimdall_crypto::CipherKey;

/// An established, authenticated channel.
pub struct Session {
    side: Side,
    stream: Stream,
    keys: SessionKeys,
    send_seq: u64,
    recv_seq: u64,
    closing: bool,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("side", &self.side)
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .field("closing", &self.closing)
            .finish_non_exhaustive()
    }
}

impl Session {
    pub fn side(&self) -> Side {
        self.side
    }

    pub fn sent(&self) -> u64 {
        self.send_seq
    }

    pub fn received(&self) -> u64 {
        self.recv_seq
    }

    /// Encrypts and writes one message.
    pub async fn send(&mut self, message: &Message) -> Result<()> {
        if self.closing {
            return Err(Error::Protocol("session is closing".into()));
        }
        let plaintext = message.encode()?;
        let kind = self.side.frame_kind(true);
        let bytes = frame::seal_frame(kind, self.send_seq, self.side.key(&self.keys), &plaintext)?;
        self.stream.write_frame(&bytes).await?;
        self.send_seq += 1;
        Ok(())
    }

    /// Reads and decrypts one message. Returns `Ok(None)` when the peer has
    /// closed cleanly.
    pub async fn recv(&mut self) -> Result<Option<Message>> {
        let raw = self.stream.read_frame().await?;
        let (header, body) = frame::split_frame_header(&raw)?;

        if header.kind == FrameKind::Hello {
            return Err(Error::Protocol(
                "handshake frame received on an established session".into(),
            ));
        }
        if header.kind != self.side.frame_kind(false) {
            return Err(Error::Protocol(format!(
                "frame direction {:?} is not valid for a {:?} session",
                header.kind, self.side
            )));
        }
        if header.seq != self.recv_seq {
            // A gap means a record was dropped or reordered. There is no safe
            // way to resynchronise: terminate and force a fresh handshake.
            return Err(Error::OutOfOrder {
                expected: self.recv_seq,
                actual: header.seq,
            });
        }

        let mut plaintext = frame::open_frame(header, body, self.side.peer_key(&self.keys))?;
        let decoded = Message::decode(&plaintext);
        frame::scrub(&mut plaintext);
        let message = decoded?;

        self.recv_seq += 1;
        if let Message::Close { reason } = message {
            tracing::debug!(side = ?self.side, ?reason, "peer closed the session");
            self.closing = true;
            return Ok(None);
        }
        Ok(Some(message))
    }

    /// Sends a `Close` frame. Errors are swallowed: the peer is going away
    /// regardless, and a failed courtesy notice must not mask the real cause.
    pub async fn close(&mut self, reason: CloseReason) {
        if self.closing {
            return;
        }
        self.closing = true;

        let Ok(payload) = (Message::Close { reason }).encode() else {
            return;
        };
        let kind = self.side.frame_kind(true);
        let keyed = self.side.key(&self.keys);
        let Ok(frame) = frame::seal_frame(kind, self.send_seq, keyed, &payload) else {
            return;
        };
        let _ = self.stream.write_frame(&frame).await;
        self.send_seq += 1;
    }
}

/// Core side: connect, send a hello, receive and verify the reply.
pub async fn connect_as_core(
    endpoint: &str,
    signer: Signer,
    pinned_peer: Identity,
    suite: Suite,
    guard: &mut ReplayGuard,
) -> Result<Session> {
    let mut stream = Stream::connect(endpoint).await?;
    let mut handshake = Handshake::initiator(signer, pinned_peer, suite);
    let hello = handshake
        .begin()
        .map_err(|e| Error::Handshake(e.to_string()))?;

    stream
        .write_frame(&frame::hello_frame(&hello.encode())?)
        .await?;

    let raw = stream.read_frame().await?;
    let (header, body) = frame::split_frame_header(&raw)?;
    if header.kind != FrameKind::Hello {
        return Err(Error::Protocol(
            "expected a hello frame from the responder".into(),
        ));
    }
    let peer = Hello::decode(body).map_err(|e| Error::Handshake(e.to_string()))?;
    let keys = handshake
        .finish(&peer, guard)
        .map_err(|e| Error::Handshake(e.to_string()))?;

    Ok(Session {
        side: Side::Core,
        stream,
        keys,
        send_seq: 1,
        recv_seq: 0,
        closing: false,
    })
}

/// Sentinel side: accept, verify the hello, reply.
pub async fn accept_as_sentinel(
    mut stream: Stream,
    signer: Signer,
    pinned_peer: Identity,
    suite: Suite,
    guard: &mut ReplayGuard,
) -> Result<Session> {
    let raw = stream.read_frame().await?;
    let (header, body) = frame::split_frame_header(&raw)?;
    if header.kind != FrameKind::Hello {
        return Err(Error::Protocol(
            "expected a hello frame from the initiator".into(),
        ));
    }
    let peer = Hello::decode(body).map_err(|e| Error::Handshake(e.to_string()))?;

    let mut handshake = Handshake::responder(signer, pinned_peer, suite);
    let keys = handshake
        .finish(&peer, guard)
        .map_err(|e| Error::Handshake(e.to_string()))?;
    let hello = handshake
        .begin()
        .map_err(|e| Error::Handshake(e.to_string()))?;

    stream
        .write_frame(&frame::hello_frame(&hello.encode())?)
        .await?;

    Ok(Session {
        side: Side::Sentinel,
        stream,
        keys,
        send_seq: 0,
        recv_seq: 1,
        closing: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{HealthReport, PatchProposal, Severity, ThreatAlert};

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
    }

    /// Runs a full handshake over one in-memory duplex pipe and returns both
    /// sessions. The pipe is bidirectional, so one end reads exactly what the
    /// other writes.
    async fn session_pair(p: &Pair) -> (Session, Session) {
        let (mut core_side, mut sentinel_side) = Stream::in_memory_pair(256 * 1024);

        let core = {
            let (signer, peer) = (p.core.clone(), p.sentinel_id.clone());
            let mut guard = ReplayGuard::default();
            tokio::spawn(async move {
                let mut hs = Handshake::initiator(signer, peer, Suite::ChaCha20Poly1305);
                let hello = hs.begin().expect("initiator may always begin");
                core_side
                    .write_frame(&frame::hello_frame(&hello.encode()).unwrap())
                    .await
                    .unwrap();

                let raw = core_side.read_frame().await.unwrap();
                let (_, body) = frame::split_frame_header(&raw).unwrap();
                let keys = hs
                    .finish(&Hello::decode(body).unwrap(), &mut guard)
                    .expect("initiator must accept");

                Session {
                    side: Side::Core,
                    stream: core_side,
                    keys,
                    send_seq: 1,
                    recv_seq: 0,
                    closing: false,
                }
            })
        };

        let sentinel = {
            let (signer, peer) = (p.sentinel.clone(), p.core_id.clone());
            let mut guard = ReplayGuard::default();
            tokio::spawn(async move {
                let mut hs = Handshake::responder(signer, peer, Suite::ChaCha20Poly1305);

                let raw = sentinel_side.read_frame().await.unwrap();
                let (_, body) = frame::split_frame_header(&raw).unwrap();
                let keys = hs
                    .finish(&Hello::decode(body).unwrap(), &mut guard)
                    .expect("responder must accept");
                let hello = hs.begin().unwrap();
                sentinel_side
                    .write_frame(&frame::hello_frame(&hello.encode()).unwrap())
                    .await
                    .unwrap();

                Session {
                    side: Side::Sentinel,
                    stream: sentinel_side,
                    keys,
                    send_seq: 0,
                    recv_seq: 1,
                    closing: false,
                }
            })
        };

        (core.await.unwrap(), sentinel.await.unwrap())
    }

    fn threat(id: u64) -> Message {
        Message::ThreatAlert(ThreatAlert {
            alert_id: id,
            severity: Severity::High,
            category: "process".into(),
            summary: "unsigned binary spawned".into(),
            observed_at_unix: 1_700_000_000,
        })
    }

    #[tokio::test]
    async fn messages_flow_both_ways() {
        let p = Pair::new();
        let (mut core, mut sentinel) = session_pair(&p).await;

        let alert = threat(1);
        sentinel.send(&alert).await.unwrap();
        assert_eq!(core.recv().await.unwrap(), Some(alert));

        let health = Message::Health(HealthReport {
            sentinel_id: "s-1".into(),
            uptime_secs: 5,
            events_scanned: 10,
            active_containments: 0,
            engine_load_permille: 5,
        });
        sentinel.send(&health).await.unwrap();
        assert_eq!(core.recv().await.unwrap(), Some(health));

        let ack = Message::Ack { ref_id: 1 };
        core.send(&ack).await.unwrap();
        assert_eq!(sentinel.recv().await.unwrap(), Some(ack));
    }

    #[tokio::test]
    async fn a_full_patch_proposal_survives_the_round_trip() {
        // The self-repair payload is the most sensitive thing on this channel:
        // it is source code the AI intends to change. Verify it arrives intact
        // and that nothing about the framing truncates it.
        let p = Pair::new();
        let (mut core, mut sentinel) = session_pair(&p).await;

        let diff = format!(
            "--- a\n+++ b\n@@ -1,3 +1,3 @@\n-{}\n+{}\n",
            "let x = old;", "let x = new;"
        );
        let proposal = Message::PatchProposal(PatchProposal {
            proposal_id: 77,
            target_path: "crates/heimdall-core/src/gate.rs".into(),
            rationale: "bounds check was inverted".into(),
            diff,
            generated_by_model: "heimdall-core/self-repair".into(),
        });

        sentinel.send(&proposal).await.unwrap();
        assert_eq!(core.recv().await.unwrap(), Some(proposal));
    }

    #[tokio::test]
    async fn close_returns_none_and_is_final() {
        let p = Pair::new();
        let (mut core, mut sentinel) = session_pair(&p).await;

        sentinel.close(CloseReason::Shutdown).await;
        assert_eq!(core.recv().await.unwrap(), None);
        assert!(
            core.send(&Message::Ack { ref_id: 1 }).await.is_err(),
            "sending after the peer closed must be refused"
        );
    }

    #[tokio::test]
    async fn sequence_numbers_advance_in_both_directions() {
        let p = Pair::new();
        let (mut core, mut sentinel) = session_pair(&p).await;

        for i in 0..4u64 {
            sentinel.send(&Message::Ack { ref_id: i }).await.unwrap();
        }
        for _ in 0..4 {
            core.recv().await.unwrap();
        }
        assert_eq!(sentinel.sent(), 4);
        assert_eq!(core.received(), 4);

        // The handshake consumed one slot in each direction.
        assert_eq!(core.sent(), 1);
        assert_eq!(sentinel.received(), 1);
    }

    /// Handshakes both sides and hands back Core's session plus the Sentinel-side
    /// raw stream, so a test can inject an arbitrary (possibly hostile) frame.
    async fn session_with_raw_sentinel_side(p: &Pair) -> (Session, Stream) {
        let (mut core_side, mut sentinel_side) = Stream::in_memory_pair(256 * 1024);

        let core = {
            let (signer, peer) = (p.core.clone(), p.sentinel_id.clone());
            let mut guard = ReplayGuard::default();
            tokio::spawn(async move {
                let mut hs = Handshake::initiator(signer, peer, Suite::ChaCha20Poly1305);
                let hello = hs.begin().unwrap();
                core_side
                    .write_frame(&frame::hello_frame(&hello.encode()).unwrap())
                    .await
                    .unwrap();
                let raw = core_side.read_frame().await.unwrap();
                let (_, body) = frame::split_frame_header(&raw).unwrap();
                let keys = hs
                    .finish(&Hello::decode(body).unwrap(), &mut guard)
                    .unwrap();
                Session {
                    side: Side::Core,
                    stream: core_side,
                    keys,
                    send_seq: 0,
                    recv_seq: 0,
                    closing: false,
                }
            })
        };

        let sentinel_side = {
            let (signer, peer) = (p.sentinel.clone(), p.core_id.clone());
            let mut guard = ReplayGuard::default();
            tokio::spawn(async move {
                let mut hs = Handshake::responder(signer, peer, Suite::ChaCha20Poly1305);
                let raw = sentinel_side.read_frame().await.unwrap();
                let (_, body) = frame::split_frame_header(&raw).unwrap();
                hs.finish(&Hello::decode(body).unwrap(), &mut guard)
                    .unwrap();
                let hello = hs.begin().unwrap();
                sentinel_side
                    .write_frame(&frame::hello_frame(&hello.encode()).unwrap())
                    .await
                    .unwrap();
                sentinel_side
            })
        };

        (core.await.unwrap(), sentinel_side.await.unwrap())
    }

    #[tokio::test]
    async fn a_sequence_gap_terminates_the_session() {
        let p = Pair::new();
        let (mut core, mut raw_sentinel) = session_with_raw_sentinel_side(&p).await;

        // A correctly encrypted record carrying the wrong sequence number, as
        // a desynchronising attacker would produce.
        let forged = frame::seal_frame(
            FrameKind::SentinelToCore,
            5,
            &core.keys.sentinel_to_core,
            &Message::Ack { ref_id: 1 }.encode().unwrap(),
        )
        .unwrap();
        raw_sentinel.write_frame(&forged).await.unwrap();

        assert!(
            matches!(
                core.recv().await,
                Err(Error::OutOfOrder {
                    expected: 0,
                    actual: 5
                })
            ),
            "a sequence gap must terminate the session, not be skipped"
        );
    }

    #[tokio::test]
    async fn a_replayed_record_is_rejected_as_out_of_order() {
        let p = Pair::new();
        let (mut core, mut raw_sentinel) = session_with_raw_sentinel_side(&p).await;

        let record = frame::seal_frame(
            FrameKind::SentinelToCore,
            0,
            &core.keys.sentinel_to_core,
            &Message::Ack { ref_id: 1 }.encode().unwrap(),
        )
        .unwrap();

        raw_sentinel.write_frame(&record).await.unwrap();
        assert_eq!(core.recv().await.unwrap(), Some(Message::Ack { ref_id: 1 }));

        // Byte-identical replay of an already-accepted record.
        raw_sentinel.write_frame(&record).await.unwrap();
        assert!(matches!(
            core.recv().await,
            Err(Error::OutOfOrder {
                expected: 1,
                actual: 0
            })
        ));
    }

    #[tokio::test]
    async fn a_mislabelled_direction_is_rejected() {
        let p = Pair::new();
        let (mut core, mut raw_sentinel) = session_with_raw_sentinel_side(&p).await;

        // A record encrypted with the *correct* Sentinel->Core key but labelled
        // as Core->Sentinel: it must not be accepted inbound by Core.
        let mislabelled = frame::seal_frame(
            FrameKind::CoreToSentinel,
            0,
            &core.keys.sentinel_to_core,
            &Message::Ack { ref_id: 1 }.encode().unwrap(),
        )
        .unwrap();
        raw_sentinel.write_frame(&mislabelled).await.unwrap();
        assert!(matches!(core.recv().await, Err(Error::Protocol(_))));
    }

    #[tokio::test]
    async fn a_record_encrypted_with_the_wrong_key_is_rejected() {
        let p = Pair::new();
        let (mut core, mut raw_sentinel) = session_with_raw_sentinel_side(&p).await;

        // Correct direction label and sequence, but sealed under Core's outbound
        // key instead of Sentinel's.
        let wrong_key = frame::seal_frame(
            FrameKind::SentinelToCore,
            0,
            &core.keys.core_to_sentinel,
            &Message::Ack { ref_id: 1 }.encode().unwrap(),
        )
        .unwrap();
        raw_sentinel.write_frame(&wrong_key).await.unwrap();
        assert!(core.recv().await.is_err());
    }

    #[tokio::test]
    async fn wrong_direction_keys_are_distinct() {
        let p = Pair::new();
        let (core, sentinel) = session_pair(&p).await;
        assert!(
            !core
                .keys
                .core_to_sentinel
                .key()
                .ct_eq(core.keys.sentinel_to_core.key())
        );
        assert!(
            core.keys
                .core_to_sentinel
                .key()
                .ct_eq(sentinel.keys.core_to_sentinel.key())
        );
    }

    #[tokio::test]
    async fn a_core_record_cannot_be_opened_with_the_reverse_key() {
        let p = Pair::new();
        let (core, _sentinel) = session_pair(&p).await;
        let raw = frame::seal_frame(
            FrameKind::CoreToSentinel,
            0,
            &core.keys.core_to_sentinel,
            &Message::Ack { ref_id: 1 }.encode().unwrap(),
        )
        .unwrap();
        let (header, body) = frame::split_frame_header(&raw).unwrap();
        assert!(
            frame::open_frame(header, body, &core.keys.sentinel_to_core).is_err(),
            "directional keys must not be interchangeable"
        );
    }

    #[tokio::test]
    async fn impostor_cannot_establish_a_session() {
        // An attacker with a self-signed identity, holding no key Sentinel
        // pinned, presents a well-formed hello. The handshake must fail on
        // identity pinning.
        let p = Pair::new();
        let (attacker, _) = Signer::generate();

        let (mut attacker_side, sentinel_side) = Stream::in_memory_pair(64 * 1024);
        let hello = {
            let mut hs =
                Handshake::initiator(attacker, p.sentinel_id.clone(), Suite::ChaCha20Poly1305);
            hs.begin().unwrap()
        };
        attacker_side
            .write_frame(&frame::hello_frame(&hello.encode()).unwrap())
            .await
            .unwrap();

        let mut guard = ReplayGuard::default();
        let result = accept_as_sentinel(
            sentinel_side,
            p.sentinel.clone(),
            p.core_id.clone(),
            Suite::ChaCha20Poly1305,
            &mut guard,
        )
        .await;

        match result {
            Err(Error::Handshake(_)) => {}
            other => panic!("expected a handshake failure, got {other:?}"),
        }
    }
}
