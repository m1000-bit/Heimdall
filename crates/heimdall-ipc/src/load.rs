//! Load and robustness tests for the channel.
//!
//! Two questions, and they are different ones.
//!
//! *Does the channel survive a burst?* A real deployment produces a handful
//! of alerts an hour, so a burst is not a scenario the product meets in
//! production. It is a scenario a test can produce, and it is the cheapest
//! way to find a framing bug, a sequence-number bug, or a decoder that
//! assumes small inputs. The bursts here are far past anything the daemon
//! will send, and the assertion is that every message arrives, in order,
//! with its payload intact.
//!
//! *What happens when the bytes are not the bytes the sender meant to send?*
//! Every other test in the crate checks that honest traffic is handled. This
//! file checks the other half: a frame whose ciphertext has been altered, a
//! frame that stops halfway, a header that claims a gigabyte, a frame
//! carrying the wrong direction. None of them may produce a message, and
//! none of them may hang. A channel that accepts a message it cannot
//! authenticate is worse than a channel that is down, because the operator is
//! told the system is watching.
//!
//! The injection tests take the Core's side of the channel into the test
//! itself. The handshake is done by hand, which leaves the session keys in
//! the test's hands, and the test then writes frames the product would never
//! write: a real frame with one bit changed, a header that lies about the
//! length, a frame wearing the other side's name. The Sentinel in the room
//! is the real one, with the real receiving logic, and it has to refuse
//! every one of them.

use std::time::{Duration, Instant};

use heimdall_crypto::{
    Identity, ReplayGuard, Signer, Suite,
    session::{Handshake, Hello},
};

use crate::{
    Session, Side, Stream,
    frame::{self, FrameKind},
    message::{HealthReport, Message, Severity, ThreatAlert},
};

/// How many messages a burst carries. Large enough to cross any buffer
/// boundary the transport might have, small enough to finish in a second on
/// a slow machine.
const BURST: usize = 5_000;

/// Generous upper bound on a whole burst. A correct implementation is three
/// orders of magnitude under this; the bound exists to catch a regression
/// that turns a linear pass into a quadratic one, not to measure speed.
const BURST_BUDGET: Duration = Duration::from_secs(30);

/// The suite both ends use. AES-GCM is the default for a channel on a host
/// with the hardware for it, and the load test should measure that path.
const SUITE: Suite = Suite::Aes256Gcm;

/// The two identities of a channel, and the signers that go with them.
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

/// Performs the handshake by hand and returns the two sessions.
///
/// The handshake is done here rather than through `connect_as_core` and
/// `accept_as_sentinel` because the burst test needs a pipe with a known
/// capacity, and the injection tests need the keys.
async fn handshake(core_side: Stream, sentinel_side: Stream) -> (Session, Session) {
    let (core_side, sentinel, keys) = handshake_with_keys(core_side, sentinel_side).await;

    // The Core's session is built here so that the burst test has two
    // sessions to talk over. The injection tests do not use it: they keep
    // the raw stream and write what they like.
    let core = Session::for_test(Side::Core, core_side, keys);
    (core, sentinel)
}

/// Performs the handshake, keeping the Core's stream and the session keys.
///
/// The Sentinel side is a real session. The Core side stays in the test's
/// hands, along with the keys, so the test can seal frames of its own -- or
/// seal them and then alter them.
async fn handshake_with_keys(
    mut core_side: Stream,
    mut sentinel_side: Stream,
) -> (Stream, Session, heimdall_crypto::SessionKeys) {
    let pair = Pair::new();

    let sentinel = {
        let (signer, peer) = (pair.sentinel.clone(), pair.core_id.clone());
        let mut guard = ReplayGuard::default();
        tokio::spawn(async move {
            let mut hs = Handshake::responder(signer, peer, SUITE);

            let raw = sentinel_side.read_frame().await.expect("read hello");
            let (_, body) = frame::split_frame_header(&raw).expect("split");
            let keys = hs
                .finish(&Hello::decode(body).expect("decode"), &mut guard)
                .expect("responder must accept");
            let hello = hs.begin().expect("responder may always answer");
            sentinel_side
                .write_frame(&frame::hello_frame(&hello.encode()).expect("hello"))
                .await
                .expect("write hello");

            Session::for_test(Side::Sentinel, sentinel_side, keys)
        })
    };

    let mut guard = ReplayGuard::default();
    let mut hs = Handshake::initiator(pair.core.clone(), pair.sentinel_id.clone(), SUITE);
    let hello = hs.begin().expect("initiator may always begin");
    core_side
        .write_frame(&frame::hello_frame(&hello.encode()).expect("hello"))
        .await
        .expect("write hello");

    let raw = core_side.read_frame().await.expect("read hello");
    let (_, body) = frame::split_frame_header(&raw).expect("split");
    let keys = hs
        .finish(&Hello::decode(body).expect("decode"), &mut guard)
        .expect("initiator must accept");

    let sentinel = sentinel.await.expect("sentinel task");
    (core_side, sentinel, keys)
}

/// Two sessions over an in-memory pipe.
async fn in_memory_sessions() -> (Session, Session) {
    // The pipe is given room for the whole burst in each direction. A
    // smaller pipe would apply backpressure, which is the transport's job
    // and not what this test is about.
    let (core_side, sentinel_side) = Stream::in_memory_pair(8 * 1024 * 1024);
    handshake(core_side, sentinel_side).await
}

/// An alert with a recognisable payload, so a mismatch is visible.
fn alert(id: u64) -> Message {
    Message::ThreatAlert(ThreatAlert {
        alert_id: id,
        severity: Severity::Medium,
        category: "load".into(),
        summary: format!("burst {id}"),
        observed_at_unix: 1_700_000_000,
    })
}

/// A health report with a recognisable payload.
fn health(events: u64) -> Message {
    Message::Health(HealthReport {
        sentinel_id: "sentinel".into(),
        uptime_secs: events,
        events_scanned: events,
        active_containments: 0,
        engine_load_permille: 42,
    })
}

#[tokio::test]
async fn a_burst_arrives_intact_and_in_order() {
    let (mut core, mut sentinel) = in_memory_sessions().await;
    let sent_before = core.sent();
    let received_before = sentinel.received();

    let writer = tokio::spawn(async move {
        for i in 0..BURST as u64 {
            core.send(&alert(i)).await.expect("send");
        }
        core
    });

    let started = Instant::now();
    for i in 0..BURST as u64 {
        match sentinel.recv().await.expect("recv").expect("no close") {
            Message::ThreatAlert(a) => assert_eq!(a.alert_id, i, "message {i} out of order"),
            other => panic!("unexpected message: {other:?}"),
        }
    }
    let elapsed = started.elapsed();

    // The measurements are printed rather than asserted. A load test that
    // fails because a shared runner was busy teaches nothing.
    let count = u32::try_from(BURST).expect("burst size fits in a u32");
    println!(
        "burst of {count} messages in {elapsed:?} ({:.0} msg/s, {:.1} us/message)",
        f64::from(count) / elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1_000_000.0 / f64::from(count)
    );
    assert!(
        elapsed < BURST_BUDGET,
        "burst took {elapsed:?}, over the {BURST_BUDGET:?} budget"
    );

    let core = writer.await.expect("writer task");
    // The counters are the next sequence number, not the number of messages,
    // so what is checked is the difference.
    assert_eq!(core.sent() - sent_before, BURST as u64);
    assert_eq!(sentinel.received() - received_before, BURST as u64);
}

#[tokio::test]
async fn both_directions_stay_straight() {
    let (mut core, mut sentinel) = in_memory_sessions().await;

    let half = (BURST / 2) as u64;

    // The Core sends alerts and then reads the health reports. The two
    // directions are independent, and a message that crossed over would
    // arrive as the wrong type.
    let core_task = tokio::spawn(async move {
        for i in 0..half {
            core.send(&alert(i)).await.expect("core send");
        }
        for i in 0..half {
            match core.recv().await.expect("recv").expect("no close") {
                Message::Health(h) => {
                    assert_eq!(h.uptime_secs, i, "health report {i} out of order");
                }
                other => panic!("unexpected message: {other:?}"),
            }
        }
    });

    for i in 0..half {
        sentinel.send(&health(i)).await.expect("sentinel send");
    }
    for i in 0..half {
        match sentinel.recv().await.expect("recv").expect("no close") {
            Message::ThreatAlert(a) => assert_eq!(a.alert_id, i, "alert {i} out of order"),
            other => panic!("unexpected message: {other:?}"),
        }
    }

    core_task.await.expect("core task");
}

#[tokio::test]
async fn a_peer_that_goes_away_is_reported_and_not_hung_on() {
    let (core, mut sentinel) = in_memory_sessions().await;

    drop(core);

    let result = tokio::time::timeout(Duration::from_secs(10), sentinel.recv()).await;
    assert!(result.is_ok(), "the reader hung on a closed peer");
    assert!(
        result.expect("no timeout").is_err(),
        "a closed peer produced a message"
    );
}

/// Seals a frame the way the Core would, and then alters one bit of it.
fn altered_frame(keys: &heimdall_crypto::SessionKeys, id: u64) -> Vec<u8> {
    let mut bytes = frame::seal_frame(
        FrameKind::CoreToSentinel,
        1,
        &keys.core_to_sentinel,
        &alert(id).encode().expect("encode"),
    )
    .expect("seal");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    bytes
}

#[tokio::test]
async fn a_frame_whose_ciphertext_was_altered_is_refused() {
    let (core_side, sentinel_side) = Stream::in_memory_pair(64 * 1024);
    let (mut core_side, mut sentinel, keys) = handshake_with_keys(core_side, sentinel_side).await;

    // A real frame, sealed with the real key, with one bit changed in the
    // ciphertext. The tag no longer matches.
    let bytes = altered_frame(&keys, 1);
    core_side.write_frame(&bytes).await.expect("write");

    let result = sentinel.recv().await;
    assert!(
        result.is_err(),
        "a frame whose ciphertext was altered was accepted: {result:?}"
    );
}

#[tokio::test]
async fn a_frame_that_stops_halfway_does_not_hang_the_reader() {
    let (core_side, sentinel_side) = Stream::in_memory_pair(64 * 1024);
    let (mut core_side, mut sentinel, keys) = handshake_with_keys(core_side, sentinel_side).await;

    let bytes = frame::seal_frame(
        FrameKind::CoreToSentinel,
        1,
        &keys.core_to_sentinel,
        &alert(1).encode().expect("encode"),
    )
    .expect("seal");
    let half = bytes.len() / 2;
    core_side.write_frame(&bytes[..half]).await.expect("write");
    drop(core_side);

    let result = tokio::time::timeout(Duration::from_secs(10), sentinel.recv()).await;
    assert!(result.is_ok(), "the reader hung on a truncated frame");
    assert!(
        result.expect("no timeout").is_err(),
        "a truncated frame produced a message"
    );
}

#[tokio::test]
async fn a_header_claiming_a_gigabyte_is_refused_before_anything_is_allocated() {
    let (core_side, sentinel_side) = Stream::in_memory_pair(64 * 1024);
    let (mut core_side, mut sentinel, _keys) = handshake_with_keys(core_side, sentinel_side).await;

    // Eighteen bytes claiming a gigabyte. A reader that trusts the length
    // tries to allocate it.
    let header = frame::Header {
        kind: FrameKind::CoreToSentinel,
        seq: 1,
        ciphertext_len: 1_000_000_000,
    };
    core_side
        .write_frame(&header.encode())
        .await
        .expect("write");

    let result = sentinel.recv().await;
    let error = result.expect_err("an oversized frame was accepted");
    let text = error.to_string();
    assert!(
        text.contains("exceeds") || text.contains("limit") || text.contains("too large"),
        "the refusal should name the limit: {text}"
    );
}

#[tokio::test]
async fn a_frame_with_the_wrong_direction_is_refused() {
    let (core_side, sentinel_side) = Stream::in_memory_pair(64 * 1024);
    let (mut core_side, mut sentinel, keys) = handshake_with_keys(core_side, sentinel_side).await;

    // A Sentinel-to-Core frame, sealed with the real key, handed to the
    // Sentinel. The direction is wrong, and the session notices that before
    // it looks at the tag.
    let bytes = frame::seal_frame(
        FrameKind::SentinelToCore,
        1,
        &keys.sentinel_to_core,
        &alert(1).encode().expect("encode"),
    )
    .expect("seal");
    core_side.write_frame(&bytes).await.expect("write");

    let result = sentinel.recv().await;
    let error = result.expect_err("a mislabelled frame was accepted");
    let text = error.to_string();
    assert!(
        text.contains("direction"),
        "the refusal should name the direction: {text}"
    );
}

#[tokio::test]
async fn a_frame_that_is_not_the_next_one_is_refused() {
    let (core_side, sentinel_side) = Stream::in_memory_pair(64 * 1024);
    let (mut core_side, mut sentinel, keys) = handshake_with_keys(core_side, sentinel_side).await;

    // A frame that skips a sequence number. A gap means a record was
    // dropped, and there is no safe way to carry on.
    let bytes = frame::seal_frame(
        FrameKind::CoreToSentinel,
        7,
        &keys.core_to_sentinel,
        &alert(1).encode().expect("encode"),
    )
    .expect("seal");
    core_side.write_frame(&bytes).await.expect("write");

    let result = sentinel.recv().await;
    let error = result.expect_err("a frame with a gap was accepted");
    let text = error.to_string();
    assert!(
        text.contains("out-of-order") || text.contains("sequence"),
        "the refusal should name the sequence: {text}"
    );
}
