//! The Core-to-Sentinel link, driven from the UI thread without blocking it.
//!
//! # Why the socket lives on its own thread
//!
//! `eframe::App::update` is called on the main thread and must return promptly;
//! anything slow in it drops frames. An `await` on a socket read inside `update`
//! would do exactly that. So the session runs on a dedicated OS thread and talks
//! to the UI through a channel.
//!
//! # What crosses the boundary
//!
//! Only [`LinkEvent`] and outbound [`Message`]s, both plain data. The session --
//! and the keys it holds -- never leaves the network thread. That matters beyond
//! tidiness: a type that reaches the render path is a type that ends up in a
//! screenshot or a core dump.
//!
//! # Who updates Core
//!
//! The network thread decodes messages; the UI thread folds them into Core with
//! [`Orchestrator::observe_alert`] and [`Orchestrator::observe_health`]. Core is
//! single-threaded state and stays that way, so there is no lock held across an
//! `await` anywhere.
//!
//! # Failure
//!
//! A broken link is a state, not a crash. The thread reports it and the UI shows
//! it. Reconnection is an explicit operator action rather than an automatic
//! retry: a link that silently reconnects is a link that will happily reconnect
//! to whatever answered last time.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use heimdall_core::Orchestrator;
use heimdall_crypto::{ReplayGuard, Suite};
use heimdall_ipc::message::{ContainmentRecommendation, HealthReport, ThreatAlert};
use heimdall_ipc::{Message, Session};
use tokio::sync::mpsc as async_channel;

/// What the network thread tells the UI.
#[derive(Debug, Clone)]
pub enum LinkEvent {
    /// The handshake completed and the session is live.
    Connected { sentinel_identity: String },
    /// A threat alert arrived.
    Alert(ThreatAlert),
    /// Sentinel reported its health.
    Health(Box<HealthReport>),
    /// Sentinel recommended a containment. Advice, not an instruction: the
    /// operator decides whether it becomes an order.
    Recommendation(Box<ContainmentRecommendation>),
    /// The session ended. `reason` is for display.
    Disconnected { reason: String },
    /// The link could not be established.
    ///
    /// `retryable` separates "no Sentinel is running" from "the peer was not who
    /// we pinned": the first is fixed by starting a process, the second is a
    /// security event. The UI colours them differently for that reason.
    Failed { reason: String, retryable: bool },
}

/// Where the link is, for display. Deliberately coarser than [`LinkEvent`] so the
/// UI never has to interpret an error string to decide what to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkState {
    #[default]
    Idle,
    Connecting,
    Live,
    Failed,
}

impl LinkState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "not connected",
            Self::Connecting => "connecting",
            Self::Live => "live",
            Self::Failed => "failed",
        }
    }

    pub const fn colour(self) -> egui::Color32 {
        match self {
            Self::Idle => egui::Color32::from_rgb(150, 150, 155),
            Self::Connecting => egui::Color32::from_rgb(220, 170, 60),
            Self::Live => egui::Color32::from_rgb(70, 190, 110),
            Self::Failed => egui::Color32::from_rgb(220, 80, 80),
        }
    }
}

/// The UI's handle to the link.
pub struct Link {
    events: Receiver<LinkEvent>,
    outbound: async_channel::UnboundedSender<Message>,
    /// Directives queued but not yet written. Tracked here because the channel is
    /// unbounded: a Sentinel that stops reading would otherwise grow it without
    /// limit while the UI reported every send as successful.
    queued: Arc<AtomicUsize>,
    state: LinkState,
    started: Option<Instant>,
    /// Bounded so a wedged Sentinel cannot grow the UI's memory without limit.
    seen: Vec<LinkEvent>,
    max_seen: usize,
}

const MAX_SEEN: usize = 512;
/// Directives that may be outstanding. A UI that queues more than this against a
/// daemon that has stopped reading has a problem the operator needs to see.
const MAX_QUEUED: usize = 64;

impl Link {
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        // The channel is replaced in `connect`; this one exists so `drain` is
        // well-defined before the first connection attempt.
        drop(tx);
        let (outbound, _rx) = async_channel::unbounded_channel();
        Self {
            events: rx,
            outbound,
            queued: Arc::new(AtomicUsize::new(0)),
            state: LinkState::Idle,
            started: None,
            seen: Vec::new(),
            max_seen: MAX_SEEN,
        }
    }

    /// Starts a connection attempt on a background thread.
    ///
    /// Returns immediately; the outcome arrives as a [`LinkEvent`]. Any previous
    /// session is abandoned: this is a fresh link, not a renegotiation.
    pub fn connect(&mut self, endpoint: &str, orchestrator: &Orchestrator) {
        self.state = LinkState::Connecting;
        self.started = Some(Instant::now());
        self.seen.clear();

        let (tx, rx) = std::sync::mpsc::channel();
        self.events = rx;

        let (signer, pinned) = orchestrator.link_credentials();
        let pinned_hex = pinned.hex();
        let endpoint = endpoint.to_string();
        let (outbound, outbound_rx) = async_channel::unbounded_channel();
        self.outbound = outbound;
        let queued = Arc::new(AtomicUsize::new(0));
        self.queued = Arc::clone(&queued);

        let spawned = std::thread::Builder::new()
            .name("heimdall-link".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx.send(LinkEvent::Failed {
                            reason: format!("cannot start the network runtime: {e}"),
                            retryable: false,
                        });
                        return;
                    }
                };

                runtime.block_on(async move {
                    let mut guard = ReplayGuard::new(HANDSHAKE_WINDOW);
                    let session = match heimdall_ipc::session::connect_as_core(
                        &endpoint,
                        signer,
                        pinned,
                        Suite::ChaCha20Poly1305,
                        &mut guard,
                    )
                    .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            let reason = e.to_string();
                            let _ = tx.send(LinkEvent::Failed {
                                retryable: is_retryable(&reason),
                                reason,
                            });
                            return;
                        }
                    };

                    let _ = tx.send(LinkEvent::Connected {
                        sentinel_identity: pinned_hex,
                    });

                    let outcome = read_loop(session, &tx, Some(outbound_rx), &queued).await;
                    let _ = tx.send(LinkEvent::Disconnected { reason: outcome });
                });
            });

        if spawned.is_err() {
            // The OS refused a thread. Report it rather than leaving the UI
            // stuck on "connecting" forever.
            self.state = LinkState::Failed;
            tracing::error!("cannot start the link thread");
        }
    }

    /// Drains everything that has arrived since the last call.
    ///
    /// Called once per frame; must never block.
    pub fn drain(&mut self) -> Vec<LinkEvent> {
        let mut out = Vec::new();
        while let Ok(e) = self.events.try_recv() {
            {
                match &e {
                    LinkEvent::Connected { .. } => self.state = LinkState::Live,
                    LinkEvent::Failed { .. } | LinkEvent::Disconnected { .. } => {
                        self.state = LinkState::Failed;
                    }
                    LinkEvent::Alert(_) | LinkEvent::Health(_) | LinkEvent::Recommendation(_) => {}
                }
                self.remember(&e);
                out.push(e);
            }
        }
        out
    }

    /// Recent events, oldest first, for the activity panel. Includes the ones
    /// already drained, so the panel does not go blank when it is scrolled.
    pub fn history(&self) -> &[LinkEvent] {
        &self.seen
    }

    fn remember(&mut self, event: &LinkEvent) {
        self.seen.push(event.clone());
        if self.seen.len() > self.max_seen {
            let drop = self.seen.len() - self.max_seen;
            self.seen.drain(..drop);
        }
    }

    pub const fn state(&self) -> LinkState {
        self.state
    }

    pub fn uptime(&self) -> Duration {
        self.started.map_or(Duration::ZERO, |s| s.elapsed())
    }

    /// Whether a session is currently available for sending.
    pub const fn is_live(&self) -> bool {
        matches!(self.state, LinkState::Live)
    }

    /// Queues a directive for Sentinel.
    ///
    /// Returns `false` if the link is down or the queue is full. Never blocks and
    /// never reports success for something that was not queued: a directive the
    /// UI believes was sent but was not is worse than one it knows failed.
    pub fn send(&self, message: &Message) -> bool {
        if !self.is_live() {
            return false;
        }
        // Checked before the send, and again implicitly by the reader's
        // decrement: the count only ever rises here.
        if self.queued.load(Ordering::Relaxed) >= MAX_QUEUED {
            tracing::warn!(
                limit = MAX_QUEUED,
                "outbound queue is full; sentinel is not reading"
            );
            return false;
        }
        match self.outbound.send(message.clone()) {
            Ok(()) => {
                self.queued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(e) => {
                tracing::debug!(error = %e, "outbound channel is closed");
                false
            }
        }
    }

    /// How many directives are waiting to go out. For the UI's pending count.
    pub fn pending(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    /// Forgets the session state so the next `connect` starts clean.
    pub fn reset(&mut self) {
        self.state = LinkState::Idle;
        self.started = None;
        self.seen.clear();
    }
}

impl Default for Link {
    fn default() -> Self {
        Self::new()
    }
}

/// Window of accepted handshake sequence numbers. Generous, because it covers a
/// single handshake; a real replay would have to land inside it to matter.
const HANDSHAKE_WINDOW: usize = 128;

/// Reads until the session ends, forwarding inbound messages and flushing
/// whatever the UI queued.
///
/// # Why the send is outside the `select!`
///
/// `Session::send` and `Session::recv` both need `&mut session`, so they cannot be
/// polled concurrently. The `select!` therefore yields a *wake* value -- the recv
/// future is dropped at the end of the statement -- and the send happens after,
/// where the borrow is free. Selecting and then acting, rather than selecting
/// while acting.
async fn read_loop(
    mut session: Session,
    tx: &Sender<LinkEvent>,
    mut outbound: Option<async_channel::UnboundedReceiver<Message>>,
    queued: &AtomicUsize,
) -> String {
    loop {
        // Once the UI drops its sender the channel closes; stop selecting on it
        // and let the session end on its own rather than spinning on a closed
        // channel, which returns immediately and would burn the CPU.
        let wake = match &mut outbound {
            Some(rx) => {
                tokio::select! {
                    inbound = session.recv() => Wake::Inbound(inbound),
                    queued = rx.recv() => match queued {
                        Some(m) => Wake::Outbound(m),
                        None => Wake::OutboundClosed,
                    },
                }
            }
            None => Wake::Inbound(session.recv().await),
        };

        match wake {
            Wake::Inbound(Ok(Some(msg))) => {
                let event = match msg {
                    Message::ThreatAlert(a) => LinkEvent::Alert(a),
                    Message::Health(h) => LinkEvent::Health(Box::new(h)),
                    Message::ContainmentRecommendation(r) => LinkEvent::Recommendation(Box::new(r)),
                    Message::Ack { ref_id } => {
                        tracing::debug!(ref_id, "sentinel acknowledged a directive");
                        continue;
                    }
                    // Anything else is Sentinel sending something it should not.
                    // Inbound is alerts, health, containment advice and acks; a
                    // command or a contain order coming the other way is a
                    // protocol violation, not something to act on.
                    other => {
                        tracing::warn!(message = ?other, "ignoring an unexpected inbound message");
                        continue;
                    }
                };
                if tx.send(event).is_err() {
                    return "the shell closed the link".to_string();
                }
            }
            Wake::Outbound(message) => {
                // The directive has left the queue and is going to the socket.
                // Decrementing here rather than after the write would let a
                // stalled write hide a full queue.
                queued.fetch_sub(1, Ordering::Relaxed);
                if let Err(e) = session.send(&message).await {
                    return e.to_string();
                }
            }
            Wake::Inbound(Ok(None)) => return "sentinel closed the session".to_string(),
            Wake::Inbound(Err(e)) => return e.to_string(),
            Wake::OutboundClosed => {
                // The UI is gone, so nothing can be sent any more. Keep the
                // session until Sentinel closes it: dropping the reader here
                // would strand a peer that is still mid-report.
                outbound = None;
            }
        }
    }
}

/// What woke the read loop.
enum Wake {
    Inbound(heimdall_ipc::Result<Option<Message>>),
    Outbound(Message),
    OutboundClosed,
}

/// Distinguishes "nobody is listening" from "the peer was not who we pinned".
///
/// They need different operator actions, so the UI is told which it was rather
/// than left parsing a message. A handshake that failed on *identity* is a
/// security event, not a transient condition.
fn is_retryable(reason: &str) -> bool {
    const ABSENT: [&str; 5] = [
        "not found",
        "no such file",
        "connection refused",
        "cannot find",
        "os error 2",
    ];
    let lowered = reason.to_ascii_lowercase();
    ABSENT.iter().any(|m| lowered.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_sentinel_is_retryable_but_a_bad_pin_is_not() {
        assert!(is_retryable(
            "connect: No such file or directory (os error 2)"
        ));
        assert!(is_retryable("connection refused"));

        // Identity mismatches are security events: retrying them on a loop is
        // just noise aimed at whoever is answering.
        assert!(!is_retryable(
            "peer identity mismatch: expected abcd, got ef01"
        ));
        assert!(!is_retryable("handshake tag mismatch"));
    }

    #[test]
    fn history_is_bounded_and_keeps_the_newest() {
        let mut link = Link::new();
        link.max_seen = 4;
        for i in 0..10 {
            link.remember(&LinkEvent::Disconnected {
                reason: i.to_string(),
            });
        }
        assert_eq!(link.history().len(), 4);
        let oldest = format!("{:?}", link.history()[0]);
        let newest = format!("{:?}", link.history()[3]);
        assert!(oldest.contains('6'), "oldest kept entry is 6, got {oldest}");
        assert!(newest.contains('9'), "newest kept entry is 9, got {newest}");
    }

    #[test]
    fn a_link_that_never_connected_refuses_to_queue() {
        let link = Link::new();
        let msg = Message::Ack { ref_id: 1 };
        assert!(!link.is_live());
        assert!(!link.send(&msg));
    }

    #[test]
    fn state_and_uptime_are_sane_before_the_first_attempt() {
        let mut link = Link::new();
        assert_eq!(link.state(), LinkState::Idle);
        assert_eq!(link.uptime(), Duration::ZERO);
        assert!(link.drain().is_empty());
    }
}
