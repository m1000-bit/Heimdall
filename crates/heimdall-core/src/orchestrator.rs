//! Heimdall Core: the orchestrator.
//!
//! Owns Core's long-term identity, the link to Sentinel, and the self-repair
//! gate. The design lists Core as the interface, the command engine and the code
//! engine; only the parts that carry security weight are implemented, because
//! those are the parts that are expensive to retrofit.
//!
//! Two ways to construct one:
//!
//! * [`Orchestrator::provision`] -- the real path. Loads a durable identity from
//!   the keystore and a pinned Sentinel identity from [`crate::link`].
//! * [`Orchestrator::bootstrap`] -- in-memory, for tests and for the demo mode
//!   in the shell. Its identities are ephemeral and cannot authenticate across
//!   processes, which is why it is not the default.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use heimdall_crypto::identity::{KeystoreLocation, PersistedIdentity};
use heimdall_crypto::{Identity, KeyStore, Passphrase, ReplayGuard, Signer, Suite};
use heimdall_ipc::{
    CloseReason, Listener, Message, Session, Severity,
    message::{ContainmentRecommendation, HealthReport, ThreatAlert},
};

use crate::{
    analysis::{Analyzer, Finding, RepairPlan},
    error::{Error, Result},
    gate::{AuditEntry, AuditSink, Gate, PatchProposal, ProposalId, ProposalState},
    link::{PeerPin, PinLocation},
    reasoning::{ReasoningBackend, ReasoningRequest, Reply},
};

/// Live status of the Core -> Sentinel link, as shown in the shell.
#[derive(Debug, Clone, Default)]
pub struct LinkStatus {
    pub connected: bool,
    pub sentinel_id: Option<String>,
    pub last_health: Option<HealthReport>,
    pub alerts_seen: u64,
    pub last_error: Option<String>,
    /// How Core decided to trust the peer, for display.
    pub trust_basis: Option<crate::link::TrustBasis>,
}

/// Core's runtime state.
pub struct Orchestrator {
    identity: Identity,
    signer: Signer,
    keystore: Option<KeyStore>,
    pinned_peer: Identity,
    peer_pin: Option<PeerPin>,
    suite: Suite,
    replay_guard: ReplayGuard,
    gate: Gate,
    status: LinkStatus,
    /// Set when Sentinel reports an incident that Core should surface
    /// immediately, so the UI can break out of its normal loop.
    pending_alerts: Vec<ThreatAlert>,
    /// Bounded mirror of recent alerts, fed to the backend as context.
    alerts: Vec<ThreatAlert>,
    next_command_id: u64,
    /// True when this run minted a fresh identity. Surfaced so an unexpected
    /// rotation is visible rather than silent.
    identity_created_this_run: bool,
    /// The conversational engine. Boxed so an alternative -- a model-backed
    /// backend, a test double -- can be substituted without the orchestrator
    /// knowing.
    backend: Box<dyn ReasoningBackend>,
    /// The last reply, kept so the UI can show what Core concluded.
    last_reply: Option<Reply>,
    /// Repairs the analyser found, waiting to be proposed one at a time.
    ///
    /// The gate shows one proposal at a time on purpose, so a queue is the only
    /// honest way to offer several repairs: each is reviewed separately, and
    /// refusing one does not throw away the rest.
    repair_queue: Vec<RepairPlan>,
    /// Containment recommendations Sentinel has sent and nobody has decided on.
    pending_containments: Vec<ContainmentRecommendation>,
}

impl core::fmt::Debug for Orchestrator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Orchestrator")
            .field("identity", &self.identity.hex())
            .field("pinned_peer", &self.pinned_peer.hex())
            .field("suite", &self.suite)
            .field("status", &self.status)
            .field("identity_created_this_run", &self.identity_created_this_run)
            .finish_non_exhaustive()
    }
}

impl Orchestrator {
    /// The real construction path: durable identity, durable peer pin.
    ///
    /// `expected_sentinel` may be supplied by configuration. When it is, the
    /// first run verifies the pin it creates rather than trusting whatever is on
    /// disk, and later runs fail if the peer has changed.
    pub fn provision(
        repository_root: impl Into<PathBuf>,
        keystore: &KeystoreLocation,
        passphrase: &Passphrase,
        expected_sentinel: Option<&str>,
    ) -> Result<Self> {
        Self::provision_in(
            repository_root,
            keystore,
            passphrase,
            &PinLocation::for_role("sentinel")?,
            expected_sentinel,
        )
    }

    /// [`Self::provision`], with the pin's location chosen by the caller.
    ///
    /// The location is a parameter rather than an environment lookup on purpose.
    /// A pin is a trust decision about one specific peer, and two Core instances
    /// sharing one pin file cannot both be right -- so isolation has to be
    /// something the caller asks for explicitly. A test, a second instance, or a
    /// portable install each pass their own path.
    pub fn provision_in(
        repository_root: impl Into<PathBuf>,
        keystore: &KeystoreLocation,
        passphrase: &Passphrase,
        pin_location: &PinLocation,
        expected_sentinel: Option<&str>,
    ) -> Result<Self> {
        let identity = heimdall_crypto::identity::provision(keystore, passphrase)?;
        let identity_created = identity.was_created();
        let pin = pin_location.load_or_pin("sentinel", expected_sentinel)?;

        let mut orchestrator = Self::assemble(
            repository_root,
            &identity,
            pin.identity.clone(),
            Some(keystore.read(passphrase)?),
            Some(pin.clone()),
        );

        orchestrator.identity_created_this_run = identity_created;
        orchestrator.status.trust_basis = Some(pin.basis);
        tracing::info!(
            identity = %orchestrator.identity.hex(),
            sentinel = %pin.identity.hex(),
            basis = pin.basis.label(),
            "core provisioned"
        );
        Ok(orchestrator)
    }

    /// In-memory construction. Identities are ephemeral: two processes built this
    /// way cannot authenticate each other, because neither holds the other's
    /// key. Use it for tests and the shell's demo mode.
    pub fn bootstrap(repository_root: impl Into<PathBuf>) -> Result<Self> {
        let (signer, identity) = Signer::generate();
        let (peer_signer, pinned_peer) = Signer::generate();
        let _ = peer_signer;
        Ok(Self::assemble(
            repository_root,
            &PersistedIdentity::from_signer(signer, identity),
            pinned_peer,
            None,
            None,
        ))
    }

    fn assemble(
        repository_root: impl Into<PathBuf>,
        identity: &PersistedIdentity,
        pinned_peer: Identity,
        keystore: Option<KeyStore>,
        peer_pin: Option<PeerPin>,
    ) -> Self {
        Self {
            identity: identity.identity().clone(),
            signer: identity.signer(),
            keystore,
            pinned_peer,
            peer_pin,
            suite: Suite::ChaCha20Poly1305,
            replay_guard: ReplayGuard::new(128),
            gate: Gate::new(repository_root),
            status: LinkStatus::default(),
            pending_alerts: Vec::new(),
            alerts: Vec::new(),
            next_command_id: 1,
            identity_created_this_run: false,
            backend: Box::new(crate::reasoning::DeterministicBackend::new()),
            last_reply: None,
            repair_queue: Vec::new(),
            pending_containments: Vec::new(),
        }
    }

    /// Replaces the conversational engine.
    #[must_use]
    pub fn with_backend(mut self, backend: Box<dyn ReasoningBackend>) -> Self {
        self.backend = backend;
        self
    }

    /// Asks the backend one question, with whatever context Core can justify
    /// passing.
    ///
    /// The request deliberately carries alert *summaries*, never alert internals,
    /// never key material, and never file contents. The prompt path is where a
    /// backend's access boundary has to be drawn, so it is drawn narrow here
    /// rather than left to whichever backend is plugged in.
    pub fn reason(&mut self, prompt: &str) -> Reply {
        let request = ReasoningRequest::new(prompt).with_alerts(
            self.alerts
                .iter()
                .map(|a| format!("[{}] {}: {}", a.severity.label(), a.category, a.summary))
                .collect(),
        );
        let reply = self.backend.reason(&request);
        tracing::debug!(
            backend = self.backend.name(),
            confidence = reply.confidence,
            "reasoned about operator input"
        );
        self.last_reply = Some(reply.clone());
        reply
    }

    /// The most recent reply, if any.
    pub fn last_reply(&self) -> Option<&Reply> {
        self.last_reply.as_ref()
    }

    /// Routes a reply's action. Directives go to Sentinel; proposals go to the
    /// gate and nowhere else.
    ///
    /// Returns the proposal id when the reply asked for a code change, so the UI
    /// can jump to the review panel.
    pub async fn dispatch(
        &mut self,
        reply: &Reply,
        session: Option<&mut Session>,
    ) -> Result<Option<ProposalId>> {
        match &reply.action {
            crate::reasoning::ReplyAction::None
            | crate::reasoning::ReplyAction::Declined { .. } => Ok(None),
            crate::reasoning::ReplyAction::ProposePatch(p) => {
                let id = self.propose_patch(&p.target_path, &p.summary, &p.rationale, &p.diff)?;
                Ok(Some(id))
            }
            crate::reasoning::ReplyAction::Directive(d) => {
                let Some(session) = session else {
                    self.status.last_error =
                        Some("the reply needs Sentinel, and there is no live link".into());
                    return Ok(None);
                };
                let args = d.arguments.clone();
                self.command(session, &d.intent, args).await?;
                Ok(None)
            }
        }
    }

    /// Overrides the self-repair approval window. Shorter is safer; the default is
    /// [`DEFAULT_APPROVAL_WINDOW`].
    #[must_use]
    pub fn with_approval_window(mut self, window: Duration) -> Self {
        let replacement = Gate::new(std::path::PathBuf::new()).with_approval_window(window);
        self.gate = std::mem::replace(&mut self.gate, replacement);
        self
    }

    /// True when this run minted a new long-term identity. A rotation is a
    /// security event, so it must never pass silently.
    pub fn identity_was_created(&self) -> bool {
        self.identity_created_this_run
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn pinned_peer(&self) -> &Identity {
        &self.pinned_peer
    }

    /// The persisted peer pin, if this instance was provisioned rather than
    /// bootstrapped.
    pub fn peer_pin(&self) -> Option<&PeerPin> {
        self.peer_pin.as_ref()
    }

    pub fn link_status(&self) -> &LinkStatus {
        &self.status
    }

    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    pub fn gate_mut(&mut self) -> &mut Gate {
        &mut self.gate
    }

    /// The keystore, when this instance was provisioned rather than bootstrapped.
    pub fn keystore(&self) -> Option<&KeyStore> {
        self.keystore.as_ref()
    }

    /// Health of Sentinel as last reported, if the link has ever been up.
    pub fn sentinel_health(&self) -> Option<&HealthReport> {
        self.status.last_health.as_ref()
    }

    /// Alerts received since the UI last drained them.
    pub fn drain_alerts(&mut self) -> Vec<ThreatAlert> {
        std::mem::take(&mut self.pending_alerts)
    }

    /// The material needed to open one authenticated session, for callers that
    /// drive the socket themselves -- the desktop shell, which must not await
    /// inside its render loop.
    ///
    /// The replay guard is deliberately not returned: it guards the handshake
    /// only, and the session carries its own sequence counters from then on.
    pub fn link_credentials(&self) -> (Signer, Identity) {
        (self.signer.clone(), self.pinned_peer.clone())
    }

    /// Folds one inbound alert into Core's state.
    ///
    /// Separate from the socket so a caller that has already decoded a message
    /// -- the shell's link thread -- takes the same path as [`Self::poll_once`].
    /// Two copies of the history trimming would be one copy too many.
    pub fn observe_alert(&mut self, alert: ThreatAlert) {
        tracing::warn!(
            severity = alert.severity.label(),
            category = %alert.category,
            "sentinel reported a threat"
        );
        self.status.alerts_seen += 1;

        // Keep a bounded history for backend context. Unbounded growth here
        // would be a memory-growth vector fed by the peer, and the context is
        // capped at the tail anyway.
        self.alerts.push(alert.clone());
        if self.alerts.len() > MAX_ALERT_HISTORY {
            let drop = self.alerts.len() - MAX_ALERT_HISTORY;
            self.alerts.drain(..drop);
        }

        // Critical and high alerts are surfaced immediately rather than left in
        // the queue: the user needs to know now.
        if alert.severity >= Severity::High {
            self.pending_alerts.push(alert);
        }
    }

    /// Folds one health report into Core's state.
    pub fn observe_health(&mut self, report: HealthReport) {
        self.status.last_health = Some(report.clone());
        self.status.sentinel_id = Some(report.sentinel_id);
    }

    /// Records that the link is gone, and why.
    ///
    /// The reason is kept because "disconnected" with no explanation is the
    /// least useful thing a monitor can tell an operator.
    pub fn note_link_down(&mut self, reason: impl Into<String>) {
        self.status.connected = false;
        self.status.last_error = Some(reason.into());
    }

    /// Connects to Sentinel and completes the mutual handshake.
    pub async fn connect(&mut self, endpoint: &str) -> Result<Session> {
        let session = heimdall_ipc::session::connect_as_core(
            endpoint,
            self.signer.clone(),
            self.pinned_peer.clone(),
            self.suite,
            &mut self.replay_guard,
        )
        .await?;

        self.status.connected = true;
        self.status.last_error = None;
        tracing::info!(identity = %self.identity.hex(), "core link established");
        Ok(session)
    }

    /// Listens for a Sentinel connection. Used by the embedded single-process
    /// mode and by integration tests.
    pub async fn listen(endpoint: &str) -> Result<Listener> {
        Listener::bind(endpoint).await.map_err(Error::from)
    }

    /// Polls the session once, folding whatever arrives into Core's state.
    ///
    /// Returns `Ok(false)` when the peer closed cleanly.
    pub async fn poll_once(&mut self, session: &mut Session) -> Result<bool> {
        match session.recv().await {
            Ok(Some(Message::ThreatAlert(alert))) => {
                self.observe_alert(alert);
                Ok(true)
            }
            Ok(Some(Message::Health(h))) => {
                self.observe_health(h);
                Ok(true)
            }
            Ok(Some(Message::ContainmentRecommendation(r))) => {
                self.observe_containment_recommendation(r);
                Ok(true)
            }
            Ok(Some(Message::Ack { ref_id })) => {
                tracing::debug!(ref_id, "sentinel acknowledged a directive");
                Ok(true)
            }
            Ok(Some(_)) => Ok(true),
            Ok(None) => {
                self.status.connected = false;
                Ok(false)
            }
            Err(e) => {
                // An error here means the channel can no longer be trusted:
                // either authentication failed or ordering broke. Both are
                // terminal, and both are recorded before the link is dropped.
                self.status.connected = false;
                self.status.last_error = Some(e.to_string());
                tracing::error!(error = %e, "core link failed");
                Err(Error::from(e))
            }
        }
    }

    /// Sends a command to Sentinel.
    pub async fn command(
        &mut self,
        session: &mut Session,
        intent: &str,
        arguments: Vec<String>,
    ) -> Result<u64> {
        let command_id = self.next_command_id;
        self.next_command_id += 1;
        session
            .send(&Message::Command(heimdall_ipc::message::Command {
                command_id,
                intent: intent.to_string(),
                arguments,
            }))
            .await?;
        Ok(command_id)
    }

    /// Asks Sentinel to contain an incident.
    ///
    /// `approved_by` names the person who authorised it. The order is refused
    /// by the peer when the name is empty: an instruction to change the host
    /// that nobody owns is not an instruction.
    pub async fn contain(
        &mut self,
        session: &mut Session,
        incident_id: u64,
        scope: heimdall_ipc::message::ContainmentScope,
        approved_by: &str,
    ) -> Result<()> {
        let message = self.containment_order(incident_id, scope, approved_by)?;
        session.send(&message).await?;
        Ok(())
    }

    /// Builds a containment order, refusing one that nobody owns.
    ///
    /// The message is returned rather than sent because the session lives on the
    /// link thread: the UI queues it on the same channel as every other
    /// directive. The check lives here so that the shell cannot invent a
    /// well-formed order the Core would have refused.
    pub fn containment_order(
        &self,
        incident_id: u64,
        scope: heimdall_ipc::message::ContainmentScope,
        approved_by: &str,
    ) -> Result<Message> {
        let approved_by = approved_by.trim();
        if approved_by.is_empty() {
            return Err(Error::Core(
                "a containment order must name the operator who approved it".into(),
            ));
        }
        Ok(Message::ContainmentOrder(
            heimdall_ipc::message::ContainmentOrder {
                incident_id,
                scope,
                approved_by: approved_by.to_string(),
            },
        ))
    }

    /// Closes the link cleanly.
    pub async fn shutdown(&mut self, session: &mut Session) {
        session.close(CloseReason::UserRequested).await;
        self.status.connected = false;
    }

    // -- Self-repair surface -------------------------------------------------

    /// The proposal the user is currently being asked about, if any.
    pub fn pending_patch(&self) -> Option<&PatchProposal> {
        self.gate.pending()
    }

    /// Submits a self-repair proposal. Nothing is written until the user
    /// approves it through [`Self::approve_patch`].
    pub fn propose_patch(
        &mut self,
        target_path: &str,
        summary: &str,
        rationale: &str,
        diff: &str,
    ) -> Result<ProposalId> {
        let id = self.gate.submit(
            target_path,
            summary,
            rationale,
            diff,
            "heimdall-core/self-repair",
        )?;
        tracing::info!(
            proposal = id,
            path = target_path,
            "self-repair proposal submitted"
        );
        Ok(id)
    }

    /// Records the user's decision to allow the change and returns the token
    /// the applier must present.
    pub fn approve_patch(
        &mut self,
        id: ProposalId,
        user: &str,
    ) -> Result<crate::gate::ApprovalToken> {
        self.gate.approve(id, user).map_err(Error::Gate)
    }

    /// Records the user's refusal.
    pub fn reject_patch(&mut self, id: ProposalId, user: &str, reason: &str) -> Result<()> {
        self.gate.reject(id, user, reason).map_err(Error::Gate)
    }

    /// Exchanges an approval for the change to write.
    ///
    /// There is deliberately no other route from "the AI wants to change the
    /// code" to "the code changed".
    pub fn authorise_application(
        &mut self,
        token: &crate::gate::ApprovalToken,
    ) -> Result<crate::gate::Application> {
        self.gate.consume(token).map_err(Error::Gate)
    }

    /// Authorises and writes, in one step.
    ///
    /// The pair [`Self::authorise_application`] and [`Self::apply_approved`]
    /// exists for a caller that wants to inspect the authorisation before
    /// touching the disk -- the UI shows what it is about to write. This method
    /// is for a caller that has already shown it.
    ///
    /// A write that fails is recorded against the proposal, so the audit trail
    /// says "approved and failed" rather than leaving a silent gap that reads
    /// like the change was never attempted.
    pub fn apply_approved(
        &mut self,
        token: &crate::gate::ApprovalToken,
    ) -> Result<crate::apply::Applied> {
        let application = self.authorise_application(token)?;
        let id = application.id;
        match crate::apply::Applier::new(self.gate.repository_root()).apply(&application) {
            Ok(applied) => Ok(applied),
            Err(e) => {
                // Best-effort: if even the failure cannot be recorded, the original
                // error is the one worth surfacing.
                let _ = self.gate.report_failure(id, &e.to_string());
                Err(e)
            }
        }
    }

    pub fn patch_state(&self, id: ProposalId) -> Result<ProposalState> {
        self.gate.state_of(id).map_err(Error::Gate)
    }

    /// The audit trail, newest last.
    pub fn audit_trail(&self) -> &[AuditEntry] {
        self.gate.audit()
    }

    // -- Analysis-driven self-repair -----------------------------------------

    /// Analyses the repository and reports everything it finds.
    ///
    /// Nothing is proposed here. A finding is an observation; a proposal is a
    /// request for permission to change something, and the two are separated so
    /// that "the analyser is sure" can never be mistaken for "the change is
    /// approved".
    pub fn scan_repository(&self) -> Vec<Finding> {
        Analyzer::new(self.gate.repository_root()).scan()
    }

    /// Analyses the repository and queues the repairs it is willing to make.
    ///
    /// Returns how many repairs are waiting. The queue is per file, because a
    /// proposal is confined to one path.
    pub fn queue_self_repairs(&mut self) -> Result<usize> {
        let plans = Analyzer::new(self.gate.repository_root()).plans();
        self.repair_queue = plans;
        let count = self.repair_queue.len();
        tracing::info!(repairs = count, "queued self-repair candidates");
        Ok(count)
    }

    /// Proposes the next queued repair, if any.
    ///
    /// One at a time: the gate supersedes any proposal still waiting, so
    /// offering several at once would show the operator a different diff from
    /// the one they approved.
    pub fn propose_next_repair(&mut self) -> Result<Option<ProposalId>> {
        if self.gate.pending().is_some() {
            return Ok(None);
        }
        let Some(plan) = self.repair_queue.first().cloned() else {
            return Ok(None);
        };
        let path = plan
            .edits
            .first()
            .map_or_else(String::new, |e| e.path.clone());
        if path.is_empty() {
            self.repair_queue.remove(0);
            return Ok(None);
        }
        self.repair_queue.remove(0);
        let id = self.propose_patch(&path, &plan.summary, &plan.rationale, &plan.diff)?;
        Ok(Some(id))
    }

    /// How many repairs are waiting to be proposed.
    pub fn queued_repairs(&self) -> usize {
        self.repair_queue.len()
    }

    // -- Containment ---------------------------------------------------------

    /// Records a containment recommendation from Sentinel.
    ///
    /// A recommendation is advice. It is kept until the operator decides, and
    /// it never becomes an action on its own.
    pub fn observe_containment_recommendation(
        &mut self,
        recommendation: ContainmentRecommendation,
    ) {
        tracing::warn!(
            incident = recommendation.incident_id,
            scope = %recommendation.scope.label(),
            severity = recommendation.severity.label(),
            "sentinel recommends a containment"
        );
        if self.pending_containments.len() < MAX_PENDING_CONTAINMENTS {
            self.pending_containments.push(recommendation);
        } else {
            tracing::warn!("dropping a containment recommendation: the queue is full");
        }
    }

    /// The containment recommendations nobody has decided on yet.
    pub fn pending_containments(&self) -> &[ContainmentRecommendation] {
        &self.pending_containments
    }

    /// Takes the recommendations for the UI to show, and forgets them.
    pub fn drain_containment_recommendations(&mut self) -> Vec<ContainmentRecommendation> {
        std::mem::take(&mut self.pending_containments)
    }

    /// Authorises a containment and sends the order to Sentinel.
    ///
    /// The approver's name travels with the order, because "the AI contained
    /// the host" and "an operator authorised the containment" are different
    /// events.
    pub async fn approve_containment(
        &mut self,
        session: &mut Session,
        incident_id: u64,
        scope: heimdall_ipc::message::ContainmentScope,
        approved_by: &str,
    ) -> Result<()> {
        self.contain(session, incident_id, scope, approved_by).await
    }

    // -- Durable audit -------------------------------------------------------

    /// Attaches a durable, encrypted audit log to the gate.
    ///
    /// The gate keeps its own history either way; this makes that history
    /// survive the process. The log is written as the decisions happen, so a
    /// crash cannot lose the record of what was approved.
    pub fn attach_audit_log(
        &mut self,
        path: impl Into<PathBuf>,
        passphrase: &heimdall_crypto::Passphrase,
    ) -> Result<()> {
        let log = crate::audit::AuditLog::open(path, passphrase)?;
        self.gate.set_sink(Box::new(LogSink { log }));
        Ok(())
    }
}

/// Writes every gate transition into a durable audit log.
struct LogSink {
    log: crate::audit::AuditLog,
}

impl AuditSink for LogSink {
    fn record(&mut self, entry: &AuditEntry) {
        if let Err(e) = self.log.append(entry) {
            // The in-memory trail still has the entry, so the UI is not wrong;
            // but the durable log has just lost a record, and that is worth a
            // loud failure rather than a line in a log file.
            tracing::error!(error = %e, "cannot append to the audit log");
        }
    }
}

/// Shared handle used by the UI layer, which must not block the render loop.
pub type SharedOrchestrator = Arc<tokio::sync::Mutex<Orchestrator>>;

/// Default approval window. Kept short: an approval left open overnight is an
/// unreviewed approval.
pub const DEFAULT_APPROVAL_WINDOW: Duration = Duration::from_secs(300);

/// How many alerts Core keeps for conversational context. Only the tail is ever
/// passed to a backend, so a larger history costs memory and buys nothing.
pub const MAX_ALERT_HISTORY: usize = 200;

/// How many containment recommendations Core holds for the operator.
///
/// Bounded, because the recommendations come from the peer: an unbounded queue
/// would be a memory-growth vector fed by whatever Sentinel chooses to report.
pub const MAX_PENDING_CONTAINMENTS: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn orchestrator() -> Orchestrator {
        Orchestrator::bootstrap("./repo")
            .unwrap()
            .with_approval_window(DEFAULT_APPROVAL_WINDOW)
    }

    /// A git repository containing one committable file, or `None` without git.
    fn scratch_repo(tag: &str) -> Option<PathBuf> {
        let root =
            std::env::temp_dir().join(format!("heimdall-repair-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).ok()?;
        let git = |args: &[&str]| -> bool {
            Command::new("git")
                .args(args)
                .current_dir(&root)
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
                .output()
                .is_ok_and(|o| o.status.success())
        };
        if !git(&["init", "--quiet"]) {
            return None;
        }
        std::fs::write(root.join("a.txt"), "one\ntwo\nthree\n").ok()?;
        if !git(&["add", "."]) || !git(&["commit", "--quiet", "-m", "base"]) {
            return None;
        }
        Some(root)
    }

    #[test]
    fn an_approved_repair_reaches_the_disk_and_the_audit_trail() {
        let Some(root) = scratch_repo("happy") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        let mut o = Orchestrator::bootstrap(&root).unwrap();

        let id = o
            .propose_patch(
                "a.txt",
                "Replace a literal",
                "The value was a magic number in a loop bound.",
                "--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n",
            )
            .unwrap();
        let token = o.approve_patch(id, "operator").unwrap();
        let applied = o
            .apply_approved(&token)
            .expect("the approved repair should land");

        assert_eq!(applied.proposal_id, id);
        assert_eq!(applied.approved_by, "operator");
        let after = std::fs::read_to_string(root.join("a.txt")).unwrap();
        assert!(
            after.contains("TWO"),
            "the file must carry the change: {after}"
        );
        assert_eq!(o.patch_state(id).unwrap(), ProposalState::Applied);
        assert!(
            o.audit_trail()
                .iter()
                .any(|e| e.event == crate::gate::AuditEvent::Applied)
        );
    }

    #[test]
    fn a_repair_that_cannot_land_is_recorded_rather_than_swallowed() {
        let Some(root) = scratch_repo("stale") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        let mut o = Orchestrator::bootstrap(&root).unwrap();

        // Context that does not match the file on disk: the model read a version
        // that no longer exists.
        let id = o
            .propose_patch(
                "a.txt",
                "Stale context",
                "Based on a version of the file that has since changed.",
                "--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n gone\n-gone\n+gone\n gone\n",
            )
            .unwrap();
        let token = o.approve_patch(id, "operator").unwrap();
        let err = o
            .apply_approved(&token)
            .expect_err("a stale diff must not be written");

        assert!(err.to_string().contains("apply"), "got: {err}");
        assert_eq!(o.patch_state(id).unwrap(), ProposalState::Failed);
        assert!(
            o.audit_trail()
                .iter()
                .any(|e| e.event == crate::gate::AuditEvent::ApplicationFailed),
            "a failed write must be visible in the audit trail"
        );
    }

    #[test]
    fn a_token_cannot_be_reused_for_a_second_write() {
        let Some(root) = scratch_repo("reuse") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        let mut o = Orchestrator::bootstrap(&root).unwrap();
        let id = o
            .propose_patch(
                "a.txt",
                "Once",
                "One approval, one write.",
                "--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n",
            )
            .unwrap();
        let token = o.approve_patch(id, "operator").unwrap();
        o.apply_approved(&token)
            .expect("the first write should land");

        // The same token again: the gate has already consumed it, and a token
        // that could be replayed would let one approval mean two changes.
        assert!(o.apply_approved(&token).is_err());
    }

    #[test]
    fn the_self_repair_path_requires_user_approval() {
        let mut o = orchestrator();
        let id = o
            .propose_patch(
                "crates/heimdall-core/src/gate.rs",
                "Fix a bounds check",
                "The comparison used the wrong bound.",
                "@@ -1 +1 @@\n-a\n+b\n",
            )
            .unwrap();

        assert_eq!(o.patch_state(id).unwrap(), ProposalState::AwaitingApproval);
        assert!(o.pending_patch().is_some());

        // Refusing is always available and needs no token.
        o.reject_patch(id, "operator", "not now").unwrap();
        assert_eq!(o.patch_state(id).unwrap(), ProposalState::Rejected);
        assert!(
            o.audit_trail()
                .iter()
                .any(|e| matches!(e.event, crate::gate::AuditEvent::Rejected))
        );
    }

    #[test]
    fn a_token_minted_by_another_gate_is_rejected() {
        // An approval is a capability issued by one gate. A second gate instance,
        // even one holding the same proposal, must not honour it: the nonce is
        // not in its used-token set and its state machine never reached Approved.
        let mut o = orchestrator();
        o.propose_patch("src/a.rs", "what", "why", "diff").unwrap();

        let mut impostor = Gate::new("./repo").with_approval_window(DEFAULT_APPROVAL_WINDOW);
        let smuggled = impostor
            .submit("src/a.rs", "what", "why", "diff", "model")
            .unwrap();
        let token = impostor.approve(smuggled, "someone").unwrap();

        assert!(o.authorise_application(&token).is_err());
    }

    #[test]
    fn out_of_repository_patches_are_refused() {
        let mut o = orchestrator();
        assert!(
            o.propose_patch(
                "../../../etc/passwd",
                "escalate",
                "self-modifying code should not escape the repo",
                "@@ -1 +1 @@\n-a\n+b\n"
            )
            .is_err()
        );
    }

    #[test]
    fn debug_output_shows_public_identities_only() {
        let o = orchestrator();
        let rendered = format!("{o:?}");
        assert!(rendered.contains(&o.identity().hex()));
        assert!(!rendered.contains("passphrase"));
    }

    #[test]
    fn a_scan_reports_findings_without_proposing_anything() {
        let Some(root) = scratch_repo("scan") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        std::fs::write(
            root.join("a.rs"),
            "pub fn f(v: u32) -> u32 {\n    dbg!(v);\n    v * 2\n}\n",
        )
        .expect("write");

        let o = Orchestrator::bootstrap(&root).unwrap();
        let findings = o.scan_repository();
        assert!(
            findings
                .iter()
                .any(|f| f.rule == crate::analysis::Rule::DebugPrint)
        );
        assert!(
            o.pending_patch().is_none(),
            "a finding is an observation, not a request to change something"
        );
        assert_eq!(o.audit_trail().len(), 0);
    }

    #[test]
    fn queued_repairs_are_proposed_one_at_a_time() {
        let Some(root) = scratch_repo("queue") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        std::fs::write(
            root.join("a.rs"),
            "pub fn f(v: u32) -> u32 {\n    dbg!(v);\n    v * 2\n}\n",
        )
        .expect("write");
        std::fs::write(
            root.join("b.rs"),
            "pub fn g(v: u32) -> u32 {\n    dbg!(v);\n    v * 3\n}\n",
        )
        .expect("write");

        let mut o = Orchestrator::bootstrap(&root).unwrap();
        assert_eq!(o.queue_self_repairs().unwrap(), 2);

        let first = o.propose_next_repair().unwrap().expect("a proposal");
        assert!(o.pending_patch().is_some());
        assert_eq!(
            o.propose_next_repair().unwrap(),
            None,
            "a second proposal would supersede the one the operator is reading"
        );

        // The operator decides, and only then does the next repair appear.
        o.reject_patch(first, "operator", "not now").unwrap();
        let second = o.propose_next_repair().unwrap().expect("the next repair");
        assert_ne!(first, second);
    }

    #[test]
    fn the_audit_log_outlives_the_process() {
        let Some(root) = scratch_repo("audit") else {
            eprintln!("git unavailable; skipping");
            return;
        };
        let log_path = root.join("audit.log");
        let passphrase = heimdall_crypto::Passphrase::from_utf8(b"test-passphrase");

        let mut o = Orchestrator::bootstrap(&root).unwrap();
        o.attach_audit_log(&log_path, &passphrase)
            .expect("an audit log");

        let id = o
            .propose_patch(
                "a.txt",
                "What",
                "Why",
                "--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n",
            )
            .unwrap();
        let token = o.approve_patch(id, "operator").unwrap();
        o.apply_approved(&token).expect("the repair lands");

        // A fresh reader sees the same history, and the chain verifies.
        let reopened = crate::audit::AuditLog::open(&log_path, &passphrase).expect("reopen");
        assert!(reopened.len() >= 3, "got {} entries", reopened.len());
        assert!(
            reopened
                .entries()
                .iter()
                .any(|e| e.event == crate::gate::AuditEvent::Approved)
        );
        crate::audit::AuditLog::verify(&log_path, &passphrase).expect("the chain verifies");
    }

    #[test]
    fn a_containment_recommendation_waits_for_a_decision() {
        let mut o = orchestrator();
        assert_eq!(o.pending_containments().len(), 0);

        o.observe_containment_recommendation(ContainmentRecommendation {
            incident_id: 7,
            scope: heimdall_ipc::message::ContainmentScope::Process { pid: 4242 },
            severity: Severity::High,
            reason: "the process is beaconing".into(),
        });

        assert_eq!(o.pending_containments().len(), 1);
        let drained = o.drain_containment_recommendations();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].incident_id, 7);
        assert_eq!(o.pending_containments().len(), 0);
    }

    #[test]
    fn a_containment_order_names_the_operator_who_approved_it() {
        let o = orchestrator();
        let scope = heimdall_ipc::message::ContainmentScope::Process { pid: 4242 };

        let message = o
            .containment_order(7, scope.clone(), "  gianluca  ")
            .expect("an order with an author is well formed");

        match message {
            Message::ContainmentOrder(order) => {
                assert_eq!(order.incident_id, 7);
                assert_eq!(order.scope, scope);
                assert_eq!(order.approved_by, "gianluca");
            }
            other => panic!("expected a containment order, got {other:?}"),
        }
    }

    #[test]
    fn a_containment_order_without_an_author_is_refused() {
        let o = orchestrator();
        let scope = heimdall_ipc::message::ContainmentScope::HostQuarantine;
        for name in ["", "   ", "\t\n"] {
            let refused = o.containment_order(7, scope.clone(), name);
            assert!(
                refused.is_err(),
                "an order that names nobody must not be built: {name:?}"
            );
        }
    }
}
