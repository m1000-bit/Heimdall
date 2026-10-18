//! Heimdall Core: the orchestrator.
//!
//! Owns the two long-lived cryptographic identities, the link to Sentinel, and
//! the self-repair gate. The design lists Core as the interface, the command
//! engine and the code engine; in Phase 1 only the parts that carry security
//! weight are implemented, because those are the parts that are expensive to
//! retrofit.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use heimdall_crypto::{Identity, KeyStore, Passphrase, ReplayGuard, Signer, Suite};
use heimdall_ipc::{
    CloseReason, Listener, Message, Session, Severity,
    message::{HealthReport, ThreatAlert},
};

use crate::{
    error::{Error, Result},
    gate::{AuditEntry, Gate, PatchProposal, ProposalId, ProposalState},
};

/// Live status of the Core -> Sentinel link, as shown in the shell.
#[derive(Debug, Clone, Default)]
pub struct LinkStatus {
    pub connected: bool,
    pub sentinel_id: Option<String>,
    pub last_health: Option<HealthReport>,
    pub alerts_seen: u64,
    pub last_error: Option<String>,
}

/// Core's runtime state.
pub struct Orchestrator {
    identity: Identity,
    signer: Signer,
    keystore: KeyStore,
    pinned_peer: Identity,
    suite: Suite,
    replay_guard: ReplayGuard,
    gate: Gate,
    status: LinkStatus,
    /// Set when Sentinel reports an incident that Core should surface
    /// immediately, so the UI can break out of its normal loop.
    pending_alerts: Vec<ThreatAlert>,
    next_command_id: u64,
}

impl core::fmt::Debug for Orchestrator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Orchestrator")
            .field("identity", &self.identity.hex())
            .field("pinned_peer", &self.pinned_peer.hex())
            .field("suite", &self.suite)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl Orchestrator {
    /// Builds a Core instance with a freshly generated identity.
    ///
    /// In Phase 1 the identity is ephemeral. Loading a persistent identity from
    /// the keystore is Phase 4 work; doing it now would mean shipping an
    /// identity-provisioning story before there is anything worth signing.
    pub fn bootstrap(repository_root: impl Into<PathBuf>) -> Result<Self> {
        let (signer, identity) = Signer::generate();
        let (peer_signer, pinned_peer) = Signer::generate();

        // The keystore is opened in memory only in this phase. Its passphrase
        // derivation is exercised by the crypto tests; wiring it to a file here
        // would create an on-disk secret with no UI to protect it yet.
        let keystore = KeyStore::create(&Passphrase::from_utf8(b"ephemeral-phase-1"))?;

        // The demo peer identity is handed to Sentinel at startup. A real
        // deployment exchanges these out of band.
        let _ = peer_signer;

        Ok(Self {
            identity,
            signer,
            keystore,
            pinned_peer,
            suite: Suite::ChaCha20Poly1305,
            replay_guard: ReplayGuard::new(128),
            gate: Gate::new(repository_root),
            status: LinkStatus::default(),
            pending_alerts: Vec::new(),
            next_command_id: 1,
        })
    }

    /// Overrides the self-repair approval window. Shorter is safer; the default is
    /// [`DEFAULT_APPROVAL_WINDOW`].
    #[must_use]
    pub fn with_approval_window(mut self, window: Duration) -> Self {
        self.gate = std::mem::replace(&mut self.gate, Gate::new(std::path::PathBuf::new()))
            .with_approval_window(window);
        self
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn pinned_peer(&self) -> &Identity {
        &self.pinned_peer
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

    pub fn keystore(&self) -> &KeyStore {
        &self.keystore
    }

    /// Health of Sentinel as last reported, if the link has ever been up.
    pub fn sentinel_health(&self) -> Option<&HealthReport> {
        self.status.last_health.as_ref()
    }

    /// Alerts received since the UI last drained them.
    pub fn drain_alerts(&mut self) -> Vec<ThreatAlert> {
        std::mem::take(&mut self.pending_alerts)
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
                tracing::warn!(
                    severity = alert.severity.label(),
                    category = %alert.category,
                    "sentinel reported a threat"
                );
                self.status.alerts_seen += 1;
                // Critical and high alerts are surfaced immediately rather than
                // left in the queue: the user needs to know now.
                if alert.severity >= Severity::High {
                    self.pending_alerts.push(alert);
                }
                Ok(true)
            }
            Ok(Some(Message::Health(h))) => {
                self.status.last_health = Some(h.clone());
                self.status.sentinel_id = Some(h.sentinel_id);
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
    pub async fn contain(
        &mut self,
        session: &mut Session,
        incident_id: u64,
        scope: heimdall_ipc::message::ContainmentScope,
    ) -> Result<()> {
        let message = Message::Contain { incident_id, scope };
        session.send(&message).await?;
        Ok(())
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

    pub fn patch_state(&self, id: ProposalId) -> Result<ProposalState> {
        self.gate.state_of(id).map_err(Error::Gate)
    }

    /// The audit trail, newest last.
    pub fn audit_trail(&self) -> &[AuditEntry] {
        self.gate.audit()
    }
}

/// Shared handle used by the UI layer, which must not block the render loop.
pub type SharedOrchestrator = Arc<tokio::sync::Mutex<Orchestrator>>;

/// Default approval window. Kept short: an approval left open overnight is an
/// unreviewed approval.
pub const DEFAULT_APPROVAL_WINDOW: Duration = Duration::from_secs(300);

#[cfg(test)]
mod tests {
    use super::*;

    fn orchestrator() -> Orchestrator {
        Orchestrator::bootstrap("./repo")
            .unwrap()
            .with_approval_window(DEFAULT_APPROVAL_WINDOW)
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
}
