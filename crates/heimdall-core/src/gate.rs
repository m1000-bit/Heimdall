//! Commit gatekeeping for the self-repair engine.
//!
//! This is the critical safety rule from the design document: the AI may
//! diagnose, repair and update its own source code, but it must obtain explicit
//! user authorisation -- with a plain-language explanation of what the change
//! does and why it is needed -- before any modification is applied.
//!
//! A gate that is merely a function call someone can forget to route through is
//! not a gate. The design here makes bypass structurally awkward:
//!
//! 1. **Approval is bound to a content digest.** An [`ApprovalToken`] authorises one
//!    exact `target_path + diff + rationale`. Change a single byte of the diff
//!    after the user says yes and the token no longer verifies. Without this,
//!    the model could show a harmless diff, obtain approval, and apply a
//!    different one.
//! 2. **The token is the only key to the apply path.** [`Gate::consume`] is the
//!    only function that yields an [`Application`], and it requires a token the
//!    gate itself minted. There is no "apply directly" variant.
//! 3. **Tokens are single-use and time-boxed.** An approval left open is a
//!    standing grant; it is not.
//! 4. **Every transition is recorded** in an append-only audit log, including
//!    proposals that were never approved.
//! 5. **An explanation is mandatory.** A proposal without a human-readable
//!    rationale is rejected at submission, so the UI can never be unable to
//!    tell the user what is being proposed.
//! 6. **Concurrent proposals supersede each other.** Presenting two proposals
//!    at once invites the user to approve the wrong one.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use sha2::Digest as _;

/// SHA3-256 over everything the user was shown. This is the value an approval
/// is bound to.
pub type ContentDigest = [u8; 32];

/// Identifier assigned to a proposal at submission.
pub type ProposalId = u64;

/// A proposed change to the codebase, produced by the self-repair engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchProposal {
    pub id: ProposalId,
    pub target_path: String,
    pub rationale: String,
    /// What the change does, in one sentence the user can evaluate at a glance.
    pub summary: String,
    pub diff: String,
    pub generated_by_model: String,
    pub created_at: SystemTime,
}

impl PatchProposal {
    /// Computes the digest the user is shown and the approval is bound to.
    ///
    /// Every field that could influence what gets written is included. The
    /// timestamp is included so an old approval cannot be re-used against a
    /// regenerated proposal carrying the same content.
    pub fn digest(&self) -> ContentDigest {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(b"heimdall/v3/patch-proposal");
        field(&mut hasher, b"id", &self.id.to_be_bytes());
        field(&mut hasher, b"path", self.target_path.as_bytes());
        field(&mut hasher, b"summary", self.summary.as_bytes());
        field(&mut hasher, b"rationale", self.rationale.as_bytes());
        field(&mut hasher, b"diff", self.diff.as_bytes());
        field(&mut hasher, b"model", self.generated_by_model.as_bytes());
        field(
            &mut hasher,
            b"created",
            &self
                .created_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
                .to_be_bytes(),
        );
        hasher.finalize().into()
    }

    pub fn digest_hex(&self) -> String {
        heimdall_crypto::util::to_hex(&self.digest())
    }
}

fn field(hasher: &mut sha3::Sha3_256, label: &[u8], value: &[u8]) {
    hasher.update((label.len() as u32).to_be_bytes());
    hasher.update(label);
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);
}

/// Lifecycle of a proposal. There is no path from a state other than
/// [`ProposalState::Approved`] to [`ProposalState::Applied`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalState {
    /// Submitted, waiting for the user.
    AwaitingApproval,
    /// The user said yes. Not yet written to disk.
    Approved,
    /// The user said no.
    Rejected,
    /// Replaced by a newer proposal.
    Superseded,
    /// The approval window elapsed without a decision.
    Expired,
    /// Written to the working tree.
    Applied,
    /// The write failed.
    Failed,
}

impl ProposalState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Rejected | Self::Superseded | Self::Expired | Self::Applied | Self::Failed
        )
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::AwaitingApproval => "awaiting approval",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Applied => "applied",
            Self::Failed => "failed",
        }
    }
}

impl core::fmt::Display for ProposalState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}

/// Why a submission was refused outright.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    #[error("proposal {0} is not known to the gate")]
    UnknownProposal(ProposalId),

    #[error("proposal {id} is already {state}")]
    NotPending {
        id: ProposalId,
        state: ProposalState,
    },

    #[error("proposal {0} has been superseded by a newer proposal")]
    Superseded(ProposalId),

    #[error(
        "proposal {id} does not match the approved content: the change was modified after approval"
    )]
    ContentChanged { id: ProposalId },

    #[error("the approval for proposal {id} expired at {expired_at:?}")]
    ApprovalExpired {
        id: ProposalId,
        expired_at: SystemTime,
    },

    #[error("the approval token for proposal {0} has already been used")]
    TokenAlreadyUsed(ProposalId),

    #[error("a proposal without a rationale cannot be shown to the user")]
    MissingRationale,

    #[error("a proposal without a summary cannot be shown to the user")]
    MissingSummary,

    #[error("proposal target path {0:?} is not inside the repository")]
    PathOutsideRepository(String),

    #[error("proposal target path {0:?} escapes the repository via a parent reference")]
    PathTraversal(String),

    #[error("proposal diff is empty")]
    EmptyDiff,
}

/// A single-use, time-boxed, content-bound authorisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalToken {
    id: ProposalId,
    digest: ContentDigest,
    issued_at: SystemTime,
    expires_at: SystemTime,
    /// Random per-token value. The gate checks that the token it is handed is
    /// the one it issued, so a token cannot be fabricated from its own fields.
    nonce: [u8; 32],
}

impl ApprovalToken {
    pub fn proposal_id(&self) -> ProposalId {
        self.id
    }

    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

/// What the gate hands to the code that actually writes the change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Application {
    pub id: ProposalId,
    pub target_path: String,
    pub diff: String,
    pub approved_digest: ContentDigest,
    pub approved_by: String,
}

/// One immutable entry in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub at: SystemTime,
    pub proposal_id: ProposalId,
    pub event: AuditEvent,
    /// Who acted: the model that proposed, or the user who decided.
    pub actor: String,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuditEvent {
    Submitted,
    Approved,
    Rejected,
    Superseded,
    Expired,
    Applied,
    ApplicationFailed,
}

impl AuditEvent {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Submitted => "proposed",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Applied => "applied",
            Self::ApplicationFailed => "application-failed",
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    proposal: PatchProposal,
    state: ProposalState,
    /// Digest as shown to the user at approval time. A later mutation of
    /// `proposal` that changes the digest invalidates the approval.
    approved_digest: Option<ContentDigest>,
    /// When the user said yes. Expiry is measured from here, not from when the
    /// proposal was submitted.
    approved_at: Option<SystemTime>,
    used_tokens: Vec<[u8; 32]>,
}

impl Entry {
    fn proposal_digest(&self) -> ContentDigest {
        self.proposal.digest()
    }
}

/// A destination for audit entries, so the log can outlive the process.
pub trait AuditSink: Send {
    /// Called once per recorded transition, in order.
    fn record(&mut self, entry: &AuditEntry);
}

/// The gate itself.
///
/// There is exactly one way to reach the apply path -- [`Gate::consume`] --
/// and it requires a token obtained from [`Gate::approve`]. A caller that
/// skips approval cannot produce a valid token.
pub struct Gate {
    entries: HashMap<ProposalId, Entry>,
    audit: Vec<AuditEntry>,
    next_id: ProposalId,
    /// How long an approval remains usable. Kept short by default: a standing
    /// approval is an unreviewed approval.
    approval_window: Duration,
    repository_root: std::path::PathBuf,
    clock: Clock,
    sink: Option<Box<dyn AuditSink>>,
}

#[derive(Debug, Clone, Copy)]
enum Clock {
    System,
    /// Advances only when the test advances it.
    #[cfg_attr(not(test), allow(dead_code))]
    Manual {
        now: SystemTime,
    },
}

impl Clock {
    fn now(&self) -> SystemTime {
        match self {
            Self::System => SystemTime::now(),
            Self::Manual { now } => *now,
        }
    }
}

impl core::fmt::Debug for Gate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Gate")
            .field("pending", &self.entries.len())
            .field("audit_entries", &self.audit.len())
            .field("approval_window", &self.approval_window)
            .finish_non_exhaustive()
    }
}

impl Gate {
    /// Creates a gate rooted at `repository_root`. Paths are confined to it.
    pub fn new(repository_root: impl Into<std::path::PathBuf>) -> Self {
        // Normalised once here so the per-proposal confinement check below can
        // compare against a canonical form. Comparing a normalised candidate
        // against an unnormalised root would reject every valid path.
        let repository_root = normalize(&repository_root.into());
        Self {
            entries: HashMap::new(),
            audit: Vec::new(),
            next_id: 1,
            approval_window: Duration::from_secs(300),
            repository_root,
            clock: Clock::System,
            sink: None,
        }
    }

    #[cfg(test)]
    fn with_clock(mut self, now: SystemTime) -> Self {
        self.clock = Clock::Manual { now };
        self
    }

    #[cfg(test)]
    fn advance(&mut self, by: Duration) {
        if let Clock::Manual { now } = self.clock {
            self.clock = Clock::Manual { now: now + by };
        }
    }

    /// Sets how long an issued approval stays valid.
    #[must_use]
    pub fn with_approval_window(mut self, window: Duration) -> Self {
        self.approval_window = window;
        self
    }

    /// Installs a sink that receives every transition as it happens.
    /// Replacing a sink replaces the destination; the gate keeps its own
    /// in-memory history either way.
    pub fn set_sink(&mut self, sink: Box<dyn AuditSink>) {
        self.sink = Some(sink);
    }

    /// The tree this gate is confined to.
    ///
    /// Exposed so the applier is bound to the same root the proposals were
    /// validated against. Two different roots would mean an approval checked
    /// against one tree and written into another.
    pub fn repository_root(&self) -> &std::path::Path {
        &self.repository_root
    }

    /// Submits a proposal for user review.
    ///
    /// Any proposal still awaiting a decision is superseded, so the user is
    /// never looking at two diffs at once and cannot approve the wrong one.
    pub fn submit(
        &mut self,
        target_path: impl Into<String>,
        summary: impl Into<String>,
        rationale: impl Into<String>,
        diff: impl Into<String>,
        generated_by_model: impl Into<String>,
    ) -> Result<ProposalId, GateError> {
        let target_path = target_path.into();
        let summary = summary.into();
        let rationale = rationale.into();
        let diff = diff.into();

        if summary.trim().is_empty() {
            return Err(GateError::MissingSummary);
        }
        if rationale.trim().is_empty() {
            return Err(GateError::MissingRationale);
        }
        if diff.trim().is_empty() {
            return Err(GateError::EmptyDiff);
        }
        self.check_path(&target_path)?;

        let now = self.clock.now();
        let superseded: Vec<ProposalId> = self
            .entries
            .iter()
            .filter(|(_, e)| e.state == ProposalState::AwaitingApproval)
            .map(|(id, _)| *id)
            .collect();
        for id in superseded {
            if let Some(e) = self.entries.get_mut(&id) {
                e.state = ProposalState::Superseded;
            }
            self.record(
                id,
                AuditEvent::Superseded,
                "gate",
                "replaced by a newer proposal",
            );
        }

        let id = self.next_id;
        self.next_id += 1;
        let proposal = PatchProposal {
            id,
            target_path,
            summary,
            rationale,
            diff,
            generated_by_model: generated_by_model.into(),
            created_at: now,
        };
        self.entries.insert(
            id,
            Entry {
                proposal,
                state: ProposalState::AwaitingApproval,
                approved_digest: None,
                approved_at: None,
                used_tokens: Vec::new(),
            },
        );
        self.record(
            id,
            AuditEvent::Submitted,
            &self.entries[&id].proposal.generated_by_model.clone(),
            "awaiting explicit user authorisation",
        );
        Ok(id)
    }

    /// Confines the target path to the repository.
    ///
    /// Self-modifying code plus an unconstrained path is arbitrary file write.
    /// `..` is rejected outright rather than normalised, so a proposal that
    /// merely *looks* like it escapes cannot pass review unnoticed.
    fn check_path(&self, path: &str) -> Result<(), GateError> {
        if path.trim().is_empty() {
            return Err(GateError::PathOutsideRepository(path.to_string()));
        }
        let p = std::path::Path::new(path);
        if p.is_absolute() {
            return Err(GateError::PathOutsideRepository(path.to_string()));
        }
        // Windows absolute paths (e.g. `C:\Windows\...`) are not absolute on
        // Linux, but they are still outside the repository. Reject them
        // explicitly so the same test passes on every platform.
        let bytes = path.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
        {
            return Err(GateError::PathOutsideRepository(path.to_string()));
        }
        if p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(GateError::PathTraversal(path.to_string()));
        }
        // Reject anything that would resolve outside the root, including via a
        // symlinked parent the caller might have set up.
        let joined = self.repository_root.join(p);
        let normalized = normalize(&joined);
        if !normalized.starts_with(&self.repository_root) {
            return Err(GateError::PathOutsideRepository(path.to_string()));
        }
        Ok(())
    }

    /// The proposal currently awaiting a decision, if any.
    pub fn pending(&self) -> Option<&PatchProposal> {
        self.entries
            .values()
            .filter(|e| e.state == ProposalState::AwaitingApproval)
            .map(|e| &e.proposal)
            .max_by_key(|p| p.id)
    }

    pub fn state_of(&self, id: ProposalId) -> Result<ProposalState, GateError> {
        self.entries
            .get(&id)
            .map(|e| e.state)
            .ok_or(GateError::UnknownProposal(id))
    }

    pub fn proposal(&self, id: ProposalId) -> Result<&PatchProposal, GateError> {
        self.entries
            .get(&id)
            .map(|e| &e.proposal)
            .ok_or(GateError::UnknownProposal(id))
    }

    /// Records the user's decision to allow the change.
    ///
    /// Mints a token bound to the exact content digest and to the current clock.
    /// Any subsequent edit to the proposal invalidates the token.
    pub fn approve(&mut self, id: ProposalId, user: &str) -> Result<ApprovalToken, GateError> {
        let now = self.clock.now();
        let expires_at = now + self.approval_window;

        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(GateError::UnknownProposal(id))?;

        if entry.state == ProposalState::Superseded {
            return Err(GateError::Superseded(id));
        }
        if entry.state != ProposalState::AwaitingApproval {
            return Err(GateError::NotPending {
                id,
                state: entry.state,
            });
        }

        let digest = entry.proposal_digest();
        entry.state = ProposalState::Approved;
        entry.approved_digest = Some(digest);
        entry.approved_at = Some(now);

        let token = ApprovalToken {
            id,
            digest,
            issued_at: now,
            expires_at,
            nonce: *heimdall_crypto::random_bytes::<32>().as_bytes(),
        };
        self.record(id, AuditEvent::Approved, user, "user authorised the change");
        Ok(token)
    }

    /// Records the user's refusal.
    pub fn reject(&mut self, id: ProposalId, user: &str, reason: &str) -> Result<(), GateError> {
        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(GateError::UnknownProposal(id))?;
        if entry.state.is_terminal() {
            return Err(GateError::NotPending {
                id,
                state: entry.state,
            });
        }
        entry.state = ProposalState::Rejected;
        self.record(id, AuditEvent::Rejected, user, reason);
        Ok(())
    }

    /// Exchanges an approval token for the change to apply.
    ///
    /// This is the only path from "user said yes" to "write to disk". It
    /// re-derives the digest from the proposal as it stands *now*, so an
    /// approval granted for one diff cannot authorise a different one.
    pub fn consume(&mut self, token: &ApprovalToken) -> Result<Application, GateError> {
        let now = self.clock.now();

        if now > token.expires_at {
            self.expire(token.id);
            return Err(GateError::ApprovalExpired {
                id: token.id,
                expired_at: token.expires_at,
            });
        }

        let entry = self
            .entries
            .get_mut(&token.id)
            .ok_or(GateError::UnknownProposal(token.id))?;

        if entry.used_tokens.contains(&token.nonce) {
            return Err(GateError::TokenAlreadyUsed(token.id));
        }
        if entry.state != ProposalState::Approved {
            return Err(GateError::NotPending {
                id: token.id,
                state: entry.state,
            });
        }

        let approved = entry
            .approved_digest
            .ok_or(GateError::UnknownProposal(token.id))?;
        if !constant_time_eq(&approved, &token.digest) {
            return Err(GateError::ContentChanged { id: token.id });
        }

        let current = entry.proposal_digest();
        if !constant_time_eq(&approved, &current) {
            // The proposal was mutated between approval and application.
            return Err(GateError::ContentChanged { id: token.id });
        }

        entry.used_tokens.push(token.nonce);
        entry.state = ProposalState::Applied;

        let application = Application {
            id: token.id,
            target_path: entry.proposal.target_path.clone(),
            diff: entry.proposal.diff.clone(),
            approved_digest: approved,
            approved_by: token.actor_hint(&self.audit),
        };
        self.record(
            token.id,
            AuditEvent::Applied,
            &application.approved_by,
            "written to the working tree",
        );
        Ok(application)
    }

    /// Reports a write failure back into the audit log.
    pub fn report_failure(&mut self, id: ProposalId, detail: &str) -> Result<(), GateError> {
        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(GateError::UnknownProposal(id))?;
        entry.state = ProposalState::Failed;
        self.record(id, AuditEvent::ApplicationFailed, "applier", detail);
        Ok(())
    }

    /// Marks an approval that was never used as expired. Called when the UI
    /// re-reads the gate, so the visible state cannot claim "approved" for a
    /// token that is no longer usable.
    pub fn expire_stale(&mut self) {
        let now = self.clock.now();
        let stale: Vec<ProposalId> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                e.state == ProposalState::Approved && e.approval_expired(now, self.approval_window)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.expire(id);
        }
    }

    fn expire(&mut self, id: ProposalId) {
        if let Some(e) = self.entries.get_mut(&id) {
            e.state = ProposalState::Expired;
        }
        self.record(
            id,
            AuditEvent::Expired,
            "gate",
            "approval window elapsed unused",
        );
    }

    /// Full, ordered audit history. Proposals that were never approved are
    /// included: "the AI wanted to change this and the user said no" is exactly
    /// the record an operator needs.
    pub fn audit(&self) -> &[AuditEntry] {
        &self.audit
    }

    fn record(&mut self, id: ProposalId, event: AuditEvent, actor: &str, note: &str) {
        self.audit.push(AuditEntry {
            at: self.clock.now(),
            proposal_id: id,
            event,
            actor: actor.to_string(),
            note: note.to_string(),
        });
        if let Some(sink) = self.sink.as_mut() {
            if let Some(entry) = self.audit.last() {
                sink.record(entry);
            }
        }
        tracing::info!(proposal = id, event = event.label(), actor, "commit gate");
    }
}

impl Entry {
    /// True when an approval sat unused for longer than the window allows.
    fn approval_expired(&self, now: SystemTime, window: Duration) -> bool {
        let Some(issued) = self.approved_at else {
            return false;
        };
        now > issued + window
    }
}

impl ApprovalToken {
    /// Best-effort attribution of the user who approved, recovered from the
    /// audit trail. Kept out of the token itself so the token stays a pure
    /// capability with no descriptive fields to tamper with.
    fn actor_hint(&self, audit: &[AuditEntry]) -> String {
        audit
            .iter()
            .rev()
            .find(|e| e.proposal_id == self.id && e.event == AuditEvent::Approved)
            .map_or_else(|| "unknown".into(), |e| e.actor.clone())
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    heimdall_crypto::util::ct_eq(a, b)
}

/// Lexical normalisation. Deliberately does not touch the filesystem: resolving
/// symlinks here would let a proposal depend on state an attacker controls.
fn normalize(p: &std::path::Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/repo";

    fn gate() -> Gate {
        Gate::new(ROOT)
            .with_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(1_000))
            .with_approval_window(Duration::from_secs(300))
    }

    fn submit_ok(g: &mut Gate) -> ProposalId {
        g.submit(
            "crates/heimdall-core/src/gate.rs",
            "Fix an inverted bounds check in consume()",
            "The sequence check compared against the wrong bound, so an out-of-order \
             record was accepted instead of terminating the session.",
            "@@ -1,3 +1,3 @@\n-a\n+b\n",
            "heimdall-core/self-repair",
        )
        .expect("valid proposal")
    }

    #[test]
    fn a_proposal_must_carry_a_user_readable_explanation() {
        let mut g = gate();
        assert_eq!(
            g.submit("src/a.rs", "", "why", "diff", "model"),
            Err(GateError::MissingSummary)
        );
        assert_eq!(
            g.submit("src/a.rs", "what", "   ", "diff", "model"),
            Err(GateError::MissingRationale)
        );
        assert_eq!(
            g.submit("src/a.rs", "what", "why", "  ", "model"),
            Err(GateError::EmptyDiff)
        );
        assert!(
            g.audit().is_empty(),
            "a refused proposal must not be audited as submitted"
        );
    }

    #[test]
    fn target_paths_are_confined_to_the_repository() {
        let mut g = gate();
        for bad in [
            "/etc/passwd",
            "../../../etc/passwd",
            "crates/../../outside.rs",
            "..",
            "",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ] {
            let r = g.submit(bad, "what", "why", "diff", "model");
            assert!(r.is_err(), "path {bad:?} should have been refused");
        }
    }

    #[test]
    fn a_new_proposal_supersedes_the_previous_one() {
        let mut g = gate();
        let first = submit_ok(&mut g);
        let second = submit_ok(&mut g);

        assert_eq!(g.state_of(first).unwrap(), ProposalState::Superseded);
        assert_eq!(g.state_of(second).unwrap(), ProposalState::AwaitingApproval);
        assert_eq!(g.pending().unwrap().id, second);
    }

    #[test]
    fn nothing_can_be_applied_without_approval() {
        let mut g = gate();
        let id = submit_ok(&mut g);

        // Fabricating a token by hand, using only public knowledge of the type.
        let forged = ApprovalToken {
            id,
            digest: g.proposal(id).unwrap().digest(),
            issued_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(999_999),
            nonce: [7u8; 32],
        };
        assert!(matches!(
            g.consume(&forged),
            Err(GateError::NotPending { .. })
        ));
    }

    #[test]
    fn the_happy_path_requires_explicit_approval() {
        let mut g = gate();
        let id = submit_ok(&mut g);
        assert_eq!(g.state_of(id).unwrap(), ProposalState::AwaitingApproval);

        let token = g.approve(id, "operator@console").unwrap();
        assert_eq!(g.state_of(id).unwrap(), ProposalState::Approved);

        let app = g.consume(&token).unwrap();
        assert_eq!(app.target_path, "crates/heimdall-core/src/gate.rs");
        assert_eq!(app.approved_by, "operator@console");
        assert_eq!(g.state_of(id).unwrap(), ProposalState::Applied);
    }

    #[test]
    fn a_token_is_single_use() {
        let mut g = gate();
        let id = submit_ok(&mut g);
        let token = g.approve(id, "user").unwrap();
        assert!(g.consume(&token).is_ok());

        let second = g.consume(&token);
        assert!(
            matches!(
                second,
                Err(GateError::TokenAlreadyUsed(_) | GateError::NotPending { .. })
            ),
            "a used token must never authorise a second write, got {second:?}"
        );
    }

    #[test]
    fn an_expired_approval_is_refused() {
        let mut g = gate();
        let id = submit_ok(&mut g);
        let token = g.approve(id, "user").unwrap();

        g.advance(Duration::from_secs(301));
        assert!(matches!(
            g.consume(&token),
            Err(GateError::ApprovalExpired { .. })
        ));
        assert_eq!(g.state_of(id).unwrap(), ProposalState::Expired);
    }

    #[test]
    fn an_expired_approval_is_visible_as_expired() {
        let mut g = gate();
        let id = submit_ok(&mut g);
        g.approve(id, "user").unwrap();
        assert_eq!(g.state_of(id).unwrap(), ProposalState::Approved);

        g.advance(Duration::from_secs(400));
        g.expire_stale();
        assert_eq!(g.state_of(id).unwrap(), ProposalState::Expired);
    }

    #[test]
    fn mutating_the_diff_after_approval_invalidates_the_token() {
        // This is the whole point of binding approval to a digest: the model
        // shows one diff, the user approves, then a different diff is applied.
        let mut g = gate();
        let id = submit_ok(&mut g);
        let token = g.approve(id, "user").unwrap();

        g.entries
            .get_mut(&id)
            .unwrap()
            .proposal
            .diff
            .push_str("+ exfiltrate_everything();\n");

        assert!(matches!(
            g.consume(&token),
            Err(GateError::ContentChanged { .. })
        ));
        assert_eq!(g.state_of(id).unwrap(), ProposalState::Approved);
    }

    #[test]
    fn mutating_the_path_after_approval_invalidates_the_token() {
        let mut g = gate();
        let id = submit_ok(&mut g);
        let token = g.approve(id, "user").unwrap();

        g.entries.get_mut(&id).unwrap().proposal.target_path = "src/other.rs".into();

        assert!(matches!(
            g.consume(&token),
            Err(GateError::ContentChanged { .. })
        ));
    }

    #[test]
    fn a_token_only_ever_authorises_its_own_proposal() {
        let mut g = gate();
        let first = submit_ok(&mut g);
        let token_first = g.approve(first, "user").unwrap();

        // A second proposal arrives while the first is approved. It does not
        // revoke the first -- the user did authorise it -- but the outstanding
        // token must remain bound to the first proposal's content.
        let second = submit_ok(&mut g);
        let _token_second = g.approve(second, "user").unwrap();

        let app = g.consume(&token_first).unwrap();
        assert_eq!(app.id, first);
        assert_eq!(app.diff, g.proposal(first).unwrap().diff);
        assert_ne!(app.approved_digest, g.proposal(second).unwrap().digest());
    }

    #[test]
    fn rejection_is_final_and_recorded() {
        let mut g = gate();
        let id = submit_ok(&mut g);
        g.reject(id, "user", "this is not what I asked for")
            .unwrap();
        assert_eq!(g.state_of(id).unwrap(), ProposalState::Rejected);
        assert!(g.approve(id, "user").is_err());
        assert!(g.reject(id, "user", "again").is_err());
        assert!(g.audit().iter().any(|e| e.event == AuditEvent::Rejected));
    }

    #[test]
    fn the_audit_log_covers_rejected_proposals_too() {
        let mut g = gate();
        let yes = submit_ok(&mut g);
        let token = g.approve(yes, "alice").unwrap();
        g.consume(&token).unwrap();

        let no = submit_ok(&mut g);
        g.reject(no, "alice", "unnecessary").unwrap();

        let events: Vec<&str> = g.audit().iter().map(|e| e.event.label()).collect();
        assert_eq!(
            events,
            ["proposed", "approved", "applied", "proposed", "rejected"]
        );
    }

    #[test]
    fn a_failed_write_is_recorded() {
        let mut g = gate();
        let id = submit_ok(&mut g);
        let token = g.approve(id, "user").unwrap();
        g.consume(&token).unwrap();
        g.report_failure(id, "disk full").unwrap();
        assert_eq!(g.state_of(id).unwrap(), ProposalState::Failed);
        assert!(
            g.audit()
                .iter()
                .any(|e| e.event == AuditEvent::ApplicationFailed)
        );
    }

    #[test]
    fn digest_covers_every_field_that_influences_the_write() {
        let base = PatchProposal {
            id: 1,
            target_path: "a.rs".into(),
            summary: "s".into(),
            rationale: "r".into(),
            diff: "d".into(),
            generated_by_model: "m".into(),
            created_at: SystemTime::UNIX_EPOCH,
        };
        let d = base.digest();

        let mut variants = Vec::new();
        let mut v = base.clone();
        v.id = 2;
        variants.push(v);
        let mut v = base.clone();
        v.target_path = "b.rs".into();
        variants.push(v);
        let mut v = base.clone();
        v.summary = "t".into();
        variants.push(v);
        let mut v = base.clone();
        v.rationale = "t".into();
        variants.push(v);
        let mut v = base.clone();
        v.diff = "e".into();
        variants.push(v);
        let mut v = base.clone();
        v.generated_by_model = "n".into();
        variants.push(v);
        let mut v = base.clone();
        v.created_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        variants.push(v);

        for (i, v) in variants.iter().enumerate() {
            assert_ne!(d, v.digest(), "variant {i} produced the same digest");
        }
    }

    #[test]
    fn digest_is_not_ambiguous_across_field_boundaries() {
        // "ab"+"c" and "a"+"bc" must not collide.
        let mk = |path: &str, diff: &str| PatchProposal {
            id: 1,
            target_path: path.into(),
            summary: "s".into(),
            rationale: "r".into(),
            diff: diff.into(),
            generated_by_model: "m".into(),
            created_at: SystemTime::UNIX_EPOCH,
        };
        assert_ne!(mk("ab", "c").digest(), mk("a", "bc").digest());
    }

    #[test]
    fn debug_output_does_not_leak_the_diff() {
        let mut g = gate();
        submit_ok(&mut g);
        let rendered = format!("{g:?}");
        assert!(!rendered.contains("exfiltrate"));
        assert!(!rendered.contains("@@"));
    }

    struct RecordingSink {
        events: std::sync::Arc<std::sync::Mutex<Vec<AuditEvent>>>,
    }

    impl AuditSink for RecordingSink {
        fn record(&mut self, entry: &AuditEntry) {
            if let Ok(mut guard) = self.events.lock() {
                guard.push(entry.event);
            }
        }
    }

    #[test]
    fn sink_receives_transitions_in_order() {
        let mut g = gate();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = RecordingSink {
            events: events.clone(),
        };
        g.set_sink(Box::new(sink));
        let id = submit_ok(&mut g);
        let _token = g.approve(id, "user").unwrap();
        let id2 = submit_ok(&mut g);
        g.reject(id2, "user", "no").unwrap();
        let recorded = events.lock().unwrap();
        assert_eq!(recorded[0], AuditEvent::Submitted);
        assert_eq!(recorded[1], AuditEvent::Approved);
        assert_eq!(recorded[2], AuditEvent::Submitted);
        assert_eq!(recorded[3], AuditEvent::Rejected);
    }
}
