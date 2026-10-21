//! # heimdall-core
//!
//! Heimdall Core: the primary AI. It owns the conversational interface, the
//! command engine, and the self-repair code engine.
//!
//! ## The security invariant
//!
//! Core is permitted to read, reason about and propose changes to its own
//! source code. It is **not** permitted to apply one without explicit,
//! informed user authorisation. That rule lives in [`gate`] and is the reason
//! this crate exists separately from the shell: the gate must be reviewable on
//! its own, without a UI in the way.
//!
//! The invariant is enforced structurally rather than by convention:
//!
//! * There is exactly one function that turns an approval into a write, and it
//!   requires a token the gate minted.
//! * That token is bound to a digest of the exact diff, path and rationale the
//!   user reviewed, so an approved change cannot be swapped afterwards.
//! * Tokens are single-use and expire.
//! * Every transition lands in an append-only audit log, including refusals.
//!
//! ## Peer trust
//!
//! [`link`] records which Sentinel Core is willing to talk to. It is trust on
//! first use by default, and it says so: [`link::TrustBasis::is_weak`] exists so
//! the UI can show the operator that the first run established the pin rather
//! than verifying it.

pub mod analysis;
pub mod apply;
pub mod audit;
pub mod error;
pub mod gate;
pub mod link;
pub mod orchestrator;
pub mod reasoning;

pub use analysis::{Analyzer, Edit, Finding, RepairPlan, Rule};
pub use audit::AuditLog;
pub use error::{Error, Result};
pub use gate::{
    Application, ApprovalToken, AuditEntry, AuditEvent, AuditSink, Gate, PatchProposal, ProposalId,
    ProposalState,
};
pub use link::{PeerPin, PinLocation, TrustBasis};
pub use orchestrator::{LinkStatus, Orchestrator, SharedOrchestrator};
pub use reasoning::{DeterministicBackend, ReasoningBackend, ReasoningRequest, Reply};
