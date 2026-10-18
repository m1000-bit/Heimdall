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

pub mod error;
pub mod gate;
pub mod orchestrator;

pub use error::{Error, Result};
pub use gate::{
    Application, ApprovalToken, AuditEntry, AuditEvent, Gate, PatchProposal, ProposalId,
    ProposalState,
};
pub use orchestrator::{LinkStatus, Orchestrator, SharedOrchestrator};
