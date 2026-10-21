//! # heimdall-sentinel
//!
//! The secondary AI: defence of the host and network.
//!
//! ## Containment is advisory, not automatic
//!
//! An autonomous defender that can isolate a host the instant a score crosses a
//! threshold is a denial-of-service engine pointed at your own infrastructure.
//! Containment is therefore produced as a *recommendation* with an explicit
//! confidence and a human-readable rationale. Acting on it is Core's call, and
//! Core asks the operator. The blast radius of a false positive stays at "an
//! alert in a log".
//!
//! ## The pipeline
//!
//! ```text
//!   Source ──> AnomalyEngine ──> Correlator ──> Policy ──> Alert
//!   (real or     (point +        (multi-stream    (severity +
//!    replayed)    drift)          agreement)       containment)
//! ```
//!
//! Each stage answers a different question, and none of them substitutes for
//! another:
//!
//! * [`anomaly`] -- is *this* sample unusual for this stream?
//! * [`correlate`] -- is anything else unusual at the same time? A CPU spike
//!   alone is a build. A CPU spike plus outbound traffic plus new processes is
//!   something else.
//! * [`policy`] -- given how strongly corroborated this is, what is the
//!   proportionate response?
//!
//! Sources live in [`source`]. The system source reads real machine telemetry;
//! the replay source exists because a detector's behaviour on a *known* sequence
//! cannot be tested any other way.
//!
//! ## When containment is actually carried out
//!
//! [`containment`] holds the part that can change the host, and it is the
//! narrowest module in the crate: it acts only when the daemon was started
//! with `--allow-containment`, only on the processes, addresses and interfaces
//! the operator listed, and only on an order that names its approver.
//!
//! ## Baselines survive a restart
//!
//! [`baseline_store`] keeps what the engine has learned in a sealed file. A
//! detector that forgets everything on every reboot is a detector that spends
//! its first minutes of every boot learning what the host looks like, and one
//! that is quiet exactly when a fresh compromise would be hiding in the noise.
//! The file is sealed, so a baseline that was tampered with is refused rather
//! than believed.

pub mod anomaly;
pub mod baseline_store;
pub mod containment;
pub mod correlate;
pub mod engine;
pub mod policy;
pub mod source;

pub use anomaly::{Anomaly, AnomalyEngine, BaselineSnapshot, DetectorConfig};
pub use baseline_store::{BaselineStore, StoreError};
pub use containment::{ContainmentExecutor, ContainmentOutcome, ContainmentPolicy};
pub use correlate::{CorrelatedAssessment, Correlator, RiskBand, WindowDetector};
pub use engine::{Detection, Engine, HealthSnapshot, Observation};
pub use policy::{AutonomousAction, ContainmentPlan, Policy};
pub use source::{MultiSource, ReplaySource, SharedSource, Source, SystemSource};

/// Identity of the Sentinel instance, reported to Core on connect.
pub const DEFAULT_SENTINEL_ID: &str = "heimdall-sentinel-01";

/// How often the engine samples its sources.
pub const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
