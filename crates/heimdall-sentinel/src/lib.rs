//! # heimdall-sentinel
//!
//! The secondary AI: autonomous defence of the host and network.
//!
//! Phase 1 scope is deliberately narrow. What exists here is the *shape* of the
//! defense pipeline and the one component whose output must be explainable --
//! the anomaly detector. Collection sources (ETW, eBPF, netfilter) are Phase 2.
//!
//! ## Containment is advisory, not automatic
//!
//! An autonomous defender that can isolate a host the instant a score crosses a
//! threshold is a denial-of-service engine pointed at your own infrastructure.
//! Containment is therefore produced as a *recommendation* with an explicit
//! confidence and a human-readable rationale. Acting on it is Core's call, and
//! Core asks the user. The blast radius of a false positive stays at "an alert
//! in a log".

pub mod anomaly;
pub mod engine;
pub mod policy;

pub use anomaly::{Anomaly, AnomalyEngine, DetectorConfig};
pub use engine::{Engine, HealthSnapshot};
pub use policy::{ContainmentPlan, Policy};

/// Identity of the Sentinel instance, reported to Core on connect.
pub const DEFAULT_SENTINEL_ID: &str = "heimdall-sentinel-01";
