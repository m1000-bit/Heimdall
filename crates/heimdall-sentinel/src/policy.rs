//! What Sentinel is allowed to do on its own, and what it must ask about.
//!
//! The policy is the second half of the "containment is advisory" rule from the
//! crate docs. It is deliberately a small, readable table rather than a rules
//! engine: a security policy nobody can read is one nobody can audit.

use heimdall_ipc::message::ContainmentScope;

/// Actions Sentinel may take without a human in the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutonomousAction {
    /// Record and correlate.
    Observe,
    /// Raise an alert to Core.
    Alert,
    /// Block a single connection, scoped to the offending flow. Reverting it is
    /// cheap and the blast radius is one flow.
    RateLimit,
    /// Refuse this action category entirely.
    Forbidden,
}

/// The policy table.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Threshold multiplier above which containment is suggested at all.
    pub escalation_factor: f64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            // Requiring a much larger deviation before recommending a
            // containment action than before alerting keeps noisy-but-benign
            // traffic from triggering disruptive recommendations.
            escalation_factor: 4.0,
        }
    }
}

impl Policy {
    /// What Sentinel may do about a signal of the given magnitude, measured in
    /// multiples of the alerting threshold.
    pub fn autonomous_action(&self, multiples_of_threshold: f64) -> AutonomousAction {
        if multiples_of_threshold >= self.escalation_factor * 4.0 {
            AutonomousAction::Alert
        } else if multiples_of_threshold >= self.escalation_factor {
            AutonomousAction::RateLimit
        } else {
            AutonomousAction::Observe
        }
    }

    /// Builds a containment recommendation, or `None` when the signal is not
    /// strong enough to justify suggesting one.
    pub fn plan_containment(
        &self,
        anomaly: &crate::anomaly::Anomaly,
        alert_threshold: f64,
    ) -> Option<ContainmentPlan> {
        let magnitude = anomaly.modified_z().abs() / alert_threshold.max(f64::MIN_POSITIVE);
        match self.autonomous_action(magnitude) {
            AutonomousAction::Forbidden | AutonomousAction::Observe => None,
            AutonomousAction::Alert => Some(ContainmentPlan {
                summary: format!(
                    "Strong anomaly on {}: {}. Recommend a temporary, scoped containment.",
                    anomaly.stream,
                    anomaly.describe()
                ),
                scope: ContainmentScope::Address {
                    cidr: anomaly.stream.clone(),
                },
                magnitude,
                requires_user_confirmation: true,
            }),
            AutonomousAction::RateLimit => Some(ContainmentPlan {
                summary: format!(
                    "Anomaly on {} is above the escalation bar: {}. Recommend rate limiting only.",
                    anomaly.stream,
                    anomaly.describe()
                ),
                scope: ContainmentScope::Address {
                    cidr: anomaly.stream.clone(),
                },
                magnitude,
                requires_user_confirmation: true,
            }),
        }
    }

    /// Builds a containment recommendation from a rate burst.
    ///
    /// A burst is evidence in its own right: an attack that stays inside its
    /// historical range on every single sample is invisible to a point detector
    /// and obvious here. But a burst alone is weaker evidence than a corroborated
    /// multi-stream picture, so it produces a recommendation only from `Elevated`
    /// upward, and its summary says the evidence is weak.
    pub fn plan_containment_from_burst(
        &self,
        burst: &crate::correlate::Burst,
        band: crate::correlate::RiskBand,
    ) -> Option<ContainmentPlan> {
        if band < crate::correlate::RiskBand::Elevated {
            return None;
        }
        Some(ContainmentPlan {
            summary: format!(
                "Rate anomaly with no single extreme sample: {}. Cross-stream risk is {}. \
                 Recommend rate limiting only, and confirm the traffic is expected.",
                burst.describe(),
                band.label()
            ),
            scope: ContainmentScope::Address {
                cidr: burst.stream.clone(),
            },
            magnitude: burst.multiple,
            requires_user_confirmation: true,
        })
    }
}

/// A recommendation. Nothing acts on this without the operator saying yes.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainmentPlan {
    pub summary: String,
    pub scope: ContainmentScope,
    pub magnitude: f64,
    /// Always true in Phase 1. Present as an explicit field so that the moment a
    /// future version introduces autonomous containment, the difference is
    /// visible in a diff and in a review.
    pub requires_user_confirmation: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::{Anomaly, DetectorConfig};

    fn anomaly(stream: &str, value: f64, mean: f64, scale: f64) -> Anomaly {
        Anomaly {
            stream: stream.into(),
            value,
            baseline_mean: mean,
            baseline_scale: scale,
            observations: 500,
            drift: false,
            drift_gap_sigmas: 0.0,
        }
    }

    #[test]
    fn weak_signals_are_only_observed() {
        let p = Policy::default();
        assert_eq!(p.autonomous_action(0.5), AutonomousAction::Observe);
        assert_eq!(p.autonomous_action(2.0), AutonomousAction::Observe);
    }

    #[test]
    fn escalation_bars_scale_with_the_signal() {
        let p = Policy::default();
        assert_eq!(p.autonomous_action(5.0), AutonomousAction::RateLimit);
        assert_eq!(p.autonomous_action(20.0), AutonomousAction::Alert);
    }

    #[test]
    fn containment_is_never_autonomous_in_phase_1() {
        let p = Policy::default();
        let cfg = DetectorConfig::default();
        let a = anomaly("net.out", 50_000.0, 100.0, 10.0);

        let plan = p
            .plan_containment(&a, cfg.threshold)
            .expect("a 300-sigma anomaly must produce a recommendation");
        assert!(
            plan.requires_user_confirmation,
            "Sentinel must never contain a host on its own"
        );
        assert_ne!(plan.summary, "");
    }

    #[test]
    fn a_benign_signal_produces_no_recommendation() {
        let p = Policy::default();
        let cfg = DetectorConfig::default();
        let a = anomaly("cpu", 101.0, 100.0, 2.0);
        assert!(p.plan_containment(&a, cfg.threshold).is_none());
    }

    #[test]
    fn the_plan_explains_itself() {
        let p = Policy::default();
        let cfg = DetectorConfig::default();
        let a = anomaly("dns.out", 4000.0, 120.0, 8.0);
        let plan = p.plan_containment(&a, cfg.threshold).unwrap();
        assert!(plan.summary.contains("dns.out"));
        assert!(plan.summary.contains("sigma"));
    }
}
