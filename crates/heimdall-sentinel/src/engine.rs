//! The Sentinel runtime: event intake, detection, and reporting to Core.

use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_ipc::message::{HealthReport, Severity, ThreatAlert};

use crate::{
    anomaly::{Anomaly, AnomalyEngine, DetectorConfig},
    policy::{ContainmentPlan, Policy},
};

/// A raw observation from a collection source.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub stream: String,
    pub value: f64,
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub alert: ThreatAlert,
    pub anomaly: Anomaly,
    /// Present when the policy recommends acting on the alert.
    pub containment: Option<ContainmentPlan>,
}

/// A snapshot of Sentinel's health, reported to Core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub uptime_secs: u64,
    pub events_scanned: u64,
    pub active_containments: u32,
    pub engine_load_permille: u16,
    pub sentinel_id: String,
}

/// Sentinel's runtime state.
pub struct Engine {
    id: String,
    anomaly: AnomalyEngine,
    policy: Policy,
    started: Instant,
    alerts_emitted: u64,
    containments_active: u32,
    next_alert_id: u64,
    /// Detector configuration, kept alongside so a health report can explain
    /// what threshold produced the alerts.
    config: DetectorConfig,
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine")
            .field("id", &self.id)
            .field("alerts_emitted", &self.alerts_emitted)
            .field("events_scanned", &self.anomaly.scanned())
            .finish_non_exhaustive()
    }
}

impl Engine {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self::with_config(id, DetectorConfig::default(), Policy::default())
    }

    #[must_use]
    pub fn with_config(id: impl Into<String>, config: DetectorConfig, policy: Policy) -> Self {
        Self {
            id: id.into(),
            anomaly: AnomalyEngine::new(config),
            policy,
            started: Instant::now(),
            alerts_emitted: 0,
            containments_active: 0,
            next_alert_id: 1,
            config,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Ingests one observation. Returns a detection when the value is anomalous.
    pub fn ingest(&mut self, obs: &Observation) -> Option<Detection> {
        let anomaly = self.anomaly.observe(&obs.stream, obs.value)?;
        let alert_id = self.next_alert_id;
        self.next_alert_id += 1;
        self.alerts_emitted += 1;

        let magnitude = anomaly.modified_z().abs() / self.config.threshold.max(f64::MIN_POSITIVE);
        let containment = self
            .policy
            .plan_containment(&anomaly, self.config.threshold);

        Some(Detection {
            alert: ThreatAlert {
                alert_id,
                severity: severity_for(magnitude),
                category: obs.stream.clone(),
                summary: anomaly.describe(),
                observed_at_unix: now_unix(),
            },
            anomaly,
            containment,
        })
    }

    /// Ingested events per second, scaled by 1000 so it fits in a `u16`.
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    pub fn engine_load_permille(&self) -> u16 {
        let elapsed = self.started.elapsed().as_secs_f64().max(1e-3);
        let per_sec = self.anomaly.scanned() as f64 / elapsed;
        // Saturating conversion: a load reading must never wrap into a small
        // number, which would read as "idle" exactly when the engine is busiest.
        // `clamp` makes the cast to `u16` total.
        (per_sec * 1000.0).clamp(0.0, f64::from(u16::MAX)) as u16
    }

    pub fn health(&self) -> HealthSnapshot {
        HealthSnapshot {
            uptime_secs: self.started.elapsed().as_secs(),
            events_scanned: self.anomaly.scanned(),
            active_containments: self.containments_active,
            engine_load_permille: self.engine_load_permille(),
            sentinel_id: self.id.clone(),
        }
    }

    /// Renders the health snapshot as the message Core expects.
    pub fn health_report(&self) -> HealthReport {
        let h = self.health();
        HealthReport {
            sentinel_id: h.sentinel_id,
            uptime_secs: h.uptime_secs,
            events_scanned: h.events_scanned,
            active_containments: h.active_containments,
            engine_load_permille: h.engine_load_permille,
        }
    }

    /// Records that a containment Core approved is now in force.
    pub fn note_containment_activated(&mut self) {
        self.containments_active = self.containments_active.saturating_add(1);
    }

    pub fn alerts_emitted(&self) -> u64 {
        self.alerts_emitted
    }
}

fn severity_for(magnitude: f64) -> Severity {
    match magnitude {
        m if m >= 16.0 => Severity::Critical,
        m if m >= 8.0 => Severity::High,
        m if m >= 3.0 => Severity::Medium,
        m if m >= 1.0 => Severity::Low,
        _ => Severity::Info,
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Convenience for the shell, which holds the engine behind a lock.
pub type SharedEngine = Arc<std::sync::Mutex<Engine>>;

/// Default health interval. Frequent enough to look live, sparse enough that a
/// health report never becomes a denial-of-service vector against the IPC link.
pub const HEALTH_INTERVAL: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next_f64(&mut self) -> f64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            f64::from(u32::try_from((z >> 40) % 1000).unwrap_or(0)) / 1000.0
        }
    }

    fn engine() -> Engine {
        Engine::new("sentinel-test")
    }

    fn feed_baseline(e: &mut Engine, stream: &str, n: usize, rng: &mut Rng) {
        for _ in 0..n {
            e.ingest(&Observation {
                stream: stream.into(),
                value: 100.0 + rng.next_f64() * 4.0,
            });
        }
    }

    fn observe(e: &mut Engine, stream: &str, value: f64) -> Option<Detection> {
        e.ingest(&Observation {
            stream: stream.into(),
            value,
        })
    }

    #[test]
    fn a_normal_stream_produces_nothing() {
        let mut rng = Rng(7);
        let mut e = engine();
        feed_baseline(&mut e, "cpu", 300, &mut rng);
        for _ in 0..200 {
            let v = 100.0 + rng.next_f64() * 4.0;
            assert!(observe(&mut e, "cpu", v).is_none());
        }
        assert_eq!(e.alerts_emitted(), 0);
    }

    #[test]
    fn a_spike_becomes_a_critical_alert_with_a_containment_plan() {
        let mut rng = Rng(0xbeef);
        let mut e = engine();
        feed_baseline(&mut e, "net.out", 300, &mut rng);

        let d = observe(&mut e, "net.out", 1_000_000.0).expect("a massive spike must be detected");

        assert_eq!(d.alert.severity, Severity::Critical);
        assert!(
            d.alert.summary.contains("sigma"),
            "alerts must explain themselves"
        );
        assert!(d.containment.is_some());
        assert!(
            d.containment.unwrap().requires_user_confirmation,
            "Sentinel must not act on its own"
        );
    }

    #[test]
    fn alert_ids_are_unique_and_monotonic() {
        let mut rng = Rng(11);
        let mut e = engine();
        feed_baseline(&mut e, "a", 300, &mut rng);

        let mut ids = Vec::new();
        for v in [50_000.0, 60_000.0, 70_000.0] {
            ids.push(observe(&mut e, "a", v).unwrap().alert.alert_id);
        }
        assert_eq!(ids.len(), 3);
        assert!(
            ids.windows(2).all(|w| w[1] > w[0]),
            "alert ids must be strictly increasing, got {ids:?}"
        );
    }

    #[test]
    fn health_tracks_progress() {
        let mut rng = Rng(3);
        let mut e = engine();
        feed_baseline(&mut e, "a", 50, &mut rng);

        let h = e.health();
        assert_eq!(h.sentinel_id, "sentinel-test");
        assert_eq!(h.events_scanned, 50);
        assert_eq!(h.active_containments, 0);
        assert_eq!(e.health_report().events_scanned, 50);
    }

    #[test]
    fn engine_load_is_bounded() {
        let mut e = engine();
        for _ in 0..1000 {
            observe(&mut e, "x", 1.0);
        }
        assert!(e.engine_load_permille() > 0);
    }

    #[test]
    fn severity_escalates_with_magnitude() {
        assert_eq!(severity_for(0.5), Severity::Info);
        assert_eq!(severity_for(1.5), Severity::Low);
        assert_eq!(severity_for(4.0), Severity::Medium);
        assert_eq!(severity_for(9.0), Severity::High);
        assert_eq!(severity_for(100.0), Severity::Critical);
    }
}
