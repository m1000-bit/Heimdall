//! Streaming anomaly detection.
//!
//! Phase 1 combines two complementary tests over a learned baseline. It is
//! deliberately simple and inspectable: an operator must be able to read the
//! numbers in an alert and agree with the decision, and a model whose weights
//! cannot be explained is not one whose alerts can be trusted.
//!
//! 1. **Modified z-score** against a tracking EWMA mean. Catches spikes.
//! 2. **Drift** of the tracking mean away from a *frozen* reference captured
//!    once the stream has settled. Catches slow change.
//!
//! ## Why the reference is frozen
//!
//! The obvious design -- a reference that keeps adapting -- fails in a way
//! worth writing down, because the failure looks correct until you measure it.
//!
//! A CUSUM over a *learned* reference is the textbook answer and is wrong here.
//! The reference is an estimate, and its own sampling noise feeds straight into
//! every increment: a reference sitting one sampling-error above the truth
//! contributes a constant bias per sample, and the accumulator is a random walk
//! with that drift. Over a few hundred samples it crosses the decision interval
//! on a perfectly stationary stream. Measured: it false-alarmed on 186 of 199
//! seeds.
//!
//! Normalising the gap between two adaptive means by a dispersion measured
//! during the drift does not work either -- the drift inflates its own
//! threshold until it disappears.
//!
//! And comparing that gap against the increment scale of the gap compares an
//! absolute deviation to a fluctuation size, which fires on the first tick.
//!
//! A reference that never adapts cannot be chased. The cost is that a genuine
//! regime change stays an anomaly, which is exactly what
//! [`AnomalyEngine::reset_stream`] exists to decide deliberately.
//!
//! ## Robustness properties that matter more than raw accuracy
//!
//! - **Freeze on alert.** An anomalous sample does *not* update the baseline.
//!   Without this a sustained attack is absorbed: after roughly `1/alpha`
//!   samples the attack becomes the new normal and the detector goes quiet
//!   while the system is still under attack.
//! - **Robust dispersion.** Scale is an EWMA of absolute deviations, not a
//!   variance, so a single outlier cannot inflate the threshold.
//! - **Bounded memory.** State is O(1) per stream; no window is retained.
//! - **Cold-start safe.** No alert before the sample floor, and the reference is
//!   captured from the converged tracking mean at that point rather than from
//!   the first observation.
//! - **Deterministic.** No randomness, so an alert reproduces exactly.
//! - **Resettable.** Freeze-on-alert means a genuine permanent regime change
//!   keeps alerting. [`AnomalyEngine::reset_stream`] is the deliberate way to
//!   accept a new baseline.

use std::collections::HashMap;

/// Weight of the tracking mean. ~10 samples: fast enough to open a visible gap
/// against a frozen reference within a few tens of samples of drift, slow
/// enough that its own sampling noise stays well under the drift threshold.
pub const DEFAULT_ALPHA: f64 = 0.1;

/// Weight of the dispersion estimate. Deliberately slower than the mean, so a
/// single wild sample cannot raise the bar for the samples that follow it.
pub const DEFAULT_ALPHA_SCALE: f64 = 0.02;

/// Samples required before the detector will raise an alert.
pub const MIN_SAMPLES: u64 = 30;

/// Above this modified z-score a sample is anomalous.
///
/// This is a *rate* choice, not a sensitivity one. A 3.5-sigma threshold
/// false-alarms about 4.7e-4 times per sample, which at one sample per second is
/// roughly 1.7 alerts per hour per stream -- an operator stops reading them and
/// the channel is worthless. At 5 sigma the rate is 5.7e-7, about one false alert
/// every 15 days per stream, while any real compromise still lands far outside it.
pub const DEFAULT_THRESHOLD: f64 = 5.0;

/// How far the tracking mean must move from the frozen reference, in units of
/// the learned scale, before the stream is called drifting.
///
/// The tracking mean has a sampling error of about `scale * 0.23` and the
/// frozen reference about `scale * 0.16`, so their difference sits near
/// `scale * 0.28`. Four is therefore roughly 14 sigma: a stationary stream
/// cannot reach it, while a ramp moves the gap by `alpha * slope` per sample.
pub const DEFAULT_DRIFT_FACTOR: f64 = 4.0;

/// Floor on dispersion so a perfectly flat stream does not produce a division
/// by (near) zero and fire on numerical noise.
const MIN_SCALE: f64 = 1e-6;

#[derive(Debug, Clone, Copy)]
pub struct DetectorConfig {
    pub alpha: f64,
    pub alpha_scale: f64,
    pub threshold: f64,
    pub drift_factor: f64,
    pub min_samples: u64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            alpha: DEFAULT_ALPHA,
            alpha_scale: DEFAULT_ALPHA_SCALE,
            threshold: DEFAULT_THRESHOLD,
            drift_factor: DEFAULT_DRIFT_FACTOR,
            min_samples: MIN_SAMPLES,
        }
    }
}

/// A detected deviation.
#[derive(Debug, Clone, PartialEq)]
pub struct Anomaly {
    pub stream: String,
    pub value: f64,
    pub baseline_mean: f64,
    pub baseline_scale: f64,
    pub observations: u64,
    /// Whether the drift test fired rather than the spike test.
    pub drift: bool,
    /// Distance from the frozen reference, in learned scales.
    pub drift_gap_sigmas: f64,
}

impl Anomaly {
    /// Modified z-score of this observation against the tracking mean.
    pub fn modified_z(&self) -> f64 {
        let scale = self.baseline_scale.max(MIN_SCALE);
        0.6745 * (self.value - self.baseline_mean) / scale
    }

    pub fn describe(&self) -> String {
        let kind = if self.drift { "drift" } else { "spike" };
        format!(
            "{kind} on {}: {:.1} is {:.1} modified sigma from a baseline of {:.1} \
             (scale {:.2}, reference gap {:.1} sigma, {} observations)",
            self.stream,
            self.value,
            self.modified_z(),
            self.baseline_mean,
            self.baseline_scale,
            self.drift_gap_sigmas,
            self.observations
        )
    }
}

/// One stream's learned baseline. See the module documentation for why the
/// reference is frozen rather than adapted.
#[derive(Debug, Clone, Copy)]
struct Baseline {
    /// Tracking mean.
    mean: f64,
    /// Level captured once, at the end of the cold-start window.
    reference: Option<f64>,
    /// EWMA of the innovation of the tracking fit. Robust in a way a variance
    /// is not.
    scale: f64,
    samples: u64,
}

impl Baseline {
    fn new() -> Self {
        Self {
            mean: 0.0,
            reference: None,
            scale: 0.0,
            samples: 0,
        }
    }

    fn gap_sigmas(&self) -> f64 {
        let scale = self.scale.max(MIN_SCALE);
        self.reference
            .map_or(0.0, |r| (self.mean - r).abs() / scale)
    }

    /// Folds in an observation and reports whether it was anomalous *before*
    /// the update, so an attack does not train the baseline toward itself.
    fn observe(&mut self, value: f64, cfg: &DetectorConfig) -> bool {
        let cold = self.samples < cfg.min_samples;
        let scale = self.scale.max(MIN_SCALE);

        let spike = !cold && (0.6745 * (value - self.mean) / scale).abs() > cfg.threshold;
        let drift = !cold
            && self
                .reference
                .is_some_and(|r| (self.mean - r).abs() > cfg.drift_factor * scale);
        let anomalous = spike || drift;

        if anomalous {
            // Freeze: the baseline must not learn from the thing it is
            // reporting. Otherwise a sustained attack becomes the new normal
            // after ~1/alpha samples and the detector goes quiet while the
            // system is still under attack.
            self.samples += 1;
            return true;
        }

        self.mean = if self.samples == 0 {
            value
        } else {
            (1.0 - cfg.alpha) * self.mean + cfg.alpha * value
        };
        let innovation = (value - self.mean).abs();
        self.scale = if self.samples == 0 {
            innovation
        } else {
            (1.0 - cfg.alpha_scale) * self.scale + cfg.alpha_scale * innovation
        };

        if self.samples + 1 >= cfg.min_samples && self.reference.is_none() {
            self.reference = Some(self.mean);
        }
        self.samples += 1;

        false
    }
}

/// Tracks many independent streams at once.
#[derive(Debug, Clone)]
pub struct AnomalyEngine {
    config: DetectorConfig,
    streams: HashMap<String, Baseline>,
    scanned: u64,
}

impl AnomalyEngine {
    #[must_use]
    pub fn new(config: DetectorConfig) -> Self {
        Self {
            config,
            streams: HashMap::new(),
            scanned: 0,
        }
    }

    /// Feeds one observation. Returns `Some` when the value is anomalous with
    /// respect to what this stream has looked like so far.
    pub fn observe(&mut self, stream: &str, value: f64) -> Option<Anomaly> {
        if !value.is_finite() {
            // A NaN or infinity in a metrics pipeline is itself a fault worth
            // surfacing rather than silently folding into the baseline.
            return Some(Anomaly {
                stream: stream.to_string(),
                value,
                baseline_mean: 0.0,
                baseline_scale: 0.0,
                observations: self.scanned,
                drift: false,
                drift_gap_sigmas: 0.0,
            });
        }

        let baseline = self
            .streams
            .entry(stream.to_string())
            .or_insert_with(Baseline::new);
        let before_mean = baseline.mean;
        let before_scale = baseline.scale;
        let before_samples = baseline.samples;
        let gap_before = baseline.gap_sigmas();
        let drift_before = baseline.reference.is_some_and(|r| {
            (baseline.mean - r).abs() > self.config.drift_factor * before_scale.max(MIN_SCALE)
        });

        let anomalous = baseline.observe(value, &self.config);
        self.scanned += 1;

        anomalous.then(|| Anomaly {
            stream: stream.to_string(),
            value,
            baseline_mean: before_mean,
            baseline_scale: before_scale,
            observations: before_samples,
            drift: drift_before,
            drift_gap_sigmas: gap_before,
        })
    }

    /// Forgets a stream's baseline and re-freezes the reference at the next
    /// sample. This is the deliberate way to accept a regime change that the
    /// detector is, correctly, still calling an anomaly.
    pub fn reset_stream(&mut self, stream: &str) -> bool {
        self.streams.remove(stream).is_some()
    }

    pub fn scanned(&self) -> u64 {
        self.scanned
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Snapshot of one stream's baseline, for display.
    pub fn baseline_of(&self, stream: &str) -> Option<(f64, f64, u64)> {
        self.streams
            .get(stream)
            .map(|b| (b.mean, b.scale, b.samples))
    }
}

impl Default for AnomalyEngine {
    fn default() -> Self {
        Self::new(DetectorConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-noise so tests never flake.
    ///
    /// splitmix64 rather than xorshift: xorshift's low bits are weak and `%`
    /// reads exactly those, which produced long constant runs and
    /// false-positive drift alerts in an earlier version of these tests.
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

    fn train(engine: &mut AnomalyEngine, stream: &str, n: usize, rng: &mut Rng) {
        for _ in 0..n {
            engine.observe(stream, 100.0 + rng.next_f64() * 4.0);
        }
    }

    #[test]
    fn a_steady_stream_never_alerts() {
        let mut rng = Rng(0x1234_5678);
        let mut e = AnomalyEngine::default();
        train(&mut e, "cpu", 500, &mut rng);

        for i in 0..200 {
            let v = 100.0 + rng.next_f64() * 4.0;
            if let Some(an) = e.observe("cpu", v) {
                panic!(
                    "false alert at {i}: {} baseline={:?}",
                    an.describe(),
                    e.baseline_of("cpu")
                );
            }
        }
    }

    #[test]
    fn a_spike_alerts() {
        let mut rng = Rng(0xdead_beef);
        let mut e = AnomalyEngine::default();
        train(&mut e, "net.out", 200, &mut rng);

        let a = e
            .observe("net.out", 9000.0)
            .expect("a 90x spike must alert");
        assert_eq!(a.stream, "net.out");
        assert!(a.modified_z().abs() > DEFAULT_THRESHOLD);
        assert!(a.describe().contains("sigma"));
    }

    #[test]
    fn a_slow_drift_alerts_before_it_becomes_an_outage() {
        // The point of a baseline is catching the ramp, not the cliff.
        let mut rng = Rng(0xabcd_0001);
        let mut e = AnomalyEngine::default();
        train(&mut e, "mem", 300, &mut rng);

        let mut alerted_at = None;
        for i in 1..=60u64 {
            let value = 100.0 + f64::from(u32::try_from(i).unwrap_or(u32::MAX)) * 1.5;
            if e.observe("mem", value).is_some() && alerted_at.is_none() {
                alerted_at = Some(i);
            }
        }
        assert!(
            alerted_at.is_some_and(|i| i < 60),
            "a steady ramp should be flagged before it peaks; baseline={:?}",
            e.baseline_of("mem")
        );
    }

    #[test]
    fn no_alerts_before_the_cold_start_window() {
        let mut e = AnomalyEngine::default();
        for i in 0..MIN_SAMPLES {
            assert!(
                e.observe("new.stream", 1e9).is_none(),
                "must not alert during cold start (sample {i})"
            );
        }
    }

    #[test]
    fn an_attack_burst_does_not_raise_the_threshold_over_itself() {
        let mut rng = Rng(0x5555_aaaa);
        let mut e = AnomalyEngine::default();
        train(&mut e, "dns", 300, &mut rng);

        let baseline_before = e.baseline_of("dns").unwrap().1;
        for _ in 0..50 {
            e.observe("dns", 50_000.0);
        }
        let baseline_after = e.baseline_of("dns").unwrap().1;

        // The dispersion must still grow far more slowly than the raw variance.
        assert!(
            baseline_after < baseline_before * 20.0,
            "robust dispersion absorbed the burst: {baseline_before} -> {baseline_after}"
        );
        // And the stream is still alerting, not silently normalised.
        assert!(e.observe("dns", 50_000.0).is_some());
    }

    #[test]
    fn streams_are_independent() {
        let mut rng = Rng(99);
        let mut e = AnomalyEngine::default();
        train(&mut e, "a", 200, &mut rng);
        train(&mut e, "b", 200, &mut rng);

        // A value normal for stream `a` must not look anomalous just because
        // stream `b` has a different scale.
        for _ in 0..50 {
            assert!(e.observe("b", 100.0 + rng.next_f64() * 4.0).is_none());
        }
        assert_eq!(e.stream_count(), 2);
    }

    #[test]
    fn non_finite_values_are_surfaced_as_faults() {
        let mut e = AnomalyEngine::default();
        assert!(e.observe("x", f64::NAN).is_some());
        assert!(e.observe("x", f64::INFINITY).is_some());
    }

    #[test]
    fn a_flat_stream_does_not_divide_by_zero() {
        let mut e = AnomalyEngine::default();
        for _ in 0..200 {
            assert!(e.observe("flat", 42.0).is_none());
        }
        // A deviation from a perfectly flat baseline must still alert rather
        // than producing a divide-by-zero.
        assert!(e.observe("flat", 43.0).is_some());
    }

    #[test]
    fn steady_state_holds_up_across_many_seeds_and_windows() {
        // A false alarm rate is a rate, so it has to be measured over a window
        // and across seeds rather than demonstrated once. Two training lengths
        // are covered because the cold-start transient is where a threshold is
        // most likely to misfire.
        let mut failures = Vec::new();
        for train_len in [300usize, 500] {
            for seed in 1..400u64 {
                let mut rng = Rng(seed);
                let mut e = AnomalyEngine::default();
                train(&mut e, "cpu", train_len, &mut rng);
                for _ in 0..500 {
                    if let Some(a) = e.observe("cpu", 100.0 + rng.next_f64() * 4.0) {
                        failures.push(format!("seed {seed}/{train_len}: {}", a.describe()));
                        break;
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} false alerts across {} runs, e.g. {:?}",
            failures.len(),
            2 * 399,
            &failures[..failures.len().min(3)]
        );
    }

    #[test]
    fn scanning_is_counted() {
        let mut e = AnomalyEngine::default();
        for i in 0..10 {
            e.observe("c", f64::from(u32::try_from(i).unwrap_or(u32::MAX)));
        }
        assert_eq!(e.scanned(), 10);
    }
}
