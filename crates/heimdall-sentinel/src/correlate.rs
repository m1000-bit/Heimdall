//! What a point detector cannot see.
//!
//! [`crate::anomaly`] answers one question per sample: is *this* value unusual
//! for this stream? That leaves three blind spots, all of which are ordinary
//! attack shapes.
//!
//! 1. **Rate.** A connection attempt 1000x above baseline is a spike. The same
//!    attempt repeated at exactly baseline, continuously, is an attack that never
//!    trips a single threshold. Rate has to be counted.
//! 2. **Correlation.** Any one signal on a real machine is explainable. CPU is
//!    high because something is compiling, disk is filling because logs are
//!    rotating, network is up because there is a backup. What distinguishes an
//!    intrusion is *agreement*: several independent streams moving at once is
//!    far less likely to have an innocent explanation than any one of them.
//! 3. **Novelty.** A stream that has been flat for a long time and then starts
//!    moving *within* its historical range is suspicious even though nothing
//!    exceeded a threshold.
//!
//! Each is implemented here, on a fixed-size window so memory is bounded and a
//! flood cannot grow the state.

use std::collections::HashMap;

/// Samples retained per stream for the rate and novelty tests.
///
/// At a two-second poll this is eight minutes of history. Long enough to
/// characterise a daily cycle, short enough that the state stays a few hundred
/// bytes per stream.
pub const WINDOW: usize = 256;

/// How much traffic a burst summary covers, in seconds. Fixed, because the
/// summary is meant to be comparable between reports rather than precise.
const REPORT_WINDOW: f64 = 120.0;

/// Rate detector: watches the *interval between events* on each stream.
///
/// Inter-arrival time, smoothed twice at different rates:
///
/// * `live` moves fast (alpha 0.3) and tracks the current interval.
/// * `baseline` moves slowly (alpha 0.02) and represents the stream's normal
///   cadence.
///
/// A burst is `live` collapsing well below `baseline`. Comparing two *rates*
/// instead would mean dividing by an interval that can approach zero during the
/// exact event the detector is looking for.
///
/// # Freeze on burst
///
/// While a burst is firing the baseline does **not** move. This is the same
/// principle as the point detector's frozen baseline, and for the same reason:
/// without it a sustained flood is absorbed within `1/alpha` events, after which
/// the attack has become the stream's normal cadence and the detector goes quiet
/// while the flood continues. With it, a sustained flood keeps alerting, and
/// [`WindowDetector::forget`] is the deliberate way to accept a new cadence.
///
/// # Warm-up
///
/// Nothing is reported until a stream has enough observations for `baseline` to
/// mean anything. A stream seen twice has no cadence to compare against, and a
/// ratio built from one sample would fire on the first sign of life.
pub struct WindowDetector {
    state: HashMap<String, StreamRate>,
    /// Events before the baseline is trusted.
    warmup: usize,
    /// How far `live` collapses relative to `baseline` before a burst is called.
    burst_factor: f64,
    alpha_live: f64,
    alpha_baseline: f64,
    /// Interval floor. A gap of a microsecond would otherwise be an unbounded
    /// rate.
    min_interval: f64,
}

#[derive(Debug, Clone, Copy)]
struct StreamRate {
    /// Smoothed current interval.
    live: f64,
    /// Smoothed normal interval, frozen while bursting.
    baseline: f64,
    last_seen: f64,
    observations: u64,
    /// Magnitude seen inside the current window, for reporting.
    window_total: f64,
    window_events: usize,
    window_start: f64,
}

/// A detected burst.
#[derive(Debug, Clone, PartialEq)]
pub struct Burst {
    pub stream: String,
    /// Observed events per unit time.
    pub observed_rate: f64,
    /// The stream's own normal cadence, in events per unit time.
    pub baseline_rate: f64,
    /// `observed / baseline`, floored so it is never zero.
    pub multiple: f64,
    /// Total magnitude seen inside the window.
    pub magnitude: f64,
}

impl Burst {
    pub fn describe(&self) -> String {
        format!(
            "burst on {}: {:.2}/s against a baseline of {:.1}/s ({:.1}x, {:.0} total)",
            self.stream, self.observed_rate, self.baseline_rate, self.multiple, self.magnitude
        )
    }
}

impl core::fmt::Debug for WindowDetector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WindowDetector")
            .field("streams", &self.state.len())
            .field("warmup", &self.warmup)
            .field("burst_factor", &self.burst_factor)
            .finish_non_exhaustive()
    }
}

impl Default for WindowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowDetector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
            warmup: 30,
            burst_factor: 4.0,
            alpha_live: 0.3,
            alpha_baseline: 0.02,
            min_interval: 1e-3,
        }
    }

    /// Events required before the baseline is trusted.
    #[must_use]
    pub fn with_warmup(mut self, warmup: usize) -> Self {
        self.warmup = warmup.max(1);
        self
    }

    /// How far the interval must collapse relative to baseline before a burst.
    #[must_use]
    pub fn with_burst_factor(mut self, factor: f64) -> Self {
        self.burst_factor = factor.max(1.0);
        self
    }

    /// Reports one event and returns a burst when the cadence has collapsed.
    ///
    /// `now` is supplied rather than read from the clock so a replayed sequence
    /// is timestamped exactly as recorded. A detector that reads the wall clock
    /// cannot be tested against a timeline.
    pub fn observe(&mut self, stream: &str, magnitude: f64, now: f64) -> Option<Burst> {
        let s = self.state.entry(stream.to_string()).or_insert(StreamRate {
            live: 0.0,
            baseline: 0.0,
            last_seen: now,
            observations: 0,
            window_total: 0.0,
            window_events: 0,
            window_start: now,
        });

        let gap = (now - s.last_seen).max(self.min_interval);
        s.last_seen = now;
        s.observations += 1;

        // Report-window accounting, so a burst can say how much traffic it saw.
        if now - s.window_start > REPORT_WINDOW {
            s.window_start = now;
            s.window_total = 0.0;
            s.window_events = 0;
        }
        s.window_total += magnitude;
        s.window_events += 1;

        // First observation establishes the cadence; there is no interval to
        // measure yet.
        if s.live == 0.0 {
            s.live = gap;
            s.baseline = gap;
            return None;
        }

        s.live = (1.0 - self.alpha_live) * s.live + self.alpha_live * gap;

        if s.observations <= self.warmup as u64 {
            // Running mean during warm-up, so the baseline is usable the moment
            // it is trusted rather than starting from zero.
            // `observations` is a `u64` counter and `n` is its divisor for a
            // running mean. The `f64` mantissa holds 2^53 exactly; a counter
            // that large would need centuries of observations at any realistic
            // poll rate, and warm-up ends long before it.
            #[allow(clippy::cast_precision_loss)]
            let n = s.observations as f64;
            s.baseline += (gap - s.baseline) / n;
            return None;
        }

        let baseline = s.baseline.max(self.min_interval);
        if s.live * self.burst_factor < baseline {
            // Burst. The baseline is deliberately left alone.
            return Some(Burst {
                stream: stream.to_string(),
                observed_rate: 1.0 / s.live,
                baseline_rate: 1.0 / baseline,
                multiple: baseline / s.live,
                magnitude: s.window_total,
            });
        }

        s.baseline = (1.0 - self.alpha_baseline) * s.baseline + self.alpha_baseline * gap;
        None
    }

    /// Observed rate for a stream, from its smoothed interval.
    pub fn rate_of(&self, stream: &str) -> Option<f64> {
        self.state
            .get(stream)
            .filter(|s| s.live > 0.0)
            .map(|s| 1.0 / s.live)
    }

    /// Normalised cadence for a stream, for display.
    pub fn baseline_rate_of(&self, stream: &str) -> Option<f64> {
        self.state
            .get(stream)
            .filter(|s| s.baseline > 0.0)
            .map(|s| 1.0 / s.baseline)
    }

    pub fn stream_count(&self) -> usize {
        self.state.len()
    }

    /// Forgets a stream's cadence, so the next events rebuild it. This is the
    /// deliberate way to accept a machine that has genuinely changed.
    pub fn forget(&mut self, stream: &str) -> bool {
        self.state.remove(stream).is_some()
    }
}
/// How strongly corroborated an incident is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskBand {
    /// One stream, at detection level. Frequently benign.
    Low,
    /// Several streams agreeing, or one stream well past its threshold.
    Elevated,
    /// Several streams agreeing, one of them a network stream.
    High,
    /// Several streams agreeing including a network stream, at high magnitude.
    Severe,
}

impl RiskBand {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Elevated => "elevated",
            Self::High => "high",
            Self::Severe => "severe",
        }
    }

    pub const fn index(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Elevated => 1,
            Self::High => 2,
            Self::Severe => 3,
        }
    }
}

/// The assessed picture across all streams.
#[derive(Debug, Clone)]
pub struct CorrelatedAssessment {
    pub band: RiskBand,
    /// Number of distinct streams currently anomalous.
    pub anomalous_streams: usize,
    /// Strongest single-stream magnitude, in multiples of its threshold.
    pub peak_magnitude: f64,
    /// Whether any network stream is among the anomalous ones.
    pub network_involved: bool,
    /// Whether a rate burst fired recently enough to count as part of this
    /// incident.
    pub burst_active: bool,
    /// One-line explanation, suitable for an alert body.
    pub rationale: String,
}

impl CorrelatedAssessment {
    pub fn describe(&self) -> String {
        format!(
            "risk {} -- {} anomalous stream(s), peak {:.1}x threshold{}, {}, {}",
            self.band.label(),
            self.anomalous_streams,
            self.peak_magnitude,
            if self.network_involved {
                ", network involved"
            } else {
                ""
            },
            if self.burst_active {
                "rate burst active"
            } else {
                "no burst"
            },
            self.rationale
        )
    }
}

/// Combines point anomalies and rate bursts into a single risk judgement.
#[derive(Debug)]
pub struct Correlator {
    window: WindowDetector,
    /// Streams considered network-facing. Their involvement raises the band,
    /// because an intruder on this host is leaving via one of them.
    network_streams: Vec<String>,
    /// Streams still inside their anomaly window, with the magnitude that put
    /// them there.
    active: HashMap<String, (f64, f64)>,
    /// How long an anomalous stream stays "active" after its last hit. Long
    /// enough that a burst across three poll cycles reads as one incident.
    linger_seconds: f64,
    /// When the most recent rate burst was seen. Tracked separately from the
    /// stream map so 'a burst is active' means a burst actually fired, not
    /// merely that some stream has history.
    last_burst_at: Option<f64>,
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}

impl Correlator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            window: WindowDetector::new(),
            network_streams: vec![
                "sys.network.received_bytes".into(),
                "sys.network.transmitted_bytes".into(),
                "net.egress".into(),
            ],
            active: HashMap::new(),
            linger_seconds: 30.0,
            last_burst_at: None,
        }
    }

    #[must_use]
    pub fn with_network_streams(mut self, streams: Vec<String>) -> Self {
        self.network_streams = streams;
        self
    }

    #[must_use]
    pub fn with_linger(mut self, seconds: f64) -> Self {
        self.linger_seconds = seconds.max(0.0);
        self
    }

    /// Replaces the rate detector, so its window and factor can be tuned with the
    /// rest of the pipeline.
    #[must_use]
    pub fn with_window_detector(mut self, window: WindowDetector) -> Self {
        self.window = window;
        self
    }

    /// Forgets every stream's cadence and active anomaly. Used when the operator
    /// accepts that the machine has genuinely changed.
    pub fn reset(&mut self) {
        self.window = WindowDetector::new();
        self.active.clear();
        self.last_burst_at = None;
    }

    /// Forgets one stream.
    pub fn reset_stream(&mut self, stream: &str) {
        self.window.forget(stream);
        self.active.remove(stream);
    }

    /// Folds in one point anomaly.
    pub fn note_anomaly(&mut self, stream: &str, magnitude: f64, now: f64) {
        self.active.insert(stream.to_string(), (now, magnitude));
    }

    /// Folds in one rate observation, for every stream, not only anomalous ones.
    ///
    /// Rate has to be measured on all traffic: a stream that is busy without being
    /// unusual is exactly the case the point detector cannot see.
    pub fn note_rate(&mut self, stream: &str, magnitude: f64, now: f64) -> Option<Burst> {
        let burst = self.window.observe(stream, magnitude, now);
        if burst.is_some() {
            self.last_burst_at = Some(now);
        }
        burst
    }

    /// Drops streams whose anomaly has aged out, then judges the current picture.
    pub fn assess(&mut self, now: f64) -> CorrelatedAssessment {
        self.active
            .retain(|_, (at, _)| now - *at <= self.linger_seconds);

        let count = self.active.len();
        // `f64` is not `Ord`, so the maximum is a fold rather than `Iterator::max`.
        let peak = self.active.values().fold(0.0f64, |acc, (_, m)| acc.max(*m));
        let network_involved = self.active.keys().any(|s| self.is_network(s));
        // A burst is 'active' while it is inside the same linger window as an
        // anomaly, so one incident reports one burst rather than one per poll.
        let burst_active = self
            .last_burst_at
            .is_some_and(|at| now - at <= self.linger_seconds);

        let band = Self::band(count, peak, network_involved);
        let rationale = Self::rationale(count, peak, network_involved);

        CorrelatedAssessment {
            band,
            anomalous_streams: count,
            peak_magnitude: peak,
            network_involved,
            burst_active,
            rationale,
        }
    }

    fn is_network(&self, stream: &str) -> bool {
        self.network_streams.iter().any(|n| n == stream)
    }

    fn band(count: usize, peak: f64, network: bool) -> RiskBand {
        // Thresholds are ordered so that "more streams" and "stronger magnitude"
        // are independent escalators: a single enormous spike and five mild
        // simultaneous blips both deserve more than one anomaly, but for
        // different reasons.
        match (count, network, peak) {
            (0, _, _) => RiskBand::Low,
            (1, false, p) if p < 8.0 => RiskBand::Low,
            (1, true, p) if p < 16.0 => RiskBand::Elevated,
            (1, _, p) if p < 32.0 => RiskBand::Elevated,
            (_, false, p) if p < 16.0 => RiskBand::Elevated,
            (_, true, p) if p < 32.0 => RiskBand::High,
            _ => RiskBand::Severe,
        }
    }

    fn rationale(count: usize, peak: f64, network: bool) -> String {
        match count {
            0 => "Nothing is outside its baseline.".into(),
            1 if network => format!(
                "A single network stream is {peak:.0}x its threshold. Often a download or \
                 a backup; worth confirming nothing left the host that should not have."
            ),
            1 => format!(
                "One stream is {peak:.0}x its threshold and nothing else corroborates it. \
                 Treat as probably benign until it recurs."
            ),
            n if network => format!(
                "{n} streams are anomalous together and one of them is network-facing. \
                 Independent streams rarely move at once by chance, and peak magnitude is \
                 {peak:.0}x threshold."
            ),
            n => format!(
                "{n} streams are anomalous together, none network-facing. Peak magnitude \
                 {peak:.0}x threshold."
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Emits `count` events evenly spaced between `from` and `to`.
    fn spread(
        d: &mut WindowDetector,
        stream: &str,
        from: f64,
        to: f64,
        count: usize,
    ) -> Vec<Burst> {
        #[allow(clippy::cast_precision_loss)]
        let step = if count > 1 {
            (to - from) / (count - 1) as f64
        } else {
            0.0
        };
        (0..count)
            .filter_map(|i| {
                #[allow(clippy::cast_precision_loss)]
                let at = from + step * i as f64;
                d.observe(stream, 1.0, at)
            })
            .collect()
    }

    #[test]
    fn a_steady_cadence_never_bursts() {
        let mut d = WindowDetector::new().with_burst_factor(3.0);
        // One event every 2 seconds for twenty minutes.
        let bursts = spread(&mut d, "s", 0.0, 2400.0, 1200);
        assert!(bursts.is_empty(), "steady traffic bursted: {bursts:?}");
        assert!(d.rate_of("s").is_some());
        let baseline = d.baseline_rate_of("s").unwrap();
        assert!(
            (baseline - 0.5).abs() < 0.05,
            "baseline rate was {baseline}"
        );
    }

    #[test]
    fn a_busy_machine_at_a_constant_high_rate_does_not_burst() {
        // The specific false positive this is guarding against: a machine that
        // is simply busy should not read as an attack.
        let mut d = WindowDetector::new().with_burst_factor(3.0);
        let bursts = spread(&mut d, "s", 0.0, 600.0, 1200);
        assert!(bursts.is_empty(), "sustained high load bursted: {bursts:?}");
    }

    #[test]
    fn a_sudden_flood_bursts_at_its_onset() {
        let mut d = WindowDetector::new().with_burst_factor(3.0);
        // One event every 10 seconds for ten minutes: a clear baseline.
        spread(&mut d, "s", 0.0, 600.0, 60);

        // Then ten events per second for twenty seconds.
        let bursts = spread(&mut d, "s", 600.0, 620.0, 200);
        assert!(!bursts.is_empty(), "a 100x cadence jump must burst");
        let worst = bursts.iter().fold(0.0f64, |a, b| a.max(b.multiple));
        assert!(worst > 3.0, "weakest observed multiple was {worst}");
        assert!(bursts[0].describe().contains("burst"));
    }

    #[test]
    fn a_sustained_flood_keeps_bursting() {
        // The property a two-half window could not provide: because the baseline
        // is frozen while a burst fires, an attack that never stops never becomes
        // the new normal.
        let mut d = WindowDetector::new().with_burst_factor(3.0);
        spread(&mut d, "s", 0.0, 600.0, 60);

        let bursts = spread(&mut d, "s", 600.0, 1800.0, 1200);
        assert!(!bursts.is_empty(), "a 20-minute flood must keep alerting");

        // Not merely the first few: it must still be firing at the end.
        let last = bursts.last().unwrap();
        assert!(
            last.multiple > 3.0,
            "the flood stopped being detected: {last:?}"
        );
    }

    #[test]
    fn a_stream_never_bursts_during_warmup() {
        let mut d = WindowDetector::new();
        // Fewer events than the warm-up threshold, however irregular.
        for i in 0..20 {
            let t = f64::from(i) * if i % 3 == 0 { 0.1 } else { 50.0 };
            assert!(d.observe("s", 1.0, t).is_none(), "event {i} bursted");
        }
    }

    #[test]
    fn a_first_event_establishes_the_cadence_without_bursting() {
        let mut d = WindowDetector::new();
        assert!(d.observe("s", 1.0, 0.0).is_none());
        assert!(d.observe("s", 1.0, 0.001).is_none());
    }

    #[test]
    fn forget_accepts_a_genuinely_new_cadence() {
        let mut d = WindowDetector::new().with_burst_factor(3.0);
        spread(&mut d, "s", 0.0, 600.0, 60);
        let quiet = d.baseline_rate_of("s").unwrap();

        spread(&mut d, "s", 600.0, 620.0, 200);
        assert!(
            d.forget("s"),
            "forgetting a known stream should report true"
        );
        assert!(!d.forget("s"), "forgetting twice should report false");
        assert!(d.rate_of("s").is_none());

        // After forgetting, the new cadence is learned rather than compared.
        let bursts = spread(&mut d, "s", 1000.0, 1600.0, 600);
        assert!(
            bursts.is_empty(),
            "a deliberately accepted cadence must not alert: {bursts:?}"
        );
        assert!(d.baseline_rate_of("s").unwrap() > quiet);
    }

    #[test]
    fn forgetting_one_stream_leaves_the_others() {
        let mut d = WindowDetector::new();
        spread(&mut d, "a", 0.0, 60.0, 60);
        spread(&mut d, "b", 0.0, 60.0, 60);
        assert_eq!(d.stream_count(), 2);
        d.forget("a");
        assert_eq!(d.stream_count(), 1);
        assert!(d.rate_of("b").is_some());
    }

    // -- correlation ------------------------------------------------------

    #[test]
    fn nothing_anomalous_is_low_risk() {
        let mut c = Correlator::new();
        let a = c.assess(0.0);
        assert_eq!(a.band, RiskBand::Low);
        assert!(!a.network_involved);
        assert!(a.describe().contains("Nothing"));
    }

    #[test]
    fn one_mild_non_network_signal_stays_low() {
        let mut c = Correlator::new();
        c.note_anomaly("sys.cpu.load_percent", 4.0, 0.0);
        assert_eq!(c.assess(0.0).band, RiskBand::Low);
    }

    #[test]
    fn one_network_signal_is_at_least_elevated() {
        let mut c = Correlator::new();
        c.note_anomaly("sys.network.received_bytes", 6.0, 0.0);
        let a = c.assess(0.0);
        assert!(a.band >= RiskBand::Elevated, "{a:?}");
        assert!(a.network_involved);
        assert!(a.rationale.contains("network"));
    }

    #[test]
    fn agreement_between_streams_escalates_where_one_would_not() {
        let mut c = Correlator::new();
        c.note_anomaly("sys.cpu.load_percent", 3.0, 0.0);
        let one = c.assess(0.0).band;

        let mut c2 = Correlator::new();
        for s in [
            "sys.cpu.load_percent",
            "sys.process.count",
            "sys.thread.count",
        ] {
            c2.note_anomaly(s, 3.0, 0.0);
        }
        let three = c2.assess(0.0).band;

        assert!(
            three > one,
            "three agreeing streams ({}) should outrank one ({})",
            three.label(),
            one.label()
        );
        assert_eq!(three, RiskBand::Elevated);
    }

    #[test]
    fn network_plus_agreement_reaches_high() {
        let mut c = Correlator::new();
        for s in ["sys.cpu.load_percent", "sys.network.transmitted_bytes"] {
            c.note_anomaly(s, 10.0, 0.0);
        }
        let a = c.assess(0.0);
        assert_eq!(a.band, RiskBand::High, "{a:?}");
        assert!(a.rationale.contains("network-facing"));
    }

    #[test]
    fn a_very_large_single_spike_is_escalated() {
        // Magnitude alone escalates: an enormous outlier is worth more attention
        // even with nothing corroborating it.
        let mut c = Correlator::new();
        c.note_anomaly("sys.memory.used_bytes", 100.0, 0.0);
        assert!(c.assess(0.0).band >= RiskBand::Elevated);
    }

    #[test]
    fn risk_bands_are_ordered() {
        assert!(RiskBand::Low < RiskBand::Elevated);
        assert!(RiskBand::Elevated < RiskBand::High);
        assert!(RiskBand::High < RiskBand::Severe);
        assert_eq!(RiskBand::High.index(), 2);
    }

    #[test]
    fn an_anomaly_ages_out_of_the_assessment() {
        let mut c = Correlator::new().with_linger(10.0);
        c.note_anomaly("sys.cpu.load_percent", 5.0, 0.0);
        assert_eq!(c.assess(1.0).anomalous_streams, 1);
        assert_eq!(c.assess(5.0).anomalous_streams, 1);
        assert_eq!(
            c.assess(50.0).anomalous_streams,
            0,
            "the anomaly should have expired"
        );
    }

    #[test]
    fn a_burst_across_several_polls_reads_as_one_incident() {
        let mut c = Correlator::new()
            .with_linger(30.0)
            .with_window_detector(WindowDetector::new().with_burst_factor(3.0).with_warmup(5));
        // A clear baseline: one event every 10 seconds.
        for t in [0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0] {
            c.note_rate("sys.network.received_bytes", 1.0, t);
        }
        // Then a flood.
        for i in 0..20 {
            let t = 80.0 + f64::from(i) * 0.5;
            c.note_rate("sys.network.received_bytes", 1.0, t);
            c.note_anomaly("sys.network.received_bytes", 6.0, t);
        }

        let a = c.assess(89.0);
        assert_eq!(a.anomalous_streams, 1, "one stream, however many hits");
        assert!(
            a.burst_active,
            "the flood should register as an active burst"
        );
    }

    #[test]
    fn a_burst_ages_out_of_the_assessment() {
        let mut c = Correlator::new().with_linger(10.0);
        c.note_anomaly("sys.cpu.load_percent", 5.0, 0.0);
        assert!(!c.assess(0.0).burst_active);
        c.note_anomaly("sys.cpu.load_percent", 5.0, 60.0);
        c.note_rate("s", 1.0, 60.0);
        assert!(!c.assess(500.0).burst_active);
    }

    #[test]
    fn network_streams_can_be_reconfigured() {
        let mut c = Correlator::new().with_network_streams(vec!["my.stream".into()]);
        c.note_anomaly("sys.network.received_bytes", 6.0, 0.0);
        assert!(!c.assess(0.0).network_involved);

        c.note_anomaly("my.stream", 6.0, 0.0);
        assert!(c.assess(0.0).network_involved);
    }

    #[test]
    fn rate_is_measured_on_all_traffic_not_only_anomalies() {
        let mut c = Correlator::new()
            .with_window_detector(WindowDetector::new().with_burst_factor(3.0).with_warmup(5));
        // A stream busy but not anomalous produces no band change on its own.
        for i in 0..60 {
            c.note_rate("busy", 1.0, f64::from(i) * 2.0);
        }
        assert_eq!(c.assess(0.0).band, RiskBand::Low);
    }
}
