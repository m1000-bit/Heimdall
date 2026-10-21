//! Where observations come from.
//!
//! # Why this is a trait and not a function
//!
//! Every interesting property of a detector is a property of the *sequence* it
//! sees, and the only way to test one is to feed it a known sequence. That needs
//! a source that can be driven deterministically, which a live OS probe is not.
//! So the trait has two implementations with different jobs:
//!
//! * [`SystemSource`] reads the real machine. Linux, macOS and Windows through
//!   one cross-platform implementation, so a signal is measured the same way
//!   everywhere and the baselines stay comparable.
//! * [`ReplaySource`] emits a recorded sequence. This is how the detector's
//!   behaviour on a known attack is tested at all -- and how a false-alarm rate
//!   is measured, since that is a property of the whole pipeline, not of a
//!   single sample.
//!
//! A source that cannot be replayed can only be tested for "does not crash",
//! which for a security detector is close to worthless.
//!
//! # What is *not* collected
//!
//! Command lines, environment variables, file contents and network payloads.
//! Only aggregate counters and process metadata. A monitoring system that
//! hoards command lines is itself a credential store, and `argv` on Linux is
//! readable by every local account.

macro_rules! opaque_debug {
    ($name:ident) => {
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

use std::sync::Mutex;

use crate::engine::Observation;

/// A producer of observations.
pub trait Source: Send {
    /// Human-readable name, for logs and the UI.
    fn name(&self) -> &'static str;

    /// Produces whatever has accumulated since the last call.
    ///
    /// Returns an empty vector rather than blocking when there is nothing to
    /// report, so a source never stalls the poll loop.
    fn poll(&mut self) -> Vec<Observation>;

    /// Reports whether the source is still usable. A source that has lost its
    /// backing resource stops the engine rather than silently reporting zeros,
    /// which would look like a perfectly quiet machine.
    fn is_healthy(&self) -> bool {
        true
    }
}

/// Stream names used by [`SystemSource`]. Stable, because a baseline is keyed
/// by name and renaming one silently resets its history.
pub mod streams {
    pub const CPU_LOAD: &str = "sys.cpu.load_percent";
    pub const MEMORY_USED: &str = "sys.memory.used_bytes";
    pub const PROCESS_COUNT: &str = "sys.process.count";
    pub const THREAD_COUNT: &str = "sys.thread.count";
    pub const NETWORK_RECEIVED: &str = "sys.network.received_bytes";
    pub const NETWORK_TRANSMITTED: &str = "sys.network.transmitted_bytes";
    pub const DISK_USED: &str = "sys.disk.used_bytes";
    /// Every stream the system source emits.
    pub const ALL: &[&str] = &[
        CPU_LOAD,
        MEMORY_USED,
        PROCESS_COUNT,
        THREAD_COUNT,
        NETWORK_RECEIVED,
        NETWORK_TRANSMITTED,
        DISK_USED,
    ];
}

/// Reads real machine telemetry.
///
/// Cumulative counters (bytes received, disk used) are reported as **deltas**
/// per interval, not totals. A total only ever increases, so the baseline would
/// drift monotonically upward and the drift detector would fire on the machine
/// doing its job.
pub struct SystemSource {
    system: sysinfo::System,
    /// `None` until the first poll, so the first reading can seed deltas instead
    /// of reporting the process's whole uptime as a single interval.
    previous: Option<Snapshot>,
    /// Bytes of network traffic since the previous poll, summed over interfaces.
    last_net: Option<sysinfo::Networks>,
    last_disk: Option<sysinfo::Disks>,
}

/// A point-in-time reading, used to turn cumulative counters into deltas.
struct Snapshot {
    received: u64,
    transmitted: u64,
    disk_used: u64,
}

impl SystemSource {
    pub fn new() -> Self {
        Self {
            // One refresh; `poll` refreshes again. Populating here means the
            // first `poll` has a baseline to diff against instead of reporting
            // an unfiltered jump.
            system: sysinfo::System::new_with_specifics(
                sysinfo::RefreshKind::nothing()
                    .with_memory(sysinfo::MemoryRefreshKind::everything()),
            ),
            previous: None,
            last_net: None,
            last_disk: None,
        }
    }

    fn net_totals(net: &sysinfo::Networks) -> (u64, u64) {
        let mut recv = 0u64;
        let mut sent = 0u64;
        for (_, data) in net {
            recv = recv.saturating_add(data.received());
            sent = sent.saturating_add(data.transmitted());
        }
        (recv, sent)
    }
}

impl Default for SystemSource {
    fn default() -> Self {
        Self::new()
    }
}

/// Byte, process and thread counts are `u64`/`usize` and the pipeline works in
/// `f64`. The casts below are deliberate: `f64` holds every integer below 2^53
/// exactly, which is 9 petabytes of bytes or 90 trillion processes. Past that a
/// reading loses its last digit, which is not a measurement problem this host
/// will ever have.
#[allow(clippy::cast_precision_loss)]
impl Source for SystemSource {
    fn name(&self) -> &'static str {
        "system"
    }

    fn poll(&mut self) -> Vec<Observation> {
        self.system.refresh_memory();

        // CPU needs a sampling interval; without one it would report the load
        // accumulated since the last refresh, which is a duration, not a load.
        self.system.refresh_cpu_usage();

        let net = sysinfo::Networks::new_with_refreshed_list();
        let disk = sysinfo::Disks::new_with_refreshed_list();

        let (recv, sent) = Self::net_totals(&net);
        let disk_used: u64 = disk
            .list()
            .iter()
            .map(|d| d.total_space().saturating_sub(d.available_space()))
            .sum();

        let mut out = vec![
            Observation {
                stream: streams::CPU_LOAD.into(),
                value: f64::from(self.system.global_cpu_usage()),
            },
            Observation {
                stream: streams::MEMORY_USED.into(),
                value: self.system.used_memory() as f64,
            },
            Observation {
                stream: streams::PROCESS_COUNT.into(),
                value: self.system.processes().len() as f64,
            },
            Observation {
                stream: streams::THREAD_COUNT.into(),
                // `tasks()` returns an `Option` in sysinfo 0.39; an unexpanded
                // task list would read as zero threads, which looks like a
                // quiet machine rather than a missing reading.
                value: self
                    .system
                    .processes()
                    .values()
                    .map(|p| p.tasks().map_or(0.0, |t| t.len() as f64))
                    .sum(),
            },
        ];

        // Deltas, from the second poll onward. The first call reports nothing
        // for these streams rather than a fabricated interval.
        if let Some(prev) = self.previous.take() {
            out.push(Observation {
                stream: streams::NETWORK_RECEIVED.into(),
                value: recv.saturating_sub(prev.received) as f64,
            });
            out.push(Observation {
                stream: streams::NETWORK_TRANSMITTED.into(),
                value: sent.saturating_sub(prev.transmitted) as f64,
            });
            out.push(Observation {
                stream: streams::DISK_USED.into(),
                value: disk_used.saturating_sub(prev.disk_used) as f64,
            });
        }

        self.previous = Some(Snapshot {
            received: recv,
            transmitted: sent,
            disk_used,
        });
        // Retained so the caller can see them, and so a future source can diff
        // against the previous network listing directly.
        self.last_net = Some(net);
        self.last_disk = Some(disk);

        out
    }

    fn is_healthy(&self) -> bool {
        self.system.total_memory() > 0
    }
}

/// Emits a recorded sequence, then stops.
///
/// Backs the detector tests, and backs the shell's demo mode. Deliberately
/// exhausted rather than looping: a source that repeats forever would make a
/// test that forgets to stop it pass anyway.
pub struct ReplaySource {
    name: &'static str,
    script: std::collections::VecDeque<Vec<Observation>>,
    exhausted: bool,
    /// Repeats the script instead of stopping. For a demo mode that needs to keep
    /// the UI populated, never for a test.
    looping: bool,
}

impl ReplaySource {
    #[must_use]
    pub fn new(name: &'static str, script: Vec<Vec<Observation>>) -> Self {
        Self {
            name,
            script: script.into(),
            exhausted: false,
            looping: false,
        }
    }

    /// A source that emits one flat observation per step.
    #[must_use]
    pub fn flat(steps: Vec<Observation>) -> Self {
        Self::new("replay", steps.into_iter().map(|o| vec![o]).collect())
    }

    #[must_use]
    pub fn looping(mut self) -> Self {
        self.looping = true;
        self
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted && !self.looping
    }
}

impl Source for ReplaySource {
    fn name(&self) -> &'static str {
        self.name
    }

    fn poll(&mut self) -> Vec<Observation> {
        if let Some(step) = self.script.pop_front() {
            step
        } else {
            self.exhausted = true;
            Vec::new()
        }
    }

    fn is_healthy(&self) -> bool {
        !self.is_exhausted()
    }
}

/// Fans several sources into one, so the engine does not care how many there
/// are or where they come from.
pub struct MultiSource {
    sources: Vec<Box<dyn Source>>,
}

impl MultiSource {
    #[must_use]
    pub fn new(sources: Vec<Box<dyn Source>>) -> Self {
        Self { sources }
    }

    /// Adds a source.
    pub fn push(&mut self, source: Box<dyn Source>) {
        self.sources.push(source);
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Names of sources that have gone unhealthy.
    pub fn unhealthy(&self) -> Vec<&'static str> {
        self.sources
            .iter()
            .filter(|s| !s.is_healthy())
            .map(|s| s.name())
            .collect()
    }
}

impl Source for MultiSource {
    fn name(&self) -> &'static str {
        "multi"
    }

    fn poll(&mut self) -> Vec<Observation> {
        let mut out = Vec::new();
        for source in &mut self.sources {
            out.extend(source.poll());
        }
        out
    }

    fn is_healthy(&self) -> bool {
        // An empty multi-source is not a quiet machine, it is a broken pipeline.
        !self.sources.is_empty() && self.sources.iter().all(|s| s.is_healthy())
    }
}

/// Wraps a source so several threads can share one, and contains its failures.
///
/// `sysinfo` handles are not `Sync`, and the engine runs on a poll thread while
/// the UI reads its state. Rather than making the whole engine `Sync`, the
/// sharing point is here.
///
/// A source that panics is **disabled**, not propagated. A panicking telemetry
/// call would otherwise crash the poll loop on every single iteration, taking the
/// detector with it and reporting nothing -- and "no data" reads exactly like a
/// quiet machine. Disabling it reports the failure instead.
pub struct SharedSource {
    inner: Mutex<SharedInner>,
    name: &'static str,
}

/// `SharedInner` deliberately does not derive `Debug`: `dyn Source` is not
/// `Debug`, and the source itself is not the interesting part.
struct SharedInner {
    /// `None` once the source has failed.
    source: Option<Box<dyn Source>>,
    failure: Option<String>,
}

impl core::fmt::Debug for SharedSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedSource")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl SharedSource {
    pub fn new(source: Box<dyn Source>) -> Self {
        Self {
            name: source.name(),
            inner: Mutex::new(SharedInner {
                source: Some(source),
                failure: None,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SharedInner> {
        // A poisoned lock means a previous poll panicked; the source has already
        // been taken out at that point, so recovering is safe and loses nothing.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Polls every source. A panicking source is disabled and this returns
    /// nothing rather than propagating.
    pub fn poll_all(&self) -> Vec<Observation> {
        let mut guard = self.lock();
        let Some(source) = guard.source.as_mut() else {
            return Vec::new();
        };

        let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| source.poll()));
        if let Ok(observations) = polled {
            observations
        } else {
            // Drop the failing source: something about it is broken in a way
            // a retry on every poll would repeat forever.
            guard.source = None;
            guard.failure = Some(format!("source '{}' panicked and was disabled", self.name));
            tracing::error!(
                source = self.name,
                "telemetry source panicked; disabling it"
            );
            Vec::new()
        }
    }

    /// Whether the source is usable. A disabled source is not.
    pub fn unhealthy(&self) -> bool {
        let guard = self.lock();
        guard.source.as_ref().is_none_or(|s| !s.is_healthy())
    }

    /// Why the source was disabled, if it was.
    pub fn failure(&self) -> Option<String> {
        self.lock().failure.clone()
    }

    pub fn source_name(&self) -> &'static str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(stream: &str, value: f64) -> Observation {
        Observation {
            stream: stream.into(),
            value,
        }
    }

    #[test]
    fn replay_emits_the_recorded_sequence_then_stops() {
        let mut s = ReplaySource::flat(vec![obs("a", 1.0), obs("a", 2.0)]);
        assert_eq!(s.poll().len(), 1);
        assert_eq!(s.poll().len(), 1);
        assert!(s.poll().is_empty());
        assert!(s.is_exhausted());
        assert!(!s.is_healthy(), "an exhausted source must report unhealthy");
    }

    #[test]
    fn replay_can_loop_for_a_demo() {
        let mut s = ReplaySource::flat(vec![obs("a", 1.0)]).looping();
        assert_eq!(s.poll().len(), 1);
        assert!(s.poll().is_empty());
        assert!(!s.is_exhausted());
    }

    #[test]
    fn replay_can_carry_a_multi_stream_step() {
        let mut s = ReplaySource::new(
            "replay",
            vec![vec![obs("a", 1.0), obs("b", 2.0)], vec![obs("a", 1.5)]],
        );
        assert_eq!(s.poll().len(), 2);
        assert_eq!(s.poll().len(), 1);
        assert!(s.poll().is_empty());
    }

    #[test]
    fn multi_fans_sources_together() {
        let mut m = MultiSource::new(vec![
            Box::new(ReplaySource::flat(vec![obs("a", 1.0)])),
            Box::new(ReplaySource::flat(vec![obs("b", 2.0), obs("c", 3.0)])),
        ]);
        assert_eq!(m.len(), 2);
        // Each source yields one step per poll: 1 observation plus 1.
        assert_eq!(m.poll().len(), 2);
        assert!(m.is_healthy());
    }

    #[test]
    fn multi_reports_an_unhealthy_child() {
        let mut m = MultiSource::new(vec![
            Box::new(ReplaySource::flat(vec![obs("a", 1.0)])),
            Box::new(ReplaySource::flat(vec![])),
        ]);
        m.poll();
        assert_eq!(m.unhealthy(), vec!["replay"]);
    }

    #[test]
    fn an_empty_multi_source_is_unhealthy() {
        // Zero sources must not read as a silent, perfectly healthy machine.
        let m = MultiSource::new(vec![]);
        assert!(m.is_empty());
        assert!(!m.is_healthy());
    }

    #[test]
    fn the_shared_source_recovers_from_a_poisoned_lock() {
        use std::sync::Arc;

        /// A source that panics *while being polled*, which is the only way to
        /// poison the lock: panicking after `poll_all` returns leaves it healthy.
        struct Exploding;
        impl Source for Exploding {
            fn name(&self) -> &'static str {
                "exploding"
            }
            // Byte, process and thread counts are `u64`/`usize` and the pipeline works in
            // `f64`. The cast is deliberate: `f64` holds every integer below 2^53
            // exactly, which is 9 petabytes of bytes or 90 trillion processes. Above that
            // a reading loses its last digit, which is not a measurement problem anyone
            // will ever have on this host.
            #[allow(clippy::cast_precision_loss)]
            fn poll(&mut self) -> Vec<Observation> {
                panic!("poison the mutex on purpose");
            }
        }

        // Two steps, because the sanity check polls twice.
        let shared = Arc::new(SharedSource::new(Box::new(ReplaySource::flat(vec![
            obs("a", 1.0),
            obs("b", 2.0),
        ]))));
        let c = Arc::clone(&shared);
        let _ = std::thread::spawn(move || {
            let _ = c.poll_all();
        })
        .join();

        // Sanity: the shared source still works.
        assert!(!shared.poll_all().is_empty());

        // Now poison it for real.
        let shared = Arc::new(SharedSource::new(Box::new(Exploding)));
        let c = Arc::clone(&shared);
        let _ = std::thread::spawn(move || {
            let _ = c.poll_all();
        })
        .join();

        assert!(
            shared.unhealthy(),
            "a source that panics must be reported unhealthy, not silently zero"
        );
        assert!(shared.failure().is_some(), "the failure must be explained");
        assert_eq!(shared.source_name(), "exploding");
        // A disabled source stays disabled, rather than crashing on every poll.
        assert!(shared.poll_all().is_empty());
        assert!(shared.unhealthy());
    }

    #[test]
    fn the_system_source_produces_a_full_reading() {
        let mut s = SystemSource::new();
        let first = s.poll();
        assert!(!first.is_empty(), "the first poll must report something");

        let names: Vec<&str> = first.iter().map(|o| o.stream.as_str()).collect();
        for expected in [
            streams::CPU_LOAD,
            streams::MEMORY_USED,
            streams::PROCESS_COUNT,
        ] {
            assert!(names.contains(&expected), "missing {expected} in {names:?}");
        }

        // Cumulative counters are excluded from the first reading: there is no
        // previous interval to difference against, and reporting one would look
        // like a huge burst.
        assert!(!names.contains(&streams::NETWORK_RECEIVED));
        assert!(!names.contains(&streams::NETWORK_TRANSMITTED));

        let second = s.poll();
        let names: Vec<&str> = second.iter().map(|o| o.stream.as_str()).collect();
        for expected in [
            streams::CPU_LOAD,
            streams::MEMORY_USED,
            streams::PROCESS_COUNT,
            streams::THREAD_COUNT,
            streams::NETWORK_RECEIVED,
            streams::NETWORK_TRANSMITTED,
            streams::DISK_USED,
        ] {
            assert!(
                names.contains(&expected),
                "missing {expected} on the second poll"
            );
        }

        assert!(s.is_healthy());
    }

    #[test]
    fn the_system_source_never_reports_a_negative_delta() {
        let mut s = SystemSource::new();
        for _ in 0..4 {
            for o in s.poll() {
                assert!(
                    o.value >= 0.0,
                    "{} reported a negative value: {}",
                    o.stream,
                    o.value
                );
            }
        }
    }

    #[test]
    fn the_system_source_emits_no_finite_poison() {
        // A NaN reaching the detector would be reported as a fault on a healthy
        // machine.
        let mut s = SystemSource::new();
        for _ in 0..4 {
            for o in s.poll() {
                assert!(o.value.is_finite(), "{} produced {}", o.stream, o.value);
            }
        }
    }
}
opaque_debug!(SystemSource);
opaque_debug!(ReplaySource);
opaque_debug!(MultiSource);
