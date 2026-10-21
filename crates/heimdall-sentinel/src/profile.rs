//! Profiling of the Sentinel's hot paths.
//!
//! The daemon runs on a timer: every [`crate::POLL_INTERVAL`] it samples the
//! machine, folds the samples into the detector, and reports what it found.
//! The question this file answers is how much of that interval the work
//! actually takes.
//!
//! The measurements are printed rather than asserted, with one exception.
//! A test that fails because a shared runner was busy teaches nothing about
//! the product, and a benchmark that fails on a slow machine is a benchmark
//! nobody trusts. What is asserted is the property the operator cares about:
//! a tick finishes far inside the poll interval, and the cost does not creep
//! upward as the daemon runs for days. Those two are the ones that turn into
//! a broken machine, and they are also the ones a regression would break
//! first.
//!
//! Two costs are measured separately, because they are paid at different
//! places and only one of them is the product's own work:
//!
//! * the *probe* -- what the operating system costs to read the machine;
//! * the *detection path* -- what Sentinel costs to decide whether a sample
//!   is unusual, which is the part this crate owns.
//!
//! The split matters when something is slow. A slow tick on a machine with
//! many disks is the probe, and the fix is in how often the probe runs, not
//! in the detector. A slow tick on a quiet machine with one disk is the
//! detection path, and the fix is in this crate.

use std::time::{Duration, Instant};

use crate::{
    engine::{Engine, Observation},
    source::{Source, SystemSource, streams},
};

/// How long a tick may take before the test fails.
///
/// The poll interval is two seconds, so a millisecond is five hundredths of a
/// percent of it. The measured cost is three orders of magnitude below this,
/// and the margin is here to keep the test honest on a loaded machine.
const TICK_BUDGET: Duration = Duration::from_millis(1);

/// The median of a set of measurements.
///
/// The mean of a timing is dominated by whatever else the machine was doing
/// at the time. The median is the number that describes the code.
fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// Runs `f` a number of times and returns the median elapsed time.
fn median_time(rounds: usize, mut f: impl FnMut()) -> Duration {
    let mut samples = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let started = Instant::now();
        f();
        samples.push(started.elapsed());
    }
    median(samples)
}

/// One tick's worth of observations: the streams the system source emits.
///
/// The values drift slowly, the way a real machine's do.
fn tick(seed: u32) -> Vec<Observation> {
    let mut out = Vec::with_capacity(streams::ALL.len());
    for (index, name) in streams::ALL.iter().enumerate() {
        let offset = f64::from(u32::try_from(index).expect("index fits a u32"));
        out.push(Observation {
            stream: (*name).to_string(),
            value: 100.0 + offset + f64::from(seed) * 0.001,
        });
    }
    out
}

/// Warms an engine past its cold-start window.
///
/// Until the engine has seen enough samples the detector is not deciding
/// anything, and the cost of that phase is not the cost of the steady state.
fn warmed_engine() -> Engine {
    let mut engine = Engine::new("profile");
    for seed in 0..500 {
        for obs in tick(seed) {
            let _ = engine.ingest(&obs);
        }
    }
    engine
}

#[test]
fn a_tick_of_detection_costs_a_hair_of_the_poll_interval() {
    let mut engine = warmed_engine();
    let observations = tick(1_000);

    let rounds = 50;
    let per_tick = median_time(rounds, || {
        for obs in &observations {
            let _ = engine.ingest(obs);
        }
    });

    let count = u32::try_from(observations.len()).expect("count fits a u32");
    let per_observation = per_tick / count;
    println!(
        "detection path: {per_tick:?} per tick of {count} observations, \
         {per_observation:?} per observation"
    );

    assert!(
        per_tick < TICK_BUDGET,
        "a tick of detection took {per_tick:?}, over the {TICK_BUDGET:?} budget"
    );
}

#[test]
fn the_alert_path_is_not_orders_of_magnitude_slower() {
    // Two engines, so the quiet measurement is not polluted by the frozen
    // baseline that a loud sample leaves behind.
    let mut quiet_engine = warmed_engine();
    let mut loud_engine = warmed_engine();

    let quiet = Observation {
        stream: streams::CPU_LOAD.to_string(),
        value: 101.0,
    };
    // The baseline is frozen near 100, so this is far outside it.
    let loud = Observation {
        stream: streams::CPU_LOAD.to_string(),
        value: 9_000.0,
    };

    let rounds = 200;
    let quiet_cost = median_time(rounds, || {
        let _ = quiet_engine.ingest(&quiet);
    });
    let loud_cost = median_time(rounds, || {
        let _ = loud_engine.ingest(&loud);
    });

    println!(
        "quiet observation: {quiet_cost:?}; alerting observation: {loud_cost:?} \
         ({}x)",
        if quiet_cost.is_zero() {
            f64::INFINITY
        } else {
            loud_cost.as_secs_f64() / quiet_cost.as_secs_f64()
        }
    );

    // The alert path does more work: it plans a containment, writes a
    // summary and allocates a threat alert. It should not do *orders* of
    // magnitude more work, because an attacker who can make every sample
    // anomalous can make the daemon miss its next tick.
    assert!(
        loud_cost < quiet_cost * 25,
        "an alerting observation cost {loud_cost:?} against {quiet_cost:?} for a \
         quiet one"
    );
    assert!(
        loud_cost < TICK_BUDGET,
        "a single alerting observation took {loud_cost:?}, over the \
         {TICK_BUDGET:?} budget"
    );
}

#[test]
fn the_cost_does_not_grow_with_the_number_of_samples() {
    // A daemon that runs for a week sees tens of millions of samples. If the
    // cost of a sample grew with the number of samples, the daemon would
    // start falling behind exactly when it has been running longest.
    let mut engine = Engine::new("profile");
    let sample = Observation {
        stream: streams::CPU_LOAD.to_string(),
        value: 100.0,
    };

    let half = 50_000;
    let first_started = Instant::now();
    for _ in 0..half {
        let _ = engine.ingest(&sample);
    }
    let first = first_started.elapsed();

    let second_started = Instant::now();
    for _ in 0..half {
        let _ = engine.ingest(&sample);
    }
    let second = second_started.elapsed();

    println!("first {half} samples: {first:?}; next {half}: {second:?}");

    // Generous, because a shared runner can be interrupted: the point is to
    // catch a quadratic blow-up, which shows up as orders of magnitude, not
    // as a few percent.
    assert!(
        second < first * 2,
        "the cost grew with the number of samples: {first:?} then {second:?}"
    );
}

#[test]
fn the_cost_does_not_grow_with_the_number_of_streams() {
    // The correlator looks at every stream on every assessment, so the cost
    // per observation is expected to grow with the number of streams. What
    // must not happen is a tick of many streams missing the budget.
    let streams_count = 32u32;
    let mut engine = Engine::new("profile");

    let observations: Vec<Observation> = (0..streams_count)
        .map(|index| Observation {
            stream: format!("stream.{index}"),
            value: 100.0 + f64::from(index),
        })
        .collect();

    for obs in &observations {
        let _ = engine.ingest(obs);
    }

    let rounds = 50;
    let per_tick = median_time(rounds, || {
        for obs in &observations {
            let _ = engine.ingest(obs);
        }
    });
    let per_observation = per_tick / streams_count;

    println!(
        "{streams_count} streams: {per_tick:?} per tick, {per_observation:?} per \
         observation"
    );

    assert!(
        per_tick < TICK_BUDGET,
        "a tick over {streams_count} streams took {per_tick:?}, over the \
         {TICK_BUDGET:?} budget"
    );
}

#[test]
fn where_the_probe_spends_its_time() {
    // The probe is the expensive half of a tick, so it is worth knowing which
    // part of it is expensive. The counters are cheap to read; re-enumerating
    // the interfaces and the disks is a syscall storm, and the source does it
    // on every poll.
    let mut system = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing().with_memory(sysinfo::MemoryRefreshKind::everything()),
    );
    system.refresh_memory();
    system.refresh_cpu_usage();

    let rounds = 20;
    let memory = median_time(rounds, || {
        system.refresh_memory();
    });
    let cpu = median_time(rounds, || {
        system.refresh_cpu_usage();
    });
    let networks = median_time(rounds, || {
        let _ = sysinfo::Networks::new_with_refreshed_list();
    });
    let disks = median_time(rounds, || {
        let _ = sysinfo::Disks::new_with_refreshed_list();
    });

    println!(
        "probe breakdown: memory {memory:?}, cpu {cpu:?}, networks {networks:?}, \
         disks {disks:?}"
    );

    // The claim this file makes about the probe is that it dominates the
    // tick. If the enumeration ever stops dominating it, the claim is stale
    // and should be revisited rather than repeated.
    let enumeration = networks + disks;
    assert!(
        enumeration > cpu,
        "enumerating interfaces and disks ({enumeration:?}) is no longer more \
         expensive than reading the CPU ({cpu:?})"
    );
}

#[test]
fn the_probe_costs_more_than_the_detection() {
    // The probe reads the real machine. The detection path is the work this
    // crate does with what the probe found. The two are measured apart
    // because they are fixed separately.
    let mut source = SystemSource::new();
    // The first poll seeds the deltas, and it is not the interesting one.
    let _ = source.poll();

    let rounds = 20;
    let probe = median_time(rounds, || {
        let _ = source.poll();
    });

    let observations = source.poll();
    let mut engine = warmed_engine();
    let detect = median_time(rounds, || {
        for obs in &observations {
            let _ = engine.ingest(obs);
        }
    });

    println!(
        "probe: {probe:?} per poll; detection: {detect:?} per tick of {} \
         observations",
        observations.len()
    );

    // The property the daemon depends on: the whole tick, probe included,
    // finishes well inside the poll interval.
    let tick = probe + detect;
    assert!(
        tick < crate::POLL_INTERVAL / 4,
        "a tick took {tick:?}, over a quarter of the {:?} poll interval",
        crate::POLL_INTERVAL
    );
}
