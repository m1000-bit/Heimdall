//! Heimdall Sentinel: the defence daemon.
//!
//! Binds the IPC endpoint, provisions its long-term identity, samples telemetry
//! on a fixed interval, and serves Core.
//!
//! # What "autonomous" means here
//!
//! Sentinel decides *what to report* on its own. It never decides *what to
//! change*: every containment is a recommendation with a rationale, and acting
//! on one is Core's call and then the operator's. That boundary is enforced by
//! the message types -- there is no message that makes Sentinel alter the host.
//!
//! # Identity
//!
//! The identity is loaded from the keystore, created on first run, and published
//! to the peers directory so Core can pin it. If the keystore is corrupt, this
//! exits rather than minting a replacement: an identity that silently changes
//! looks exactly like a compromise and behaves like one.

use std::sync::Arc;
use std::time::Duration;

use heimdall_crypto::identity::{KeystoreLocation, provision};
use heimdall_crypto::{Identity, Passphrase, ReplayGuard, Suite};
use heimdall_ipc::{
    CloseReason, Listener, Message, Session,
    message::{Command, ContainmentRecommendation},
    transport::DEFAULT_ENDPOINT,
};

use heimdall_sentinel::{
    BaselineStore, ContainmentExecutor, ContainmentPolicy, DEFAULT_SENTINEL_ID, Engine,
    Observation, POLL_INTERVAL, Policy, SharedSource, SystemSource, source::streams,
};

/// Sent on startup so the operator can pin Core before the first connection.
const PUBLISH_ROLE: &str = "sentinel";

/// How long to wait for Core to publish its identity before giving up.
const PEER_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// How often the learned baselines are written to disk.
///
/// Frequent enough that a crash loses little, sparse enough that the write
/// does not become a way to wear the disk out.
const BASELINE_SAVE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct Options {
    endpoint: String,
    keystore: Option<KeystoreLocation>,
    /// The passphrase, when it was given on the command line. When it was not,
    /// it is read from the environment.
    passphrase: Option<String>,
    poll: Duration,
    /// Refuse to serve. Used by the self-check path.
    once: bool,
    /// Whether containment may be carried out at all.
    allow_containment: bool,
    /// The allow-list of what may be contained.
    policy: ContainmentPolicy,
    /// Where the learned baselines are kept.
    baseline: Option<std::path::PathBuf>,
    /// Core's identity, when it was configured rather than read from disk.
    core_id: Option<String>,
    /// Where Core's published identity is read from.
    core_identity_path: Option<std::path::PathBuf>,
}
impl Options {
    fn parse() -> Result<Self, String> {
        Self::parse_from(std::env::args().skip(1))
    }

    /// Parses the arguments.
    ///
    /// Split out from [`Options::parse`] so the rules can be tested without
    /// changing the environment of the test process.
    fn parse_from<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut endpoint = DEFAULT_ENDPOINT.to_string();
        let mut keystore = None;
        let mut passphrase = None;
        let mut poll = POLL_INTERVAL;
        let mut once = false;
        let mut allow_containment = false;
        let mut policy = ContainmentPolicy::default();
        let mut baseline = None;
        let mut core_id = None;
        let mut core_identity_path = None;

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--endpoint" => {
                    endpoint = args.next().ok_or("--endpoint needs a value")?;
                }
                "--keystore" => {
                    keystore = Some(KeystoreLocation::at(
                        args.next().ok_or("--keystore needs a path")?,
                    ));
                }
                "--passphrase" => {
                    passphrase = Some(args.next().ok_or("--passphrase needs a value")?);
                }
                "--poll-secs" => {
                    let v = args.next().ok_or("--poll-secs needs a value")?;
                    poll =
                        Duration::from_secs(v.parse().map_err(|_| "--poll-secs must be a number")?);
                }
                // Opt in to carrying out containment. Without it this daemon
                // recommends and refuses, which is the default posture.
                "--allow-containment" => allow_containment = true,
                // The allow-list: which processes, addresses and interfaces may
                // be contained. Without one, nothing is contained even with the
                // flag above.
                "--contain-policy" => {
                    let path = args.next().ok_or("--contain-policy needs a path")?;
                    let parsed = ContainmentPolicy::load(std::path::Path::new(&path))
                        .map_err(|e| format!("cannot use the containment policy: {e}"))?;
                    policy.allowed_pids = parsed.allowed_pids;
                    policy.allowed_cidrs = parsed.allowed_cidrs;
                    policy.allowed_interfaces = parsed.allowed_interfaces;
                    policy.hook = parsed.hook;
                }
                // Where the learned baselines live. The default is under the
                // data directory; the flag exists for the cases where that is
                // not where the operator wants them.
                "--baseline" => {
                    let path = args.next().ok_or("--baseline needs a path")?;
                    baseline = Some(std::path::PathBuf::from(path));
                }
                // Core's identity, when it is known. Pinning Core by
                // configuration is the same upgrade the operator makes on the
                // other side, and it is what a deployment wants: the daemon
                // does not need to trust whatever a file happens to say.
                "--core-id" => {
                    let hex = args.next().ok_or("--core-id needs a hex identity")?;
                    core_id = Some(hex);
                }
                // Where Core's published identity is read from. The default is
                // under the data directory, which is where the shell writes it
                // unless HEIMDALL_PUBLISH_DIR says otherwise.
                "--core-identity" => {
                    let path = args.next().ok_or("--core-identity needs a path")?;
                    core_identity_path = Some(std::path::PathBuf::from(path));
                }
                // Establish the identity, publish it, and exit. What an operator
                // runs before first contact.
                "--print-identity" => once = true,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        policy.enabled = allow_containment;
        // Containment without an allow-list would contain nothing, so the
        // flag would only misdescribe the daemon's posture. Refusing to start
        // is better than running in a state that looks armed and is not.
        if allow_containment
            && policy.allowed_pids.is_empty()
            && policy.allowed_cidrs.is_empty()
            && policy.allowed_interfaces.is_empty()
        {
            return Err(
                "--allow-containment needs a --contain-policy file: without an allow-list \
                 nothing could be contained, and the daemon would only appear to be armed"
                    .into(),
            );
        }
        Ok(Self {
            endpoint,
            keystore,
            passphrase,
            poll,
            once,
            allow_containment,
            policy,
            baseline,
            core_id,
            core_identity_path,
        })
    }
}

fn print_help() {
    println!(
        "heimdall-sentinel -- host and network defence daemon\n\
         \n\
         Options:\n\
         \x20 --endpoint <name>      IPC endpoint name (default {DEFAULT_ENDPOINT})\n\
         \x20 --keystore <path>      keystore file (default: per-user data directory)\n\
         \x20 --passphrase <text>    keystore passphrase (default: from the environment)\n\
         \x20 --poll-secs <n>        telemetry interval (default {})\n\
         \x20 --allow-containment   permit carrying out approved containment orders\n\
         \x20 --contain-policy <p>  file listing what may be contained (pids, cidrs, interfaces)\n\
         \x20 --baseline <path>      where the learned baselines are kept (default: data directory)\n\
         \x20 --core-id <hex>       Core's identity, when it is known in advance\n\
         \x20 --core-identity <p>   where Core's published identity is read from\n\
         \x20 --print-identity       provision and publish the identity, then exit\n\
         \x20 -h, --help             this message\n\
         \n\
         The passphrase may instead be supplied in $HEIMDALL_KEYSTORE_PASSPHRASE, or in a\n\
         systemd credential named 'passphrase', which is the better option on Unix where argv\n\
         is world-readable.\n\
         \n\
         Containment is advisory unless --allow-containment is given. Even then, only the\n\
         targets named in the policy file may be contained, and only on an order that names\n\
         the operator who approved it. A whole-host quarantine is never carried out.",
        POLL_INTERVAL.as_secs()
    );
}

/// Publishes Sentinel's identity so Core can pin it.
fn publish_identity(identity: &Identity) -> Result<(), String> {
    let path = heimdall_crypto::identity::base_dir()
        .map_err(|e| e.to_string())?
        .join("published");
    std::fs::create_dir_all(&path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    let file = path.join(format!("{PUBLISH_ROLE}.identity"));
    std::fs::write(&file, identity.hex())
        .map_err(|e| format!("cannot write {}: {e}", file.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644));
    }
    tracing::info!(path = %file.display(), "published sentinel identity");
    Ok(())
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,wgpu=warn,heimdall=info".into()),
        )
        .init();

    let opts = match Options::parse() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("heimdall-sentinel: {e}\n");
            print_help();
            return std::process::ExitCode::from(2);
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("heimdall-sentinel: cannot start the runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(opts)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("heimdall-sentinel: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(opts: Options) -> Result<(), String> {
    let keystore = match opts.keystore.clone() {
        Some(k) => k,
        None => KeystoreLocation::default_path().map_err(|e| e.to_string())?,
    };
    let passphrase = match &opts.passphrase {
        Some(text) => Passphrase::from_utf8(text.as_bytes()),
        None => heimdall_crypto::kdf::passphrase_from_environment(),
    };
    let identity = provision(&keystore, &passphrase)
        .map_err(|e| format!("cannot provision the identity: {e}"))?;
    publish_identity(identity.identity())?;

    println!("sentinel identity: {}", identity.identity().hex());
    if identity.was_created() {
        println!("(newly created; pin this in Core before first contact)");
    }

    if opts.once {
        return Ok(());
    }

    // Core's identity is pinned from the file it publishes, so the two daemons
    // bootstrap each other on first contact and verify thereafter. A configured
    // identity skips the file: the operator said which key, and the daemon
    // holds it to that.
    let core_identity = resolve_core_identity(&opts)?;
    tracing::info!(core = %core_identity.hex(), "sentinel ready");

    let mut listener = Listener::bind(&opts.endpoint)
        .await
        .map_err(|e| format!("cannot bind {}: {e}", opts.endpoint))?;
    tracing::info!(
        endpoint = %opts.endpoint,
        path = %listener.endpoint_path().display(),
        "sentinel listening"
    );

    let source: Arc<SharedSource> = Arc::new(SharedSource::new(Box::new(SystemSource::new())));
    let mut engine = Engine::new(DEFAULT_SENTINEL_ID);
    let mut guard = ReplayGuard::new(256);
    let mut executor = ContainmentExecutor::new(opts.policy.clone());

    // The baselines the engine has learned. A daemon that forgets everything
    // on every restart spends its first minutes of every boot learning what
    // the host looks like, and is quiet exactly when a fresh compromise would
    // be hiding in the noise.
    let baseline_path = match &opts.baseline {
        Some(path) => path.clone(),
        None => heimdall_crypto::identity::base_dir()
            .map_err(|e| format!("cannot locate the data directory: {e}"))?
            .join("baselines")
            .join("host.baseline"),
    };
    let store = open_baselines(&baseline_path, &passphrase, &mut engine);

    if opts.allow_containment {
        tracing::warn!(
            pids = ?opts.policy.allowed_pids,
            cidrs = ?opts.policy.allowed_cidrs,
            interfaces = ?opts.policy.allowed_interfaces,
            "containment is enabled on this daemon"
        );
    } else {
        tracing::info!("containment is advisory: orders will be refused");
    }

    loop {
        let stream = listener
            .accept()
            .await
            .map_err(|e| format!("accept failed: {e}"))?;

        let signer = identity.signer();
        let peer = core_identity.clone();
        let mut session = match heimdall_ipc::session::accept_as_sentinel(
            stream,
            signer,
            peer,
            Suite::ChaCha20Poly1305,
            &mut guard,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                // A rejected handshake is an expected event, not a crash: it is
                // exactly what an unauthorised local process looks like.
                tracing::warn!(error = %e, "rejected an inbound session");
                continue;
            }
        };

        tracing::info!("core connected");
        if let Err(e) = serve(
            &mut session,
            &mut engine,
            &source,
            &mut executor,
            opts.poll,
            store.as_ref(),
        )
        .await
        {
            tracing::warn!(error = %e, "session ended");
        }
        tracing::info!("core disconnected");
    }
}

/// Resolves Core's identity: the configured one, or the one Core published.
///
/// A configured identity is the better posture: the daemon is not trusting
/// whatever a file happens to say at the moment it starts. The published
/// file is the fallback, because on a desk the shell usually runs first.
fn resolve_core_identity(opts: &Options) -> Result<Identity, String> {
    if let Some(hex) = &opts.core_id {
        return Identity::parse_hex(hex.trim())
            .map_err(|e| format!("Core's identity is malformed: {e}"));
    }
    let path = match &opts.core_identity_path {
        Some(path) => path.clone(),
        None => heimdall_crypto::identity::base_dir()
            .map_err(|e| format!("cannot locate the data directory: {e}"))?
            .join("published")
            .join("core.identity"),
    };
    load_core_identity(&path, PEER_WAIT)
}

/// Core's identity, as Core published it.
///
/// Retried for a bounded time rather than read once. On a cold boot Sentinel may
/// well start first, and a daemon that exits because the UI has not launched yet
/// would be useless in exactly the situation it exists for. Bounded, because a
/// peer that never appears is a configuration problem the operator must hear
/// about rather than a reason to wait forever.
fn load_core_identity(
    path: &std::path::Path,
    within: std::time::Duration,
) -> Result<Identity, String> {
    let deadline = std::time::Instant::now() + within;

    loop {
        match std::fs::read_to_string(path) {
            Ok(hex) => {
                let trimmed = hex.trim();
                if !trimmed.is_empty() {
                    return Identity::parse_hex(trimmed).map_err(|e| {
                        format!("Core's identity in {} is malformed: {e}", path.display())
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "Core's identity never appeared at {}. Start the shell once to \
                         publish it; sentinel will not serve a peer it cannot verify.",
                        path.display()
                    ));
                }
                tracing::debug!(path = %path.display(), "waiting for core's identity");
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => {
                return Err(format!("cannot read {}: {e}", path.display()));
            }
        }
    }
}

/// Opens the baseline store and loads what the engine has learned.
///
/// Returns `None` when the store cannot be used at all. A store that exists
/// but whose file does not authenticate is reported loudly and the engine
/// stays cold: a defence that keeps running on a baseline it could not verify
/// is worse than one that relearns and says so.
fn open_baselines(
    path: &std::path::Path,
    passphrase: &Passphrase,
    engine: &mut Engine,
) -> Option<BaselineStore> {
    let store = match BaselineStore::open(path, passphrase) {
        Ok(store) => store,
        Err(e) => {
            // Without a store the daemon still works; it just relearns on
            // every start. That is a degraded mode, not a reason to refuse to
            // defend the host, so it is reported and the daemon continues.
            tracing::error!(error = %e, path = %path.display(), "cannot use the baseline store");
            return None;
        }
    };
    match store.load(engine.anomaly_mut()) {
        Ok(true) => tracing::info!(
            path = %store.path().display(),
            streams = engine.stream_count(),
            "restored the learned baselines"
        ),
        Ok(false) => tracing::info!(path = %store.path().display(), "no baselines yet; learning"),
        Err(e) => {
            // A file that does not authenticate is not used. The engine stays
            // cold and relearns, and the operator is told that the file on
            // disk is not what it claims to be.
            tracing::error!(error = %e, path = %store.path().display(), "the baseline file was refused; learning from cold");
        }
    }
    Some(store)
}

/// One Core session: poll telemetry, report health and alerts, act on
/// directives.
async fn serve(
    session: &mut Session,
    engine: &mut Engine,
    source: &Arc<SharedSource>,
    executor: &mut ContainmentExecutor,
    poll: Duration,
    store: Option<&BaselineStore>,
) -> Result<(), String> {
    // A heartbeat interval independent of the telemetry poll, so a quiet machine
    // still proves the link is alive.
    const HEARTBEAT: Duration = Duration::from_secs(5);

    let mut ticker = tokio::time::interval(poll.max(Duration::from_millis(100)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_heartbeat = std::time::Instant::now().checked_sub(HEARTBEAT).unwrap();
    let mut last_save = std::time::Instant::now();

    loop {
        tokio::select! {
            // Inbound from Core. A failure here is terminal for the session:
            // the channel can no longer be trusted.
            incoming = session.recv() => {
                match incoming {
                    Ok(Some(msg)) => handle_directive(engine, executor, msg, store),
                    Ok(None) => return Ok(()),
                    Err(e) => return Err(e.to_string()),
                }
            }
            _ = ticker.tick() => {
                if source.unhealthy() {
                    // Report the failure rather than reporting nothing. Silence
                    // from a broken sensor reads as a healthy machine.
                    tracing::warn!("telemetry source is unhealthy; alerts are degraded");
                }
                for obs in source.poll_all() {
                    let Some(detection) = ingest(engine, &obs, poll) else {
                        continue;
                    };
                    let severity = detection.alert.severity;
                    let alert_id = detection.alert.alert_id;
                    if let Err(e) = session.send(&Message::ThreatAlert(detection.alert)).await {
                        return Err(e.to_string());
                    }
                    // The recommendation is advice, and it travels separately
                    // from the alert: Core may show it to the operator, and
                    // only an order coming back turns it into an action.
                    if let Some(plan) = detection.containment {
                        let recommendation = ContainmentRecommendation {
                            incident_id: alert_id,
                            scope: plan.scope,
                            severity,
                            reason: plan.summary,
                        };
                        if let Err(e) = session
                            .send(&Message::ContainmentRecommendation(recommendation))
                            .await
                        {
                            return Err(e.to_string());
                        }
                    }
                }
            }
        }

        if last_heartbeat.elapsed() >= HEARTBEAT {
            last_heartbeat = std::time::Instant::now();
            let report = engine.health_report();
            if let Err(e) = session.send(&Message::Health(report)).await {
                return Err(e.to_string());
            }
        }

        // Persist what the engine has learned. Done here rather than on a
        // timer of its own so that it happens on the same clock as everything
        // else, and skipped when nothing has changed.
        if let Some(store) = store
            && last_save.elapsed() >= BASELINE_SAVE_INTERVAL
        {
            last_save = std::time::Instant::now();
            if let Err(e) = store.save(engine.anomaly()) {
                tracing::error!(error = %e, "cannot write the baselines");
            }
        }
    }
}

fn ingest(
    engine: &mut Engine,
    obs: &Observation,
    poll: Duration,
) -> Option<heimdall_sentinel::engine::Detection> {
    engine.advance(poll.as_secs_f64());
    engine.ingest(obs)
}

/// Acts on one directive from Core.
///
/// Returns nothing because there is nothing to fail: every branch either takes
/// effect or is deliberately ignored, and a directive that cannot be carried out is
/// reported in the log rather than as an error the caller could do anything
/// about.
fn handle_directive(
    engine: &mut Engine,
    executor: &mut ContainmentExecutor,
    msg: Message,
    store: Option<&BaselineStore>,
) {
    match msg {
        Message::Command(Command {
            intent, arguments, ..
        }) => {
            tracing::info!(%intent, ?arguments, "directive received");
            match intent.as_str() {
                // Nothing is enforced automatically. A directive that reaches
                // this point has already been decided by Core and by the
                // operator; the engine records it and reports the outcome.
                "reset-baseline" => {
                    let stream = arguments.first().map_or("", String::as_str);
                    if stream.is_empty() {
                        engine.reset_streams();
                        tracing::info!("all baselines reset");
                    } else {
                        engine.reset_stream(stream);
                        tracing::info!(stream, "baseline reset");
                    }
                    // The file has to be rewritten as well: a reset that only
                    // lives in memory would come back with the old baselines
                    // after the next restart.
                    if let Some(store) = store
                        && let Err(e) = store.save(engine.anomaly())
                    {
                        tracing::error!(error = %e, "cannot write the baselines after a reset");
                    }
                }
                "scan" | "status" | "list-alerts" | "explain" => {
                    tracing::debug!(%intent, "acknowledged");
                }
                other => {
                    // An unknown intent is logged, never guessed at.
                    tracing::warn!(intent = other, "unrecognised directive; ignoring");
                }
            }
        }
        Message::ContainmentOrder(order) => {
            let outcome = executor.execute(&order);
            if outcome.performed {
                tracing::warn!(
                    incident = order.incident_id,
                    approved_by = %order.approved_by,
                    detail = %outcome.detail,
                    "containment carried out"
                );
                engine.note_containment_activated();
            } else {
                // A refusal is the common case, and it is reported as loudly as
                // an action: an operator who ordered containment and saw
                // nothing happen must be able to tell that it was refused.
                tracing::warn!(
                    incident = order.incident_id,
                    approved_by = %order.approved_by,
                    detail = %outcome.detail,
                    "containment refused"
                );
            }
        }
        other => {
            tracing::debug!(message = ?other, "ignoring an inbound message from Core");
        }
    }
}

/// Close reason used when the daemon shuts down.
#[allow(dead_code)]
const SHUTDOWN: CloseReason = CloseReason::Shutdown;

/// Streams this daemon reports on, for the self-check path.
#[allow(dead_code)]
const REPORTED: &[&str] = streams::ALL;

/// A policy value, so `Policy` is proven reachable from the binary.
#[allow(dead_code)]
fn default_policy() -> Policy {
    Policy::default()
}

#[cfg(test)]
mod tests {
    use super::Options;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn containment_cannot_be_enabled_without_an_allow_list() {
        // The flag on its own would make the daemon look armed while it could
        // contain nothing, so it is refused outright.
        let error = Options::parse_from(args(&["--allow-containment"])).unwrap_err();
        assert!(
            error.contains("--contain-policy"),
            "the refusal should say what is missing: {error}"
        );
    }

    #[test]
    fn containment_is_advisory_unless_it_is_asked_for() {
        let options = Options::parse_from(args(&[])).unwrap();
        assert!(!options.allow_containment);
        assert!(!options.policy.enabled);
    }

    #[test]
    fn the_baseline_path_can_be_named() {
        let options = Options::parse_from(args(&["--baseline", "/tmp/host.baseline"])).unwrap();
        assert_eq!(
            options.baseline.as_deref(),
            Some(std::path::Path::new("/tmp/host.baseline"))
        );
    }

    #[test]
    fn the_baseline_defaults_to_the_data_directory() {
        let options = Options::parse_from(args(&[])).unwrap();
        assert!(options.baseline.is_none());
    }

    #[test]
    fn an_unknown_argument_is_refused() {
        let error = Options::parse_from(args(&["--wat"])).unwrap_err();
        assert!(error.contains("--wat"), "{error}");
    }

    #[test]
    fn a_configured_core_identity_is_kept() {
        let options = Options::parse_from(args(&["--core-id", "ab12"])).unwrap();
        assert_eq!(options.core_id.as_deref(), Some("ab12"));
    }

    #[test]
    fn the_core_identity_file_can_be_named() {
        let options =
            Options::parse_from(args(&["--core-identity", "/run/core.identity"])).unwrap();
        assert_eq!(
            options.core_identity_path.as_deref(),
            Some(std::path::Path::new("/run/core.identity"))
        );
    }
}
