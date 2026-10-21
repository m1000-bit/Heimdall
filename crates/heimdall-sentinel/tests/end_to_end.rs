//! End-to-end: the real `heimdall-sentinel` process, over a real OS endpoint.
//!
//! Every other test in this workspace exercises one process talking to itself
//! over an in-memory pipe. That is the right way to test the protocol, and the
//! wrong way to find out whether the daemon starts, binds a socket, keeps its
//! identity across restarts, or is willing to answer a pinned peer. This test
//! spawns the actual binary and speaks to it as Core.
//!
//! What it deliberately does *not* do is invent a trust relationship. Sentinel's
//! identity is read from the keystore it creates, and Core pins exactly that
//! value; there is no way to get past the handshake here without the real keys.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use heimdall_core::Orchestrator;
use heimdall_crypto::Passphrase;
use heimdall_crypto::identity::KeystoreLocation;
use heimdall_ipc::Message;
use heimdall_ipc::message::Command as Directive;

/// The binary under test, built by cargo for this test run.
const SENTINEL: &str = env!("CARGO_BIN_EXE_heimdall-sentinel");

const PASSPHRASE: &str = "end-to-end-test-passphrase";

/// How long to wait for the daemon to bind before calling the test a failure.
/// Generous, because a cold debug build on a loaded machine is slow; not
/// unbounded, because a daemon that never binds should not hang a CI job.
const STARTUP: Duration = Duration::from_secs(30);

/// A temporary directory that removes itself.
///
/// Written out rather than pulled from a crate: the test needs exactly one
/// thing from a temp-dir library, and a dependency that exists for a test's
/// benefit is a dependency the project then has to keep supporting.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        // The process id keeps concurrent test binaries from colliding, and the
        // tag keeps two scratch dirs in the same run apart.
        let path = std::env::temp_dir().join(format!("heimdall-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("cannot create the scratch directory");
        Self(path)
    }

    fn join(&self, tail: &str) -> PathBuf {
        self.0.join(tail)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The daemon, killed when this goes out of scope.
///
/// A leaked Sentinel would outlive the test and hold an endpoint name that the
/// next run then fails to bind, turning one flake into a cascade.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs the binary. Panics with the output, because a silent failure here is
/// indistinguishable from a broken build.
fn run(args: &[&str], home: &Path) -> String {
    let out = Command::new(SENTINEL)
        .args(args)
        // The daemon reads its state directory from this; isolating it keeps the
        // test off the developer's real keystore and pins.
        .env("HEIMDALL_HOME", home)
        .env("HEIMDALL_KEYSTORE_PASSPHRASE", PASSPHRASE)
        .env("RUST_LOG", "warn")
        .output()
        .expect("cannot run the sentinel binary");
    assert!(
        out.status.success(),
        "sentinel {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The hex identity the daemon printed on stdout.
fn identity_from(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("sentinel identity: "))
        .unwrap_or_else(|| panic!("no identity in the daemon output:\n{stdout}"))
        .trim()
        .to_string()
}

#[test]
fn the_daemon_keeps_one_identity_across_restarts() {
    let scratch = Scratch::new("identity");
    let keystore = scratch.join("sentinel.key");

    let first = run(
        &["--print-identity", "--keystore", keystore.to_str().unwrap()],
        &scratch.0,
    );
    let identity = identity_from(&first);
    assert_eq!(identity.len(), 64, "an Ed25519 key is 32 bytes of hex");
    assert!(
        first.contains("newly created"),
        "the first run must say the identity is new, so a later silent rotation is visible:\n{first}"
    );

    // A second process, same keystore, same passphrase. If this produced a
    // different key the whole pinning scheme would be theatre.
    let second = run(
        &["--print-identity", "--keystore", keystore.to_str().unwrap()],
        &scratch.0,
    );
    assert_eq!(
        identity_from(&second),
        identity,
        "the identity must survive a restart"
    );
    assert!(
        !second.contains("newly created"),
        "a restart must not claim to have created an identity it already had"
    );

    // And it published the same value Core pins from.
    let published = std::fs::read_to_string(scratch.join("published").join("sentinel.identity"))
        .expect("the daemon must publish its identity for Core to pin");
    assert_eq!(published.trim(), identity);
}

#[test]
fn the_daemon_refuses_to_start_on_the_wrong_passphrase() {
    let scratch = Scratch::new("passphrase");
    let keystore = scratch.join("sentinel.key");
    run(
        &["--print-identity", "--keystore", keystore.to_str().unwrap()],
        &scratch.0,
    );

    // A wrong passphrase must fail loudly. Silently minting a new identity here
    // would let anyone with write access to the keystore path replace Sentinel's
    // key and have Core pin the replacement.
    let out = Command::new(SENTINEL)
        .args(["--print-identity", "--keystore", keystore.to_str().unwrap()])
        .env("HEIMDALL_HOME", &scratch.0)
        .env("HEIMDALL_KEYSTORE_PASSPHRASE", "not the passphrase")
        .output()
        .expect("cannot run the sentinel binary");
    assert!(
        !out.status.success(),
        "a keystore that will not decrypt must not be replaced"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("identity"),
        "the failure must explain itself: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pinned_core_receives_health_from_the_real_daemon() {
    let scratch = Scratch::new("session");
    let keystore = scratch.join("sentinel.key");
    // Unique per run: the endpoint name is a global resource on both Unix sockets
    // and Windows named pipes, and a stale one from a crashed run would still be
    // held.
    let endpoint = format!(
        "e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos())
    );

    // Provision Sentinel first, so Core pins the real key rather than whatever
    // the daemon happens to mint later.
    let identity = identity_from(&run(
        &["--print-identity", "--keystore", keystore.to_str().unwrap()],
        &scratch.0,
    ));

    let mut daemon = Daemon(
        Command::new(SENTINEL)
            .args([
                "--keystore",
                keystore.to_str().unwrap(),
                "--endpoint",
                &endpoint,
                // Fast, so the health heartbeat lands inside the test timeout.
                "--poll-secs",
                "1",
            ])
            .env("HEIMDALL_HOME", &scratch.0)
            .env("HEIMDALL_KEYSTORE_PASSPHRASE", PASSPHRASE)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("cannot spawn the sentinel daemon"),
    );

    // Core: its own keystore, with the pin written into the scratch directory
    // rather than the shared default. An explicit location rather than an
    // environment variable, because a pin is a trust decision about one peer and two
    // instances sharing one pin file cannot both be right.
    let core_keystore = KeystoreLocation::at(scratch.join("core.key"));
    let passphrase = Passphrase::from_utf8(PASSPHRASE.as_bytes());
    let pin = heimdall_core::link::PinLocation::at(scratch.join("peers").join("sentinel.pin"));
    let mut orchestrator = Orchestrator::provision_in(
        &scratch.0,
        &core_keystore,
        &passphrase,
        &pin,
        Some(&identity),
    )
    .expect("core must provision and pin the daemon's identity");

    // Sentinel verifies Core the same way, from what Core publishes.
    std::fs::write(
        scratch.join("published").join("core.identity"),
        orchestrator.identity().hex(),
    )
    .expect("core must publish its own identity");

    let mut session =
        connect_with_retry(&endpoint, &mut orchestrator, STARTUP, &mut daemon.0).await;
    assert!(orchestrator.link_status().connected);

    // Sentinel sends health on its own schedule. Waiting for a real report is
    // the point: it proves the daemon is polling, not just holding a socket
    // open.
    let health = await_health(&mut orchestrator, &mut session, Duration::from_secs(20))
        .await
        .expect("the daemon never reported its health");

    assert_eq!(
        health.sentinel_id,
        heimdall_sentinel::DEFAULT_SENTINEL_ID,
        "the report must come from the daemon, labelled as itself"
    );
    assert!(
        health.uptime_secs < 60 * 60,
        "a daemon running for hours must not answer as if freshly started"
    );

    // A directive must be accepted by the daemon without dropping the session.
    session
        .send(&Message::Command(Directive {
            command_id: 7,
            intent: "reset-baseline".into(),
            arguments: Vec::new(),
        }))
        .await
        .expect("a reset directive must be accepted");

    // And the session must still be usable afterwards.
    let live = tokio::time::timeout(Duration::from_secs(10), session.recv())
        .await
        .expect("the session must survive a directive")
        .expect("the session must survive a directive");
    assert!(
        live.is_some(),
        "sentinel must keep reporting after a directive, not go quiet"
    );

    let _ = daemon.0.kill();
}

/// Connects, retrying while the daemon is still binding.
///
/// The socket is not there the instant the process starts, and the window is not
/// fixed, so this polls. Every failure is a *connect* failure: a handshake
/// failure would mean the keys do not match, and retrying that would only hide
/// the real fault. A daemon that has exited stops the retries, because retrying
/// a dead process just delays the failure by `within`.
async fn connect_with_retry(
    endpoint: &str,
    orchestrator: &mut Orchestrator,
    within: Duration,
    daemon: &mut Child,
) -> heimdall_ipc::Session {
    let deadline = Instant::now() + within;
    let mut attempt = 0u32;
    loop {
        match orchestrator.connect(endpoint).await {
            Ok(session) => return session,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "could not reach the daemon at {endpoint} after {attempt} attempts: {e}"
                );
                if let Some(status) = daemon.try_wait().expect("cannot poll the daemon") {
                    // A daemon that exited will never bind. Its own output is the
                    // explanation, and it is almost always the answer.
                    panic!(
                        "the daemon exited early with {status}:\n{}",
                        drain_output(daemon)
                    );
                }
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Whatever the daemon wrote before it died.
///
/// Read only on the failure path: the pipe buffer is small, and a daemon left
/// running for the whole test could block on a full stdout instead of serving.
fn drain_output(daemon: &mut Child) -> String {
    use std::io::Read as _;
    let mut out = String::new();
    if let Some(mut pipe) = daemon.stdout.take() {
        let _ = pipe.read_to_string(&mut out);
    }
    if let Some(mut pipe) = daemon.stderr.take() {
        let _ = pipe.read_to_string(&mut out);
    }
    out
}

/// Reads until a health report arrives, folding everything else into Core.
async fn await_health(
    orchestrator: &mut Orchestrator,
    session: &mut heimdall_ipc::Session,
    within: Duration,
) -> Option<heimdall_ipc::message::HealthReport> {
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        // A clean close, a timeout, or a broken channel all mean "nothing more is
        // coming"; the caller reports the deadline, not this detail.
        let Ok(Ok(Some(msg))) = tokio::time::timeout(left, session.recv()).await else {
            return None;
        };
        match msg {
            Message::Health(h) => {
                orchestrator.observe_health(h.clone());
                return Some(h);
            }
            other => tracing::debug!(message = ?other, "other inbound message"),
        }
    }
}
