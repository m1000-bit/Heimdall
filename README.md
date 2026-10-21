# Heimdall

A dual-AI platform: **Heimdall Core** (interface, command, self-repairing code
engine) and **Heimdall Sentinel** (host and network defence), speaking over an
authenticated, encrypted local channel, with a native operator's console on
top.

This repository is at **Phase 3**: the daemon, its transport, persistent
identities, live telemetry, the self-repair path from an approved patch to a
change on disk, the containment path, the voice pipeline and the operator
console are all wired end to end. The deployment definitions for Sentinel
are in [`deploy/`](deploy/).

## Crates

| Crate | Responsibility |
|---|---|
| `heimdall-crypto` | X25519 + Ed25519, AEAD, Argon2id KMS, persistent identities |
| `heimdall-ipc` | Framing, typed messages, encrypted ordered session, local transport |
| `heimdall-core` | Orchestrator, peer pinning, self-repair gate, patch applier, audit log |
| `heimdall-sentinel` | Telemetry sources, anomaly and correlation detection, containment, learned baselines |
| `heimdall-shell` | Native console (egui/wgpu) with a custom WGSL background |
| `heimdall-voice` | Microphone capture, voice-activity detection, recognition seam, local speech |

## Running it

Two processes. The shell is Core; Sentinel is the daemon.

```sh
# Terminal 1: the defence daemon. Provisions its identity on first run.
cargo run --release -p heimdall-sentinel

# Terminal 2: the desktop console.
cargo run --release -p heimdall-shell
```

The shell prints its identity and Sentinel prints its own on startup. The first
run pins whatever it finds on disk (**trust on first use**); after that, a
different key is a hard failure. To skip TOFU, supply the expected fingerprint:

```sh
export HEIMDALL_SENTINEL_ID=<sentinel's hex identity>
```

| Variable | Meaning |
|---|---|
| `HEIMDALL_KEYSTORE_PASSPHRASE` | Keystore passphrase. Read from the environment, not `argv`, because on Unix every process can read `argv`. A systemd credential named `passphrase` is also read. |
| `HEIMDALL_SENTINEL_ID` | Expected Sentinel identity. Supplying it upgrades the pin from TOFU to verified. |
| `HEIMDALL_HOME` | Overrides the state directory (keystore, pins, published identities, baselines). |
| `HEIMDALL_ENDPOINT` | The IPC endpoint. A name, or an absolute path for a deployment whose socket lives outside the operator's runtime directory. |
| `HEIMDALL_SOCKET_MODE` | The mode of the Unix socket and its directory, in octal. `0600` by default. |

`heimdall-sentinel --help` lists its flags; `--print-identity` provisions and
publishes the identity, then exits.

With no Sentinel present the shell still runs, and says so: the **Simulate
traffic** button feeds synthetic observations through the real detector. That is
the production code path with a synthetic source, not a stub, and the panel
labels the figures as local.

## The operator's console

Five panels, arranged around the decisions the operator has to make:

- **Link and alerts** -- the state of the channel to Sentinel, the health
  reports, and the alerts that have been raised.
- **Self-repair** -- a scan of the repository produces findings, a finding
  becomes a proposal, and the proposal is shown as a diff next to Approve and
  Reject. The diff and the buttons are the only route to a change on disk.
- **Containment** -- what Sentinel recommends, with its reason and severity,
  and an Approve and a Decline beside each.
- **Voice** -- the microphone, the utterance, and what the grammar understood
  from it.
- **Audit trail** -- every gate transition, including the refusals.

## The security invariant

Heimdall Core may analyse, repair and propose changes to its own source code. It
may **not** apply one without explicit user authorisation.

That rule is enforced structurally in `heimdall_core::gate`, not by convention:

- An approval is bound to a SHA3-256 digest of the exact path, summary,
  rationale, diff, model and timestamp the user reviewed. Editing any of them
  after approval invalidates the token.
- `Gate::consume` is the only function that yields an `Application`, and it
  requires a token the gate itself minted. `ApprovalToken`'s fields are private,
  so a token cannot be fabricated even from inside the crate.
- Tokens are single-use and expire (5 minutes by default).
- Target paths are confined to the repository; absolute paths and `..` are
  refused at submission.
- A proposal without a summary or rationale is refused at submission, so the UI
  can never be unable to explain itself.
- Submitting a new proposal supersedes any earlier one still awaiting a decision.
- Every transition lands in an append-only audit log, **including refusals**.

And `heimdall_core::apply` is what turns an authorised proposal into a change:

- The diff is verified with `git apply --check` before a single byte is written,
  and the write is confirmed afterwards -- a repair is never reported as having
  happened without the file having changed.
- A target with uncommitted changes is refused. A patch describes the code as it
  was read; applying it to a file that has moved since is how unreviewed code
  reaches a repository.
- Paths are confined to the repository, re-checked at apply time and after path
  normalisation, so `../../.ssh/authorized_keys` fails before git is involved.
- Nothing is staged or committed. The result is an ordinary unstaged change for a
  human to review, which is the entire point of the gate.

## The other invariants

**Sentinel never contains on its own.** It produces a recommendation with a
rationale; a human decides. Containment is advisory unless the daemon was
started with `--allow-containment`, and even then only the processes, address
ranges and interfaces named in the operator's allow-list can be contained, only
on an order that names the operator who approved it, and a whole-host
quarantine is never carried out. See [`docs/containment.md`](docs/containment.md).

**Voice never decides.** A spoken command can ask for a scan, list the
alerts, explain a finding, or ask the daemon to forget its baselines. A spoken
"approve", "reject" or "contain" moves the operator's attention to the control
that carries the authority and does nothing else. A microphone hears the room;
ambient speech is not consent. See [`docs/voice.md`](docs/voice.md).

**A baseline that does not authenticate is not used.** The learned baselines
are sealed under a passphrase-derived key. A tampered file is reported loudly
and the daemon starts cold, rather than a defence continuing on a baseline it
could not vouch for.

## Security posture of the rest

- **Peer trust is cryptographic, never positional.** Holding the IPC endpoint
  confers nothing. A peer is authenticated by a pinned Ed25519 identity.
- **Identity pinning happens before signature verification**, so no unpinned key
  is ever an oracle.
- **Perfect forward secrecy.** A fresh X25519 keypair per session.
- **No key material in logs.** `Secret<N>` scrubs on drop through volatile
  writes and redacts in `Debug`.
- **Every length is checked before it allocates.** On the IPC path, on the
  message decoder, and on the keystore.
- **Frame type and sequence are authenticated data**, so they cannot be rewritten
  without invalidating the AEAD tag.
- **The daemon runs in a narrow sandbox.** Its own account, a read-only
  filesystem apart from its own data directory, no network socket of its own, and
  only the capabilities the containment path needs. See
  [`deploy/README.md`](deploy/README.md).
- **The audit log is encrypted and hash-chained**, so a record that was altered
  or removed is detected when the chain is verified.

## Known limitations

Stated plainly, because they are the things most likely to be wrong:

1. **There is no acoustic model.** The microphone, the voice-activity
   detection and the English/Italian grammar are real; the recognition step is a
   documented seam with a scripted stand-in, so the voice path does not yet
   understand free-form speech.
2. **The reasoning backend is deterministic, not a model.**
   `DeterministicBackend` classifies operator input into directives and
   explanations. The `ReasoningBackend` trait is the seam where a model-backed
   implementation goes; nothing in the transport or gate assumes the current one.
3. **First contact is TOFU unless configured.** Both daemons publish their
   identity to a plain file and pin whatever they find. Anyone who can write that
   file before first run owns the link. `HEIMDALL_SENTINEL_ID` removes this, and
   the UI shows which basis a pin has.
4. **The isolation posture is not the same on every platform.** Linux gets a real
   sandbox from systemd; macOS gets an account and a plist; Windows gets a
   scheduled task, which is not a sandbox.
5. **Telemetry is host-level.** CPU, memory, processes, threads, network and disk
   counters. No ETW, eBPF, or syscall-level collection.
6. **The applier shells out to `git`.** Deliberate -- `git apply` is the
   reference implementation of "does this patch apply cleanly" -- but it means git
   must be installed and on `PATH`, and a Heimdall that cannot find it refuses to
   patch rather than guessing.
7. **The keystore passphrase has no OS keychain integration.** The environment
   and a systemd credential are both supported; a desktop keychain is not.
8. **No rate limiting or resource caps** on the IPC listener beyond a maximum
   frame size.
9. **One endpoint, one session.** The listener accepts one Core connection at a
   time; a second concurrent Core is not supported or rejected gracefully.

## Tests

```sh
cargo test --workspace
```

344 tests, all passing, clippy clean. The security-relevant ones are worth knowing about:

- RFC 7748 X25519 and RFC 8439 ChaCha20-Poly1305 known-answer vectors.
- Handshake negative cases: identity mismatch, forged signature, suite
  downgrade, reflection, whole-flight replay, sub-minute replay.
- Injected hostile frames: sequence gap, byte-identical replay, mislabelled
  direction, wrong-key record.
- A channel under load: a burst of five thousand messages arrives whole and in
  order, and a frame whose ciphertext was altered, whose header claims a
  gigabyte, or that stops halfway is refused instead of trusted.
- Exhaustive truncation and single-bit-flip fuzzing of the message decoder.
- A 798-run false-alarm sweep over the anomaly detector across 399 seeds and two
  cold-start window lengths.
- Gate: content mutation after approval, token replay, expiry, traversal,
  cross-gate token smuggling.
- Applier: dirty target, stale diff, path escape, oversized diff, a failed write
  recorded in the audit trail, and a token that cannot authorise twice.
- Containment: an order without an approver is refused, a target outside the
  allow-list is refused, a whole-host quarantine is refused, and containment
  stays advisory unless it was enabled.
- The daemon's own rules: containment cannot be enabled without an
  allow-list, the baseline path can be named or defaulted, and Core's
  identity can be configured or read from where it was published.
- Voice: a spoken approval approves nothing, a spoken containment orders
  nothing, and the grammar understands both languages it claims to.
- Baselines: a round trip, a missing file, a tampered file refused, and the
  wrong passphrase refused.
- End-to-end: the real `heimdall-sentinel` **process**, over a real socket,
  authenticated with keys from a real keystore -- including that its identity
  survives a restart and that a wrong passphrase fails instead of minting a
  replacement key.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) -- component map and data flow
- [`docs/threat-model.md`](docs/threat-model.md) -- what is defended, what is not
- [`docs/operations.md`](docs/operations.md) -- running, deploying, and what to do when it breaks
- [`docs/containment.md`](docs/containment.md) -- the containment path and its limits
- [`docs/voice.md`](docs/voice.md) -- the voice pipeline and what it may not do
- [`deploy/README.md`](deploy/README.md) -- the service definitions and the isolation posture

## Licence

Apache-2.0.
