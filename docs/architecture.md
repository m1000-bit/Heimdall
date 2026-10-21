# Architecture

## Component map

```
┌──────────────────────────────────────────────────────────────────┐
│  heimdall-shell  (egui / wgpu, native window)                   │
│    ├─ link status          ├─ alert feed    └─ self-repair review│
│    ├─ containment panel    ├─ voice panel   └─ audit trail       │
│    └─ WGSL background via egui_wgpu::CallbackTrait              │
│    link::Link ─ thread ─ socket ─ decoded LinkEvent per frame    │
│    voice::VoicePanel ─ thread ─ microphone ─ VAD ─ grammar       │
└───────────────┬──────────────────────────────┬───────────────────┘
                │                              │
        ┌───────▼────────┐            ┌────────▼─────────┐
        │  heimdall-core │            │ heimdall-sentinel│
        │  Orchestrator  │            │ Engine           │
        │  Gate          │            │ AnomalyEngine    │
        │  Applier       │            │ Correlator       │
        │  PeerPin       │            │ Policy           │
        │  AuditLog      │            │ Containment      │
        └───────┬────────┘            │ BaselineStore    │
                │                     └────────┬─────────┘
                │                     ┌───────▼─────────┐
                │                     │  Source trait   │
                │                     │ System/Replay   │
                │                     └─────────────────┘
                │    encrypted, ordered,        │
                │    authenticated records     │
                └──────────────┬────────────────┘
                               │
                     ┌─────────▼──────────┐
                     │   heimdall-ipc     │
                     │ transport → frame   │
                     │ → session → message │
                     └─────────┬──────────┘
                               │
                     ┌─────────▼──────────┐
                     │  heimdall-crypto   │
                     │ session → kex/kdf  │
                     │ aead → kms → secret│
                     │ identity → keystore│
                     └────────────────────┘
```

## The two processes

Sentinel is a daemon; the shell is Core. Neither is in the other.

```
  shell (Core)                                   sentinel (daemon)
  ───────────                                    ────────────────
  provision keystore ──── published/core.identity ───▶ read at startup
  pin Sentinel     ◀──── published/sentinel.identity ── provision keystore
  connect(endpoint) ──── X25519 + Ed25519 handshake ───▶ accept
  [link thread]      ◀═══════ Health / ThreatAlert ══════ poll + detect
  [link thread]      ◀═══════ ContainmentRecommendation ══ escalate
  [link thread]      ───────▶ ContainmentOrder ─────────── contain
  [link thread]      ───────▶ Command / PatchProposal ───── record, never enforce
```

Both sides publish their identity before serving and pin what they find, which is
trust on first use. Supplying the expected fingerprint moves the pin to
`Configured`, which is a strictly better posture and the one the UI displays.
The two bootstrap each other: each waits for the other's published key rather
than requiring a launch order.

The daemon's side of that pin has two forms. `--core-identity` says where to
read the published key from, and `--core-id` gives the key outright, which
skips the file and is the better posture: the daemon is then not trusting
whatever a file happens to say at the moment it starts. The console publishes
into `HEIMDALL_PUBLISH_DIR`, so a daemon running as a service account and a
console running as the operator can still find the same file.

The UI never touches the socket. `link::Link` owns a thread with its own runtime;
the render thread calls `drain()` once per frame and folds decoded events into
Core with `observe_alert` / `observe_health`. Keys stay on the network thread.

## The channel

Four layers, each with one job.

### transport

A local IPC endpoint: a Unix domain socket on Linux and macOS, a named pipe on
Windows. Neither is confidential, which is why everything above is encrypted.

Access control is the operating system's, not the application's:

- **Unix** — the socket lives in a `0700` directory and the socket itself is
  `0600`. The directory is chosen to avoid a world-writable location, because a
  socket in `/tmp` can be pre-created by another local account.
- **Windows** — the pipe is created with `first_pipe_instance(true)` and two
  instances are held at all times. A named pipe only exists while a handle is
  open, so dropping the listener between connections would let another process
  claim the name and become the peer Core trusts.

**Holding the endpoint confers nothing.** Trust comes from the pinned Ed25519
identity in the handshake. A process that can open the socket still cannot
produce a session.

### frame

```
| magic(4) | version(1) | type(1) | seq(8) | ct_len(4) | ciphertext+tag |
```

The 18-byte header is fed to the AEAD as associated data. Two consequences
matter:

- Frame type and sequence number cannot be rewritten without invalidating the
  tag, so an attacker cannot relabel a payload or inject a `Close` mid-stream.
- Every length is validated before it is used to allocate, so a hostile header
  cannot make the receiver reserve gigabytes.

### session

Directional keys, strict ordering, and replay rejection.

- Each side holds a different key for each direction, so a frame sealed by Core
  can never be opened with the Core-side key.
- Records carry a monotonic sequence number per direction. A gap **terminates**
  the session rather than being skipped: a skipped record is exactly how a
  replay-based desynchronisation proceeds, and there is no safe way to
  resynchronise a stream that has lost a record.
- A `Hello` frame arriving on an established session is a protocol error.

### message

A hand-rolled, length-prefixed, bounded encoding. Not serde-derived: this format
crosses a trust boundary, and a derived format would make a future field
addition a silent protocol change rather than an explicit one.

Every field is capped. `Command` and `PatchProposal` are executed by the peer,
so an unbounded string from a compromised or buggy AI must not be able to
exhaust the receiver's memory. The decoder is bounds-checked at every step; a
truncated or hostile buffer produces a protocol error, never a panic.

## The handshake

```
Core     -> Sentinel : Hello { role=initiator, eph_i, sig_i }
Sentinel -> Core     : Hello { role=responder, eph_r, sig_r }
```

Transcript layout, fixed so both sides compute the same hash without exchanging
it:

```
magic || suite || init_id || resp_id || init-flight(eph_i) || resp-flight(eph_r)
```

Three properties the implementation is built around:

1. **Identity pinning runs before signature verification.** A valid signature
   from an unpinned key proves nothing, and checking it first would turn the
   handshake into a signature oracle for arbitrary keys.

2. **The responder's flight is committed to both ephemerals.** A responder flight
   is otherwise self-authenticating: it verifies on its own, so a recorded reply
   replayed at a fresh Core session would be accepted. Committing to the
   initiator's ephemeral means a replay produces a transcript hash that does not
   match. The responder therefore cannot emit its flight before verifying one.

3. **A whole recorded flight is still a valid flight**, so a fresh Sentinel would
   accept a replayed Core hello and derive keys for a session Core never asked
   for. No attacker gains the traffic keys — Core's ephemeral scalar is secret —
   but the Sentinel would allocate and encrypt toward a peer that does not
   exist. `ReplayGuard` remembers recently accepted transcripts and must be
   **long-lived per peer** for this to hold.

Traffic keys come from HKDF-SHA256 over the X25519 output, salted with the
transcript hash and bound to a direction label by name. Binding the label to the
direction rather than to the tuple position is what stops the two sides deriving
each other's keys.

## The self-repair gate

```
Submitted ──> AwaitingApproval ──approve──> Approved ──consume──> Applied
     │                │                        │                    │
     │                ├──reject──> Rejected   │                    └──> Failed
     │                ├──superseded            └──expired──> Expired
     │                └──superseded──> Superseded
     └──> Superseded (a newer proposal arrived)
```

`consume` is the only path from "the user said yes" to "this may be written".

```rust
let token = gate.approve(id, user)?;        // user decision recorded
let app   = gate.consume(&token)?;          // content re-verified, token burned
// `app` is the authorisation to write `app.diff` to `app.target_path`.
```

There is no `apply` variant that skips the token, and `ApprovalToken` has no
public fields.

### From authorisation to a changed file

`heimdall_core::apply` is the only writer, and it refuses before it writes:

```
Application ─> size cap ─> path confinement ─> git status (clean?)
                                               │
            ┌──────────────────────────────────┘
            ├─ dirty ──> refuse, recorded as Failed
            └─ clean ──> git apply --check ──> git apply ──> git status (changed?)
                                                                        │
                                                       not changed ──> refuse
```

The last check is the one that is easy to skip and expensive to get wrong: git
reporting success is not evidence the file changed, and a repair that did not
happen must never be recorded as one. Nothing is staged or committed. The result
is an unstaged change in the working tree, reviewed and committed by a human.

### The daemon

Sentinel runs as its own process: bind the endpoint, load or create the
keystore, publish the identity, wait for Core's published identity, then accept
one session at a time. Inside a session it polls telemetry on a fixed interval
and sends health on an independent heartbeat, so a quiet machine still proves
the link is alive.

A telemetry source that panics is disabled rather than retried. A panicking poll
would otherwise crash the loop on every iteration, and "no data" reads exactly
like a quiet machine — the failure has to be reported, not absorbed.

## What Sentinel may do

| Signal | Action |
|---|---|
| below the escalation bar | observe |
| above the escalation bar | rate limit + alert |
| far above | alert with a containment recommendation |

Every containment output carries `requires_user_confirmation: true`. An autonomous
defender that can isolate a host the instant a score crosses a threshold is a
denial-of-service engine pointed at your own infrastructure; the blast radius of
a false positive should be "an alert in a log", not "the machine is offline".

## The containment path

Three messages, and the direction of authority runs through them:

```
Sentinel ──ContainmentRecommendation──> Core ──ContainmentOrder──> Sentinel
          what should be contained              who authorised it
```

A recommendation carries the incident, the scope, the severity and one
sentence of reason. It has no authority: it is a proposal that the operator
reads. An order carries the same incident and scope and adds `approved_by`,
which may not be empty. The check that it is not empty lives in
`Orchestrator::containment_order`, in Core, so the shell cannot construct a
well-formed order that Core would refuse.

The executor on the other side applies three limits before it acts: the
daemon must have been started with `--allow-containment`, the order must
name an approver, and the target must be in the operator's allow-list. A
whole-host quarantine is refused unconditionally, and there is no
configuration that changes that. The full description is in
[`containment.md`](containment.md).

## The learned baselines

The detector compares what it sees now against what this host normally looks
like. That "normally" is state, and state that only lives in memory is state
that a daemon forgets every time it restarts -- which means the first
minutes of every boot are spent learning, and are quiet exactly when a
fresh compromise would be hiding in the noise.

`BaselineStore` keeps it in a file: a header, a salt, and the baselines
sealed with ChaCha20-Poly1305 under a key derived from the passphrase with
Argon2id and HKDF. The salt lives in a sidecar file beside it, so the file
can be read without a second secret, and it is the associated data of the
seal, so a swapped salt is a failed seal rather than a wrong key.

The daemon writes the file every thirty seconds, on a baseline reset and at
shutdown. On startup it verifies the file, and a file that does not
authenticate is refused: the daemon says so and starts cold, because a
defence that keeps running on a baseline it could not vouch for is worse
than one that relearns and says so.

## The voice path

```
microphone ──> capture ──> VAD ──> transcript ──> grammar ──> intent ──> panel
```

The acoustic model is the missing piece, and it is a seam rather than a
pretence: `heimdall_voice::Recognizer` has one implementation today, which
replays fixed transcripts, and everything around it is real. The capture is
real, the voice-activity detection is real, the grammar understands English
and Italian, and the panel tells the operator plainly that there is no
transcript because there is no model.

The important property is not the pipeline but the routing. Voice can ask
for a scan or a reset; it cannot approve, reject or contain. Those three
only move the operator's attention to the control that carries the
authority. The reasoning is in [`voice.md`](voice.md).

## The deployment

The daemon runs as a service with a narrow posture: its own account, a
read-only filesystem apart from its own data directory, no network socket of
its own, and only the capabilities the containment path needs. The service
definitions are in [`../deploy`](../deploy), and the isolation posture is
written out in [`../deploy/README.md`](../deploy/README.md).

Two things about the transport matter for a deployment. The endpoint may be
an absolute path, so a service account and an operator's session can be
pointed at the same socket; and the socket's mode is configurable, so the
two can share a group without either running as root.

## The shell

`egui` composites widgets on the CPU and uploads a vertex buffer, which is right
for chrome and wrong for a full-screen animated field. The background is drawn by
a separate wgpu pipeline through `egui_wgpu::CallbackTrait`: one draw call, six
synthesised vertices, no vertex buffer, no texture bindings.

The shader is deliberately cheap — two octaves of value noise, one sweep, one
smoothstep. It runs full-screen every frame for as long as the app is open, on a
machine that is supposed to be watching for other things.

The pipeline is built in the first `prepare` rather than in the constructor,
because `eframe` gives the application a creation context but not the `wgpu::Device`.

### The panels

The shell is the operator's instrument, and it is organised around the
decisions the operator has to make:

- **Link and alerts.** The state of the channel to Sentinel, the health
  reports, and the alerts that have been raised.
- **Self-repair.** A scan of the repository produces findings; a finding can
  be turned into a proposal; the proposal is shown as a diff, next to
  Approve and Reject. The diff and the buttons are the only route to a
  change on disk.
- **Containment.** What Sentinel recommends, with the reason and the
  severity, and an Approve and a Decline next to each. Approving sends an
  order that names the operator; declining sends nothing.
- **Voice.** The microphone, the utterance, and what the grammar understood
  from it. The voice panel is the only place where a spoken word can point
  at a decision, and it never makes one.
- **Audit trail.** The gate's history, newest last, including the
  refusals.

The render thread never blocks. The link and the microphone each have their
own thread, and the frame loop drains what they produced: `link::Link`
decodes a session into `LinkEvent`s, and `voice::VoicePanel` folds a
finished capture into a state. Neither touches the socket or the audio
device from the render thread.

### The audit trail

The gate keeps its history in memory, and the shell attaches a durable log
so that it survives the process. The log is encrypted under a key derived
from the same passphrase as the keystore, and it is hash-chained: each
record commits to the one before it, so a record that has been altered or
removed is detected when the chain is verified. Refusals are recorded as
well as decisions, because a trail that only records what was allowed is a
trail that cannot answer "what tried".