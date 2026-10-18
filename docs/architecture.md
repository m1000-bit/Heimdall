# Architecture

## Component map

```
┌──────────────────────────────────────────────────────────────────┐
│  heimdall-shell  (egui / wgpu, native window)                   │
│    ├─ link status          ├─ alert feed    └─ self-repair review│
│    └─ WGSL background via egui_wgpu::CallbackTrait              │
└───────────────┬──────────────────────────────┬───────────────────┘
                │                              │
        ┌───────▼────────┐            ┌────────▼─────────┐
        │  heimdall-core │            │ heimdall-sentinel│
        │  Orchestrator  │            │ Engine           │
        │  Gate          │            │ AnomalyEngine    │
        └───────┬────────┘            │ Policy           │
                │                     └────────┬─────────┘
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
                     └────────────────────┘
```

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