# Threat model

## What Heimdall defends against

1. **A local attacker who reaches the IPC endpoint.** The socket or pipe is the
   most reachable surface. Anything that can open it is refused unless it can
   produce a valid signature from the pinned long-term identity.
2. **A passive observer of the channel.** All records are AEAD-sealed with
   associated data binding the frame type and sequence number.
3. **A record-level attacker.** Reordering, duplication, deletion, truncation and
   direction confusion are each detected: the sequence number is authenticated,
   enforced strictly, and gaps terminate the session.
4. **Compromise of a long-term identity after the fact.** Every session runs a
   fresh X25519 exchange, so a stolen identity decrypts nothing already
   recorded.
5. **The self-modifying-code failure mode.** This is the one the design document
   singles out, and it is treated as the primary threat rather than a feature.
6. **Detector blind spots.** The anomaly detector is frozen on alert, so a
   sustained attack cannot train the baseline into treating itself as normal.

## What Heimdall does not defend against

Stated explicitly, because a threat model that only lists wins is marketing.

1. **A root-equivalent local attacker.** The keystore is encrypted under a
   passphrase-derived key, but an attacker with root can read process memory,
   ptrace the process, or replace the binary. Memory protection here raises the
   cost of a casual scrape; it does not survive `ptrace`.
2. **Supply-chain compromise of dependencies.** Mitigated by `cargo-deny` and
   audit tooling, not eliminated.
3. **A malicious or confused Heimdall Core.** The gate constrains what Core can
   *do* without approval. It does not constrain what Core can *say*: a
   persuasive but wrong rationale is still persuasive. Reviewing the diff, not
   the explanation, is the user's job. This is the deepest remaining limitation
   in the system and no amount of mechanism removes it.
4. **Traffic analysis.** Record sizes and timing are visible. Contents are not.
5. **Physical access to an unlocked session.** There is no screen lock.
6. **Denial of service against the listener.** No connection rate limiting or
   resource caps beyond the maximum frame size. A local process that can open the
   endpoint can occupy the listener.
7. **Kernel-level compromise.** Out of scope.

## Trust boundaries

| Boundary | Crossing | Control |
|---|---|---|
| Untrusted local process → IPC listener | `heimdall-ipc::transport` | pinned Ed25519 identity; endpoint possession is not trust |
| Wire → `Message` | `heimdall-ipc::message` | AEAD with the header as AAD; strict sequence; bounded decoder |
| AI → source code | `heimdall-core::gate` | digest-bound, single-use, expiring approval token |
| Observation → alert | `heimdall-sentinel::anomaly` | frozen baseline, 5-sigma threshold, explainable alert |
| Alert → containment | `heimdall-sentinel::policy` | advisory only; `requires_user_confirmation` |

## Attack paths considered, and what stops them

**Replay a recorded Sentinel reply at a fresh Core session.**
The reply's transcript hash commits to Core's ephemeral. A new session has a new
ephemeral, so the recomputed hash differs. The flight is rejected before the
signature is even checked.

**Replay a recorded Core hello at a fresh Sentinel.**
Transcript binding alone does not stop this: the flight is internally consistent.
`ReplayGuard` rejects it, provided the guard is long-lived per peer. The guard is
a parameter to `Handshake::finish` rather than internal state precisely so its
lifetime cannot be scoped to a single handshake by accident.

**Apply a benign diff after getting approval for a malicious one.**
The approval token carries a SHA3-256 digest of the path, summary, rationale,
diff, model and timestamp. `consume` recomputes it from the proposal as it now
stands. A single changed byte fails the check and the state stays `Approved`
rather than becoming `Applied`.

**Fabricate an approval token.**
`ApprovalToken`'s fields are private. A caller cannot construct one. A token
minted by a different `Gate` instance is rejected: the nonce is not in this
gate's used set and this gate's state machine never reached `Approved`.

**Reuse an approval.**
The nonce is recorded on consumption and checked before anything else.

**Exploit a sequence gap.**
A gap returns `OutOfOrder` and the session is unusable. There is no resynchronise
path, because a stream that has lost a record cannot be safely rejoined.

**Rewrite a frame's type or sequence number.**
Both are AEAD associated data. Changing either invalidates the tag.

**Feed the decoder a hostile length.**
Validated before allocation, at every layer: frame header, message field
lengths, keystore records. The message decoder is fuzzed by exhaustive truncation
and single-bit flips in the test suite.

**Make the detector learn the attack as normal.**
Anomalous samples do not update the baseline. A sustained attack keeps alerting.

**Make the detector blind with a slow ramp.**
The reference is frozen once the stream settles and never adapts, so a ramp opens
a gap that no amount of adaptation can close.

**Self-modifying code writes itself without approval.**
There is no code path from a proposal to a write that does not pass through
`Gate::consume`, and no way to construct a token outside the gate.

**Self-modifying code writes outside the repository.**
`Gate::check_path` rejects absolute paths and `..` components at submission, and
re-checks that the normalised path is inside the root.

## Accepted risks

| Risk | Rationale |
|---|---|
| Gate identities are ephemeral in Phase 1 | A provisioning story before there is anything worth signing would be harder to change later than to add now. |
| Sentinel containment is not implemented | An untested containment path is worse than no containment path. |
| No kernel isolation for Sentinel | The design calls for it; Phase 2. Without isolation Sentinel runs with the same privileges as Core, which is a known gap. |
| 5-sigma threshold can miss a 4-sigma anomaly | A lower threshold would produce ~1.7 false alerts per hour per stream, and an alert channel nobody reads catches nothing. The drift test covers the slow case. |
| No replay protection at the transport layer | Covered by the session layer; defence in depth at the transport would duplicate the sequence check. |