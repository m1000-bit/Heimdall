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
7. **A false containment.** A defence tool that suspends a process or blocks
   an address on a bad reading is a denial-of-service engine pointed at the
   operator's own machine. The containment path is bounded by an
   allow-list, a named approver, and a refusal of whole-host quarantine.
8. **A tampered baseline file.** The learned baselines are sealed under a
   passphrase-derived key. A file that does not authenticate is refused and
   the daemon starts cold, so a rewritten baseline buys an attacker a
   window of silence rather than a permanent one.
9. **A spoken word.** A microphone hears the room. Voice can ask for things
   and cannot approve, reject or contain: the spoken request only moves the
   operator's attention to the control that carries the authority.

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
8. **A recording of the operator's voice.** There is no speaker verification.
   The voice path cannot approve or contain anything, so a recording buys the
   attacker the attention of the operator rather than an action. It is still
   an annoyance, and a good reason to keep the microphone closed by default.
9. **A tampered or replayed audio stream.** The pipeline has no
   anti-spoofing and no replay detection at the audio layer. The
   consequence is bounded by the same rule as the rest of the voice path:
   the worst a hostile recording can do is ask for a scan.

## Trust boundaries

| Boundary | Crossing | Control |
|---|---|---|
| Untrusted local process → IPC listener | `heimdall-ipc::transport` | pinned Ed25519 identity; endpoint possession is not trust |
| Wire → `Message` | `heimdall-ipc::message` | AEAD with the header as AAD; strict sequence; bounded decoder |
| AI → source code | `heimdall-core::gate` | digest-bound, single-use, expiring approval token |
| Approved diff → working tree | `heimdall-core::apply` | clean-tree check, `git apply --check`, path confinement, no commit |
| Observation → alert | `heimdall-sentinel::anomaly` | frozen baseline, 5-sigma threshold, explainable alert |
| Alert → correlated risk | `heimdall-sentinel::correlate` | inter-arrival rate detection across independent streams |
| Alert → containment | `heimdall-sentinel::policy` | advisory unless `--allow-containment`; `requires_user_confirmation` |
| Recommendation → order | `heimdall-core::orchestrator` | an order must name the operator who approved it; an empty approver is refused |
| Order → action on the host | `heimdall-sentinel::containment` | allow-list of pids, ranges and interfaces; whole-host quarantine always refused |
| Learned baseline → disk | `heimdall-sentinel::baseline_store` | sealed under a passphrase-derived key; an unauthenticating file is refused |
| Microphone → intent | `heimdall-shell::voice` | voice may request; approval, rejection and containment need the operator's own click |
| Host counters → `Observation` | `heimdall-sentinel::source` | typed streams; a failing source is disabled and reported, never zero-filled |
| UI thread → network | `heimdall-shell::link` | the socket and its keys stay off the render path; the UI only sees decoded events |

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
re-checks that the normalised path is inside the root. `heimdall_core::apply`
repeats the check at write time, on the canonicalised parent, because a gate that
only checked at submission has not seen the file system since.

**Get an approval, then change the file underneath the patch.**
`git apply --check` runs against the tree as it is at apply time. A file with
uncommitted changes is refused outright, and a diff whose context no longer
matches fails the check. Neither path writes anything, so the worst case is a
refusal in the audit log rather than a file nobody reviewed.

**Patch something other than what was approved.**
The digest binds the path, not just the diff. A proposal approved for
`a.txt` cannot be redirected to `b.txt` by editing the record, because the path
is inside the digest. The applier resolves the path from the authorised
`Application`, never from the diff's own headers.

**Lose the trust-on-first-use window.**
Both daemons publish their identity to a file under the state directory. An
attacker who writes that file *before* first run chooses the key Core will trust.
This is why `HEIMDALL_SENTINEL_ID` exists, why the UI shows which basis a pin
has, and why a mismatch after the pin exists is fatal rather than a re-pin.

**Make the daemon report silence as health.**
A telemetry source that panics is disabled, not retried forever, and the link
panel shows that no report is arriving. A live connection with no data is drawn
as half-healthy rather than healthy, because "up but mute" and "working" are not
the same claim.

**Talk the daemon into containing something.**
Three checks stand in the way, in order: the daemon refuses to act at all
unless it was started with `--allow-containment`; an order that names no
approver is refused by Core before it is sent and by the executor when it
arrives; and the target has to be in an allow-list the operator wrote by
hand. A whole-host quarantine is refused unconditionally, and no
configuration makes it happen.

**Rewrite the learned baselines to hide a compromise.**
The file is sealed with ChaCha20-Poly1305 under a key derived from the
passphrase, with the salt as associated data, so an edited baseline file
does not open. The daemon reports the refusal and starts cold, which costs
the attacker the window it was trying to buy and costs the operator a few
minutes of relearning.

**Use the microphone to authorise a change.**
A spoken "approve" does not approve. The intent reaches the shell, and the
shell moves the operator's attention to the button and says that voice
cannot approve. The same is true of rejection and containment. The only
voice commands that act are the ones that read or that ask the daemon to
forget what it learned.

**Use a replayed recording to get a decision made.**
There is no anti-spoofing at the audio layer, so a recording can be
transcribed. What it cannot do is decide anything: the authority for
approval and containment is a click on a control that shows what is being
approved, and no audio can produce that click.

## Accepted risks

| Risk | Rationale |
|---|---|
| Trust on first use on first run | An attacker who can write the state directory before either daemon starts chooses the key. Configured pinning removes it; the residual window is small but real, and the UI reports which basis is in use. |
| The keystore passphrase comes from the environment | `argv` is world-readable on Unix, which is worse. A systemd credential is supported and is the better answer for unattended operation; there is still no OS keychain integration. |
| Containment is advisory unless it is explicitly enabled | The default is that Sentinel recommends and refuses. The allow-list, the named approver and the refusal of whole-host quarantine are the limits that make enabling it survivable. |
| The isolation posture differs per platform | Linux gets a real sandbox from systemd. macOS gets an account and a plist, and Windows gets a scheduled task, which is not a sandbox. The definitions say so rather than implying parity. |
| No acoustic model in the voice pipeline | The microphone, the detector and the grammar are real; the recognition step is a documented seam. The consequence is that the voice path is not yet usable for free-form speech. |
| The applier depends on `git` being installed | `git apply` is the reference implementation of "does this patch apply cleanly here, now". Reimplementing it would put the risk in the one component that writes source code, so a missing `git` means refusing to patch. |
| Host-level telemetry only | No ETW, eBPF or syscall visibility. An attack that changes nothing observable at that layer is invisible to it, by construction. |
| 5-sigma threshold can miss a 4-sigma anomaly | A lower threshold would produce ~1.7 false alerts per hour per stream, and an alert channel nobody reads catches nothing. The drift test covers the slow case. |
| No replay protection at the transport layer | Covered by the session layer; defence in depth at the transport would duplicate the sequence check. |
| One Core connection at a time | A second concurrent connection is not served rather than refused politely. Fine for a two-process design; it is not a multi-tenant listener. |