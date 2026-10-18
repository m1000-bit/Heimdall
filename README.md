# Heimdall

A dual-AI platform: **Heimdall Core** (interface, command, self-repairing code
engine) and **Heimdall Sentinel** (autonomous host and network defense), speaking
over an authenticated, encrypted local channel.

This repository is at **Phase 1**: infrastructure, cryptography, the inter-AI
protocol, the self-repair safety gate, and a native desktop shell.

## Crates

| Crate | Responsibility |
|---|---|
| `heimdall-crypto` | X25519 + Ed25519, AEAD, Argon2id KMS, memory scrubbing |
| `heimdall-ipc` | Framing, typed messages, encrypted ordered session, local transport |
| `heimdall-core` | Orchestrator and the self-repair commit gate |
| `heimdall-sentinel` | Anomaly detection, containment policy |
| `heimdall-shell` | Native GUI (egui/wgpu) with a custom WGSL background |

## Running it

```sh
cargo run --release -p heimdall-shell
```

With no Sentinel present the shell runs in a clearly-labelled demo mode: the
**Simulate traffic** button feeds synthetic observations through the real
detector, and **Submit a proposal** pushes a realistic patch through the real
gate. Both paths are the production code paths, not stubs.

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
- **Sentinel never contains autonomously.** It produces recommendations with a
  rationale; a human decides.
- **Containment authority is bounded**: alerts escalate through a policy table,
  and every recommendation carries `requires_user_confirmation`.

## Known limitations

Stated plainly, because they are the things most likely to be wrong:

1. **Identities are ephemeral.** Both AIs generate a fresh Ed25519 identity at
   startup and exchange it in process. There is no provisioning, pinning to a
   stored identity, or revocation. Two runs cannot authenticate each other.
2. **The transport is not yet wired end to end.** `heimdall-ipc` is complete and
   tested over in-memory pipes, but the shell does not yet spawn a Sentinel
   process and drive a real socket.
3. **No collection sources.** Sentinel detects anomalies in observations handed
   to it; ETW, eBPF and netfeed taps are Phase 2.
4. **Applying a patch does not yet write to disk.** `Gate::consume` produces the
   authorised `Application`; the step that applies the diff to the working tree
   is not implemented, deliberately, until the diff is verified to apply cleanly
   against a clean tree.
5. **The keystore is not persisted.** It is exercised in memory.
6. **No rate limiting or resource caps** on the IPC listener beyond a maximum
   frame size.
7. **The self-repair engine itself is not implemented.** The gate it must pass
   through is.

## Tests

```sh
cargo test --workspace
```

130 tests, all passing, clippy clean. The security-relevant ones are worth knowing about:

- RFC 7748 X25519 and RFC 8439 ChaCha20-Poly1305 known-answer vectors.
- Handshake negative cases: identity mismatch, forged signature, suite
  downgrade, reflection, whole-flight replay, sub-minute replay.
- Injected hostile frames: sequence gap, byte-identical replay, mislabelled
  direction, wrong-key record.
- Exhaustive truncation and single-bit-flip fuzzing of the message decoder.
- A 798-run false-alarm sweep over the anomaly detector across 399 seeds and two
  cold-start window lengths.
- Gate: content mutation after approval, token replay, expiry, traversal,
  cross-gate token smuggling.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) -- component map and data flow
- [`docs/threat-model.md`](docs/threat-model.md) -- what is defended, what is not

## Licence

Apache-2.0.