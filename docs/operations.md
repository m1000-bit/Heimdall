# Operations

How to run Heimdall, what the knobs are, and what to do when something is
not working.

## Running it

Two processes. The shell is Core; Sentinel is the daemon.

```sh
# Terminal 1: the defence daemon. Provisions its identity on first run.
cargo run --release -p heimdall-sentinel

# Terminal 2: the desktop shell.
cargo run --release -p heimdall-shell
```

Both publish their identity before serving and pin what they find, which is
trust on first use. Supplying the expected fingerprint moves the pin to
*verified*, which is what a deployment should do:

```sh
export HEIMDALL_SENTINEL_ID=<sentinel's hex identity>
```

The shell prints its identity on startup and Sentinel prints its own. The
sentinel writes its identity to `published/sentinel.identity` under the
data directory, and `--print-identity` provisions and publishes it without
starting the daemon.

## The environment

| Variable | Meaning |
|---|---|
| `HEIMDALL_KEYSTORE_PASSPHRASE` | Keystore passphrase. Read from the environment, never from `argv`, because on Unix every process can read `argv`. |
| `HEIMDALL_SENTINEL_ID` | Expected Sentinel identity. Supplying it upgrades the pin from TOFU to verified. |
| `HEIMDALL_HOME` | Overrides the data directory (keystore, pins, published identities, baselines). |
| `HEIMDALL_ENDPOINT` | The IPC endpoint. A name, or an absolute path (on Linux and macOS) for a deployment whose socket lives outside the operator's runtime directory. |
| `HEIMDALL_PUBLISH_DIR` | Where the console publishes its own identity for the daemon to pin. Defaults to `published` under the data directory. |
| `HEIMDALL_SOCKET_MODE` | The mode of the Unix socket and the directory around it, in octal. `0600` by default; `0660` when the daemon and the operator's tools run as different accounts in the same group. |
| `CREDENTIALS_DIRECTORY` | Read by the daemons for a credential named `passphrase`, which is how a systemd unit supplies the passphrase without a world-readable environment. |
| `RUST_LOG` | Log filter. `info` by default. |

The passphrase is the same one for the keystore and for the learned
baselines, because both are sealed under a key derived from it. Changing it
makes the old files refuse to open: that is the correct outcome, and it is
worth knowing before it happens rather than after.

## The daemon's flags

| Flag | Meaning |
|---|---|
| `--endpoint <name or path>` | Where to serve. A name resolves to the per-user runtime directory; a path is used as it stands. |
| `--keystore <path>` | Where the keystore lives. |
| `--passphrase <text>` | The keystore passphrase. Prefer the environment or a credential. |
| `--poll-secs <n>` | Telemetry interval. |
| `--allow-containment` | Permit carrying out approved containment orders. Off by default. |
| `--contain-policy <path>` | The allow-list of what may be contained. |
| `--baseline <path>` | Where the learned baselines are kept. Defaults to `baselines/host.baseline` under the data directory. |
| `--core-id <hex>` | Core's identity, when it is known in advance. Pins it outright instead of reading a file. |
| `--core-identity <path>` | Where Core's published identity is read from. Defaults to `published/core.identity` under the data directory. |
| `--print-identity` | Provision and publish the identity, then exit. |

## The learned baselines

Sentinel learns what the host normally looks like -- the per-stream mean and
the spread around it -- and compares what it sees now against that. The
baselines are sealed in a file under a key derived from the passphrase, with
a salt kept in a sidecar file beside it, and they are written every 30
seconds and whenever a baseline is reset.

Three rules govern the file:

1. **A file that does not authenticate is not used.** On startup the daemon
   verifies the file. If it does not open, the daemon says so loudly and
   starts cold rather than trusting a file it cannot vouch for.
2. **A reset rewrites the file.** Resetting a baseline in the shell resets
   the daemon's memory and the file together, so the old baselines do not
   come back on the next restart.
3. **A missing file is not an error.** The daemon learns, writes the file
   and carries on.

To start over deliberately, delete the file and its `.salt` sidecar and
restart the daemon.

## What the daemon costs

The daemon samples the machine every two seconds, decides whether the samples
are unusual, and reports what it found. On a laptop the whole tick takes
about four milliseconds, which is a fifth of a percent of the interval
between two ticks.

Almost all of that is the operating system, not Sentinel. Reading the
counters is cheap: memory in ten microseconds, the CPU in twenty. The
expensive part is re-enumerating the network interfaces, at three and a half
milliseconds, because the source asks the operating system for the list of
interfaces on every poll rather than reading the counters of the ones it
already knows. Enumerating the disks costs a quarter of a millisecond.

The detection itself -- the part this project owns, from a sample to a
decision -- takes about one microsecond per sample, so nine microseconds for
a whole tick of seven samples. It does not grow with the number of samples
ingested: fifty thousand samples cost the same per sample as the first
hundred, because the baselines are a mean and a spread, not a window. It
does not grow with the number of streams either: a tick over thirty-two
streams costs two and a half microseconds.

An alerting sample costs the same as a quiet one, which matters more than it
sounds: an attacker who can make every sample anomalous cannot make the
daemon miss its next tick.

The measurements are in `crates/heimdall-sentinel/src/profile.rs` and run
with the rest of the tests. The one that would need revisiting if the budget
ever shrank is the interface enumeration, and the fix is to keep the list
and refresh the counters, at the price of not noticing a new interface for
as long as the list is kept.

## Deploying

See [`../deploy/README.md`](../deploy/README.md) for the service definitions
and the isolation posture. In short:

```sh
sudo sh deploy/systemd/install.sh     # Linux
sudo sh deploy/launchd/install.sh     # macOS
powershell -ExecutionPolicy Bypass -File deploy\windows\install-task.ps1
```

The installers create the account, the directories, the passphrase credential
and the service definition, and they do not start the daemon. The first run
provisions an identity that Core has to pin, so the order matters: start the
daemon, read its identity, pin it, then start the shell.

## When something is not working

**The shell says it cannot reach Sentinel.** Check that the daemon is
running and that both sides point at the same endpoint. If the daemon runs
as a service account, `HEIMDALL_ENDPOINT` must name the socket it actually
bound, and the operator's account must be in the same group as the socket
when `HEIMDALL_SOCKET_MODE` is not `0600`.

**The shell says the identity does not match.** The pin and the daemon
disagree. Either the daemon's keystore was replaced, or the passphrase
changed, or the pin was taken from a different machine. Read the daemon's
identity from its log and pin that, or delete the pin and accept the new
one deliberately.

**The daemon says the baseline file was refused.** The passphrase changed,
or the file was edited, or it was copied from somewhere else. The daemon
continues and relearns. If that is not what you want, restore the matching
passphrase; if it is, delete the file and its sidecar and let it relearn.

**Sentinel recommends containment and nothing happens.** That is the default
posture working. The daemon refuses orders unless it was started with
`--allow-containment` and a policy file. See
[`containment.md`](containment.md).

**The voice panel says it heard something but shows no transcript.** There
is no acoustic model in this build. The panel reports the speech it
detected and the loudness, and the command has to be typed. See
[`voice.md`](voice.md).

**A repair is proposed and nothing changes.** That is the gate working. The
diff is applied only after an approval, and the approval is bound to the
exact bytes that were reviewed. See the README.

## Logs

The daemons log to stderr through `tracing`, filtered by `RUST_LOG`. The
shell writes its own audit trail -- every transition, including the
refusals -- to a hash-chained, encrypted log under the data directory.

The audit log is the record of what was decided and who decided it. It is
encrypted under a key derived from the passphrase, and it is chained: a
record that has been altered or removed is detected when the chain is
verified.
