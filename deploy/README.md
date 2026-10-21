# Deployment

Heimdall has two long-running parts and one operator-facing part:

| Part | What it is | Where it runs |
| --- | --- | --- |
| **Sentinel** | the host and network defence daemon | a service, unattended |
| **Core** | the orchestrator: the self-repair queue, the audit log, the gate | with the operator |
| **Shell** | the operator interface: the panels, the approvals, the voice | on the operator's desk |

This directory holds the service definitions for Sentinel, and the notes on
the isolation posture they take.

## The posture, in one paragraph

Sentinel can read the host and change almost nothing. It runs as its own
account, sees the filesystem read-only apart from its own data directory,
has no network socket of its own, and holds only the capabilities the
containment path needs. Containment is advisory until it is explicitly
enabled, and even then only the targets named in a policy file can be
contained, and only on an order that names the operator who approved it.
The daemon never quarantines the whole host, and it never applies a patch
without a human approval that is bound to the exact bytes of the change.

## The pieces

```
deploy/systemd/heimdall-sentinel.service   the Linux service
deploy/systemd/install.sh                   installs it: account, dirs, credential, unit
deploy/launchd/com.heimdall.sentinel.plist the macOS service
deploy/launchd/install.sh                   installs it
deploy/windows/heimdall-sentinel-task.xml  the Windows scheduled task
deploy/windows/install-task.ps1             installs it
```

## The shared rules

**The passphrase is a credential, not an argument.** The keystore passphrase
is read from `$HEIMDALL_KEYSTORE_PASSPHRASE`, or from a systemd credential
named `passphrase`, or -- if neither is set -- from the development default
`heimdall-development`, which is a keystore anyone can open. A deployment
that leaves it unset is a deployment with no keystore protection, so the
installers ask for it and write it to a file that only root can read.

Changing the passphrase changes the key the keystore and the learned baselines
are sealed with. The old files then refuse to open, which is the correct
outcome but worth knowing before it happens.

**The socket is private by default.** On Linux and macOS the socket is
created `0600` inside a `0700` directory: only the account the daemon runs as
can reach it. A deployment that runs the daemon as a service account and the
operator's tools as another account sets `HEIMDALL_SOCKET_MODE=660` and puts
the two in the same group, and points Core at the socket with
`HEIMDALL_ENDPOINT`. The mode applies to the directory as well as the
socket, because a readable socket inside a directory nobody can traverse is
not reachable anyway.

**The endpoint may be a path.** An endpoint that begins with `/` is a path
rather than a name, which is what lets a service account and an operator
session find the same socket.

**The two sides agree on where the identity is published.** The console
writes its public identity to `$HEIMDALL_PUBLISH_DIR` (by default, under
its own data directory), and the daemon reads it from `--core-identity`.
The daemon also accepts `--core-id`, which pins the console's identity
outright and skips the file -- the better posture, because the daemon is
then not trusting whatever a file happens to say at the moment it starts.
The service definitions use the file, because the console's key is usually
not known before the console has run once.

**Containment is off unless it is asked for.** The service definitions do
not pass `--allow-containment`. A daemon started that way will receive
containment orders, consider them, and refuse them, and the operator sees
the refusal. Turning it on means passing `--allow-containment` and a
`--contain-policy` file that names the processes, addresses and interfaces
that may be contained; the daemon refuses to start with the flag and no
policy, because an empty allow-list would contain nothing while making the
daemon look armed. The unit grants `CAP_KILL` and `CAP_NET_ADMIN` for that
path; if containment stays advisory, drop them from the unit.

**The baselines are sealed, and a file that does not authenticate is not
used.** The learned baselines are written to a file encrypted under a key
derived from the passphrase. On startup the daemon verifies it; if it does
not authenticate, the daemon says so loudly and starts cold rather than
trusting a file it cannot vouch for.

## Linux

```sh
sudo sh deploy/systemd/install.sh
```

The installer creates the `heimdall` account (system account, no shell, not
in `sudo`), the state and runtime directories, the passphrase credential at
`/etc/heimdall/passphrase` (0400, root), and enables the unit. It does not
start it.

The unit takes the posture from systemd itself:

- `User=heimdall`, `NoNewPrivileges=true`
- `ProtectSystem=strict` with `ReadWritePaths=/var/lib/heimdall /run/heimdall`:
  the filesystem is read-only apart from the daemon's own data and its
  runtime directory
- `ProtectHome=true`, `PrivateTmp=true`, `PrivateDevices=true`
- `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`,
  `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`: the kernel is
  not the daemon's to change
- `RestrictNamespaces=true`, `RestrictSUIDSGID=true`,
  `LockPersonality=true`, `MemoryDenyWriteExecute=true`
- `SystemCallFilter=@system-service`: the system calls a service needs, and
  not the ones it does not. The group includes process creation, which the
  containment path needs to run `kill`; a refused call fails the operation
  rather than the daemon
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`: no raw
  sockets, no packet crafting
- `AmbientCapabilities=CAP_KILL CAP_NET_ADMIN`: only for the containment
  path
- `UMask=0077`: nothing it creates is world-readable
- `StateDirectory=heimdall`, `RuntimeDirectory=heimdall`: the directories
  exist before the daemon starts, and the runtime directory is removed when
  it stops, so a stale socket is never left behind
- `RuntimeDirectoryMode=0770`: the operator's group may write the runtime
  directory, which is where the console publishes the identity the daemon
  pins

The operator's side is two environment variables and one group membership:

```sh
export HEIMDALL_ENDPOINT=/run/heimdall/heimdall-sentinel.sock
export HEIMDALL_PUBLISH_DIR=/run/heimdall/published
sudo usermod -aG heimdall "$USER"
```

Log out and back in for the group change to take effect. The console writes
its identity into the publish directory on start; the daemon reads it from
there, waits for it if the daemon started first, and pins it from then on.

To see the result on the machine:

```sh
systemd-analyze security heimdall-sentinel.service
```

## macOS

```sh
sudo sh deploy/launchd/install.sh
```

macOS has no equivalent of the systemd sandbox, so the posture is thinner
and the file says so: the daemon runs as its own account with its own data
directory, launchd keeps it running, and the file limits apply to the
process group rather than to the kernel. A macOS deployment that needs a
stronger boundary should put the daemon in a VM or a container; this
definition is the honest baseline, not a claim of isolation.

## Windows

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\install-task.ps1
```

A scheduled task is not a sandbox. The daemon runs as the account named in
the task, with that account's rights and no more, so the installer insists
on a dedicated local account used for nothing else. The task runs at boot
with `RunLevel=LeastPrivilege`, and the account is granted the "log on as a
batch job" right so the task can run without a stored password and without
anyone being logged on.

The named pipe uses the default Windows security descriptor, which grants
write access to the creator, LocalSystem and the administrators. Core
therefore has to run as the same account as the daemon. Running the daemon
under the operator's own account is the simplest arrangement, and is what
the installer sets up when the account it is given is the operator's.

## Turning containment on

Containment is advisory in the definitions above. To arm it, write the
allow-list and add the two flags to the unit:

```text
# /etc/heimdall/contain.policy
pid 4242
```

```ini
ExecStart=/usr/local/bin/heimdall-sentinel \
    --endpoint /run/heimdall/heimdall-sentinel.sock \
    --baseline /var/lib/heimdall/baselines/host.baseline \
    --core-identity /run/heimdall/published/core.identity \
    --allow-containment \
    --contain-policy /etc/heimdall/contain.policy
```

```sh
sudo systemctl daemon-reload
sudo systemctl restart heimdall-sentinel
```

The daemon refuses to start with `--allow-containment` and no policy file,
so a half-configured unit fails loudly instead of sitting there looking
armed. The format of the policy file, and what each scope does, are in
[`../docs/containment.md`](../docs/containment.md).

## Pinning the console outright

Once the console's identity is known, the daemon can be told it directly
and stop reading the file:

```ini
ExecStart=/usr/local/bin/heimdall-sentinel \
    --endpoint /run/heimdall/heimdall-sentinel.sock \
    --baseline /var/lib/heimdall/baselines/host.baseline \
    --core-id 3f2a...
```

The identity is printed by the console when it starts. This is the better
posture: the daemon holds the daemon's own operator to the key it was
given, and a file that anyone with write access can change no longer
decides who the daemon talks to.

## What the deployment does not do

It does not promise the host is safe. The daemon watches, learns, reports
and, when it is told to, contains. The gate in Core is the part that
decides whether anything is changed, and it will not change anything
without a human who saw the change.
