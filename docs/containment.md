# Containment

Containment is the part of Heimdall that acts on the host. It is therefore
the part with the most ways to be wrong, and it is deliberately the
narrowest thing in the project.

## The path

```
  anomaly     ──> recommendation ──> operator ──> order ──> executor
  (daemon)         (Sentinel → Core)     (a human)   (Core → Sentinel)
```

1. The detector finds something and the policy table says it is serious
   enough to escalate.
2. Sentinel sends a **recommendation** to Core: what to contain, how
   urgent, and one sentence of reason. A recommendation is a proposal; it
   carries no authority.
3. The operator sees it in the containment panel and decides. Approving
   produces an **order** that names the person who approved it.
4. The daemon carries out the order, or explains why it did not. Every
   outcome, performed or refused, is recorded.

Nothing in that path is automatic. The daemon does not escalate its own
recommendation into an order, and the shell does not send an order that
was not approved by a human who could see what they were approving.

## The three limits

**A named allow-list.** Only the processes, addresses and interfaces the
operator wrote down in the policy file can be contained. Anything else is
refused, however urgent the recommendation was. An allow-list a
recommendation could widen would not be an allow-list.

**A named approver.** An order whose `approved_by` is empty is refused by
the peer that receives it, and refused again by the executor. The name is
what the log records, and a log that cannot say who acted cannot answer
the question an incident review asks first.

**No whole-host quarantine.** `ContainmentScope::HostQuarantine` exists in
the protocol so that the refusal can be explicit, and there is no
configuration that makes the executor carry it out. A defence tool that can
take the whole machine down is a different kind of tool.

## The policy file

```text
# comments and blank lines are ignored
pid 4242
cidr 203.0.113.7/32
interface eth0
hook /usr/local/sbin/heimdall-contain-block
```

One rule per line, so the file can be read, diffed and reviewed by a
person. `pid` names a process that may be suspended, `cidr` an address
range that may be blocked, `interface` a network interface that may be
disabled, and `hook` the command that carries out an address or interface
containment. It is called as:

```
<hook> <kind> <target>
```

for example `heimdall-contain-block address 203.0.113.7/32`. The daemon
does not manipulate the firewall itself: how a host is contained is the
operator's decision, and without a hook those scopes are refused rather
than approximated.

The file is passed with `--contain-policy`, and it is only consulted when
the daemon was also started with `--allow-containment`. Containment is
advisory by default, and the refusal says so, so the log shows the
daemon's posture rather than leaving the operator to guess.

## What the executor does

| Scope | What happens |
|---|---|
| `Process { pid }` | `kill -STOP <pid>`, if the pid is in the allow-list |
| `Address { cidr }` | the hook is run, if the range is in the allow-list and a hook is configured |
| `Interface { name }` | the hook is run, if the interface is in the allow-list and a hook is configured |
| `HostQuarantine` | always refused |

The checks are in the order of the rules: posture first, then the
approver, then the allow-list, and only then the action. A daemon that is
not allowed to contain anything refuses before it looks at what it was
asked to do, because a refusal that quotes the request is more useful in a
log than a refusal that quotes the policy.

Suspending a process uses `kill -STOP` rather than a direct syscall, and
that has a consequence worth stating: the process is stopped, not killed.
Nothing is destroyed, the state is preserved, and `SIGCONT` resumes it.
The operator's hook decides what "blocked" means for an address, and it is
the operator's hook that gets the capability to do it.

## The refusals

A refusal is a result, not an error. The daemon records what it did not
do and why, and the operator sees the same sentence in the panel:

- "containment is not enabled on this daemon; it was started without
  `--allow-containment`"
- "the order names nobody who approved it"
- "process 4242 is not in the allow-list"
- "address 203.0.113.7/32 is not in the allow-list"
- "a whole-host quarantine is never carried out automatically"

## Where it lives

| Piece | Location |
|---|---|
| The policy, the executor, the refusals | `crates/heimdall-sentinel/src/containment.rs` |
| The recommendation and the order on the wire | `crates/heimdall-ipc/src/message.rs` |
| Building a validated order in Core | `crates/heimdall-core/src/orchestrator.rs` |
| The panel, the approve and decline buttons | `crates/heimdall-shell/src/main.rs` |

## Turning it on

```sh
heimdall-sentinel --allow-containment --contain-policy /etc/heimdall/contain.policy
```

The daemon refuses to start if `--allow-containment` is given without a
policy file. An empty allow-list would contain nothing, and the flag would
only make the daemon look armed when it is not.

Start with a policy that names one process you understand. The point of
the allow-list is that it is narrow enough to be obviously right.
