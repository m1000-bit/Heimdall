//! Carrying out a containment order -- when the operator has allowed it.
//!
//! # The posture
//!
//! Containment is advisory by default. A Sentinel that was started without
//! `--allow-containment` will *recommend* a containment to Core and will refuse
//! every order it receives. That refusal is not a limitation to be worked
//! around; it is the rule this module implements.
//!
//! When the operator does allow containment, three further limits apply, and
//! each of them exists because the alternative was a defence tool that could
//! take a machine offline by misreading a metric:
//!
//! 1. **A named allow-list.** Only the processes, addresses and interfaces the
//!    operator wrote down can be contained. Anything else is refused, however
//!    urgent the recommendation was.
//! 2. **A named approver.** An order that does not say who authorised it is
//!    refused. The name is what the log records, and a log that cannot say
//!    who acted cannot answer the question an incident review asks first.
//! 3. **No whole-host quarantine.** There is no configuration that makes the
//!    executor quarantine the host, because a defence tool that can take the
//!    whole machine down is a different kind of tool.
//!
//! # What the daemon does not do
//!
//! It does not manipulate the firewall. Address and interface containment are
//! carried out by a command the operator supplies, which keeps the decision
//! about *how* a host is contained with the operator rather than with this
//! program. Without such a command, those scopes are refused rather than
//! approximated.

use std::collections::BTreeSet;
use std::process::Command;

use heimdall_ipc::message::{ContainmentOrder, ContainmentScope};

/// What this executor is allowed to touch.
///
/// The allow-lists are the operator's, not the model's. An allow-list that a
/// recommendation could widen would not be an allow-list.
#[derive(Debug, Clone, Default)]
pub struct ContainmentPolicy {
    /// Whether containment may be carried out at all.
    ///
    /// Set by `--allow-containment`. Without it every order is refused, and
    /// the refusal says so, so the log shows the daemon's posture rather than
    /// leaving the operator to guess.
    pub enabled: bool,
    /// The only processes that may be suspended.
    pub allowed_pids: BTreeSet<u32>,
    /// The only address ranges that may be blocked.
    pub allowed_cidrs: BTreeSet<String>,
    /// The only interfaces that may be disabled.
    pub allowed_interfaces: BTreeSet<String>,
    /// The command that carries out an address or interface containment.
    ///
    /// Called as `<hook> <kind> <target>`, for example
    /// `heimdall-contain-block address 203.0.113.7/32`.
    pub hook: Option<Vec<String>>,
}

impl ContainmentPolicy {
    /// Parses a policy file.
    ///
    /// The format is a line per rule, so that a policy can be read, diffed and
    /// reviewed by a person:
    ///
    /// ```text
    /// # comments and blank lines are ignored
    /// pid 4242
    /// cidr 203.0.113.7/32
    /// interface eth0
    /// hook /usr/local/sbin/heimdall-contain-block
    /// ```
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let mut policy = Self {
            enabled: true,
            ..Self::default()
        };
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((keyword, rest)) = line.split_once(char::is_whitespace) else {
                return Err(PolicyError::Syntax {
                    line: number + 1,
                    detail: "expected a keyword and a value".into(),
                });
            };
            let keyword = keyword.trim();
            let values: Vec<&str> = rest.split_whitespace().collect();
            let one = || -> Result<&str, PolicyError> {
                match values.as_slice() {
                    [value] => Ok(value),
                    other => Err(PolicyError::Syntax {
                        line: number + 1,
                        detail: format!("expected exactly one value, found {}", other.len()),
                    }),
                }
            };
            match keyword {
                "pid" => {
                    let value = one()?;
                    let pid = value.parse::<u32>().map_err(|_| PolicyError::Syntax {
                        line: number + 1,
                        detail: format!("{value:?} is not a process id"),
                    })?;
                    policy.allowed_pids.insert(pid);
                }
                "cidr" => {
                    policy.allowed_cidrs.insert(one()?.to_string());
                }
                "interface" => {
                    policy.allowed_interfaces.insert(one()?.to_string());
                }
                "hook" => {
                    if values.is_empty() {
                        return Err(PolicyError::Syntax {
                            line: number + 1,
                            detail: "the hook needs a command".into(),
                        });
                    }
                    policy.hook = Some(values.iter().map(|v| (*v).to_string()).collect());
                }
                other => {
                    return Err(PolicyError::Syntax {
                        line: number + 1,
                        detail: format!("unknown keyword {other:?}"),
                    });
                }
            }
        }
        Ok(policy)
    }

    /// Reads a policy file.
    pub fn load(path: &std::path::Path) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(|source| PolicyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text)
    }
}

/// Why a policy file could not be used.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("cannot read the policy file {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("policy line {line}: {detail}")]
    Syntax { line: usize, detail: String },
}

/// The result of trying to carry out an order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentOutcome {
    /// Whether anything was actually done.
    pub performed: bool,
    /// What was ordered.
    pub scope: ContainmentScope,
    /// What happened, in words. Written for a person reading a log at 3am.
    pub detail: String,
}

impl ContainmentOutcome {
    fn refused(scope: ContainmentScope, detail: impl Into<String>) -> Self {
        Self {
            performed: false,
            scope,
            detail: detail.into(),
        }
    }
}

/// The effects the executor can have on the host.
///
/// A trait rather than direct calls, so that the decision logic -- which is
/// where the security-relevant behaviour lives -- can be tested without
/// suspending real processes or touching real firewall rules.
pub trait ContainmentBackend: std::fmt::Debug + Send {
    /// Suspends a process.
    fn suspend(&mut self, pid: u32) -> Result<(), String>;

    /// Runs the operator's hook for a containment.
    fn run_hook(&mut self, hook: &[String], kind: &str, target: &str) -> Result<(), String>;
}

/// The real backend: process suspension on Unix, and the operator's hook for
/// everything else.
///
/// Process suspension uses `kill -STOP` rather than a direct syscall because
/// the workspace forbids unsafe code, and a shell out to the standard utility
/// is both auditable and identical to what an operator would type.
#[derive(Debug, Default)]
pub struct SystemBackend;

impl ContainmentBackend for SystemBackend {
    fn suspend(&mut self, pid: u32) -> Result<(), String> {
        if !cfg!(unix) {
            return Err(
                "process suspension is not implemented on this platform; configure a hook".into(),
            );
        }
        let status = Command::new("kill")
            .arg("-STOP")
            .arg(pid.to_string())
            .status()
            .map_err(|e| format!("cannot run kill: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("kill -STOP {pid} failed with {status}"))
        }
    }

    fn run_hook(&mut self, hook: &[String], kind: &str, target: &str) -> Result<(), String> {
        let (program, args) = hook.split_first().ok_or("the hook command is empty")?;
        let status = Command::new(program)
            .args(args)
            .arg(kind)
            .arg(target)
            .status()
            .map_err(|e| format!("cannot run the hook {program:?}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("the hook {program:?} failed with {status}"))
        }
    }
}

/// Carries out containment orders that the policy allows.
#[derive(Debug)]
pub struct ContainmentExecutor {
    policy: ContainmentPolicy,
    backend: Box<dyn ContainmentBackend>,
}

impl ContainmentExecutor {
    /// An executor with the real backend.
    #[must_use]
    pub fn new(policy: ContainmentPolicy) -> Self {
        Self {
            policy,
            backend: Box::new(SystemBackend),
        }
    }

    /// An executor with a substituted backend, for tests.
    #[must_use]
    pub fn with_backend(policy: ContainmentPolicy, backend: Box<dyn ContainmentBackend>) -> Self {
        Self { policy, backend }
    }

    /// The policy this executor enforces.
    #[must_use]
    pub fn policy(&self) -> &ContainmentPolicy {
        &self.policy
    }

    /// Carries out an order, or explains why it did not.
    ///
    /// The order of the checks is the order of the rules: posture first, then
    /// the approver, then the allow-list, and only then the action. A daemon
    /// that is not allowed to contain anything refuses before it looks at what
    /// it was asked to do.
    pub fn execute(&mut self, order: &ContainmentOrder) -> ContainmentOutcome {
        if !self.policy.enabled {
            return ContainmentOutcome::refused(
                order.scope.clone(),
                "containment is not enabled on this daemon; it was started without --allow-containment",
            );
        }

        let approved_by = order.approved_by.trim();
        if approved_by.is_empty() {
            return ContainmentOutcome::refused(
                order.scope.clone(),
                "the order names nobody who approved it",
            );
        }

        match &order.scope {
            ContainmentScope::Process { pid } => self.suspend_process(*pid, approved_by),
            ContainmentScope::Address { cidr } => self.run_hook("address", cidr, approved_by),
            ContainmentScope::Interface { name } => self.run_hook("interface", name, approved_by),
            ContainmentScope::HostQuarantine => ContainmentOutcome::refused(
                order.scope.clone(),
                "a whole-host quarantine is never carried out automatically",
            ),
        }
    }

    fn suspend_process(&mut self, pid: u32, approved_by: &str) -> ContainmentOutcome {
        if !self.policy.allowed_pids.contains(&pid) {
            return ContainmentOutcome::refused(
                ContainmentScope::Process { pid },
                format!("process {pid} is not in the allow-list"),
            );
        }
        match self.backend.suspend(pid) {
            Ok(()) => ContainmentOutcome {
                performed: true,
                scope: ContainmentScope::Process { pid },
                detail: format!("suspended process {pid}, approved by {approved_by}"),
            },
            Err(e) => ContainmentOutcome::refused(
                ContainmentScope::Process { pid },
                format!("could not suspend process {pid}: {e}"),
            ),
        }
    }

    fn run_hook(&mut self, kind: &str, target: &str, approved_by: &str) -> ContainmentOutcome {
        let scope = match kind {
            "address" => ContainmentScope::Address {
                cidr: target.to_string(),
            },
            _ => ContainmentScope::Interface {
                name: target.to_string(),
            },
        };

        let listed = match kind {
            "address" => self.policy.allowed_cidrs.contains(target),
            _ => self.policy.allowed_interfaces.contains(target),
        };
        if !listed {
            return ContainmentOutcome::refused(
                scope,
                format!("{target} is not in the allow-list"),
            );
        }

        let Some(hook) = self.policy.hook.clone() else {
            return ContainmentOutcome::refused(
                scope,
                format!("no hook is configured to contain {target}"),
            );
        };
        match self.backend.run_hook(&hook, kind, target) {
            Ok(()) => ContainmentOutcome {
                performed: true,
                scope,
                detail: format!(
                    "contained {target} through the configured hook, approved by {approved_by}"
                ),
            },
            Err(e) => ContainmentOutcome::refused(scope, format!("the hook failed: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct RecordingBackend {
        calls: Arc<Mutex<Vec<String>>>,
        fail: bool,
    }

    impl ContainmentBackend for RecordingBackend {
        fn suspend(&mut self, pid: u32) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!("suspend {pid}"));
            if self.fail {
                Err("simulated failure".into())
            } else {
                Ok(())
            }
        }

        fn run_hook(&mut self, hook: &[String], kind: &str, target: &str) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("hook {} {kind} {target}", hook.join(" ")));
            if self.fail {
                Err("simulated failure".into())
            } else {
                Ok(())
            }
        }
    }

    fn order(scope: ContainmentScope, approved_by: &str) -> ContainmentOrder {
        ContainmentOrder {
            incident_id: 1,
            scope,
            approved_by: approved_by.into(),
        }
    }

    fn policy() -> ContainmentPolicy {
        ContainmentPolicy {
            enabled: true,
            allowed_pids: BTreeSet::from([4242]),
            allowed_cidrs: BTreeSet::from(["203.0.113.7/32".to_string()]),
            allowed_interfaces: BTreeSet::from(["eth0".to_string()]),
            hook: Some(vec!["/bin/block".into()]),
        }
    }

    #[test]
    fn a_daemon_that_was_not_allowed_to_contain_refuses_every_order() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut policy = policy();
        policy.enabled = false;
        let mut executor = ContainmentExecutor::with_backend(
            policy,
            Box::new(RecordingBackend {
                calls: calls.clone(),
                fail: false,
            }),
        );

        let outcome = executor.execute(&order(ContainmentScope::Process { pid: 4242 }, "operator"));
        assert!(!outcome.performed);
        assert!(
            outcome.detail.contains("--allow-containment"),
            "{outcome:?}"
        );
        assert!(calls.lock().unwrap().is_empty(), "nothing may be attempted");
    }

    #[test]
    fn an_order_without_an_approver_is_refused() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut executor = ContainmentExecutor::with_backend(
            policy(),
            Box::new(RecordingBackend {
                calls: calls.clone(),
                fail: false,
            }),
        );

        let outcome = executor.execute(&order(ContainmentScope::Process { pid: 4242 }, "   "));
        assert!(!outcome.performed);
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_process_outside_the_allow_list_is_not_suspended() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut executor = ContainmentExecutor::with_backend(
            policy(),
            Box::new(RecordingBackend {
                calls: calls.clone(),
                fail: false,
            }),
        );

        let outcome = executor.execute(&order(ContainmentScope::Process { pid: 9999 }, "operator"));
        assert!(!outcome.performed);
        assert!(outcome.detail.contains("allow-list"), "{outcome:?}");
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn an_allowed_process_is_suspended_and_the_approver_is_recorded() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut executor = ContainmentExecutor::with_backend(
            policy(),
            Box::new(RecordingBackend {
                calls: calls.clone(),
                fail: false,
            }),
        );

        let outcome = executor.execute(&order(ContainmentScope::Process { pid: 4242 }, "operator"));
        assert!(outcome.performed, "{outcome:?}");
        assert!(outcome.detail.contains("operator"), "{outcome:?}");
        assert_eq!(calls.lock().unwrap().as_slice(), ["suspend 4242"]);
    }

    #[test]
    fn a_whole_host_quarantine_is_never_carried_out() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut executor = ContainmentExecutor::with_backend(
            policy(),
            Box::new(RecordingBackend {
                calls: calls.clone(),
                fail: false,
            }),
        );

        let outcome = executor.execute(&order(ContainmentScope::HostQuarantine, "operator"));
        assert!(!outcome.performed);
        assert!(outcome.detail.contains("never"), "{outcome:?}");
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn an_address_needs_both_the_allow_list_and_a_hook() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut executor = ContainmentExecutor::with_backend(
            policy(),
            Box::new(RecordingBackend {
                calls: calls.clone(),
                fail: false,
            }),
        );
        let outcome = executor.execute(&order(
            ContainmentScope::Address {
                cidr: "203.0.113.7/32".into(),
            },
            "operator",
        ));
        assert!(outcome.performed, "{outcome:?}");
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            ["hook /bin/block address 203.0.113.7/32"]
        );
    }

    #[test]
    fn an_address_without_a_hook_is_refused_rather_than_approximated() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut mut_policy = policy();
        mut_policy.hook = None;
        let mut executor = ContainmentExecutor::with_backend(
            mut_policy,
            Box::new(RecordingBackend {
                calls: calls.clone(),
                fail: false,
            }),
        );

        let outcome = executor.execute(&order(
            ContainmentScope::Address {
                cidr: "203.0.113.7/32".into(),
            },
            "operator",
        ));
        assert!(!outcome.performed);
        assert!(outcome.detail.contains("hook"), "{outcome:?}");
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_failing_action_is_reported_as_a_failure_not_a_success() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut executor = ContainmentExecutor::with_backend(
            policy(),
            Box::new(RecordingBackend {
                calls: calls.clone(),
                fail: true,
            }),
        );

        let outcome = executor.execute(&order(ContainmentScope::Process { pid: 4242 }, "operator"));
        assert!(!outcome.performed);
        assert!(outcome.detail.contains("could not suspend"), "{outcome:?}");
    }

    #[test]
    fn a_policy_file_is_readable_by_a_person() {
        let text = "# only these may be contained\npid 4242\ncidr 203.0.113.7/32\ninterface eth0\nhook /bin/block --force\n";
        let parsed = ContainmentPolicy::parse(text).expect("a valid policy");
        assert!(parsed.allowed_pids.contains(&4242));
        assert!(parsed.allowed_cidrs.contains("203.0.113.7/32"));
        assert!(parsed.allowed_interfaces.contains("eth0"));
        assert_eq!(
            parsed.hook.as_deref(),
            Some(["/bin/block".to_string(), "--force".to_string()].as_slice())
        );
    }

    #[test]
    fn a_malformed_policy_file_is_rejected_with_the_line_number() {
        let err = ContainmentPolicy::parse("pid not-a-number\n").expect_err("a bad policy");
        assert!(err.to_string().contains("line 1"), "got: {err}");

        let err = ContainmentPolicy::parse("wat 1\n").expect_err("a bad policy");
        assert!(err.to_string().contains("line 1"), "got: {err}");
    }
}
