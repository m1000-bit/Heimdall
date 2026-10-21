//! The conversational interface, behind a swappable reasoning backend.
//!
//! Core's job is to turn what the operator said into something actionable:
//! a directive for Sentinel, an assessment of an alert, or a self-repair
//! proposal. Doing that well needs a language model; this module is the seam
//! where one goes, not the model itself.
//!
//! Two decisions shape the interface:
//!
//! 1. **No streaming, no tool-calling, no chat template.** A backend returns one
//!    finished [`Reply`]. Streaming would put a partially-generated answer in
//!    front of the operator, and for a system whose whole value is that its
//!    outputs get reviewed, a half-formed proposal is worse than none. Tool
//!    calling would let the model reach past the gate; actions go through
//!    [`crate::gate`] instead, with the operator in the loop.
//! 2. **The backend may only *propose*.** [`Reply`] carries a
//!    [`ReplyAction::ProposePatch`] variant, which is data for the gate, never an
//!    instruction to write. This is enforced by the type: there is no variant
//!    that means "apply this".
//!
//! [`DeterministicBackend`] implements the trait with rules rather than weights.
//! It is what runs in CI and what the shell uses until a model is attached: it is
//! deterministic, inspectable, and its failure modes are obvious, which makes it
//! a useful reference for what a model-backed backend is supposed to do.

/// What the operator said, plus whatever context Core can justify passing along.
#[derive(Debug, Clone)]
pub struct ReasoningRequest {
    pub prompt: String,
    /// Alerts Core wants the backend to consider, oldest first.
    pub alerts: Vec<String>,
    /// Paths of files the backend is being asked about, if any.
    pub referenced_files: Vec<String>,
    /// Replies already exchanged, oldest first. Present so a backend with a
    /// conversation can use it; a stateless one may ignore it.
    pub transcript: Vec<String>,
}

impl ReasoningRequest {
    #[must_use]
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            alerts: Vec::new(),
            referenced_files: Vec::new(),
            transcript: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_alerts(mut self, alerts: Vec<String>) -> Self {
        self.alerts = alerts;
        self
    }

    #[must_use]
    pub fn with_files(mut self, files: Vec<String>) -> Self {
        self.referenced_files = files;
        self
    }
}

/// What the backend concluded.
#[derive(Debug, Clone)]
pub struct Reply {
    /// Prose for the operator. Always present: a backend that cannot explain
    /// itself should say so rather than emit a proposal alone.
    pub explanation: String,
    pub action: ReplyAction,
    /// Backend confidence in `0.0..=1.0`. A model that is guessing should be
    /// able to say so.
    pub confidence: f32,
}

/// A self-repair proposal, reduced to the fields a backend chooses.
///
/// The gate mints the id and the timestamp. A backend supplies content only, so
/// it cannot fabricate a proposal that looks like it came from an earlier turn.
#[derive(Debug, Clone, PartialEq)]
pub struct ProposedPatch {
    pub target_path: String,
    pub summary: String,
    pub rationale: String,
    pub diff: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReplyAction {
    /// Nothing to do.
    None,
    /// A directive for Sentinel. Sent over the encrypted link.
    Directive(Directive),
    /// A self-repair proposal. Goes to the gate, never to disk.
    ProposePatch(ProposedPatch),
    /// The backend cannot answer, and says why.
    Declined { reason: String },
}

/// A directive Core sends to Sentinel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    pub intent: String,
    pub arguments: Vec<String>,
}

impl Directive {
    #[must_use]
    pub fn new(intent: impl Into<String>, arguments: Vec<String>) -> Self {
        Self {
            intent: intent.into(),
            arguments,
        }
    }
}

/// The seam a language model plugs into.
pub trait ReasoningBackend: Send + Sync {
    /// Identifies the implementation, for logs and the UI.
    fn name(&self) -> &'static str;

    /// One turn. Must not have side effects outside its argument.
    fn reason(&self, request: &ReasoningRequest) -> Reply;
}

/// A rule-based backend.
///
/// Its value is not that it is clever. It is that it is deterministic and that
/// every reply can be traced to the rule that produced it, which makes it the
/// reference implementation the model-backed backend is tested against, and the
/// backend the shell runs before one is attached.
#[derive(Debug, Clone)]
pub struct DeterministicBackend {
    /// Identity shown in the UI. Distinguishes several instances.
    name: String,
    /// Directives this backend is willing to emit. Anything else is declined
    /// rather than passed through, so a rule typo cannot widen its authority.
    allowed_intents: Vec<String>,
    /// Proposals are refused unless explicitly enabled. A backend that can
    /// always produce a patch proposal is a backend that will eventually
    /// produce one nobody wanted.
    allow_proposals: bool,
}

impl Default for DeterministicBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl DeterministicBackend {
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "deterministic-v1".into(),
            allowed_intents: ["status", "scan", "list-alerts", "explain", "reset-baseline"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            allow_proposals: true,
        }
    }

    #[must_use]
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Restricts or extends the intent vocabulary.
    #[must_use]
    pub fn with_intents(mut self, intents: Vec<String>) -> Self {
        self.allowed_intents = intents;
        self
    }

    #[must_use]
    pub fn with_proposals(mut self, allow: bool) -> Self {
        self.allow_proposals = allow;
        self
    }

    fn match_intent(prompt: &str) -> Directive {
        let p = prompt.trim().to_ascii_lowercase();
        let has = |needle: &str| p.contains(needle);

        if has("status") || has("health") || has("come stai") {
            Directive::new("status", vec![])
        } else if has("alert") && (has("list") || has("mostrami") || has("show")) {
            Directive::new("list-alerts", vec![])
        } else if has("scan") || has("analizza") {
            let stream = extract_quoted(&p).unwrap_or_else(|| "all".to_string());
            Directive::new("scan", vec![stream])
        } else if has("reset") || has("baseline") {
            Directive::new(
                "reset-baseline",
                vec![extract_quoted(&p).unwrap_or_default()],
            )
        } else if has("explain") || has("perche") || has("why") {
            Directive::new("explain", vec![extract_quoted(&p).unwrap_or_default()])
        } else {
            Directive::new("status", vec![])
        }
    }
}

fn extract_quoted(text: &str) -> Option<String> {
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '"' || c == '\'' || c == '\u{2018}' {
            let rest = chars.as_str();
            let end = rest.find(['"', '\'', '\u{2019}']).unwrap_or(rest.len());
            let inner = rest[..end].trim();
            if !inner.is_empty() {
                return Some(inner.to_string());
            }
        }
    }
    None
}

impl ReasoningBackend for DeterministicBackend {
    fn name(&self) -> &'static str {
        // Leaked once per backend instance, which is bounded by the number of
        // configured backends. Keeps the trait object-free and the signature
        // simple; a hot path would want `&str` back from an owned name instead.
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn reason(&self, request: &ReasoningRequest) -> Reply {
        let intent = Self::match_intent(&request.prompt);

        if !self.allowed_intents.iter().any(|a| a == &intent.intent) {
            return Reply {
                explanation: format!(
                    "'{}' is outside this backend's vocabulary. It may issue: {}.",
                    intent.intent,
                    self.allowed_intents.join(", ")
                ),
                action: ReplyAction::Declined {
                    reason: "intent not permitted".into(),
                },
                confidence: 1.0,
            };
        }

        // A request that names a file is a request to change code, not to run a
        // directive. Those take different paths and must not be conflated: one
        // goes to Sentinel, the other to the gate.
        let mentions_file = !request.referenced_files.is_empty()
            || request.prompt.contains(".rs")
            || request.prompt.contains(".toml");

        if mentions_file {
            if !self.allow_proposals {
                return Reply {
                    explanation: format!(
                        "This backend has patch proposal generation disabled, so it \
                         cannot act on a request about {}.",
                        request
                            .referenced_files
                            .first()
                            .map_or("source files", String::as_str)
                    ),
                    action: ReplyAction::Declined {
                        reason: "proposals disabled".into(),
                    },
                    confidence: 1.0,
                };
            }

            let target = request
                .referenced_files
                .first()
                .cloned()
                .unwrap_or_else(|| "(unspecified)".into());

            // The proposal is *data*: a path and a rationale. It carries no
            // instruction, and the gate supplies the id and timestamp.
            let proposal = ProposedPatch {
                target_path: target,
                summary: "Review requested for a source file".into(),
                rationale: format!(
                    "The operator asked about a source file: \"{}\". This proposal \
                     carries no diff. It exists so the request passes through the \
                     gate and appears in the audit trail rather than being acted on \
                     silently or dropped.",
                    truncate(&request.prompt, 200)
                ),
                diff: String::new(),
            };
            return Reply {
                explanation: "That names a source file, so it is a self-repair request rather \
                     than a directive to Sentinel. It has been recorded as a proposal \
                     with no diff attached and will appear in the audit trail."
                    .to_string(),
                action: ReplyAction::ProposePatch(proposal),
                confidence: 0.6,
            };
        }

        let context = if request.alerts.is_empty() {
            String::new()
        } else {
            format!(
                " I have {} open alert(s); the most recent is {}.",
                request.alerts.len(),
                truncate(request.alerts.last().map_or("", String::as_str), 140)
            )
        };

        Reply {
            explanation: format!(
                "Understood as '{}'{}. Acting on it now; nothing is changed in the \
                 codebase by this reply.",
                intent.intent, context
            ),
            action: ReplyAction::Directive(intent.clone()),
            confidence: 0.85,
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect::<String>() + "..."
}

/// Where a model-backed backend plugs in.
///
/// Intentionally not implemented. It is a stub so the integration point is
/// visible in the tree and so nobody has to reverse-engineer where a model would
/// go -- but filling it in needs a decision this phase has not made:
///
/// * Which runtime. Candle for a pure-Rust build, or `llama.cpp` bindings for
///   better quantised-model coverage.
/// * Whether the model runs in-process. In-process means one address space holds
///   the prompt history and every secret the process can reach; out-of-process
///   means an IPC boundary to get wrong.
/// * What the model is allowed to see. Alert summaries are sanitised, but a model
///   that can read the keystore is a model that can exfiltrate it, and the
///   prompt path is where that boundary has to be drawn.
///
/// Those are the questions, not the plumbing. The plumbing is [`ReasoningBackend`].
#[derive(Debug)]
pub struct LocalModelBackend;

impl ReasoningBackend for LocalModelBackend {
    fn name(&self) -> &'static str {
        "local-model (unimplemented)"
    }

    fn reason(&self, _request: &ReasoningRequest) -> Reply {
        Reply {
            explanation: "No local model runtime is configured. This is the seam where \
                          one attaches; see the module documentation for what has to be \
                          decided first."
                .into(),
            action: ReplyAction::Declined {
                reason: "no model runtime attached".into(),
            },
            confidence: 1.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> DeterministicBackend {
        DeterministicBackend::new()
    }

    #[test]
    fn a_status_request_becomes_a_status_directive() {
        for prompt in ["status", "what is the health?", "come stai"] {
            let r = backend().reason(&ReasoningRequest::new(prompt));
            assert!(
                matches!(&r.action, ReplyAction::Directive(d) if d.intent == "status"),
                "{prompt:?} produced {r:?}"
            );
            assert!(r.explanation.contains("nothing is changed"));
        }
    }

    #[test]
    fn a_scan_request_carries_the_named_stream() {
        let r = backend().reason(&ReasoningRequest::new("run a scan on \"net.egress\""));
        match &r.action {
            ReplyAction::Directive(d) => {
                assert_eq!(d.intent, "scan");
                assert_eq!(d.arguments, vec!["net.egress".to_string()]);
            }
            other => panic!("expected a directive, got {other:?}"),
        }
    }

    #[test]
    fn an_unquoted_scan_defaults_to_all_streams() {
        let r = backend().reason(&ReasoningRequest::new("analizza"));
        match &r.action {
            ReplyAction::Directive(d) => assert_eq!(d.arguments, vec!["all".to_string()]),
            other => panic!("expected a directive, got {other:?}"),
        }
    }

    #[test]
    fn a_source_file_request_becomes_a_proposal_not_a_directive() {
        // The distinction matters: a directive reaches Sentinel, a proposal
        // reaches the gate. Conflating them would let a code request skip review.
        let r = backend().reason(&ReasoningRequest::new("why does src/gate.rs do this?"));
        match &r.action {
            ReplyAction::ProposePatch(p) => {
                assert_eq!(p.target_path, "(unspecified)");
                assert!(p.rationale.contains("src/gate.rs"));
                assert!(
                    p.diff.is_empty(),
                    "a proposal must not smuggle in an action"
                );
            }
            other => panic!("expected a proposal, got {other:?}"),
        }
    }

    #[test]
    fn proposals_can_be_switched_off_entirely() {
        let b = backend().with_proposals(false);
        let r = b.reason(&ReasoningRequest::new(
            "fix crates/heimdall-core/src/lib.rs",
        ));
        assert!(matches!(r.action, ReplyAction::Declined { .. }));
        assert!(r.explanation.contains("disabled"));
    }

    #[test]
    fn the_intent_vocabulary_can_be_restricted() {
        // Restricting the vocabulary must *decline*, not silently fall back to
        // a default intent: a fallback would turn a typo into a command.
        let b = backend().with_intents(vec!["status".into()]);

        let declined = b.reason(&ReasoningRequest::new("run a scan"));
        assert!(matches!(declined.action, ReplyAction::Declined { .. }));
        assert!(declined.explanation.contains("scan"));
        assert!(declined.explanation.contains("status"));

        let allowed = b.reason(&ReasoningRequest::new("status"));
        assert!(matches!(
            allowed.action,
            ReplyAction::Directive(ref d) if d.intent == "status"
        ));
    }

    #[test]
    fn alerts_are_surfaced_in_the_reply_context() {
        let r = backend().reason(
            &ReasoningRequest::new("status")
                .with_alerts(vec!["net.egress spike".into(), "cpu spike".into()]),
        );
        assert!(r.explanation.contains("2 open alert"), "{}", r.explanation);
        assert!(r.explanation.contains("cpu spike"));
    }

    #[test]
    fn no_reply_is_actionable_without_an_explanation() {
        // Every reply must carry prose. A backend that emits only an action
        // forces the operator to approve something unexplained.
        for prompt in ["status", "scan", "why is src/lib.rs like that?"] {
            let r = backend().reason(&ReasoningRequest::new(prompt));
            assert!(
                !r.explanation.trim().is_empty(),
                "{prompt:?} had no explanation"
            );
            assert!((0.0..=1.0).contains(&r.confidence));
        }
    }

    #[test]
    fn the_backend_is_deterministic() {
        let req = ReasoningRequest::new("run a scan on net.egress");
        let first = backend().reason(&req);
        for _ in 0..50 {
            let again = backend().reason(&req);
            assert_eq!(first.action, again.action);
            assert_eq!(first.explanation, again.explanation);
        }
    }

    #[test]
    fn quoted_argument_extraction_handles_the_usual_quotings() {
        for (text, want) in [
            ("scan \"a.b\"", Some("a.b")),
            ("scan 'a.b'", Some("a.b")),
            ("scan \u{2018}a.b\u{2019}", Some("a.b")),
            ("scan a.b", None),
        ] {
            let got = extract_quoted(&text.to_ascii_lowercase());
            assert_eq!(got.as_deref(), want, "{text}");
        }
    }

    #[test]
    fn an_empty_quoted_value_does_not_produce_an_empty_argument() {
        assert_eq!(extract_quoted("scan \"\""), None);
    }

    #[test]
    fn truncation_preserves_a_readable_prefix() {
        let long = "x".repeat(500);
        let t = truncate(&long, 10);
        assert_eq!(t.chars().count(), 13);
        assert!(t.ends_with("..."));
        assert_eq!(truncate("short", 10), "short");
    }

    #[test]
    fn the_unimplemented_model_backend_declines_rather_than_guessing() {
        let r = LocalModelBackend.reason(&ReasoningRequest::new("status"));
        assert!(matches!(r.action, ReplyAction::Declined { .. }));
        assert!(r.explanation.contains("seam"));
    }

    #[test]
    fn a_backend_can_be_used_through_a_trait_object() {
        let backends: Vec<Box<dyn ReasoningBackend>> = vec![
            Box::new(DeterministicBackend::new().named("rules-a")),
            Box::new(DeterministicBackend::new().named("rules-b")),
        ];
        for b in &backends {
            let r = b.reason(&ReasoningRequest::new("status"));
            assert!(matches!(r.action, ReplyAction::Directive(_)));
        }
        assert_ne!(backends[0].name(), backends[1].name());
    }
}
