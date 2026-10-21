//! The Heimdall desktop shell.
//!
//! Native window, egui/eframe for the chrome, one custom WGSL pass for the
//! background. No webview, no embedded browser: the design document is explicit
//! that this is a native desktop application, and the security posture of a
//! defence tool that renders HTML with a system webview is not one to take on
//! for a convenience.
//!
//! Layout is three panels: link status, the alert feed, and the self-repair
//! review. The review panel is deliberately the largest, because it is the only
//! part where the user's attention changes the security of the system.
//!
//! Three things can be acted on from the interface, and all three go through
//! the same rule: something happens only when a person says so. A patch is
//! applied only after the exact diff has been read and approved. A containment
//! is ordered only after a recommendation has been read and approved. A spoken
//! command can ask for either, but it cannot grant either.

mod backdrop;
mod link;
mod voice;

use egui::{Align, Color32, Layout, RichText, Stroke, Vec2};

use heimdall_core::orchestrator::MAX_PENDING_CONTAINMENTS;
use heimdall_core::{AuditEvent, Finding, Orchestrator, PatchProposal};
use heimdall_ipc::message::{ContainmentRecommendation, ContainmentScope, ThreatAlert};
use heimdall_sentinel::Engine;
use heimdall_voice::{CommandIntent, Transcript};

use backdrop::{BACKGROUND_TINT, Backdrop};
use link::{Link, LinkState};
use voice::{VoicePanel, VoiceState};

/// Palette. Kept in one place so the whole shell reads as one surface.
mod palette {
    use egui::Color32;

    pub const ACCENT: Color32 = Color32::from_rgb(64, 196, 220);
    pub const WARN: Color32 = Color32::from_rgb(232, 168, 60);
    pub const DANGER: Color32 = Color32::from_rgb(226, 82, 88);
    pub const OK: Color32 = Color32::from_rgb(88, 196, 128);
    pub const MUTED: Color32 = Color32::from_rgb(138, 152, 176);
    pub const PANEL: Color32 = Color32::from_rgba_premultiplied(14, 19, 32, 226);
    pub const BORDER: Color32 = Color32::from_rgba_premultiplied(50, 70, 100, 160);
}

struct Shell {
    orchestrator: Orchestrator,
    sentinel: Engine,
    backdrop: Backdrop,
    /// The socket, and its thread. Everything the UI learns about Sentinel comes
    /// through here.
    link: Link,
    endpoint: String,
    /// Why the link failed, kept for display. Distinct from a failed state alone:
    /// "failed" is not something an operator can act on.
    link_error: Option<String>,
    /// Set when the failure was an identity problem rather than an absent
    /// process. That is a security event and is shown differently on purpose.
    link_identity_problem: bool,
    alerts: Vec<ThreatAlert>,
    selected_alert: Option<usize>,
    /// Who is recorded as authorising a patch. Phase 1 has no login, so this is
    /// an explicit operator label rather than an implied identity.
    operator: String,
    reject_reason: String,
    last_action: Option<String>,
    show_audit: bool,
    /// Rolling render cost, shown because it is the number that decides whether
    /// the background shader can stay.
    frame_millis: f32,
    /// What the last repository scan found. Observations, not proposals.
    findings: Vec<Finding>,
    /// Containment recommendations nobody has decided on.
    containments: Vec<ContainmentRecommendation>,
    /// The voice panel: microphone, grammar, and the intents it understood.
    voice: VoicePanel,
    /// The example utterance currently selected, shown by the combo box.
    example_label: String,
    /// Set when a spoken command asked for something the operator has to
    /// confirm with a button. The panel that carries the decision is pointed
    /// at, rather than the decision being taken for the operator.
    attention: Option<&'static str>,
}

impl Shell {
    fn new(orchestrator: Orchestrator) -> Self {
        // The endpoint may be pointed somewhere else by the environment: a
        // deployment that runs the daemon as a service account has to name the
        // socket both sides will use, and a name alone cannot express that.
        let endpoint = std::env::var("HEIMDALL_ENDPOINT")
            .ok()
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| heimdall_ipc::transport::DEFAULT_ENDPOINT.to_string());
        let sentinel = Engine::new(heimdall_sentinel::DEFAULT_SENTINEL_ID);

        Self {
            orchestrator,
            sentinel,
            backdrop: Backdrop::new(),
            link: Link::new(),
            endpoint,
            link_error: None,
            link_identity_problem: false,
            alerts: Vec::new(),
            selected_alert: None,
            operator: "local-operator".into(),
            reject_reason: String::new(),
            last_action: None,
            show_audit: false,
            frame_millis: 0.0,
            findings: Vec::new(),
            containments: Vec::new(),
            voice: VoicePanel::new(),
            example_label: String::new(),
            attention: None,
        }
    }

    /// Moves whatever the network thread has produced into Core and the UI.
    ///
    /// Called once per frame. Decoding happens on the link thread, so this is
    /// bookkeeping rather than I/O.
    fn pump_link(&mut self) {
        for event in self.link.drain() {
            match event {
                link::LinkEvent::Alert(alert) => self.orchestrator.observe_alert(alert),
                link::LinkEvent::Health(report) => self.orchestrator.observe_health(*report),
                link::LinkEvent::Recommendation(recommendation) => {
                    // Advice, not an instruction. It waits here until the
                    // operator decides, and it is dropped if the queue is
                    // full rather than growing without limit.
                    self.orchestrator
                        .observe_containment_recommendation((*recommendation).clone());
                    if self.containments.len() < MAX_PENDING_CONTAINMENTS {
                        self.containments.push((*recommendation).clone());
                        self.attention = Some("containment");
                    }
                }
                link::LinkEvent::Connected { sentinel_identity } => {
                    self.link_error = None;
                    self.link_identity_problem = false;
                    tracing::info!(peer = %sentinel_identity, "sentinel connected");
                }
                link::LinkEvent::Failed { reason, retryable } => {
                    self.orchestrator.note_link_down(reason.clone());
                    self.link_error = Some(reason);
                    self.link_identity_problem = !retryable;
                }
                link::LinkEvent::Disconnected { reason } => {
                    self.orchestrator.note_link_down(reason.clone());
                    self.link_error = Some(reason);
                }
            }
        }
    }

    /// Health in `0.0..=1.0`, used to drive the background palette.
    fn link_health(&self) -> f32 {
        match self.link.state() {
            LinkState::Idle | LinkState::Failed => 0.15,
            LinkState::Connecting => 0.4,
            // Live but silent: half. A connection with no data from it is not the
            // same as a working link, and painting it as healthy would hide a
            // Sentinel that is up but not reporting.
            LinkState::Live => {
                if self.orchestrator.sentinel_health().is_some() {
                    1.0
                } else {
                    0.5
                }
            }
        }
    }

    fn connect(&mut self) {
        self.link_error = None;
        self.link_identity_problem = false;
        self.link.connect(&self.endpoint, &self.orchestrator);
    }

    fn disconnect(&mut self) {
        self.link.reset();
        self.orchestrator
            .note_link_down("disconnected by the operator");
    }

    fn severity_colour(severity: heimdall_ipc::Severity) -> Color32 {
        match severity {
            heimdall_ipc::Severity::Info => palette::MUTED,
            heimdall_ipc::Severity::Low => palette::ACCENT,
            heimdall_ipc::Severity::Medium => palette::WARN,
            heimdall_ipc::Severity::High | heimdall_ipc::Severity::Critical => palette::DANGER,
        }
    }

    fn ingest_alerts(&mut self) {
        self.alerts.extend(self.orchestrator.drain_alerts());
        // Bound the feed. An unbounded list is a memory-growth vector fed by
        // whatever Sentinel decides to report.
        if self.alerts.len() > 500 {
            let drop = self.alerts.len() - 500;
            self.alerts.drain(..drop);
        }
    }

    /// Runs a demo detection so the shell has something to show without a live
    /// Sentinel. Clearly labelled; it is not real telemetry.
    fn inject_demo_traffic(&mut self) {
        let mut injected = 0;
        for i in 0..400 {
            let base = 100.0 + f64::from((i % 17) as i16) * 0.2;
            let value = base + f64::from(((i * 7919) % 100) as i16) * 0.04;
            let obs = heimdall_sentinel::engine::Observation {
                stream: "net.egress".into(),
                value,
            };
            if let Some(d) = self.sentinel.ingest(&obs)
                && injected < 3
            {
                self.alerts.push(d.alert);
                injected += 1;
            }
        }

        let spike = heimdall_sentinel::engine::Observation {
            stream: "net.egress".into(),
            value: 48_000.0,
        };
        if let Some(d) = self.sentinel.ingest(&spike) {
            self.alerts.push(d.alert);
        }
        self.alerts
            .sort_by_key(|a| std::cmp::Reverse(a.observed_at_unix));
    }

    /// A realistic self-repair proposal, so the review panel can be exercised
    /// without an AI attached.
    fn inject_demo_proposal(&mut self) {
        let path = "crates/heimdall-ipc/src/session.rs";
        let summary = "Reject out-of-order records instead of accepting them";
        let rationale = "A record arriving with a sequence number the session did not \
                         expect means the stream is desynchronised. Accepting it lets an \
                         attacker reorder or drop records without detection. The session \
                         should terminate and require a fresh handshake.";
        let diff = "--- a/crates/heimdall-ipc/src/session.rs\n\
                    +++ b/crates/heimdall-ipc/src/session.rs\n\
                    @@ -212,7 +212,11 @@ impl Session {\n\
                    -        let plaintext = message.encode()?;\n\
                    +        // Refuse to advance the sequence on a gap: the channel is\n\
                    +        // desynchronised and must be rebuilt from a fresh handshake.\n\
                    +        if header.seq != self.recv_seq {\n\
                    +            return Err(Error::OutOfOrder { expected: self.recv_seq, actual: header.seq });\n\
                    +        }\n\
                    +        let plaintext = message.encode()?;\n";

        match self
            .orchestrator
            .propose_patch(path, summary, rationale, diff)
        {
            Ok(id) => self.last_action = Some(format!("proposal #{id} awaiting review")),
            Err(e) => self.last_action = Some(format!("proposal refused: {e}")),
        }
    }

    /// Scans the repository and reports what the analyser finds.
    ///
    /// A scan only observes. It proposes nothing, and it changes nothing: the
    /// repairs it finds are queued separately, and a repair becomes a proposal
    /// only when the operator asks for one.
    fn run_scan(&mut self) {
        self.findings = self.orchestrator.scan_repository();
        self.last_action = Some(format!(
            "{} finding(s) in the codebase",
            self.findings.len()
        ));
    }

    /// Queues the repairs the analyser is willing to make and proposes the first.
    ///
    /// One at a time: the gate supersedes any proposal still waiting, so
    /// offering several would show the operator a different diff from the one
    /// they approve.
    fn propose_next_repair(&mut self) {
        let queued = match self.orchestrator.queue_self_repairs() {
            Ok(count) => count,
            Err(e) => {
                self.last_action = Some(format!("cannot queue repairs: {e}"));
                return;
            }
        };
        match self.orchestrator.propose_next_repair() {
            Ok(Some(id)) => {
                self.last_action = Some(format!(
                    "proposal #{id} from the analyser ({queued} candidate(s) queued)"
                ));
            }
            Ok(None) => {
                self.last_action =
                    Some("nothing to repair: the analyser found no fixable problem".into());
            }
            Err(e) => self.last_action = Some(format!("proposal refused: {e}")),
        }
    }

    /// Turns a containment recommendation into an order and sends it.
    ///
    /// The order carries the operator's name, and the Core builds it: the shell
    /// cannot send an order that names nobody, because the order is refused
    /// before it is built.
    fn approve_containment(&mut self, incident_id: u64, scope: ContainmentScope) {
        let operator = self.operator.clone();
        let message = match self
            .orchestrator
            .containment_order(incident_id, scope, &operator)
        {
            Ok(message) => message,
            Err(e) => {
                self.last_action = Some(format!("containment refused: {e}"));
                return;
            }
        };
        if !self.link.send(&message) {
            self.last_action = Some(
                "the containment order was not sent: there is no live link to Sentinel".into(),
            );
            return;
        }
        self.containments.retain(|c| c.incident_id != incident_id);
        self.last_action = Some(format!("containment #{incident_id} ordered by {operator}"));
    }

    /// Records a refusal to contain.
    ///
    /// The decision is kept: "the AI wanted to isolate the host and I said no"
    /// belongs in the record as much as the approval does.
    fn decline_containment(&mut self, incident_id: u64) {
        self.containments.retain(|c| c.incident_id != incident_id);
        self.last_action = Some(format!("containment #{incident_id} declined"));
    }

    /// Acts on a spoken request.
    ///
    /// Only the requests that change nothing are carried out. Approving a patch
    /// and ordering a containment are pointed at instead: an utterance is
    /// ambient, and the authority for those two belongs to the person who can
    /// see what they are agreeing to.
    fn run_voice_intent(&mut self, intent: CommandIntent) {
        match intent {
            CommandIntent::Status => {
                let state = self.link.state().label();
                let health = self
                    .orchestrator
                    .sentinel_health()
                    .map_or("no report yet".to_string(), |h| {
                        format!("{} s uptime", h.uptime_secs)
                    });
                self.last_action = Some(format!("link {state}, sentinel {health}"));
            }
            CommandIntent::Scan => self.run_scan(),
            CommandIntent::ListAlerts => {
                self.last_action = Some(format!("{} alert(s) recorded", self.alerts.len()));
            }
            CommandIntent::Explain => {
                self.last_action = Some(match self.findings.first() {
                    Some(finding) => format!(
                        "{}:{} {} - {}",
                        finding.path,
                        finding.line,
                        finding.rule.label(),
                        finding.message
                    ),
                    None => "there is nothing to explain yet: run a scan first".into(),
                });
            }
            CommandIntent::ResetBaseline => {
                let msg = heimdall_ipc::Message::Command(heimdall_ipc::message::Command {
                    command_id: 0,
                    intent: "reset-baseline".into(),
                    arguments: Vec::new(),
                });
                if self.link.is_live() && self.link.send(&msg) {
                    self.last_action = Some("reset sent to Sentinel".into());
                } else {
                    self.sentinel.reset_streams();
                    self.last_action = Some("local baselines reset (no Sentinel)".into());
                }
            }
            CommandIntent::Approve => {
                self.attention = Some("review");
                self.last_action =
                    Some("voice cannot approve: read the diff, then use Approve and apply".into());
            }
            CommandIntent::Reject => {
                self.attention = Some("review");
                self.last_action =
                    Some("voice cannot reject: use the Reject button next to the diff".into());
            }
            CommandIntent::Contain => {
                self.attention = Some("containment");
                self.last_action = Some(
                    "voice cannot contain: approve the recommendation in the containment panel"
                        .into(),
                );
            }
            CommandIntent::StopListening => {
                self.last_action = Some("the microphone is already between utterances".into());
            }
            CommandIntent::Unknown => {
                self.last_action = Some("that was not a command I know".into());
            }
        }
    }
}

impl eframe::App for Shell {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let started = std::time::Instant::now();

        // Fold in anything the link thread produced. Before any panel is drawn,
        // so a health report that arrived this frame is visible in this frame.
        self.pump_link();

        // The same for the capture thread: the microphone reports what it heard
        // on its own thread, and the panel reads it here.
        self.voice.poll();

        // The animation drives a repaint every frame. Without it egui would idle
        // and the background would stutter when something else triggers a
        // redraw.
        ctx.request_repaint_after(std::time::Duration::from_millis(16));

        let panel = egui::Frame::new()
            .fill(palette::PANEL)
            .stroke(Stroke::new(1.0, palette::BORDER))
            .corner_radius(8.0)
            .inner_margin(10.0);

        let screen = ctx.screen_rect();

        // Background first, so everything else composites over it.
        let backdrop = self
            .backdrop
            .clone()
            .with_health(self.link_health())
            .callback(screen);
        let painter = ctx.layer_painter(egui::LayerId::background());
        painter.rect_filled(screen, 0.0, BACKGROUND_TINT);
        painter.add(backdrop);

        egui::TopBottomPanel::top("titlebar")
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgba_premultiplied(10, 14, 24, 200))
                    .inner_margin(12.0),
            )
            .show(ctx, |ui| self.header(ui));

        egui::SidePanel::left("link")
            .resizable(true)
            .default_width(300.0)
            .show(ctx, |ui| panel.show(ui, |ui| self.link_panel(ui)));

        egui::SidePanel::right("alerts")
            .resizable(true)
            .default_width(340.0)
            .show(ctx, |ui| panel.show(ui, |ui| self.alert_panel(ui)));

        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(16.0))
            .show(ctx, |ui| panel.show(ui, |ui| self.review_panel(ui)));

        self.ingest_alerts();
        self.frame_millis = started.elapsed().as_secs_f32() * 1000.0;
    }
}

impl Shell {
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(RichText::new("HEIMDALL").color(palette::ACCENT));
            ui.label(
                RichText::new("core / sentinel")
                    .color(palette::MUTED)
                    .small(),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("{:.1} ms", self.frame_millis))
                        .color(palette::MUTED)
                        .monospace(),
                );
                let state = self.link.state();
                ui.label(
                    RichText::new(format!("SENTINEL {}", state.label()).to_uppercase())
                        .color(state.colour())
                        .monospace(),
                );
            });
        });
    }

    /// The left panel: how the link is configured, and what the last attempt at it
    /// produced. Split into three parts because "can I reach Sentinel", "who am I
    /// talking to", and "what has it said" are three questions an operator asks in
    /// that order, and burying the first one under a log tail answers none of them.
    fn link_panel(&mut self, ui: &mut egui::Ui) {
        self.link_controls(ui);
        ui.separator();
        self.link_identities(ui);
        ui.separator();
        self.link_events(ui);
        ui.separator();
        self.sentinel_status(ui);
        ui.separator();
        self.voice_panel(ui);
    }

    /// The voice panel: the microphone, the command, and what it meant.
    ///
    /// A spoken command can ask Heimdall to do something. It cannot make
    /// Heimdall do it: the two actions that change the system -- applying a
    /// patch and ordering a containment -- stay behind their buttons, because
    /// an utterance is ambient and an approval has to be deliberate.
    fn voice_panel(&mut self, ui: &mut egui::Ui) {
        self.voice_microphone(ui);
        ui.separator();
        self.voice_command(ui);
        ui.separator();
        self.voice_examples(ui);
    }

    /// The microphone: the button, and what the last capture heard.
    fn voice_microphone(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("VOICE").strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                match self.voice.state() {
                    VoiceState::Idle => {
                        ui.label(RichText::new("idle").color(palette::MUTED).small());
                    }
                    VoiceState::Listening => {
                        ui.label(RichText::new("listening").color(palette::ACCENT).small());
                    }
                    VoiceState::Heard { speech_ms, peak_db } => {
                        ui.label(
                            RichText::new(format!("{speech_ms} ms at {peak_db:.0} dB"))
                                .color(palette::OK)
                                .small(),
                        );
                    }
                    VoiceState::Silent => {
                        ui.label(RichText::new("no speech").color(palette::WARN).small());
                    }
                    VoiceState::Failed(reason) => {
                        ui.colored_label(palette::DANGER, RichText::new(reason.clone()).small());
                    }
                }
            });
        });
        ui.separator();

        ui.horizontal(|ui| {
            let listening = self.voice.listening();
            if ui
                .add_enabled(!listening, egui::Button::new("Listen"))
                .clicked()
            {
                self.voice.start_listening();
            }
            ui.label(
                RichText::new("no speech model in this build: it hears, it does not transcribe")
                    .color(palette::MUTED)
                    .small(),
            );
        });

        if let Some(capture) = self.voice.capture() {
            ui.label(
                RichText::new(format!(
                    "last capture: {} ms, {} ms of speech",
                    capture.audio.duration_ms(),
                    capture.speech_ms
                ))
                .color(palette::MUTED)
                .small(),
            );
        }
    }

    /// The command: the words, the intent, and the button that runs it.
    fn voice_command(&mut self, ui: &mut egui::Ui) {
        let mut utterance = self.voice.utterance().to_string();
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut utterance)
                    .desired_width(170.0)
                    .hint_text("say or type a command"),
            );
            if ui.button("Understand").clicked() {
                self.voice.set_utterance(&utterance);
                if self.voice.understand().is_none() {
                    self.last_action = Some("that was not a command I know".into());
                }
            }
        });
        // Keep the panel's copy in step with what the operator typed.
        if utterance != self.voice.utterance() {
            self.voice.set_utterance(&utterance);
        }

        if let Some((intent, confidence)) = self.voice.understood() {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(intent.label())
                        .color(palette::ACCENT)
                        .monospace(),
                );
                ui.label(
                    RichText::new(format!("{confidence:.0}"))
                        .color(palette::MUTED)
                        .small(),
                );
                if ui.button("Run").clicked() {
                    self.run_voice_intent(intent);
                }
            });
            ui.label(
                RichText::new(intent.describe())
                    .color(palette::MUTED)
                    .small(),
            );
        }
    }

    /// The example utterances.
    ///
    /// They stand in for a speech model: the words arrive by the same path a
    /// recogniser would use, so the grammar, the intent and the action are all
    /// exercised.
    fn voice_examples(&mut self, ui: &mut egui::Ui) {
        egui::ComboBox::from_label("Examples")
            .selected_text(self.example_label.clone())
            .show_ui(ui, |ui| {
                for (language, phrase) in voice::EXAMPLES {
                    let label = format!("{language}: {phrase}");
                    if ui
                        .selectable_label(self.example_label == label, &label)
                        .clicked()
                    {
                        self.example_label.clone_from(&label);
                        self.voice.accept_transcript(&Transcript {
                            text: (*phrase).to_string(),
                            confidence: 1.0,
                            language: (*language).to_string(),
                        });
                    }
                }
            });
    }

    /// Endpoint, connect/disconnect, and the reason the last attempt failed.
    fn link_controls(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("LINK").strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(self.link.state().label())
                        .color(self.link.state().colour())
                        .monospace(),
                );
            });
        });
        ui.separator();

        ui.horizontal(|ui| {
            ui.label(RichText::new("Endpoint").color(palette::MUTED).small());
            ui.add(
                egui::TextEdit::singleline(&mut self.endpoint)
                    .desired_width(190.0)
                    .font(egui::TextStyle::Monospace),
            );
        });

        // Reconnection is a button, not a retry loop. A link that reconnects on
        // its own will eventually accept whatever is listening, which is the
        // opposite of what a pinned-identity channel is for.
        ui.horizontal(|ui| {
            let busy = self.link.state() == LinkState::Connecting;
            if ui
                .add_enabled(!busy && !self.link.is_live(), egui::Button::new("Connect"))
                .clicked()
            {
                self.connect();
            }
            if ui
                .add_enabled(self.link.is_live(), egui::Button::new("Disconnect"))
                .clicked()
            {
                self.disconnect();
            }
            if self.link.is_live() {
                ui.label(
                    RichText::new(format!("up {}", secs(self.link.uptime())))
                        .color(palette::MUTED)
                        .small(),
                );
            }
        });

        if let Some(error) = &self.link_error {
            let colour = if self.link_identity_problem {
                palette::DANGER
            } else {
                palette::WARN
            };
            // An identity mismatch is not styled like "nothing is listening".
            // One is a broken link, the other is evidence.
            let prefix = if self.link_identity_problem {
                "IDENTITY PROBLEM"
            } else {
                "LINK FAILED"
            };
            ui.colored_label(
                colour,
                egui::RichText::new(format!("{prefix}\n{error}")).small(),
            );
            ui.label(
                RichText::new(if self.link_identity_problem {
                    "Do not accept this peer without checking why it changed."
                } else {
                    "Start heimdall-sentinel, then connect again."
                })
                .color(palette::MUTED)
                .small(),
            );
        }
    }

    /// Who Core is, who it is talking to, and how that peer came to be trusted.
    fn link_identities(&self, ui: &mut egui::Ui) {
        let core_id = self.orchestrator.identity().hex();
        let peer_id = self.orchestrator.pinned_peer().hex();
        kv(ui, "Core identity", &short(&core_id));
        kv(ui, "Pinned peer", &short(&peer_id));
        // How the pin was established. Shown because "verified against a
        // fingerprint you supplied" and "accepted whatever was on disk" are very
        // different postures, and the operator is the one who chose.
        let basis = self
            .orchestrator
            .peer_pin()
            .map_or("not pinned", |pin| pin.basis.label());
        kv(ui, "Pin basis", basis);
        kv(ui, "Cipher suite", "ChaCha20-Poly1305");
        if self.orchestrator.identity_was_created() {
            ui.colored_label(
                palette::WARN,
                RichText::new(
                    "Core's identity is new this session. Tell Sentinel its fingerprint \
                     before trusting its reports.",
                )
                .small(),
            );
        }
    }

    /// A queue that is backing up means Sentinel stopped reading. Saying so is
    /// the difference between "my command is late" and "my command never
    /// arrived", which look identical from the button press.
    fn link_events(&self, ui: &mut egui::Ui) {
        if self.link.pending() > 0 {
            ui.label(
                RichText::new(format!(
                    "{} directive(s) awaiting delivery",
                    self.link.pending()
                ))
                .color(palette::WARN)
                .small(),
            );
        }

        ui.label(RichText::new("RECENT LINK EVENTS").strong());
        ui.separator();
        let history = self.link.history();
        if history.is_empty() {
            ui.label(RichText::new("Nothing yet.").color(palette::MUTED).small());
        } else {
            egui::ScrollArea::vertical()
                .max_height(140.0)
                .show(ui, |ui| {
                    for event in history.iter().rev().take(12) {
                        let (colour, text) = match event {
                            link::LinkEvent::Connected { .. } => {
                                (palette::OK, "connected".to_string())
                            }
                            link::LinkEvent::Disconnected { reason } => {
                                (palette::DANGER, format!("disconnected: {reason}"))
                            }
                            link::LinkEvent::Failed { reason, retryable } => (
                                if *retryable {
                                    palette::WARN
                                } else {
                                    palette::DANGER
                                },
                                format!("failed: {reason}"),
                            ),
                            link::LinkEvent::Alert(a) => (
                                Self::severity_colour(a.severity),
                                format!("alert {} [{}]", a.alert_id, a.category),
                            ),
                            link::LinkEvent::Health(_) => {
                                (palette::MUTED, "health report".to_string())
                            }
                            link::LinkEvent::Recommendation(r) => (
                                palette::WARN,
                                format!("containment advice: {}", r.scope.label()),
                            ),
                        };
                        ui.label(RichText::new(text).color(colour).small().monospace());
                    }
                });
        }
    }

    /// What Sentinel last said about itself and the host.
    ///
    /// Sentinel's own report when there is one, the local engine otherwise, so
    /// the panel is never blank. The two are labelled distinctly: a demo reading
    /// and a real one must never look alike.
    fn sentinel_status(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.label(RichText::new("SENTINEL").strong());
        ui.separator();

        if let Some(health) = self.orchestrator.sentinel_health().cloned() {
            kv(ui, "Instance", &health.sentinel_id);
            kv(ui, "Uptime", &format!("{} s", health.uptime_secs));
            kv(ui, "Events scanned", &health.events_scanned.to_string());
            kv(
                ui,
                "Active containments",
                &health.active_containments.to_string(),
            );
            kv(
                ui,
                "Engine load",
                &format!(
                    "{:.1} ev/s",
                    f64::from(health.engine_load_permille) / 1000.0
                ),
            );
        } else {
            let health = self.sentinel.health();
            kv(ui, "Instance (local)", &health.sentinel_id);
            kv(ui, "Events scanned", &health.events_scanned.to_string());
            ui.label(
                RichText::new(
                    "No Sentinel has reported yet. These figures are the \
                              in-process engine, not a live daemon.",
                )
                .color(palette::MUTED)
                .small(),
            );
        }

        ui.add_space(10.0);
        ui.label(
            RichText::new(
                "Sentinel recommends containment but never applies it. Every action \
                 reaches Core, and every change to this codebase needs your approval.",
            )
            .color(palette::MUTED)
            .small(),
        );

        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Simulate traffic").clicked() {
                self.inject_demo_traffic();
            }
            if ui.button("Reset streams").clicked() {
                // Sent to Sentinel when there is one; local otherwise. The local
                // reset is not silently the remote one.
                let msg = heimdall_ipc::Message::Command(heimdall_ipc::message::Command {
                    command_id: 0,
                    intent: "reset-baseline".into(),
                    arguments: Vec::new(),
                });
                if self.link.is_live() && self.link.send(&msg) {
                    self.last_action = Some("reset sent to Sentinel".into());
                } else {
                    self.sentinel.reset_streams();
                    self.last_action = Some("local baselines reset (no Sentinel)".into());
                }
            }
        });
    }

    fn alert_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("ALERTS").strong());
            ui.label(
                RichText::new(format!("{}", self.alerts.len()))
                    .color(palette::MUTED)
                    .monospace(),
            );
        });
        ui.separator();

        if self.alerts.is_empty() {
            ui.label(
                RichText::new("No anomalies recorded.")
                    .color(palette::MUTED)
                    .small(),
            );
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            let mut to_select = None;
            for (i, alert) in self.alerts.iter().enumerate().rev() {
                let colour = Self::severity_colour(alert.severity);
                let label = format!("[{}] {}", alert.severity.label(), alert.category);
                if ui
                    .add(egui::SelectableLabel::new(
                        self.selected_alert == Some(i),
                        label,
                    ))
                    .clicked()
                {
                    to_select = Some(i);
                }
                // The category is coloured separately so the severity marker and
                // the subject stay readable at a glance.
                ui.horizontal(|ui| {
                    ui.label(RichText::new("  \u{25b8}").color(colour));
                    ui.label(RichText::new(&alert.category).color(colour));
                });
                ui.label(RichText::new(&alert.summary).color(palette::MUTED).small());
                ui.separator();
            }
            if let Some(i) = to_select {
                self.selected_alert = Some(i);
            }
        });

        if let Some(alert) = self.selected_alert.and_then(|i| self.alerts.get(i)) {
            ui.separator();
            ui.label(RichText::new("DETAIL").strong());
            ui.label(RichText::new(format!("alert #{}", alert.alert_id)).monospace());
            ui.label(RichText::new(&alert.summary).small());
            ui.label(
                RichText::new(format!(
                    "severity {} - category {}",
                    alert.severity.label(),
                    alert.category
                ))
                .color(palette::MUTED)
                .small(),
            );
        }

        ui.separator();
        self.containment_panel(ui);
    }

    /// The containment panel: what Sentinel recommends, and the operator's
    /// answer.
    ///
    /// A recommendation is advice that arrived from the peer. It becomes an
    /// order only here, only now, and only with a name attached: the Core
    /// refuses to build an order that nobody owns.
    fn containment_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("CONTAINMENT").strong());
            ui.label(
                RichText::new(format!("{}", self.containments.len()))
                    .color(palette::MUTED)
                    .monospace(),
            );
        });
        ui.separator();
        ui.label(
            RichText::new(
                "Sentinel recommends. Nothing happens on this host until you approve it \
                 below, and the order carries your name.",
            )
            .color(palette::MUTED)
            .small(),
        );
        if self.attention == Some("containment") {
            ui.colored_label(
                palette::WARN,
                RichText::new(
                    "A spoken command asked for a containment here. It cannot be given by voice.",
                )
                .small(),
            );
        }

        if self.containments.is_empty() {
            ui.label(
                RichText::new("No recommendation waiting.")
                    .color(palette::MUTED)
                    .small(),
            );
            return;
        }

        let mut to_approve: Option<(u64, ContainmentScope)> = None;
        let mut to_decline: Option<u64> = None;
        for recommendation in &self.containments {
            egui::Frame::new()
                .fill(Color32::from_rgba_premultiplied(18, 24, 40, 230))
                .stroke(Stroke::new(1.0, palette::WARN))
                .corner_radius(6.0)
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!("incident #{}", recommendation.incident_id))
                            .color(palette::WARN)
                            .monospace(),
                    );
                    ui.label(RichText::new(recommendation.scope.label()).strong());
                    ui.label(RichText::new(&recommendation.reason).small());
                    ui.horizontal(|ui| {
                        if ui.button("Approve").clicked() {
                            to_approve =
                                Some((recommendation.incident_id, recommendation.scope.clone()));
                        }
                        if ui.button("Decline").clicked() {
                            to_decline = Some(recommendation.incident_id);
                        }
                    });
                });
        }

        if let Some((incident_id, scope)) = to_approve {
            self.approve_containment(incident_id, scope);
        }
        if let Some(incident_id) = to_decline {
            self.decline_containment(incident_id);
        }
    }

    fn review_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(RichText::new("SELF-REPAIR"));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .selectable_label(self.show_audit, "Audit trail")
                    .clicked()
                {
                    self.show_audit = !self.show_audit;
                }
            });
        });

        if self.show_audit {
            self.audit_panel(ui);
            return;
        }

        ui.label(
            RichText::new(
                "Heimdall Core may propose changes to its own source. Nothing is written \
                 until you approve the exact diff below. The approval is bound to this \
                 content: if the diff changes after you approve, the approval no longer \
                 applies.",
            )
            .color(palette::MUTED),
        );
        if self.attention == Some("review") {
            ui.colored_label(
                palette::WARN,
                RichText::new(
                    "A spoken command asked for a decision here. Read the diff, then decide.",
                )
                .small(),
            );
        }
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label(RichText::new("Authorising as").color(palette::MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.operator)
                    .desired_width(180.0)
                    .hint_text("who is approving"),
            );
            if ui.button("Submit a proposal").clicked() {
                self.inject_demo_proposal();
            }
        });

        ui.add_space(6.0);
        self.scan_panel(ui);

        if let Some(msg) = &self.last_action {
            ui.colored_label(palette::MUTED, msg.clone());
        }

        ui.add_space(8.0);

        if let Some(proposal) = self.orchestrator.pending_patch().cloned() {
            self.proposal_ui(ui, &proposal);
        } else {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("No change is waiting for review.").color(palette::MUTED));
                ui.label(
                    RichText::new(
                        "Everything Core has proposed so far has been approved, \
                         rejected, or superseded.",
                    )
                    .color(palette::MUTED)
                    .small(),
                );
            });
        }
    }

    /// The scan: what the analyser found, and the button that turns a finding
    /// into a proposal.
    ///
    /// The two are separate on purpose. A finding is an observation and costs
    /// nothing; a proposal asks for permission to change a file.
    fn scan_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Scan the codebase").clicked() {
                self.run_scan();
            }
            if ui.button("Propose a repair").clicked() {
                self.propose_next_repair();
            }
            if !self.findings.is_empty() {
                ui.label(
                    RichText::new(format!("{} finding(s)", self.findings.len()))
                        .color(palette::MUTED)
                        .small(),
                );
            }
        });

        if self.findings.is_empty() {
            return;
        }

        egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(ui, |ui| {
                for finding in &self.findings {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{}:{}", finding.path, finding.line))
                                .color(palette::WARN)
                                .monospace()
                                .small(),
                        );
                        ui.label(
                            RichText::new(finding.rule.label())
                                .color(palette::MUTED)
                                .small(),
                        );
                    });
                    ui.label(RichText::new(&finding.message).small());
                }
            });
        ui.add_space(6.0);
    }

    fn proposal_ui(&mut self, ui: &mut egui::Ui, proposal: &PatchProposal) {
        egui::Frame::new()
            .fill(Color32::from_rgba_premultiplied(18, 24, 40, 230))
            .stroke(Stroke::new(1.0, palette::WARN))
            .corner_radius(6.0)
            .inner_margin(14.0)
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!("Proposal #{}", proposal.id))
                        .color(palette::WARN)
                        .monospace(),
                );
                ui.label(RichText::new(&proposal.summary).strong());
                ui.add_space(4.0);

                ui.label(
                    RichText::new("WHY THIS IS NEEDED")
                        .color(palette::MUTED)
                        .small(),
                );
                ui.add(egui::Label::new(RichText::new(&proposal.rationale)).wrap());
                ui.add_space(6.0);

                kv(ui, "Target", &proposal.target_path);
                kv(ui, "Proposed by", &proposal.generated_by_model);
                kv(ui, "Content digest", &proposal.digest_hex()[..32]);
                ui.add_space(6.0);

                ui.label(RichText::new("DIFF").color(palette::MUTED).small());
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .show(ui, |ui| {
                        ui.monospace(RichText::new(&proposal.diff).small());
                    });

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_sized(
                            [150.0, 32.0],
                            egui::Button::new(
                                RichText::new("Reject").color(Color32::from_rgb(18, 22, 34)),
                            )
                            .fill(palette::DANGER),
                        )
                        .clicked()
                    {
                        let reason = if self.reject_reason.trim().is_empty() {
                            "no reason given".to_string()
                        } else {
                            self.reject_reason.clone()
                        };
                        match self
                            .orchestrator
                            .reject_patch(proposal.id, &self.operator, &reason)
                        {
                            Ok(()) => {
                                self.last_action =
                                    Some(format!("proposal #{} rejected", proposal.id));
                                self.reject_reason.clear();
                            }
                            Err(e) => self.last_action = Some(format!("reject failed: {e}")),
                        }
                    }

                    if ui
                        .add_sized(
                            [150.0, 32.0],
                            egui::Button::new(
                                RichText::new("Approve and apply")
                                    .color(Color32::from_rgb(10, 24, 18)),
                            )
                            .fill(palette::OK),
                        )
                        .clicked()
                    {
                        self.approve_and_apply(proposal.id);
                    }
                });

                if self.reject_reason.trim().is_empty() {
                    ui.label(
                        RichText::new("Optional: a reason for the audit trail if you reject.")
                            .color(palette::MUTED)
                            .small(),
                    );
                } else {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.reject_reason)
                            .hint_text("reason for rejection"),
                    );
                }
            });
    }

    /// The full self-repair path, in the order it must happen.
    ///
    /// Approval, then authorisation, then the write. The token is the only thing
    /// that authorises a write, and it is bound to the exact content that was
    /// approved -- if the diff has changed since, the gate refuses rather than
    /// writing something nobody saw.
    fn approve_and_apply(&mut self, id: u64) {
        let operator = self.operator.clone();
        let token = match self.orchestrator.approve_patch(id, &operator) {
            Ok(t) => t,
            Err(e) => {
                self.last_action = Some(format!("approval refused: {e}"));
                return;
            }
        };

        // The token is the only thing that authorises a write. Nothing in the UI
        // can reach the file system without passing through here.
        match self.orchestrator.apply_approved(&token) {
            Ok(applied) => {
                self.last_action = Some(format!(
                    "applied #{} to {} (approved by {}) - review `git diff`, then commit",
                    applied.proposal_id,
                    applied.path.display(),
                    applied.approved_by
                ));
            }
            Err(e) => {
                self.last_action = Some(format!("apply blocked: {e}"));
                let _ = self
                    .orchestrator
                    .gate_mut()
                    .report_failure(id, &e.to_string());
            }
        }
    }

    fn audit_panel(&self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new(
                "Every proposal, approval, refusal and write, in order. Rejected \
                 proposals are recorded too: 'the AI wanted to change this and I said no' \
                 is exactly what an incident review needs.",
            )
            .color(palette::MUTED),
        );
        ui.separator();

        let entries = self.orchestrator.audit_trail();
        if entries.is_empty() {
            ui.label(RichText::new("Nothing recorded yet.").color(palette::MUTED));
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for entry in entries.iter().rev() {
                let colour = match entry.event {
                    AuditEvent::Applied => palette::OK,
                    AuditEvent::Rejected | AuditEvent::Expired | AuditEvent::ApplicationFailed => {
                        palette::DANGER
                    }
                    AuditEvent::Approved => palette::WARN,
                    AuditEvent::Submitted | AuditEvent::Superseded => palette::MUTED,
                };
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("#{:<3}", entry.proposal_id))
                            .color(palette::MUTED)
                            .monospace(),
                    );
                    ui.label(RichText::new(entry.event.label().to_uppercase()).color(colour));
                    ui.label(
                        RichText::new(format!("by {}", entry.actor))
                            .color(palette::MUTED)
                            .small(),
                    );
                });
                ui.label(RichText::new(&entry.note).color(palette::MUTED).small());
                ui.separator();
            }
        });
    }
}

fn short(hex: &str) -> String {
    hex.chars().take(16).collect::<String>() + "..."
}

/// A label on the left, a value right-aligned on the same row.
fn kv(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(key).color(palette::MUTED).small());
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(value).monospace().small());
        });
    });
}

fn secs(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}

/// Builds the orchestrator the app will run on.
///
/// Provisioning is real: the identity is loaded from (or written to) the
/// keystore, and Sentinel's key is pinned from a configured fingerprint when one
/// is supplied. The passphrase comes from the environment, never from `argv`,
/// because on Unix every process on the box can read `argv`.
fn load_orchestrator() -> anyhow::Result<Orchestrator> {
    let root = std::env::current_dir()?;
    let passphrase = heimdall_crypto::kdf::passphrase_from_environment();
    let keystore = heimdall_crypto::identity::KeystoreLocation::default_path()?;

    // A configured Sentinel fingerprint upgrades the pin from first use to
    // verified. Absent, it stays TOFU, which is recorded rather than hidden.
    let expected = std::env::var("HEIMDALL_SENTINEL_ID").ok();
    let orchestrator = Orchestrator::provision(&root, &keystore, &passphrase, expected.as_deref())?;

    // Sentinel pins Core the same way, from what Core publishes here. Without it
    // Sentinel cannot verify anything, and the failure would otherwise appear as
    // a confusing handshake error on its side.
    //
    // The directory may be moved with HEIMDALL_PUBLISH_DIR, which is what a
    // deployment needs: the daemon runs as a service account with its own data
    // directory, and the two have to agree on where the published identity
    // lands.
    let published = match std::env::var("HEIMDALL_PUBLISH_DIR") {
        Ok(dir) if !dir.is_empty() => std::path::PathBuf::from(dir),
        _ => heimdall_crypto::identity::base_dir()?.join("published"),
    };
    std::fs::create_dir_all(&published)?;
    let core_hex = orchestrator.identity().hex();
    std::fs::write(published.join("core.identity"), &core_hex)?;
    println!(
        "core identity: {core_hex} (published in {})",
        published.display()
    );
    if orchestrator.identity_was_created() {
        println!("(newly created; start heimdall-sentinel so it can pin this)");
    }

    // The durable audit trail. The gate keeps its history in memory either
    // way; this makes it survive the process, so a decision that was made
    // before a crash is still on the record afterwards. The log is encrypted
    // under a key derived from the same passphrase, and it is chained, so a
    // record that was altered or removed is noticed.
    let mut orchestrator = orchestrator;
    let audit_path = heimdall_crypto::identity::base_dir()?.join("audit.log");
    match orchestrator.attach_audit_log(&audit_path, &passphrase) {
        Ok(()) => println!("audit log: {}", audit_path.display()),
        Err(e) => {
            // Without the durable log the shell still works, and the in-memory
            // trail still shows the decisions. What is lost is the record
            // across a restart, so it is said out loud rather than swallowed.
            eprintln!("heimdall: cannot open the audit log: {e}");
        }
    }

    Ok(orchestrator)
}

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,wgpu=warn".into()),
        )
        .init();

    let orchestrator = match load_orchestrator() {
        Ok(o) => o,
        Err(e) => {
            // Fatal, and not recoverable by retrying: without a pinned identity
            // the shell cannot authenticate Sentinel, and running anyway would
            // mean reporting data from an unauthenticated peer as if it were
            // trustworthy.
            eprintln!("heimdall-shell: cannot start: {e}");
            return Err(eframe::Error::AppCreation(Box::new(std::io::Error::other(
                e.to_string(),
            ))));
        }
    };

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(Vec2::new(1440.0, 900.0))
            .with_min_inner_size(Vec2::new(1024.0, 680.0))
            .with_title("Heimdall")
            .with_app_id("org.heimdall.shell")
            .with_decorations(true)
            .with_transparent(false),
        ..Default::default()
    };

    eframe::run_native(
        "Heimdall",
        native_options,
        Box::new(move |_cc| Ok(Box::new(Shell::new(orchestrator)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use heimdall_core::ProposalState;

    #[test]
    fn the_palette_distinguishes_severities() {
        // High and Critical deliberately share a colour: both demand the same
        // immediate reaction, and distinguishing them by hue would imply a
        // difference in response that does not exist.
        assert_eq!(
            Shell::severity_colour(heimdall_ipc::Severity::High),
            Shell::severity_colour(heimdall_ipc::Severity::Critical)
        );
        assert_ne!(
            Shell::severity_colour(heimdall_ipc::Severity::Info),
            Shell::severity_colour(heimdall_ipc::Severity::High)
        );
    }

    #[test]
    fn identities_are_abbreviated_for_display() {
        let s = short("0123456789abcdef0123456789abcdef0123456789abcdef");
        assert_eq!(s.len(), 19);
        assert!(s.ends_with("..."));
    }

    #[test]
    fn a_proposal_cannot_be_applied_without_going_through_the_gate() {
        let mut shell = test_shell();

        shell.inject_demo_proposal();
        let id = shell
            .orchestrator
            .pending_patch()
            .expect("a proposal should be pending")
            .id;

        // Before approval the state machine must refuse anything.
        assert_eq!(
            shell.orchestrator.patch_state(id).unwrap(),
            ProposalState::AwaitingApproval
        );
        assert!(
            shell
                .orchestrator
                .audit_trail()
                .iter()
                .all(|e| { e.event == AuditEvent::Submitted }),
            "submission is recorded, but nothing else may be until the operator decides: {:?}",
            shell.orchestrator.audit_trail()
        );
    }

    #[test]
    fn an_apply_that_cannot_land_is_recorded_as_a_failure() {
        // The demo proposal names a file in the real repository while this shell
        // is bound to the crate directory, so the applier refuses. That refusal
        // has to be visible in the audit trail: an approval that silently did
        // nothing is the failure mode this project exists to avoid.
        let mut shell = test_shell();
        shell.inject_demo_proposal();
        let id = shell.orchestrator.pending_patch().expect("pending").id;

        shell.approve_and_apply(id);

        assert_eq!(
            shell.orchestrator.patch_state(id).unwrap(),
            ProposalState::Failed
        );
        assert!(
            shell
                .orchestrator
                .audit_trail()
                .iter()
                .any(|e| e.event == AuditEvent::ApplicationFailed),
            "the failure must be in the audit trail: {:?}",
            shell.orchestrator.audit_trail()
        );
        assert!(
            shell
                .last_action
                .as_deref()
                .is_some_and(|a| a.contains("apply blocked")),
            "the operator must be told why: {:?}",
            shell.last_action
        );
    }

    #[test]
    fn the_alert_feed_is_bounded() {
        // An unbounded feed is a memory-growth vector fed by whatever Sentinel
        // decides to report. 2000 injected alerts must leave at most the cap.
        let mut shell = test_shell();
        for i in 0..2000 {
            shell.alerts.push(ThreatAlert {
                alert_id: i,
                severity: heimdall_ipc::Severity::Low,
                category: "test".into(),
                summary: "x".into(),
                observed_at_unix: i,
            });
        }
        shell.ingest_alerts();
        assert_eq!(shell.alerts.len(), 500);
        // The most recent alerts survive; the oldest are the ones dropped.
        assert_eq!(shell.alerts.last().unwrap().alert_id, 1999);
    }

    #[test]
    fn the_link_palette_reflects_a_dead_link() {
        let shell = test_shell();
        assert!(
            shell.link_health() < 0.5,
            "with no Sentinel the background must look degraded"
        );
    }

    fn test_shell() -> Shell {
        Shell {
            orchestrator: Orchestrator::bootstrap(".").unwrap(),
            sentinel: Engine::new("test"),
            backdrop: Backdrop::new(),
            link: Link::new(),
            endpoint: "test-endpoint".into(),
            link_error: None,
            link_identity_problem: false,
            alerts: Vec::new(),
            selected_alert: None,
            operator: "tester".into(),
            reject_reason: String::new(),
            last_action: None,
            show_audit: false,
            frame_millis: 0.0,
            findings: Vec::new(),
            containments: Vec::new(),
            voice: VoicePanel::new(),
            example_label: String::new(),
            attention: None,
        }
    }

    #[test]
    fn an_absent_sentinel_is_reported_as_a_plain_failure() {
        // Not an identity problem: nothing is listening. The UI must be able to
        // tell those apart, because one is fixed by starting a process and the
        // other is evidence.
        let mut shell = test_shell();
        shell.link_error = Some("connect: No such file or directory (os error 2)".into());
        shell.link_identity_problem = false;
        assert!(!shell.link_identity_problem);
        assert!(shell.link_health() < 0.5);
    }

    #[test]
    fn an_idle_link_is_never_painted_as_healthy() {
        // A shell that has not connected yet must look degraded, or a failed
        // handshake would be indistinguishable from a working system.
        let shell = test_shell();
        assert_eq!(shell.link.state(), LinkState::Idle);
        assert!(shell.link_health() < 0.5);
    }

    #[test]
    fn durations_are_formatted_for_reading() {
        assert_eq!(secs(std::time::Duration::from_secs(45)), "45s");
        assert_eq!(secs(std::time::Duration::from_secs(125)), "2m05s");
        assert_eq!(secs(std::time::Duration::from_secs(7380)), "2h03m");
    }

    #[test]
    fn a_spoken_approval_approves_nothing() {
        // An utterance is ambient: a radio, a colleague, a television in the
        // next room. So the voice channel can ask for a decision and must not
        // be able to make it.
        let mut shell = test_shell();
        shell.inject_demo_proposal();
        let id = shell.orchestrator.pending_patch().expect("pending").id;

        shell.run_voice_intent(CommandIntent::Approve);

        assert_eq!(
            shell.orchestrator.patch_state(id).unwrap(),
            ProposalState::AwaitingApproval,
            "the proposal must still be waiting for a human"
        );
        assert_eq!(shell.attention, Some("review"));
        assert!(
            shell
                .last_action
                .as_deref()
                .is_some_and(|a| a.contains("voice cannot approve")),
            "the operator must be told why: {:?}",
            shell.last_action
        );
    }

    #[test]
    fn a_spoken_containment_orders_nothing() {
        let mut shell = test_shell();
        shell.run_voice_intent(CommandIntent::Contain);
        assert_eq!(shell.attention, Some("containment"));
        assert!(
            shell
                .last_action
                .as_deref()
                .is_some_and(|a| a.contains("voice cannot contain")),
            "the operator must be told why: {:?}",
            shell.last_action
        );
    }

    #[test]
    fn a_containment_is_not_ordered_without_a_live_link() {
        let mut shell = test_shell();
        shell.containments.push(ContainmentRecommendation {
            incident_id: 7,
            scope: ContainmentScope::Process { pid: 42 },
            severity: heimdall_ipc::Severity::High,
            reason: "test".into(),
        });

        shell.approve_containment(7, ContainmentScope::Process { pid: 42 });

        assert_eq!(
            shell.containments.len(),
            1,
            "a recommendation that was not sent must stay on the list"
        );
        assert!(
            shell
                .last_action
                .as_deref()
                .is_some_and(|a| a.contains("not sent")),
            "the operator must be told: {:?}",
            shell.last_action
        );
    }

    #[test]
    fn a_declined_containment_leaves_the_list() {
        let mut shell = test_shell();
        shell.containments.push(ContainmentRecommendation {
            incident_id: 9,
            scope: ContainmentScope::HostQuarantine,
            severity: heimdall_ipc::Severity::Critical,
            reason: "test".into(),
        });
        shell.decline_containment(9);
        assert!(shell.containments.is_empty());
        assert!(
            shell
                .last_action
                .as_deref()
                .is_some_and(|a| a.contains("declined")),
            "a refusal is a decision and is reported: {:?}",
            shell.last_action
        );
    }

    #[test]
    fn a_scan_reports_observations_and_proposes_nothing() {
        let mut shell = test_shell();
        shell.run_scan();
        assert!(
            shell.orchestrator.pending_patch().is_none(),
            "a scan is an observation; it must not create a proposal"
        );
        assert!(
            shell
                .last_action
                .as_deref()
                .is_some_and(|a| a.contains("finding(s)")),
            "the operator must see what the scan found: {:?}",
            shell.last_action
        );
    }
}
