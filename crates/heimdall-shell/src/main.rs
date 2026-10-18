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

mod backdrop;

use egui::{Align, Color32, Layout, RichText, Stroke, Vec2};

use heimdall_core::{AuditEvent, Orchestrator, PatchProposal};
use heimdall_ipc::message::ThreatAlert;
use heimdall_sentinel::Engine;

use backdrop::{BACKGROUND_TINT, Backdrop};

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
}

impl Shell {
    fn new() -> anyhow::Result<Self> {
        let repository_root = std::env::current_dir()?;
        let orchestrator = Orchestrator::bootstrap(&repository_root)?;
        let sentinel = Engine::new(heimdall_sentinel::DEFAULT_SENTINEL_ID);

        Ok(Self {
            orchestrator,
            sentinel,
            backdrop: Backdrop::new(),
            alerts: Vec::new(),
            selected_alert: None,
            operator: "local-operator".into(),
            reject_reason: String::new(),
            last_action: None,
            show_audit: false,
            frame_millis: 0.0,
        })
    }

    /// Health in `0.0..=1.0`, used to drive the background palette.
    fn link_health(&self) -> f32 {
        let status = self.orchestrator.link_status();
        if !status.connected {
            return 0.15;
        }
        match &status.last_health {
            Some(_) => 1.0,
            None => 0.5,
        }
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
}

impl eframe::App for Shell {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let started = std::time::Instant::now();

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
                let status = self.orchestrator.link_status();
                let (label, colour) = if status.connected {
                    ("LINK ESTABLISHED", palette::OK)
                } else {
                    ("NO SENTINEL", palette::DANGER)
                };
                ui.label(RichText::new(label).color(colour).monospace());
            });
        });
    }

    fn link_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.label(RichText::new("LINK").strong());
        ui.separator();

        let core_id = self.orchestrator.identity().hex();
        let peer_id = self.orchestrator.pinned_peer().hex();
        kv(ui, "Core identity", &short(&core_id));
        kv(ui, "Pinned peer", &short(&peer_id));
        kv(
            ui,
            "Cipher suite",
            if self.orchestrator.link_status().connected {
                "ChaCha20-Poly1305"
            } else {
                "-"
            },
        );

        ui.add_space(8.0);
        ui.label(RichText::new("SENTINEL").strong());
        ui.separator();

        let health = self.sentinel.health();
        kv(ui, "Instance", &health.sentinel_id);
        kv(ui, "Uptime", &format!("{} s", health.uptime_secs));
        kv(ui, "Events scanned", &health.events_scanned.to_string());
        kv(ui, "Containments", &health.active_containments.to_string());
        kv(
            ui,
            "Engine load",
            &format!(
                "{:.1} ev/s",
                f64::from(health.engine_load_permille) / 1000.0
            ),
        );

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
                self.sentinel.reset_streams();
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
        match self.orchestrator.authorise_application(&token) {
            Ok(app) => {
                self.last_action = Some(format!(
                    "authorised #{} on {} (approved by {})",
                    app.id, app.target_path, app.approved_by
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

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,wgpu=warn".into()),
        )
        .init();

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
        Box::new(|_cc| Ok(Box::new(Shell::new()?))),
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

        shell.approve_and_apply(id);
        assert_eq!(
            shell.orchestrator.patch_state(id).unwrap(),
            ProposalState::Applied
        );
        assert!(
            shell
                .orchestrator
                .audit_trail()
                .iter()
                .any(|e| e.event == AuditEvent::Applied)
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
            alerts: Vec::new(),
            selected_alert: None,
            operator: "tester".into(),
            reject_reason: String::new(),
            last_action: None,
            show_audit: false,
            frame_millis: 0.0,
        }
    }
}
