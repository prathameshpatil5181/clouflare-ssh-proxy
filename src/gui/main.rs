//! cfssh-gui — the Windows-first desktop app around the same engine the CLI
//! uses. One window: fill the tunnel target (+ optional Access token), click
//! Connect, and point IntelliJ/ssh at the shown local host:port. Everything is
//! user-scope: config in %APPDATA%, default bind 127.0.0.1:22022, no elevated
//! rights, no installer.
//!
//! Same crate, same pump: the GUI drives `cfssh_proxy::engine` in-process.

// No console window for release builds on Windows; debug builds keep stderr.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod tray;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cfssh_proxy as cfp;
use cfssh_proxy::engine::{self, ForwarderConfig, ForwarderEvent};
use cfssh_proxy::known_hosts::{self, HostPort};
use cfssh_proxy::subcommands::{learn_and_pin, TrustOutcome};
use eframe::egui;

const LOG_CAPACITY: usize = 1000;

/// Shared log ring buffer, fed by the tracing subscriber.
type LogRing = Arc<Mutex<VecDeque<String>>>;

fn main() -> eframe::Result {
    cfp::install_crypto_provider();
    init_log_ring();

    // Renderer selection: WSLg's EGL/GL path can lose the font texture
    // (layout renders, glyphs don't). wgpu (Vulkan — lavapipe on WSLg) works
    // there; on real Windows both work. CFSSH_RENDERER=wgpu|glow overrides.
    let renderer = match std::env::var("CFSSH_RENDERER").as_deref() {
        Ok("wgpu") => eframe::Renderer::Wgpu,
        Ok("glow") => eframe::Renderer::Glow,
        _ => {
            if std::env::var_os("WSL_DISTRO_NAME").is_some() || std::env::var_os("WSLENV").is_some()
            {
                eframe::Renderer::Wgpu // WSLg fallback
            } else {
                eframe::Renderer::Glow // native Windows default
            }
        }
    };
    let options = eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([580.0, 460.0])
            .with_min_inner_size([480.0, 380.0])
            .with_title("cfssh-proxy"),
        ..Default::default()
    };

    let settings = cfp::gui_settings::GuiSettings::load().unwrap_or_else(|e| {
        eprintln!("cfssh-gui: settings not loaded ({e}); starting fresh");
        Default::default()
    });

    eframe::run_native(
        "cfssh-proxy",
        options,
        Box::new(move |_cc| Ok(Box::new(App::new(settings)))),
    )
}

struct LogSink(LogRing);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSinkWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogSinkWriter(self.0.clone())
    }
}

struct LogSinkWriter(LogRing);

impl std::io::Write for LogSinkWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf).trim_end().to_string();
        if !text.is_empty() {
            let mut ring = self.0.lock().unwrap();
            ring.push_back(text);
            while ring.len() > LOG_CAPACITY {
                ring.pop_front();
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_log_ring() {
    let ring: LogRing = Arc::new(Mutex::new(VecDeque::new()));
    // Store the global ring in a OnceCell-ish holder: the App reads it through
    // the same Arc by creating it first and passing it down.
    LOG.with(|cell| *cell.borrow_mut() = Some(ring.clone()));
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(LogSink(ring))
        .without_time()
        .try_init();
}

// The ring is created in init and shared with the App through this cell.
thread_local! {
    static LOG: std::cell::RefCell<Option<LogRing>> = const { std::cell::RefCell::new(None) };
}

fn take_log_ring() -> LogRing {
    LOG.with(|cell| cell.borrow().clone().unwrap_or_default())
}

#[derive(Debug, Clone, Default, PartialEq)]
enum Status {
    #[default]
    Disconnected,
    Listening {
        addr: std::net::SocketAddr,
    },
    Stopping,
}

// Trust work runs on the shared tokio runtime; the UI polls this.
struct TrustJob {
    rx: tokio::sync::mpsc::UnboundedReceiver<Result<TrustOutcome, String>>,
    running: bool,
}

struct EngineHandle {
    events: tokio::sync::mpsc::UnboundedReceiver<ForwarderEvent>,
    shutdown: tokio::sync::watch::Sender<bool>,
    sessions: usize,
}

struct App {
    settings: cfp::gui_settings::GuiSettings,
    runtime: tokio::runtime::Runtime,
    engine: Option<EngineHandle>,
    status: Status,
    logs: LogRing,
    log_tab: bool,
    trust: Option<TrustJob>,
    trust_result: Option<Result<TrustOutcome, String>>,
    known_entries: Vec<String>,
    settings_error: Option<String>,
    ssh_entry_state: Option<cfp::ssh_config::EnsureOutcome>,
    ssh_entry_error: Option<String>,
    tray: Option<tray::Tray>,
    quit: bool,
}

impl App {
    fn new(settings: cfp::gui_settings::GuiSettings) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");
        App {
            engine: None,
            status: Status::default(),
            logs: take_log_ring(),
            log_tab: false,
            trust: None,
            trust_result: None,
            known_entries: Vec::new(),
            settings_error: None,
            ssh_entry_state: None,
            ssh_entry_error: None,
            tray: tray::Tray::create(),
            quit: false,
            runtime,
            settings,
        }
    }

    // ---- actions -------------------------------------------------------

    fn write_ssh_entry(&mut self) {
        let port = self
            .settings
            .bind_addr()
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok());
        let Some(port) = port else {
            self.ssh_entry_error = Some("the forwarder port must be a plain number".to_string());
            return;
        };
        let matches_block = |text: &str, want: &str| {
            use cfp::ssh_config as sc;
            match (text.find(sc::MANAGED_START), text.find(sc::MANAGED_END)) {
                (Some(s), Some(e)) if e > s => text.get(s..e + sc::MANAGED_END.len()) == Some(want),
                _ => false,
            }
        };
        let path = match cfp::ssh_config::path() {
            Ok(p) => p,
            Err(e) => {
                self.ssh_entry_error = Some(e.to_string());
                return;
            }
        };
        // Preview first so an exact match can short-circuit without rewriting.
        let want = cfp::ssh_config::block(
            cfp::ssh_config::DEFAULT_ALIAS,
            cfp::ssh_config::LISTEN_HOST,
            port,
            &self.settings.ssh_user,
        );
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        if matches_block(&existing, &want) {
            self.ssh_entry_state = Some(cfp::ssh_config::EnsureOutcome::Unchanged);
            self.ssh_entry_error = None;
            return;
        }
        match cfp::ssh_config::ensure(
            &path,
            cfp::ssh_config::DEFAULT_ALIAS,
            cfp::ssh_config::LISTEN_HOST,
            port,
            &self.settings.ssh_user,
        ) {
            Ok((outcome, hosts)) => {
                tracing::info!(
                    "ssh config: {:?} for Host {} ({} managed host(s)) in {}",
                    outcome,
                    cfp::ssh_config::DEFAULT_ALIAS,
                    hosts,
                    path.display()
                );
                self.ssh_entry_state = Some(outcome);
                self.ssh_entry_error = None;
                self.settings.save().ok();
            }
            Err(e) => self.ssh_entry_error = Some(format!("ssh config: {e}")),
        }
    }

    fn connect(&mut self) {
        if self.engine.is_some() {
            return;
        }
        self.settings_error = None;
        let url = match cfp::config::normalize_target(&self.settings.target, false) {
            Ok(u) => u,
            Err(e) => {
                self.settings_error = Some(e.to_string());
                return;
            }
        };
        self.settings.save().ok(); // persist on every successful attempt
        let cfg = ForwarderConfig {
            target: url,
            credentials: self.settings.credentials(),
            bind: self.settings.bind_addr(),
            keepalive: Duration::from_secs(self.settings.keepalive_secs.max(1)),
            insecure_ws: false,
        };
        let (events, shutdown) = engine::spawn_forwarder(&self.runtime, cfg);
        self.engine = Some(EngineHandle {
            events,
            shutdown,
            sessions: 0,
        });
        self.status = Status::Disconnected; // until the Listening event lands
        tracing::info!("starting forwarder for {}", self.settings.target);
    }

    fn disconnect(&mut self) {
        match self.engine.take() {
            Some(handle) => {
                self.status = Status::Stopping;
                // Fire shutdown; remaining events are drained during stopping.
                let _ = handle.shutdown.send(true);
            }
            None => self.status = Status::Disconnected,
        }
        if let Some(t) = self.tray.as_mut() {
            t.set_connected(false);
        }
    }

    fn trust_now(&mut self) {
        if self.trust.as_ref().is_some_and(|t| t.running) {
            return;
        }
        self.settings_error = None;
        let port = self
            .settings
            .bind_addr()
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .unwrap_or(0);
        if port == 0 {
            self.settings_error =
                Some("the local port must be a number to re-learn the key".to_string());
            return;
        }
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let req = cfp::subcommands::TrustRequest {
            target: self.settings.target.clone(),
            credentials: self.settings.credentials(),
            // The UI's endpoint is exactly what the user connects with.
            client: HostPort::new("127.0.0.1", Some(port)),
            known_hosts: None,
            keepalive: Duration::from_secs(self.settings.keepalive_secs.max(1)),
            insecure_ws: false,
        };
        self.runtime.spawn(async move {
            let result = learn_and_pin(&req).await;
            let _ = tx.send(result.map_err(|e| e.to_string()));
        });
        self.trust_result = None;
        self.trust = Some(TrustJob { rx, running: true });
    }

    fn untrust_now(&mut self) {
        // Clear pins for both the forwarder endpoint and the raw target host.
        let port = self
            .settings
            .bind_addr()
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok());
        let mut endpoints: Vec<HostPort> = vec![HostPort::new("127.0.0.1", port)];
        endpoints.push(HostPort::new(
            cfp::subcommands::plain_host(&self.settings.target),
            None,
        ));
        let removed = endpoints
            .iter()
            .map(|e| {
                known_hosts::remove_entries(&default_known_hosts(), std::slice::from_ref(e))
                    .unwrap_or(0)
            })
            .sum::<usize>();
        tracing::info!("untrust: removed {removed} pin(s) for the current endpoints");
        self.refresh_known_entries();
    }

    fn refresh_known_entries(&mut self) {
        let port = self
            .settings
            .bind_addr()
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok());
        let endpoint = HostPort::new("127.0.0.1", port);
        self.known_entries =
            known_hosts::list_entries(&default_known_hosts(), &endpoint).unwrap_or_default();
    }

    // ---- per-frame upkeep ----------------------------------------------

    /// (dot color, header text) for the current state.
    fn status_line(&self) -> (egui::Color32, String) {
        let green = egui::Color32::from_rgb(0x3C, 0xB0, 0x57);
        let amber = egui::Color32::from_rgb(0xE8, 0xB0, 0x30);
        let gray = egui::Color32::from_rgb(0x90, 0x90, 0x90);
        match (&self.status, self.engine.as_ref()) {
            (Status::Listening { addr }, Some(e)) => (
                green,
                if e.sessions > 0 {
                    format!(
                        "Connected · {} · {} active session{}",
                        addr,
                        e.sessions,
                        if e.sessions == 1 { "" } else { "s" }
                    )
                } else {
                    format!("Connected · {addr} (waiting for the first connection)")
                },
            ),
            (Status::Listening { .. }, None) => (green, "Connected".to_owned()),
            (Status::Stopping, _) => (amber, "Disconnecting…".to_owned()),
            (Status::Disconnected, Some(_)) => (amber, "Connecting…".to_owned()),
            (Status::Disconnected, None) => (gray, "Disconnected".to_owned()),
        }
    }

    fn poll(&mut self, ctx: &egui::Context) {
        // Forwarder events.
        if let Some(handle) = self.engine.as_mut() {
            while let Ok(ev) = handle.events.try_recv() {
                match ev {
                    ForwarderEvent::Listening { addr } => {
                        self.status = Status::Listening { addr };
                        if let Some(t) = self.tray.as_mut() {
                            t.set_connected(true);
                        }
                    }
                    ForwarderEvent::Accepted => handle.sessions += 1,
                    ForwarderEvent::SessionEnded { .. } => {
                        handle.sessions = handle.sessions.saturating_sub(1)
                    }
                    ForwarderEvent::Stopped { error } => {
                        if let Some(e) = error {
                            tracing::error!("forwarder stopped: {e}");
                        }
                        self.engine = None;
                        self.status = Status::Disconnected;
                        if let Some(t) = self.tray.as_mut() {
                            t.set_connected(false);
                        }
                        return;
                    }
                }
            }
        }

        // Trust job result.
        if let Some(job) = self.trust.as_mut() {
            let mut latest = None;
            while let Ok(res) = job.rx.try_recv() {
                latest = Some(res);
                job.running = false;
            }
            if let Some(res) = latest {
                if let Ok(outcome) = &res {
                    tracing::info!(
                        "trust: pinned {} of {} keys (replaced {})",
                        outcome.pinned,
                        outcome.keys.len(),
                        outcome.replaced
                    );
                }
                self.trust_result = Some(res);
                self.refresh_known_entries();
            }
        }

        // Keepalive repaint only while something is pending.
        let busy = self.engine.is_some() || self.trust.as_ref().is_some_and(|t| t.running);
        ctx.request_repaint_after(if busy {
            Duration::from_millis(150)
        } else {
            Duration::from_secs(30)
        });
    }
}

fn default_known_hosts() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".ssh").join("known_hosts"))
        .unwrap_or_else(|| PathBuf::from("known_hosts"))
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll tray actions regardless of the current UI state.
        if let Some(t) = self.tray.as_mut() {
            match t.poll(ctx) {
                tray::Action::None => {}
                tray::Action::Connect => self.connect(),
                tray::Action::Disconnect => self.disconnect(),
                tray::Action::Quit => self.quit = true,
            }
        }

        if self.quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        self.poll(ctx);

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::Label::new(
                    egui::RichText::new("cfssh-proxy").strong().size(18.0),
                ));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (color, text) = self.status_line();
                    // Painted dot: independent of which glyphs the font has.
                    let (rect, _) =
                        ui.allocate_at_least(egui::vec2(12.0, 12.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 4.5, color);
                    ui.label(text);
                });
            });
        });

        egui::SidePanel::right("tip").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.heading("Point your IDE here");
            ui.add_space(4.0);
            let ep = self.settings.display_endpoint();
            ui.label(egui::RichText::new(&ep).monospace().size(15.0));
            ui.add_space(6.0);
            ui.label(
                "VS Code Remote-SSH / IntelliJ Gateway: Host + Port above \
                 (User dev by default; password auth; no proxy settings).",
            );
            ui.add_space(6.0);
            if ui.button("Copy endpoint").clicked() {
                ui.ctx().copy_text(ep.clone());
            }
            ui.add_space(4.0);
            // One click writes/repairs the managed `Host` block in
            // ~/.ssh/config so Remote-SSH shows this tunnel as "cfssh-dev".
            if ui.button("Write ssh config entry (VS Code)").clicked() {
                self.write_ssh_entry();
            }
            match self.ssh_entry_state {
                Some(cfp::ssh_config::EnsureOutcome::Unchanged) => {
                    ui.label(
                        egui::RichText::new("config already up to date")
                            .weak()
                            .small(),
                    );
                }
                Some(cfp::ssh_config::EnsureOutcome::Added) => {
                    ui.label(egui::RichText::new("added Host cfssh-dev").weak().small());
                }
                Some(cfp::ssh_config::EnsureOutcome::Updated) => {
                    ui.label(egui::RichText::new("updated Host cfssh-dev").weak().small());
                }
                None => {}
            }
            if let Some(err) = &self.ssh_entry_error {
                ui.colored_label(egui::Color32::from_rgb(0xE8, 0x60, 0x50), err);
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.selectable_label(!self.log_tab, "Connection").clicked() {
                    self.log_tab = false;
                }
                if ui.selectable_label(self.log_tab, "Logs").clicked() {
                    self.log_tab = true;
                }
            });
            ui.separator();

            if self.log_tab {
                self.logs_ui(ui);
            } else {
                self.connection_ui(ui);
            }
        });
    }

    // eframe 0.29 has no on_close_event; the tray Quit path terminates the
    // process and the forwarder drains via on_exit below.

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(handle) = self.engine.take() {
            let _ = handle.shutdown.send(true);
        }
        // Runtime drops at App drop; drain timeout inside shutdown: give the
        // listener a moment to see our shutdown flip.
        let rt = std::mem::replace(
            &mut self.runtime,
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("shutdown runtime"),
        );
        rt.shutdown_timeout(Duration::from_millis(500));
    }
}

impl App {
    fn connection_ui(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("conn")
            .num_columns(2)
            .spacing([10.0, 8.0])
            .show(ui, |ui| {
                ui.label("Tunnel host / URL");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.target)
                        .hint_text("ssh.example.com   (your Cloudflare tunnel)")
                        .desired_width(320.0),
                );
                ui.end_row();

                ui.label("Access client id");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.client_id)
                        .hint_text("optional — leave empty for anonymous tunnels")
                        .desired_width(320.0),
                );
                ui.end_row();

                ui.label("Access client secret");
                let secret = egui::TextEdit::singleline(&mut self.settings.client_secret)
                    .password(true)
                    .hint_text("optional")
                    .desired_width(320.0);
                ui.add(secret);
                ui.end_row();

                ui.label("Forwarder port");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.bind)
                        .hint_text("22022")
                        .desired_width(120.0),
                );
                ui.horizontal(|ui| {
                    ui.checkbox(
                        &mut self.settings.lan_reachable,
                        "reachable from LAN (Windows may ask about the firewall once)",
                    );
                });
                ui.end_row();

                ui.label("SSH user");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.ssh_user)
                        .hint_text("dev")
                        .desired_width(120.0),
                );
                ui.end_row();
            });

        ui.add_space(12.0);

        // Status banner: the state, in words and color, right where the eye
        // lands before the form.
        let (color, text) = self.status_line();
        ui.add(egui::Label::new(
            egui::RichText::new(text).strong().size(15.0).color(color),
        ));
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            let connected = self.engine.is_some();
            if ui
                .add_enabled(
                    !connected,
                    egui::Button::new("▶ Connect").min_size(egui::vec2(120.0, 28.0)),
                )
                .clicked()
            {
                self.connect();
            }
            if ui
                .add_enabled(
                    connected,
                    egui::Button::new("■ Disconnect").min_size(egui::vec2(120.0, 28.0)),
                )
                .clicked()
            {
                self.disconnect();
            }
            ui.separator();
            let trusting = self.trust.as_ref().is_some_and(|t| t.running);
            if ui
                .add_enabled(!trusting, egui::Button::new("⟳ Learn host key"))
                .clicked()
            {
                self.trust_now();
            }
        });

        if let Some(err) = &self.settings_error {
            ui.add_space(6.0);
            ui.colored_label(egui::Color32::from_rgb(0xE8, 0x60, 0x50), err);
        }

        if let Some(outcome) = &self.trust_result {
            match outcome {
                Ok(t) => {
                    ui.add_space(6.0);
                    for key in &t.keys {
                        ui.monospace(format!("{}  {}", key.fingerprint, key.keytype));
                    }
                }
                Err(e) => {
                    ui.add_space(6.0);
                    ui.colored_label(
                        egui::Color32::from_rgb(0xE8, 0x60, 0x50),
                        format!("trust: {e}"),
                    );
                }
            }
        }

        if !self.known_entries.is_empty() {
            ui.add_space(4.0);
            ui.collapsing(
                format!("Trusted keys ({})", self.known_entries.len()),
                |ui| {
                    for entry in &self.known_entries {
                        ui.monospace(entry);
                    }
                },
            );
            if ui
                .button("Forget pins for this endpoint (untrust)")
                .clicked()
            {
                self.untrust_now();
            }
        }

        ui.add_space(8.0);
        ui.separator();
        ui.collapsing("Saved on disk", |ui| {
            ui.label("Settings live in your user profile — no admin needed:");
            if let Ok(p) = cfp::gui_settings::GuiSettings::path() {
                ui.monospace(p.display().to_string());
            }
            if ui.button("Save settings now").clicked() {
                self.settings_error = self.settings.save().err().map(|e| e.to_string());
            }
        });
    }

    fn logs_ui(&mut self, ui: &mut egui::Ui) {
        if ui.button("Clear").clicked() {
            self.logs.lock().unwrap().clear();
        }
        ui.separator();
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                let ring = self.logs.lock().unwrap().clone();
                for line in &ring {
                    ui.monospace(line);
                }
            });
    }
}
