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

    // Exactly one GUI per user: a second copy of the app is the classic
    // "one window works, the other says Disconnected forever" trap — it
    // cannot bind the forwarder port. Advisory lock file, released at exit.
    match acquire_instance_lock() {
        Ok(()) => {}
        Err(_) => {
            eprintln!(
                "cfssh-gui: another instance is already running — use its window (nothing started)."
            );
            return Ok(());
        }
    }

    eframe::run_native(
        "cfssh-proxy",
        options,
        Box::new(move |_cc| Ok(Box::new(App::new(settings)))),
    )
}

/// Advisory single-instance lock; Ok only exactly once per user profile.
fn acquire_instance_lock() -> Result<(), std::io::Error> {
    let mut dir = dirs::config_dir().ok_or_else(|| std::io::Error::other("no config dir"))?;
    dir.push("cfssh-proxy");
    std::fs::create_dir_all(&dir)?;
    dir.push("app.lock");
    let mut f = std::fs::File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&dir)?;
    f.try_lock()?;
    let _ = std::io::Write::write_all(&mut f, format!("pid={}\n", std::process::id()).as_bytes());
    // Intentionally leak: the lock must live for the whole process, and the
    // OS releases it on exit.
    Box::leak(Box::new(f));
    Ok(())
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
            // Teed: the Logs tab ring, and stderr (captured by our launcher).
            eprintln!("{text}");
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
    // Third-party render spam (wgpu's "Device::maintain: waiting for
    // submission index N" fires hundreds of times per SECOND at INFO while
    // the GUI paints) drowned the app's own lines out of the 1000-line ring
    // and made the Logs tab scroll forever. Clamp those crates to warning;
    // CFSSH_LOUD=1 (or RUST_LOG=trace) opts a developer back into the firehose.
    let default_filter = "info,wgpu_core=error,wgpu_hal=error,naga=error,winit=warn,eframe=warn";
    let filter = if std::env::var("CFSSH_LOUD").as_deref() == Ok("1") {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug"))
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter))
    };
    // Ring for the Logs tab AND stderr (visible when launched from a
    // terminal or via our launcher logs) — tunnel failures must never be
    // invisible. Timestamps on (UTC, ISO); ANSI off so gui.log stays plain.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(LogSink(ring))
        .with_ansi(false)
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
    /// live connections, one row each (the Devices table)
    sessions: Vec<SessionRow>,
}

struct SessionRow {
    id: u64,
    peer: String,
    started: std::time::Instant,
    stats: std::sync::Arc<cfp::engine::SessionStats>,
}

struct App {
    settings: cfp::gui_settings::GuiSettings,
    runtime: tokio::runtime::Runtime,
    engine: Option<EngineHandle>,
    status: Status,
    logs: LogRing,
    log_tab: bool,
    /// Logs tab: live substring filter (case-insensitive)
    log_filter: String,
    trust: Option<TrustJob>,
    trust_result: Option<Result<TrustOutcome, String>>,
    known_entries: Vec<String>,
    settings_error: Option<String>,
    ssh_entry_state: Option<cfp::ssh_config::EnsureOutcome>,
    ssh_entry_error: Option<String>,
    /// why the last Connect attempt did not reach Connected (bind failure etc.)
    last_error: Option<String>,
    /// when Disconnect was clicked; watchdog in case no Stopped event lands
    stopping_since: Option<std::time::Instant>,
    /// hidden CFSSH_AUTOSTART=1: fire Connect on the first frame (deep links,
    /// launcher shortcuts, diagnostics)
    auto_connect: bool,
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
            log_filter: String::new(),
            trust: None,
            trust_result: None,
            known_entries: Vec::new(),
            settings_error: None,
            ssh_entry_state: None,
            ssh_entry_error: None,
            last_error: None,
            stopping_since: None,
            auto_connect: std::env::var("CFSSH_AUTOSTART").as_deref() == Ok("1"),
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
        self.last_error = None;
        self.stopping_since = None;
        let url = match cfp::config::normalize_target(&self.settings.target, false) {
            Ok(u) => u,
            Err(e) => {
                self.settings_error = Some(e.to_string());
                return;
            }
        };
        // Preflight: resolve the tunnel host before the listener comes up.
        // A NXDOMAIN host previously produced one amber note PER CLIENT
        // connection while the banner stayed green; a typo must instead fail
        // loudly, ONCE, right here, naming the field to check.
        let host = url
            .trim_start_matches("wss://")
            .trim_start_matches("ws://")
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let lookup_host = host.clone();
        std::thread::spawn(move || {
            use std::net::ToSocketAddrs;
            let res = (lookup_host.as_str(), 443u16)
                .to_socket_addrs()
                .map_err(|e| format!("'{lookup_host}' could not be resolved: {e}"))
                .and_then(|addrs| {
                    if addrs.count() > 0 {
                        Ok(())
                    } else {
                        Err(format!("'{lookup_host}' resolved to no addresses"))
                    }
                });
            let _ = tx.send(res);
        });
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                self.settings_error = Some(format!(
                    "{e}\nThe tunnel host looks like a typo — check the field \
                     above (recent loads used ssh.ppcoder.xyz)."
                ));
                tracing::error!("connect rejected: {e}");
                return;
            }
            Err(_) => {
                self.settings_error = Some(format!(
                    "'{host}' did not resolve within 5 s (network down?) — \
                     check the field above."
                ));
                tracing::error!("connect rejected: {host} DNS timeout");
                return;
            }
        }
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
            sessions: Vec::new(),
        });
        self.status = Status::Disconnected; // until the Listening event lands
        tracing::info!("starting forwarder for {}", self.settings.target);
    }

    fn disconnect(&mut self) {
        // Keep the handle: the Stopped event must still be drained before the
        // UI can leave `Stopping`. (Taking it orphaned the event channel and
        // left the banner on "Disconnecting…" forever.)
        if self.engine.is_some() {
            self.status = Status::Stopping;
            self.stopping_since = Some(std::time::Instant::now());
            if let Some(handle) = self.engine.as_ref() {
                let _ = handle.shutdown.send(true);
            }
        } else {
            self.status = Status::Disconnected;
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
                if !e.sessions.is_empty() {
                    format!(
                        "Connected · {} · {} active session{}",
                        addr,
                        e.sessions.len(),
                        if e.sessions.len() == 1 { "" } else { "s" }
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
        // Watchdog: Disconnect should never take more than a moment; if the
        // Stopped event somehow never arrives, stop waiting on it.
        if let Some(t0) = self.stopping_since {
            if t0.elapsed() > Duration::from_secs(5) {
                self.engine = None;
                self.status = Status::Disconnected;
                self.stopping_since = None;
                tracing::warn!("disconnect watchdog: no Stopped event within 5s; recovered");
            }
        }
        // Forwarder events.
        if let Some(handle) = self.engine.as_mut() {
            while let Ok(ev) = handle.events.try_recv() {
                match ev {
                    ForwarderEvent::Listening { addr } => {
                        self.status = Status::Listening { addr };
                        self.last_error = None;
                        if let Some(t) = self.tray.as_mut() {
                            t.set_connected(true);
                        }
                    }
                    ForwarderEvent::Accepted { id, addr, stats } => {
                        let peer = addr.to_string();
                        tracing::info!("device connected: session #{id} from {peer}");
                        self.last_error = None;
                        handle.sessions.push(SessionRow {
                            id,
                            peer,
                            started: std::time::Instant::now(),
                            stats,
                        });
                    }
                    ForwarderEvent::SessionEnded { id, error: Some(e) } => {
                        // Session failures are the #1 invisible failure mode:
                        // the listener is green while every client connection
                        // dies inside the bridge (wrong host, closed sshd...).
                        // Strip tungstenite boilerplate for readability.
                        let short = e.replace(
                            "connection error: WebSocket error: WebSocket protocol error: ",
                            "",
                        );
                        tracing::warn!("session failed: {short}");
                        self.last_error = Some(format!("session failed: {short}"));
                        tracing::info!("device disconnected: session #{id}");
                        handle.sessions.retain(|r| r.id != id);
                    }
                    ForwarderEvent::SessionEnded { id, error: None } => {
                        tracing::info!("device disconnected: session #{id}");
                        handle.sessions.retain(|r| r.id != id);
                    }
                    ForwarderEvent::Stopped { error } => {
                        if let Some(e) = error {
                            tracing::error!("forwarder stopped: {e}");
                            self.last_error = Some(e);
                        }
                        self.engine = None;
                        self.status = Status::Disconnected;
                        self.stopping_since = None;
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

/// Human phrasing for the common forwarder startup failures.
fn human_bytes(n: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    let n = n as f64;
    if n >= MIB {
        format!("{:.1} MiB", n / MIB)
    } else if n >= KIB {
        format!("{:.1} KiB", n / KIB)
    } else {
        format!("{n} B")
    }
}

fn human_duration(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

/// Small monospace cell (independent of egui convenience methods).
fn mono_small(ui: &mut egui::Ui, text: impl Into<String>) {
    let text: String = text.into();
    ui.add(
        egui::Label::new(egui::RichText::new(text).small().monospace())
            .wrap_mode(egui::TextWrapMode::Truncate),
    );
}

/// Level-aware styling for one log line (plain logs, ANSI stripped).
fn level_styled(line: &str) -> egui::RichText {
    let rt = egui::RichText::new(line).monospace().size(11.0);
    if line.contains(" ERROR ") {
        rt.color(egui::Color32::from_rgb(0xE8, 0x60, 0x50))
    } else if line.contains(" WARN ") {
        rt.color(egui::Color32::from_rgb(0xE8, 0xB0, 0x30))
    } else if line.contains(" DEBUG ") || line.contains(" TRACE ") {
        rt.color(egui::Color32::from_rgb(0x90, 0x90, 0x90))
    } else if line.contains("device connected") {
        rt.color(egui::Color32::from_rgb(0x3C, 0xB0, 0x57))
    } else {
        rt.color(egui::Color32::from_rgb(0xC8, 0xC8, 0xC8))
    }
}

fn count_matched(ring: &VecDeque<String>, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    ring.iter()
        .filter(|l| l.to_lowercase().contains(needle))
        .count()
}

fn rc_error_text(err: &str) -> String {
    // session-level notes are informational: one client connection ended
    if let Some(rest) = err.strip_prefix("session failed: ") {
        format!(
            "a client connection dropped: {rest}\n\
             (usually a client or IDE reachability probe closing abruptly — \
             the forwarder stays up; retry the connection)"
        )
    } else if err.contains("cannot listen on")
        && (err.contains("already in use")
            || err.contains("os error 98")
            || err.contains("os error 10048"))
    {
        format!(
            "{err}\nThe port is taken — usually a second app instance (now prevented) or an old `cfssh-proxy --listen` still running."
        )
    } else if err.contains("UnrecognisedName") {
        format!(
            "{err}\n\
             The edge rejected the hostname during TLS — the tunnel host is \
             most likely a typo. Check the field above against your real \
             Cloudflare hostname."
        )
    } else {
        format!("could not start the forwarder: {err}")
    }
}

fn default_known_hosts() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".ssh").join("known_hosts"))
        .unwrap_or_else(|| PathBuf::from("known_hosts"))
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.auto_connect {
            self.auto_connect = false;
            self.connect();
        }
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
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.settings.target)
                        .hint_text("ssh.example.com   (your Cloudflare tunnel)")
                        .desired_width(320.0),
                );
                if r.changed() {
                    self.settings.save().ok();
                }
                ui.end_row();

                ui.label("Access client id");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.settings.client_id)
                        .hint_text("optional — leave empty for anonymous tunnels")
                        .desired_width(320.0),
                );
                if r.changed() {
                    self.settings.save().ok();
                }
                ui.end_row();

                ui.label("Access client secret");
                let secret = egui::TextEdit::singleline(&mut self.settings.client_secret)
                    .password(true)
                    .hint_text("optional")
                    .desired_width(320.0);
                let r = ui.add(secret);
                if r.changed() {
                    self.settings.save().ok();
                }
                ui.end_row();

                ui.label("Forwarder port");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.settings.bind)
                        .hint_text("22022")
                        .desired_width(120.0),
                );
                if r.changed() {
                    self.settings.save().ok();
                }
                ui.horizontal(|ui| {
                    let r = ui.checkbox(
                        &mut self.settings.lan_reachable,
                        "reachable from LAN (Windows may ask about the firewall once)",
                    );
                    if r.changed() {
                        self.settings.save().ok();
                    }
                });
                ui.end_row();

                ui.label("SSH user");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.settings.ssh_user)
                        .hint_text("dev")
                        .desired_width(120.0),
                );
                if r.changed() {
                    self.settings.save().ok();
                }
                ui.end_row();
            });

        ui.add_space(12.0);

        // Status banner: the state, in words and color, right where the eye
        // lands before the form.
        let (color, text) = self.status_line();
        ui.add(egui::Label::new(
            egui::RichText::new(text).strong().size(15.0).color(color),
        ));
        if let Some(err) = &self.last_error {
            let (color, text) = if err.starts_with("session failed: ") {
                // informational: one connection died, the forwarder is fine
                (
                    egui::Color32::from_rgb(0xE8, 0xB0, 0x30),
                    rc_error_text(err),
                )
            } else {
                (
                    egui::Color32::from_rgb(0xE8, 0x60, 0x50),
                    rc_error_text(err),
                )
            };
            ui.colored_label(color, text);
        }
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

        // ---- Devices: every live connection with live traffic ------------
        if let Some(handle) = self.engine.as_ref() {
            if !handle.sessions.is_empty() {
                ui.add_space(8.0);
                ui.heading(format!("Devices ({})", handle.sessions.len()));
                egui::Grid::new("devices")
                    .num_columns(5)
                    .spacing([14.0, 3.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for h in ["#", "from", "connected", "↓ received", "↑ sent"] {
                            ui.add(egui::Label::new(egui::RichText::new(h).small().strong()));
                        }
                        ui.end_row();
                        for row in &handle.sessions {
                            mono_small(ui, format!("#{}", row.id));
                            mono_small(ui, &row.peer);
                            mono_small(ui, human_duration(row.started.elapsed()));
                            mono_small(
                                ui,
                                human_bytes(
                                    row.stats.down.load(std::sync::atomic::Ordering::Relaxed),
                                ),
                            );
                            mono_small(
                                ui,
                                human_bytes(
                                    row.stats.up.load(std::sync::atomic::Ordering::Relaxed),
                                ),
                            );
                            ui.end_row();
                        }
                    });
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

    /// Logs tab: color-coded, filterable, stable — no third-party spam.
    fn logs_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Clear").clicked() {
                self.logs.lock().unwrap().clear();
            }
            ui.separator();
            let r = ui.add(
                egui::TextEdit::singleline(&mut self.log_filter)
                    .hint_text("filter lines (substring)")
                    .desired_width(160.0),
            );
            if r.changed() {
                ui.ctx().request_repaint();
            }
            ui.weak("UTC timestamps · CFSSH_LOUD=1 for full wire detail");
        });
        ui.separator();
        let needle = self.log_filter.trim().to_lowercase();
        let ring = self.logs.lock().unwrap().clone();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                let mut shown = 0usize;
                for line in &ring {
                    if !needle.is_empty() && !line.to_lowercase().contains(&needle) {
                        continue;
                    }
                    shown += 1;
                    ui.add(egui::Label::new(level_styled(line)).wrap());
                }
                if shown == 0 && !needle.is_empty() {
                    ui.weak(format!("no lines match “{}”", self.log_filter.trim()));
                }
            });
        ui.separator();
        ui.small(format!(
            "{matched} of {total} lines",
            matched = count_matched(&ring, &needle),
            total = ring.len()
        ));
    }
}
