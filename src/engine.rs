//! The forwarder engine: one local TCP listener, each accepted connection
//! bridged through its own fresh WebSocket to the tunnel origin.
//!
//! Shared by every mode — the CLI `--listen` flag and the GUI's Connect
//! button — so the GUI cannot drift from the tested path. The CLI wraps this
//! in a never-firing shutdown channel (runs until killed, as before); the
//! GUI passes a shutdown receiver it can trigger.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::config::{self, CliCredentials, EnvSource};
use crate::error::Error;
use crate::tunnel;

/// Origin-health probes run once right after the listener is up and then
/// every PROBE_INTERVAL. One probe is one extra WebSocket through the
/// tunnel; sshd answers instantly, so this is cheap and quiet.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(60);

/// Everything needed to bring up a forwarder. `target` is the tunnel target
/// exactly as presented by the user (bare host or URL; normalized here).
#[derive(Debug, Clone)]
pub struct ForwarderConfig {
    pub target: String,
    pub credentials: Option<config::Credentials>,
    /// `[ADDR:]PORT` as parsed from `--listen`; `PORT` alone binds 127.0.0.1.
    pub bind: String,
    pub keepalive: Duration,
    /// Test-only: allow `ws://` targets (integration tests). Never exposed in GUI/CLI flags for real use.
    pub insecure_ws: bool,
}

impl ForwarderConfig {
    /// Resolve credentials from the same source chain as the CLI
    /// (flags > env > token-file > config dir) and normalize the target.
    pub fn resolve(
        &self,
        cli: &CliCredentials,
        env: &EnvSource,
        token_file: Option<&std::path::Path>,
        allow_insecure_perms: bool,
    ) -> Result<Self, Error> {
        debug_assert!(self.credentials.is_none(), "already resolved");
        Ok(ForwarderConfig {
            credentials: config::resolve_credentials(cli, env, token_file, allow_insecure_perms)?,
            target: config::normalize_target(&self.target, self.insecure_ws)?,
            ..self.clone()
        })
    }
}

/// Live per-session counters, shared between the bridge task and the UI (the
/// engine hands the same handle through the event channel).
#[derive(Debug)]
pub struct SessionStats {
    /// Bytes tunneled client → server (what the client sent).
    pub up: AtomicU64,
    /// Bytes tunneled server → client (what the client received).
    pub down: AtomicU64,
    /// Roughly "is it alive": monotonic traffic markers, touched on every
    /// message so a UI can show a heartbeat instead of raw bytes.
    pub activity: std::sync::atomic::AtomicBool,
}

impl SessionStats {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            activity: std::sync::atomic::AtomicBool::new(false),
        })
    }
    pub fn note_up(&self, n: u64) {
        self.up.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        self.activity
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn note_down(&self, n: u64) {
        self.down.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        self.activity
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Everything the UI needs to know, in order.
#[derive(Debug, Clone)]
pub enum ForwarderEvent {
    /// Listener bound and accepting.
    Listening { addr: SocketAddr },
    /// A client TCP connection was accepted (session started). `id` is
    /// unique within one forwarder lifetime; `stats` is the live counter
    /// handle for this session.
    Accepted {
        id: u64,
        addr: SocketAddr,
        stats: std::sync::Arc<SessionStats>,
    },
    /// One bridged session ended (client or tunnel side closed).
    SessionEnded { id: u64, error: Option<String> },
    /// The most recent origin-health check result. `healthy == true` means
    /// the backend (sshd) PROVED it answers — inbound bytes arrived through
    /// the tunnel; `false` means the tunnel was up but the origin was silent.
    /// The UI must never present a plain green "Connected" while the origin
    /// is dead (production incident, 2026-10-29).
    OriginHealth { healthy: bool, detail: String },
    /// The forwarder itself stopped (shutdown triggered, or error).
    Stopped { error: Option<String> },
}

/// Start a forwarder on `rt` and return its control channels. The GUI calls
/// this; the CLI uses the never-shutdown variant directly.
pub fn spawn_forwarder(
    rt: &tokio::runtime::Runtime,
    cfg: ForwarderConfig,
) -> (
    tokio::sync::mpsc::UnboundedReceiver<ForwarderEvent>,
    tokio::sync::watch::Sender<bool>,
) {
    let (ev_tx, ev_rx) = tokio::sync::mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let stop_tx = ev_tx.clone();
    rt.spawn(async move {
        let result = run_forwarder(&cfg, ev_tx, shutdown_rx).await;
        let _ = stop_tx.send(ForwarderEvent::Stopped {
            error: result.err().map(|e| e.to_string()),
        });
    });
    (ev_rx, shutdown_tx)
}

/// Run the forwarder until `shutdown` flips to `true`, then return Ok(()) after
/// a clean stop (accepted sessions are their own tasks and drain independently).
pub async fn run_forwarder(
    cfg: &ForwarderConfig,
    events: tokio::sync::mpsc::UnboundedSender<ForwarderEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Error> {
    let bind_addr = if cfg.bind.contains(':') {
        cfg.bind.clone()
    } else {
        format!("127.0.0.1:{}", cfg.bind)
    };
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| Error::WsSetup(format!("cannot listen on {bind_addr}: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Error::WsSetup(format!("listener has no address: {e}")))?;
    let _ = events.send(ForwarderEvent::Listening { addr });

    // Origin-health watchdog. The listener being up says nothing about the
    // backend behind the tunnel — TLS/WS can be perfectly green while sshd
    // is dead. probe_origin (tunnel.rs) asks the question once at startup
    // and then on a slow cadence, and publishes OriginHealth events so the
    // UI can show the REAL state.
    let probe_target = cfg.target.clone();
    let probe_creds = cfg.credentials.clone();
    let probe_events = events.clone();
    let mut probe_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PROBE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = probe_shutdown.changed() => return,
                _ = ticker.tick() => {}
            }
            let (healthy, detail) = tunnel::probe_origin(&probe_target, probe_creds.as_ref()).await;
            if healthy {
                tracing::info!(origin_healthy = true, detail = %detail, "origin probe ok");
            } else {
                tracing::warn!(origin_healthy = false, detail = %detail, "origin probe failed");
            }
            if probe_events
                .send(ForwarderEvent::OriginHealth { healthy, detail })
                .is_err()
            {
                return;
            }
        }
    });

    let mut next_id: u64 = 0;
    loop {
        let sock = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((s, peer)) => (s, peer),
                Err(e) => {
                    tracing::warn!(error = %e, "listen accept failed; continuing");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => return Ok(()),
        };
        let (sock, peer) = sock;
        next_id += 1;
        let id = next_id;
        let stats = SessionStats::new();
        let _ = events.send(ForwarderEvent::Accepted {
            id,
            addr: peer,
            stats: stats.clone(),
        });
        let url = cfg.target.clone();
        let creds = cfg.credentials.clone();
        let keepalive = cfg.keepalive;
        let ev = events.clone();
        tokio::spawn(async move {
            let result =
                tunnel::serve_conn(sock, &url, creds, keepalive, Some(stats.clone())).await;
            let error = result.as_ref().err().map(|e| e.to_string());
            if let Some(err_text) = &error {
                tracing::debug!(error = %err_text, "session ended with error");
            }
            // A session that failed WITHOUT a single inbound byte is direct
            // evidence of a dead origin: a healthy sshd sends its banner
            // immediately, and everything before it (TLS, WS upgrade) can be
            // green while it happens. This is the customer-visible signature
            // of the "tunnel green, backend dead" failure class.
            if error.is_some() && stats.down.load(Ordering::Relaxed) == 0 {
                let short = error.as_deref().unwrap_or("error").replace(
                    "connection error: WebSocket error: WebSocket protocol error: ",
                    "",
                );
                let detail =
                    format!("a client session failed before any data from the origin ({short})");
                tracing::warn!(origin_healthy = false, detail = %detail, "origin not reachable");
                let _ = ev.send(ForwarderEvent::OriginHealth {
                    healthy: false,
                    detail,
                });
            }
            let _ = ev.send(ForwarderEvent::SessionEnded { id, error });
        });
    }
}
