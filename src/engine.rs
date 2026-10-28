//! The forwarder engine: one local TCP listener, each accepted connection
//! bridged through its own fresh WebSocket to the tunnel origin.
//!
//! Shared by every mode — the CLI `--listen` flag and the GUI's Connect
//! button — so the GUI cannot drift from the tested path. The CLI wraps this
//! in a never-firing shutdown channel (runs until killed, as before); the
//! GUI passes a shutdown receiver it can trigger.

use std::net::SocketAddr;
use std::time::Duration;

use crate::config::{self, CliCredentials, EnvSource};
use crate::error::Error;
use crate::tunnel;

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
    pub up: std::sync::atomic::AtomicU64,
    /// Bytes tunneled server → client (what the client received).
    pub down: std::sync::atomic::AtomicU64,
    /// Roughly "is it alive": monotonic traffic markers, touched on every
    /// message so a UI can show a heartbeat instead of raw bytes.
    pub activity: std::sync::atomic::AtomicBool,
}

impl SessionStats {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            up: std::sync::atomic::AtomicU64::new(0),
            down: std::sync::atomic::AtomicU64::new(0),
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
            let result = tunnel::serve_conn(sock, &url, creds, keepalive, Some(stats)).await;
            let error = result.as_ref().err().map(|e| e.to_string());
            if let Some(err_text) = &error {
                tracing::debug!(error = %err_text, "session ended with error");
            }
            let _ = ev.send(ForwarderEvent::SessionEnded { id, error });
        });
    }
}
