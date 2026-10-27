use std::io::Write as _;
use std::time::Duration;
use std::time::Instant;

use cfp::config::{CliCredentials, EnvSource};
use cfp::engine::{ForwarderConfig, ForwarderEvent};
use cfp::error::Error;
use cfssh_proxy as cfp;
use clap::Parser;

/// OpenSSH ProxyCommand helper: bridges local SSH (stdin/stdout) to an SSH
/// endpoint published through a Cloudflare Tunnel (WebSocket), authenticating
/// with a Cloudflare Access service token.
///
///   ssh / IntelliJ -> OpenSSH ProxyCommand -> cfssh-proxy
///     -> wss://<hostname> -> Cloudflare -> cloudflared -> sshd
///
/// stdout always carries only SSH protocol bytes; logs and errors go to stderr.
#[derive(Debug, clap::Parser)]
#[command(name = "cfssh-proxy", version, about)]
struct Args {
    /// Target published by the tunnel: bare hostname, or https:// / wss:// URL
    /// (e.g. `ssh.ppcoder.xyz`).
    host: String,

    /// Cloudflare Access service token client id.
    #[arg(long)]
    client_id: Option<String>,

    /// Cloudflare Access service token client secret.
    #[arg(long)]
    client_secret: Option<String>,

    /// Credentials file (TOML or KEY=VALUE with keys client_id, client_secret).
    #[arg(long)]
    token_file: Option<std::path::PathBuf>,

    /// Use a credentials file whose permissions are wider than 0600 anyway.
    #[arg(long)]
    allow_insecure_perms: bool,

    /// Log debug details to stderr (secret still redacted).
    #[arg(long)]
    verbose: bool,

    /// Allow plaintext ws:// (hidden; integration tests only — never send SSH
    /// through the open internet like this).
    #[arg(long, hide = true)]
    insecure_ws: bool,

    /// Keepalive ping interval in seconds (hidden; default 25).
    #[arg(long, hide = true, default_value_t = 25)]
    keepalive_secs: u64,

    /// Run as a local TCP forwarder: listen on [ADDR:]PORT and bridge every
    /// accepted connection through the tunnel. For IDEs/terminals that cannot
    /// use a ProxyCommand — point them at 127.0.0.1:<port> like a normal SSH
    /// host.
    #[arg(long)]
    listen: Option<String>,
}

fn init_tracing(verbose: bool) {
    use tracing_subscriber::EnvFilter;
    if verbose {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
        let _ = tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .try_init();
        tracing::debug!(version = env!("CARGO_PKG_VERSION"), "cfssh-proxy starting");
    }
}

fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    cfp::install_crypto_provider();

    let code = match argv.get(1).map(String::as_str) {
        Some("untrust") => {
            let a = cfp::subcommands::UntrustArgs::parse_from(
                std::iter::once("cfssh-proxy".to_string()).chain(argv.into_iter().skip(2)),
            );
            let r = cfp::subcommands::run_untrust(&a);
            finish(r)
        }
        Some("trust") => {
            let a = cfp::subcommands::TrustArgs::parse_from(
                std::iter::once("cfssh-proxy".to_string()).chain(argv.into_iter().skip(2)),
            );
            let r = cfp::subcommands::run_trust(&a);
            finish(r)
        }
        _ => {
            let args = Args::parse();
            init_tracing(args.verbose);
            finish(run(&args))
        }
    };
    std::process::ExitCode::from(code as u8)
}

fn finish(result: Result<(), Error>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            // One clear error line to stderr; never the secret.
            let _ = writeln!(std::io::stderr(), "cfssh-proxy: error: {e}");
            e.exit_code()
        }
    }
}

fn run(args: &Args) -> Result<(), Error> {
    let started = Instant::now();
    let cli = CliCredentials {
        client_id: args.client_id.clone(),
        client_secret: args.client_secret.clone(),
    };

    let keepalive = Duration::from_secs(args.keepalive_secs.max(1));
    if let Some(listen) = &args.listen {
        let cfg = ForwarderConfig {
            target: args.host.clone(),
            credentials: None, // resolved below so errors follow the CLI chain
            bind: listen.clone(),
            keepalive,
            insecure_ws: args.insecure_ws,
        }
        .resolve(
            &cli,
            &EnvSource::from_real_env(),
            args.token_file.as_deref(),
            args.allow_insecure_perms,
        )?;
        match &cfg.credentials {
            Some(c) => {
                tracing::debug!(%listen, client_id = %c.client_id, "forwarder (with Access service token)")
            }
            None => {
                tracing::debug!(%listen, "forwarder (no Access service token; connecting without Access headers)")
            }
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to start async runtime");
        let (ev_tx, ev_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let result = rt.block_on(async {
            // Event printer: stderr only, exact historical wording (tests parse
            // the port out of the "listening on" line). Spawned inside the
            // runtime — outside it tokio::spawn panics.
            let printer = tokio::spawn({
                let mut ev_rx = ev_rx;
                async move {
                    let stderr = std::io::stderr();
                    while let Some(ev) = ev_rx.recv().await {
                        let mut out = stderr.lock();
                        match ev {
                            ForwarderEvent::Listening { addr } => {
                                let _ = writeln!(out, "cfssh-proxy: listening on {addr}");
                                let _ = writeln!(
                                    out,
                                    "cfssh-proxy: VS Code Remote-SSH / IntelliJ: Host 127.0.0.1, Port {} (User dev; password auth — no proxy settings needed)",
                                    addr.port()
                                );
                            }
                            ForwarderEvent::Accepted => {}
                            ForwarderEvent::SessionEnded { error: Some(e) } => {
                                let _ = writeln!(out, "cfssh-proxy: connection error: {e}");
                            }
                            ForwarderEvent::SessionEnded { error: None } => {}
                            ForwarderEvent::Stopped { error: Some(e) } => {
                                let _ = writeln!(out, "cfssh-proxy: forwarder stopped: {e}");
                            }
                            ForwarderEvent::Stopped { error: None } => {}
                        }
                    }
                }
            });
            let result = cfp::engine::run_forwarder(&cfg, ev_tx, shutdown_rx).await;
            printer.abort();
            result
        });
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            "listener stopped"
        );
        result?;
        return Ok(());
    }

    let creds = cfp::config::resolve_credentials(
        &cli,
        &EnvSource::from_real_env(),
        args.token_file.as_deref(),
        args.allow_insecure_perms,
    )?;

    let url_string = cfp::config::normalize_target(&args.host, args.insecure_ws)?;
    match &creds {
        Some(c) => tracing::debug!(
            %url_string,
            client_id = %c.client_id,
            keepalive_secs = keepalive.as_secs(),
            "opening tunnel (with Access service token)"
        ),
        None => tracing::debug!(
            %url_string,
            keepalive_secs = keepalive.as_secs(),
            "opening tunnel (no Access service token; connecting without Access headers)"
        ),
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to start async runtime");

    rt.block_on(run_bridge(&url_string, creds.as_ref(), keepalive))?;
    tracing::debug!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        "clean close"
    );
    Ok(())
}

async fn run_bridge(
    url: &str,
    creds: Option<&cfp::config::Credentials>,
    keepalive: Duration,
) -> Result<(), Error> {
    let ws = cfp::tunnel::connect_ws(url, creds).await?;
    let stdin_rx = cfp::bridge::spawn_stdin_reader();
    cfp::bridge::run(ws, stdin_rx, keepalive).await
}
