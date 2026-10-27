mod bridge;
mod config;
mod error;
mod known_hosts;
mod subcommands;
mod tunnel;

use std::io::Write as _;
use std::time::Duration;
use std::time::Instant;

use clap::Parser;
use config::{CliCredentials, EnvSource};
use error::Error;

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

fn install_crypto_provider() {
    // Selecting explicitly (ring) avoids rustls' ambiguous-provider panic when
    // multiple backends end up unified in the dependency tree.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    install_crypto_provider();

    let code = match argv.get(1).map(String::as_str) {
        Some("untrust") => {
            let a = subcommands::UntrustArgs::parse_from(
                std::iter::once("cfssh-proxy".to_string()).chain(argv.into_iter().skip(2)),
            );
            let r = subcommands::run_untrust(&a);
            finish(r)
        }
        Some("trust") => {
            let a = subcommands::TrustArgs::parse_from(
                std::iter::once("cfssh-proxy".to_string()).chain(argv.into_iter().skip(2)),
            );
            let r = subcommands::run_trust(&a);
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

    let creds = config::resolve_credentials(
        &cli,
        &EnvSource::from_real_env(),
        args.token_file.as_deref(),
        args.allow_insecure_perms,
    )?;

    let url_string = config::normalize_target(&args.host, args.insecure_ws)?;
    let keepalive = Duration::from_secs(args.keepalive_secs.max(1));
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

    if let Some(listen) = &args.listen {
        let creds_owned = creds.clone();
        rt.block_on(listen_mode(listen, &url_string, creds_owned, keepalive))?;
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            "listener stopped"
        );
        return Ok(());
    }

    rt.block_on(run_bridge(&url_string, creds.as_ref(), keepalive))?;
    tracing::debug!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        "clean close"
    );
    Ok(())
}

async fn run_bridge(
    url: &str,
    creds: Option<&config::Credentials>,
    keepalive: Duration,
) -> Result<(), Error> {
    let ws = tunnel::connect_ws(url, creds).await?;
    let stdin_rx = bridge::spawn_stdin_reader();
    bridge::run(ws, stdin_rx, keepalive).await
}

/// Listen mode: accept TCP connections locally and bridge each one through a
/// fresh WebSocket to the tunnel. Run forever (Ctrl-C stops it).
async fn listen_mode(
    listen: &str,
    url: &str,
    creds: Option<config::Credentials>,
    keepalive: Duration,
) -> Result<(), Error> {
    let bind_addr = if listen.contains(':') {
        listen.to_string()
    } else {
        format!("127.0.0.1:{listen}")
    };
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| Error::WsSetup(format!("cannot listen on {bind_addr}: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::WsSetup(format!("listener has no address: {e}")))?
        .port();

    // Machine-readable first line; humans get a hint for their IDE.
    let _ = writeln!(
        std::io::stderr(),
        "cfssh-proxy: listening on 127.0.0.1:{port}"
    );
    let _ = writeln!(
        std::io::stderr(),
        "cfssh-proxy: IntelliJ/Gateway: Host 127.0.0.1, Port {port} (User dev; password auth — no proxy settings needed)"
    );

    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                let url_s = url.to_string();
                let creds_c = creds.clone();
                tokio::spawn(async move {
                    if let Err(e) = tunnel::serve_conn(sock, &url_s, creds_c, keepalive).await {
                        let _ = writeln!(std::io::stderr(), "cfssh-proxy: connection error: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "listen accept failed; continuing");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
