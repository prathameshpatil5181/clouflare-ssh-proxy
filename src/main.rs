mod bridge;
mod config;
mod error;

use std::io::Write as _;
use std::time::Duration;
use std::time::Instant;

use clap::Parser;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{HeaderName, HeaderValue};

use config::{CliCredentials, EnvSource};
use error::Error;

const CF_ID_HEADER: HeaderName = HeaderName::from_static("cf-access-client-id");
const CF_SECRET_HEADER: HeaderName = HeaderName::from_static("cf-access-client-secret");

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
    let args = Args::parse();
    install_crypto_provider();
    init_tracing(args.verbose);

    let code = match run(&args) {
        Ok(()) => 0,
        Err(e) => {
            // One clear error line to stderr; never the secret.
            let _ = writeln!(std::io::stderr(), "cfssh-proxy: error: {e}");
            e.exit_code()
        }
    };
    std::process::ExitCode::from(code as u8)
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

async fn connect_ws(
    url: &str,
    creds: Option<&config::Credentials>,
) -> Result<bridge::WsStream, Error> {
    let mut request = url
        .into_client_request()
        .map_err(|e| Error::BadTarget(format!("{url}: {e}")))?;

    // Cloudflare Access service token headers, only when configured. Tunnels
    // published without an Access application accept the upgrade as-is.
    if let Some(creds) = creds {
        let headers = request.headers_mut();
        headers.insert(
            CF_ID_HEADER,
            HeaderValue::from_str(&creds.client_id)
                .map_err(|e| Error::WsSetup(format!("invalid client id: {e}")))?,
        );
        headers.insert(
            CF_SECRET_HEADER,
            HeaderValue::from_str(creds.client_secret.expose())
                .map_err(|e| Error::WsSetup(format!("invalid client secret: {e}")))?,
        );
    }

    tracing::debug!("connecting to the tunnel (WebSocket upgrade)…");
    let (ws, response) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| map_connect_error(e, creds.map(|c| c.client_id.as_str())))?;
    tracing::debug!(status = ?response.status(), "tunnel established (HTTP 101)");
    Ok(ws)
}

/// Map the many ways an upgrade can fail to one clear, actionable message.
fn map_connect_error(e: tokio_tungstenite::tungstenite::Error, client_id: Option<&str>) -> Error {
    use tokio_tungstenite::tungstenite::Error as WsError;
    match e {
        WsError::Http(response) => {
            let status = response.status();
            match status.as_u16() {
                401 | 403 => match client_id {
                    Some(id) => Error::AccessDeniedWithToken {
                        status: status.as_u16(),
                        client_id: id.to_string(),
                    },
                    None => Error::AccessDeniedNoToken {
                        status: status.as_u16(),
                    },
                },
                302 => {
                    let location = response
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("(no Location header)")
                        .to_string();
                    Error::AccessRedirect { location }
                }
                502 => Error::OriginUnreachable {
                    status: status.as_u16(),
                },
                other => Error::UnexpectedStatus(other),
            }
        }
        WsError::Tls(tls_err) => Error::WsSetup(format!(
            "TLS handshake failed: {tls_err}. Check the certificate chain and system trust roots."
        )),
        WsError::Io(io_err) => {
            if io_err.kind() == std::io::ErrorKind::ConnectionRefused {
                Error::Io(format!("connection refused: {io_err}"))
            } else {
                Error::Io(format!(
                    "{io_err} (network/DNS problem reaching the Cloudflare edge)"
                ))
            }
        }
        other => Error::Connect(format!("{other}")),
    }
}

async fn run_bridge(
    url: &str,
    creds: Option<&config::Credentials>,
    keepalive: Duration,
) -> Result<(), Error> {
    let ws = connect_ws(url, creds).await?;
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
                    if let Err(e) = serve_conn(sock, &url_s, creds_c, keepalive).await {
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

async fn serve_conn(
    sock: tokio::net::TcpStream,
    url: &str,
    creds: Option<config::Credentials>,
    keepalive: Duration,
) -> Result<(), Error> {
    sock.set_nodelay(true).ok();
    let ws = connect_ws(url, creds.as_ref()).await?;
    let (read_half, write_half) = tokio::io::split(sock);
    let input_rx = bridge::spawn_stream_reader(read_half).await;
    bridge::run_duplex(ws, write_half, input_rx, keepalive).await
}
