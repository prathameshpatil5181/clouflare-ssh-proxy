//! General-purpose subcommands for the "container recreated / host key
//! legitimately changed" recovery flow — nothing here knows about any
//! particular repo, container, or tunnel URL.
//!
//! - `untrust <hosts…> [-p PORT]`: remove stale known_hosts pins.
//! - `trust  <tunnel-target> [--client-host H --client-port P]`: re-learn the
//!   CURRENT host key through the tunnel (one-shot local bridge + ssh-keyscan)
//!   and pin it, printing the fingerprint for the user to see.
//!
//! Security note: `trust` is Trust-On-First-Use with a fingerprint display.
//! It deliberately cannot silently overwrite a pin; use `untrust` first (it
//! does that internally) precisely because a changed key SHOULD be noticed —
//! this just makes the manual dance unnecessary when the change is expected.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use crate::config::{self, CliCredentials, EnvSource};
use crate::error::Error;
use crate::known_hosts;
use crate::known_hosts::HostPort;
use crate::tunnel::serve_conn;

/// Client-visible stderr line (stdout is never used for diagnostics).
#[macro_export]
macro_rules! stderr_line {
    ($($arg:tt)*) => {
        writeln!(std::io::stderr(), $arg).ok()
    };
}

fn out(args: std::fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr(), "{args}");
}

fn default_known_hosts() -> Result<PathBuf, Error> {
    dirs::home_dir()
        .map(|h| h.join(".ssh").join("known_hosts"))
        .ok_or_else(|| Error::WsSetup("cannot locate the user home directory".to_string()))
}

// --------------------------------------------------------------------- untrust

#[derive(Parser, Debug)]
#[command(
    name = "cfssh-proxy untrust",
    about = "Remove stale SSH host-key pins for an endpoint from known_hosts (all key types, incl. hashed entries)"
)]
pub struct UntrustArgs {
    /// Endpoints whose pins should be removed, e.g. `ssh.ppcoder.xyz` and/or
    /// `127.0.0.1:22022`. A bare token is treated as port 22; `host:port`
    /// tokens and `-p N` select the bracketed `[host]:port` pin form.
    #[arg(required = true)]
    hosts: Vec<String>,

    /// Client port applied to bare host tokens (default: 22 — the bare form).
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Alternate known_hosts file (default: ~/.ssh/known_hosts).
    #[arg(long)]
    known_hosts: Option<PathBuf>,
}

pub fn run_untrust(args: &UntrustArgs) -> Result<(), Error> {
    let path = args.known_hosts.clone().unwrap_or_else(|| {
        default_known_hosts().unwrap_or_else(|_| PathBuf::from(".ssh/known_hosts"))
    });
    let endpoints: Vec<HostPort> = {
        let mut v = Vec::new();
        let push = |v: &mut Vec<HostPort>, e: HostPort| {
            if !v.contains(&e) {
                v.push(e);
            }
        };
        for h in &args.hosts {
            match h.rsplit_once(':') {
                // token carries its own port, e.g. 127.0.0.1:22022
                Some((host, p)) => {
                    if let Ok(port) = p.parse::<u16>() {
                        push(&mut v, HostPort::new(host, Some(port)));
                    } else {
                        push(&mut v, HostPort::new(h.clone(), args.port));
                    }
                }
                None => {
                    push(&mut v, HostPort::new(h.clone(), args.port));
                    if args.port.is_some() {
                        // also clear the plain (port-22) pin form for this host
                        push(&mut v, HostPort::new(h.clone(), None));
                    }
                }
            }
        }
        v
    };
    let forms: Vec<String> = endpoints.iter().flat_map(|e| e.candidates()).collect();

    let removed = known_hosts::remove_entries(&path, &endpoints)?;
    out(std::format_args!(
        "cfssh-proxy: removed {removed} pin(s) from {} for {forms:?}",
        path.display()
    ));
    Ok(())
}

// ---------------------------------------------------------------------- trust

#[derive(Parser, Debug)]
#[command(
    name = "cfssh-proxy trust",
    about = "Fetch the CURRENT SSH host key through the tunnel and pin it locally (fingerprint shown; replaces old pins)"
)]
pub struct TrustArgs {
    /// Tunnel target exactly like the connect mode: bare host or URL
    /// (e.g. `ssh.ppcoder.xyz`).
    target: String,

    /// The host form your ssh CLIENT connects to. Default: the tunnel host
    /// itself (e.g. `ssh.ppcoder.xyz`); use `127.0.0.1` (or a LAN IP) when
    /// connecting through a `--listen` forwarder.
    #[arg(long)]
    client_host: Option<String>,

    /// The port your ssh CLIENT connects to (default 22; e.g. 22022 for a
    /// `--listen` forwarder).
    #[arg(long)]
    client_port: Option<u16>,

    /// Alternate known_hosts file (default: ~/.ssh/known_hosts).
    #[arg(long)]
    known_hosts: Option<PathBuf>,

    // --- connect-mode flags (same semantics) ---
    #[arg(long)]
    client_id: Option<String>,
    #[arg(long)]
    client_secret: Option<String>,
    #[arg(long)]
    token_file: Option<PathBuf>,
    #[arg(long)]
    allow_insecure_perms: bool,
    #[arg(long)]
    verbose: bool,
    #[arg(long, hide = true)]
    insecure_ws: bool,
    #[arg(long, hide = true, default_value_t = 5)]
    keepalive_secs: u64,
}

/// Strip scheme/URL parts from the target so defaults match what the user
/// actually types as the ssh hostname.
pub fn plain_host(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    let after_scheme = t
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(t)
        .split('/')
        .next()
        .unwrap_or(t);
    // strip any userinfo
    after_scheme
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(after_scheme)
        .to_string()
}

struct TrustResolved {
    url: String,
    creds: Option<config::Credentials>,
    client: HostPort,
    keepalive: Duration,
}

pub fn run_trust(args: &TrustArgs) -> Result<(), Error> {
    let req = TrustRequest {
        target: args.target.clone(),
        credentials: {
            let cli = CliCredentials {
                client_id: args.client_id.clone(),
                client_secret: args.client_secret.clone(),
            };
            config::resolve_credentials(
                &cli,
                &EnvSource::from_real_env(),
                args.token_file.as_deref(),
                args.allow_insecure_perms,
            )?
        },
        client: HostPort::new(
            args.client_host
                .clone()
                .unwrap_or_else(|| plain_host(&args.target)),
            args.client_port,
        ),
        known_hosts: args.known_hosts.clone(),
        keepalive: Duration::from_secs(args.keepalive_secs.max(1)),
        insecure_ws: args.insecure_ws,
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to start async runtime");
    let outcome = rt.block_on(learn_and_pin(&req))?;
    out(std::format_args!(
        "cfssh-proxy: pinned {} key(s) for {} in {} (replaced {} old pin(s))",
        outcome.pinned,
        req.client.pin_host(),
        outcome.known_hosts.display(),
        outcome.replaced
    ));
    for key in &outcome.keys {
        out(std::format_args!(
            "cfssh-proxy:   {} ({})",
            key.fingerprint,
            key.keytype
        ));
    }
    out(std::format_args!(
        "cfssh-proxy: connect now with `ssh -p {} {}` — the key above is the one sshd presented",
        req.client.port.unwrap_or(22),
        req.client.host
    ));
    Ok(())
}

/// Everything learn_and_pin needs; shared by the CLI `trust` and the GUI's
/// Trust button.
#[derive(Debug, Clone)]
pub struct TrustRequest {
    /// Tunnel target exactly like the connect mode (bare host or URL).
    pub target: String,
    /// Cloudflare Access service token, or None for anonymous connect.
    pub credentials: Option<config::Credentials>,
    /// The host form the ssh CLIENT connects to (e.g. 127.0.0.1:22022).
    pub client: HostPort,
    /// known_hosts file (None = ~/.ssh/known_hosts).
    pub known_hosts: Option<PathBuf>,
    pub keepalive: Duration,
    /// Test-only ws:// allowance (never exposed in the GUI).
    pub insecure_ws: bool,
}

/// What learn_and_pin produced — the GUI renders this directly.
#[derive(Debug, Clone)]
pub struct TrustOutcome {
    pub keys: Vec<crate::probe::HostKey>,
    pub known_hosts: PathBuf,
    pub pinned: usize,
    pub replaced: usize,
}

/// Learn the CURRENT sshd host keys through the tunnel and pin them for the
/// client endpoint. One-shot ephemeral listener -> russh KEX probe -> replace
/// the pins. Never sends credentials; captures fingerprints only.
pub async fn learn_and_pin(req: &TrustRequest) -> Result<TrustOutcome, Error> {
    let r = TrustResolved {
        url: config::normalize_target(&req.target, req.insecure_ws)?,
        creds: req.credentials.clone(),
        client: req.client.clone(),
        keepalive: req.keepalive,
    };
    // 1. One-shot ephemeral listener that tunnels local TCP -> the origin sshd.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| Error::WsSetup(format!("cannot bind the scan listener: {e}")))?;
    let listen_port = listener
        .local_addr()
        .map_err(|e| Error::WsSetup(format!("scan listener: {e}")))?
        .port();
    let listen_addr = listener
        .local_addr()
        .map_err(|e| Error::WsSetup(format!("scan listener: {e}")))?;
    tracing::debug!("scan listener on 127.0.0.1:{listen_port} -> {}", r.url);

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let url_s = r.url.clone();
    let creds_c = r.creds.clone();
    let ka = r.keepalive;
    let accept_loop = tokio::spawn(async move {
        let mut stop_rx = stop_rx;
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    match accepted {
                        Ok((sock, _)) => {
                            let u = url_s.clone();
                            let c = creds_c.clone();
                            tokio::spawn(async move {
                                if let Err(e) = serve_conn(sock, &u, c, ka, None).await {
                                    tracing::debug!(%e, "scan bridge conn ended");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!(%e, "accept failed");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(40)) => break,
                _ = &mut stop_rx => break,
            }
        }
    });

    // 2. Pure-Rust SSH2 KEX probe over that local port — no ssh-keyscan
    // dependency, so this works identically on a bare Windows GUI install.
    let keys = crate::probe::probe_host_keys(listen_addr).await?;

    let _ = stop_tx.send(());
    accept_loop.abort();

    let pins: Vec<String> = keys.iter().map(|k| k.pin_line()).collect();

    // 3. Un-trust old pins for the client form, then pin the fresh keys.
    let kh_path = match req.known_hosts.clone() {
        Some(p) => p,
        None => default_known_hosts()?,
    };
    let removed = known_hosts::remove_entries(&kh_path, std::slice::from_ref(&r.client))?;
    let added = known_hosts::append_entries(&kh_path, &r.client, &pins)?;

    Ok(TrustOutcome {
        keys,
        known_hosts: kh_path,
        pinned: added,
        replaced: removed,
    })
}
