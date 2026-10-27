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
fn plain_host(target: &str) -> String {
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

fn resolve_trust(args: &TrustArgs) -> Result<TrustResolved, Error> {
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
    let url = config::normalize_target(&args.target, args.insecure_ws)?;
    let host = args
        .client_host
        .clone()
        .unwrap_or_else(|| plain_host(&args.target));
    Ok(TrustResolved {
        url,
        creds,
        client: HostPort::new(host, args.client_port),
        keepalive: Duration::from_secs(args.keepalive_secs.max(1)),
    })
}

pub fn run_trust(args: &TrustArgs) -> Result<(), Error> {
    let resolved = resolve_trust(args)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to start async runtime");
    rt.block_on(scan_and_pin(args, &resolved))
}

async fn scan_and_pin(args: &TrustArgs, r: &TrustResolved) -> Result<(), Error> {
    // 1. One-shot ephemeral listener that tunnels local TCP -> the origin sshd.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| Error::WsSetup(format!("cannot bind the scan listener: {e}")))?;
    let listen_port = listener
        .local_addr()
        .map_err(|e| Error::WsSetup(format!("scan listener: {e}")))?
        .port();
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
                                if let Err(e) = serve_conn(sock, &u, c, ka).await {
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

    // 2. ssh-keyscan speaks the SSH protocol over that local port.
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::process::Command::new("ssh-keyscan")
            .args([
                "-T", // per-connection timeout (round-trips through the edge)
                "15",
                "-p",
                &listen_port.to_string(),
                "127.0.0.1", // the scan is addressed by its own port; rewritten below
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::WsSetup(
                    "ssh-keyscan not found. It ships with OpenSSH client tools \
                     (openssh-client on Debian/Ubuntu, alongside `ssh`)."
                        .to_string(),
                ),
                _ => Error::Io(format!("cannot run ssh-keyscan: {e}")),
            })
    })
    .await
    .map_err(|_| {
        Error::WsSetup(
            "ssh-keyscan timed out while scanning through the tunnel \
             (is the tunnel up and the origin sshd running?)"
                .to_string(),
        )
    })??;

    let _ = stop_tx.send(());
    accept_loop.abort();

    // 3. Parse key lines: `127.0.0.1[:p] ssh-ed25519 AAAA… [comment]`.
    let stdout = String::from_utf8_lossy(&result.stdout);
    let mut pins: Vec<(String, String)> = Vec::new(); // (fingerprint, line-without-host)
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let _host_field = it.next(); // not used; rewritten below
        let Some(keytype) = it.next() else { continue };
        let Some(blob) = it.next() else { continue };
        if !(keytype.starts_with("ssh-") || keytype.starts_with("ecdsa-")) {
            continue;
        }
        let fp = known_hosts::fingerprint(blob)?;
        let rest: Vec<&str> = std::iter::once(keytype)
            .chain(std::iter::once(blob))
            .chain(it.collect::<Vec<_>>())
            .collect();
        pins.push((fp, rest.join(" ")));
    }

    if pins.is_empty() {
        let stderr_tail = String::from_utf8_lossy(&result.stderr);
        let tail: Vec<&str> = stderr_tail.lines().rev().take(5).collect();
        return Err(Error::WsSetup(format!(
            "ssh-keyscan captured no host keys through the tunnel. Likely causes: the origin sshd \
             is down (container recreated?), wrong tunnel target, or the Access policy rejected us. \
             Recent keyscan errors: {}",
            if tail.is_empty() { "(none)".to_string() } else { tail.join(" | ") }
        )));
    }

    // 4. Un-trust old pins for the client form, then pin the fresh keys.
    let kh_path = match args.known_hosts.clone() {
        Some(p) => p,
        None => default_known_hosts()?,
    };
    let removed = known_hosts::remove_entries(&kh_path, std::slice::from_ref(&r.client))?;
    let lines: Vec<String> = pins.iter().map(|(_, l)| l.clone()).collect();
    let added = known_hosts::append_entries(&kh_path, &r.client, &lines)?;

    out(std::format_args!(
        "cfssh-proxy: pinned {added} key(s) for {} in {} (replaced {removed} old pin(s))",
        r.client.pin_host(),
        kh_path.display()
    ));
    for (fp, line) in &pins {
        out(std::format_args!(
            "cfssh-proxy:   {} ({})",
            fp,
            line.split(' ').next().unwrap_or("")
        ));
    }
    out(std::format_args!(
        "cfssh-proxy: connect now with `ssh -p {} {}` — the key above is the one sshd presented",
        r.client.port.unwrap_or(22),
        r.client.host
    ));
    Ok(())
}
