//! Tunnel connection plumbing shared by the connect/listen CLI modes and the
//! `trust` subcommand (one-shot bridge for ssh-keyscan).

use std::time::Duration;

use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

use crate::bridge;
use crate::config;
use crate::error::Error;

const CF_ID_HEADER: HeaderName = HeaderName::from_static("cf-access-client-id");
const CF_SECRET_HEADER: HeaderName = HeaderName::from_static("cf-access-client-secret");

pub async fn connect_ws(
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

// ------------------------------------------------------------ origin probe

/// How long to wait for the origin's first bytes once the tunnel is up. sshd
/// transmits its `SSH-2.0-…` banner immediately on connect, so a live origin
/// answers far sooner.
const PROBE_BANNER_WAIT: Duration = Duration::from_secs(5);
/// Whole-probe watchdog (tunnel upgrade + banner wait). A probe must never
/// hang: it is only an instrument, not the connection.
const PROBE_TOTAL: Duration = Duration::from_secs(12);

/// Probe the ORIGIN behind the tunnel (usually sshd), NOT the tunnel itself.
///
/// The failure this exists for: TLS and the WS upgrade both succeed against
/// Cloudflare even when the backend service is dead ("tunnel green, origin
/// dead" — the 2026-10-29 production incident). The proof of origin health
/// is inbound bytes: sshd speaks first, so receiving anything at all after
/// the upgrade proves the last hop is alive. A silent tunnel (upgrade OK,
/// no data, then reset/close) is exactly the "sshd is down" signature.
///
/// Returns `(healthy, human detail for the banner/log)`.
pub async fn probe_origin(url: &str, creds: Option<&config::Credentials>) -> (bool, String) {
    match tokio::time::timeout(PROBE_TOTAL, probe_origin_inner(url, creds)).await {
        Ok(res) => res,
        Err(_) => (
            false,
            format!(
                "the origin probe did not complete within {} s",
                PROBE_TOTAL.as_secs()
            ),
        ),
    }
}

async fn probe_origin_inner(url: &str, creds: Option<&config::Credentials>) -> (bool, String) {
    let mut ws = match connect_ws(url, creds).await {
        Ok(ws) => ws,
        Err(e) => return (false, format!("tunnel upgrade failed: {e}")),
    };
    let deadline = tokio::time::Instant::now() + PROBE_BANNER_WAIT;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(WsMessage::Binary(data)))) => {
                return (
                    true,
                    format!("origin answered with {}", first_bytes_summary(&data)),
                );
            }
            // Tunnel keepalives carry no origin evidence; keep waiting.
            Ok(Some(Ok(WsMessage::Ping(_)))) | Ok(Some(Ok(WsMessage::Pong(_)))) => {}
            Ok(Some(Ok(WsMessage::Close(_)))) | Ok(None) => {
                return (
                    false,
                    "the tunnel closed without any data from the origin (sshd is not answering)"
                        .to_string(),
                );
            }
            Ok(Some(Ok(_))) => {
                // Any other frame type (text, raw frame) is still inbound
                // traffic from the origin: first bytes received.
                return (true, "the origin sent a frame".to_string());
            }
            Ok(Some(Err(e))) => {
                return (
                    false,
                    format!("the connection reset before any data from the origin: {e}"),
                );
            }
            Err(_) => {
                return (
                    false,
                    format!(
                        "no data from the origin within {} s (is sshd running on the backend?)",
                        PROBE_BANNER_WAIT.as_secs()
                    ),
                );
            }
        }
    }
}

/// The first printable run of bytes, for a human detail line like
/// "SSH-2.0-OpenSSH_9.6p1 Ubuntu…". ASCII-only, so truncation is char-safe.
fn first_bytes_summary(data: &[u8]) -> String {
    let printable: String = data
        .iter()
        .take(96)
        .take_while(|&&b| b.is_ascii_graphic() || b == b' ')
        .map(|&b| b as char)
        .collect();
    if printable.is_empty() {
        format!("{} bytes of binary data", data.len())
    } else {
        printable
    }
}

/// Bridge one accepted TCP connection through a fresh WebSocket to the tunnel.
pub async fn serve_conn(
    sock: tokio::net::TcpStream,
    url: &str,
    creds: Option<config::Credentials>,
    keepalive: std::time::Duration,
    stats: Option<std::sync::Arc<crate::engine::SessionStats>>,
) -> Result<(), Error> {
    sock.set_nodelay(true).ok();
    let ws = connect_ws(url, creds.as_ref()).await?;
    let (read_half, write_half) = tokio::io::split(sock);
    let input_rx = bridge::spawn_stream_reader(read_half).await;
    bridge::run_duplex(ws, write_half, input_rx, keepalive, stats).await
}
