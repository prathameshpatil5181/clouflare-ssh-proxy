//! Tunnel connection plumbing shared by the connect/listen CLI modes and the
//! `trust` subcommand (one-shot bridge for ssh-keyscan).

use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{HeaderName, HeaderValue};

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

/// Bridge one accepted TCP connection through a fresh WebSocket to the tunnel.
pub async fn serve_conn(
    sock: tokio::net::TcpStream,
    url: &str,
    creds: Option<config::Credentials>,
    keepalive: std::time::Duration,
) -> Result<(), Error> {
    sock.set_nodelay(true).ok();
    let ws = connect_ws(url, creds.as_ref()).await?;
    let (read_half, write_half) = tokio::io::split(sock);
    let input_rx = bridge::spawn_stream_reader(read_half).await;
    bridge::run_duplex(ws, write_half, input_rx, keepalive).await
}
