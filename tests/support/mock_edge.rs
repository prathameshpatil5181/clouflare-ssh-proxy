//! A fake "Cloudflare edge" for integration tests: minimal HTTP handling for
//! the WebSocket upgrade (so 401/403/302/502 can be exercised), then a small
//! manual RFC 6455 framing loop — so that raw frame control (e.g. continuation
//! fragments) is possible.
//!
//! The credential gate mirrors the real thing:
//! - wrong/missing CF-Access headers -> 401
//! - `reject_status` with valid creds -> that status (302 carries a Location;
//!   502 carries an "error code: 1033" body, like a real Cloudflare error page)

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Never close mid-echo (sentinel for Echo / Fragment).
const CLOSE_NEVER: usize = usize::MAX;

#[derive(Debug, Clone, PartialEq)]
pub enum EdgeMode {
    /// Echo binary frames back.
    Echo,
    /// Relay to a local TCP address (simulates `cloudflared -> localhost:2222`).
    TcpBridge(String),
    /// After N total payload bytes have been echoed, send a Close frame.
    CloseAfterN(usize),
    /// Re-send every received Binary as a non-final binary frame plus a final
    /// continuation frame, so the client must merge fragments.
    Fragment,
    /// Never send anything (used to observe keepalive Pings).
    Silent,
    /// Send one fixed binary frame immediately (simulates sshd's greeting
    /// banner: the origin speaks first), then hold the connection.
    Banner(Vec<u8>),
}

#[derive(Clone)]
pub struct EdgeOptions {
    pub client_id: String,
    pub client_secret: String,
    /// When set, valid credentials still get this HTTP status instead of the
    /// upgrade (simulates a non-Service-Auth Access policy).
    pub reject_status: Option<u16>,
    /// When false, the edge accepts the upgrade with-or-without the Access
    /// headers (simulates a tunnel published WITHOUT an Access application —
    /// anonymous WS upgrade). Defaults to true in realistic configurations.
    pub require_auth: bool,
}

pub struct EdgeHandle {
    pub addr: std::net::SocketAddr,
    observed: Arc<Mutex<HashMap<String, String>>>,
    pings: Arc<AtomicUsize>,
}

impl EdgeHandle {
    pub async fn headers(&self) -> HashMap<String, String> {
        self.observed.lock().await.clone()
    }

    pub fn pings(&self) -> usize {
        self.pings.load(Ordering::SeqCst)
    }
}

pub async fn start(mode: EdgeMode, opts: EdgeOptions) -> EdgeHandle {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock edge");
    let addr = listener.local_addr().expect("local addr");

    let observed: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let pings: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

    let (obs, cnt) = (observed.clone(), pings.clone());
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let mode = mode.clone();
            let opts = opts.clone();
            let (obs, cnt) = (obs.clone(), cnt.clone());
            tokio::spawn(async move {
                let _ = serve_conn(socket, mode, opts, obs, cnt).await;
            });
        }
    });

    EdgeHandle {
        addr,
        observed,
        pings,
    }
}

// ------------------------------------------------------------- HTTP side

type ReadHalf = tokio::io::ReadHalf<TcpStream>;
type WriteHalf = tokio::io::WriteHalf<TcpStream>;

async fn serve_conn(
    socket: TcpStream,
    mode: EdgeMode,
    opts: EdgeOptions,
    observed: Arc<Mutex<HashMap<String, String>>>,
    pings: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    socket.set_nodelay(true).ok();
    let (mut input, mut output) = tokio::io::split(socket);

    let Some((_, headers)) = read_http_request(&mut input).await else {
        return Ok(()); // client hung up before a full request: irrelevant
    };
    *observed.lock().await = headers.clone();

    let id_ok = !opts.require_auth
        || headers.get("cf-access-client-id").map(String::as_str) == Some(opts.client_id.as_str());
    let secret_ok = !opts.require_auth
        || headers.get("cf-access-client-secret").map(String::as_str)
            == Some(opts.client_secret.as_str());
    if !id_ok || !secret_ok {
        return reject(&mut output, 401, None, "no or bad Access service token").await;
    }
    if let Some(status) = opts.reject_status {
        let location =
            (status == 302).then(|| "https://mockedge.test/cdn-cgi/access/login".to_string());
        let body = (status == 502).then(|| "error code: 1033\n".to_string());
        return reject(&mut output, status, location, body.as_deref().unwrap_or("")).await;
    }

    // Complete the WebSocket upgrade.
    let key = headers
        .get("sec-websocket-key")
        .cloned()
        .unwrap_or_default();
    let accept = accept_key(&key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    output.write_all(response.as_bytes()).await?;
    output.flush().await?;

    run_session(input, output, mode, pings).await
}

async fn reject(
    out: &mut WriteHalf,
    status: u16,
    location: Option<String>,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status {
        401 => "Unauthorized",
        403 => "Forbidden",
        302 => "Found",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nServer: mock-edge\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(loc) = &location {
        response.push_str(&format!("Location: {loc}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(body);
    let _ = out.write_all(response.as_bytes()).await;
    let _ = out.shutdown().await;
    Ok(())
}

async fn read_http_request(input: &mut ReadHalf) -> Option<(String, HashMap<String, String>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        if buf.len() >= 4 && buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        let n = input.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 {
            return None;
        }
    }
    let headers_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    let text = String::from_utf8_lossy(&buf[..headers_end]).into_owned();
    let mut lines = text.split("\r\n");
    let first = lines.next()?.to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Some((first, headers))
}

// ------------------------------------------------------------- crypto bits

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).map(|&v| v as u32).unwrap_or(0);
        let b2 = chunk.get(2).map(|&v| v as u32).unwrap_or(0);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// RFC 6455 Sec-WebSocket-Accept computation.
fn accept_key(client_key: &str) -> String {
    let mut concat = client_key.trim().to_string();
    concat.push_str(WS_GUID);
    base64(&sha1(concat.as_bytes()))
}

// ------------------------------------------------------------- frame layer

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BIN: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

struct Frame {
    opcode: u8,
    #[allow(dead_code)] // parsed for completeness; sessions only need opcode+payload
    fin: bool,
    payload: Vec<u8>,
}

async fn read_frame(input: &mut ReadHalf) -> Option<Frame> {
    let mut hdr = [0u8; 2];
    input.read_exact(&mut hdr).await.ok()?;
    let fin = hdr[0] & 0x80 != 0;
    let opcode = hdr[0] & 0x0F;
    let masked = hdr[1] & 0x80 != 0;
    let len7 = (hdr[1] & 0x7F) as u64;
    let payload_len = match len7 {
        126 => {
            let mut b = [0u8; 2];
            input.read_exact(&mut b).await.ok()?;
            u16::from_be_bytes(b) as u64
        }
        127 => {
            let mut b = [0u8; 8];
            input.read_exact(&mut b).await.ok()?;
            u64::from_be_bytes(b)
        }
        n => n,
    };
    let mask = if masked {
        let mut m = [0u8; 4];
        input.read_exact(&mut m).await.ok()?;
        m
    } else {
        [0u8; 4]
    };

    let mut payload = vec![0u8; payload_len as usize];
    input.read_exact(&mut payload).await.ok()?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Some(Frame {
        opcode,
        fin,
        payload,
    })
}

async fn write_frame(
    out: &mut WriteHalf,
    opcode: u8,
    payload: &[u8],
    fin: bool,
) -> std::io::Result<()> {
    let mut head = Vec::with_capacity(10);
    head.push(if fin { 0x80 } else { 0x00 } | opcode);
    let len = payload.len();
    if len < 126 {
        head.push(len as u8);
    } else if len <= u16::MAX as usize {
        head.push(126);
        head.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        head.push(127);
        head.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.write_all(&head).await?;
    out.write_all(payload).await?;
    out.flush().await
}

async fn send_close(out: &mut WriteHalf) -> std::io::Result<()> {
    write_frame(out, OP_CLOSE, &1000u16.to_be_bytes(), true).await
}

// ------------------------------------------------------------- sessions

async fn run_session(
    input: ReadHalf,
    output: WriteHalf,
    mode: EdgeMode,
    pings: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    match &mode {
        EdgeMode::TcpBridge(addr) => tcp_bridge_session(input, output, addr.clone()).await,
        EdgeMode::Silent => silent_session(input, output, pings).await,
        EdgeMode::Banner(payload) => banner_session(input, output, payload.clone()).await,
        _ => data_session(input, output, mode, pings).await,
    }
}

/// Speak first (like an sshd greeting), then hold silence: banner probes,
/// origin-health checks, "did the backend answer" style tests.
async fn banner_session(
    input: ReadHalf,
    mut out: WriteHalf,
    payload: Vec<u8>,
) -> std::io::Result<()> {
    write_frame(&mut out, OP_BIN, &payload, true).await?;
    silent_session(input, out, Arc::new(AtomicUsize::new(0))).await
}

/// Echo / Fragment / CloseAfterN loop.
async fn data_session(
    mut input: ReadHalf,
    mut out: WriteHalf,
    mode: EdgeMode,
    pings: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    let close_after = match &mode {
        EdgeMode::CloseAfterN(n) => *n,
        _ => CLOSE_NEVER,
    };
    let mut echoed: usize = 0;

    while let Some(f) = read_frame(&mut input).await {
        match f.opcode {
            OP_PING => {
                pings.fetch_add(1, Ordering::SeqCst);
                write_frame(&mut out, OP_PONG, &f.payload, true).await?;
            }
            OP_PONG => {}
            OP_CLOSE => {
                write_frame(&mut out, OP_CLOSE, &f.payload, true).await?;
                break;
            }
            OP_CONT => {
                // The client always sends whole frames; ignore stray continuations.
            }
            OP_BIN | OP_TEXT => {
                match mode {
                    EdgeMode::Fragment => {
                        let split_at = f.payload.len() / 2;
                        let (first, second) = f.payload.split_at(split_at);
                        write_frame(&mut out, OP_BIN, first, false).await?;
                        write_frame(&mut out, OP_CONT, second, true).await?;
                    }
                    _ => write_frame(&mut out, OP_BIN, &f.payload, true).await?,
                }
                echoed += f.payload.len();
                if echoed >= close_after {
                    send_close(&mut out).await?;
                    return wait_for_close_reply(&mut input, &mut out).await;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// After sending our Close, wait for the client's close reply before dropping
/// the socket (so the client reliably sees our Close frame).
async fn wait_for_close_reply(input: &mut ReadHalf, out: &mut WriteHalf) -> std::io::Result<()> {
    while let Some(f) = read_frame(input).await {
        match f.opcode {
            OP_CLOSE => {
                write_frame(out, OP_CLOSE, &f.payload, true).await?;
                break;
            }
            OP_PING => {
                write_frame(out, OP_PONG, &f.payload, true).await?;
            }
            _ => {}
        }
    }
    Ok(())
}

async fn silent_session(
    mut input: ReadHalf,
    mut out: WriteHalf,
    pings: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    while let Some(f) = read_frame(&mut input).await {
        match f.opcode {
            OP_PING => {
                pings.fetch_add(1, Ordering::SeqCst);
                write_frame(&mut out, OP_PONG, &f.payload, true).await?;
            }
            OP_CLOSE => {
                write_frame(&mut out, OP_CLOSE, &f.payload, true).await?;
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

/// WS-client <-> local-origin TCP relay (two pump tasks + one writer task so
/// pings can still be answered while origin data streams both ways).
async fn tcp_bridge_session(
    input: ReadHalf,
    output: WriteHalf,
    addr: String,
) -> std::io::Result<()> {
    let origin = TcpStream::connect(&addr).await?;
    origin.set_nodelay(true).ok();
    let (mut origin_read, mut origin_write) = tokio::io::split(origin);

    // Channel to the single WS writer task.
    struct Send {
        opcode: u8,
        payload: Vec<u8>,
    }
    let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<Send>(64);

    // Task W: frames out to the ws-client.
    let writer = tokio::spawn({
        let mut output = output;
        async move {
            while let Some(msg) = send_rx.recv().await {
                if write_frame(&mut output, msg.opcode, &msg.payload, true)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    });

    // Task A: ws-client frames -> origin socket.
    let to_origin = {
        let send_tx = send_tx.clone();
        let mut input = input;
        tokio::spawn(async move {
            while let Some(f) = read_frame(&mut input).await {
                match f.opcode {
                    OP_BIN | OP_TEXT => {
                        if origin_write.write_all(&f.payload).await.is_err() {
                            break;
                        }
                    }
                    OP_PING => {
                        let _ = send_tx
                            .send(Send {
                                opcode: OP_PONG,
                                payload: f.payload,
                            })
                            .await;
                    }
                    OP_CLOSE => {
                        // Half-close semantics: the client closing its side
                        // must NOT race a close frame back through the relay
                        // channel — that can beat the origin's reply to the
                        // wire and the child would exit with zero bytes out
                        // (observed deterministically on macOS/Windows CI).
                        // Just finished: shut down the origin write half; the
                        // WS close frame to the client comes from task B
                        // after the origin's EOF, i.e. after its final data.
                        break;
                    }
                    _ => {}
                }
            }
            let _ = origin_write.shutdown().await;
        })
    };
    // Task B: origin socket -> ws-client frames (owns the final Sender; the
    // writer task ends when it completes).
    let from_origin = {
        tokio::spawn(async move {
            let send_tx = send_tx;
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match origin_read.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        let _ = send_tx
                            .send(Send {
                                opcode: OP_CLOSE,
                                payload: 1000u16.to_be_bytes().to_vec(),
                            })
                            .await;
                        break;
                    }
                    Ok(n) => {
                        if send_tx
                            .send(Send {
                                opcode: OP_BIN,
                                payload: buf[..n].to_vec(),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        })
    };

    let _ = tokio::join!(writer, to_origin, from_origin);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_vector() {
        // sha1("abc")
        assert_eq!(
            sha1(b"abc")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn accept_key_rfc_example() {
        // RFC 6455 1.3 example
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
