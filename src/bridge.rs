use std::io::Read as _;
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::Receiver;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;

use crate::error::Error;

pub const CHUNK_SIZE: usize = 32 * 1024;
pub const CHANNEL_CAPACITY: usize = 16; // 16 * 32 KiB of bounded buffering
/// How long to keep draining the WebSocket after stdin EOF / Close, so any
/// last bytes from the origin are flushed to stdout before we exit.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub type WsStream = WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Spawn an OS thread that reads stdin into bounded chunks and feeds a tokio
/// channel. This is deliberately a blocking thread + channel: it works
/// identically on Linux, macOS and Windows, is binary-safe on Windows (no CRLF
/// translation), and gives real backpressure (bounded channel capacity; the
/// reader thread parks when the async side is slower than the TTY).
pub fn spawn_stdin_reader() -> Receiver<std::io::Result<Vec<u8>>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Vec<u8>>>(CHANNEL_CAPACITY);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        loop {
            let mut buf = vec![0u8; CHUNK_SIZE];
            match lock.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.blocking_send(Ok(Vec::new()));
                    break;
                }
                Ok(n) => {
                    buf.truncate(n);
                    if tx.blocking_send(Ok(buf)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    let _ = tx.blocking_send(Err(e));
                    break;
                }
            }
        }
    });
    rx
}

/// Async variant of the reader for arbitrary streams (listen mode): same
/// chunking, channel semantics and backpressure as spawn_stdin_reader.
/// An empty payload signals EOF; exactly like the stdin reader.
pub async fn spawn_stream_reader<R>(mut reader: R) -> Receiver<std::io::Result<Vec<u8>>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Vec<u8>>>(CHANNEL_CAPACITY);
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt as _;
        loop {
            let mut buf = vec![0u8; CHUNK_SIZE];
            match reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = tx.send(Ok(Vec::new())).await;
                    break;
                }
                Ok(n) => {
                    buf.truncate(n);
                    if tx.send(Ok(buf)).await.is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });
    rx
}

/// Run the bridge until both sides are finished (clean close -> Ok).
///
/// Design: the send side and the receive side run as separate tasks, each with
/// its own stream half. This keeps the receive side always draining, so a
/// serial peer can never wedge us in the classic write-echo-write deadlock;
/// backpressure still applies because every write is awaited.
///
/// Shutdown is coordinated with two oneshots:
/// - stdin EOF/error -> sender sends a Close frame and tells the receiver to
///   drain for a bounded time (DRAIN_TIMEOUT),
/// - server Close/error -> receiver tells the sender to stop; exiting the
///   process closes the pipe, which ssh sees as ProxyCommand end.
///
/// Ping frames are answered automatically by tungstenite (queued on the read
/// half, flushed via the sink); we additionally send our own keepalive Pings.
///
/// ProxyCommand mode: stdin -> tunnel, tunnel -> stdout.
pub async fn run(
    ws: WsStream,
    stdin_rx: Receiver<std::io::Result<Vec<u8>>>,
    keepalive: Duration,
) -> Result<(), Error> {
    run_duplex(ws, tokio::io::stdout(), stdin_rx, keepalive).await
}

/// Listen-mode bridge: an arbitrary AsyncWrite target (e.g. one half of a
/// local TCP connection) receives the tunnel payload.
pub async fn run_duplex<W>(
    ws: WsStream,
    writer: W,
    stdin_rx: Receiver<std::io::Result<Vec<u8>>>,
    keepalive: Duration,
) -> Result<(), Error>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = ws.split();
    let (stdin_closed_tx, stdin_closed_rx) = tokio::sync::oneshot::channel::<()>();
    let (server_closed_tx, server_closed_rx) = tokio::sync::oneshot::channel::<()>();

    let sender = tokio::spawn(send_side(
        sink,
        stdin_rx,
        keepalive,
        stdin_closed_tx,
        server_closed_rx,
    ));
    let receiver = tokio::spawn(recv_side(stream, writer, stdin_closed_rx, server_closed_tx));

    let send_res = sender
        .await
        .map_err(|e| Error::Io(format!("send task panicked: {e}")))?;
    let recv_res = receiver
        .await
        .map_err(|e| Error::Io(format!("recv task panicked: {e}")))?;

    match (send_res, recv_res) {
        (Err(e), _) | (_, Err(e)) => Err(e),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> Error {
    Error::Io(format!("WebSocket error: {e}"))
}

async fn send_side(
    mut sink: SplitSink<WsStream, Message>,
    mut stdin_rx: Receiver<std::io::Result<Vec<u8>>>,
    keepalive: Duration,
    stdin_closed_tx: tokio::sync::oneshot::Sender<()>,
    mut server_closed_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), Error> {
    let mut interval = tokio::time::interval(keepalive);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Keepalive Pings keep Cloudflare from idling the connection out.
                if sink.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }

            chunk = stdin_rx.recv() => {
                match chunk {
                    Some(Ok(data)) if !data.is_empty() => {
                        if sink.send(Message::Binary(data)).await.is_err() {
                            let _ = stdin_closed_tx.send(());
                            return Ok(()); // receiver will surface its own error
                        }
                    }
                    // Empty payload = stdin EOF (see spawn_stdin_reader).
                    Some(Ok(_)) => {
                        let _ = stdin_closed_tx.send(());
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "stdin read error");
                        let _ = stdin_closed_tx.send(());
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                    None => {
                        // stdin reader thread ended unexpectedly; treat as EOF.
                        let _ = stdin_closed_tx.send(());
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                }
            }

            _ = &mut server_closed_rx => {
                // Server closed/hung up: nothing more to send.
                break;
            }
        }
    }
    Ok(())
}

async fn recv_side<W>(
    mut stream: SplitStream<WsStream>,
    mut sink_to_client: W,
    mut stdin_closed_rx: tokio::sync::oneshot::Receiver<()>,
    server_closed_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<(), Error>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let drain_deadline = tokio::time::sleep(DRAIN_TIMEOUT);
    tokio::pin!(drain_deadline);
    let mut draining = false;

    loop {
        // Poll the next server frame; once stdin EOF has been signaled, put a
        // bounded timeout on the drain.
        let next = if draining {
            tokio::select! {
                _ = &mut drain_deadline => break,
                msg = stream.next() => msg,
            }
        } else {
            tokio::select! {
                msg = stream.next() => msg,
                _ = &mut stdin_closed_rx => {
                    tracing::debug!("stdin closed; draining until the server closes");
                    draining = true;
                    continue;
                }
            }
        };

        match next {
            Some(Ok(Message::Binary(data))) => {
                // The client sink is sacred: write the payload immediately and flush.
                // During drain the client is already gone — a failed write is
                // routine, not a session error.
                if draining {
                    let _ = sink_to_client.write_all(&data).await;
                    let _ = sink_to_client.flush().await;
                } else {
                    sink_to_client.write_all(&data).await?;
                    sink_to_client.flush().await?;
                }
            }
            // Pings are answered with Pongs automatically by tungstenite on the
            // next sink write/flush; Pongs from our own keepalives are ignored.
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
            Some(Ok(Message::Close(_))) | None => {
                // Server said goodbye (or hung up): clean shutdown, exit 0.
                let _ = server_closed_tx.send(());
                return Ok(());
            }
            Some(Ok(_)) => {} // Text frames carry no meaning for a TCP tunnel
            Some(Err(e)) => {
                let _ = server_closed_tx.send(());
                if draining {
                    // Our client is already gone; the close dance frequently
                    // ends in a TCP RST instead of a WS close frame
                    // ("Connection reset without closing handshake" et al.).
                    // Routine and undeliverable: treat as end-of-drain.
                    tracing::debug!(error = %e, "drain ended with error (benign: client gone)");
                    return Ok(());
                }
                return Err(ws_err(e));
            }
        }
    }
    let _ = server_closed_tx.send(());
    Ok(())
}
