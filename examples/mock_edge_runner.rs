//! A minimal local stand-in for `cloudflared`: accepts a WebSocket on
//! 127.0.0.1:<random-port>, prints the port to stdout, and relays the
//! WebSocket to a TCP origin (like the real tunnel does with
//! `tcp://localhost:2222`).
//!
//! Used by `scripts/e2e.sh` (Layer 3) to exercise cfssh-proxy's
//! ProxyCommand path against a real sshd without any Cloudflare account:
//!
//!   target/debug/examples/mock_edge_runner tcp-bridge 127.0.0.1:2223
//!
//! The `--client-id`/`--client-secret` flags are accepted (and echoed, as
//! CF headers, just like the real edge) but ignored for validation.

use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::Message;

#[derive(Parser, Debug)]
#[command(
    name = "mock_edge_runner",
    about = "Local tunnel stand-in for e2e tests"
)]
struct Args {
    /// The tunnel listener mode (only tcp-bridge is implemented).
    #[arg(default_value = "tcp-bridge")]
    _mode: String,

    /// Origin TCP address to bridge the WebSocket to, e.g. 127.0.0.1:2223.
    addr: Option<String>,

    /// Accepted for realism; not validated.
    #[arg(long, default_value = "")]
    client_id: String,

    /// Accepted for realism; not validated.
    #[arg(long, default_value = "")]
    client_secret: String,

    /// Stop after this many seconds (0 = run forever).
    #[arg(long, default_value_t = 0)]
    run_for: u64,
}

fn main() {
    let args = Args::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let code = runtime.block_on(run(args));
    if code != 0 {
        std::process::exit(code);
    }
}

async fn run(args: Args) -> i32 {
    let origin = match &args.addr {
        Some(a) => a.clone(),
        None => {
            eprintln!("usage: mock_edge_runner tcp-bridge <origin_addr> [--run-for SECS]");
            return 2;
        }
    };

    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return 1;
        }
    };
    let port = listener.local_addr().expect("local addr").port();
    // First stdout line is the port (scripts parse this).
    println!("{port}");
    use std::io::Write as _;
    std::io::stdout().flush().ok();
    eprintln!("mock_edge_runner: ws://127.0.0.1:{port} -> tcp://{origin}");

    let deadline = if args.run_for > 0 {
        Some(tokio::time::Instant::now() + Duration::from_secs(args.run_for))
    } else {
        None
    };

    loop {
        let (socket, _) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(x) => x,
                Err(_) => break,
            },
            _ = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending::<()>().await,
                }
            } => break,
        };
        tokio::spawn(serve(socket, origin.clone()));
    }
    0
}

async fn serve(socket: TcpStream, origin_addr: String) {
    socket.set_nodelay(true).ok();
    // Perform the WebSocket server handshake (thin wrapper around tungstenite).
    let ws = match tokio_tungstenite::accept_async(socket).await {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("handshake failed: {e}");
            return;
        }
    };
    let origin = match TcpStream::connect(&origin_addr).await {
        Ok(o) => o,
        Err(e) => {
            eprintln!("origin connect failed: {e}");
            return;
        }
    };
    origin.set_nodelay(true).ok();

    let (mut sink, mut stream) = ws.split();
    let (mut read_half, mut write_half) = tokio::io::split(origin);
    let mut buf = vec![0u8; 32 * 1024];

    loop {
        tokio::select! {
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if !data.is_empty() && write_half.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
            n = read_half.read(&mut buf) => {
                match n {
                    Ok(0) => {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                    Ok(n) => {
                        if sink.send(Message::Binary(buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
        }
    }
    let _ = write_half.shutdown().await;
}
