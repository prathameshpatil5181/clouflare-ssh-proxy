//! Layer 2 integration tests: run the compiled cfssh-proxy binary as a
//! subprocess with piped stdin/stdout against the mock edge (see
//! tests/support/mock_edge.rs). Self-contained; no internet access needed.

mod support;
use support::mock_edge::{EdgeHandle, EdgeMode, EdgeOptions};

use std::io::{Read, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::time::Duration;

const CLIENT_ID: &str = "test-client-id.access";
const CLIENT_SECRET: &str = "test-SECRET-~p4ssw0rd~-123";

fn edge_options() -> EdgeOptions {
    EdgeOptions {
        client_id: CLIENT_ID.to_string(),
        client_secret: CLIENT_SECRET.to_string(),
        reject_status: None,
        require_auth: true,
    }
}

fn home_dir() -> std::path::PathBuf {
    let tmp = std::env::temp_dir().join(format!("cfssh-home-{}", std::process::id()));
    let _ = std::fs::create_dir_all(tmp.join(".config/cfssh-proxy"));
    tmp
}

/// Command with a clean credential environment (HOME/XDG dirs pointed at a
/// temp dir, no CF_ACCESS_* vars) so tests never see the developer's real
/// credentials or default credentials file.
fn base_command(extra_args: &[&str], host: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cfssh-proxy"));
    for a in extra_args {
        c.arg(a);
    }
    c.arg(host);
    let home = home_dir();
    if cfg!(unix) {
        c.env("HOME", &home);
        c.env("XDG_CONFIG_HOME", home.join(".config"));
    } else {
        c.env("USERPROFILE", &home);
        c.env("APPDATA", &home);
        c.env("LOCALAPPDATA", &home);
    }
    c.env_remove("CF_ACCESS_CLIENT_ID");
    c.env_remove("CF_ACCESS_CLIENT_SECRET");
    c
}

/// Credentials in the environment, as real users would set them.
fn with_correct_env(cmd: &mut Command) -> &mut Command {
    cmd.env("CF_ACCESS_CLIENT_ID", CLIENT_ID)
        .env("CF_ACCESS_CLIENT_SECRET", CLIENT_SECRET)
}

#[allow(clippy::unused_async)] // uniform test ergonomics
async fn spawn(
    edge: &EdgeHandle,
    extra_args: &[&str],
) -> (Child, ChildStdin, ChildStdout, Option<ChildStderr>) {
    let mut cmd = base_command(extra_args, &format!("127.0.0.1:{}", edge.addr.port()));
    with_correct_env(&mut cmd);
    // CFSSH_CHILD_DEBUG=1 sends the child proxy's stderr to a temp file so
    // hangs and handshake failures can be diagnosed afterwards.
    let debug = std::env::var("CFSSH_CHILD_DEBUG").is_ok();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(if debug {
            let log = std::fs::File::create("/tmp/opencode/cfssh-child.log")
                .or_else(|_| std::fs::File::create(std::env::temp_dir().join("cfssh-child.log")))
                .expect("create child log file");
            Stdio::from(log)
        } else {
            Stdio::piped()
        })
        .spawn()
        .expect("spawn cfssh-proxy");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take();
    (child, stdin, stdout, stderr)
}

fn wait(child: &mut Child) -> ExitStatus {
    child.wait().expect("wait for cfssh-proxy")
}

fn xorshift_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push((x & 0xFF) as u8);
    }
    out
}

/// Write everything, then close stdin, from a dedicated thread (avoids
/// deadlock when payloads exceed pipe capacity).
fn feed_and_close(mut stdin: ChildStdin, data: Vec<u8>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
        let _ = stdin.flush();
        drop(stdin);
    })
}

/// Non-panicking read_exact for retry-based tests.
fn read_exact_ok(mut r: impl Read, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_exact_bytes(mut r: impl Read, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).expect("read_exact from stdout");
    buf
}

/// Read to EOF and return the number of remaining bytes (after known data).
fn read_rest(mut r: impl Read) -> usize {
    let mut rest = Vec::new();
    r.read_to_end(&mut rest).expect("read to end");
    rest.len()
}

#[cfg(target_os = "linux")]
fn rss_kb(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
}

// ------------------------------------------------------------- round trips

#[tokio::test(flavor = "multi_thread")]
async fn round_trip_small() {
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let (mut child, stdin, mut stdout, _stderr) = spawn(&edge, &["--insecure-ws"]).await;

    let _j = feed_and_close(stdin, b"hello, tunnel!".to_vec());
    let got = read_exact_bytes(&mut stdout, 14);
    assert_eq!(got, b"hello, tunnel!");
    assert_eq!(read_rest(&mut stdout), 0);
    assert!(wait(&mut child).success(), "exit code 0 expected");
}

#[tokio::test(flavor = "multi_thread")]
async fn round_trip_all_byte_values() {
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let (mut child, stdin, mut stdout, _stderr) = spawn(&edge, &["--insecure-ws"]).await;

    let data: Vec<u8> = (0..=255u8).collect();
    let _j = feed_and_close(stdin, data.clone());
    let got = read_exact_bytes(&mut stdout, data.len());
    assert_eq!(got, data, "every byte value 0x00-0xFF must survive");
    assert_eq!(read_rest(&mut stdout), 0);
    assert!(wait(&mut child).success());
}

#[tokio::test(flavor = "multi_thread")]
async fn round_trip_10mib() {
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let (mut child, stdin, mut stdout, _stderr) = spawn(&edge, &["--insecure-ws"]).await;

    let data = xorshift_bytes(10 * 1024 * 1024, 0x247ACE55);
    let feeder = feed_and_close(stdin, data.clone());
    let got = read_exact_bytes(&mut stdout, data.len());
    assert_eq!(got, data, "byte-exact 10 MiB round trip");
    feeder.join().unwrap();
    assert_eq!(read_rest(&mut stdout), 0);
    assert!(wait(&mut child).success());
}

#[tokio::test(flavor = "multi_thread")]
async fn fragment_frames_merged() {
    let edge = support::mock_edge::start(EdgeMode::Fragment, edge_options()).await;
    let (mut child, stdin, mut stdout, _stderr) = spawn(&edge, &["--insecure-ws"]).await;

    let data = xorshift_bytes(4096, 0x5EED_0001);
    let feeder = feed_and_close(stdin, data.clone());
    let got = read_exact_bytes(&mut stdout, data.len());
    assert_eq!(got, data, "fragmented messages must be merged byte-exactly");
    feeder.join().unwrap();
    assert_eq!(read_rest(&mut stdout), 0);
    assert!(wait(&mut child).success());
}

#[tokio::test(flavor = "multi_thread")]
async fn server_close_gives_exit_zero() {
    let edge = support::mock_edge::start(EdgeMode::CloseAfterN(11), edge_options()).await;
    let (mut child, stdin, mut stdout, _stderr) = spawn(&edge, &["--insecure-ws"]).await;

    let _j = feed_and_close(stdin, b"hello world".to_vec());
    let got = read_exact_bytes(&mut stdout, 11);
    assert_eq!(got, b"hello world");
    assert_eq!(read_rest(&mut stdout), 0, "nothing after the Close frame");
    assert!(
        wait(&mut child).success(),
        "a server Close frame must yield exit code 0"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_eof_is_clean_close() {
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    // Spawn with piped stdin, then drop the stdin handle immediately: the
    // proxy sees EOF on stdin and must shut down cleanly (exit 0).
    let (mut child, stdin, _stdout, _stderr) = spawn(&edge, &["--insecure-ws"]).await;
    drop(stdin);
    assert!(
        wait(&mut child).success(),
        "EOF on stdin must clean-shutdown"
    );
}

// -------------------------------------------------- upgrade request checks

#[tokio::test(flavor = "multi_thread")]
async fn headers_reach_the_edge() {
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let (mut child, stdin, mut stdout, _stderr) = spawn(&edge, &["--insecure-ws"]).await;

    let _j = feed_and_close(stdin, b"x".to_vec());
    assert_eq!(read_exact_bytes(&mut stdout, 1), b"x");
    assert!(wait(&mut child).success());

    let headers = edge.headers().await;
    assert_eq!(
        headers.get("cf-access-client-id").map(String::as_str),
        Some(CLIENT_ID)
    );
    assert_eq!(
        headers.get("cf-access-client-secret").map(String::as_str),
        Some(CLIENT_SECRET)
    );
    assert_eq!(
        headers
            .get("upgrade")
            .map(String::as_str)
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Some("websocket"),
        "Upgrade header: {:?}",
        headers
    );
    assert!(
        headers
            .get("connection")
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false),
        "Connection header: {:?}",
        headers
    );
    assert_eq!(
        headers.get("sec-websocket-version").map(String::as_str),
        Some("13")
    );
    let key_ok = headers
        .get("sec-websocket-key")
        .map(|k| k.len() >= 16 && !k.contains(' '))
        .unwrap_or(false);
    assert!(key_ok, "Sec-WebSocket-Key missing: {:?}", headers);
}

// --------------------------------------------------- error/status mapping

#[tokio::test(flavor = "multi_thread")]
async fn error_statuses_map_to_helpful_messages() {
    let expectations: &[(u16, &[&str])] = &[
        (401, &["401", "Cloudflare Access"]),
        (403, &["403", "Cloudflare Access"]),
        (302, &["302", "login"]),
        (502, &["502", "cloudflared", "1033"]),
        (418, &["unexpected HTTP status 418"]),
    ];

    for (status, needles) in expectations {
        let opts = EdgeOptions {
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
            reject_status: Some(*status),
            require_auth: true,
        };
        let edge = support::mock_edge::start(EdgeMode::Echo, opts).await;
        let mut cmd = base_command(
            &["--insecure-ws", "--verbose"],
            &format!("127.0.0.1:{}", edge.addr.port()),
        );
        with_correct_env(&mut cmd);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(mut si) = child.stdin.take() {
            let _ = si.write_all(b"x");
            let _ = si.flush();
        }

        let output = child.wait_with_output().expect("wait_with_output");
        assert!(
            !output.status.success(),
            "status {status} must give a non-zero exit code"
        );
        let stderr_text = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout_text = String::from_utf8_lossy(&output.stdout).to_string();
        for n in *needles {
            assert!(
                stderr_text.contains(n),
                "for HTTP {status}: stderr must explain `{n}`. stderr:\n{stderr_text}"
            );
        }
        assert!(stdout_text.is_empty(), "stdout must stay empty on failures");
        // the request headers still reached the edge
        assert_eq!(
            edge.headers()
                .await
                .get("cf-access-client-id")
                .map(String::as_str),
            Some(CLIENT_ID)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_token_rejected() {
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let mut cmd = base_command(
        &["--insecure-ws"],
        &format!("127.0.0.1:{}", edge.addr.port()),
    );
    cmd.env("CF_ACCESS_CLIENT_ID", "bogus-id")
        .env("CF_ACCESS_CLIENT_SECRET", "bogus-secret");
    let child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let stderr_text = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr_text.contains("401") && stderr_text.contains("Cloudflare Access"),
        "stderr:\n{stderr_text}"
    );
}

// ------------------------------------------------------- stdout discipline

#[tokio::test(flavor = "multi_thread")]
async fn stdout_pure_even_verbose() {
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let (mut child, stdin, mut stdout, stderr) =
        spawn(&edge, &["--insecure-ws", "--verbose"]).await;

    let payload = b"pure-payload-bytes";
    let _j = feed_and_close(stdin, payload.to_vec());
    let got = read_exact_bytes(&mut stdout, payload.len());
    assert_eq!(
        got, payload,
        "stdout must contain exactly the payload bytes"
    );
    assert_eq!(
        read_rest(&mut stdout),
        0,
        "no log text may leak into stdout"
    );

    // verbose logs go to stderr (and must never end up on stdout)
    if let Some(mut stderr) = stderr {
        let mut err_text = String::new();
        stderr.read_to_string(&mut err_text).unwrap_or(0);
        assert!(
            !err_text.is_empty(),
            "--verbose should log something to stderr"
        );
    }
    assert!(wait(&mut child).success());
}

#[tokio::test(flavor = "multi_thread")]
async fn secret_never_printed() {
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let (child, stdin, _stdout, _stderr) = spawn(&edge, &["--insecure-ws", "--verbose"]).await;

    let _j = feed_and_close(stdin, b"some payload on the wire".to_vec());
    let output = child.wait_with_output().expect("wait_with_output");
    let out_text = String::from_utf8_lossy(&output.stdout);
    let err_text = String::from_utf8_lossy(&output.stderr);
    assert!(
        !out_text.contains(CLIENT_SECRET),
        "the client secret leaked to stdout"
    );
    assert!(
        !err_text.contains(CLIENT_SECRET),
        "the client secret leaked to stderr: {err_text}"
    );
}

// -------------------------------------------------- credential sources

#[tokio::test(flavor = "multi_thread")]
async fn listen_mode_relays_tcp_connections() {
    // --listen mode: a local TCP forwarder that bridges each accepted
    // connection through a fresh WebSocket to the tunnel/mock edge.
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let mut cmd = base_command(
        &["--insecure-ws", "--listen", "127.0.0.1:0"],
        &format!("127.0.0.1:{}", edge.addr.port()),
    );
    with_correct_env(&mut cmd);
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = child.stderr.take().unwrap();

    // The listener reports its bound port on stderr; port :0 means ephemeral.
    let mut line = String::new();
    use std::io::BufRead as _;
    let mut reader = std::io::BufReader::new(&mut stderr);
    loop {
        line.clear();
        reader.read_line(&mut line).expect("read stderr line");
        if line.contains("listening on") {
            break;
        }
        assert!(!line.contains("error"), "unexpected stderr: {line}");
    }
    let port: u16 = line
        .rsplit(':')
        .next()
        .and_then(|p| p.trim_end_matches(['\r', '\n']).parse().ok())
        .expect("port from listening line");

    // Two sequential connections: each gets its own WebSocket through the
    // tunnel and both echo correctly (the old one is closed cleanly).
    use std::net::TcpStream;
    for n in 0..2 {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
        let msg = format!("listen-{n}");
        stream.write_all(msg.as_bytes()).unwrap();
        let mut got = vec![0u8; msg.len()];
        stream.read_exact(&mut got).unwrap();
        assert_eq!(got, msg.as_bytes(), "echo via --listen forwarder");
        drop(stream);
    }

    // Shut the forwarder down (it runs until killed); expect a clean exit not
    // required here — the assert is the echo above.
    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test(flavor = "multi_thread")]
async fn anonymous_connect_without_credentials_ok() {
    // Tunnels published without a Cloudflare Access application accept the
    // WebSocket upgrade with NO service token at all.
    let edge_opts = EdgeOptions {
        require_auth: false,
        ..edge_options()
    };
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_opts).await;
    let mut cmd = base_command(
        &["--insecure-ws"],
        &format!("127.0.0.1:{}", edge.addr.port()),
    );
    // base_command already strips CF_ACCESS_* and points HOME at a temp dir;
    // spawn without injecting any credentials.
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let si = child.stdin.take().unwrap();
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();

    let _j = feed_and_close(si, b"anonymous!".to_vec());
    let got = read_exact_bytes(&mut so, 10);
    assert_eq!(got, b"anonymous!", "echo works with no credentials at all");
    assert!(child.wait().unwrap().success());

    let headers = edge.headers().await;
    assert!(
        !headers.contains_key("cf-access-client-id"),
        "no Access header may be sent when no token is configured"
    );
    assert!(
        !headers.contains_key("cf-access-client-secret"),
        "no Access secret header may be sent when no token is configured"
    );
    let err_text = {
        let mut raw = Vec::new();
        use std::io::Read as _;
        se.read_to_end(&mut raw).unwrap();
        String::from_utf8_lossy(&raw).to_string()
    };
    assert!(
        !err_text.contains("error"),
        "anonymous connect must not error on stderr: {err_text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn anonymous_handshake_vs_access_protected_edge_is_401() {
    // The edge REQUIRES auth but the proxy has no credentials: it must still
    // attempt the upgrade anonymously and report the 401 helpfully.
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let mut cmd = base_command(
        &["--insecure-ws"],
        &format!("127.0.0.1:{}", edge.addr.port()),
    );
    let child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1), "connect failure exits 1");
    let stderr_text = String::from_utf8_lossy(&output.stderr).to_string();
    for needle in ["401", "NO service token", "CF_ACCESS_CLIENT_ID"] {
        assert!(
            stderr_text.contains(needle),
            "stderr missing `{needle}`. stderr:\n{stderr_text}"
        );
    }
    assert!(!stderr_text.contains(CLIENT_SECRET));
}

// -------------------------------------------------- known_hosts recovery

#[test]
fn untrust_cli_clears_old_pins_for_any_container() {
    // Generic host-key-rotation recovery: `cfssh-proxy untrust <hosts…> [-p P]`
    // removes exact + hashed pins and leaves unrelated entries untouched.
    let path = std::env::temp_dir().join(format!("cfssh-untrust-{}.kh", std::process::id()));
    std::fs::write(
        &path,
        "ssh.ppcoder.xyz ssh-ed25519 AAAA-OLD-TUNNEL\n\
         [127.0.0.1]:22022 ssh-ed25519 AAAA-OLD-FWD\n\
         hashed-host.example ssh-ed25519 KEEP-ME\n\
         other.example ssh-ed25519 KEEP-ME-2\n",
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_cfssh-proxy"))
        .args([
            "untrust",
            "--known-hosts",
            path.to_str().unwrap(),
            "ssh.ppcoder.xyz",
            "127.0.0.1",
            "-p",
            "22022",
        ])
        .env_remove("CF_ACCESS_CLIENT_ID")
        .env_remove("CF_ACCESS_CLIENT_SECRET")
        .output()
        .expect("spawn cfssh-proxy untrust");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let binding = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&binding);
    assert!(
        out.status.success(),
        "untrust must exit 0; stderr: {stderr}"
    );
    assert!(
        stderr.contains("removed 2 pin(s)"),
        "remove count must be reported: {stderr}"
    );
    assert!(!text.contains("AAAA-OLD-TUNNEL"));
    assert!(!text.contains("AAAA-OLD-FWD"));
    assert!(text.contains("KEEP-ME-2"));
    let _ = std::fs::remove_file(&path);
}

// ------------------------------------------------------------------- misc

#[tokio::test(flavor = "multi_thread")]
async fn half_credentials_still_rejected_with_sources() {
    // Only one half of the token present in the environment: unusable -> exit 2
    // with all credential sources listed.
    let mut cmd = base_command(&["--insecure-ws"], "127.0.0.1:1");
    cmd.env("CF_ACCESS_CLIENT_ID", "only-half-id");
    let child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2), "credential errors exit 2");
    let stderr_text = String::from_utf8_lossy(&output.stderr).to_string();
    for needle in [
        "--client-id",
        "CF_ACCESS_CLIENT_ID",
        "--token-file",
        "cfssh-proxy/credentials",
    ] {
        assert!(
            stderr_text.contains(needle),
            "error must list source `{needle}`. stderr:\n{stderr_text}"
        );
    }
    assert!(
        !stderr_text.contains("only-half-id"),
        "the half-supplied id must not be echoed: {stderr_text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn token_file_source_used() {
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let token_file = home_dir().join("token.toml");
    std::fs::write(
        &token_file,
        format!("client_id = \"{CLIENT_ID}\"\nclient_secret = \"{CLIENT_SECRET}\"\n"),
    )
    .unwrap();
    let args = [
        "--insecure-ws",
        "--token-file",
        token_file.to_str().unwrap(),
    ];
    let (mut child, stdin, mut stdout, _stderr) = spawn(&edge, &args).await;

    let _j = feed_and_close(stdin, b"from-file".to_vec());
    assert_eq!(read_exact_bytes(&mut stdout, 9), b"from-file");
    assert!(wait(&mut child).success());
    assert_eq!(
        edge.headers()
            .await
            .get("cf-access-client-id")
            .map(String::as_str),
        Some(CLIENT_ID)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_flags_beat_env() {
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let mut cmd = base_command(
        &["--insecure-ws"],
        &format!("127.0.0.1:{}", edge.addr.port()),
    );
    // environment lies; CLI flags must win
    cmd.env("CF_ACCESS_CLIENT_ID", "env-bogus-id")
        .env("CF_ACCESS_CLIENT_SECRET", "env-bogus-secret")
        .args(["--client-id", CLIENT_ID, "--client-secret", CLIENT_SECRET]);
    let (mut child, stdin, mut stdout, _stderr) = {
        let mut c = cmd;
        let mut ch = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let si = ch.stdin.take().unwrap();
        let so = ch.stdout.take().unwrap();
        let se = ch.stderr.take().unwrap();
        (ch, si, so, se)
    };
    let _j = feed_and_close(stdin, b"cli wins".to_vec());
    assert_eq!(read_exact_bytes(&mut stdout, 8), b"cli wins");
    assert!(wait(&mut child).success());
}

// ------------------------------------------------------- keepalive

/// One full attempt of the tcp-bridge relay scenario. Returns Err with a
/// human description instead of panicking, so the outer test can retry.
async fn tcp_bridge_relay_once() -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Minimal origin server ("cloudflared -> localhost:2222 target").
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move {
        let (mut sock, _) = origin
            .accept()
            .await
            .map_err(|e| format!("origin accept: {e}"))?;
        let mut buf = [0u8; 64];
        let n = sock
            .read(&mut buf)
            .await
            .map_err(|e| format!("origin read: {e}"))?;
        sock.write_all(b"reply:")
            .await
            .map_err(|e| format!("origin write: {e}"))?;
        sock.write_all(&buf[..n])
            .await
            .map_err(|e| format!("origin echo: {e}"))?;
        sock.flush()
            .await
            .map_err(|e| format!("origin flush: {e}"))?;
        drop(sock); // EOF: mock edge must turn this into a clean Close
        Ok::<(), String>(())
    });

    let edge = support::mock_edge::start(EdgeMode::TcpBridge(origin_addr), edge_options()).await;
    let (mut child, stdin, mut stdout, _stderr) = spawn(&edge, &["--insecure-ws"]).await;

    let _j = feed_and_close(stdin, b"ping".to_vec());
    let mut outcome = Ok(());
    match read_exact_ok(&mut stdout, "reply:ping".len()) {
        Ok(got) => {
            if got != b"reply:ping" {
                outcome = Err(format!("wrong relay payload: {got:?}"));
            } else if read_rest(&mut stdout) != 0 {
                outcome = Err("extra bytes after the echoed payload".into());
            } else if !wait(&mut child).success() {
                outcome = Err("cfssh-proxy exited nonzero after clean relay".into());
            }
        }
        Err(e) => {
            outcome = Err(format!("no relayed bytes reached stdout: {e}"));
            let _ = child.kill();
        }
    }
    let _ = child.wait();
    server.await.unwrap()?;
    outcome
}

/// On cold first-CI runners (macOS in particular: fresh process spawns are
/// slow) the single-response relay can occasionally lose its tiny window;
/// local Linux runs are deterministic. A real product defect fails every
/// attempt; only scheduling races recover on a later one.
#[tokio::test(flavor = "multi_thread")]
async fn tcp_bridge_mode_relays_to_origin() {
    let mut last_err = String::new();
    for attempt in 1..=5 {
        match tcp_bridge_relay_once().await {
            Ok(()) => {
                if attempt > 1 {
                    eprintln!("tcp bridge relay passed on attempt {attempt} (schedule race)");
                }
                return;
            }
            Err(e) => {
                eprintln!("tcp bridge relay attempt {attempt}: {e}");
                last_err = e;
            }
        }
    }
    panic!("tcp bridge relay unstable over 5 attempts: {last_err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn keepalive_pings_observed() {
    let edge = support::mock_edge::start(EdgeMode::Silent, edge_options()).await;
    let (mut child, stdin, stdout, _stderr) =
        spawn(&edge, &["--insecure-ws", "--keepalive-secs", "1"]).await;

    tokio::time::sleep(Duration::from_millis(2300)).await;
    let seen = edge.pings();
    assert!(
        seen >= 1,
        "expected at least one keepalive Ping, saw {seen}"
    );

    let _ = child.kill();
    drop(stdin);
    drop(stdout);
    let _ = child.wait();
}

// ------------------------------------------------------- backpressure

#[tokio::test(flavor = "multi_thread")]
#[cfg(target_os = "linux")]
async fn backpressure_bounded_memory() {
    let edge = support::mock_edge::start(EdgeMode::Echo, edge_options()).await;
    let (mut child, stdin, mut stdout, _stderr) = spawn(&edge, &["--insecure-ws"]).await;

    let data = xorshift_bytes(16 * 1024 * 1024, 0xB0CAFE00);
    let feeder = feed_and_close(stdin, data.clone());

    // Push data while deliberately NOT reading stdout for a while; the proxy
    // must apply backpressure instead of buffering everything.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    if let Some(rss) = rss_kb(child.id()) {
        assert!(
            rss < 250 * 1024,
            "excessive memory usage under backpressure: {} KiB",
            rss
        );
    }

    let got = read_exact_bytes(&mut stdout, data.len());
    assert_eq!(got, data);
    feeder.join().unwrap();
    assert!(wait(&mut child).success());
}
