# AGENTS.md — context for coding agents working on `cfssh-proxy`

Read this before changing anything. It captures the design, the invariants,
the deployed state on this machine, and the traps we already fell into.

---

## 1. What this project is

`cfssh-proxy` is a **Rust OpenSSH `ProxyCommand` helper** that bridges SSH
(stdin/stdout) over a **Cloudflare Tunnel WebSocket** (`wss://ssh.ppcoder.xyz`),
so IntelliJ/JetBrains Gateway (or plain `ssh`) can reach `dev@` inside a
Docker container, with **no `cloudflared` and no WARP on the local machine**.

```
ssh / IntelliJ <-> cfssh-proxy <-> wss://ssh.ppcoder.xyz <-> cloudflared (server)
        <-> localhost:2222 <-> Docker container sshd (port 22)
```

- One process **per SSH session**; not a daemon (except `--listen` mode, below).
- **stdout carries ONLY SSH bytes.** All logs/errors go to stderr. Secrets are
  never printed (see `error.rs::Secret` — a type that redacts Debug/Display).
- Cloudflare Access service tokens are **optional**: tunnels published without
  an Access application accept anonymous upgrades, and the proxy sends no
  headers then. Supported token sources (priority): CLI flags >
  `CF_ACCESS_CLIENT_ID`/`CF_ACCESS_CLIENT_SECRET` env > `--token-file` >
  `~/.config/cfssh-proxy/credentials` (TOML or KEY=VALUE). A **half** token
  (id without secret) is a hard error (exit code 2).

## 2. Source map

| Path | Role |
|---|---|
| `src/main.rs` | CLI, rustls `ring` provider install, WS connect + status→error mapping, `--listen` mode (local TCP forwarder) |
| `src/bridge.rs` | The pump: split send/recv tasks, oneshot shutdown coordination, `DRAIN_TIMEOUT` drain after EOF, generic `run_duplex` (any AsyncWrite) + `run` (stdio) |
| `src/config.rs` | Credential resolution (optional!), file parsing/perms, `normalize_target` (bare host → `wss://`) |
| `src/error.rs` | `Secret` redaction type, error texts, exit codes (cred errors = 2, others = 1) |
| `tests/support/mock_edge.rs` | Hand-rolled RFC 6455 fake Cloudflare edge (401/403/302/502/echo/tcp-bridge/fragment/close-after-n/silent modes; `require_auth` flag) |
| `tests/integration.rs` | Layer-2 suite spawning the real binary as a subprocess |
| `scripts/e2e.sh` | Layer-3: real user-mode sshd + mock edge (`examples/mock_edge_runner.rs`) + real OpenSSH through ProxyCommand |
| `scripts/live-test.sh` | Optional live tunnel check (CF creds optional) |
| `examples/mock_edge_runner.rs` | Local "cloudflared" stand-in: prints bound port on stdout line 1 |
| `container/` | Dockerfile + docker-compose.yml (volumes for host keys, home, JetBrains cache) |
| `.github/workflows/ci.yml` | Layers 1–3 Ubuntu; 1–2 macOS/Windows; 5-target release matrix |

## 3. Commands

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings   # both must stay clean
cargo test                 # layers 1+2: 13 unit + 22 integration, ~2.5 s
./scripts/e2e.sh           # layer 3 (Linux; needs openssh-server)
./scripts/live-test.sh     # optional; CF_ACCESS_* NOT required (anonymous ok)
cargo build --release      # ~2.3 MiB stripped binary
```

Hidden CLI flags (test-only, still supported): `--insecure-ws` (plaintext
`ws://` / bare-host `ws://` for the mock edge), `--keepalive-secs <N>`.
Public flags: `--client-id`, `--client-secret`, `--token-file`,
`--allow-insecure-perms`, `--verbose`, `--listen [ADDR:]PORT`.

## 4. Design decisions — do not undo these

1. **Two concurrent tasks in `bridge.rs`** (send side / recv side via
   `ws.split()`) — a single `select!` loop DEADLOCKS on serial-echo-style
   servers at 10 MiB. The recv side must always drain. Keep both oneshots
   (`stdin_closed`, `server_closed`) intact.
2. **stdin is read on a blocking OS thread** (not tokio) for Windows
   binary-safety; backpressure via a bounded mpsc (16 × 32 KiB). The
   `--listen` mode uses an async `spawn_stream_reader` for TCP instead.
3. **rustls only, with the `ring` provider installed explicitly** in `main()`
   (`rustls::crypto::ring::default_provider().install_default()`) — avoids
   rustls' ambiguous-CryptoProvider panic. Never add OpenSSL.
4. **Anonymous mode**: `resolve_credentials` returns `Ok(None)`; when absent,
   connect WITHOUT the CF headers. `AccessDeniedNoToken` explains that the
   hostname IS Access-protected and how to add a token.
5. Backpressure, 32 KiB frames, flush per message; WebSocket ping keepalive
   (25 s default, answered automatically by tungstenite).

## 5. Verification history (as of 2026-10-27)

- Layer 1+2: **35 tests, all passing**; fmt + clippy `-D warnings` clean.
- Layer 3 e2e: **5/5** (command round trip, 50 MiB sha256, `ssh -L`, idle
  keepalive, kill-edge mid-session).
- Release build verified; musl static build NOT built locally (needs
  `x86_64-linux-musl-gcc`); Windows/macOS jobs untested (Linux-only so far).
- Live: anonymous connect to the real tunnel returns the container's
  `SSH-2.0-OpenSSH_9.6p1` banner.

## 6. State on THIS machine (important for ops-style tasks)

- Stripped release binary installed at `~/.local/bin/cfssh-proxy` (sourced
  from `target/release/`).
- **Listener running**: `cfssh-proxy --listen 0.0.0.0:22022 ssh.ppcoder.xyz`
  (started 2026-10-26, survives across days via `setsid nohup`; log at
  `/tmp/opencode/cfssh-listen.log`). Binds all interfaces → reachable from
  the user's WSL via the box IP `172.19.2.15:22022`. Restart recipe:
  `pkill -f 'cfssh-proxy --listen'; setsid nohup ~/.local/bin/cfssh-proxy ... &`
- `$HOME/.local/bin` is NOT on non-interactive PATH → the ProxyCommand in
  `~/.ssh/config` uses the **absolute** path.
- `~/.ssh/config` has `Host devbox` (ProxyCommand + `StrictHostKeyChecking`).
- The user **recreated the container** on 2026-10-27 → the container's SSH
  host key changed; stale keys were purged from `known_hosts` and the new
  key (`SHA256:AeOtwbdDQ0xHNAu1ZIfHPLl/mrNsUxFrufNc00QXc34`) auto-trusted.
  Container password presumably back to `changeme`; user should `passwd`.
- IntelliJ/Gateway connection: Host `127.0.0.1` (this box) **or**
  `172.19.2.15:22022` from WSL/Windows; IntelliJ's Test Connection does its
  own DNS for aliases and does NOT honor ProxyCommand there → that is why
  `--listen` mode exists. `ssh devbox` DOES work from a normal terminal.
- GitHub push to `prathameshpatil5181/clouflare-ssh-proxy.git` is PENDING —
  local repo (branch `main`, commit `1b44667`, remote `origin` set) was
  initialized; user chose to push manually (no gh CLI, no stored creds).

## 7. Traps already discovered — do not rediscover the hard way

1. **sshd `secure_filename()` silently refuses `authorized_keys` under any
   world-writable dir (including `/tmp`).** e2e keys/config live under
   `$HOME/.cfssh-e2e.$$` for exactly this reason. Symptom: sshd logs
   "trying public key file …" then "Failed publickey", no "matching key".
2. **Automated edits to this codebase once corrupted match arms** (extra
   closing brace) and `rustc` errors pointed at the *middle* of an unrelated
   function. After any scripted edit, run `cargo build` and, if errors look
   impossible, re-inspect the surrounding braces before trusting the error
   location.
3. **`pkill -f` matches the invoking shell's own command line** — in this
   sandbox it has SIGTERM-killed our own shell repeatedly. Kill by PID or
   `pgrep`/`/proc` cmdline greps instead.
4. Mock edge validates Access headers **before** the WS upgrade;
   `EdgeOptions.require_auth=false` is the only anonymous mode.
5. `wait_with_output`-style tests must use piped stderr; `spawn()` returns
   `Option<ChildStderr>`.
6. The e2e ProxyCommand uses an absolute-path stub script (`$PROXY_STUB`)
   because PATH may not resolve `cfssh-proxy` from ssh's ProxyCommand shell.
7. WS-TLS handshake against the REAL edge requires `wss://` (never ship
   `--insecure-ws` to users; it's hidden and test-only).

## 8. Open follow-ups

- Complete the GitHub push (auth pending; see §6).
- Consider key-only SSH login (README §2) / change the default password.
- CI on macOS/Windows and cross-compiled release binaries are defined but
  never executed outside Linux — first push will validate.
- Persistence: if the user's latest container was recreated WITHOUT the
  repo's compose volumes, host keys break on every rebuild — nudge them to
  `container/docker-compose.yml`.
