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
| `src/main.rs` | CLI, rustls `ring` provider install, subcommand dispatch (`untrust`/`trust` via `argv[1]`, clap from `argv.skip(2)`), `--listen` mode (local TCP forwarder), `run_bridge` |
| `src/bridge.rs` | The pump: split send/recv tasks, oneshot shutdown coordination, `DRAIN_TIMEOUT` drain after EOF, generic `run_duplex` (any AsyncWrite) + `run` (stdio) |
| `src/config.rs` | Credential resolution (optional!), file parsing/perms, `normalize_target` (bare host → `wss://`) |
| `src/error.rs` | `Secret` redaction type, error texts, exit codes (cred errors = 2, others = 1) |
| `src/tunnel.rs` | Hoisted connect plumbing shared by connect/listen/trust: `connect_ws`, `map_connect_error` (status→error), `serve_conn` (TCP→WS bridge) |
| `src/engine.rs` | The forwarder engine (`ForwarderConfig`, `ForwarderEvent`, `run_forwarder`, `spawn_forwarder`): one listener → per-connection WS bridges; shutdown via a watch channel. Shared by `--listen`, the GUI, anything future |
| `src/gui_settings.rs` | Persisted user settings (Windows: `%APPDATA%\cfssh-proxy\config.toml`): target/token/bind/keepalive/LAN flag; half-token saves sanitized to anonymous |
| `src/probe.rs` | Pure-Rust SSH2 host-key probe (russh): completes KEX, captures every offered host key, aborts before userauth — no ssh-keyscan dependency |
| `src/ssh_config.rs` | Managed `Host cfssh-dev` block in `~/.ssh/config` (`%USERPROFILE%\.ssh\config`): idempotent `ensure` (Added/Updated/Unchanged), `remove_managed`, byte-stable delimited block, 0600 atomic write — the VS Code Remote-SSH hook |
| `src/gui/main.rs` | eframe GUI (Windows-first, compiles everywhere): connect panel, status, IDE endpoint hint, logs (tracing ring via writer), host-keys tab, tray hooks; no console in release (`windows_subsystem`) |
| `src/gui/tray.rs` | Windows tray (state-colored icons, connect/disconnect/quit menu) behind `cfg(windows)`; inert stub on other platforms |
| `src/subcommands.rs` | `untrust`/`trust` implementation + pub `learn_and_pin(TrustRequest)->TrustOutcome` shared with the GUI: endpoint parsing (`host:port` tokens, `-p` duality), one-shot accept loop + probe, pin + report |
| `src/known_hosts.rs` | Pin manager: `HostPort` (`candidates`/`pin_host`), `remove_entries` (plain+`[h]:p`+hashed `|1|…` via ring HMAC-SHA1), `append_entries`, `fingerprint`; atomic write 0600 |
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
cargo clippy --features gui --all-targets -- -D warnings # ... and with the GUI feature
cargo test                 # layers 1+2: 20 lib + 23 integration, ~2.5 s
./scripts/e2e.sh           # layer 3 (Linux; needs openssh-server; keyscan NOT needed)
./scripts/live-test.sh     # optional; CF_ACCESS_* NOT required (anonymous ok)
cargo build --release                       # CLI: ~2.3 MiB stripped binary
cargo build --release --features gui        # + GUI: target/release/cfssh-gui(.exe)
```

Subcommands (general-purpose host-key recovery, dispatched in `main()` before
the legacy parser; clap parses from `argv.skip(2)`):

```bash
cfssh-proxy untrust <hosts…> [-p PORT] [--known-hosts PATH]
# Removes plain, `[host]:port`, AND OpenSSH-hashed `|1|…` pins.
# `-p N` with bare host tokens clears BOTH the bare and `[host]:N` forms
# (deletion is intentionally broad). A `host:port` token embeds its port.

cfssh-proxy trust <tunnel-target> [--client-host H] [--client-port P] [--known-hosts PATH]
# TOFU with fingerprint display: one-shot ephemeral local listener ->
# `ssh-keyscan -T 15 -p <port> 127.0.0.1` over that bridge -> remove old pins
# for the client form -> pin the CURRENT keys (prints `SHA256:…` per key).
# Clear error (never a silent no-op) if 0 keys are captured.
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

- Layer 1+2: **46 tests, all passing** (23 lib incl. known_hosts/gui_settings
  + 3 ssh_config; 23 integration incl. the untrust CLI test); fmt + clippy
  `-D warnings` clean **with and without** `--features gui`.
- Layer 3 e2e: **7/7** (command round trip, 50 MiB sha256, `ssh -L`, idle
  keepalive, **3.5 trust** — keyscan-independent probe matches the real sshd
  key, **3.6 untrust** — pins removed others untouched, kill-edge
  mid-session).
- Live: anonymous connect to the real tunnel returns the container's
  `SSH-2.0-OpenSSH_9.6p1` banner.
- Live `trust` on the real tunnel (probe-based, post-Phase-2): pinned the
  same 3 keys (ecdsa+rsa+ed25519) with fingerprints identical to the earlier
  ssh-keyscan run; rc=0. ed25519: `SHA256:AeOtwbdDQ0xHNAu1ZIfHPLl/mrNsUxFrufNc00QXc34`.
- GUI: compiles clean (cargo check + clippy `--features gui`) on Linux and
  the app logic is reviewed, but it has NOT yet been run interactively — the
  first real run happens on a Windows laptop (tray behavior + HiDPI are the
  watch items). The `.exe` ships from the windows-gui CI job once the
  GitHub push lands.

## 6. State on THIS machine (important for ops-style tasks)

- Stripped release binary installed at `~/.local/bin/cfssh-proxy` (sourced
  from `target/release/`).
- **Listener running**: `cfssh-proxy --listen 0.0.0.0:22022 ssh.ppcoder.xyz`
  (pid **15258**, rebuilt + restarted 2026-10-27; survives via
  `setsid nohup`; log at `/tmp/opencode/cfssh-listen.log`). Binds all
  interfaces → reachable from the user's WSL via the box IP
  `172.19.2.15:22022`. Restart recipe: kill **by PID from
  `ss -tlnp`** (never `pkill -f` — see trap 3), then
  `setsid nohup ~/.local/bin/cfssh-proxy --listen 0.0.0.0:22022 ssh.ppcoder.xyz … &`
- `~/.ssh/known_hosts` has `[127.0.0.1]:22022` pinned with 3 keys
  (ecdsa/rsa/ed25519) produced by a live `trust` run on 2026-10-27.
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
8. **Trimming eframe's default features (`default-features = false`) kills
   text rendering entirely** — `default_fonts` is one of eframe's defaults,
   and egui then boots with zero font bytes: panels/buttons (vector fills)
   render but no glyph ever does, on every renderer backend. That produced
   the "window opens, nothing usable" bug on 2026-10-27. Ship eframe with
   `features = ["default_fonts", ...]`.
9. **WSLg's Wayland windowing reports a giant surface (8192×8192 RAIL) to
   winit**, so egui mis-scales its layout (glyph slivers at window edges).
   Forcing X11 (`WAYLAND_DISPLAY` unset + `libxkbcommon-x11` +
   `libxcb-xkb.so.1` via `LD_LIBRARY_PATH=/tmp/opencode/xkb/ext/...` +
   `WINIT_X11_SCALE_FACTOR=1`) fixes geometry on this box. Native Windows is
   unaffected.

## 8. Open follow-ups

- Complete the GitHub push (`git push -u origin main`) — it triggers the
  first-ever CI run, incl. the **windows-gui job that produces
  `cfssh-gui-portable.zip`**. User chose to push manually (no gh CLI, no
  stored creds).
- First GUI run on a real Windows machine: confirm tray icon/menu, no
  console flash, connection flow end-to-end (engine code path identical to
  the tested CLI, but the window/tray layer is unverified until then).
- macOS/Linux GUI builds work via `--features gui` (tray stub) if the user
  wants them — untested so far.
- Consider key-only SSH login (README §2) / change the default password
  (`changeme` after the container was recreated on 2026-10-27).
- CI on macOS/Windows and cross-compiled release binaries are defined but
  never executed outside Linux — first push will validate.
- Persistence: if the user's latest container was recreated WITHOUT the
  repo's compose volumes, host keys break on every rebuild — nudge them to
  `container/docker-compose.yml`.
