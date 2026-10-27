# cfssh-proxy: Project Context and AI Agent Prompt

Saved context for building a Rust OpenSSH `ProxyCommand` helper that lets IntelliJ / JetBrains Gateway reach a Docker dev container over SSH through a Cloudflare Tunnel, with **no `cloudflared` or WARP on the local machine**.

---

## Part 1: Project context (decisions so far)

### Goal
Remote development in IntelliJ IDEA / JetBrains Gateway into a Docker container on an Ubuntu server, via a Cloudflare Tunnel hostname, using only a small local helper binary.

### Why this design
- A browser terminal (Cloudflare browser-rendered SSH, ttyd, Wetty) does not work for IntelliJ. JetBrains needs a real SSH connection (SFTP, command execution, port forwarding).
- A tunnel hostname is HTTP/WebSocket only, so a local helper must bridge SSH's raw TCP to a WebSocket. This is what `cloudflared access ssh` does internally.
- The helper is launched on demand by OpenSSH via `ProxyCommand`. It is not a daemon and lives for one SSH connection.

### Architecture
```
IntelliJ / Gateway -> OpenSSH (ProxyCommand) -> cfssh-proxy
   -> wss://ssh.ppcoder.xyz -> Cloudflare -> cloudflared (server host)
   -> localhost:2222 -> Docker container sshd (port 22)
```

### Current setup (verified)
| Item | Value |
|---|---|
| Hostname | `ssh.ppcoder.xyz` |
| Tunnel route | `tcp://localhost:2222` (correct, since `cloudflared` runs on the Ubuntu host, not in Docker) |
| Docker port mapping | `127.0.0.1:2222:22` (verified with `ss -tlnp`: listening on `127.0.0.1:2222`) |
| Container | Ubuntu 24.04, `openssh-server`, user `dev` |
| Local SSH test on server | `ssh -p 2222 dev@localhost` works (password login) |
| Auth (for now) | Password login. Key-only login deferred ("will handle later") |

### Decisions and caveats
- **`tcp://` vs `ssh://`**: both carry raw TCP over WebSocket. `tcp://` is fine for this tool.
- **Access application**: `ssh.ppcoder.xyz` should have a self-hosted Access application with a **Service Auth** policy (action must be Service Auth, not Allow) including the service token. Without it, anyone could try passwords against the container.
- **Password login is acceptable for now**, but it should be switched to key-only before long-term use. The later checklist is in Part 3.
- **Container requirements for JetBrains**: glibc-based image (not Alpine), `AllowTcpForwarding yes`, `curl`, `tar`, `gzip`, `procps`. Persist `/etc/ssh/ssh_host_*`, `/home/dev` and `~/.cache/JetBrains` in volumes.
- **Security**: if the container is privileged or mounts the Docker socket or host paths, the service token plus SSH credentials effectively give host control. Keep the Access policy tight.
- **IntelliJ setting**: enable "Use OpenSSH config and authentication agent" so `ProxyCommand` is honored.
- **Fallback**: if Cloudflare changes how the WebSocket path behaves, fall back to running `cloudflared access ssh` or WARP locally.

### Recommended order of work
1. On the server, confirm the container sshd works: `ssh -p 2222 dev@localhost` (done).
2. Confirm the Access application and Service Auth policy exist with your service token.
3. From the laptop, run the curl WebSocket test (below). `101 Switching Protocols` followed by an `SSH-2.0-OpenSSH_...` banner means the whole path works.
4. Give the prompt in Part 2 to the AI agent to build `cfssh-proxy`.
5. Test with `ssh -v devbox` first, then IntelliJ / Gateway.

### Curl WebSocket test (run from the laptop)
```bash
curl -i -N \
  -H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" \
  -H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET" \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://ssh.ppcoder.xyz
```

| Result | Likely cause |
|---|---|
| `101` + `SSH-2.0-...` banner | Everything works |
| `302`, `401`, `403` | Access policy or token wrong (needs Service Auth) |
| `502` / `1033` | Tunnel cannot reach the origin. Check `systemctl status cloudflared` and port 2222 |

---

## Part 2: The AI agent prompt (copy everything below this line into the agent)

````markdown
# Task: Build `cfssh-proxy`, a Rust OpenSSH ProxyCommand helper for SSH over Cloudflare Tunnel

## Context (my setup)
- Ubuntu server runs `cloudflared` as a host service (not in Docker).
- The tunnel publishes `ssh.ppcoder.xyz -> tcp://localhost:2222`.
- Docker publishes the dev container's sshd as `127.0.0.1:2222:22`. The container runs Ubuntu 24.04 with `openssh-server`, user `dev`, and password login enabled for now (key-only login will come later).
- `ssh.ppcoder.xyz` is protected by a Cloudflare Access self-hosted application with a **Service Auth** policy (service token).
- My local machine must NOT run `cloudflared` or WARP. The only local component is this tool.
- Purpose: let IntelliJ IDEA / JetBrains Gateway do remote development into the container over normal SSH, using "Use OpenSSH config and authentication agent" so that `ProxyCommand` is honored.

## Architecture
```
ssh / IntelliJ -> ProxyCommand: cfssh-proxy -> wss://ssh.ppcoder.xyz -> Cloudflare
   -> cloudflared (server) -> localhost:2222 -> container sshd
```
The tool transparently carries raw TCP bytes (the SSH protocol) in both directions. It must never interpret, modify, or delay-batch them.

## CLI
```
cfssh-proxy <hostname> [--client-id <ID>] [--client-secret <SECRET>]
            [--token-file <PATH>] [--allow-insecure-perms] [--verbose]
            [--insecure-ws]          # hidden, for tests only
            [--keepalive-secs <N>]   # hidden, default 25, for tests
```
SSH config example:
```
Host devbox
  HostName ssh.ppcoder.xyz
  User dev
  ProxyCommand cfssh-proxy %h
```

## Functional requirements
1. **Connect** to `wss://<hostname>`. Accept an optional `https://` or `wss://` prefix and normalize it. Plaintext `ws://` is allowed only behind the hidden `--insecure-ws` flag (or a test cfg).
2. **Auth headers**: send `CF-Access-Client-Id` and `CF-Access-Client-Secret` on the WebSocket upgrade request.
3. **Credential sources**, in priority order:
   1. CLI flags
   2. Env vars `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`
   3. `--token-file` (TOML or `KEY=VALUE` with keys `client_id`, `client_secret`)
   4. Default file `~/.config/cfssh-proxy/credentials`

   On Unix, warn (or refuse unless `--allow-insecure-perms`) if the credentials file is readable by group/others (wider than 0600). Missing credentials give a clear error that lists all four sources.
4. **Bridge**:
   - stdin -> WebSocket **Binary** frames; WebSocket Binary frames -> stdout, flushed after every write.
   - Reply to Ping with Pong. Send keepalive Pings every 20-30 s to survive Cloudflare idle timeouts.
   - A Close frame or EOF on either side cleanly shuts down the other side.
   - Handle large and fragmented messages correctly.
5. **stdout is sacred**: only SSH bytes ever go to stdout. All logs and errors go to stderr. Never print the client secret, even with `--verbose` (redact it).
6. **Exit codes**: 0 on clean close. Non-zero with a clear stderr message for: DNS failure, TLS failure, HTTP 401/403 (bad or missing service token, or Access policy is not Service Auth), HTTP 302 to the Access login page (token not accepted), 502/1033 (tunnel cannot reach the origin; check `cloudflared` and port 2222), and any other unexpected upgrade status.
7. **Performance**: async I/O with ~32 KiB buffers, bounded buffering, and real backpressure. Never block the async runtime. SFTP and the JetBrains backend transfer large files, so throughput matters.
8. **Password auth note**: the SSH client reads passwords from the TTY, not stdin, so the bridge must not touch the TTY. Confirm that password login works end to end.

## Technical constraints
- Rust stable, edition 2021+.
- Suggested crates: `tokio`, `tokio-tungstenite` (rustls with webpki or native roots), `futures-util`, `clap` (derive), `anyhow`/`thiserror`, `tracing` + `tracing-subscriber` (stderr only), `serde` + `toml`, `dirs`.
- No OpenSSL dependency, for easy cross-compilation and static builds.
- Must build and run on Linux, macOS and Windows. On Windows, stdin/stdout must be binary-safe (no CRLF translation). If tokio's stdin is problematic there, use a dedicated blocking reader thread feeding a channel.
- Keep the code small: roughly `main.rs`, `config.rs`, `bridge.rs`, `error.rs`.

## Testing and self-verification

The agent must be able to prove the tool works without my Cloudflare account. Build a three-layer test setup and run all of it yourself before declaring the task done.

### Layer 1: Unit tests (`cargo test`)
- Credential resolution and priority (flags > env > --token-file > default file), including the missing-credentials error text
- Hostname normalization (`host`, `https://host`, `wss://host`, trailing slash, rejecting `ws://` without `--insecure-ws`)
- Secret redaction in logs and Debug output
- Credentials file permission check (Unix only)

### Layer 2: Integration tests against a mock Cloudflare edge (`cargo test --test integration`)
Write a reusable test helper, `tests/support/mock_edge.rs`, that acts as a fake Cloudflare tunnel:
- It listens on `127.0.0.1:0` (random port) and accepts WebSocket upgrades.
- It validates that `CF-Access-Client-Id` and `CF-Access-Client-Secret` match expected values. If not, it responds with a configurable status (401, 403, or 302 with a `Location` header).
- It has selectable modes:
  - **echo**: echoes binary frames back
  - **tcp-bridge**: connects to a configurable local TCP address and relays bytes both ways (this simulates `cloudflared -> localhost:2222`)
  - **close-after-n**: sends a Close frame after N bytes
  - **fragment**: re-sends data as fragmented messages
  - **silent**: sends nothing, to test that keepalive Pings are sent
  - **error-status**: returns 502 or 1033-style responses on upgrade

Tests (run the compiled `cfssh-proxy` binary as a subprocess with piped stdin/stdout, using `--insecure-ws`):
- byte-exact round trip for small data, 10 MiB random data, and all byte values 0x00-0xFF
- correct headers received by the mock edge
- a server Close frame gives exit code 0, and stdin EOF gives a clean close
- 401, 403, 302 and 502 give a non-zero exit code and the specific helpful message from the requirements
- stdout contains only payload bytes (assert that no log text leaks into it, even with `--verbose`)
- the secret never appears in stderr or stdout
- keepalive Pings are observed by the mock edge within the configured interval (configurable via the hidden `--keepalive-secs` flag so the test runs fast)
- backpressure: a slow stdout consumer does not cause unbounded memory growth

### Layer 3: Real SSH end-to-end test (`scripts/e2e.sh`, also runnable as an ignored cargo test)
This proves the tool works as an actual OpenSSH ProxyCommand, including the SFTP and port forwarding that JetBrains needs.
1. Start a throwaway user-mode `sshd` on `127.0.0.1:2223` with a temp config, a generated ed25519 host key, a generated client key, `AllowTcpForwarding yes`, and the `internal-sftp` subsystem. If `sshd` is not installed or cannot run in this sandbox, fall back to a Docker container (`docker run` with `openssh-server`). If neither is possible, skip this layer, say so clearly in the final report, and do not claim it passed.
2. Start the mock edge in **tcp-bridge** mode pointing at `127.0.0.1:2223`.
3. Run real OpenSSH through the tool:
   ```
   ssh -F /dev/null -o ProxyCommand="cfssh-proxy --insecure-ws 127.0.0.1:<edge-port>" \
       -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -i <client-key> -p 2223 testuser@127.0.0.1 'echo ok && uname -a'
   ```
   Assert the output and a zero exit code.
4. Verify SFTP with a 50 MiB file (upload, download, compare SHA-256 checksums).
5. Verify port forwarding: `ssh -L` to a local TCP echo server, then send data through the forward and check it.
6. Verify an idle session survives longer than the keepalive interval, then still runs a command.
7. Kill the mock edge mid-session and verify `ssh` exits with a clear error and no hung processes remain.
8. Clean up all processes and temp files, even on failure (use a trap).

### Optional live test (`scripts/live-test.sh`, not run in CI)
A script I can run myself against the real tunnel. It reads `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET` and `LIVE_HOST` (default `ssh.ppcoder.xyz`) from the environment and does the following, printing PASS/FAIL for each step:
1. Run a `curl` WebSocket upgrade and expect `101`
2. Run `cfssh-proxy` and expect an `SSH-2.0-` banner on stdout
3. Print the exact `ssh -v -o ProxyCommand="cfssh-proxy %h" dev@ssh.ppcoder.xyz true` command to try next (it prompts for the password, so do not automate it)
4. On failure, map the HTTP status to the likely cause (401/403 -> Access policy or token, 302 -> not Service Auth, 502/1033 -> `cloudflared` or port 2222)

### Self-test rules
- Add a `Makefile` or `justfile` with `make test` (layers 1-2), `make e2e` (layer 3) and `make live` (optional live test).
- Layers 1-3 must pass on Linux. Keep tests portable to macOS and Windows where practical, and gate the sshd-based layer to Unix.
- CI (GitHub Actions) runs layers 1-3 on Ubuntu and layers 1-2 on macOS and Windows before building releases.
- The final report must list each layer and whether it **ran and passed**, **failed**, or **was skipped (with the reason)**. Never report a skipped test as passed.

## Deliverables
1. Complete Cargo project (`Cargo.toml` + source).
2. `README.md` with:
   - Cloudflare setup: tunnel route (`ssh.ppcoder.xyz -> tcp://localhost:2222`), Access application with a **Service Auth** policy, creating the service token
   - Container setup: sshd in the container, `127.0.0.1:2222:22` port mapping, a glibc-based image, `AllowTcpForwarding yes`, volumes for `/etc/ssh/ssh_host_*`, `/home/dev` and `~/.cache/JetBrains`, and a "later: switch to key-only auth" section
   - Installing the binary and the `~/.ssh/config` entry
   - Step-by-step IntelliJ / JetBrains Gateway setup, including enabling "Use OpenSSH config and authentication agent"
   - Troubleshooting: 401/403, 302, 502/1033, idle disconnects, `ssh -v devbox`, and a `curl` WebSocket upgrade test
   - How to run the self-tests (`make test`, `make e2e`, `make live`)
3. A sample `Dockerfile` and `docker-compose.yml` for the SSH-enabled dev container.
4. GitHub Actions workflow that runs the test layers, then produces release binaries for Linux x86_64/aarch64, macOS x86_64/aarch64 and Windows x86_64.
5. Release profile tuned for size (`opt-level = "z"`, `lto = true`, `strip = true`, `panic = "abort"`) as long as throughput isn't noticeably hurt.

## Out of scope
Interactive Cloudflare Access login (browser/OAuth), a local TCP listener mode, daemons or background services. The tool lives only for the duration of one SSH connection.

## Process
1. State your plan and assumptions briefly before coding.
2. Implement incrementally. After each milestone run `cargo fmt --check`, `cargo clippy -- -D warnings`, `make test` and `make e2e`. Fix failures before moving on. Do not finish until the self-verification report is complete.
3. Finish with a short summary of how to run it, the self-verification report (ran/passed, failed, or skipped with reason for each layer), and any known limitations.
````

---

## Part 3: Later checklist (deferred items)

### Switch the container to key-only SSH login
1. On the laptop: `ssh-keygen -t ed25519`
2. Install the public key in the container: `ssh-copy-id -p 2222 dev@localhost` (from the server), or paste `~/.ssh/id_ed25519.pub` into `/home/dev/.ssh/authorized_keys` (`~/.ssh` = 700, `authorized_keys` = 600).
3. Confirm key login works in a **separate terminal** before disabling passwords, to avoid lockout.
4. In the container's `/etc/ssh/sshd_config` (or a file in `/etc/ssh/sshd_config.d/`):
   ```
   PasswordAuthentication no
   PermitRootLogin no
   AllowTcpForwarding yes
   ```
5. Restart sshd and bake these settings into the Dockerfile so they survive a rebuild.

### Other follow-ups
- Make sure `/etc/ssh/ssh_host_*` and `/home/dev` are in Docker volumes (stable host key, IDE backend not re-downloaded).
- Keep the Access application with a Service Auth policy on `ssh.ppcoder.xyz` at all times.
- Treat the service token like a password. Store it in `~/.config/cfssh-proxy/credentials` with mode 0600.
