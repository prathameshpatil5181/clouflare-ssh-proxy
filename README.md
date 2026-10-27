# cfssh-proxy

Rust OpenSSH `ProxyCommand` helper that lets **IntelliJ IDEA / JetBrains
Gateway** reach a Docker dev container over SSH through a **Cloudflare
Tunnel**, with **no `cloudflared` or WARP on the local machine**. The only
local component is this small helper binary.

```
IntelliJ / Gateway -> OpenSSH (ProxyCommand: cfssh-proxy)
   -> wss://ssh.ppcoder.xyz -> Cloudflare -> cloudflared (server host)
   -> localhost:2222 -> Docker container sshd (port 22)
```

The tool transparently carries raw TCP bytes (the SSH protocol) in both
directions — it never interprets, modifies, or delay-batches them. It is not a
daemon: launched by OpenSSH through `ProxyCommand`, it lives for exactly one
SSH connection.

---

## 1. Cloudflare setup (server side)

1. **Tunnel route**: `ssh.ppcoder.xyz -> tcp://localhost:2222`. The `tcp://`
   scheme is correct because `cloudflared` runs on the Ubuntu host (not in
   Docker) and carries raw TCP over the WebSocket.
2. **Access application (OPTIONAL)**: only needed if you want Zero Trust
   protection on the hostname. If you publish the public hostname without an
   Access application, the WebSocket upgrade is accepted anonymously and no
   token is required — cfssh-proxy connects with **no credentials at all**.
   If you DO protect it, create a *self-hosted* Access application with a
   **Service Auth** policy (action = Service Auth, not Allow) that includes
   your service token; without this, anyone on the internet could try
   passwords against your container.
3. **Service token (only with Access)**: create it (Zero Trust dashboard →
   Access → Service Auth → tokens — client id + client secret). Treat the
   secret like a password.

### Verify the whole path without `cfssh-proxy`

With a token in the environment:

```bash
curl -i -N \
  -H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" \
  -H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET" \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://ssh.ppcoder.xyz
```

Without Access (public hostname, no Access app): same curl **minus the two
`CF-Access-*` headers** — you should still get `101` + the SSH banner if the
tunnel is set up.

| Result | Meaning |
|---|---|
| `101` + `SSH-2.0-...` banner | whole path works |
| `302` | an Access login page is in the way — the hostname has an Access policy that isn't Service Auth |
| `401`, `403` | hostname IS Access-protected and the token is missing/wrong |
| `502` / body `error code: 1033` | tunnel can't reach the origin |

---

## 2. Container setup (server side)

Requirements for a JetBrains-friendly dev container:

- **glibc-based** image (Ubuntu/Debian) — not Alpine.
- `openssh-server`, user `dev`, password login enabled (for now; see "later").
- `AllowTcpForwarding yes` in `/etc/ssh/sshd_config` (Gateway needs it).
- Tools Gateway uses to bootstrap backends: `curl`, `tar`, `gzip`, `procps`.
- Docker port mapping: `127.0.0.1:2222:22` (verify with `ss -tlnp`).
- Persist in volumes: `/etc/ssh/ssh_host_*` (stable host key), `/home/dev`,
  and `~/.cache/JetBrains` (so the IDE backend isn't re-downloaded).

See `examples/Dockerfile` + `examples/docker-compose.yml` for a working
starting point. Sanity check on the server: `ssh -p 2222 dev@localhost`.

### When the container is recreated (SSH host key changed) — one-line recovery

```bash
# Re-learn the CURRENT key through the tunnel and pin it (prints fingerprints):
cfssh-proxy trust ssh.ppcoder.xyz                                          # direct (client port 22)
cfssh-proxy trust ssh.ppcoder.xyz --client-host 127.0.0.1 --client-port 22022
                                                                           # via a --listen forwarder

# Only clear stale pins, without re-learning:
cfssh-proxy untrust ssh.ppcoder.xyz 127.0.0.1:22022
```

`trust` is Trust-On-First-Use with a fingerprint display: it runs the
ephemeral local tunnel bridge itself, scans the key with `ssh-keyscan`,
shows the `SHA256:…` fingerprint, and replaces the old pin. If the tunnel or
origin sshd is down, it fails with a clear error instead of pinning nothing.
Both subcommands are fully generic — any tunnel target, host, or port.

### Later: switch to key-only SSH login

1. On the laptop: `ssh-keygen -t ed25519`.
2. Install the public key in the container (from the server:
   `ssh-copy-id -p 2222 dev@localhost`, or paste into
   `/home/dev/.ssh/authorized_keys`; `~/.ssh` = 700, file = 600).
3. **Verify key login in a separate terminal before disabling passwords.**
4. In the container's `/etc/ssh/sshd_config` (or `sshd_config.d/*.conf`):

   ```
   PasswordAuthentication no
   PermitRootLogin no
   AllowTcpForwarding yes
   ```
5. Restart sshd and bake these settings into the Dockerfile (a rebuild must
   not undo them).

---

## 3. Installing cfssh-proxy (laptop)

Windows users: download **`cfssh-gui-portable.zip`** from the GitHub
releases/actions artifacts — it contains the desktop app (`cfssh-gui.exe`)
and the CLI (`cfssh-proxy.exe`). Unzip anywhere user-writable such as
`%LOCALAPPDATA%\cfssh-proxy` (no admin rights, no installer, no UAC), run
`cfssh-gui.exe`, type your tunnel host, click **Connect**, and point
IntelliJ/ssh at the shown `host:port` (default `127.0.0.1:22022`).
**Learn host key** (the ⟳ button) pins the sshd fingerprint through the
tunnel; run it again whenever the container/server is recreated.

CLI users on all platforms: grab a release binary for your platform
(Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64), or build it:

```bash
cargo build --release        # binary in target/release/cfssh-proxy
cargo build --release --features gui   # + the GUI app (cfssh-gui)
```

Put the binary on your `PATH` (e.g. `~/.local/bin/cfssh-proxy`).

### Credentials (optional)

**If your tunnel has no Access application on the hostname, you need none:
`cfssh-proxy ssh.ppcoder.xyz` connects anonymously with zero configuration.**

If the hostname is Access-protected, supply the service token (priority
order):

1. `--client-id <ID> --client-secret <SECRET>` flags
2. `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` environment variables
3. `--token-file <PATH>` (TOML or `KEY=VALUE` with keys `client_id`,
   `client_secret`)
4. Default file `~/.config/cfssh-proxy/credentials`, e.g. TOML:

   ```toml
   client_id = "my-id.access"
   client_secret = "my-secret"
   ```

On Unix a credentials file must be readable **only by you** (`chmod 600`);
the tool refuses wider permissions unless `--allow-insecure-perms` is given.
Only half a token (id without secret) is an error. The secret is always
redacted from logs; stderr is used for all output except the SSH bytes
themselves.

### SSH config

```
Host devbox
  HostName ssh.ppcoder.xyz
  User dev
  ProxyCommand cfssh-proxy %h
```

CLI reference:

```
cfssh-proxy <hostname> [--client-id <ID>] [--client-secret <SECRET>]
            [--token-file <PATH>] [--allow-insecure-perms] [--verbose]
```

Accepts a bare hostname, or an explicit `https://`/`wss://` URL, and
normalizes it. Plaintext `ws://` is refused (there is a hidden `--insecure-ws`
used only by the test suite).

---

## 4. IntelliJ / JetBrains Gateway setup

### Preferred: the `devbox` alias (ProxyCommand)

1. Install the binary and the `~/.ssh/config` entry above.
2. Test from a terminal first: `ssh -v devbox` (it will prompt for the
   container password — output of typing goes through the TTY, the tool
   never touches it).
3. In IntelliJ: **Settings → Tools → SSH Configuration → check "Use OpenSSH
   config and authentication agent"**, or in Gateway's SSH-level wizard.
   Without this, IntelliJ builds its own connection and ignores
   `ProxyCommand`. *Note: some IntelliJ versions resolve the alias with DNS
   before consulting the config ("\_host not found\_" on `devbox`). If Test
   Connection fails that way, use the fallback below.*
4. In Gateway, use Host `devbox` / IDE deployment target of the container.

### Fallback: `--listen` (plain local port — no proxy config at all)

Run the proxy as a small local forwarder:

```bash
cfssh-proxy --listen 22022 ssh.ppcoder.xyz &
```

Every connection to `127.0.0.1:22022` gets its own WebSocket through the
tunnel (multiplexing unlimited parallel connections; Ctrl-C stops it).
Then in IntelliJ/Gateway use:

| Setting | Value |
|---|---|
| Host | `127.0.0.1` |
| Port | `22022` |
| Username | `dev` |
| Auth | password (or whatever the container allows) |

No ProxyCommand, no "Use OpenSSH config" checkbox needed — the IDE sees an
ordinary SSH host.

### VS Code Remote-SSH

VS Code drives the system OpenSSH client, so it honors the same local
forwarder. Two ways to hook it up:

**One click from the GUI** — click **"Write ssh config entry (VS Code)"**
in the right panel. The app appends (or repairs) one delimited block to your
SSH config, idempotently and without touching anything else:

```
# --- cfssh-proxy ( managed block; safe to edit or delete ) ---
Host cfssh-dev
    HostName 127.0.0.1
    Port 22322
    User dev
# --- end cfssh-proxy ---
```

(`Port` follows the GUI's forwarder port; `User` is the **SSH user** field.)
Then in VS Code: `F1` → **Remote-SSH: Connect to Host…** → `cfssh-dev`.
Re-run the button whenever you change the port or user in the GUI; the block
is updated in place.

**Manual** — add the block above to `~/.ssh/config` (Windows: 
`%USERPROFILE%\.ssh\config`) yourself, or add a `Host cfssh-dev` entry with
`HostName 127.0.0.1` / `Port <forwarder port>`.

Notes:

- The tunnel's host key is pinned per-client-endpoint: after **Learn host
  key** or `trust`, `[127.0.0.1]:<port>` is in `known_hosts`, so VS Code's
  ssh connects without prompting — and refuses promptly if the key changes
  (container recreated), same as plain ssh.
- VS Code's remote host binary lands in the container (`~/.vscode-server`),
  and the container needs `bash` + download tooling — already true for the
  repo's Docker image.
- If you keep your SSH config elsewhere (`remote.SSH.configFile`), copy the
  block there; the GUI's button always writes the default location.

---

## 5. Self-tests

| Layer | Command | What it covers |
|---|---|---|
| 1+2 | `make test` (`cargo test`) | credential priority, half-token rejection, **anonymous connect with no credentials (no headers sent)**, host normalization, secret redaction, Unix file-permission checks; integration tests vs. a mock Cloudflare edge: byte-exact round trips (incl. 10 MiB and every byte value), header validation, anonymous handshake vs. Access-protected edge → clear 401 message, 401/403/302/502 messages, stdout purity, secret-leak checks, keepalive pings, fragmented frames, close/EOF semantics, backpressure memory bound |
| 3 | `make e2e` (`scripts/e2e.sh`) | real user-mode sshd + mock edge + real OpenSSH through ProxyCommand: command round trip, 50 MiB transfer with SHA-256, `ssh -L` port forwarding, idle-session survival, kill-edge mid-session |
| live | `make live` (`scripts/live-test.sh`) | your real tunnel: curl 101 check, banner check, prints the exact `ssh -v` command to try next, maps HTTP statuses to causes |

```bash
make test    # no internet account needed; no credentials needed either
make e2e     # Linux/Unix only (needs openssh-server)
make live    # optional; CF_ACCESS_* env vars are OPTIONAL (leave unset for an unprotected tunnel)
```

---

## 6. Troubleshooting

| Symptom | Likely cause & fix |
|---|---|
| `401` / `403` with "NO service token was sent" | The hostname IS Access-protected but no token is configured. Supply one via flags/env/token-file/default file. |
| `401` / `403` with a token configured | Token wrong, or the hostname's Access application policy doesn't include it. The policy action must be **Service Auth**. |
| `302` redirect | An Access login page is in the way (policy is not Service Auth): plain Allow/SSO policies do not accept service tokens. Fix the policy. |
| `502` / `error code: 1033` | Tunnel ↔ origin broken: on the server run `systemctl status cloudflared`; verify the container publishes `127.0.0.1:2222:22` (`ss -tlnp`). |
| Idle disconnects | keepalive Pings are sent (default 25 s; hidden `--keepalive-secs`). If you still see drops, check Cloudflare/proxy idle timeouts. |
| Connection hangs at start | run `ssh -v devbox` for detail; check the curl command in §1 to isolate tunnel vs. Access problems. |
| JetBrains can't connect | make sure "Use OpenSSH config and authentication agent" is enabled so `ProxyCommand` runs. |
| Password prompts | password auth uses the TTY (never stdin); the helper doesn't interfere. Consider key-only auth for the long term (§2). |

---

## 7. Design notes

- **stdout is sacred**: only SSH protocol bytes ever go to stdout; logs,
  verbose tracing, and errors go to stderr. The client secret is redacted in
  every log/Debug render.
- **Performance**: async I/O (`tokio`), ~32 KiB frames, bounded channel
  buffering with true backpressure; the receive side is never starved, so a
  serial peer can't wedge an echo deadlock. Large SFTP/Gateway transfers are
  the design target.
- **No OpenSSL** — rustls (ring provider). Static Linux builds
  (`x86_64-unknown-linux-musl`) are possible for easy deployment.
- Binary exists only for one SSH connection; no daemons.

## 8. Repository layout

```
src/            main.rs · bridge.rs (the pump) · config.rs (creds/target) · error.rs
tests/          integration.rs + tests/support/mock_edge.rs (fake CF edge)
examples/       mock_edge_runner.rs (local "cloudflared" stand-in for e2e)
scripts/        e2e.sh (layer 3) · live-test.sh (optional, real tunnel)
container/      Dockerfile + docker-compose.yml for the dev container
.github/        CI: layers 1-3 + release binaries
```
