# Changelog

## 1.0.0 — 2026-10-29

First tagged release. Tunnel proxy + desktop GUI for reaching an SSH
server (e.g. a Docker container `dev@`) through a Cloudflare Tunnel —
no `cloudflared` and no WARP on the client machine.

### Highlights

- **`cfssh-proxy`** (CLI): OpenSSH `ProxyCommand` bridge over
  `wss://<your-tunnel-host>`; `--listen` mode turns it into a plain
  local TCP listener for IDEs that ignore ProxyCommand.
- **`cfssh-gui`** (Windows-first desktop app): one-click Connect /
  Disconnect with a colored status banner, live **Devices** table
  (session id, source address, uptime, up/down bytes), VS Code
  Remote-SSH config writer, host-key learning (TOFU) without
  ssh-keyscan, single-instance lock, settings saved as you type.
- **Reliability work that 1.0 earned its keep on**: abrupt client
  disconnects no longer look like failures; session errors surface in
  the UI (never hidden behind a green banner); the tunnel host is
  DNS-preflighted at Connect — a typo fails once, loudly, naming the
  field (three separate host typos motivated this).
- **Honest connection state**: "Connected" means the backend SSH is
  actually answering, not just that the tunnel is green. The engine
  probes the origin (sshd's greeting banner) right after Connect and
  every 60 s, and any session that dies before a single byte comes
  back from the origin is reported the same way. A dead backend now
  shows a red "Listener up · the backend origin is NOT answering"
  banner (and an amber tray icon) instead of a misleading green
  "Connected" — the production failure class of 2026-10-29.
- **Usable logs**: UTC timestamps, no ANSI, third-party render spam
  clamped by default, live substring filter in the Logs tab,
  `CFSSH_LOUD=1` / `RUST_LOG=debug` for full detail.
- Test suite grew to 46 items across 3 layers (unit, integration with
  a hand-rolled RFC 6455 mock edge, and a real-OpenSSH e2e), plus
  platform CI on Ubuntu/macOS/Windows and a 5-target release matrix.

### Notes for testers of earlier builds

- If your stored tunnel host was a typo (`ssh.ppdev.xyz` /
  `ssh.ppcoder.dev`), Connect now catches it immediately.
- The GUI settings round-trip test no longer touches the real user
  profile.
- eframe ships with `default_fonts` (trimming it once left the GUI
  booting with zero font bytes).
