# How to publish a release (what *you* run, what the CI does)

A push of a tag like `v1.1.0` is all it takes. The workflow
(`.github/workflows/ci.yml`) builds, tests, and attaches every binary to
the GitHub Release automatically.

## One-time setup (only if you haven't pushed at all yet)

```bash
git push -u origin main
```

Auth: the sandbox has no stored GitHub credentials, so run this from your
own machine/terminal where a `gh auth login` token or HTTPS PAT is set up.
First push triggers the full CI (Linux+macOS+Windows) — give it ~15 min.

## Publish a release

```bash
git tag v1.0.0
git push origin v1.0.0
```

What happens next, automatically:

1. `linux-full`, `macos-tests`, `windows-tests` re-verify the tagged commit.
2. `release` (5-target matrix) builds and attaches to the release:
   - `cfssh-proxy-1.0.0-x86_64-unknown-linux-gnu`
   - `cfssh-proxy-1.0.0-aarch64-unknown-linux-gnu`
   - `cfssh-proxy-1.0.0-x86_64-apple-darwin`
   - `cfssh-proxy-1.0.0-aarch64-apple-darwin`
   - `cfssh-proxy-1.0.0-x86_64-pc-windows-msvc.exe` **plus `cfssh-gui-1.0.0.exe`**
   - each with a `.sha256`
3. Release page: https://github.com/prathameshpatil5181/clouflare-ssh-proxy/releases

Failed gate = no release: any of the three test jobs must pass before
`release` runs, so a red run means fix and re-tag (delete + push the tag
again: `git tag -d v1.0.0 && git push origin :refs/tags/v1.0.0`).

## Windows GUI portable zip (without a tag)

`git push` alone builds `cfssh-gui-portable.zip` on every commit as a CI
**artifact** (Actions tab → latest run → `gui-portable-windows`).
Artifacts require a GitHub login to download; Release section files do
not. If you just want a link to share, tag it.

## Before a new tag — quick pre-flight (mirrors CI)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --features gui --all-targets -- -D warnings
cargo test
./scripts/e2e.sh                       # Linux; needs openssh-server
```
