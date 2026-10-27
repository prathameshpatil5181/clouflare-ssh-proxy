.PHONY: build test e2e live check fmt clippy clean release

build:
	cargo build

## Layer 1 + 2: unit tests and integration tests (no external listeners)
test:
	cargo test

## Layer 3: real sshd + mock edge + real OpenSSH ProxyCommand (Linux/Unix)
e2e:
	./scripts/e2e.sh

## Optional: live test against the real Cloudflare tunnel
## (requires CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET, optional LIVE_HOST)
live:
	./scripts/live-test.sh

check: fmt clippy

fmt:
	cargo fmt --check

clippy:
	cargo clippy --all-targets -- -D warnings

release:
	cargo build --release

clean:
	cargo clean
