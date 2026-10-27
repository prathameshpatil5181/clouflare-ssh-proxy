//! cfssh-proxy — the connection engine shared by every distribution:
//! the `cfssh-proxy` CLI (ProxyCommand / `--listen` forwarder / subcommands)
//! and the GUI app. This crate is the single source of tunnel behavior.

pub mod bridge;
pub mod config;
pub mod engine;
pub mod error;
pub mod known_hosts;
pub mod subcommands;
pub mod tunnel;

/// Install the rustls `ring` CryptoProvider once per process. Selecting
/// explicitly (ring) avoids rustls' ambiguous-provider panic when multiple
/// backends end up in the dependency tree. Idempotent; never fails hard.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
