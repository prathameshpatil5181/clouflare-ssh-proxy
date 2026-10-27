//! cfssh-gui — Windows-first desktop app around the same engine the CLI uses.
//! Skeleton for now; the full eframe UI (connect panel, tray, host keys) is
//! the next phase. Built with `cargo build --features gui --bin cfssh-gui`.

fn main() {
    cfssh_proxy::install_crypto_provider();
    eprintln!("cfssh-gui {} (skeleton)", env!("CARGO_PKG_VERSION"));
}
