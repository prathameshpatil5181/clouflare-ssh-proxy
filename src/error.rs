use std::fmt;
use std::path::PathBuf;

/// A string that must never appear in logs or Debug output.
///
/// All logs and error messages go through types that redact this value, so the
/// Cloudflare Access client secret can never leak to stderr/stdout.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }

    /// Intentional, explicit access to the raw value (only for sending auth headers).
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(REDACTED)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("stdin/stdout error: {0}")]
    Stdio(#[from] std::io::Error),

    #[error("missing credentials. Supply them via one of: 1) --client-id/--client-secret flags, 2) CF_ACCESS_CLIENT_ID/CF_ACCESS_CLIENT_SECRET environment variables, 3) --token-file <PATH> (TOML or KEY=VALUE file with keys client_id, client_secret), 4) the default file ~/.config/cfssh-proxy/credentials")]
    MissingCredentials,

    #[error("invalid credentials file {0}: expected keys `client_id` and `client_secret` (TOML or KEY=VALUE format)")]
    BadCredentialsFile(PathBuf),

    #[error(
        "insecure permissions on credentials file {0}: refusing to use it (accessible by group/others). \
Fix with: chmod 600 {0}  — or pass --allow-insecure-perms to use it anyway (not recommended)"
    )]
    InsecureCredentialsPerms(PathBuf),

    #[error("invalid target: `{0}` is a plaintext ws:// URL; plaintext is only allowed with the test-only --insecure-ws flag")]
    PlaintextWs(String),

    #[error("invalid target: `{0}` (expected a bare hostname or a wss:// / https:// URL)")]
    BadTarget(String),

    #[error("connection failed: {0}")]
    Connect(String),

    #[error("authentication failed: HTTP {status} from Cloudflare Access. The service token was sent but rejected. \
Check that the Access application for this hostname has a Service Auth policy including this token \
(CF-Access-Client-Id: {client_id})")]
    AccessDeniedWithToken { status: u16, client_id: String },

    #[error("authentication failed: HTTP {status} from Cloudflare Access, and NO service token was sent because none is configured. \
If this hostname is protected by Zero Trust Access, supply a service token via --client-id/--client-secret, \
CF_ACCESS_CLIENT_ID/CF_ACCESS_CLIENT_SECRET, --token-file, or ~/.config/cfssh-proxy/credentials")]
    AccessDeniedNoToken { status: u16 },

    #[error("the service token was not accepted: Cloudflare redirected to the Access login page (HTTP 302, Location: {location}). \
A hostname route like this usually requires a Service Auth policy; plain Allow/SSO policies do not accept service tokens")]
    AccessRedirect { location: String },

    #[error("HTTP {status} from Cloudflare: the Tunnel cannot reach the origin (this is often reported as 'error code: 1033'). \
Check on the server that cloudflared is running (`systemctl status cloudflared`) and that the origin service (e.g. port 2222) is up")]
    OriginUnreachable { status: u16 },

    #[error("unexpected HTTP status {0} during the WebSocket upgrade (expected 101 Switching Protocols)")]
    UnexpectedStatus(u16),

    #[error("WebSocket/TLS setup failed: {0}")]
    WsSetup(String),

    #[error("connection error: {0}")]
    Io(String),
}

impl Error {
    /// Process exit code for `main`.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::MissingCredentials
            | Error::BadCredentialsFile(_)
            | Error::InsecureCredentialsPerms(_) => 2,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_redacted() {
        let s = Secret::new("topsecret123");
        assert_eq!(format!("{:?}", s), "Secret(REDACTED)");
        assert_eq!(format!("{}", s), "REDACTED");
        // also check any derived containers
        let bundle = vec![s.clone()];
        let dbg = format!("{:?}", bundle);
        assert!(!dbg.contains("topsecret"), "debug leaked secret: {dbg}");
        // explicit access still works internally
        assert_eq!(s.expose(), "topsecret123");
    }

    #[test]
    fn exit_codes() {
        assert_eq!(Error::MissingCredentials.exit_code(), 2);
        assert_eq!(
            Error::InsecureCredentialsPerms(PathBuf::from("x")).exit_code(),
            2
        );
        assert_eq!(Error::UnexpectedStatus(418).exit_code(), 1);
    }
}
