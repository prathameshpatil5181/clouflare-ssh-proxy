use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Secret};

/// CLI-provided credentials (highest priority source).
#[derive(Debug, Default, Clone)]
pub struct CliCredentials {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// Environment-provided credential variables. Abstracted so resolution can be
/// unit-tested without mutating the real process environment.
pub struct EnvSource {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl EnvSource {
    pub fn from_real_env() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        EnvSource {
            client_id: var("CF_ACCESS_CLIENT_ID"),
            client_secret: var("CF_ACCESS_CLIENT_SECRET"),
        }
    }

    #[cfg(test)]
    fn empty() -> Self {
        EnvSource {
            client_id: None,
            client_secret: None,
        }
    }
}

impl From<&BTreeMap<String, String>> for EnvSource {
    fn from(map: &BTreeMap<String, String>) -> Self {
        // keep this private-ish: only needed by tests
        EnvSource {
            client_id: map.get("CF_ACCESS_CLIENT_ID").cloned(),
            client_secret: map.get("CF_ACCESS_CLIENT_SECRET").cloned(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub client_id: String,
    pub client_secret: Secret,
}

const DEFAULT_FILE: &str = "cfssh-proxy/credentials";

/// Resolve credentials, in priority order:
/// 1. CLI flags
/// 2. `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` env vars
/// 3. `--token-file <PATH>`
/// 4. Default file `~/.config/cfssh-proxy/credentials`
///
/// Returns `Ok(None)` when no source supplies credentials: tunnels published
/// on a public hostname *without* a Cloudflare Access application accept the
/// WebSocket upgrade anonymously, and the headers are simply not sent.
/// Half-credentials from one source (only one of id/secret) are still an error.
pub fn resolve_credentials(
    cli: &CliCredentials,
    env: &EnvSource,
    token_file: Option<&Path>,
    allow_insecure_perms: bool,
) -> Result<Option<Credentials>, Error> {
    // 1. CLI flags (both halves must come from the same source)
    if let (Some(id), Some(sec)) = (&cli.client_id, &cli.client_secret) {
        tracing::debug!(client_id = %id, "using credentials from CLI flags");
        return Ok(Some(Credentials {
            client_id: id.clone(),
            client_secret: Secret::new(sec.clone()),
        }));
    }
    if cli.client_id.is_some() != cli.client_secret.is_some() {
        return Err(Error::MissingCredentials);
    }

    // 2. Environment variables
    if let (Some(id), Some(sec)) = (&env.client_id, &env.client_secret) {
        tracing::debug!(client_id = %id, "using credentials from environment");
        return Ok(Some(Credentials {
            client_id: id.clone(),
            client_secret: Secret::new(sec.clone()),
        }));
    }
    if env.client_id.is_some() != env.client_secret.is_some() {
        return Err(Error::MissingCredentials);
    }

    // 3. Explicit token file
    if let Some(path) = token_file {
        let creds = load_credentials_file(path, allow_insecure_perms)?;
        tracing::debug!(client_id = %creds.client_id, path = %path.display(), "using credentials from --token-file");
        return Ok(Some(creds));
    }

    // 4. Default credentials file (skipped silently when absent)
    let Some(default_path) = default_credentials_path() else {
        tracing::debug!("no Access credentials configured; connecting without Access headers");
        return Ok(None);
    };
    if !default_path.exists() {
        tracing::debug!("no Access credentials configured; connecting without Access headers");
        return Ok(None);
    }
    let creds = load_credentials_file(&default_path, allow_insecure_perms)?;
    tracing::debug!(client_id = %creds.client_id, path = %default_path.display(), "using credentials from default file");
    Ok(Some(creds))
}

fn default_credentials_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(DEFAULT_FILE))
}

fn load_credentials_file(path: &Path, allow_insecure_perms: bool) -> Result<Credentials, Error> {
    let bytes = fs::read_to_string(path).map_err(|e| {
        Error::WsSetup(format!(
            "cannot read credentials file {}: {}",
            path.display(),
            e
        ))
    })?;
    parse_credentials(&bytes).ok_or_else(|| Error::BadCredentialsFile(path.to_path_buf()))?;

    check_credentials_file_permissions(path, allow_insecure_perms)?;

    parse_credentials(&bytes)
        .map(|(id, secret)| Credentials {
            client_id: id,
            client_secret: Secret::new(secret),
        })
        .ok_or_else(|| Error::BadCredentialsFile(path.to_path_buf()))
}

/// Parse a credentials file: TOML (`client_id = "..."`) or `KEY=VALUE` lines.
/// Returns (client_id, client_secret).
pub fn parse_credentials(text: &str) -> Option<(String, String)> {
    // Try TOML first.
    #[derive(serde::Deserialize)]
    struct TomlCreds {
        client_id: Option<String>,
        client_secret: Option<String>,
    }
    if let Ok(c) = toml::from_str::<TomlCreds>(text) {
        if let (Some(id), Some(secret)) = (c.client_id, c.client_secret) {
            if !id.trim().is_empty() && !secret.trim().is_empty() {
                return Some((id.trim().to_string(), secret.trim().to_string()));
            }
        }
    }

    // Fall back to KEY=VALUE lines.
    let mut id = None;
    let mut secret = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
        match k.trim() {
            "client_id" => id = Some(v),
            "client_secret" => secret = Some(v),
            _ => {}
        }
    }
    let (id, secret) = (id?, secret?);
    if id.trim().is_empty() || secret.trim().is_empty() {
        return None;
    }
    Some((id.trim().to_string(), secret.trim().to_string()))
}

/// On Unix: refuse (unless `allow_insecure_perms`) if the file is readable by
/// group/others (wider than 0600).
pub fn check_credentials_file_permissions(
    path: &Path,
    allow_insecure_perms: bool,
) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = fs::metadata(path)
            .map_err(|e| {
                Error::WsSetup(format!(
                    "cannot stat credentials file {}: {}",
                    path.display(),
                    e
                ))
            })?
            .mode();
        if mode & 0o077 != 0 {
            if allow_insecure_perms {
                tracing::warn!(
                    path = %path.display(),
                    "credentials file permissions are wider than 0600 (continuing because of --allow-insecure-perms)"
                );
            } else {
                return Err(Error::InsecureCredentialsPerms(path.to_path_buf()));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, allow_insecure_perms);
    }
    Ok(())
}

/// Normalize the CLI target into a `wss://host[...]` URL.
///
/// Accepted inputs:
/// - bare hostname / host[:port]  -> wss://host
/// - `https://host`               -> wss://host
/// - `wss://host`                 -> unchanged (minus a trailing slash)
/// - `ws://host` / `http://host`  -> rejected unless `allow_insecure` (test mode)
pub fn normalize_target(raw: &str, allow_insecure: bool) -> Result<String, Error> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Error::BadTarget(raw.to_string()));
    }

    let lowered = raw.to_ascii_lowercase();
    if let Some(rest) = lowered
        .strip_prefix("ws://")
        .or(lowered.strip_prefix("http://"))
    {
        if !allow_insecure {
            return Err(Error::PlaintextWs(raw.to_string()));
        }
        let host_port = &raw[(raw.len() - rest.len())..].trim_end_matches('/');
        return Ok(format!("ws://{host_port}"));
    }

    let host_port = if let Some(rest) = lowered.strip_prefix("https://") {
        raw[(raw.len() - rest.len())..].to_string()
    } else if let Some(rest) = lowered.strip_prefix("wss://") {
        raw[(raw.len() - rest.len())..].to_string()
    } else if lowered.contains("://") {
        return Err(Error::BadTarget(raw.to_string()));
    } else {
        raw.to_string()
    };

    let host_port = host_port.trim_end_matches('/');
    if host_port.is_empty() {
        return Err(Error::BadTarget(raw.to_string()));
    }
    // Bare hostnames follow the flag too: with --insecure-ws they go plaintext.
    let scheme = if allow_insecure { "ws" } else { "wss" };
    Ok(format!("{scheme}://{host_port}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn env(pairs: &[(&str, &str)]) -> EnvSource {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v.to_string());
        }
        EnvSource::from(&m)
    }

    fn cli(id: Option<&str>, secret: Option<&str>) -> CliCredentials {
        CliCredentials {
            client_id: id.map(str::to_string),
            client_secret: secret.map(str::to_string),
        }
    }

    #[test]
    fn priority_cli_over_everything() {
        let cli = cli(Some("cli-id"), Some("cli-sec"));
        let env = env(&[
            ("CF_ACCESS_CLIENT_ID", "env-id"),
            ("CF_ACCESS_CLIENT_SECRET", "env-sec"),
        ]);
        let c = resolve_credentials(&cli, &env, None, false)
            .unwrap()
            .expect("some creds");
        assert_eq!(c.client_id, "cli-id");
        assert_eq!(c.client_secret.expose(), "cli-sec");
    }

    #[test]
    fn half_credentials_rejected() {
        let env = env(&[("CF_ACCESS_CLIENT_ID", "only-id")]);
        assert!(matches!(
            resolve_credentials(&cli(None, None), &env, None, false),
            Err(Error::MissingCredentials)
        ));
        assert!(matches!(
            resolve_credentials(&cli(Some("only"), None), &EnvSource::empty(), None, false),
            Err(Error::MissingCredentials)
        ));
    }

    #[test]
    fn no_credentials_means_anonymous() {
        // Tunnels without an Access application must work with no token at all.
        assert!(
            resolve_credentials(&cli(None, None), &EnvSource::empty(), None, false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn priority_env_over_token_file() {
        let env = env(&[
            ("CF_ACCESS_CLIENT_ID", "env-id"),
            ("CF_ACCESS_CLIENT_SECRET", "env-sec"),
        ]);
        let c = resolve_credentials(&cli(None, None), &env, None, false)
            .unwrap()
            .expect("some creds");
        assert_eq!(c.client_id, "env-id");
        assert_eq!(c.client_secret.expose(), "env-sec");
    }

    #[test]
    #[cfg(unix)]
    fn token_file_toml() {
        let dir = std::env::temp_dir().join(format!("cfssh-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token.toml");
        std::fs::write(
            &path,
            "client_id = \"toml-id\"\nclient_secret = \"toml-secret\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let c = resolve_credentials(&cli(None, None), &EnvSource::empty(), Some(&path), false)
            .unwrap()
            .expect("some creds");
        assert_eq!(c.client_id, "toml-id");
        assert_eq!(c.client_secret.expose(), "toml-secret");
    }

    #[test]
    fn token_file_keyvalue() {
        let text = "# comment\nclient_id=kv-id\nclient_secret = \"kv-secret\"\nother=1\n";
        let (id, secret) = parse_credentials(text).unwrap();
        assert_eq!(id, "kv-id");
        assert_eq!(secret, "kv-secret");
    }

    #[test]
    fn parse_credentials_bad() {
        assert!(parse_credentials("client_id = \"only id\"").is_none());
        assert!(parse_credentials("\n\n").is_none());
    }

    #[test]
    fn missing_credentials_error_lists_sources() {
        // The error survives for the half-credential case: it must tell the
        // user all the places a token can come from.
        let env = env(&[("CF_ACCESS_CLIENT_ID", "only-id")]);
        let err = resolve_credentials(&cli(None, None), &env, None, false).unwrap_err();
        let msg = err.to_string();
        for needle in [
            "--client-id",
            "CF_ACCESS_CLIENT_ID",
            "--token-file",
            "cfssh-proxy/credentials",
        ] {
            assert!(msg.contains(needle), "error text missing `{needle}`: {msg}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn insecure_permissions_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cfssh-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("creds");
        std::fs::write(&path, "client_id = \"a\"\nclient_secret = \"b\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            load_credentials_file(&path, false),
            Err(Error::InsecureCredentialsPerms(_))
        ));
        // with the flag, it is used but warns
        let c = load_credentials_file(&path, true).unwrap();
        assert_eq!(c.client_id, "a");
    }

    #[cfg(unix)]
    #[test]
    fn secure_permissions_ok() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cfssh-perm-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("creds");
        std::fs::write(&path, "client_id = \"a\"\nclient_secret = \"b\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_credentials_file(&path, false).is_ok());
    }

    #[test]
    fn normalize_targets() {
        assert_eq!(
            normalize_target("ssh.ppcoder.xyz", false).unwrap(),
            "wss://ssh.ppcoder.xyz"
        );
        assert_eq!(
            normalize_target("https://ssh.ppcoder.xyz", false).unwrap(),
            "wss://ssh.ppcoder.xyz"
        );
        assert_eq!(
            normalize_target("wss://ssh.ppcoder.xyz/", false).unwrap(),
            "wss://ssh.ppcoder.xyz"
        );
        assert_eq!(
            normalize_target("host:8443", false).unwrap(),
            "wss://host:8443"
        );
        // plaintext rejected without the flag
        assert!(matches!(
            normalize_target("ws://host", false),
            Err(Error::PlaintextWs(_))
        ));
        assert!(matches!(
            normalize_target("http://host", false),
            Err(Error::PlaintextWs(_))
        ));
        // allowed with the flag
        assert_eq!(
            normalize_target("ws://127.0.0.1:9000", true).unwrap(),
            "ws://127.0.0.1:9000"
        );
        assert_eq!(
            normalize_target("http://127.0.0.1:9000", true).unwrap(),
            "ws://127.0.0.1:9000"
        );
        // a bare host with the flag also goes plaintext (mock-edge tests rely on it)
        assert_eq!(
            normalize_target("127.0.0.1:9000", true).unwrap(),
            "ws://127.0.0.1:9000"
        );
        // garbage
        assert!(normalize_target("", false).is_err());
        assert!(normalize_target("ftp://host", false).is_err());
    }
}
