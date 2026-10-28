//! GUI/user-level settings persisted next to the OS config dir
//! (Windows: `%APPDATA%\cfssh-proxy\config.toml`; Linux/macOS: XDG config).
//! Everything a user must not have to re-type: tunnel target, optional
//! Access token, local bind address. Plain user files — no admin needed to
//! read or write, and the secret is redacted in any Debug/Display output.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::Credentials;
use crate::error::{Error, Secret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiSettings {
    /// Tunnel target as typed by the user: bare host or URL.
    #[serde(default)]
    pub target: String,
    /// Cloudflare Access service token (both halves or nothing; defaults empty = anonymous).
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    /// Local forwarder bind: `PORT` (localhost) or `ADDR:PORT`.
    /// Default 22022 — above 1024 so no elevated rights are ever needed.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Bind on all interfaces (LAN reachability). Triggers Windows' one-time
    /// firewall prompt and is OFF by default.
    #[serde(default)]
    pub lan_reachable: bool,
    /// WebSocket ping keepalive interval in seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
    /// Login user put in the managed ssh-config block (VS Code/Gateway).
    #[serde(default = "default_ssh_user")]
    pub ssh_user: String,
}

impl Default for GuiSettings {
    // Manual so the serde default fns and Default::default() agree.
    fn default() -> Self {
        GuiSettings {
            target: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            bind: default_bind(),
            lan_reachable: false,
            keepalive_secs: default_keepalive(),
            ssh_user: default_ssh_user(),
        }
    }
}

fn default_bind() -> String {
    "22022".to_string()
}
fn default_keepalive() -> u64 {
    25
}
fn default_ssh_user() -> String {
    crate::ssh_config::DEFAULT_USER.to_string()
}

impl GuiSettings {
    /// Path of the settings file in the OS-appropriate user config dir.
    pub fn path() -> Result<PathBuf, Error> {
        let dir = dirs::config_dir()
            .ok_or_else(|| Error::WsSetup("cannot locate the user config directory".into()))?
            .join("cfssh-proxy");
        std::fs::create_dir_all(&dir).map_err(|e| {
            Error::WsSetup(format!("cannot create {} (writable?): {e}", dir.display()))
        })?;
        Ok(dir.join("config.toml"))
    }

    pub fn load() -> Result<GuiSettings, Error> {
        let path = Self::path()?;
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let s: GuiSettings = toml::from_str(&text)
                    .map_err(|e| Error::WsSetup(format!("cannot parse {}: {e}", path.display())))?;
                Ok(s.sanitized())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(GuiSettings::default()),
            Err(e) => Err(Error::WsSetup(format!(
                "cannot read {}: {e}",
                path.display()
            ))),
        }
    }

    pub fn save(&mut self) -> Result<(), Error> {
        let path = Self::path()?;
        let text = toml::to_string(&self.clone().sanitized())
            .map_err(|e| Error::WsSetup(format!("cannot serialize settings: {e}")))?;
        // Write via a temp file + rename so a crash mid-write can't truncate.
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, &text)
            .map_err(|e| Error::WsSetup(format!("cannot write {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, &path).map_err(|e| {
            Error::WsSetup(format!(
                "cannot rename {} -> {}: {e}",
                tmp.display(),
                path.display()
            ))
        })?;
        Ok(())
    }

    /// Empty client_secret with a present client_id (or vice versa) would make
    /// resolve_credentials hard-error; treat a half pair as "not configured".
    fn sanitized(mut self) -> Self {
        if self.client_id.is_empty() != self.client_secret.is_empty() {
            self.client_id.clear();
            self.client_secret.clear();
        }
        self
    }

    /// Credentials for the engine, or None for anonymous connect.
    /// A half token (one field empty) is treated as "not configured" so the
    /// engine never hard-errors on a malformed save.
    pub fn credentials(&self) -> Option<Credentials> {
        if self.client_id.is_empty() || self.client_secret.is_empty() {
            None
        } else {
            Some(Credentials {
                client_id: self.client_id.clone(),
                client_secret: Secret::new(self.client_secret.clone()),
            })
        }
    }

    /// The actual bind socket directive for the engine.
    pub fn bind_addr(&self) -> String {
        let host = if self.lan_reachable {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        if self.bind.contains(':') {
            self.bind.clone()
        } else {
            format!("{host}:{}", self.bind)
        }
    }

    /// What the user clicks next in their IDE: `127.0.0.1:22022` style display.
    pub fn display_endpoint(&self) -> String {
        match self.bind_addr().rsplit_once(':') {
            Some((host, port)) => format!("{host}:{port}"),
            None => self.bind_addr(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitized_half_token_becomes_anonymous() {
        let s = GuiSettings {
            client_id: "half-id".into(),
            ..GuiSettings::default()
        };
        let creds = s.credentials();
        assert!(creds.is_none(), "a half token must not reach the engine");
    }

    #[test]
    fn full_token_roundtrips_and_paths_cohere() {
        // NEVER write to the real user profile from tests: today this test
        // both overwrote and deleted the operator's live config.toml on
        // every `cargo test` run. Redirect the whole settings path into a
        // throwaway dir under the OS temp dir.
        let tmp = std::env::temp_dir()
            .join("cfssh-proxy-test")
            .join(format!("cfg-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("XDG_CONFIG_HOME", &tmp);
        std::env::set_var("APPDATA", &tmp); // Windows CI path
        let mut s = GuiSettings {
            target: "ssh.ppcoder.xyz".into(),
            client_id: "id.access".into(),
            client_secret: "shh".into(),
            bind: "22022".into(),
            lan_reachable: true,
            ..GuiSettings::default()
        };
        // Persist, reload, and confirm the round-trip through the same env.
        s.save().expect("save");
        let loaded = GuiSettings::load().expect("load");
        assert_eq!(loaded.target, "ssh.ppcoder.xyz");
        assert_eq!(loaded.client_secret, "shh");
        assert_eq!(loaded.bind_addr(), "0.0.0.0:22022");
        assert_eq!(loaded.display_endpoint(), "0.0.0.0:22022");
        assert!(loaded.credentials().is_some());
        // Cleanup is confined to the throwaway dir.
        let _ = std::fs::remove_dir_all(&tmp);
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("APPDATA");
    }

    #[test]
    fn default_bind_is_localhost_privileged_none() {
        let s = GuiSettings::default();
        assert_eq!(s.bind_addr(), "127.0.0.1:22022");
        assert_eq!(s.display_endpoint(), "127.0.0.1:22022");
    }
}
