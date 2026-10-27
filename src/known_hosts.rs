//! OpenSSH `known_hosts` pin management — the generic side of the "container
//! was recreated and its host key changed" recovery flow.
//!
//! Two operations, both completely generic (no repo/container/URL knowledge):
//! - [`remove_entries`]: drop every pin for one or more endpoints (plain,
//!   non-standard-port `[host]:port`, and OpenSSH-hashed `|1|salt|hash`
//!   entries). Equivalent to `ssh-keygen -R`, with hash support built in.
//! - [`append_entries`]: pin a freshly learned key under the exact host form
//!   the client will later use.
//! - [`fingerprint`]: OpenSSH-style `SHA256:…` fingerprint of a key blob.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::error::Error;

/// One ssh endpoint as the *client* sees it (host + optional port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    pub host: String,
    pub port: Option<u16>,
}

impl HostPort {
    pub fn new(host: impl Into<String>, port: Option<u16>) -> Self {
        HostPort {
            host: host.into(),
            port,
        }
    }

    /// Host-parts a known_hosts entry can use for this endpoint:
    /// bare `host`, plus `[host]:port` when the port is non-standard.
    pub fn candidates(&self) -> Vec<String> {
        match self.port {
            None | Some(22) => vec![self.host.clone()],
            Some(p) => vec![format!("[{}]:{}", self.host, p)],
        }
    }

    /// The host-part written when pinning a key for this endpoint.
    pub fn pin_host(&self) -> String {
        match self.port {
            None | Some(22) => self.host.clone(),
            Some(p) => format!("[{}]:{}", self.host, p),
        }
    }
}

fn is_hashed(host_field: &str) -> bool {
    host_field.starts_with("|1|")
}

/// Match an OpenSSH hashed host entry (`|1|<salt b64>|<hmac b64>`) against the
/// candidate forms. OpenSSH hashes = HMAC-SHA1(salt, host_string); ring
/// exposes SHA-1 HMAC strictly for such legacy uses.
fn hashed_matches(host_field: &str, candidates: &[String]) -> bool {
    let parts: Vec<&str> = host_field.split('|').collect();
    if parts.len() != 4 || parts[1] != "1" {
        return false;
    }
    let (Ok(salt), Ok(digest)) = (B64.decode(parts[2]), B64.decode(parts[3])) else {
        return false;
    };
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
    candidates
        .iter()
        .any(|c| ring::hmac::sign(&key, c.as_bytes()).as_ref() == digest.as_slice())
}

fn hosts_part_matches(hosts_field: &str, candidates: &[String]) -> bool {
    hosts_field.split(',').any(|single| {
        if is_hashed(single) {
            hashed_matches(single, candidates)
        } else {
            candidates.contains(&single.to_string())
        }
    })
}

/// Remove every pin (all key types) for the given endpoints from a
/// known_hosts file. Missing file is not an error (nothing pinned yet).
/// Returns the number of lines removed.
pub fn remove_entries(path: &Path, endpoints: &[HostPort]) -> Result<usize, Error> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(Error::WsSetup(format!(
                "cannot read known_hosts {}: {e}",
                path.display()
            )))
        }
    };

    let candidates: Vec<String> = endpoints.iter().flat_map(|e| e.candidates()).collect();
    let mut out = String::with_capacity(text.len());
    let mut removed = 0usize;
    for line in text.lines() {
        // First whitespace-separated field is the hosts list ("host",
        // "[host]:port", "|1|salt|hash", or comma-separated forms). Lines
        // without a hosts field are preserved as-is.
        let hosts_field = line.split_whitespace().next().unwrap_or("");
        let keep = hosts_field.is_empty() || !hosts_part_matches(hosts_field, &candidates);
        if keep {
            out.push_str(line);
            out.push('\n');
        } else {
            removed += 1;
        }
    }
    if removed > 0 {
        write_atomic(path, &out)?;
    }
    Ok(removed)
}

/// Append pin lines for one endpoint, under the host form the client uses.
/// Each line is `keytype key [comment]` (as produced by ssh-keyscan minus the
/// leading host field). Returns how many lines were written.
pub fn append_entries(
    path: &Path,
    endpoint: &HostPort,
    key_lines: &[String],
) -> Result<usize, Error> {
    let hostpart = endpoint.pin_host();
    let mut out = fs::read_to_string(path).unwrap_or_default();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    let mut added = 0usize;
    for line in key_lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push_str(&format!("{hostpart} {line}\n"));
        added += 1;
    }
    if added > 0 {
        write_atomic(path, &out)?;
    }
    Ok(added)
}

/// OpenSSH-style `SHA256:<base64>` fingerprint of a base64-encoded key blob
/// (the third field of a known_hosts line or ssh-keyscan output).
pub fn fingerprint(key_blob: &str) -> Result<String, Error> {
    let blob = B64
        .decode(key_blob.trim())
        .map_err(|e| Error::WsSetup(format!("invalid key blob: {e}")))?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &blob);
    let mut s = B64.encode(digest.as_ref());
    while s.ends_with('=') {
        s.pop(); // OpenSSH strips padding in fingerprints
    }
    Ok(format!("SHA256:{s}"))
}

fn write_atomic(path: &Path, content: &str) -> Result<(), Error> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|e| Error::WsSetup(format!("cannot create {}: {e}", parent.display())))?;
    let tmp = parent.join(format!(
        ".known_hosts.tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));
    let mut f = fs::File::create(&tmp)
        .map_err(|e| Error::WsSetup(format!("cannot create {}: {e}", tmp.display())))?;
    f.write_all(content.as_bytes())
        .map_err(|e| Error::WsSetup(format!("cannot write {}: {e}", tmp.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::WsSetup(format!("cannot chmod {}: {e}", tmp.display())))?;
    }
    fs::rename(&tmp, path).map_err(|e| {
        Error::WsSetup(format!(
            "cannot rename {} -> {}: {e}",
            tmp.display(),
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpfile(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cfssh-kh-{}-{}", tag, std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        dir.join("known_hosts")
    }

    fn hashed_line_for(candidate: &str, salt: &[u8]) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
        let mac = ring::hmac::sign(&key, candidate.as_bytes());
        format!("|1|{}|{}", B64.encode(salt), B64.encode(mac.as_ref()))
    }

    #[test]
    fn remove_matches_plain_port_and_hashed_and_keeps_others() {
        let path = tmpfile("rm");
        let salt = b"12345678";
        let content = format!(
            "ssh.ppcoder.xyz ssh-ed25519 AAAA-OLD-A\n\
             [127.0.0.1]:22022 ssh-ed25519 AAAA-OLD-B\n\
             {} ssh-rsa AAAA-OLD-HASHED\n\
             other.host.example ssh-ed25519 KEEP-ME\n",
            hashed_line_for("ssh.ppcoder.xyz", salt)
        );
        std::fs::write(&path, &content).unwrap();

        let removed = remove_entries(
            &path,
            &[
                HostPort::new("ssh.ppcoder.xyz", None),
                HostPort::new("127.0.0.1", Some(22022)),
            ],
        )
        .unwrap();

        assert_eq!(removed, 3, "plain + port + hashed pins must go");
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("other.host.example ssh-ed25519 KEEP-ME"));
        assert!(!after.contains("AAAA-OLD-A"));
        assert!(!after.contains("AAAA-OLD-B"));
        assert!(!after.contains("AAAA-OLD-HASHED"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remove_missing_file_is_zero() {
        let path = std::env::temp_dir().join(format!("cfssh-kh-missing-{}", std::process::id()));
        assert_eq!(
            remove_entries(&path, &[HostPort::new("x", None)]).unwrap(),
            0
        );
    }

    #[test]
    fn append_uses_bracketed_port_form() {
        let path = tmpfile("ap");
        let n = append_entries(
            &path,
            &HostPort::new("ssh.ppcoder.xyz", Some(2222)),
            &["ssh-ed25519 AAAA-NEW".to_string()],
        )
        .unwrap();
        assert_eq!(n, 1);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("[ssh.ppcoder.xyz]:2222 ssh-ed25519 AAAA-NEW"));
        // idempotent-ish second write leaves a valid file
        append_entries(&path, &HostPort::new("host", None), &["ssh-rsa K2".into()]).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("host ssh-rsa K2"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fingerprint_is_openssh_style() {
        // 32 zero bytes -> deterministic digest; assert format + stability.
        let blob = B64.encode([0u8; 32]);
        let fp = fingerprint(&blob).unwrap();
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp[7..].len(), 43); // base64(32B) sans padding
        assert!(!fp.contains('='));
        assert_eq!(fp, fingerprint(&format!("  {blob}\n")).unwrap()); // trims
    }
}
