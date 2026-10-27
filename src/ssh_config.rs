//! Managed SSH-config `Host` block for GUI-first clients (VS Code Remote-SSH,
//! JetBrains). The GUI writes/repairs ONE delimited block inside the user's
//! `~/.ssh/config` (`%USERPROFILE%\.ssh\config` on Windows) and everything
//! outside the markers is never touched.
//!
//! Why a block in the config instead of a per-app wrapper: Remote-SSH and
//! Gateway both drive the system OpenSSH client, which honors this file —
//! no plugin settings either of them may ignore.

use std::path::{Path, PathBuf};

use crate::error::Error;

pub const MANAGED_START: &str = "# --- cfssh-proxy ( managed block; safe to edit or delete ) ---";
pub const MANAGED_END: &str = "# --- end cfssh-proxy ---";
/// The alias VS Code picks from the Remote-SSH tree; short and unambiguous.
pub const DEFAULT_ALIAS: &str = "cfssh-dev";
/// Default login user on the container (matches README/container setup).
pub const DEFAULT_USER: &str = "dev";

pub const LISTEN_HOST: &str = "127.0.0.1";

/// `~/.ssh/config` of the current user. Creates the `.ssh` dir if missing.
pub fn path() -> Result<PathBuf, Error> {
    let home = dirs::home_dir()
        .ok_or_else(|| Error::WsSetup("cannot locate the home directory".into()))?;
    let dir = home.join(".ssh");
    std::fs::create_dir_all(&dir).map_err(|e| {
        Error::WsSetup(format!("cannot create {} (writable?): {e}", dir.display()))
    })?;
    Ok(dir.join("config"))
}

/// The exact block text for one endpoint. Deliberately byte-stable: `ensure`
/// compares this to what is already on disk.
pub fn block(alias: &str, listen_host: &str, port: u16, user: &str) -> String {
    format!(
        "{MANAGED_START}\nHost {alias}\n    HostName {listen_host}\n    Port {port}\n    User {user}\n{MANAGED_END}\n"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureOutcome {
    /// The file did not exist, or nothing managed was in it: block appended.
    Added,
    /// A managed block existed with different content: replaced.
    Updated,
    /// The exact desired block was already present.
    Unchanged,
}

/// Idempotently make the managed block say what it should. Content outside
/// the markers is preserved byte-for-byte.
pub fn ensure(
    path: &Path,
    alias: &str,
    listen_host: &str,
    port: u16,
    user: &str,
) -> Result<(EnsureOutcome, usize /* hosts now managed */), Error> {
    let desired = block(alias, listen_host, port, user);
    let text = std::fs::read_to_string(path).unwrap_or_default();

    // Locate the currently managed region, or heal a stray unclosed marker.
    let region: Option<std::ops::Range<usize>> = match (
        text.find(MANAGED_START),
        text.find(MANAGED_END),
    ) {
        (Some(s), Some(e)) if e > s => Some(s..e + MANAGED_END.len()),
        (Some(s), _) => {
            // A start without an end (manual paste / crash mid-write): treat
            // the stray marker line as unmanaged junk to keep, minus itself.
            let after = &text[s..];
            let body = after.find('\n').map(|n| &after[n + 1..]).unwrap_or("");
            let kept = format!("{}{body}", &text[..s]);
            write_with_permissions(path, &kept)?;
            return Ok((EnsureOutcome::Added, count_hosts(path)?));
        }
        _ => None,
    };

    if let Some(r) = &region {
        if text[r.clone()] == desired {
            return Ok((EnsureOutcome::Unchanged, count_hosts(path)?));
        }
    }

    let new_text = match region {
        Some(r) => {
            let mut out = String::with_capacity(text.len());
            out.push_str(&text[..r.start]);
            out.push_str(&desired);
            out.push_str(&text[r.end..]);
            out
        }
        None => {
            let mut t = text;
            if !t.is_empty() && !t.ends_with('\n') {
                t.push('\n');
            }
            t.push_str(&desired);
            t
        }
    };
    write_with_permissions(path, &new_text)?;
    let outcome = if region.is_some() {
        EnsureOutcome::Updated
    } else {
        EnsureOutcome::Added
    };
    Ok((outcome, count_hosts(path)?))
}

/// Remove every managed block; returns how many were found (0 = was clean).
pub fn remove_managed(path: &Path) -> Result<usize, Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(Error::WsSetup(format!(
                "cannot read ssh config {}: {e}",
                path.display()
            )))
        }
    };
    // Strip start..end pairs greedily.
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    let mut removed = 0;
    while let Some(start) = rest.find(MANAGED_START) {
        match rest[start..].find(MANAGED_END) {
            Some(off) => {
                out.push_str(&rest[..start]);
                rest = &rest[start + off + MANAGED_END.len()..];
                if let Some(stripped) = rest.strip_prefix('\n') {
                    rest = stripped;
                }
                removed += 1;
            }
            None => break,
        }
    }
    if removed == 0 {
        return Ok(0);
    }
    out.push_str(rest);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    write_with_permissions(path, &out)?;
    Ok(removed)
}

/// How many `Host` lines the managed block currently pins (0/1/…).
pub fn count_hosts(path: &Path) -> Result<usize, Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(Error::WsSetup(format!(
                "cannot read ssh config {}: {e}",
                path.display()
            )))
        }
    };
    let Some(start) = text.find(MANAGED_START) else { return Ok(0) };
    let region = text.get(start..).unwrap_or_default();
    let end = region.find(MANAGED_END).unwrap_or(region.len());
    Ok(region[..end]
        .lines()
        .filter(|l| l.trim().starts_with("Host "))
        .count())
}

fn write_with_permissions(path: &Path, text: &str) -> Result<(), Error> {
    use std::io::Write as _;
    let tmp = path.with_extension("cfssh.tmp");
    {
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| Error::WsSetup(format!("cannot create {}: {e}", tmp.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        f.write_all(text.as_bytes())
            .and_then(|_| f.flush())
            .map_err(|e| Error::WsSetup(format!("cannot write {}: {e}", tmp.display())))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        Error::WsSetup(format!("cannot rename {} -> {}: {e}", tmp.display(), path.display()))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("cfssh-ssh-config-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn ensure_added_then_idempotent_then_updated() {
        let p = tmp_path("add");
        // No pre-existing config.
        let (o, hosts) = ensure(&p, DEFAULT_ALIAS, LISTEN_HOST, 22322, DEFAULT_USER).unwrap();
        assert_eq!(o, EnsureOutcome::Added);
        assert_eq!(hosts, 1);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("Host cfssh-dev"));
        assert!(text.contains("Port 22322"));
        assert!(text.contains("User dev"));

        // Second call with same data: byte-identical → Unchanged.
        let (o, _) = ensure(&p, DEFAULT_ALIAS, LISTEN_HOST, 22322, DEFAULT_USER).unwrap();
        assert_eq!(o, EnsureOutcome::Unchanged);

        // Port change → Updated in place.
        let (o, _) = ensure(&p, DEFAULT_ALIAS, LISTEN_HOST, 22400, DEFAULT_USER).unwrap();
        assert_eq!(o, EnsureOutcome::Updated);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("Port 22400"));
        assert!(!text.contains("Port 22322"));
        assert_eq!(count_hosts(&p).unwrap(), 1);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn other_content_is_preserved() {
        let p = tmp_path("preserve");
        std::fs::write(
            &p,
            "Host work\n    HostName git.corp\n    User someone\n",
        )
        .unwrap();
        let (o, _) = ensure(&p, DEFAULT_ALIAS, LISTEN_HOST, 22022, DEFAULT_USER).unwrap();
        assert_eq!(o, EnsureOutcome::Added);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("HostName git.corp"), "pre-existing host lost");
        assert!(text.contains("Host work"));
        assert!(text.contains("Host cfssh-dev"));

        // Same after update of our block.
        ensure(&p, DEFAULT_ALIAS, LISTEN_HOST, 22322, DEFAULT_USER).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("HostName git.corp"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn remove_clears_only_the_block() {
        let p = tmp_path("remove");
        std::fs::write(&p, "Host keep\n    HostName a\n").unwrap();
        ensure(&p, DEFAULT_ALIAS, LISTEN_HOST, 22222, DEFAULT_USER).unwrap();
        assert_eq!(remove_managed(&p).unwrap(), 1);
        assert_eq!(remove_managed(&p).unwrap(), 0);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("Host keep"));
        assert!(!text.contains("cfssh-proxy"));
        // New user content survives re-add too.
        ensure(&p, DEFAULT_ALIAS, LISTEN_HOST, 22222, DEFAULT_USER).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("Host keep") && text.contains("Host cfssh-dev"));
        std::fs::remove_file(&p).ok();
    }
}
