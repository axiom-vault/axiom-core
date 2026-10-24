//! Launch-time policy enforced by the daemon.
//!
//! The daemon is the security boundary: any process of an allowed uid can
//! talk to the socket directly, so every check lives here rather than in a
//! client such as the MCP server.

use std::{
    io::ErrorKind as IoErrorKind,
    path::{Component, Path, PathBuf},
};

use crate::protocol::{AgentError, ErrorKind};

/// Launch-time capabilities. Everything is off by default; a request cannot
/// turn any of it on.
#[derive(Clone, Debug)]
pub struct ServerPolicy {
    allow_writes: bool,
    file_io_root: Option<PathBuf>,
    root: VaultRoot,
}

impl Default for ServerPolicy {
    fn default() -> Self {
        Self {
            allow_writes: false,
            file_io_root: None,
            root: VaultRoot::whole_vault(),
        }
    }
}

impl ServerPolicy {
    /// `file_io_dir` is canonicalised here, so the jail root is fixed at launch.
    pub fn new(
        allow_writes: bool,
        file_io_dir: Option<&Path>,
        root: VaultRoot,
    ) -> std::io::Result<Self> {
        let file_io_root = match file_io_dir {
            Some(dir) => {
                let root = std::fs::canonicalize(dir)?;
                if !root.is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("--allow-file-io is not a directory: {}", root.display()),
                    ));
                }
                Some(root)
            }
            None => None,
        };
        Ok(Self {
            allow_writes,
            file_io_root,
            root,
        })
    }

    pub fn allow_writes(&self) -> bool {
        self.allow_writes
    }

    pub fn file_io_dir(&self) -> Option<&Path> {
        self.file_io_root.as_deref()
    }

    pub fn root(&self) -> &VaultRoot {
        &self.root
    }

    pub fn write_guard(&self) -> Result<(), AgentError> {
        if self.allow_writes {
            Ok(())
        } else {
            Err(AgentError::new(
                ErrorKind::Denied,
                "mutating requests are disabled; axiom-agent must be launched with --allow-writes",
            ))
        }
    }

    pub fn file_io_root(&self) -> Result<&Path, AgentError> {
        self.file_io_root.as_deref().ok_or_else(|| {
            AgentError::new(
                ErrorKind::Denied,
                "local file I/O is disabled; axiom-agent must be launched with --allow-file-io=<dir>",
            )
        })
    }
}

/// The vault subtree the daemon serves. Stored normalised: absolute, no
/// trailing slash except for `/` itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRoot(String);

impl VaultRoot {
    pub fn whole_vault() -> Self {
        Self("/".to_string())
    }

    pub fn parse(root: &str) -> Result<Self, AgentError> {
        normalize_vault_path(root).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Normalises `path` and returns it if it is the root or below it.
    pub fn scope(&self, path: &str) -> Result<String, AgentError> {
        let path = normalize_vault_path(path)?;
        let inside = self.0 == "/"
            || path == self.0
            || path
                .strip_prefix(self.0.as_str())
                .is_some_and(|rest| rest.starts_with('/'));
        if inside {
            Ok(path)
        } else {
            Err(AgentError::new(
                ErrorKind::Denied,
                format!("vault path is outside the agent's --root {}", self.0),
            ))
        }
    }
}

/// Accepts only an absolute vault path whose segments are non-empty and not
/// `.` or `..`. One trailing slash is tolerated and stripped. The vault's own
/// parser is laxer (it accepts relative paths and repeated slashes), so the
/// scope check must not rely on it.
fn normalize_vault_path(path: &str) -> Result<String, AgentError> {
    let invalid = |why: &str| AgentError::new(ErrorKind::InvalidParams, format!("{why}: {path:?}"));
    let rest = path
        .strip_prefix('/')
        .ok_or_else(|| invalid("vault path must be absolute"))?;
    if rest.is_empty() {
        return Ok("/".to_string());
    }
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    for segment in rest.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(invalid("vault path has an empty, '.' or '..' segment"));
        }
        if segment.contains('\\') || segment.contains('\0') {
            return Err(invalid("vault path segment contains '\\' or NUL"));
        }
    }
    Ok(format!("/{rest}"))
}

/// True if a peer with `uid` may use the socket.
pub fn peer_allowed(allowed_uids: &[u32], uid: u32) -> bool {
    allowed_uids.contains(&uid)
}

fn jail_error(message: impl Into<String>) -> AgentError {
    AgentError::new(ErrorKind::InvalidParams, message)
}

const JAIL_IMPORT_DENIED: &str = "local_path is not a regular file inside the file I/O directory";
const JAIL_EXPORT_DENIED: &str =
    "local_path is not in an existing directory inside the file I/O directory";

/// Joins `local_path` onto the jail root without touching the filesystem.
/// Any `..` is rejected outright, and an absolute path must already sit
/// under the root, so nothing outside the jail is ever stat'ed. Callers
/// still check the canonical result, which catches symlinked directories.
fn jail_candidate(root: &Path, local_path: &str) -> Result<PathBuf, AgentError> {
    let requested = Path::new(local_path);
    if local_path.is_empty() {
        return Err(jail_error("local_path is empty"));
    }
    if requested
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(jail_error("local_path must not contain '..'"));
    }
    if requested.is_absolute() && !requested.starts_with(root) {
        return Err(jail_error("local_path is outside the file I/O directory"));
    }
    Ok(root.join(requested))
}

/// Resolves an import source: an existing regular file, not a symlink, whose
/// canonical path is inside the jail root.
pub async fn jail_import_source(root: &Path, local_path: &str) -> Result<PathBuf, AgentError> {
    let candidate = jail_candidate(root, local_path)?;
    let metadata = tokio::fs::symlink_metadata(&candidate)
        .await
        .map_err(|_| jail_error(JAIL_IMPORT_DENIED))?;
    if metadata.file_type().is_symlink() {
        return Err(jail_error("local_path must not be a symlink"));
    }
    let canonical = tokio::fs::canonicalize(&candidate)
        .await
        .map_err(|_| jail_error(JAIL_IMPORT_DENIED))?;
    if !metadata.is_file() || !canonical.starts_with(root) {
        return Err(jail_error(JAIL_IMPORT_DENIED));
    }
    Ok(canonical)
}

/// Resolves an export target: a name that does not exist yet, in a parent
/// directory whose canonical path is inside the jail root. The vault layer
/// publishes with a no-clobber rename, so a file that appears after this
/// check is still not overwritten.
pub async fn jail_export_target(root: &Path, local_path: &str) -> Result<PathBuf, AgentError> {
    let candidate = jail_candidate(root, local_path)?;
    let name = candidate
        .file_name()
        .ok_or_else(|| jail_error("local_path has no file name"))?;
    let parent = candidate
        .parent()
        .ok_or_else(|| jail_error("local_path has no parent directory"))?;
    let canonical_parent = tokio::fs::canonicalize(parent)
        .await
        .map_err(|_| jail_error(JAIL_EXPORT_DENIED))?;
    if !canonical_parent.starts_with(root) {
        return Err(jail_error(JAIL_EXPORT_DENIED));
    }
    let target = canonical_parent.join(name);
    match tokio::fs::symlink_metadata(&target).await {
        Ok(_) => Err(jail_error(
            "local_path already exists; refusing to overwrite",
        )),
        Err(err) if err.kind() == IoErrorKind::NotFound => Ok(target),
        Err(_) => Err(jail_error("local_path cannot be inspected")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(path: &str) -> VaultRoot {
        VaultRoot::parse(path).unwrap()
    }

    #[test]
    fn write_guard_blocks_without_launch_flag() {
        let err = ServerPolicy::default().write_guard().unwrap_err();
        assert_eq!(err.kind, ErrorKind::Denied);
        assert!(err.message.contains("--allow-writes"));
        let err = ServerPolicy::default().file_io_root().unwrap_err();
        assert!(err.message.contains("--allow-file-io"));
    }

    #[test]
    fn root_is_normalised() {
        assert_eq!(root("/").as_str(), "/");
        assert_eq!(root("/notes").as_str(), "/notes");
        assert_eq!(root("/notes/").as_str(), "/notes");
        assert_eq!(root("/notes/work/").as_str(), "/notes/work");
        for bad in [
            "",
            "notes",
            "notes/",
            "//",
            "/notes//work",
            "/notes/../etc",
            "/..",
            "/./notes",
            "/notes/.",
            "/a\\b",
        ] {
            assert!(VaultRoot::parse(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn scope_confines_to_the_subtree() {
        let notes = root("/notes");
        assert_eq!(notes.scope("/notes").unwrap(), "/notes");
        assert_eq!(notes.scope("/notes/").unwrap(), "/notes");
        assert_eq!(notes.scope("/notes/a/b.txt").unwrap(), "/notes/a/b.txt");
        assert_eq!(notes.scope("/notes/a/").unwrap(), "/notes/a");

        for outside in ["/", "/notes2", "/notes2/x", "/note", "/other/notes"] {
            let err = notes.scope(outside).unwrap_err();
            assert_eq!(err.kind, ErrorKind::Denied, "{outside}");
        }
        for invalid in [
            "notes/a",
            "",
            "/notes/../secret",
            "/notes/./a",
            "/notes//a",
            "//notes",
            "/notes/a\\..\\b",
        ] {
            let err = notes.scope(invalid).unwrap_err();
            assert_eq!(err.kind, ErrorKind::InvalidParams, "{invalid:?}");
        }

        let all = VaultRoot::whole_vault();
        assert_eq!(all.scope("/").unwrap(), "/");
        assert_eq!(all.scope("/notes2/x").unwrap(), "/notes2/x");
        assert!(all.scope("relative").is_err());
        assert!(all.scope("/a/../b").is_err());
    }

    #[test]
    fn peer_allowlist_checks_uid() {
        assert!(peer_allowed(&[1000], 1000));
        assert!(peer_allowed(&[1000, 1001], 1001));
        assert!(!peer_allowed(&[1000], 0));
        assert!(!peer_allowed(&[1000], 1001));
        assert!(!peer_allowed(&[], 1000));
    }

    #[test]
    fn jail_candidate_rejects_without_touching_the_filesystem() {
        let jail = Path::new("/jail");
        assert_eq!(
            jail_candidate(jail, "a/b.txt").unwrap(),
            Path::new("/jail/a/b.txt")
        );
        assert_eq!(
            jail_candidate(jail, "/jail/x").unwrap(),
            Path::new("/jail/x")
        );
        for bad in [
            "",
            "../x",
            "a/../../x",
            "/jail/../etc",
            "/etc/passwd",
            "/jailbreak/x",
        ] {
            assert!(jail_candidate(jail, bad).is_err(), "{bad:?} accepted");
        }
    }
}
