//! Launch-time policy enforced by the daemon.
//!
//! The daemon is the security boundary: any process of an allowed uid can
//! talk to the socket directly, so every check lives here rather than in a
//! client such as the MCP server.

use std::path::{Component, Path, PathBuf};
#[cfg(target_os = "linux")]
use std::{
    ffi::CString,
    fs::File,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    sync::Arc,
};

use crate::protocol::{AgentError, ErrorKind};

/// Launch-time capabilities. Everything is off by default; a request cannot
/// turn any of it on.
#[derive(Clone, Debug)]
pub struct ServerPolicy {
    allow_writes: bool,
    file_io: Option<FileIoJail>,
    root: VaultRoot,
}

impl Default for ServerPolicy {
    fn default() -> Self {
        Self {
            allow_writes: false,
            file_io: None,
            root: VaultRoot::whole_vault(),
        }
    }
}

impl ServerPolicy {
    /// `file_io_dir` is canonicalised (and on Linux opened) here, so the jail
    /// root is fixed at launch.
    pub fn new(
        allow_writes: bool,
        file_io_dir: Option<&Path>,
        root: VaultRoot,
    ) -> std::io::Result<Self> {
        Ok(Self {
            allow_writes,
            file_io: file_io_dir.map(FileIoJail::open).transpose()?,
            root,
        })
    }

    pub fn allow_writes(&self) -> bool {
        self.allow_writes
    }

    pub fn file_io_dir(&self) -> Option<&Path> {
        self.file_io.as_ref().map(|jail| jail.root.as_path())
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

    pub fn file_io_jail(&self) -> Result<&FileIoJail, AgentError> {
        self.file_io.as_ref().ok_or_else(|| {
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
const JAIL_EXPORT_EXISTS: &str = "local_path already exists; refusing to overwrite";

/// Joins `local_path` onto the jail root without touching the filesystem.
/// Any `..` is rejected outright, and an absolute path must already sit
/// under the root, so nothing outside the jail is ever stat'ed. Callers
/// then resolve it without following symlinks (Linux) or check the
/// canonical result (elsewhere).
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

/// The `--allow-file-io` directory. On Linux it is opened at launch and
/// every lookup below it goes through `openat2` with
/// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, and the vault layer is handed a
/// `/proc/self/fd` path to the descriptor that was checked. A symlink or
/// directory swapped in after the check therefore cannot redirect the
/// daemon, which matters when the directory is writable by someone else.
/// Elsewhere the checks are path-based and race a concurrent writer.
#[derive(Clone, Debug)]
pub struct FileIoJail {
    root: PathBuf,
    #[cfg(target_os = "linux")]
    dir: Arc<OwnedFd>,
}

impl FileIoJail {
    fn open(dir: &Path) -> std::io::Result<Self> {
        let root = std::fs::canonicalize(dir)?;
        if !root.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("--allow-file-io is not a directory: {}", root.display()),
            ));
        }
        Ok(Self {
            #[cfg(target_os = "linux")]
            dir: Arc::new(OwnedFd::from(File::open(&root)?)),
            root,
        })
    }

    /// `local_path` relative to the root, after the path-only checks.
    #[cfg(target_os = "linux")]
    fn relative(&self, local_path: &str, denied: &str) -> Result<PathBuf, AgentError> {
        let candidate = jail_candidate(&self.root, local_path)?;
        candidate
            .strip_prefix(&self.root)
            .map(Path::to_path_buf)
            .map_err(|_| jail_error(denied))
    }
}

/// A local path for the vault layer that resolves to what the jail
/// approved. On Linux it names a descriptor held here (`/proc/self/fd/<n>`),
/// so it is valid, and pinned, only while this value lives.
pub struct JailedPath {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    _fd: OwnedFd,
}

impl JailedPath {
    pub fn as_str(&self) -> Result<&str, AgentError> {
        self.path
            .to_str()
            .ok_or_else(|| jail_error("local_path is not valid UTF-8"))
    }
}

/// `openat2(dir, rel, flags, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
/// RESOLVE_NO_MAGICLINKS)`: `rel` may not leave `dir` or pass through any
/// symlink, including its last component.
#[cfg(target_os = "linux")]
fn open_beneath(dir: impl AsFd, rel: &Path, flags: libc::c_int) -> std::io::Result<OwnedFd> {
    let rel = CString::new(rel.as_os_str().as_bytes())?;
    // SAFETY: open_how is plain data; all-zero is its documented default.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
    // SAFETY: the pointers are valid for the call and the size matches.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_fd().as_raw_fd(),
            rel.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat2 returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}

#[cfg(target_os = "linux")]
fn open_beneath_error(err: std::io::Error, denied: &str) -> AgentError {
    match err.raw_os_error() {
        Some(libc::ENOSYS) => AgentError::new(
            ErrorKind::Denied,
            "local file I/O needs openat2 (Linux 5.6 or later); \
             refusing the path-based fallback, which a symlink swap could redirect",
        ),
        Some(libc::ELOOP) => jail_error("local_path must not be or pass through a symlink"),
        _ => jail_error(denied),
    }
}

#[cfg(target_os = "linux")]
fn proc_fd_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// Resolves an import source: a regular file with a single link, reached
/// without any symlink, inside the jail root.
#[cfg(target_os = "linux")]
pub async fn jail_import_source(
    jail: &FileIoJail,
    local_path: &str,
) -> Result<JailedPath, AgentError> {
    let rel = jail.relative(local_path, JAIL_IMPORT_DENIED)?;
    // O_NONBLOCK so that a FIFO planted in the jail cannot hang the open.
    let fd = open_beneath(&*jail.dir, &rel, libc::O_RDONLY | libc::O_NONBLOCK)
        .map_err(|err| open_beneath_error(err, JAIL_IMPORT_DENIED))?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|_| jail_error(JAIL_IMPORT_DENIED))?;
    if !metadata.is_file() {
        return Err(jail_error(JAIL_IMPORT_DENIED));
    }
    // A second link could be a hard link to a file outside the jail.
    if metadata.nlink() > 1 {
        return Err(jail_error(
            "local_path has more than one hard link; refusing to import it",
        ));
    }
    let fd = OwnedFd::from(file);
    Ok(JailedPath {
        path: proc_fd_path(&fd),
        _fd: fd,
    })
}

/// Resolves an export target: a name that does not exist yet, in a
/// directory reached without any symlink inside the jail root. The vault
/// layer publishes with a no-clobber rename, so a file that appears after
/// this check is still not overwritten.
#[cfg(target_os = "linux")]
pub async fn jail_export_target(
    jail: &FileIoJail,
    local_path: &str,
) -> Result<JailedPath, AgentError> {
    let rel = jail.relative(local_path, JAIL_EXPORT_DENIED)?;
    let name = rel
        .file_name()
        .ok_or_else(|| jail_error("local_path has no file name"))?;
    let parent = match rel.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let dir = open_beneath(&*jail.dir, parent, libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(|err| open_beneath_error(err, JAIL_EXPORT_DENIED))?;
    // With O_PATH | O_NOFOLLOW even a symlink or FIFO opens, so any entry
    // counts as existing; ELOOP is a symlink refused by RESOLVE_NO_SYMLINKS.
    match open_beneath(&dir, Path::new(name), libc::O_PATH) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(JailedPath {
            path: proc_fd_path(&dir).join(name),
            _fd: dir,
        }),
        Ok(_) => Err(jail_error(JAIL_EXPORT_EXISTS)),
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => Err(jail_error(JAIL_EXPORT_EXISTS)),
        Err(err) => Err(open_beneath_error(err, "local_path cannot be inspected")),
    }
}

/// Resolves an import source: an existing regular file, not a symlink, whose
/// canonical path is inside the jail root.
#[cfg(not(target_os = "linux"))]
pub async fn jail_import_source(
    jail: &FileIoJail,
    local_path: &str,
) -> Result<JailedPath, AgentError> {
    let root = jail.root.as_path();
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
    Ok(JailedPath { path: canonical })
}

/// Resolves an export target: a name that does not exist yet, in a parent
/// directory whose canonical path is inside the jail root. The vault layer
/// publishes with a no-clobber rename, so a file that appears after this
/// check is still not overwritten.
#[cfg(not(target_os = "linux"))]
pub async fn jail_export_target(
    jail: &FileIoJail,
    local_path: &str,
) -> Result<JailedPath, AgentError> {
    let root = jail.root.as_path();
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
        Ok(_) => Err(jail_error(JAIL_EXPORT_EXISTS)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(JailedPath { path: target }),
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
        let err = ServerPolicy::default().file_io_jail().unwrap_err();
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
