//! The daemon: holds the unlocked vault and answers requests on the socket.

use std::{
    fs::{DirBuilder, File, OpenOptions, Permissions, TryLockError},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use axiomvault_app::{AppError, AppService, FileMetadataDto, OpenVaultParams};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{Mutex, Notify},
};
use tracing::{info, warn};

use crate::{
    policy::{jail_export_target, jail_import_source, peer_allowed, ServerPolicy},
    protocol::{
        write_line, AgentError, AgentStatus, Base64Content, DirEntry, ErrorKind, LineReader,
        Metadata, Payload, Request, Response, UnlockParams, VaultInfo, LOCKED_MESSAGE,
        MAX_LINE_BYTES,
    },
};

/// Largest file slice a `ReadFile` response carries, so that its base64 form
/// plus the JSON envelope stays under [`MAX_LINE_BYTES`].
const MAX_READ_BYTES: usize = (MAX_LINE_BYTES - 4096) / 4 * 3;

/// Cap on the delay after a failed unlock.
const MAX_UNLOCK_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// The local vault this daemon serves, canonicalised at startup. Unlock
    /// requests carry only a password, so a client cannot point the daemon
    /// at a different vault.
    pub vault_dir: PathBuf,
    pub policy: ServerPolicy,
    /// `None` disables idle auto-lock.
    pub idle_lock: Option<Duration>,
    /// Longest an unlock lasts, however busy the vault is (ssh-agent `-t`).
    /// `None` disables it.
    pub max_unlock: Option<Duration>,
    /// Peers with any other uid are disconnected before anything is read.
    pub allowed_uids: Vec<u32>,
}

struct Agent {
    app: AppService,
    config: DaemonConfig,
    /// Inputs of the automatic lock. The lock task holds this while it
    /// locks, so no request can start in between.
    timers: Mutex<Timers>,
    /// Requests being handled. Idle lock waits for them to finish. Raised
    /// under `timers`, lowered by [`InFlight`]'s `Drop`, so a request that
    /// panics still releases idle lock.
    in_flight: AtomicUsize,
    /// Wakes the lock task after the timers change.
    timers_changed: Notify,
    /// Consecutive failed unlocks. Held across each attempt and its backoff,
    /// so parallel connections cannot run guesses side by side.
    unlock_failures: Mutex<u32>,
}

struct Timers {
    last_activity: Instant,
    /// Set by a successful unlock, cleared by any lock.
    unlocked_at: Option<Instant>,
}

/// Counts one request as in flight for as long as it lives.
struct InFlight<'a>(&'a Agent);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.0.timers_changed.notify_one();
    }
}

impl Timers {
    /// The next automatic lock and its reason. A deadline that does not fit
    /// in an `Instant` never comes.
    fn next_lock(
        &self,
        config: &DaemonConfig,
        in_flight: usize,
    ) -> Option<(Instant, &'static str)> {
        let unlocked_at = self.unlocked_at?;
        let max_unlock = config
            .max_unlock
            .and_then(|max| unlocked_at.checked_add(max))
            .map(|deadline| (deadline, "max_unlock"));
        let idle_lock = config
            .idle_lock
            .filter(|_| in_flight == 0)
            .and_then(|idle| self.last_activity.checked_add(idle))
            .map(|deadline| (deadline, "idle_lock"));
        [max_unlock, idle_lock]
            .into_iter()
            .flatten()
            .min_by_key(|(deadline, _)| *deadline)
    }
}

/// Exclusive hold on an agent socket path, taken by [`bind_socket`] and
/// kept for the daemon's lifetime. Dropping it removes the socket and only
/// then releases the lock, so a daemon starting meanwhile never finds a
/// socket of ours to remove. The lock file itself stays behind.
#[derive(Debug)]
pub struct SocketLock {
    socket: PathBuf,
    _lock: File,
}

impl Drop for SocketLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Creates the listening socket at `path` with permissions `mode`.
///
/// First takes an exclusive `flock` on `<path>.lock`, held by the returned
/// [`SocketLock`], so of two daemons started together only one gets past
/// it. The lock file is not followed if it is a symlink, and must be a
/// regular file owned by the effective uid that group and others cannot
/// write. An existing socket that accepts connections means another agent is
/// running, which is an error; a stale one is removed. Anything else at
/// `path` is left alone and is an error.
///
/// A missing parent directory is created 0700. That would shut out the
/// group a `mode` such as 0660 shares the socket with, so with such a mode
/// the directory must already exist.
pub fn bind_socket(path: &Path, mode: u32) -> std::io::Result<(UnixListener, SocketLock)> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            if mode & 0o077 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "socket directory {} does not exist; create it first, owned by \
                         the daemon user and the clients' group with mode 0750 (a \
                         directory created here would be 0700)",
                        parent.display()
                    ),
                ));
            }
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
    }
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)
        .map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("cannot open lock file {}: {err}", lock_path.display()),
            )
        })?;
    // A lock file someone else owns or can write could be held, or swapped,
    // by them to keep this daemon from starting or to start beside it.
    let metadata = lock.metadata()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != euid || metadata.mode() & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing lock file {}: it must be a regular file owned by uid {euid} and \
                 writable only by it (found uid {}, mode {:o}); remove it",
                lock_path.display(),
                metadata.uid(),
                metadata.mode() & 0o7777
            ),
        ));
    }
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("another agent holds {}", lock_path.display()),
            ))
        }
        Err(TryLockError::Error(err)) => return Err(err),
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("an agent is already listening on {}", path.display()),
                ));
            }
            if !metadata.file_type().is_socket() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
            std::fs::remove_file(path)?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    // The umask is process-wide, so it is not narrowed around bind. Until
    // the chmod below the socket has the umask's mode; a peer that connects
    // in that window is still checked against the uid allowlist.
    let listener = UnixListener::bind(path)?;
    let lock = SocketLock {
        socket: path.to_path_buf(),
        _lock: lock,
    };
    std::fs::set_permissions(path, Permissions::from_mode(mode))?;
    Ok((listener, lock))
}

/// Serves connections on `listener` until the process exits.
pub async fn serve(listener: UnixListener, config: DaemonConfig) {
    let timed = config.idle_lock.is_some() || config.max_unlock.is_some();
    let agent = Arc::new(Agent {
        app: AppService::new(),
        config,
        timers: Mutex::new(Timers {
            last_activity: Instant::now(),
            unlocked_at: None,
        }),
        in_flight: AtomicUsize::new(0),
        timers_changed: Notify::new(),
        unlock_failures: Mutex::new(0),
    });
    if timed {
        tokio::spawn(lock_timer_task(Arc::clone(&agent)));
    }
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(Arc::clone(&agent), stream));
            }
            Err(err) => {
                warn!(%err, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Locks the vault when `--idle-lock` passes with no request in flight, or
/// when `--max-unlock` has passed since the unlock, whichever comes first.
async fn lock_timer_task(agent: Arc<Agent>) {
    loop {
        let changed = agent.timers_changed.notified();
        let next = agent
            .timers
            .lock()
            .await
            .next_lock(&agent.config, agent.in_flight.load(Ordering::SeqCst));
        match next {
            Some((deadline, _)) => tokio::select! {
                () = tokio::time::sleep_until(deadline.into()) => {}
                () = changed => continue,
            },
            None => {
                changed.await;
                continue;
            }
        }
        // Re-check under the lock: a request may have started or ended since.
        let mut timers = agent.timers.lock().await;
        let in_flight = agent.in_flight.load(Ordering::SeqCst);
        let Some((deadline, reason)) = timers.next_lock(&agent.config, in_flight) else {
            continue;
        };
        if deadline > Instant::now() {
            continue;
        }
        match agent.app.close_vault().await {
            Ok(()) => info!(op = reason, outcome = "ok", "vault locked"),
            Err(AppError::NoOpenVault) => {}
            Err(err) => {
                warn!(op = reason, %err, outcome = "error", "automatic lock failed; retrying");
                drop(timers);
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        }
        timers.unlocked_at = None;
    }
}

async fn handle_connection(agent: Arc<Agent>, stream: UnixStream) {
    let cred = match stream.peer_cred() {
        Ok(cred) => cred,
        Err(err) => {
            warn!(%err, "peer credentials unavailable; connection closed");
            return;
        }
    };
    let (uid, pid) = (cred.uid(), cred.pid());
    if !peer_allowed(&agent.config.allowed_uids, uid) {
        warn!(
            peer_uid = uid,
            peer_pid = ?pid,
            outcome = "denied",
            "connection refused: uid not allowed"
        );
        return;
    }
    let (reader, mut writer) = stream.into_split();
    let mut reader = LineReader::new(reader);
    loop {
        let mut last = false;
        let response = match reader.read_line().await {
            Ok(None) => return,
            Ok(Some(line)) => match serde_json::from_slice::<Request>(&line) {
                Ok(request) => {
                    // An unlock ends its connection, so no buffer that held
                    // the password outlives the request.
                    last = matches!(request, Request::Unlock(_));
                    agent.handle(request, uid, pid).await
                }
                // serde's message can quote the offending value, which may be
                // a secret, so only the position is reported.
                Err(err) => {
                    warn!(peer_uid = uid, peer_pid = ?pid, outcome = "invalid_request", "malformed request");
                    Response::Error(AgentError::new(
                        ErrorKind::InvalidRequest,
                        format!(
                            "malformed request at line {} column {}",
                            err.line(),
                            err.column()
                        ),
                    ))
                }
            },
            Err(err) => {
                warn!(peer_uid = uid, peer_pid = ?pid, %err, outcome = "invalid_request", "unreadable request");
                let _ = write_line(
                    &mut writer,
                    &Response::Error(AgentError::new(ErrorKind::InvalidRequest, err.to_string())),
                )
                .await;
                return;
            }
        };
        if write_line(&mut writer, &response).await.is_err() || last {
            return;
        }
    }
}

fn app_error(err: AppError) -> AgentError {
    let kind = match &err {
        AppError::NoOpenVault | AppError::VaultLocked => {
            return AgentError::new(ErrorKind::Locked, LOCKED_MESSAGE)
        }
        AppError::InvalidPassword | AppError::InvalidRecoveryKey => ErrorKind::AuthFailed,
        AppError::PathNotFound(_) | AppError::VaultNotFound(_) => ErrorKind::NotFound,
        AppError::PathAlreadyExists(_) | AppError::VaultAlreadyExists(_) => {
            ErrorKind::AlreadyExists
        }
        AppError::InvalidInput(_) => ErrorKind::InvalidParams,
        _ => ErrorKind::Internal,
    };
    AgentError::new(kind, err.to_string())
}

fn decode(content: &Base64Content) -> Result<Vec<u8>, AgentError> {
    BASE64
        .decode(&content.0)
        .map_err(|err| AgentError::new(ErrorKind::InvalidParams, format!("content_b64: {err}")))
}

fn metadata_payload(metadata: FileMetadataDto) -> Payload {
    Payload::Metadata(Metadata {
        name: metadata.name,
        path: metadata.path,
        is_directory: metadata.is_directory,
        size: metadata.size,
    })
}

/// 1s after the first failure, doubling, capped at [`MAX_UNLOCK_BACKOFF`].
fn unlock_backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(6);
    Duration::from_secs(1 << exponent).min(MAX_UNLOCK_BACKOFF)
}

impl Agent {
    /// Runs one request and writes its audit record. Contents, passwords
    /// and provider configuration never reach the log.
    async fn handle(&self, request: Request, uid: u32, pid: Option<i32>) -> Response {
        let op = request.op();
        let vault_path = request.vault_path().map(str::to_owned);
        let in_flight = {
            let mut timers = self.timers.lock().await;
            self.in_flight.fetch_add(1, Ordering::SeqCst);
            timers.last_activity = Instant::now();
            InFlight(self)
        };
        let result = self.dispatch(request).await;
        {
            let mut timers = self.timers.lock().await;
            drop(in_flight);
            timers.last_activity = Instant::now();
            match (op, &result) {
                ("unlock", Ok(_)) => timers.unlocked_at = Some(Instant::now()),
                ("lock", Ok(_)) => timers.unlocked_at = None,
                _ => {}
            }
        }
        self.timers_changed.notify_one();
        match &result {
            Ok(_) => {
                info!(op, vault_path, peer_uid = uid, peer_pid = ?pid, outcome = "ok", "request")
            }
            Err(err) => {
                warn!(op, vault_path, peer_uid = uid, peer_pid = ?pid, outcome = ?err.kind, "request")
            }
        }
        result.into()
    }

    async fn dispatch(&self, request: Request) -> Result<Payload, AgentError> {
        let policy = &self.config.policy;
        let app = &self.app;
        match request {
            Request::Unlock(params) => self.unlock(params).await,
            Request::Lock => match app.close_vault().await {
                Ok(()) | Err(AppError::NoOpenVault) => Ok(Payload::Done),
                Err(err) => Err(app_error(err)),
            },
            Request::Status => Ok(Payload::Status(AgentStatus {
                vault_dir: self.config.vault_dir.clone(),
                unlocked: app.is_vault_open().await,
                allow_writes: policy.allow_writes(),
                file_io_dir: policy.file_io_dir().map(Path::to_path_buf),
                root: policy.root().as_str().to_string(),
                idle_lock_secs: self.config.idle_lock.map_or(0, |idle| idle.as_secs()),
                max_unlock_secs: self.config.max_unlock.map_or(0, |max| max.as_secs()),
            })),
            Request::VaultInfo => {
                let info = app.vault_info().await.map_err(app_error)?;
                Ok(Payload::VaultInfo(VaultInfo {
                    id: info.id,
                    provider_type: info.provider_type,
                    is_unlocked: info.is_unlocked,
                }))
            }
            Request::ListDirectory { path } => {
                let path = policy.root().scope(&path)?;
                let entries = app.list_directory(&path).await.map_err(app_error)?;
                Ok(Payload::Entries {
                    entries: entries
                        .into_iter()
                        .map(|entry| DirEntry {
                            name: entry.name,
                            path: entry.path,
                            is_directory: entry.is_directory,
                            size: entry.size,
                        })
                        .collect(),
                })
            }
            Request::ReadFile {
                path,
                offset,
                max_bytes,
            } => {
                let path = policy.root().scope(&path)?;
                let offset = offset.unwrap_or(0);
                // The size comes from the tree, so an oversized read is
                // refused before anything is decrypted.
                let size = app.metadata(&path).await.map_err(app_error)?.size;
                let limit = size
                    .unwrap_or(0)
                    .saturating_sub(offset)
                    .min(max_bytes.unwrap_or(u64::MAX));
                if limit > MAX_READ_BYTES as u64 {
                    return Err(AgentError::new(
                        ErrorKind::InvalidParams,
                        format!(
                            "file is {} bytes; reads over the socket are capped at {MAX_READ_BYTES}, \
                             pass max_bytes (and offset) or use export_file",
                            size.unwrap_or(0)
                        ),
                    ));
                }
                let (bytes, size) = app
                    .read_file_range(&path, offset, limit as usize)
                    .await
                    .map_err(app_error)?;
                Ok(Payload::File {
                    content_b64: Base64Content(BASE64.encode(&bytes)),
                    size,
                })
            }
            Request::CreateFile { path, content_b64 } => {
                policy.write_guard()?;
                let path = policy.root().scope(&path)?;
                let bytes = decode(&content_b64)?;
                app.create_file(&path, &bytes).await.map_err(app_error)?;
                Ok(Payload::Done)
            }
            Request::UpdateFile { path, content_b64 } => {
                policy.write_guard()?;
                let path = policy.root().scope(&path)?;
                let bytes = decode(&content_b64)?;
                app.update_file(&path, &bytes).await.map_err(app_error)?;
                Ok(Payload::Done)
            }
            Request::Delete { path } => {
                policy.write_guard()?;
                let path = policy.root().scope(&path)?;
                let metadata = app.metadata(&path).await.map_err(app_error)?;
                if metadata.is_directory {
                    app.delete_directory(&path).await.map_err(app_error)?;
                } else {
                    app.delete_file(&path).await.map_err(app_error)?;
                }
                Ok(metadata_payload(metadata))
            }
            Request::Mkdir { path } => {
                policy.write_guard()?;
                let path = policy.root().scope(&path)?;
                app.create_directory(&path).await.map_err(app_error)?;
                Ok(Payload::Done)
            }
            Request::Metadata { path } => {
                let path = policy.root().scope(&path)?;
                let metadata = app.metadata(&path).await.map_err(app_error)?;
                Ok(metadata_payload(metadata))
            }
            Request::Exists { path } => {
                let path = policy.root().scope(&path)?;
                let exists = app.exists(&path).await.map_err(app_error)?;
                Ok(Payload::Exists { exists })
            }
            Request::ImportFile {
                local_path,
                vault_path,
            } => {
                policy.write_guard()?;
                let jail = policy.file_io_jail()?;
                let vault_path = policy.root().scope(&vault_path)?;
                // Held until the import returns: on Linux the path names
                // its descriptor.
                let source = jail_import_source(jail, &local_path).await?;
                app.import_file(source.as_str()?, &vault_path)
                    .await
                    .map_err(app_error)?;
                drop(source);
                Ok(Payload::Done)
            }
            Request::ExportFile {
                vault_path,
                local_path,
            } => {
                let jail = policy.file_io_jail()?;
                let vault_path = policy.root().scope(&vault_path)?;
                let target = jail_export_target(jail, &local_path).await?;
                app.export_file(&vault_path, target.as_str()?)
                    .await
                    .map_err(app_error)?;
                drop(target);
                Ok(Payload::Done)
            }
        }
    }

    /// Opens the pinned vault, and only when it is not open already. Each
    /// failure delays its own response; attempts are serialised, so the delay
    /// throttles every connection, not just the one that failed.
    async fn unlock(&self, params: UnlockParams) -> Result<Payload, AgentError> {
        let mut failures = self.unlock_failures.lock().await;
        if self.app.is_vault_open().await {
            return Err(AgentError::new(
                ErrorKind::AlreadyUnlocked,
                "a vault is already unlocked; lock it first",
            ));
        }
        let opened = self
            .app
            .open_vault(OpenVaultParams {
                password: params.password,
                provider_type: "local".to_string(),
                provider_config: serde_json::json!({
                    "root": self.config.vault_dir.to_string_lossy(),
                }),
            })
            .await;
        match opened {
            Ok(info) => {
                *failures = 0;
                Ok(Payload::VaultInfo(VaultInfo {
                    id: info.id,
                    provider_type: info.provider_type,
                    is_unlocked: info.is_unlocked,
                }))
            }
            Err(err) => {
                *failures = failures.saturating_add(1);
                tokio::time::sleep(unlock_backoff(*failures)).await;
                Err(app_error(err))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_backoff_doubles_and_caps() {
        let secs: Vec<u64> = (1..=9).map(|n| unlock_backoff(n).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(unlock_backoff(u32::MAX), MAX_UNLOCK_BACKOFF);
    }

    #[test]
    fn locked_errors_point_at_the_terminal_unlock() {
        let err = app_error(AppError::NoOpenVault);
        assert_eq!(err.kind, ErrorKind::Locked);
        assert!(err.message.contains("axiom-agent unlock"));
    }

    fn config(idle: Option<Duration>, max: Option<Duration>) -> DaemonConfig {
        DaemonConfig {
            vault_dir: PathBuf::from("/vault"),
            policy: ServerPolicy::default(),
            idle_lock: idle,
            max_unlock: max,
            allowed_uids: Vec::new(),
        }
    }

    #[test]
    fn idle_lock_waits_for_requests_in_flight_but_max_unlock_does_not() {
        let now = Instant::now();
        let mut timers = Timers {
            last_activity: now,
            unlocked_at: Some(now),
        };
        let both = config(Some(Duration::from_secs(5)), Some(Duration::from_secs(60)));
        assert_eq!(
            timers.next_lock(&both, 0),
            Some((now + Duration::from_secs(5), "idle_lock"))
        );
        assert_eq!(
            timers.next_lock(&both, 1),
            Some((now + Duration::from_secs(60), "max_unlock"))
        );
        assert_eq!(
            timers.next_lock(&config(Some(Duration::from_secs(5)), None), 1),
            None
        );
        timers.unlocked_at = None;
        assert_eq!(timers.next_lock(&both, 0), None);
    }

    #[test]
    fn a_panicking_request_still_leaves_flight() {
        let agent = Agent {
            app: AppService::new(),
            config: config(Some(Duration::from_secs(5)), None),
            timers: Mutex::new(Timers {
                last_activity: Instant::now(),
                unlocked_at: None,
            }),
            in_flight: AtomicUsize::new(0),
            timers_changed: Notify::new(),
            unlock_failures: Mutex::new(0),
        };
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            agent.in_flight.fetch_add(1, Ordering::SeqCst);
            let _in_flight = InFlight(&agent);
            panic!("handler panicked");
        }));
        assert!(panicked.is_err());
        assert_eq!(agent.in_flight.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn lock_deadlines_that_overflow_never_come() {
        let timers = Timers {
            last_activity: Instant::now(),
            unlocked_at: Some(Instant::now()),
        };
        let huge = Some(Duration::MAX);
        assert_eq!(timers.next_lock(&config(huge, huge), 0), None);
    }
}
