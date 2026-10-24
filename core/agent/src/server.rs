//! The daemon: holds the unlocked vault and answers requests on the socket.

use std::{
    fs::{DirBuilder, Permissions},
    os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use axiomvault_app::{AppError, AppService, FileMetadataDto, OpenVaultParams};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tokio::{
    io::BufReader,
    net::{UnixListener, UnixStream},
    sync::{watch, Mutex},
};
use tracing::{info, warn};

use crate::{
    policy::{jail_export_target, jail_import_source, peer_allowed, ServerPolicy},
    protocol::{
        read_line, write_line, AgentError, AgentStatus, Base64Content, DirEntry, ErrorKind,
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
    pub policy: ServerPolicy,
    /// `None` disables idle auto-lock.
    pub idle_lock: Option<Duration>,
    /// Peers with any other uid are disconnected before anything is read.
    pub allowed_uids: Vec<u32>,
}

struct Agent {
    app: AppService,
    config: DaemonConfig,
    activity: watch::Sender<Instant>,
    /// Consecutive failed unlocks. Held across each attempt and its backoff,
    /// so parallel connections cannot run guesses side by side.
    unlock_failures: Mutex<u32>,
}

/// Creates the listening socket at `path` with permissions `mode`.
///
/// A missing parent directory is created 0700. An existing socket that
/// accepts connections means another agent is running, which is an error; a
/// stale one is removed. Anything else at `path` is left alone and is an
/// error.
pub fn bind_socket(path: &Path, mode: u32) -> std::io::Result<UnixListener> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
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
    std::fs::set_permissions(path, Permissions::from_mode(mode))?;
    Ok(listener)
}

/// Serves connections on `listener` until the process exits.
pub async fn serve(listener: UnixListener, config: DaemonConfig) {
    let (activity, activity_rx) = watch::channel(Instant::now());
    let idle_lock = config.idle_lock;
    let agent = Arc::new(Agent {
        app: AppService::new(),
        config,
        activity,
        unlock_failures: Mutex::new(0),
    });
    if let Some(idle) = idle_lock {
        tokio::spawn(idle_lock_task(Arc::clone(&agent), idle, activity_rx));
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

/// Locks the vault once no request has arrived for `idle`, then waits for
/// the next request before arming again.
async fn idle_lock_task(agent: Arc<Agent>, idle: Duration, mut activity: watch::Receiver<Instant>) {
    loop {
        let last = *activity.borrow_and_update();
        tokio::select! {
            _ = tokio::time::sleep_until((last + idle).into()) => {
                match agent.app.close_vault().await {
                    Ok(()) => info!(op = "idle_lock", idle_secs = idle.as_secs(), outcome = "ok", "vault locked"),
                    Err(AppError::NoOpenVault) => {}
                    Err(err) => warn!(op = "idle_lock", %err, outcome = "error", "idle lock failed"),
                }
                if activity.changed().await.is_err() {
                    return;
                }
            }
            changed = activity.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
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
    let mut reader = BufReader::new(reader);
    loop {
        let response = match read_line(&mut reader).await {
            Ok(None) => return,
            Ok(Some(line)) => match serde_json::from_slice::<Request>(&line) {
                Ok(request) => agent.handle(request, uid, pid).await,
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
        if write_line(&mut writer, &response).await.is_err() {
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
        self.activity.send_replace(Instant::now());
        let op = request.op();
        let vault_path = request.vault_path().map(str::to_owned);
        let result = self.dispatch(request).await;
        self.activity.send_replace(Instant::now());
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
                unlocked: app.is_vault_open().await,
                allow_writes: policy.allow_writes(),
                file_io_dir: policy.file_io_dir().map(Path::to_path_buf),
                root: policy.root().as_str().to_string(),
                idle_lock_secs: self.config.idle_lock.map_or(0, |idle| idle.as_secs()),
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
            Request::ReadFile { path, max_bytes } => {
                let path = policy.root().scope(&path)?;
                let bytes = app.read_file(&path).await.map_err(app_error)?;
                let limit = max_bytes.map_or(bytes.len(), |max| {
                    usize::try_from(max).unwrap_or(usize::MAX).min(bytes.len())
                });
                if limit > MAX_READ_BYTES {
                    return Err(AgentError::new(
                        ErrorKind::InvalidParams,
                        format!(
                            "file is {} bytes; reads over the socket are capped at {MAX_READ_BYTES}, \
                             pass max_bytes or use export_file",
                            bytes.len()
                        ),
                    ));
                }
                Ok(Payload::File {
                    content_b64: Base64Content(BASE64.encode(&bytes[..limit])),
                    size: bytes.len() as u64,
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
                let jail = policy.file_io_root()?;
                let vault_path = policy.root().scope(&vault_path)?;
                let source = jail_import_source(jail, &local_path).await?;
                let source = source.to_str().ok_or_else(|| {
                    AgentError::new(ErrorKind::InvalidParams, "local_path is not valid UTF-8")
                })?;
                app.import_file(source, &vault_path)
                    .await
                    .map_err(app_error)?;
                Ok(Payload::Done)
            }
            Request::ExportFile {
                vault_path,
                local_path,
            } => {
                let jail = policy.file_io_root()?;
                let vault_path = policy.root().scope(&vault_path)?;
                let target = jail_export_target(jail, &local_path).await?;
                let target = target.to_str().ok_or_else(|| {
                    AgentError::new(ErrorKind::InvalidParams, "local_path is not valid UTF-8")
                })?;
                app.export_file(&vault_path, target)
                    .await
                    .map_err(app_error)?;
                Ok(Payload::Done)
            }
        }
    }

    /// Unlocks only when no vault is open, so a request cannot silently swap
    /// the vault that other clients are working in. Each failure delays its
    /// own response; attempts are serialised, so the delay throttles every
    /// connection, not just the one that failed.
    async fn unlock(&self, params: UnlockParams) -> Result<Payload, AgentError> {
        let mut failures = self.unlock_failures.lock().await;
        if self.app.is_vault_open().await {
            return Err(AgentError::new(
                ErrorKind::AlreadyUnlocked,
                "a vault is already unlocked; lock it first",
            ));
        }
        let UnlockParams {
            provider_type,
            provider_config,
            password,
        } = params;
        let opened = self
            .app
            .open_vault(OpenVaultParams {
                password,
                provider_type,
                provider_config,
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
}
