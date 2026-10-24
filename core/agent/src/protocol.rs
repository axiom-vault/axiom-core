//! Wire protocol between `axiom-agent` and its clients.
//!
//! Newline-delimited JSON over a Unix stream socket: each request line gets
//! exactly one response line. A line longer than [`MAX_LINE_BYTES`] is
//! refused and the connection is closed.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// Longest accepted line in either direction, newline excluded.
pub const MAX_LINE_BYTES: usize = 32 * 1024 * 1024;

/// Sent whenever a request needs an unlocked vault. It names the only way to
/// unlock: a human at their own terminal.
pub const LOCKED_MESSAGE: &str =
    "vault is locked; ask the user to run `axiom-agent unlock` in their own terminal";

/// One request to the agent. Unknown fields are an error, so a client cannot
/// believe it is steering something (such as which vault to unlock) that the
/// daemon ignores.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Unlock(UnlockParams),
    Lock,
    Status,
    VaultInfo,
    ListDirectory {
        path: String,
    },
    /// Returns at most `max_bytes` of the file (all of it when absent),
    /// together with the full size.
    ReadFile {
        path: String,
        #[serde(default)]
        max_bytes: Option<u64>,
    },
    CreateFile {
        path: String,
        content_b64: Base64Content,
    },
    UpdateFile {
        path: String,
        content_b64: Base64Content,
    },
    /// Deletes a file, or an empty directory.
    Delete {
        path: String,
    },
    Mkdir {
        path: String,
    },
    Metadata {
        path: String,
    },
    Exists {
        path: String,
    },
    ImportFile {
        local_path: String,
        vault_path: String,
    },
    ExportFile {
        vault_path: String,
        local_path: String,
    },
}

impl Request {
    /// Operation name, for the audit log.
    pub fn op(&self) -> &'static str {
        match self {
            Self::Unlock(_) => "unlock",
            Self::Lock => "lock",
            Self::Status => "status",
            Self::VaultInfo => "vault_info",
            Self::ListDirectory { .. } => "list_directory",
            Self::ReadFile { .. } => "read_file",
            Self::CreateFile { .. } => "create_file",
            Self::UpdateFile { .. } => "update_file",
            Self::Delete { .. } => "delete",
            Self::Mkdir { .. } => "mkdir",
            Self::Metadata { .. } => "metadata",
            Self::Exists { .. } => "exists",
            Self::ImportFile { .. } => "import_file",
            Self::ExportFile { .. } => "export_file",
        }
    }

    /// The vault path a request touches, if any.
    pub fn vault_path(&self) -> Option<&str> {
        match self {
            Self::ListDirectory { path }
            | Self::ReadFile { path, .. }
            | Self::CreateFile { path, .. }
            | Self::UpdateFile { path, .. }
            | Self::Delete { path }
            | Self::Mkdir { path }
            | Self::Metadata { path }
            | Self::Exists { path } => Some(path),
            Self::ImportFile { vault_path, .. } | Self::ExportFile { vault_path, .. } => {
                Some(vault_path)
            }
            Self::Unlock(_) | Self::Lock | Self::Status | Self::VaultInfo => None,
        }
    }
}

/// Unlock parameters: only the password, held in [`Zeroizing`] and redacted
/// in `Debug`. Which vault it unlocks is fixed by `serve --vault`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockParams {
    #[serde(with = "zeroizing_string")]
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for UnlockParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockParams")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// `zeroize` has no serde support, so the secret is (de)serialised through a
/// plain string that is moved straight into the wrapper.
mod zeroizing_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(value: &Zeroizing<String>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
        String::deserialize(d).map(Zeroizing::new)
    }
}

/// Base64 file content. `Debug` prints only the length, so vault plaintext
/// never reaches a log through a derived `Debug`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Base64Content(pub String);

impl std::fmt::Debug for Base64Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Base64Content({} chars)", self.0.len())
    }
}

/// One response from the agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Response {
    Ok { payload: Payload },
    Error(AgentError),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Payload {
    Done,
    Status(AgentStatus),
    VaultInfo(VaultInfo),
    Entries {
        entries: Vec<DirEntry>,
    },
    File {
        content_b64: Base64Content,
        size: u64,
    },
    Metadata(Metadata),
    Exists {
        exists: bool,
    },
}

/// The daemon's launch policy and lock state. `unlock` shows this before
/// prompting, so the user can spot a daemon that is not the one they started.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentStatus {
    /// The local vault directory this daemon is pinned to.
    pub vault_dir: PathBuf,
    pub unlocked: bool,
    pub allow_writes: bool,
    pub file_io_dir: Option<PathBuf>,
    pub root: String,
    /// 0 when idle auto-lock is disabled.
    pub idle_lock_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultInfo {
    pub id: String,
    pub provider_type: String,
    pub is_unlocked: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// No vault is unlocked.
    Locked,
    /// Unlock was sent while a vault is already unlocked.
    AlreadyUnlocked,
    /// Wrong password or recovery material.
    AuthFailed,
    /// Refused by the daemon's launch policy.
    Denied,
    NotFound,
    AlreadyExists,
    InvalidParams,
    /// Malformed or oversized request line.
    InvalidRequest,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentError {
    pub kind: ErrorKind,
    pub message: String,
}

impl AgentError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AgentError {}

impl From<Result<Payload, AgentError>> for Response {
    fn from(result: Result<Payload, AgentError>) -> Self {
        match result {
            Ok(payload) => Self::Ok { payload },
            Err(err) => Self::Error(err),
        }
    }
}

impl From<Response> for Result<Payload, AgentError> {
    fn from(response: Response) -> Self {
        match response {
            Response::Ok { payload } => Ok(payload),
            Response::Error(err) => Err(err),
        }
    }
}

/// Reads one line without its newline. `Ok(None)` is a clean end of stream.
/// The buffer is [`Zeroizing`] because an unlock line carries the password.
pub async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut line = Zeroizing::new(Vec::new());
    let read = reader
        .take(MAX_LINE_BYTES as u64 + 1)
        .read_until(b'\n', &mut line)
        .await?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    } else if line.len() > MAX_LINE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("line exceeds {MAX_LINE_BYTES} bytes"),
        ));
    }
    Ok(Some(line))
}

/// Serialises `value` as one line into a [`Zeroizing`] buffer and writes it.
pub async fn write_line<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> std::io::Result<()> {
    let mut line = Zeroizing::new(serde_json::to_vec(value)?);
    if line.len() > MAX_LINE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("line exceeds {MAX_LINE_BYTES} bytes"),
        ));
    }
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn round_trip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
        value: T,
    ) {
        let text = serde_json::to_string(&value).unwrap();
        assert!(!text.contains('\n'));
        assert_eq!(serde_json::from_str::<T>(&text).unwrap(), value, "{text}");
    }

    fn unlock() -> Request {
        Request::Unlock(UnlockParams {
            password: Zeroizing::new("correct horse battery staple".into()),
        })
    }

    #[test]
    fn requests_round_trip() {
        let content = Base64Content("aGVsbG8=".into());
        for request in [
            unlock(),
            Request::Lock,
            Request::Status,
            Request::VaultInfo,
            Request::ListDirectory { path: "/".into() },
            Request::ReadFile {
                path: "/a".into(),
                max_bytes: Some(5),
            },
            Request::CreateFile {
                path: "/a".into(),
                content_b64: content.clone(),
            },
            Request::UpdateFile {
                path: "/a".into(),
                content_b64: content,
            },
            Request::Delete { path: "/a".into() },
            Request::Mkdir { path: "/d".into() },
            Request::Metadata { path: "/a".into() },
            Request::Exists { path: "/a".into() },
            Request::ImportFile {
                local_path: "in.txt".into(),
                vault_path: "/a".into(),
            },
            Request::ExportFile {
                vault_path: "/a".into(),
                local_path: "out.txt".into(),
            },
        ] {
            round_trip(request);
        }
    }

    #[test]
    fn unlock_wire_format_is_flat() {
        let value = serde_json::to_value(unlock()).unwrap();
        assert_eq!(
            value,
            json!({ "op": "unlock", "password": "correct horse battery staple" })
        );
    }

    /// The daemon is pinned to one vault; a request naming another must be
    /// refused, not silently ignored. (serde does not apply
    /// `deny_unknown_fields` to unit variants such as `status`, which carry
    /// nothing to steer.)
    #[test]
    fn unknown_fields_are_rejected() {
        for line in [
            json!({ "op": "unlock", "password": "p", "provider_type": "local" }),
            json!({
                "op": "unlock",
                "password": "p",
                "provider_config": { "root": "/attacker/vault" },
            }),
            json!({ "op": "read_file", "path": "/a", "vault": "/other" }),
        ] {
            assert!(
                serde_json::from_value::<Request>(line.clone()).is_err(),
                "{line} accepted"
            );
        }
        assert!(
            serde_json::from_value::<Request>(json!({ "op": "unlock", "password": "p" })).is_ok()
        );
    }

    #[test]
    fn responses_round_trip() {
        for response in [
            Response::Ok {
                payload: Payload::Done,
            },
            Response::Ok {
                payload: Payload::Status(AgentStatus {
                    vault_dir: "/srv/vault".into(),
                    unlocked: true,
                    allow_writes: false,
                    file_io_dir: Some("/tmp/io".into()),
                    root: "/notes".into(),
                    idle_lock_secs: 900,
                }),
            },
            Response::Ok {
                payload: Payload::VaultInfo(VaultInfo {
                    id: "v".into(),
                    provider_type: "local".into(),
                    is_unlocked: true,
                }),
            },
            Response::Ok {
                payload: Payload::Entries {
                    entries: vec![DirEntry {
                        name: "a".into(),
                        path: "/a".into(),
                        is_directory: false,
                        size: Some(1),
                    }],
                },
            },
            Response::Ok {
                payload: Payload::File {
                    content_b64: Base64Content("aGk=".into()),
                    size: 2,
                },
            },
            Response::Ok {
                payload: Payload::Metadata(Metadata {
                    name: "d".into(),
                    path: "/d".into(),
                    is_directory: true,
                    size: None,
                }),
            },
            Response::Ok {
                payload: Payload::Exists { exists: false },
            },
            Response::Error(AgentError::new(ErrorKind::Locked, "vault is locked")),
        ] {
            round_trip(response);
        }
    }

    #[test]
    fn unlock_debug_redacts_secrets() {
        let debug = format!("{:?}", unlock());
        assert!(!debug.contains("correct horse"), "{debug}");
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn content_debug_prints_only_length() {
        let request = Request::CreateFile {
            path: "/a".into(),
            content_b64: Base64Content("c2VjcmV0LXBsYWludGV4dA==".into()),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("c2VjcmV0"), "{debug}");
        assert!(debug.contains("24 chars"), "{debug}");
    }

    #[tokio::test]
    async fn read_line_refuses_oversized_lines() {
        let mut long = vec![b'x'; MAX_LINE_BYTES + 1];
        long.push(b'\n');
        let mut reader = tokio::io::BufReader::new(long.as_slice());
        let err = read_line(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        let mut reader = tokio::io::BufReader::new(&b"{\"op\":\"status\"}\nrest"[..]);
        let line = read_line(&mut reader).await.unwrap().unwrap();
        assert_eq!(line.as_slice(), b"{\"op\":\"status\"}");
        let tail = read_line(&mut reader).await.unwrap().unwrap();
        assert_eq!(tail.as_slice(), b"rest");
        assert!(read_line(&mut reader).await.unwrap().is_none());
    }
}
