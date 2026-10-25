//! End-to-end tests of the daemon over a real Unix socket: unlock, launch
//! policy, root scoping, locking and the import/export jail.

use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use axiomvault_agent::{
    bind_socket, hardening,
    protocol::{Base64Content, UnlockParams},
    serve, AgentClient, ClientError, DaemonConfig, ErrorKind, Payload, Request, ServerPolicy,
    VaultRoot, LOCKED_MESSAGE,
};
use axiomvault_app::{AppService, CreateVaultParams, OpenVaultParams};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASSWORD: &str = "old-password";

struct Fixture {
    dir: TempDir,
    vault_dir: PathBuf,
}

/// A local vault containing `/hello.txt`, `/docs`, `/notes/a.txt` and
/// `/notes2/b.txt`, created directly through `AppService`.
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    // Canonical, as `serve --vault` makes it.
    let vault_dir = std::fs::canonicalize(dir.path()).unwrap().join("vault");
    let app = AppService::new();
    app.create_vault(CreateVaultParams {
        vault_id: "agent".into(),
        password: Zeroizing::new(PASSWORD.into()),
        provider_type: "local".into(),
        provider_config: json!({ "root": vault_dir }),
    })
    .await
    .unwrap();
    app.create_file("/hello.txt", b"hello").await.unwrap();
    app.create_directory("/docs").await.unwrap();
    app.create_directory("/notes").await.unwrap();
    app.create_file("/notes/a.txt", b"note a").await.unwrap();
    app.create_directory("/notes2").await.unwrap();
    app.create_file("/notes2/b.txt", b"note b").await.unwrap();
    app.close_vault().await.unwrap();
    Fixture { dir, vault_dir }
}

impl Fixture {
    fn uid(&self) -> u32 {
        self.dir.path().metadata().unwrap().uid()
    }

    fn config(&self, policy: ServerPolicy) -> DaemonConfig {
        DaemonConfig {
            vault_dir: self.vault_dir.clone(),
            policy,
            idle_lock: None,
            max_unlock: None,
            allowed_uids: vec![self.uid()],
        }
    }

    /// Starts a daemon on a fresh socket in the fixture directory.
    fn start(&self, config: DaemonConfig) -> PathBuf {
        let socket = self
            .dir
            .path()
            .join(format!("agent-{}.sock", rand_suffix()));
        let (listener, lock) = bind_socket(&socket, 0o600).unwrap();
        tokio::spawn(async move {
            let _lock = lock;
            serve(listener, config).await
        });
        socket
    }

    fn unlock_request(&self, password: &str) -> Request {
        Request::Unlock(UnlockParams {
            password: Zeroizing::new(password.into()),
        })
    }
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

async fn req(socket: &Path, request: Request) -> Result<Payload, ClientError> {
    AgentClient::connect(socket).await?.request(&request).await
}

fn kind(result: Result<Payload, ClientError>) -> (ErrorKind, String) {
    match result {
        Err(ClientError::Agent(err)) => (err.kind, err.message),
        other => panic!("expected an agent error, got {other:?}"),
    }
}

async fn unlocked(fx: &Fixture, policy: ServerPolicy) -> PathBuf {
    let socket = fx.start(fx.config(policy));
    req(&socket, fx.unlock_request(PASSWORD)).await.unwrap();
    socket
}

async fn read_text(socket: &Path, path: &str) -> Result<String, ClientError> {
    match req(
        socket,
        Request::ReadFile {
            path: path.into(),
            offset: None,
            max_bytes: None,
        },
    )
    .await?
    {
        Payload::File { content_b64, .. } => {
            Ok(String::from_utf8(BASE64.decode(content_b64.0).unwrap()).unwrap())
        }
        other => panic!("unexpected {other:?}"),
    }
}

async fn exists(socket: &Path, path: &str) -> bool {
    match req(socket, Request::Exists { path: path.into() }).await {
        Ok(Payload::Exists { exists }) => exists,
        other => panic!("unexpected {other:?}"),
    }
}

fn content(text: &str) -> Base64Content {
    Base64Content(BASE64.encode(text))
}

fn writes() -> ServerPolicy {
    ServerPolicy::new(true, None, VaultRoot::whole_vault()).unwrap()
}

fn file_io(allow_writes: bool, jail: &Path) -> ServerPolicy {
    ServerPolicy::new(allow_writes, Some(jail), VaultRoot::whole_vault()).unwrap()
}

fn mutating_requests() -> Vec<Request> {
    vec![
        Request::CreateFile {
            path: "/new.txt".into(),
            content_b64: content("x"),
        },
        Request::UpdateFile {
            path: "/hello.txt".into(),
            content_b64: content("changed"),
        },
        Request::Mkdir {
            path: "/made".into(),
        },
        Request::Delete {
            path: "/docs".into(),
        },
    ]
}

#[tokio::test]
async fn unlock_needs_the_right_password_and_backs_off_on_failure() {
    let fx = fixture().await;
    let socket = fx.start(fx.config(ServerPolicy::default()));

    let (locked, message) = kind(
        read_text(&socket, "/hello.txt")
            .await
            .map(|_| Payload::Done),
    );
    assert_eq!(locked, ErrorKind::Locked);
    assert_eq!(message, LOCKED_MESSAGE);

    let started = Instant::now();
    let (failed, _) = kind(req(&socket, fx.unlock_request("wrong-password")).await);
    assert_ne!(failed, ErrorKind::Locked);
    assert!(started.elapsed() >= Duration::from_secs(1), "no backoff");
    assert!(matches!(
        req(&socket, Request::Status).await.unwrap(),
        Payload::Status(status) if !status.unlocked
    ));

    let info = req(&socket, fx.unlock_request(PASSWORD)).await.unwrap();
    assert!(matches!(info, Payload::VaultInfo(info) if info.id == "agent"));
    assert_eq!(read_text(&socket, "/hello.txt").await.unwrap(), "hello");

    // A second unlock cannot swap the open vault, and runs no KDF.
    let (again, _) = kind(req(&socket, fx.unlock_request(PASSWORD)).await);
    assert_eq!(again, ErrorKind::AlreadyUnlocked);
}

/// Unlock carries only the password: a request that names a vault is
/// refused, so a client cannot redirect the daemon to a vault it controls.
#[tokio::test]
async fn unlock_cannot_name_another_vault() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let fx = fixture().await;
    let other = tempfile::tempdir().unwrap();
    let socket = fx.start(fx.config(ServerPolicy::default()));

    let Payload::Status(status) = req(&socket, Request::Status).await.unwrap() else {
        panic!("not a status");
    };
    assert_eq!(status.vault_dir, fx.vault_dir);

    let line = json!({
        "op": "unlock",
        "password": PASSWORD,
        "provider_type": "local",
        "provider_config": { "root": other.path() },
    });
    let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
    stream
        .write_all(format!("{line}\n").as_bytes())
        .await
        .unwrap();
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .await
        .unwrap();
    assert!(response.contains("invalid_request"), "{response}");
    assert!(matches!(
        req(&socket, Request::Status).await.unwrap(),
        Payload::Status(status) if !status.unlocked
    ));
}

#[tokio::test]
async fn mutating_requests_refuse_without_allow_writes() {
    let fx = fixture().await;
    let socket = unlocked(&fx, ServerPolicy::default()).await;

    for request in mutating_requests() {
        let op = request.op();
        let (denied, message) = kind(req(&socket, request).await);
        assert_eq!(denied, ErrorKind::Denied, "{op}");
        assert!(message.contains("--allow-writes"), "{op}: {message}");
    }
    assert_eq!(read_text(&socket, "/hello.txt").await.unwrap(), "hello");
    assert!(!exists(&socket, "/new.txt").await);
    assert!(!exists(&socket, "/made").await);
    assert!(exists(&socket, "/docs").await);
}

#[tokio::test]
async fn mutating_requests_work_with_allow_writes() {
    let fx = fixture().await;
    let socket = unlocked(&fx, writes()).await;

    for request in mutating_requests() {
        let op = request.op();
        req(&socket, request)
            .await
            .unwrap_or_else(|err| panic!("{op}: {err}"));
    }
    assert_eq!(read_text(&socket, "/new.txt").await.unwrap(), "x");
    assert_eq!(read_text(&socket, "/hello.txt").await.unwrap(), "changed");
    assert!(exists(&socket, "/made").await);
    assert!(!exists(&socket, "/docs").await);
}

#[tokio::test]
async fn paths_outside_root_are_refused() {
    let fx = fixture().await;
    let policy = ServerPolicy::new(true, None, VaultRoot::parse("/notes").unwrap()).unwrap();
    let socket = unlocked(&fx, policy).await;

    assert_eq!(read_text(&socket, "/notes/a.txt").await.unwrap(), "note a");
    let listed = req(
        &socket,
        Request::ListDirectory {
            path: "/notes/".into(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(listed, Payload::Entries { entries } if entries.len() == 1));

    for path in ["/hello.txt", "/notes2/b.txt", "/", "/notes2"] {
        let (denied, _) = kind(read_text(&socket, path).await.map(|_| Payload::Done));
        assert_eq!(denied, ErrorKind::Denied, "{path}");
        let (denied, _) = kind(req(&socket, Request::Exists { path: path.into() }).await);
        assert_eq!(denied, ErrorKind::Denied, "{path}");
    }
    for path in ["/notes/../hello.txt", "notes/a.txt", "//hello.txt"] {
        let (invalid, _) = kind(read_text(&socket, path).await.map(|_| Payload::Done));
        assert_eq!(invalid, ErrorKind::InvalidParams, "{path}");
    }
    let (denied, _) = kind(
        req(
            &socket,
            Request::CreateFile {
                path: "/notes2/c.txt".into(),
                content_b64: content("x"),
            },
        )
        .await,
    );
    assert_eq!(denied, ErrorKind::Denied);
    let (denied, _) = kind(
        req(
            &socket,
            Request::Delete {
                path: "/hello.txt".into(),
            },
        )
        .await,
    );
    assert_eq!(denied, ErrorKind::Denied);
}

#[tokio::test]
async fn lock_drops_the_vault() {
    let fx = fixture().await;
    let socket = unlocked(&fx, ServerPolicy::default()).await;
    assert_eq!(read_text(&socket, "/hello.txt").await.unwrap(), "hello");

    req(&socket, Request::Lock).await.unwrap();
    let (locked, message) = kind(
        read_text(&socket, "/hello.txt")
            .await
            .map(|_| Payload::Done),
    );
    assert_eq!(locked, ErrorKind::Locked);
    assert!(message.contains("axiom-agent unlock"), "{message}");
    let (locked, _) = kind(req(&socket, Request::VaultInfo).await);
    assert_eq!(locked, ErrorKind::Locked);
    // Locking again is a no-op, not an error.
    req(&socket, Request::Lock).await.unwrap();

    req(&socket, fx.unlock_request(PASSWORD)).await.unwrap();
    assert_eq!(read_text(&socket, "/hello.txt").await.unwrap(), "hello");
}

#[tokio::test]
async fn idle_lock_locks_after_the_timeout() {
    let fx = fixture().await;
    let socket = fx.start(DaemonConfig {
        idle_lock: Some(Duration::from_secs(1)),
        ..fx.config(ServerPolicy::default())
    });
    req(&socket, fx.unlock_request(PASSWORD)).await.unwrap();
    assert_eq!(read_text(&socket, "/hello.txt").await.unwrap(), "hello");

    tokio::time::sleep(Duration::from_millis(2500)).await;
    let Payload::Status(status) = req(&socket, Request::Status).await.unwrap() else {
        panic!("not a status");
    };
    assert!(!status.unlocked);
    assert_eq!(status.idle_lock_secs, 1);
    let (locked, _) = kind(
        read_text(&socket, "/hello.txt")
            .await
            .map(|_| Payload::Done),
    );
    assert_eq!(locked, ErrorKind::Locked);
}

#[tokio::test]
async fn peers_with_other_uids_are_disconnected() {
    let fx = fixture().await;
    let socket = fx.start(DaemonConfig {
        allowed_uids: vec![fx.uid().wrapping_add(1)],
        ..fx.config(ServerPolicy::default())
    });
    match req(&socket, Request::Status).await {
        Err(ClientError::Io(_)) => {}
        other => panic!("expected a dropped connection, got {other:?}"),
    }
}

#[tokio::test]
async fn malformed_requests_are_refused_without_echo() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let fx = fixture().await;
    let socket = fx.start(fx.config(ServerPolicy::default()));
    let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
    stream
        .write_all(b"{\"op\":\"unlock\",\"password\":42,\"provider_type\":\"hunter2\"}\n")
        .await
        .unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).await.unwrap();
    assert!(line.contains("invalid_request"), "{line}");
    assert!(!line.contains("hunter2"), "{line}");
}

#[tokio::test]
async fn large_files_are_read_in_ranges_and_never_whole() {
    let fx = fixture().await;
    // A streamed file larger than one response can carry.
    let data: Vec<u8> = (0..25 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let source = fx.dir.path().join("big.bin");
    std::fs::write(&source, &data).unwrap();
    let app = AppService::new();
    app.open_vault(OpenVaultParams {
        password: Zeroizing::new(PASSWORD.into()),
        provider_type: "local".into(),
        provider_config: json!({ "root": fx.vault_dir }),
    })
    .await
    .unwrap();
    app.import_file(source.to_str().unwrap(), "/big.bin")
        .await
        .unwrap();
    app.close_vault().await.unwrap();
    let socket = unlocked(&fx, ServerPolicy::default()).await;
    let read = |offset, max_bytes| Request::ReadFile {
        path: "/big.bin".into(),
        offset,
        max_bytes,
    };

    let (kind, message) = kind(req(&socket, read(None, None)).await);
    assert_eq!(kind, ErrorKind::InvalidParams);
    assert!(
        message.contains(&format!("file is {} bytes", data.len())),
        "{message}"
    );

    // Across the boundary between the third and fourth 64 KiB frames.
    let offset = 3 * 64 * 1024 - 7;
    for (offset, wanted) in [(None, 0..16), (Some(offset as u64), offset..offset + 20)] {
        let max_bytes = Some(wanted.len() as u64);
        match req(&socket, read(offset, max_bytes)).await.unwrap() {
            Payload::File { content_b64, size } => {
                assert_eq!(BASE64.decode(content_b64.0).unwrap(), &data[wanted]);
                assert_eq!(size, data.len() as u64);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn socket_setup_refuses_a_live_agent_and_replaces_a_stale_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run/agent.sock");
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;

    // A directory created here would be 0700 and shut out the group that a
    // 660 socket is shared with.
    let err = bind_socket(&socket, 0o660).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(!dir.path().join("run").exists());

    let (listener, lock) = bind_socket(&socket, 0o600).unwrap();
    assert_eq!(mode(&dir.path().join("run")), 0o700);
    assert_eq!(mode(&socket), 0o600);
    assert_eq!(mode(&dir.path().join("run/agent.sock.lock")), 0o600);

    let err = bind_socket(&socket, 0o600).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    assert!(err.to_string().contains("another agent holds"), "{err}");
    // The lock decides, not the socket file.
    std::fs::remove_file(&socket).unwrap();
    assert!(bind_socket(&socket, 0o600).is_err());

    // Dropping the lock removes the socket and lets a new daemon start.
    drop(listener);
    drop(lock);
    assert!(!socket.exists());
    let (_listener, _lock) = bind_socket(&socket, 0o660).unwrap();
    assert_eq!(mode(&socket), 0o660);

    // A stale socket that no daemon holds a lock for is replaced.
    let stale = dir.path().join("stale.sock");
    drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
    bind_socket(&stale, 0o600).unwrap();

    let file = dir.path().join("not-a-socket");
    std::fs::write(&file, b"keep").unwrap();
    bind_socket(&file, 0o600).unwrap_err();
    assert_eq!(std::fs::read(&file).unwrap(), b"keep");
}

/// Two daemons started together on a stale socket: both used to see it as
/// stale, and the loser kept running on an unlinked socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_starts_leave_exactly_one_daemon() {
    for _ in 0..10 {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let starts: Vec<_> = (0..2)
            .map(|_| {
                let (socket, barrier) = (socket.clone(), barrier.clone());
                tokio::task::spawn_blocking(move || {
                    barrier.wait();
                    bind_socket(&socket, 0o600)
                })
            })
            .collect();
        let mut started = Vec::new();
        for start in starts {
            match start.await.unwrap() {
                Ok(bound) => started.push(bound),
                Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse, "{err}"),
            }
        }
        assert_eq!(started.len(), 1);
        // The socket on disk is the winner's.
        std::os::unix::net::UnixStream::connect(&socket).unwrap();
    }
}

#[tokio::test]
async fn file_io_refuses_without_allow_file_io() {
    let fx = fixture().await;
    let outside = tempfile::tempdir().unwrap();
    let source = outside.path().join("source.txt");
    std::fs::write(&source, b"secret").unwrap();
    let target = outside.path().join("exported.txt");

    // With no flags, import is refused by the write gate first.
    for (policy, import_refusal) in [
        (ServerPolicy::default(), "--allow-writes"),
        (writes(), "--allow-file-io"),
    ] {
        let socket = unlocked(&fx, policy).await;
        let (_, message) = kind(
            req(
                &socket,
                Request::ImportFile {
                    local_path: source.to_str().unwrap().into(),
                    vault_path: "/imported".into(),
                },
            )
            .await,
        );
        assert!(message.contains(import_refusal), "import_file: {message}");
        let (_, message) = kind(
            req(
                &socket,
                Request::ExportFile {
                    vault_path: "/hello.txt".into(),
                    local_path: target.to_str().unwrap().into(),
                },
            )
            .await,
        );
        assert!(
            message.contains("--allow-file-io"),
            "export_file: {message}"
        );
        assert!(!exists(&socket, "/imported").await);
        req(&socket, Request::Lock).await.unwrap();
    }
    assert!(!target.exists());
}

fn import(local_path: impl Into<String>, vault_path: &str) -> Request {
    Request::ImportFile {
        local_path: local_path.into(),
        vault_path: vault_path.into(),
    }
}

fn export(local_path: impl Into<String>) -> Request {
    Request::ExportFile {
        vault_path: "/hello.txt".into(),
        local_path: local_path.into(),
    }
}

fn path_str(path: PathBuf) -> String {
    path.to_str().unwrap().to_string()
}

#[tokio::test]
async fn import_is_confined_to_the_file_io_directory() {
    let fx = fixture().await;
    let base = tempfile::tempdir().unwrap();
    let jail = base.path().join("jail");
    std::fs::create_dir(&jail).unwrap();
    std::fs::write(jail.join("inside.txt"), b"inside").unwrap();
    std::fs::write(base.path().join("secret"), b"secret").unwrap();
    std::os::unix::fs::symlink(base.path().join("secret"), jail.join("link")).unwrap();
    std::os::unix::fs::symlink(base.path(), jail.join("linkdir")).unwrap();
    // Symlinks that stay inside the jail are refused too: any symlink could
    // be swapped for one that leaves it after the check.
    std::os::unix::fs::symlink(jail.join("inside.txt"), jail.join("inlink")).unwrap();
    std::fs::create_dir(jail.join("sub")).unwrap();
    std::fs::write(jail.join("sub/f.txt"), b"f").unwrap();
    std::os::unix::fs::symlink(jail.join("sub"), jail.join("sublink")).unwrap();
    std::fs::hard_link(base.path().join("secret"), jail.join("hard")).unwrap();
    let fifo = std::ffi::CString::new(path_str(jail.join("fifo"))).unwrap();
    // SAFETY: a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    // The daemon is non-dumpable; the /proc/self/fd paths must still work.
    hardening::disable_dumping().unwrap();
    let socket = unlocked(&fx, file_io(true, &jail)).await;

    req(&socket, import("inside.txt", "/a")).await.unwrap();
    assert_eq!(read_text(&socket, "/a").await.unwrap(), "inside");
    req(&socket, import("sub/f.txt", "/f")).await.unwrap();
    assert_eq!(read_text(&socket, "/f").await.unwrap(), "f");
    req(&socket, import(path_str(jail.join("inside.txt")), "/b"))
        .await
        .unwrap();

    let escapes = [
        path_str(jail.join("../secret")),
        "../secret".to_string(),
        path_str(base.path().join("secret")),
        "link".to_string(),
        "linkdir/secret".to_string(),
        "inlink".to_string(),
        "sublink/f.txt".to_string(),
        "hard".to_string(),
        "fifo".to_string(),
        "sub".to_string(),
        ".".to_string(),
        "/etc/passwd".to_string(),
        String::new(),
    ];
    for (index, local_path) in escapes.into_iter().enumerate() {
        let vault_path = format!("/escape{index}");
        let (_, message) = kind(req(&socket, import(local_path.clone(), &vault_path)).await);
        if ["link", "inlink", "sublink/f.txt", "linkdir/secret"].contains(&local_path.as_str()) {
            assert!(message.contains("symlink"), "{local_path}: {message}");
        }
        assert!(
            !exists(&socket, &vault_path).await,
            "{local_path} was imported"
        );
    }

    // Refusals must not reveal whether a path outside the jail exists.
    for pair in [
        ["/etc/passwd", "/etc/no-such-file-here"],
        ["linkdir/secret", "linkdir/no-such-file-here"],
    ] {
        let mut messages = Vec::new();
        for local_path in pair {
            messages.push(kind(req(&socket, import(local_path, "/oracle")).await).1);
        }
        assert_eq!(messages[0], messages[1], "{pair:?}");
    }

    // Import mutates the vault, so it also needs --allow-writes.
    let socket = unlocked(&fx, file_io(false, &jail)).await;
    let (_, message) = kind(req(&socket, import("inside.txt", "/c")).await);
    assert!(message.contains("--allow-writes"), "{message}");
}

#[tokio::test]
async fn export_is_confined_and_never_overwrites() {
    let fx = fixture().await;
    let base = tempfile::tempdir().unwrap();
    let jail = base.path().join("jail");
    std::fs::create_dir(&jail).unwrap();
    std::fs::write(jail.join("existing.txt"), b"keep me").unwrap();
    std::os::unix::fs::symlink(base.path().join("victim"), jail.join("dangling")).unwrap();
    std::os::unix::fs::symlink(base.path(), jail.join("linkdir")).unwrap();
    std::fs::create_dir(jail.join("sub")).unwrap();
    std::os::unix::fs::symlink(jail.join("sub"), jail.join("sublink")).unwrap();

    // Export writes only inside the jail and does not need --allow-writes.
    hardening::disable_dumping().unwrap();
    let socket = unlocked(&fx, file_io(false, &jail)).await;

    let refused = [
        "existing.txt".to_string(),
        "dangling".to_string(),
        "../escape.txt".to_string(),
        path_str(jail.join("../escape.txt")),
        path_str(base.path().join("escape.txt")),
        "linkdir/escape.txt".to_string(),
        "sublink/out.txt".to_string(),
        "missing-dir/out.txt".to_string(),
    ];
    for local_path in refused {
        req(&socket, export(local_path)).await.unwrap_err();
    }
    assert_eq!(
        std::fs::read(jail.join("existing.txt")).unwrap(),
        b"keep me"
    );
    assert!(!base.path().join("escape.txt").exists());
    assert!(!base.path().join("victim").exists());

    req(&socket, export("out.txt")).await.unwrap();
    let out = jail.join("out.txt");
    assert_eq!(std::fs::read(&out).unwrap(), b"hello");
    let mode = std::fs::symlink_metadata(&out)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    // A second export to the same name is refused.
    req(&socket, export("out.txt")).await.unwrap_err();

    // A real subdirectory works; the same directory through a symlink did not.
    req(&socket, export("sub/out.txt")).await.unwrap();
    assert_eq!(std::fs::read(jail.join("sub/out.txt")).unwrap(), b"hello");
    assert_eq!(std::fs::read_dir(jail.join("sub")).unwrap().count(), 1);
}

#[tokio::test]
async fn failed_unlocks_are_throttled_across_connections() {
    let fx = fixture().await;
    let socket = fx.start(fx.config(ServerPolicy::default()));
    let started = Instant::now();
    let (first, second) = tokio::join!(
        req(&socket, fx.unlock_request("wrong-1")),
        req(&socket, fx.unlock_request("wrong-2")),
    );
    first.unwrap_err();
    second.unwrap_err();
    // Serialised: one waits out the other's 1s backoff, then its own 2s.
    assert!(
        started.elapsed() >= Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn an_unlock_ends_its_connection() {
    let fx = fixture().await;
    let socket = fx.start(fx.config(ServerPolicy::default()));
    let mut client = AgentClient::connect(&socket).await.unwrap();
    client.request(&fx.unlock_request(PASSWORD)).await.unwrap();
    match client.request(&Request::Status).await {
        Err(ClientError::Io(_)) => {}
        other => panic!("connection stayed open: {other:?}"),
    }
    assert_eq!(read_text(&socket, "/hello.txt").await.unwrap(), "hello");
}

#[tokio::test]
async fn activity_resets_the_idle_timer() {
    let fx = fixture().await;
    let socket = fx.start(DaemonConfig {
        idle_lock: Some(Duration::from_secs(2)),
        ..fx.config(ServerPolicy::default())
    });
    req(&socket, fx.unlock_request(PASSWORD)).await.unwrap();
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(4) {
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(read_text(&socket, "/hello.txt").await.unwrap(), "hello");
    }
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let (locked, _) = kind(
        read_text(&socket, "/hello.txt")
            .await
            .map(|_| Payload::Done),
    );
    assert_eq!(locked, ErrorKind::Locked);
}

#[tokio::test]
async fn max_unlock_locks_however_busy() {
    let fx = fixture().await;
    let socket = fx.start(DaemonConfig {
        idle_lock: Some(Duration::from_secs(60)),
        max_unlock: Some(Duration::from_secs(2)),
        ..fx.config(ServerPolicy::default())
    });
    req(&socket, fx.unlock_request(PASSWORD)).await.unwrap();
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(1500) {
        assert_eq!(read_text(&socket, "/hello.txt").await.unwrap(), "hello");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let Payload::Status(status) = req(&socket, Request::Status).await.unwrap() else {
        panic!("not a status");
    };
    assert_eq!(status.max_unlock_secs, 2);
    assert!(!status.unlocked);

    // The next unlock gets a fresh lifetime.
    req(&socket, fx.unlock_request(PASSWORD)).await.unwrap();
    assert_eq!(read_text(&socket, "/hello.txt").await.unwrap(), "hello");
}

/// Runs the `axiom-agent` binary with `args`; returns (success, stdout, stderr).
async fn agent_cli(args: Vec<String>) -> (bool, String, String) {
    tokio::task::spawn_blocking(move || {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_axiom-agent"))
            .args(&args)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn cli_labels_daemon_claims_and_enforces_expect_uid() {
    let fx = fixture().await;
    let socket = fx.start(fx.config(ServerPolicy::default()));
    let socket_arg = path_str(socket.clone());

    let (ok, stdout, stderr) =
        agent_cli(vec!["status".into(), "--socket".into(), socket_arg.clone()]).await;
    assert!(ok, "{stderr}");
    let (checked, reported) = stdout
        .split_once("reported by the daemon (unverified")
        .unwrap_or_else(|| panic!("{stdout}"));
    assert!(checked.contains("checked by this client"), "{stdout}");
    assert!(
        checked.contains(&format!("uid:        {}", fx.uid())),
        "{stdout}"
    );
    assert!(checked.contains("exe:"), "{stdout}");
    assert!(
        reported.contains(&format!("vault:      {}", fx.vault_dir.display())),
        "{stdout}"
    );

    let wrong = fx.uid().wrapping_add(1).to_string();
    let (ok, stdout, stderr) = agent_cli(vec![
        "unlock".into(),
        "--socket".into(),
        socket_arg,
        "--expect-uid".into(),
        wrong.clone(),
    ])
    .await;
    assert!(!ok, "{stdout}");
    assert!(
        stderr.contains(&format!("not {wrong}; refusing to send the password")),
        "{stderr}"
    );
    assert!(!stdout.contains("password:"), "{stdout}");
    assert!(matches!(
        req(&socket, Request::Status).await.unwrap(),
        Payload::Status(status) if !status.unlocked
    ));
}
