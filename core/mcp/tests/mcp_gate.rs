//! End-to-end tests of the launch-time gates (H-5, M-6), driven through a
//! real MCP client over an in-process transport, the way an agent drives the
//! server over stdio.

use std::path::Path;

use axiomvault_app::{AppService, CreateVaultParams};
use axiomvault_mcp::{AxiomMcpServer, ServerPolicy};
use rmcp::{
    model::{CallToolRequestParams, ReadResourceRequestParams, ResourceContents},
    service::{RunningService, ServiceError},
    RoleClient, ServiceExt,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASSWORD: &str = "old-password";

struct Fixture {
    _dir: TempDir,
    config: Value,
    words: String,
}

/// A local vault containing `/hello.txt` and `/docs`, created outside MCP.
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let config = json!({ "root": dir.path().join("vault") });
    let app = AppService::new();
    let created = app
        .create_vault(CreateVaultParams {
            vault_id: "gate".into(),
            password: Zeroizing::new(PASSWORD.into()),
            provider_type: "local".into(),
            provider_config: config.clone(),
        })
        .await
        .unwrap();
    app.create_file("/hello.txt", b"hello").await.unwrap();
    app.create_directory("/docs").await.unwrap();
    app.close_vault().await.unwrap();
    Fixture {
        _dir: dir,
        config,
        words: created.recovery_words.to_string(),
    }
}

async fn connect(server: AxiomMcpServer) -> RunningService<RoleClient, ()> {
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    ().serve(client_io).await.unwrap()
}

async fn call(
    client: &RunningService<RoleClient, ()>,
    name: &'static str,
    args: Value,
) -> Result<Value, String> {
    let params = CallToolRequestParams::new(name).with_arguments(args.as_object().unwrap().clone());
    match client.call_tool(params).await {
        Ok(result) => {
            let text = &result.content[0].raw.as_text().unwrap().text;
            Ok(serde_json::from_str(text).unwrap())
        }
        Err(ServiceError::McpError(err)) => Err(err.message.to_string()),
        Err(other) => panic!("transport failure: {other}"),
    }
}

async fn open(client: &RunningService<RoleClient, ()>, fx: &Fixture, password: &str) {
    call(
        client,
        "open_vault",
        json!({ "password": password, "provider_type": "local", "provider_config": fx.config }),
    )
    .await
    .unwrap();
}

async fn read_text(client: &RunningService<RoleClient, ()>, path: &str) -> String {
    let value = call(client, "read_file", json!({ "path": path }))
        .await
        .unwrap();
    value["content"].as_str().unwrap().to_string()
}

fn writes() -> AxiomMcpServer {
    AxiomMcpServer::with_policy(ServerPolicy::new(true, None).unwrap())
}

fn file_io(allow_writes: bool, jail: &Path) -> AxiomMcpServer {
    AxiomMcpServer::with_policy(ServerPolicy::new(allow_writes, Some(jail)).unwrap())
}

fn mutating_calls(fx: &Fixture) -> Vec<(&'static str, Value)> {
    vec![
        (
            "write_file",
            json!({ "path": "/new.txt", "content": "x", "allow_write": true }),
        ),
        (
            "update_file",
            json!({ "path": "/hello.txt", "content": "changed", "allow_write": true }),
        ),
        ("mkdir", json!({ "path": "/made", "allow_write": true })),
        (
            "delete_path",
            json!({ "path": "/docs", "allow_write": true }),
        ),
        (
            "recover_vault",
            json!({
                "recovery_words": fx.words,
                "new_password": "new-password",
                "provider_type": "local",
                "provider_config": fx.config,
                "allow_write": true,
            }),
        ),
    ]
}

#[tokio::test]
async fn mutating_tools_refuse_without_allow_writes_even_with_allow_write_true() {
    let fx = fixture().await;
    let client = connect(AxiomMcpServer::new()).await;
    open(&client, &fx, PASSWORD).await;

    for (name, args) in mutating_calls(&fx) {
        let err = call(&client, name, args).await.unwrap_err();
        assert!(err.contains("--allow-writes"), "{name}: {err}");
    }
    let err = call(
        &client,
        "create_vault",
        json!({
            "vault_id": "other",
            "password": "p",
            "provider_type": "memory",
            "allow_write": true,
        }),
    )
    .await
    .unwrap_err();
    assert!(err.contains("--allow-writes"), "create_vault: {err}");

    // Nothing changed, and the password was not reset.
    assert_eq!(read_text(&client, "/hello.txt").await, "hello");
    for (path, expected) in [("/new.txt", false), ("/made", false), ("/docs", true)] {
        let value = call(&client, "exists", json!({ "path": path }))
            .await
            .unwrap();
        assert_eq!(value["exists"], expected, "{path}");
    }
    call(&client, "close_vault", json!({})).await.unwrap();
    open(&client, &fx, PASSWORD).await;
}

#[tokio::test]
async fn mutating_tools_work_with_allow_writes() {
    let fx = fixture().await;
    let client = connect(writes()).await;
    open(&client, &fx, PASSWORD).await;

    for (name, args) in mutating_calls(&fx) {
        call(&client, name, args)
            .await
            .unwrap_or_else(|err| panic!("{name}: {err}"));
    }
    assert_eq!(read_text(&client, "/new.txt").await, "x");
    assert_eq!(read_text(&client, "/hello.txt").await, "changed");
    let made = call(&client, "exists", json!({ "path": "/made" }))
        .await
        .unwrap();
    assert_eq!(made["exists"], true);
    let docs = call(&client, "exists", json!({ "path": "/docs" }))
        .await
        .unwrap();
    assert_eq!(docs["exists"], false);

    call(&client, "close_vault", json!({})).await.unwrap();
    open(&client, &fx, "new-password").await;
}

#[tokio::test]
async fn recover_vault_refuses_wrong_words_even_with_allow_writes() {
    let fx = fixture().await;
    let client = connect(writes()).await;
    let wrong = "abandon ".repeat(23) + "art";
    for words in ["", wrong.as_str()] {
        call(
            &client,
            "recover_vault",
            json!({
                "recovery_words": words,
                "new_password": "new-password",
                "provider_type": "local",
                "provider_config": fx.config,
            }),
        )
        .await
        .unwrap_err();
    }
    open(&client, &fx, PASSWORD).await;
}

#[tokio::test]
async fn file_io_refuses_without_allow_file_io() {
    let fx = fixture().await;
    let outside = tempfile::tempdir().unwrap();
    let source = outside.path().join("source.txt");
    std::fs::write(&source, b"secret").unwrap();
    let target = outside.path().join("exported.txt");

    // With no flags, import is refused by the write gate first.
    let servers = [
        (AxiomMcpServer::new(), "--allow-writes"),
        (writes(), "--allow-file-io"),
    ];
    for (server, import_refusal) in servers {
        let client = connect(server).await;
        open(&client, &fx, PASSWORD).await;
        let err = call(
            &client,
            "import_file",
            json!({ "local_path": source, "vault_path": "/imported", "allow_write": true }),
        )
        .await
        .unwrap_err();
        assert!(err.contains(import_refusal), "import_file: {err}");
        let err = call(
            &client,
            "export_file",
            json!({ "vault_path": "/hello.txt", "local_path": target, "allow_write": true }),
        )
        .await
        .unwrap_err();
        assert!(err.contains("--allow-file-io"), "export_file: {err}");
        let imported = call(&client, "exists", json!({ "path": "/imported" }))
            .await
            .unwrap();
        assert_eq!(imported["exists"], false);
    }
    assert!(!target.exists());
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

    let client = connect(file_io(true, &jail)).await;
    open(&client, &fx, PASSWORD).await;

    call(
        &client,
        "import_file",
        json!({ "local_path": "inside.txt", "vault_path": "/a" }),
    )
    .await
    .unwrap();
    assert_eq!(read_text(&client, "/a").await, "inside");
    call(
        &client,
        "import_file",
        json!({ "local_path": jail.join("inside.txt"), "vault_path": "/b" }),
    )
    .await
    .unwrap();

    let escapes = [
        json!(jail.join("../secret")),
        json!("../secret"),
        json!(base.path().join("secret")),
        json!("link"),
        json!("linkdir/secret"),
        json!("/etc/passwd"),
        json!(""),
    ];
    for (index, local_path) in escapes.into_iter().enumerate() {
        let vault_path = format!("/escape{index}");
        let err = call(
            &client,
            "import_file",
            json!({ "local_path": local_path, "vault_path": vault_path }),
        )
        .await
        .unwrap_err();
        assert!(!err.is_empty(), "{local_path}");
        let exists = call(&client, "exists", json!({ "path": vault_path }))
            .await
            .unwrap();
        assert_eq!(exists["exists"], false, "{local_path} was imported");
    }

    // Refusals must not reveal whether a path outside the jail exists.
    for pair in [
        ["/etc/passwd", "/etc/no-such-file-here"],
        ["linkdir/secret", "linkdir/no-such-file-here"],
    ] {
        let mut messages = Vec::new();
        for local_path in pair {
            messages.push(
                call(
                    &client,
                    "import_file",
                    json!({ "local_path": local_path, "vault_path": "/oracle" }),
                )
                .await
                .unwrap_err(),
            );
        }
        assert_eq!(messages[0], messages[1], "{pair:?}");
    }

    // Import mutates the vault, so it also needs --allow-writes.
    let client = connect(file_io(false, &jail)).await;
    open(&client, &fx, PASSWORD).await;
    let err = call(
        &client,
        "import_file",
        json!({ "local_path": "inside.txt", "vault_path": "/c" }),
    )
    .await
    .unwrap_err();
    assert!(err.contains("--allow-writes"), "{err}");
}

#[tokio::test]
async fn export_is_confined_and_never_overwrites() {
    use std::os::unix::fs::PermissionsExt;

    let fx = fixture().await;
    let base = tempfile::tempdir().unwrap();
    let jail = base.path().join("jail");
    std::fs::create_dir(&jail).unwrap();
    std::fs::write(jail.join("existing.txt"), b"keep me").unwrap();
    std::os::unix::fs::symlink(base.path().join("victim"), jail.join("dangling")).unwrap();
    std::os::unix::fs::symlink(base.path(), jail.join("linkdir")).unwrap();

    // Export writes only inside the jail and does not need --allow-writes.
    let client = connect(file_io(false, &jail)).await;
    open(&client, &fx, PASSWORD).await;

    let refused = [
        json!("existing.txt"),
        json!("dangling"),
        json!("../escape.txt"),
        json!(jail.join("../escape.txt")),
        json!(base.path().join("escape.txt")),
        json!("linkdir/escape.txt"),
        json!("missing-dir/out.txt"),
    ];
    for local_path in refused {
        let err = call(
            &client,
            "export_file",
            json!({ "vault_path": "/hello.txt", "local_path": local_path }),
        )
        .await
        .unwrap_err();
        assert!(!err.is_empty(), "{local_path}");
    }
    assert_eq!(
        std::fs::read(jail.join("existing.txt")).unwrap(),
        b"keep me"
    );
    assert!(!base.path().join("escape.txt").exists());
    assert!(!base.path().join("victim").exists());

    call(
        &client,
        "export_file",
        json!({ "vault_path": "/hello.txt", "local_path": "out.txt" }),
    )
    .await
    .unwrap();
    let out = jail.join("out.txt");
    assert_eq!(std::fs::read(&out).unwrap(), b"hello");
    let mode = std::fs::symlink_metadata(&out)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    // A second export to the same name is refused.
    call(
        &client,
        "export_file",
        json!({ "vault_path": "/hello.txt", "local_path": "out.txt" }),
    )
    .await
    .unwrap_err();
}

#[tokio::test]
async fn read_only_tools_and_resources_work_without_flags() {
    let fx = fixture().await;
    let client = connect(AxiomMcpServer::new()).await;
    open(&client, &fx, PASSWORD).await;

    let info = call(&client, "vault_info", json!({})).await.unwrap();
    assert_eq!(info["id"], "gate");
    let entries = call(&client, "list_directory", json!({ "path": "/" }))
        .await
        .unwrap();
    assert_eq!(entries.as_array().unwrap().len(), 2);
    assert_eq!(read_text(&client, "/hello.txt").await, "hello");
    let metadata = call(&client, "metadata", json!({ "path": "/docs" }))
        .await
        .unwrap();
    assert_eq!(metadata["is_directory"], true);
    let exists = call(&client, "exists", json!({ "path": "/hello.txt" }))
        .await
        .unwrap();
    assert_eq!(exists["exists"], true);

    let listed = client.list_resources(None).await.unwrap();
    assert_eq!(listed.resources.len(), 3);
    for uri in [
        "axiom://server/status",
        "axiom://vault/status",
        "axiom://vault/tree",
    ] {
        let result = client
            .read_resource(ReadResourceRequestParams::new(uri))
            .await
            .unwrap();
        let ResourceContents::TextResourceContents { text, .. } = &result.contents[0] else {
            panic!("{uri}: not text");
        };
        assert!(!text.is_empty(), "{uri}");
        if uri == "axiom://vault/tree" {
            assert!(text.contains("hello.txt"));
        }
    }
}
