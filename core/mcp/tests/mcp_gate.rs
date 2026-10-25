//! End-to-end tests of the MCP server as a thin client of `axiom-agent`,
//! driven through a real MCP client over an in-process transport, the way an
//! agent drives the server over stdio. The daemon's own policy checks are
//! tested in the agent crate.

use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use axiomvault_agent::{
    bind_socket, protocol::UnlockParams, serve, AgentClient, DaemonConfig, Request, ServerPolicy,
    VaultRoot, LOCKED_MESSAGE,
};
use axiomvault_app::{AppService, CreateVaultParams};
use axiomvault_mcp::AxiomMcpServer;
use rmcp::{
    model::{CallToolRequestParams, ReadResourceRequestParams, ResourceContents},
    service::{RunningService, ServiceError},
    RoleClient, ServiceExt,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASSWORD: &str = "old-password";

/// A local vault containing `/hello.txt` and `/docs`, created outside MCP,
/// with an agent serving it on a socket in the same temporary directory.
struct Fixture {
    _dir: TempDir,
    socket: PathBuf,
}

async fn fixture(policy: ServerPolicy) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    // Canonical, as `serve --vault` makes it.
    let vault_dir = std::fs::canonicalize(dir.path()).unwrap().join("vault");
    let app = AppService::new();
    app.create_vault(CreateVaultParams {
        vault_id: "gate".into(),
        password: Zeroizing::new(PASSWORD.into()),
        provider_type: "local".into(),
        provider_config: json!({ "root": vault_dir }),
    })
    .await
    .unwrap();
    app.create_file("/hello.txt", b"hello").await.unwrap();
    app.create_directory("/docs").await.unwrap();
    app.close_vault().await.unwrap();

    let socket = dir.path().join("agent.sock");
    let listener = bind_socket(&socket, 0o600).unwrap();
    tokio::spawn(serve(
        listener,
        DaemonConfig {
            vault_dir,
            policy,
            idle_lock: None,
            max_unlock: None,
            allowed_uids: vec![dir.path().metadata().unwrap().uid()],
        },
    ));
    Fixture { _dir: dir, socket }
}

impl Fixture {
    /// What `axiom-agent unlock` does on the user's behalf, outside MCP.
    async fn unlock(&self) {
        AgentClient::connect(&self.socket)
            .await
            .unwrap()
            .request(&Request::Unlock(UnlockParams {
                password: Zeroizing::new(PASSWORD.into()),
            }))
            .await
            .unwrap();
    }
}

async fn connect(socket: &Path) -> RunningService<RoleClient, ()> {
    let server = AxiomMcpServer::new(socket);
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

async fn resource(client: &RunningService<RoleClient, ()>, uri: &str) -> String {
    let result = client
        .read_resource(ReadResourceRequestParams::new(uri))
        .await
        .unwrap();
    let ResourceContents::TextResourceContents { text, .. } = &result.contents[0] else {
        panic!("{uri}: not text");
    };
    text.clone()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The server must have no way to accept, hold or return a vault secret,
/// and must not link the vault service that could hold a key.
#[test]
fn server_source_handles_no_secrets() {
    let mut sources = Vec::new();
    rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    assert!(!sources.is_empty());
    for path in sources {
        let text = std::fs::read_to_string(&path).unwrap().to_lowercase();
        for needle in ["password", "recovery_words", "axiomvault_app"] {
            assert!(
                !text.contains(needle),
                "{} mentions {needle}",
                path.display()
            );
        }
    }
}

#[tokio::test]
async fn tool_list_has_no_secret_taking_tools() {
    let client = connect(Path::new("/nonexistent/agent.sock")).await;
    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    for removed in ["create_vault", "open_vault", "recover_vault", "close_vault"] {
        assert!(!names.contains(&removed), "{removed} is still a tool");
    }
    assert!(names.contains(&"lock_vault"));
    for tool in &tools {
        let schema = serde_json::to_string(&tool.input_schema).unwrap();
        for needle in ["password", "recovery"] {
            assert!(!schema.contains(needle), "{}: {schema}", tool.name);
        }
    }
    let prompts = client.list_all_prompts().await.unwrap();
    assert!(prompts
        .iter()
        .all(|prompt| prompt.name != "vault_recovery_workflow"));
}

#[tokio::test]
async fn unreachable_agent_is_reported() {
    let client = connect(Path::new("/nonexistent/agent.sock")).await;
    let err = call(&client, "vault_info", json!({})).await.unwrap_err();
    assert!(err.contains("axiom-agent serve"), "{err}");
}

#[tokio::test]
async fn locked_vault_tells_the_model_to_ask_the_user() {
    let fx = fixture(ServerPolicy::default()).await;
    let client = connect(&fx.socket).await;

    let err = call(&client, "read_file", json!({ "path": "/hello.txt" }))
        .await
        .unwrap_err();
    assert_eq!(err, LOCKED_MESSAGE);
    let status: Value =
        serde_json::from_str(&resource(&client, "axiom://vault/status").await).unwrap();
    assert_eq!(status, json!({ "open": false }));
    let server: Value =
        serde_json::from_str(&resource(&client, "axiom://server/status").await).unwrap();
    assert_eq!(server["agent"]["Ok"]["unlocked"], false);

    fx.unlock().await;
    let value = call(&client, "read_file", json!({ "path": "/hello.txt" }))
        .await
        .unwrap();
    assert_eq!(value["content"], "hello");

    call(&client, "lock_vault", json!({})).await.unwrap();
    let err = call(&client, "vault_info", json!({})).await.unwrap_err();
    assert_eq!(err, LOCKED_MESSAGE);
}

#[tokio::test]
async fn read_only_tools_and_resources_go_through_the_agent() {
    let fx = fixture(ServerPolicy::default()).await;
    fx.unlock().await;
    let client = connect(&fx.socket).await;

    let info = call(&client, "vault_info", json!({})).await.unwrap();
    assert_eq!(info["id"], "gate");
    let entries = call(&client, "list_directory", json!({ "path": "/" }))
        .await
        .unwrap();
    assert_eq!(entries.as_array().unwrap().len(), 2);
    let read = call(
        &client,
        "read_file",
        json!({ "path": "/hello.txt", "max_bytes": 2 }),
    )
    .await
    .unwrap();
    assert_eq!(read["content"], "he");
    assert_eq!(read["size"], 5);
    assert_eq!(read["returned_bytes"], 2);
    assert_eq!(read["truncated"], true);
    let read = call(
        &client,
        "read_file",
        json!({ "path": "/hello.txt", "offset": 2, "max_bytes": 2 }),
    )
    .await
    .unwrap();
    assert_eq!(read["content"], "ll");
    assert_eq!(read["offset"], 2);
    assert_eq!(read["truncated"], true);
    let metadata = call(&client, "metadata", json!({ "path": "/docs" }))
        .await
        .unwrap();
    assert_eq!(metadata["is_directory"], true);
    let exists = call(&client, "exists", json!({ "path": "/hello.txt" }))
        .await
        .unwrap();
    assert_eq!(exists["exists"], true);

    // The agent was launched without --allow-writes, and its refusal reaches
    // the model unchanged.
    let err = call(
        &client,
        "write_file",
        json!({ "path": "/new.txt", "content": "x" }),
    )
    .await
    .unwrap_err();
    assert!(err.contains("--allow-writes"), "{err}");

    let listed = client.list_resources(None).await.unwrap();
    assert_eq!(listed.resources.len(), 3);
    for uri in [
        "axiom://server/status",
        "axiom://vault/status",
        "axiom://vault/tree",
    ] {
        assert!(!resource(&client, uri).await.is_empty(), "{uri}");
    }
    assert!(resource(&client, "axiom://vault/tree")
        .await
        .contains("hello.txt"));
}

#[tokio::test]
async fn mutating_tools_work_when_the_agent_allows_writes() {
    let fx = fixture(ServerPolicy::new(true, None, VaultRoot::whole_vault()).unwrap()).await;
    fx.unlock().await;
    let client = connect(&fx.socket).await;

    call(
        &client,
        "write_file",
        json!({ "path": "/new.txt", "content": "eA==", "encoding": "base64" }),
    )
    .await
    .unwrap();
    call(
        &client,
        "update_file",
        json!({ "path": "/hello.txt", "content": "changed" }),
    )
    .await
    .unwrap();
    call(&client, "mkdir", json!({ "path": "/made" }))
        .await
        .unwrap();
    let deleted = call(&client, "delete_path", json!({ "path": "/docs" }))
        .await
        .unwrap();
    assert_eq!(deleted["directory"], true);

    for (path, content) in [("/new.txt", "x"), ("/hello.txt", "changed")] {
        let read = call(&client, "read_file", json!({ "path": path }))
            .await
            .unwrap();
        assert_eq!(read["content"], content, "{path}");
    }
    for (path, expected) in [("/made", true), ("/docs", false)] {
        let value = call(&client, "exists", json!({ "path": path }))
            .await
            .unwrap();
        assert_eq!(value["exists"], expected, "{path}");
    }
}

#[tokio::test]
async fn vault_tree_starts_at_the_agent_root() {
    let fx =
        fixture(ServerPolicy::new(false, None, VaultRoot::parse("/docs").unwrap()).unwrap()).await;
    fx.unlock().await;
    let client = connect(&fx.socket).await;

    let tree: Value = serde_json::from_str(&resource(&client, "axiom://vault/tree").await).unwrap();
    assert_eq!(tree["root"], "/docs");
    assert_eq!(tree["truncated"], false);
    let err = call(&client, "read_file", json!({ "path": "/hello.txt" }))
        .await
        .unwrap_err();
    assert!(err.contains("--root"), "{err}");
}

#[tokio::test]
async fn vault_tree_is_bounded_and_valid_json() {
    let fx = fixture(ServerPolicy::new(true, None, VaultRoot::whole_vault()).unwrap()).await;
    fx.unlock().await;
    let client = connect(&fx.socket).await;

    // Deeper than the depth cap: a recursive walk would follow it all.
    let mut path = String::new();
    for _ in 0..40 {
        path.push_str("/d");
        call(&client, "mkdir", json!({ "path": path }))
            .await
            .unwrap();
    }
    let tree: Value = serde_json::from_str(&resource(&client, "axiom://vault/tree").await).unwrap();
    assert_eq!(tree["truncated"], true);
    let entries = tree["entries"].as_array().unwrap();
    assert!(entries.iter().any(|entry| entry["path"] == "/hello.txt"));
    assert!(entries.len() < 40, "{}", entries.len());

    // More entries than fit: the listing stops early and stays valid JSON.
    for index in 0..200 {
        let path = format!("/docs/{index:03}-{}", "x".repeat(60));
        call(
            &client,
            "write_file",
            json!({ "path": path, "content": "" }),
        )
        .await
        .unwrap();
    }
    let text = resource(&client, "axiom://vault/tree").await;
    assert!(text.len() <= 16 * 1024, "{}", text.len());
    let tree: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(tree["truncated"], true);
    assert!(tree["entries"].as_array().unwrap().len() < 200);
}
