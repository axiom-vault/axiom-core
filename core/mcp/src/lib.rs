//! MCP front end for an `axiom-agent` daemon.
//!
//! This server holds no key and no secret, and has no tool that accepts or
//! returns one: the agent keeps the unlocked vault, enforces the launch
//! policy, and is unlocked only by the user at their own terminal.

use std::{collections::VecDeque, path::PathBuf};

use axiomvault_agent::{
    protocol::{Base64Content, DirEntry},
    AgentClient, AgentStatus, ClientError, ErrorKind, Payload, Request, LOCKED_MESSAGE,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rmcp::{
    handler::server::{
        router::{prompt::PromptRouter, tool::ToolRouter},
        wrapper::Parameters,
    },
    model::*,
    prompt, prompt_handler, prompt_router,
    schemars::{self, JsonSchema},
    service::RequestContext,
    tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

const MAX_READ_BYTES: usize = 64 * 1024;
const MAX_RESOURCE_BYTES: usize = 16 * 1024;
const SERVER_STATUS_URI: &str = "axiom://server/status";
const VAULT_STATUS_URI: &str = "axiom://vault/status";
const VAULT_TREE_URI: &str = "axiom://vault/tree";
/// Directories below the root that the tree resource descends into.
const MAX_TREE_DEPTH: usize = 32;
/// Allowance per tree entry for the whitespace of pretty-printed JSON.
const TREE_ENTRY_OVERHEAD: usize = 64;

#[derive(Clone)]
pub struct AxiomMcpServer {
    socket: PathBuf,
    #[expect(
        dead_code,
        reason = "stored router used by rmcp macro-generated handlers"
    )]
    tool_router: ToolRouter<Self>,
    #[expect(
        dead_code,
        reason = "stored router used by rmcp macro-generated handlers"
    )]
    prompt_router: PromptRouter<Self>,
}

impl AxiomMcpServer {
    /// A client of the agent listening on `socket`. What is allowed (writes,
    /// file I/O, the visible subtree) is the agent's launch policy.
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            tool_router: Self::tool_router(),
            prompt_router: Self::prompt_router(),
        }
    }

    async fn connect(&self) -> Result<AgentClient, McpError> {
        AgentClient::connect(&self.socket).await.map_err(|err| {
            McpError::internal_error(
                format!(
                    "cannot reach axiom-agent at {} ({err}); ask the user to start `axiom-agent serve`",
                    self.socket.display()
                ),
                None,
            )
        })
    }

    async fn agent(&self, request: Request) -> Result<Payload, McpError> {
        self.connect()
            .await?
            .request(&request)
            .await
            .map_err(map_client_error)
    }

    /// Bytes to read: the requested amount, capped at `ceiling`, at least 1.
    fn read_limit(requested: Option<usize>, ceiling: usize) -> usize {
        requested.unwrap_or(ceiling).min(ceiling).max(1)
    }

    /// Describes `slice`, the bytes at `offset` of something `size` bytes
    /// long. Text cut inside a character by the size limit is returned up
    /// to the last whole character rather than switched to base64.
    fn read_buffer(slice: &[u8], offset: u64, size: u64) -> ReadBuffer {
        let end = offset.saturating_add(slice.len() as u64);
        let text = match std::str::from_utf8(slice) {
            Ok(text) => Some(text),
            Err(err) if err.error_len().is_none() && err.valid_up_to() > 0 && size > end => {
                std::str::from_utf8(&slice[..err.valid_up_to()]).ok()
            }
            Err(_) => None,
        };
        let (encoding, content, returned) = match text {
            Some(text) => ("utf-8", text.to_string(), text.len()),
            None => ("base64", BASE64.encode(slice), slice.len()),
        };
        ReadBuffer {
            encoding: encoding.to_string(),
            content,
            size,
            offset,
            returned_bytes: returned,
            truncated: size > offset.saturating_add(returned as u64),
        }
    }

    /// A flat listing of the agent's `--root` subtree, breadth first, that
    /// stops at [`MAX_TREE_DEPTH`] or once it would no longer fit in
    /// [`MAX_RESOURCE_BYTES`], and says so in `truncated`.
    async fn vault_tree(&self) -> Result<VaultTree, McpError> {
        let mut client = self.connect().await?;
        let root = match ask(&mut client, Request::Status).await? {
            Payload::Status(status) => status.root,
            other => return Err(unexpected(other)),
        };
        let root_meta = match ask(&mut client, Request::Metadata { path: root.clone() }).await? {
            Payload::Metadata(metadata) => metadata,
            other => return Err(unexpected(other)),
        };
        let mut tree = VaultTree {
            root: root.clone(),
            entries: Vec::new(),
            truncated: false,
        };
        if !root_meta.is_directory {
            tree.entries.push(DirEntry {
                name: root_meta.name,
                path: root_meta.path,
                is_directory: false,
                size: root_meta.size,
            });
            return Ok(tree);
        }
        let mut used = serde_json::to_vec_pretty(&tree)
            .map_err(|err| McpError::internal_error(err.to_string(), None))?
            .len();
        let mut queue = VecDeque::from([(root, 0)]);
        while let Some((dir, depth)) = queue.pop_front() {
            let entries = match ask(&mut client, Request::ListDirectory { path: dir }).await? {
                Payload::Entries { entries } => entries,
                other => return Err(unexpected(other)),
            };
            for entry in entries {
                let cost = serde_json::to_vec(&entry)
                    .map_err(|err| McpError::internal_error(err.to_string(), None))?
                    .len()
                    + TREE_ENTRY_OVERHEAD;
                if used + cost > MAX_RESOURCE_BYTES {
                    tree.truncated = true;
                    return Ok(tree);
                }
                used += cost;
                if entry.is_directory {
                    if depth < MAX_TREE_DEPTH {
                        queue.push_back((entry.path.clone(), depth + 1));
                    } else {
                        tree.truncated = true;
                    }
                }
                tree.entries.push(entry);
            }
        }
        Ok(tree)
    }

    /// Pretty JSON, or, past [`MAX_RESOURCE_BYTES`], a small valid JSON
    /// object saying so instead of a cut-off document.
    fn resource_text<T: Serialize>(uri: &str, value: &T) -> Result<ResourceContents, McpError> {
        let json = serde_json::to_string_pretty(value)
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;
        let payload = if json.len() > MAX_RESOURCE_BYTES {
            json!({
                "truncated": true,
                "size": json.len(),
                "message": format!("resource exceeds {MAX_RESOURCE_BYTES} bytes"),
            })
            .to_string()
        } else {
            json
        };
        Ok(ResourceContents::text(payload, uri.to_string()))
    }
}

async fn ask(client: &mut AgentClient, request: Request) -> Result<Payload, McpError> {
    client.request(&request).await.map_err(map_client_error)
}

fn map_client_error(err: ClientError) -> McpError {
    match err {
        ClientError::Io(err) => {
            McpError::internal_error(format!("axiom-agent connection failed: {err}"), None)
        }
        ClientError::Agent(err) => match err.kind {
            ErrorKind::Locked => McpError::invalid_request(LOCKED_MESSAGE, None),
            ErrorKind::NotFound => {
                McpError::resource_not_found("not_found", Some(json!({ "message": err.message })))
            }
            ErrorKind::InvalidParams | ErrorKind::AlreadyExists => {
                McpError::invalid_params(err.message, None)
            }
            ErrorKind::Denied
            | ErrorKind::AlreadyUnlocked
            | ErrorKind::AuthFailed
            | ErrorKind::InvalidRequest => McpError::invalid_request(err.message, None),
            ErrorKind::Internal => McpError::internal_error(err.message, None),
        },
    }
}

fn unexpected(payload: Payload) -> McpError {
    McpError::internal_error(
        format!("unexpected axiom-agent response: {payload:?}"),
        None,
    )
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct VaultPathArgs {
    pub path: String,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct ReadFileArgs {
    pub path: String,
    /// Byte offset to start reading at (default 0).
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct WriteFileArgs {
    pub path: String,
    pub content: String,
    #[serde(default = "default_encoding")]
    pub encoding: String,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct DeletePathArgs {
    pub path: String,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct ImportFileArgs {
    pub local_path: String,
    pub vault_path: String,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct ExportFileArgs {
    pub vault_path: String,
    pub local_path: String,
}

#[derive(Clone, Serialize)]
pub struct ReadBuffer {
    pub encoding: String,
    pub content: String,
    pub size: u64,
    pub offset: u64,
    pub returned_bytes: usize,
    pub truncated: bool,
}

#[derive(Clone, Serialize)]
pub struct StatusResponse {
    pub server: &'static str,
    pub max_read_bytes: usize,
    /// The agent's launch policy and lock state, or why it is unavailable.
    pub agent: Result<AgentStatus, String>,
}

#[derive(Clone, Serialize)]
pub struct VaultTree {
    pub root: String,
    pub entries: Vec<DirEntry>,
    /// True if entries were left out to stay within the size or depth cap.
    pub truncated: bool,
}

fn default_encoding() -> String {
    "utf-8".to_string()
}

fn decode_content(args: &WriteFileArgs) -> Result<Vec<u8>, McpError> {
    match args.encoding.as_str() {
        "utf-8" => Ok(args.content.as_bytes().to_vec()),
        "base64" => BASE64
            .decode(&args.content)
            .map_err(|err| McpError::invalid_params(err.to_string(), None)),
        other => Err(McpError::invalid_params(
            format!("unsupported encoding: {other}"),
            None,
        )),
    }
}

fn ok_json<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    let body = serde_json::to_string_pretty(value)
        .map_err(|err| McpError::internal_error(err.to_string(), None))?;
    Ok(CallToolResult::success(vec![Content::text(body)]))
}

#[tool_router]
impl AxiomMcpServer {
    #[tool(description = "Lock the vault; only the user can unlock it again")]
    async fn lock_vault(&self) -> Result<CallToolResult, McpError> {
        self.agent(Request::Lock).await?;
        ok_json(&json!({ "locked": true }))
    }

    #[tool(description = "Get active vault info")]
    async fn vault_info(&self) -> Result<CallToolResult, McpError> {
        match self.agent(Request::VaultInfo).await? {
            Payload::VaultInfo(info) => ok_json(&info),
            other => Err(unexpected(other)),
        }
    }

    #[tool(description = "List a vault directory")]
    async fn list_directory(
        &self,
        Parameters(args): Parameters<VaultPathArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self
            .agent(Request::ListDirectory { path: args.path })
            .await?
        {
            Payload::Entries { entries } => ok_json(&entries),
            other => Err(unexpected(other)),
        }
    }

    #[tool(
        description = "Read a file, or the part from offset on, with size limits and truncation metadata"
    )]
    async fn read_file(
        &self,
        Parameters(args): Parameters<ReadFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let limit = Self::read_limit(args.max_bytes, MAX_READ_BYTES);
        let offset = args.offset.unwrap_or(0);
        let (content, size) = match self
            .agent(Request::ReadFile {
                path: args.path,
                offset: Some(offset),
                max_bytes: Some(limit as u64),
            })
            .await?
        {
            Payload::File { content_b64, size } => (content_b64, size),
            other => return Err(unexpected(other)),
        };
        let bytes = BASE64
            .decode(content.0)
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;
        ok_json(&Self::read_buffer(&bytes, offset, size))
    }

    #[tool(description = "Create a new file inside the vault")]
    async fn write_file(
        &self,
        Parameters(args): Parameters<WriteFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let bytes = decode_content(&args)?;
        self.agent(Request::CreateFile {
            path: args.path.clone(),
            content_b64: Base64Content(BASE64.encode(&bytes)),
        })
        .await?;
        ok_json(&json!({ "written": true, "path": args.path, "bytes": bytes.len() }))
    }

    #[tool(description = "Update an existing file inside the vault")]
    async fn update_file(
        &self,
        Parameters(args): Parameters<WriteFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let bytes = decode_content(&args)?;
        self.agent(Request::UpdateFile {
            path: args.path.clone(),
            content_b64: Base64Content(BASE64.encode(&bytes)),
        })
        .await?;
        ok_json(&json!({ "updated": true, "path": args.path, "bytes": bytes.len() }))
    }

    #[tool(description = "Delete a file or directory from the vault")]
    async fn delete_path(
        &self,
        Parameters(args): Parameters<DeletePathArgs>,
    ) -> Result<CallToolResult, McpError> {
        let metadata = match self
            .agent(Request::Delete {
                path: args.path.clone(),
            })
            .await?
        {
            Payload::Metadata(metadata) => metadata,
            other => return Err(unexpected(other)),
        };
        ok_json(&json!({
            "deleted": true,
            "path": args.path,
            "directory": metadata.is_directory,
        }))
    }

    #[tool(description = "Create a directory inside the vault")]
    async fn mkdir(
        &self,
        Parameters(args): Parameters<DeletePathArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.agent(Request::Mkdir {
            path: args.path.clone(),
        })
        .await?;
        ok_json(&json!({ "created": true, "path": args.path }))
    }

    #[tool(description = "Get file or directory metadata")]
    async fn metadata(
        &self,
        Parameters(args): Parameters<VaultPathArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self.agent(Request::Metadata { path: args.path }).await? {
            Payload::Metadata(metadata) => ok_json(&metadata),
            other => Err(unexpected(other)),
        }
    }

    #[tool(description = "Check whether a vault path exists")]
    async fn exists(
        &self,
        Parameters(args): Parameters<VaultPathArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self
            .agent(Request::Exists {
                path: args.path.clone(),
            })
            .await?
        {
            Payload::Exists { exists } => ok_json(&json!({ "path": args.path, "exists": exists })),
            other => Err(unexpected(other)),
        }
    }

    #[tool(description = "Import a local file into the vault")]
    async fn import_file(
        &self,
        Parameters(args): Parameters<ImportFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.agent(Request::ImportFile {
            local_path: args.local_path.clone(),
            vault_path: args.vault_path.clone(),
        })
        .await?;
        ok_json(&json!({
            "imported": true,
            "local_path": args.local_path,
            "vault_path": args.vault_path,
        }))
    }

    #[tool(description = "Export a vault file to the local filesystem")]
    async fn export_file(
        &self,
        Parameters(args): Parameters<ExportFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.agent(Request::ExportFile {
            vault_path: args.vault_path.clone(),
            local_path: args.local_path.clone(),
        })
        .await?;
        ok_json(&json!({
            "exported": true,
            "vault_path": args.vault_path,
            "local_path": args.local_path,
        }))
    }
}

#[prompt_router]
impl AxiomMcpServer {
    #[prompt(
        name = "safe_readonly_workflow",
        description = "Checklist for safe read-only vault inspection"
    )]
    async fn safe_readonly_workflow(&self) -> Vec<PromptMessage> {
        vec![PromptMessage::new_text(
            PromptMessageRole::Assistant,
            "1. Inspect vault_info. If the vault is locked, ask the user to run `axiom-agent unlock` in their own terminal; no tool can unlock it. 2. Use exists, metadata, list_directory, and read_file before any mutation. 3. Respect truncation flags; read large files in parts with offset and max_bytes.",
        )]
    }

    #[prompt(
        name = "safe_write_workflow",
        description = "Checklist for guarded write operations"
    )]
    async fn safe_write_workflow(&self) -> Vec<PromptMessage> {
        vec![PromptMessage::new_text(
            PromptMessageRole::Assistant,
            "1. Verify target paths with exists/metadata. 2. Require explicit user approval. 3. Mutating tools work only when the user launched axiom-agent with --allow-writes; import/export also need --allow-file-io=<dir> and stay inside that directory; every vault path must lie under the agent's --root. 4. Re-read metadata after write/update/delete/mkdir/import/export.",
        )]
    }
}

#[tool_handler]
#[prompt_handler]
impl ServerHandler for AxiomMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        )
        .with_instructions(
            "AxiomVault MCP server. It is a client of axiom-agent, which holds the vault keys; this server handles no secrets and cannot unlock the vault. If a tool reports that the vault is locked, ask the user to run `axiom-agent unlock` in their own terminal. Mutating tools need an agent launched with --allow-writes; import_file/export_file need --allow-file-io=<dir> and are confined to that directory; vault paths must lie under the agent's --root. Read responses may be truncated.",
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            resources: vec![
                RawResource::new(SERVER_STATUS_URI, "server-status").no_annotation(),
                RawResource::new(VAULT_STATUS_URI, "vault-status").no_annotation(),
                RawResource::new(VAULT_TREE_URI, "vault-tree").no_annotation(),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let contents = match request.uri.as_str() {
            SERVER_STATUS_URI => {
                let agent = match self.agent(Request::Status).await {
                    Ok(Payload::Status(status)) => Ok(status),
                    Ok(other) => Err(unexpected(other).message.to_string()),
                    Err(err) => Err(err.message.to_string()),
                };
                Self::resource_text(
                    SERVER_STATUS_URI,
                    &StatusResponse {
                        server: "axiomvault-mcp",
                        max_read_bytes: MAX_READ_BYTES,
                        agent,
                    },
                )?
            }
            VAULT_STATUS_URI => {
                let response = self.connect().await?.request(&Request::VaultInfo).await;
                let payload = match response {
                    Ok(Payload::VaultInfo(info)) => serde_json::to_value(info)
                        .map_err(|err| McpError::internal_error(err.to_string(), None))?,
                    Ok(other) => return Err(unexpected(other)),
                    Err(ClientError::Agent(err)) if err.kind == ErrorKind::Locked => {
                        json!({ "open": false })
                    }
                    Err(err) => return Err(map_client_error(err)),
                };
                Self::resource_text(VAULT_STATUS_URI, &payload)?
            }
            VAULT_TREE_URI => {
                let tree = self.vault_tree().await?;
                Self::resource_text(VAULT_TREE_URI, &tree)?
            }
            _ => {
                return Err(McpError::resource_not_found(
                    "resource_not_found",
                    Some(json!({ "uri": request.uri })),
                ))
            }
        };
        Ok(ReadResourceResult::new(vec![contents]))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(ListResourceTemplatesResult {
            next_cursor: None,
            resource_templates: Vec::new(),
            meta: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiomvault_agent::AgentError;

    #[test]
    fn read_buffer_marks_truncation_and_size() {
        let output = AxiomMcpServer::read_buffer(b"hello", 0, 11);
        assert_eq!(output.content, "hello");
        assert_eq!(output.returned_bytes, 5);
        assert_eq!(output.size, 11);
        assert!(output.truncated);

        // A read at an offset is truncated only if bytes follow it.
        let output = AxiomMcpServer::read_buffer(b"world", 6, 11);
        assert_eq!(output.offset, 6);
        assert!(!output.truncated);
        let output = AxiomMcpServer::read_buffer(b"wor", 6, 11);
        assert!(output.truncated);
    }

    #[test]
    fn read_buffer_uses_base64_for_binary_content() {
        let output = AxiomMcpServer::read_buffer(&[0, 159, 146, 150], 0, 4);
        assert_eq!(output.encoding, "base64");
        assert!(!output.content.is_empty());
        assert!(!output.truncated);
    }

    #[test]
    fn read_buffer_backs_off_to_a_character_boundary() {
        // "aé" is 61 c3 a9; a 2-byte read cuts the é in half.
        let output = AxiomMcpServer::read_buffer("aé".as_bytes().get(..2).unwrap(), 0, 3);
        assert_eq!(output.encoding, "utf-8");
        assert_eq!(output.content, "a");
        assert_eq!(output.returned_bytes, 1);
        assert!(output.truncated);

        // A cut before the first whole character, and a file that really
        // ends mid-character, are not text.
        let output = AxiomMcpServer::read_buffer(&"é".as_bytes()[..1], 0, 2);
        assert_eq!(output.encoding, "base64");
        let output = AxiomMcpServer::read_buffer(&"aé".as_bytes()[..2], 0, 2);
        assert_eq!(output.encoding, "base64");
        assert!(!output.truncated);
    }

    #[test]
    fn oversized_resources_stay_valid_json() {
        let big = vec!["x".repeat(100); 1000];
        let ResourceContents::TextResourceContents { text, .. } =
            AxiomMcpServer::resource_text("axiom://test", &big).unwrap()
        else {
            panic!("not text");
        };
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["truncated"], true);
        assert!(text.len() < MAX_RESOURCE_BYTES);
    }

    #[test]
    fn read_limit_is_capped_and_positive() {
        assert_eq!(AxiomMcpServer::read_limit(None, 10), 10);
        assert_eq!(AxiomMcpServer::read_limit(Some(50), 10), 10);
        assert_eq!(AxiomMcpServer::read_limit(Some(0), 10), 1);
        assert_eq!(AxiomMcpServer::read_limit(Some(3), 10), 3);
    }

    #[test]
    fn decode_content_rejects_unknown_encoding() {
        let err = decode_content(&WriteFileArgs {
            path: "/note.txt".into(),
            content: "abc".into(),
            encoding: "hex".into(),
        })
        .unwrap_err();
        assert!(err.message.contains("unsupported encoding"));
    }

    #[test]
    fn locked_error_tells_the_model_to_ask_the_user() {
        let err = map_client_error(ClientError::Agent(AgentError::new(
            ErrorKind::Locked,
            "anything",
        )));
        assert_eq!(err.message, LOCKED_MESSAGE);
    }
}
