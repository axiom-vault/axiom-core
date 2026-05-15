use std::{future::Future, pin::Pin, sync::Arc};

use axiomvault_app::{
    AppError, AppService, CreateVaultParams, DirectoryEntryDto, FileMetadataDto, OpenVaultParams,
    RecoverVaultParams, VaultCreatedDto, VaultInfoDto,
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
use zeroize::Zeroizing;

const MAX_READ_BYTES: usize = 64 * 1024;
const MAX_RESOURCE_BYTES: usize = 16 * 1024;
const SERVER_STATUS_URI: &str = "axiom://server/status";
const VAULT_STATUS_URI: &str = "axiom://vault/status";
const VAULT_TREE_URI: &str = "axiom://vault/tree";

#[derive(Clone)]
pub struct AxiomMcpServer {
    app: Arc<AppService>,
    #[expect(dead_code, reason = "stored router used by rmcp macro-generated handlers")]
 tool_router: ToolRouter<Self>,
    #[expect(dead_code, reason = "stored router used by rmcp macro-generated handlers")]
 prompt_router: PromptRouter<Self>,
}

impl AxiomMcpServer {
    pub fn new() -> Self {
        Self {
            app: Arc::new(AppService::new()),
            tool_router: Self::tool_router(),
            prompt_router: Self::prompt_router(),
        }
    }

    fn write_guard(allow_write: bool) -> Result<(), McpError> {
        if allow_write {
            Ok(())
        } else {
            Err(McpError::invalid_params(
                "mutating tools require allow_write=true",
                None,
            ))
        }
    }

    fn map_app_error(err: AppError) -> McpError {
        match err {
            AppError::InvalidInput(message) => McpError::invalid_params(message, None),
            AppError::NoOpenVault => McpError::invalid_request("no vault is open", None),
            AppError::PathNotFound(message) | AppError::VaultNotFound(message) => {
                McpError::resource_not_found("not_found", Some(json!({ "message": message })))
            }
            other => McpError::internal_error(other.to_string(), None),
        }
    }

    fn truncate_bytes(bytes: &[u8], requested: Option<usize>, ceiling: usize) -> ReadBuffer {
        let limit = requested.unwrap_or(ceiling).min(ceiling).max(1);
        let returned = bytes.len().min(limit);
        let slice = &bytes[..returned];
        let truncated = bytes.len() > returned;

        match String::from_utf8(slice.to_vec()) {
            Ok(text) => ReadBuffer {
                encoding: "utf-8".to_string(),
                content: text,
                size: bytes.len(),
                returned_bytes: returned,
                truncated,
            },
            Err(_) => ReadBuffer {
                encoding: "base64".to_string(),
                content: BASE64.encode(slice),
                size: bytes.len(),
                returned_bytes: returned,
                truncated,
            },
        }
    }

    async fn vault_tree(&self) -> Result<VaultTreeNode, AppError> {
        self.walk_tree("/").await
    }

    fn walk_tree<'a>(
        &'a self,
        path: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<VaultTreeNode, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let metadata = self.app.metadata(path).await?;
            let mut node = VaultTreeNode::from_metadata(metadata);
            if node.is_directory {
                let entries = self.app.list_directory(path).await?;
                let mut children = Vec::with_capacity(entries.len());
                for entry in entries {
                    children.push(Box::new(self.walk_tree(&entry.path).await?));
                }
                node.children = Some(children);
            }
            Ok(node)
        })
    }

    fn resource_text<T: Serialize>(uri: &str, value: &T) -> Result<ResourceContents, McpError> {
        let json = serde_json::to_vec_pretty(value)
            .map_err(|err| McpError::internal_error(err.to_string(), None))?;
        let truncated = Self::truncate_bytes(&json, Some(MAX_RESOURCE_BYTES), MAX_RESOURCE_BYTES);
        let payload = if truncated.truncated {
            json!({
                "content": truncated.content,
                "encoding": truncated.encoding,
                "size": truncated.size,
                "returned_bytes": truncated.returned_bytes,
                "truncated": true,
            })
            .to_string()
        } else {
            truncated.content
        };
        Ok(ResourceContents::text(payload, uri.to_string()))
    }
}

impl Default for AxiomMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct CreateVaultArgs {
    pub vault_id: String,
    pub password: String,
    pub provider_type: String,
    #[serde(default)]
    pub provider_config: serde_json::Value,
    #[serde(default)]
    pub allow_write: bool,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct OpenVaultArgs {
    pub password: String,
    pub provider_type: String,
    #[serde(default)]
    pub provider_config: serde_json::Value,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct RecoverVaultArgs {
    pub recovery_words: String,
    pub new_password: String,
    pub provider_type: String,
    #[serde(default)]
    pub provider_config: serde_json::Value,
    #[serde(default)]
    pub allow_write: bool,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct CloseVaultArgs {
    #[serde(default)]
    pub allow_write: bool,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct VaultPathArgs {
    pub path: String,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct ReadFileArgs {
    pub path: String,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct WriteFileArgs {
    pub path: String,
    pub content: String,
    #[serde(default = "default_encoding")]
    pub encoding: String,
    #[serde(default)]
    pub allow_write: bool,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct DeletePathArgs {
    pub path: String,
    #[serde(default)]
    pub allow_write: bool,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct ImportFileArgs {
    pub local_path: String,
    pub vault_path: String,
    #[serde(default)]
    pub allow_write: bool,
}

#[derive(Clone, Deserialize, JsonSchema)]
pub struct ExportFileArgs {
    pub vault_path: String,
    pub local_path: String,
    #[serde(default)]
    pub allow_write: bool,
}

#[derive(Clone, Serialize)]
pub struct ReadBuffer {
    pub encoding: String,
    pub content: String,
    pub size: usize,
    pub returned_bytes: usize,
    pub truncated: bool,
}

#[derive(Clone, Serialize)]
pub struct StatusResponse {
    pub server: &'static str,
    pub max_read_bytes: usize,
    pub write_protection_default: bool,
    pub vault_open: bool,
}

#[derive(Clone, Serialize)]
pub struct VaultTreeNode {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<Box<VaultTreeNode>>>,
}

impl VaultTreeNode {
    fn from_metadata(metadata: FileMetadataDto) -> Self {
        Self {
            name: metadata.name,
            path: metadata.path,
            is_directory: metadata.is_directory,
            size: metadata.size,
            children: None,
        }
    }
}

fn default_encoding() -> String {
    "utf-8".to_string()
}

#[derive(Clone)]
struct CreateVaultSecretDto {
    vault_id: String,
    password: Zeroizing<String>,
    provider_type: String,
    provider_config: serde_json::Value,
    allow_write: bool,
}

impl From<CreateVaultArgs> for CreateVaultSecretDto {
    fn from(value: CreateVaultArgs) -> Self {
        Self {
            vault_id: value.vault_id,
            password: Zeroizing::new(value.password),
            provider_type: value.provider_type,
            provider_config: value.provider_config,
            allow_write: value.allow_write,
        }
    }
}

impl std::fmt::Debug for CreateVaultSecretDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateVaultSecretDto")
            .field("vault_id", &self.vault_id)
            .field("password", &"[REDACTED]")
            .field("provider_type", &self.provider_type)
            .field("provider_config", &"[REDACTED]")
            .field("allow_write", &self.allow_write)
            .finish()
    }
}

#[derive(Clone)]
struct RecoverVaultSecretDto {
    recovery_words: Zeroizing<String>,
    new_password: Zeroizing<String>,
    provider_type: String,
    provider_config: serde_json::Value,
    allow_write: bool,
}

impl From<RecoverVaultArgs> for RecoverVaultSecretDto {
    fn from(value: RecoverVaultArgs) -> Self {
        Self {
            recovery_words: Zeroizing::new(value.recovery_words),
            new_password: Zeroizing::new(value.new_password),
            provider_type: value.provider_type,
            provider_config: value.provider_config,
            allow_write: value.allow_write,
        }
    }
}

impl std::fmt::Debug for RecoverVaultSecretDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoverVaultSecretDto")
            .field("recovery_words", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .field("provider_type", &self.provider_type)
            .field("provider_config", &"[REDACTED]")
            .field("allow_write", &self.allow_write)
            .finish()
    }
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
    #[tool(description = "Create a vault and return recovery words once")]
    async fn create_vault(
        &self,
        Parameters(args): Parameters<CreateVaultArgs>,
    ) -> Result<CallToolResult, McpError> {
        let dto = CreateVaultSecretDto::from(args);
        Self::write_guard(dto.allow_write)?;
        let created: VaultCreatedDto = self
            .app
            .create_vault(CreateVaultParams {
                vault_id: dto.vault_id,
                password: dto.password,
                provider_type: dto.provider_type,
                provider_config: dto.provider_config,
            })
            .await
            .map_err(Self::map_app_error)?;
        ok_json(&json!({
            "info": created.info,
            "recovery_words": created.recovery_words.to_string(),
            "secret_note": "show once and store securely",
        }))
    }

    #[tool(description = "Open an existing vault")]
    async fn open_vault(
        &self,
        Parameters(args): Parameters<OpenVaultArgs>,
    ) -> Result<CallToolResult, McpError> {
        let info = self
            .app
            .open_vault(OpenVaultParams {
                password: Zeroizing::new(args.password),
                provider_type: args.provider_type,
                provider_config: args.provider_config,
            })
            .await
            .map_err(Self::map_app_error)?;
        ok_json(&info)
    }

    #[tool(description = "Recover a vault using recovery words and set a new password")]
    async fn recover_vault(
        &self,
        Parameters(args): Parameters<RecoverVaultArgs>,
    ) -> Result<CallToolResult, McpError> {
        let dto = RecoverVaultSecretDto::from(args);
        Self::write_guard(dto.allow_write)?;
        let info = self
            .app
            .recover_vault(RecoverVaultParams {
                recovery_words: dto.recovery_words,
                new_password: dto.new_password,
                provider_type: dto.provider_type,
                provider_config: dto.provider_config,
            })
            .await
            .map_err(Self::map_app_error)?;
        ok_json(&info)
    }

    #[tool(description = "Close the active vault")]
    async fn close_vault(
        &self,
        Parameters(args): Parameters<CloseVaultArgs>,
    ) -> Result<CallToolResult, McpError> {
        Self::write_guard(args.allow_write)?;
        self.app.close_vault().await.map_err(Self::map_app_error)?;
        ok_json(&json!({ "closed": true }))
    }

    #[tool(description = "Get active vault info")]
    async fn vault_info(&self) -> Result<CallToolResult, McpError> {
        let info: VaultInfoDto = self.app.vault_info().await.map_err(Self::map_app_error)?;
        ok_json(&info)
    }

    #[tool(description = "List a vault directory")]
    async fn list_directory(
        &self,
        Parameters(args): Parameters<VaultPathArgs>,
    ) -> Result<CallToolResult, McpError> {
        let entries: Vec<DirectoryEntryDto> = self
            .app
            .list_directory(&args.path)
            .await
            .map_err(Self::map_app_error)?;
        ok_json(&entries)
    }

    #[tool(description = "Read a file with size limits and truncation metadata")]
    async fn read_file(
        &self,
        Parameters(args): Parameters<ReadFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let bytes = self
            .app
            .read_file(&args.path)
            .await
            .map_err(Self::map_app_error)?;
        let buffer = Self::truncate_bytes(&bytes, args.max_bytes, MAX_READ_BYTES);
        ok_json(&buffer)
    }

    #[tool(description = "Create a new file inside the vault")]
    async fn write_file(
        &self,
        Parameters(args): Parameters<WriteFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        Self::write_guard(args.allow_write)?;
        let bytes = decode_content(&args)?;
        self.app
            .create_file(&args.path, &bytes)
            .await
            .map_err(Self::map_app_error)?;
        ok_json(&json!({ "written": true, "path": args.path, "bytes": bytes.len() }))
    }

    #[tool(description = "Update an existing file inside the vault")]
    async fn update_file(
        &self,
        Parameters(args): Parameters<WriteFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        Self::write_guard(args.allow_write)?;
        let bytes = decode_content(&args)?;
        self.app
            .update_file(&args.path, &bytes)
            .await
            .map_err(Self::map_app_error)?;
        ok_json(&json!({ "updated": true, "path": args.path, "bytes": bytes.len() }))
    }

    #[tool(description = "Delete a file or directory from the vault")]
    async fn delete_path(
        &self,
        Parameters(args): Parameters<DeletePathArgs>,
    ) -> Result<CallToolResult, McpError> {
        Self::write_guard(args.allow_write)?;
        let metadata = self
            .app
            .metadata(&args.path)
            .await
            .map_err(Self::map_app_error)?;
        if metadata.is_directory {
            self.app
                .delete_directory(&args.path)
                .await
                .map_err(Self::map_app_error)?;
        } else {
            self.app
                .delete_file(&args.path)
                .await
                .map_err(Self::map_app_error)?;
        }
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
        Self::write_guard(args.allow_write)?;
        self.app
            .create_directory(&args.path)
            .await
            .map_err(Self::map_app_error)?;
        ok_json(&json!({ "created": true, "path": args.path }))
    }

    #[tool(description = "Get file or directory metadata")]
    async fn metadata(
        &self,
        Parameters(args): Parameters<VaultPathArgs>,
    ) -> Result<CallToolResult, McpError> {
        let metadata = self
            .app
            .metadata(&args.path)
            .await
            .map_err(Self::map_app_error)?;
        ok_json(&metadata)
    }

    #[tool(description = "Check whether a vault path exists")]
    async fn exists(
        &self,
        Parameters(args): Parameters<VaultPathArgs>,
    ) -> Result<CallToolResult, McpError> {
        let exists = self
            .app
            .exists(&args.path)
            .await
            .map_err(Self::map_app_error)?;
        ok_json(&json!({ "path": args.path, "exists": exists }))
    }

    #[tool(description = "Import a local file into the vault")]
    async fn import_file(
        &self,
        Parameters(args): Parameters<ImportFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        Self::write_guard(args.allow_write)?;
        self.app
            .import_file(&args.local_path, &args.vault_path)
            .await
            .map_err(Self::map_app_error)?;
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
        Self::write_guard(args.allow_write)?;
        self.app
            .export_file(&args.vault_path, &args.local_path)
            .await
            .map_err(Self::map_app_error)?;
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
            "1. Open the vault with open_vault. 2. Inspect vault_info. 3. Use exists, metadata, list_directory, and read_file before any mutation. 4. Respect truncation flags and request smaller reads when needed.",
        )]
    }

    #[prompt(
        name = "safe_write_workflow",
        description = "Checklist for guarded write operations"
    )]
    async fn safe_write_workflow(&self) -> Vec<PromptMessage> {
        vec![PromptMessage::new_text(
            PromptMessageRole::Assistant,
            "1. Verify target paths with exists/metadata. 2. Require explicit user approval. 3. Pass allow_write=true only for the specific mutating call. 4. Re-read metadata after write/update/delete/mkdir/import/export.",
        )]
    }

    #[prompt(
        name = "vault_recovery_workflow",
        description = "Checklist for safe vault recovery handling"
    )]
    async fn vault_recovery_workflow(&self) -> Vec<PromptMessage> {
        vec![PromptMessage::new_text(
            PromptMessageRole::Assistant,
            "1. Confirm recovery intent. 2. Use recover_vault with allow_write=true. 3. Never log recovery words or passwords. 4. Rotate to a fresh password and validate vault_info after recovery.",
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
            "AxiomVault MCP server. Secrets are redacted in debug output. Mutating tools require allow_write=true. Read responses may be truncated.",
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
            SERVER_STATUS_URI => Self::resource_text(
                SERVER_STATUS_URI,
                &StatusResponse {
                    server: "axiomvault-mcp",
                    max_read_bytes: MAX_READ_BYTES,
                    write_protection_default: true,
                    vault_open: self.app.is_vault_open().await,
                },
            )?,
            VAULT_STATUS_URI => {
                let payload = match self.app.vault_info().await {
                    Ok(info) => serde_json::to_value(info)
                        .map_err(|err| McpError::internal_error(err.to_string(), None))?,
                    Err(AppError::NoOpenVault) => json!({ "open": false }),
                    Err(err) => return Err(Self::map_app_error(err)),
                };
                Self::resource_text(VAULT_STATUS_URI, &payload)?
            }
            VAULT_TREE_URI => {
                let tree = self.vault_tree().await.map_err(Self::map_app_error)?;
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

    #[test]
    fn write_guard_blocks_without_explicit_approval() {
        let err = AxiomMcpServer::write_guard(false).unwrap_err();
        assert!(err.message.contains("allow_write=true"));
    }

    #[test]
    fn truncate_bytes_marks_truncation_and_size() {
        let output = AxiomMcpServer::truncate_bytes(b"hello world", Some(5), MAX_READ_BYTES);
        assert_eq!(output.content, "hello");
        assert_eq!(output.returned_bytes, 5);
        assert_eq!(output.size, 11);
        assert!(output.truncated);
    }

    #[test]
    fn truncate_bytes_uses_base64_for_binary_content() {
        let output = AxiomMcpServer::truncate_bytes(&[0, 159, 146, 150], None, MAX_READ_BYTES);
        assert_eq!(output.encoding, "base64");
        assert!(!output.content.is_empty());
    }

    #[test]
    fn decode_content_rejects_unknown_encoding() {
        let err = decode_content(&WriteFileArgs {
            path: "/note.txt".into(),
            content: "abc".into(),
            encoding: "hex".into(),
            allow_write: true,
        })
        .unwrap_err();
        assert!(err.message.contains("unsupported encoding"));
    }

    #[test]
    fn secret_debug_redacts_values() {
        let create = CreateVaultSecretDto::from(CreateVaultArgs {
            vault_id: "vault-1".into(),
            password: "top-secret".into(),
            provider_type: "local".into(),
            provider_config: json!({ "token": "secret-token" }),
            allow_write: true,
        });
        let create_debug = format!("{:?}", create);
        assert!(!create_debug.contains("top-secret"));
        assert!(!create_debug.contains("secret-token"));
        assert!(create_debug.contains("[REDACTED]"));

        let recover = RecoverVaultSecretDto::from(RecoverVaultArgs {
            recovery_words: "abandon ability able".into(),
            new_password: "another-secret".into(),
            provider_type: "local".into(),
            provider_config: json!({ "refresh_token": "hidden" }),
            allow_write: true,
        });
        let recover_debug = format!("{:?}", recover);
        assert!(!recover_debug.contains("abandon ability able"));
        assert!(!recover_debug.contains("another-secret"));
        assert!(!recover_debug.contains("hidden"));
    }
}
