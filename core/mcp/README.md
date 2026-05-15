# axiomvault-mcp

MCP server for AxiomVault built on the official `rmcp` Rust SDK over stdio.

## Features

- Vault lifecycle tools: `create_vault`, `open_vault`, `recover_vault`, `close_vault`, `vault_info`
- File and directory tools: `list_directory`, `read_file`, `write_file`, `update_file`, `delete_path`, `mkdir`, `metadata`, `exists`, `import_file`, `export_file`
- Resources: `axiom://server/status`, `axiom://vault/status`, `axiom://vault/tree`
- Static prompts for safe read-only, write, and recovery workflows
- Write protection for mutating tools via explicit `allow_write: true`
- Redacted secret DTOs using `Zeroizing`
- Read-size caps and truncation metadata

## Run

```bash
cargo run -p axiomvault-mcp
```

## Inspector

```bash
npx @modelcontextprotocol/inspector cargo run -p axiomvault-mcp
```

## Notes

- Logging is sent to stderr only.
- Mutating/destructive tools are blocked unless `allow_write` is set to `true`.
- Vault paths are validated through `AppService` operations.
