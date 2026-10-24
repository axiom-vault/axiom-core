# axiomvault-mcp

MCP server for AxiomVault built on the official `rmcp` Rust SDK over stdio.

It is a thin client of [`axiom-agent`](../agent/README.md). The agent holds the
unlocked vault and enforces all policy; this server holds no key, no password
and no crypto code, and has no tool that accepts or returns a secret. The vault
is unlocked only by the user, in their own terminal, with `axiom-agent unlock`.

## Features

- Vault tools: `lock_vault`, `vault_info`
- File and directory tools: `list_directory`, `read_file`, `write_file`, `update_file`, `delete_path`, `mkdir`, `metadata`, `exists`, `import_file`, `export_file`
- Resources: `axiom://server/status`, `axiom://vault/status`, `axiom://vault/tree` (the tree starts at the agent's `--root`)
- Static prompts for safe read-only and write workflows
- Read-size caps and truncation metadata

There is no tool to create, open or recover a vault. When the vault is locked,
tools answer "vault is locked; ask the user to run `axiom-agent unlock` in their
own terminal".

## Run

```bash
axiom-agent serve &                      # see ../agent/README.md for flags
axiom-agent unlock --path ~/vaults/main  # in your own terminal
cargo run -p axiomvault-mcp -- [--socket <path>]
```

`--socket` defaults to `$XDG_RUNTIME_DIR/axiom-agent.sock`. Unknown arguments
are an error.

## Inspector

```bash
npx @modelcontextprotocol/inspector cargo run -p axiomvault-mcp
```

## Notes

- Logging is sent to stderr only.
- Writes (`--allow-writes`), import/export (`--allow-file-io=<dir>`) and the
  visible vault subtree (`--root`) are launch flags of `axiom-agent serve`, not
  of this server. A tool call cannot change them.
