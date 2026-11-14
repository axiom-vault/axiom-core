# axiom-core

## Agent notes

- Never open, unlock, list or read real vaults, credentials, passwords or contents;
  use synthetic fixtures only, because vault secrets must not enter agent context.
  Deliver real-vault password/unlock commands for private human execution; never run them.
- Run checks from the workspace root; these are the README/CI commands and warning gate:
  ```sh
  cargo build --workspace
  cargo test --workspace
  cargo fmt --all -- --check
  cargo clippy --workspace -- -D warnings
  RUSTFLAGS='-D warnings' cargo check --workspace
  ```
- FUSE coverage needs `cargo test -p axiomvault-fuse --features fuse --test file_io`;
  default features omit it, and missing `/dev/fuse` makes these tests return early.
  Keep FUSE out of iOS dependencies: `core/fuse` is Linux/macOS-only.
- Keep agent/MCP fixture socket paths short: their sockets live beneath temporary
  directories, so a long temporary root can exceed Unix-domain socket path limits.
- Route frontend operations through `core/app::AppService` and backends through
  `core/storage::StorageProvider`/its registry; avoid duplicating lifecycle/crypto policy.
- Preserve hand-written redacted `Debug` for secret-bearing DTOs: deriving `Debug`
  on `Zeroizing<String>` still prints its contents (`core/app/src/dto.rs`).
- Persist cloud folder identity and `credential_ref`, never OAuth tokens/auth config;
  config serialization rejects embedded credentials (`core/vault/src/config.rs`).
- For manifest-backed sessions, publish snapshots through the vault/session APIs:
  `m/generation.manifest` binds generation objects; `vault.config` and `m/tree.json`
  are compatibility caches, not independent commit points (`core/vault/src/session.rs`).
- Keep upload-new-blob, snapshot-publication, then obsolete-blob cleanup ordering;
  replacing old content first can destroy the recoverable snapshot (`core/vault/src/operations.rs`).
- Use bounded metadata reads in `core/vault/src/config.rs` for untrusted config/tree/
  manifest objects; unrestricted provider downloads can exceed metadata limits.
- Opening a 1.1 vault is refused; use the explicit `VaultManager::upgrade_to_current`
  path rather than silently upgrading during ordinary open (`core/vault/src/manager.rs`).
- Drop shared session references/unmount FUSE before locking or changing passwords;
  `AppService` needs exclusive `Arc` access for those operations (`core/app/src/service.rs`).
- Edit FFI Rust declarations/cbindgen config, not generated headers: `core/ffi/build.rs`
  writes `<target-dir>/include/axiom_ffi.h`. Free recovery-word buffers with
  `axiom_recovery_words_free`, not `axiom_string_free`, so their bytes are wiped.
