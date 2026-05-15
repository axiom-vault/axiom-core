# axiom-core

<p align="center">
  Core Rust library for AxiomVault — cross-platform encrypted vault with client-side encryption.
</p>

<p align="center">
  <a href="https://github.com/axiom-vault/axiom-core/actions/workflows/rust.yml"><img src="https://github.com/axiom-vault/axiom-core/actions/workflows/rust.yml/badge.svg" alt="Rust CI"></a>
  <a href="https://github.com/axiom-vault/axiom-core/releases/latest"><img src="https://img.shields.io/github/v/release/axiom-vault/axiom-core?include_prereleases" alt="Latest Release"></a>
  <a href="https://github.com/axiom-vault/axiom-core/blob/main/LICENSE"><img src="https://img.shields.io/github/license/axiom-vault/axiom-core" alt="License"></a>
</p>

---

> [!WARNING]
> This project is in **early development** and is **not production ready**. APIs may change, features may be incomplete. Do not use for storing sensitive data in production.

## Overview

`axiom-core` is the shared Rust library powering all AxiomVault clients. It handles encryption, vault management, cloud storage, sync, and the C-ABI FFI layer for mobile platforms.

**Consumers:** [axiom-cli](https://github.com/axiom-vault/axiom-cli), Linux desktop client, macOS/iOS (SwiftUI), Android (Compose)

## Crates

| Crate | Description |
|-------|-------------|
| `core/crypto` | XChaCha20-Poly1305, Argon2id, Blake2b key derivation, streaming encryption |
| `core/vault` | Vault engine, config, tree index, session management |
| `core/storage` | Storage provider trait + Google Drive, local, Dropbox, OneDrive, iCloud |
| `core/sync` | Sync engine, conflict resolution, retry with exponential backoff |
| `core/app` | Application service layer, DTOs, local index |
| `core/ffi` | C-ABI bindings for mobile (cbindgen) |
| `core/fuse` | FUSE virtual filesystem |
| `core/webdav` | WebDAV server |
| `core/common` | Shared types and error handling |

## Features

### Encryption

| Property | Details |
|----------|---------|
| Content encryption | XChaCha20-Poly1305 (AEAD) with 24-byte nonces |
| Key derivation | Argon2id (memory-hard, GPU-resistant) |
| Filename encryption | Deterministic XChaCha20-Poly1305 |
| Directory structure | Fully encrypted tree index |
| Streaming | Chunked encryption (64 KiB) with per-chunk authentication |
| Key hierarchy | Blake2b-derived file keys, directory keys, and index keys |
| Memory safety | Automatic zeroization, constant-time comparisons, no plaintext logging |

### Cloud Storage

- **Google Drive** — full OAuth2 integration with resumable uploads
- **Local filesystem** — for offline or self-hosted storage
- iCloud, Dropbox, OneDrive — planned

### Sync Engine

- On-demand or periodic background sync
- Conflict detection via ETags with configurable resolution (keep both, prefer local, prefer remote, manual)
- Exponential backoff retry

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) stable toolchain

**Linux (for the FUSE crate):**
```bash
sudo apt-get install -y libfuse3-dev
```

### Build

```bash
git clone https://github.com/axiom-vault/axiom-core.git
cd axiom-core
cargo build --workspace
```

### Test

```bash
cargo test --workspace
```

### MCP Server

```bash
cargo run -p axiomvault-mcp
```

### Lint

```bash
cargo fmt --all                          # Format
cargo clippy --workspace -- -D warnings  # Lint
```

## Vault Format

```
vault-root/
├── vault.config          # Encrypted metadata (salt, KDF params, version)
├── d/                    # Encrypted file content
└── m/
    └── tree.json         # Encrypted directory tree index
```

## Security Design

- **Client-side only** — data is encrypted before leaving your device
- **Zero-knowledge** — no server, no accounts, no key escrow
- **Authenticated encryption** — AEAD on every chunk prevents tampering
- **Chunk ordering protection** — chunk index is authenticated to prevent reordering
- **Memory safety** — `Zeroize` + `ZeroizeOnDrop` on all key types, `subtle` for constant-time ops
- **No plaintext in logs** — keys and sensitive data are redacted in `Display` impls

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push and open a pull request

All PRs must pass CI checks (formatting, clippy, tests) before merging.

## Related Repositories

- [axiom-cli](https://github.com/axiom-vault/axiom-cli) — Command-line interface

## License

[Apache 2.0](LICENSE)