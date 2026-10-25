//! Key custody for AxiomVault, in the ssh-agent model.
//!
//! `axiom-agent serve` holds the unlocked vault; clients such as the MCP
//! server talk to it over a Unix socket and never see a password or a key.
//! The password reaches the daemon only through `axiom-agent unlock`, which
//! reads it from the user's terminal.

#![cfg(unix)]

pub mod client;
#[cfg(feature = "daemon")]
pub mod hardening;
#[cfg(feature = "daemon")]
pub mod policy;
pub mod protocol;
#[cfg(feature = "daemon")]
pub mod server;

use std::path::PathBuf;

pub use client::{AgentClient, ClientError};
#[cfg(feature = "daemon")]
pub use policy::{peer_allowed, ServerPolicy, VaultRoot};
pub use protocol::{
    AgentError, AgentStatus, ErrorKind, Payload, Request, Response, LOCKED_MESSAGE,
};
#[cfg(feature = "daemon")]
pub use server::{bind_socket, serve, DaemonConfig, SocketLock};

/// Socket file name inside `$XDG_RUNTIME_DIR`.
pub const SOCKET_NAME: &str = "axiom-agent.sock";

/// `$XDG_RUNTIME_DIR/axiom-agent.sock`. Errors if the variable is unset or
/// not absolute; pass an explicit socket path then.
pub fn default_socket_path() -> std::io::Result<PathBuf> {
    match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => Ok(dir.join(SOCKET_NAME)),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "XDG_RUNTIME_DIR is not set to an absolute path; pass --socket <path>",
        )),
    }
}
