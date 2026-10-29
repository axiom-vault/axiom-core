use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use axiomvault_agent::default_socket_path;
use axiomvault_mcp::AxiomMcpServer;
use rmcp::{transport::stdio, ServiceExt};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: axiom-mcp [--socket <path>]

  --socket <path>  axiom-agent socket to use
                   (default $XDG_RUNTIME_DIR/axiom-agent.sock)

What the tools may do (writes, file I/O, the visible vault subtree) is set
by the flags `axiom-agent serve` was launched with, not here.";

/// Hand-parsed launch flags. Unknown arguments are an error, so a typo never
/// silently starts a server with different settings than intended.
fn parse_args(args: impl IntoIterator<Item = String>) -> Result<PathBuf> {
    let mut socket: Option<PathBuf> = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let path = match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "--socket" => args.next().context("--socket needs a path")?,
            other => match other.strip_prefix("--socket=") {
                Some(path) => path.to_string(),
                None => bail!("unknown argument: {other}\n{USAGE}"),
            },
        };
        if path.is_empty() || socket.replace(PathBuf::from(path)).is_some() {
            bail!("--socket needs exactly one non-empty path");
        }
    }
    match socket {
        Some(socket) => Ok(socket),
        None => default_socket_path().context("no agent socket"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let socket = parse_args(std::env::args().skip(1))?;
    let service = AxiomMcpServer::new(socket).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
