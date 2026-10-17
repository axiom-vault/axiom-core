use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use axiomvault_mcp::{AxiomMcpServer, ServerPolicy};
use rmcp::{transport::stdio, ServiceExt};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: axiom-mcp [--allow-writes] [--allow-file-io=<dir>]

  --allow-writes         enable mutating tools (create, write, update, delete,
                         mkdir, import, recover). Off by default.
  --allow-file-io=<dir>  enable import_file/export_file, confined to <dir>.
                         Off by default.";

/// Hand-parsed launch flags. Unknown arguments are an error, so a typo never
/// silently starts a server with different capabilities than intended.
fn parse_args(args: impl IntoIterator<Item = String>) -> Result<ServerPolicy> {
    let mut allow_writes = false;
    let mut file_io_dir: Option<PathBuf> = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let dir = match arg.as_str() {
            "--allow-writes" => {
                allow_writes = true;
                continue;
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "--allow-file-io" => args.next().context("--allow-file-io needs a directory")?,
            other => match other.strip_prefix("--allow-file-io=") {
                Some(dir) => dir.to_string(),
                None => bail!("unknown argument: {other}\n{USAGE}"),
            },
        };
        if dir.is_empty() || file_io_dir.replace(PathBuf::from(dir)).is_some() {
            bail!("--allow-file-io needs exactly one non-empty directory");
        }
    }
    ServerPolicy::new(allow_writes, file_io_dir.as_deref())
        .context("invalid --allow-file-io directory")
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let policy = parse_args(std::env::args().skip(1))?;
    let service = AxiomMcpServer::with_policy(policy).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
