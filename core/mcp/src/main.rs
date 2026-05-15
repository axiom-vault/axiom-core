use anyhow::Result;
use axiomvault_mcp::AxiomMcpServer;
use rmcp::{transport::stdio, ServiceExt};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let service = AxiomMcpServer::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
