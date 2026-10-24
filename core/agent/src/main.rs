#[cfg(unix)]
mod cli;

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    cli::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("axiom-agent is only supported on Unix");
    std::process::exit(1);
}
