#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    axiomvault_agent::cli::run("axiom-agent", std::env::args_os().skip(1))
}

#[cfg(not(unix))]
fn main() {
    eprintln!("axiom-agent is only supported on Unix");
    std::process::exit(1);
}
