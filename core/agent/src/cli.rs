//! Command-line front end of the `axiom-agent` binary.

use std::{path::PathBuf, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use axiomvault_agent::{
    bind_socket, default_socket_path, hardening,
    protocol::{AgentStatus, UnlockParams},
    serve, AgentClient, DaemonConfig, Payload, Request, ServerPolicy, VaultRoot,
};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

const USAGE: &str = "usage:
  axiom-agent serve  [--socket <path>] [--socket-mode <octal>] [--allow-writes]
                     [--allow-file-io=<dir>] [--root <vault path>]
                     [--idle-lock <secs>] [--allow-uid <uid>]...
  axiom-agent unlock --path <local vault dir> [--socket <path>] [--expect-uid <uid>]
  axiom-agent lock   [--socket <path>]
  axiom-agent status [--socket <path>]

  --socket <path>        agent socket (default $XDG_RUNTIME_DIR/axiom-agent.sock)
  --socket-mode <octal>  socket permissions: 600 (default), or 660 to share it
                         with the socket's group
  --allow-writes         enable mutating requests. Off by default.
  --allow-file-io=<dir>  enable import/export, confined to <dir>. Off by default.
  --root <vault path>    serve only this vault subtree (default /)
  --idle-lock <secs>     lock after this long without requests; 0 disables
                         (default 900)
  --allow-uid <uid>      uid allowed to connect; repeatable (default: the
                         daemon's own uid)
  --path <dir>           local vault directory to unlock
  --expect-uid <uid>     refuse to send the password unless the daemon runs
                         as <uid>

unlock reads the password from the controlling terminal and nowhere else.";

const DEFAULT_IDLE_LOCK_SECS: u64 = 900;

pub fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => run_serve(parse_serve(args)?),
        Some("unlock") => run_client(parse_unlock(args)?),
        Some("lock") => run_client(Command::Lock(parse_socket_only(args)?)),
        Some("status") => run_client(Command::Status(parse_socket_only(args)?)),
        Some("-h" | "--help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => bail!("unknown command: {other}\n{USAGE}"),
        None => bail!("missing command\n{USAGE}"),
    }
}

/// Returns the value of `--name <v>` or `--name=<v>`, or `None` if `arg` is
/// a different flag. Empty values are an error.
fn flag_value(
    arg: &str,
    name: &str,
    rest: &mut impl Iterator<Item = String>,
) -> Result<Option<String>> {
    let value = if arg == name {
        rest.next()
            .with_context(|| format!("{name} needs a value"))?
    } else {
        match arg
            .strip_prefix(name)
            .and_then(|tail| tail.strip_prefix('='))
        {
            Some(value) => value.to_string(),
            None => return Ok(None),
        }
    };
    if value.is_empty() {
        bail!("{name} needs a non-empty value");
    }
    Ok(Some(value))
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        bail!("{name} given more than once");
    }
    Ok(())
}

fn help_or_unknown(arg: &str) -> anyhow::Error {
    if matches!(arg, "-h" | "--help") {
        println!("{USAGE}");
        std::process::exit(0);
    }
    anyhow!("unknown argument: {arg}\n{USAGE}")
}

fn socket_or_default(socket: Option<String>) -> Result<PathBuf> {
    match socket {
        Some(path) => Ok(PathBuf::from(path)),
        None => default_socket_path().context("no socket path"),
    }
}

struct ServeOptions {
    socket: PathBuf,
    socket_mode: u32,
    config: DaemonConfig,
}

/// Hand-parsed launch flags. Unknown arguments are an error, so a typo never
/// silently starts a daemon with different capabilities than intended.
fn parse_serve(args: impl IntoIterator<Item = String>) -> Result<ServeOptions> {
    let mut allow_writes = false;
    let mut socket = None;
    let mut socket_mode = None;
    let mut file_io_dir = None;
    let mut root = None;
    let mut idle_lock = None;
    let mut allowed_uids = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--allow-writes" {
            allow_writes = true;
        } else if let Some(value) = flag_value(&arg, "--socket", &mut args)? {
            set_once(&mut socket, value, "--socket")?;
        } else if let Some(value) = flag_value(&arg, "--socket-mode", &mut args)? {
            let mode = u32::from_str_radix(&value, 8)
                .ok()
                .filter(|mode| matches!(mode, 0o600 | 0o660))
                .context("--socket-mode must be 600 or 660")?;
            set_once(&mut socket_mode, mode, "--socket-mode")?;
        } else if let Some(value) = flag_value(&arg, "--allow-file-io", &mut args)? {
            set_once(&mut file_io_dir, PathBuf::from(value), "--allow-file-io")?;
        } else if let Some(value) = flag_value(&arg, "--root", &mut args)? {
            let parsed = VaultRoot::parse(&value).map_err(|err| anyhow!("--root: {err}"))?;
            set_once(&mut root, parsed, "--root")?;
        } else if let Some(value) = flag_value(&arg, "--idle-lock", &mut args)? {
            let secs: u64 = value
                .parse()
                .context("--idle-lock needs a number of seconds")?;
            set_once(&mut idle_lock, secs, "--idle-lock")?;
        } else if let Some(value) = flag_value(&arg, "--allow-uid", &mut args)? {
            allowed_uids.push(value.parse().context("--allow-uid needs a numeric uid")?);
        } else {
            return Err(help_or_unknown(&arg));
        }
    }
    if allowed_uids.is_empty() {
        // SAFETY: getuid has no preconditions and cannot fail.
        allowed_uids.push(unsafe { libc::getuid() });
    }
    let policy = ServerPolicy::new(
        allow_writes,
        file_io_dir.as_deref(),
        root.unwrap_or_else(VaultRoot::whole_vault),
    )
    .context("invalid --allow-file-io directory")?;
    let idle_lock = match idle_lock.unwrap_or(DEFAULT_IDLE_LOCK_SECS) {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    };
    Ok(ServeOptions {
        socket: socket_or_default(socket)?,
        socket_mode: socket_mode.unwrap_or(0o600),
        config: DaemonConfig {
            policy,
            idle_lock,
            allowed_uids,
        },
    })
}

enum Command {
    Unlock {
        socket: PathBuf,
        vault_dir: PathBuf,
        expect_uid: Option<u32>,
    },
    Lock(PathBuf),
    Status(PathBuf),
}

fn parse_unlock(args: impl IntoIterator<Item = String>) -> Result<Command> {
    let mut socket = None;
    let mut vault_dir = None;
    let mut expect_uid = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if let Some(value) = flag_value(&arg, "--socket", &mut args)? {
            set_once(&mut socket, value, "--socket")?;
        } else if let Some(value) = flag_value(&arg, "--path", &mut args)? {
            set_once(&mut vault_dir, PathBuf::from(value), "--path")?;
        } else if let Some(value) = flag_value(&arg, "--expect-uid", &mut args)? {
            let uid = value.parse().context("--expect-uid needs a numeric uid")?;
            set_once(&mut expect_uid, uid, "--expect-uid")?;
        } else {
            return Err(help_or_unknown(&arg));
        }
    }
    Ok(Command::Unlock {
        socket: socket_or_default(socket)?,
        vault_dir: vault_dir.context("unlock needs --path <local vault dir>")?,
        expect_uid,
    })
}

fn parse_socket_only(args: impl IntoIterator<Item = String>) -> Result<PathBuf> {
    let mut socket = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match flag_value(&arg, "--socket", &mut args)? {
            Some(value) => set_once(&mut socket, value, "--socket")?,
            None => return Err(help_or_unknown(&arg)),
        }
    }
    socket_or_default(socket)
}

fn run_serve(options: ServeOptions) -> Result<()> {
    // Harden before the runtime starts: no secret is in memory yet, and the
    // runtime's threads and allocations are then covered by MCL_FUTURE.
    match hardening::disable_dumping() {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::Unsupported => {
            warn!(%err, "process is dumpable; same-uid processes may read its memory")
        }
        Err(err) => return Err(err).context("prctl(PR_SET_DUMPABLE, 0) failed"),
    }
    if let Err(err) = hardening::lock_memory() {
        warn!(%err, "memory is not locked; key material may be swapped to disk");
    }

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let listener = bind_socket(&options.socket, options.socket_mode)
            .with_context(|| format!("cannot listen on {}", options.socket.display()))?;
        let config = options.config;
        info!(
            socket = %options.socket.display(),
            mode = format_args!("{:o}", options.socket_mode),
            allow_writes = config.policy.allow_writes(),
            file_io_dir = ?config.policy.file_io_dir(),
            root = config.policy.root().as_str(),
            idle_lock_secs = config.idle_lock.map_or(0, |idle| idle.as_secs()),
            allowed_uids = ?config.allowed_uids,
            "axiom-agent listening"
        );
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            () = serve(listener, config) => {}
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
        }
        info!("shutting down");
        let _ = std::fs::remove_file(&options.socket);
        Ok(())
    })
}

fn run_client(command: Command) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        match command {
            Command::Unlock {
                socket,
                vault_dir,
                expect_uid,
            } => unlock(&socket, vault_dir, expect_uid).await,
            Command::Lock(socket) => {
                connect(&socket).await?.request(&Request::Lock).await?;
                println!("locked");
                Ok(())
            }
            Command::Status(socket) => {
                describe(&socket, &mut connect(&socket).await?).await?;
                Ok(())
            }
        }
    })
}

async fn connect(socket: &std::path::Path) -> Result<AgentClient> {
    AgentClient::connect(socket).await.with_context(|| {
        format!(
            "cannot reach axiom-agent at {}; is `axiom-agent serve` running?",
            socket.display()
        )
    })
}

/// Prints who is listening on the socket and with what policy, so the user
/// can spot a daemon they did not start before typing a password into it.
async fn describe(socket: &std::path::Path, client: &mut AgentClient) -> Result<AgentStatus> {
    let peer = client.peer();
    let Payload::Status(status) = client.request(&Request::Status).await? else {
        bail!("unexpected status response from the agent");
    };
    let pid = peer
        .pid()
        .map_or_else(|| "unknown".to_string(), |pid| pid.to_string());
    println!("agent at {}", socket.display());
    println!("  pid:       {pid}");
    println!("  uid:       {}", peer.uid());
    println!(
        "  writes:    {}",
        if status.allow_writes { "on" } else { "off" }
    );
    println!(
        "  file I/O:  {}",
        status
            .file_io_dir
            .as_ref()
            .map_or_else(|| "off".to_string(), |dir| dir.display().to_string())
    );
    println!("  root:      {}", status.root);
    println!(
        "  idle lock: {}",
        match status.idle_lock_secs {
            0 => "off".to_string(),
            secs => format!("{secs}s"),
        }
    );
    println!(
        "  state:     {}",
        if status.unlocked {
            "unlocked"
        } else {
            "locked"
        }
    );
    Ok(status)
}

async fn unlock(
    socket: &std::path::Path,
    vault_dir: PathBuf,
    expect_uid: Option<u32>,
) -> Result<()> {
    // Best effort: this process holds the password only briefly.
    if let Err(err) = hardening::disable_dumping() {
        warn!(%err, "process is dumpable");
    }
    // Same resolution as the FFI layer, so the provider config (and the
    // freshness anchor derived from it) matches the one used at creation.
    // Not checked here: a daemon running as another user may be the only
    // one that can see the directory.
    let vault_dir = if vault_dir.is_absolute() {
        vault_dir
    } else {
        std::env::current_dir()?.join(vault_dir)
    };

    let mut client = connect(socket).await?;
    let status = describe(socket, &mut client).await?;
    if let Some(expected) = expect_uid {
        let actual = client.peer().uid();
        if actual != expected {
            bail!("the agent runs as uid {actual}, not {expected}; refusing to send the password");
        }
    }
    if status.unlocked {
        bail!("the agent already has a vault unlocked; run `axiom-agent lock` first");
    }

    let password = rpassword::prompt_password("Vault password: ")
        .map(Zeroizing::new)
        .map_err(|err| {
            anyhow!(
                "cannot read the password from the controlling terminal ({err}); \
                 run `axiom-agent unlock` in an interactive terminal"
            )
        })?;
    let request = Request::Unlock(UnlockParams {
        provider_type: "local".to_string(),
        provider_config: serde_json::json!({ "root": vault_dir }),
        password,
    });
    let result = client.request(&request).await;
    drop(request);
    match result? {
        Payload::VaultInfo(info) => println!("unlocked vault {}", info.id),
        _ => println!("unlocked"),
    }
    Ok(())
}
