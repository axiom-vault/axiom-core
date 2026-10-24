# axiomvault-agent

Key custody for AxiomVault in the ssh-agent model. `axiom-agent serve` holds
the unlocked vault and answers requests on a Unix socket. Clients such as
`axiom-mcp` never see the password or the master key. Unix only.

## Threat model

- **The LLM never sees a secret.** No MCP tool takes or returns a password or
  recovery words. The password reaches the daemon only through
  `axiom-agent unlock`, which reads it from the controlling terminal
  (`/dev/tty`): never from arguments, environment variables, stdin or files.
- **The key is not in the MCP process.** An MCP server started by an agent is
  that agent's child and, with `kernel.yama.ptrace_scope=1`, can be traced by
  it. The key lives in the daemon instead, which marks itself non-dumpable
  (`PR_SET_DUMPABLE=0`), so its memory, environment and ptrace are closed to
  other processes of the same uid.
- **The daemon is the policy boundary.** Writes, file I/O, the vault subtree
  and idle locking are launch flags enforced in the daemon, because any
  allowed process can talk to the socket directly.
- **Same uid is not a security boundary.** A process running as your uid can
  send requests within the daemon's policy, lock the vault, or start a more
  permissive daemon on the socket path and wait for you to unlock it. `unlock`
  prints the daemon's pid, uid and policy before prompting so you can spot
  that. To make it a real boundary, run the daemon as a separate user (below).

## Usage

```bash
axiom-agent serve [--socket <path>] [--socket-mode 600|660] [--allow-writes]
                  [--allow-file-io=<dir>] [--root <vault path>]
                  [--idle-lock <secs>] [--allow-uid <uid>]...
axiom-agent unlock --path <local vault dir> [--socket <path>] [--expect-uid <uid>]
axiom-agent lock   [--socket <path>]
axiom-agent status [--socket <path>]
```

| Flag | Default | Meaning |
|---|---|---|
| `--socket` | `$XDG_RUNTIME_DIR/axiom-agent.sock` | Socket path. The parent is created 0700 if missing. A live socket is an error; a stale one is replaced. |
| `--socket-mode` | `600` | `660` shares the socket with its group. |
| `--allow-writes` | off | Create, update, delete, mkdir, import. |
| `--allow-file-io=<dir>` | off | Import/export, confined to `<dir>`: no `..`, no symlinked sources, no overwrites. |
| `--root` | `/` | Serve only this vault subtree. Paths must be absolute without `.`, `..` or empty segments. |
| `--idle-lock` | `900` | Lock after this many seconds without requests. `0` disables. |
| `--allow-uid` | daemon's uid | Peer uids allowed to connect (checked with `SO_PEERCRED` before reading). Repeatable. |

Other behaviour:

- Locking drops the vault session, and with it the master key.
- An unlock is refused while a vault is already unlocked, so a client cannot
  swap the vault others are using.
- Each failed unlock delays its response: 1s, doubling to 60s, reset on
  success. Attempts are serialised across connections.
- Memory is locked with `mlockall` only when `RLIMIT_MEMLOCK` is unlimited
  (e.g. `LimitMEMLOCK=infinity`); otherwise the daemon warns and runs
  unlocked, because a finite limit would make large allocations abort it.
- An audit line per request goes to stderr: operation, vault path, peer
  pid/uid, outcome. Contents, passwords and provider configuration are never
  logged.

The protocol is newline-delimited JSON, one response per request, at most
32 MiB per line (see `src/protocol.rs`).

## Separate-user deployment

1. Create a user, e.g. `axiomvault`, that owns the vault directory
   (`chmod 700`), and a group shared with you, e.g. `axiomvault-clients`.
2. Run the daemon as that user, socket in a directory you can reach:

   ```bash
   sudo -u axiomvault axiom-agent serve \
     --socket /run/axiom-agent/agent.sock --socket-mode 660 \
     --allow-uid "$(id -u you)"
   ```

   `/run/axiom-agent` should be owned by `axiomvault:axiomvault-clients`,
   mode `0750`. Under systemd, set `User=`, `RuntimeDirectory=` and
   `LimitMEMLOCK=infinity`.
3. Unlock from your own terminal, pinning the daemon's uid:

   ```bash
   axiom-agent unlock --socket /run/axiom-agent/agent.sock \
     --path /srv/axiomvault/main --expect-uid "$(id -u axiomvault)"
   ```

4. Point `axiom-mcp --socket /run/axiom-agent/agent.sock` at it.

Your uid can still use the vault within the daemon's policy, but can no
longer read the daemon's memory or replace it with a daemon of its own.
`--allow-file-io` paths are opened by the daemon's user, and the vault's
freshness anchor is kept in that user's data directory
(`~/.local/share/axiomvault/freshness`), so it needs a home directory.
