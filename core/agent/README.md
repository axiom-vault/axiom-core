# axiomvault-agent

Key custody for AxiomVault in the ssh-agent model. `axiom-agent serve` holds
the unlocked vault and answers requests on a Unix socket. Clients such as
`axiom-mcp` never see the password or the master key. Unix only.

## Threat model

What this guarantees:

- **The password and the key never enter the MCP process or any MCP tool.**
  No tool takes or returns a password or recovery words; the MCP server
  links no vault or crypto code. The password reaches the daemon only
  through `axiom-agent unlock`, which reads it from the controlling terminal
  (`/dev/tty`), never from arguments, environment variables, stdin or files.
- **The daemon is the policy boundary.** The vault, writes, file I/O, the
  vault subtree and the lock timers are launch flags enforced in the daemon,
  because any allowed process can talk to the socket directly. An unlock
  carries only the password, and requests with unknown fields are refused.
- **Running the daemon as a separate user protects the key in memory.** It
  is non-dumpable (`PR_SET_DUMPABLE=0`), so even as your own uid its memory,
  environment and ptrace are closed to other processes, but only a separate
  uid stops your uid from replacing it with a daemon of its own.

What it does not guarantee:

- **Password entry is only as trustworthy as your shell.** `axiom-agent
  unlock` runs as you. An LLM agent with a shell as your uid can shadow it
  in `PATH`, alias it in a shell rc file, inject `LD_PRELOAD`, or start a
  rogue daemon on the socket. To make entry trustworthy, run the LLM itself
  sandboxed or as a different uid, or unlock with
  `sudo -u <daemon-user> /absolute/path/to/axiom-agent unlock` from a terminal
  the LLM cannot touch.
- **The pre-prompt summary is not a check.** Only the pid, uid and
  executable it prints come from the kernel (`SO_PEERCRED`); everything
  marked "reported by the daemon" is whatever the daemon claims. With a
  separate daemon user, `--expect-uid` is the check that holds.
- **Same uid is not a security boundary.** Any process of an allowed uid can
  use or lock the vault within the daemon's policy.

## Usage

```bash
axiom-agent serve --vault <local vault dir> [--socket <path>]
                  [--socket-mode 600|660] [--allow-writes]
                  [--allow-file-io=<dir>] [--root <vault path>]
                  [--idle-lock <secs>] [--max-unlock <secs>]
                  [--allow-uid <uid>]...
axiom-agent unlock [--socket <path>] [--expect-uid <uid>]
axiom-agent lock   [--socket <path>]
axiom-agent status [--socket <path>]
```

| Flag | Default | Meaning |
|---|---|---|
| `--vault` | required | The local vault this daemon serves, canonicalised at startup (must exist). Unlock opens this vault and no other. |
| `--socket` | `$XDG_RUNTIME_DIR/axiom-agent.sock` | Socket path. The parent is created 0700 if missing. A live socket is an error; a stale one is replaced. |
| `--socket-mode` | `600` | `660` shares the socket with its group. |
| `--allow-writes` | off | Create, update, delete, mkdir, import. |
| `--allow-file-io=<dir>` | off | Import/export, confined to `<dir>`: no `..`, no symlinks anywhere in the path, single-link regular files only, no overwrites. On Linux every lookup uses `openat2(RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS)` on a descriptor opened at launch and the vault layer works on the descriptor that was checked, so swapping a symlink in later cannot redirect it; without `openat2` (Linux < 5.6) file I/O is refused. On other Unix systems the checks are path-based and race a concurrent writer to the directory. |
| `--root` | `/` | Serve only this vault subtree. Paths must be absolute without `.`, `..` or empty segments. |
| `--idle-lock` | `900` | Lock after this many seconds without requests; never while a request is running. `0` disables. At most one year. |
| `--max-unlock` | `0` | Lock this many seconds after unlocking, however busy (ssh-agent `-t`). `0` disables. At most one year. |
| `--allow-uid` | daemon's uid | Peer uids allowed to connect (checked with `SO_PEERCRED` before reading). Repeatable. |

Other behaviour:

- Locking drops the vault session, and with it the master key.
- An unlock is refused while the vault is already unlocked, and the
  connection that carried it is closed afterwards.
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
   sudo -u axiomvault axiom-agent serve --vault /srv/axiomvault/main \
     --socket /run/axiom-agent/agent.sock --socket-mode 660 \
     --allow-uid "$(id -u you)"
   ```

   `/run/axiom-agent` should be owned by `axiomvault:axiomvault-clients`,
   mode `0750`. Under systemd, set `User=`, `RuntimeDirectory=` and
   `LimitMEMLOCK=infinity`.
3. Unlock from your own terminal, pinning the daemon's uid:

   ```bash
   axiom-agent unlock --socket /run/axiom-agent/agent.sock \
     --expect-uid "$(id -u axiomvault)"
   ```

   If an LLM agent has a shell as your uid, it can tamper with that command
   (see the threat model). Unlock as the daemon user instead, which needs
   `--allow-uid "$(id -u axiomvault)"` added in step 2:

   ```bash
   sudo -u axiomvault /usr/local/bin/axiom-agent unlock \
     --socket /run/axiom-agent/agent.sock --expect-uid "$(id -u axiomvault)"
   ```

4. Point `axiom-mcp --socket /run/axiom-agent/agent.sock` at it.

Your uid can still use the vault within the daemon's policy, but can no
longer read the daemon's memory or replace it with a daemon of its own.
`--allow-file-io` paths are opened by the daemon's user, and the vault's
freshness anchor is kept in that user's data directory
(`~/.local/share/axiomvault/freshness`), so it needs a home directory.
