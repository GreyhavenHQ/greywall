---
id: cli-reference
title: CLI Reference
---

# CLI Reference

## Synopsis

```
greywall [flags] [--] <command> [args...]
greywall -c "<shell string>"
greywall <subcommand> [args...]
```

## Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--settings <path>` | `-s` | Path to a JSON/JSONC config file. Defaults to `~/.config/greywall/greywall.json` (macOS: `~/Library/Application Support/greywall/greywall.json`) |
| `--profile <names>` | | Comma-separated list of profiles to apply (e.g., `--profile claude,python`). Also accepts a learned profile name from `--learning`. |
| `--auto-profile` | | Silently apply a saved or built-in profile for the command without prompting on first run |
| `--proxy <url>` | | Override the SOCKS5 proxy URL (default: `socks5://localhost:43052`) |
| `--http-proxy <url>` | | Override the HTTP CONNECT proxy URL (default: `http://localhost:43051`) |
| `--dns <addr>` | | Override the host-side DNS server address (default: `localhost:43053`) |
| `--port <port>` | `-p` | Expose a port for inbound connections into the sandbox (repeatable) |
| `--forward <port>` | `-f` | Forward a host `localhost` port into the sandbox (Linux only, repeatable) |
| `--command <cmd>` | `-c` | Run a shell command string (supports `&&`, `;`, pipes) |
| `--debug` | `-d` | Verbose output: proxy activity, filter decisions, sandbox command |
| `--monitor` | `-m` | Show only violations and blocked requests (audit mode) |
| `--learning` | | Trace filesystem access with strace/eslogger and auto-generate a profile |
| `--secret <VAR>` | | Treat an environment variable as a credential even if it doesn't match the auto-detection rules (repeatable). See [Credential Protection](./credential-protection). |
| `--inject <LABEL>` | | Inject a credential stored in the greyproxy dashboard into the sandbox by label (repeatable) |
| `--ignore-secret <VAR>` | | Exclude a variable from credential detection even if it matches the heuristics (repeatable) |
| `--no-credential-protection` | | Disable credential substitution entirely; real values are visible inside the sandbox |
| `--no-network-rules` | | Skip pushing the profile's network rules to greyproxy. Filesystem and keyring restrictions from the profile still apply, and `--allow` rules are still forwarded. See [Templates](./templates#network-rules-and---no-network-rules). |
| `--linux-features` | | Print the Linux kernel security features available on the current system and exit |
| `--version` | `-v` | Print the greywall version and exit |
| `--help` | `-h` | Show help |

> `-t/--template` is a hidden, deprecated alias for `--profile`. New scripts should use `--profile`.

### `-m` and `-d` together

You can combine both flags to get violation monitoring **and** the full sandbox command:

```bash
greywall -m -d -- npm install
```

### `-p / --port`

Expose ports for sandboxed servers so external processes can connect:

```bash
# Single port
greywall -p 3000 -c "npm run dev"

# Multiple ports
greywall -p 3000 -p 8080 -c "make start"
```

### `-f / --forward` (Linux only)

Forward a host `localhost` port *into* the sandbox so the sandboxed process can reach a host service (database, cache, and so on). This is the Linux equivalent of `allowLocalOutbound` on macOS, which only works there because the macOS sandbox shares the host network stack.

```bash
# Reach a host Postgres from inside the sandbox
greywall -f 5432 -- psql -h localhost

# Forward multiple ports
greywall -f 5432 -f 6379 -- make test
```

See [Concepts](./concepts#port-forwarding-platform-differences) for the full explanation of the platform difference.

## Subcommands

### `greywall check`

Check that greywall and its dependencies are correctly installed.

```bash
greywall check
```

Verifies:
- Required binaries (`bwrap`, `socat` on Linux)
- Linux kernel security features (Landlock, seccomp, eBPF)
- Greyproxy installation and service status

### `greywall setup`

Download and install [Greyproxy](../greyproxy), then start it as a service.

```bash
greywall setup
```

Installs greyproxy to `~/.local/bin/greyproxy` and registers it as a systemd user service (Linux) or launchd agent (macOS).

### `greywall --linux-features`

Print the Linux kernel security features available on the current system.

```bash
greywall --linux-features
```

Example output:

```
Linux Sandbox Features:
  Kernel: 6.8
  Bubblewrap (bwrap): true
  Socat: true
  Seccomp: true (log level: 2)
  Landlock: true (ABI v4)
  eBPF: true (CAP_BPF: true, root: false)

Feature Status:
  ✓ Minimum requirements met (bwrap + socat)
  ✓ Landlock available for enhanced filesystem control
  ✓ Violation monitoring available
  ✓ eBPF monitoring available (enhanced visibility)
```

### `greywall profiles list`

List all available and saved profiles. This covers built-in agent profiles (Claude Code, Codex, Cursor, Aider, and so on), built-in toolchain profiles (Node, Python, Go, Rust, and so on), and any profiles you have saved with `--learning`. The `templates` name is accepted as an alias for backwards compatibility.

```bash
greywall profiles list
```

### `greywall profiles show <name>`

Print the JSONC content of a profile.

```bash
greywall profiles show opencode
```

### `greywall profiles edit <name>`

Open a saved profile in `$EDITOR` for direct editing.

```bash
greywall profiles edit opencode
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GREYWALL_SANDBOX` | Set to `1` inside sandboxed processes. Lets commands detect they are running under greywall. |
| `GREYWALL_TEST_NETWORK` | Set to `1` in smoke tests to enable network-dependent tests. |
| `HTTP_PROXY` / `HTTPS_PROXY` | Set by greywall to point to the local HTTP proxy (macOS and Linux fallback mode). |
| `ALL_PROXY` | Set by greywall to point to the SOCKS5 proxy. |
| `GIT_SSH_COMMAND` | Set by greywall on macOS to route SSH through the proxy. |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Greywall error (config invalid, dependency missing, command blocked by policy) |
| Other | The exit code of the sandboxed command itself |

## Examples

```bash
# Sandbox a single command
greywall -- curl https://example.com

# Sandbox a shell pipeline
greywall -c "cat package.json | grep name"

# Use a built-in profile
greywall --profile code -- claude

# Combine multiple profiles (agent + toolchain)
greywall --profile claude,python -- claude

# Override proxy
greywall --proxy socks5://proxy.internal:1080 -- npm install

# Monitor what gets blocked without stopping the command
greywall -m -- pip install -r requirements.txt

# Learn filesystem access, then run normally
greywall --learning -- cargo build
greywall -- cargo build          # auto-loads learned profile

# Expose dev server port
greywall -p 5173 -c "npm run dev"

# Debug with custom config
greywall -d -s ./greywall.json -- go test ./...
```

## Config File Locations

| Platform | Default path |
|----------|-------------|
| Linux | `~/.config/greywall/greywall.json` |
| macOS | `~/Library/Application Support/greywall/greywall.json` |
| Legacy (both) | `~/.greywall.json` |

Pass `--settings <path>` to use any other location. Config files support JSONC (JSON with comments).
