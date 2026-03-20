# Configuration

Greywall reads settings from `~/.config/greywall/greywall.json` by default (or `~/Library/Application Support/greywall/greywall.json` on macOS). Legacy `~/.greywall.json` is also supported. Pass `--settings ./greywall.json` to use a custom path. Config files support JSONC.

Example config:

```json
{
  "network": {
    "proxyUrl": "socks5://localhost:43052",
    "dnsAddr": "localhost:43053"
  },
  "filesystem": {
    "denyRead": ["/etc/passwd"],
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".git/hooks"]
  },
  "command": {
    "deny": ["git push", "npm publish"]
  },
  "ssh": {
    "allowedHosts": ["*.example.com"],
    "allowedCommands": ["ls", "cat", "grep", "tail", "head"]
  }
}
```

## Config Inheritance

You can extend built-in templates or other config files using the `extends` field. This reduces boilerplate by inheriting settings from a base and only specifying your overrides.

### Extending a template

```json
{
  "extends": "code",
  "filesystem": {
    "allowWrite": [".", "/tmp"]
  }
}
```

This config:

- Inherits all settings from the `code` template (filesystem protections, command restrictions)
- Adds custom writable paths

### Extending a file

You can also extend other config files using absolute or relative paths:

```json
{
  "extends": "./base-config.json",
  "command": {
    "deny": ["git push"]
  }
}
```

```json
{
  "extends": "/etc/greywall/company-base.json",
  "filesystem": {
    "denyRead": ["~/company-secrets/**"]
  }
}
```

Relative paths are resolved relative to the config file's directory. The extended file is validated before merging.

### Detection

The `extends` value is treated as a file path if it contains `/` or `\`, or starts with `.`. Otherwise it's treated as a template name.

### Merge behavior

- Slice fields (paths, commands) are appended and deduplicated
- Boolean fields use OR logic (true if either base or override enables it)
- Integer fields (ports) use override-wins semantics (0 keeps base value)

### Chaining

Extends chains are supported—a file can extend a template, and another file can extend that file. Circular extends are detected and rejected. Maximum chain depth is 10.

See [templates.md](templates.md) for available templates.

## Network Configuration

Greywall routes all network traffic through an external SOCKS5 proxy. Domain filtering and access control are handled by the proxy (e.g., [GreyProxy](https://github.com/greyhavenhq/greyproxy)), not by greywall itself.

| Field | Description |
|-------|-------------|
| `proxyUrl` | External SOCKS5 proxy URL (default: `socks5://localhost:43052`) |
| `dnsAddr` | Host-side DNS server address (default: `localhost:43053`) |
| `allowUnixSockets` | List of allowed Unix socket paths (macOS) |
| `allowAllUnixSockets` | Allow all Unix sockets |
| `allowLocalBinding` | Allow binding to local ports |
| `allowLocalOutbound` | Allow outbound connections to localhost, e.g., local DBs (defaults to `allowLocalBinding` if not set; macOS only) |
| `forwardPorts` | Host localhost ports to forward into the sandbox (Linux only; array of integers) |

## Filesystem Configuration

| Field | Description |
|-------|-------------|
| `defaultDenyRead` | Deny reads by default, allowing only system paths, CWD, and `allowRead` entries (default: `true` when not set) |
| `allowRead` | Paths to allow reading (used when `defaultDenyRead` is enabled) |
| `denyRead` | Paths to deny reading (overrides `allowRead`) |
| `allowWrite` | Paths to allow writing |
| `denyWrite` | Paths to deny writing (takes precedence over `allowWrite`) |
| `allowGitConfig` | Allow writes to `.git/config` files |

To opt out of deny-by-default reads, set `"defaultDenyRead": false`. Use `--learning` mode to automatically discover which paths a command needs. See [Learning Mode](learning.md).

## Command Configuration

Block specific commands from being executed, even within command chains.

| Field | Description |
|-------|-------------|
| `deny` | List of command prefixes to block (e.g., `["git push", "rm -rf"]`) |
| `allow` | List of command prefixes to allow, overriding `deny` |
| `useDefaults` | Enable default deny list of dangerous system commands (default: `true`) |

Example:

```json
{
  "command": {
    "deny": ["git push", "npm publish"],
    "allow": ["git push origin docs"]
  }
}
```

### Default Denied Commands

When `useDefaults` is `true` (the default), greywall blocks these dangerous commands:

- System control: `shutdown`, `reboot`, `halt`, `poweroff`, `init 0/6`
- Kernel manipulation: `insmod`, `rmmod`, `modprobe`, `kexec`
- Disk operations: `mkfs*`, `fdisk`, `parted`, `dd if=`
- Container escape: `docker run -v /:/`, `docker run --privileged`
- Namespace escape: `chroot`, `unshare`, `nsenter`

To disable defaults: `"useDefaults": false`

### Command Detection

Greywall detects blocked commands in:

- Direct commands: `git push origin main`
- Command chains: `ls && git push` or `ls; git push`
- Pipelines: `echo test | git push`
- Shell invocations: `bash -c "git push"` or `sh -lc "ls && git push"`

## SSH Configuration

Control which SSH commands are allowed. By default, SSH uses **allowlist mode** for security - only explicitly allowed hosts and commands can be used.

| Field | Description |
|-------|-------------|
| `allowedHosts` | Host patterns to allow SSH connections to (supports wildcards like `*.example.com`, `prod-*`) |
| `deniedHosts` | Host patterns to deny SSH connections to (checked before allowed) |
| `allowedCommands` | Commands allowed over SSH (allowlist mode) |
| `deniedCommands` | Commands denied over SSH (checked before allowed) |
| `allowAllCommands` | If `true`, use denylist mode instead of allowlist (allow all commands except denied) |
| `inheritDeny` | If `true`, also apply global `command.deny` rules to SSH commands |

### Basic Example (Allowlist Mode)

```json
{
  "ssh": {
    "allowedHosts": ["*.example.com"],
    "allowedCommands": ["ls", "cat", "grep", "tail", "head", "find"]
  }
}
```

This allows:

- SSH to any `*.example.com` host
- Only the listed commands (and their arguments)
- Interactive sessions (no remote command)

### Denylist Mode Example

```json
{
  "ssh": {
    "allowedHosts": ["dev-*.example.com"],
    "allowAllCommands": true,
    "deniedCommands": ["rm -rf", "shutdown", "chmod"]
  }
}
```

This allows:

- SSH to any `dev-*.example.com` host
- Any command except the denied ones

### Inheriting Global Denies

```json
{
  "command": {
    "deny": ["shutdown", "reboot", "rm -rf /"]
  },
  "ssh": {
    "allowedHosts": ["*.example.com"],
    "allowAllCommands": true,
    "inheritDeny": true
  }
}
```

With `inheritDeny: true`, SSH commands also check against:

- Global `command.deny` list
- Default denied commands (if `command.useDefaults` is true)

### Host Pattern Matching

SSH host patterns support wildcards anywhere:

| Pattern | Matches |
|---------|---------|
| `server1.example.com` | Exact match only |
| `*.example.com` | Any subdomain of example.com |
| `prod-*` | Any hostname starting with `prod-` |
| `prod-*.us-east.*` | Multiple wildcards |
| `*` | All hosts |

### Evaluation Order

1. Check if host matches `deniedHosts` → **DENY**
2. Check if host matches `allowedHosts` → continue (else **DENY**)
3. If no remote command (interactive session) → **ALLOW**
4. Check if command matches `deniedCommands` → **DENY**
5. If `inheritDeny`, check global `command.deny` → **DENY**
6. If `allowAllCommands` → **ALLOW**
7. Check if command matches `allowedCommands` → **ALLOW**
8. Default → **DENY**

## Other Options

| Field | Description |
|-------|-------------|
| `allowPty` | Allow pseudo-terminal (PTY) allocation in the sandbox (for MacOS) |

## Importing from Claude Code

If you've been using Claude Code and have already built up permission rules, you can import them into greywall:

```bash
# Preview import (prints JSON to stdout)
greywall import --claude

# Save to the default config path
greywall import --claude --save

# Import from a specific file
greywall import --claude -f ~/.claude/settings.json --save

# Save to a specific output file
greywall import --claude -o ./greywall.json

# Import without extending any template (minimal config)
greywall import --claude --no-extend --save

# Import and extend a different template
greywall import --claude --extend local-dev-server --save
```

### Default Template

By default, imports extend the `code` template which provides sensible defaults:

- Filesystem protections for secrets and sensitive paths
- Command restrictions for dangerous operations

Use `--no-extend` if you want a minimal config without these defaults, or `--extend <template>` to choose a different base template.

### Permission Mapping

| Claude Code | Greywall |
|-------------|-------|
| `Bash(xyz)` allow | `command.allow: ["xyz"]` |
| `Bash(xyz:*)` deny | `command.deny: ["xyz"]` |
| `Read(path)` deny | `filesystem.denyRead: [path]` |
| `Write(path)` allow | `filesystem.allowWrite: [path]` |
| `Write(path)` deny | `filesystem.denyWrite: [path]` |
| `Edit(path)` | Same as `Write(path)` |
| `ask` rules | Converted to deny (greywall doesn't support interactive prompts) |

Global tool permissions (e.g., bare `Read`, `Write`, `Grep`) are skipped since greywall uses path/command-based rules.

## See Also

- Config templates: [`docs/templates/`](docs/templates/)
- Workflow guides: [`docs/recipes/`](docs/recipes/)
