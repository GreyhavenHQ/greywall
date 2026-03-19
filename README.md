# Greywall — Sandbox for AI Coding Agents

[![GitHub stars](https://img.shields.io/github/stars/GreyhavenHQ/greywall)](https://github.com/GreyhavenHQ/greywall/stargazers)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/GreyhavenHQ/greywall)](go.mod)
[![Release](https://img.shields.io/github/v/release/GreyhavenHQ/greywall)](https://github.com/GreyhavenHQ/greywall/releases)

Greywall is a container-free, deny-by-default sandbox for AI agents on Linux and macOS. It restricts filesystem access, network connections, and system calls to only what you explicitly allow, so tools like Claude Code, Cursor, Codex, and other AI coding agents can't access your SSH keys, environment secrets, or anything outside the working directory.

Use `--learning` to trace what a command needs and auto-generate a least-privilege config profile. All network traffic is transparently redirected through [greyproxy](https://github.com/GreyhavenHQ/greyproxy), a deny-by-default transparent proxy with a live allow/deny dashboard.

*Supports Linux and macOS. See [platform support](docs/platform-support.md) for details.*

https://github.com/user-attachments/assets/7d62d45d-a201-4f24-9138-b460e4c157a8

### Key features

- **Deny-by-default filesystem** — only the working directory is accessible unless you allow more
- **Network isolation** — all traffic blocked or routed through [greyproxy](https://github.com/GreyhavenHQ/greyproxy) with a live dashboard
- **Command blocking** — dangerous commands like `rm -rf /` and `git push --force` are denied
- **Built-in agent profiles** — one-command setup for Claude Code, Cursor, Codex, Aider, Goose, Gemini, OpenCode, Amp, Cline, Copilot, and more
- **Learning mode** — traces filesystem access and auto-generates least-privilege profiles
- **Five security layers on Linux** — Bubblewrap namespaces, Landlock, Seccomp BPF, eBPF monitoring, TUN-based network capture
- **No containers required** — kernel-enforced sandboxing without Docker overhead

```bash
# Sandbox a command (network + filesystem denied by default)
greywall -- curl https://example.com

# Sandbox an AI coding agent with a built-in profile
greywall -- claude

# Learn what filesystem access a command needs, then auto-generate a profile
greywall --learning -- opencode

# Block dangerous commands
greywall -c "rm -rf /"  # → blocked by command deny rules
```

## Install

**Homebrew (macOS):**

```bash
brew tap greyhavenhq/tap
brew install greywall
```

This also installs [greyproxy](https://github.com/GreyhavenHQ/greyproxy) as a dependency.

**Linux / Mac:**

```bash
curl -fsSL https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/install.sh | sh
```

<details>
<summary>Other installation methods</summary>

**Go install:**

```bash
go install github.com/GreyhavenHQ/greywall/cmd/greywall@latest
```

**Build from source:**

```bash
git clone https://github.com/GreyhavenHQ/greywall
cd greywall
make setup && make build
```

</details>

**Linux dependencies:**

- `bubblewrap` - container-free sandboxing (required)
- `socat` - network bridging (required)

Check dependency status with `greywall check`.

## Usage

### Basic commands

```bash
# Run with all network blocked (default)
greywall -- curl https://example.com

# Run with shell expansion
greywall -c "echo hello && ls"

# Route through a SOCKS5 proxy
greywall --proxy socks5://localhost:1080 -- npm install

# Expose a port for inbound connections (e.g., dev servers)
greywall -p 3000 -c "npm run dev"

# Enable debug logging
greywall -d -- curl https://example.com

# Monitor sandbox violations
greywall -m -- npm install

# Show available Linux security features
greywall --linux-features

# Show version
greywall --version

# Check dependencies, security features, and greyproxy status
greywall check

# Install and start greyproxy
greywall setup
```

### Agent profiles

Greywall ships with built-in sandbox profiles for popular AI coding agents (Claude Code, Codex, Cursor, Aider, Goose, Gemini CLI, OpenCode, Amp, Cline, Copilot, Kilo, Auggie, Droid) and toolchains (Node, Python, Go, Rust, Java, Ruby, Docker).

On first run, greywall shows what the profile allows and lets you apply, edit, or skip:

```bash
$ greywall -- claude

[greywall] Running claude in a sandbox.
A built-in profile is available. Without it, only the current directory is accessible.

Allow read:  ~/.claude  ~/.claude.json  ~/.config/claude  ~/.local/share/claude  ~/.gitconfig  ...  + working dir
Allow write: ~/.claude  ~/.claude.json  ~/.cache/claude  ~/.config/claude  ...  + working dir
Deny read:   ~/.ssh/id_*  ~/.gnupg/**  .env  .env.*
Deny write:  ~/.bashrc  ~/.zshrc  ~/.ssh  ~/.gnupg

[Y] Use profile (recommended)   [e] Edit first   [s] Skip (restrictive)   [n] Don't ask again
>
```

Combine agent and toolchain profiles with `--profile`:

```bash
# Agent + Python toolchain (allows access to ~/.cache/uv, ~/.local/pipx, etc.)
greywall --profile claude,python -- claude

# Agent + multiple toolchains
greywall --profile opencode,node,go -- opencode

# List all available and saved profiles
greywall profiles list
```

### Learning mode

Greywall can trace a command's filesystem access and generate a config profile automatically:

```bash
# Run in learning mode - traces file access via strace
greywall --learning -- opencode

# List generated profiles
greywall profiles list

# Show a profile's content
greywall profiles show opencode

# Next run auto-loads the learned profile
greywall -- opencode
```

### Configuration

Greywall reads from `~/.config/greywall/greywall.json` by default (or `~/Library/Application Support/greywall/greywall.json` on macOS).

```jsonc
{
  // Route traffic through an external SOCKS5 proxy
  "network": {
    "proxyUrl": "socks5://localhost:1080",
    "dnsAddr": "localhost:5353"
  },
  // Control filesystem access
  "filesystem": {
    "defaultDenyRead": true,
    "allowRead": ["~/.config/myapp"],
    "allowWrite": ["."],
    "denyWrite": ["~/.ssh/**"],
    "denyRead": ["~/.ssh/id_*", ".env"]
  },
  // Block dangerous commands
  "command": {
    "deny": ["git push", "npm publish"]
  }
}
```

Use `greywall --settings ./custom.json` to specify a different config file.

By default, traffic routes through the GreyProxy SOCKS5 proxy at `localhost:43052` with DNS via `localhost:43053`.

## Platform support

| Feature | Linux | macOS |
|---------|:-----:|:-----:|
| **Sandbox engine** | bubblewrap | sandbox-exec (Seatbelt) |
| **Filesystem deny-by-default (read/write)** | ✅ | ✅ |
| **Syscall filtering** | ✅ (seccomp) | ✅ (Seatbelt) |
| **Filesystem access control** | ✅ (Landlock + bubblewrap) | ✅ (Seatbelt) |
| **Violation monitoring** | ✅ (eBPF) | ✅ (Seatbelt denial logs) |
| **Transparent proxy (full traffic capture)** | ✅ (tun2socks + TUN) | ❌ |
| **DNS capture** | ✅ (DNS bridge) | ❌ |
| **Proxy via env vars (SOCKS5 / HTTP)** | ✅ | ✅ |
| **Network isolation** | ✅ (network namespace) | N/A |
| **Command allow/deny lists** | ✅ | ✅ |
| **Environment sanitization** | ✅ | ✅ |
| **Learning mode** | ✅ (strace) | ✅ (eslogger, requires sudo) |
| **PTY support** | ✅ | ✅ |
| **External deps** | bwrap, socat | none |

See [platform support](docs/platform-support.md) for more details.

Greywall can also be used as a [Go package](docs/library.md).

## Documentation

Full documentation is available at [docs.greywall.io](https://docs.greywall.io/) and in the `docs/` directory:

- [Quickstart Guide](docs/quickstart.md)
- [Why Greywall](docs/why-greywall.md)
- [Configuration Reference](docs/configuration.md)
- [Learning Mode](docs/learning.md)
- [Security Model](docs/security-model.md)
- [Architecture](ARCHITECTURE.md)
- [Platform Support](docs/platform-support.md)
- [Linux Security Features](docs/linux-security-features.md)
- [AI Agent Integration](docs/agents.md)
- [Library Usage (Go)](docs/library.md)
- [Troubleshooting](docs/troubleshooting.md)

## Attribution

Greywall is a fork of [Fence](https://github.com/Use-Tusk/fence), originally
created by [JY Tan](https://github.com/jy-tan) at [Tusk AI, Inc](https://github.com/Use-Tusk).
Copyright 2025 Tusk AI, Inc. Licensed under the Apache License 2.0.

Inspired by Anthropic's [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).
