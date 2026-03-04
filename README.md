# Greywall

Greywall wraps commands in a deny-by-default sandbox. Filesystem access is restricted to the current directory by default — use `--learning` to trace what else a command needs and auto-generate a config template. All network traffic is transparently redirected through [greyproxy](https://github.com/GreyhavenHQ/greyproxy), a deny-by-default transparent proxy with a live allow/deny dashboard. Run `greywall setup` to install greyproxy automatically.

*Note: linux only at the moment, macos support is coming!*

https://github.com/user-attachments/assets/7d62d45d-a201-4f24-9138-b460e4c157a8

```bash
# Sandbox a command (network + filesystem denied by default)
greywall -- curl https://example.com

# Learn what filesystem access a command needs, then auto-generate a template
greywall --learning -- opencode

# Block dangerous commands
greywall -c "rm -rf /"  # → blocked by command deny rules
```

## Install

**Linux:**

```bash
curl -fsSL https://github.com/GreyhavenHQ/greywall/raw/branch/main/install.sh | sh
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

- `bubblewrap` — container-free sandboxing (required)
- `socat` — network bridging (required)

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

### Learning mode

Greywall can trace a command's filesystem access and generate a config template automatically:

```bash
# Run in learning mode — traces file access via strace
greywall --learning -- opencode

# List generated templates
greywall templates list

# Show a template's content
greywall templates show opencode

# Next run auto-loads the learned template
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

## Features

- **Transparent proxy** — All TCP/UDP traffic captured at the kernel level via tun2socks and routed through an external SOCKS5 proxy (Linux)
- **Network isolation** — All outbound blocked by default; traffic only flows when a proxy is available
- **Filesystem restrictions** — Deny-by-default read mode, controlled write paths, sensitive file protection
- **Learning mode** — Trace filesystem access with strace and auto-generate config templates
- **Command blocking** — Deny dangerous commands (`rm -rf /`, `git push`, `shutdown`, etc.)
- **SSH filtering** — Control which hosts and commands are allowed over SSH
- **Environment hardening** — Strips dangerous env vars (`LD_PRELOAD`, `DYLD_*`, etc.)
- **Violation monitoring** — Real-time logging of sandbox violations (`-m`)
- **Shell completions** — `greywall completion bash|zsh|fish|powershell`
- **Cross-platform** — Linux (bubblewrap + seccomp + Landlock + eBPF) and macOS (sandbox-exec)

Greywall can also be used as a [Go package](docs/library.md).

## Documentation

- [Documentation Index](docs/README.md)
- [Quickstart Guide](docs/quickstart.md)
- [Why Greywall](docs/why-greywall.md)
- [Configuration Reference](docs/configuration.md)
- [Learning Mode](docs/learning.md)
- [Security Model](docs/security-model.md)
- [Architecture](ARCHITECTURE.md)
- [Linux Security Features](docs/linux-security-features.md)
- [AI Agent Integration](docs/agents.md)
- [Library Usage (Go)](docs/library.md)
- [Troubleshooting](docs/troubleshooting.md)

## Attribution

Greywall is a fork of [Fence](https://github.com/Use-Tusk/fence), originally
created by [JY Tan](https://github.com/jy-tan) at [Tusk AI, Inc](https://github.com/Use-Tusk).
Copyright 2025 Tusk AI, Inc. Licensed under the Apache License 2.0.

Inspired by Anthropic's [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).
