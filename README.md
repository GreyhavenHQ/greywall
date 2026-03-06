# Greywall

Greywall wraps commands in a deny-by-default sandbox. Filesystem access is restricted to the current directory by default. Use `--learning` to trace what else a command needs and auto-generate a config template. All network traffic is transparently redirected through [greyproxy](https://github.com/GreyhavenHQ/greyproxy), a deny-by-default transparent proxy with a live allow/deny dashboard. Run `greywall setup` to install greyproxy automatically.

*Supports Linux and macOS. See [platform support](docs/platform-support.md) for details.*

https://github.com/user-attachments/assets/7d62d45d-a201-4f24-9138-b460e4c157a8

```bash
# Check that greywall installation is ok
greywall check

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

### Learning mode

Greywall can trace a command's filesystem access and generate a config template automatically:

```bash
# Run in learning mode - traces file access via strace
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

- [Documentation Index](docs/README.md)
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
