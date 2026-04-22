---
id: index
title: Greywall
sidebar_label: Overview
slug: /greywall
---

# Greywall

Greywall wraps commands in a **deny-by-default sandbox**. Filesystem access is restricted to the current directory by default. Use `--learning` to trace what a command needs and auto-generate a config profile. All network traffic is transparently redirected through a SOCKS5 proxy — by default [Greyproxy](/greyproxy), but you can point it at any SOCKS5 proxy.

Supports **Linux** and **macOS**. See [Platform Support](/greywall/platform-support) for details.

```bash
# Check that greywall installation is ok
greywall check

# Sandbox a command (network + filesystem denied by default)
greywall -- curl https://example.com

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

This also installs [Greyproxy](https://github.com/GreyhavenHQ/greyproxy) as a dependency.

**Linux / Mac:**

```bash
curl -fsSL https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/install.sh | sh
```

<details>
<summary>Other installation methods</summary>

**Go install:**

```bash
go install github.com/GreyhavenHQ/greywall/cmd/greywall@latest
greywall setup
```

`go install` places the binary on your `$PATH`; `greywall setup` installs and starts [greyproxy](/greyproxy), which greywall relies on for network filtering.

**[mise](https://mise.jdx.dev/):**

```bash
mise use -g github:GreyhavenHQ/greywall
mise use -g github:GreyhavenHQ/greyproxy
```

**Build from source:**

```bash
git clone https://github.com/GreyhavenHQ/greywall
cd greywall
make setup && make build
```

</details>

**Linux dependencies:**

- `bubblewrap` (required), container-free sandboxing
- `socat` (required), network bridging
- `xdg-dbus-proxy` (optional), filtered D-Bus proxy for `notify-send` support
- `libsecret-tools` (optional), keyring credential injection for `gh` and `glab`

Check dependency status with `greywall check`.

## Basic Usage

```bash
# Run with all network blocked (default)
greywall -- curl https://example.com

# Run with shell expansion
greywall -c "echo hello && ls"

# Route through a SOCKS5 proxy (any proxy, not just greyproxy)
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

## Agent Profiles

Greywall ships with built-in profiles for popular AI coding agents (Claude Code, Codex, Cursor, Aider, Goose, Gemini, OpenCode, Amp, Cline, Copilot, Kilo, Auggie, Droid) and toolchains (Node, Python, Go, Rust, Java, Ruby, Docker).

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
# Agent + Python toolchain
greywall --profile claude,python -- claude

# Agent + multiple toolchains
greywall --profile opencode,node,go -- opencode

# List all available and saved profiles
greywall profiles list
```

## Platform Support

| Feature | Linux | macOS |
|---------|:-----:|:-----:|
| **Sandbox engine** | bubblewrap | sandbox-exec (Seatbelt) |
| **Filesystem deny-by-default** | ✅ | ✅ |
| **Syscall filtering** | ✅ (seccomp) | ✅ (Seatbelt) |
| **Transparent proxy** | ✅ (tun2socks + TUN) | ❌ (env vars only) |
| **Network isolation** | ✅ (network namespace) | N/A |
| **Learning mode** | ✅ (strace) | ✅ (eslogger, needs sudo) |
| **Violation monitoring** | ✅ (eBPF) | ✅ (Seatbelt denial logs) |

See [Platform Support](/greywall/platform-support) for a full comparison.

## Documentation

- [Quickstart](/greywall/quickstart) — Install and run your first sandboxed command
- [Why Greywall](/greywall/why-greywall) — What problem it solves
- [Concepts](/greywall/concepts) — Mental model: OS sandbox + proxies + config
- [Configuration](/greywall/configuration) — Full configuration reference
- [Learning Mode](/greywall/learning-mode) — Auto-discover filesystem access needs
- [AI Agent Integration](/greywall/agents) — Defense-in-depth for coding agents
- [Security Model](/greywall/security-model) — Threat model and guarantees
- [Platform Support](/greywall/platform-support) — Linux vs macOS details
- [Troubleshooting](/greywall/troubleshooting) — Common issues and fixes

## Attribution

Greywall is a fork of [Fence](https://github.com/Use-Tusk/fence), originally created by [JY Tan](https://github.com/jy-tan) at [Tusk AI, Inc](https://github.com/Use-Tusk). Copyright 2025 Tusk AI, Inc. Licensed under the Apache License 2.0.

Inspired by Anthropic's [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime).
