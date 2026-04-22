---
id: quickstart
title: Quickstart
---

# Quickstart

## Installation

### Homebrew (macOS)

```bash
brew tap greyhavenhq/tap
brew install greywall
```

This also installs [Greyproxy](../greyproxy) as a dependency.

### Linux / Mac install script

```bash
curl -fsSL https://raw.githubusercontent.com/GreyhavenHQ/greywall/main/install.sh | sh
```

The script downloads the latest release from GitHub, verifies its checksum, installs the binary to `~/.local/bin/greywall`, and then runs `greywall setup` to install and start greyproxy. Set `INSTALL_DIR` to pick a different install location, or pass a version tag (e.g. `sh -s -- v0.1.0`) to pin a specific release.

### Using Go install

```bash
go install github.com/GreyhavenHQ/greywall/cmd/greywall@latest
greywall setup
```

`go install` only places the greywall binary on your `$PATH`. Run `greywall setup` afterwards to install and start [greyproxy](/greyproxy), which greywall relies on for network filtering. Without it, the sandbox has no reachable network.

### Using mise

```bash
mise use -g github:GreyhavenHQ/greywall
mise use -g github:GreyhavenHQ/greyproxy
```

### From source

```bash
git clone https://github.com/GreyhavenHQ/greywall
cd greywall
make setup && make build
```

### Linux Dependencies

On Linux, you also need:

```bash
# Ubuntu/Debian
sudo apt install bubblewrap socat xdg-dbus-proxy libsecret-tools

# Fedora
sudo dnf install bubblewrap socat xdg-dbus-proxy libsecret

# Arch
sudo pacman -S bubblewrap socat xdg-dbus-proxy libsecret
```

`xdg-dbus-proxy` is optional but recommended (it enables `notify-send` inside the sandbox). `libsecret-tools` provides `secret-tool`, which greywall uses to inject keyring credentials (for example a `gh` OAuth token) into the sandbox.

### Do I need sudo to run greywall?

No, for most Linux systems. Greywall works without root privileges because:

- Package-manager-installed `bubblewrap` is typically already setuid
- Greywall detects available capabilities and adapts automatically

If some features aren't available (like network namespaces in Docker/CI), greywall falls back gracefully — you'll still get filesystem isolation, command blocking, and proxy-based network routing.

Run `greywall --linux-features` to see what's available in your environment.

### Install Greyproxy (optional)

[Greyproxy](../greyproxy) provides SOCKS5 proxying and a live allow/deny dashboard for sandboxed commands. Without it (or another SOCKS5 proxy), all network access is blocked.

You can use any SOCKS5 proxy with greywall — greyproxy is the recommended companion but not required.

```bash
# Install and start greyproxy
greywall setup
```

This downloads the latest greyproxy release, installs it to `~/.local/bin/greyproxy`, and starts a systemd user service.

## Verify Installation

```bash
# Show version
greywall --version

# Check dependencies, security features, and greyproxy status
greywall check
```

## Your First Sandboxed Command

By default, greywall routes traffic through the Greyproxy SOCKS5 proxy at `localhost:43052` with DNS via `localhost:43053`. If no proxy is running, all network access is blocked:

```bash
# This will fail if no proxy is running
greywall curl https://example.com
```

You should see something like:

```
curl: (7) Failed to connect to ... Connection refused
```

Run `greywall setup` to install and start greyproxy, or use `greywall check` to verify its status.

## Route Through a Proxy

You can override the default proxy with `--proxy`:

```bash
greywall --proxy socks5://localhost:1080 curl https://example.com
```

Or in a config file at `~/.config/greywall/greywall.json` (macOS: `~/Library/Application Support/greywall/greywall.json`):

```json
{
  "network": {
    "proxyUrl": "socks5://localhost:1080"
  }
}
```

## Debug Mode

Use `-d` to see what's happening under the hood:

```bash
greywall -d curl https://example.com
```

## Monitor Mode

Use `-m` to see only violations and blocked requests:

```bash
greywall -m npm install
```

This is useful for:

- Auditing what a command tries to access
- Debugging why something isn't working
- Understanding a package's network behavior

## Running Shell Commands

Use `-c` to run compound commands:

```bash
greywall -c "echo hello && ls -la"
```

## Expose Ports for Servers

If you're running a server that needs to accept connections:

```bash
greywall -p 3000 -c "npm run dev"
```

## Next Steps

- Read **[Why Greywall](./why-greywall)** to understand when greywall is a good fit (and when it isn't).
- Learn the mental model in **[Concepts](./concepts)**.
- Use **[Troubleshooting](./troubleshooting)** if something is blocked unexpectedly.
