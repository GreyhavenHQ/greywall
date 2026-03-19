# Quickstart

## Installation

### From Source (recommended for now)

```bash
git clone https://github.com/GreyhavenHQ/greywall
cd greywall
go build -o greywall ./cmd/greywall
sudo mv greywall /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/GreyhavenHQ/greywall/cmd/greywall@latest
```

### Linux Dependencies

On Linux, you also need:

```bash
# Ubuntu/Debian
sudo apt install bubblewrap socat xdg-dbus-proxy

# Fedora
sudo dnf install bubblewrap socat xdg-dbus-proxy

# Arch
sudo pacman -S bubblewrap socat xdg-dbus-proxy
```

`xdg-dbus-proxy` is optional but recommended. It enables `notify-send` inside the sandbox while keeping the D-Bus session bus isolated.

### Do I need sudo to run greywall?

No, for most Linux systems. Greywall works without root privileges because:

- Package-manager-installed `bubblewrap` is typically already setuid
- Greywall detects available capabilities and adapts automatically

If some features aren't available (like network namespaces in Docker/CI), greywall falls back gracefully - you'll still get filesystem isolation, command blocking, and proxy-based network routing.

Run `greywall --linux-features` to see what's available in your environment.

### Install GreyProxy (optional)

GreyProxy provides SOCKS5 proxying and DNS resolution for sandboxed commands. Without it, all network access is blocked.

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

By default, greywall routes traffic through the GreyProxy SOCKS5 proxy at `localhost:43052` with DNS via `localhost:43053`. If greyproxy is not running, all network access is blocked:

```bash
# This will fail if greyproxy is not running
greywall curl https://example.com
```

You should see something like:

```text
curl: (7) Failed to connect to ... Connection refused
```

Run `greywall setup` to install and start greyproxy, or use `greywall check` to verify its status.

## Route Through a Proxy

You can override the default proxy with `--proxy`:

```bash
greywall --proxy socks5://localhost:1080 curl https://example.com
```

Or in a config file at `~/.config/greywall/greywall.json` (or `~/Library/Application Support/greywall/greywall.json` on macOS):

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

This shows:

- The sandbox command being run
- Proxy activity (allowed/blocked requests)
- Filter rule matches

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

This allows external connections to port 3000 while keeping outbound network restricted.

## Next steps

- Read **[Why Greywall](why-greywall.md)** to understand when greywall is a good fit (and when it isn't).
- Learn the mental model in **[Concepts](concepts.md)**.
- Use **[Troubleshooting](troubleshooting.md)** if something is blocked unexpectedly.
- Start from copy/paste configs in **[`docs/templates/`](templates/README.md)**.
- Follow workflow-specific guides in **[Recipes](recipes/README.md)** (npm/pip/git/CI).
