---
id: troubleshooting
title: Troubleshooting
---

# Troubleshooting

## Nested Sandboxing Not Supported

Greywall cannot run inside another sandbox that uses the same underlying technology.

**macOS (Seatbelt)**: If you try to run greywall inside an existing `sandbox-exec` sandbox (e.g., Nix's Darwin build sandbox), you'll see:

```text
Sandbox: sandbox-exec(...) deny(1) forbidden-sandbox-reinit
```

This is a macOS kernel limitation - nested Seatbelt sandboxes are not allowed. There is no workaround.

**Linux (Landlock)**: Landlock supports stacking (nested restrictions), but greywall's test binaries cannot use the Landlock wrapper (see [Testing docs](testing.md#sandboxed-build-environments-nix-etc)).

## "bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted" (Linux)

This error occurs when the environment prevents Greywall's Bubblewrap child from administering its network namespace. This is common in:

- **Docker containers** (unless run with `--privileged` or `--cap-add=NET_ADMIN`)
- **GitHub Actions** and other CI runners
- **Ubuntu 24.04+** where AppArmor allows Bubblewrap to create namespaces but removes child capabilities
- **Kubernetes pods** without elevated security contexts

**What happens now:**

Greywall probes both namespace creation and child-side TUN access. If TUN setup is unavailable but the network namespace works, Greywall keeps the namespace and uses `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` instead. Programs that honor those variables can reach the configured proxy; programs that ignore them remain blocked by the namespace.

If the network namespace itself is unavailable, Greywall retains its filesystem, PID, seccomp, and Landlock restrictions, but direct network access is not contained. `greywall check` reports this weaker state explicitly.

**To check if your environment supports network namespaces:**

```bash
greywall --linux-features
```

Look for "Network namespace (--unshare-net): true/false"

**Solutions if you need transparent proxying:**

1. Prefer an application that honors standard proxy environment variables; the network namespace still prevents bypass.
2. In containers, grant `NET_ADMIN` only to the container running Greywall when that is acceptable for your threat model.
3. In CI, use a self-hosted runner whose sandbox policy supports child-side TUN administration.
4. On Ubuntu 24.04+, use a narrowly scoped AppArmor policy reviewed for your deployment. Do not disable AppArmor's unprivileged-user-namespace restriction globally.

## "bwrap: setting up uid map: Permission denied" (Linux)

This error occurs when bwrap cannot create user namespaces. This typically happens when:

- The `uidmap` package is not installed
- `/etc/subuid` and `/etc/subgid` are not configured for your user
- bwrap is not setuid

**Quick fix (if you have root access):**

```bash
# Install uidmap
sudo apt install uidmap  # Debian/Ubuntu

# Make bwrap setuid
sudo chmod u+s $(which bwrap)
```

**Or configure subuid/subgid for your user:**

```bash
echo "$(whoami):100000:65536" | sudo tee -a /etc/subuid
echo "$(whoami):100000:65536" | sudo tee -a /etc/subgid
```

On most systems with package-manager-installed bwrap, this error shouldn't occur. If it does, your system may have non-standard security policies.

## Network errors (connection refused, timeout, 403)

**"Connection refused"** — greyproxy is not running. Install and start it:

```bash
greywall setup    # install and start greyproxy
greywall check    # verify status
```

**"CONNECT tunnel failed, response 403"** — the proxy rejected the request (e.g., the domain is not allowed by the proxy's policy).

Fix:

- Run with monitor mode to see what was blocked:
  - `greywall -m <command>`
- Update the proxy's configuration to allow the required destination(s).

## "It works outside greywall but not inside"

Start with:

- `greywall -m <command>` to see what's being denied
- `greywall -d <command>` to see full proxy and sandbox detail

Common causes:

- The external proxy is not running or rejecting the request
- Localhost outbound blocked (DB/cache on `127.0.0.1`)
- Writes blocked (you didn't include a directory in `filesystem.allowWrite`)

## Symlinked config files not found inside the sandbox

If a path in `filesystem.allowRead` is a symlink (common with dotfiles managers like stow), greywall recreates the link inside the sandbox and exposes its resolved target, so this works out of the box.

If the symlink sits *inside* an allowed directory and points outside it, greywall must also expose the target. By default it scans only the direct entries of each allowed directory (`"symlinkScan": "shallow"`). For symlinks in nested subdirectories, set `"symlinkScan": "deep"` in the `filesystem` section, or add the symlink target to `allowRead` directly:

```json
{
  "filesystem": {
    "allowRead": ["~/.claude", "~/dotfiles/claude"]
  }
}
```

Targets under credential-bearing locations (`~/.ssh`, `~/.aws`, `.env` files, and similar) are never exposed by the scan; they always need an explicit `allowRead` entry. Run with `-d` to see which symlinks and targets were detected. See [Configuration](./configuration#symlinks-in-allowed-paths).

## Node.js HTTP(S) and proxy env vars

Node's built-in `http`/`https` modules ignore `HTTP_PROXY`/`HTTPS_PROXY`. With greywall's default TUN-based transparent proxying, this is not an issue — all traffic is routed through the proxy regardless of whether the application respects proxy environment variables.

If TUN is unavailable (fallback mode), Node apps that make direct HTTP(S) requests will need a proxy-aware client like `undici` with `ProxyAgent` to route through the proxy.

## Local services (Redis/Postgres/etc.) fail inside the sandbox

If your process needs to connect to host `localhost` services on macOS, set:

```json
{
  "network": { "allowLocalOutbound": true }
}
```

On Linux, the sandbox runs in an isolated network namespace and `allowLocalOutbound` is a no-op. Forward the specific host ports instead:

```bash
greywall -f 5432 -f 6379 -- make test
```

Or in the config file:

```json
{
  "network": { "forwardPorts": [5432, 6379] }
}
```

If you're running a server inside the sandbox that must accept connections:

- set `network.allowLocalBinding: true` (to bind)
- use `-p <port>` (to expose inbound port(s))

## `notify-send` fails inside the sandbox

`notify-send` needs the D-Bus session bus, which is blocked by default to prevent sandbox escape via GVFS and gnome-keyring. Install `xdg-dbus-proxy` to enable it:

```bash
# Ubuntu/Debian
sudo apt install xdg-dbus-proxy

# Fedora
sudo dnf install xdg-dbus-proxy

# Arch
sudo pacman -S xdg-dbus-proxy
```

When `xdg-dbus-proxy` is present, greywall automatically starts a filtered D-Bus proxy that only allows `org.freedesktop.Notifications` and blocks everything else. Run `greywall check` to verify it was picked up.

## Local host services unreachable from Linux sandbox

On Linux the sandbox runs in its own network namespace, so the host's `localhost` is not reachable even if `allowLocalOutbound` is enabled. Use `-f/--forward` (or `forwardPorts` in the config file) to forward specific host ports into the sandbox:

```bash
# Reach a host Postgres on 5432 from inside the sandbox
greywall -f 5432 -- psql -h localhost
```

See [Concepts](./concepts#port-forwarding-platform-differences) for the full explanation of the macOS/Linux difference.

## "Permission denied" on file writes

Writes are denied by default.

- Add the minimum required writable directories to `filesystem.allowWrite`.
- Protect sensitive targets with `filesystem.denyWrite` (and note greywall protects some targets regardless).

Example:

```json
{
  "filesystem": {
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".env", "*.key"]
  }
}
```
