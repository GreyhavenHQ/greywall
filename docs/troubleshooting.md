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

This error occurs when greywall tries to create a network namespace but the environment lacks the `CAP_NET_ADMIN` capability. This is common in:

- **Docker containers** (unless run with `--privileged` or `--cap-add=NET_ADMIN`)
- **GitHub Actions** and other CI runners
- **Ubuntu 24.04+** with restrictive AppArmor policies
- **Kubernetes pods** without elevated security contexts

**What happens now:**

Greywall automatically detects this limitation and falls back to running **without network namespace isolation**. The sandbox still provides:

- Filesystem restrictions (read-only root, allowWrite paths)
- PID namespace isolation
- Seccomp syscall filtering
- Landlock (if available)

**What's reduced:**

- Network isolation via namespace is skipped
- Proxy-based routing still works (via `HTTP_PROXY`/`HTTPS_PROXY` env vars)
- But programs that bypass proxy env vars won't be network-isolated

**To check if your environment supports network namespaces:**

```bash
greywall --linux-features
```

Look for "Network namespace (--unshare-net): true/false"

**Solutions if you need full network isolation:**

1. **Run with elevated privileges:**

   ```bash
   sudo greywall <command>
   ```

2. **In Docker, add capability:**

   ```bash
   docker run --cap-add=NET_ADMIN ...
   ```

3. **In GitHub Actions**, this typically isn't possible without self-hosted runners with elevated permissions.

4. **On Ubuntu 24.04+**, you may need to modify AppArmor profiles (see [Ubuntu bug 2069526](https://bugs.launchpad.net/bugs/2069526)).

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

## Node.js HTTP(S) and proxy env vars

Node's built-in `http`/`https` modules ignore `HTTP_PROXY`/`HTTPS_PROXY`. With greywall's default TUN-based transparent proxying, this is not an issue — all traffic is routed through the proxy regardless of whether the application respects proxy environment variables.

If TUN is unavailable (fallback mode), Node apps that make direct HTTP(S) requests will need a proxy-aware client like `undici` with `ProxyAgent` to route through the proxy.

## Local services (Redis/Postgres/etc.) fail inside the sandbox

If your process needs to connect to `localhost` services, set:

```json
{
  "network": { "allowLocalOutbound": true }
}
```

If you're running a server inside the sandbox that must accept connections:

- set `network.allowLocalBinding: true` (to bind)
- use `-p <port>` (to expose inbound port(s))

## notify-send fails inside sandbox

`notify-send` requires the D-Bus session bus, which is blocked to prevent sandbox escape via GVFS/gnome-keyring. Install `xdg-dbus-proxy` to enable it:

```bash
# Ubuntu/Debian
sudo apt install xdg-dbus-proxy

# Fedora
sudo dnf install xdg-dbus-proxy

# Arch
sudo pacman -S xdg-dbus-proxy
```

When installed, greywall automatically starts a filtered D-Bus proxy that only allows `org.freedesktop.Notifications`, blocking all other services. Run `greywall check` to verify.

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
