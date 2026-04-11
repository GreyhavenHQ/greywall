---
id: faq
title: FAQ
---

# Frequently Asked Questions

## General

### Does greywall work inside Docker containers?

Partially. Inside Docker, network namespace isolation (`--unshare-net`) is typically unavailable without `--cap-add=NET_ADMIN`. Greywall detects this and falls back automatically:

- Filesystem isolation via bubblewrap still works
- Command blocking still works
- Network routing falls back to proxy environment variables (`HTTP_PROXY`, `ALL_PROXY`)
- Programs that ignore proxy env vars won't be network-isolated in this mode

Run `greywall --linux-features` to see what's available in your environment. For CI environments like GitHub Actions, this fallback is normal and expected.

If you need full network isolation in Docker, add `--cap-add=NET_ADMIN` to your container.

### Does greywall work on Windows?

No. Greywall requires macOS or Linux. It depends on `sandbox-exec` (macOS) or `bubblewrap` (Linux) for OS-level sandboxing — neither is available on Windows.

### Can I use greywall without greyproxy?

Yes. Greywall can point at **any** SOCKS5 proxy:

```bash
greywall --proxy socks5://my-proxy:1080 -- npm install
```

If no proxy is configured or running, all outbound network access is blocked — which is often exactly what you want for an offline build or test run.

[Greyproxy](../greyproxy) is the recommended companion because it adds a live dashboard and rule engine, but it's optional.

### Why is macOS network isolation weaker than Linux?

On Linux, greywall creates a separate **network namespace** and routes all traffic through `tun2socks`, capturing everything regardless of whether applications respect proxy environment variables.

On macOS, there is no equivalent user-accessible network namespace. Greywall sets `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` environment variables. Applications that don't honor these (e.g., some native binaries, Node.js with certain HTTP libraries) can bypass network isolation.

This is a fundamental macOS limitation, not a greywall limitation. For workloads where full traffic capture matters, run them on Linux.

### What's the performance overhead?

It depends on how you use greywall:

**For long-running agents** (`greywall -- claude`): startup cost is paid once (Linux: ~215ms, macOS: ~22ms). Child process tool calls run at native speed. For agent use cases, the overhead is negligible.

**For per-command invocations** (`greywall -c "command"`): each invocation pays the full startup cost. On Linux this is ~215ms per command; on macOS ~22ms. For scripts running dozens of commands, this can add up.

See [Benchmarking](./benchmarking) for detailed numbers.

---

## Installation

### Do I need `sudo` to run greywall?

No, for most Linux systems. Package-manager-installed `bubblewrap` is typically setuid, so greywall works as a regular user.

Some features require elevated privileges:

- **eBPF violation monitoring** (`-m` on Linux): requires `CAP_BPF` or root. You can grant it without running as root: `sudo setcap cap_bpf+ep $(which greywall)`
- **Learning mode on macOS**: `eslogger` (used to trace filesystem access) requires `sudo`. Only the `eslogger` process runs as root; the sandboxed command runs as the current user.

### `bwrap` isn't found after installing bubblewrap

On some systems the binary is called `bwrap`. Check:

```bash
which bwrap
```

If it's installed but not on your PATH, add its location:

```bash
export PATH="/usr/sbin:$PATH"
```

### I installed greywall via `go install` but the binary isn't found

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

Add this to your shell profile (`.bashrc`, `.zshrc`, etc.) to make it permanent.

---

## Configuration

### Where does greywall look for its config file?

| Platform | Default path |
|----------|-------------|
| Linux | `~/.config/greywall/greywall.json` |
| macOS | `~/Library/Application Support/greywall/greywall.json` |
| Legacy | `~/.greywall.json` |

Override with `--settings <path>` or `-s <path>`.

### What happens if there's no config file?

Greywall uses restrictive defaults: all network access is blocked, filesystem writes are denied, and the default command deny list is active. The current working directory is readable and writable.

### Can I commit my greywall config to the repo?

Yes — that's a good practice. Store it as `greywall.json` at the repo root and reference it with:

```bash
greywall -s ./greywall.json -- <command>
```

This ensures all developers and CI environments use the same policy.

### How do I allow a specific domain?

Greywall delegates domain filtering to the external SOCKS5 proxy (e.g., greyproxy). Configure allow rules in the [Greyproxy dashboard](../greyproxy/dashboard) or via the [Greyproxy API](../greyproxy/api) — not in the greywall config itself.

To route traffic through greyproxy:

```json
{
  "network": {
    "proxyUrl": "socks5://localhost:43052"
  }
}
```

### How does `denyWrite` interact with `allowWrite`?

`denyWrite` always wins. Even if a path is listed in `allowWrite`, adding it to `denyWrite` blocks it. This lets you protect sensitive files within an otherwise writable directory:

```json
{
  "filesystem": {
    "allowWrite": ["."],
    "denyWrite": [".env", ".git/hooks"]
  }
}
```

---

## Behavior

### A command is being blocked but I don't know why

Run with `-m` (monitor mode) to see what's blocked:

```bash
greywall -m -- your-command
```

Add `-d` (debug) to also see the full sandbox command and proxy decisions:

```bash
greywall -m -d -- your-command
```

### My command needs to connect to localhost services (Redis, Postgres, etc.)

On **macOS**, the sandbox shares the host network stack, so enabling `allowLocalOutbound` is enough:

```json
{
  "network": {
    "allowLocalOutbound": true
  }
}
```

On **Linux**, the sandbox runs in an isolated network namespace and `allowLocalOutbound` has no effect. Forward the specific host ports into the sandbox instead:

```bash
# CLI
greywall -f 5432 -f 6379 -- your-command
```

```json
// Config
{
  "network": {
    "forwardPorts": [5432, 6379]
  }
}
```

You can also apply the `local-dev-server` profile, which enables binding (and `allowLocalOutbound` on macOS):

```bash
greywall --profile local-dev-server -- your-command
```

### Can greywall detect what filesystem paths a command needs automatically?

Yes — that's what [Learning Mode](./learning-mode) is for. Run with `--learning` and greywall traces all filesystem access, then generates a config template:

```bash
greywall --learning -- your-command
```

### Does greywall sandbox child processes too?

Yes. All processes spawned by the sandboxed command inherit the sandbox restrictions. There's no way for a child process to escape to an unsandboxed environment.

### The GREYWALL_SANDBOX env var — what is it for?

Commands running inside a greywall sandbox have `GREYWALL_SANDBOX=1` set in their environment. You can use this in scripts to detect whether they're running sandboxed:

```bash
if [ "$GREYWALL_SANDBOX" = "1" ]; then
  echo "Running inside greywall"
fi
```

---

## Security

### Is greywall suitable for running untrusted/malicious code?

No. Greywall is defense-in-depth for **semi-trusted** code — supply-chain scripts, unfamiliar repos, AI agents. It is not designed to contain actively malicious code attempting to escape:

- It doesn't prevent resource exhaustion (CPU, memory, disk)
- It doesn't prevent data exfiltration to *allowed* domains
- It doesn't guard against kernel exploits or privilege escalation

See [Security Model](./security-model) for the full threat model.

### Does greywall protect against LD_PRELOAD attacks?

Yes. Greywall strips `LD_PRELOAD`, `LD_LIBRARY_PATH`, and related environment variables before running sandboxed commands. This prevents a sandboxed process from writing a malicious `.so` file and then injecting it into subsequent commands via `LD_PRELOAD`. See [Security Model](./security-model#environment-sanitization).

### Can greywall prevent a sandboxed process from writing to its own source files?

Yes — use `denyWrite` with the repo root, or just don't include the repo in `allowWrite`. By default, writes are only allowed to paths explicitly listed in `allowWrite`.

---

## Greywall vs Alternatives

### Greywall vs Firejail

[Firejail](https://github.com/netblue30/firejail) is a mature Linux sandbox focused on desktop application isolation (browsers, media players). Key differences:

- Greywall is designed for **command-line tools and build workflows**, not desktop apps
- Greywall has first-class support for **macOS** via `sandbox-exec`; Firejail is Linux-only
- Greywall delegates network filtering to an external proxy (greyproxy), giving you a **live dashboard** and interactive allow/deny
- Firejail has 1000+ pre-built app profiles; greywall's `--learning` mode generates profiles automatically

### Greywall vs `docker run --network none`

Docker with `--network none` gives you strong network isolation, but:

- Requires Docker to be installed and a container image prepared
- Cold start is much higher (container spin-up vs ~22–215ms for greywall)
- Filesystem access requires volume mounts
- Not practical for wrapping arbitrary CLI commands in a dev workflow

Greywall wraps any command transparently with no container setup.

### Greywall vs macOS Sandbox Profiles

macOS `sandbox-exec` with a hand-written Seatbelt profile can achieve similar results — greywall *is* doing exactly that under the hood. The difference is greywall generates the profile dynamically from a simple JSON config and handles the proxy routing, monitoring, and learning mode on top.
