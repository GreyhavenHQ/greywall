# Platform Support

Greywall supports Linux and macOS with platform-specific sandboxing technologies.

## Feature comparison

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
| **Credential substitution (env vars)** | ✅ | ✅ |
| **Credential substitution (.env files)** | ✅ (bind-mount rewrite) | ⚠️ (files denied; see below) |
| **Environment sanitization** | ✅ | ✅ |
| **Learning mode** | ✅ (strace) | ✅ (eslogger, requires sudo) |
| **PTY support** | ✅ | ✅ |
| **External deps** | bwrap, socat, xdg-dbus-proxy (optional) | none |

## Linux

Greywall uses [bubblewrap](https://github.com/containers/bubblewrap) for container-free sandboxing, layering multiple kernel security features:

- **seccomp** — BPF-based syscall filtering to block dangerous syscalls
- **Landlock** — kernel filesystem access control (Linux 5.13+), restricts file operations independently of bubblewrap mount rules
- **D-Bus isolation** — blocks the session bus to prevent sandbox escape via GVFS file reads, gnome-keyring password access, and Flatpak portal process launch
- **eBPF** — real-time violation monitoring for blocked syscalls and file access attempts
- **Network namespace** — full network isolation via `unshare-net`; all traffic flows through tun2socks into the SOCKS5 proxy
- **DNS bridge** — socat relay that captures DNS queries inside the namespace and forwards them to a configured DNS server

All features degrade gracefully when the kernel or permissions don't support them. Run `greywall --linux-features` to see what's available on your system.

**Dependencies:** `bubblewrap`, `socat`, `xdg-dbus-proxy` (optional, for notify-send support)

## macOS

Greywall uses `sandbox-exec` with dynamically generated [Seatbelt](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) profiles. The Seatbelt profile controls file reads/writes, network access, process operations, and Mach IPC.

Network traffic is routed through greyproxy via `ALL_PROXY` / `HTTP_PROXY` environment variables. There is no full traffic capture (no TUN device or DNS bridge) — only applications that honor proxy environment variables are redirected.

Learning mode uses Apple's Endpoint Security framework via `eslogger` to trace filesystem access. This requires `sudo` (only `eslogger` runs as root, the sandboxed command runs as the current user).

**Dependencies:** none (sandbox-exec and eslogger ship with macOS)

### `.env` file credential substitution on macOS

On Linux, greywall uses bubblewrap's `--ro-bind` to mount rewritten `.env` files (containing credential placeholders) over the originals. The sandboxed process reads `.env` as usual and gets placeholder values transparently.

macOS lacks bind-mount namespaces. Seatbelt profiles can control whether a file is readable but cannot redirect reads to a different file. As a result, `.env` files are **denied entirely** in the sandbox profile when credential substitution is active. The sandboxed process receives a permission-denied error if it tries to read them.

This affects applications that read credentials from `.env` files on disk rather than from environment variables. Environment variable substitution works identically on both platforms.

**Workaround**: use `--inject` to provide credentials as environment variables (with placeholder values) instead of relying on `.env` files. See [credential-protection.md](credential-protection.md) for details.
