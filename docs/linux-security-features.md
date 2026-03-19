# Linux Security Features

Greywall uses multiple layers of security on Linux, with graceful fallback when features are unavailable.

## Security Layers

| Layer | Technology | Purpose | Minimum Kernel |
|-------|------------|---------|----------------|
| 1 | **bubblewrap (bwrap)** | Namespace isolation | 3.8+ |
| 2 | **seccomp** | Syscall filtering | 3.5+ (logging: 4.14+) |
| 3 | **Landlock** | Filesystem access control | 5.13+ |
| 4 | **D-Bus isolation** | Block session bus escape | N/A (always active) |
| 5 | **eBPF monitoring** | Violation visibility | 4.15+ (requires CAP_BPF) |

## Feature Detection

Greywall automatically detects available features and uses the best available combination.

To see what features are detected:

```bash
# Check what features are available on your system
greywall --linux-features

# Example output:
# Linux Sandbox Features:
#   Kernel: 6.8
#   Bubblewrap (bwrap): true
#   Socat: true
#   Seccomp: true (log level: 2)
#   Landlock: true (ABI v4)
#   eBPF: true (CAP_BPF: true, root: true)
#
# Feature Status:
#   ✓ Minimum requirements met (bwrap + socat)
#   ✓ Landlock available for enhanced filesystem control
#   ✓ Violation monitoring available
#   ✓ eBPF monitoring available (enhanced visibility)
```

## Landlock Integration

Landlock is applied via an **embedded wrapper** approach:

1. bwrap spawns `greywall --landlock-apply -- <user-command>`
2. The wrapper applies Landlock kernel restrictions
3. The wrapper `exec()`s the user command

This provides **defense-in-depth**: both bwrap mounts AND Landlock kernel restrictions are enforced.

## Fallback Behavior

### When Landlock is not available (kernel < 5.13)

- **Impact**: No Landlock wrapper used; bwrap isolation only
- **Fallback**: Uses bwrap mount-based restrictions only
- **Security**: Still protected by bwrap's read-only mounts

### When seccomp logging is not available (kernel < 4.14)

- **Impact**: Blocked syscalls are not logged
- **Fallback**: Syscalls are still blocked, just silently
- **Workaround**: Use `dmesg` manually to check for blocked syscalls

### When eBPF is not available (no CAP_BPF/root)

- **Impact**: Filesystem violations not visible in monitor mode
- **Fallback**: Only proxy-level (network) violations are logged
- **Workaround**: Run with `sudo` or grant CAP_BPF capability

> [!NOTE]
> The eBPF monitor uses PID-range filtering (`pid >= SANDBOX_PID`) to exclude pre-existing system processes. This significantly reduces noise but isn't perfect—processes spawned after the sandbox starts may still appear.

### When network namespace is not available (containerized environments)

- **Impact**: `--unshare-net` is skipped; network is not fully isolated
- **Cause**: Running in Docker, GitHub Actions, or other environments without `CAP_NET_ADMIN`
- **Fallback**: Proxy-based routing still works; filesystem/PID/seccomp isolation still active
- **Check**: Run `greywall --linux-features` and look for "Network namespace (--unshare-net): false"
- **Workaround**: Run with `sudo`, or in Docker use `--cap-add=NET_ADMIN`

> [!NOTE]
> This is the most common "reduced isolation" scenario. Greywall automatically detects this at startup and adapts. See the troubleshooting guide for more details.

### When bwrap is not available

- **Impact**: Cannot run greywall on Linux
- **Solution**: Install bubblewrap: `apt install bubblewrap` or `dnf install bubblewrap`

### When socat is not available

- **Impact**: Cannot run greywall on Linux
- **Solution**: Install socat: `apt install socat` or `dnf install socat`

## D-Bus Session Bus Isolation

The D-Bus session bus at `/run/user/<uid>/bus` is a significant escape vector. A sandboxed process that can connect to the host's D-Bus session bus can:

- **Read arbitrary host files** via GVFS (`gio cat localtest:///path/to/secret`)
- **Read stored passwords** via gnome-keyring (`org.freedesktop.secrets`)
- **Launch processes outside the sandbox** via the Flatpak portal
- **Access documents** via the Document portal

Read-only bind mounts do not prevent `connect()` on Unix domain sockets, and Landlock (up to ABI v5) does not restrict Unix socket connections either. This means that simply mounting `/run` read-only is insufficient.

Greywall blocks the D-Bus session bus by overlaying `/run/user` with a tmpfs:

```
--ro-bind /run /run    # System /run paths (DNS, systemd)
--tmpfs /run/user      # Hide D-Bus socket, GVFS, Wayland, PipeWire, and all session sockets
```

This is always active in all sandbox modes (deny-by-default, legacy, and learning).

### What breaks with D-Bus isolation

- `notify-send` - works if `xdg-dbus-proxy` is installed (only `org.freedesktop.Notifications` is allowed); blocked otherwise
- 1Password CLI (uses D-Bus for IPC)
- Git over SSH (SSH agent socket is under `/run/user/`; use HTTPS or add `allowRead` for the socket)
- GPG commit signing (GPG agent socket is under `/run/user/`; add `allowRead` if needed)
- Wayland/PipeWire access (display server, audio; not needed for CLI tools)

### What still works

- DNS resolution (uses UDP via network bridge, not `/run` files)
- Network requests (go through proxy)
- Git over HTTPS (uses network proxy)
- All CLI tools (git, npm, cargo, go, python, etc.)

### Re-enabling SSH/GPG agent access

If your workflow requires git-over-SSH or GPG commit signing, add the agent socket paths to `allowRead` in your greywall config:

```json
{
  "filesystem": {
    "allowRead": [
      "/run/user/1000/ssh-agent.socket",
      "/run/user/1000/gnupg"
    ]
  }
}
```

Note that exposing the SSH agent socket allows the sandboxed process to authenticate to any SSH server your keys have access to. The GPG agent socket allows signing operations with your GPG keys. Neither provides a filesystem escape vector, but both grant the sandboxed process the ability to act under your identity for SSH/GPG operations.

## Blocked Syscalls (seccomp)

Greywall blocks dangerous syscalls that could be used for sandbox escape or privilege escalation:

| Syscall | Reason |
|---------|--------|
| `ptrace` | Process debugging/injection |
| `process_vm_readv/writev` | Cross-process memory access |
| `keyctl`, `add_key`, `request_key` | Kernel keyring access |
| `personality` | Can bypass ASLR |
| `userfaultfd` | Potential sandbox escape vector |
| `perf_event_open` | Information leak |
| `bpf` | eBPF without proper capabilities |
| `kexec_load/file_load` | Kernel replacement |
| `mount`, `umount2`, `pivot_root` | Filesystem manipulation |
| `init_module`, `finit_module`, `delete_module` | Kernel module loading |
| And more... | See source for complete list |

## Violation Monitoring

On Linux, violation monitoring (`greywall -m`) shows:

| Source | What it shows | Requirements |
|--------|---------------|--------------|
| `[greywall:http]` | Blocked HTTP/HTTPS requests | None |
| `[greywall:socks]` | Blocked SOCKS connections | None |
| `[greywall:ebpf]` | Blocked filesystem access + syscalls | CAP_BPF or root |

**Notes**:

- The eBPF monitor tracks sandbox processes and logs `EACCES`/`EPERM` errors from syscalls
- Seccomp violations are blocked but not logged (programs show "Operation not permitted")
- eBPF requires `bpftrace` to be installed: `sudo apt install bpftrace`

## Comparison with macOS

| Feature | macOS (Seatbelt) | Linux (greywall) |
|---------|------------------|---------------|
| Filesystem control | Native | bwrap + Landlock |
| Glob patterns | Native regex | Expanded at startup |
| Network isolation | Syscall filtering | Network namespace |
| Syscall filtering | Implicit | seccomp (27 blocked) |
| Violation logging | log stream | eBPF (PID-filtered) |
| Root required | No | No (eBPF monitoring: yes) |

## Kernel Version Reference

| Distribution | Default Kernel | Landlock | seccomp LOG | eBPF |
|--------------|----------------|----------|-------------|------|
| Ubuntu 24.04 | 6.8 | ✅ v4 | ✅ | ✅ |
| Ubuntu 22.04 | 5.15 | ✅ v1 | ✅ | ✅ |
| Ubuntu 20.04 | 5.4 | ❌ | ✅ | ✅ |
| Debian 12 | 6.1 | ✅ v2 | ✅ | ✅ |
| Debian 11 | 5.10 | ❌ | ✅ | ✅ |
| RHEL 9 | 5.14 | ✅ v1 | ✅ | ✅ |
| RHEL 8 | 4.18 | ❌ | ✅ | ✅ |
| Fedora 40 | 6.8 | ✅ v4 | ✅ | ✅ |
| Arch Linux | Latest | ✅ | ✅ | ✅ |

## Installing Dependencies

### Debian/Ubuntu

```bash
sudo apt install bubblewrap socat xdg-dbus-proxy
```

### Fedora/RHEL

```bash
sudo dnf install bubblewrap socat xdg-dbus-proxy
```

### Arch Linux

```bash
sudo pacman -S bubblewrap socat xdg-dbus-proxy
```

### Alpine Linux

```bash
sudo apk add bubblewrap socat xdg-dbus-proxy
```

`xdg-dbus-proxy` is optional but recommended. Without it, `notify-send` will not work inside the sandbox.

## Enabling eBPF Monitoring

For full violation visibility without root:

```bash
# Grant CAP_BPF to the greywall binary
sudo setcap cap_bpf+ep /usr/local/bin/greywall
```

Or run greywall with sudo when monitoring is needed:

```bash
sudo greywall -m <command>
```
