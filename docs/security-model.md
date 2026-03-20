# Security Model

Greywall is intended as defense-in-depth for running semi-trusted commands with reduced side effects (package installs, build scripts, CI jobs, unfamiliar repos).

It is not designed to be a strong isolation boundary against actively malicious code that is attempting to escape.

## Threat model (what Greywall helps with)

Greywall is useful when you want to reduce risk from:

- Supply-chain scripts that unexpectedly call out to the network
- Tools that write broadly across your filesystem
- Accidental leakage of secrets via "phone home" behavior
- Unfamiliar repos that run surprising commands during install/build/test

## What Greywall enforces

### Network

- **Default deny**: outbound network is blocked unless routed through the proxy.
- **Transparent proxying**: all traffic is routed through an external SOCKS5 proxy via a TUN device (using `tun2socks`). The proxy (e.g., [GreyProxy](https://github.com/greyhavenhq/greyproxy)) handles domain filtering and access control.
- **Localhost controls**: inbound binding and localhost outbound are separately controlled.

Important: greywall does not perform domain filtering itself. Access control is delegated to the external proxy.

#### How network isolation works

Greywall combines OS-level enforcement with transparent SOCKS5 proxying:

- The OS sandbox / network namespace blocks direct outbound connections.
- A TUN device inside the sandbox routes all traffic through `tun2socks`, which forwards it to the external SOCKS5 proxy via a Unix socket bridge.
- If TUN is unavailable, greywall falls back to setting proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`).

Localhost is separate from external traffic:

- `allowLocalOutbound=false` can intentionally block connections to local services like Redis on `127.0.0.1:6379` (see the dev-server example).

### Filesystem

- **Reads are denied by default** (`defaultDenyRead` is `true` when not set); only system paths, the current working directory, and explicitly allowed paths (`allowRead`) are accessible.
- **Writes are denied by default**; you must opt in with `allowWrite`.
- **denyWrite** can block specific files/patterns even if the parent directory is writable.
- **denyRead** can block reads from specific paths even within allowed areas.
- Greywall includes an internal list of always-protected targets (e.g. shell configs, git hooks, `.env` files) to reduce common persistence vectors.

### D-Bus isolation (Linux)

The D-Bus session bus is blocked inside the sandbox. Without this, a sandboxed process can use the host's GVFS daemon to read arbitrary files, access gnome-keyring passwords, or launch processes outside the sandbox. Greywall overlays `/run/user` with a tmpfs, blocking all user session sockets (D-Bus, Wayland, PipeWire, SSH agent, GPG agent). SSH/GPG agent sockets can be selectively re-added via `allowRead` if needed, though this grants the sandbox the ability to authenticate under your identity.

### Environment sanitization

Greywall strips dangerous environment variables before passing them to sandboxed commands:

- `LD_*` (Linux): `LD_PRELOAD`, `LD_LIBRARY_PATH`, etc.
- `DYLD_*` (macOS): `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, etc.

This prevents a library injection attack where a sandboxed process writes a malicious `.so`/`.dylib` and then uses `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` in a subsequent command to load it.

## Visibility / auditing

- `-m/--monitor` helps you discover what a command *tries* to access (blocked only).
- `-d/--debug` shows more detail to understand why something was blocked.

## Limitations (what Greywall does NOT try to solve)

- **Hostile code containment**: assume determined attackers may escape via kernel/OS vulnerabilities.
- **Resource limits**: CPU, memory, disk, fork bombs, etc. are out of scope.
- **Content-based controls**: Greywall does not block data exfiltration to *allowed* destinations.
- **TUN fallback limitations**: when the TUN device is unavailable, greywall falls back to proxy environment variables. Programs that ignore these variables (e.g. Node.js native `http`/`https`) won't be network-isolated in fallback mode.

### Content inspection

Greywall does not inspect request content. Access control is delegated to the external proxy.

### Not a hostile-code containment boundary

Greywall is defense-in-depth for running semi-trusted code, not a strong isolation boundary against malware designed to escape sandboxes.

For implementation details (how proxies/sandboxes/bridges work), see [`ARCHITECTURE.md`](../ARCHITECTURE.md).
