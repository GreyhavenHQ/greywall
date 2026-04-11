---
id: concepts
title: Concepts
---

# Concepts

Greywall combines two ideas:

1. **An OS sandbox** that blocks direct network access and restricts filesystem operations.
2. **Delegated network filtering** through an external SOCKS5 proxy, by default [Greyproxy](/greyproxy).

## Network Model

Greywall does not run its own proxy and does not decide which hosts are allowed. The sandbox blocks direct outbound traffic at the OS layer, and the only reachable network endpoint from inside the sandbox is a SOCKS5 proxy. Every rule, every allowlist, every decision about what can talk to what lives in that proxy.

By default, greywall points at [Greyproxy](/greyproxy) at `socks5://localhost:43052` with DNS at `localhost:43053`. If no proxy is running, the sandbox has no network at all. You can point at any SOCKS5 proxy with `--proxy <url>` or the `proxyUrl` config key.

How traffic reaches the proxy depends on the platform:

- **Linux**: the sandbox runs in an isolated network namespace (`bubblewrap --unshare-net`) with a TUN device inside. All traffic is captured by `tun2socks` and forwarded to the external proxy over a Unix-socket bridge. This works for any process regardless of whether it honors proxy environment variables. If TUN is unavailable, greywall falls back to setting `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY`.
- **macOS**: the Seatbelt profile blocks direct outbound connections and greywall sets `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` to point at the proxy. Applications that honor those variables are routed through it. Applications that ignore them (for example Node.js's built-in `http`/`https`) are blocked by the sandbox rather than silently bypassing the proxy.

Because filtering lives in the proxy, domain allowlists, rule changes, and live approval all happen in the proxy's dashboard or API, not in the greywall config. See [Greyproxy](/greyproxy) for how that side works.

### Localhost Controls

- `allowLocalBinding`: lets a sandboxed process *listen* on local ports (e.g., dev servers).
- `allowLocalOutbound`: lets a sandboxed process connect to host `localhost` services (macOS only; see below).
- `-p/--port`: exposes inbound ports so things outside the sandbox can reach your server.
- `-f/--forward`: forwards a host localhost port *into* the sandbox (Linux only).
- `forwardPorts`: config-file equivalent of `-f` for specifying ports to forward.

These are separate on purpose. A typical safe default for dev servers is:

- allow binding + expose just the needed port(s)
- disallow localhost outbound unless you explicitly need it

### Port forwarding: platform differences

On macOS, the sandbox shares the host network stack, so `allowLocalOutbound: true` is enough for the sandboxed process to reach any host localhost service.

On Linux, the sandbox runs in an isolated network namespace (bubblewrap `--unshare-net`). The host's `localhost` is not reachable from inside the sandbox. To connect to a specific host service, you must explicitly forward its port with `-f` (or `forwardPorts` in the config file).

| Feature | macOS | Linux |
|---------|-------|-------|
| Sandbox connects to host `localhost` | `allowLocalOutbound: true` | `-f <port>` or `forwardPorts: [port]` |
| Host connects to sandbox port | `-p <port>` | `-p <port>` |
| Sandbox listens on local port | `allowLocalBinding: true` | `allowLocalBinding: true` |

For example, connecting to a Postgres server running on port 5432 of the host:

```bash
# macOS: allowLocalOutbound in the config is enough
greywall -- psql -h localhost

# Linux: the specific port must be forwarded
greywall -f 5432 -- psql -h localhost
```

## Filesystem Model

Greywall uses a deny-by-default model for both reads and writes:

- **Reads**: denied by default (`defaultDenyRead` is `true` when not set). Only system paths, the current working directory, and paths listed in `allowRead` are accessible.
- **Writes**: denied by default (you must opt-in with `allowWrite`).
- **denyWrite**: overrides `allowWrite` (useful for protecting secrets and dangerous files).

Use `--learning` mode to automatically discover the read/write paths a command needs and generate a config template. See [Learning Mode](./learning-mode) for details.

Greywall also protects some dangerous targets regardless of config (e.g., shell startup files, git hooks, `.env` files).

## Debug vs Monitor Mode

- `-d/--debug`: verbose output (proxy activity, filter decisions, sandbox command details).
- `-m/--monitor`: show blocked requests/violations only (great for auditing and policy tuning).

Workflow tip:

1. Start restrictive.
2. Run with `-m` to see what gets blocked.
3. Add the minimum domains/paths required.

## Platform Notes

- **macOS**: uses `sandbox-exec` with generated Seatbelt profiles; the sandbox shares the host network stack and relies on proxy environment variables to route outbound traffic through greyproxy.
- **Linux**: uses `bubblewrap` for namespace isolation with a TUN device inside the sandbox, so `tun2socks` captures every outbound connection and forwards it to greyproxy through a Unix-socket bridge.

For the under-the-hood view, see [Architecture](./architecture).
