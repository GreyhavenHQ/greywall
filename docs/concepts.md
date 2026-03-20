# Concepts

Greywall combines two ideas:

1. **An OS sandbox** to enforce "no direct network" and restrict filesystem operations.
2. **Local filtering proxies** (HTTP + SOCKS5) to selectively allow outbound traffic by domain.

## Network model

By default, greywall blocks all outbound network access.

When you allow domains, greywall:

- Starts local HTTP and SOCKS5 proxies
- Sets proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`)
- Allows the sandboxed process to connect only to the local proxies
- Filters outbound connections by **destination domain**

### Localhost controls

- `allowLocalBinding`: lets a sandboxed process *listen* on local ports (e.g. dev servers).
- `allowLocalOutbound`: lets a sandboxed process connect to `localhost` services (macOS only).
- `-p/--port`: exposes inbound ports so things outside the sandbox can reach your server.
- `-f/--forward`: forwards a host localhost port into the sandbox (Linux only).
- `forwardPorts`: config equivalent of `-f` for specifying ports to forward.

These are separate on purpose. A typical safe default for dev servers is:

- allow binding + expose just the needed port(s)
- disallow localhost outbound unless you explicitly need it

### Port forwarding: platform differences

On macOS, the sandbox shares the host network stack, so `allowLocalOutbound: true` is enough for the sandboxed process to connect to any host localhost service.

On Linux, the sandbox runs in an isolated network namespace (bubblewrap `--unshare-net`). The host's `localhost` is not reachable from inside the sandbox. To connect to a specific host service, you must explicitly forward its port:

| Feature | macOS | Linux |
|---------|-------|-------|
| Sandbox connects to host `localhost` | `allowLocalOutbound: true` | `-f <port>` or `forwardPorts: [port]` |
| Host connects to sandbox port | `-p <port>` | `-p <port>` |
| Sandbox listens on local port | `allowLocalBinding: true` | `allowLocalBinding: true` |

Example: connecting to a local database on port 5432 from a sandboxed command:

```bash
# macOS (allowLocalOutbound in config is sufficient)
greywall -- psql -h localhost

# Linux (must forward the specific port)
greywall -f 5432 -- psql -h localhost
```

## Filesystem model

Greywall uses a deny-by-default model for both reads and writes:

- **Reads**: denied by default (`defaultDenyRead` is `true` when not set). Only system paths, the current working directory, and paths listed in `allowRead` are accessible. You can use `denyRead` to block specific paths even within allowed areas.
- **Writes**: denied by default (you must opt-in with `allowWrite`).
- **denyWrite**: overrides `allowWrite` (useful for protecting secrets and dangerous files).

Use `--learning` mode to automatically discover the read/write paths a command needs and generate a config template. See [Learning Mode](learning.md) for details.

Greywall also protects some dangerous targets regardless of config (e.g. shell startup files, git hooks, `.env` files). See `ARCHITECTURE.md` for the full list.

## Debug vs Monitor mode

- `-d/--debug`: verbose output (proxy activity, filter decisions, sandbox command details).
- `-m/--monitor`: show blocked requests/violations only (great for auditing and policy tuning).

Workflow tip:

1. Start restrictive.
2. Run with `-m` to see what gets blocked.
3. Add the minimum domains/paths required.

## Platform notes

- **macOS**: uses `sandbox-exec` with generated Seatbelt profiles.
- **Linux**: uses `bubblewrap` for namespaces + `socat` bridges to connect the isolated network namespace to host-side proxies.

If you want the under-the-hood view, see [Architecture](../ARCHITECTURE.md).
