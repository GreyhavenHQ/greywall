# Architecture

Greywall restricts network, filesystem, and command access for arbitrary commands. It works by:

1. **Blocking commands** via configurable deny/allow lists before execution
2. **Routing network traffic** through an external SOCKS5 proxy (e.g., [GreyProxy](https://github.com/greyhavenhq/greyproxy)) via transparent TUN-based proxying
3. **Sandboxing processes** using OS-native mechanisms (macOS sandbox-exec, Linux bubblewrap)
4. **Sanitizing environment** by stripping dangerous variables (LD_PRELOAD, DYLD_INSERT_LIBRARIES, etc.)

```mermaid
flowchart TB
    subgraph Greywall
        Config["Config<br/>(JSON)"]
        Manager
        CmdCheck["Command<br/>Blocking"]
        EnvSanitize["Env<br/>Sanitization"]
        Sandbox["Platform Sandbox<br/>(macOS/Linux)"]
    end

    subgraph External
        Proxy["SOCKS5 Proxy<br/>(e.g. GreyProxy)"]
        DNS["DNS Server"]
    end

    Config --> Manager
    Manager --> CmdCheck
    CmdCheck --> EnvSanitize
    EnvSanitize --> Sandbox
    Sandbox -->|tun2socks| Proxy
    Sandbox -->|DNS bridge| DNS
```

## Project Structure

```text
greywall/
├── cmd/greywall/           # CLI entry point
│   └── main.go          # Includes --landlock-apply wrapper mode
├── internal/            # Private implementation
│   ├── config/          # Configuration loading/validation
│   ├── platform/        # OS detection
│   ├── proxy/           # GreyProxy detection, installation, and lifecycle
│   └── sandbox/         # Platform-specific sandboxing
│       ├── manager.go   # Orchestrates sandbox lifecycle
│       ├── macos.go     # macOS sandbox-exec profiles
│       ├── linux.go     # Linux bubblewrap + socat bridges + D-Bus proxy
│       ├── linux_seccomp.go    # Seccomp BPF syscall filtering
│       ├── linux_landlock.go   # Landlock filesystem control
│       ├── linux_ebpf.go       # eBPF violation monitoring
│       ├── linux_features.go   # Kernel feature detection
│       ├── linux_*_stub.go     # Non-Linux build stubs
│       ├── monitor.go   # macOS log stream violation monitoring
│       ├── command.go   # Command blocking/allow lists
│       ├── hardening.go # Environment sanitization
│       ├── dangerous.go # Protected file/directory lists
│       ├── shell.go     # Shell quoting utilities
│       └── utils.go     # Path normalization
└── pkg/greywall/           # Public Go API
    └── greywall.go
```

## Core Components

### Config (`internal/config/`)

Handles loading and validating sandbox configuration:

```go
type Config struct {
    Network    NetworkConfig    // Proxy URL, DNS, localhost controls
    Filesystem FilesystemConfig // Read/write restrictions
    Command    CommandConfig    // Command deny/allow lists
    AllowPty   bool             // Allow pseudo-terminal allocation
}
```

- Loads from XDG config dir (`~/.config/greywall/greywall.json` or `~/Library/Application Support/greywall/greywall.json`) or custom path
- Falls back to restrictive defaults (block all network, default command deny list)
- Validates paths and normalizes them

### Platform (`internal/platform/`)

Simple OS detection:

```go
func Detect() Platform  // Returns MacOS, Linux, Windows, or Unknown
func IsSupported() bool // True for MacOS and Linux
```

### Proxy (`internal/proxy/`)

Manages the external GreyProxy lifecycle (detection, installation, startup):

- `detect.go` - Checks if greyproxy is installed and running (health endpoint)
- `install.go` - Downloads and installs greyproxy from GitHub releases
- `start.go` - Starts the greyproxy service

Domain filtering and access control are handled entirely by the external proxy, not by greywall.

### Sandbox (`internal/sandbox/`)

#### Manager (`manager.go`)

Orchestrates the sandbox lifecycle:

1. Sets up proxy and DNS bridges to the external SOCKS5 proxy (Linux)
2. Extracts embedded `tun2socks` binary for transparent proxying
3. Checks command against deny/allow lists
4. Wraps commands with sandbox restrictions
5. Handles cleanup on exit

#### Command Blocking (`command.go`)

Blocks commands before they run based on configurable policies:

- **Default deny list**: Dangerous system commands (`shutdown`, `reboot`, `mkfs`, `rm -rf`, etc.)
- **Custom deny/allow**: User-configured prefixes (e.g., `git push`, `npm publish`)
- **Chain detection**: Parses `&&`, `||`, `;`, `|` to catch blocked commands in pipelines
- **Nested shells**: Detects `bash -c "blocked_cmd"` patterns

#### Environment Sanitization (`hardening.go`)

Strips dangerous environment variables before command execution:

- Linux: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, etc.
- macOS: `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, etc.

This prevents library injection attacks where a sandboxed process writes a malicious `.so`/`.dylib` and uses `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` in a subsequent command.

#### macOS Implementation (`macos.go`)

Uses Apple's `sandbox-exec` with Seatbelt profiles:

```mermaid
flowchart LR
    subgraph macOS Sandbox
        CMD["User Command"]
        SE["sandbox-exec -p profile"]
        ENV["Environment Variables<br/>HTTP_PROXY, HTTPS_PROXY<br/>ALL_PROXY, GIT_SSH_COMMAND"]
    end

    subgraph Profile Controls
        NET["Network: deny except localhost"]
        FS["Filesystem: read/write rules"]
        PROC["Process: fork/exec permissions"]
    end

    CMD --> SE
    SE --> ENV
    SE -.-> NET
    SE -.-> FS
    SE -.-> PROC
```

Seatbelt profiles are generated dynamically based on config:

- `(deny default)` - deny all by default
- `(allow network-outbound (remote ip "localhost:*"))` - only allow proxy
- `(allow file-read* ...)` - selective file access
- `(allow process-fork)`, `(allow process-exec)` - allow running programs

#### Linux Implementation (`linux.go`)

Uses `bubblewrap` (bwrap) with network namespace isolation and transparent SOCKS5 proxying:

```mermaid
flowchart TB
    subgraph Host
        PROXY["External SOCKS5 Proxy<br/>(e.g. GreyProxy :43052)"]
        DNS["DNS Server<br/>(:43053)"]
        PSOCAT["socat<br/>(proxy bridge)"]
        DSOCAT["socat<br/>(DNS bridge)"]
        USOCK["Unix Sockets<br/>/tmp/greywall-*.sock"]
    end

    subgraph Sandbox ["Sandbox (bwrap --unshare-net)"]
        CMD["User Command"]
        TUN["tun2socks<br/>(TUN device)"]
        ISOCAT["socat<br/>(relay)"]
    end

    PROXY <--> PSOCAT
    DNS <--> DSOCAT
    PSOCAT <--> USOCK
    DSOCAT <--> USOCK
    USOCK <-->|bind-mounted| ISOCAT
    CMD -->|all traffic| TUN
    TUN --> ISOCAT
```

**How it works:**

With `--unshare-net`, the sandbox has its own isolated network namespace. Unix sockets provide filesystem-based IPC across namespace boundaries:

1. Host creates Unix sockets, connects via socat to the external SOCKS5 proxy and DNS server
2. Socket files are bind-mounted into the sandbox
3. Inside the sandbox, a TUN device routes all traffic through `tun2socks`, which forwards to the external proxy via the Unix socket bridge
4. If TUN is unavailable, greywall falls back to setting proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`)

## Inbound Connections (Reverse Bridge)

For servers running inside the sandbox that need to accept connections:

```mermaid
flowchart TB
    EXT["External Request"]

    subgraph Host
        HSOCAT["socat<br/>TCP-LISTEN:8888"]
        USOCK["Unix Socket<br/>/tmp/greywall-rev-8888-*.sock"]
    end

    subgraph Sandbox
        ISOCAT["socat<br/>UNIX-LISTEN"]
        APP["App Server<br/>:8888"]
    end

    EXT --> HSOCAT
    HSOCAT -->|UNIX-CONNECT| USOCK
    USOCK <-->|shared via bind /| ISOCAT
    ISOCAT --> APP
```

Flow:

1. Host socat listens on TCP port (e.g., 8888)
2. Sandbox socat creates Unix socket, forwards to app
3. External request → Host:8888 → Unix socket → Sandbox socat → App:8888

## Execution Flow

```mermaid
flowchart TD
    A["1. CLI parses arguments"] --> B["2. Load config from XDG config dir"]
    B --> C["3. Create Manager"]
    C --> D["4. Manager.Initialize()"]

    D --> D1["Extract tun2socks binary"]
    D --> D2["[Linux] Create proxy bridge (socat → external SOCKS5)"]
    D --> D3["[Linux] Create DNS bridge (socat → DNS server)"]
    D --> D4["[Linux] Create reverse bridges (exposed ports)"]

    D1 & D2 & D3 & D4 --> E["5. Manager.WrapCommand()"]

    E --> E0{"Check command<br/>deny/allow lists"}
    E0 -->|blocked| ERR["Return error"]
    E0 -->|allowed| E1["[macOS] Generate Seatbelt profile"]
    E0 -->|allowed| E2["[Linux] Generate bwrap command"]

    E1 & E2 --> F["6. Sanitize env<br/>(strip LD_*/DYLD_*)"]
    F --> G["7. Execute wrapped command"]
    G --> H["8. Manager.Cleanup()"]

    H --> H1["Kill socat/tun2socks processes"]
    H --> H2["Remove Unix sockets"]
```

## Platform Comparison

| Feature | macOS | Linux |
|---------|-------|-------|
| Sandbox mechanism | sandbox-exec (Seatbelt) | bubblewrap + Landlock + seccomp |
| Network isolation | Syscall filtering | Network namespace |
| Proxy routing | Environment variables | tun2socks + socat bridges (fallback: env vars) |
| Filesystem control | Profile rules | Bind mounts + Landlock (5.13+) |
| Syscall filtering | Implicit (Seatbelt) | seccomp BPF |
| Inbound connections | Profile rules (`network-bind`) | Reverse socat bridges |
| Violation monitoring | log stream | eBPF |
| Env sanitization | Strips DYLD_* | Strips LD_* |
| Requirements | Built-in | bwrap, socat |

### Linux Security Layers

On Linux, greywall uses multiple security layers with graceful fallback:

1. bubblewrap (core isolation via Linux namespaces)
2. seccomp (syscall filtering)
3. Landlock (filesystem access control)
4. eBPF monitoring (violation visibility)

> [!NOTE]
> Seccomp blocks syscalls silently (no logging). With `-m` and root/CAP_BPF, the eBPF monitor catches these failures by tracing syscall exits that return EPERM/EACCES.

See [Linux Security Features](./docs/linux-security-features.md) for details.

## Violation Monitoring

The `-m` (monitor) flag enables real-time visibility into blocked operations. These only apply to filesystem and network operations, not blocked commands.

### Output Prefixes

| Prefix | Source | Description |
|--------|--------|-------------|
| `[greywall:logstream]` | macOS only | Kernel-level sandbox violations from `log stream` |
| `[greywall:ebpf]` | Linux only | Filesystem/syscall failures (requires CAP_BPF or root) |

### macOS Log Stream

On macOS, greywall spawns `log stream` with a predicate to capture sandbox violations:

```bash
log stream --predicate 'eventMessage ENDSWITH "_SBX"' --style compact
```

Violations include:

- `network-outbound` - blocked network connections
- `file-read*` - blocked file reads
- `file-write*` - blocked file writes

Filtered out (too noisy):

- `mach-lookup` - IPC service lookups
- `file-ioctl` - device control operations
- `/dev/tty*` writes - terminal output
- `mDNSResponder` - system DNS resolution
- `/private/var/run/syslog` - system logging

### Debug vs Monitor Mode

| Flag | Log stream | eBPF | Sandbox command |
|------|------------|------|-----------------|
| `-m` | Yes (macOS) | Yes (Linux) | No |
| `-d` | No | No | Yes |
| `-m -d` | Yes (macOS) | Yes (Linux) | Yes |

## Security Model

See [`docs/security-model.md`](docs/security-model.md) for Greywall's threat model, guarantees, and limitations.
