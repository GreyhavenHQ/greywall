---
id: library
title: Go Library Usage
---

# Library Usage (Go)

Greywall can be used as a Go library to sandbox commands programmatically.

## Installation

```bash
go get github.com/GreyhavenHQ/greywall
```

## Quick Start

```go
package main

import (
    "fmt"
    "os/exec"

    "github.com/GreyhavenHQ/greywall/pkg/greywall"
)

func main() {
    // Check platform support
    if !greywall.IsSupported() {
        fmt.Println("Sandboxing not supported on this platform")
        return
    }

    // Create config
    cfg := &greywall.Config{
        Network: greywall.NetworkConfig{
            AllowedDomains: []string{"api.example.com"},
        },
    }

    // Create and initialize manager
    manager := greywall.NewManager(cfg, false, false)
    defer manager.Cleanup()

    if err := manager.Initialize(); err != nil {
        panic(err)
    }

    // Wrap the command
    wrapped, err := manager.WrapCommand("curl https://api.example.com/data")
    if err != nil {
        panic(err)
    }

    // Execute it
    cmd := exec.Command("sh", "-c", wrapped)
    output, _ := cmd.CombinedOutput()
    fmt.Println(string(output))
}
```

## API Reference

### Functions

#### `IsSupported() bool`

Returns `true` if the current platform supports sandboxing (macOS or Linux).

```go
if !greywall.IsSupported() {
    log.Fatal("Platform not supported")
}
```

#### `DefaultConfig() *Config`

Returns a default configuration with all network blocked and deny-by-default filesystem reads enabled.

```go
cfg := greywall.DefaultConfig()
cfg.Network.AllowedDomains = []string{"example.com"}
```

#### `LoadConfig(path string) (*Config, error)`

Loads configuration from a JSON file. Supports JSONC (comments allowed).

```go
cfg, err := greywall.LoadConfig(greywall.DefaultConfigPath())
if err != nil {
    log.Fatal(err)
}
if cfg == nil {
    cfg = greywall.DefaultConfig() // File doesn't exist
}
```

#### `DefaultConfigPath() string`

Returns the default config file path (`~/.config/greywall/greywall.json` on Linux, `~/Library/Application Support/greywall/greywall.json` on macOS, with fallback to legacy `~/.greywall.json`).

#### `NewManager(cfg *Config, debug, monitor bool) *Manager`

Creates a new sandbox manager.

| Parameter | Description |
|-----------|-------------|
| `cfg` | Configuration for the sandbox |
| `debug` | Enable verbose logging (proxy activity, sandbox commands) |
| `monitor` | Log only violations (blocked requests) |

### Manager Methods

#### `Initialize() error`

Sets up sandbox infrastructure (starts HTTP and SOCKS proxies). Called automatically by `WrapCommand` if not already initialized.

```go
manager := greywall.NewManager(cfg, false, false)
defer manager.Cleanup()

if err := manager.Initialize(); err != nil {
    log.Fatal(err)
}
```

#### `WrapCommand(command string) (string, error)`

Wraps a shell command with sandbox restrictions. Returns an error if:

- The command is blocked by policy (`command.deny`)
- The platform is unsupported
- Initialization fails

```go
wrapped, err := manager.WrapCommand("npm install")
if err != nil {
    // Command may be blocked by policy
    log.Fatal(err)
}
```

#### `SetExposedPorts(ports []int)`

Sets ports to expose for inbound connections (e.g., dev servers).

```go
manager.SetExposedPorts([]int{3000, 8080})
```

#### `Cleanup()`

Stops proxies and releases resources. Always call via `defer`.

#### `HTTPPort() int` / `SOCKSPort() int`

Returns the ports used by the filtering proxies.

## Configuration Types

### Config

```go
type Config struct {
    Extends    string           // Template to extend (e.g., "code")
    Network    NetworkConfig
    Filesystem FilesystemConfig
    Command    CommandConfig
    SSH        SSHConfig
    AllowPty   bool             // Allow PTY allocation
}
```

### NetworkConfig

```go
type NetworkConfig struct {
    AllowedDomains      []string // Domains to allow (supports *.example.com)
    DeniedDomains       []string // Domains to explicitly deny
    AllowUnixSockets    []string // Specific Unix socket paths to allow
    AllowAllUnixSockets bool     // Allow all Unix socket connections
    AllowLocalBinding   bool     // Allow binding to localhost ports
    AllowLocalOutbound  *bool    // Allow outbound to localhost (defaults to AllowLocalBinding)
    HTTPProxyPort       int      // Override HTTP proxy port (0 = auto)
    SOCKSProxyPort      int      // Override SOCKS proxy port (0 = auto)
}
```

### FilesystemConfig

```go
type FilesystemConfig struct {
    DefaultDenyRead *bool    // Deny reads by default (true when nil)
    AllowRead       []string // Paths to allow reading (used with deny-by-default)
    DenyRead        []string // Paths to deny read access
    AllowWrite      []string // Paths to allow write access
    DenyWrite       []string // Paths to explicitly deny write access
    AllowGitConfig  bool     // Allow read access to ~/.gitconfig
}
```

### CommandConfig

```go
type CommandConfig struct {
    Deny        []string // Command patterns to block
    Allow       []string // Exceptions to deny rules
    UseDefaults *bool    // Use default deny list (true if nil)
}
```

### SSHConfig

```go
type SSHConfig struct {
    AllowedHosts     []string // Host patterns to allow (supports wildcards)
    DeniedHosts      []string // Host patterns to deny
    AllowedCommands  []string // Commands allowed over SSH
    DeniedCommands   []string // Commands denied over SSH
    AllowAllCommands bool     // Use denylist mode instead of allowlist
    InheritDeny      bool     // Apply global command.deny rules to SSH
}
```

## Examples

### Allow specific domains

```go
cfg := &greywall.Config{
    Network: greywall.NetworkConfig{
        AllowedDomains: []string{
            "registry.npmjs.org",
            "*.github.com",
            "api.openai.com",
        },
    },
}
```

### Restrict filesystem access

```go
cfg := &greywall.Config{
    Filesystem: greywall.FilesystemConfig{
        AllowWrite: []string{".", "/tmp"},
        DenyRead:   []string{"~/.ssh", "~/.aws"},
    },
}
```

### Block dangerous commands

```go
cfg := &greywall.Config{
    Command: greywall.CommandConfig{
        Deny: []string{
            "rm -rf /",
            "git push",
            "npm publish",
        },
    },
}
```

### Expose dev server port

```go
manager := greywall.NewManager(cfg, false, false)
manager.SetExposedPorts([]int{3000})
defer manager.Cleanup()

wrapped, _ := manager.WrapCommand("npm run dev")
```

### Load and extend config

```go
cfg, err := greywall.LoadConfig(greywall.DefaultConfigPath())
if err != nil {
    log.Fatal(err)
}
if cfg == nil {
    cfg = greywall.DefaultConfig()
}

// Add additional restrictions
cfg.Command.Deny = append(cfg.Command.Deny, "dangerous-cmd")
```

## Error Handling

`WrapCommand` returns an error when a command is blocked:

```go
wrapped, err := manager.WrapCommand("git push origin main")
if err != nil {
    // err.Error() = "command blocked by policy: git push origin main"
    fmt.Println("Blocked:", err)
    return
}
```

## Platform Differences

| Feature | macOS | Linux |
|---------|-------|-------|
| Sandbox mechanism | sandbox-exec | bubblewrap |
| Network isolation | HTTP/SOCKS proxy | Network namespace + proxy |
| Filesystem restrictions | Seatbelt profiles | Bind mounts |
| Requirements | None | `bubblewrap`, `socat` |

## Thread Safety

- `Manager` instances are **not** thread-safe
- Create one manager per goroutine, or synchronize access
- Proxies are shared and handle concurrent connections
