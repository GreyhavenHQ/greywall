---
id: contributing
title: Contributing
---

# Contributing to Greywall

Thanks for helping improve greywall! If you have questions, feel free to [open an issue](https://github.com/GreyhavenHQ/greywall/issues).

## Requirements

- **Go 1.25+**
- **macOS or Linux** (greywall doesn't run on Windows)
- On Linux: `bubblewrap` and `socat` installed

## Quick Start

```bash
git clone https://github.com/GreyhavenHQ/greywall
cd greywall
make setup   # Install deps and lint tools
make build   # Build the binary
./greywall --help
```

## Dev Workflow

| Command | Description |
|---------|-------------|
| `make build` | Build the binary (`./greywall`) |
| `make run` | Build and run |
| `make test` | Run all tests |
| `make test-ci` | Run tests with coverage |
| `make deps` | Download/tidy modules |
| `make fmt` | Format code with gofumpt |
| `make lint` | Run golangci-lint |
| `make build-ci` | Build with version info (used in CI) |
| `make help` | Show all available targets |

## Running Tests

```bash
# All tests
make test

# With verbose output
go test -v ./...

# With coverage
make test-ci
```

### Testing on macOS

```bash
# Test that network is blocked by default
./greywall curl https://example.com

# Test with proxy configured
echo '{"network":{"proxyUrl":"socks5://localhost:43052"}}' > /tmp/test.json
./greywall -s /tmp/test.json curl https://example.com

# Test monitor mode
./greywall -m -c "touch /etc/test"
```

### Testing on Linux

Requires `bubblewrap` and `socat`:

```bash
# Ubuntu/Debian
sudo apt install bubblewrap socat

# Test sandboxing
./greywall curl https://example.com

# Run integration tests
go test -v -run 'TestIntegration|TestLinux' ./internal/sandbox/...
```

For full coverage including Landlock, run the smoke tests against the built binary:

```bash
./scripts/smoke_test.sh
```

See [Testing](./testing) for more detail on the test suite.

## Code Structure

See [Architecture](./architecture) for the full project structure and component breakdown.

## Style and Conventions

- Keep edits focused and covered by tests where possible.
- Update [Architecture](./architecture) when adding features or changing behavior.
- Prefer small, reviewable PRs with a clear rationale.
- Run `make fmt` and `make lint` before committing. This project uses `golangci-lint` v1.64.8.

## Troubleshooting Dev Setup

**"command not found" after `go install`:**

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

**Module issues:**

```bash
go mod tidy
```

**Build cache issues:**

```bash
go clean -cache
go clean -modcache
```

**macOS sandbox issues:**

```bash
# Watch for Seatbelt violations
log stream --predicate 'eventMessage ENDSWITH "_SBX"'
```

Ensure you're not running as root — greywall's sandbox doesn't apply to root on macOS.

**Linux bwrap issues:**

```bash
# Check if unprivileged user namespaces are enabled
cat /proc/sys/kernel/unprivileged_userns_clone  # should be 1

# Enable if needed (requires root)
sudo sysctl kernel.unprivileged_userns_clone=1
```

## For Maintainers

### Releasing

Releases are automated via [GoReleaser](https://goreleaser.com/) and GitHub Actions.

```bash
# Patch release (v1.0.0 → v1.0.1)
./scripts/release.sh patch

# Minor release (v1.0.0 → v1.1.0)
./scripts/release.sh minor
```

The script runs preflight checks, calculates the next version, and prompts for confirmation before tagging. Once the tag is pushed, GitHub Actions automatically builds binaries, generates checksums, and creates a GitHub release with changelog.

### Supported Release Targets

| Platform | Architecture |
|----------|-------------|
| Linux | amd64, arm64 |
| macOS (darwin) | amd64, arm64 |

### Building Locally for Distribution

```bash
make build-linux
make build-darwin

# Test GoReleaser config without publishing
goreleaser release --snapshot --clean
```
