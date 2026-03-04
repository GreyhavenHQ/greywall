# Greywall

Deny-by-default command sandbox. Wraps commands with restricted filesystem access (current directory only by default) and transparent network redirection through [greyproxy](https://github.com/GreyhavenHQ/greyproxy). Supports `--learning` mode to trace filesystem access and auto-generate config templates. Linux only (bubblewrap + seccomp/Landlock/eBPF); macOS support coming.

## Build & Run

```bash
make setup          # install deps + lint tools (first time)
make build          # compile binary (downloads tun2socks)
make run            # build and run
./greywall --help   # CLI usage
```

## Test

```bash
make test           # all unit + integration tests
make test-ci        # with coverage and race detection (-race -coverprofile)
GREYWALL_TEST_NETWORK=1 ./scripts/smoke_test.sh ./greywall  # smoke tests
```

## Lint & Format

```bash
make fmt            # format with gofumpt
make lint           # golangci-lint (staticcheck, errcheck, gosec, govet, revive, gofumpt, misspell, etc.)
```

Always run `make fmt && make lint` before committing.

## Project Structure

```
cmd/greywall/          CLI entry point
internal/
  config/              Configuration loading & validation
  platform/            OS detection
  sandbox/             Platform-specific sandboxing (~7k lines)
    manager.go         Sandbox lifecycle orchestration
    command.go         Command blocking/allow lists
    linux.go           bubblewrap + bridges (ProxyBridge, DnsBridge)
    macos.go           sandbox-exec Seatbelt profiles
    linux_seccomp.go   Seccomp BPF syscall filtering
    linux_landlock.go  Landlock filesystem control
    linux_ebpf.go      eBPF violation monitoring
    sanitize.go        Environment variable hardening
    dangerous.go       Protected files/dirs lists
pkg/greywall/          Public Go API
docs/                  Full documentation
scripts/               Smoke tests, benchmarks, release
```

## Code Conventions

- **Language:** Go 1.25+
- **Formatter:** `gofumpt` (enforced in CI)
- **Linter:** `golangci-lint` v2 (config in `.golangci.yml`)
- **Import order:** stdlib, third-party, local (`github.com/GreyhavenHQ/greywall`)
- **Platform code:** build tags (`//go:build linux`, `//go:build darwin`) with `*_stub.go` for unsupported platforms
- **Error handling:** custom error types (e.g., `CommandBlockedError`)
- **Logging:** stderr with `[greywall:component]` prefixes
- **Config:** JSON with comments (via `tidwall/jsonc`), optional pointer fields for three-state booleans

## Dependencies

4 direct deps: `doublestar` (glob matching), `cobra` (CLI), `jsonc` (config parsing), `golang.org/x/sys`.

Runtime (Linux): `bubblewrap`, `socat`, embedded `tun2socks` v2.5.2.

## CI

GitHub Actions workflows: `main.yml` (build/lint/test on Linux+macOS), `release.yml` (GoReleaser + SLSA provenance), `benchmark.yml`.

## Release

```bash
make release          # patch (v0.0.X)
make release-minor    # minor (v0.X.0)
```
