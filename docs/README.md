# Greywall Documentation

Greywall is a sandboxing tool that restricts network and filesystem access for arbitrary commands. It's most useful for running semi-trusted code (package installs, build scripts, CI jobs, unfamiliar repos) with controlled side effects.

## Getting Started

- [Quickstart](quickstart.md) - Install greywall and run your first sandboxed command in 5 minutes
- [Why Greywall](why-greywall.md) - What problem it solves (and what it doesn't)

## Guides

- [Concepts](concepts.md) - Mental model: OS sandbox + local proxies + config
- [Learning Mode](learning.md) - Automatically discover filesystem needs with `--learning`
- [Troubleshooting](troubleshooting.md) - Common failure modes and fixes
- [Using Greywall with AI agents](agents.md) - Defense-in-depth and policy standardization
- [Recipes](recipes/README.md) - Common workflows (npm/pip/git/CI)
- [Templates](./templates.md) - Copy/paste templates you can start from

## Reference

- [README](../README.md) - CLI usage
- [Library Usage (Go)](library.md) - Using Greywall as a Go package
- [Configuration](./configuration.md) - How to configure Greywall
- [Architecture](../ARCHITECTURE.md) - How greywall works under the hood
- [Security model](security-model.md) - Threat model, guarantees, and limitations
- [Platform support](platform-support.md) - Linux vs macOS feature comparison
- [Linux security features](linux-security-features.md) - Landlock, seccomp, eBPF details and fallback behavior
- [Testing](testing.md) - How to run tests and write new ones
- [Benchmarking](benchmarking.md) - Performance overhead and profiling

## Quick Reference

### Common commands

```bash
# Block all network (default)
greywall <command>

# Use custom config
greywall --settings ./greywall.json <command>

# Debug mode (verbose output)
greywall -d <command>

# Monitor mode (show blocked requests)
greywall -m <command>

# Expose port for servers
greywall -p 3000 <command>

# Run shell command
greywall -c "echo hello && ls"

# Learn filesystem needs and generate a template
greywall --learning -- <command>

# Check dependencies and greyproxy status
greywall check

# Install and start greyproxy
greywall setup
```
