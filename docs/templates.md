---
id: templates
title: Config Templates
---

# Config Templates

Greywall includes built-in config templates for common use cases. Templates are embedded in the binary, so you can use them directly without copying files.

## Using templates

Apply a template with the `--profile` flag. (Templates and profiles are the same thing in greywall; the older `-t/--template` flag is still accepted as a hidden alias but new scripts should use `--profile`.)

```bash
# Use a built-in template
greywall --profile npm-install -- npm install

# Wrap Claude Code with its built-in profile
greywall --profile code -- claude

# Combine multiple profiles (agent + toolchain)
greywall --profile claude,python -- claude

# List all available and saved profiles
greywall profiles list
```

You can also copy and customize templates from [`internal/templates/`](https://github.com/GreyhavenHQ/greywall/tree/main/internal/templates/).

## Extending templates

Instead of copying and modifying templates, you can extend them in your config file using the `extends` field:

```json
{
  "extends": "code",
  "filesystem": {
    "allowWrite": [".", "/tmp"]
  }
}
```

This inherits all settings from the `code` template and adds custom writable paths. Settings are merged:

- Slice fields (paths, commands): Appended and deduplicated
- Boolean fields: OR logic (true if either enables it)
- Integer fields (ports): Override wins (0 keeps base value)

### Extending files

You can also extend other config files using file paths:

```json
{
  "extends": "./shared/base-config.json",
  "command": {
    "deny": ["git push"]
  }
}
```

The `extends` value is treated as a file path if it contains `/` or `\`, or starts with `.`. Relative paths are resolved relative to the config file's directory. The extended file is validated before merging.

Chains are supported: a file can extend a template, and another file can extend that file. Circular extends are detected and rejected.

### Example: Company-specific AI agent config

```json
{
  "extends": "code",
  "filesystem": {
    "denyRead": ["~/.company-secrets/**"]
  },
  "command": {
    "deny": ["npm publish"]
  }
}
```

This config:

- Extends the battle-tested `code` template
- Protects company-specific secret directories
- Blocks publishing commands

## Available Templates

| Template | Description |
|----------|-------------|
| `code` | Production-ready config for AI coding agents (Claude Code, Codex, Copilot, etc.) |
| `code-relaxed` | Like `code` but allows direct network for apps that ignore HTTP_PROXY |
| `git-readonly` | Blocks destructive commands like `git push`, `rm -rf`, etc. |
| `local-dev-server` | Allow binding and localhost outbound; allow writes to workspace/tmp |
