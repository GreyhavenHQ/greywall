---
id: agents
title: AI Agent Integration
---

# Using Greywall with AI Agents

Many popular coding agents already include sandboxing. Greywall can still be useful when you want a tool-agnostic policy layer that works the same way across:

- local developer machines
- CI jobs
- custom/internal agents or automation scripts
- different agent products (as defense-in-depth)

## Recommended approach

Treat an agent as "semi-trusted automation":

- Restrict writes to the workspace (and maybe `/tmp`)
- Configure the external proxy to allow only the network destinations you need
- Use `-m` (monitor mode) to audit blocked attempts and tighten policy

Greywall can also reduce the risk of running agents with fewer interactive permission prompts (e.g. "skip permissions"), as long as your Greywall config tightly scopes writes and outbound destinations. It's defense-in-depth, not a substitute for the agent's own safeguards.

## Example: API-only agent

```json
{
  "filesystem": {
    "allowWrite": ["."]
  }
}
```

Run:

```bash
greywall --settings ./greywall.json <agent-command>
```

## Popular CLI coding agents

We provide these template for guardrailing CLI coding agents:

- [`code`](https://github.com/GreyhavenHQ/greywall/blob/main/internal/templates/code.json) - Routes all network traffic through an external SOCKS5 proxy. Protects secrets, restricts dangerous commands.
- [`code-relaxed`](https://github.com/GreyhavenHQ/greywall/blob/main/internal/templates/code-relaxed.json) - Same filesystem/command protections as `code`, with relaxed network settings for environments where TUN is unavailable.

You can use it like `greywall --profile code -- claude`.

| Agent | Works with template | Notes |
|-------|--------| ----- |
| Claude Code | `code` | - |
| Codex | `code` | - |
| Gemini CLI | `code` | - |
| OpenCode | `code` | - |
| Droid | `code` | - |
| Cursor Agent | `code-relaxed` | Node.js/undici doesn't respect HTTP_PROXY |

These configs can drift as agents evolve. If you encounter false positives on blocked requests or want a CLI agent listed, please open an issue or PR.

Note: On Linux, if OpenCode or Gemini CLI is installed via Linuxbrew, Landlock can block the Linuxbrew node binary unless you widen filesystem access. Installing OpenCode/Gemini under your home directory (e.g., via nvm or npm prefix) avoids this without relaxing the template.

## Protecting your environment

Greywall includes additional "dangerous file protection" (writes blocked regardless of config) to reduce persistence and environment-tampering vectors like:

- `.git/hooks/*`
- shell startup files (`.zshrc`, `.bashrc`, etc.)
- some editor/tool config directories

See [Architecture](./architecture) for the full list and rationale.
