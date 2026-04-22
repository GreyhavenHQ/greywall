---
id: credential-protection
title: Credential Protection
---

# Credential Protection

Greywall can keep API keys and secrets out of sandboxed processes entirely. At startup it detects credential-shaped environment variables, replaces their values with opaque placeholders, and relies on greyproxy to substitute the real values back in at the HTTP layer. The sandboxed process reads a placeholder, sends it in an outbound request, and greyproxy swaps it for the real credential before forwarding upstream.

This feature requires [greyproxy](../greyproxy) v0.3.4 or later.

## How it works

1. **Detection.** Greywall scans environment variables against a list of well-known credential names (for example `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`) and common suffixes (`_API_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`).
2. **Placeholder generation.** Each detected credential receives a unique placeholder of the form `greyproxy:credential:v1:gw-<id>:<digest>`.
3. **Session registration.** Greywall registers the placeholder to real-value mapping with greyproxy via its sessions API.
4. **Environment rewrite.** The sandbox environment is rewritten so every credential variable contains the placeholder instead of the real value.
5. **Proxy substitution.** When the sandboxed process makes an HTTP request that contains a placeholder (in headers or query parameters), greyproxy replaces every occurrence with the real value before forwarding upstream.
6. **Cleanup.** Greywall deletes the session from greyproxy when the sandbox exits.

No configuration is required for credentials that match the detection heuristics.

## Flags

### `--secret VAR`

Mark an environment variable as a secret even if it doesn't match the auto-detection rules. Use this for custom variable names that don't end in `_API_KEY`, `_TOKEN`, or similar patterns.

```bash
greywall --secret LITELLM_NOTRACK_API_KEY -- opencode
greywall --secret MY_INTERNAL_KEY --secret ANOTHER_VAR -- command
```

The variable must exist in the environment. Empty values are skipped.

### `--inject LABEL`

Inject a credential stored in the greyproxy dashboard. The value does not need to exist in your shell environment; greyproxy provides the placeholder, and greywall sets it as an environment variable inside the sandbox.

```bash
greywall --inject ANTHROPIC_API_KEY -- opencode
greywall --inject ANTHROPIC_API_KEY --inject OPENAI_API_KEY -- command
```

To store credentials in the dashboard, open Settings, then Credentials in the greyproxy UI (typically at `http://localhost:43080/settings#credentials`).

### `--ignore-secret VAR`

Exclude a variable from credential detection even if it matches the heuristics. Useful when a variable has a credential-looking name but is not actually a secret.

```bash
greywall --ignore-secret PUBLIC_API_TOKEN -- command
```

### `--no-credential-protection`

Disable credential substitution entirely. The real values are visible inside the sandbox.

```bash
greywall --no-credential-protection -- command
```

## Configuration file

All three flags have equivalents in the config file and in profiles. CLI values are merged with config values and deduplicated.

```json
{
  "credentials": {
    "secrets": ["LITELLM_NOTRACK_API_KEY", "MY_INTERNAL_KEY"],
    "inject": ["ANTHROPIC_API_KEY"],
    "ignore": ["PUBLIC_API_TOKEN"]
  }
}
```

Putting these in a saved profile means you don't need to repeat flags on every invocation. If you ran learning mode with `--secret`, the learned profile already contains the list.

```bash
# Learned once
greywall --learning --secret LITELLM_NOTRACK_API_KEY -- opencode

# Subsequent runs reuse the learned profile
greywall -- opencode
```

You can also edit a manual profile at `~/.config/greywall/greywall.json`:

```json
{
  "credentials": {
    "inject": ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
  }
}
```

## Session lifecycle

- **TTL.** Sessions expire after 15 minutes by default.
- **Heartbeat.** Greywall refreshes the session every 60 seconds.
- **Re-registration.** If a heartbeat fails (for example because greyproxy was restarted), greywall re-registers the session automatically.
- **Cleanup.** On exit, greywall deletes the session from greyproxy.

Active sessions are visible in the greyproxy dashboard under Settings, then Credentials, then Active Sessions.

## What gets protected

Credential substitution applies to:

- **HTTP request headers** (for example `Authorization: Bearer <placeholder>`)
- **URL query parameters** (for example `?api_key=<placeholder>`)

It does **not** apply to:

- **Request bodies.** The placeholder is sent as-is; most APIs read credentials from headers, so this is usually fine.
- **Non-HTTP protocols.** Raw TCP and WebSocket frames after upgrade are not inspected.

## `.env` file rewriting

Many tools read credentials from `.env` files in addition to, or instead of, environment variables. Greywall can rewrite these files with placeholder values so the sandboxed process never sees the real secrets. Support depends on the platform.

### Linux (full support)

Greywall uses bubblewrap's `--ro-bind` to mount rewritten `.env` files over the originals inside the sandbox namespace. The sandboxed process reads `.env` as usual and receives placeholder values. This works with all binaries regardless of how they are compiled or signed.

### macOS (partial support)

macOS has no equivalent to Linux's bind-mount namespaces. The `sandbox-exec` (Seatbelt) profile can allow or deny file access but cannot redirect a read to a different file.

By default, `.env` files are **denied entirely** in the Seatbelt profile when credential protection is active. A sandboxed process that tries to read them will receive a permission-denied error. Credentials in environment variables are still substituted normally, and HTTP-layer substitution still protects secrets in headers and query parameters.

As a workaround, use `--inject` so credentials only exist as environment variables (with placeholder values) inside the sandbox, rather than on disk in `.env` files. See [Platform Support](./platform-support) for more detail on why macOS cannot rewrite files in place.

## Sandbox hardening

Greyproxy stores its encryption key (`session.key`) and CA private key (`ca-key.pem`) on disk. Greywall denies access to both files from the sandbox on both platforms:

- **Linux.** Bubblewrap bind rules prevent access.
- **macOS.** Seatbelt deny-read rules block access.

This prevents a sandboxed process from reading the key material needed to decrypt stored credentials.

## Limitations

- Credential detection is heuristic-based. Use `--secret` for any variables the auto-detection misses.
- Body substitution is not supported. An API that accepts credentials in the request body (rather than headers) will receive the placeholder string instead of the real secret.
- On macOS, `.env` file rewriting is not supported for most binaries, so `.env` files are denied entirely. See the section above for the workaround.
