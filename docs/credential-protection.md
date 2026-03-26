# Credential Protection

Greywall automatically detects API keys and secrets in your environment and replaces them with opaque placeholders before they enter the sandbox. The real values are injected transparently by greyproxy at the HTTP layer, so the sandboxed process never sees them.

## How it works

1. **Detection**: greywall scans environment variables against a list of 100+ well-known credential names (e.g. `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`) and suffix patterns (`_API_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`)
2. **Placeholder generation**: each detected credential gets a unique placeholder like `greyproxy:credential:v1:gw-abc123:deadbeef...`
3. **Session registration**: greywall registers the placeholder-to-real-value mappings with greyproxy via `POST /api/sessions`
4. **Environment rewrite**: the sandbox environment is rewritten so every credential variable contains the placeholder instead of the real value
5. **Proxy substitution**: when the sandboxed process makes HTTP requests containing placeholders (in headers or query parameters), greyproxy replaces every occurrence with the real value before forwarding upstream
6. **Cleanup**: when the sandbox exits, the session is deleted from greyproxy

This is all automatic. No configuration needed for credentials that match the detection heuristics.

## Flags

### `--secret VAR`

Mark an environment variable as a secret even if it doesn't match the auto-detection rules. Use this for custom variable names that don't end in `_API_KEY`, `_TOKEN`, etc.

```bash
greywall --secret LITELLM_NOTRACK_API_KEY -- opencode
greywall --secret MY_INTERNAL_KEY --secret ANOTHER_VAR -- command
```

The variable must exist in the environment. If it's empty, it's skipped.

### `--inject LABEL`

Inject a credential stored in the greyproxy dashboard. The value doesn't need to exist in your environment; greyproxy provides the placeholder, and greywall sets it as an environment variable in the sandbox.

```bash
greywall --inject ANTHROPIC_API_KEY -- opencode
greywall --inject ANTHROPIC_API_KEY --inject OPENAI_API_KEY -- command
```

To store credentials in the dashboard, open Settings > Credentials in the greyproxy UI (http://localhost:43080/settings#credentials).

Requires greyproxy v0.3.4 or later. Use `--skip-version-check` to bypass this check in development.

### `--no-credential-protection`

Disable credential substitution entirely. Real values are visible inside the sandbox.

```bash
greywall --no-credential-protection -- command
```

## Configuration file

Both `--secret` and `--inject` can be set in the config file or in profiles. CLI flags are merged with config values (deduplicated).

```json
{
  "credentials": {
    "secrets": ["LITELLM_NOTRACK_API_KEY", "MY_INTERNAL_KEY"],
    "inject": ["ANTHROPIC_API_KEY"]
  }
}
```

This is useful in saved profiles so you don't need to repeat flags every time:

```bash
# After learning
greywall --learning --secret LITELLM_NOTRACK_API_KEY -- opencode

# The learned profile includes the secrets; subsequent runs just work
greywall -- opencode
```

Or in a manual profile at `~/.config/greywall/greywall.json`:

```json
{
  "credentials": {
    "inject": ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
  }
}
```

## Session lifecycle

- **TTL**: sessions expire after 15 minutes by default
- **Heartbeat**: greywall sends a heartbeat every 60 seconds to extend the session
- **Re-registration**: if the heartbeat fails (e.g. greyproxy restarted), greywall automatically re-registers the session
- **Cleanup**: on exit, greywall deletes the session from greyproxy

Active sessions are visible in the greyproxy dashboard under Settings > Credentials > Active Sessions.

## What gets protected

Credential substitution applies to:

- **HTTP request headers** (e.g. `Authorization: Bearer <placeholder>`)
- **URL query parameters** (e.g. `?api_key=<placeholder>`)

It does NOT apply to:

- **Request bodies** (the placeholder is sent as-is; most APIs read keys from headers)
- **Non-HTTP protocols** (raw TCP, WebSocket frames after upgrade)

## Sandbox hardening

Greyproxy stores the encryption key (`session.key`) and CA private key (`ca-key.pem`) on disk. These files are denied from the sandbox on both platforms:

- **Linux**: bubblewrap bind rules prevent access
- **macOS**: Seatbelt deny-read rules block access

This prevents the sandboxed process from reading the key material needed to decrypt stored credentials.

## Limitations

- `.env` file rewriting is planned but not yet implemented. If your application reads credentials from `.env` or `.env.local` instead of the environment, it may get the real value directly. As a workaround, use `--inject` so the credential only exists as a placeholder in the sandbox.
- Credential detection is heuristic-based. Use `--secret` for any variables the auto-detection misses.
- Body substitution is not supported. APIs that accept credentials in the request body (rather than headers) will receive the placeholder string.
