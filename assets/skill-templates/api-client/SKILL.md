---
name: {{name}}
description: {{description}}
allowed-tools:
  - Read
  - Bash
---

# {{title}}

This skill queries an external provider via the relay-proxied
`telclaude provider-query` CLI. Direct network calls to provider endpoints
are blocked by the firewall and hook layer; always use the CLI.

## When to Use

Invoke this skill when the user asks for data from the provider this skill
wraps. Consult `references/provider-schema.md` (written by the relay at
startup) for the authoritative list of services and actions.

## User ID

You must extract the actor user ID from `<request-context user-id="..." />`
in your system context and pass it via `--user-id` on every call. Requests
without it are rejected with HTTP 401.

## Calling the Provider

```bash
telclaude provider-query \
  --provider {{name}} \
  --service <service> \
  --action <action> \
  --user-id <actor-id>
```

Pass structured parameters via `--params` with a JSON string:

```bash
telclaude provider-query \
  --provider {{name}} \
  --service <service> \
  --action <action> \
  --user-id <actor-id> \
  --params '{"startDate": "2026-01-01"}'
```

## Handling Responses

The CLI emits a JSON object. The common shape is:

```json
{
  "status": "ok",
  "data": { },
  "attachments": []
}
```

- `status: ok` — present the data, respecting any `confidence` / `lastUpdated` fields.
- `status: auth_required` — tell the operator the service needs setup.
- `status: challenge_pending` — explain the `/otp <service> <code>` flow.
- `status: error` — surface the error message concisely.

## Attachments

When an attachment has a `ref`, deliver it with
`telclaude send-attachment --ref <ref>`. When it has only an `id`, fetch via
`telclaude fetch-attachment`. The path emitted on stdout must appear verbatim
in your reply so the relay can forward the file to the user.

## Guardrails

- Never call provider URLs directly (WebFetch, curl, fetch). The firewall
  blocks them and the hook layer returns a descriptive error.
- Never ask the user for API keys or OAuth tokens. The relay handles auth.
- Do not log or echo response bodies that may contain secrets.
