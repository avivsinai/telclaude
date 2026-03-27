---
name: external-provider
description: Access configured sidecar providers (health, banking, government) via CLI commands.
allowed-tools:
  - Read
  - Bash
---

# External Provider

Use this skill when the user asks about data from configured external providers (citizen services, banking, health, etc.).

## Available Services

Check the provider schema to see which services are available. The authoritative list is the provider's `/v1/schema` response (cached in `references/provider-schema.md` when available). Common examples:
- Health services (appointments, records)
- Banking services (balance, transactions)
- Government services (documents, status)

## How to Use

**IMPORTANT: Use the `telclaude` CLI commands for all provider operations.**
- Do NOT use WebFetch or curl to call provider endpoints directly
- Use Bash only to run `telclaude` CLI commands (provider-query, send-attachment, etc.)
- The CLI handles authentication through the relay (mechanism is provider-dependent)
- Direct HTTP calls will fail with "Missing internal auth headers"
- The relay sanitizes responses (strips inline base64, stores attachments)

### User ID (REQUIRED)

**You MUST extract the user ID from `<request-context>` and pass it to ALL provider commands.**

Look for this tag in your system context:
```
<request-context user-id="admin" />
```

Extract the `user-id` value and pass it via `--user-id` flag. Without this, requests will fail with 401.

### 1. Read the schema file

```
Read references/provider-schema.md
```

This shows the provider ID and available services/actions.

### 2. Query the provider via CLI

```bash
telclaude provider-query --provider <providerId> --service <service> --action <action> --user-id <userId>
```

With parameters:
```bash
telclaude provider-query --provider <providerId> --service <service> --action <action> --user-id <userId> --params '{"key": "value"}'
```

Examples (assuming `<request-context user-id="admin" />`):
```bash
# Get appointments
telclaude provider-query --provider my-provider --service health-api --action appointments --user-id admin

# Get bank transactions with date range
telclaude provider-query --provider my-provider --service bank-api --action transactions --user-id admin --params '{"startDate": "2024-01-01"}'

# Get document status
telclaude provider-query --provider my-provider --service gov-api --action status --user-id admin
```

### 3. Parse the response

The command outputs JSON. The exact shape is provider-dependent, but the common structure is:
```json
{
  "status": "ok" | "auth_required" | "challenge_pending" | "error",
  "data": { ... },
  "attachments": [
    {
      "id": "att_123",
      "filename": "document.pdf",
      "mimeType": "application/pdf",
      "size": 12345,
      "ref": "att_abc123.1234567890.signature",
      "textContent": "Extracted text from the PDF for analysis..."
    }
  ]
}
```

Some providers may include additional fields (e.g., `confidence`, `lastUpdated`, `errorCode`).
```

**Note:** The relay proxy intercepts responses and:
- Strips `inline` base64 content (you won't see it)
- Stores the file in the outbox
- Adds a `ref` token for delivery

### 4. Handle status codes

- `ok`: Present the data. Check for `noResults` field - if present, tell user "no records found"
- `auth_required`: Inform user that service needs authentication setup
- `challenge_pending`: Ask user to complete verification via `/otp <service> <code>`
- `error`: Show error message to user

## Handling Attachments

Attachments include:
- `ref`: Token to retrieve the stored file (use with `telclaude send-attachment`)
- `textContent`: Extracted text content (for PDFs, documents) - use this to analyze/summarize

**Important:** You will NOT see `inline` base64 content. The relay proxy strips it and stores the file automatically. Use `ref` to send files to users.

### Reading document content

Use `textContent` to answer questions about the document:
```
"Based on the document, [relevant information extracted from textContent]..."
```

### Sending files to the user

There are two cases depending on file size:

#### Case 1: Has `ref` — already stored

If the attachment has a `ref` field, the relay proxy already stored the file:

```bash
telclaude send-attachment --ref <attachment.ref>
```

#### Case 2: No `ref` — fetch from provider

If `ref` is empty, fetch the attachment directly:

```bash
telclaude fetch-attachment --provider <providerId> --id <attachment.id> --filename <attachment.filename> --mime <attachment.mimeType>
```

#### Output and delivery

Both commands output:
```
Attachment ready: /media/outbox/documents/<filename>.pdf
```
or
```
Attachment saved to: /media/outbox/documents/<filename>.pdf
```

You MUST include the exact path in your response. The relay watches for this path to trigger Telegram delivery.

#### Example workflow

1. User asks for data or a document
2. Call provider via `telclaude provider-query`
3. Response includes `data` and optionally `attachments` with `ref` and `textContent`
4. Present the data to the user
5. If attachments exist, use `textContent` to summarize the document
6. If user wants the file:
   - If `ref` is present: `telclaude send-attachment --ref <ref>`
   - If `ref` is empty: `telclaude fetch-attachment --provider <providerId> --id <id> ...`
7. Include the exact path from output in your response

## Important Rules

1. **ALWAYS extract user-id** - Look for `<request-context user-id="..." />` in your context and pass it via `--user-id`. Requests without this will fail with 401.
2. **ALWAYS use the provider** - NEVER search for local files in the workspace when the user asks for health, banking, or government data. Always use `telclaude provider-query` to fetch fresh data from the provider.
3. **Use CLI for provider queries** - Use `telclaude provider-query`, not WebFetch or curl
4. **Never ask for credentials** - The provider handles authentication separately
5. **Show confidence levels** - If confidence < 1.0, mention data may be incomplete
6. **Show freshness** - Always tell user when data was last updated
7. **Handle challenges gracefully** - If OTP needed, explain the `/otp <service> <code>` command
8. **Never copy files directly to outbox** - Only use `telclaude send-attachment` or `telclaude fetch-attachment` to deliver files. Copying files directly to `/media/outbox/` will NOT trigger delivery.

## Example Responses

### Successful data fetch:
"Your next appointment is on [date] at [time]. This information was last updated [X] minutes ago."

### Challenge pending:
"To access this service, please complete verification. Check your phone for an SMS code, then reply with `/otp <service> <code>`."

### Auth required:
"This service needs to be set up first. Please ask the operator to configure authentication."

### Attachment available:
"I found a document from [date]. There's a PDF available ([size]). Would you like me to send it to you?"

### Attachment sent (use EXACT path from relay response):
"Here's your document: /media/outbox/documents/<exact-path-from-response>.pdf"

## CLI Command Reference

| Command | Description |
|---------|-------------|
| `telclaude provider-query --provider <id> --service <svc> --action <act> --user-id <uid>` | Query provider data |
| `telclaude send-attachment --ref <ref>` | Send stored attachment to user |
| `telclaude fetch-attachment --provider <id> --id <att-id> ...` | Fetch and send large attachment |

**Note:** `--user-id` is REQUIRED for `provider-query`. Extract it from `<request-context user-id="..." />`.

## Provider Schemas (auto-generated)

See `references/provider-schema.md` for the latest schema fetched from `/v1/schema`.
