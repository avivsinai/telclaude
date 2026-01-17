---
name: external-provider
description: Access configured sidecar providers (health, banking, government) via WebFetch.
allowed-tools: Read, WebFetch, Bash
---

# External Provider

Use this skill when the user asks about data from configured external providers (citizen services, banking, health, etc.).

## Available Services

Check the provider schema to see which services are available. The authoritative list is the provider's `/v1/schema` response (cached in `references/provider-schema.md` when available). Common examples:
- Health services (appointments, records)
- Banking services (balance, transactions)
- Government services (documents, status)

## How to Use

**CRITICAL: You MUST read `references/provider-schema.md` BEFORE making any WebFetch calls.**
Never guess or fabricate URLs. The schema file contains the exact base URL and available endpoints.

1. **First, read the schema file** to get the provider's base URL and available endpoints:
   ```
   Read references/provider-schema.md
   ```
   This file shows the exact base URL (e.g., `http://provider-sidecar:3001`) and all available service endpoints.

2. **Then fetch data via WebFetch** to the provider's REST API (POST for service endpoints):
   - Use the EXACT base URL from the schema (do NOT use localhost, 127.0.0.1, or made-up hostnames)
   - Use the EXACT endpoint paths from the schema (e.g., `/v1/{service}/{action}`)
   ```
   WebFetch({
     url: "<exact-base-url-from-schema>/v1/{service}/{endpoint}",
     method: "POST",
     body: "{\"subjectUserId\":\"<target-user-id>\",\"params\":{...}}"
   })
   ```
   - Telclaude injects `x-actor-user-id` for provider calls automatically; do not fabricate headers
   - If the user is requesting their own data, omit `subjectUserId`.
   - Use `/v1/health` with GET only when checking provider status.

3. **Parse the JSON response**. Expected shape (provider-defined fields may vary):
   ```json
   {
     "status": "ok" | "auth_required" | "challenge_pending" | "error" | "<provider-specific>",
     "data": {
       "noResults": "Optional - if present, means no data found (valid response)",
       "items": [],
       ...
     },
     "confidence": 0.0-1.0,
     "lastUpdated": "ISO timestamp",
     "error": "message if status indicates failure",
     "partial": { ... },
     "challenge": {
       "id": "challenge-id",
       "type": "<provider-specific challenge type>",
       "hint": "sent to ***1234",
       "service": "service-name",
       "prompt": "SMS verification code",
       "captureMethod": "text" | "browser",
       "interactUrl": "https://... (if browser-based)",
       "instructions": "Optional instructions"
     },
     "attachments": [
       {
         "id": "att_abc123.<expires>.<sig>",
         "filename": "document.pdf",
         "mimeType": "application/pdf",
         "size": 12345,
         "expiresAt": "ISO timestamp",
         "inline": "base64-content-if-small"
       }
     ]
   }
   ```

4. **Handle status codes**:
   - `ok`: Present the data. **IMPORTANT**: Check for `noResults` field in data - if present, tell user "no records found" (this is NOT an error, just empty results)
   - `auth_required`: Inform user that service needs authentication setup (never ask for credentials)
   - `challenge_pending`: Ask user to complete verification via `/otp <service> <code>` (or include `challengeId` if provided)
   - `parse_error`/`extraction_error` (if returned): Some data couldn't be extracted; check `partial` for available data and `error` for details
   - `error`: Show error message to user

5. **Handle attachments** (if present):
   - The `id` is a signed token: `att_<hash>.<expiresTimestamp>.<signature>`
   - Small files (≤256KB) may include `inline` base64 content
   - Large files omit `inline` - the relay must fetch via `/v1/attachment/{id}` using the full signed ID
   - Attachments expire after ~15 minutes (check `expiresAt`)
   - Mention available attachments to the user (filename, type, size)

## Delivering Attachments to Users

When a provider response includes attachments and the user wants the file delivered:

1. **Use the `telclaude fetch-attachment` CLI command**:
   ```bash
   # For attachments with inline base64 content (small files):
   telclaude fetch-attachment --provider <provider-id> --id <attachment.id> \
     --filename <attachment.filename> --mime <attachment.mimeType> \
     --inline "<base64-content>"

   # For attachments that need fetching (large files):
   telclaude fetch-attachment --provider <provider-id> --id <attachment.id> \
     --filename <attachment.filename> --mime <attachment.mimeType>
   ```

2. **The command outputs the saved file path**:
   ```
   Attachment saved to: /media/outbox/documents/visit_summary-1737099600-abc123.pdf
   ```

3. **Include the path in your response** - the relay automatically sends files from `/media/outbox/documents/` to Telegram:
   ```
   "I've downloaded your document: /media/outbox/documents/visit_summary-1737099600-abc123.pdf"
   ```

**Example**:
```bash
# User asked for an attachment
telclaude fetch-attachment --provider <provider-id> \
  --id "att_abc123.1737100000.sig" \
  --filename "attachment.pdf" \
  --mime "application/pdf"
```

**Note**: Only fetch attachments when the user explicitly requests the file. First tell them what's available, then offer to send it.

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

### Attachment available:
"I found your visit summary from January 10th. There's a PDF document available (visit_summary_2024-01-10.pdf, 245 KB). Would you like me to send it to you?"

### Attachment delivered:
"I've downloaded your visit summary: /media/outbox/documents/visit_summary_2024-01-10.pdf"

## Endpoints Reference

| Command | Description |
|---------|-------------|
| `telclaude provider-query --provider <id> --service <svc> --action <act> --user-id <uid>` | Query provider data |
| `telclaude send-attachment --ref <ref>` | Send stored attachment to user |
| `telclaude fetch-attachment --provider <id> --id <att-id> ...` | Fetch and send large attachment |

| Endpoint | Description |
|----------|-------------|
| `/v1/{service}/summary` | Overview/dashboard data |
| `/v1/{service}/appointments` | Upcoming appointments |
| `/v1/{service}/transactions` | Recent transactions |
| `/v1/{service}/balance` | Current balance |
| `/v1/health` | Provider health status |
| `/v1/challenge/respond` | OTP submission (relay-only) |
| `/v1/attachment/{id}` | Download attachment by signed ID |
| `/v1/attachment/fetch` | Relay endpoint - fetch and save attachment for Telegram delivery |

## Provider Schemas (auto-generated)

See `references/provider-schema.md` for the latest schema fetched from `/v1/schema`.
