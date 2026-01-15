---
name: external-provider
description: Access configured sidecar providers (health, banking, government) via WebFetch.
allowed-tools: Read, WebFetch
---

# External Provider

Use this skill when the user asks about data from configured external providers (citizen services, banking, health, etc.).

## Available Services

Check the provider configuration to see which services are available. The authoritative list is the provider's `/v1/schema` response (cached in `references/provider-schema.md` when available). Common examples:
- Health services (appointments, records)
- Banking services (balance, transactions)
- Government services (documents, status)
If the schema includes `credentialFields`, use them to explain which fields an operator must configure (never ask users for credentials).

## How to Use

**CRITICAL: You MUST read `references/provider-schema.md` BEFORE making any WebFetch calls.**
Never guess or fabricate URLs. The schema file contains the exact base URL and available endpoints.

1. **First, read the schema file** to get the provider's base URL and available endpoints:
   ```
   Read references/provider-schema.md
   ```
   This file shows the exact base URL (e.g., `http://citizen-services:3001`) and all available service endpoints.

2. **Then fetch data via WebFetch** to the provider's REST API (POST for service endpoints):
   - Use the EXACT base URL from the schema (do NOT use localhost, 127.0.0.1, or made-up hostnames)
   - Use the EXACT endpoint paths from the schema (e.g., `/v1/health-api/visit_summaries`)
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
   - Small files (≤256KB) include `inline` base64 content
   - Large files omit `inline` - fetch via `/v1/attachment/{id}` endpoint using the full signed ID
   - Attachments expire after ~15 minutes (check `expiresAt`)
   - Mention available attachments to the user (filename, type, size)

## Important Rules

1. **Never ask for credentials** - The provider handles authentication separately
2. **Never guess URLs** - Only call endpoints documented by the provider
3. **Show confidence levels** - If confidence < 1.0, mention data may be incomplete
4. **Show freshness** - Always tell user when data was last updated
5. **Handle challenges gracefully** - If OTP needed, explain the `/otp <service> <code>` command
6. **Browser challenges** - If `captureMethod` is `browser` or `interactUrl` is present, give the user the link and instructions to complete it

## Example Responses

### Successful data fetch:
"Your next appointment is on January 15th at 2:30 PM with Dr. Cohen (Cardiology). This information was last updated 5 minutes ago."

### Challenge pending:
"To access your bank balance, please complete verification. Check your phone for an SMS code, then reply with `/otp <service> <code>`."

### Auth required:
"This service needs to be set up first. Please ask the operator to configure authentication for the banking service."

### No results found (status ok, but noResults field present):
"I checked your hospital summaries but there are no records available. This means there are no discharge summaries on file for the selected hospital."

### Partial/parse error:
"I couldn't fully retrieve your data - some information may be missing. Here's what I found: [partial data]. The service may need maintenance if this persists."

## Endpoints Reference

Common provider endpoints (actual availability depends on configuration). For the
authoritative list, see the Provider Schemas section below.

| Endpoint | Description |
|----------|-------------|
| `/v1/{service}/summary` | Overview/dashboard data |
| `/v1/{service}/appointments` | Upcoming appointments |
| `/v1/{service}/transactions` | Recent transactions |
| `/v1/{service}/balance` | Current balance |
| `/v1/health` | Provider health status |
| `/v1/challenge/respond` | OTP submission (relay-only) |
| `/v1/attachment/{id}` | Download attachment by signed ID |

## Provider Schemas (auto-generated)

See `references/provider-schema.md` for the latest schema fetched from `/v1/schema`.
