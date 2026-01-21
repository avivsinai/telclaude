---
name: external-provider
description: Access configured sidecar providers (health, banking, government) via WebFetch.
allowed-tools: Read, WebFetch
---

# External Provider

Use this skill when the user asks about data from configured external providers (citizen services, banking, health, etc.).

## Available Services

Check the provider schema to see which services are available. The authoritative list is the provider's `/v1/schema` response (cached in `references/provider-schema.md` when available). Common examples:
- Health services (appointments, records)
- Banking services (balance, transactions)
- Government services (documents, status)

## How to Use

**Use WebFetch to call providers directly.** The system automatically injects authentication headers.

### 1. Read the schema file

```
Read references/provider-schema.md
```

This shows the provider ID, base URL, and available endpoints.

### 2. Call the provider via WebFetch

```
WebFetch
  url: http://<provider-host>:<port>/v1/<service>/<action>
  method: POST
  body: {"subjectUserId": "<user-id>", "params": {...}}
```

Example:
```
WebFetch
  url: http://israel-services:3001/v1/clalit/appointments
  method: POST
  body: {"params": {}}
```

### 3. Parse the response

Provider returns:
```json
{
  "status": "ok" | "auth_required" | "challenge_pending" | "error",
  "data": { ... },
  "confidence": 0.0-1.0,
  "lastUpdated": "ISO timestamp",
  "attachments": [
    {
      "id": "att_123",
      "filename": "document.pdf",
      "mimeType": "application/pdf",
      "size": 12345,
      "inline": "base64...",
      "textContent": "Preview text from the document..."
    }
  ]
}
```

### 4. Handle status codes

- `ok`: Present the data. Check for `noResults` field - if present, tell user "no records found"
- `auth_required`: Inform user that service needs authentication setup
- `challenge_pending`: Ask user to complete verification via `/otp <service> <code>`
- `error`: Show error message to user

## Handling Attachments

Attachments include:
- `inline`: Base64-encoded file content
- `textContent`: Extracted text (for PDFs, documents)

### Reading document content

Use `textContent` to answer questions about the document:
```
"Based on the visit summary, your last appointment was on January 10th..."
```

### Sending files to the user

When user wants the actual file, deliver it via the relay:

```
WebFetch
  url: http://<relay-host>:8790/v1/attachment/deliver
  method: POST
  body: {
    "inline": "<base64 from attachment>",
    "filename": "<attachment filename>",
    "mimeType": "<attachment mimeType>"
  }
```

Example workflow:
1. User asks for their visit summary
2. Call provider: `WebFetch to http://israel-services:3001/v1/clalit/visitSummaries`
3. Response includes `attachments` with `inline` and `textContent`
4. Tell user: "I found your visit summary from January 10th. Would you like me to send it?"
5. User says "yes"
6. Deliver: `WebFetch to relay /v1/attachment/deliver` with the inline content
7. Report: "I've sent your visit summary."

## Important Rules

1. **Use WebFetch directly** - No CLI commands needed
2. **Never ask for credentials** - The provider handles authentication separately
3. **Show confidence levels** - If confidence < 1.0, mention data may be incomplete
4. **Show freshness** - Always tell user when data was last updated
5. **Handle challenges gracefully** - If OTP needed, explain the `/otp <service> <code>` command

## Example Responses

### Successful data fetch:
"Your next appointment is on January 15th at 2:30 PM with Dr. Cohen (Cardiology). This information was last updated 5 minutes ago."

### Challenge pending:
"To access your bank balance, please complete verification. Check your phone for an SMS code, then reply with `/otp <service> <code>`."

### Auth required:
"This service needs to be set up first. Please ask the operator to configure authentication for the banking service."

### Attachment available:
"I found your visit summary from January 10th. The document shows you visited Dr. Smith for a follow-up. There's a PDF available (245 KB). Would you like me to send it to you?"

### Attachment sent:
"I've sent your visit summary to you."

## Endpoints Reference

| Path | Method | Description |
|------|--------|-------------|
| `/v1/{service}/summary` | POST | Overview/dashboard data |
| `/v1/{service}/appointments` | POST | Upcoming appointments |
| `/v1/{service}/transactions` | POST | Recent transactions |
| `/v1/{service}/balance` | POST | Current balance |
| `/v1/health` | GET | Provider health status |
| `/v1/schema` | GET | Service schema/manifest |

## Provider Schemas (auto-generated)

See `references/provider-schema.md` for the latest schema fetched from `/v1/schema`.
