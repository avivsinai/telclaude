---
name: external-provider
description: Access configured sidecar providers (health, banking, government) via WebFetch.
allowed-tools: [WebFetch]
---

# External Provider

Use this skill when the user asks about data from configured external providers (citizen services, banking, health, etc.).

## Available Services

Check the provider configuration to see which services are available. Common examples:
- Health services (appointments, records)
- Banking services (balance, transactions)
- Government services (documents, status)

## How to Use

1. **Fetch data via WebFetch** to the provider's REST API (POST for service endpoints):
   - Determine the base URL from `telclaude.json` (`providers[].baseUrl`)
   - If multiple providers exist, choose the one mapped to the service
   ```
   WebFetch({
     url: "<provider.baseUrl>/v1/{service}/{endpoint}",
     method: "POST",
     body: "{\"subjectUserId\":\"<target-user-id>\",\"params\":{...}}"
   })
   ```
   - If the user is requesting their own data, omit `subjectUserId`.
   - Use `/v1/health` with GET only when checking provider status.

2. **Parse the JSON response**. Expected shape:
   ```json
   {
     "status": "ok" | "auth_required" | "challenge_pending" | "parse_error" | "error",
     "data": { ... },
     "confidence": 0.0-1.0,
     "lastUpdated": "ISO timestamp",
     "error": "message if status is error",
     "challenge": {
       "id": "challenge-id",
       "type": "sms_otp" | "app_otp" | "push",
       "hint": "sent to ***1234",
       "service": "service-name"
     }
   }
   ```

3. **Handle status codes**:
   - `ok`: Present the data with confidence level and last-updated time
   - `auth_required`: Inform user that service needs authentication setup
   - `challenge_pending`: Tell user to complete OTP via `/otp <service> <code>`
   - `parse_error`: Service data couldn't be parsed; may need maintenance
   - `error`: Show error message to user

## Important Rules

1. **Never ask for credentials** - The provider handles authentication separately
2. **Never guess URLs** - Only call endpoints documented by the provider
3. **Show confidence levels** - If confidence < 1.0, mention data may be incomplete
4. **Show freshness** - Always tell user when data was last updated
5. **Handle challenges gracefully** - If OTP needed, explain the `/otp <service> <code>` command

## Example Responses

### Successful data fetch:
"Your next appointment is on January 15th at 2:30 PM with Dr. Cohen (Cardiology). This information was last updated 5 minutes ago."

### Challenge pending:
"To access your bank balance, please complete verification. Check your phone for an SMS code, then reply with `/otp poalim <code>`."

### Auth required:
"This service needs to be set up first. Please ask the operator to configure authentication for the banking service."

### Parse error:
"I couldn't retrieve your appointments - the service may need maintenance. Try again later or contact the operator."

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

## Provider Schemas (auto-generated)

See `references/provider-schema.md` for the latest schema fetched from `/v1/schema`.
