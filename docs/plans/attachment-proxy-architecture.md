# Attachment Proxy Architecture Plan

> **Status: IMPLEMENTED** (v0.5.4+). See `src/relay/provider-proxy.ts`, `src/storage/attachment-refs.ts`, and `src/commands/send-attachment.ts`. This document is retained as design rationale.

## Problem Statement

Claude bypasses the `telclaude fetch-attachment` CLI when handling provider attachments. Unlike image-gen/TTS (where Claude CANNOT generate content without the API key), Claude CAN decode inline base64 and process PDFs directly. Skill instructions are just guidance - when Claude has raw bytes, it can bypass any policy.

**Root cause**: The provider returns `inline` base64 directly to Claude via WebFetch. Claude sees the data and processes it itself instead of using the CLI.

## Design Principles (Rich Hickey-inspired)

1. **Capability, not policy**: Don't tell Claude "don't do X" - make it so Claude CAN'T do X
2. **Separation of concerns**: Reading (derived data) vs Delivering (capability)
3. **Simple parts**: Each component does one thing well
4. **No bypass paths**: If Claude never sees raw bytes, it can't bypass

## Proposed Architecture

```
Current (broken):
  Claude --WebFetch--> Provider --> {inline: "base64..."}
  Claude decodes base64 itself, bypasses CLI

Proposed (fixed):
  Claude --WebFetch--> Relay /v1/provider/proxy --> Provider
  Relay intercepts response, strips inline, stores file, returns:
  {ref: "att_xxx", textContent: "extracted text preview"}
  Claude can READ (via textContent) but cannot DELIVER (no bytes)
  To send: Claude calls "telclaude send-attachment --ref att_xxx"
  Relay already has file, sends to Telegram
```

## Implementation Components

### 1. Provider Proxy Endpoint (Relay)

**File**: `src/relay/capabilities.ts`

New endpoint: `POST /v1/provider/proxy`

```typescript
type ProviderProxyRequest = {
  providerId: string;
  path: string;        // e.g., "/v1/service/action"
  method?: string;     // default: POST
  body?: string;       // JSON string
  userId?: string;
};

type ProviderProxyResponse = {
  status: "ok" | "error";
  data?: unknown;        // Provider response with inline stripped
  error?: string;
};
```

**Logic**:
1. Validate request (providerId, path)
2. Look up provider config
3. Forward request to provider (with auth headers if needed)
4. Parse JSON response
5. If response has `attachments[]`:
   - For each attachment with `inline`:
     - Store in `attachment_refs` table
     - Save bytes to `/media/outbox/documents/`
     - Replace `inline` with `ref` (signed token)
     - Optionally extract `textContent` (first ~500 chars of PDF text)
6. Return sanitized response

### 2. Attachment Ref Store (SQLite)

**File**: `src/storage/db.ts` - add to schema

```sql
CREATE TABLE IF NOT EXISTS attachment_refs (
  ref TEXT PRIMARY KEY,           -- e.g., "att_abc123.1737100000.sig"
  actor_user_id TEXT NOT NULL,    -- who requested it
  provider_id TEXT NOT NULL,      -- which provider
  filepath TEXT NOT NULL,         -- path in outbox
  filename TEXT NOT NULL,         -- original filename
  mime_type TEXT,
  size INTEGER,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL     -- 15 min TTL
);
CREATE INDEX IF NOT EXISTS idx_attachment_refs_expires ON attachment_refs(expires_at);
```

**Ref format**: `att_<hash>.<expiresTimestamp>.<signature>`
- Hash: first 8 chars of SHA256(filepath + actorUserId + createdAt)
- Signature: HMAC-SHA256(ref_without_sig, TELCLAUDE_INTERNAL_AUTH_SECRET)

### 3. Send Attachment CLI

**File**: `src/cli/send-attachment.ts` (new)

```bash
telclaude send-attachment --ref att_abc123.1737100000.sig
```

**Logic**:
1. Verify signature on ref
2. Look up in `attachment_refs` table
3. Check not expired
4. Read file from filepath
5. Output to stdout or trigger Telegram send (via existing outbox mechanism)

### 4. Skill Update

**File**: `.claude/skills/external-provider/SKILL.md`

Change instructions:
- All provider calls go through `telclaude-cap /v1/provider/proxy`
- Attachments in response have `ref` + `textContent` (no `inline`)
- To send file: `telclaude send-attachment --ref <ref>`

### 5. Cleanup

Add to `cleanupExpired()` in `src/storage/db.ts`:
- Delete expired `attachment_refs` rows
- Optionally delete orphaned files from outbox

## Security Considerations

1. **Refs are scoped**: Bound to `actorUserId` + `providerId`
2. **Signed tokens**: Can't forge refs without secret
3. **TTL**: 15-minute expiry prevents stale refs
4. **No exfiltration**: Claude can't write to outbox (blocked by SDK hook)
5. **Outbox is read-only for agent**: Only relay can write

## Why This Works

| Feature | Image-gen | TTS | Attachments (current) | Attachments (proposed) |
|---------|-----------|-----|----------------------|------------------------|
| Claude has raw data? | No (API call) | No (API call) | Yes (inline b64) | No (ref only) |
| Must use CLI? | Yes (no key) | Yes (no key) | No (can decode) | Yes (no bytes) |
| Bypass possible? | No | No | Yes | No |

## Migration Path

1. Deploy relay with new `/v1/provider/proxy` endpoint
2. Deploy CLI with `send-attachment` command
3. Update skill to use proxy
4. Existing `fetch-attachment` CLI remains for backward compat

## Open Questions

1. **Text extraction**: Provider-side (preferred) or relay-side fallback?
   - Recommendation: Relay extracts via `pdf-parse` as fallback
   - Provider can include `textContent` if it already has it

2. **Large files**: Stream or buffer?
   - Recommendation: Buffer (max 20MB, same as current)

3. **Multiple attachments**: Handle array in single response?
   - Yes, iterate and store each, return array of refs

## Codex Review Feedback (Approved 2026-01-19)

**Conditions incorporated:**
1. ✅ Proxy-intercept approach is correct
2. ✅ TTL configurable via env (default 15min, extend to 30-60min for slow OTP flows)
3. ✅ Prefer provider-side text extraction; relay as fallback
4. ✅ HMAC covers ref + actorUserId + providerId + expiresAt + filename + mime
5. ✅ Proxy only rewrites JSON; reject/passthrough non-JSON/streaming
6. ✅ Handle multiple attachments in single response
7. ✅ Enforce size limits BEFORE decoding base64 (avoid memory spikes)
8. ✅ Keep outbox write-blocked for agent; only relay writes

## Acceptance Criteria

- [ ] Claude cannot access raw attachment bytes
- [ ] Claude can read textContent preview
- [ ] Claude can trigger delivery via CLI
- [ ] Refs expire after configurable TTL (default 15 min)
- [ ] Signature verification prevents forgery
- [ ] Size limits enforced before base64 decode
- [ ] Multiple attachments handled in single response
- [ ] Existing provider endpoints continue to work
