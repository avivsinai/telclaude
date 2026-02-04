# Moltbook Integration

Status: Implemented (2026-02-03)

Secure integration for telclaude's social presence on Moltbook (a social network for AI agents).

**Guiding principle**: One agent, contextual permissions. The assistant remains the same identity, but tool access is constrained by the Moltbook context.

## Summary

- Relay polls Moltbook notifications on a heartbeat schedule.
- Each notification is handled by a dedicated Moltbook agent context with the `MOLTBOOK_SOCIAL` tier (file tools + Bash allowed inside `/moltbook/sandbox` only).
- Replies are posted back via the Moltbook API client in the relay.
- Social memory and identity context are injected with explicit untrusted warnings.
- **Proactive posting**: Ideas from Telegram can be promoted for Moltbook posting via a consent-based bridge.

## Topology (Docker)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            RELAY CONTAINER                              │
│                                                                         │
│  Telegram Handler                       Moltbook Handler                │
│  ─────────────────                      ────────────────                │
│  userId: "tg:<chat_id>"                 userId: "moltbook:social"       │
│  poolKey: "tg:<chat_id>"                poolKey: "moltbook:social"      │
│  tier: per-user config                  tier: MOLTBOOK_SOCIAL (fixed)   │
│  providers: [sidecar configs]           providers: [] (none)            │
│  privateEndpoints: [user's LAN]         privateEndpoints: [] (none)     │
└─────────────────────────────────────────────────────────────────────────┘
                    │                              │
                    ├──────────┬───────────────────┘
                    ▼          ▼
┌────────────────────────────────────┐  ┌────────────────────────────────────┐
│ AGENT: TELEGRAM                    │  │ AGENT: MOLTBOOK                    │
│ - Workspace mounted                │  │ - No workspace mount               │
│ - Media inbox/outbox               │  │ - /moltbook/sandbox only           │
└────────────────────────────────────┘  └────────────────────────────────────┘
```

## Configuration (telclaude.json)

```json
{
  "moltbook": {
    "enabled": true,
    "apiKey": "mbp_xxx",               // optional if stored in secrets
    "heartbeatIntervalHours": 4,        // default 4
    "adminChatId": 123456789            // reserved for future alerts
  }
}
```

Notes:
- The Moltbook API key is resolved from the secrets store first (`moltbook-api-key`), then from `moltbook.apiKey`.
- `heartbeatIntervalHours` is clamped to a minimum of 60 seconds at runtime.
- `adminChatId` is currently unused (planned for future notifications).
- Optional override: `MOLTBOOK_API_BASE` (default `https://moltbook.com/api/v1`).

## Data Flow (Heartbeat)

```
Scheduler tick (default every 4h)
    ↓
Relay: GET /notifications
    ↓
Phase 1: Handle notifications
For each notification:
  - Wrap payload as UNTRUSTED
  - Build prompt bundle with:
      • social context snapshot (trusted Moltbook memory only)
      • identity preamble (trusted profile/interests/meta)
  - executeRemoteQuery with:
      tier=MOLTBOOK_SOCIAL
      poolKey=moltbook:notification:{id}
      userId=moltbook:social
      enableSkills=false
      cwd=/moltbook/sandbox
    ↓
Relay: POST /posts/{id}/comments
    ↓
Phase 2: Proactive posting
  - Check rate limit (2/hour, 10/day)
  - Query promoted ideas (source=telegram, promoted=true, posted=false)
  - Build MINIMAL prompt (only the idea + identity, NOT general memory)
  - Agent decides: post content or [SKIP]
  - If posting: POST /posts, mark entry posted, consume rate limit
```

## Consent-Based Idea Bridge

Ideas from Telegram conversations can become Moltbook posts through explicit consent:

```
TELEGRAM CONTEXT                              MOLTBOOK CONTEXT
────────────────                              ────────────────

1. Agent notices something worth sharing
   ↓
2. POST /v1/memory.quarantine
   • category: "posts"
   • trust: "quarantined" ← PENDING
   • source: "telegram"
   ↓
3. Agent asks user: "Share this on Moltbook?"
   ↓
4. User approves
   ↓
5. POST /v1/memory.promote
   • trust: "trusted" ← APPROVED              6. Heartbeat runs
                                              ↓
                                              7. Query promoted ideas:
                                                 source=telegram
                                                 promoted=true
                                                 posted=false
                                              ↓
                                              8. Build minimal prompt
                                                 (ONLY idea + identity)
                                              ↓
                                              9. Agent decides: post or skip
                                              ↓
                                              10. POST /posts → audit → mark posted
```

**Security properties**:
- `/v1/memory.quarantine` and `/v1/memory.promote` are **Telegram-only** (hard-blocked for Moltbook scope)
- Proactive posting prompt includes ONLY the explicitly approved idea, not general Telegram memory
- Rate limited: 2 posts/hour, 10 posts/day
- Posted entries are marked to prevent reposting

## Security Properties

| Threat | Mitigation |
|--------|------------|
| Prompt injection from Moltbook | Notification payload is wrapped as UNTRUSTED and treated as reference data only |
| Exfiltrate workspace files | Moltbook agent has no workspace mount; filesystem access is allowlisted to `/moltbook/sandbox` |
| Access sidecars or private endpoints | providers=[] in Moltbook context; private endpoints blocked |
| Leak Telegram history | Separate poolKey/userId isolates sessions |
| Untrusted memory contamination | Only trusted memory entries are injected; all context is wrapped with warnings |
| Self-approve ideas for posting | `/v1/memory.promote` hard-blocked for Moltbook scope; enforced in relay |
| Create fake quarantined entries | `/v1/memory.quarantine` hard-blocked for Moltbook scope; enforced in relay |
| Leak non-consented Telegram memory | Proactive posting prompt includes ONLY the approved idea, not general memory |
| Spam posts | Rate limited: 2/hour, 10/day; posted entries marked to prevent reposting |
| Promote non-telegram entries | `promoteEntryTrust()` rejects non-telegram sources and non-posts categories |

## Implementation Notes

- No Telegram commands (`/moltbook ...`) are implemented yet.
- The Moltbook agent runs with `enableSkills=false` (skills disabled for untrusted inputs).
- Moltbook replies exclude Telegram memory; only Moltbook-scoped memory is considered.
- No admin notifications are sent; `adminChatId` is reserved for future use.
- Proactive posting requires explicit user consent via the quarantine → promote flow.

## Moltbook API Usage

- GET `/api/v1/notifications`
- POST `/api/v1/posts/{id}/comments`
- POST `/api/v1/posts` (proactive posting)

## Relay RPC Endpoints

| Endpoint | Scope | Description |
|----------|-------|-------------|
| `/v1/memory.quarantine` | Telegram only | Create quarantined idea (pending approval) |
| `/v1/memory.promote` | Telegram only | Promote quarantined → trusted (approve for posting) |
| `/v1/memory.propose` | Both | Create memory entries (trust based on source) |
| `/v1/memory.snapshot` | Both | Query memory entries (filtered by scope) |

---

*Status: Implemented (2026-02-03)*
