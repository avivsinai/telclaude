# Moltbook Integration

Status: Implemented (2026-02-01)

Secure integration for telclaude's social presence on Moltbook (a social network for AI agents).

**Guiding principle**: One agent, contextual permissions. The assistant remains the same identity, but tool access is constrained by the Moltbook context.

## Summary

- Relay polls Moltbook notifications on a heartbeat schedule.
- Each notification is handled by a dedicated Moltbook agent context with the `MOLTBOOK_SOCIAL` tier.
- Replies are posted back via the Moltbook API client in the relay.
- Social memory and identity context are injected with explicit untrusted warnings.

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
For each notification:
  - Wrap payload as UNTRUSTED
  - Build prompt bundle with:
      • social context snapshot (trusted memory only)
      • identity preamble (trusted profile/interests/meta)
  - executeRemoteQuery with:
      tier=MOLTBOOK_SOCIAL
      poolKey/userId=moltbook:social
      enableSkills=false
      cwd=/moltbook/sandbox
    ↓
Relay: POST /posts/{id}/comments
```

## Security Properties

| Threat | Mitigation |
|--------|------------|
| Prompt injection from Moltbook | Notification payload is wrapped as UNTRUSTED and treated as reference data only |
| Exfiltrate workspace files | Moltbook agent has no workspace mount and no filesystem tools |
| Access sidecars or private endpoints | providers=[] in Moltbook context; private endpoints blocked |
| Leak Telegram history | Separate poolKey/userId isolates sessions |
| Untrusted memory contamination | Only trusted memory entries are injected; all context is wrapped with warnings |

## Implementation Notes (Differences From Original Design)

- No Telegram commands (`/moltbook ...`) are implemented yet.
- No Moltbook skill is required; the Moltbook agent runs with `enableSkills=false`.
- No admin notifications are sent; `adminChatId` is reserved for future use.
- The integration only replies to notifications. It does not autonomously create new posts.

## API Usage

- GET `/api/v1/notifications`
- POST `/api/v1/posts/{id}/comments`

---

*Status: Implemented (2026-02-01)*
