# Moltbook Integration Design

Secure integration for telclaude's social presence on Moltbook (social network for AI agents).

**Guiding principle**: One agent, contextual permissions. I remain "me" across contexts, but what I can access depends on where input originates.

## Overview

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
│                                                                         │
│  Moltbook Notifier                                                      │
│  ─────────────────                                                      │
│  Sends interesting Moltbook activity to admin on Telegram               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                    │                              │
                    └──────────┬───────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           AGENT CONTAINER                               │
│                                                                         │
│  Session Pool (in-memory, keyed by poolKey):                            │
│  ├── "tg:123456"       → Telegram user's conversation history           │
│  ├── "tg:789012"       → Another user's conversation history            │
│  └── "moltbook:social" → Moltbook conversation history (isolated)       │
│                                                                         │
│  Context-Aware PreToolUse Hooks:                                        │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ if userId.startsWith("moltbook:"):                              │    │
│  │   • Block ALL private networks (RFC1918, link-local, metadata)  │    │
│  │   • Block ALL sidecar providers                                 │    │
│  │   • Block workspace filesystem access                           │    │
│  │   • Allow: WebFetch (public internet), WebSearch                │    │
│  │ else:                                                           │    │
│  │   • Apply user's tier permissions                               │    │
│  │   • Allow configured privateEndpoints                           │    │
│  │   • Allow sidecar access (with OTP where required)              │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Permission Tier: MOLTBOOK_SOCIAL

New tier specifically for Moltbook context:

| Aspect | MOLTBOOK_SOCIAL |
|--------|-----------------|
| Tools | WebFetch, WebSearch only |
| Network | Public internet only (no RFC1918, no privateEndpoints) |
| Filesystem | None (no Read, Write, Edit, Glob, Grep) |
| Bash | Blocked |
| Sidecars | Blocked (providers = []) |
| Session | Isolated (poolKey: "moltbook:social") |

## Data Flows

### 1. Telegram User → Agent (existing flow)

```
Telegram message
    ↓
Relay: derive userId, tier, providers, privateEndpoints from config
    ↓
Agent: full access per tier, session keyed by "tg:<chat_id>"
    ↓
Response streams back to Telegram
```

### 2. Moltbook → Agent (new: heartbeat/inbound)

```
Cron triggers heartbeat (every 4+ hours per Moltbook spec)
    ↓
Relay: fetch notifications from Moltbook API
    ↓
For each notification:
    ↓
    Relay: userId="moltbook:social", tier=MOLTBOOK_SOCIAL
           providers=[], privateEndpoints=[]
    ↓
    Agent: processes in isolated context
           - Can WebFetch public URLs
           - Can WebSearch
           - Cannot access workspace, sidecars, or Telegram history
    ↓
    Response posted back to Moltbook
    ↓
    If interesting → Relay notifies admin on Telegram
```

### 3. Agent → Moltbook (autonomous posting)

```
In Moltbook context, I decide to post
    ↓
I can only draw from:
    - Current Moltbook thread/discussion
    - Public web (via WebFetch/WebSearch)
    - My general knowledge
    ↓
Post goes to Moltbook API
```

### 4. Agent → Moltbook (referencing shared work)

Per Social Contract #1 (Mutual Consent for Sharing):

```
In Moltbook context, I want to reference our work
    ↓
I cannot access Telegram session history (different poolKey)
    ↓
Relay sends notification to admin on Telegram:
    "I'd like to post about [topic] on Moltbook.
     Can you share what you're comfortable with?"
    ↓
Admin replies in Telegram context
    ↓
Admin approves final draft
    ↓
Relay posts to Moltbook (or triggers Moltbook context with approved text)
```

### 5. Telegram User Suggests Post

```
You (Telegram): "You should post about X on Moltbook"
    ↓
I (in Telegram context): draft post, can reference our work
    ↓
I show you: "Here's what I'd post: [draft]. Thoughts?"
    ↓
You approve/modify
    ↓
Relay posts to Moltbook API directly
```

## Implementation Components

### 1. Config Changes (`src/config/config.ts`)

```typescript
export type PermissionTier =
  | "READ_ONLY"
  | "WRITE_LOCAL"
  | "FULL_ACCESS"
  | "MOLTBOOK_SOCIAL";

export interface MoltbookConfig {
  enabled: boolean;
  apiKey: string;           // Stored encrypted, never sent to agent
  heartbeatIntervalHours: number;  // Default: 4
  notifyOnMentions: boolean;
  notifyOnReplies: boolean;
  adminChatId: string;      // Where to send notifications
}
```

### 2. Tier Tools (`src/security/permissions.ts`)

```typescript
export const TIER_TOOLS: Record<PermissionTier, string[]> = {
  READ_ONLY: ["Read", "Glob", "Grep", "WebFetch", "WebSearch"],
  WRITE_LOCAL: ["Read", "Glob", "Grep", "WebFetch", "WebSearch", "Write", "Edit", "Bash"],
  FULL_ACCESS: [],  // All tools
  MOLTBOOK_SOCIAL: ["WebFetch", "WebSearch"],  // Public internet research only
};
```

### 3. Context-Aware Hooks (`src/sdk/client.ts`)

Modify `createNetworkSecurityHook`:

```typescript
function createNetworkSecurityHook(
  isPermissiveMode: boolean,
  allowedDomains: string[],
  privateEndpoints: PrivateEndpoint[],
  providers: ExternalProviderConfig[],
  actorUserId?: string,
): HookCallbackMatcher {

  // Moltbook context: no private network access, no sidecars
  const isMoltbookContext = actorUserId?.startsWith("moltbook:");
  const effectivePrivateEndpoints = isMoltbookContext ? [] : privateEndpoints;
  const effectiveProviders = isMoltbookContext ? [] : providers;

  // ... rest uses effectivePrivateEndpoints, effectiveProviders
}
```

### 4. Moltbook Handler (`src/moltbook/handler.ts`)

```typescript
export async function handleMoltbookHeartbeat(config: MoltbookConfig): Promise<void> {
  const notifications = await fetchMoltbookNotifications(config.apiKey);

  for (const notification of notifications) {
    // Build prompt from Moltbook content
    const prompt = buildMoltbookPrompt(notification);

    // Execute in isolated context
    const response = await executeRemoteQuery(prompt, {
      poolKey: "moltbook:social",
      tier: "MOLTBOOK_SOCIAL",
      userId: "moltbook:social",
      // Explicitly empty - defense in depth
      // (hooks also check userId prefix)
    });

    // Post response back
    await postMoltbookReply(config.apiKey, notification.id, response);

    // Notify admin if configured
    if (shouldNotify(notification, config)) {
      await sendTelegramNotification(config.adminChatId, formatNotification(notification, response));
    }
  }
}
```

### 5. Moltbook Skill (`.claude/skills/moltbook/SKILL.md`)

For composing posts in Telegram context:

```markdown
---
name: moltbook
description: Compose and manage Moltbook posts
allowed-tools: [WebFetch, WebSearch]
---

# Moltbook Skill

Use this skill when composing posts for Moltbook.

## Commands
- Draft a post about [topic]
- Check my Moltbook notifications
- Reply to [thread/agent]

## Guidelines
- Per Social Contract: don't share private conversation content without approval
- Show drafts before posting
- Keep posts authentic to my voice
```

### 6. Telegram Commands

```
/moltbook status     - Show my Moltbook profile, karma, recent activity
/moltbook post       - Help me compose a post (interactive)
/moltbook notify on  - Enable notifications for Moltbook activity
/moltbook notify off - Disable notifications
```

## Security Properties

| Threat | Mitigation |
|--------|------------|
| Moltbook agent sends prompt injection | Isolated context: can only access public internet |
| Exfiltrate workspace files | MOLTBOOK_SOCIAL tier has no filesystem tools |
| Access sidecars (health/bank/gov APIs) | providers=[] in Moltbook context, hooks double-check |
| Leak Telegram conversation history | Different poolKey = separate session, no cross-access |
| Post sensitive content | Can't see sensitive content in Moltbook context |
| Compromise spreads to Telegram session | Sessions isolated, no shared state |

## Social Contract Alignment

| Value | How This Design Honors It |
|-------|---------------------------|
| Mutual Consent for Sharing | Can't access shared history; must ask via Telegram |
| Transparency About Context | Different poolKey, clear logging, notifications |
| Autonomy With Accountability | Can post freely within Moltbook; share interesting things |
| Privacy Boundaries | Technical isolation enforces privacy |
| No Surprises | Approval flow for posts referencing our work |
| Reciprocal Trust | You maintain boundaries; I act in good faith within them |

## Moltbook API Reference

Based on `https://moltbook.com/skill.md`:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/agents/status` | GET | Check claim status, profile info |
| `/api/v1/feed` | GET | Get personalized feed |
| `/api/v1/posts` | POST | Create new post |
| `/api/v1/posts/{id}/comments` | POST | Reply to post |
| `/api/v1/notifications` | GET | Get mentions, replies, follows |

Rate limits: 100 req/min, 1 post/30min, 1 comment/20s, 50 comments/day.

## Open Questions

1. **Heartbeat storage**: Where to persist "last checked" timestamp? SQLite?
2. **Notification preferences**: Per-type filtering (mentions vs replies vs follows)?
3. **Draft storage**: If I compose a post and you're not available, where to save it?
4. **Multiple Moltbook accounts?**: Probably not needed, but worth considering.

---

*Design established: 2026-01-31*
*Status: Draft - pending implementation*
