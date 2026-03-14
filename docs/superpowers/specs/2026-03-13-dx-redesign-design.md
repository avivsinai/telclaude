# Telclaude DX Redesign — Design Spec

**Date:** 2026-03-13
**Status:** Approved (verbal), implementing
**Approach:** B — Relay-Owned Card System with Agent Intent Routing

## Problem

1. 38 flat Telegram commands + 46 flat CLI commands — no hierarchy, hard to discover/remember
2. Control plane is text-only despite Telegram supporting inline keyboards, callbacks, media
3. The agent (Claude) is passive — it responds to commands but doesn't guide, suggest, or reason across actions

## Design Principles

- **Agent owns reasoning; relay owns rendering.** The agent emits typed intents. The relay materializes cards, buttons, and callbacks. The agent never defines control UI or callback semantics.
- **Finite card protocol, not generic framework.** A small set of first-class card types with fixed renderers, action enums, and reducers. Not a widget tree.
- **Text parity.** Every button-backed action has an equivalent text command and CLI path.
- **Callbacks are control-plane actions.** Audited, idempotent, actor-scoped, expiry-aware.
- **TOTP flow is the gold standard.** Sequential, guided, each step tells you what's next.

## Architecture

```
NL / Command Input
       │
       ▼
┌─────────────────┐
│  Intent Router   │  ← Agent resolves NL to typed intent; commands map directly
│  (relay-side)    │
└────────┬────────┘
         │ TypedIntent
         ▼
┌─────────────────┐
│ Domain Controller│  ← Executes read/action logic, produces view model
│  (relay-side)    │
└────────┬────────┘
         │ DomainResult
         ▼
┌─────────────────┐
│   Presenter      │  ← Chooses card vs plain text; renders fixed template
│  (relay-side)    │
└────────┬────────┘
         │ Telegram message + InlineKeyboard
         ▼
      Telegram
         │
    Button press
         │
         ▼
┌─────────────────┐
│Callback Controller│ ← Resolves opaque token → card + action + revision
│  (relay-side)     │   Validates actor, expiry, state; executes idempotently
└──────────────────┘
```

## Command Taxonomy

### Telegram (6 domain roots + 2 shortcuts)

| Root | Subcommands | Purpose |
|------|-------------|---------|
| `/help [topic]` | — | Contextual help, topic list |
| `/me [link\|unlink]` | link `<code>`, unlink | Identity management |
| `/auth [setup\|verify\|logout\|disable\|skip]` | Maps to current 2FA commands | Authentication |
| `/system [sessions\|cron]` | sessions, cron | System introspection |
| `/social [queue\|promote\|run\|log\|ask]` | queue (pending), promote `<id>`, run `[svc]`, log `[svc] [hours]`, ask `[svc] <q>` | Social persona |
| `/skills [drafts\|promote\|reload]` | drafts, promote `<name>`, reload | Skill management |
| `/approve <code>` | — | Fast-path approval (also available as button) |
| `/new` | — | Fast-path session reset (also available as button) |

**Scoped bot menus**: Use Telegram's per-scope command menu API — private chat gets all 8, groups get only `/help` and `/new`.

### CLI (same domain nouns)

```
telclaude relay|agent|status|sessions       # Core services
telclaude identity link|list|remove         # Identity
telclaude auth totp-setup|totp-disable|force-reauth|oauth ...  # Auth
telclaude social heartbeat|activity|pending|promote  # Social
telclaude provider query|health             # Providers
telclaude secrets openai|git|github-app|google|vault  # Secret management
telclaude skills import|scan|drafts|promote # Skills
telclaude admin ban|unban|list-bans         # Admin
telclaude dev doctor|integration-test|diagnose-sandbox-network|quickstart|keygen  # Dev/diag
telclaude maintenance reset-auth|reset-db|vault-daemon|totp-daemon|agent  # Maintenance
```

### Natural Language Routing

The agent handles free-text input by resolving it to a typed intent:

```typescript
type DomainIntent =
  | { domain: 'social'; action: 'show_queue' }
  | { domain: 'social'; action: 'promote'; entryId: string }
  | { domain: 'social'; action: 'run_heartbeat'; serviceId?: string }
  | { domain: 'system'; action: 'status' }
  | { domain: 'system'; action: 'explain'; question: string }
  | { domain: 'auth'; action: 'setup_2fa' }
  | { domain: 'approval'; action: 'approve'; nonce: string }
  // ... etc
```

The agent can also chain intents conversationally: "Check if anything's pending, and if there's only one, promote it."

## Card System

### Card Types (7 first-class)

| Card | Buttons | Use Case |
|------|---------|----------|
| `ApprovalCard` | Approve, Deny, Explain | Pending approval requests |
| `PendingQueueCard` | Promote, Dismiss, Next, Prev | Social post queue |
| `StatusCard` | Refresh, Run Heartbeat, Reset Session | System status dashboard |
| `AuthCard` | Setup 2FA, Verify, Skip | Auth flow steps |
| `HeartbeatCard` | Run [service], Run All, View Log | Social heartbeat control |
| `SkillDraftCard` | Promote, Reject, Refresh | Draft skill management |
| `SessionCard` | Reset, View History | Session management |

### Card Instance (SQLite-backed)

```typescript
interface CardInstance {
  cardId: string;           // UUID
  kind: CardKind;           // enum of 7 types
  version: number;          // schema version for migration
  chatId: number;           // Telegram chat
  messageId: number;        // Telegram message (for edit-in-place)
  threadId?: number;        // Forum thread if applicable
  actorScope: string;       // who may interact (userId or 'admin')
  entityRef: string;        // approval nonce, queue cursor, session key, etc.
  revision: number;         // monotonic, for optimistic concurrency
  state: Record<string, unknown>;  // card-specific state (page, selection, etc.)
  expiresAt: number;        // Unix ms
  status: 'active' | 'consumed' | 'expired' | 'superseded';
  createdAt: number;
  updatedAt: number;
}
```

### Callback Token Format

Opaque, compact token in Telegram callback_data (64 byte limit):

```
c:<cardId_short>:<action>:<revision>
```

On callback:
1. Load card by short ID
2. Verify actor matches actorScope
3. Verify chat/thread matches
4. Verify not expired/superseded
5. Verify revision matches (optimistic concurrency)
6. Execute action idempotently
7. Update card state + revision, edit message in-place

### Card Renderer

Each card type has a fixed renderer:

```typescript
interface CardRenderer<K extends CardKind> {
  render(state: CardState<K>): { text: string; keyboard: InlineKeyboard };
  reduce(state: CardState<K>, action: CardAction<K>): CardState<K>;
  execute(state: CardState<K>, action: CardAction<K>): Promise<void>;
}
```

## Proactive Nudges

- **Broken things**: auth expired, provider approval waiting, heartbeat failures → immediate card
- **Periodic digest**: configurable interval (default daily), structured StatusCard with action buttons
- **Deduplication**: same nudge type + entity_ref within TTL window is suppressed
- **Quiet periods**: configurable hours where only urgent nudges fire
- **Rate limit**: max N nudge cards per hour per chat

## Onboarding

`/start` deep-link flow:
1. CLI generates `t.me/botname?start=LINK_CODE`
2. Bot receives `/start LINK_CODE`, auto-links identity
3. Bot sends AuthCard: "Welcome! Set up 2FA?" [Setup 2FA] [Skip for now]
4. After auth: StatusCard with system overview + [Run Health Check] button

## Migration Strategy

### Phase 1: Foundation
- Card system core (types, SQLite, callback routing, lifecycle)
- Callback security (opaque tokens, validation, idempotency)
- Command taxonomy refactor (Telegram commands + CLI hierarchy)

### Phase 2: Card Implementations
- ApprovalCard, PendingQueueCard, StatusCard
- HeartbeatCard, AuthCard, SkillDraftCard, SessionCard
- Edit-in-place updates, pagination

### Phase 3: Agent Integration
- NL intent router (agent resolves free-text to typed intents)
- Conversational action chaining
- /start onboarding flow
- Proactive nudge system with digest

### No Backward Compatibility
Alpha 0.x — old flat commands are removed, not aliased. Clean break.
