# Social Follow/Unfollow

Spec co-authored with Codex via AMQ spec workflow.

## Problem

The social agent cannot follow or unfollow accounts during autonomous activity. This limits its ability to curate its timeline and engage with interesting accounts it discovers.

## Design

### Slice A — Backend Capability

**New types** (`src/social/types.ts`):

```typescript
export type SocialUserLookupResult = {
  ok: boolean;
  status: number;
  userId?: string;
  displayName?: string;
  handle?: string;
  error?: string;
  rateLimited?: boolean;
};

export type SocialFollowResult = {
  ok: boolean;
  status: number;
  following?: boolean;
  pending?: boolean;
  error?: string;
  rateLimited?: boolean;
};
```

**Interface methods** (`src/social/client.ts`) — all optional:

```typescript
lookupUser?(handle: string): Promise<SocialUserLookupResult>;
follow?(userId: string): Promise<SocialFollowResult>;
unfollow?(userId: string): Promise<SocialFollowResult>;
```

**Moltbook implementation** — Mastodon-compatible API:
- `lookupUser(handle)` → `GET /accounts/lookup?acct={handle}`
- `follow(userId)` → `POST /accounts/{userId}/follow`
- `unfollow(userId)` → `POST /accounts/{userId}/unfollow`
- Paths are relative to base URL (already includes `/api/v1`)

**X/Twitter implementation** — API v2 with graceful tier degradation:
- `lookupUser(handle)` → `GET /2/users/by/username/{handle}` (free tier OK)
- `follow(userId)` → `POST /2/users/{authenticatedUserId}/following` with body `{target_user_id}`
- `unfollow(userId)` → `DELETE /2/users/{authenticatedUserId}/following/{userId}`
- 402/403 → graceful error (free tier lacks follow endpoints, requires Basic $200/month)
- 429 → `rateLimited: true`

**OAuth scope** (`src/oauth/registry.ts`): add `follows.write` to xtwitter scopes.

### Slice B — Autonomous Handler Integration

**Action schema** — handle-based, not userId-based:

```typescript
| { action: "follow"; handle: string; rationale?: string }
| { action: "unfollow"; handle: string; rationale?: string }
```

**Handler flow** (in `handleAutonomousActivity`):
1. Parse follow/unfollow action with handle
2. Normalize handle (trim, strip leading `@`, lowercase for matching)
3. Validate handle exists in visible timeline authors (case-insensitive)
4. Use canonical timeline `authorHandle` for API lookup (preserves domain-qualified handles)
5. Check follow budget BEFORE lookupUser (avoid wasted API calls)
6. Call `client.lookupUser(canonicalHandle)` → get userId
7. Call `client.follow(userId)` or `client.unfollow(userId)`
8. Consume budget, log outcome

**Rate budgets** — mirror existing autonomous reply budget pattern:
- Service-wide: `social:{serviceId}:autonomous-follow` (e.g., 5 per heartbeat)
- Per-handle: `social:{serviceId}:follow-target:{handle}` (1 per handle per 24h)
- Separate keys for follow vs unfollow

**Prompt update** — add follow/unfollow examples to `buildAutonomousPrompt`:
```
- {"action":"follow","handle":"@someone","rationale":"interesting AI researcher"}
- {"action":"unfollow","handle":"@someone","rationale":"account appears to be spam"}
```

### Tests

- **Moltbook**: lookupUser (200, 404, 429), follow (200 following, 200 pending, 429), unfollow (200, 429)
- **X/Twitter**: lookupUser (200, 404, 402/403), follow (200, pending, 402/403, 429), unfollow (200, 402/403, 429)
- **Handler**: test through `handleSocialHeartbeat()` with mocked structuredOutput (not private helper exports)

## Files Modified

| File | Change |
|------|--------|
| `src/social/types.ts` | Add SocialUserLookupResult, SocialFollowResult |
| `src/social/client.ts` | Add lookupUser?, follow?, unfollow? |
| `src/social/index.ts` | Re-export new types |
| `src/social/backends/moltbook.ts` | Implement lookupUser, follow, unfollow |
| `src/social/backends/xtwitter.ts` | Implement lookupUser, follow, unfollow |
| `src/oauth/registry.ts` | Add follows.write to xtwitter scopes |
| `src/social/handler.ts` | Extend AutonomousAction, parser, handler, budgets, prompt |

## Decisions

- **Handle-based actions**: Model emits handles (visible in timeline), handler resolves to userId server-side. Prevents hallucinated account IDs.
- **Timeline-constrained**: Follow/unfollow only allowed for authors visible in current timeline fetch. Bounds attack surface from prompt injection.
- **Graceful X/Twitter degradation**: Free tier gets clean error messages, not exceptions. Works automatically if user upgrades.
- **Canonical handle for lookup**: After case-insensitive matching, use the original timeline authorHandle for API calls (preserves Mastodon domain-qualified handles).
