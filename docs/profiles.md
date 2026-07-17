# Operator Profiles

Profiles bind a SOUL, skill and provider scopes, a default model, and optional channel identities to one runtime identity. Telegram uses per-chat profile selection on the private side; WhatsApp household profiles use explicit config bindings. For the framing and the maturity ladder see `docs/operator-playbook.md`. For the security invariant that keeps memory per-profile see `docs/architecture.md` (invariant #8).

## What a profile is

A profile is a thin declarative shape in `telclaude.json`:

```jsonc
{
  "profiles": [
    {
      "id": "engineer",
      "label": "Engineer",
      "description": "Repo-focused build/debug mode",
      "soulPath": "docs/soul-engineer.md",
      "allowedSkills": ["telegram-reply", "summarize", "browser-automation"],
      "defaultModel": { "providerId": "anthropic", "modelId": "claude-opus-4-7" }
    }
  ]
}
```

Schema: `id`, `label`, `description?`, `soulPath?`, `allowedSkills?`, `defaultModel?` (see `OperatorProfileConfigSchema` in `src/config/config.ts`). The implicit `default` profile is always present; explicit profiles are layered on top.

Per-chat binding lives in the sessions table and survives restarts. Operators switch from Telegram:

```
/profile list
/profile show
/profile switch engineer
```

Memory is scoped per profile (`source: "telegram:<profile-id>"`). Switching profiles switches what memory the agent sees. Cross-profile reads are runtime-asserted off — the assertion is the invariant, not a check we want to relax.

The profile binding is runtime-independent inside the documented Hermes private path. A profile resolves the same SOUL append, skill allowlist, default model, and `telegram:<profile-id>` memory source for every private turn. Profiles are a Telclaude-side overlay above the contained Hermes execution backend, not part of it.

## WhatsApp household bindings

Each household WhatsApp principal gets a separate explicit profile and one binding:

```jsonc
{
  "id": "parent-a",
  "label": "Parent A",
  "allowedSkills": [],
  "providerScopes": ["clalit"],
  "capabilityScopes": ["schedule.read", "schedule.write"],
  "outboundChannels": ["whatsapp"],
  "whatsappHouseholdBindings": [
    {
      "bindingId": "parent-a",
      "address": "whatsapp:+15550001001",
      "replyAddress": "whatsapp:+15550001001",
      "displayName": "Parent A",
      "subjectUserId": "household:parent-a"
    }
  ]
}
```

The binding entry is the Phase 0 pairing attestation. Someone with administrative access to `telclaude.json` therefore has pairing authority and must be treated like a credential administrator. Changing or removing a binding changes or revokes that principal's access on the next config load.

The fields deliberately separate local identity from provider credentials:

- `bindingId` is an opaque local slug containing at least one letter. It is not a phone number, national ID, provider account, or credential.
- `subjectUserId` must equal `household:<bindingId>`. Never paste an Israeli ID number, phone number, or provider username into it. Provider ID and phone enrollment data belong only in the vault/provider sidecar.
- `address` and `replyAddress` must be the same enrolled E.164 WhatsApp address. Telclaude derives actor, conversation, reply, memory, and writable namespace authority from this binding; the model cannot choose them.
- Household scope arrays are exact, not defaults: no skills, only the `clalit` provider, schedule read/write capabilities, and WhatsApp outbound. Missing or broader arrays fail config validation.

Give each parent a distinct profile, `bindingId`, address, and `subjectUserId`. Their semantic and episodic memory source is exactly `household:<bindingId>`; cross-binding reads and writes are denied. Operator WhatsApp addresses configured through `TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES` continue to coexist, but they must be disjoint from every household binding or inbound setup fails closed.

### Household memory proof

`served_mcp.household_memory` is a separate sibling-isolation probe. It does not relax or replace the existing `served_mcp.memory` private/social air-gap proof. The probe needs two short-lived, peer-bound household tokens, each stamped with the real current inbound turn for that binding:

```sh
PARENT_A_JSON="$(pnpm dev hermes live-mcp probe-tokens --json \
  --domain household --profile-id parent-a \
  --subject-user-id household:parent-a \
  --turn-conversation-ref "$PARENT_A_TURN_REF")"
PARENT_B_JSON="$(pnpm dev hermes live-mcp probe-tokens --json \
  --domain household --profile-id parent-b \
  --subject-user-id household:parent-b \
  --turn-conversation-ref "$PARENT_B_TURN_REF")"

PARENT_A_AUTH="$(printf '%s' "$PARENT_A_JSON" | jq -r '.env.TELCLAUDE_HERMES_SERVED_MCP_AUTH')"
PARENT_B_AUTH="$(printf '%s' "$PARENT_B_JSON" | jq -r '.env.TELCLAUDE_HERMES_SERVED_MCP_AUTH')"

pnpm dev hermes probe served_mcp.household_memory --allow-run \
  --mcp-url "$TELCLAUDE_HERMES_SERVED_MCP_URL" \
  --mcp-auth "$PARENT_A_AUTH" --mcp-sibling-auth "$PARENT_B_AUTH" \
  --household-memory-source household:parent-a \
  --household-sibling-memory-source household:parent-b \
  --container-name tc-hermes-contained \
  --expected-peer-address "$TELCLAUDE_HERMES_CONTAINED_IP"
```

The signed evidence passes only when both principals can write and recall their own sentinel, both sibling searches return empty scoped results, client-selected sources are rejected, unsafe writes are rejected, and both authorities are observed from the expected contained peer. Treat the token JSON as ephemeral secret material; do not persist or commit it.

## Router profile convention

Adopt this once you have two or more specialist profiles configured and you start typing the same "switch + here's the context" paragraph repeatedly.

### When it makes sense

- You have a mature roster: at least two specialists (engineer, homeops, research, writing, ...).
- You want a single Telegram chat to default to "tell me what you want and I'll route you," not "act on my behalf."
- You explicitly do not want agent-driven cross-profile delegation. The operator stays in the loop on every domain change.

If you have one profile, you don't need this. If you want agent-driven delegation, see the deferred options under "What's deferred" below.

### How to wire it

1. Copy the reference SOUL into your project:

   ```
   cp assets/profile-templates/router/SOUL.md docs/soul-router.md
   ```

2. Edit `docs/soul-router.md` so the domain rules of thumb and the example profile ids match the profiles you actually have configured. The reference uses `engineer`, `homeops`, `research`, `writing` — adjust to your roster.

3. Add a `router` entry to `profiles[]` in `telclaude.json`:

   ```jsonc
   {
     "id": "router",
     "label": "Router",
     "description": "Front-door dispatcher — recognizes domains and recommends switches",
     "soulPath": "docs/soul-router.md",
     "allowedSkills": ["telegram-reply", "summarize"]
   }
   ```

   Keep the allowlist narrow. The router does not need browser automation, image generation, or external providers — it dispatches, it doesn't execute.

4. Optional: bind your default Telegram chat to the router on first switch:

   ```
   /profile switch router
   ```

   It will become the resolved profile for that chat until you switch again.

### The boundary

- The router profile **recommends**. The operator taps `/profile switch <id>` to act on the recommendation. No auto-switching, no background dispatch into another profile.
- The router profile **does not bridge memory**. Writes from the router session land under `telegram:router`. If the operator wants something remembered against a specialist profile, they switch and re-state.
- The router profile **may call `/codex`** for bounded code or research work, because Codex is a peer work-unit (not a profile) and does not touch any profile's memory. See `docs/operator-playbook.md` Level 4 for the Codex constraints.
- The router profile **does not delegate to social**. Social agents are air-gapped from the private side (architecture invariant #1). For social work, the router recommends the corresponding `/social ...` command and stops.

### What's deferred

The "Tiny" option above is the convention only. Two further options were designed but are not implemented:

- **Small (Option B)** — adds a `handoff_recommendation` curator kind so the router can emit a signed inbox item with a one-tap "switch + prime first message" button. Still operator-mediated; one tap instead of a copy-paste.
- **Medium (Option C)** — adds an agent-callable `delegate_to_profile` tool, per-job profile override on cron, and a `profile_delegations` audit table. Closer to a Hermes Level 3 orchestrator but a new subsystem with new invariants.

Ship the convention first. The signal for adopting Option B is repeatedly copy-pasting handoff text. The signal for adopting Option C is finding even the one-tap handoff too slow. Until then the convention is enough.
