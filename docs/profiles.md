# Operator Profiles

Per-chat overlays that bind a SOUL, a skill allowlist, and a default model to a Telegram chat on the private side. For the framing and the maturity ladder see `docs/operator-playbook.md`. For the security invariant that keeps memory per-profile see `docs/architecture.md` (invariant #8).

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
