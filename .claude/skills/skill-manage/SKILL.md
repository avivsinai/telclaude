---
name: skill-manage
description: Create new agent-authored telclaude skills through the guarded managed-skill writer. Use only for private/telegram agent work when a durable new skill is clearly useful.
allowed-tools:
  - Bash
  - Read
---

# Skill Manage

Use this skill only to create a new managed skill. It does not patch, rename, archive, or promote skills.

The guarded writer only lands files under agent-authored paths:

- Telegram/private agent: `.claude/skills/agent/telegram/<name>/SKILL.md`
- Social persona target: `.claude/skills/agent/social/<service-id>/<name>/SKILL.md`

Never write `.claude/skills/<name>/` directly. That namespace is user-authored.

## Create

Pipe the complete `SKILL.md` body through stdin:

```bash
pnpm dev maintenance skill-manage create \
  --persona telegram \
  --name <skill-name> \
  --actor-tier WRITE_LOCAL \
  --user-id <request-user-id> \
  --json <<'EOF'
---
name: <skill-name>
description: Use when ...
allowed-tools:
  - Read
---

# <Title>

Instructions.
EOF
```

To create a skill for a social service, target the service path but keep the caller private:

```bash
pnpm dev maintenance skill-manage create \
  --persona social \
  --service-id xtwitter \
  --name <skill-name> \
  --actor-tier WRITE_LOCAL \
  --user-id <request-user-id> \
  --json <<'EOF'
---
name: <skill-name>
description: Use when ...
allowed-tools:
  - Read
---

# <Title>

Instructions.
EOF
```

New social-targeted skills are not usable by the social runtime until the operator adds the skill name to that service's `agentSkillsAllowed` config.

## Guardrails

- SOCIAL callers are rejected by the command.
- Names must match `^[a-z0-9-]{1,63}$`.
- `SKILL.md` must be 64 KB or smaller.
- The scanner runs on a temp copy before the real file lands.
- The command snapshots the whole skill tree before writing.
- Every attempt is written to the skill-manage audit log.
- Bash examples must avoid shell chaining, pipes, redirection, command substitution, and process substitution.
- Secret names, secret-looking values, private URLs, metadata URLs, and sensitive host filesystem paths are rejected.
