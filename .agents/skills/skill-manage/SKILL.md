---
name: skill-manage
description: Create, patch, pin, unpin, rename, or archive agent-authored telclaude skills through the guarded managed-skill writer. Use only for private/telegram agent work when durable skill changes are clearly useful.
allowed-tools:
  - Bash
  - Read
---

# Skill Manage

Use this skill to create, patch, pin, unpin, rename, or archive managed skills. It does not promote skills into the user-authored namespace.

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

New social-targeted skills are not usable by the social runtime until the operator adds the skill name to that service's `allowedSkills` config.

## Patch

Patch replaces the complete `SKILL.md` body for an existing managed skill. Pass the current `SKILL.md` SHA-256 with `--expected-sha256`; stale edits fail closed.

```bash
pnpm dev maintenance skill-manage patch \
  --persona telegram \
  --name <skill-name> \
  --actor-tier WRITE_LOCAL \
  --user-id <request-user-id> \
  --expected-sha256 <current-skill-md-sha256> \
  --json <<'EOF'
---
name: <skill-name>
description: Use when ...
allowed-tools:
  - Read
---

# <Title>

Updated instructions.
EOF
```

## Archive

Archive moves an existing managed skill under the persona-local `archived/` directory after snapshotting the active tree. It requires the current `SKILL.md` SHA-256.

```bash
pnpm dev maintenance skill-manage archive \
  --persona telegram \
  --name <skill-name> \
  --actor-tier WRITE_LOCAL \
  --user-id <request-user-id> \
  --expected-sha256 <current-skill-md-sha256> \
  --json
```

## Pin And Unpin

Pin protects a managed skill from archive and rename while still allowing content patches. Unpin removes the marker. Both commands require the current `SKILL.md` SHA-256.

```bash
pnpm dev maintenance skill-manage pin \
  --persona telegram \
  --name <skill-name> \
  --actor-tier WRITE_LOCAL \
  --user-id <request-user-id> \
  --expected-sha256 <current-skill-md-sha256> \
  --json

pnpm dev maintenance skill-manage unpin \
  --persona telegram \
  --name <skill-name> \
  --actor-tier WRITE_LOCAL \
  --user-id <request-user-id> \
  --expected-sha256 <current-skill-md-sha256> \
  --json
```

## Rename

Rename moves an existing managed skill to a new managed name and rewrites only the frontmatter `name:` field. Body text, examples, and headings are left unchanged. It requires the current `SKILL.md` SHA-256.

```bash
pnpm dev maintenance skill-manage rename \
  --persona telegram \
  --name <old-skill-name> \
  --new-name <new-skill-name> \
  --actor-tier WRITE_LOCAL \
  --user-id <request-user-id> \
  --expected-sha256 <current-skill-md-sha256> \
  --json
```

## Guardrails

- SOCIAL callers are rejected by the command.
- Names must match `^[a-z0-9-]{1,63}$`.
- `archived` is reserved and cannot be used as a managed skill name.
- `SKILL.md` must be 64 KB or smaller.
- The scanner runs on a temp copy before the real file lands.
- Patch replaces the full `SKILL.md`; it does not apply partial diffs.
- Patch, archive, pin, unpin, and rename require `--expected-sha256`.
- Pinned or malformed-pin-marker skills cannot be archived or renamed; unpin removes only the marker path.
- Rename rewrites only frontmatter `name:` and fails on name collisions across loaded skill roots.
- If a process is interrupted mid-rename, inspect hidden `.telclaude-rename-*.tmp-*` or `.telclaude-rename-*.bak-*` directories under the persona path before retrying.
- Archive moves skills to `agent/<persona>/archived/` so normal persona loading ignores them.
- The command snapshots the whole skill tree before writing, patching, pinning, unpinning, renaming, or archiving.
- Every attempt is written to the skill-manage audit log.
- Bash examples must avoid shell chaining, pipes, redirection, command substitution, and process substitution.
- Secret names, secret-looking values, private URLs, metadata URLs, and sensitive host filesystem paths are rejected.
- Use neutral credential placeholders such as `<provider-token-placeholder>`, `sk-...`, `ghp_xxxxxxxxxxxxxxxxxxxx`, `example-token-placeholder`, or `redacted`; do not include realistic provider tokens, bearer tokens, cookies, sessions, or infrastructure secret environment names.
