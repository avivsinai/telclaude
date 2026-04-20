# Skills — scaffold, promote, and doctor

This document is about standalone telclaude skills. For official Claude
plugins and marketplaces, use [plugins.md](./plugins.md).

Telclaude has one canonical writable skill store plus optional read-only skill
roots. Active skills live under `<skill-root>/skills/<name>/`. Draft skills
live under `<skill-root>/skills-draft/<name>/` until promoted. This document
explains the lifecycle: scaffold → edit → doctor/scan → promote → reload.

## The canonical skill root

The writable skill root is resolved by `getSkillRoot()` /
`getDraftSkillRoot()` in `src/commands/skill-path.ts`. Candidates, in priority
order, are:

1. `$TELCLAUDE_SKILL_CATALOG_DIR/skills/` and `/skills-draft/` when set
2. `$CLAUDE_CONFIG_DIR/skills/` or `$TELCLAUDE_CLAUDE_HOME/skills/`
3. `<cwd>/.claude/skills/` and `.claude/skills-draft/`

If none of these are writable, `getSkillRoot()` throws
`SkillRootUnavailableError`. There is no silent fallback to prompt-injection
mode — a missing root is surfaced as a hard error so operators can fix the
environment.

Read-only consumers (e.g. `telclaude skill-path`) additionally fall back to
the bundled skill directory shipped inside the telclaude package. Writers
never touch that directory.

In Docker, telclaude uses one operator-managed standalone skill catalog for
both personas, while official Claude plugins stay profile-local. `agent-social`
mounts the standalone skill catalog read-only; social-specific restrictions are
enforced at runtime policy plus the container boundary, not by copying skills
into a separate catalog.

## `telclaude skills scaffold <name>`

Creates a new draft skill under the canonical draft root from a template. The
scaffold is pre-filled with:

- `SKILL.md` — valid YAML frontmatter (`name`, `description`, `allowed-tools`).
- `scripts/`, `references/`, `assets/` — empty subdirectories with `.gitkeep`.
- `PREVIEW.md` — promotion checklist (edit → doctor → promote).

### Templates

| Template | What it ships |
|---|---|
| `basic` | Read-only skill (Read, Grep, Glob). Good default. |
| `api-client` | Skill that calls a provider via `telclaude provider-query`. |
| `telegram-render` | Skill that produces Telegram-friendly reply text. |

Choose with `--template`:

```
telclaude skills scaffold my-helper --template api-client \
  --description "Use when the user asks about the Acme API."
```

Collisions (existing draft with the same name in the canonical draft root) fail with an explicit
error — the scaffold refuses to overwrite.

## `telclaude skills doctor`

Walks every active and draft skill discovered through the canonical root
helpers, and for each emits one of:

- `[PASS]` — frontmatter valid, scanner clean.
- `[WARN]` — scanner saw medium-severity findings, frontmatter has
  minor issues (unknown allowed-tools entry, formatting quirks), or the
  draft duplicates an active skill name.
- `[FAIL]` — SKILL.md missing, required frontmatter field missing,
  frontmatter name disagrees with directory name, or the scanner blocked
  the skill (critical/high findings).

Doctor exits non-zero when any skill is `[FAIL]`. Use `--json` to emit the
full report for CI.

## `telclaude skills scan`

Runs the static scanner (`src/security/skill-scanner.ts`) across every
active and draft skill. Doctor invokes the scanner; `scan` is the
scanner-only view.

## `/skills` on Telegram

Catalog (un-hidden): `/skills list|new|import|scan|doctor|drafts|promote|reload`.

| Command | Summary |
|---|---|
| `/skills` | Open the skills menu card (drafts + reload). |
| `/skills list` | Active + draft skills with status. |
| `/skills new [name]` | Scaffold a draft via a wizard (template + description prompts). |
| `/skills import` | Prints the CLI instruction for standalone filesystem skills. |
| `/skills scan` | Runs the scanner across active + draft roots. |
| `/skills doctor` | Mirrors the CLI doctor output. |
| `/skills drafts` | List draft skills awaiting promotion. |
| `/skills promote <name>` | Promote a draft into the active skill set. |
| `/skills reload` | Force the next session to start with the refreshed skill set. |

All subcommands are admin-only.

## Promotion rules

Promotion copies the draft directory on top of the active directory, then
removes the draft. Rules:

- `security-gate` and `telegram-reply` are **immutable core skills** — any
  attempt to promote them is rejected.
- Imports from OpenClaw land in the canonical draft root and must go through
  the same `/skills promote` gate.
- Promotion re-runs the scanner; critical/high findings block promotion.

## Official plugins are separate

Do not use `/skills import` for a real Claude plugin or marketplace package.
Those go through the official profile-scoped lifecycle:

```bash
telclaude plugins install <plugin@marketplace> --persona private
```
