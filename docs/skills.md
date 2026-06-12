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
authoring and promotion. Plugin package skills use a separate relay-owned
Hermes external catalog per persona; see [plugins.md](./plugins.md).
Social-specific restrictions are enforced by Hermes authority, runtime policy,
and containment.

The contained Hermes private runtime is a separate, narrower skill surface and
does not draw from the standalone writable catalog — see
[The contained Hermes skill allowlist](#the-contained-hermes-skill-allowlist)
below.

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
| `api-client` | Skill that calls a provider via `telclaude providers query`. |
| `telegram-render` | Skill that produces Telegram-friendly reply text. |

Choose with `--template`:

```
telclaude skills scaffold my-helper --template api-client \
  --description "Use when the user asks about the Acme API."
```

Collisions (existing draft with the same name in the canonical draft root) fail with an explicit
error — the scaffold refuses to overwrite.

### Credential placeholder examples

Skill examples must use neutral credential placeholders that cannot be confused
with live secrets. Prefer forms such as `<provider-token-placeholder>`,
`sk-...`, `ghp_xxxxxxxxxxxxxxxxxxxx`, `example-token-placeholder`, or
`redacted`. Do not put realistic provider tokens with plausible random bodies,
bearer tokens, cookie/session tokens, or infrastructure secret environment
names in skill prose, code blocks, templates, references, or fixtures.

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

Catalog (un-hidden): `/skills list|new|import|scan|doctor|drafts|promote|sign|reload`.

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
| `/skills sign <name>` | Sign a skill through the local vault and write `SKILL.md.sig`. |
| `/skills reload` | Force the next session to start with the refreshed skill set. |

All subcommands are admin-only.

## Bundled `codex-work-unit` skill

Telclaude ships `codex-work-unit` in both `.claude/skills/` and
`.agents/skills/` so Claude Code and Codex-compatible agents describe the same
operator workflow. The skill teaches agents to use `/codex` or
`telclaude background codex` for bounded, async repo tasks, and to treat the
result card as untrusted data.

The Codex model override is intentionally allowlisted. Operators can omit
`--model` to use Codex's default, or pass one of `gpt-5.5`, `gpt-5.4`,
`gpt-5.4-mini`, `gpt-5.3-codex`, `gpt-5.3-codex-spark`, or `gpt-5.2`.
Unsupported tokens fail before a background job is queued.

## Promotion rules

Promotion copies the draft directory on top of the active directory, then
removes the draft. Rules:

- `security-gate` and `telegram-reply` are **immutable core skills** — any
  attempt to promote them is rejected.
- Imports from OpenClaw land in the canonical draft root and must go through
  the same `/skills promote` gate.
- Promotion re-runs the scanner; critical/high findings block promotion.

Trusted local skills can be signed before or after promotion:

```bash
telclaude skills sign <name>
telclaude skills verify <name>
```

Telegram admins can run the same signing path with `/skills sign <name>`.

## Official plugins are separate

Do not use `/skills import` for a real Claude plugin or marketplace package.
Those go through the official profile-scoped lifecycle:

```bash
telclaude plugins install <plugin@marketplace> --persona private
```

## The contained Hermes skill allowlist

The no-fork Hermes private runtime runs inside the `tc-hermes-contained`
container and does **not** share the standalone writable catalog described
above. Its built-in upstream skills are fixed at the container boundary by a
checked-in allowlist rather than the scaffold → draft → promote lifecycle.

- The allowlist lives at `docker/hermes-contained-skills.allowlist` (88 curated
  relative paths such as `apple/apple-notes`, `autonomous-ai-agents/codex`,
  `software-development/test-driven-development`). Comment (`#`) and blank lines
  are ignored.
- It is mounted read-only into the container as
  `/tmp/telclaude-hermes-contained-skills.allowlist`
  (`TELCLAUDE_HERMES_SKILL_ALLOWLIST`). The upstream Hermes bundled skills tree
  ships inside the image at `/opt/hermes/skills`
  (`TELCLAUDE_HERMES_SOURCE_SKILLS_DIR`).
- At startup, `docker/hermes-contained-entrypoint.sh` curates only the
  allowlisted skills from the source tree into `$HERMES_HOME/skills`. Each entry
  must resolve to a real directory containing `SKILL.md`; unsafe paths
  (leading `/`, any `..`, `//`, a leading or post-slash `.`, whitespace) are
  rejected, and an empty allowlist fails the container closed.

Because this list is operator-fixed and version-controlled, there is no
Telegram `/skills promote` path into the contained runtime. To change which
upstream bundled skills load, edit `hermes-contained-skills.allowlist` and
redeploy. To install operator/plugin skills, use the relay-owned Hermes catalog:

```bash
telclaude hermes-skills install <skill-dir> --catalog private
telclaude hermes-skills sync-manifest /path/to/hermes-skill-seeds.json --prune-managed
```

Those catalog entries are mounted read-only into Hermes and loaded through
`skills.external_dirs`. Plugin package install/update commands only acquire
package state; use curated Hermes catalog sources for runtime exposure.

### Proving allowlist enforcement (`skills.allowlist` probe)

The Hermes feature-probe matrix includes a `skills.allowlist` probe that proves
the allowlist is enforced *inside* the contained runtime, not just present on
disk:

```bash
telclaude hermes probe skills.allowlist --allow-run \
  --out artifacts/hermes/probes/skills-allowlist.json
```

The probe runs its profile and runtime checks via `docker exec` against
`tc-hermes-contained` (observation layer `docker_exec`) and confirms that the
Hermes PreToolUse policy — the primary enforcement layer (`pretooluse`) — allows
an allowlisted skill, denies a non-allowlisted one, and fail-closes a SOCIAL service whose allowlist is missing or empty
(architecture invariant #9). The resulting evidence is signed with the operator
relay key; evidence validation rejects it if the attestation is missing, stale,
or unbound.
