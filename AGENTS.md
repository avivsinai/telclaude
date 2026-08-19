# Agents Guide

For all agent usage, start with `CLAUDE.md` (project memory, workflows, guardrails). It auto-loads for Claude Code; Codex should read it via this file.

Claude Code skills live under `.claude/skills/`. Codex-compatible project skills live under `.agents/skills/`. When adding or changing operator skills, keep both surfaces equivalent unless the skill is intentionally runtime-specific.

## Beads

Use Beads (`bd`) for durable project task tracking. Start with `bd prime` and the beads skill (`.agents/skills/beads/SKILL.md` / `.claude/skills/beads/SKILL.md`). Keep the local `.beads/` Dolt workspace out of git.
