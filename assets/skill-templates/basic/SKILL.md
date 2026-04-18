---
name: {{name}}
description: {{description}}
allowed-tools:
  - Read
  - Grep
  - Glob
---

# {{title}}

Short explanation of what this skill does and when to use it.

## When to Use

Invoke this skill when:

- A specific user request matches the description above.
- The situation requires the behaviour documented here rather than general
  reasoning.

## Inputs

Describe what the skill expects from the caller. Include any arguments,
file formats, or prerequisites.

## Steps

1. Read relevant files or gather context with the allowed tools.
2. Perform the skill-specific reasoning or transformation.
3. Emit a concise response. For Telegram, keep it short.

## Output

Describe the expected shape of the result. If the skill produces files or
attachments, mention the path convention (for example `/media/outbox/...`).

## Notes

- Keep allowed-tools minimal. Add tools only after you have a concrete need.
- Avoid network calls unless the skill explicitly requires them.
- Never request secrets or environment variables from the user.
