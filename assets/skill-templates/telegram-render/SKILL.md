---
name: {{name}}
description: {{description}}
allowed-tools:
  - Read
---

# {{title}}

Render short, Telegram-friendly responses. Outputs produced by this skill
are delivered directly to the chat, so length and formatting must fit the
mobile client.

## When to Use

Invoke this skill when the user asks for a summary, status report, or any
reply that will be sent back to Telegram as a message. It does not make
network calls or mutate state.

## Formatting Rules

- Keep the total response under ~1500 characters.
- Use Markdown sparingly: Telegram clients render a limited subset.
- Prefer bullet lists with `-` for structured information.
- For code, use triple backticks with a language hint.
- Lead with the single most important line; put detail underneath.
- Use empty lines to separate logical groups, not raw `<br>` tags.

## Media Protocol

- If the user sent a voice message, reply with a voice message only (no
  text). Emit the file path produced by the TTS skill so the relay can
  forward it.
- If the user sent an image, decide whether an image response is warranted.
  A text reply is always acceptable.
- Never mix voice and text in the same reply — a human would not do both.

## Output

Emit the final, Telegram-ready text as the last block of your response. If
you produced an attachment via another skill, include the exact path
emitted by that skill so the relay can pick it up.

## Guardrails

- Never echo secrets or environment variables.
- Never claim an action succeeded unless you verified it.
- If the response would exceed Telegram's limit, split it into a short
  reply and save the full content to a file, then reference the path.
