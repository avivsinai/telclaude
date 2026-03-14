---
name: weather
description: Fetches weather forecasts using wttr.in. Use when users ask about weather, temperature, forecasts, or conditions for any location.
allowed-tools: Bash
---

# Weather Skill

Fetch weather information using wttr.in — no API key required.

## When to Use

Use when users ask about weather, temperature, forecast, or conditions for any location.

## Commands

Use the bundled wrapper script via `telclaude skill-path`:

```bash
# Current weather (concise one-liner)
bash "$(telclaude skill-path weather scripts/weather.sh)" "Tel Aviv" current

# Today's forecast (compact)
bash "$(telclaude skill-path weather scripts/weather.sh)" "Tel Aviv" forecast

# Multi-day forecast (detailed)
bash "$(telclaude skill-path weather scripts/weather.sh)" "Tel Aviv" detailed

# Moon phase
bash "$(telclaude skill-path weather scripts/weather.sh)" "" moon
```

## Format Tokens (reference)

| Token | Meaning |
|-------|---------|
| `%c` | Weather condition emoji |
| `%t` | Temperature |
| `%w` | Wind |
| `%h` | Humidity |
| `%p` | Precipitation |
| `%l` | Location |

## Output Guidelines

- Lead with the condition emoji and temperature
- Keep it to 2-3 lines for current weather
- For forecasts, use a compact table or bullet list
- Include wind/humidity only if notable
- If location is ambiguous, ask the user to clarify
