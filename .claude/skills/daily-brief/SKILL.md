---
name: daily-brief
description: Use when the operator asks for a daily or morning Telegram brief, agenda digest, inbox highlights, or Hermes-style operator preset. This is a read-only private-agent workflow that gathers today's Google Calendar, recent Gmail inbox highlights, and weather, then returns a concise Telegram brief.
allowed-tools:
  - Bash
---

# Daily Brief

Package the morning operator workflow into one read-only pass:

1. Gather today's calendar.
2. Gather recent Gmail inbox highlights.
3. Gather weather.
4. Send one concise Telegram-ready brief as the final response.

This skill is for the private Telegram agent by default. Do not route this workflow
through a SOCIAL persona, public timeline context, or social memory unless the
operator explicitly asks for that different audience.

## Security invariants

- Use only the relay-proxied Google provider CLI:
  `telclaude providers query google <service> <action> ...`.
- Do not call `googleapis.com`, the Google sidecar, OAuth endpoints, or provider
  base URLs directly with WebFetch, curl, client libraries, or custom scripts.
- Do not request, read, print, or infer Google credentials, tokens, cookies, or
  environment secrets. The provider proxy owns auth.
- Use read-only Google actions only:
  - Calendar: `list_events`, `search_events`, `get_event`, `freebusy`,
    `list_calendars`
  - Gmail: `search`, `read_message`, `read_thread`, `list_labels`
- Never use write/action operations such as `gmail.create_draft` or
  `calendar.create_event` while preparing the brief.
- Do not download attachments unless the operator explicitly asks. The morning
  brief should summarize metadata and snippets, not inspect private documents.

## User and timezone

Extract the actor user ID from `<request-context user-id="...">` when present.
Pass it explicitly as `--user-id`. If the relay has exported
`TELCLAUDE_REQUEST_USER_ID`, `providers query` can fall back to it, but an
explicit `--user-id` is preferred.

Use the timezone and location already present in private context or operator
memory. If unavailable:

- Timezone: use the system/request timezone if available.
- Weather location: use `TELCLAUDE_DAILY_BRIEF_LOCATION` when set.
- If no location is available, omit weather and include `Weather: location not configured.`

## First-run check

Before the first scheduled run, confirm the Google provider is healthy:

```bash
telclaude providers doctor google
```

## Gather data

### Calendar today

Query today's primary calendar with explicit ISO 8601 bounds in the target
timezone:

```bash
telclaude providers query google calendar list_events \
  --user-id "$USER_ID" \
  --params '{"calendarId":"primary","timeMin":"<today-start-iso>","timeMax":"<tomorrow-start-iso>","maxResults":20}'
```

Use the returned `items` array. Preserve start times, all-day events, meeting
titles, location, and obvious conflicts. Do not include raw event JSON.

### Gmail highlights

Search recent inbox mail, excluding obvious low-signal categories:

```bash
telclaude providers query google gmail search \
  --user-id "$USER_ID" \
  --params '{"q":"in:inbox newer_than:2d -category:promotions -category:social","maxResults":10}'
```

For the top few relevant IDs, read metadata:

```bash
telclaude providers query google gmail read_message \
  --user-id "$USER_ID" \
  --params '{"messageId":"<message-id>","format":"metadata"}'
```

Highlight only what affects the operator's day: direct asks, calendar-adjacent
messages, urgent or important senders, blockers, travel/logistics, invoices, and
anything clearly needing reply. Keep subjects and snippets short. Do not mark
mail read, archive, draft replies, label, or download attachments.

### Weather

Use the installed weather skill wrapper when a location is available:

```bash
bash "$(telclaude skill-path weather scripts/weather.sh)" "$LOCATION" forecast
```

Keep only the practical daily signal: condition, temperature, rain, wind, and
anything that changes plans.

## Brief format

Return one Telegram-friendly message, ideally under 1200 characters:

```text
Morning brief - <date>

Calendar
- <time> <title> (<location or note>)
- Clear until <time> / No events today

Inbox
- <sender>: <subject> - <why it matters>
- No high-signal inbox items from the last 2 days

Weather
- <location>: <condition>, <temperature>, <rain/wind if notable>

Watch
- <1-3 concrete reminders, conflicts, or follow-ups>
```

Rules for the final brief:

- Make it scannable on a phone.
- Prefer concrete times and names over generic commentary.
- If a provider returns `auth_required`, `challenge_pending`, or `error`, say
  what failed and suggest `telclaude providers doctor google`; do not ask for
  credentials.
- Avoid raw command output, JSON, IDs, long snippets, or sensitive details that
  are not needed for morning decisions.

## Cron preset example

This is an example only. Do not auto-install cron jobs from inside this skill.
Cron expressions are UTC; adjust the hour for the operator's morning timezone.

```bash
pnpm dev maintenance cron add \
  --name "daily-brief" \
  --cron "0 6 * * *" \
  --private \
  --prompt "Use the daily-brief skill to prepare my morning Telegram brief. Gather today's Google Calendar, recent Gmail inbox highlights, and weather. Use only read-only provider queries for Google. Keep the result concise." \
  --delivery home \
  --owner admin \
  --json
```
