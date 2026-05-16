---
name: meeting-prep
description: Prepare a concise Telegram briefing before an upcoming calendar event using read-only Google Calendar and Gmail context through the telclaude provider proxy.
allowed-tools:
  - Bash
---

# Meeting Prep

Operator-run preset for workflow #4: send a private Telegram briefing roughly
30 minutes before a calendar event. This skill is a cron/template recipe, not
auto-installed runtime code. The operator must create the scheduled job.

## Security Invariants

- Use Google only through `telclaude providers query google ...`.
- Never call the Google sidecar directly with WebFetch, curl, fetch, or an
  internal container URL.
- Never ask for, read, print, or store OAuth tokens, API keys, cookies, or
  provider credentials.
- Use read-only Google actions only:
  - Calendar: `list_events`, `get_event`, optionally `list_calendars`.
  - Gmail: `search`, `read_message`, `read_thread`, optionally `list_labels`.
- Do not use `calendar create_event`, `gmail create_draft`, social commands,
  social-profile writes, or post queues.
- Keep this in the private/operator persona. If invoked from a SOCIAL profile,
  stop and say the preset is private-only.

## Operator Setup

Check that the Google provider and cron scheduler are available:

```bash
telclaude providers doctor google
pnpm dev maintenance cron status --json
pnpm dev maintenance cron list --all --json
```

The scheduled agent needs an actor user id for provider proxy auth. In normal
Telegram-originated sessions, extract it from:

```xml
<request-context user-id="admin" />
```

For cron, pass the same value in `--owner` and in the prompt text. If the relay
exports `TELCLAUDE_REQUEST_USER_ID`, `telclaude providers query` can use it, but
prefer an explicit `--user-id`.

## Cron Limitation

Current telclaude cron supports fixed `--at`, `--every`, and 5-field UTC
`--cron` schedules. It cannot natively express "run 30 minutes before each
calendar event", because event times come from Google at runtime.

Use a small polling cron job instead: run every 10 minutes, look for events
starting 25-35 minutes from now, and return `[IDLE]` when nothing matches. That
window catches normal meetings once on an on-time scheduler. If duplicate-free
delivery must be guaranteed across scheduler delays, add a tiny polling wrapper
with event-id dedupe state; do not fake event-relative scheduling with static
cron alone.

## Cron Examples

Private home delivery after `/sethome`:

```bash
pnpm dev maintenance cron add \
  --name "meeting-prep-poller" \
  --cron "*/10 * * * 1-5" \
  --prompt "Use the meeting-prep skill. Actor user id: admin. Look for Google Calendar events starting 25-35 minutes from now. Use only read-only telclaude providers query calls against google calendar and gmail. If no event matches, reply exactly [IDLE]. If one or more events match, prepare one concise Telegram briefing for the next event." \
  --delivery home \
  --owner admin \
  --json
```

Explicit chat delivery:

```bash
pnpm dev maintenance cron add \
  --name "meeting-prep-chat" \
  --cron "*/10 * * * 1-5" \
  --prompt "Use the meeting-prep skill. Actor user id: tg:123456789. Look for Google Calendar events starting 25-35 minutes from now. Use only read-only telclaude providers query calls against google calendar and gmail. If no event matches, reply exactly [IDLE]. If a match exists, send a private Telegram briefing." \
  --delivery chat \
  --chat-id 123456789 \
  --json
```

One-shot dry run:

```bash
pnpm dev maintenance cron add \
  --name "meeting-prep-dry-run" \
  --at "$(node -e 'console.log(new Date(Date.now()+60000).toISOString())')" \
  --prompt "Use the meeting-prep skill. Actor user id: admin. Dry-run the next Google Calendar event in the next 24 hours and prepare the Telegram briefing. Use read-only provider calls only." \
  --delivery home \
  --owner admin \
  --json
```

Manual execution:

```bash
pnpm dev maintenance cron run meeting-prep-poller
```

## Runtime Procedure

1. Resolve actor user id from the prompt or `<request-context>`.
2. Compute the event window. For polling, use 25-35 minutes from now. For dry
   runs, use the requested explicit window.
3. Query Calendar through the provider proxy:

```bash
TIME_MIN="$(node -e 'console.log(new Date(Date.now()+25*60*1000).toISOString())')"
TIME_MAX="$(node -e 'console.log(new Date(Date.now()+35*60*1000).toISOString())')"
telclaude providers query google calendar list_events \
  --user-id "$USER_ID" \
  --params "{\"calendarId\":\"primary\",\"timeMin\":\"$TIME_MIN\",\"timeMax\":\"$TIME_MAX\",\"maxResults\":5}"
```

4. If no matching event exists, return exactly:

```text
[IDLE]
```

5. Pick the next non-declined event. Prefer meetings with a concrete start time
   over all-day events. Ignore cancelled events.
6. Fetch full event details:

```bash
telclaude providers query google calendar get_event \
  --user-id "$USER_ID" \
  --params '{"calendarId":"primary","eventId":"EVENT_ID"}'
```

7. Extract title, start/end, location or conferencing hint, organizer,
   attendee names/emails, description, and any visible agenda. Do not reveal
   attendee email addresses unless they are necessary to disambiguate people.
8. Search recent Gmail context with tight queries. Prefer organizer/attendee
   emails and distinctive event title terms; cap results to 10.

```bash
telclaude providers query google gmail search \
  --user-id "$USER_ID" \
  --params '{"q":"newer_than:14d (\"EVENT TITLE\" OR from:person@example.com OR to:person@example.com)","maxResults":10}'
```

9. Read only the most relevant messages or threads:

```bash
telclaude providers query google gmail read_thread \
  --user-id "$USER_ID" \
  --params '{"threadId":"THREAD_ID"}'
```

10. Summarize, do not dump. Mention uncertainty when Gmail context is thin.
    Do not download attachments unless the event explicitly depends on one and
    the operator asked for attachment handling.

## Briefing Format

Keep the Telegram message under about 1200 characters:

```text
Meeting in ~30m: <title>
<time> | <location or video hint>

People: <organizer>; <key attendees>

Context:
- <1-3 bullets from calendar description and recent email>

Prep:
- <open question or decision>
- <document/link/name to have ready, if present>

Gaps: <only if provider data was missing or email context was weak>
```

If provider auth fails, send a short operator-facing error with the failing
command name and no sensitive payload. If provider output is unexpectedly broad
or private, minimize the briefing and say more context is available on request.
