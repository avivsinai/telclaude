---
name: browser-automation
description: Headless browser automation via agent-browser CLI
allowed-tools:
  - Bash
  - Read
  - Write
  - Glob
  - Grep
---

# Browser Automation Skill

Use `agent-browser` for headless Chromium browser automation when you need to:
- Navigate web pages and extract content
- Fill forms and click buttons
- Take screenshots for visual verification
- Execute JavaScript in page context

## When to Use Browser vs Other Tools

- **WebFetch**: Simple GET requests, reading page text. Preferred when sufficient.
- **Browser**: JavaScript-heavy SPAs, form interactions, screenshots, multi-step flows.

## CLI Reference

```bash
# Navigate to a URL
agent-browser navigate --url "https://example.com"

# Take a snapshot (accessibility tree — lightweight alternative to screenshot)
agent-browser snapshot

# Take a screenshot (saves PNG)
agent-browser screenshot --path /tmp/screenshot.png

# Click an element (by CSS selector or text)
agent-browser click --selector "button.submit"
agent-browser click --text "Sign In"

# Fill a form field
agent-browser fill --selector "input[name=email]" --value "user@example.com"

# Execute JavaScript in page context
agent-browser execute --script "document.title"

# Wait for an element to appear
agent-browser wait --selector ".results" --timeout 5000
```

## Headless Mode

All commands run in headless Chromium by default. No display server required.
Set `PLAYWRIGHT_BROWSERS_PATH=/ms-playwright` if browsers are installed there (Docker default).

## Error Handling

- If `agent-browser` is not installed, fall back to `WebFetch` for simple page reads.
- Timeouts default to 30 seconds. Use `--timeout` to override.
- Navigation errors (DNS, SSL) are reported as exit code 1 with stderr details.

## Security

- Browser runs inside the sandboxed agent container.
- No credentials are available — use the relay proxy for authenticated requests.
- Screenshots are written to the sandbox working directory.
