---
name: summarize
description: Extracts and summarizes web content from URLs. Use when users share links or ask to summarize articles, YouTube videos, or web pages.
---

# Summarize Skill

Extract readable content from URLs — articles, YouTube videos, podcasts, and web pages.

## When to Use

Use this skill when users:
- Share a URL and want a summary or key points
- Ask to "read", "summarize", or "extract" a web page
- Paste a YouTube link and want transcript/content
- Want to understand an article without visiting it

## How to Summarize

Use the `telclaude summarize` CLI command via Bash:

```bash
# Basic usage — extract content from URL
telclaude summarize "https://example.com/article"

# Limit output size (default: 8000 characters)
telclaude summarize "https://example.com/article" --max-chars 4000

# Get markdown-formatted output
telclaude summarize "https://example.com/article" --format markdown

# Custom timeout (default: 30000ms)
telclaude summarize "https://example.com/article" --timeout 60000
```

## Output Format

The command outputs structured metadata followed by the extracted content:

```
Title: Article Title Here
Site: example.com
Words: 1234
Transcript: youtube-captions     (only for video/audio content)
Note: Content was truncated      (only if content exceeded max-chars)
---
[Extracted text content here]
```

## Supported Content Types

- **Articles/blog posts**: HTML extraction via readability
- **YouTube videos**: Automatic caption/transcript extraction
- **Podcasts**: Audio transcript when available
- **General web pages**: Best-effort content extraction

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--max-chars <n>` | Maximum characters to extract | 8000 |
| `--format <fmt>` | Output format: `text` or `markdown` | text |
| `--timeout <ms>` | Request timeout in milliseconds | 30000 |

## Rate Limits

- 30 requests per hour per user
- 100 requests per day per user

## Tips

- For long articles, use `--max-chars 16000` to get more content
- Use `--format markdown` when the user wants formatted output with headings/links
- YouTube URLs automatically extract captions — no special flags needed
- If extraction fails, the URL may require JavaScript rendering (not currently supported)
