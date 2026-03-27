---
name: gifgrep
description: Searches for GIFs from Tenor/Giphy and downloads them for sending via Telegram. Use when users want reaction GIFs, memes, or animated images.
allowed-tools: Bash
---

# GIF Search Skill

Search and download GIFs using `gifgrep` for sending via Telegram.

## When to Use

Use when users:
- Ask for a reaction GIF ("send me a laughing GIF")
- Want a meme or animated image for a topic
- Say things like "GIF me", "send a GIF of..."

## Commands

### Search and download (recommended)
```bash
bash "$(telclaude skill-path gifgrep scripts/download-gif.sh)" "celebration"
bash "$(telclaude skill-path gifgrep scripts/download-gif.sh)" "thumbs up" /media/outbox/thumbsup.gif
```

### Search only (browse results)
```bash
gifgrep "search terms"
gifgrep -n 5 "thumbs up"
```

## Output Guidelines

- Downloaded GIFs go to `/media/outbox/` — the relay picks them up and sends to Telegram
- Use `.gif` extension so Telegram sends it as an animation
- Pick the first/best result unless the user wants options
- Keep search terms short and descriptive for better results
