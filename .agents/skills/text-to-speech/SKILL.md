---
name: text-to-speech
description: Converts text to speech audio using OpenAI TTS API. Use when users request audio versions of text or want responses read aloud.
---

# Text-to-Speech Skill

## CRITICAL: Voice Message Reply Rules

When a user sends you a voice message, follow these rules:

1. **ALWAYS use `--voice-message` flag** - Required for Telegram waveform display
2. **Generate TTS in the SAME LANGUAGE the user spoke** - If they spoke English, generate English audio
3. **Output ONLY the file path** - No text commentary alongside the voice reply

**Exception**: If the user explicitly asks for a text response (e.g., "respond in text", "don't send voice"), respond with text instead.

### Correct Example (user sent voice in English):
```bash
telclaude tts "Hello! How can I help you today?" --voice-message
```
Then output ONLY:
```
/media/outbox/voice/1234567890-abc123.ogg
```

### WRONG - Do NOT do this:
```
Hello! Here is the audio you requested:
/media/outbox/tts/1234567890-abc123.mp3
```
This is wrong because: (1) added text alongside voice, (2) missing --voice-message flag, (3) mp3 instead of ogg, (4) wrong directory

---

## When to Use

Use this skill when users:
- Ask to "read aloud", "speak", or "say" something
- Request audio versions of text content
- Want voice messages or audio responses
- Ask for text to be converted to speech
- **Send a voice message** (respond in voice - see CRITICAL rules above)

## How to Generate Speech

### Voice Messages (Telegram waveform display)

For conversational voice replies, use `--voice-message` to get proper Telegram voice message formatting:

```bash
telclaude tts "Your response here" --voice-message
```

This outputs OGG/Opus format that displays as a voice message with waveform in Telegram.

### Audio Files (music player display)

For regular audio files (longer content, podcast-style):

```bash
telclaude tts "Your text to convert to speech here"
```

Or use the short alias:

```bash
telclaude tts "Your text here"
```

### Options

- `--voice-message`: Output as Telegram voice message (OGG/Opus with waveform display)
- `--voice`: Voice to use (alloy, echo, fable, onyx, nova, shimmer). Default: alloy
  - alloy: Neutral, balanced voice
  - echo: Deeper, more resonant voice
  - fable: Expressive, storytelling voice
  - onyx: Deep, authoritative voice
  - nova: Warm, conversational voice
  - shimmer: Soft, gentle voice
- `--speed`: Speech speed from 0.25 to 4.0. Default: 1.0
- `--model`: Quality model (tts-1, tts-1-hd). Default: tts-1
  - tts-1: Standard quality, faster
  - tts-1-hd: Higher quality, slightly slower
- `--format`: Audio format (mp3, opus, aac, flac, wav). Default: mp3 (ignored with --voice-message)

### Examples

```bash
# Voice message reply (when user sent a voice message)
telclaude tts "Sure, I can help you with that!" --voice-message

# Voice message with specific voice
telclaude tts "Here's what I found..." --voice-message --voice nova

# Regular audio file
telclaude tts "Hello! Here is your summary."

# High quality audio file
telclaude tts "Important announcement" --voice onyx --model tts-1-hd --speed 0.9
```

## Response Format

The `telclaude tts` command outputs metadata (file path, size, format, voice, duration). **You only need to include the file path in your response** - the relay handles sending it to Telegram.

### Voice message replies (responding to incoming voice)

Output ONLY the file path - no commentary:

```
/media/outbox/voice/1234567890-abc123.ogg
```

That's it. No "I've generated..." or "Here's your audio...". The relay sends just the voice message, like a human would.

### Audio files or text+audio responses

If the user requested an audio FILE (not a voice reply), or you need to include text context:

```
Here's the summary as audio:
/media/outbox/tts/1234567890-abc123.mp3
```

**Key points:**
- Voice messages: `.../voice/*.ogg` - waveform display, path only
- Audio files: `.../tts/*.mp3` - music player display, text OK
- The relay automatically detects paths and sends the media
- Paths live under `TELCLAUDE_MEDIA_OUTBOX_DIR` (default `.telclaude-media` in native mode; `/media/outbox` in Docker)

## Best Practices

1. **Match the medium**: If user sends voice, respond with voice
2. **Choose Appropriate Voice**: Match the voice to the content type (e.g., fable for stories, onyx for announcements)
3. **Keep Text Reasonable**: Maximum 4096 characters per request
4. **Consider Speed**: Use slower speed (0.8-0.9) for important content, faster (1.2-1.5) for casual updates
5. **Use HD Sparingly**: tts-1-hd costs 2x more; use for important or long-form content

## Limitations

- Maximum 4096 characters per request (longer text is truncated)
- Audio files are stored temporarily and cleaned up after 24 hours
- Requires OPENAI_API_KEY to be configured

## Cost Awareness

OpenAI TTS pricing (per 1000 characters):
- tts-1: $0.015/1K chars
- tts-1-hd: $0.030/1K chars

Example: A 500-word response (~2500 chars) costs ~$0.04 with tts-1
