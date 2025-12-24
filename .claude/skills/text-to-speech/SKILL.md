---
name: text-to-speech
description: Converts text to speech audio using OpenAI TTS API. Use when users request audio versions of text or want responses read aloud.
---

# Text-to-Speech Skill

You can convert text to speech using the OpenAI TTS API when users request audio content.

## When to Use

Use this skill when users:
- Ask to "read aloud", "speak", or "say" something
- Request audio versions of text content
- Want voice messages or audio responses
- Ask for text to be converted to speech

## How to Generate Speech

To convert text to speech, use the Bash tool to run the telclaude TTS command:

```bash
telclaude text-to-speech "Your text to convert to speech here"
```

Or use the short alias:

```bash
telclaude tts "Your text here"
```

### Options

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
- `--format`: Audio format (mp3, opus, aac, flac, wav). Default: mp3

### Examples

```bash
# Basic usage
telclaude tts "Hello! Here is your summary."

# With a specific voice
telclaude tts "Welcome to the story" --voice fable

# High quality, slower speech
telclaude tts "Important announcement" --voice onyx --model tts-1-hd --speed 0.9

# Fast playback
telclaude tts "Quick update" --speed 1.5
```

## Response Format

After generation, the command outputs:
- The local file path where the audio was saved
- File size in KB
- Audio format
- Voice used
- Estimated duration

**Important**: Include the full file path in your response. The telclaude relay automatically detects paths to generated audio and sends the file to the user via Telegram.

**Example response:**
```
I've generated the audio and saved it to:
/workspace/.telclaude-media/tts/1234567890-abc123.mp3

[The relay will automatically send the audio to you]
```

**Key points:**
- Always include the full path from the command output in your response
- The relay detects `.telclaude-media/tts/` paths and sends them automatically
- No additional commands are needed - just include the path

## Best Practices

1. **Choose Appropriate Voice**: Match the voice to the content type (e.g., fable for stories, onyx for announcements)
2. **Keep Text Reasonable**: Maximum 4096 characters per request
3. **Consider Speed**: Use slower speed (0.8-0.9) for important content, faster (1.2-1.5) for casual updates
4. **Use HD Sparingly**: tts-1-hd costs 2x more; use for important or long-form content

## Limitations

- Maximum 4096 characters per request (longer text is truncated)
- Audio files are stored temporarily and cleaned up after 24 hours
- Requires OPENAI_API_KEY to be configured

## Cost Awareness

OpenAI TTS pricing (per 1000 characters):
- tts-1: $0.015/1K chars
- tts-1-hd: $0.030/1K chars

Example: A 500-word response (~2500 chars) costs ~$0.04 with tts-1
