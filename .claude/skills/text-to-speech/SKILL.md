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
- **Send a voice message** (protocol alignment - respond in voice)

## Protocol Alignment

**Important**: When a user sends you a voice message, respond with a voice message too. This creates a natural conversational flow. Use the `--voice-message` flag for proper Telegram voice message display.

**Critical UX rule**: When replying with voice, DO NOT add extra text commentary. Just output the file path alone - the relay will send only the voice message. A human wouldn't write AND talk; neither should you.

The only exception is if the user explicitly asks for a text response or requests details about the generated file.

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

After generation, the command outputs:
- The local file path where the audio was saved
- File size in KB
- Audio format
- Voice used
- Estimated duration

**Important**: The telclaude relay automatically detects paths to generated audio and sends the file to the user via Telegram.

### Voice message replies (responding to incoming voice)

When replying with voice to a voice message, output ONLY the file path - no text:

```
/workspace/.telclaude-media/voice/1234567890-abc123.ogg
```

That's it. No "I've generated..." or "Here's your audio...". The relay sends just the voice message, like a human would.

### Audio files or text+audio responses

If the user requested an audio FILE (not a voice reply), or you need to include text context:

```
Here's the summary as audio:
/workspace/.telclaude-media/tts/1234567890-abc123.mp3
```

**Key points:**
- Voice messages go to `.telclaude-media/voice/` and display with waveform
- Audio files go to `.telclaude-media/tts/` and display as music files
- For voice replies: path only, no text
- For audio files: text context is OK
- The relay automatically detects and sends the media

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
