---
name: image-generator
description: Generates images using GPT Image 1.5 API. Use when users request image creation, illustration, or visual content.
---

# Image Generation Skill

Generate images using GPT Image 1.5 when users request visual content.

## When to Use

Use this skill when users:
- Ask to "create", "generate", "draw", or "make" an image
- Request illustrations, artwork, diagrams, or visual content
- Want to visualize concepts, ideas, or descriptions

## How to Generate Images

Use the `telclaude generate-image` CLI command. This handles API key retrieval from keychain, rate limiting, and proper error handling.

```bash
# Basic usage - generates image and outputs file path
telclaude generate-image "YOUR_PROMPT_HERE"

# With size option (default: 1024x1024)
telclaude generate-image "YOUR_PROMPT" --size 1536x1024

# With quality option (default: medium)
telclaude generate-image "YOUR_PROMPT" --quality high
```

**Options:**
- `--size`: "1024x1024" (square), "1536x1024" (landscape), "1024x1536" (portrait)
- `--quality`: "low" (fast/cheap), "medium" (balanced), "high" (best quality)

### Example

To generate a landscape sunset image:
```bash
telclaude generate-image "A serene mountain landscape at sunset with a lake reflection" --size 1536x1024 --quality high
```

The command outputs:
```
Generated image saved to: /path/to/generated-image.png
Size: 1234.5 KB
Model: gpt-image-1.5
```

## Response Format

After running the command, **include the full file path in your response**. The telclaude relay automatically detects paths to generated media and sends the file to the user via Telegram.

**Example response:**
```
I've generated your image and saved it to:
/workspace/.telclaude-media/generated/1234567890-abc123.png

[The relay will automatically send the image to you]
```

**Important:**
- Always include the full path from the command output in your response
- The relay detects `.telclaude-media/generated/` paths and sends them automatically
- No additional commands are needed - just include the path

## Best Practices

1. **Be Descriptive**: Include details about style, mood, colors, composition
2. **Specify Style**: Mention if you want photorealistic, illustration, cartoon, etc.
3. **Avoid Prohibited Content**: No copyrighted characters, real people, or inappropriate content
4. **Use Quality Wisely**: "low" for drafts, "high" for final images

## Rate Limits

- Maximum 10 images per hour per user
- Maximum 50 images per day per user
- Images are stored temporarily and cleaned up after 24 hours

## Error Handling

If you get "Image generation not available", the user needs to run `telclaude setup-openai` to configure their API key.
