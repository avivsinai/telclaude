---
name: image-generator
description: Generates images using GPT Image 1.5 API. Use when users request image creation, illustration, or visual content.
---

# Image Generation Skill

You can generate images using the GPT Image 1.5 API when users request visual content.

## When to Use

Use this skill when users:
- Ask to "create", "generate", "draw", or "make" an image
- Request illustrations, artwork, diagrams, or visual content
- Want to visualize concepts, ideas, or descriptions

## How to Generate Images

To generate an image, use the Bash tool to run the telclaude image generation command:

```bash
telclaude generate-image "your detailed prompt here"
```

### Options

- `--size`: Image dimensions. Default: 1024x1024
  - `auto`: Let the model choose optimal size
  - `1024x1024`: Square (default)
  - `1536x1024`: Landscape
  - `1024x1536`: Portrait
- `--quality`: Quality tier (low, medium, high). Default: medium
  - low: ~$0.01/image, fastest
  - medium: ~$0.04/image, balanced
  - high: ~$0.17/image, best quality

### Example

```bash
telclaude generate-image "A serene mountain landscape at sunset with a lake reflection" --quality high --size 1536x1024
```

## Response Format

After generation, the command outputs the local file path. Use this path to:
1. Tell the user the image has been generated
2. The image will be automatically sent to the Telegram chat

## Best Practices

1. **Be Descriptive**: Include details about style, mood, colors, composition
2. **Specify Style**: Mention if you want photorealistic, illustration, cartoon, etc.
3. **Avoid Prohibited Content**: No copyrighted characters, real people, or inappropriate content
4. **Consider Cost**: Use "low" quality for quick drafts, "high" for final images

## Limitations

- Maximum 10 images per hour per user (configurable)
- Maximum 50 images per day per user (configurable)
- Some content may be blocked by OpenAI's safety filters
- Images are stored temporarily and cleaned up after 24 hours

## Cost Awareness

Inform users of approximate costs when generating multiple images:
- 1024x1024 medium quality: ~$0.04 each
- High quality or larger sizes cost more
