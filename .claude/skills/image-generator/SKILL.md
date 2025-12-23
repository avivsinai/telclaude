---
name: image-generator
description: Generates images using OpenAI's gpt-image-1.5 API. Use when users request image creation, illustration, or visual content.
---

# Image Generation Skill

Generate images using OpenAI's gpt-image-1.5 API when users request visual content.

## When to Use

Use this skill when users:
- Ask to "create", "generate", "draw", or "make" an image
- Request illustrations, artwork, diagrams, or visual content
- Want to visualize concepts, ideas, or descriptions

## How to Generate Images

Use curl to call the OpenAI API directly. The `OPENAI_API_KEY` environment variable is available.

```bash
# Generate image and save to file (uses current directory)
curl -s https://api.openai.com/v1/images/generations \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-image-1.5","prompt":"YOUR_PROMPT_HERE","size":"1024x1024","output_format":"png"}' \
  | jq -r '.data[0].b64_json' | base64 -d > ./generated-image.png
```

**Parameters in the JSON body:**
- `prompt`: Text description of the image (required)
- `size`: "1024x1024" (square), "1536x1024" (landscape), "1024x1536" (portrait)
- `output_format`: "png" (required for base64 output)

### Example

To generate a landscape sunset image:
```bash
curl -s https://api.openai.com/v1/images/generations \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-image-1.5","prompt":"A serene mountain landscape at sunset with a lake reflection","size":"1536x1024","output_format":"png"}' \
  | jq -r '.data[0].b64_json' | base64 -d > ./sunset.png
```

## Response Format

After running the curl command, verify the file was created:
```bash
ls -la ./*.png
```

**Important**: Tell the user the image has been generated and include the file path. Use the Read tool to show the image to the user.

## Best Practices

1. **Be Descriptive**: Include details about style, mood, colors, composition
2. **Specify Style**: Mention if you want photorealistic, illustration, cartoon, etc.
3. **Avoid Prohibited Content**: No copyrighted characters, real people, or inappropriate content
4. **Consider Cost**: Use "low" for quick drafts, "high" for final images

## Limitations

- Maximum 10 images per hour per user
- Maximum 50 images per day per user
- Some content may be blocked by OpenAI's safety filters
- Images are stored temporarily and cleaned up after 24 hours
