---
name: video-frames
description: Extracts frames from video files using ffmpeg for visual analysis. Use when users send videos and want frame-by-frame analysis, thumbnails, or key moment extraction.
allowed-tools: Bash, Read, Glob, Write
---

# Video Frames Skill

Extract frames from video files using ffmpeg for LLM visual analysis.

## When to Use

Use when users:
- Send a video and ask "what's in this video?"
- Want specific frames or timestamps extracted
- Need thumbnails or key frames from a video
- Ask to analyze video content visually

## Frame Extraction

Use the bundled script via `telclaude skill-path`:

```bash
bash "$(telclaude skill-path video-frames scripts/frame.sh)" <video_path> [output_dir] [interval]
```

- `video_path`: Path to the video file (check `/media/inbox/` for Telegram uploads)
- `output_dir`: Where to save frames (default: `/media/outbox/frames/`)
- `interval`: Seconds between frames (default: 2)

### Manual extraction (alternative)

Single frame at timestamp:
```bash
ffmpeg -ss 00:00:05 -i /media/inbox/video.mp4 -frames:v 1 -q:v 2 /media/outbox/frame.jpg
```

Key frames only (I-frames):
```bash
ffmpeg -i /media/inbox/video.mp4 -vf "select=eq(pict_type\,I)" -vsync vfr -q:v 2 /media/outbox/keyframe_%03d.jpg
```

Every N seconds:
```bash
ffmpeg -i /media/inbox/video.mp4 -vf "fps=1/5" -q:v 2 /media/outbox/frame_%03d.jpg
```

## Video Info

Get duration and metadata:
```bash
ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 /media/inbox/video.mp4
```

## Output Guidelines

- Extract 3-5 representative frames for short videos (<30s)
- For longer videos, use wider intervals or key frames only
- After extraction, use the Read tool to view frames and describe what you see
- Save output frames to `/media/outbox/` so the relay can send them back
