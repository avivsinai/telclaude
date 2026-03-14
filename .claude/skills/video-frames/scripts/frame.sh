#!/usr/bin/env bash
# Extract frames from a video at regular intervals using ffmpeg.
# Usage: frame.sh <video_path> [output_dir] [interval_seconds]

set -euo pipefail

VIDEO="${1:?Usage: frame.sh <video_path> [output_dir] [interval_seconds]}"
OUTDIR="${2:-/media/outbox/frames}"
INTERVAL="${3:-2}"

if [ ! -f "$VIDEO" ]; then
  echo "Error: Video file not found: $VIDEO" >&2
  exit 1
fi

mkdir -p "$OUTDIR"

# Get video duration
DURATION=$(ffprobe -v error -show_entries format=duration \
  -of default=noprint_wrappers=1:nokey=1 "$VIDEO" 2>/dev/null | cut -d. -f1)

echo "Video: $VIDEO"
echo "Duration: ${DURATION}s"
echo "Extracting frames every ${INTERVAL}s to $OUTDIR"

ffmpeg -i "$VIDEO" -vf "fps=1/${INTERVAL}" -q:v 2 "${OUTDIR}/frame_%03d.jpg" -y 2>/dev/null

COUNT=$(ls -1 "${OUTDIR}"/frame_*.jpg 2>/dev/null | wc -l | tr -d ' ')
echo "Extracted $COUNT frames"
