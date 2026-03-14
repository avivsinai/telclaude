#!/usr/bin/env bash
# Search for a GIF and download the best result.
# Usage: download-gif.sh <query> [output_path]

set -euo pipefail

QUERY="${1:?Usage: download-gif.sh <query> [output_path]}"
OUTPUT="${2:-/media/outbox/reaction.gif}"

mkdir -p "$(dirname "$OUTPUT")"

URL=$(gifgrep -n 1 "$QUERY" | head -1)

if [ -z "$URL" ]; then
  echo "No GIFs found for: $QUERY" >&2
  exit 1
fi

curl -sL -o "$OUTPUT" "$URL"
echo "$OUTPUT"
