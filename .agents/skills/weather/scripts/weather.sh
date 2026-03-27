#!/usr/bin/env bash
# Fetch weather from wttr.in.
# Usage: weather.sh <location> [mode]
#   mode: current (default), forecast, detailed, moon

set -euo pipefail

LOCATION="${1:?Usage: weather.sh <location> [current|forecast|detailed|moon]}"
MODE="${2:-current}"

# URL-encode spaces in location
ENCODED=$(echo "$LOCATION" | sed 's/ /+/g')

case "$MODE" in
  current)
    curl -s "wttr.in/${ENCODED}?format=%l:+%c+%t+%w+%h+%p"
    ;;
  forecast)
    curl -s "wttr.in/${ENCODED}?0&format=3"
    ;;
  detailed)
    curl -s "wttr.in/${ENCODED}?2&Q&lang=en" | head -40
    ;;
  moon)
    curl -s "wttr.in/Moon"
    ;;
  *)
    echo "Unknown mode: $MODE (use: current, forecast, detailed, moon)" >&2
    exit 1
    ;;
esac
