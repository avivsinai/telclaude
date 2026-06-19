#!/bin/sh
# Build telclaude Docker images with automatic git revision stamping.
#
# Usage: ./docker/build.sh [docker compose build args...]
set -e

cd "$(dirname "$0")/.."

export GIT_COMMIT
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

if [ "${TELCLAUDE_BUILD_BROWSER:-0}" = "1" ]; then
	set -- -f docker/docker-compose.yml -f docker/docker-compose.browser.yml --profile whatsapp build "$@"
else
	set -- -f docker/docker-compose.yml --profile whatsapp build "$@"
fi

exec docker compose "$@"
