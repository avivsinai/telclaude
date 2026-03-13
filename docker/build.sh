#!/bin/sh
# Build telclaude Docker images with automatic git revision stamping.
# Usage: ./docker/build.sh [docker compose build args...]
set -e

cd "$(dirname "$0")/.."

export GIT_COMMIT
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

exec docker compose -f docker/docker-compose.yml build "$@"
