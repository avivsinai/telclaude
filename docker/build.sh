#!/bin/sh
# Build telclaude Docker images with automatic git revision stamping.
#
# Build order matters: telclaude-agent's Dockerfile.agent starts from
# `FROM telclaude:latest`, so the base image must be rebuilt *before* the
# agent image. `docker compose build` parallelizes by default, which lets
# the agent pull a stale `telclaude:latest` from the local cache. We
# therefore build the base explicitly first, then let compose finish the
# rest (agent + sidecars) in parallel.
#
# Usage: ./docker/build.sh [docker compose build args...]
set -e

cd "$(dirname "$0")/.."

export GIT_COMMIT
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

docker compose -f docker/docker-compose.yml build "$@" telclaude
exec docker compose -f docker/docker-compose.yml build "$@"
