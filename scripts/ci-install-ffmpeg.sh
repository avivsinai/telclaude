#!/usr/bin/env bash
set -euo pipefail

# GitHub-hosted Ubuntu runners often stall on azure.archive.ubuntu.com.
# Retry apt-get update so a 180s timeout does not fail the whole Verify job.
apt_opts=(
	-o Acquire::Retries=3
	-o Acquire::http::Timeout=20
	-o Acquire::https::Timeout=20
	-o DPkg::Lock::Timeout=30
)

attempt=1
max_attempts=3
until sudo timeout 180s apt-get "${apt_opts[@]}" update; do
	if ((attempt >= max_attempts)); then
		echo "error: apt-get update failed after ${max_attempts} attempts" >&2
		exit 1
	fi
	attempt=$((attempt + 1))
	sleep 10
done

sudo env DEBIAN_FRONTEND=noninteractive timeout 900s apt-get \
	"${apt_opts[@]}" \
	install -y --no-install-recommends ffmpeg
