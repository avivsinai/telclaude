#!/usr/bin/env bash
set -euo pipefail

PROFILE_NAME="telclaude-moltbook"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_SRC="${SCRIPT_DIR}/${PROFILE_NAME}"
PROFILE_DEST="/etc/apparmor.d/${PROFILE_NAME}"

if [ ! -f "${PROFILE_SRC}" ]; then
  echo "[apparmor] profile not found: ${PROFILE_SRC}" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "[apparmor] install must be run as root" >&2
  exit 1
fi

mkdir -p /etc/apparmor.d
cp "${PROFILE_SRC}" "${PROFILE_DEST}"

if ! command -v apparmor_parser >/dev/null 2>&1; then
  echo "[apparmor] apparmor_parser not found. Install apparmor-utils." >&2
  exit 1
fi

apparmor_parser -r "${PROFILE_DEST}"

if command -v aa-status >/dev/null 2>&1; then
  aa-status | grep -q "${PROFILE_NAME}" || {
    echo "[apparmor] profile not listed in aa-status" >&2
    exit 1
  }
fi

echo "[apparmor] loaded ${PROFILE_NAME}"
