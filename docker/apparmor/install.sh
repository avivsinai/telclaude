#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# Telclaude AppArmor Profile Installer
#
# Installs all telclaude AppArmor profiles into the system.
# Must be run as root on the Docker host (not inside a container).
#
# Usage:
#   sudo ./install.sh              # Install all profiles
#   sudo ./install.sh vault relay  # Install specific profiles
# ═══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# All available profiles
ALL_PROFILES=(
  telclaude-vault
  telclaude-relay
  telclaude-agent
  telclaude-moltbook
)

if [ "$(id -u)" -ne 0 ]; then
  echo "[apparmor] install must be run as root" >&2
  exit 1
fi

if ! command -v apparmor_parser >/dev/null 2>&1; then
  echo "[apparmor] apparmor_parser not found. Install apparmor-utils:" >&2
  echo "  sudo apt-get install apparmor-utils" >&2
  exit 1
fi

# Determine which profiles to install
if [ $# -gt 0 ]; then
  # Install specific profiles (strip telclaude- prefix if provided)
  PROFILES=()
  for arg in "$@"; do
    name="${arg#telclaude-}"
    PROFILES+=("telclaude-${name}")
  done
else
  # Install all profiles
  PROFILES=("${ALL_PROFILES[@]}")
fi

mkdir -p /etc/apparmor.d

INSTALLED=0
FAILED=0

for PROFILE_NAME in "${PROFILES[@]}"; do
  PROFILE_SRC="${SCRIPT_DIR}/${PROFILE_NAME}"
  PROFILE_DEST="/etc/apparmor.d/${PROFILE_NAME}"

  if [ ! -f "${PROFILE_SRC}" ]; then
    echo "[apparmor] profile not found: ${PROFILE_SRC}" >&2
    FAILED=$((FAILED + 1))
    continue
  fi

  cp "${PROFILE_SRC}" "${PROFILE_DEST}"
  apparmor_parser -r "${PROFILE_DEST}"

  if command -v aa-status >/dev/null 2>&1; then
    if ! aa-status 2>/dev/null | grep -q "${PROFILE_NAME}"; then
      echo "[apparmor] WARNING: ${PROFILE_NAME} not listed in aa-status" >&2
      FAILED=$((FAILED + 1))
      continue
    fi
  fi

  echo "[apparmor] loaded ${PROFILE_NAME}"
  INSTALLED=$((INSTALLED + 1))
done

echo ""
echo "[apparmor] installed: ${INSTALLED}, failed: ${FAILED}"

if [ "${FAILED}" -gt 0 ]; then
  exit 1
fi
