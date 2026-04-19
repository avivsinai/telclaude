#!/bin/sh
# Install bundled Claude assets into the writable profile volume.
#
# Repo-local `.claude/skills/*` entries are symlinks into `.agents/skills/*`.
# When these are copied into a different root (for example `/home/telclaude-auth`)
# the relative symlinks break unless we dereference them during install.
set -eu

TELCLAUDE_CLAUDE_HOME="${TELCLAUDE_CLAUDE_HOME:-${CLAUDE_CONFIG_DIR:-/home/telclaude-skills}}"
TELCLAUDE_BUNDLED_CLAUDE_DIR="${TELCLAUDE_BUNDLED_CLAUDE_DIR:-/app/.claude}"
TELCLAUDE_UID="${TELCLAUDE_UID:-1000}"
TELCLAUDE_GID="${TELCLAUDE_GID:-1000}"

if [ -d "${TELCLAUDE_BUNDLED_CLAUDE_DIR}/skills" ]; then
	echo "[entrypoint] Installing bundled skills"
	mkdir -p "${TELCLAUDE_CLAUDE_HOME}/skills"

	for skill_path in "${TELCLAUDE_BUNDLED_CLAUDE_DIR}"/skills/*; do
		if [ ! -e "${skill_path}" ] && [ ! -L "${skill_path}" ]; then
			continue
		fi

		skill_name=$(basename "${skill_path}")
		rm -rf "${TELCLAUDE_CLAUDE_HOME}/skills/${skill_name}"
		cp -RL "${skill_path}" "${TELCLAUDE_CLAUDE_HOME}/skills/${skill_name}"
	done

	# chown may fail on NFS with UID squashing; the copied files remain readable.
	chown -R "${TELCLAUDE_UID}:${TELCLAUDE_GID}" "${TELCLAUDE_CLAUDE_HOME}" 2>/dev/null || true
fi

if [ -f "${TELCLAUDE_BUNDLED_CLAUDE_DIR}/CLAUDE.md" ]; then
	echo "[entrypoint] Installing bundled CLAUDE.md"
	mkdir -p "${TELCLAUDE_CLAUDE_HOME}"
	cp "${TELCLAUDE_BUNDLED_CLAUDE_DIR}/CLAUDE.md" "${TELCLAUDE_CLAUDE_HOME}/CLAUDE.md"
fi
