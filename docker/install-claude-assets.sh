#!/bin/sh
# Install bundled Claude assets into the writable profile volume or the shared
# skill catalog.
#
# Repo-local `.claude/skills/*` entries are symlinks into `.agents/skills/*`.
# When these are copied into a different root (for example `/home/telclaude-auth`
# or `/home/telclaude-skill-catalog`) the relative symlinks break unless we
# dereference them during install. We also migrate any legacy per-profile
# `skills/` and `skills-draft/` directories into the shared catalog before
# replacing them with symlinks.
set -eu

TELCLAUDE_CLAUDE_HOME="${TELCLAUDE_CLAUDE_HOME:-${CLAUDE_CONFIG_DIR:-/home/telclaude-skills}}"
TELCLAUDE_SKILL_CATALOG_DIR="${TELCLAUDE_SKILL_CATALOG_DIR:-}"
TELCLAUDE_BUNDLED_CLAUDE_DIR="${TELCLAUDE_BUNDLED_CLAUDE_DIR:-/app/.claude}"
TELCLAUDE_UID="${TELCLAUDE_UID:-1000}"
TELCLAUDE_GID="${TELCLAUDE_GID:-1000}"
ACTIVE_SKILLS_DIR="${TELCLAUDE_CLAUDE_HOME}/skills"
DRAFT_SKILLS_DIR="${TELCLAUDE_CLAUDE_HOME}/skills-draft"
CAN_MUTATE_SKILL_CATALOG=1

can_write_dir() {
	dir="$1"
	test_file="${dir}/.telclaude-write-test.$$"

	if ! mkdir -p "${dir}" 2>/dev/null; then
		return 1
	fi

	if ! (umask 077 && : >"${test_file}") 2>/dev/null; then
		return 1
	fi

	rm -f "${test_file}"
	return 0
}

merge_missing_entries() {
	source_dir="$1"
	target_dir="$2"

	if [ ! -d "${source_dir}" ] || [ -L "${source_dir}" ]; then
		return 0
	fi

	echo "[entrypoint] Migrating legacy skill data from ${source_dir} to ${target_dir}"
	mkdir -p "${target_dir}"

	for entry in "${source_dir}"/* "${source_dir}"/.[!.]* "${source_dir}"/..?*; do
		if [ ! -e "${entry}" ] && [ ! -L "${entry}" ]; then
			continue
		fi

		entry_name=$(basename "${entry}")
		if [ -e "${target_dir}/${entry_name}" ] || [ -L "${target_dir}/${entry_name}" ]; then
			continue
		fi

		cp -a "${entry}" "${target_dir}/${entry_name}"
	done
}

ensure_symlink() {
	link_path="$1"
	target_path="$2"

	if [ -L "${link_path}" ] && [ "$(readlink "${link_path}")" = "${target_path}" ]; then
		return 0
	fi

	rm -rf "${link_path}"
	ln -s "${target_path}" "${link_path}"
}

materialize_skill() {
	source_path="$1"
	skill_name=$(basename "${source_path}")
	target_path="${ACTIVE_SKILLS_DIR}/${skill_name}"

	if [ -L "${target_path}" ] || [ -f "${target_path}" ]; then
		rm -rf "${target_path}"
	fi

	mkdir -p "${target_path}"
	cp -RL "${source_path}/." "${target_path}/"
}

if [ -n "${TELCLAUDE_SKILL_CATALOG_DIR}" ]; then
	ACTIVE_SKILLS_DIR="${TELCLAUDE_SKILL_CATALOG_DIR}/skills"
	DRAFT_SKILLS_DIR="${TELCLAUDE_SKILL_CATALOG_DIR}/skills-draft"
	mkdir -p "${TELCLAUDE_CLAUDE_HOME}"
	if can_write_dir "${TELCLAUDE_SKILL_CATALOG_DIR}"; then
		mkdir -p "${ACTIVE_SKILLS_DIR}" "${DRAFT_SKILLS_DIR}"
		merge_missing_entries "${TELCLAUDE_CLAUDE_HOME}/skills" "${ACTIVE_SKILLS_DIR}"
		merge_missing_entries "${TELCLAUDE_CLAUDE_HOME}/skills-draft" "${DRAFT_SKILLS_DIR}"
	else
		CAN_MUTATE_SKILL_CATALOG=0
		echo "[entrypoint] Shared skill catalog is read-only; skipping catalog mutation"
	fi
	ensure_symlink "${TELCLAUDE_CLAUDE_HOME}/skills" "${ACTIVE_SKILLS_DIR}"
	ensure_symlink "${TELCLAUDE_CLAUDE_HOME}/skills-draft" "${DRAFT_SKILLS_DIR}"
fi

if [ "${CAN_MUTATE_SKILL_CATALOG}" = "1" ] && [ -d "${TELCLAUDE_BUNDLED_CLAUDE_DIR}/skills" ]; then
	echo "[entrypoint] Installing bundled skills"
	mkdir -p "${ACTIVE_SKILLS_DIR}"

	for skill_path in "${TELCLAUDE_BUNDLED_CLAUDE_DIR}"/skills/*; do
		if [ ! -e "${skill_path}" ] && [ ! -L "${skill_path}" ]; then
			continue
		fi

		materialize_skill "${skill_path}"
	done

	# chown may fail on NFS with UID squashing; the copied files remain readable.
	chown -R "${TELCLAUDE_UID}:${TELCLAUDE_GID}" \
		"${TELCLAUDE_CLAUDE_HOME}" \
		"${ACTIVE_SKILLS_DIR}" \
		"${DRAFT_SKILLS_DIR}" 2>/dev/null || true
elif [ "${CAN_MUTATE_SKILL_CATALOG}" = "0" ] && [ -d "${TELCLAUDE_BUNDLED_CLAUDE_DIR}/skills" ]; then
	echo "[entrypoint] Shared skill catalog is read-only; assuming another container materialized bundled skills"
fi

if [ -f "${TELCLAUDE_BUNDLED_CLAUDE_DIR}/CLAUDE.md" ]; then
	echo "[entrypoint] Installing bundled CLAUDE.md"
	mkdir -p "${TELCLAUDE_CLAUDE_HOME}"
	cp "${TELCLAUDE_BUNDLED_CLAUDE_DIR}/CLAUDE.md" "${TELCLAUDE_CLAUDE_HOME}/CLAUDE.md"
fi
