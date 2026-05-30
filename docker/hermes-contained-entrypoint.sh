#!/bin/sh
set -eu

die() {
	printf 'telclaude hermes contained entrypoint: %s\n' "$*" >&2
	exit 1
}

copy_description_chain() {
	rel_dir=$1
	while [ "$rel_dir" != "." ] && [ -n "$rel_dir" ]; do
		src_desc="${SOURCE_SKILLS_DIR}/${rel_dir}/DESCRIPTION.md"
		if [ -f "$src_desc" ]; then
			dst_desc="${CURATED_SKILLS_DIR}/${rel_dir}/DESCRIPTION.md"
			mkdir -p "$(dirname "$dst_desc")"
			cp "$src_desc" "$dst_desc"
		fi
		next_dir=$(dirname "$rel_dir")
		[ "$next_dir" = "$rel_dir" ] && break
		rel_dir=$next_dir
	done
}

SOURCE_SKILLS_DIR=${TELCLAUDE_HERMES_SOURCE_SKILLS_DIR:-/opt/hermes/skills}
ALLOWLIST_PATH=${TELCLAUDE_HERMES_SKILL_ALLOWLIST:-/tmp/telclaude-hermes-contained-skills.allowlist}
HERMES_HOME=${HERMES_HOME:-/home/hermes/.hermes}
CURATED_SKILLS_DIR=${TELCLAUDE_HERMES_CURATED_BUNDLED_SKILLS:-/home/hermes/.telclaude-curated-bundled-skills}
DEST_SKILLS_DIR="${HERMES_HOME}/skills"

[ -d "$SOURCE_SKILLS_DIR" ] || die "source skills directory missing: $SOURCE_SKILLS_DIR"
[ -f "$ALLOWLIST_PATH" ] || die "skill allowlist missing: $ALLOWLIST_PATH"

case "$HERMES_HOME" in
	/home/hermes/*) ;;
	*) die "refusing to manage HERMES_HOME outside /home/hermes: $HERMES_HOME" ;;
esac

case "$CURATED_SKILLS_DIR" in
	/home/hermes/*) ;;
	*) die "refusing to build curated skills outside /home/hermes: $CURATED_SKILLS_DIR" ;;
esac

rm -rf "$CURATED_SKILLS_DIR" "$DEST_SKILLS_DIR"
mkdir -p "$CURATED_SKILLS_DIR" "$HERMES_HOME"

count=0
while IFS= read -r rel || [ -n "$rel" ]; do
	case "$rel" in
		""|\#*) continue ;;
	esac
	case "$rel" in
		/*|*..*|*//*|.*|*/.*|*' '*|*'	'*)
			die "invalid allowlist path: $rel"
			;;
	esac

	src="${SOURCE_SKILLS_DIR}/${rel}"
	dst="${CURATED_SKILLS_DIR}/${rel}"
	[ -d "$src" ] || die "allowlisted skill missing: $rel"
	[ -f "${src}/SKILL.md" ] || die "allowlisted path is not a skill: $rel"

	mkdir -p "$(dirname "$dst")"
	cp -R "$src" "$dst"
	copy_description_chain "$(dirname "$rel")"
	count=$((count + 1))
done < "$ALLOWLIST_PATH"

[ "$count" -gt 0 ] || die "skill allowlist is empty"

mkdir -p "$DEST_SKILLS_DIR"
cp -R "${CURATED_SKILLS_DIR}/." "$DEST_SKILLS_DIR"
cp "$ALLOWLIST_PATH" "${HERMES_HOME}/telclaude-contained-skills.allowlist"
export HERMES_BUNDLED_SKILLS="$CURATED_SKILLS_DIR"

exec /opt/hermes/hermes "$@"
