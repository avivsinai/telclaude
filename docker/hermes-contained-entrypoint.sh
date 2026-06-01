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
CODEX_PROVIDER=${HERMES_INFERENCE_PROVIDER:-}
CODEX_MODEL=${HERMES_INFERENCE_MODEL:-}
CODEX_BASE_URL=${HERMES_CODEX_BASE_URL:-}
CODEX_RELAY_TOKEN=${TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN:-}

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
chmod 700 "$HERMES_HOME"

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

if [ "$CODEX_PROVIDER" = "openai-codex" ]; then
	[ -n "$CODEX_MODEL" ] || die "HERMES_INFERENCE_MODEL is required for openai-codex"
	[ "$CODEX_BASE_URL" = "http://telclaude:8790/v1/openai-codex-proxy" ] || \
		die "HERMES_CODEX_BASE_URL must point at the Telclaude OpenAI Codex relay proxy"
	[ -n "$CODEX_RELAY_TOKEN" ] || die "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN is required"
	case "$CODEX_RELAY_TOKEN" in
		*[!A-Za-z0-9._~+/@:=,-]*)
			die "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN contains unsupported characters"
			;;
	esac
	case "$CODEX_MODEL" in
		*[!A-Za-z0-9._:/+-]*)
			die "HERMES_INFERENCE_MODEL contains unsupported characters"
			;;
	esac

	umask 077
	cat > "${HERMES_HOME}/config.yaml" <<EOF
model:
  provider: openai-codex
  default: ${CODEX_MODEL}
  api_mode: codex_responses
  openai_runtime: auto
EOF
	tmp_auth="${HERMES_HOME}/auth.json.tmp.$$"
	cat > "$tmp_auth" <<EOF
{
  "version": 1,
  "active_provider": "openai-codex",
  "providers": {
    "openai-codex": {
      "auth_mode": "telclaude-relay",
      "last_refresh": "1970-01-01T00:00:00.000Z",
      "tokens": {
        "access_token": "${CODEX_RELAY_TOKEN}",
        "refresh_token": "telclaude-relay-token-is-not-refreshable"
      }
    }
  },
  "credential_pool": {
    "openai-codex": [
      {
        "id": "telclaude-relay",
        "label": "Telclaude OpenAI Codex relay",
        "auth_type": "api_key",
        "priority": 0,
        "source": "manual:telclaude-relay",
        "access_token": "${CODEX_RELAY_TOKEN}",
        "base_url": "http://telclaude:8790/v1/openai-codex-proxy"
      }
    ]
  }
}
EOF
	mv "$tmp_auth" "${HERMES_HOME}/auth.json"
	chmod 600 "${HERMES_HOME}/auth.json"
	unset TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN CODEX_RELAY_TOKEN
fi

exec /opt/hermes/hermes "$@"
