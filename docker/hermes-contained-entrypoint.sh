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

restore_owner_write_if_present() {
	target=$1
	if [ -d "$target" ]; then
		chmod -R u+w "$target" 2>/dev/null || true
	fi
}

SOURCE_SKILLS_DIR=${TELCLAUDE_HERMES_SOURCE_SKILLS_DIR:-/opt/hermes/skills}
ALLOWLIST_PATH=${TELCLAUDE_HERMES_SKILL_ALLOWLIST:-/tmp/telclaude-hermes-contained-skills.allowlist}
HERMES_HOME=${HERMES_HOME:-/home/hermes/.hermes}
HERMES_RUNTIME_UID=${TELCLAUDE_HERMES_RUNTIME_UID:-10000}
HERMES_RUNTIME_GID=${TELCLAUDE_HERMES_RUNTIME_GID:-10000}
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

restore_owner_write_if_present "$CURATED_SKILLS_DIR"
restore_owner_write_if_present "$DEST_SKILLS_DIR"
rm -rf "$CURATED_SKILLS_DIR" "$DEST_SKILLS_DIR"
mkdir -p "$CURATED_SKILLS_DIR" "$HERMES_HOME"
if [ "$(id -u)" = "0" ]; then
	chown "0:$HERMES_RUNTIME_GID" "$HERMES_HOME"
	chmod 1770 "$HERMES_HOME"
	chown "$HERMES_RUNTIME_UID:$HERMES_RUNTIME_GID" "$CURATED_SKILLS_DIR"
else
	chmod 700 "$HERMES_HOME"
fi

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
find "$DEST_SKILLS_DIR" -type d -exec chmod 0550 {} +
find "$DEST_SKILLS_DIR" -type f -exec chmod 0440 {} +
chmod 0440 "${HERMES_HOME}/telclaude-contained-skills.allowlist"
if [ "$(id -u)" = "0" ]; then
	chown -R "$HERMES_RUNTIME_UID:$HERMES_RUNTIME_GID" \
		"$CURATED_SKILLS_DIR" \
		"$DEST_SKILLS_DIR" \
		"${HERMES_HOME}/telclaude-contained-skills.allowlist"
	find "$DEST_SKILLS_DIR" -type d -exec chmod 0550 {} +
	find "$DEST_SKILLS_DIR" -type f -exec chmod 0440 {} +
	chmod 0440 "${HERMES_HOME}/telclaude-contained-skills.allowlist"
fi
export HERMES_BUNDLED_SKILLS="$CURATED_SKILLS_DIR"

mint_peer_bound_codex_relay_token() {
	secret=$1
	token_scope=$2
	peer_address=$(hostname -i 2>/dev/null | awk '{print $1}')
	[ -n "$peer_address" ] || die "could not determine contained peer address for Codex relay token"
	node - "$secret" "$peer_address" "$token_scope" <<'NODE'
const crypto = require("node:crypto");
const secret = process.argv[2];
const peerAddress = process.argv[3];
const tokenScope = process.argv[4];
if (tokenScope !== "run" && tokenScope !== "server") {
  throw new Error(`unsupported token scope: ${tokenScope}`);
}
const now = Date.now();
const payload = {
  version: 1,
  tokenScope,
  runId: `hermes-contained-${crypto.randomUUID()}`,
  peerAddress,
  issuedAt: now,
  expiresAt: tokenScope === "server" ? null : now + 300000,
  nonce: crypto.randomUUID(),
};
const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
const signature = crypto.createHmac("sha256", secret).update(encodedPayload).digest("base64url");
process.stdout.write(`tc-openai-codex-relay-v1.${encodedPayload}.${signature}`);
NODE
}

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
	CODEX_TOKEN_SCOPE=run
	if [ "${1:-}" = "gateway" ] && [ "${2:-}" = "run" ]; then
		CODEX_TOKEN_SCOPE=server
	fi
	CODEX_PEER_BOUND_TOKEN=$(mint_peer_bound_codex_relay_token "$CODEX_RELAY_TOKEN" "$CODEX_TOKEN_SCOPE")

	umask 077
	cat > "${HERMES_HOME}/config.yaml" <<EOF
model:
  provider: openai-codex
  default: ${CODEX_MODEL}
  api_mode: codex_responses
  openai_runtime: auto
skills:
  creation_nudge_interval: 0
EOF
	cat > "${HERMES_HOME}/secret-manifest.json" <<'EOF'
{
  "schemaVersion": 1,
  "rawCredentialPolicy": "relay-owned-only",
  "relayTokenBinding": "run-peer-bound"
}
EOF
	tmp_auth="${HERMES_HOME}/auth.json.tmp.$$"
	cat > "$tmp_auth" <<EOF
{
  "version": 1,
  "active_provider": "openai-codex",
  "suppressed_sources": {
    "openai-codex": [
      "device_code"
    ]
  },
  "providers": {
    "openai-codex": {
      "auth_mode": "telclaude-relay",
      "last_refresh": "1970-01-01T00:00:00.000Z"
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
        "access_token": "${CODEX_PEER_BOUND_TOKEN}",
        "base_url": "http://telclaude:8790/v1/openai-codex-proxy"
      }
    ]
  }
}
EOF
	mv "$tmp_auth" "${HERMES_HOME}/auth.json"
	if [ "$(id -u)" = "0" ]; then
		chown "0:$HERMES_RUNTIME_GID" \
			"${HERMES_HOME}/config.yaml" \
			"${HERMES_HOME}/secret-manifest.json" \
			"${HERMES_HOME}/auth.json"
		chmod 0440 \
			"${HERMES_HOME}/config.yaml" \
			"${HERMES_HOME}/secret-manifest.json" \
			"${HERMES_HOME}/auth.json"
	else
		chmod 600 "${HERMES_HOME}/config.yaml" "${HERMES_HOME}/secret-manifest.json" "${HERMES_HOME}/auth.json"
	fi
	unset TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN CODEX_RELAY_TOKEN CODEX_PEER_BOUND_TOKEN CODEX_TOKEN_SCOPE
fi

if [ "$(id -u)" = "0" ]; then
	command -v setpriv >/dev/null 2>&1 || die "setpriv is required to drop privileges"
	exec setpriv \
		--reuid="$HERMES_RUNTIME_UID" \
		--regid="$HERMES_RUNTIME_GID" \
		--clear-groups \
		--bounding-set=-all \
		--inh-caps=-all \
		--ambient-caps=-all \
		/opt/hermes/hermes "$@"
fi

exec /opt/hermes/hermes "$@"
