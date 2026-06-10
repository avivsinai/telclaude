#!/bin/sh
set -eu

DOCKER_BIN=${TELCLAUDE_DOCKER_BIN:-}
if [ -z "$DOCKER_BIN" ]; then
	if [ -x /opt/homebrew/opt/docker/bin/docker ]; then
		DOCKER_BIN=/opt/homebrew/opt/docker/bin/docker
	else
		DOCKER_BIN=docker
	fi
fi

HERMES_IMAGE=${TELCLAUDE_HERMES_IMAGE:-nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7}
CONTAINER_HERMES_HOME=${TELCLAUDE_HERMES_CONTAINER_HOME:-/home/hermes/.hermes}
CONTAINER_CWD=${TELCLAUDE_HERMES_CONTAINER_CWD:-/workspace}
CONTAINER_NAME=${TELCLAUDE_HERMES_CONTAINER_NAME:-tc-hermes-contained}
NETWORK_NAME=${TELCLAUDE_HERMES_NETWORK:-telclaude-hermes-private}
CONTAINER_IP=${TELCLAUDE_HERMES_CONTAINED_IP:-192.0.2.11}

: "${HERMES_HOME:?HERMES_HOME is required}"
: "${HERMES_INFERENCE_PROVIDER:?HERMES_INFERENCE_PROVIDER is required}"
: "${HERMES_INFERENCE_MODEL:?HERMES_INFERENCE_MODEL is required}"
: "${HERMES_CODEX_BASE_URL:?HERMES_CODEX_BASE_URL is required}"

mkdir -p "$HERMES_HOME"
HOST_HERMES_HOME=$(cd "$HERMES_HOME" && pwd -P)
HOST_CWD=$(pwd -P)
RUNTIME_OBSERVATION_PATH="$CONTAINER_HERMES_HOME/runtime-observation.json"
RELAY_PROOF_PATH="$CONTAINER_HERMES_HOME/relay-proof.json"
HOST_RUNTIME_OBSERVATION_PATH="$HOST_HERMES_HOME/runtime-observation.json"
HOST_RUNTIME_EVIDENCE_PATH="$HOST_HERMES_HOME/runtime-evidence.json"
HOST_RELAY_PROOF_PATH="$HOST_HERMES_HOME/relay-proof.json"
IMAGE_DIGEST=
case "$HERMES_IMAGE" in
	*@sha256:*) IMAGE_DIGEST="sha256:${HERMES_IMAGE##*@sha256:}" ;;
esac

if [ -z "${DOCKER_HOST:-}" ]; then
	HOME_DIR=${HOME:-$(cd ~ && pwd)}
	if [ -S "$HOME_DIR/.colima/default/docker.sock" ]; then
		DOCKER_HOST="unix://$HOME_DIR/.colima/default/docker.sock"
		export DOCKER_HOST
	fi
fi

NETWORK_JSON=$("$DOCKER_BIN" network inspect "$NETWORK_NAME" --format '{{json .}}' 2>/dev/null || true)
if [ -z "$NETWORK_JSON" ]; then
	printf 'Hermes contained probe requires existing Docker network: %s\n' "$NETWORK_NAME" >&2
	exit 125
fi

python3 - "$NETWORK_JSON" <<'PY'
import json
import sys

network = json.loads(sys.argv[1])
name = network.get("Name", "")
if network.get("Internal") is not True:
    raise SystemExit(f"Hermes contained probe network is not internal: {name}")
containers = network.get("Containers") or {}
names = sorted((container.get("Name") or "") for container in containers.values())
if "telclaude" not in names:
    raise SystemExit("Hermes contained probe requires relay container 'telclaude' on the network")
unexpected = [value for value in names if value not in {"telclaude"}]
if unexpected:
    raise SystemExit(
        "Hermes contained probe network has unexpected pre-existing containers: "
        + ", ".join(unexpected)
    )
PY

if "$DOCKER_BIN" container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
	printf 'Hermes contained probe container already exists: %s\n' "$CONTAINER_NAME" >&2
	exit 125
fi

rm -f "$HOST_RUNTIME_OBSERVATION_PATH" "$HOST_RUNTIME_EVIDENCE_PATH" "$HOST_RELAY_PROOF_PATH"

set +e
"$DOCKER_BIN" run \
	--name "$CONTAINER_NAME" \
	--network "$NETWORK_NAME" \
	--ip "$CONTAINER_IP" \
	--add-host api.anthropic.com:192.0.2.1 \
	--add-host api.openai.com:192.0.2.1 \
	--add-host auth.openai.com:192.0.2.1 \
	--add-host chatgpt.com:192.0.2.1 \
	--add-host generativelanguage.googleapis.com:192.0.2.1 \
	--add-host openrouter.ai:192.0.2.1 \
	--add-host api.x.ai:192.0.2.1 \
	--cap-drop ALL \
	--security-opt no-new-privileges:true \
	--pids-limit 256 \
	--memory 2g \
	--cpus 2 \
	--tmpfs /tmp:size=128m,mode=1777 \
	-e HERMES_HOME="$CONTAINER_HERMES_HOME" \
	-e HOME="/home/hermes" \
	-e NO_COLOR="${NO_COLOR:-1}" \
	-e HERMES_INFERENCE_PROVIDER="$HERMES_INFERENCE_PROVIDER" \
	-e HERMES_INFERENCE_MODEL="$HERMES_INFERENCE_MODEL" \
	-e HERMES_CODEX_BASE_URL="$HERMES_CODEX_BASE_URL" \
	-e TELCLAUDE_HERMES_RUNTIME_OBSERVATION_PATH="$RUNTIME_OBSERVATION_PATH" \
	-e TELCLAUDE_HERMES_RELAY_PROOF_PATH="$RELAY_PROOF_PATH" \
	-v "$HOST_HERMES_HOME:$CONTAINER_HERMES_HOME:rw" \
	-v "$HOST_CWD:$CONTAINER_CWD:ro" \
	-w "$CONTAINER_CWD" \
	--entrypoint /bin/sh \
	"$HERMES_IMAGE" \
	-c 'python - "$TELCLAUDE_HERMES_RUNTIME_OBSERVATION_PATH" <<'"'"'PY'"'"'
import json
import os
import socket
import urllib.request

path = os.environ["TELCLAUDE_HERMES_RUNTIME_OBSERVATION_PATH"]
relay_ip = ""
observed_peer = ""
try:
    relay_ip = socket.gethostbyname("telclaude")
except Exception:
    relay_ip = ""
try:
    request = urllib.request.Request("http://telclaude:8790/v1/models", method="GET")
    with urllib.request.urlopen(request, timeout=5) as response:
        observed_peer = response.headers.get("x-telclaude-model-relay-observed-peer-address", "")
except Exception:
    observed_peer = ""
payload = {
    "hostname": socket.gethostname(),
    "relayResolvedAddress": relay_ip,
    "observedPeerAddress": observed_peer,
}
tmp_path = f"{path}.tmp"
with open(tmp_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True)
    handle.write("\n")
os.replace(tmp_path, path)
PY
/opt/hermes/hermes "$@"
status=$?
python - "$TELCLAUDE_HERMES_RELAY_PROOF_PATH" "$TELCLAUDE_HERMES_RUNTIME_OBSERVATION_PATH" <<'"'"'PY'"'"'
import json
import os
import re
import sys
import urllib.request

path = sys.argv[1]
runtime_observation_path = sys.argv[2]
auth_path = os.path.join(os.environ["HERMES_HOME"], "auth.json")
try:
    with open(auth_path, encoding="utf-8") as handle:
        auth = json.load(handle)
token = ""
for entry in auth.get("credential_pool", {}).get("openai-codex", []):
    if entry.get("id") == "telclaude-relay" and entry.get("source") == "manual:telclaude-relay":
        token = entry.get("access_token", "")
        break
    if not token:
        raise RuntimeError("relay token missing from Hermes auth store")
    request = urllib.request.Request(
        "http://telclaude:8790/v1/openai-codex-proxy/_telclaude/relay-proof/latest",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        proof = json.loads(response.read().decode("utf-8"))
    if not isinstance(proof, dict):
        raise RuntimeError("relay proof is not a JSON object")
    expected = {
        "schemaVersion": "telclaude.hermes.cli-headless-relay-proof.v1",
        "source": "telclaude-openai-codex-proxy",
        "method": "POST",
        "path": "/backend-api/codex/responses",
    }
    for key, value in expected.items():
        if proof.get(key) != value:
            raise RuntimeError(f"relay proof {key} is {proof.get(key)!r}, expected {value!r}")
    upstream_status = proof.get("upstreamStatus")
    if not isinstance(upstream_status, int) or upstream_status < 200 or upstream_status >= 300:
        raise RuntimeError(f"relay proof upstreamStatus is {upstream_status!r}")
    proof_token_sha256 = proof.get("proofTokenSha256")
    if not isinstance(proof_token_sha256, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", proof_token_sha256):
        raise RuntimeError("relay proof proofTokenSha256 is missing or invalid")
    signature = proof.get("signature")
    if not isinstance(signature, dict):
        raise RuntimeError("relay proof signature is missing")
    for key in ("version", "scope", "timestamp", "nonce", "method", "path", "requestBodySha256", "responseBodySha256", "signature"):
        value = signature.get(key)
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"relay proof signature.{key} is missing")
    observed_peer = proof.get("observedPeerAddress")
    if not isinstance(observed_peer, str) or not observed_peer.strip():
        raise RuntimeError("relay proof observedPeerAddress is missing")
    if os.path.exists(runtime_observation_path):
        with open(runtime_observation_path, encoding="utf-8") as handle:
            observation = json.load(handle)
        runtime_peer = observation.get("observedPeerAddress")
        if isinstance(runtime_peer, str) and runtime_peer.strip() and runtime_peer.strip() != observed_peer.strip():
            raise RuntimeError(
                f"relay proof observedPeerAddress {observed_peer!r} does not match runtime observedPeerAddress {runtime_peer!r}"
            )
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(proof, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp_path, path)
except Exception as exc:
    print(f"failed to collect relay proof evidence: {exc}", file=sys.stderr)
    sys.exit(126)
PY
proof_status=$?
if [ "$status" -eq 0 ] && [ "$proof_status" -ne 0 ]; then
	status=$proof_status
fi
exit "$status"' \
	sh "$@"
status=$?
set -e

if [ -f "$HOST_RUNTIME_OBSERVATION_PATH" ]; then
	CONTAINER_ID=$("$DOCKER_BIN" inspect --format '{{.Id}}' "$CONTAINER_NAME" 2>/dev/null || true)
	CONTAINER_HOSTNAME=$("$DOCKER_BIN" inspect --format '{{.Config.Hostname}}' "$CONTAINER_NAME" 2>/dev/null || true)
	CONTAINER_INSPECT_JSON=$("$DOCKER_BIN" inspect "$CONTAINER_NAME" 2>/dev/null || printf '[]')
	python3 - "$HOST_RUNTIME_OBSERVATION_PATH" "$HOST_RUNTIME_EVIDENCE_PATH" \
		"$CONTAINER_NAME" "$NETWORK_NAME" "$CONTAINER_ID" "$HERMES_IMAGE" "$IMAGE_DIGEST" \
		"$CONTAINER_HOSTNAME" "$CONTAINER_INSPECT_JSON" "$CONTAINER_IP" <<'PY'
import ipaddress
import json
import os
import sys

observation_path, evidence_path = sys.argv[1], sys.argv[2]
container_name, network_name, container_id, image, image_digest, inspected_hostname, inspect_json, configured_container_ip = sys.argv[3:11]
with open(observation_path, encoding="utf-8") as handle:
    observation = json.load(handle)
container_ip = ""
try:
    inspect_docs = json.loads(inspect_json)
    if inspect_docs:
        networks = inspect_docs[0].get("NetworkSettings", {}).get("Networks", {})
        container_ip = (networks.get(network_name) or {}).get("IPAddress", "")
except Exception:
    container_ip = ""
try:
    ipaddress.ip_address(container_ip)
except ValueError:
    container_ip = configured_container_ip
payload = {
    "kind": "contained-docker",
    "containerName": container_name,
    "networkName": network_name,
    "containerId": container_id or observation.get("hostname", ""),
    "image": image,
    "imageDigest": image_digest,
    "hostname": inspected_hostname or observation.get("hostname", ""),
    "relayHost": "telclaude",
    "relayResolvedAddress": observation.get("relayResolvedAddress", ""),
    "containerIpAddress": container_ip,
    "observedPeerAddress": observation.get("observedPeerAddress", ""),
    "provenanceSource": "docker-inspect-container-dns-and-relay-peer",
}
tmp_path = f"{evidence_path}.tmp"
with open(tmp_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.replace(tmp_path, evidence_path)
PY
fi

"$DOCKER_BIN" rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
exit "$status"
