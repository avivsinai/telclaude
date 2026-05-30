# Hermes Local Colima Live-Run Playbook

Status: prepared only. Do not start Colima or run `docker compose up` until Aviv explicitly gives the go for this machine.

This playbook executes the contained Hermes private-runtime live run for the no-fork wrapper. It is intentionally local and operational: it records the commands, the expected evidence, and the places where the operator must choose whether live evidence becomes committed repo state or remains generated runtime proof.

## Invariants

- The committed default remains `TELCLAUDE_HERMES_PRIVATE_RUNTIME=0`.
- The live run may set `TELCLAUDE_HERMES_PRIVATE_RUNTIME=1` in the shell for this run only.
- `TELCLAUDE_HERMES_API_SERVER_KEY` is generated for this compose-up and is not written to `docker/.env`.
- The Hermes image is pinned by digest, not by tag:
  `nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7`.
- The dedicated Docker network `telclaude-hermes-relay` must be `Internal=true` and contain only `telclaude` and `tc-hermes-contained` during the production topology snapshot.
- The relay overlay assigns stable internal IPs so live MCP bearer tokens are peer-bound or accepted only from the contained Hermes peer IP.
- The contained Hermes runtime must start as uid `10000:10000`, with no added capabilities, `no-new-privileges`, read-only rootfs, and `noexec` tmpfs mounts for `/tmp`, `/run`, and `/home/hermes`.
- The contained Hermes runtime uses `/opt/hermes/hermes` as the direct entrypoint. The pinned image's default s6 wrapper drops privileges internally and is incompatible with starting the container itself as uid `10000` with all capabilities dropped.
- The relay `/run/telclaude` tmpfs must be owned by uid `1000` with mode `0700`; live MCP admin creates its `0600` Unix socket after the relay entrypoint drops privileges.

## 0. Shell Setup

Run from the repo root:

```bash
cd /home/user/MyProjects/telclaude-hermes-wrapper-phase0
export PATH="/opt/homebrew/opt/docker/bin:/opt/homebrew/bin:$PATH"
export DOCKER_BIN="/opt/homebrew/opt/docker/bin/docker"

export TELCLAUDE_HERMES_IMAGE="nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7"
export TELCLAUDE_HERMES_IMAGE_TAG="nousresearch/hermes-agent:v2026.5.29"
export TELCLAUDE_HERMES_PIN="0.15.1"
export TELCLAUDE_HERMES_API_SERVER_KEY="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')"
export TELCLAUDE_HERMES_PRIVATE_RUNTIME=1
export TELCLAUDE_HERMES_RELAY_SUBNET=172.29.92.0/24
export TELCLAUDE_HERMES_RELAY_IP=172.29.92.10
export TELCLAUDE_HERMES_CONTAINED_IP=172.29.92.11
export TELCLAUDE_HERMES_LIVE_MCP_ENABLED=1
export TELCLAUDE_HERMES_LIVE_MCP_ALLOWED_PEERS="$TELCLAUDE_HERMES_CONTAINED_IP"
export TELCLAUDE_HERMES_LIVE_MCP_ADMIN_ENABLED=1
export TELCLAUDE_HERMES_LIVE_MCP_ADMIN_SOCKET=/run/telclaude/hermes-live-mcp-admin.sock

# Required for the one-off operator CLI and relay-authenticated rollback evidence.
# Generate once with `pnpm dev keygen operator`; keep OPERATOR_RPC_AGENT_PRIVATE_KEY
# on the host, pass OPERATOR_RPC_AGENT_PUBLIC_KEY and OPERATOR_RPC_RELAY_PRIVATE_KEY
# into the relay, and pass OPERATOR_RPC_RELAY_PUBLIC_KEY to the rollback CLI.
export OPERATOR_RPC_AGENT_PRIVATE_KEY="${OPERATOR_RPC_AGENT_PRIVATE_KEY:?set from pnpm dev keygen operator}"
export OPERATOR_RPC_AGENT_PUBLIC_KEY="${OPERATOR_RPC_AGENT_PUBLIC_KEY:?set from pnpm dev keygen operator}"
export OPERATOR_RPC_RELAY_PRIVATE_KEY="${OPERATOR_RPC_RELAY_PRIVATE_KEY:?set from pnpm dev keygen operator}"
export OPERATOR_RPC_RELAY_PUBLIC_KEY="${OPERATOR_RPC_RELAY_PUBLIC_KEY:?set from pnpm dev keygen operator}"
```

Compose requires these base-stack values. For a local containment rehearsal without real accounts, use generated placeholders. For an operator smoke against real services, use the real local secret source instead.

```bash
export WORKSPACE_PATH="${WORKSPACE_PATH:-/home/user/MyProjects}"
export TOTP_ENCRYPTION_KEY="${TOTP_ENCRYPTION_KEY:-$(openssl rand -hex 32)}"
export VAULT_ENCRYPTION_KEY="${VAULT_ENCRYPTION_KEY:-$(openssl rand -hex 32)}"
export ANTHROPIC_PROXY_TOKEN="${ANTHROPIC_PROXY_TOKEN:-local-probe-anthropic-proxy-token}"
export TELEGRAM_RPC_AGENT_PRIVATE_KEY="${TELEGRAM_RPC_AGENT_PRIVATE_KEY:-local-probe-telegram-agent-private}"
export TELEGRAM_RPC_AGENT_PUBLIC_KEY="${TELEGRAM_RPC_AGENT_PUBLIC_KEY:-local-probe-telegram-agent-public}"
export TELEGRAM_RPC_RELAY_PRIVATE_KEY="${TELEGRAM_RPC_RELAY_PRIVATE_KEY:-local-probe-telegram-relay-private}"
export TELEGRAM_RPC_RELAY_PUBLIC_KEY="${TELEGRAM_RPC_RELAY_PUBLIC_KEY:-local-probe-telegram-relay-public}"
export SOCIAL_RPC_AGENT_PRIVATE_KEY="${SOCIAL_RPC_AGENT_PRIVATE_KEY:-local-probe-social-agent-private}"
export SOCIAL_RPC_AGENT_PUBLIC_KEY="${SOCIAL_RPC_AGENT_PUBLIC_KEY:-local-probe-social-agent-public}"
export SOCIAL_RPC_RELAY_PRIVATE_KEY="${SOCIAL_RPC_RELAY_PRIVATE_KEY:-local-probe-social-relay-private}"
export SOCIAL_RPC_RELAY_PUBLIC_KEY="${SOCIAL_RPC_RELAY_PUBLIC_KEY:-local-probe-social-relay-public}"
export TELCLAUDE_GIT_PROXY_SECRET="${TELCLAUDE_GIT_PROXY_SECRET:-local-probe-git-proxy-secret}"
```

## 1. Start Colima

Only run this after the explicit go:

```bash
colima status || colima start --runtime docker --cpu 4 --memory 8 --disk 60
docker context use colima
docker version
```

Verify the published image digest before the stack uses it:

```bash
docker buildx imagetools inspect "$TELCLAUDE_HERMES_IMAGE_TAG"
docker pull "$TELCLAUDE_HERMES_IMAGE"
```

Expected digest:

```text
sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7
```

## 2. Validate Compose

```bash
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.hermes.yml \
  config --quiet
```

## 3. Stand Up The Local Stack

This is the first command that actually starts the Hermes overlay:

```bash
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.hermes.yml \
  up -d telclaude tc-hermes-contained
```

Inspect the two relevant services:

```bash
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.hermes.yml \
  ps telclaude tc-hermes-contained

docker inspect tc-hermes-contained --format '{{json .State.Health}}' | jq .
docker logs --tail 120 tc-hermes-contained
```

The live-run blocker here is factual: if Hermes does not start with read-only rootfs plus only non-executable `/tmp`, `/run`, and `/home/hermes` tmpfs mounts, add the smallest specific tmpfs mount needed. Do not relax to writable rootfs, executable tmpfs, or added capabilities.

## 4. Verify Network Topology

The production topology snapshot must show exactly two containers on the internal network:

```bash
docker network inspect telclaude-hermes-relay --format '{{json .}}' \
  | jq -e '
      .Internal == true
      and ([.Containers[]?.Name] | sort) == ["tc-hermes-contained", "telclaude"]
    '
```

If this fails, stop. Do not run probes against a topology with extra peers.

## 5. Probe Commands

These commands are the evidence-generating commands. Use `--json` for machine-readable logs and keep stdout/stderr from the run in the operator notes.

### 5.1 CLI Headless

Use the local Hermes checkout pinned to `v2026.5.29` / `0.15.1` unless the operator chooses a different verified binary.

```bash
git -C /home/user/MyProjects/hermes-agent describe --tags --exact-match
git -C /home/user/MyProjects/hermes-agent show v2026.5.29:pyproject.toml | rg -n '^version = "0.15.1"$'

pnpm dev hermes probe execution.cli_headless \
  --allow-run \
  --json \
  --hermes-bin /home/user/MyProjects/hermes-agent/hermes \
  --hermes-home "$(mktemp -d /tmp/tc-hermes-cli.XXXXXX)" \
  --cwd "$PWD" \
  --timeout-ms 120000 \
  --out artifacts/hermes/probes/execution-cli-headless.json
```

Expected green: exit code `0`, `status=pass`, `ran=true`, and evidence at `artifacts/hermes/probes/execution-cli-headless.json`.

### 5.2 Approval Continuation

```bash
pnpm dev hermes probe execution.approval_continuation \
  --allow-run \
  --json \
  --pin "$TELCLAUDE_HERMES_PIN" \
  --out artifacts/hermes/probes/execution-approval-continuation.json
```

Expected green: exit code `0`, `status=pass`, fallback fixtures written next to the evidence, wrong-actor/stale/replay/mutated-decision denials proven.

### 5.3 API Server Containment

The API containment probe starts and removes its own `tc-hermes-contained` container. It cannot run while the compose-owned `tc-hermes-contained` container still exists on `telclaude-hermes-relay`, because the topology gate requires exactly the relay plus the probe container.

After the production topology snapshot above, remove only the compose Hermes container and leave the relay running:

```bash
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.hermes.yml \
  rm -sf tc-hermes-contained
```

Then run the probe:

```bash
pnpm dev hermes probe execution.api_server_containment \
  --allow-run \
  --json \
  --docker-bin "$DOCKER_BIN" \
  --image "$TELCLAUDE_HERMES_IMAGE" \
  --container-name tc-hermes-contained \
  --network telclaude-hermes-relay \
  --relay-container telclaude \
  --relay-host telclaude \
  --relay-url http://telclaude:8790/health \
  --provider-url http://google-services:3002/v1/health \
  --vault-socket /run/vault/vault.sock \
  --model-url https://api.anthropic.com/v1/models \
  --dns-url http://169.254.169.254/latest/meta-data/,http://10.0.0.1/,http://100.64.0.1/ \
  --timeout-ms 120000 \
  --out artifacts/hermes/probes/execution-api-server-containment.json
```

Expected green: all gates pass, including `lifecycle.started`, `readiness.health`, `readiness.capabilities`, `network.topology`, `network.relay_only`, and `network.tamper_resistant`. The runtime user is not a CLI flag; the command uses the code default `10000:10000` and the evidence should show non-root uid `10000`.

Restore the compose Hermes service after the probe:

```bash
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.hermes.yml \
  up -d tc-hermes-contained
```

### 5.4 Network Probes

Important: `telclaude hermes network-probes` measures the namespace where the command runs. A host run proves host networking only. For relay firewall evidence, run it inside the `telclaude` container and copy the produced artifacts back out.

```bash
docker exec telclaude mkdir -p /data/hermes/network

docker exec telclaude telclaude hermes network-probes \
  --allow-run \
  --json \
  --relay-url http://127.0.0.1:8790/health \
  --provider-url http://google-services:3002/v1/health \
  --vault-socket /run/vault/vault.sock \
  --model-url https://api.anthropic.com/v1/models \
  --dns-url http://169.254.169.254/latest/meta-data/,http://10.0.0.1/,http://100.64.0.1/ \
  --firewall-sentinel /run/telclaude/firewall-active \
  --timeout-ms 3000 \
  --out /data/hermes/network-probes.json \
  --evidence-dir /data/hermes/network

docker cp telclaude:/data/hermes/network-probes.json docs/hermes/network-probes.json
rm -rf artifacts/hermes/network
docker cp telclaude:/data/hermes/network artifacts/hermes/network
```

Expected green: exit code `0`, all five required network probes pass, and every network evidence file includes a passing firewall sentinel attempt.

### 5.5 Model Relay

The model-relay probe must run from the same namespace and generated profile
that production Hermes uses for model calls. A host-side run proves only host
networking and is not production evidence.

The relay model endpoint used by this probe must echo the source peer IP in
`x-telclaude-model-relay-observed-peer-address`. Do not count self-declared
container or peer flags as proof; the cutover gate accepts only a server-observed
peer address matching `TELCLAUDE_HERMES_CONTAINED_IP`.

Production command shape once a contained-peer probe runner exists:

```bash
<contained-peer-runner> telclaude hermes probe model.relay \
  --allow-run \
  --json \
  --relay-url http://telclaude:8790/v1/models \
  --model-url https://api.anthropic.com/v1/models \
  --profile-dir /home/hermes/.hermes \
  --firewall-sentinel /run/telclaude/firewall-active \
  --container-name tc-hermes-contained \
  --expected-peer-address "$TELCLAUDE_HERMES_CONTAINED_IP" \
  --relay-peer-address "$TELCLAUDE_HERMES_RELAY_IP" \
  --timeout-ms 3000 \
  --out /data/hermes/model-relay.json
```

Copy accepted evidence back to the host checkout:

```bash
docker cp tc-hermes-contained:/data/hermes/model-relay.json artifacts/hermes/probes/model-relay.json
```

Expected green: exit code `0`, `status=pass`, firewall sentinel present, relay
endpoint reachable, origin gate reports `tc-hermes-contained` with a
server-observed peer address equal to `TELCLAUDE_HERMES_CONTAINED_IP`, direct
model-provider egress denied, and scanned profile files contain no raw model
credentials or direct model-provider hosts. The profile scan must be complete:
unsupported extensions, symlinks, files above the scan cap, or scan-limit skips
fail the evidence instead of proving absence. Do not count this proof unless it
was produced from the contained Hermes runtime namespace.

### 5.6 Served MCP Containment

This probe must target the relay-internal MCP HTTP endpoint. Do not publish the
MCP port to the host to make this easier. The production cutover evidence must
be produced from the contained Hermes peer namespace, not from the relay
namespace; a relay-side run is useful only as smoke evidence and must fail the
production origin gate.

Runtime inputs required before this command can be real:

- `TELCLAUDE_HERMES_SERVED_MCP_AUTH`: a relay-issued `Authorization: Bearer tc_mcp_conn_...` header for the private authority.
- `TELCLAUDE_HERMES_SERVED_MCP_OFF_DOMAIN_PEER_AUTH`: a relay-issued `Authorization: Bearer tc_mcp_conn_...` header bound to the off-domain negative-control peer.
- `TELCLAUDE_HERMES_SERVED_MCP_FORGED_AUTH`: an intentionally unregistered `Authorization: Bearer tc_mcp_conn_...` header.
- `TELCLAUDE_HERMES_SERVED_MCP_WRONG_CONNECTION_AUTH`: a relay-issued `Authorization: Bearer tc_mcp_conn_...` header for a different registered connection.

Mint those tokens from the relay-local admin Unix socket. This socket is created by the relay only when `TELCLAUDE_HERMES_LIVE_MCP_ADMIN_ENABLED=1`, is chmod `0600`, and must not be mounted into the Hermes runtime or any agent container. The command below prints shell exports for the probe tokens; do not commit the token values or command transcript with live values.

```bash
eval "$(
  docker exec \
    -e OPERATOR_RPC_AGENT_PRIVATE_KEY="$OPERATOR_RPC_AGENT_PRIVATE_KEY" \
    telclaude telclaude hermes live-mcp probe-tokens \
    --socket /run/telclaude/hermes-live-mcp-admin.sock \
    --peer-address "$TELCLAUDE_HERMES_CONTAINED_IP"
)"
```

Optional audit view without shell export:

```bash
docker exec \
  -e OPERATOR_RPC_AGENT_PRIVATE_KEY="$OPERATOR_RPC_AGENT_PRIVATE_KEY" \
  telclaude telclaude hermes live-mcp probe-tokens \
  --socket /run/telclaude/hermes-live-mcp-admin.sock \
  --peer-address "$TELCLAUDE_HERMES_CONTAINED_IP" \
  --json
```

The one-off probe tokens above are bound to `TELCLAUDE_HERMES_CONTAINED_IP`.
Production proof must run the probe from `tc-hermes-contained` or an equivalent
contained-peer namespace whose source IP is that contained peer IP. The live MCP
server echoes the observed source peer into the evidence; probe CLI flags cannot
fake it. A relay-side run is not a substitute: under the production allowlist it
should fail authorization, and without that allowlist it must still fail the
production origin gate.

Production command shape once a contained-peer probe runner exists:

```bash
<contained-peer-runner> telclaude hermes probe execution.served_mcp_containment \
  --allow-run \
  --json \
  --mcp-url http://telclaude:8793/mcp \
  --mcp-auth "${TELCLAUDE_HERMES_SERVED_MCP_AUTH}" \
  --mcp-off-domain-peer-auth "${TELCLAUDE_HERMES_SERVED_MCP_OFF_DOMAIN_PEER_AUTH}" \
  --mcp-forged-auth "${TELCLAUDE_HERMES_SERVED_MCP_FORGED_AUTH}" \
  --mcp-wrong-connection-auth "${TELCLAUDE_HERMES_SERVED_MCP_WRONG_CONNECTION_AUTH}" \
  --timeout-ms 30000 \
  --out /data/hermes/execution-served-mcp-containment.json
```

The contained-peer runner must have the Telclaude CLI or an equivalent packaged
probe available inside the contained namespace. The resulting evidence must show
`origin.observedPeerSource=server-peer-echo` with
`origin.observedPeerAddress == TELCLAUDE_HERMES_CONTAINED_IP`.

Expected green: all required served-MCP properties pass, including exact tools list, empty resources/prompts/roots, sampling disabled, forged handle denied, wrong connection denied, cross-domain memory denied, out-of-scope provider/outbound denied, execute-without-ledger denied, malformed/unauthenticated/batch/prototype denial, and artifact redaction.

## 6. Rollback Rehearsal

Run the rollback rehearsal after the live probes. It must call the relay
capability surface, observe Hermes mode enabled, drive the durable runtime
overlay back to legacy mode, and observe legacy mode after the change. Do not
hand-write this evidence.

```bash
docker exec \
  -e TELCLAUDE_CAPABILITIES_URL=http://127.0.0.1:${TELCLAUDE_CAPABILITIES_PORT:-8790} \
  -e OPERATOR_RPC_AGENT_PRIVATE_KEY="${OPERATOR_RPC_AGENT_PRIVATE_KEY:?set from pnpm dev keygen operator}" \
  -e OPERATOR_RPC_RELAY_PUBLIC_KEY="${OPERATOR_RPC_RELAY_PUBLIC_KEY:?set from pnpm dev keygen operator}" \
  telclaude telclaude hermes rollback-rehearsal \
    --allow-run \
    --json \
    --out /data/hermes/rollback-rehearsal.json \
    --evidence-path artifacts/hermes/rollback-rehearsal.json

docker cp telclaude:/data/hermes/rollback-rehearsal.json artifacts/hermes/rollback-rehearsal.json
```

Expected green: `passed=true`, `observedBeforeValue=1`,
`observedAfterValue=0`, `controlSurface=relay.capabilities:/v1/hermes.private-runtime.mode`,
`observationSurface=relay.capabilities:/v1/hermes.private-runtime.status`,
and `observedAfterControlSource=runtime-config`.

The rehearsal intentionally leaves the durable mode at `legacy`. After the
evidence file is copied to the host, re-enable Hermes through the same relay
operator surface before the final cutover check and any real flag flip:

```bash
docker exec \
  -e TELCLAUDE_CAPABILITIES_URL=http://127.0.0.1:${TELCLAUDE_CAPABILITIES_PORT:-8790} \
  -e OPERATOR_RPC_AGENT_PRIVATE_KEY="${OPERATOR_RPC_AGENT_PRIVATE_KEY:?set from pnpm dev keygen operator}" \
  telclaude telclaude hermes private-runtime set hermes --json

docker exec \
  -e TELCLAUDE_CAPABILITIES_URL=http://127.0.0.1:${TELCLAUDE_CAPABILITIES_PORT:-8790} \
  -e OPERATOR_RPC_AGENT_PRIVATE_KEY="${OPERATOR_RPC_AGENT_PRIVATE_KEY:?set from pnpm dev keygen operator}" \
  telclaude telclaude hermes private-runtime status --json
```

## 7. Cutover Check

`cutover-check` consumes docs/evidence files from the host checkout. Run it only after host-side files point at the live evidence paths chosen for this run:

```bash
pnpm dev hermes cutover-check \
  --strict \
  --dry-run \
  --json \
  --feature-probes docs/hermes/feature-probes.json \
  --lockfile docs/hermes/hermes-compat.lock.json \
  --network-probes docs/hermes/network-probes.json
```

Expected green: exit code `0`, `status=safe`, and all gates pass. If it fails only because placeholder docs still say `skip`, `fail`, `pending`, empty fixtures, no-fork not clean, or rollback not rehearsed, do not override the result. Update those artifacts from real evidence or keep the cutover blocked.

## 8. Remaining Non-Probe Gates

The live probes are necessary, not sufficient. A green probe set does not authorize flipping `TELCLAUDE_HERMES_PRIVATE_RUNTIME` by itself.

Before any flag flip, these non-probe gates also need real evidence:

- Served-MCP token issuance: the live served-MCP probe must mint the allowed, forged, and wrong-connection `tc_mcp_conn_...` tokens through `telclaude hermes live-mcp probe-tokens` over the relay-local admin Unix socket, not through a host-published HTTP endpoint.
- Workflow scope: `docs/hermes/cutover-scope.json` must name the included workflows and their required surfaces instead of the placeholder empty list.
- Fixtures: `docs/hermes/fixture-results.json` must contain passing parity and negative fixture results for the workflows in scope.
- Compatibility lockfile: `docs/hermes/hermes-compat.lock.json` must be regenerated from the real probe matrix and accepted evidence, with passing feature probes tied to the same Hermes pin.
- No-fork proof: `docs/hermes/no-fork-proof.json` must prove the Hermes checkout stays clean/upstream rather than carrying wrapper changes as a fork.
- Rollback rehearsal: `docs/hermes/rollback-rehearsal.json` must prove the operator can return traffic to the pre-Hermes path.
- Decision log and queue ownership: unresolved decisions and pending operator queues must be closed or explicitly excluded by the cutover scope.

Treat any placeholder `skip`, `fail`, `pending`, empty bundle, missing evidence file, stale lockfile digest, dirty no-fork proof, or failed rollback as a hard cutover block.

## 9. Regenerate The Compatibility Lockfile Draft

After evidence is accepted and `docs/hermes/feature-probes.json` reflects the live pass/fail status and evidence paths, regenerate a reviewable lockfile draft:

```bash
pnpm dev hermes compat-lock \
  --dry-run \
  --json \
  --pin "$TELCLAUDE_HERMES_PIN" \
  --feature-probes docs/hermes/feature-probes.json \
  > artifacts/hermes/hermes-compat.lock.generated.json
```

Review the draft before replacing `docs/hermes/hermes-compat.lock.json`. There is no automatic write command by design; committing a lockfile update is an explicit evidence decision.

## 10. Evidence Policy Decision

Resolve this at live-run time before committing anything beyond this playbook.

Option A: commit sanitized live evidence.

- Pros: repeatable audit trail and cutover proof in git.
- Cons: evidence may expose host/container metadata and requires redaction review.
- Required before commit: inspect every artifact under `artifacts/hermes/**`, confirm no secrets, no tokens, no raw provider data, and no operator-sensitive paths beyond accepted local machine metadata.

Option B: keep live evidence generated and untracked.

- Pros: avoids committing machine-local artifacts.
- Cons: cutover proof must be regenerated for every reviewer or release gate.
- Required before cutover: document the exact run id, commit hash, command transcript, and artifact hashes outside git.

Default for the first Colima run: keep `artifacts/` untracked until Aviv and Claude choose Option A or Option B.

## 10. Cleanup

When done:

```bash
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.hermes.yml \
  down

unset TELCLAUDE_HERMES_API_SERVER_KEY
unset TELCLAUDE_HERMES_SERVED_MCP_AUTH
unset TELCLAUDE_HERMES_SERVED_MCP_FORGED_AUTH
unset TELCLAUDE_HERMES_SERVED_MCP_WRONG_CONNECTION_AUTH
```

Do not remove Colima or Docker images as part of this playbook unless Aviv asks.
