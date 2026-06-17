# Telclaude Docker Deployment

Secure containerized deployment for telclaude on any Docker-capable host (Linux, macOS with Colima/Docker Desktop, or WSL2).

## Architecture

See `docs/architecture.md` for the full system design. At a glance:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Docker Host                                  │
│                                                                     │
│  ┌───────────────┐  ┌────────────────┐  ┌────────────────────────┐ │
│  │   telclaude   │  │ google-services│  │  tc-hermes-contained   │ │
│  │    (relay)    │  │   (sidecar)    │  │  + tc-hermes-social    │ │
│  └───────┬───────┘  └───────┬────────┘  └───────┬────────────────┘ │
│          │                  │                    │                   │
│  ┌───────┴───────┐  ┌──────┴────────┐  ┌───────┴────────────────┐ │
│  │ totp  │ vault │  │ Google egress │  │ relay-internal MCP     │ │
│  │(2FA)  │(creds)│  │ network       │  │ + model relay only     │ │
│  └───────────────┘  └───────────────┘  └────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

**4 containers** (base stack): relay, Google services sidecar, TOTP sidecar, vault sidecar.
**4 images**: `telclaude:latest`, `telclaude-google-services:latest`, `telclaude-totp:latest`, `telclaude-vault:latest`.

The Hermes overlay adds `tc-hermes-contained` and `tc-hermes-social` (pinned upstream image) on its own internal network — see [Hermes Private Runtime](#hermes-private-runtime). This is the only LLM/persona runtime path.

## Security Features

Based on [2025 Docker security best practices](https://cloudnativenow.com/topics/cloudnativedevelopment/docker/docker-security-in-2025-best-practices-to-protect-your-containers-from-cyberthreats/):

| Feature | Description |
|---------|-------------|
| **Privilege dropping** | Entrypoint starts as root for firewall init, then drops to UID 1000 via `gosu` |
| **Capability dropping** | `--cap-drop=ALL` with only required caps added back |
| **Read-only root** | Root filesystem is read-only; `/tmp` uses tmpfs |
| **Resource limits** | CPU and memory limits prevent resource exhaustion |
| **Network isolation** | **Required** firewall restricts outbound connections (requires root at startup) |
| **Named volumes** | Persistent data isolated from host filesystem |
| **Multi-stage build** | Minimal runtime image without build tools |

**Note on privilege dropping**: The container uses the standard Docker "gosu pattern" - it starts as root
to perform privileged operations (iptables firewall setup), then irrevocably drops to non-root user
before executing the application. This is the [recommended approach](https://github.com/tianon/gosu)
for containers that need initial root privileges.

## Quick Start

### Prerequisites

- Docker Engine 24+ (or Docker Desktop / Colima)
- `docker compose` v2

### Setup

1. **Clone the repository** (or copy the docker folder):
   ```bash
   git clone https://github.com/avivsinai/telclaude.git
   cd telclaude/docker
   ```

2. **Create your environment file**:
   ```bash
   cp .env.example .env
   ```

3. **Edit `.env`** with your values:
   ```bash
   # Required
   WORKSPACE_PATH=/path/to/your/projects
   TOTP_ENCRYPTION_KEY=<openssl rand -base64 32>
   VAULT_ENCRYPTION_KEY=<openssl rand -base64 32>
   ANTHROPIC_PROXY_TOKEN=<openssl rand -hex 32>

   # Credentials (vault preferred; env vars as fallback)
   TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
   # ANTHROPIC_API_KEY=sk-ant-...   # or use `claude login` after first run
   ```

4. **Create config files** (see [Config Split](#config-split) below):
   ```bash
   cp telclaude.json.example telclaude.json
   cp telclaude-private.json.example telclaude-private.json
   ```

5. **Generate RPC keys** (required for relay/Hermes authority and operator authentication):
   ```bash
   # From the repo root (not docker/):
   pnpm dev keygen telegram   # generates 4 keys for Telegram-side relay RPC
   pnpm dev keygen social     # generates 4 keys for social-domain relay RPC
   # Copy the output into your .env file
   ```

6. **Build and start**:
   ```bash
   docker compose up -d --build
   ```

7. **Check logs**:
   ```bash
   docker compose logs -f
   ```

### First-Time Volume Setup

**Before first run**, create the external volumes that protect your secrets:

```bash
./setup-volumes.sh
```

This creates `telclaude-claude-auth`, `telclaude-skill-catalog`, `telclaude-totp-data`, and `telclaude-vault-data` as external volumes that **cannot be deleted** by `docker compose down -v`.

**Note:** `docker compose up` will fail if these volumes don't exist. Always run `setup-volumes.sh` first.

### First-Time Authentication

If you didn't set `ANTHROPIC_API_KEY`, authenticate Claude (relay container):

```bash
docker compose exec -e CLAUDE_CONFIG_DIR=/home/telclaude-auth telclaude claude login
```

This stores credentials in the relay-only `telclaude-claude-auth` volume. Hermes uses relay-owned model/provider capability, so you do **not** run `claude login` in a runtime container.

### Migration: Old Claude Profile Volume

If you previously used a single `telclaude-claude` or `telclaude-claude-private` volume, you have two options:

**Option A: Re-login (simplest)**
```bash
docker compose exec -e CLAUDE_CONFIG_DIR=/home/telclaude-auth telclaude claude login
```

**Option B: Copy credentials from old volume**
```bash
docker volume create telclaude-claude-auth
# Use your old volume name (e.g., telclaude-claude or telclaude-claude-private)
docker run --rm -v telclaude-claude:/old:ro -v telclaude-claude-auth:/new \
  alpine cp -a /old/.credentials.json /new/ 2>/dev/null || true
```

If you had custom skills in the old profile volumes, the new entrypoint will migrate
legacy `skills/` and `skills-draft/` directories into `telclaude-skill-catalog`
automatically on first boot.

## Volume Safety

Some volumes contain **critical secrets** that cannot be recovered if deleted.

### Critical Volumes (External)

| Volume | Contains | If Deleted |
|--------|----------|------------|
| `telclaude-claude-auth` | Claude OAuth tokens | Must re-run `claude login` |
| `telclaude-skill-catalog` | Shared active + draft skill catalog | Must reinstall or recreate custom skills |
| `telclaude-totp-data` | Encrypted 2FA secrets | **UNRECOVERABLE** - must re-enroll all 2FA |
| `telclaude-vault-data` | Encrypted credentials (API keys, OAuth tokens) | **UNRECOVERABLE** - must re-add all credentials |

These are marked `external: true` in docker-compose.yml, so `docker compose down -v` **cannot delete them**.

**Profile volume note:** persona-scoped plugin/profile volumes are relay-managed acquisition state. Standalone telclaude skills live in the shared `telclaude-skill-catalog`; runtime skills must be curated into the relay-owned Hermes catalogs before Hermes can use them.

**Hermes skill catalog.** The Hermes overlay adds relay-owned external skill catalogs for the contained runtimes. The relay mounts `telclaude-hermes-skill-catalog` and `telclaude-hermes-social-skill-catalog` read-write; `tc-hermes-contained` mounts only the private catalog read-only, and `tc-hermes-social` mounts only the social catalog read-only. Operators install private/runtime skills relay-side with `telclaude hermes-skills install <dir>` (or `install-upstream <rel>` / `install-from-curator <itemId>`); target the social catalog with `--catalog social`. Production deploys should replay declared curated seed sources with `telclaude hermes-skills sync-manifest <manifest> --prune-managed` instead of hand-installing entries. Every install is validated (no scripts, symlinks, or executables; size caps; secret + injection scan) and recorded in `catalog-manifest.json`. The contained entrypoint re-validates the mounted tree at boot and serves it to upstream Hermes via `skills.external_dirs`; use upstream `/reload-skills` to pick up changes without a restart, or restart the affected contained runtime after a manifest replay, and `telclaude hermes-skills verify` to detect manifest/tree drift.

### Safe Operations

```bash
# Safe - preserves all data
docker compose restart
docker compose down && docker compose up -d
```

### Dangerous Operations

```bash
# DANGEROUS - deletes non-external volumes (telclaude-data)
docker compose down -v

# DANGEROUS - can delete ALL volumes including external ones
docker volume prune
docker volume rm telclaude-totp-data  # DO NOT RUN
```

### Backup Critical Volumes

```bash
# Backup TOTP secrets (CRITICAL - do this regularly)
docker run --rm -v telclaude-totp-data:/data:ro -v $(pwd):/backup \
  alpine tar czf /backup/totp-backup-$(date +%Y%m%d).tar.gz -C /data .

# Backup vault credentials (CRITICAL)
docker run --rm -v telclaude-vault-data:/data:ro -v $(pwd):/backup \
  alpine tar czf /backup/vault-backup-$(date +%Y%m%d).tar.gz -C /data .

# Backup Claude credentials
docker run --rm -v telclaude-claude-auth:/data:ro -v $(pwd):/backup \
  alpine tar czf /backup/claude-backup-$(date +%Y%m%d).tar.gz -C /data .
```

## Configuration

### Volume Mounts

| Container | Path | Purpose | Persisted |
|----------|------|---------|-----------|
| `telclaude` | `/data` | SQLite DB, config, sessions | Named volume |
| `telclaude` | `/home/telclaude-auth` | Claude auth profile (OAuth tokens) | External volume |
| `telclaude` | `/home/telclaude-skill-catalog` | Shared active + draft standalone skill catalog | External volume |
| `telclaude` | `/opt/data/telclaude-hermes-skill-catalog` | Relay-owned private Hermes skill catalog | Hermes overlay named volume |
| `telclaude` | `/opt/data/telclaude-hermes-social-skill-catalog` | Relay-owned social Hermes skill catalog | Hermes overlay named volume |
| `tc-hermes-contained` | `/opt/data/telclaude-hermes-skill-catalog` | Private Hermes catalog, read-only inside runtime | Hermes overlay named volume |
| `tc-hermes-social` | `/opt/data/telclaude-hermes-social-skill-catalog` | Social Hermes catalog, read-only inside runtime | Hermes overlay named volume |
| `telclaude` | `/home/telclaude-private-profile` / `/home/telclaude-social-profile` | Persona-scoped plugin acquisition/profile state | Named volume |
| `telclaude` | `/media/inbox` + `/media/outbox` | Shared media (inbox/outbox split) | Named volume |
| `telclaude` | `/social/sandbox` | Social working area controlled by relay/Hermes authority | Named volume |
| `telclaude` | `/social/memory` | Social memory (relay authoritative) | Named volume |

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `WORKSPACE_PATH` | Yes | Host path to mount as /workspace |
| `TOTP_ENCRYPTION_KEY` | Yes | AES-256-GCM key for 2FA secrets. Generate: `openssl rand -base64 32` |
| `VAULT_ENCRYPTION_KEY` | Yes | AES-256-GCM key for credential storage. Generate: `openssl rand -base64 32` |
| `ANTHROPIC_PROXY_TOKEN` | Yes | Shared token for relay-internal Anthropic proxy access. Generate: `openssl rand -hex 32` |
| `TELEGRAM_BOT_TOKEN` | Vault/env | Bot token from @BotFather (vault preferred) |
| `ANTHROPIC_API_KEY` | No | Alternative to `claude login` (vault preferred) |
| `OPERATOR_RPC_AGENT_PRIVATE_KEY` | Host CLI only | Operator private key — signs operator-only relay mutations such as provider add/edit/remove/refresh |
| `OPERATOR_RPC_AGENT_PUBLIC_KEY` | Yes | Operator public key — relay verifies operator-only RPC mutations |
| `OPERATOR_RPC_RELAY_PRIVATE_KEY` | Yes | Operator relay private key — signs relay-observed operator RPC responses such as Hermes rollback evidence |
| `OPERATOR_RPC_RELAY_PUBLIC_KEY` | Host CLI only | Operator relay public key — CLI verifies relay-observed operator RPC responses |
| `TELEGRAM_RPC_AGENT_PRIVATE_KEY` | Yes | Telegram-domain runtime private key — signs runtime→relay requests. Generate with `telclaude keygen telegram` |
| `TELEGRAM_RPC_AGENT_PUBLIC_KEY` | Yes | Telegram-domain runtime public key — relay verifies runtime→relay requests |
| `TELEGRAM_RPC_RELAY_PRIVATE_KEY` | Yes | Relay private key — signs relay-observed Telegram-domain responses |
| `TELEGRAM_RPC_RELAY_PUBLIC_KEY` | Yes | Relay public key — runtime/operator verifies relay-observed Telegram-domain responses |
| `SOCIAL_RPC_AGENT_PRIVATE_KEY` | Yes (if social enabled) | Social-domain runtime private key |
| `SOCIAL_RPC_AGENT_PUBLIC_KEY` | Yes (if social enabled) | Social-domain runtime public key — relay verifies social-domain requests |
| `SOCIAL_RPC_RELAY_PRIVATE_KEY` | Yes (if social enabled) | Relay private key for social-domain responses |
| `SOCIAL_RPC_RELAY_PUBLIC_KEY` | Yes (if social enabled) | Relay public key for social-domain verification |
| `TELCLAUDE_GIT_PROXY_SECRET` | No | HMAC secret for git proxy session tokens. Generate: `openssl rand -hex 32` |
| `TELCLAUDE_FIREWALL` | **Yes** | **Must be `1`** for network isolation (containers will refuse to start without it) |
| `TELCLAUDE_LOG_LEVEL` | No | `debug`, `info`, `warn`, `error` |
| `TELCLAUDE_INTERNAL_HOSTS` | No | Comma-separated internal hostnames to allow through the firewall (defaults to `telclaude,google-services`) |
| `TELCLAUDE_FIREWALL_RETRY_COUNT` | No | Internal host DNS retry count (defaults to 10) |
| `TELCLAUDE_FIREWALL_RETRY_DELAY` | No | Seconds between internal host DNS retries (defaults to 2) |
| `TELCLAUDE_IPV6_FAIL_CLOSED` | No | If IPv6 is enabled and ip6tables is missing, refuse to start (defaults to 1) |

Generate:
- `telclaude keygen operator` for operator-only relay mutations and relay-observed rollback evidence. Keep `OPERATOR_RPC_AGENT_PRIVATE_KEY` and `OPERATOR_RPC_RELAY_PUBLIC_KEY` on the host where you run the CLI; put `OPERATOR_RPC_AGENT_PUBLIC_KEY` and `OPERATOR_RPC_RELAY_PRIVATE_KEY` in the relay container env.
- `telclaude keygen telegram` / `telclaude keygen social` for runtime scopes. Each command generates two keypairs (4 keys): the runtime keypair (runtime signs, relay verifies) and the relay keypair (relay signs, runtime verifies). The relay container gets `*_AGENT_PUBLIC_KEY` + `*_RELAY_PRIVATE_KEY`; private deployment secrets provide `*_AGENT_PRIVATE_KEY` + `*_RELAY_PUBLIC_KEY` to the approved runtime path.

Telegram admin wizards for `/providers add|edit|remove` do not require `OPERATOR_RPC_AGENT_PRIVATE_KEY`. They run inside the relay process, which writes the runtime overlay locally after Telegram admin/TOTP checks. The operator keypair is still required for host-side CLI or agent-container calls that hit the relay's operator-scope RPC endpoints over HTTP.

`ANTHROPIC_PROXY_TOKEN` is relay-internal and must match the relay-side proxy configuration.

### Config Split

Telclaude uses a two-file config split to keep secrets out of runtime-capable surfaces:

| File | Mounted to | Contents |
|------|-----------|----------|
| `telclaude.json` | Relay and approved sidecars | Policy: providers, network rules, rate limits, Hermes/runtime config |
| `telclaude-private.json` | Relay only | Relay-only: allowedChats, permissions, deprecated secret fields |

The relay deep-merges private on top of policy (`TELCLAUDE_PRIVATE_CONFIG` env var). Hermes receives scoped runtime authority from the relay, not raw policy files.

### Relay-Compiled Claude Memory

The private Telegram agent does not own durable memory. The relay stores the authoritative memory state in SQLite and compiles a working-memory file for Claude only when needed.

- Semantic memory entries and episodic shared-history summaries live in the relay database.
- Before a private query starts, the relay writes a derived `MEMORY.md` file into `/home/telclaude-skills/projects/<project-slug>/memory/MEMORY.md`.
- That file is a cache for Claude's local memory mechanism. It is safe to delete; the relay will regenerate it.
- The file must not be treated as a secret store or as an independent source of truth.

This keeps the "good friend" continuity benefits of Claude's local memory system without weakening the relay boundary.

**Policy config** (`telclaude.json` — safe for all containers):
```json
{
  "providers": [{"id": "svc", "baseUrl": "http://localhost:3001", "services": ["api"]}],
  "security": {"profile": "strict"}
}
```

**Private config** (`telclaude-private.json` — relay only):
```json
{
  "telegram": {"allowedChats": [123456789]},
  "security": {"permissions": {"defaultTier": "READ_ONLY", "users": {"tg:123456789": {"tier": "FULL_ACCESS"}}}}
}
```

> **Important:** `allowedChats` is required (in either file). The container ignores all chats not listed. Add your chat ID before running `docker compose up`.

> **Single-file mode:** For simple setups, put everything in `telclaude.json` and create an empty `telclaude-private.json` (`{}`). The relay works fine without `TELCLAUDE_PRIVATE_CONFIG`.

### External Providers (Sidecars)

Telclaude can communicate with private REST APIs (sidecars) for services like health records, banking, or government portals.

The default Docker stack includes the Google Services sidecar. The checked-in
`telclaude.json.example` wires it as provider `google`, allowlists the
`google-services:3002` private endpoint, and scopes Hermes to that provider via
`hermes.privateRuntime.providerScopes`. Gmail, Calendar, Drive, and Contacts are
provider actions; provider writes still use prepare -> approval/TOTP -> execute.

**Setup:**

1. **Configure the provider** in `telclaude.json`:
   ```json
   {
     "providers": [{
       "id": "my-sidecar",
       "baseUrl": "http://127.0.0.1:3001",
       "services": ["health-api", "bank-api"],
       "description": "My local sidecar"
     }],
     "security": {
       "network": {
         "privateEndpoints": [{
           "label": "my-sidecar",
           "host": "127.0.0.1",
           "ports": [3001]
         }]
       }
     }
   }
   ```

2. **Start your sidecar** - it should expose `/v1/{service}/{action}` endpoints.

3. **The firewall auto-allows** provider hosts (parsed from config at startup).

**OTP flow:** When a provider returns `challenge_pending`, the user completes verification via Telegram:
```
/otp <service> <code>
```

See `telclaude.json.example` and `telclaude-private.json.example` for safe templates.
Use local `docker-compose.override.yml` for host-specific services or volumes; keep private sidecars out of tracked compose files.

## Hermes Private Runtime

Telclaude drives private Telegram, social, cron, and observer work through a pinned, unmodified upstream Hermes runtime. The relay stays the security envelope; Hermes is the agent loop behind it. Start the Hermes overlay for runtime operation; the base stack is not a complete LLM/persona deployment without it.

The overlay (`docker-compose.hermes.yml`) adds two pinned upstream Hermes containers on two **internal-only** RFC1918 bridge networks. `tc-hermes-contained` joins only `telclaude-hermes-private` (default `172.30.92.11`); `tc-hermes-social` joins only `telclaude-hermes-social` (default `172.30.93.11`). The relay joins both networks (`172.30.92.10` and `172.30.93.10`) and is the only non-runtime member. Do not attach sidecars, vault, providers, or egress helpers to these networks.

### Containment posture

| Control | `tc-hermes-contained` / `tc-hermes-social` |
|---------|---------------------------------------------|
| **User** | Non-root `10000:10000` |
| **Capabilities** | `cap_drop: ALL`, `no-new-privileges` |
| **Filesystem** | Read-only root; `noexec` tmpfs for `/tmp`, `/home/hermes`, `/run` |
| **Resources** | 2GB memory, 2 CPUs, 256 PIDs |
| **Model egress** | Model-provider hostnames (OpenAI, Anthropic, Google, OpenRouter, x.ai) pinned to a blackhole IP (`192.0.2.1`) — direct inference egress fails at the network layer |

Inference is routed only through the relay's OpenAI Codex proxy (`HERMES_CODEX_BASE_URL=http://telclaude:8790/v1/openai-codex-proxy`). The entrypoint (`hermes-contained-entrypoint.sh`) curates skills from the upstream Hermes skills directory (`TELCLAUDE_HERMES_SOURCE_SKILLS_DIR=/opt/hermes/skills`) into a read-only `skills.external_dirs` tree against read-only allowlists — `hermes-contained-skills.allowlist` for private/cron/observer and `hermes-social-skills.allowlist` for social — while the managed `$HERMES_HOME/skills` directory is an empty root-owned `0550` tmpfs mount. Social does not inherit the broad private allowlist. The entrypoint rejects path traversal and any entry missing a `SKILL.md`, writes the `.no-bundled-skills` marker, and mints a peer-bound Codex relay token so model traffic can only reach the relay's proxy route.

When the relay firewall is enabled, configure `security.network.additionalDomains` in the deployment config with `chatgpt.com` for the relay. The contained Hermes runtime reaches Codex only through the relay proxy.

### Relay live MCP bridge

When enabled (`TELCLAUDE_HERMES_LIVE_MCP_ENABLED=1`), the relay serves a relay-owned MCP bridge (memory search/write, provider read/prepare/execute, attachment get, outbound prepare/execute, audit note) over relay-internal HTTP endpoints on port **8793** (path `/mcp`), reachable only from the contained private/social peers on their own networks. It is not an agent tool allowlist: each connection binds to an opaque, TTL-limited authority handle, memory access is domain-scoped (the private Hermes runtime can never read social memory), and provider/outbound writes are two-phase (prepare → human approval → execute) with one-time, Ed25519-signed, request-bound approval tokens.

### Bring it up

Base Hermes runtime:

```bash
TELCLAUDE_HERMES_API_SERVER_KEY="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')" \
TELCLAUDE_HERMES_SOCIAL_API_SERVER_KEY="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')" \
TELCLAUDE_HERMES_MCP_RELAY_TOKEN="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')" \
docker compose -f docker-compose.yml -f docker-compose.hermes.yml up -d telclaude tc-hermes-contained tc-hermes-social
```

Connector-enabled personal/family runtime, including the optional WhatsApp bridge
container but without committing real phone numbers:

```bash
TELCLAUDE_HERMES_API_SERVER_KEY="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')" \
TELCLAUDE_HERMES_SOCIAL_API_SERVER_KEY="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')" \
TELCLAUDE_HERMES_MCP_RELAY_TOKEN="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')" \
docker compose -f docker-compose.yml -f docker-compose.hermes.yml --profile whatsapp up -d --build
```

Set `TELCLAUDE_NETWORK_MODE=permissive` for relay-served arbitrary public fetch.
Set `TELCLAUDE_BRAVE_SEARCH_API_KEY` or the host keychain Brave secret for
`tc_web_search`. Generate `TELCLAUDE_WHATSAPP_BRIDGE_SECRET` with
`openssl rand -hex 32`, then set `TELCLAUDE_WHATSAPP_ALLOWED_RECIPIENTS` and
`TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES` only in local `.env` /
deployment secrets. `telclaude dev doctor` reports the Hermes connector category
as advisory readiness without failing a minimal deployment.

### Overlay environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TELCLAUDE_HERMES_API_SERVER_KEY` | Yes | Ephemeral Bearer shared between relay and the private contained API server (port `8642`). Generate per `compose up`: `openssl rand -base64 48 \| tr '+/' '-_' \| tr -d '='` |
| `TELCLAUDE_HERMES_SOCIAL_API_SERVER_KEY` | Yes | Ephemeral Bearer shared between relay and the social contained API server (port `8642`). Generate separately from the private runtime key |
| `TELCLAUDE_HERMES_MCP_RELAY_TOKEN` | Yes | Ephemeral relay-to-Hermes live MCP transport token. Generate per `compose up` and rotate with the API-server keys |
| `TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN` | Yes | Relay-scoped OpenAI Codex subscription token (relay owns the credential; Hermes only sees a peer-bound relay token) |
| `OPERATOR_RPC_AGENT_PUBLIC_KEY` | Yes | Operator RPC public key (`pnpm dev keygen operator`); relay verifies operator RPC mutations |
| `OPERATOR_RPC_RELAY_PRIVATE_KEY` | Yes | Operator relay private key; signs relay-observed RPC responses such as rollback evidence |
| `TELCLAUDE_HERMES_IMAGE` | No | Override the pinned Hermes image digest (default pinned in the compose file) |
| `TELCLAUDE_HERMES_INFERENCE_MODEL` | No | Hermes inference model (default `gpt-5.5`) |
| `TELCLAUDE_HERMES_LIVE_MCP_ENABLED` | No | Enable the relay live MCP bridge (default `0`) |
| `TELCLAUDE_HERMES_RELAY_IP` / `TELCLAUDE_HERMES_SOCIAL_RELAY_IP` | No | Override the relay IP on the private/social networks (defaults `172.30.92.10` / `172.30.93.10`) |
| `TELCLAUDE_HERMES_CONTAINED_IP` / `TELCLAUDE_HERMES_SOCIAL_IP` | No | Override private/social runtime IPs (defaults `172.30.92.11` / `172.30.93.11`) |
| `TELCLAUDE_HERMES_RELAY_SUBNET` / `TELCLAUDE_HERMES_SOCIAL_RELAY_SUBNET` | No | Override the private/social internal network CIDRs (defaults `172.30.92.0/24` / `172.30.93.0/24`) |
| `TELCLAUDE_HERMES_LIVE_MCP_ADDITIONAL_BINDS` | No | Extra relay live-MCP binds as `host@network` (default social bind `172.30.93.10@telclaude-hermes-social`) |

The overlay default for `TELCLAUDE_INTERNAL_HOSTS` includes `tc-hermes-contained` and `tc-hermes-social` so the relay firewall allows both contained peers. If you override that variable, include both hosts explicitly.

### Proof spine

Hermes runtime operation is gated by signed evidence, not trust. The `telclaude hermes` command group (`pnpm dev hermes ...`) generates and evaluates the steady-state proofs — no-fork proof (`prove --upstream-clean`), feature probes (`probes` / `probe <surface>`), network-isolation probes (`network-probes`), and the live canary (`verify-live`). Production readiness is `doctor` + `probes` + `verify-live`; rollback is the previous container image. See `docs/operator-playbook.md` and `docs/architecture.md` for the trust-boundary rationale.

## Commands

```bash
# Start
docker compose up -d

# Stop
docker compose down

# View logs
docker compose logs -f telclaude

# Rebuild after code changes
docker compose up -d --build

# Shell into container
docker compose exec telclaude bash

# Run telclaude doctor
docker compose exec telclaude telclaude doctor

# Claude login (if not using API key)
docker compose exec -e CLAUDE_CONFIG_DIR=/home/telclaude-auth telclaude claude login

# View volumes
docker volume ls | grep telclaude
```

## Network Firewall (Required)

**The network firewall is required for Docker mode.** The relay and sidecars enable it by default. Hermes runtime containment is provided by the internal-only overlay network, model-provider blackholing, relay-owned model proxy, and served-MCP authority.

### Configuration

1. Set in `.env`:
   ```bash
   TELCLAUDE_FIREWALL=1
   ```

2. Ensure docker-compose.yml has `cap_add: [NET_ADMIN]` (already included by default).

3. The firewall will restrict outbound connections to:
   - Anthropic API (api.anthropic.com)
   - Telegram API (api.telegram.org)
   - Package registries (npm, PyPI)
   - GitHub

### Verification

The firewall creates a sentinel file at `/run/telclaude/firewall-active` when successfully applied. Containers check for this file and fail if missing.

### IPv6

If Docker IPv6 is enabled, the firewall enforces a default-deny IPv6 policy. When IPv6 is enabled but `ip6tables` is unavailable, the container will fail to start by default (`TELCLAUDE_IPV6_FAIL_CLOSED=1`). You can override this (not recommended) with `TELCLAUDE_IPV6_FAIL_CLOSED=0`.

Internal RPC between the relay and approved sidecars is allowed by hostname. If you rename the
services, set `TELCLAUDE_INTERNAL_HOSTS` (comma-separated) to match.

Note: The compose files enable the firewall in relay/sidecar containers by default. The relay enforces the capability boundary and limits egress; Hermes is separately constrained by its overlay.

### Bypass (Testing Only)

**SECURITY WARNING:** For testing only. Never use in production.

```bash
# Disables firewall requirement (Bash will have unrestricted network access)
TELCLAUDE_ACCEPT_NO_FIREWALL=1
```

This bypass is logged to the audit log.

## Troubleshooting

### "Hermes unavailable"

LLM/persona execution requires `tc-hermes-contained`, `tc-hermes-social`, and relay live MCP/model proxy configuration. Confirm `TELCLAUDE_HERMES_API_BASE_URL`, `TELCLAUDE_HERMES_API_KEY`, `TELCLAUDE_HERMES_SOCIAL_API_BASE_URL`, `TELCLAUDE_HERMES_SOCIAL_API_KEY`, `TELCLAUDE_HERMES_MCP_RELAY_TOKEN`, `TELCLAUDE_HERMES_LIVE_MCP_ENABLED`, and the Hermes overlay are set and running.

For production repairs, use the deployment's Hermes release gate or private
overlay replay procedure instead of a full-stack `docker compose down` / `up`.
Skill seeds, live MCP wiring, and contained-runtime reloads should be restored
with service-scoped Compose operations so vault, TOTP, and provider sidecars are
not cold-recreated just to fix Hermes runtime state.

### "Permission denied" on workspace

Ensure `WORKSPACE_PATH` in `.env` points to a readable directory on the host:

```bash
ls -la $WORKSPACE_PATH
```

### Claude CLI not working

```bash
# Check Claude version
docker compose exec telclaude claude --version

# Re-authenticate
docker compose exec -e CLAUDE_CONFIG_DIR=/home/telclaude-auth telclaude claude login
```

### Reset session data (keeps secrets)

```bash
# Remove containers and non-external volumes (keeps auth, shared skills, TOTP secrets, and vault creds)
docker compose down -v

# Rebuild fresh
docker compose up -d --build
```

**Note:** External volumes (`telclaude-claude-auth`, `telclaude-skill-catalog`, `telclaude-totp-data`, `telclaude-vault-data`) are protected and will NOT be deleted by `docker compose down -v`.

## TOTP Daemon (2FA Support)

The Docker deployment includes full TOTP support via a sidecar container (`telclaude-totp`) that uses encrypted file storage instead of the OS keychain.

### Setup

1. **Generate an encryption key**:
   ```bash
   openssl rand -base64 32
   ```

2. **Add to your `.env` file**:
   ```bash
   TOTP_ENCRYPTION_KEY=<your-generated-key>
   ```

3. **Start the stack** - the TOTP sidecar starts automatically:
   ```bash
   docker compose up -d
   ```

### How it works

- The `totp` sidecar container runs the TOTP daemon with `TOTP_STORAGE_BACKEND=file`
- Secrets are encrypted with AES-256-GCM using your `TOTP_ENCRYPTION_KEY`
- Encrypted secrets are stored in the `telclaude-totp-data` volume
- The relay and TOTP daemon communicate via Unix socket on a shared tmpfs volume

### Security notes

- The encryption key is the only secret you need to back up
- Keep `TOTP_ENCRYPTION_KEY` secure - it protects all TOTP secrets
- The key never leaves the TOTP container (relay doesn't have access)

## Sources

- [Docker Security Best Practices 2025](https://cloudnativenow.com/topics/cloudnativedevelopment/docker/docker-security-in-2025-best-practices-to-protect-your-containers-from-cyberthreats/)
- [Docker Desktop WSL 2 Best Practices](https://docs.docker.com/desktop/features/wsl/best-practices/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Claude Code Dev Containers](https://code.claude.com/docs/en/devcontainer)
- [Docker Docs - Configure Claude Code](https://docs.docker.com/ai/sandboxes/claude-code/)
