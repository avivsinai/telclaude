# Telclaude Docker Deployment

Secure containerized deployment for telclaude on Windows (WSL2) or Linux hosts.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows Host (WSL2)                          │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                 Docker Network                            │  │
│  │                                                           │  │
│  │  ┌─────────────────┐    internal    ┌─────────────────┐  │  │
│  │  │    telclaude    │◀──────────────▶│ telclaude-agent  │  │  │
│  │  │     relay       │                │  SDK + tools     │  │  │
│  │  └────────┬────────┘                └────────┬────────┘  │  │
│  │           │                                 │             │  │
│  │   /data volume (secrets, DB)       /workspace volume       │  │
│  │   /media inbox/outbox (shared)     (your projects folder)  │  │
│  │                                                           │  │
│  └────────────────────────────────────────────┬───────────────┘  │
│                                               │                  │
│                    ┌──────────────────────────┘                  │
│                    ▼                                             │
│         C:\Users\YourName\Projects                               │
│         (host filesystem - ONLY this folder exposed)             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

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

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) 4.50+ with WSL2 backend
- Windows 10/11 with WSL2 enabled

### Setup

1. **Clone the repository** (or copy the docker folder):
   ```powershell
   git clone https://github.com/avivsinai/telclaude.git
   cd telclaude/docker
   ```

2. **Create your environment file**:
   ```powershell
   cp .env.example .env
   ```

3. **Edit `.env`** with your values:
   ```bash
   # Required
   TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
   WORKSPACE_PATH=/mnt/c/Users/YourName/Projects

   # Optional
   ANTHROPIC_API_KEY=sk-ant-...
   ```

4. **Build and start**:
   ```powershell
   docker compose up -d --build
   ```

5. **Check logs**:
   ```powershell
   docker compose logs -f
   ```

### First-Time Volume Setup

**Before first run**, create the external volumes that protect your secrets:

```bash
./setup-volumes.sh
```

This creates `telclaude-claude-auth` and `telclaude-totp-data` as external volumes that **cannot be deleted** by `docker compose down -v`.
The skills volume (`telclaude-claude-skills`) is non-external and will be created automatically.

**Note:** `docker compose up` will fail if these volumes don't exist. Always run `setup-volumes.sh` first.

### First-Time Authentication

If you didn't set `ANTHROPIC_API_KEY`, authenticate Claude (relay container):

```powershell
docker compose exec -e CLAUDE_CONFIG_DIR=/home/telclaude-auth telclaude claude login
```

This stores credentials in the relay-only `telclaude-claude-auth` volume. Agents use the relay proxy, so you do **not** need to run `claude login` in the agent containers.

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

If you had custom skills in the old volume, copy them into the new shared skills volume:
```bash
docker volume create telclaude-claude-skills
# Use your old volume name (e.g., telclaude-claude or telclaude-claude-private)
docker run --rm -v telclaude-claude:/old:ro -v telclaude-claude-skills:/new \
  alpine cp -a /old/skills /new/ 2>/dev/null || true
```

## Volume Safety

Some volumes contain **critical secrets** that cannot be recovered if deleted.

### Critical Volumes (External)

| Volume | Contains | If Deleted |
|--------|----------|------------|
| `telclaude-claude-auth` | Claude OAuth tokens | Must re-run `claude login` |
| `telclaude-totp-data` | Encrypted 2FA secrets | **UNRECOVERABLE** - must re-enroll all 2FA |

These are marked `external: true` in docker-compose.yml, so `docker compose down -v` **cannot delete them**.

**Skills volume warning:** `telclaude-claude-skills` is **not** external, so `docker compose down -v` **will delete it**. Reinstalling built-in skills is automatic, but back up custom skills if you added any.

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

# Backup Claude credentials
docker run --rm -v telclaude-claude-auth:/data:ro -v $(pwd):/backup \
  alpine tar czf /backup/claude-backup-$(date +%Y%m%d).tar.gz -C /data .
```

## Configuration

### Volume Mounts

| Container | Path | Purpose | Persisted |
|----------|------|---------|-----------|
| `telclaude-agent` | `/workspace` | Your projects folder | Host mount |
| `telclaude` | `/data` | SQLite DB, config, sessions, secrets | Named volume |
| `telclaude` | `/home/telclaude-auth` | Claude auth profile (OAuth tokens) | Named volume |
| `telclaude` + `telclaude-agent` + `agent-moltbook` | `/home/telclaude-skills` | Claude skills profile (skills/plugins, no secrets) | Named volume |
| `telclaude` + `telclaude-agent` | `/media/inbox` + `/media/outbox` | Shared media (inbox/outbox split) | Named volume |
| `agent-moltbook` | `/moltbook/sandbox` | Moltbook isolated workspace | Named volume |
| `telclaude` + `agent-moltbook` | `/moltbook/memory` | Moltbook social memory (relay RW, agent RO) | Named volume |

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Yes | Bot token from @BotFather |
| `WORKSPACE_PATH` | Yes | Host path to mount as /workspace |
| `ANTHROPIC_API_KEY` | No | Alternative to `claude login` |
| `TELCLAUDE_AUTH_DIR` | No | Relay-only path for Claude OAuth tokens (default `/home/telclaude-auth`) |
| `TELCLAUDE_LOG_LEVEL` | No | `debug`, `info`, `warn`, `error` |
| `TELEGRAM_RPC_AGENT_PRIVATE_KEY` | Yes | Agent private key — signs agent→relay requests. Generate with `telclaude keygen telegram` |
| `TELEGRAM_RPC_AGENT_PUBLIC_KEY` | Yes | Agent public key — relay verifies agent→relay requests |
| `TELEGRAM_RPC_RELAY_PRIVATE_KEY` | Yes | Relay private key — signs relay→agent requests |
| `TELEGRAM_RPC_RELAY_PUBLIC_KEY` | Yes | Relay public key — agent verifies relay→agent requests |
| `TELCLAUDE_MOLTBOOK_AGENT_URL` | No | Relay URL for Moltbook agent RPC (default `http://agent-moltbook:8789`) |
| `MOLTBOOK_RPC_AGENT_PRIVATE_KEY` | Yes (if Moltbook enabled) | Agent private key for Moltbook bidirectional auth |
| `MOLTBOOK_RPC_AGENT_PUBLIC_KEY` | Yes (if Moltbook enabled) | Agent public key — relay verifies Moltbook agent requests |
| `MOLTBOOK_RPC_RELAY_PRIVATE_KEY` | Yes (if Moltbook enabled) | Relay private key for Moltbook agent requests |
| `MOLTBOOK_RPC_RELAY_PUBLIC_KEY` | Yes (if Moltbook enabled) | Relay public key — Moltbook agent verifies relay requests |
| `MOLTBOOK_PROXY_TOKEN` | Yes (if Moltbook enabled) | Shared token for Anthropic proxy access |
| `TELCLAUDE_FIREWALL` | **Yes** | **Must be `1`** for network isolation (containers will refuse to start without it) |
| `TELCLAUDE_INTERNAL_HOSTS` | No | Comma-separated internal hostnames to allow through the firewall (defaults to `telclaude,telclaude-agent,agent-moltbook`) |
| `TELCLAUDE_FIREWALL_RETRY_COUNT` | No | Internal host DNS retry count (defaults to 10) |
| `TELCLAUDE_FIREWALL_RETRY_DELAY` | No | Seconds between internal host DNS retries (defaults to 2) |
| `TELCLAUDE_IPV6_FAIL_CLOSED` | No | If IPv6 is enabled and ip6tables is missing, refuse to start (defaults to 1) |

For both Telegram and Moltbook agents, generate key pairs with `telclaude keygen telegram` / `telclaude keygen moltbook`. Each command generates two keypairs (4 keys): the agent keypair (agent signs, relay verifies) and the relay keypair (relay signs, agent verifies). The relay container gets `*_AGENT_PUBLIC_KEY` + `*_RELAY_PRIVATE_KEY`; the agent container gets `*_AGENT_PRIVATE_KEY` + `*_RELAY_PUBLIC_KEY`. `MOLTBOOK_PROXY_TOKEN` must match between relay and Moltbook agent.

### Custom Configuration

**Required:** Create `telclaude.json` before starting:

```bash
cp telclaude.json.example telclaude.json
# Edit telclaude.json with your chat ID and settings
```

The config file is mounted into both containers:

```yaml
volumes:
  - ./telclaude.json:/data/telclaude.json:ro
```

Minimal `telclaude.json`:
```json
{
  "telegram": {
    "allowedChats": [123456789]
  },
  "security": {
    "permissions": {
      "defaultTier": "READ_ONLY"
    }
  }
}
```

> **Important:** `allowedChats` is required. The container ignores all chats that are not explicitly listed, even for the first admin claim. Add your own chat ID (e.g., from `@userinfobot`) before running `docker compose up` or the bot will not respond.

### External Providers (Sidecars)

Telclaude can communicate with private REST APIs (sidecars) for services like health records, banking, or government portals.

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

See `telclaude.json.example` for a full configuration template.

## Commands

```powershell
# Start
docker compose up -d

# Stop
docker compose down

# View logs
docker compose logs -f telclaude
docker compose logs -f telclaude-agent

# Rebuild after code changes
docker compose up -d --build

# Shell into container
docker compose exec telclaude bash
docker compose exec telclaude-agent bash

# Run telclaude doctor
docker compose exec telclaude telclaude doctor

# Claude login (if not using API key)
docker compose exec -e CLAUDE_CONFIG_DIR=/home/telclaude-auth telclaude claude login

# View volumes
docker volume ls | grep telclaude
```

## Network Firewall (Required)

**The network firewall is required for Docker mode.** Both relay and agent enable it by default; the agent (tool runner) refuses to start without it because Docker mode disables the SDK sandbox, leaving Bash with no network isolation.

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

Internal RPC between the agent and relay is allowed by hostname. If you rename the
services, set `TELCLAUDE_INTERNAL_HOSTS` (comma-separated) to match.

Note: The compose files enable the firewall in both relay and agent containers
by default. The agent enforces the tool boundary; the relay firewall limits
egress even though it does not run tools.

### Bypass (Testing Only)

**SECURITY WARNING:** For testing only. Never use in production.

```bash
# Disables firewall requirement (Bash will have unrestricted network access)
TELCLAUDE_ACCEPT_NO_FIREWALL=1
```

This bypass is logged to the audit log.

## Troubleshooting

### "Sandbox unavailable" (native mode only)

Docker mode disables the SDK sandbox, so this error should not appear inside the container.
If you see it, you are likely running native mode outside Docker. On Linux, install
`bubblewrap` and `socat` and retry.

### "Permission denied" on workspace

Ensure the workspace path is accessible from WSL2:

```powershell
# Check WSL2 can access the path
wsl ls /mnt/c/Users/YourName/Projects
```

### Claude CLI not working

```powershell
# Check Claude version
docker compose exec telclaude claude --version

# Re-authenticate
docker compose exec -e CLAUDE_CONFIG_DIR=/home/telclaude-auth telclaude claude login
```

### Reset session data (keeps secrets)

```powershell
# Remove containers and non-external volumes (keeps TOTP secrets and Claude creds)
docker compose down -v

# Rebuild fresh
docker compose up -d --build
```

**Note:** External volumes (`telclaude-claude-auth`, `telclaude-totp-data`) are protected and will NOT be deleted by `docker compose down -v`.

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
   ```powershell
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
