# Telclaude Docker Deployment

Secure containerized deployment for telclaude on Windows (WSL2) or Linux hosts.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows Host (WSL2)                          │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                 Docker Container                          │  │
│  │                                                           │  │
│  │  ┌─────────────────┐    ┌─────────────────────────────┐  │  │
│  │  │    telclaude    │───▶│     Claude Code CLI        │  │  │
│  │  │     relay       │    │  (tools: Read, Write, etc)  │  │  │
│  │  └────────┬────────┘    └──────────────┬──────────────┘  │  │
│  │           │                            │                  │  │
│  │           ▼                            ▼                  │  │
│  │  ┌─────────────────┐    ┌─────────────────────────────┐  │  │
│  │  │   /data volume  │    │     /workspace volume       │  │  │
│  │  │  (SQLite, cfg)  │    │   (your projects folder)    │  │  │
│  │  └─────────────────┘    └──────────────┬──────────────┘  │  │
│  │                                        │                  │  │
│  └────────────────────────────────────────┼──────────────────┘  │
│                                           │                     │
│                    ┌──────────────────────┘                     │
│                    ▼                                            │
│         C:\Users\YourName\Projects                              │
│         (host filesystem - ONLY this folder exposed)            │
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
| **Network isolation** | Optional firewall restricts outbound connections (requires root at startup) |
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

### First-Time Authentication

If you didn't set `ANTHROPIC_API_KEY`, authenticate Claude:

```powershell
docker compose exec telclaude claude login
```

This stores credentials in the `telclaude-claude` volume.

## Configuration

### Volume Mounts

| Container Path | Purpose | Persisted |
|---------------|---------|-----------|
| `/workspace` | Your projects folder | Host mount |
| `/data` | SQLite DB, config, sessions | Named volume |
| `/home/node/.claude` | Claude credentials | Named volume |

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Yes | Bot token from @BotFather |
| `WORKSPACE_PATH` | Yes | Host path to mount as /workspace |
| `ANTHROPIC_API_KEY` | No | Alternative to `claude login` |
| `TELCLAUDE_LOG_LEVEL` | No | `debug`, `info`, `warn`, `error` |
| `TELCLAUDE_FIREWALL` | No | Set to `1` to enable network firewall |

### Custom Configuration

Mount a custom config file:

```yaml
volumes:
  - ./telclaude.json:/data/telclaude.json:ro
```

Example `telclaude.json`:
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

## Commands

```powershell
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
docker compose exec telclaude claude login

# View volumes
docker volume ls | grep telclaude
```

## Enabling Network Firewall

For stricter security, enable the network firewall:

1. Set in `.env`:
   ```bash
   TELCLAUDE_FIREWALL=1
   ```

2. The container will restrict outbound connections to:
   - Anthropic API (api.anthropic.com)
   - Telegram API (api.telegram.org)
   - Package registries (npm, PyPI)
   - GitHub

## Troubleshooting

### "Sandbox unavailable"

The container includes `bubblewrap` for sandboxing. If it fails:

```powershell
# Check if bubblewrap works
docker compose exec telclaude bwrap --version

# May need additional capabilities (already in docker-compose.yml)
cap_add:
  - SYS_ADMIN
  - NET_ADMIN
```

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
docker compose exec telclaude claude login
```

### Reset all data

```powershell
# Remove containers and volumes
docker compose down -v

# Rebuild fresh
docker compose up -d --build
```

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
