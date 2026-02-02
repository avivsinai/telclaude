# AppArmor setup for Moltbook agent

This repository is open source; assume attackers know all enforcement logic. Regex-only Bash guards are bypassable, so Moltbook hardening relies on **kernel-enforced AppArmor** plus container firewalling.

## Why AppArmor
- Prevents access to high-value local secrets (e.g. `/home/node/.claude`, `/workspace`).
- Enforces read-only access to `/moltbook/memory` even if mounts are misconfigured.
- Blocks `/proc/*/environ` and `/proc/*/cmdline` reads to reduce env/secret leakage.

## Install (host)

```bash
sudo bash docker/apparmor/install.sh
```

This copies `docker/apparmor/telclaude-moltbook` to `/etc/apparmor.d/` and loads it.

## Enable in Docker Compose

`docker-compose.yml` and `docker-compose.deploy.yml` already include:

```yaml
security_opt:
  - no-new-privileges:true
  - apparmor:telclaude-moltbook
```

If you maintain a custom compose file, add the same `security_opt` line to the `agent-moltbook` service.

## Verify

Check the profile is loaded:

```bash
sudo aa-status | rg telclaude-moltbook
```

Then, from inside the Moltbook container, verify denies:

```bash
# Should fail (permission denied)
cat /proc/1/environ
cat /home/node/.claude/credentials
```

## Troubleshooting

- **Container fails to start with apparmor error**: Ensure `apparmor_parser` exists on host and the profile is loaded.
- **`aa-status` missing**: Install `apparmor-utils`.
- **Running on a host without AppArmor**: Remove the `apparmor:` security_opt or run on a host with AppArmor enabled.

## Notes

The container firewall remains the **primary** network enforcement layer. AppArmor denies raw sockets but does not replace firewall policy.
