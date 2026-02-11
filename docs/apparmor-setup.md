# AppArmor setup for telclaude containers

This repository is open source; assume attackers know all enforcement logic. Regex-only Bash guards are bypassable, so container hardening relies on **kernel-enforced AppArmor** plus container firewalling.

## Why AppArmor
- Prevents access to high-value local secrets (e.g. `/home/telclaude-auth`, `/workspace`).
- Enforces read-only access to `/social/memory` even if mounts are misconfigured.
- Blocks `/proc/*/environ` and `/proc/*/cmdline` reads to reduce env/secret leakage.

## Install (host)

```bash
sudo bash docker/apparmor/install.sh
```

This copies all profiles (`telclaude-vault`, `telclaude-relay`, `telclaude-agent`, `telclaude-social`) to `/etc/apparmor.d/` and loads them.

## Enable in Docker Compose

`docker-compose.yml` and `docker-compose.deploy.yml` already include per-container profiles:

```yaml
security_opt:
  - no-new-privileges:true
  - apparmor:telclaude-agent   # or telclaude-relay, telclaude-social, telclaude-vault
```

If you maintain a custom compose file, add the matching `security_opt` line to each service.

## Verify

Check profiles are loaded:

```bash
sudo aa-status | rg telclaude
```

Then, from inside a container, verify denies:

```bash
# Should fail (permission denied)
cat /proc/1/environ
cat /home/telclaude-auth/credentials
```

## Troubleshooting

- **Container fails to start with apparmor error**: Ensure `apparmor_parser` exists on host and the profile is loaded.
- **`aa-status` missing**: Install `apparmor-utils`.
- **Running on a host without AppArmor**: Remove the `apparmor:` security_opt or run on a host with AppArmor enabled.

## Notes

The container firewall remains the **primary** network enforcement layer. AppArmor denies raw sockets but does not replace firewall policy.
