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

This copies all telclaude profiles (`telclaude-vault`, `telclaude-relay`) to `/etc/apparmor.d/` and loads them.

## Enable in Docker Compose

`docker-compose.yml` and `docker-compose.deploy.yml` already include per-container profiles:

```yaml
security_opt:
  - no-new-privileges:true
  - apparmor:telclaude-relay   # or telclaude-vault
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

## Hermes private-runtime overlay

The `docker/docker-compose.hermes.yml` overlay adds contained Hermes runtimes (`tc-hermes-contained` and `tc-hermes-social`) on isolated private/social internal networks. The relay container in this overlay is the same `telclaude` service from the base compose, so it keeps its `apparmor:telclaude-relay` profile. The contained Hermes containers, however, run the pinned upstream `nousresearch/hermes-agent` image (`@sha256:192a4078...`), which is **not** covered by a telclaude AppArmor profile and is therefore not in `install.sh`.

Instead of AppArmor, the Hermes runtime containers are hardened with kernel/runtime primitives declared directly in the overlay:

- `cap_drop: ALL` and `no-new-privileges:true`.
- Non-root `user: "10000:10000"`.
- `read_only: true` root filesystem; the only writable surfaces are `noexec` tmpfs mounts (`/tmp`, `/run`, `/home/hermes`).
- `pids_limit: 256`, `mem_limit: 2G`, `cpus: 2`.
- Internal-only bridge network (`internal: true`) with model-provider hosts (`api.openai.com`, `api.anthropic.com`, etc.) pinned to a blackhole address via `extra_hosts`, so direct model egress fails. All model traffic must go through the relay's OpenAI Codex proxy.
- The telclaude code is mounted into the contained runtime read-only (`..:/opt/data/telclaude-runner:ro`).

Because there is no `telclaude-hermes` profile, `aa-status | rg telclaude` will not list anything for the contained runtime — that is expected. Hermes egress is constrained by the `internal: true` bridge, model-provider `extra_hosts` blackholing, and relay-only routing rather than by the agent-container firewall path.

## Notes

For the relay and sidecars, the container firewall remains the **primary** network enforcement layer. AppArmor denies raw sockets but does not replace firewall policy. The Hermes contained runtime uses the overlay constraints described above rather than a telclaude AppArmor profile.
