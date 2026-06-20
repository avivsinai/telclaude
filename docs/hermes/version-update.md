# Hermes Version Update Path

The production Hermes default remains the last fully proven pin until the target
pin passes the steady-state gates. Do not update Docker/script defaults or
tracked green proof artifacts just because a newer upstream tag exists.

## Current Production Pin

- Upstream ref: `v2026.5.29`
- Hermes package version: `0.15.1`
- Source commit: `e71a2bd11b733f3be7cf99deafde0066c343d462`
- Docker image: `nousresearch/hermes-agent@sha256:192a40783e9227b5f162b76af4d133050557adebd46e1c9cb40cb79a1317a9f7`

## Next Target

- Upstream ref: `v2026.6.19`
- Hermes package version: `0.17.0`
- Source commit: `2bd1977d8fad185c9b4be47884f7e87f1add0ce3`
- Docker image: `nousresearch/hermes-agent@sha256:9f367c7756ef087661a361536a89f438d57a122b958dc23d82d456b1433e6e9e`

The target is worth testing because it is the latest upstream release with a
published Docker manifest. Source the version from upstream `pyproject.toml`;
the Docker manifest does not carry a version label.

## Command Surface

Use the machine-readable plan first:

```bash
pnpm dev hermes version-update --json
```

That command reports the current pin, the target pin, and the required proof
gates. It does not promote the target and does not write artifacts.

The `--wrapper-run` input for the no-fork proof must be a
`telclaude.hermes.no-fork-wrapper-run.v1` machine report from
`telclaude-hermes-no-fork-wrapper` / `telclaude-hermes-wrapper-p0` with a valid
inner signature. The proof command rejects reports with the wrong schema
identity, malformed timestamps, invalid signature, non-SHA-256 digests, failed
P0 status, or missing runtime-source/monkeypatch denial observations. It also
rejects reports whose checkout path, expected ref, expected version, expected
commit, HEAD, or expected-ref commit do not match the git checkout being proved.

## Required Gates

Run the target through these gates before changing production defaults:

```bash
pnpm dev hermes prove --upstream-clean \
  --checkout artifacts/hermes/version-update-v2026.6.19/hermes-agent-v2026.6.19-git \
  --expected-ref v2026.6.19 \
  --expected-version 0.17.0 \
  --expected-commit 2bd1977d8fad185c9b4be47884f7e87f1add0ce3 \
  --wrapper-run artifacts/hermes/version-update-v2026.6.19/wrapper-run.json \
  --out artifacts/hermes/version-update-v2026.6.19/no-fork.json
```

```bash
TELCLAUDE_HERMES_IMAGE=nousresearch/hermes-agent@sha256:9f367c7756ef087661a361536a89f438d57a122b958dc23d82d456b1433e6e9e \
  pnpm dev hermes network-probes --allow-run --posture contained-internal \
    --out artifacts/hermes/version-update-v2026.6.19/network-probes.json \
    --evidence-dir artifacts/hermes/version-update-v2026.6.19/network-probes
```

Run the live surface probes against the target image, then regenerate the
feature matrix only from observed passing evidence:

```bash
pnpm dev hermes probes --pin 0.17.0 \
  --out artifacts/hermes/version-update-v2026.6.19/feature-probes.json
```

Bind the regenerated matrix and no-fork proof into the compatibility lock:

```bash
pnpm dev hermes compat-lock --dry-run \
  --pin 0.17.0 \
  --feature-probes artifacts/hermes/version-update-v2026.6.19/feature-probes.json \
  --nofork-proof artifacts/hermes/version-update-v2026.6.19/no-fork.json \
  --out artifacts/hermes/version-update-v2026.6.19/hermes-compat.lock.json
```

Finish with both static and live gates:

```bash
pnpm dev hermes doctor --pin 0.17.0 \
  --feature-probes artifacts/hermes/version-update-v2026.6.19/feature-probes.json \
  --probes \
  --lockfile artifacts/hermes/version-update-v2026.6.19/hermes-compat.lock.json \
  --compat-lock \
  --json
TELCLAUDE_HERMES_IMAGE=nousresearch/hermes-agent@sha256:9f367c7756ef087661a361536a89f438d57a122b958dc23d82d456b1433e6e9e \
  pnpm dev hermes verify-live --json \
    --out artifacts/hermes/version-update-v2026.6.19/verify-live.json
```

`verify-live` must include `runtime.toolset_inventory` and
`runtime.skill_manage_write_denied`. Those prove the contained runtime's native
tool surface, which is distinct from served-MCP endpoint containment.

## Promotion Rule

Promote the target by updating compose/script defaults, tracked proof artifacts,
and architecture docs only after every gate above passes on the target image.
Until then, `v2026.6.19 / 0.17.0` is an identified target, not the production
runtime.
