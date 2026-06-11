# Plugin Packages In The Hermes Runtime

Plugin packages are not the same thing as standalone telclaude skills.

- Standalone telclaude skills use the draft/promote catalog described in [skills.md](./skills.md).
- Plugin packages use Claude Code's marketplace/install/update lifecycle as an acquisition mechanism.
- Runtime execution is Hermes-only: deploys seed curated skill directories into the persona's relay-owned Hermes skill catalog.

This split is intentional:

- plugins can carry more than skills (`bin/`, hooks, agents, settings, MCP, monitors)
- private vs social is a Hermes catalog boundary
- private defaults broad; social stays fail-closed at runtime

## Persona model

The relay maintains persona-scoped plugin state for operator-managed acquisition:

- private profile: `/home/telclaude-private-profile`
- social profile: `/home/telclaude-social-profile`

The contained Hermes runtimes do not execute directly from profile plugin state.
They mount relay-owned external catalogs read-only and load them through
upstream `skills.external_dirs`:

- private catalog: `$TELCLAUDE_HERMES_SKILL_CATALOG_DIR`
- social catalog: `$TELCLAUDE_HERMES_SOCIAL_SKILL_CATALOG_DIR`

Profile plugin state does not create an alternate runtime route.

For reproducible deploys, do not hand-install catalog entries. Declare seed
sources in a private deploy manifest and replay it with:

```bash
telclaude hermes-skills sync-manifest /path/to/hermes-skill-seeds.json --prune-managed
```

The manifest uses container-visible `sourceDir` paths, records audit `origin`
strings, and only prunes existing catalog entries whose origin starts with
`seed:`. Use curated source directories for safety-sensitive skills; the
manifest source is the runtime contract, not necessarily the upstream plugin
skill verbatim.

Telclaude manages plugin packages with:

```bash
telclaude plugins list [--persona private|social|both]
telclaude plugins install <plugin@marketplace> [--persona ...] [--marketplace-source <source>]
telclaude plugins update <plugin@marketplace> [--persona ...] [--marketplace-source <source>]
telclaude plugins uninstall <plugin@marketplace> [--persona ...]
```

Default persona is `private`.

## First install vs later updates

Use `--marketplace-source` the first time a profile does not know the marketplace yet. The source is passed through to Claude's marketplace add command, so it can be a GitHub shorthand, git URL, remote `marketplace.json` URL, or local test path.

Example:

```bash
telclaude plugins install shaon@avivsinai-marketplace \
  --persona private \
  --marketplace-source avivsinai/skills-marketplace
```

Later updates usually only need:

```bash
telclaude plugins update shaon@avivsinai-marketplace --persona private
```

Rerunning `telclaude plugins install ...` only repairs plugin/profile state.
Runtime repair is `telclaude hermes-skills sync-manifest ...` followed by a
Hermes skill reload or runtime restart.

For runtime activation, upstream Hermes must re-scan its external skill dirs.
Use upstream `/reload-skills` when available, or restart the affected contained
runtime after replaying the manifest.

## Social boundary

Acquiring a plugin package into the social profile does not authorize the
social agent to invoke its skills. Social runtime exposure still goes through
the curated Hermes catalog.

For social use, both of these must be true:

1. the curated skill is installed in the social Hermes catalog
2. the service's `allowedSkills` includes the Hermes skill names

Private agents do not use service `allowedSkills`; they can invoke active private Hermes catalog skills through the private runtime.

## When to use which path

Use `telclaude skills ...` when:

- you are authoring or importing a standalone skill folder
- you want draft quarantine, scanner review, and explicit promotion

Use `telclaude plugins ...` when:

- the upstream package is a real plugin or marketplace entry
- you want official install/update/uninstall semantics
- the package may include more than plain skills, and you are only acquiring or updating that package state
