# Official Claude Plugins

Official Claude plugins are not the same thing as standalone telclaude skills.

- Standalone telclaude skills use the shared draft/promote catalog described in [skills.md](./skills.md).
- Official Claude plugins use Claude Code's own marketplace/install/update lifecycle and stay scoped to a Claude profile.

This split is intentional:

- plugins can carry more than skills (`bin/`, hooks, agents, settings, MCP, monitors)
- private vs social is a profile boundary, not a catalog-copying trick
- private defaults broad; social stays fail-closed at runtime

## Persona model

Each persona has its own Claude profile volume:

- private profile: `/home/telclaude-skills`
- social profile: `/home/telclaude-skills` inside `agent-social`
- relay mounts both real profile volumes at `/home/telclaude-private-profile` and `/home/telclaude-social-profile` so operator CLI commands act on the live Linux runtime state

Telclaude manages official plugins with:

```bash
telclaude plugins list [--persona private|social|both]
telclaude plugins install <plugin@marketplace> [--persona ...] [--marketplace-source <source>]
telclaude plugins update <plugin@marketplace> [--persona ...] [--marketplace-source <source>]
telclaude plugins uninstall <plugin@marketplace> [--persona ...]
```

Default persona is `private`.

## First install vs later updates

Use `--marketplace-source` the first time a profile does not know the marketplace yet. The source is passed straight through to Claude's official marketplace add command, so it can be a GitHub shorthand, git URL, remote `marketplace.json` URL, or local test path.

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

## Social boundary

Installing a plugin into the social profile does not automatically authorize the social agent to invoke all of its skills.

For social use, both of these must be true:

1. the plugin is installed in the social profile
2. the service's `allowedSkills` includes the plugin skill names (for example `shaon:attendance`)

Private agents do not use `allowedSkills`; they can invoke any active skill/plugin in their own profile.

## When to use which path

Use `telclaude skills ...` when:

- you are authoring or importing a standalone skill folder
- you want draft quarantine, scanner review, and explicit promotion

Use `telclaude plugins ...` when:

- the upstream package is a real Claude plugin or marketplace entry
- you want official install/update/uninstall semantics
- the asset includes more than plain skills
