# Hermes Runtime Token Custody Slice 1

Slice 1 now prevents the contained entrypoint from writing the startup OpenAI Codex proxy root token or the static Hermes MCP relay transport token into generated `HERMES_HOME` files.

What changed:

- `config.yaml` keeps the Telclaude live MCP endpoint and tool policy, but the MCP `Authorization` header is written as an environment reference (`${TELCLAUDE_HERMES_MCP_RELAY_TOKEN}`), not as the bearer value.
- `auth.json` still contains the upstream-Hermes compatibility OpenAI Codex credential-pool entry, but the entrypoint mints it as a peer-bound relay handle instead of copying the root proxy token.
- The entrypoint now scans generated `config.yaml`, `auth.json`, and `secret-manifest.json` and fails startup if either startup root token appears in those files.

Remaining blocker:

- The contained runtime still receives `TELCLAUDE_HERMES_MCP_RELAY_TOKEN` in process env so upstream Hermes can authenticate to live MCP, and `auth.json` still contains a peer-bound OpenAI Codex relay handle for upstream Hermes compatibility. Full "no meaningful runtime token custody" requires relay-side issuance/injection of short-lived MCP connection tokens and a model-auth path that upstream Hermes can use without a persistent credential-pool token in `HERMES_HOME`.
