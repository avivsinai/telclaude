# Hermes Wrapper Spec Coverage

This note tracks the implementation against the original no-fork Hermes wrapper
spec without restoring the removed draft plan.

## Spec Provenance

- Original path: `docs/plans/2026-05-29-hermes-wrapper-pristine-spec.md`.
- Added in current history by `75b1134cfb5bed9548d3ec4114bb8fa6056ea585`
  (`Add Hermes wrapper foundation gates`, 2026-05-29).
- Removed by `f70941db46b39459486f90d0a3ad0f8216cfb73d`
  (`chore(hermes): OSS-harden cleanup`, 2026-06-03) together with generated
  run seeds and plans.
- A working-copy copy still exists in
  `../telclaude-hermes-peer-followup/docs/plans/2026-05-29-hermes-wrapper-pristine-spec.md`.

## Current Implementation Mapping

The implementation does not keep the spec's `G-*` names as primary gate names.
The spec is enforced through these runtime artifacts and checks:

- `src/hermes/parity-roster.ts` maps the 25 Complete Parity Matrix rows to
  required surfaces, fixtures, required checks, or cutover meta-gates. The
  non-descopable rows are `cutover`, `redaction`, `private-chat`,
  `approval-tokens`, `identity-migration`, `memory`, and `skills`.
- `docs/hermes/cutover-proof-bundle.json` byte-binds the ten strict cutover
  artifacts: inventory, scope, decisions, compatibility lockfile, feature-probe
  matrix, fixture results, no-fork proof, network probe bundle, queue snapshot,
  and rollback rehearsal.
- `src/hermes/foundation.ts:evaluateCutoverCheck()` evaluates the strict gate
  sequence: proof-bundle validity, workflow scope, decisions, profile-generation
  proof, feature probes, lockfile consistency, fixtures, no-fork proof, network
  probes, queue ownership, rollback rehearsal, and complete parity roster.
- `src/commands/hermes.ts` now resolves default `cutover-check` inputs through
  the proof bundle's `artifactPath` entries when the operator does not pass an
  explicit path. This prevents a green proof bundle from being mixed with stale
  default `docs/hermes/*` inputs.
- Archived dry-run verification resolves the operator relay public key from the
  checked-in rollback relay public-key lock when `OPERATOR_RPC_RELAY_PUBLIC_KEY`
  is not exported. Live cutover still requires live operator key material.

## Coverage Status

Implemented and proven on this branch:

- No-fork runner proof and P0 proof-bundle binding.
- Complete-parity roster coverage with 25 backed rows and one explicit
  `parity-descope:chief-of-staff` decision.
- Feature probes for headless execution, approval continuation, model relay,
  API/served-MCP containment, provider domains, Google/provider approval,
  served-MCP memory, skills allowlist, edge adapters, browser/computer broker,
  workflows, side-effect ledger, and network egress broker.
- Fixture bundle covering the private Telegram cutover workflow plus provider,
  identity, public/household edge, browser/computer, cron, long-run, and negative
  bypass fixtures.
- Signed/origin-bound evidence for the sensitive probes, with archived public
  key provenance in `docs/hermes/rollback-relay-public-key.lock.json`.

Still outside the proven cutover boundary:

- Actual live production cutover on the NUC is not proven by this branch alone;
  the current green command is strict dry-run evidence.
- The included scope has one first-cutover workflow
  (`telegram-chat.telegram-chat-eafeee3bce50006d5d19`). The broader WhatsApp,
  email, AgentMail, household, social, provider, browser/computer, cron, and
  long-running rows are represented by parity proofs and fixtures, not by a
  production traffic flip for every channel.
- `chief-of-staff` remains explicitly descoped until a production fixture
  (`fixture.profile.chief-of-staff`) is added.
- A live non-dry-run cutover requires fresh attestations and the operator
  runtime environment, including the actual contained relay/container IPs.

## Current Green Command

On this branch, after refreshing `execution.headless_entrypoint`, the strict
dry-run cutover is green with the contained runtime IPs exported from the
current cli-headless evidence:

```bash
TELCLAUDE_HERMES_RELAY_IP=$(jq -r '.runtime.relayResolvedAddress' artifacts/hermes/probes/execution-cli-headless.json) \
TELCLAUDE_HERMES_CONTAINED_IP=$(jq -r '.runtime.containerIpAddress' artifacts/hermes/probes/execution-cli-headless.json) \
pnpm dev hermes cutover-check --dry-run --json
```

Expected result: `status: "safe"`, `exitCode: 0`,
`parity.rosterCovered: pass`, `proofBundle.complete: pass`.
