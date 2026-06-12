# Hermes Multichannel Current-State Inventory

Date: 2026-06-12

Scope: first Slice 0 pass for the multichannel Hermes security plan.

## Commands Run

1. `pnpm dev hermes doctor --json`
   - Status: pass.
   - Observed pin: Hermes package version `0.15.1`.

2. `pnpm dev hermes prove --upstream-clean --p0 --json`
   - Status: input error, exit code 2.
   - `hermes-agent` checkout is missing at `/Users/avivsinai/MyProjects/telclaude/hermes-agent`.
   - P0 proof also requires `OPERATOR_RPC_RELAY_PRIVATE_KEY`.
   - Result: no fresh `nofork.clean` evidence from this worktree.

3. `pnpm dev hermes cutover-check --strict --dry-run --json`
   - Status: input error, exit code 2.
   - Current proof bundle points rollback evidence at `artifacts/hermes/no-fork-run-20260605T095434Z/rollback-rehearsal.json`.
   - That artifact is stale relative to the current Hermes-only rollback schema: it includes old mutable-control fields `observedFallbackPath` and `signedRelayTranscripts.afterControl`, and it records fallback to legacy mode.
   - Result: strict cutover proof is not fresh or readable for the current control model.

4. `pnpm dev hermes network-probes --json`
   - Status: pending/input-gated, exit code 2.
   - Real network probes require `--allow-run`.
   - Result: no fresh network containment proof was generated in this pass.

## Inventory

| Surface | Current State | Notes |
| --- | --- | --- |
| Hermes pin doctor | Pass | Pin is present and parseable. |
| No-fork proof | Blocked | Missing local upstream checkout and operator relay signing env. |
| Strict cutover check | Blocked | Stored rollback evidence is stale and schema-incompatible. |
| Network probes | Not run | Requires explicit `--allow-run`. |
| Explicit authority scopes | Implemented in this pass | Private runtime no longer grants all capability scopes by default. |
| Build verification | Pass | Focused tests, typecheck, and lint passed after implementation. |

## Next Proof Work

1. Rehydrate or point `pnpm dev hermes prove` at the pinned upstream Hermes checkout.
2. Provide the operator relay signing environment needed for P0 proof.
3. Regenerate rollback evidence against the current Hermes-only control model.
4. Run network probes with the intended containment posture and `--allow-run`.
5. Rebuild the cutover proof bundle and rerun strict dry-run cutover check.
