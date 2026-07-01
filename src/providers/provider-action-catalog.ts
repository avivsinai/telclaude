/**
 * Agent-facing provider action catalog.
 *
 * The contained Hermes runtime only ever learns its granted provider *scopes*
 * (e.g. `clalit`, `bank`, `google`) — never the concrete action ids each scope
 * exposes. Without that list the model guesses action names (`list_capabilities`,
 * `get_medications`, `status`, ...) which the sidecar rejects as invalid-action
 * 404s, so a Clalit/bank request silently fails.
 *
 * This module turns the relay's cached provider `/v1/schema` data into a compact,
 * scope-keyed prompt block listing the exact `tc_provider_read` /
 * `tc_provider_prepare_write` service + action pairs the agent may call. It is
 * pure and data-driven: the schema is the source of truth, so the catalog stays
 * correct when a sidecar blueprint gains or loses an action.
 *
 * Two safety properties, because the ids are provider-derived and land inside the
 * system prompt:
 *   1. Read vs. write actions are kept separate so the model uses the two-phase
 *      write path (tc_provider_prepare_write) for side-effecting actions instead
 *      of calling tc_provider_read on them.
 *   2. Every service/action id is validated against a strict identifier grammar
 *      before it reaches the prompt. A malicious/misconfigured schema cannot emit
 *      `</hermes-provider-actions>` or instruction-looking text — an id that is
 *      not a clean identifier is one the agent could not call verbatim anyway, so
 *      it is dropped rather than escaped.
 */

/** One catalog action: its verbatim id plus whether it is a side-effecting write. */
export type CatalogAction = { readonly id: string; readonly write: boolean };

/** providerId -> serviceId -> actions, derived from each provider's /v1/schema. */
export type ProviderActionCatalog = Record<string, Record<string, readonly CatalogAction[]>>;

/**
 * Agent-facing provider scopes backed by a differently-named configured service.
 * The MCP authority grants e.g. `bank`, but the sidecar exposes `poalim` /
 * `massad`; the relay proxy resolves and rewrites the request body service
 * accordingly (see provider-proxy `resolveConfiguredProvider` +
 * `rewriteProviderRequestBody`). Keep this in sync with that rewrite — the agent
 * always calls `service: "<scope>"`, never the backing service name.
 */
export const CANONICAL_PROVIDER_SERVICE_ALIASES: Record<string, readonly string[]> = {
	bank: ["poalim", "massad"],
};

/**
 * Strict grammar for a service/action id that is safe to place verbatim in the
 * prompt AND callable verbatim by the agent: leading alphanumeric, then
 * alphanumeric / underscore / hyphen, bounded length. Deliberately excludes `.`,
 * `/`, `<`, `>`, backticks, whitespace, and newlines.
 */
const SAFE_PROVIDER_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

export function isSafeProviderIdentifier(value: string): boolean {
	return SAFE_PROVIDER_IDENTIFIER.test(value);
}

type CatalogEntry = { service: string; reads: string[]; writes: string[] };

function safeSortedIds(actions: readonly CatalogAction[], write: boolean): string[] {
	return [
		...new Set(
			actions
				.filter((action) => action.write === write)
				.map((action) => action.id.trim())
				.filter(isSafeProviderIdentifier),
		),
	].sort();
}

function collectServiceActions(
	catalog: ProviderActionCatalog,
	service: string,
): readonly CatalogAction[] {
	const collected: CatalogAction[] = [];
	for (const services of Object.values(catalog)) {
		const found = services[service];
		if (found) collected.push(...found);
	}
	return collected;
}

function toEntry(service: string, actions: readonly CatalogAction[]): CatalogEntry | null {
	// The alias service label (e.g. "bank") is relay-generated, but the real
	// service ids from the schema are provider-derived — validate both.
	if (!isSafeProviderIdentifier(service)) return null;
	const reads = safeSortedIds(actions, false);
	const writes = safeSortedIds(actions, true);
	if (reads.length === 0 && writes.length === 0) return null;
	return { service, reads, writes };
}

/**
 * Resolve the agent-facing (service, actions) entries a granted scope unlocks.
 * Mirrors the relay's provider routing so the prompt teaches exactly the call
 * shape the authority + proxy will accept.
 */
function resolveScopeEntries(scope: string, catalog: ProviderActionCatalog): CatalogEntry[] {
	// 1. Scope is itself a configured provider id (e.g. "google") — list every
	//    sub-service it exposes; the agent calls with that service id
	//    (resolveTelclaudeProviderOperation maps service gmail/calendar/... to the
	//    google providerId).
	const providerServices = catalog[scope];
	if (providerServices) {
		return Object.entries(providerServices)
			.map(([service, actions]) => toEntry(service, actions))
			.filter((entry): entry is CatalogEntry => entry !== null)
			.sort((a, b) => a.service.localeCompare(b.service));
	}

	// 2. Scope names a configured service directly (e.g. "clalit"). The agent calls
	//    with service === scope.
	const direct = toEntry(scope, collectServiceActions(catalog, scope));
	if (direct) return [direct];

	// 3. Scope is an alias (e.g. "bank" -> poalim/massad). The agent still calls
	//    service === scope; the relay rewrites it to the backing service.
	const aliasServices = CANONICAL_PROVIDER_SERVICE_ALIASES[scope];
	if (aliasServices) {
		const merged = aliasServices.flatMap((aliasService) =>
			collectServiceActions(catalog, aliasService),
		);
		const entry = toEntry(scope, merged);
		if (entry) return [entry];
	}

	// 4. Unresolvable (e.g. a stale "government" grant with no configured sidecar).
	//    Emit nothing so the guardrail keeps the agent from inventing actions.
	return [];
}

/**
 * Build the prompt block that tells the contained Hermes agent EXACTLY which
 * provider operations it may call, split by read vs. write path. Returns "" when
 * nothing resolves (no cached catalog, or only unconfigured scopes) so the caller
 * can omit the block.
 */
export function formatGrantedProviderActionCatalog(
	grantedScopes: readonly string[],
	catalog: ProviderActionCatalog | null | undefined,
): string {
	if (!catalog) return "";
	const seen = new Set<string>();
	const readLines: string[] = [];
	const writeLines: string[] = [];
	for (const scope of [...new Set(grantedScopes.map((s) => s.trim()).filter(Boolean))].sort()) {
		for (const entry of resolveScopeEntries(scope, catalog)) {
			if (seen.has(entry.service)) continue;
			seen.add(entry.service);
			if (entry.reads.length > 0) {
				readLines.push(`- service "${entry.service}": ${entry.reads.join(", ")}`);
			}
			if (entry.writes.length > 0) {
				writeLines.push(`- service "${entry.service}": ${entry.writes.join(", ")}`);
			}
		}
	}
	if (readLines.length === 0 && writeLines.length === 0) return "";

	const lines: string[] = [
		"<hermes-provider-actions>",
		"These are the ONLY provider operations you may call. Use the exact service + action ids below (case-sensitive). Do not invent, translate, or guess action names — if none matches the request, tell the user the provider does not expose that action.",
	];
	if (readLines.length > 0) {
		lines.push("Reads — call tc_provider_read with the service and action:", ...readLines);
	}
	if (writeLines.length > 0) {
		lines.push(
			"Writes — call tc_provider_prepare_write with the service and action (each requires operator approval before it runs):",
			...writeLines,
		);
	}
	lines.push("</hermes-provider-actions>");
	return lines.join("\n");
}
