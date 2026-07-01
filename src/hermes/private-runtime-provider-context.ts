import type { PermissionTier, TelclaudeConfig } from "../config/config.js";
import type { EffectiveOperatorProfile } from "../config/profiles.js";
import {
	formatGrantedProviderActionCatalog,
	type ProviderActionCatalog,
} from "../providers/provider-action-catalog.js";
import { getCachedProviderActionCatalog } from "../providers/provider-skill.js";
import type { TelclaudeMcpCapabilityScope } from "./mcp/bridge.js";

export type HermesPrivateRuntimeProviderContext = {
	readonly providerScopes: readonly string[];
	readonly capabilityScopes: readonly TelclaudeMcpCapabilityScope[];
	readonly outboundChannels: readonly string[];
	readonly systemPromptAppend: string;
};

/**
 * Capability scopes that mutate relay state and therefore require a write tier.
 * schedule.read / browse.use are fine at READ_ONLY (listing your own reminders or
 * reading a public page is harmless); the side-effecting scopes are stripped below
 * WRITE_LOCAL:
 *   - schedule.write (create/cancel a relay-owned reminder)
 *   - browse.act (drive interactive browser writes via tc_browse_act*) — every
 *     browse.act write is itself two-phase prepare→human-approve→execute, but the
 *     *capability to initiate one* is still a write and must match the same tier
 *     as other writes, so a READ_ONLY authority never receives it.
 */
const WRITE_TIER_CAPABILITY_SCOPES: ReadonlySet<TelclaudeMcpCapabilityScope> = new Set([
	"schedule.write",
	"browse.act",
]);

export function buildHermesPrivateRuntimeProviderContext(
	config: Pick<TelclaudeConfig, "hermes">,
	profile?: Pick<
		EffectiveOperatorProfile,
		"providerScopes" | "capabilityScopes" | "outboundChannels"
	>,
	tier?: PermissionTier,
	actionCatalog: ProviderActionCatalog | null = getCachedProviderActionCatalog(),
): HermesPrivateRuntimeProviderContext {
	const providerScopes = uniqueSorted(
		profile?.providerScopes ?? config.hermes?.privateRuntime?.providerScopes,
	);
	const capabilityScopes = gateCapabilityScopesByTier(
		uniqueSorted(
			profile?.capabilityScopes ?? config.hermes?.privateRuntime?.capabilityScopes,
		) as TelclaudeMcpCapabilityScope[],
		tier,
	);
	const outboundChannels = uniqueSorted(
		profile?.outboundChannels ?? config.hermes?.privateRuntime?.outboundChannels,
	);
	// The valid-action catalog is what stops the agent from guessing action ids
	// (list_capabilities, get_medications, ...) that the sidecar rejects as 404s.
	// Empty scopes -> empty block, so no separate guard is needed here.
	const actionCatalogAppend = formatGrantedProviderActionCatalog(providerScopes, actionCatalog);
	const runtimeBlock =
		providerScopes.length > 0
			? [
					"<hermes-provider-runtime>",
					"Provider access is relay-owned. Do not call provider hostnames, provider URLs, curl, WebFetch, or telclaude provider CLI commands.",
					"This supersedes any legacy external-provider or provider-query instructions in the surrounding context.",
					"Use only the served MCP provider tools: tc_provider_read for reads, tc_provider_prepare_write for proposed writes, and tc_provider_execute_write after operator approval.",
					`Granted provider scopes: ${providerScopes.join(", ")}.`,
					capabilityScopes.length > 0
						? `Granted capability scopes: ${capabilityScopes.join(", ")}.`
						: "No web, media, or skill-request capability scopes are granted for this turn.",
					"</hermes-provider-runtime>",
				].join("\n")
			: [
					"<hermes-provider-runtime>",
					"No provider scopes are granted for this Hermes private-runtime turn. Do not attempt provider reads or writes.",
					capabilityScopes.length > 0
						? `Granted capability scopes: ${capabilityScopes.join(", ")}.`
						: "No web, media, or skill-request capability scopes are granted for this turn.",
					"</hermes-provider-runtime>",
				].join("\n");
	return {
		providerScopes,
		capabilityScopes,
		outboundChannels,
		systemPromptAppend: actionCatalogAppend
			? `${runtimeBlock}\n${actionCatalogAppend}`
			: runtimeBlock,
	};
}

function gateCapabilityScopesByTier(
	scopes: readonly TelclaudeMcpCapabilityScope[],
	tier: PermissionTier | undefined,
): TelclaudeMcpCapabilityScope[] {
	// Fail-closed: write-tier scopes (e.g. schedule.write) are granted ONLY when
	// the caller passes an explicit write-capable tier. A missing/undefined tier
	// or READ_ONLY strips them, so a future caller that forgets to thread `tier`
	// cannot silently grant write capability. All current call sites pass a
	// concrete tier (live / READ_ONLY / WRITE_LOCAL), so this changes only the
	// unreachable no-tier path.
	if (tier && tier !== "READ_ONLY") return [...scopes];
	return scopes.filter((scope) => !WRITE_TIER_CAPABILITY_SCOPES.has(scope));
}

function uniqueSorted(values: readonly string[] | undefined): string[] {
	return [...new Set(values ?? [])]
		.map((value) => value.trim())
		.filter(Boolean)
		.sort();
}
