import type { TelclaudeConfig } from "../config/config.js";
import type { EffectiveOperatorProfile } from "../config/profiles.js";
import type { TelclaudeMcpCapabilityScope } from "./mcp/bridge.js";

export type HermesPrivateRuntimeProviderContext = {
	readonly providerScopes: readonly string[];
	readonly capabilityScopes: readonly TelclaudeMcpCapabilityScope[];
	readonly outboundChannels: readonly string[];
	readonly systemPromptAppend: string;
};

export function buildHermesPrivateRuntimeProviderContext(
	config: Pick<TelclaudeConfig, "hermes">,
	profile?: Pick<
		EffectiveOperatorProfile,
		"providerScopes" | "capabilityScopes" | "outboundChannels"
	>,
): HermesPrivateRuntimeProviderContext {
	const providerScopes = uniqueSorted(
		profile?.providerScopes ?? config.hermes?.privateRuntime?.providerScopes,
	);
	const capabilityScopes = uniqueSorted(
		profile?.capabilityScopes ?? config.hermes?.privateRuntime?.capabilityScopes,
	) as TelclaudeMcpCapabilityScope[];
	const outboundChannels = uniqueSorted(profile?.outboundChannels);
	return {
		providerScopes,
		capabilityScopes,
		outboundChannels,
		systemPromptAppend:
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
					].join("\n"),
	};
}

function uniqueSorted(values: readonly string[] | undefined): string[] {
	return [...new Set(values ?? [])]
		.map((value) => value.trim())
		.filter(Boolean)
		.sort();
}
