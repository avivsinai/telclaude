import type { TelclaudeConfig } from "../config/config.js";

export type HermesPrivateRuntimeProviderContext = {
	readonly providerScopes: readonly string[];
	readonly systemPromptAppend: string;
};

export function buildHermesPrivateRuntimeProviderContext(
	config: Pick<TelclaudeConfig, "hermes">,
): HermesPrivateRuntimeProviderContext {
	const providerScopes = [...new Set(config.hermes?.privateRuntime?.providerScopes ?? [])].sort();
	return {
		providerScopes,
		systemPromptAppend:
			providerScopes.length > 0
				? [
						"<hermes-provider-runtime>",
						"Provider access is relay-owned. Do not call provider hostnames, provider URLs, curl, WebFetch, or telclaude provider CLI commands.",
						"This supersedes any legacy external-provider or provider-query instructions in the surrounding context.",
						"Use only the served MCP provider tools: tc_provider_read for reads, tc_provider_prepare_write for proposed writes, and tc_provider_execute_write after operator approval.",
						`Granted provider scopes: ${providerScopes.join(", ")}.`,
						"</hermes-provider-runtime>",
					].join("\n")
				: [
						"<hermes-provider-runtime>",
						"No provider scopes are granted for this Hermes private-runtime turn. Do not attempt provider reads or writes.",
						"</hermes-provider-runtime>",
					].join("\n"),
	};
}
