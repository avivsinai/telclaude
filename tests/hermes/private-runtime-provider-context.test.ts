import { describe, expect, it } from "vitest";
import { buildHermesPrivateRuntimeProviderContext } from "../../src/hermes/private-runtime-provider-context.js";

describe("Hermes private runtime provider context", () => {
	it("fails closed when no provider scopes are configured", () => {
		const context = buildHermesPrivateRuntimeProviderContext({
			hermes: {
				privateRuntime: { providerScopes: [], capabilityScopes: [], outboundChannels: [] },
			},
		});

		expect(context.providerScopes).toEqual([]);
		expect(context.capabilityScopes).toEqual([]);
		expect(context.outboundChannels).toEqual([]);
		expect(context.systemPromptAppend).toContain("No provider scopes are granted");
		expect(context.systemPromptAppend).toContain("Do not attempt provider reads or writes");
		expect(context.systemPromptAppend).toContain(
			"No web, media, or skill-request capability scopes are granted",
		);
	});

	it("binds configured canonical scopes to MCP-only provider instructions", () => {
		const context = buildHermesPrivateRuntimeProviderContext({
			hermes: {
				privateRuntime: {
					providerScopes: ["bank", "google", "bank"],
					capabilityScopes: ["web.search", "web.fetch", "web.search"],
					outboundChannels: ["whatsapp", "whatsapp"],
				},
			},
		});

		expect(context.providerScopes).toEqual(["bank", "google"]);
		expect(context.capabilityScopes).toEqual(["web.fetch", "web.search"]);
		expect(context.outboundChannels).toEqual(["whatsapp"]);
		expect(context.systemPromptAppend).toContain("tc_provider_read");
		expect(context.systemPromptAppend).toContain("tc_provider_prepare_write");
		expect(context.systemPromptAppend).toContain("tc_provider_execute_write");
		expect(context.systemPromptAppend).toContain("Granted provider scopes: bank, google");
		expect(context.systemPromptAppend).toContain(
			"Granted capability scopes: web.fetch, web.search",
		);
		expect(context.systemPromptAppend).toContain("Do not call provider hostnames");
		expect(context.systemPromptAppend).toContain("supersedes any legacy external-provider");
	});

	it("lets explicit profile scopes override global private-runtime scopes", () => {
		const context = buildHermesPrivateRuntimeProviderContext(
			{
				hermes: {
					privateRuntime: {
						providerScopes: ["bank"],
						capabilityScopes: ["media.tts"],
						outboundChannels: ["whatsapp"],
					},
				},
			},
			{
				providerScopes: ["google"],
				capabilityScopes: ["web.search"],
				outboundChannels: ["whatsapp"],
			},
		);

		expect(context.providerScopes).toEqual(["google"]);
		expect(context.capabilityScopes).toEqual(["web.search"]);
		expect(context.outboundChannels).toEqual(["whatsapp"]);
	});
});
