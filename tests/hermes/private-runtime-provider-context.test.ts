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

	it("strips schedule.write below WRITE_LOCAL but keeps schedule.read", () => {
		const grant = {
			providerScopes: [],
			capabilityScopes: ["schedule.read", "schedule.write", "web.search"],
			outboundChannels: [],
		} as const;
		const config = { hermes: { privateRuntime: grant } };

		// READ_ONLY: schedule.write (a relay-mutating scope) is dropped.
		const readOnly = buildHermesPrivateRuntimeProviderContext(config, grant, "READ_ONLY");
		expect(readOnly.capabilityScopes).toEqual(["schedule.read", "web.search"]);

		// WRITE_LOCAL and above keep the full grant.
		const writeLocal = buildHermesPrivateRuntimeProviderContext(config, grant, "WRITE_LOCAL");
		expect(writeLocal.capabilityScopes).toEqual(["schedule.read", "schedule.write", "web.search"]);

		// Fail-closed: a missing/undefined tier strips write-tier scopes, so a
		// caller that forgets to thread `tier` cannot silently grant schedule.write.
		const noTier = buildHermesPrivateRuntimeProviderContext(config, grant);
		expect(noTier.capabilityScopes).toEqual(["schedule.read", "web.search"]);
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
