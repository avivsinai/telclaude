import { describe, expect, it } from "vitest";
import { buildHermesPrivateRuntimeProviderContext } from "../../src/hermes/private-runtime-provider-context.js";
import type { ProviderActionCatalog } from "../../src/providers/provider-action-catalog.js";

const ACTION_CATALOG: ProviderActionCatalog = {
	"israel-services": {
		clalit: [
			{ id: "appointments", write: false },
			{ id: "lab_results", write: false },
			{ id: "prescriptions", write: false },
			{ id: "prescription_renewal", write: true },
		],
		poalim: [
			{ id: "accounts", write: false },
			{ id: "balance", write: false },
		],
	},
	google: {
		gmail: [
			{ id: "read_message", write: false },
			{ id: "search", write: false },
		],
	},
};

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

	it("strips browse.act below WRITE_LOCAL but keeps browse.use", () => {
		const grant = {
			providerScopes: [],
			capabilityScopes: ["browse.use", "browse.act", "schedule.write"],
			outboundChannels: [],
		} as const;
		const config = { hermes: { privateRuntime: grant } };

		// READ_ONLY: browse.act (a browser-write scope) is dropped alongside
		// schedule.write, but browse.use (reading a public page) survives.
		const readOnly = buildHermesPrivateRuntimeProviderContext(config, grant, "READ_ONLY");
		expect(readOnly.capabilityScopes).toEqual(["browse.use"]);

		// WRITE_LOCAL and above keep browse.act (and schedule.write).
		const writeLocal = buildHermesPrivateRuntimeProviderContext(config, grant, "WRITE_LOCAL");
		expect(writeLocal.capabilityScopes).toEqual(["browse.act", "browse.use", "schedule.write"]);

		// Fail-closed: a missing/undefined tier strips the write-tier scopes, so a
		// caller that forgets to thread `tier` cannot silently grant browse.act.
		const noTier = buildHermesPrivateRuntimeProviderContext(config, grant);
		expect(noTier.capabilityScopes).toEqual(["browse.use"]);
	});

	it("injects the granted-scope action catalog so the agent stops guessing action ids", () => {
		const context = buildHermesPrivateRuntimeProviderContext(
			{
				hermes: {
					privateRuntime: {
						providerScopes: ["clalit", "bank", "google", "government"],
						capabilityScopes: [],
						outboundChannels: [],
					},
				},
			},
			undefined,
			"WRITE_LOCAL",
			ACTION_CATALOG,
		);

		expect(context.systemPromptAppend).toContain("</hermes-provider-runtime>");
		expect(context.systemPromptAppend).toContain("<hermes-provider-actions>");
		expect(context.systemPromptAppend).toContain(
			'- service "clalit": appointments, lab_results, prescriptions',
		);
		// bank alias -> poalim actions, presented under the agent-facing "bank" service.
		expect(context.systemPromptAppend).toContain('- service "bank": accounts, balance');
		expect(context.systemPromptAppend).toContain('- service "gmail": read_message, search');
		// The clalit write is routed to the two-phase prepare-write path, not read.
		expect(context.systemPromptAppend).toContain("tc_provider_prepare_write");
		expect(context.systemPromptAppend).toMatch(
			/Writes[\s\S]*- service "clalit": prescription_renewal/,
		);
		// Stale/unconfigured government grant must not sprout invented actions.
		expect(context.systemPromptAppend).not.toContain('service "government"');
	});

	it("omits the action catalog block when no schema catalog is available", () => {
		const context = buildHermesPrivateRuntimeProviderContext(
			{
				hermes: {
					privateRuntime: {
						providerScopes: ["clalit"],
						capabilityScopes: [],
						outboundChannels: [],
					},
				},
			},
			undefined,
			"WRITE_LOCAL",
			null,
		);

		expect(context.systemPromptAppend).toContain("Granted provider scopes: clalit");
		expect(context.systemPromptAppend).not.toContain("<hermes-provider-actions>");
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
