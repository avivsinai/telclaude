import { describe, expect, it } from "vitest";
import { buildHermesPrivateRuntimeProviderContext } from "../../src/hermes/private-runtime-provider-context.js";

describe("Hermes private runtime provider context", () => {
	it("fails closed when no provider scopes are configured", () => {
		const context = buildHermesPrivateRuntimeProviderContext({
			hermes: { privateRuntime: { providerScopes: [] } },
		});

		expect(context.providerScopes).toEqual([]);
		expect(context.systemPromptAppend).toContain("No provider scopes are granted");
		expect(context.systemPromptAppend).toContain("Do not attempt provider reads or writes");
	});

	it("binds configured canonical provider scopes to MCP-only provider instructions", () => {
		const context = buildHermesPrivateRuntimeProviderContext({
			hermes: { privateRuntime: { providerScopes: ["bank", "google", "bank"] } },
		});

		expect(context.providerScopes).toEqual(["bank", "google"]);
		expect(context.systemPromptAppend).toContain("tc_provider_read");
		expect(context.systemPromptAppend).toContain("tc_provider_prepare_write");
		expect(context.systemPromptAppend).toContain("tc_provider_execute_write");
		expect(context.systemPromptAppend).toContain("Granted provider scopes: bank, google");
		expect(context.systemPromptAppend).toContain("Do not call provider hostnames");
		expect(context.systemPromptAppend).toContain("supersedes any legacy external-provider");
	});
});
