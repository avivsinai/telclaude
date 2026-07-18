import { Command } from "commander";
import { afterEach, describe, expect, it, vi } from "vitest";

const relayProviderProxy = vi.hoisted(() => vi.fn());

vi.mock("../../src/relay/capabilities-client.js", () => ({
	relayProviderProxy,
}));

vi.mock("../../src/commands/cli-guards.js", () => ({
	requireRelay: vi.fn(),
}));

import { registerProviderQueryCommand } from "../../src/commands/provider-query.js";

describe("provider-query command", () => {
	afterEach(() => {
		relayProviderProxy.mockReset();
		vi.restoreAllMocks();
	});

	it("continues to surface runtime provider errors", async () => {
		relayProviderProxy.mockResolvedValue({
			status: "error",
			error: "Authentication timed out",
		});
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		const exit = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
			throw new Error(`exit ${code}`);
		}) as never);
		const program = new Command();
		registerProviderQueryCommand(program);

		await expect(
			program.parseAsync([
				"node",
				"telclaude",
				"provider-query",
				"--provider",
				"israel-services",
				"--service",
				"health-api",
				"--action",
				"appointments",
			]),
		).rejects.toThrow("exit 1");

		expect(error).toHaveBeenCalledWith("Error: Authentication timed out");
		expect(exit).toHaveBeenCalledWith(1);
	});
});
