import { afterEach, describe, expect, it, vi } from "vitest";

import {
	buildRelayTelegramMonitorOptions,
	handleProviderStartupHealth,
	shouldValidateTelegramEnv,
	validateProbeNoTelegramRelayMode,
} from "../../src/commands/relay.js";

describe("relay command", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("keeps probe-no-telegram behind explicit dry-run Hermes live-probe gates", () => {
		expect(
			validateProbeNoTelegramRelayMode({
				probeNoTelegram: true,
				dryRun: false,
				liveMcpEnabled: true,
				liveMcpAdminEnabled: true,
			}),
		).toContain("--dry-run");

		expect(
			validateProbeNoTelegramRelayMode({
				probeNoTelegram: true,
				dryRun: true,
				liveMcpEnabled: false,
				liveMcpAdminEnabled: true,
			}),
		).toContain("TELCLAUDE_HERMES_LIVE_MCP_ENABLED=1");

		expect(
			validateProbeNoTelegramRelayMode({
				probeNoTelegram: true,
				dryRun: true,
				liveMcpEnabled: true,
				liveMcpAdminEnabled: false,
			}),
		).toContain("TELCLAUDE_HERMES_LIVE_MCP_ADMIN_ENABLED=1");

		expect(
			validateProbeNoTelegramRelayMode({
				probeNoTelegram: true,
				dryRun: true,
				liveMcpEnabled: true,
				liveMcpAdminEnabled: true,
			}),
		).toBeNull();
	});

	it("does not affect normal relay mode", () => {
		expect(validateProbeNoTelegramRelayMode({ probeNoTelegram: false })).toBeNull();
		expect(validateProbeNoTelegramRelayMode({})).toBeNull();
	});

	it("skips Telegram env validation only for probe-no-telegram mode", () => {
		expect(shouldValidateTelegramEnv({})).toBe(true);
		expect(shouldValidateTelegramEnv({ probeNoTelegram: false })).toBe(true);
		expect(shouldValidateTelegramEnv({ probeNoTelegram: true })).toBe(false);
	});

	it("passes the live MCP conversation store into Telegram monitoring", () => {
		const abortController = new AbortController();
		const onReady = () => {};
		const mcpConversationStore = { marker: "store" } as never;

		const options = buildRelayTelegramMonitorOptions({
			verbose: true,
			abortSignal: abortController.signal,
			securityProfile: "strict",
			dryRun: false,
			onReady,
			mcpConversationStore,
		});

		expect(options).toMatchObject({
			verbose: true,
			keepAlive: true,
			abortSignal: abortController.signal,
			securityProfile: "strict",
			dryRun: false,
		});
		expect(options.onReady).toBe(onReady);
		expect(options.mcpConversationStore).toBe(mcpConversationStore);
	});

	it("warns and continues when a provider is unhealthy by default", () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);

		handleProviderStartupHealth([
			{
				providerId: "israel-services",
				baseUrl: "http://israel-services:3003",
				reachable: true,
				response: { status: "unhealthy" },
			},
		]);

		expect(warn).toHaveBeenCalledWith("Provider health check failed: israel-services: unhealthy");
		expect(warn).toHaveBeenCalledWith(
			expect.stringContaining("TELCLAUDE_REQUIRE_HEALTHY_PROVIDERS=1"),
		);
		expect(error).not.toHaveBeenCalled();
		expect(exit).not.toHaveBeenCalled();
	});

	it("keeps fatal startup health checks behind the strict opt-in", () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);

		handleProviderStartupHealth(
			[
				{
					providerId: "israel-services",
					baseUrl: "http://israel-services:3003",
					reachable: true,
					response: { status: "unhealthy" },
				},
			],
			true,
		);

		expect(error).toHaveBeenCalledWith("Provider health check failed: israel-services: unhealthy");
		expect(exit).toHaveBeenCalledWith(2);
		expect(warn).not.toHaveBeenCalled();
	});
});
