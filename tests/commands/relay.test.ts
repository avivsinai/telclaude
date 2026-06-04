import { describe, expect, it } from "vitest";

import {
	buildRelayTelegramMonitorOptions,
	shouldValidateTelegramEnv,
	validateProbeNoTelegramRelayMode,
} from "../../src/commands/relay.js";

describe("relay command", () => {
	it("keeps probe-no-telegram behind explicit dry-run Hermes live-probe gates", () => {
		expect(
			validateProbeNoTelegramRelayMode({
				probeNoTelegram: true,
				dryRun: false,
				privateRuntimeEnabled: true,
				liveMcpEnabled: true,
				liveMcpAdminEnabled: true,
			}),
		).toContain("--dry-run");

		expect(
			validateProbeNoTelegramRelayMode({
				probeNoTelegram: true,
				dryRun: true,
				privateRuntimeEnabled: false,
				liveMcpEnabled: true,
				liveMcpAdminEnabled: true,
			}),
		).toContain("TELCLAUDE_HERMES_PRIVATE_RUNTIME=1");

		expect(
			validateProbeNoTelegramRelayMode({
				probeNoTelegram: true,
				dryRun: true,
				privateRuntimeEnabled: true,
				liveMcpEnabled: false,
				liveMcpAdminEnabled: true,
			}),
		).toContain("TELCLAUDE_HERMES_LIVE_MCP_ENABLED=1");

		expect(
			validateProbeNoTelegramRelayMode({
				probeNoTelegram: true,
				dryRun: true,
				privateRuntimeEnabled: true,
				liveMcpEnabled: true,
				liveMcpAdminEnabled: false,
			}),
		).toContain("TELCLAUDE_HERMES_LIVE_MCP_ADMIN_ENABLED=1");

		expect(
			validateProbeNoTelegramRelayMode({
				probeNoTelegram: true,
				dryRun: true,
				privateRuntimeEnabled: true,
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
});
