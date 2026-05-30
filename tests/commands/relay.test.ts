import { describe, expect, it } from "vitest";

import {
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
});
