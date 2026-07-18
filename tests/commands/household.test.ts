import { Command } from "commander";
import { describe, expect, it, vi } from "vitest";

const collectRollupsMock = vi.hoisted(() => vi.fn());

vi.mock("../../src/household-metrics/store.js", () => ({
	collectHouseholdMetricRollups: collectRollupsMock,
}));

import {
	collectHouseholdStatsRows,
	formatHouseholdPreflightText,
	formatHouseholdStatsRows,
	householdPreflightExitCode,
	probeHouseholdBridgeHealth,
	registerHouseholdCommand,
	runHouseholdPreflight,
} from "../../src/commands/household.js";
import type { TelclaudeConfig } from "../../src/config/config.js";
import type { HealthCheckResult } from "../../src/providers/provider-health.js";

const VALID_ENV = {
	TELCLAUDE_HOUSEHOLD_MEDIA_CONFIRMATION_KEY: "household-media-test-encryption-key-32chars",
	TELCLAUDE_WHATSAPP_SIDECAR_URL: "http://whatsapp-bridge:3004",
	TELCLAUDE_WHATSAPP_BRIDGE_SECRET: "bridge-secret",
	TELCLAUDE_WHATSAPP_ALLOWED_RECIPIENTS: "+15551234567,+15557654321",
	TELCLAUDE_WHATSAPP_INBOUND_SECRET: "inbound-secret",
	TELCLAUDE_WHATSAPP_INBOUND_OPERATOR_ADDRESSES: "+15551234567,+15557654321",
} as const;

const HEALTHY_PROVIDER: HealthCheckResult = {
	providerId: "clalit",
	baseUrl: "http://israel-services:3010",
	reachable: true,
	response: { status: "healthy", connectors: { clalit: { status: "ok" } } },
};

function consentReceipt() {
	return {
		service: "clalit",
		state: "granted",
		ceremonyVersion: "phase0.v1",
		ceremonyHash: `sha256:${"a".repeat(64)}`,
		verifiedChannelHash: `sha256:${"b".repeat(64)}`,
		categories: {
			otpRelay: true,
			subjectOwnership: true,
			retentionDisclosure: true,
			emergencyUnderstanding: true,
		},
		recordedAt: "2026-07-18T12:00:00.000Z",
		operatorId: "operator:test",
	};
}

function reminderConsentReceipt() {
	return {
		state: "granted",
		ceremonyVersion: "phase0.v1",
		ceremonyHash: `sha256:${"c".repeat(64)}`,
		verifiedChannelHash: `sha256:${"d".repeat(64)}`,
		categories: {
			proactiveDelivery: true,
			scheduleManagement: true,
			retentionDisclosure: true,
		},
		recordedAt: "2026-07-18T12:00:00.000Z",
		operatorId: "operator:test",
	};
}

function householdBinding(index: number) {
	const suffix = index === 0 ? "1234567" : "7654321";
	return {
		bindingId: `parent-${index + 1}`,
		addresseeGender: index === 0 ? ("f" as const) : ("m" as const),
		address: `whatsapp:+1555${suffix}`,
		replyAddress: `whatsapp:+1555${suffix}`,
		displayName: index === 0 ? "Private Parent Name" : "Second Private Name",
		subjectUserId: `household:parent-${index + 1}`,
		providerConsent: consentReceipt(),
		reminderConsent: reminderConsentReceipt(),
		mediaEnabled: true,
		remindersEnabled: true,
	};
}

function householdConfig(
	rung: TelclaudeConfig["householdRollout"]["rung"] = "parentA_media",
	bindingCount = 1,
): TelclaudeConfig {
	return {
		householdRollout: { rung },
		householdReminders: { enabled: rung !== "shadow" },
		householdMedia: {
			enabled: rung !== "shadow" && rung !== "parentA_text" && rung !== "parentA_clalit",
			dataControlAck: {
				acknowledged: true,
				posture: "zdr",
				recordedAt: "2026-07-18T12:00:00.000Z",
				operatorId: "operator:test",
			},
		},
		householdEmergency: { enabled: false },
		householdMetrics: { enabled: false, dailyDigest: { enabled: false, atHour: 8 } },
		hermes: {
			privateRuntime: {
				providerScopes: ["clalit"],
				capabilityScopes: [],
				outboundChannels: ["whatsapp"],
			},
		},
		providers: [{ id: "clalit", baseUrl: "http://israel-services:3010", services: ["clalit"] }],
		profiles: Array.from({ length: bindingCount }, (_, index) => ({
			id: `parent-${index + 1}`,
			label: `Private profile ${index + 1}`,
			whatsappHouseholdBindings: [householdBinding(index)],
		})),
	} as TelclaudeConfig;
}

const CONNECTED_BRIDGE = {
	reachable: true as const,
	connected: true,
	state: "connected" as const,
};

function check(report: Awaited<ReturnType<typeof runHouseholdPreflight>>, name: string) {
	const result = report.report.checks.find((candidate) => candidate.name === name);
	if (!result) throw new Error(`missing check ${name}`);
	return result;
}

describe("household stats command", () => {
	it("collects operator-readable per-binding counters", () => {
		collectRollupsMock.mockReturnValue([
			{ bindingKey: "mom", metricKind: "inbound_received", count: 7 },
		]);

		expect(collectHouseholdStatsRows()).toEqual([
			{ bindingKey: "mom", metricKind: "inbound_received", count: 7 },
		]);
	});

	it("formats only binding, fixed metric kind, and count", () => {
		const output = formatHouseholdStatsRows([
			{ bindingKey: "mom", metricKind: "inbound_received", count: 7 },
			{ bindingKey: "mom", metricKind: "approval_latency_le_30s", count: 2 },
		]);

		expect(output).toContain("BINDING");
		expect(output).toContain("mom");
		expect(output).toContain("approval_latency_le_30s");
		expect(output).not.toContain("message");
	});
});

describe("household activation preflight", () => {
	it("returns a content-free report without mutating household config", async () => {
		const config = householdConfig("parentA_media");
		const before = structuredClone(config);
		const result = await runHouseholdPreflight(config, {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});

		expect(config).toEqual(before);
		expect(result.rung).toBe("parentA_media");
		expect(result.nextRung).toBe("parentA_renewal");
		expect(result.unmetForNext).toEqual([]);
		expect(result.report.summary.fail).toBe(0);
		expect(check(result, "household.bindings").status).toBe("pass");
		expect(check(result, "household.consent").status).toBe("pass");

		const output = JSON.stringify(result);
		expect(output).not.toContain("+1555");
		expect(output).not.toContain("Private Parent Name");
		expect(output).not.toContain("operator:test");
		expect(output).not.toContain("sha256:");
	});

	it("fails bindings and consent when no household principal is enrolled", async () => {
		const config = householdConfig("shadow", 0);
		const result = await runHouseholdPreflight(config, {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});

		expect(check(result, "household.bindings").status).toBe("fail");
		expect(check(result, "household.consent").status).toBe("fail");
		expect(check(result, "household.rollout").status).toBe("fail");
	});

	it("requires both consent receipts on the same binding", async () => {
		const config = householdConfig("shadow", 2);
		const first = config.profiles[0]?.whatsappHouseholdBindings?.[0];
		const second = config.profiles[1]?.whatsappHouseholdBindings?.[0];
		if (!first || !second) throw new Error("expected two test bindings");
		delete first.providerConsent;
		delete second.reminderConsent;

		const result = await runHouseholdPreflight(config, {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});

		expect(check(result, "household.consent").status).toBe("fail");
	});

	it("fails media and data-control checks when the declared media rung lacks an acknowledgement", async () => {
		const config = householdConfig("parentA_media");
		delete config.householdMedia.dataControlAck;

		const result = await runHouseholdPreflight(config, {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});

		expect(check(result, "household.media").status).toBe("fail");
		expect(check(result, "household.data-control").status).toBe("fail");
		expect(result.unmetForNext).toEqual(expect.arrayContaining(["media", "data-control"]));
	});

	it("warns when a later-rung lane is armed early and fails when a current-rung lane is dark", async () => {
		const early = householdConfig("shadow");
		early.householdMedia.enabled = true;
		const earlyResult = await runHouseholdPreflight(early, {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});
		expect(check(earlyResult, "household.switches").status).toBe("warn");

		const dark = householdConfig("parentA_reminders");
		dark.householdReminders.enabled = false;
		const darkResult = await runHouseholdPreflight(dark, {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});
		expect(check(darkResult, "household.switches").status).toBe("fail");
		expect(check(darkResult, "household.rollout").status).toBe("fail");
	});

	it.each([
		["unreachable", { ...HEALTHY_PROVIDER, reachable: false, response: undefined }, "fail"],
		[
			"auth expired",
			{
				...HEALTHY_PROVIDER,
				response: {
					status: "unhealthy" as const,
					connectors: { clalit: { status: "auth_expired" as const } },
				},
			},
			"fail",
		],
		[
			"connector error",
			{
				...HEALTHY_PROVIDER,
				response: {
					status: "unhealthy" as const,
					connectors: { clalit: { status: "error" as const } },
				},
			},
			"fail",
		],
		[
			"connector drift",
			{
				...HEALTHY_PROVIDER,
				response: {
					status: "degraded" as const,
					connectors: { clalit: { status: "drift_detected" as const } },
				},
			},
			"warn",
		],
		[
			"top-level degradation",
			{
				...HEALTHY_PROVIDER,
				response: {
					status: "degraded" as const,
					connectors: { clalit: { status: "ok" as const } },
				},
			},
			"warn",
		],
		["healthy", HEALTHY_PROVIDER, "pass"],
	] as const)("classifies %s Clalit health", async (_label, health, status) => {
		const result = await runHouseholdPreflight(householdConfig("parentA_clalit"), {
			env: VALID_ENV,
			checkProviderHealth: async () => health,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});

		expect(check(result, "household.provider").status).toBe(status);
		expect(check(result, "household.provider").detail).toContain("connector-scoped");
	});

	it.each([
		["connected", CONNECTED_BRIDGE, "pass"],
		[
			"waiting for pairing",
			{ reachable: true as const, connected: false, state: "waiting_for_pairing" as const },
			"fail",
		],
		[
			"disconnected",
			{ reachable: true as const, connected: false, state: "disconnected" as const },
			"fail",
		],
		[
			"logged out",
			{ reachable: true as const, connected: false, state: "logged_out" as const },
			"fail",
		],
		["unreachable", { reachable: false as const, state: "unreachable" as const }, "fail"],
	] as const)("classifies a %s bridge", async (_label, bridge, status) => {
		const result = await runHouseholdPreflight(householdConfig("parentA_text"), {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => bridge,
		});

		expect(check(result, "household.bridge").status).toBe(status);
	});

	it("requires a second independently consented binding before parent B", async () => {
		const result = await runHouseholdPreflight(householdConfig("hold_72h"), {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});

		expect(result.nextRung).toBe("parentB_text");
		expect(result.unmetForNext).toEqual(expect.arrayContaining(["bindings", "consent"]));
		expect(check(result, "household.rollout").status).toBe("pass");
	});

	it("probes only the isolated bridge health endpoint with a 2.5 second bound", async () => {
		const fetch = vi.fn(
			async () =>
				new Response(JSON.stringify({ ok: true, connected: true, state: "connected" }), {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
		);
		await expect(probeHouseholdBridgeHealth(VALID_ENV, fetch)).resolves.toEqual(CONNECTED_BRIDGE);
		expect(fetch).toHaveBeenCalledWith(
			"http://whatsapp-bridge:3004/health",
			expect.objectContaining({ method: "GET" }),
			2_500,
		);

		const forbiddenFetch = vi.fn();
		await expect(
			probeHouseholdBridgeHealth(
				{ ...VALID_ENV, TELCLAUDE_WHATSAPP_SIDECAR_URL: "http://example.com:3004" },
				forbiddenFetch,
			),
		).resolves.toEqual({ reachable: false, state: "invalid_config" });
		expect(forbiddenFetch).not.toHaveBeenCalled();
	});
});

describe("household preflight command", () => {
	it("registers stats and preflight under one household command group", () => {
		const program = new Command();
		const household = program.command("household");
		registerHouseholdCommand(household);

		expect(household.commands.map((command) => command.name())).toEqual(["stats", "preflight"]);
	});

	it("renders grouped text with a summary and immediate-next-rung ladder", async () => {
		const result = await runHouseholdPreflight(householdConfig("shadow", 0), {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});

		const output = formatHouseholdPreflightText(result);
		expect(output).toContain("bindings\n");
		expect(output).toContain("consent\n");
		expect(output).toContain("Summary: FAIL");
		expect(output).toContain(
			"Ladder: currently at shadow; to advance to parentA_text you need: bindings, consent",
		);
	});

	it("maps fail to exit 1 and pass or warn to exit 0", async () => {
		const failed = await runHouseholdPreflight(householdConfig("shadow", 0), {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});
		const passed = await runHouseholdPreflight(householdConfig("shadow"), {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});
		const warnedConfig = householdConfig("shadow");
		warnedConfig.householdMedia.enabled = true;
		const warned = await runHouseholdPreflight(warnedConfig, {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});

		expect(householdPreflightExitCode(failed)).toBe(1);
		expect(householdPreflightExitCode(passed)).toBe(0);
		expect(householdPreflightExitCode(warned)).toBe(0);
		expect(warned.report.summary.warn).toBeGreaterThan(0);
	});

	it("emits only the structured result for --json without mutating config", async () => {
		const config = householdConfig("shadow", 0);
		const before = structuredClone(config);
		const result = await runHouseholdPreflight(config, {
			env: VALID_ENV,
			checkProviderHealth: async () => HEALTHY_PROVIDER,
			probeBridgeHealth: async () => CONNECTED_BRIDGE,
		});
		let output = "";
		let exitCode: number | undefined;
		const program = new Command();
		const household = program.command("household");
		registerHouseholdCommand(household, {
			loadConfig: () => config,
			runPreflight: async () => result,
			writeOutput: (value) => {
				output += value;
			},
			setExitCode: (value) => {
				exitCode = value;
			},
		});

		await program.parseAsync(["node", "telclaude", "household", "preflight", "--json"]);

		expect(config).toEqual(before);
		expect(JSON.parse(output)).toEqual(result);
		expect(Object.keys(JSON.parse(output))).toEqual(["report", "rung", "nextRung", "unmetForNext"]);
		expect(exitCode).toBe(1);
	});

	it("returns fixed content-free input_error JSON with exit 2 when config loading fails", async () => {
		let output = "";
		let exitCode: number | undefined;
		const program = new Command();
		const household = program.command("household");
		registerHouseholdCommand(household, {
			loadConfig: () => {
				throw new Error("private config path and value must not leak");
			},
			writeOutput: (value) => {
				output += value;
			},
			setExitCode: (value) => {
				exitCode = value;
			},
		});

		await program.parseAsync(["node", "telclaude", "household", "preflight", "--json"]);

		expect(JSON.parse(output)).toEqual({
			status: "input_error",
			detail: "household preflight could not load required inputs",
		});
		expect(output).not.toContain("private config");
		expect(exitCode).toBe(2);
	});
});
