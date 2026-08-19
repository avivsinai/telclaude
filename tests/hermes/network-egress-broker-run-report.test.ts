import { describe, expect, it } from "vitest";
import {
	NETWORK_EGRESS_BROKER_RUN_REPORT_SCHEMA_VERSION,
	NETWORK_EGRESS_BROKER_RUN_REPORT_SOURCE,
} from "../../src/hermes/browser-computer-broker-probes.js";
import {
	NETWORK_EGRESS_BROKER_CORE_HTTP_KINDS,
	type NetworkEgressBrokerContainerProbeRequest,
	type NetworkEgressBrokerContainerProbeResult,
	runNetworkEgressBrokerRunReport,
} from "../../src/hermes/network-egress-broker-run-report.js";

describe("network egress-broker run report generator", () => {
	it("passes only attempts that were actually observed through container probes", async () => {
		const requests: NetworkEgressBrokerContainerProbeRequest[] = [];
		const report = await runNetworkEgressBrokerRunReport({
			allowRun: true,
			containerName: "tc-hermes-contained",
			now: new Date("2026-06-20T07:00:00.000Z"),
			mcp: {
				url: "http://telclaude:8793/mcp",
				headers: { Authorization: "Bearer probe" },
				publicResearchUrl: "https://example.com/",
			},
			targets: {
				provider: "https://provider.example.invalid/login",
				model: "https://api.openai.com/v1/responses",
				vault: "http://vault:8222/v1/secrets",
				metadata: "http://169.254.169.254/latest/meta-data",
				"private-network": "http://10.0.0.12/admin",
				doh: "https://dns.google/dns-query",
			},
			probeContainer: async (request): Promise<NetworkEgressBrokerContainerProbeResult> => {
				requests.push(request);
				if (request.mode === "mcp-web-fetch") {
					return {
						observed: "reachable",
						detail: "tc_web_fetch returned HTTP 200 through the served MCP endpoint",
						httpStatus: 200,
						durationMs: 12,
					};
				}
				if (request.kind === "model") {
					return {
						observed: "reachable",
						detail: "direct model-provider endpoint returned HTTP 200",
						httpStatus: 200,
						durationMs: 9,
					};
				}
				return {
					observed: "denied",
					detail: `${request.kind} direct egress was denied by the contained runtime`,
					errorName: "TypeError",
					errorCode: "ENETUNREACH",
					durationMs: 4,
				};
			},
		});

		expect(report).toMatchObject({
			schemaVersion: NETWORK_EGRESS_BROKER_RUN_REPORT_SCHEMA_VERSION,
			surfaceId: "network.egress-broker",
			ran: true,
			observedAt: "2026-06-20T07:00:00.000Z",
			source: NETWORK_EGRESS_BROKER_RUN_REPORT_SOURCE,
		});
		expect(report.attempts.map((attempt) => attempt.kind)).toEqual([
			"public-research",
			...NETWORK_EGRESS_BROKER_CORE_HTTP_KINDS,
		]);
		expect(report.attempts.find((attempt) => attempt.kind === "public-research")).toMatchObject({
			status: "pass",
			route: "telclaude-egress-broker",
			httpStatus: 200,
		});
		expect(report.attempts.find((attempt) => attempt.kind === "provider")).toMatchObject({
			status: "pass",
			observed: "denied",
			errorCode: "ENETUNREACH",
		});
		expect(report.attempts.find((attempt) => attempt.kind === "model")).toMatchObject({
			status: "fail",
			observed: "reachable",
			httpStatus: 200,
		});
		expect(requests).toHaveLength(1 + NETWORK_EGRESS_BROKER_CORE_HTTP_KINDS.length);
	});

	it("fails a deny attempt when a reachable target spoofs the policy-denial header", async () => {
		const report = await runNetworkEgressBrokerRunReport({
			allowRun: true,
			containerName: "tc-hermes-contained",
			now: new Date("2026-06-20T07:00:00.000Z"),
			targets: {
				provider: "https://provider.example.invalid/login",
			},
			probeContainer: async (): Promise<NetworkEgressBrokerContainerProbeResult> => ({
				observed: "policy_denied",
				detail: "target was denied by the Telclaude network policy proxy",
				httpStatus: 403,
				durationMs: 3,
			}),
		});

		expect(report.attempts).toHaveLength(1);
		expect(report.attempts[0]).toMatchObject({
			kind: "provider",
			expectation: "deny",
			status: "fail",
			observed: "reachable",
			httpStatus: 403,
		});
	});

	it("refuses to produce the machine-observed report without allowRun", async () => {
		await expect(
			runNetworkEgressBrokerRunReport({
				allowRun: false,
				containerName: "tc-hermes-contained",
				targets: {},
				probeContainer: async () => {
					throw new Error("should not execute");
				},
			}),
		).rejects.toThrow("requires --allow-run");
	});
});
